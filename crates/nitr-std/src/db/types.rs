// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use mlua::{Lua, Table, Value};
use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::{Connection, ToSql};

use std::sync::{Arc, Mutex};

/// One state's connection plus the per-connection limits that travel
/// with it onto the blocking thread.
pub(crate) struct Db {
    pub(crate) conn: Connection,
    /// Most rows one `query` may return (see `SqlitePragmas::max_rows`).
    pub(crate) max_rows: usize,
}

pub(crate) type Conn = Arc<Mutex<Db>>;

/// A plain, `Send` SQL value: the boundary type between the Lua state (async
/// thread) and rusqlite (blocking thread), so no Lua handle ever crosses
/// into `spawn_blocking`.
#[derive(Debug, Clone)]
pub(crate) enum SqlValue {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    /// Text is kept as raw bytes: both Lua strings and SQLite text are
    /// binary-safe.
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

impl ToSql for SqlValue {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(match self {
            SqlValue::Null => ToSqlOutput::from(rusqlite::types::Null),
            SqlValue::Bool(b) => ToSqlOutput::from(*b),
            SqlValue::Int(i) => ToSqlOutput::from(*i),
            SqlValue::Real(f) => ToSqlOutput::from(*f),
            SqlValue::Text(bytes) => ToSqlOutput::Borrowed(ValueRef::Text(bytes)),
            SqlValue::Blob(bytes) => ToSqlOutput::Borrowed(ValueRef::Blob(bytes)),
        })
    }
}

impl SqlValue {
    pub(crate) fn from_value_ref(value: ValueRef<'_>) -> Self {
        match value {
            ValueRef::Null => SqlValue::Null,
            ValueRef::Integer(i) => SqlValue::Int(i),
            ValueRef::Real(f) => SqlValue::Real(f),
            ValueRef::Text(bytes) => SqlValue::Text(bytes.to_vec()),
            ValueRef::Blob(bytes) => SqlValue::Blob(bytes.to_vec()),
        }
    }

    pub(crate) fn into_lua(self, lua: &Lua) -> mlua::Result<Value> {
        Ok(match self {
            SqlValue::Null => Value::Nil,
            SqlValue::Bool(b) => Value::Boolean(b),
            SqlValue::Int(i) => Value::Integer(i),
            SqlValue::Real(f) => Value::Number(f),
            SqlValue::Text(bytes) | SqlValue::Blob(bytes) => {
                Value::String(lua.create_string(bytes)?)
            }
        })
    }
}

/// A single result row as plain data: `(column name, value)` pairs in
/// column order.
/// A result row: column names are shared across every row of one query
/// (an `Arc<str>` each, cloned per cell) instead of being copied per cell.
pub(crate) type SqlRow = Vec<(Arc<str>, SqlValue)>;

/// The column names of a prepared statement, shared by all its rows.
///
/// A row is keyed by name, so two columns sharing one (`SELECT u.id,
/// o.id`) would keep only the last; that is refused. The message names
/// positions, not the names: a column named by an expression carries SQL
/// text.
pub(crate) fn column_names(
    stmt: &rusqlite::Statement<'_>,
) -> Result<Vec<Arc<str>>, rusqlite::Error> {
    let names = stmt.column_names();
    for (i, name) in names.iter().enumerate() {
        if let Some(j) = names[i + 1..].iter().position(|other| other == name) {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(format!(
                    "result columns {} and {} share a name; give one an alias (`AS`)",
                    i + 1,
                    i + j + 2
                )),
            ));
        }
    }
    Ok(names.iter().map(|s| Arc::from(*s)).collect())
}

/// `params` bound to `stmt`, the missing trailing ones as NULL: a Lua list
/// cannot end in nil (`{ name, nil }` has one element), so a shorter list
/// is one whose last values were nil. An empty list is not padded: a
/// statement called without its parameters keeps failing loudly, and a
/// lone NULL is `{ n = 1 }` or `table.pack(nil)`. More than the statement
/// takes is still an error.
pub(crate) fn bind<'a>(
    stmt: &rusqlite::Statement<'_>,
    params: &'a [SqlValue],
) -> impl rusqlite::Params + use<'a> {
    let missing = match params.len() {
        0 => 0,
        given => stmt.parameter_count().saturating_sub(given),
    };
    rusqlite::params_from_iter(
        params
            .iter()
            .chain(std::iter::repeat_n(&SqlValue::Null, missing)),
    )
}

/// Converts a result row into a Lua table keyed by column name.
///
/// `raw_set`: a fresh table has no metatable, so the metamethod-aware
/// `set` had nothing to consult and only cost the check.
pub(crate) fn row_to_lua(lua: &Lua, row: SqlRow) -> mlua::Result<Table> {
    let table = lua.create_table_with_capacity(0, row.len())?;
    for (column, value) in row {
        table.raw_set(&*column, value.into_lua(lua)?)?;
    }
    Ok(table)
}

/// `SQLITE_MAX_VARIABLE_NUMBER` in the bundled SQLite (`sqlite3.c`): no
/// statement binds more, and walking to a larger index would allocate one
/// NULL per missing slot.
const MAX_PARAMS: i64 = 32766;

/// Extracts positional SQL parameters from an optional Lua table.
///
/// A nil inside the list, or JSON `null`, binds NULL: the list runs to
/// `n` when the table carries it (`table.pack`), else to its highest
/// positive integer key, never to the first nil.
pub(crate) fn params_from_table(params: Option<&Table>) -> mlua::Result<Vec<SqlValue>> {
    let Some(table) = params else {
        return Ok(Vec::new());
    };
    let count = param_count(table)?;
    (1..=count).map(|i| sql_param(table.raw_get(i)?)).collect()
}

fn param_count(table: &Table) -> mlua::Result<usize> {
    let count = match table.raw_get::<Value>("n")? {
        Value::Integer(n) => n,
        Value::Number(n) if n.fract() == 0.0 => n as i64,
        Value::Nil => {
            let mut highest = 0;
            for pair in table.pairs::<Value, Value>() {
                if let (Value::Integer(key), _) = pair? {
                    highest = highest.max(key);
                }
            }
            highest
        }
        other => {
            return Err(mlua::Error::RuntimeError(format!(
                "SQL parameters: `n` must be an integer count, got `{}`",
                other.type_name()
            )));
        }
    };
    if !(0..=MAX_PARAMS).contains(&count) {
        return Err(mlua::Error::RuntimeError(format!(
            "SQL parameters: {count} is not a parameter count (at most {MAX_PARAMS})"
        )));
    }
    Ok(count as usize)
}

fn sql_param(value: Value) -> mlua::Result<SqlValue> {
    Ok(match value {
        Value::Nil => SqlValue::Null,
        null if null.is_null() => SqlValue::Null,
        Value::Boolean(b) => SqlValue::Bool(b),
        Value::Integer(i) => SqlValue::Int(i),
        Value::Number(n) => SqlValue::Real(n),
        Value::String(s) => SqlValue::Text(s.as_bytes().to_vec()),
        other => {
            return Err(mlua::Error::RuntimeError(format!(
                "unsupported SQL parameter type `{}`",
                other.type_name()
            )));
        }
    })
}

/// Reads all columns of the current row as plain data.
pub(crate) fn read_row(
    columns: &[Arc<str>],
    row: &rusqlite::Row<'_>,
) -> Result<SqlRow, rusqlite::Error> {
    let mut out = Vec::with_capacity(columns.len());
    for (i, column) in columns.iter().enumerate() {
        let value = SqlValue::from_value_ref(row.get_ref(i)?);
        out.push((column.clone(), value));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_lua_params_to_sql_values() {
        let lua = Lua::new();
        let table: Table = lua
            .load(r#"{ 7, 2.5, "text", true }"#)
            .eval()
            .expect("params table");
        let params = params_from_table(Some(&table)).expect("params");
        assert!(matches!(params[0], SqlValue::Int(7)));
        assert!(matches!(params[1], SqlValue::Real(f) if f == 2.5));
        assert!(matches!(&params[2], SqlValue::Text(t) if t == b"text"));
        assert!(matches!(params[3], SqlValue::Bool(true)));
        assert!(params_from_table(None).expect("empty").is_empty());
    }

    #[test]
    fn nil_and_json_null_bind_as_null() {
        let lua = Lua::new();
        lua.globals().set("null", Value::NULL).expect("set");
        for (src, len) in [
            ("{ 1, nil, 3 }", 3),
            ("table.pack(1, nil)", 2),
            ("{ 1, null }", 2),
            ("{ n = 2 }", 2),
        ] {
            let table: Table = lua.load(src).eval().expect("params table");
            let params = params_from_table(Some(&table)).expect(src);
            assert_eq!(params.len(), len, "{src}");
            assert!(matches!(params[1], SqlValue::Null), "{src}");
        }
    }

    #[test]
    fn a_parameter_index_past_sqlite_s_limit_is_refused() {
        let lua = Lua::new();
        for src in ["{ [1e9] = 1 }", "{ n = 1e9 }", "{ n = -1 }"] {
            let table: Table = lua.load(src).eval().expect("params table");
            assert!(params_from_table(Some(&table)).is_err(), "{src}");
        }
    }

    #[test]
    fn rejects_unsupported_param_types() {
        let lua = Lua::new();
        let table: Table = lua.load("{ function() end }").eval().expect("params table");
        assert!(params_from_table(Some(&table)).is_err());
    }

    #[test]
    fn row_converts_to_lua_table() {
        let lua = Lua::new();
        let row: SqlRow = vec![
            ("id".into(), SqlValue::Int(1)),
            ("name".into(), SqlValue::Text(b"Eve".to_vec())),
            ("data".into(), SqlValue::Null),
        ];
        let table = row_to_lua(&lua, row).expect("row table");
        assert_eq!(table.get::<i64>("id").expect("id"), 1);
        assert_eq!(table.get::<String>("name").expect("name"), "Eve");
        assert!(table.get::<Value>("data").expect("data").is_nil());
    }
}
