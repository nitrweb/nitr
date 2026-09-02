// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use mlua::{ExternalResult, Lua, Table, Value};
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
pub(crate) type SqlRow = Vec<(String, SqlValue)>;

/// Converts a result row into a Lua table keyed by column name.
pub(crate) fn row_to_lua(lua: &Lua, row: SqlRow) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    for (column, value) in row {
        table.set(column, value.into_lua(lua)?)?;
    }
    Ok(table)
}

/// Extracts SQL parameters from an optional Lua table (array part order).
pub(crate) fn params_from_table(params: Option<&Table>) -> mlua::Result<Vec<SqlValue>> {
    let mut out = vec![];
    let Some(table) = params else {
        return Ok(out);
    };
    for pair in table.pairs::<Value, Value>() {
        let (_, v) = pair.into_lua_err()?;
        match v {
            Value::Nil => out.push(SqlValue::Null),
            Value::Boolean(b) => out.push(SqlValue::Bool(b)),
            Value::Integer(i) => out.push(SqlValue::Int(i)),
            Value::Number(n) => out.push(SqlValue::Real(n)),
            Value::String(s) => out.push(SqlValue::Text(s.as_bytes().to_vec())),
            other => {
                return Err(mlua::Error::RuntimeError(format!(
                    "unsupported SQL parameter type `{}`",
                    other.type_name()
                )));
            }
        }
    }
    Ok(out)
}

/// Reads all columns of the current row as plain data.
pub(crate) fn read_row(
    columns: &[String],
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
