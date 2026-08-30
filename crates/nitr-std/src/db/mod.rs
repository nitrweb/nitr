// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `conn` builtin: SQLite statements and transactions. Blocking
//! rusqlite calls run on the blocking thread pool; each Lua state owns its
//! own connection, and requests are serialized per state, so a transaction
//! never interleaves with other statements.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use mlua::{AnyUserData, Function, Lua, Table, UserData, UserDataMethods, Value};
use rusqlite::Connection;
use tracing::Instrument as _;

use crate::db::types::{Conn, SqlValue, params_from_table, row_to_lua};
use nitr_core::Result;

pub(crate) mod execute;
pub mod migrate;
pub mod pragmas;
pub(crate) mod query;
pub(crate) mod query_one;
pub(crate) mod query_row;
pub(crate) mod types;

use crate::config::SqlitePragmas;

/// Set while a transaction is open on the connection.
type TxFlag = Arc<AtomicBool>;

pub(crate) struct LuaDatabase {
    conn: Conn,
    in_transaction: TxFlag,
}

/// One (possibly nested) transaction scope handed to the Lua callback of
/// `db:transaction(fn)` / `tx:transaction(fn)`.
pub(crate) struct LuaTransaction {
    conn: Conn,
    /// Names nested savepoints uniquely within this scope.
    savepoints: AtomicUsize,
}

/// Runs a blocking database operation on the blocking thread pool so it
/// stalls a blocking-pool thread instead of an async worker. Only plain
/// `Send` data crosses the boundary — never a Lua handle.
async fn run_blocking<T, F>(
    conn: Conn,
    kind: &'static str,
    sql: String,
    params: Vec<SqlValue>,
    f: F,
) -> mlua::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Connection, &str, &[SqlValue]) -> Result<T, rusqlite::Error> + Send + 'static,
{
    // The `db_query` span: which statement kind ran, for how long, and a
    // correlator for *which* statement. Deliberately no SQL text and no
    // bind values — statements can embed secrets, and logs outlive them.
    // DEBUG so the per-request decomposition is opt-in via the level
    // filter.
    let stmt_tag = stmt_tag(&sql);
    let span = tracing::debug_span!(
        "db_query",
        kind,
        stmt = %stmt_tag,
        elapsed_ms = tracing::field::Empty
    );
    let started = std::time::Instant::now();
    let result = tokio::task::spawn_blocking(move || {
        let conn = conn.lock().map_err(|_| {
            mlua::Error::RuntimeError("failed to lock the database connection".into())
        })?;
        // The same policy as the span above, and for the same reason: this
        // message becomes an ordinary Lua error, so it reaches the
        // operator's log through the handler's error path *and* reaches
        // application Lua through `nitr.errinfo`, which can forward it
        // anywhere. Interpolating the statement here put a token or an
        // email address in a literal into both. The tag keeps repeated
        // failures groupable without carrying what the statement said.
        f(&conn, &sql, &params).map_err(|err| {
            mlua::Error::RuntimeError(format!("{kind} failed (stmt {stmt_tag}): {}", redact(&err)))
        })
    })
    .instrument(span.clone())
    .await
    .map_err(mlua::Error::external)?;
    span.record("elapsed_ms", started.elapsed().as_millis() as u64);
    result
}

/// Renders a rusqlite error without the statement it came from.
///
/// Dropping the interpolated `{sql}` from our own `format!` is not enough:
/// `rusqlite::Error::SqlInputError`'s own `Display` is
/// `"{msg} in {sql} at offset {n}"`, so every prepare-time failure that
/// carries an offset — a syntax error, an unknown column — puts the whole
/// statement back into the message, quoted literals included. That is the
/// original leak, re-entering through the error type rather than through
/// the caller. Everything else formats normally: no other variant embeds
/// the statement.
///
/// The offset survives because it is a position, not content, and it is
/// what makes the message actionable next to the statement tag.
///
/// One residual, stated rather than papered over: SQLite's own `msg` names
/// the *identifier* it could not resolve (`no such column: foo`). If an
/// application interpolated an untrusted value into the statement as a
/// bare identifier, that value appears here. Nothing this function can do
/// helps — the message would have to be discarded entirely, leaving
/// "query failed (stmt a1b2c3d4)" and nothing to act on — and a value
/// reaching SQL unquoted is a SQL-injection bug in the handler, which is a
/// different and larger problem than the one this redaction addresses.
/// Bind parameters (`?1`) are the fix for that, and they never reach the
/// statement text at all.
fn redact(err: &rusqlite::Error) -> String {
    match err {
        rusqlite::Error::SqlInputError { msg, offset, .. } => {
            format!("{msg} at offset {offset}")
        }
        other => other.to_string(),
    }
}

/// A short correlator for a statement, so repeated failures of the *same*
/// query can be grouped in a log without the log carrying the query.
///
/// Stable **within one process only**: `DefaultHasher`'s output is not
/// guaranteed across Rust releases, and nothing here should encourage
/// treating the tag as an identifier that outlives the run. It is chosen
/// over a digest to avoid coupling the database to the optional `crypto`
/// feature for what is a log-grouping aid, not a security primitive.
fn stmt_tag(sql: &str) -> String {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    sql.hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
}

/// Executes a control statement (`BEGIN`, `COMMIT`, `SAVEPOINT ...`).
async fn exec_batch(conn: Conn, sql: String) -> mlua::Result<()> {
    run_blocking(conn, "tx", sql, Vec::new(), |conn, sql, _| {
        conn.execute_batch(sql)
    })
    .await
}

/// Registers `execute`/`query`/`query_row`/`query_one` on a userdata type
/// that exposes a connection — shared between `db` and transactions.
///
/// `conn_of` may refuse: the outer `nitr.db` handle does so while a
/// transaction is open on the same connection.
fn add_stmt_methods<T, M>(methods: &mut M, conn_of: fn(&T) -> mlua::Result<Conn>)
where
    T: UserData + 'static,
    M: UserDataMethods<T>,
{
    // The connection is cloned out before each async block so no
    // userdata borrow lives across an await point.
    methods.add_async_method("execute", move |_, this, args: (String, Option<Table>)| {
        let conn = conn_of(&this);
        async move {
            let (sql, params) = args;
            let params = params_from_table(params.as_ref())?;
            let affected = run_blocking(conn?, "execute", sql, params, execute::call).await?;
            Ok(affected)
        }
    });

    methods.add_async_method(
        "query_row",
        move |lua, this, args: (String, Option<Table>)| {
            let conn = conn_of(&this);
            async move {
                let (sql, params) = args;
                let params = params_from_table(params.as_ref())?;
                let row = run_blocking(conn?, "query_row", sql, params, query_row::call).await?;
                row_to_lua(&lua, row)
            }
        },
    );

    methods.add_async_method(
        "query_one",
        move |lua, this, args: (String, Option<Table>)| {
            let conn = conn_of(&this);
            async move {
                let (sql, params) = args;
                let params = params_from_table(params.as_ref())?;
                let row = run_blocking(conn?, "query_one", sql, params, query_one::call).await?;
                row_to_lua(&lua, row)
            }
        },
    );

    methods.add_async_method("query", move |lua, this, args: (String, Option<Table>)| {
        let conn = conn_of(&this);
        async move {
            let (sql, params) = args;
            let params = params_from_table(params.as_ref())?;
            let rows = run_blocking(conn?, "query", sql, params, query::call).await?;
            let table = lua.create_table()?;
            for (i, row) in rows.into_iter().enumerate() {
                table.raw_set(i + 1, row_to_lua(&lua, row)?)?;
            }
            Ok(table)
        }
    });
}

/// Which statement an unsent query will run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryKind {
    Query,
    QueryRow,
    QueryOne,
    Execute,
}

impl QueryKind {
    fn parse(name: Option<&str>) -> mlua::Result<Self> {
        match name.unwrap_or("query") {
            "query" => Ok(QueryKind::Query),
            "query_row" => Ok(QueryKind::QueryRow),
            "query_one" => Ok(QueryKind::QueryOne),
            "execute" => Ok(QueryKind::Execute),
            other => Err(mlua::Error::RuntimeError(format!(
                "unknown query kind `{other}`: expected \"query\", \"query_row\", \
                 \"query_one\" or \"execute\""
            ))),
        }
    }
}

/// The work an unsent query represents, lifted out of the Lua handle so it
/// can be awaited without holding a userdata borrow.
pub struct PendingQuery {
    conn: Conn,
    kind: QueryKind,
    sql: String,
    params: Vec<SqlValue>,
}

impl PendingQuery {
    /// Runs the statement and converts the result to a Lua value.
    pub async fn run(self, lua: &Lua) -> mlua::Result<Value> {
        let PendingQuery {
            conn,
            kind,
            sql,
            params,
        } = self;
        match kind {
            QueryKind::Execute => {
                let affected = run_blocking(conn, "execute", sql, params, execute::call).await?;
                Ok(Value::Integer(affected as i64))
            }
            QueryKind::QueryRow => {
                let row = run_blocking(conn, "query_row", sql, params, query_row::call).await?;
                row_to_lua(lua, row).map(Value::Table)
            }
            QueryKind::QueryOne => {
                let row = run_blocking(conn, "query_one", sql, params, query_one::call).await?;
                row_to_lua(lua, row).map(Value::Table)
            }
            QueryKind::Query => {
                let rows = run_blocking(conn, "query", sql, params, query::call).await?;
                let table = lua.create_table()?;
                for (i, row) in rows.into_iter().enumerate() {
                    table.raw_set(i + 1, row_to_lua(lua, row)?)?;
                }
                Ok(Value::Table(table))
            }
        }
    }
}

/// An unsent query handle, the database counterpart of an unsent `fetch`.
///
/// Exists so `nitr.await_all` can run a query and an HTTP call at the same
/// time instead of one after the other. It carries no Lua state, which is
/// what keeps `await_all` a fixed set of Rust-side jobs rather than a
/// general concurrency primitive.
pub(crate) struct LuaPendingQuery(Mutex<Option<PendingQuery>>);

impl LuaPendingQuery {
    /// Takes the pending work; a handle can only be run once.
    pub(crate) fn take(&self) -> mlua::Result<PendingQuery> {
        self.0
            .lock()
            .map_err(|_| mlua::Error::RuntimeError("the query handle lock is poisoned".into()))?
            .take()
            .ok_or_else(|| {
                mlua::Error::RuntimeError(
                    "this query handle has already been awaited; build a new one".into(),
                )
            })
    }
}

impl UserData for LuaPendingQuery {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // Awaiting one handle on its own, for symmetry with fetch:send().
        methods.add_async_method("send", |lua, handle, ()| {
            let pending = handle.take();
            async move { pending?.run(&lua).await }
        });
    }
}

/// Registers `query_async` on a userdata type that exposes a connection.
fn add_async_query_method<T, M>(methods: &mut M, conn_of: fn(&T) -> mlua::Result<Conn>)
where
    T: UserData + 'static,
    M: UserDataMethods<T>,
{
    // db:query_async(sql, params?, kind?) -> unsent handle for await_all.
    methods.add_method(
        "query_async",
        move |_, this, (sql, params, kind): (String, Option<Table>, Option<String>)| {
            Ok(LuaPendingQuery(Mutex::new(Some(PendingQuery {
                conn: conn_of(this)?,
                kind: QueryKind::parse(kind.as_deref())?,
                sql,
                params: params_from_table(params.as_ref())?,
            }))))
        },
    );
}

/// Runs the transaction body between `begin` and `commit`/`rollback`,
/// passing a fresh [`LuaTransaction`] scope and re-raising body errors
/// after rolling back.
async fn run_transaction(
    lua: &Lua,
    conn: Conn,
    f: Function,
    begin: String,
    commit: String,
    rollback: String,
) -> mlua::Result<Value> {
    exec_batch(conn.clone(), begin).await?;
    let scope = lua.create_userdata(LuaTransaction {
        conn: conn.clone(),
        savepoints: AtomicUsize::new(0),
    })?;
    match f.call_async::<Value>(&scope).await {
        Ok(value) => {
            exec_batch(conn, commit).await?;
            Ok(value)
        }
        Err(err) => {
            if let Err(rollback_err) = exec_batch(conn, rollback).await {
                tracing::error!("transaction rollback failed: {rollback_err}");
            }
            Err(err)
        }
    }
}

impl UserData for LuaDatabase {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // Statements on the outer handle are refused while a transaction is
        // open. They would run on the same connection and therefore *inside*
        // the transaction, silently — so a write meant to be independent
        // would roll back with it, and a read would see uncommitted rows.
        // Phase 6 documented this as a footgun; documenting a trap is not
        // the same as removing it.
        add_stmt_methods(methods, |db: &LuaDatabase| {
            if db.in_transaction.load(Ordering::Acquire) {
                return Err(mlua::Error::RuntimeError(
                    "a transaction is open on this connection: use the `tx` handle passed \
                     to db:transaction(function(tx) ... end), not `nitr.db`. Statements on \
                     the outer handle would join the transaction without saying so."
                        .into(),
                ));
            }
            Ok(db.conn.clone())
        });
        add_async_query_method(methods, |db: &LuaDatabase| {
            if db.in_transaction.load(Ordering::Acquire) {
                return Err(mlua::Error::RuntimeError(
                    "a transaction is open on this connection: use the `tx` handle".into(),
                ));
            }
            Ok(db.conn.clone())
        });

        // db:transaction(function(tx) ... end): commits when the function
        // returns, rolls back (and re-raises) when it errors.
        methods.add_async_method("transaction", |lua, db, f: Function| {
            let conn = db.conn.clone();
            let flag = db.in_transaction.clone();
            async move {
                if flag.swap(true, Ordering::AcqRel) {
                    return Err(mlua::Error::RuntimeError(
                        "a transaction is already open on this connection; nest with \
                         tx:transaction(...) instead"
                            .into(),
                    ));
                }
                let result = run_transaction(
                    &lua,
                    conn,
                    f,
                    "BEGIN".into(),
                    "COMMIT".into(),
                    "ROLLBACK".into(),
                )
                .await;
                flag.store(false, Ordering::Release);
                result
            }
        });
    }
}

impl UserData for LuaTransaction {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        add_stmt_methods(methods, |tx: &LuaTransaction| Ok(tx.conn.clone()));
        add_async_query_method(methods, |tx: &LuaTransaction| Ok(tx.conn.clone()));

        // Nested transactions become savepoints: rolling back the inner
        // scope keeps the outer transaction alive.
        methods.add_async_method("transaction", |lua, tx, f: Function| {
            let conn = tx.conn.clone();
            let n = tx.savepoints.fetch_add(1, Ordering::Relaxed);
            async move {
                let name = format!("nitr_sp_{n}");
                run_transaction(
                    &lua,
                    conn,
                    f,
                    format!("SAVEPOINT {name}"),
                    format!("RELEASE {name}"),
                    format!("ROLLBACK TO {name}; RELEASE {name}"),
                )
                .await
            }
        });
    }
}

/// Opens this state's SQLite connection and builds the `nitr.db` handle.
pub(crate) fn create_database_fn(
    lua: &Lua,
    path: &std::path::Path,
    pragmas: &SqlitePragmas,
) -> Result<AnyUserData> {
    let conn = Arc::new(Mutex::new(pragmas::open(path, pragmas)?));
    let value = lua.create_userdata(LuaDatabase {
        conn,
        in_transaction: Arc::new(AtomicBool::new(false)),
    })?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_kinds_parse_strictly_with_a_query_default() {
        assert_eq!(QueryKind::parse(None).expect("default"), QueryKind::Query);
        for (name, kind) in [
            ("query", QueryKind::Query),
            ("query_row", QueryKind::QueryRow),
            ("query_one", QueryKind::QueryOne),
            ("execute", QueryKind::Execute),
        ] {
            assert_eq!(QueryKind::parse(Some(name)).expect(name), kind);
        }
        let err = QueryKind::parse(Some("insert")).expect_err("unknown kind");
        assert!(err.to_string().contains("insert"), "{err}");
    }
}
