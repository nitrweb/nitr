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

use crate::db::types::{Conn, Db, SqlValue, params_from_table, row_to_lua};
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
    /// Cleared when the scope's transaction ends — normally or because
    /// the handler's timeout dropped it mid-flight. A `tx` a script
    /// stashed and reused later must fail loudly rather than write into
    /// an abandoned transaction the next outer statement will roll back.
    alive: Arc<AtomicBool>,
}

/// The connection of a live scope; an ended one is refused.
fn tx_conn(tx: &LuaTransaction) -> mlua::Result<Conn> {
    if !tx.alive.load(Ordering::Acquire) {
        return Err(mlua::Error::RuntimeError(
            "this transaction has ended: a `tx` handle is only valid inside the \
             db:transaction(function(tx) ... end) body that received it"
                .into(),
        ));
    }
    Ok(tx.conn.clone())
}

/// Where a pending query came from, which decides the check it runs
/// before touching the connection: an outer handle must not run while a
/// transaction is open (it would rollback-or-join it), an inner one must
/// not outlive its scope.
#[derive(Clone)]
enum QueryOrigin {
    Outer(TxFlag),
    Inner(Arc<AtomicBool>),
}

impl QueryOrigin {
    fn check(&self) -> mlua::Result<()> {
        match self {
            QueryOrigin::Outer(flag) if flag.load(Ordering::Acquire) => {
                Err(mlua::Error::RuntimeError(
                    "a transaction is open on this connection: a `nitr.db:query_async` handle \
                     cannot run inside db:transaction(...); use `tx:query_async` instead"
                        .into(),
                ))
            }
            QueryOrigin::Inner(alive) if !alive.load(Ordering::Acquire) => {
                Err(mlua::Error::RuntimeError(
                    "this transaction has ended: the `tx:query_async` handle can no longer run"
                        .into(),
                ))
            }
            _ => Ok(()),
        }
    }

    fn is_outer(&self) -> bool {
        matches!(self, QueryOrigin::Outer(_))
    }
}

/// Runs a blocking database operation on the blocking thread pool so it
/// stalls a blocking-pool thread instead of an async worker. Only plain
/// `Send` data crosses the boundary — never a Lua handle.
///
/// `outer` says the statement comes from the `nitr.db` handle, i.e. from
/// outside any `db:transaction` scope. Such a statement must run in
/// autocommit mode; if the connection is still inside a transaction, that
/// transaction was abandoned — its `db:transaction` future was dropped
/// mid-flight by the handler's timeout — and it is rolled back first,
/// rather than silently joined. Statements from a `tx` handle pass
/// `false`: being inside a transaction is their whole point.
async fn run_blocking<T, F>(
    conn: Conn,
    kind: &'static str,
    sql: String,
    params: Vec<SqlValue>,
    outer: bool,
    f: F,
) -> mlua::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Connection, &str, &[SqlValue], usize) -> Result<T, rusqlite::Error> + Send + 'static,
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
        let db = conn.lock().map_err(|_| {
            mlua::Error::RuntimeError("failed to lock the database connection".into())
        })?;
        let conn = &db.conn;
        if outer && !conn.is_autocommit() {
            tracing::warn!(
                "rolling back a transaction a previous request left open on this connection \
                 (its handler was cut off mid-transaction)"
            );
            conn.execute_batch("ROLLBACK").map_err(|err| {
                mlua::Error::RuntimeError(format!(
                    "failed to roll back an abandoned transaction: {}",
                    redact(&err)
                ))
            })?;
        }
        // The same policy as the span above, and for the same reason: this
        // message becomes an ordinary Lua error, so it reaches the
        // operator's log through the handler's error path *and* reaches
        // application Lua through `nitr.errinfo`, which can forward it
        // anywhere. Interpolating the statement here put a token or an
        // email address in a literal into both. The tag keeps repeated
        // failures groupable without carrying what the statement said.
        f(conn, &sql, &params, db.max_rows).map_err(|err| {
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
async fn exec_batch(conn: Conn, sql: String, outer: bool) -> mlua::Result<()> {
    run_blocking(conn, "tx", sql, Vec::new(), outer, |conn, sql, _, _| {
        conn.execute_batch(sql)
    })
    .await
}

/// Registers `execute`/`query`/`query_row`/`query_one` on a userdata type
/// that exposes a connection — shared between `db` and transactions.
///
/// `conn_of` may refuse: the outer `nitr.db` handle does so while a
/// transaction is open on the same connection. `outer` is forwarded to
/// [`run_blocking`].
fn add_stmt_methods<T, M>(methods: &mut M, conn_of: fn(&T) -> mlua::Result<Conn>, outer: bool)
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
            let affected =
                run_blocking(conn?, "execute", sql, params, outer, execute::call).await?;
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
                let row =
                    run_blocking(conn?, "query_row", sql, params, outer, query_row::call).await?;
                match row {
                    Some(row) => row_to_lua(&lua, row).map(Value::Table),
                    None => Ok(Value::Nil),
                }
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
                let row =
                    run_blocking(conn?, "query_one", sql, params, outer, query_one::call).await?;
                row_to_lua(&lua, row)
            }
        },
    );

    methods.add_async_method("query", move |lua, this, args: (String, Option<Table>)| {
        let conn = conn_of(&this);
        async move {
            let (sql, params) = args;
            let params = params_from_table(params.as_ref())?;
            let rows = run_blocking(conn?, "query", sql, params, outer, query::call).await?;
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
    /// Which handle built it; checked when it runs, not only when it was
    /// built — a handle made before `db:transaction` and awaited inside
    /// it would otherwise roll the live transaction back.
    origin: QueryOrigin,
}

impl PendingQuery {
    /// Runs the statement and converts the result to a Lua value.
    pub async fn run(self, lua: &Lua) -> mlua::Result<Value> {
        let PendingQuery {
            conn,
            kind,
            sql,
            params,
            origin,
        } = self;
        origin.check()?;
        let outer = origin.is_outer();
        match kind {
            QueryKind::Execute => {
                let affected =
                    run_blocking(conn, "execute", sql, params, outer, execute::call).await?;
                Ok(Value::Integer(affected as i64))
            }
            QueryKind::QueryRow => {
                let row =
                    run_blocking(conn, "query_row", sql, params, outer, query_row::call).await?;
                match row {
                    Some(row) => row_to_lua(lua, row).map(Value::Table),
                    None => Ok(Value::Nil),
                }
            }
            QueryKind::QueryOne => {
                let row =
                    run_blocking(conn, "query_one", sql, params, outer, query_one::call).await?;
                row_to_lua(lua, row).map(Value::Table)
            }
            QueryKind::Query => {
                let rows = run_blocking(conn, "query", sql, params, outer, query::call).await?;
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
fn add_async_query_method<T, M>(
    methods: &mut M,
    origin_of: fn(&T) -> mlua::Result<(Conn, QueryOrigin)>,
) where
    T: UserData + 'static,
    M: UserDataMethods<T>,
{
    // db:query_async(sql, params?, kind?) -> unsent handle for await_all.
    methods.add_method(
        "query_async",
        move |_, this, (sql, params, kind): (String, Option<Table>, Option<String>)| {
            let (conn, origin) = origin_of(this)?;
            Ok(LuaPendingQuery(Mutex::new(Some(PendingQuery {
                conn,
                kind: QueryKind::parse(kind.as_deref())?,
                sql,
                params: params_from_table(params.as_ref())?,
                origin,
            }))))
        },
    );
}

/// Rolls back only when a transaction is actually open: after
/// `SQLITE_FULL`/`SQLITE_IOERR` SQLite may already have aborted it, and
/// a `ROLLBACK` then fails with "no transaction is active" — noise, not
/// news.
async fn rollback_if_open(conn: Conn, sql: String) -> mlua::Result<()> {
    run_blocking(conn, "tx", sql, Vec::new(), false, |conn, sql, _, _| {
        if conn.is_autocommit() {
            Ok(())
        } else {
            conn.execute_batch(sql)
        }
    })
    .await
}

/// Ends a scope when dropped — after the body, or when the future is
/// dropped mid-flight — so its `tx` handles and pending queries refuse
/// to run from then on. Plain Rust, no Lua API: it may run while the
/// coroutine is being collected.
struct ScopeEnd(Arc<AtomicBool>);

impl Drop for ScopeEnd {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Runs the transaction body between `begin` and `commit`/`rollback`,
/// passing a fresh [`LuaTransaction`] scope and re-raising body errors
/// after rolling back.
///
/// The scope is invalidated once the body returns, so a `tx` a script
/// stashed somewhere cannot run statements after its transaction ended
/// — which would silently bypass the outer handle's transaction guard.
///
/// A `COMMIT` that fails (`SQLITE_BUSY` past the busy timeout, a full
/// disk) leaves SQLite's transaction open; it is rolled back here so the
/// connection is in autocommit mode again when the error reaches Lua,
/// instead of every later statement quietly joining a doomed transaction.
async fn run_transaction(
    lua: &Lua,
    conn: Conn,
    f: Function,
    begin: String,
    commit: String,
    rollback: String,
    outer: bool,
) -> mlua::Result<Value> {
    exec_batch(conn.clone(), begin, outer).await?;
    let alive = Arc::new(AtomicBool::new(true));
    let _scope_end = ScopeEnd(alive.clone());
    let scope = lua.create_userdata(LuaTransaction {
        conn: conn.clone(),
        savepoints: AtomicUsize::new(0),
        alive,
    })?;
    let result = f.call_async::<Value>(&scope).await;
    // A savepoint's rollback must run even when the outer transaction is
    // open (it always is), so only the top-level one is conditional.
    let roll_back = |conn: Conn| async move {
        if outer {
            rollback_if_open(conn, rollback).await
        } else {
            exec_batch(conn, rollback, false).await
        }
    };
    match result {
        Ok(value) => {
            if let Err(commit_err) = exec_batch(conn.clone(), commit, false).await {
                if let Err(rollback_err) = roll_back(conn).await {
                    tracing::error!("rollback after a failed commit failed: {rollback_err}");
                }
                return Err(commit_err);
            }
            Ok(value)
        }
        Err(err) => {
            if let Err(rollback_err) = roll_back(conn).await {
                tracing::error!("transaction rollback failed: {rollback_err}");
            }
            Err(err)
        }
    }
}

/// Holds `in_transaction` for the lifetime of one `db:transaction` call.
///
/// The flag used to be cleared by a plain store after the body — which
/// never ran when the handler's timeout dropped the future mid-await. The
/// state then went back to the pool with the flag stuck, and every later
/// `nitr.db` call on it was refused for good, while SQLite's write lock
/// stayed held against every other state. A guard clears the flag on
/// every exit, the dropped-future one included; the transaction itself
/// is rolled back by the next outer statement (see [`run_blocking`]).
struct TxGuard(TxFlag);

impl Drop for TxGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
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
        add_stmt_methods(
            methods,
            |db: &LuaDatabase| {
                if db.in_transaction.load(Ordering::Acquire) {
                    return Err(mlua::Error::RuntimeError(
                        "a transaction is open on this connection: use the `tx` handle passed \
                         to db:transaction(function(tx) ... end), not `nitr.db`. Statements \
                         on the outer handle would join the transaction without saying so."
                            .into(),
                    ));
                }
                Ok(db.conn.clone())
            },
            true,
        );
        add_async_query_method(methods, |db: &LuaDatabase| {
            if db.in_transaction.load(Ordering::Acquire) {
                return Err(mlua::Error::RuntimeError(
                    "a transaction is open on this connection: use the `tx` handle".into(),
                ));
            }
            Ok((
                db.conn.clone(),
                QueryOrigin::Outer(db.in_transaction.clone()),
            ))
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
                let _guard = TxGuard(flag);
                run_transaction(
                    &lua,
                    conn,
                    f,
                    "BEGIN".into(),
                    "COMMIT".into(),
                    "ROLLBACK".into(),
                    true,
                )
                .await
            }
        });
    }
}

impl UserData for LuaTransaction {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        add_stmt_methods(methods, tx_conn, false);
        add_async_query_method(methods, |tx: &LuaTransaction| {
            Ok((tx_conn(tx)?, QueryOrigin::Inner(tx.alive.clone())))
        });

        // Nested transactions become savepoints: rolling back the inner
        // scope keeps the outer transaction alive.
        methods.add_async_method("transaction", |lua, tx, f: Function| {
            let conn = tx_conn(&tx);
            let n = tx.savepoints.fetch_add(1, Ordering::Relaxed);
            async move {
                let name = format!("nitr_sp_{n}");
                run_transaction(
                    &lua,
                    conn?,
                    f,
                    format!("SAVEPOINT {name}"),
                    format!("RELEASE {name}"),
                    format!("ROLLBACK TO {name}; RELEASE {name}"),
                    false,
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
    let conn = Arc::new(Mutex::new(Db {
        conn: pragmas::open(path, pragmas)?,
        max_rows: pragmas.max_rows,
    }));
    let value = lua.create_userdata(LuaDatabase {
        conn,
        in_transaction: Arc::new(AtomicBool::new(false)),
    })?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Lua state with `nitr.db` over a fresh temporary database and a
    /// `stall()` builtin that never returns, standing in for the slow
    /// upstream a handler awaits inside a transaction.
    async fn db_state(label: &str) -> (Lua, std::path::PathBuf) {
        db_state_with(label, SqlitePragmas::default()).await
    }

    async fn db_state_with(label: &str, pragmas: SqlitePragmas) -> (Lua, std::path::PathBuf) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("nitr-db-test-{label}-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("app.db");
        let lua = Lua::new();
        let db = create_database_fn(&lua, &path, &pragmas).expect("db");
        let nitr = lua.create_table().expect("table");
        nitr.set("db", db).expect("set");
        lua.globals().set("nitr", nitr).expect("set");
        let stall = lua
            .create_async_function(|_, ()| async {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                Ok(())
            })
            .expect("stall");
        lua.globals().set("stall", stall).expect("set");
        lua.load("nitr.db:execute('CREATE TABLE t (x INTEGER)')")
            .exec_async()
            .await
            .expect("setup statement");
        (lua, dir)
    }

    async fn count(lua: &Lua) -> i64 {
        lua.load("return nitr.db:query_row('SELECT COUNT(*) AS n FROM t').n")
            .eval_async()
            .await
            .expect("count")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn query_row_returns_nil_for_an_empty_result() {
        let (lua, dir) = db_state("qrow").await;
        let row: Value = lua
            .load("return nitr.db:query_row('SELECT x FROM t WHERE x = 42')")
            .eval_async()
            .await
            .expect("query_row");
        assert!(row.is_nil(), "no rows must be nil, got {row:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A transaction whose future is dropped mid-await (the handler's
    /// timeout) must not brick the connection: the flag clears, the next
    /// outer statement rolls the abandoned work back, and a new
    /// transaction can begin.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_abandoned_transaction_is_rolled_back_and_the_connection_recovers() {
        let (lua, dir) = db_state("abandon").await;
        let body = lua
            .load(
                "nitr.db:transaction(function(tx)
                     tx:execute('INSERT INTO t VALUES (1)')
                     stall()
                 end)",
            )
            .exec_async();
        let timed = tokio::time::timeout(std::time::Duration::from_millis(200), body).await;
        assert!(timed.is_err(), "the stall must outlive the timeout");
        // The future is gone; the state is what the pool would hand out.

        lua.load("nitr.db:execute('INSERT INTO t VALUES (2)')")
            .exec_async()
            .await
            .expect("an outer statement runs after the abandoned transaction");
        assert_eq!(count(&lua).await, 1, "the abandoned insert was rolled back");

        lua.load("nitr.db:transaction(function(tx) tx:execute('INSERT INTO t VALUES (3)') end)")
            .exec_async()
            .await
            .expect("a new transaction opens");
        assert_eq!(count(&lua).await, 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A `nitr.db:query_async` handle built before a transaction and
    /// awaited inside it is refused, not silently run in autocommit
    /// (which would roll the live transaction back underneath it).
    #[tokio::test(flavor = "multi_thread")]
    async fn an_outer_pending_query_is_refused_inside_a_transaction() {
        let (lua, dir) = db_state("pending").await;
        let (ok, err): (bool, String) = lua
            .load(
                "local h = nitr.db:query_async('SELECT 1')
                 local ok, err = pcall(function()
                     nitr.db:transaction(function(tx)
                         tx:execute('INSERT INTO t VALUES (1)')
                         h:send()
                     end)
                 end)
                 return ok, tostring(err)",
            )
            .eval_async()
            .await
            .expect("script");
        assert!(!ok, "the handle must be refused");
        assert!(err.contains("transaction is open"), "got: {err}");
        assert_eq!(
            count(&lua).await,
            0,
            "the body's insert rolled back with the error"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A `tx` stashed past its transaction is dead, and says so.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stashed_tx_handle_is_dead_after_its_transaction_ends() {
        let (lua, dir) = db_state("stash").await;
        let (ok, err): (bool, String) = lua
            .load(
                "local saved
                 nitr.db:transaction(function(tx) saved = tx end)
                 local ok, err = pcall(function() saved:execute('INSERT INTO t VALUES (1)') end)
                 return ok, tostring(err)",
            )
            .eval_async()
            .await
            .expect("script");
        assert!(!ok);
        assert!(err.contains("has ended"), "got: {err}");
        assert_eq!(count(&lua).await, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A result past `max_rows` is an error naming the setting, never a
    /// silent truncation; results at the cap still come back whole.
    #[tokio::test(flavor = "multi_thread")]
    async fn queries_past_max_rows_are_refused_not_truncated() {
        let pragmas = SqlitePragmas {
            max_rows: 2,
            ..SqlitePragmas::default()
        };
        let (lua, dir) = db_state_with("maxrows", pragmas).await;
        lua.load("nitr.db:execute('INSERT INTO t VALUES (1), (2), (3)')")
            .exec_async()
            .await
            .expect("seed");
        let (ok, err): (bool, String) = lua
            .load(
                "local ok, err = pcall(function() return nitr.db:query('SELECT x FROM t') end)
                 return ok, tostring(err)",
            )
            .eval_async()
            .await
            .expect("script");
        assert!(!ok, "three rows over a cap of two must fail");
        assert!(err.contains("max_rows"), "got: {err}");
        let n: i64 = lua
            .load("return #nitr.db:query('SELECT x FROM t LIMIT 2')")
            .eval_async()
            .await
            .expect("at the cap");
        assert_eq!(n, 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A `COMMIT` that fails leaves SQLite's transaction open; it must be
    /// rolled back so the connection is in autocommit mode again for the
    /// next statement. Induced the way it happens in production: in
    /// rollback-journal mode a reader holding a shared lock (an open
    /// cursor on another connection) blocks the exclusive lock `COMMIT`
    /// needs, and `busy_timeout` turns that into `SQLITE_BUSY`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_commit_rolls_back_and_the_connection_recovers() {
        let pragmas = SqlitePragmas {
            journal_mode: "delete".into(),
            busy_timeout: 50,
            ..SqlitePragmas::default()
        };
        let (lua, dir) = db_state_with("commitfail", pragmas).await;
        lua.load("nitr.db:execute('INSERT INTO t VALUES (1)')")
            .exec_async()
            .await
            .expect("seed");

        // The reader: a stepped, unfinished cursor keeps the shared lock.
        let reader = Connection::open(dir.join("app.db")).expect("reader");
        let mut stmt = reader.prepare("SELECT x FROM t").expect("prepare");
        let mut rows = stmt.query([]).expect("query");
        assert!(
            rows.next().expect("step").is_some(),
            "the cursor must be live"
        );

        let (ok, err): (bool, String) = lua
            .load(
                "local ok, err = pcall(function()
                     nitr.db:transaction(function(tx) tx:execute('INSERT INTO t VALUES (2)') end)
                 end)
                 return ok, tostring(err)",
            )
            .eval_async()
            .await
            .expect("script");
        assert!(!ok, "COMMIT must fail while the reader holds its lock");
        assert!(
            err.contains("locked") || err.contains("busy"),
            "the failure must be the lock, got: {err}"
        );
        drop(rows);
        drop(stmt);
        drop(reader);

        // Autocommit again: an outer statement runs without an abandoned
        // transaction in the way, and the failed insert is gone.
        lua.load("nitr.db:execute('INSERT INTO t VALUES (3)')")
            .exec_async()
            .await
            .expect("the connection is usable after the failed commit");
        let xs: Vec<i64> = lua
            .load(
                "local out = {}
                 for _, r in ipairs(nitr.db:query('SELECT x FROM t ORDER BY x')) do
                     out[#out + 1] = r.x
                 end
                 return out",
            )
            .eval_async()
            .await
            .expect("rows");
        assert_eq!(
            xs,
            vec![1, 3],
            "row 2 was rolled back with the failed commit"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

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
