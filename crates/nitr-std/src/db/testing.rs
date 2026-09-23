// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Database fixtures for `nitr test` (`nitr.test.db`): a snapshot of the
//! migrated test database and its restore, truncation, and seeding.
//!
//! Why not the usual "wrap each test in a transaction and roll back":
//! every Lua state owns its own connection, so a transaction a test opens
//! holds SQLite's write lock against the handler's state until
//! `busy_timeout` expires, and a `tx` handle dies when its callback
//! returns. What works across connections is a copy: the runner takes a
//! snapshot once, after migrations (and the optional `[testing] seed`), and
//! [`restore`] copies it back through the runner's own connection. The
//! handlers' connections see the restored content on their next statement
//! — the backup bumps the file's change counter, and cached statements
//! re-prepare on `SQLITE_SCHEMA`.
//!
//! `VACUUM INTO` and `ATTACH` are denied by the authorizer every
//! connection carries, so SQLite's online backup API is the only snapshot
//! path. Everything here is blocking: callers run it under
//! `spawn_blocking`.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use mlua::{Table, Value};
use rusqlite::Connection;
use rusqlite::backup::{Backup, StepResult};

use super::types::SqlValue;
use crate::config::SqlitePragmas;
use nitr_core::{Error, Result};

/// Pages copied per backup step: small enough that a busy destination is
/// noticed between steps, large enough that a test database takes a few.
const PAGES_PER_STEP: i32 = 256;

/// How long to wait between steps while the destination is locked.
const BUSY_PAUSE: Duration = Duration::from_millis(5);

/// An in-memory copy of the test database, taken once per run.
pub struct Snapshot(Mutex<Connection>);

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot").finish_non_exhaustive()
    }
}

fn db_error(what: &str, path: &Path, err: impl std::fmt::Display) -> Error {
    Error::Script(format!("{what} {}: {err}", path.display()))
}

/// Copies every page from `from` into `to`, waiting on a locked
/// destination up to `wait` before naming the cause.
fn copy(from: &Connection, to: &mut Connection, wait: Duration, path: &Path) -> Result {
    let backup =
        Backup::new(from, to).map_err(|err| db_error("cannot back up the database", path, err))?;
    let deadline = Instant::now() + wait;
    loop {
        match backup
            .step(PAGES_PER_STEP)
            .map_err(|err| db_error("cannot copy the database", path, err))?
        {
            StepResult::Done => return Ok(()),
            StepResult::More => {}
            StepResult::Busy | StepResult::Locked => {
                if Instant::now() >= deadline {
                    return Err(Error::Script(format!(
                        "cannot restore the test database {}: another connection has held a \
                         lock on it for {} ms ([database] busy_timeout). A handler that timed \
                         out mid-transaction keeps its write lock until its state serves the \
                         next request; end transactions inside the handler's budget",
                        path.display(),
                        wait.as_millis()
                    )));
                }
                std::thread::sleep(BUSY_PAUSE);
            }
            // `StepResult` is non-exhaustive; anything new is an error
            // rather than a loop that might never end.
            other => {
                return Err(Error::Script(format!(
                    "cannot copy the database {}: unexpected backup state {other:?}",
                    path.display()
                )));
            }
        }
    }
}

/// Takes the snapshot [`restore`] copies back.
///
/// # Errors
///
/// The file cannot be opened or read.
pub fn snapshot(path: &Path, pragmas: &SqlitePragmas) -> Result<Snapshot> {
    let source = super::pragmas::open(path, pragmas)?;
    let mut memory = Connection::open_in_memory()
        .map_err(|err| db_error("cannot open a snapshot of", path, err))?;
    copy(
        &source,
        &mut memory,
        Duration::from_millis(pragmas.busy_timeout),
        path,
    )?;
    Ok(Snapshot(Mutex::new(memory)))
}

/// Restores the database at `path` to `snapshot`.
///
/// # Errors
///
/// A connection holds a lock past `[database] busy_timeout` (the message
/// names the likely cause), or the file cannot be written.
pub fn restore(snapshot: &Snapshot, path: &Path, pragmas: &SqlitePragmas) -> Result {
    let mut target = super::pragmas::open(path, pragmas)?;
    let memory = snapshot
        .0
        .lock()
        .map_err(|_| Error::Script("the database snapshot lock is poisoned".into()))?;
    copy(
        &memory,
        &mut target,
        Duration::from_millis(pragmas.busy_timeout),
        path,
    )
}

/// SQL identifier quoting: the name cannot end the quoted form early.
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The application's tables: everything but SQLite's own and the
/// migration bookkeeping, which a truncate must not forget. A virtual
/// table (FTS5, R-tree) counts; its shadow tables do not — emptied behind
/// the module's back they leave it corrupt ("invalid fts5 file format"),
/// while a `DELETE` on the virtual table empties them consistently.
fn user_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM pragma_table_list WHERE schema = 'main' \
         AND type IN ('table', 'virtual') \
         AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name <> ?1 ORDER BY name",
    )?;
    stmt.query_map([super::migrate::TABLE], |row| row.get(0))?
        .collect()
}

/// Empties the named tables — every application table when `tables` is
/// `None` — in one transaction with foreign-key checks deferred to the
/// commit, and resets their `AUTOINCREMENT` counters.
///
/// # Errors
///
/// A name that is not an application table, or a foreign key that still
/// points into an emptied table at commit (a partial truncate).
pub fn truncate(path: &Path, pragmas: &SqlitePragmas, tables: Option<&[String]>) -> Result {
    let mut conn = super::pragmas::open(path, pragmas)?;
    let fail = |err: rusqlite::Error| db_error("cannot truncate the database", path, err);
    let existing = user_tables(&conn).map_err(fail)?;
    let chosen: Vec<String> = match tables {
        None => existing,
        Some(names) => {
            for name in names {
                if !existing.contains(name) {
                    return Err(Error::Script(format!(
                        "t.db.truncate: `{name}` is not a table of the test database (tables: {})",
                        existing.join(", ")
                    )));
                }
            }
            names.to_vec()
        }
    };
    let tx = conn.transaction().map_err(fail)?;
    tx.execute_batch("PRAGMA defer_foreign_keys = ON")
        .map_err(fail)?;
    for table in &chosen {
        tx.execute_batch(&format!("DELETE FROM {}", quote(table)))
            .map_err(fail)?;
    }
    let has_sequence: bool = tx
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE name = 'sqlite_sequence')",
            [],
            |row| row.get(0),
        )
        .map_err(fail)?;
    if has_sequence {
        for table in &chosen {
            tx.execute("DELETE FROM sqlite_sequence WHERE name = ?1", [table])
                .map_err(fail)?;
        }
    }
    tx.commit().map_err(fail)
}

/// Runs a multi-statement SQL batch (`t.db.seed("fixtures/x.sql")`,
/// `[testing] seed`) in one transaction.
///
/// # Errors
///
/// Any statement fails; nothing of the batch is kept then.
pub fn seed_sql(path: &Path, pragmas: &SqlitePragmas, sql: &str) -> Result {
    let mut conn = super::pragmas::open(path, pragmas)?;
    let fail = |err: rusqlite::Error| db_error("cannot seed the database", path, err);
    let tx = conn.transaction().map_err(fail)?;
    tx.execute_batch(sql).map_err(fail)?;
    tx.commit().map_err(fail)
}

/// Rows to insert, read off a Lua table on the Lua thread so no Lua value
/// crosses into the blocking pool: `{ table = { { col = value }, ... } }`.
#[derive(Debug, Default)]
pub struct SeedRows(Vec<(String, Vec<SeedRow>)>);

/// One row to insert: `(column, value)` pairs, columns in name order.
type SeedRow = Vec<(String, SqlValue)>;

impl SeedRows {
    /// Reads `{ table = { row, ... }, ... }`. Tables are inserted in name
    /// order, rows in sequence order, columns by name.
    ///
    /// # Errors
    ///
    /// A shape other than the one above, or a value SQL has no type for.
    pub fn from_lua(spec: &Table) -> mlua::Result<Self> {
        let mut tables = Vec::new();
        for pair in spec.pairs::<String, Table>() {
            let (table, rows) = pair.map_err(|_| {
                mlua::Error::RuntimeError(
                    "t.db.seed takes { table = { { column = value }, ... } }".into(),
                )
            })?;
            let mut out = Vec::new();
            for row in rows.sequence_values::<Table>() {
                let row = row?;
                let mut cells = Vec::new();
                for cell in row.pairs::<String, Value>() {
                    let (column, value) = cell?;
                    let value = match value {
                        Value::Boolean(b) => SqlValue::Bool(b),
                        Value::Integer(i) => SqlValue::Int(i),
                        Value::Number(n) => SqlValue::Real(n),
                        Value::String(s) => SqlValue::Text(s.as_bytes().to_vec()),
                        other => {
                            return Err(mlua::Error::RuntimeError(format!(
                                "t.db.seed: `{table}.{column}` is a {}; seed values are \
                                 strings, numbers and booleans",
                                other.type_name()
                            )));
                        }
                    };
                    cells.push((column, value));
                }
                cells.sort_by(|a, b| a.0.cmp(&b.0));
                out.push(cells);
            }
            tables.push((table, out));
        }
        tables.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Self(tables))
    }
}

/// Inserts [`SeedRows`] with parameterized statements, in one transaction.
///
/// # Errors
///
/// Any insert fails (an unknown table or column, a constraint); nothing
/// is kept then.
pub fn seed_rows(path: &Path, pragmas: &SqlitePragmas, rows: &SeedRows) -> Result {
    let mut conn = super::pragmas::open(path, pragmas)?;
    let fail = |err: rusqlite::Error| db_error("cannot seed the database", path, err);
    let tx = conn.transaction().map_err(fail)?;
    for (table, table_rows) in &rows.0 {
        for row in table_rows {
            let sql = if row.is_empty() {
                format!("INSERT INTO {} DEFAULT VALUES", quote(table))
            } else {
                let columns: Vec<String> = row.iter().map(|(c, _)| quote(c)).collect();
                let slots: Vec<String> = (1..=row.len()).map(|i| format!("?{i}")).collect();
                format!(
                    "INSERT INTO {} ({}) VALUES ({})",
                    quote(table),
                    columns.join(", "),
                    slots.join(", ")
                )
            };
            let values: Vec<&SqlValue> = row.iter().map(|(_, v)| v).collect();
            tx.execute(&sql, rusqlite::params_from_iter(values))
                .map_err(fail)?;
        }
    }
    tx.commit().map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(name: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nitr-dbtest-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join(name)
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .expect("count")
    }

    fn schema(path: &Path) -> SqlitePragmas {
        let pragmas = SqlitePragmas::default();
        let conn = super::super::pragmas::open(path, &pragmas).expect("open");
        conn.execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL);
             CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL
                 REFERENCES users(id), text TEXT);
             CREATE TABLE _nitr_migrations (version TEXT);
             INSERT INTO _nitr_migrations VALUES ('001');
             INSERT INTO users (name) VALUES ('seeded');",
        )
        .expect("schema");
        pragmas
    }

    #[test]
    fn restore_returns_the_database_to_its_snapshot() {
        let path = temp_db("restore.db");
        let pragmas = schema(&path);
        let snap = snapshot(&path, &pragmas).expect("snapshot");

        // A connection opened before the restore, like a handler state's.
        let live = super::super::pragmas::open(&path, &pragmas).expect("open");
        live.execute_batch(
            "INSERT INTO users (name) VALUES ('a'), ('b'); DELETE FROM users WHERE name = 'seeded'",
        )
        .expect("write");
        assert_eq!(count(&live, "users"), 2);

        restore(&snap, &path, &pragmas).expect("restore");
        assert_eq!(
            count(&live, "users"),
            1,
            "an open connection sees the restore"
        );
        let name: String = live
            .query_row("SELECT name FROM users", [], |r| r.get(0))
            .expect("name");
        assert_eq!(name, "seeded");
        drop(live);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn a_held_write_lock_is_named_after_the_busy_timeout() {
        let path = temp_db("busy.db");
        let mut pragmas = schema(&path);
        pragmas.busy_timeout = 50;
        let snap = snapshot(&path, &pragmas).expect("snapshot");
        let holder = super::super::pragmas::open(&path, &pragmas).expect("open");
        holder
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO users (name) VALUES ('held')")
            .expect("hold the write lock");
        let started = Instant::now();
        let err = restore(&snap, &path, &pragmas).expect_err("locked");
        assert!(
            err.to_string().contains("busy_timeout") && err.to_string().contains("timed out"),
            "got: {err}"
        );
        assert!(started.elapsed() < Duration::from_secs(5), "bounded wait");
        holder.execute_batch("ROLLBACK").expect("release");
        restore(&snap, &path, &pragmas).expect("restores once released");
        drop(holder);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn truncate_empties_tables_across_foreign_keys_and_resets_sequences() {
        let path = temp_db("truncate.db");
        let pragmas = schema(&path);
        let conn = super::super::pragmas::open(&path, &pragmas).expect("open");
        conn.execute_batch("INSERT INTO notes (user_id, text) VALUES (1, 'n')")
            .expect("note");

        // Parent before child in name order would fail without the
        // deferred check; the whole set empties together.
        truncate(&path, &pragmas, None).expect("truncate all");
        assert_eq!(count(&conn, "users"), 0);
        assert_eq!(count(&conn, "notes"), 0);
        assert_eq!(count(&conn, "_nitr_migrations"), 1, "bookkeeping kept");
        conn.execute_batch("INSERT INTO users (name) VALUES ('fresh')")
            .expect("insert");
        let id: i64 = conn
            .query_row("SELECT id FROM users", [], |r| r.get(0))
            .expect("id");
        assert_eq!(id, 1, "AUTOINCREMENT restarted");

        // A full-text index: emptied through its virtual table, its shadow
        // tables stay consistent and it keeps answering queries.
        conn.execute_batch(
            "CREATE VIRTUAL TABLE notes_fts USING fts5(body);
             INSERT INTO notes_fts (body) VALUES ('hello world');",
        )
        .expect("fts5");
        truncate(&path, &pragmas, None).expect("truncate with fts5");
        let hits: i64 = conn
            .query_row(
                "SELECT count(*) FROM notes_fts WHERE notes_fts MATCH 'hello'",
                [],
                |r| r.get(0),
            )
            .expect("the index still answers");
        assert_eq!(hits, 0);
        conn.execute_batch("INSERT INTO notes_fts (body) VALUES ('hello again')")
            .expect("and still indexes");

        let err = truncate(&path, &pragmas, Some(&["nope".to_string()])).expect_err("unknown");
        assert!(
            err.to_string().contains("`nope` is not a table"),
            "got: {err}"
        );
        let err = truncate(&path, &pragmas, Some(&["_nitr_migrations".to_string()]))
            .expect_err("bookkeeping");
        assert!(err.to_string().contains("is not a table"), "got: {err}");
        drop(conn);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn seeds_insert_rows_and_batches_atomically() {
        let path = temp_db("seed.db");
        let pragmas = schema(&path);
        let lua = mlua::Lua::new();
        let spec: Table = lua
            .load(
                r#"return { users = { { name = "ann" }, { name = 'x"; DROP TABLE users; --' } } }"#,
            )
            .eval()
            .expect("spec");
        seed_rows(&path, &pragmas, &SeedRows::from_lua(&spec).expect("rows")).expect("seed");
        let conn = super::super::pragmas::open(&path, &pragmas).expect("open");
        assert_eq!(count(&conn, "users"), 3, "values are bound, never spliced");

        let err = seed_sql(
            &path,
            &pragmas,
            "INSERT INTO users (name) VALUES ('batch'); INSERT INTO missing VALUES (1);",
        )
        .expect_err("bad batch");
        assert!(err.to_string().contains("missing"), "got: {err}");
        assert_eq!(count(&conn, "users"), 3, "a failed batch keeps nothing");

        let bad: Table = lua
            .load(r#"return { users = { { name = {} } } }"#)
            .eval()
            .expect("spec");
        let err = SeedRows::from_lua(&bad).expect_err("table value");
        assert!(err.to_string().contains("users.name"), "got: {err}");
        drop(conn);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
}
