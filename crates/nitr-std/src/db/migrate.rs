// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Schema migrations: plain SQL files applied in order and recorded.
//!
//! No DSL, no ORM, no down-migrations. A migration is a `.sql` file whose
//! name starts with a number; they run in numeric order, each inside a
//! transaction, and each is recorded in `_nitr_migrations` so it never runs
//! twice. Rolling a production schema back by script is a decision, not
//! something a framework should do on your behalf.
//!
//! The checksum stored alongside each applied migration is not paranoia:
//! editing a file that already ran is the single easiest way to make two
//! deployments disagree about what the schema is, and it is invisible
//! without one.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use nitr_core::{Error, Result};

/// Table recording what has been applied.
const TABLE: &str = "_nitr_migrations";

/// One migration file on disk.
#[derive(Debug, Clone)]
pub struct Migration {
    /// Leading number, which defines the order.
    pub version: i64,
    /// File name, used in messages and stored in the ledger.
    pub name: String,
    /// Full path of the migration file on disk.
    pub path: PathBuf,
    sql: String,
}

impl Migration {
    /// Hex SHA-256 of the file contents.
    fn checksum(&self) -> String {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(self.sql.as_bytes());
        digest.iter().fold(String::new(), |mut acc, byte| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{byte:02x}");
            acc
        })
    }
}

/// What `--status` reports about one migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Recorded in the ledger with a matching checksum.
    Applied,
    /// Not yet applied.
    Pending,
    /// Applied, but the file has changed since — the database and the
    /// repository no longer agree.
    Modified,
}

/// Reads the migrations directory, sorted by version.
///
/// A directory that does not exist is not an error: migrations are opt-in,
/// and an application without a schema should not have to say so.
pub fn discover(dir: &Path) -> Result<Vec<Migration>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(dir).map_err(|err| {
        Error::Config(format!(
            "cannot read the migrations directory {}: {err}",
            dir.display()
        ))
    })?;

    let mut found: Vec<Migration> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "sql") {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // `001_create_users.sql` → 1. The number is what orders the set, so
        // a file without one is a mistake worth reporting rather than
        // silently skipping.
        let digits: String = name.chars().take_while(char::is_ascii_digit).collect();
        let version = digits.parse::<i64>().map_err(|_| {
            Error::Config(format!(
                "migration `{name}` must start with a version number, e.g. `001_{name}`"
            ))
        })?;
        let sql = std::fs::read_to_string(&path).map_err(|err| {
            Error::Config(format!("cannot read migration {}: {err}", path.display()))
        })?;
        found.push(Migration {
            version,
            name,
            path,
            sql,
        });
    }
    found.sort_by(|a, b| a.version.cmp(&b.version).then_with(|| a.name.cmp(&b.name)));

    if let Some(dup) = found.windows(2).find(|w| w[0].version == w[1].version) {
        return Err(Error::Config(format!(
            "migrations `{}` and `{}` share version {}: the order between them is undefined",
            dup[0].name, dup[1].name, dup[0].version
        )));
    }
    Ok(found)
}

/// Creates the ledger table if it is missing.
fn ensure_table(conn: &Connection) -> Result {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {TABLE} (
             version    INTEGER PRIMARY KEY,
             name       TEXT NOT NULL,
             checksum   TEXT NOT NULL,
             applied_at TEXT NOT NULL DEFAULT (datetime('now'))
         )"
    ))
    .map_err(|err| Error::Config(format!("cannot create the {TABLE} table: {err}")))?;
    Ok(())
}

/// `version → checksum` for everything already applied.
fn applied(conn: &Connection) -> Result<std::collections::HashMap<i64, String>> {
    ensure_table(conn)?;
    let mut stmt = conn
        .prepare(&format!("SELECT version, checksum FROM {TABLE}"))
        .map_err(|err| Error::Config(format!("cannot read {TABLE}: {err}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|err| Error::Config(format!("cannot read {TABLE}: {err}")))?;
    let mut out = std::collections::HashMap::new();
    for row in rows {
        let (version, checksum) =
            row.map_err(|err| Error::Config(format!("cannot read {TABLE}: {err}")))?;
        out.insert(version, checksum);
    }
    Ok(out)
}

/// The state of every discovered migration.
pub fn status(conn: &Connection, dir: &Path) -> Result<Vec<(Migration, State)>> {
    let applied = applied(conn)?;
    Ok(discover(dir)?
        .into_iter()
        .map(|migration| {
            let state = match applied.get(&migration.version) {
                None => State::Pending,
                Some(recorded) if *recorded == migration.checksum() => State::Applied,
                Some(_) => State::Modified,
            };
            (migration, state)
        })
        .collect())
}

/// Names of the migrations that have not run yet.
///
/// A migration whose file changed after being applied counts as an error,
/// not as pending: re-running it is as likely to be wrong as skipping it,
/// so the only safe move is to stop and let a human decide.
pub fn pending(conn: &Connection, dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for (migration, state) in status(conn, dir)? {
        match state {
            State::Pending => names.push(migration.name),
            State::Modified => {
                return Err(Error::Config(format!(
                    "migration `{}` has changed since it was applied: the database and \
                     {} no longer agree. Restore the file, or write a new migration for \
                     the change.",
                    migration.name,
                    migration.path.display()
                )));
            }
            State::Applied => {}
        }
    }
    Ok(names)
}

/// Applies every pending migration in order, returning their names.
///
/// Each runs inside its own transaction, so a failure leaves the earlier
/// migrations applied and the failing one entirely undone — the database is
/// always at some version that actually ran, never half of one.
pub fn run(conn: &Connection, dir: &Path) -> Result<Vec<String>> {
    let applied = applied(conn)?;
    let mut done = Vec::new();

    for migration in discover(dir)? {
        match applied.get(&migration.version) {
            Some(recorded) if *recorded == migration.checksum() => continue,
            Some(_) => {
                return Err(Error::Config(format!(
                    "migration `{}` has changed since it was applied; refusing to continue",
                    migration.name
                )));
            }
            None => {}
        }

        // The file name, never the file's SQL — and through `redact`,
        // because `SqlInputError`'s own `Display` would otherwise put the
        // whole failing statement back into the message. A migration is
        // operator-authored rather than request-shaped, but it is exactly
        // the kind of file that carries a seeded credential in a literal,
        // and this error reaches the boot log.
        let fail = |err: rusqlite::Error| {
            Error::Config(format!(
                "migration `{}` failed: {}",
                migration.name,
                super::redact(&err)
            ))
        };
        conn.execute_batch("BEGIN").map_err(fail)?;
        let result = conn
            .execute_batch(&migration.sql)
            .and_then(|()| {
                conn.execute(
                    &format!("INSERT INTO {TABLE} (version, name, checksum) VALUES (?1, ?2, ?3)"),
                    rusqlite::params![migration.version, &migration.name, migration.checksum()],
                )
                .map(|_| ())
            })
            .and_then(|()| conn.execute_batch("COMMIT"));

        if let Err(err) = result {
            if let Err(rollback) = conn.execute_batch("ROLLBACK") {
                tracing::error!(
                    "failed to roll back migration `{}`: {rollback}",
                    migration.name
                );
            }
            return Err(fail(err));
        }
        tracing::info!("applied migration `{}`", migration.name);
        done.push(migration.name);
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        // The counter keeps every call on its own directory, so no two
        // tests can ever write into (or wipe) the same tree.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("nitr-migrate-{}-{id}", std::process::id()))
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn write(dir: &Path, name: &str, sql: &str) {
        std::fs::write(dir.join(name), sql).expect("write migration");
    }

    fn memory() -> Connection {
        Connection::open_in_memory().expect("in-memory db")
    }

    #[test]
    fn migrations_apply_in_order_and_only_once() {
        let dir = scratch("in-order");
        write(
            &dir,
            "002_add_email.sql",
            "ALTER TABLE users ADD COLUMN email TEXT;",
        );
        write(
            &dir,
            "001_create_users.sql",
            "CREATE TABLE users (id INTEGER PRIMARY KEY);",
        );

        let conn = memory();
        let applied = run(&conn, &dir).expect("first run");
        assert_eq!(applied, vec!["001_create_users.sql", "002_add_email.sql"]);

        // The column exists, so the two really ran in numeric order rather
        // than the order the directory happened to list them.
        conn.execute("INSERT INTO users (id, email) VALUES (1, 'a@b.c')", [])
            .expect("insert");

        // A second run is a no-op.
        assert!(run(&conn, &dir).expect("second run").is_empty());
        assert!(pending(&conn, &dir).expect("pending").is_empty());
    }

    #[test]
    fn a_failing_migration_leaves_nothing_half_applied() {
        let dir = scratch("failing");
        write(&dir, "001_ok.sql", "CREATE TABLE a (id INTEGER);");
        write(
            &dir,
            "002_broken.sql",
            "CREATE TABLE b (id INTEGER); THIS IS NOT SQL;",
        );

        let conn = memory();
        let err = run(&conn, &dir).expect_err("must fail");
        assert!(err.to_string().contains("002_broken.sql"), "{err}");

        // The first migration stands; nothing from the second does.
        conn.execute("INSERT INTO a (id) VALUES (1)", [])
            .expect("table a exists");
        assert!(
            conn.execute("INSERT INTO b (id) VALUES (1)", []).is_err(),
            "table b must not exist"
        );
        // And it is still pending, so a fixed file will run.
        assert_eq!(
            pending(&conn, &dir).expect("pending"),
            vec!["002_broken.sql"]
        );
    }

    #[test]
    fn editing_an_applied_migration_is_an_error() {
        let dir = scratch("edited");
        write(&dir, "001_users.sql", "CREATE TABLE users (id INTEGER);");
        let conn = memory();
        run(&conn, &dir).expect("apply");

        write(
            &dir,
            "001_users.sql",
            "CREATE TABLE users (id INTEGER, name TEXT);",
        );
        assert_eq!(status(&conn, &dir).expect("status")[0].1, State::Modified);
        let err = pending(&conn, &dir).expect_err("must refuse");
        assert!(err.to_string().contains("has changed"), "{err}");
    }

    #[test]
    fn a_file_without_a_version_is_reported() {
        let dir = scratch("unversioned");
        write(&dir, "create_users.sql", "CREATE TABLE users (id INTEGER);");
        let err = discover(&dir).expect_err("must fail");
        assert!(err.to_string().contains("version number"), "{err}");
    }

    #[test]
    fn duplicate_versions_are_reported() {
        let dir = scratch("duplicate");
        write(&dir, "001_a.sql", "CREATE TABLE a (id INTEGER);");
        write(&dir, "001_b.sql", "CREATE TABLE b (id INTEGER);");
        let err = discover(&dir).expect_err("must fail");
        assert!(err.to_string().contains("share version"), "{err}");
    }

    #[test]
    fn a_missing_directory_is_not_an_error() {
        let missing = std::env::temp_dir().join("nitr-migrate-does-not-exist");
        assert!(discover(&missing).expect("no error").is_empty());
    }
}
