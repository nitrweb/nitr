// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Connection pragmas applied to every SQLite connection.
//!
//! These are the settings a server should have shipped with. WAL is the
//! important one: with one connection per pooled state and several states
//! writing, SQLite's default rollback journal serializes everything and
//! fails fast on contention. WAL lets readers run alongside the single
//! writer, and a busy timeout turns the remaining write contention from an
//! error into a brief wait.
//!
//! **Operational consequence of WAL**: the database becomes three files —
//! `app.db`, `app.db-wal` and `app.db-shm`. Copying only `app.db` while the
//! server runs no longer captures a consistent snapshot; use
//! `VACUUM INTO`, the `.backup` command, or stop the server first. SQLite
//! checkpoints the WAL back into the main file automatically, and on a
//! clean close the sidecars are removed.

use rusqlite::Connection;

use crate::config::SqlitePragmas;
use nitr_core::{Error, Result};

/// Journal modes SQLite accepts. Checked rather than interpolated blindly:
/// a pragma value cannot be bound as a parameter, so the only safe way to
/// build the statement is from a known-good set.
const JOURNAL_MODES: &[&str] = &["delete", "truncate", "persist", "memory", "wal", "off"];

/// `synchronous` levels SQLite accepts.
const SYNCHRONOUS_LEVELS: &[&str] = &["off", "normal", "full", "extra"];

impl SqlitePragmas {
    /// Applies the pragmas to a freshly opened connection.
    pub fn apply(&self, conn: &Connection, path: &std::path::Path) -> Result {
        let context = |what: &str, err: rusqlite::Error| {
            Error::Config(format!(
                "failed to set {what} on database {}: {err}",
                path.display()
            ))
        };

        conn.busy_timeout(std::time::Duration::from_millis(self.busy_timeout))
            .map_err(|err| context("the busy timeout", err))?;

        let journal = self.journal_mode.to_ascii_lowercase();
        if journal != "keep" {
            if !JOURNAL_MODES.contains(&journal.as_str()) {
                return Err(Error::Config(format!(
                    "unknown [database] journal_mode `{}`: expected one of {} or \"keep\"",
                    self.journal_mode,
                    JOURNAL_MODES.join(", ")
                )));
            }
            // `journal_mode` answers with the mode actually in force, which
            // can differ from what was asked for: an in-memory database
            // cannot use WAL, and a database another connection already
            // opened keeps its current mode.
            let applied: String = conn
                .pragma_update_and_check(None, "journal_mode", &journal, |row| row.get(0))
                .map_err(|err| context("the journal mode", err))?;
            if !applied.eq_ignore_ascii_case(&journal) {
                tracing::warn!(
                    "database {} runs in `{applied}` journal mode, not the configured `{journal}`",
                    path.display()
                );
            }
        }

        let synchronous = self.synchronous.to_ascii_lowercase();
        if !SYNCHRONOUS_LEVELS.contains(&synchronous.as_str()) {
            return Err(Error::Config(format!(
                "unknown [database] synchronous `{}`: expected one of {}",
                self.synchronous,
                SYNCHRONOUS_LEVELS.join(", ")
            )));
        }
        conn.pragma_update(None, "synchronous", &synchronous)
            .map_err(|err| context("the synchronous level", err))?;

        conn.pragma_update(None, "foreign_keys", self.foreign_keys)
            .map_err(|err| context("the foreign_keys pragma", err))?;
        conn.pragma_update(None, "cache_size", self.cache_size)
            .map_err(|err| context("the cache size", err))?;
        Ok(())
    }
}

/// Opens a SQLite connection with the pragmas applied.
pub fn open(path: &std::path::Path, pragmas: &SqlitePragmas) -> Result<Connection> {
    let conn = Connection::open(path).map_err(|err| {
        Error::Config(format!(
            "failed to open database at {}: {err}",
            path.display()
        ))
    })?;
    pragmas.apply(&conn, path)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(name: &str) -> std::path::PathBuf {
        // The counter keeps every call on its own directory, so no two
        // tests can ever open (or delete) the same database file.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nitr-pragma-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join(name)
    }

    #[test]
    fn the_defaults_land_on_the_connection() {
        let path = temp_db("defaults.db");
        let _ = std::fs::remove_file(&path);
        let conn = open(&path, &SqlitePragmas::default()).expect("open");

        let journal: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal_mode");
        assert_eq!(journal.to_ascii_lowercase(), "wal");

        let foreign_keys: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .expect("foreign_keys");
        assert_eq!(foreign_keys, 1, "foreign keys must be enforced");

        let synchronous: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .expect("synchronous");
        assert_eq!(synchronous, 1, "NORMAL");

        drop(conn);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn keep_leaves_the_existing_mode_alone() {
        let path = temp_db("keep.db");
        let _ = std::fs::remove_file(&path);
        // Create it in WAL, then reopen asking to keep whatever is there.
        drop(open(&path, &SqlitePragmas::default()).expect("open wal"));

        let conn = open(
            &path,
            &SqlitePragmas {
                journal_mode: "keep".into(),
                ..Default::default()
            },
        )
        .expect("reopen");
        let journal: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal_mode");
        assert_eq!(journal.to_ascii_lowercase(), "wal");

        drop(conn);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_bogus_pragma_value_is_refused_rather_than_interpolated() {
        let path = temp_db("bogus.db");
        let _ = std::fs::remove_file(&path);
        let err = open(
            &path,
            &SqlitePragmas {
                journal_mode: "wal; DROP TABLE users".into(),
                ..Default::default()
            },
        )
        .expect_err("must be refused");
        assert!(err.to_string().contains("journal_mode"), "{err}");
        let _ = std::fs::remove_file(&path);
    }
}
