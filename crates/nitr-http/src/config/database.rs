// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `[database]` section: the SQLite file plus connection pragmas.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// SQLite settings (`[database]` section).
///
/// Written as a table — `path` is the only required key; the pragma
/// defaults are what a server should have shipped with: WAL so readers do
/// not block the writer, a busy timeout so contention is a brief wait
/// rather than an error, and foreign keys actually enforced.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Path to the SQLite file.
    pub path: PathBuf,
    /// Journal mode. `"wal"` lets readers run alongside one writer;
    /// `"delete"` (SQLite's default) serializes everything. `"keep"` leaves
    /// whatever the file already uses, which is the safe choice for a
    /// database other tools also open.
    #[serde(default = "default_journal_mode")]
    pub journal_mode: String,
    /// Milliseconds a statement waits on a locked database before failing
    /// with `SQLITE_BUSY`.
    #[serde(default = "default_busy_timeout")]
    pub busy_timeout: u64,
    /// `synchronous` pragma. `"normal"` is the correct pairing with WAL:
    /// durable across an application crash, and only at risk from a power
    /// loss mid-checkpoint.
    #[serde(default = "default_synchronous")]
    pub synchronous: String,
    /// Enforce foreign-key constraints. SQLite leaves this off by default,
    /// which surprises everyone who wrote a `REFERENCES` clause.
    #[serde(default = "default_foreign_keys")]
    pub foreign_keys: bool,
    /// `cache_size` pragma, per connection. Negative values are KiB.
    #[serde(default = "default_cache_size")]
    pub cache_size: i64,
    /// Most rows a single `nitr.db:query` may return; a larger result is
    /// an error naming this setting. Rows are materialized in memory, so
    /// this is the ceiling on what one query can allocate.
    #[serde(default = "default_max_rows")]
    pub max_rows: usize,
    /// Directory holding `NNN_name.sql` migrations. Unset looks for
    /// `migrations/` in the working directory and ignores it when absent.
    #[serde(default)]
    pub migrations_dir: Option<PathBuf>,
}

fn default_journal_mode() -> String {
    "wal".into()
}
fn default_busy_timeout() -> u64 {
    5_000
}
fn default_synchronous() -> String {
    "normal".into()
}
fn default_foreign_keys() -> bool {
    true
}
fn default_cache_size() -> i64 {
    -2_000 // 2 MiB
}
fn default_max_rows() -> usize {
    10_000
}

impl DatabaseConfig {
    /// The defaults for a given path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            journal_mode: default_journal_mode(),
            busy_timeout: default_busy_timeout(),
            synchronous: default_synchronous(),
            foreign_keys: default_foreign_keys(),
            cache_size: default_cache_size(),
            max_rows: default_max_rows(),
            migrations_dir: None,
        }
    }

    /// The migrations directory to use, when one exists.
    pub fn migrations(&self) -> Option<PathBuf> {
        match &self.migrations_dir {
            Some(dir) => Some(dir.clone()),
            None => {
                let default = PathBuf::from("migrations");
                default.is_dir().then_some(default)
            }
        }
    }

    /// The pragma set handed to every connection.
    pub fn pragmas(&self) -> nitr_std::SqlitePragmas {
        nitr_std::SqlitePragmas {
            journal_mode: self.journal_mode.clone(),
            busy_timeout: self.busy_timeout,
            synchronous: self.synchronous.clone(),
            foreign_keys: self.foreign_keys,
            cache_size: self.cache_size,
            max_rows: self.max_rows,
        }
    }
}
