// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! A private database for the commands that need the application's schema
//! but must never touch its data: `nitr test` and `nitr openapi`.

use std::path::{Path, PathBuf};

/// A database file in the temporary directory, removed with its WAL
/// sidecars when dropped.
pub(crate) struct ScratchDb(PathBuf);

impl ScratchDb {
    pub(crate) fn new(label: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "nitr-{label}-{}-{}.db",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        )))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDb {
    fn drop(&mut self) {
        remove_database_files(&self.0);
    }
}

/// Removes a SQLite file and its WAL sidecars; a missing file is fine.
pub(crate) fn remove_database_files(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}

/// Gives the configured database the migrations the live one would have,
/// so it holds the schema and not an empty file, and the server's
/// pending-migration check passes.
#[cfg(feature = "db")]
pub(crate) async fn migrate(cfg: &nitr::Config) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let Some(db) = &cfg.database else {
        return Ok(());
    };
    let Some(dir) = db.migrations().filter(|dir| dir.is_dir()) else {
        return Ok(());
    };
    let path = db.path.clone();
    let pragmas = db.pragmas();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let conn = nitr::stdlib::db_open(&path, &pragmas)?;
        nitr::stdlib::migrate::run(&conn, &dir)
            .with_context(|| format!("cannot migrate the scratch database {}", path.display()))?;
        Ok(())
    })
    .await
    .context("the scratch database migration task failed")?
}
