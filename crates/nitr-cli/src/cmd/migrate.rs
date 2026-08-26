// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr migrate`: apply pending SQL migrations, or report their state.

use nitr::Config;

#[cfg(feature = "db")]
use anyhow::Context as _;
#[cfg(not(feature = "db"))]
use anyhow::bail;

/// Applies pending migrations, or reports their state with `--status`.
///
/// Deliberately separate from `nitr run`: applying schema changes at boot
/// means a rolling deployment has two instances racing to change the same
/// schema, each believing it is alone.
#[cfg(not(feature = "db"))]
pub(crate) fn migrate(_cfg: &Config, _status_only: bool) -> anyhow::Result<()> {
    bail!(
        "this build has no database support: rebuild with the `db` Cargo \
         feature (or `all`) to use `nitr migrate`"
    )
}

#[cfg(feature = "db")]
pub(crate) fn migrate(cfg: &Config, status_only: bool) -> anyhow::Result<()> {
    let db = cfg
        .database
        .as_ref()
        .context("no database is configured; add a `[database]` section to nitr.toml")?;
    let dir = db.migrations().context(
        "no migrations directory found (looked for `migrations/`; set \
         [database] migrations_dir to point elsewhere)",
    )?;
    let conn = nitr::stdlib::db_open(&db.path, &db.pragmas())?;

    if status_only {
        let entries = nitr::stdlib::migrate::status(&conn, &dir)?;
        if entries.is_empty() {
            println!("no migrations in {}", dir.display());
            return Ok(());
        }
        for (migration, state) in &entries {
            let label = match state {
                nitr::stdlib::migrate::State::Applied => "applied",
                nitr::stdlib::migrate::State::Pending => "pending",
                nitr::stdlib::migrate::State::Modified => "MODIFIED SINCE APPLIED",
            };
            println!("  {:<10} {}", label, migration.name);
        }
        let count = |wanted: nitr::stdlib::migrate::State| {
            entries.iter().filter(|(_, state)| *state == wanted).count()
        };
        let modified = count(nitr::stdlib::migrate::State::Modified);
        println!(
            "{} applied, {} pending, {modified} modified",
            count(nitr::stdlib::migrate::State::Applied),
            count(nitr::stdlib::migrate::State::Pending),
        );
        if modified > 0 {
            // Not a warning to skim past: the database and the repository
            // disagree about what the schema is.
            println!(
                "a modified migration will not be re-run; restore the file or write a new one"
            );
        }
        return Ok(());
    }

    let applied = nitr::stdlib::migrate::run(&conn, &dir)?;
    if applied.is_empty() {
        println!("ok: the schema is up to date");
    } else {
        println!("ok: applied {} migration(s)", applied.len());
        for name in applied {
            println!("  {name}");
        }
    }
    Ok(())
}
