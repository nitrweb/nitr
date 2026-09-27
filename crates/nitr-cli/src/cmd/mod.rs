// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! One module per `nitr` subcommand implementation; `main.rs` keeps only
//! argument parsing, configuration loading, and dispatch.

pub(crate) mod check;
pub(crate) mod hash_password;
pub(crate) mod migrate;
pub(crate) mod openapi;
pub(crate) mod scratch_db;
pub(crate) mod test;

/// A `[static] dir` that is not there yet (the front-end build runs later,
/// in CI) is set aside with a warning, so `check` and `test` can prove the
/// rest; `nitr run` still refuses it.
pub(crate) fn skip_missing_static_dir(cfg: &mut nitr::Config) {
    cfg.static_dirs_optional = true;
    if let Some(dir) = cfg.static_files.dir.take_if(|dir| !dir.is_dir()) {
        tracing::warn!(
            "[static] dir {} does not exist yet: static files are skipped by this command, \
             and `nitr run` refuses the directory",
            dir.display()
        );
    }
}
