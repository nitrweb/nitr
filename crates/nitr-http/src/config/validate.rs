// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Startup validation (`validate`/`validate_paths`), bundle path
//! re-anchoring (`rebase`), and the effective-config rendering.

use std::path::{Path, PathBuf};

use nitr_core::{Error, Result};

use super::Config;

impl Config {
    /// Rejects configurations that parse but cannot be honored.
    ///
    /// Called once at startup so a contradiction is a loud failure rather
    /// than a subtle runtime surprise, a browser silently ignoring a
    /// header combination is much harder to debug than a refused boot.
    pub(crate) fn validate(&self) -> Result {
        let any_origin = self
            .cors
            .origins
            .as_ref()
            .is_some_and(|o| o.iter().any(|o| o == "*"));
        if any_origin && self.cors.credentials {
            return Err(Error::Config(
                "[cors] origins = [\"*\"] cannot be combined with credentials = true: \
                 browsers reject `Access-Control-Allow-Origin: *` on a credentialed \
                 request. List the allowed origins explicitly."
                    .into(),
            ));
        }
        for name in &self.compression.algorithms {
            if !matches!(name.as_str(), "br" | "gzip") {
                return Err(Error::Config(format!(
                    "unknown [compression] algorithm `{name}`: expected \"br\" or \"gzip\""
                )));
            }
        }
        if let Some(max_streams) = self.max_streams
            && max_streams > self.workers.max(1)
        {
            return Err(Error::Config(format!(
                "max_streams = {max_streams} exceeds workers = {}: every streaming \
                 response holds a pooled Lua state, so the extra slots could never \
                 be used",
                self.workers.max(1)
            )));
        }
        // Waiting for a state longer than a handler is allowed to run means
        // the queue can only ever grow: work is admitted slower than it can
        // possibly be retired.
        if self.limits.pool_wait_ms > self.lua.exec_timeout_ms
            && self.limits.pool_wait_ms != 0
            && self.lua.exec_timeout_ms != 0
        {
            return Err(Error::Config(format!(
                "[limits] pool_wait_ms = {} exceeds [lua] exec_timeout_ms = {}: a \
                 request would wait for a state longer than any handler may run",
                self.limits.pool_wait_ms, self.lua.exec_timeout_ms
            )));
        }
        // A warning, not an error: the stall bound still protects handlers
        // that read the body incrementally past the compute budget — but
        // for the common buffered read (`req:text()`, `req:form()`) the
        // execution timeout fires first, turning what should be a clear
        // 408 into a timeout-kind 500 that blames the handler.
        if self.limits.body_read_ms > self.lua.exec_timeout_ms
            && self.limits.body_read_ms != 0
            && self.lua.exec_timeout_ms != 0
        {
            tracing::warn!(
                "[limits] body_read_ms = {} exceeds [lua] exec_timeout_ms = {}: a stalled \
                 buffered body read will surface as a handler timeout instead of a 408",
                self.limits.body_read_ms,
                self.lua.exec_timeout_ms
            );
        }
        if self.health.enabled {
            for (name, path) in [
                ("liveness", &self.health.liveness),
                ("readiness", &self.health.readiness),
            ] {
                if !path.starts_with('/') {
                    return Err(Error::Config(format!(
                        "[health] {name} = `{path}` must start with `/`"
                    )));
                }
            }
            if self.health.liveness == self.health.readiness {
                return Err(Error::Config(
                    "[health] liveness and readiness must be different paths: they \
                     answer different questions (see the [health] docs)"
                        .into(),
                ));
            }
        }
        self.validate_paths()
    }

    /// Rejects paths that cannot work before any of them is opened, so a
    /// typo'd path is a startup error naming the setting, not a confusing
    /// failure minutes later.
    fn validate_paths(&self) -> Result {
        let checks: [(&str, Option<&PathBuf>, bool); 4] = [
            ("handler_script", Some(&self.handler_script), false),
            ("config_script", self.config_script.as_ref(), false),
            ("[templating] dir", self.templating.dir.as_ref(), true),
            ("[static] dir", self.static_files.dir.as_ref(), true),
        ];
        for (name, path, want_dir) in checks {
            let Some(path) = path else { continue };
            if !path.exists() {
                return Err(Error::Config(format!(
                    "{name} points at {}, which does not exist",
                    path.display()
                )));
            }
            if want_dir != path.is_dir() {
                let (wanted, got) = if want_dir {
                    ("a directory", "a file")
                } else {
                    ("a file", "a directory")
                };
                return Err(Error::Config(format!(
                    "{name} must be {wanted}, but {} is {got}",
                    path.display()
                )));
            }
        }
        // Existence is not readability: a mis-owned static root would
        // otherwise answer every request 404 with nothing explaining why.
        // Probing with read_dir surfaces PermissionDenied at startup.
        if let Some(dir) = &self.static_files.dir
            && let Err(err) = std::fs::read_dir(dir)
        {
            return Err(Error::Config(format!(
                "[static] dir {} exists but cannot be read: {err}",
                dir.display()
            )));
        }
        // The database file itself may not exist yet (SQLite creates it),
        // but its parent directory must, SQLite will not create that.
        if let Some(db) = &self.database
            && let Some(parent) = db.path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.is_dir()
        {
            return Err(Error::Config(format!(
                "the database directory {} does not exist (SQLite creates the \
                 file, not its directory)",
                parent.display()
            )));
        }
        Ok(())
    }

    /// Re-anchors the application's relative paths under `root`.
    ///
    /// Used when running from a `nitr build` bundle: the scripts, templates
    /// and static files live in the extraction directory, while the
    /// database path is deliberately left alone, it is mutable state and
    /// stays external to the artifact, resolving against the working
    /// directory as usual.
    pub fn rebase(&mut self, root: &Path) {
        let anchor = |path: &mut PathBuf| {
            if path.is_relative() {
                *path = root.join(&path);
            }
        };
        anchor(&mut self.handler_script);
        if let Some(path) = &mut self.config_script {
            anchor(path);
        }
        if let Some(path) = &mut self.templating.dir {
            anchor(path);
        }
        if let Some(path) = &mut self.static_files.dir {
            anchor(path);
        }
        if let Some(db) = &mut self.database
            && let Some(dir) = &mut db.migrations_dir
        {
            anchor(dir);
        }
        anchor(&mut self.testing.dir);
    }

    /// The effective configuration after file, environment, and flag
    /// layering, rendered as TOML, the answer to "which value actually
    /// won?".
    pub fn effective_toml(&self) -> Result<String> {
        // Route through JSON first to drop the `None`s: TOML has no null,
        // and an absent key is exactly what an unset option means.
        let json = serde_json::to_value(self)
            .map_err(|err| Error::Config(format!("cannot serialize the configuration: {err}")))?;
        let json = strip_nulls(json);
        toml::to_string_pretty(&json)
            .map_err(|err| Error::Config(format!("cannot render the configuration: {err}")))
    }
}

/// Removes `null`s (and the entries they were) from a JSON tree, so the
/// result can render as TOML, which has no null.
fn strip_nulls(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, strip_nulls(v)))
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(strip_nulls).collect())
        }
        other => other,
    }
}
