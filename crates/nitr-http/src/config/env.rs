// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Environment layering: the dotenv-style `[env] file` loaded at startup
//! and the `NITR_*` override pass applied on top of the parsed TOML.

use std::path::{Path, PathBuf};

use nitr_core::{Error, Result};

use super::{Config, DatabaseConfig, LogFormat};

impl Config {
    /// Loads the configured dotenv-style file into the process environment.
    ///
    /// Called between [`from_file()`](Self::from_file) and
    /// [`apply_env()`](Self::apply_env); `base` is the directory relative
    /// paths resolve against (where `nitr.toml` lives, or the working
    /// directory for a bundle — the env file is external state, like the
    /// database). Precedence: `NITR_ENV_FILE` names the file outright (it
    /// can only come from the real environment), else `[env] file` from
    /// the TOML, else an implicit `.env` under `base` that may be absent —
    /// only an *explicitly* named file must exist. Loading never
    /// overwrites variables already present in the process environment.
    pub fn load_env_file(&self, base: &Path) -> Result {
        let (path, explicit) = match env_var("NITR_ENV_FILE") {
            Some(v) => (PathBuf::from(v), true),
            None => match &self.env.file {
                Some(file) => (base.join(file), true),
                None => (base.join(".env"), false),
            },
        };
        if !explicit && !path.is_file() {
            return Ok(());
        }
        dotenvy::from_path(&path).map_err(|err| {
            Error::Config(format!(
                "cannot load the env file {}: {err}",
                path.display()
            ))
        })
    }

    /// Applies `NITR_*` environment variable overrides on top of the
    /// current values.
    ///
    /// Top-level keys keep their plain names: `NITR_LISTEN`,
    /// `NITR_HANDLER_SCRIPT`, `NITR_CONFIG_SCRIPT`, `NITR_WORKERS`,
    /// `NITR_MAX_STREAMS`, `NITR_DEV_MODE`, `NITR_PIDFILE`. A sectioned
    /// option is named `NITR_<SECTION>_<OPTION>`: `NITR_DATABASE_PATH`,
    /// `NITR_TEMPLATING_DIR`,
    /// `NITR_TESTING_DIR`, `NITR_ENV_FILE`, `NITR_LUA_MEMORY_LIMIT`,
    /// `NITR_LUA_EXEC_TIMEOUT_MS`, `NITR_LIMITS_POOL_WAIT_MS`,
    /// `NITR_SHUTDOWN_GRACE`, `NITR_COMPRESSION_ENABLED`,
    /// `NITR_TLS_ENABLED`, `NITR_TLS_CERT`, `NITR_TLS_KEY`,
    /// `NITR_TLS_MIN_VERSION`, `NITR_LOG_FORMAT`, `NITR_LOG_LEVEL`.
    pub fn apply_env(&mut self) -> Result {
        self.apply_env_with(&|name| std::env::var(name).ok())
    }

    /// [`apply_env()`](Self::apply_env) against an arbitrary lookup.
    ///
    /// The process environment is global mutable state, and Rust 2024
    /// made writing to it `unsafe` — which this workspace forbids
    /// outright. Taking the lookup as a parameter is what lets the tests
    /// exercise the layering (env beats TOML, an unparseable value names
    /// its variable) over a table instead of a shared, order-dependent
    /// process environment.
    pub(crate) fn apply_env_with(&mut self, lookup: &dyn Fn(&str) -> Option<String>) -> Result {
        // An empty value is treated as unset in exactly one place, so the
        // rule holds for the real environment and for a test table alike:
        // `NITR_WORKERS=` in a unit file means "I did not set this".
        let env_var = |name: &str| lookup(name).filter(|v| !v.is_empty());
        // Superseded names are refused with the rename spelled out:
        // silently ignoring them would turn a stale deployment manifest
        // into a config mystery.
        for (old, new) in [
            ("NITR_DATABASE", "NITR_DATABASE_PATH"),
            ("NITR_POOL_WAIT_MS", "NITR_LIMITS_POOL_WAIT_MS"),
            ("NITR_COMPRESSION", "NITR_COMPRESSION_ENABLED"),
            ("NITR_TEMPLATES_DIR", "NITR_TEMPLATING_DIR"),
        ] {
            if env_var(old).is_some() {
                return Err(Error::Config(format!(
                    "{old} was renamed: set {new} instead"
                )));
            }
        }
        if let Some(v) = env_var("NITR_LISTEN") {
            self.listen = parse_env("NITR_LISTEN", &v)?;
        }
        if let Some(v) = env_var("NITR_HANDLER_SCRIPT") {
            self.handler_script = PathBuf::from(v);
        }
        if let Some(v) = env_var("NITR_CONFIG_SCRIPT") {
            self.config_script = Some(PathBuf::from(v));
        }
        if let Some(v) = env_var("NITR_TEMPLATING_DIR") {
            self.templating.dir = Some(PathBuf::from(v));
        }
        if let Some(v) = env_var("NITR_DATABASE_PATH") {
            // Overrides only the path; the pragmas stay as configured.
            match &mut self.database {
                Some(db) => db.path = PathBuf::from(v),
                None => self.database = Some(DatabaseConfig::new(v)),
            }
        }
        if let Some(v) = env_var("NITR_TESTING_DIR") {
            self.testing.dir = PathBuf::from(v);
        }
        if let Some(v) = env_var("NITR_WORKERS") {
            self.workers = parse_env("NITR_WORKERS", &v)?;
        }
        if let Some(v) = env_var("NITR_MAX_STREAMS") {
            self.max_streams = Some(parse_env("NITR_MAX_STREAMS", &v)?);
        }
        if let Some(v) = env_var("NITR_DEV_MODE") {
            self.dev_mode = parse_env("NITR_DEV_MODE", &v)?;
        }
        if let Some(v) = env_var("NITR_LUA_MEMORY_LIMIT") {
            self.lua.memory_limit = parse_env("NITR_LUA_MEMORY_LIMIT", &v)?;
        }
        if let Some(v) = env_var("NITR_LUA_EXEC_TIMEOUT_MS") {
            self.lua.exec_timeout_ms = parse_env("NITR_LUA_EXEC_TIMEOUT_MS", &v)?;
        }
        if let Some(v) = env_var("NITR_LIMITS_POOL_WAIT_MS") {
            self.limits.pool_wait_ms = parse_env("NITR_LIMITS_POOL_WAIT_MS", &v)?;
        }
        if let Some(v) = env_var("NITR_SHUTDOWN_GRACE") {
            self.shutdown.grace = parse_env("NITR_SHUTDOWN_GRACE", &v)?;
        }
        if let Some(v) = env_var("NITR_COMPRESSION_ENABLED") {
            self.compression.enabled = parse_env("NITR_COMPRESSION_ENABLED", &v)?;
        }
        if let Some(v) = env_var("NITR_TLS_ENABLED") {
            self.tls.enabled = parse_env("NITR_TLS_ENABLED", &v)?;
        }
        if let Some(v) = env_var("NITR_TLS_CERT") {
            self.tls.cert = Some(PathBuf::from(v));
        }
        if let Some(v) = env_var("NITR_TLS_KEY") {
            self.tls.key = Some(PathBuf::from(v));
        }
        if let Some(v) = env_var("NITR_TLS_MIN_VERSION") {
            self.tls.min_version = Some(v);
        }
        if let Some(v) = env_var("NITR_LOG_FORMAT") {
            self.log.format = match v.as_str() {
                "text" => LogFormat::Text,
                "json" => LogFormat::Json,
                other => {
                    return Err(Error::Config(format!(
                        "invalid NITR_LOG_FORMAT `{other}`: expected \"text\" or \"json\""
                    )));
                }
            };
        }
        if let Some(v) = env_var("NITR_LOG_LEVEL") {
            self.log.level = Some(v);
        }
        if let Some(v) = env_var("NITR_PIDFILE") {
            self.pidfile = Some(PathBuf::from(v));
        }
        Ok(())
    }
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn parse_env<T: std::str::FromStr>(name: &str, value: &str) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map_err(|err| Error::Config(format!("invalid value for {name}: {err}")))
}
