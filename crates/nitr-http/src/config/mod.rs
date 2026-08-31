// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Server configuration (`nitr.toml`), defaults, and environment overrides.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use nitr_core::RuntimeOpts;
use nitr_core::{Error, Result};
use nitr_std::Builtins;

mod database;
mod env;
mod sections;
mod validate;

pub use database::DatabaseConfig;
pub use sections::*;

/// Server configuration, typically loaded from a `nitr.toml` file.
///
/// Precedence (strongest first): CLI flags / builder setters, `NITR_*`
/// environment variables (see [`apply_env()`](Self::apply_env)), the TOML
/// file, and finally the built-in defaults.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address the server binds to.
    pub listen: SocketAddr,
    /// Lua script executed once per request.
    pub handler_script: PathBuf,
    /// Lua script executed once at startup; its returned table is passed to
    /// the handler on every request.
    pub config_script: Option<PathBuf>,
    /// SQLite database for the `db` builtin (`[database]` section): the
    /// file path plus the connection pragmas.
    pub database: Option<DatabaseConfig>,
    /// Number of pooled Lua states (the maximum concurrently executing)
    /// handlers.
    pub workers: usize,
    /// Maximum concurrent streaming responses (each holds a pooled state
    /// for its whole lifetime). Defaults to `workers - 1` (at least 1) so
    /// idle streams cannot pin the entire pool.
    pub max_streams: Option<usize>,
    /// Development mode: hot-reload the handler script on change.
    pub dev_mode: bool,
    /// Standard library (`nitr.*`) selection (`[std]` section). When the
    /// feature list is omitted, only the minimal set is enabled; an
    /// explicit list is strict and fails at startup when a listed feature
    /// is missing its configuration (e.g. `template` without
    /// `[templating] dir`).
    pub std: StdConfig,
    /// Trust an inbound `X-Request-ID` header (well-formed, <= 64 ASCII
    /// chars) instead of generating a fresh id. Enable only behind a proxy
    /// that sets or sanitizes the header.
    pub trust_request_id: bool,
    /// Request-size and connection limits (`[limits]` section).
    pub limits: LimitsConfig,
    /// Per-client rate limiting (`[rate_limit]` section).
    pub rate_limit: RateLimitConfig,
    /// Outbound-request policy for the `fetch` builtin (`[fetch]` section).
    pub fetch: FetchConfig,
    /// Graceful-shutdown timing (`[shutdown]` section).
    pub shutdown: ShutdownConfig,
    /// Response compression (`[compression]` section).
    pub compression: CompressionConfig,
    /// Cross-origin resource sharing (`[cors]` section).
    pub cors: CorsConfig,
    /// Inbound TLS termination (`[tls]` section).
    pub tls: TlsConfig,
    /// The shared `nitr.cache` (`[cache]` section).
    pub cache: CacheConfig,
    /// Static file serving (`[static]` section).
    #[serde(rename = "static")]
    pub static_files: StaticConfig,
    /// Template rendering (`[templating]` section).
    pub templating: TemplatingConfig,
    /// Filesystem policy for multipart uploads (`[multipart]` section).
    pub multipart: MultipartConfig,
    /// Cookie defaults (`[cookies]` section).
    pub cookies: CookiesConfig,
    /// Test runner settings (`[testing]` section).
    pub testing: TestingConfig,
    /// Environment access for the `nitr.env` builtin (`[env]` section).
    pub env: EnvConfig,
    /// Lua runtime settings.
    pub lua: LuaConfig,
    /// Health and readiness endpoints (`[health]` section).
    pub health: HealthConfig,
    /// Log output (`[log]` section).
    pub log: LogConfig,
    /// File the server writes its process id to at startup (and removes at
    /// exit), so `nitr reload` and scripts can find the process without
    /// grepping the process table.
    pub pidfile: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 3000)),
            handler_script: PathBuf::from("scripts/handler.lua"),
            config_script: None,
            database: None,
            workers: std::thread::available_parallelism().map_or(1, |n| n.get()),
            max_streams: None,
            dev_mode: false,
            std: StdConfig::default(),
            trust_request_id: false,
            limits: LimitsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            fetch: FetchConfig::default(),
            shutdown: ShutdownConfig::default(),
            compression: CompressionConfig::default(),
            cors: CorsConfig::default(),
            tls: TlsConfig::default(),
            cache: CacheConfig::default(),
            static_files: StaticConfig::default(),
            templating: TemplatingConfig::default(),
            multipart: MultipartConfig::default(),
            cookies: CookiesConfig::default(),
            testing: TestingConfig::default(),
            env: EnvConfig::default(),
            lua: LuaConfig::default(),
            health: HealthConfig::default(),
            log: LogConfig::default(),
            pidfile: None,
        }
    }
}

impl Config {
    /// Loads the configuration from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path).map_err(|err| {
            Error::Config(format!(
                "failed to read the config file {}: {err}",
                path.display()
            ))
        })?;
        // Deserialization alone would report the removed spellings as mere
        // unknown/invalid fields; recognize them first so the error says
        // what to write instead.
        if let Ok(doc) = toml::from_str::<toml::Value>(&data) {
            check_moved_keys(&doc)?;
        }
        toml::from_str(&data).map_err(|err| {
            Error::Config(format!(
                "failed to parse the config file {}: {err}",
                path.display()
            ))
        })
    }

    /// The read policy handed to the `nitr.env` builtin.
    pub fn env_options(&self) -> nitr_std::EnvOptions {
        nitr_std::EnvOptions {
            allow: self.env.allow.clone(),
        }
    }

    /// Limits for the shared `nitr.cache`.
    pub fn cache_options(&self) -> nitr_std::CacheOptions {
        nitr_std::CacheOptions {
            max_entries: self.cache.max_entries.max(1),
            max_bytes: self.cache.max_bytes,
            default_ttl: self.cache.default_ttl,
        }
    }

    /// Resolves the configured `[std] features` list into [`Builtins`] flags.
    ///
    /// With no explicit list, the minimal default set
    /// ([`Builtins::minimal()`]: `json`, `http`, `log`, `time`,
    /// `validate`, `base64`, `path`, `url`) is enabled to keep the
    /// standard library lightweight. An explicit list is strict:
    /// unknown names or a listed feature without its required setting fail
    /// here.
    pub fn builtins(&self) -> Result<Builtins> {
        let Some(names) = &self.std.features else {
            return Ok(Builtins::minimal());
        };
        let mut builtins = Builtins::empty();
        for name in names {
            let builtin = Builtins::from_config_name(name)
                .ok_or_else(|| Error::Config(format!("unknown std feature `{name}`")))?;
            if builtin == Builtins::TEMPLATE && self.templating.dir.is_none() {
                return Err(Error::Config(
                    "std feature `template` is enabled but `[templating] dir` is not set".into(),
                ));
            }
            if builtin == Builtins::DATABASE && self.database.is_none() {
                return Err(Error::Config(
                    "std feature `db` is enabled but `database` is not set".into(),
                ));
            }
            builtins |= builtin;
        }
        Ok(builtins)
    }

    /// The directory `require` is pinned to: the one containing the
    /// handler script.
    ///
    /// A bare `handler_script = "app.lua"` has `parent()` of `Some("")`,
    /// which names nothing — the script is in the working directory, so
    /// that is what `require` gets. Every caller must derive the root
    /// *here* rather than re-deriving it: `validate_paths` refuses an
    /// upload directory inside this root, and a second copy of the
    /// expression that disagreed with this one is exactly how that
    /// refusal was once skipped for a bare filename while `require` was
    /// still pinned to the working directory.
    pub(crate) fn package_dir(&self) -> &Path {
        self.handler_script
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    /// Builds the [`RuntimeOpts`] derived from this configuration.
    pub fn runtime_opts(&self) -> Result<RuntimeOpts> {
        // Lua module loading (`require`) is confined to the directory
        // containing the handler script.
        let package_dir = self.package_dir().to_path_buf();
        Ok(RuntimeOpts {
            libs: self.lua.parse_stdlib()?,
            memory_limit: self.lua.memory_limit,
            dev_mode: self.dev_mode,
            exec_timeout: match self.lua.exec_timeout_ms {
                0 => None,
                ms => Some(std::time::Duration::from_millis(ms)),
            },
            package_dir: Some(package_dir),
        })
    }
}

/// Rejects superseded spellings of moved settings with an error that says
/// what to write instead — `deny_unknown_fields` alone would report them
/// as a bare unknown key or type mismatch.
fn check_moved_keys(doc: &toml::Value) -> Result {
    let Some(table) = doc.as_table() else {
        return Ok(());
    };
    if table.get("database").is_some_and(toml::Value::is_str) {
        return Err(Error::Config(
            "`database` is now a table: replace `database = \"app.db\"` with a \
             `[database]` section containing `path = \"app.db\"`"
                .into(),
        ));
    }
    if table.contains_key("tests_dir") {
        return Err(Error::Config(
            "`tests_dir` moved: replace it with a `[testing]` section \
             containing `dir = \"...\"`"
                .into(),
        ));
    }
    if table.contains_key("templates_dir") {
        return Err(Error::Config(
            "`templates_dir` moved: replace it with a `[templating]` section \
             containing `dir = \"...\"`"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
