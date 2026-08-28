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
    /// The shared `nitr.cache` (`[cache]` section).
    pub cache: CacheConfig,
    /// Static file serving (`[static]` section).
    #[serde(rename = "static")]
    pub static_files: StaticConfig,
    /// Template rendering (`[templating]` section).
    pub templating: TemplatingConfig,
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
            cache: CacheConfig::default(),
            static_files: StaticConfig::default(),
            templating: TemplatingConfig::default(),
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

    /// Builds the [`RuntimeOpts`] derived from this configuration.
    pub fn runtime_opts(&self) -> Result<RuntimeOpts> {
        // Lua module loading (`require`) is confined to the directory
        // containing the handler script.
        let package_dir = self
            .handler_script
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
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
mod tests {
    use super::*;
    use nitr_std::Builtins;

    fn write_temp_config(name: &str, content: &str) -> PathBuf {
        // `fs::write` truncates before writing, so a path two tests share is
        // a race; the counter keeps every call on its own file.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nitr-test-{}-{id}-{name}", std::process::id()));
        std::fs::write(&path, content).expect("write temp config");
        path
    }

    /// A config whose paths exist, so `validate()` reaches the check under
    /// test instead of failing on a missing default handler script.
    fn valid_base() -> Config {
        let handler = write_temp_config("handler.lua", "-- test handler");
        Config {
            handler_script: handler,
            ..Config::default()
        }
    }

    #[test]
    fn contradictions_are_startup_errors() {
        let ok = valid_base();
        ok.validate().expect("a sane config validates");

        let mut cfg = valid_base();
        cfg.workers = 2;
        cfg.max_streams = Some(5);
        let err = cfg.validate().expect_err("max_streams > workers");
        assert!(err.to_string().contains("max_streams"), "got: {err}");

        let mut cfg = valid_base();
        cfg.limits.pool_wait_ms = 60_000;
        cfg.lua.exec_timeout_ms = 5_000;
        let err = cfg.validate().expect_err("pool_wait > exec budget");
        assert!(err.to_string().contains("pool_wait_ms"), "got: {err}");

        let mut cfg = valid_base();
        cfg.health.readiness = cfg.health.liveness.clone();
        let err = cfg.validate().expect_err("identical probe paths");
        assert!(err.to_string().contains("liveness"), "got: {err}");

        let mut cfg = valid_base();
        cfg.health.liveness = "healthz".into();
        let err = cfg.validate().expect_err("path without slash");
        assert!(err.to_string().contains("must start with"), "got: {err}");

        // Disabled health skips its checks entirely.
        let mut cfg = valid_base();
        cfg.health.enabled = false;
        cfg.health.liveness = "not-a-path".into();
        cfg.validate().expect("disabled health is not validated");
    }

    /// An unknown `[compression]` algorithm is a startup refusal naming
    /// the offending value, not a silently un-negotiable encoding.
    #[test]
    fn unknown_compression_algorithms_are_startup_errors() {
        let mut cfg = valid_base();
        cfg.compression.algorithms = vec!["br".into(), "zstd".into()];
        let err = cfg.validate().expect_err("unknown algorithm");
        let msg = err.to_string();
        assert!(msg.contains("zstd"), "got: {msg}");
        assert!(msg.contains("[compression]"), "got: {msg}");

        // The two supported names still validate, in either order.
        let mut cfg = valid_base();
        cfg.compression.algorithms = vec!["gzip".into(), "br".into()];
        cfg.validate().expect("br and gzip are the supported set");
    }

    /// `[lua] stdlib` is strict: a misspelled library name refuses to
    /// start, naming the string, instead of silently loading nothing.
    #[test]
    fn unknown_lua_stdlib_names_are_startup_errors() {
        let mut lua = LuaConfig::default();
        lua.stdlib.push("iio".into());
        let err = lua.parse_stdlib().expect_err("unknown stdlib name");
        assert!(err.to_string().contains("`iio`"), "got: {err}");

        // Every documented name parses, including the dangerous opt-ins.
        let all = LuaConfig {
            stdlib: [
                "coroutine",
                "table",
                "io",
                "os",
                "string",
                "utf8",
                "math",
                "package",
                "debug",
            ]
            .map(String::from)
            .to_vec(),
            ..LuaConfig::default()
        };
        let libs = all.parse_stdlib().expect("all known names");
        assert!(libs.contains(mlua::StdLib::IO));
        assert!(libs.contains(mlua::StdLib::DEBUG));
    }

    #[test]
    fn missing_paths_are_named_at_startup() {
        let mut cfg = valid_base();
        cfg.handler_script = PathBuf::from("/nonexistent/app.lua");
        let err = cfg.validate().expect_err("missing handler");
        assert!(err.to_string().contains("handler_script"), "got: {err}");

        let mut cfg = valid_base();
        cfg.templating.dir = Some(PathBuf::from("/nonexistent/templates"));
        let err = cfg.validate().expect_err("missing templates");
        assert!(err.to_string().contains("[templating] dir"), "got: {err}");

        // A file where a directory belongs is as wrong as nothing at all.
        let mut cfg = valid_base();
        cfg.templating.dir = Some(cfg.handler_script.clone());
        let err = cfg.validate().expect_err("file as the templating dir");
        assert!(err.to_string().contains("directory"), "got: {err}");

        // The database file may not exist yet, but its directory must.
        let mut cfg = valid_base();
        cfg.database = Some(DatabaseConfig::new("/nonexistent/dir/app.db"));
        let err = cfg.validate().expect_err("missing db dir");
        assert!(err.to_string().contains("database directory"), "got: {err}");
    }

    #[test]
    fn unknown_keys_are_rejected_not_ignored() {
        let path = write_temp_config("typo.toml", "max_body_byte = 1\n");
        let err = Config::from_file(&path).expect_err("unknown key");
        assert!(err.to_string().contains("max_body_byte"), "got: {err}");

        // Inside a section too.
        let path = write_temp_config("typo2.toml", "[limits]\nmax_body_byte = 1\n");
        let err = Config::from_file(&path).expect_err("unknown section key");
        assert!(err.to_string().contains("max_body_byte"), "got: {err}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn effective_config_prints_and_round_trips() {
        let mut cfg = valid_base();
        cfg.log.format = LogFormat::Json;
        cfg.pidfile = Some(PathBuf::from("/run/nitr.pid"));
        let rendered = cfg.effective_toml().expect("render");
        // Nones are absent, not null.
        assert!(!rendered.contains("null"), "got: {rendered}");
        assert!(rendered.contains("format = \"json\""), "got: {rendered}");
        assert!(
            rendered.contains("pidfile = \"/run/nitr.pid\""),
            "got: {rendered}"
        );
        // The output is itself a loadable configuration.
        let path = write_temp_config("effective.toml", &rendered);
        let reparsed = Config::from_file(&path).expect("reparse");
        assert_eq!(reparsed.log.format, LogFormat::Json);
        assert_eq!(reparsed.listen, cfg.listen);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rebase_moves_app_paths_and_leaves_the_database() {
        let mut cfg = Config {
            handler_script: PathBuf::from("app.lua"),
            config_script: Some(PathBuf::from("config.lua")),
            templating: TemplatingConfig {
                dir: Some(PathBuf::from("templates")),
            },
            database: Some(DatabaseConfig::new("data/app.db")),
            ..Config::default()
        };
        cfg.static_files.dir = Some(PathBuf::from("public"));
        cfg.rebase(Path::new("/bundle"));
        assert_eq!(cfg.handler_script, PathBuf::from("/bundle/app.lua"));
        assert_eq!(
            cfg.config_script.as_deref(),
            Some(Path::new("/bundle/config.lua"))
        );
        assert_eq!(
            cfg.templating.dir.as_deref(),
            Some(Path::new("/bundle/templates"))
        );
        assert_eq!(
            cfg.static_files.dir.as_deref(),
            Some(Path::new("/bundle/public"))
        );
        // Mutable state stays external to the artifact.
        assert_eq!(
            cfg.database.as_ref().unwrap().path,
            PathBuf::from("data/app.db")
        );
        // Absolute paths are already anchored; rebase leaves them alone.
        let mut cfg = Config {
            handler_script: PathBuf::from("/abs/app.lua"),
            ..Config::default()
        };
        cfg.rebase(Path::new("/bundle"));
        assert_eq!(cfg.handler_script, PathBuf::from("/abs/app.lua"));
    }

    #[test]
    fn defaults_are_sane() {
        let cfg = Config::default();
        assert_eq!(cfg.listen, SocketAddr::from(([127, 0, 0, 1], 3000)));
        assert_eq!(cfg.handler_script, PathBuf::from("scripts/handler.lua"));
        assert!(cfg.workers >= 1);
        assert!(!cfg.dev_mode);
        // No explicit list enables the minimal default feature set.
        assert_eq!(cfg.builtins().expect("builtins"), Builtins::minimal());
        // io/os are opt-in.
        assert!(!cfg.lua.stdlib.iter().any(|s| s == "io" || s == "os"));
    }

    #[test]
    fn parses_a_full_config_file() {
        let path = write_temp_config(
            "full.toml",
            r#"
                listen = "127.0.0.1:8080"
                handler_script = "app/handler.lua"
                workers = 2
                dev_mode = true
                [database]
                path = "app.db"
                [testing]
                dir = "spec"
                [std]
                features = ["dbg", "json", "db"]
                [lua]
                stdlib = ["math", "string", "package"]
                memory_limit = 1048576
                exec_timeout_ms = 500
            "#,
        );
        let cfg = Config::from_file(&path).expect("parse config");
        std::fs::remove_file(&path).ok();

        assert_eq!(cfg.listen, SocketAddr::from(([127, 0, 0, 1], 8080)));
        assert!(cfg.dev_mode);
        // [database] takes the pragma defaults; [testing] replaces its own.
        let db = cfg.database.as_ref().expect("database");
        assert_eq!(db.path, PathBuf::from("app.db"));
        assert_eq!(db.journal_mode, "wal");
        assert!(db.foreign_keys);
        assert_eq!(cfg.testing.dir, PathBuf::from("spec"));
        assert_eq!(
            cfg.builtins().expect("builtins"),
            Builtins::DEBUG | Builtins::JSON | Builtins::DATABASE
        );
        let opts = cfg.runtime_opts().expect("runtime opts");
        assert_eq!(opts.memory_limit, 1048576);
        assert_eq!(
            opts.exec_timeout,
            Some(std::time::Duration::from_millis(500))
        );
        assert!(opts.dev_mode);
        // package.path confinement derives from the handler script location.
        assert_eq!(opts.package_dir.as_deref(), Some(Path::new("app")));
    }

    #[test]
    fn read_timeout_limits_parse_and_default() {
        let cfg = Config::default();
        assert_eq!(cfg.limits.header_read_ms, 30_000);
        assert_eq!(cfg.limits.body_read_ms, 30_000);

        let path = write_temp_config(
            "read-timeouts.toml",
            "[limits]\nheader_read_ms = 0\nbody_read_ms = 250\n",
        );
        let cfg = Config::from_file(&path).expect("parse");
        std::fs::remove_file(&path).ok();
        assert_eq!(cfg.limits.header_read_ms, 0, "0 disables the deadline");
        assert_eq!(cfg.limits.body_read_ms, 250);
    }

    proptest::proptest! {
        /// Property: over arbitrary numeric limit combinations, validation
        /// is total — it accepts, or refuses with an error naming a
        /// setting; it never panics — and the pool-wait/exec-budget
        /// contradiction is always the refusal it promises.
        #[test]
        fn prop_limit_validation_is_total_and_names_the_setting(
            workers in 1usize..8,
            max_streams in proptest::option::of(0usize..8),
            pool_wait_ms in 0u64..100_000,
            exec_timeout_ms in 0u64..100_000,
            body_read_ms in 0u64..100_000,
            header_read_ms in 0u64..100_000,
        ) {
            let mut cfg = valid_base();
            cfg.workers = workers;
            cfg.max_streams = max_streams;
            cfg.limits.pool_wait_ms = pool_wait_ms;
            cfg.limits.body_read_ms = body_read_ms;
            cfg.limits.header_read_ms = header_read_ms;
            cfg.lua.exec_timeout_ms = exec_timeout_ms;

            match cfg.validate() {
                Ok(()) => {
                    proptest::prop_assert!(
                        !(pool_wait_ms > exec_timeout_ms
                            && pool_wait_ms != 0
                            && exec_timeout_ms != 0),
                        "the pool-wait contradiction must refuse"
                    );
                }
                Err(err) => {
                    let msg = err.to_string();
                    proptest::prop_assert!(
                        msg.contains("pool_wait_ms") || msg.contains("max_streams"),
                        "a refusal must name the offending setting: {msg}"
                    );
                }
            }
        }
    }

    #[test]
    fn moved_keys_fail_with_directions() {
        // Superseded spellings are refused with the new spelling named,
        // not as a bare unknown-field/type error.
        let path = write_temp_config("old-db.toml", "database = \"app.db\"\n");
        let err = Config::from_file(&path).expect_err("bare database string");
        std::fs::remove_file(&path).ok();
        assert!(err.to_string().contains("[database]"), "got: {err}");
        assert!(err.to_string().contains("path"), "got: {err}");

        let path = write_temp_config("old-tests.toml", "tests_dir = \"tests\"\n");
        let err = Config::from_file(&path).expect_err("tests_dir key");
        std::fs::remove_file(&path).ok();
        assert!(err.to_string().contains("[testing]"), "got: {err}");

        let path = write_temp_config("old-templates.toml", "templates_dir = \"templates\"\n");
        let err = Config::from_file(&path).expect_err("templates_dir key");
        std::fs::remove_file(&path).ok();
        assert!(err.to_string().contains("[templating]"), "got: {err}");
        assert!(err.to_string().contains("dir"), "got: {err}");
    }

    #[test]
    fn the_templating_section_parses_and_round_trips() {
        let path = write_temp_config(
            "templating.toml",
            "[templating]\ndir = \"scripts/templates\"\n",
        );
        let cfg = Config::from_file(&path).expect("parse [templating]");
        std::fs::remove_file(&path).ok();
        assert_eq!(
            cfg.templating.dir.as_deref(),
            Some(Path::new("scripts/templates"))
        );

        // The section survives `nitr check --print-config`, which serializes
        // the effective configuration back to TOML.
        let rendered = cfg.effective_toml().expect("render");
        assert!(rendered.contains("[templating]"), "got: {rendered}");
        let path = write_temp_config("templating-rt.toml", &rendered);
        let reparsed = Config::from_file(&path).expect("reparse");
        std::fs::remove_file(&path).ok();
        assert_eq!(reparsed.templating.dir, cfg.templating.dir);
    }

    /// `template` in an explicit `[std] features` list without the section
    /// it needs is a startup error naming the new spelling.
    #[test]
    fn the_template_feature_requires_the_templating_dir() {
        let mut cfg = valid_base();
        cfg.std.features = Some(vec!["template".into()]);
        let err = cfg.builtins().expect_err("template without a dir");
        assert!(err.to_string().contains("[templating] dir"), "got: {err}");

        cfg.templating.dir = Some(std::env::temp_dir());
        assert_eq!(cfg.builtins().expect("with a dir"), Builtins::TEMPLATE);
    }

    #[test]
    fn env_files_load_without_overriding_and_explicit_ones_must_exist() {
        let dir = std::env::temp_dir().join(format!("nitr-envfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join(".env"), "NITRTEST_FROM_FILE=hello\n").expect("env file");

        // Implicit `.env` next to the config loads; the value arrives in
        // the process environment.
        let cfg = Config::default();
        cfg.load_env_file(&dir).expect("implicit .env");
        assert_eq!(std::env::var("NITRTEST_FROM_FILE").as_deref(), Ok("hello"));

        // An implicit file may be absent; an explicitly named one may not.
        let empty = dir.join("sub");
        std::fs::create_dir_all(&empty).expect("dir");
        cfg.load_env_file(&empty)
            .expect("absent implicit .env is fine");
        let mut cfg = Config::default();
        cfg.env.file = Some(PathBuf::from("missing.env"));
        let err = cfg
            .load_env_file(&dir)
            .expect_err("explicit file must exist");
        assert!(err.to_string().contains("missing.env"), "got: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_unknown_fields() {
        let path = write_temp_config("typo.toml", "memroy_limit = 1\n");
        let err = Config::from_file(&path).expect_err("typo must fail");
        std::fs::remove_file(&path).ok();
        assert!(err.to_string().contains("memroy_limit"));
    }

    #[test]
    fn strict_std_features_require_their_settings() {
        let mut cfg = Config {
            std: StdConfig {
                features: Some(vec!["db".into()]),
            },
            ..Config::default()
        };
        assert!(cfg.builtins().is_err());
        cfg.database = Some(DatabaseConfig::new("x.db"));
        assert_eq!(cfg.builtins().expect("builtins"), Builtins::DATABASE);

        cfg.std.features = Some(vec!["nope".into()]);
        assert!(cfg.builtins().is_err());
    }

    #[test]
    fn exec_timeout_zero_disables_the_budget() {
        let mut cfg = Config::default();
        cfg.lua.exec_timeout_ms = 0;
        assert_eq!(cfg.runtime_opts().expect("opts").exec_timeout, None);
    }

    #[test]
    fn unknown_stdlib_name_fails() {
        let mut cfg = Config::default();
        cfg.lua.stdlib.push("ffi".into());
        assert!(cfg.runtime_opts().is_err());
    }
}
