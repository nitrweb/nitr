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

    /// Legal-but-suspicious combinations are reported as values rather than
    /// logged in place, so they can be asserted without a capturing
    /// subscriber.
    #[test]
    fn suspicious_settings_are_reported_as_warnings() {
        let clean = valid_base();
        assert!(
            clean.warnings().is_empty(),
            "the default config must warn about nothing, got: {:?}",
            clean.warnings()
        );

        // Above the execution budget, but the pool wait stays under it — the
        // pool-wait contradiction is a hard refusal and would mask this.
        let mut cfg = valid_base();
        cfg.lua.exec_timeout_ms = 5_000;
        cfg.limits.pool_wait_ms = 4_000;
        cfg.limits.body_read_ms = 9_000;
        let warnings = cfg.warnings();
        assert!(
            warnings.iter().any(|w| w.contains("body_read_ms")),
            "the body-read/exec-budget warning must survive the move: {warnings:?}"
        );
        cfg.validate().expect("a warning is never a refusal");
    }

    /// `"debug"` parses as a name but can never produce a state: mlua's safe
    /// constructor refuses `StdLib::DEBUG` outright, so accepting it only
    /// defers the failure to boot and reports it in terms of an internal
    /// Rust constructor. It is refused where the names are mapped, with a
    /// message an operator editing `nitr.toml` can act on.
    #[test]
    fn the_debug_library_is_refused_by_name() {
        let mut lua = LuaConfig::default();
        lua.stdlib.push("debug".into());
        let err = lua
            .parse_stdlib()
            .expect_err("`debug` must not map to a StdLib flag");
        let msg = err.to_string();
        assert!(
            msg.contains("[lua] stdlib") && msg.contains("debug"),
            "the refusal must name the setting and the library: {msg}"
        );
    }

    /// A config laid out the way a deployment is: the handler script in
    /// its own `scripts/` directory, with `uploads/` a sibling rather than
    /// a child.
    ///
    /// [`valid_base`] cannot serve here — it writes the handler straight
    /// into the system temp directory, which would make `require`'s root
    /// `/tmp` and every upload directory on the machine "inside" it. The
    /// layout is load-bearing, not incidental.
    fn upload_base(label: &str) -> (Config, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("nitr-up-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let scripts = base.join("scripts");
        let uploads = base.join("uploads");
        std::fs::create_dir_all(&scripts).expect("mkdir scripts");
        std::fs::create_dir_all(&uploads).expect("mkdir uploads");
        std::fs::write(scripts.join("app.lua"), "-- test handler").expect("write handler");
        let cfg = Config {
            handler_script: scripts.join("app.lua"),
            ..Config::default()
        };
        (cfg, base, uploads)
    }

    /// `[multipart] upload_dir` must exist, be a directory, and be
    /// writable — checked at startup, because the alternative is a 500 on
    /// the first upload that nobody can reproduce.
    #[test]
    fn the_upload_directory_is_validated_at_startup() {
        let (mut cfg, base, uploads) = upload_base("validated");

        // The sibling layout validates.
        cfg.multipart.upload_dir = Some(uploads.clone());
        cfg.validate().expect("a writable upload dir validates");

        // Missing entirely.
        cfg.multipart.upload_dir = Some(base.join("nope"));
        let err = cfg.validate().expect_err("a missing upload dir");
        let msg = err.to_string();
        assert!(msg.contains("[multipart] upload_dir"), "got: {msg}");
        assert!(msg.contains("does not exist"), "got: {msg}");

        // A file where a directory belongs.
        cfg.multipart.upload_dir = Some(cfg.handler_script.clone());
        let err = cfg.validate().expect_err("a file, not a directory");
        assert!(
            err.to_string().contains("must be a directory"),
            "got: {err}"
        );

        // Present but unwritable: existence is not writability, and the
        // refusal has to name the setting.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let locked = base.join("locked");
            std::fs::create_dir_all(&locked).expect("mkdir locked");
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500))
                .expect("chmod");
            cfg.multipart.upload_dir = Some(locked.clone());
            // Running as root defeats the permission bits entirely, so the
            // assertion only holds where the mode is actually enforced.
            if std::fs::File::create(locked.join(".probe")).is_err() {
                let err = cfg.validate().expect_err("an unwritable upload dir");
                let msg = err.to_string();
                assert!(msg.contains("[multipart] upload_dir"), "got: {msg}");
                assert!(msg.contains("cannot be written to"), "got: {msg}");
            }
            let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700));
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    /// An upload root under the handler script's directory is the
    /// upload-to-RCE chain spelled out in TOML: `require` is pinned there,
    /// so an uploaded `.lua` file becomes a loadable module. It refuses to
    /// boot rather than warning.
    #[test]
    fn an_upload_directory_inside_the_require_root_refuses_to_boot() {
        let (mut cfg, base, _) = upload_base("rce-chain");
        // Inside `scripts/`, where `require` is pinned — an uploaded
        // `evil.lua` here is `require("evil")`.
        let inside = base.join("scripts").join("uploads");
        std::fs::create_dir_all(&inside).expect("mkdir");
        cfg.multipart.upload_dir = Some(inside);

        let err = cfg
            .validate()
            .expect_err("an upload dir inside package_dir");
        let msg = err.to_string();
        assert!(msg.contains("[multipart] upload_dir"), "got: {msg}");
        assert!(
            msg.contains("loadable Lua module"),
            "the refusal must say why it matters: {msg}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The same refusal, for a handler script named without any
    /// directory at all.
    ///
    /// This is the shape that once slipped through: `"app.lua".parent()`
    /// is `Some("")`, which fails to canonicalize, so a guard that
    /// canonicalized the raw parent silently skipped itself — while
    /// `runtime_opts` resolved the same empty parent to `.` and pinned
    /// `require` to the working directory. The check and the runtime
    /// disagreed about where modules load from, and the disagreement
    /// favoured the attacker. Both now go through
    /// [`Config::package_dir`].
    #[test]
    fn a_bare_handler_script_still_refuses_an_upload_dir_beside_it() {
        let base = std::env::temp_dir().join(format!("nitr-up-bare-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("uploads")).expect("mkdir uploads");
        std::fs::write(base.join("app.lua"), "-- handler").expect("write handler");

        // The working directory *is* the require root for a bare name, so
        // the test has to run from `base` for the layout to be the real
        // one rather than a path-string coincidence.
        let previous = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(&base).expect("chdir");

        let cfg = Config {
            handler_script: PathBuf::from("app.lua"),
            multipart: MultipartConfig {
                upload_dir: Some(PathBuf::from("uploads")),
            },
            ..Config::default()
        };
        let result = cfg.validate();

        std::env::set_current_dir(&previous).expect("restore cwd");
        let _ = std::fs::remove_dir_all(&base);

        let err = result.expect_err("a bare handler name must not skip the check");
        assert!(
            err.to_string().contains("loadable Lua module"),
            "got: {err}"
        );
    }

    /// [`Config::package_dir`] is the single source of the `require` root,
    /// and it must agree with what `runtime_opts` actually hands the
    /// runtime for every way a handler path can be spelled.
    #[test]
    fn the_require_root_is_derived_identically_everywhere() {
        for (script, expected) in [
            ("app.lua", "."),
            ("./app.lua", "."),
            ("scripts/app.lua", "scripts"),
            ("/srv/app/scripts/app.lua", "/srv/app/scripts"),
        ] {
            let cfg = Config {
                handler_script: PathBuf::from(script),
                ..Config::default()
            };
            assert_eq!(
                cfg.package_dir(),
                Path::new(expected),
                "package_dir for {script}"
            );
            let opts = cfg.runtime_opts().expect("runtime opts");
            assert_eq!(
                opts.package_dir.as_deref(),
                Some(Path::new(expected)),
                "runtime_opts must pin `require` to the same root for {script}"
            );
        }
    }

    /// An upload root under `[static] dir` serves uploaded bytes back to
    /// browsers. A real deployment shape, so it warns and still boots —
    /// the contrast with the `package_dir` case, which refuses.
    #[test]
    fn an_upload_directory_inside_the_static_root_only_warns() {
        let (mut cfg, base, _) = upload_base("static-overlap");
        // `public/uploads` — served, and written by uploads.
        let public = base.join("public");
        let uploads = public.join("uploads");
        std::fs::create_dir_all(&uploads).expect("mkdir");
        cfg.static_files.dir = Some(public);
        cfg.multipart.upload_dir = Some(uploads);

        let warnings = cfg.warnings();
        assert!(
            warnings.iter().any(|w| w.contains("served back over HTTP")),
            "the overlap must be reported: {warnings:?}"
        );
        cfg.validate().expect("a warning is never a refusal");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The `[multipart]` section parses in every build, including one
    /// without the `multipart` feature — a config file that stops being
    /// readable depending on compilation flags is not portable. Plain
    /// `cargo test -p nitr-http` *is* that build (`default = []`).
    #[test]
    fn the_multipart_section_parses_without_the_multipart_feature() {
        let toml = r#"
            handler_script = "app.lua"
            [multipart]
            upload_dir = "uploads"
        "#;
        let cfg: Config = toml::from_str(toml).expect("[multipart] must always parse");
        assert_eq!(
            cfg.multipart.upload_dir,
            Some(PathBuf::from("uploads")),
            "the value must survive the parse, not just the section"
        );
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
            ]
            .map(String::from)
            .to_vec(),
            ..LuaConfig::default()
        };
        let libs = all.parse_stdlib().expect("all loadable names");
        assert!(libs.contains(mlua::StdLib::IO));
        assert!(libs.contains(mlua::StdLib::PACKAGE));
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

    // -----------------------------------------------------------------
    // [tls]

    /// A `[tls]` section over two files that exist. Their *contents* are
    /// irrelevant here: validation is about the shape of the
    /// configuration, and the PEM itself is `tls.rs`'s subject.
    fn tls_base() -> (Config, PathBuf, PathBuf) {
        let cert = write_temp_config("cert.pem", "not a real certificate");
        let key = write_temp_config("key.pem", "not a real key");
        let mut cfg = valid_base();
        cfg.tls = TlsConfig {
            enabled: true,
            cert: Some(cert.clone()),
            key: Some(key.clone()),
            min_version: None,
        };
        (cfg, cert, key)
    }

    #[test]
    fn the_tls_section_parses_and_round_trips() {
        let path = write_temp_config(
            "tls.toml",
            "[tls]\nenabled = true\ncert = \"tls/fullchain.pem\"\n\
             key = \"tls/privkey.pem\"\nmin_version = \"1.3\"\n",
        );
        let cfg = Config::from_file(&path).expect("parse [tls]");
        std::fs::remove_file(&path).ok();
        assert!(cfg.tls.enabled);
        assert_eq!(
            cfg.tls.cert.as_deref(),
            Some(Path::new("tls/fullchain.pem"))
        );
        assert_eq!(cfg.tls.key.as_deref(), Some(Path::new("tls/privkey.pem")));
        assert_eq!(cfg.tls.min_version.as_deref(), Some("1.3"));

        // Off by default, and absent from a rendered config that never
        // set it — a private key path is not something to print by habit.
        assert!(!Config::default().tls.enabled);

        // `nitr check --print-config` must render a loadable file.
        let rendered = cfg.effective_toml().expect("render");
        let path = write_temp_config("tls-rt.toml", &rendered);
        let reparsed = Config::from_file(&path).expect("reparse");
        std::fs::remove_file(&path).ok();
        assert_eq!(reparsed.tls.cert, cfg.tls.cert);
        assert_eq!(reparsed.tls.key, cfg.tls.key);
        assert_eq!(reparsed.tls.min_version, cfg.tls.min_version);
    }

    /// Half a `[tls]` section must fail at config load, naming the key
    /// that is missing — not at the first connection, which is where a
    /// lazy check would surface it: after traffic has been pointed at the
    /// port, looking like a network fault.
    /// Without the feature there is no handshake to configure, so asking
    /// for one is a startup refusal naming the feature to rebuild with —
    /// the same contract a `[std] features` entry with no Cargo feature
    /// behind it gets.
    #[cfg(not(feature = "tls"))]
    #[test]
    fn an_enabled_tls_section_without_the_feature_says_so() {
        let (cfg, cert, key) = tls_base();
        let err = cfg.validate().expect_err("no tls feature compiled in");
        let msg = err.to_string();
        assert!(msg.contains("[tls]"), "got: {msg}");
        assert!(msg.contains("`tls` feature"), "got: {msg}");
        std::fs::remove_file(&cert).ok();
        std::fs::remove_file(&key).ok();
    }

    #[cfg(feature = "tls")]
    #[test]
    fn an_enabled_tls_section_needs_both_paths() {
        let (cfg, cert, key) = tls_base();
        cfg.validate().expect("a complete [tls] section validates");

        let mut half = cfg.clone();
        half.tls.key = None;
        let err = half.validate().expect_err("cert without key");
        assert!(err.to_string().contains("requires `key`"), "got: {err}");

        let mut half = cfg.clone();
        half.tls.cert = None;
        let err = half.validate().expect_err("key without cert");
        assert!(err.to_string().contains("requires `cert`"), "got: {err}");

        let mut none = cfg.clone();
        none.tls.cert = None;
        none.tls.key = None;
        let err = none.validate().expect_err("neither path");
        assert!(err.to_string().contains("[tls]"), "got: {err}");

        // A path that does not exist is refused here too, so a typo is a
        // startup error naming the setting.
        let mut missing = cfg.clone();
        missing.tls.cert = Some(PathBuf::from("/nonexistent/nitr/fullchain.pem"));
        let err = missing.validate().expect_err("missing cert file");
        assert!(err.to_string().contains("[tls] cert"), "got: {err}");

        // A directory is not a PEM file.
        let mut wrong = cfg.clone();
        wrong.tls.key = Some(std::env::temp_dir());
        let err = wrong.validate().expect_err("a directory as the key");
        assert!(err.to_string().contains("[tls] key"), "got: {err}");

        // Disabled skips every check, so a half-written section can sit
        // in a file until somebody turns it on.
        let mut off = cfg.clone();
        off.tls.enabled = false;
        off.tls.cert = Some(PathBuf::from("/nonexistent/anything"));
        off.tls.key = None;
        off.validate().expect("a disabled [tls] is not validated");

        std::fs::remove_file(&cert).ok();
        std::fs::remove_file(&key).ok();
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_min_version_is_strict() {
        let (mut cfg, cert, key) = tls_base();
        for accepted in ["1.2", "1.3"] {
            cfg.tls.min_version = Some(accepted.into());
            cfg.validate()
                .unwrap_or_else(|err| panic!("min_version {accepted}: {err}"));
        }
        for rejected in ["1.1", "1.0", "TLSv1.2", "1.3 ", "13"] {
            cfg.tls.min_version = Some(rejected.into());
            let err = cfg.validate().expect_err("unknown min_version");
            assert!(err.to_string().contains("min_version"), "got: {err}");
            assert!(err.to_string().contains(rejected), "got: {err}");
        }
        std::fs::remove_file(&cert).ok();
        std::fs::remove_file(&key).ok();
    }

    /// `NITR_TLS_*` layers over the file exactly as every other section's
    /// variables do — checked side by side with `NITR_COMPRESSION_ENABLED`
    /// so "the same way" is asserted rather than assumed.
    #[test]
    fn tls_env_overrides_layer_like_every_other_section() {
        let mut cfg = Config::default();
        cfg.tls.cert = Some(PathBuf::from("from-toml.pem"));
        cfg.tls.min_version = Some("1.2".into());
        let env: [(&str, &str); 3] = [
            ("NITR_TLS_ENABLED", "true"),
            ("NITR_TLS_CERT", "from-env.pem"),
            ("NITR_TLS_KEY", "from-env.key"),
        ];
        cfg.apply_env_with(&|name| {
            env.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        })
        .expect("apply");
        assert!(cfg.tls.enabled, "NITR_TLS_ENABLED must win");
        assert_eq!(cfg.tls.cert.as_deref(), Some(Path::new("from-env.pem")));
        assert_eq!(cfg.tls.key.as_deref(), Some(Path::new("from-env.key")));
        // Untouched by the environment, so the file's value survives.
        assert_eq!(cfg.tls.min_version.as_deref(), Some("1.2"));

        // An empty value means "not set", the same rule the rest of the
        // layering follows, so it must not clear the file's value.
        let mut cfg = Config::default();
        cfg.tls.cert = Some(PathBuf::from("from-toml.pem"));
        cfg.apply_env_with(&|name| (name == "NITR_TLS_CERT").then(String::new))
            .expect("apply");
        assert_eq!(cfg.tls.cert.as_deref(), Some(Path::new("from-toml.pem")));

        // An unparseable boolean is refused naming its variable — the
        // same shape of failure `NITR_COMPRESSION_ENABLED` gives.
        for var in ["NITR_TLS_ENABLED", "NITR_COMPRESSION_ENABLED"] {
            let err = Config::default()
                .apply_env_with(&|name| (name == var).then(|| "yes".to_string()))
                .expect_err("not a boolean");
            assert!(err.to_string().contains(var), "got: {err}");
        }
    }

    proptest::proptest! {
        /// Property: validation of `[tls]` is total, and an accepted
        /// section always carries both paths.
        ///
        /// The converse is what actually matters operationally: there is
        /// no combination of settings that starts a TLS listener with a
        /// certificate but no key, or the other way round. Every refusal
        /// must also name `[tls]`, so the message points at the section
        /// to fix.
        #[test]
        fn prop_a_validating_tls_section_always_has_both_paths(
            enabled in proptest::bool::ANY,
            cert in proptest::option::of(0usize..3),
            key in proptest::option::of(0usize..3),
            min_version in proptest::option::of(
                proptest::sample::select(vec!["1.2", "1.3", "1.1", "", "tls1.3"])
            ),
        ) {
            // 0 = a real file, 1 = a directory, 2 = nothing there.
            let real = write_temp_config("prop.pem", "x");
            let pick = |slot: Option<usize>| match slot {
                Some(0) => Some(real.clone()),
                Some(1) => Some(std::env::temp_dir()),
                Some(2) => Some(PathBuf::from("/nonexistent/nitr/prop.pem")),
                _ => None,
            };
            let mut cfg = valid_base();
            cfg.tls = TlsConfig {
                enabled,
                cert: pick(cert),
                key: pick(key),
                min_version: min_version.map(String::from),
            };
            let outcome = cfg.validate();
            std::fs::remove_file(&real).ok();

            match outcome {
                Ok(()) => {
                    // Without the Cargo feature there is no handshake to
                    // configure, so an enabled section can never validate
                    // at all — the property holds from the other side.
                    proptest::prop_assert!(
                        !enabled || cfg!(feature = "tls"),
                        "an enabled [tls] validated in a build with no TLS support"
                    );
                    proptest::prop_assert!(
                        !enabled || (cert == Some(0) && key == Some(0)),
                        "an enabled [tls] validated without two real files: \
                         cert={cert:?} key={key:?}"
                    );
                    proptest::prop_assert!(
                        !enabled || matches!(
                            cfg.tls.min_version.as_deref(),
                            None | Some("1.2") | Some("1.3")
                        ),
                        "an unknown min_version validated: {:?}",
                        cfg.tls.min_version
                    );
                }
                Err(err) => {
                    let msg = err.to_string();
                    // A disabled section is never the reason for a
                    // refusal, so any refusal here is about [tls] itself.
                    proptest::prop_assert!(
                        enabled,
                        "a disabled [tls] caused a refusal: {msg}"
                    );
                    proptest::prop_assert!(
                        msg.contains("[tls]"),
                        "the refusal must name the section: {msg}"
                    );
                }
            }
        }

        /// Property: `NITR_TLS_*` composes with the file the way the rest
        /// of the layering does — present-and-non-empty wins, anything
        /// else leaves the parsed value alone — and the pass is
        /// idempotent, so re-running it cannot drift.
        #[test]
        fn prop_tls_env_overrides_compose_like_the_rest(
            toml_cert in proptest::option::of("[a-z]{1,8}\\.pem"),
            env_cert in proptest::option::of("[a-z]{0,8}"),
            env_enabled in proptest::option::of(
                proptest::sample::select(vec!["true", "false", "", "TRUE"])
            ),
        ) {
            let mut cfg = Config::default();
            cfg.tls.cert = toml_cert.as_deref().map(PathBuf::from);
            let lookup = |name: &str| match name {
                "NITR_TLS_CERT" => env_cert.clone(),
                "NITR_TLS_ENABLED" => env_enabled.map(String::from),
                _ => None,
            };
            let outcome = cfg.apply_env_with(&lookup);

            // Only a value that is neither absent nor empty may speak.
            let effective_enabled = env_enabled.filter(|v| !v.is_empty());
            match outcome {
                Ok(()) => {
                    proptest::prop_assert!(
                        !matches!(effective_enabled, Some("TRUE")),
                        "`TRUE` is not a Rust bool literal and must be refused"
                    );
                    proptest::prop_assert_eq!(
                        cfg.tls.enabled,
                        effective_enabled == Some("true"),
                        "NITR_TLS_ENABLED={:?} did not decide the value",
                        env_enabled
                    );
                    let effective_cert = env_cert
                        .clone()
                        .filter(|v| !v.is_empty())
                        .or(toml_cert)
                        .map(PathBuf::from);
                    proptest::prop_assert_eq!(
                        cfg.tls.cert.clone(),
                        effective_cert,
                        "the env value must win only when it is set and non-empty"
                    );
                    // Applying the same environment again changes nothing.
                    let before = cfg.clone();
                    cfg.apply_env_with(&lookup).expect("second pass");
                    proptest::prop_assert_eq!(
                        cfg.tls.cert,
                        before.tls.cert,
                        "the override pass is not idempotent"
                    );
                    proptest::prop_assert_eq!(cfg.tls.enabled, before.tls.enabled);
                }
                Err(err) => {
                    let msg = err.to_string();
                    proptest::prop_assert!(
                        msg.contains("NITR_TLS_ENABLED"),
                        "only an unparseable boolean can fail here: {msg}"
                    );
                    proptest::prop_assert!(
                        !matches!(effective_enabled, None | Some("true") | Some("false")),
                        "{:?} is a value that must parse",
                        env_enabled
                    );
                }
            }
        }
    }
}
