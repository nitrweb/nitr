// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The built-in `nitr.*` standard library for Nitr and its registration.
//!
//! Every builtin mounts as a field of the global `nitr` namespace table
//! (`nitr.json`, `nitr.fetch`, `nitr.db`, …) — Nitr registers no other
//! globals, so scripts always read `nitr.*` and nothing is intermixed with
//! the Lua standard library.

// Lint policy comes from `[workspace.lints]` in the root Cargo.toml.
// `unwrap_used`/`expect_used` are denied here (not in the workspace table,
// which would also hit test and bench targets); unit tests are exempt, and
// the few documented-invariant `expect()`s carry targeted allows.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::path::PathBuf;

use nitr_core::Result;

pub(crate) mod base64;
pub mod cache;
pub(crate) mod config;
#[cfg(feature = "crypto")]
pub(crate) mod crypto;
pub(crate) mod csrf;
#[cfg(feature = "db")]
pub(crate) mod db;
pub(crate) mod env;
#[cfg(feature = "fetch")]
pub(crate) mod fetch;
pub(crate) mod http;
pub(crate) mod json;
pub(crate) mod log;
pub(crate) mod path;
pub(crate) mod session;
#[cfg(feature = "template")]
pub(crate) mod template;
pub(crate) mod time;
pub(crate) mod url;
pub(crate) mod utils;
pub(crate) mod validate;

pub use cache::{Cache, CacheOptions};
// The configuration types are always available: `nitr.toml` has one shape
// regardless of which builtins this build compiled in.
pub use config::{EnvOptions, FetchOptions, MAX_PASSWORD_BYTES, SqlitePragmas};
pub use http::{RequestCookies, ResponseCookies, best_match};
pub use utils::error_lua_value;

/// Internal functions exposed for the fuzz targets in `fuzz/` only.
/// Not part of the public API; no stability promise applies here.
#[doc(hidden)]
pub mod fuzzing {
    #[cfg(feature = "crypto")]
    pub use crate::crypto::{VERIFY_REASONS, create_auth_table, create_crypto_table};
    pub use crate::http::{sign, verify};
    pub use crate::json::create_json_fn;
    pub use crate::path::{
        basename, dirname, is_absolute, is_windows_style, join, normalize, split_root,
    };
    pub use crate::url::create_url_table;
    pub use crate::validate::format::{check_format, format_names};
}

#[cfg(feature = "db")]
pub use db::migrate;
#[cfg(feature = "db")]
pub use db::pragmas::open as db_open;
#[cfg(feature = "fetch")]
pub use fetch::{reset_outbound_budget, set_trace_context};

/// Resets the per-request outbound budget. A no-op without the `fetch`
/// feature, so the server can call it unconditionally.
#[cfg(not(feature = "fetch"))]
pub fn reset_outbound_budget(_lua: &mlua::Lua) {}

/// Records the inbound request id for `traceparent` propagation. A no-op
/// without the `fetch` feature.
#[cfg(not(feature = "fetch"))]
pub fn set_trace_context(_lua: &mlua::Lua, _request_id: &str) {}

bitflags::bitflags! {
    /// Built-in `nitr.*` standard library modules that can be exposed to
    /// Lua scripts.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Builtins: u32 {
        /// `nitr.dbg(value)` debug-print function.
        const DEBUG = 1;
        /// `nitr.fetch(method, url, opts?)` HTTP client plus
        /// `nitr.await_all` for concurrent requests.
        const FETCH = 1 << 1;
        /// `nitr.template:render(name, data?)` template engine (minijinja).
        const TEMPLATE = 1 << 2;
        /// `nitr.json` JSON codec (`:encode`/`:decode`) and, called as a
        /// function, the JSON response helper.
        const JSON = 1 << 3;
        /// `nitr.db:execute/query/query_row/query_one/transaction` SQLite
        /// driver.
        const DATABASE = 1 << 4;
        /// HTTP ergonomics: the `nitr.text`/`html`/`redirect`/`status`/
        /// `negotiate`/`sse` response helpers and `nitr.error`.
        const HTTP = 1 << 5;
        /// `nitr.log.debug/info/warn/error(msg, fields?)` structured logging.
        const LOG = 1 << 6;
        /// `nitr.crypto` primitives (hashing, HMAC, passwords, AEAD, JWT)
        /// and the `nitr.auth` header parsers.
        const CRYPTO = 1 << 7;
        /// `nitr.cache`: the bounded cache shared by every pooled state.
        const CACHE = 1 << 8;
        /// `nitr.time`: safe clocks and time formatting/parsing, so
        /// scripts never need the `os` Lua standard library for a date.
        const TIME = 1 << 9;
        /// `nitr.validate`: declarative request validation, compiled once
        /// and checked in Rust.
        const VALIDATE = 1 << 10;
        /// `nitr.base64`: base64 encoding/decoding (standard and
        /// URL-safe alphabets).
        const BASE64 = 1 << 11;
        /// `nitr.path`: lexical `/`-path manipulation — pure text, no
        /// filesystem access.
        const PATH = 1 << 12;
        /// `nitr.url`: percent-encoding, query strings, and a lexical
        /// URL splitter.
        const URL = 1 << 13;
        /// `nitr.env`: read-only environment variable access
        /// (`get`/`has`/`number`/`bool`), filtered by `[env] allow` and
        /// never exposing `NITR_*` internals.
        const ENV = 1 << 14;
    }
}

impl Builtins {
    /// The minimal default feature set enabled when the configuration has
    /// no explicit `[std] features` list: the JSON codec, the HTTP response
    /// helpers, structured logging, safe time, and validation. These need
    /// no external resources (templates directory, database file, outbound
    /// network) and keep the standard library lightweight; everything else
    /// is opt-in. `time` and `validate` are here because they replace the
    /// dangerous alternatives (`os.date`, hand-rolled input checks) — a
    /// default that omitted them would push scripts toward widening the
    /// sandbox instead.
    pub const fn minimal() -> Self {
        Self::JSON
            .union(Self::HTTP)
            .union(Self::LOG)
            .union(Self::TIME)
            .union(Self::VALIDATE)
            .union(Self::BASE64)
            .union(Self::PATH)
            .union(Self::URL)
    }

    /// The field name a builtin mounts under on the `nitr` namespace table.
    ///
    /// Returns `None` for combined flags and for builtins that register
    /// several fields ([`HTTP`](Self::HTTP) and [`CRYPTO`](Self::CRYPTO)).
    pub fn nitr_name(self) -> Option<&'static str> {
        match self {
            Builtins::DEBUG => Some("dbg"),
            Builtins::FETCH => Some("fetch"),
            Builtins::TEMPLATE => Some("template"),
            Builtins::JSON => Some("json"),
            Builtins::DATABASE => Some("db"),
            Builtins::LOG => Some("log"),
            Builtins::TIME => Some("time"),
            Builtins::VALIDATE => Some("validate"),
            Builtins::BASE64 => Some("base64"),
            Builtins::PATH => Some("path"),
            Builtins::URL => Some("url"),
            Builtins::ENV => Some("env"),
            _ => None,
        }
    }

    /// Resolves a configuration name (e.g. `"dbg"`, `"fetch"`, `"db"`) into
    /// its builtin flag.
    pub fn from_config_name(name: &str) -> Option<Self> {
        match name {
            "dbg" => Some(Builtins::DEBUG),
            "fetch" => Some(Builtins::FETCH),
            "template" => Some(Builtins::TEMPLATE),
            "json" => Some(Builtins::JSON),
            "db" => Some(Builtins::DATABASE),
            "http" => Some(Builtins::HTTP),
            "log" => Some(Builtins::LOG),
            "crypto" => Some(Builtins::CRYPTO),
            "cache" => Some(Builtins::CACHE),
            "time" => Some(Builtins::TIME),
            "validate" => Some(Builtins::VALIDATE),
            "base64" => Some(Builtins::BASE64),
            "path" => Some(Builtins::PATH),
            "url" => Some(Builtins::URL),
            "env" => Some(Builtins::ENV),
            _ => None,
        }
    }
}

/// External resources required by some builtins: `template` needs a
/// templates directory and `db` a SQLite database file.
#[derive(Debug, Clone, Default)]
pub struct BuiltinsEnv {
    /// Directory the `template` builtin loads templates from.
    pub templates_dir: Option<PathBuf>,
    /// SQLite database file the `db` builtin connects to.
    pub database: Option<PathBuf>,
    /// Connection pragmas applied to that database.
    pub sqlite: SqlitePragmas,
    /// The shared cache backing `nitr.cache`. Built once by the server and
    /// handed to every state, so it survives a pool rebuild — a cache that
    /// empties on every reload is a cache that never warms.
    pub cache: Option<Cache>,
    /// Outbound-request policy for the `fetch` builtin.
    pub fetch: FetchOptions,
    /// Read policy for the `nitr.env` builtin.
    pub env: EnvOptions,
    /// Whether cookies Nitr builds carry `Secure` when the caller's own
    /// options table does not say. Resolved by the server from
    /// `[cookies] secure` and `[tls] enabled`.
    ///
    /// `false` in `Default` deliberately: an embedder who never sets one,
    /// and `nitr hash-password`, keep exactly today's behaviour.
    pub cookie_secure: bool,
}

/// Registers the selected builtins as fields of the global `nitr`
/// namespace table (`nitr.dbg`, `nitr.fetch`, `nitr.json`, `nitr.db`, …).
///
/// Builtins that need a setting from the [`BuiltinsEnv`] (`template` needs
/// `templates_dir`, `db` needs `database`) are skipped with a warning when
/// that setting is absent; callers that take an explicit builtins list
/// should reject such combinations upfront.
/// Only reachable when at least one gated builtin was left out.
#[cfg(not(all(
    feature = "crypto",
    feature = "db",
    feature = "fetch",
    feature = "template"
)))]
fn not_compiled_in(name: &str) -> nitr_core::Error {
    nitr_core::Error::Config(format!(
        "the `{name}` builtin is configured but was not compiled into this \
         binary: rebuild with the `{name}` Cargo feature (or `all`), or drop \
         it from `[std] features`"
    ))
}

/// Registers the selected builtins on the global `nitr` namespace table,
/// using the [`BuiltinsEnv`] for the resources some of them need.
pub fn register_builtins(lua: &mlua::Lua, builtins: Builtins, env: &BuiltinsEnv) -> Result {
    let nitr = nitr_core::nitr_table(lua)?;
    // The cookie policy is stashed per state rather than captured, because
    // the cookie serializer is reached from `UserData` methods whose
    // closures are registered once per type. Set unconditionally — not
    // only under `Builtins::HTTP` — so the value a state carries never
    // depends on which builtins happened to be enabled.
    lua.set_app_data(http::CookieDefaults {
        secure: env.cookie_secure,
    });
    for builtin in builtins.iter() {
        match builtin {
            Builtins::DEBUG => nitr.set("dbg", utils::create_debug_fn(lua)?)?,
            // Also registers `nitr.await_all` for concurrent requests.
            #[cfg(feature = "fetch")]
            Builtins::FETCH => {
                let opts = std::sync::Arc::new(env.fetch.clone());
                nitr.set("fetch", fetch::create_fetch_fn(lua, opts.clone())?)?;
                nitr.set("await_all", fetch::create_await_all_fn(lua, opts)?)?;
            }
            #[cfg(not(feature = "fetch"))]
            Builtins::FETCH => return Err(not_compiled_in("fetch")),

            #[cfg(feature = "template")]
            Builtins::TEMPLATE => match &env.templates_dir {
                Some(dir) => nitr.set("template", template::create_template_fn(lua, dir)?)?,
                None => {
                    tracing::warn!(
                        "skipping builtin `template`: `[templating] dir` is not configured"
                    );
                }
            },
            #[cfg(not(feature = "template"))]
            Builtins::TEMPLATE => return Err(not_compiled_in("template")),
            Builtins::JSON => nitr.set("json", json::create_json_fn(lua)?)?,
            // Registers the response helpers (`nitr.text`, `nitr.html`,
            // `nitr.redirect`, `nitr.status`, `nitr.negotiate`, `nitr.sse`),
            // `nitr.error`, and the signed-cookie ergonomics built on them:
            // `nitr.csrf` and `nitr.session`.
            Builtins::HTTP => {
                http::register(lua, &nitr)?;
                nitr.set("csrf", csrf::create_csrf_table(lua)?)?;
                nitr.set("session", session::create_session_fn(lua)?)?;
            }
            Builtins::LOG => nitr.set("log", log::create_log_table(lua)?)?,
            Builtins::TIME => nitr.set("time", time::create_time_table(lua)?)?,
            Builtins::VALIDATE => nitr.set("validate", validate::create_validate_table(lua)?)?,
            Builtins::BASE64 => nitr.set("base64", base64::create_base64_table(lua)?)?,
            Builtins::PATH => nitr.set("path", path::create_path_table(lua)?)?,
            Builtins::URL => nitr.set("url", url::create_url_table(lua)?)?,
            Builtins::ENV => nitr.set("env", env::create_env_table(lua, &env.env)?)?,
            // Registers both `nitr.crypto` and `nitr.auth`.
            #[cfg(feature = "crypto")]
            Builtins::CRYPTO => {
                nitr.set("crypto", crypto::create_crypto_table(lua)?)?;
                nitr.set("auth", crypto::create_auth_table(lua)?)?;
            }
            #[cfg(not(feature = "crypto"))]
            Builtins::CRYPTO => return Err(not_compiled_in("crypto")),

            #[cfg(feature = "db")]
            Builtins::DATABASE => match &env.database {
                Some(path) => nitr.set("db", db::create_database_fn(lua, path, &env.sqlite)?)?,
                None => {
                    tracing::warn!("skipping builtin `db`: `database` is not configured");
                }
            },
            #[cfg(not(feature = "db"))]
            Builtins::DATABASE => return Err(not_compiled_in("db")),
            Builtins::CACHE => match &env.cache {
                Some(cache) => nitr.set("cache", cache::create_cache(lua, cache.clone())?)?,
                None => {
                    tracing::warn!("skipping builtin `cache`: no shared cache was provided");
                }
            },
            _ => continue,
        };
    }
    // Always registered, independent of the configured builtins: turning a
    // caught error into its structured form is part of the error model,
    // not an optional capability.
    nitr.set("errinfo", utils::create_errinfo_fn(lua)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Builtins;

    #[test]
    fn config_names_round_trip() {
        for (name, flag) in [
            ("dbg", Builtins::DEBUG),
            ("fetch", Builtins::FETCH),
            ("template", Builtins::TEMPLATE),
            ("json", Builtins::JSON),
            ("db", Builtins::DATABASE),
            ("http", Builtins::HTTP),
            ("log", Builtins::LOG),
            ("crypto", Builtins::CRYPTO),
            ("time", Builtins::TIME),
            ("validate", Builtins::VALIDATE),
            ("base64", Builtins::BASE64),
            ("path", Builtins::PATH),
            ("url", Builtins::URL),
            ("env", Builtins::ENV),
        ] {
            assert_eq!(Builtins::from_config_name(name), Some(flag));
        }
        assert_eq!(Builtins::from_config_name("nope"), None);
        // Combined flags and multi-field builtins have no single name.
        assert_eq!((Builtins::DEBUG | Builtins::JSON).nitr_name(), None);
        assert_eq!(Builtins::HTTP.nitr_name(), None);
        assert_eq!(Builtins::DATABASE.nitr_name(), Some("db"));
    }
}
