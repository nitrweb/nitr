// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The per-section configuration structs of `nitr.toml` and their
//! defaults; everything except `[database]`, which has its own module.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use nitr_core::{Error, Result};

/// Default per-state Lua memory limit in bytes.
const DEFAULT_MEMORY_LIMIT: usize = 8 * 1024 * 1024; // 8 MiB

/// Default wall-clock budget per handler invocation, in milliseconds.
const DEFAULT_EXEC_TIMEOUT_MS: u64 = 30_000;

/// Health and readiness endpoints (`[health]` section), answered entirely
/// in Rust.
///
/// Two deliberately separate questions: liveness ("is the process alive?")
/// never touches a Lua state; a probe that queued behind a saturated pool
/// would cause the restart it exists to prevent; and readiness ("should
/// it receive traffic?") flips to `503` the moment a graceful drain
/// starts, so a rolling deploy shifts traffic before requests can fail.
/// An application cannot influence either answer.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthConfig {
    /// Whether the endpoints are served at all.
    pub enabled: bool,
    /// Liveness path: `200 ok` while the process runs.
    pub liveness: String,
    /// Readiness path: `200 ok` while accepting traffic, `503 draining`
    /// once a graceful shutdown begins.
    pub readiness: String,
    /// A separate address to serve the endpoints on, keeping them off the
    /// public port. When unset they answer on the main listener.
    pub bind: Option<SocketAddr>,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            liveness: "/healthz".into(),
            readiness: "/readyz".into(),
            bind: None,
        }
    }
}

/// Log output (`[log]` section).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// Output format.
    pub format: LogFormat,
    /// Minimum level (`trace`/`debug`/`info`/`warn`/`error`), or any
    /// `tracing` filter directive. The `RUST_LOG` environment variable
    /// wins over this; without either, `info` (`debug` in dev mode).
    pub level: Option<String>,
}

/// How log lines are rendered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable single-line text (the default).
    #[default]
    Text,
    /// One JSON object per line, with the request/error fields as real
    /// keys — what makes the structured fields usable by a log shipper.
    Json,
}

/// Standard library selection (`[std]` section): which built-in `nitr.*`
/// modules are exposed to scripts.
///
/// The standard library provides building blocks — scripts opt into the
/// features they need (or replace them with their own modules). Without an
/// explicit list only the minimal set is enabled to keep the footprint
/// small.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StdConfig {
    /// Enabled standard library features. Valid names: `"dbg"`, `"fetch"`,
    /// `"template"`, `"json"`, `"db"`, `"http"`, `"log"`, `"crypto"`,
    /// `"cache"`, `"time"`, `"validate"`, `"base64"`, `"path"`, `"url"`,
    /// `"env"`.
    /// `None` enables the minimal default set (`json`, `http`, `log`,
    /// `time`, `validate`, `base64`, `path`, `url`); an explicit list is
    /// strict —
    /// unknown names or a listed feature missing its required setting
    /// (e.g. `db` without `database`) fail at startup.
    pub features: Option<Vec<String>>,
}

/// Request-size and connection limits (`[limits]` section), enforced in
/// Rust before a request reaches Lua.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum declared request body size in bytes (413 beyond it).
    pub max_body_bytes: u64,
    /// Maximum request header buffer in bytes (hyper enforces a floor of
    /// 8 KiB).
    pub max_header_bytes: usize,
    /// Maximum request URI length in bytes (414 beyond it).
    pub max_uri_bytes: usize,
    /// Maximum concurrent TCP connections; the listener stops accepting
    /// while at the cap.
    pub max_connections: usize,
    /// How long a request may wait for a free Lua state before it is shed
    /// with `503` and a `Retry-After`, in milliseconds. `0` waits forever
    /// (the pre-phase-10 behavior). Shedding happens before any Lua runs,
    /// so an overloaded server answers quickly instead of queueing work
    /// nobody is still waiting for.
    pub pool_wait_ms: u64,
    /// How long a client may take to send its complete request headers,
    /// in milliseconds; the connection is closed past it. `0` disables
    /// the deadline.
    pub header_read_ms: u64,
    /// How long each read of the request body may wait for the next
    /// bytes, in milliseconds (`408` past it, and the connection is
    /// closed). A progress bound, not a total-transfer one: a body that
    /// keeps arriving is fine at any size the byte limits allow; one
    /// that stalls fails deterministically instead of holding a
    /// connection slot and a pooled Lua state. `0` disables the bound.
    pub body_read_ms: u64,
    /// Maximum number of parts in a `multipart/form-data` body.
    pub max_form_parts: usize,
    /// Maximum size of a single non-file form field, in bytes. Fields
    /// become Lua strings, so this bounds what a request can push into a
    /// state's heap.
    pub max_field_bytes: u64,
    /// Maximum size of a single uploaded file, in bytes. Files stream to
    /// disk in Rust and never enter the Lua heap, so this is far larger
    /// than [`max_field_bytes`](Self::max_field_bytes).
    pub max_file_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024, // 1 MiB
            max_header_bytes: 16 * 1024, // 16 KiB
            max_uri_bytes: 8 * 1024,     // 8 KiB
            max_connections: 1024,
            // Generous by default: long enough that a brief burst queues
            // rather than sheds, short enough that a saturated server fails
            // fast instead of accumulating doomed requests.
            pool_wait_ms: 5_000,
            // 30 s each: far beyond any honest client or network hiccup,
            // far short of forever. The header value matches what was a
            // hardcoded constant before it became configurable.
            header_read_ms: 30_000,
            body_read_ms: 30_000,
            max_form_parts: 64,
            max_field_bytes: 64 * 1024,       // 64 KiB
            max_file_bytes: 10 * 1024 * 1024, // 10 MiB
        }
    }
}

/// Graceful-shutdown timing (`[shutdown]` section).
///
/// On `SIGTERM`/`SIGINT` the server stops accepting, lets in-flight
/// requests finish, and only then exits. These bound how long it waits.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShutdownConfig {
    /// Seconds to let ordinary in-flight requests finish.
    pub grace: u64,
    /// Extra seconds granted to streaming and SSE bodies, which can
    /// legitimately outlive a normal request. They are cut at
    /// `grace + stream_grace`.
    pub stream_grace: u64,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            grace: 30,
            stream_grace: 5,
        }
    }
}

impl ShutdownConfig {
    /// Deadline for ordinary in-flight requests.
    pub fn grace(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.grace)
    }

    /// Total deadline including the extra budget for long-lived bodies.
    pub fn total_grace(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.grace + self.stream_grace)
    }
}

/// Outbound-request policy for the `fetch` builtin (`[fetch]` section).
/// By default, requests to loopback/private/link-local addresses are
/// refused (SSRF protection) and every redirect hop is re-checked.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FetchConfig {
    /// When set, only these exact host names may be fetched.
    pub allowed_hosts: Option<Vec<String>>,
    /// Allow requests to private/loopback/link-local addresses.
    pub allow_private_networks: bool,
    /// Maximum response body accumulated by `resp:text()`/`resp:json()`.
    pub max_response_bytes: u64,
    /// Maximum concurrent requests per `await_all(...)` call.
    pub max_concurrent: usize,
    /// Maximum outbound requests one inbound request may make in total.
    /// `max_concurrent` bounds a single `await_all`; this bounds the whole
    /// handler, including a loop issuing calls one after another. `0`
    /// removes the cap.
    pub max_per_request: u32,
    /// Seconds to wait for a TCP/TLS connection to an upstream.
    pub connect_timeout: f64,
    /// Default total budget per outbound request, in seconds. A per-call
    /// `timeout` option overrides it.
    pub timeout: f64,
    /// Idle connections kept per upstream host.
    pub pool_max_idle_per_host: usize,
    /// Maximum retry attempts a call may ask for. Retries are opt-in per
    /// call and only ever applied to idempotent methods.
    pub max_retries: u32,
    /// Proxy URL for outbound requests. Unset reads the conventional
    /// `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` environment variables.
    pub proxy: Option<String>,
    /// Ignore the proxy environment variables entirely.
    pub no_proxy: bool,
    /// Forward a W3C `traceparent` header on outbound calls, derived from
    /// the inbound request id, so a request crossing services can be
    /// correlated. Pass-through only: this is not a tracing SDK.
    pub propagate_trace_context: bool,
}

impl Default for FetchConfig {
    fn default() -> Self {
        let defaults = nitr_std::FetchOptions::default();
        Self {
            allowed_hosts: defaults.allowed_hosts,
            allow_private_networks: defaults.allow_private_networks,
            max_response_bytes: defaults.max_response_bytes,
            max_concurrent: defaults.max_concurrent,
            max_per_request: defaults.max_per_request,
            connect_timeout: defaults.connect_timeout.as_secs_f64(),
            timeout: defaults.timeout.as_secs_f64(),
            pool_max_idle_per_host: defaults.pool_max_idle_per_host,
            max_retries: defaults.max_retries,
            proxy: None,
            no_proxy: false,
            propagate_trace_context: false,
        }
    }
}

impl FetchConfig {
    /// The runtime policy handed to the `fetch` builtin.
    pub fn options(&self) -> nitr_std::FetchOptions {
        nitr_std::FetchOptions {
            allowed_hosts: self.allowed_hosts.clone(),
            allow_private_networks: self.allow_private_networks,
            max_response_bytes: self.max_response_bytes,
            max_concurrent: self.max_concurrent.max(1),
            max_per_request: self.max_per_request,
            connect_timeout: std::time::Duration::from_secs_f64(self.connect_timeout.max(0.1)),
            timeout: std::time::Duration::from_secs_f64(self.timeout.max(0.1)),
            pool_max_idle_per_host: self.pool_max_idle_per_host,
            max_retries: self.max_retries,
            proxy: self.proxy.clone(),
            no_proxy: self.no_proxy,
            propagate_trace_context: self.propagate_trace_context,
        }
    }
}

/// Static file serving (`[static]` section): requests under `mount` are
/// served from `dir` entirely in Rust, before any Lua dispatch. Scripts
/// can add further mounts with `app:static(mount, dir, opts?)`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StaticConfig {
    /// Directory served as static files; unset disables the section.
    pub dir: Option<PathBuf>,
    /// URL prefix the directory is mounted at (default `/`).
    pub mount: Option<String>,
    /// Serve `index.html` for unknown paths (single-page applications).
    pub spa: bool,
    /// `Cache-Control` header value for served files.
    pub cache_control: Option<String>,
}

/// Template rendering (`[templating]` section) for the `template`
/// builtin (`nitr.template`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TemplatingConfig {
    /// Directory `nitr.template` loads templates from. Unset leaves the
    /// builtin unavailable: there is no sensible default location to
    /// guess, and silently rendering from the wrong directory is worse
    /// than saying the builtin is not configured.
    pub dir: Option<PathBuf>,
}

/// Test runner settings (`[testing]` section).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TestingConfig {
    /// Directory `nitr test` discovers `*.lua` test files in.
    pub dir: PathBuf,
}

impl Default for TestingConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("tests"),
        }
    }
}

/// Environment handling (`[env]` section): the env file loaded at
/// startup, and the read policy for the opt-in `nitr.env` builtin
/// (`[std] features = ["env", ...]`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvConfig {
    /// Dotenv-style file loaded at startup, resolved relative to the
    /// config file. Unset loads `.env` next to `nitr.toml` when present;
    /// an explicitly named file must exist. Values never override the
    /// real process environment.
    pub file: Option<PathBuf>,
    /// Names `nitr.env` may read: exact names, or prefixes written with a
    /// trailing `_` (`"APP_"`). Unset lets an enabled `env` builtin read
    /// any variable. `NITR_*` internals are hidden from scripts either way.
    pub allow: Option<Vec<String>>,
}

/// The shared `nitr.cache` (`[cache]` section).
///
/// Bounded and owned by Rust, so it is shared *data* rather than shared
/// *state*: entries are serialized on the way in, no Lua value crosses
/// between states, and the memory cannot grow past these limits.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    /// Maximum number of live entries; the least recently used is evicted
    /// past this.
    pub max_entries: usize,
    /// Maximum total size of the stored values, in bytes.
    pub max_bytes: u64,
    /// Seconds an entry lives when `set` does not say. `0` means no
    /// expiry, leaving eviction entirely to the size bounds.
    pub default_ttl: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_bytes: 32 * 1024 * 1024, // 32 MiB
            default_ttl: 300,
        }
    }
}

/// Response compression (`[compression]` section).
///
/// Off by default: compression turns a CPU-cheap server into a
/// CPU-spending one, and that should be a decision, not a surprise. One
/// line enables it. Precompressed sidecars (`app.js.br` next to `app.js`)
/// are served regardless of this section — they cost nothing at runtime.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompressionConfig {
    /// Whether responses are compressed on the fly.
    pub enabled: bool,
    /// Algorithms offered, best first. Valid names: `"br"`, `"gzip"`.
    pub algorithms: Vec<String>,
    /// Responses smaller than this are sent uncompressed: below roughly a
    /// packet, compression costs more than it saves.
    pub min_size: u64,
    /// Content types to compress. A trailing `*` matches a prefix, so
    /// `"text/*"` covers every text subtype. Already-compressed types
    /// (images, video, archives) are skipped even when listed.
    pub types: Vec<String>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithms: vec!["br".into(), "gzip".into()],
            min_size: 1024,
            types: [
                "text/*",
                "application/json",
                "application/javascript",
                "application/xml",
                "image/svg+xml",
            ]
            .map(String::from)
            .to_vec(),
        }
    }
}

/// Cross-origin resource sharing (`[cors]` section).
///
/// Enforced in Rust: a preflight never reaches a Lua state, and the policy
/// is auditable in one place instead of spread across middleware.
/// Disabled until `origins` is set.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CorsConfig {
    /// Allowed origins, or `["*"]` for any. Unset disables CORS entirely.
    pub origins: Option<Vec<String>>,
    /// Methods allowed on cross-origin requests.
    pub methods: Option<Vec<String>>,
    /// Request headers a preflight may approve.
    pub headers: Option<Vec<String>>,
    /// Response headers scripts on other origins may read.
    pub expose_headers: Option<Vec<String>>,
    /// Allow credentialed requests (cookies, `Authorization`). Cannot be
    /// combined with `origins = ["*"]`.
    pub credentials: bool,
    /// How long (seconds) a browser may cache a preflight result.
    pub max_age: Option<u64>,
}

/// Per-client-IP fixed-window rate limiting (`[rate_limit]` section).
/// Disabled by default; rejections answer 429 with a `Retry-After` header.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enforced.
    pub enabled: bool,
    /// Allowed requests per window and client IP.
    pub requests: u32,
    /// Window length in seconds.
    pub window: u64,
    /// Key the budget by the first `X-Forwarded-For` entry instead of the
    /// peer address. Enable only behind a trusted proxy.
    pub trust_forwarded_for: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests: 100,
            window: 60,
            trust_forwarded_for: false,
        }
    }
}

/// Inbound TLS termination (`[tls]` section), served by rustls over the
/// `ring` crypto provider.
///
/// Off by default, and deliberately not inferred from the presence of a
/// certificate: turning a port from plaintext to TLS is a decision an
/// operator makes, not one a stray file makes for them. When it *is* on,
/// both paths are required — a half-configured `[tls]` fails at startup
/// rather than at the first connection, where the failure would look like
/// a network problem.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Whether the listener speaks TLS.
    pub enabled: bool,
    /// PEM file holding the server certificate, leaf first, followed by
    /// any intermediates a client needs to build the chain.
    pub cert: Option<PathBuf>,
    /// PEM file holding the matching private key (PKCS#8, PKCS#1 or
    /// SEC1). Read once at startup and never again.
    pub key: Option<PathBuf>,
    /// Oldest protocol version accepted: `"1.2"` or `"1.3"`. Unset means
    /// the floor, TLS 1.2, which is what a public endpoint wants;
    /// `"1.3"` is for a closed set of clients known to speak it.
    ///
    /// The floor cannot be lowered. TLS 1.0 and 1.1 are deprecated
    /// (RFC 8996) and are not settings this server offers under any
    /// spelling — see [`TLS_MIN_VERSIONS`].
    pub min_version: Option<String>,
}

/// Every protocol version `[tls] min_version` may name, weakest first.
///
/// `"1.2"` is the floor and the default: TLS 1.0 and 1.1 are deprecated
/// by RFC 8996, rustls implements neither, and accepting the spelling
/// would promise a downgrade no build here can — or should — keep. This
/// list is the whole vocabulary; a name outside it is a startup refusal,
/// not a silent fallback.
pub(crate) const TLS_MIN_VERSIONS: [&str; 2] = ["1.2", "1.3"];

/// Lua runtime settings (`[lua]` section).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LuaConfig {
    /// Lua standard libraries loaded into every state.
    pub stdlib: Vec<String>,
    /// Per-state Lua memory limit in bytes.
    pub memory_limit: usize,
    /// Wall-clock budget per handler invocation, in milliseconds; `0`
    /// disables the limit. Enforced by an instruction-count hook (CPU-bound
    /// loops) and an outer async timeout (slow I/O).
    pub exec_timeout_ms: u64,
}

impl Default for LuaConfig {
    fn default() -> Self {
        Self {
            // `io` and `os` are deliberately excluded: they give scripts
            // ambient filesystem/process access. Opt in via `[lua] stdlib`.
            stdlib: ["math", "table", "string", "utf8", "coroutine", "package"]
                .map(String::from)
                .to_vec(),
            memory_limit: DEFAULT_MEMORY_LIMIT,
            exec_timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
        }
    }
}

impl LuaConfig {
    /// Parses the stdlib names into [`mlua::StdLib`] flags.
    pub fn parse_stdlib(&self) -> Result<mlua::StdLib> {
        use mlua::StdLib;
        let mut libs = StdLib::NONE;
        for name in &self.stdlib {
            libs |= match name.as_str() {
                "coroutine" => StdLib::COROUTINE,
                "table" => StdLib::TABLE,
                "io" => StdLib::IO,
                "os" => StdLib::OS,
                "string" => StdLib::STRING,
                "utf8" => StdLib::UTF8,
                "math" => StdLib::MATH,
                "package" => StdLib::PACKAGE,
                "debug" => StdLib::DEBUG,
                _ => {
                    return Err(Error::Config(format!(
                        "unknown Lua standard library `{name}`"
                    )));
                }
            };
        }
        Ok(libs)
    }
}
