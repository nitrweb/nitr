// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Sections for the listener and its protections: `[health]`, `[log]`,
//! `[limits]`, `[shutdown]`, `[cors]`, `[rate_limit]`, `[tls]`.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
    /// Connection cap for the separate probe listener (`bind`), deliberately
    /// far below `[limits] max_connections`: a prober opens one connection,
    /// not a thousand, and inheriting the main cap would let the probe port
    /// consume the process's whole file-descriptor budget on its own.
    /// Ignored when the probes answer on the main listener, which has its
    /// own cap.
    pub max_connections: usize,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            liveness: "/healthz".into(),
            readiness: "/readyz".into(),
            bind: None,
            max_connections: 64,
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
    /// Key the budget by the **last** `X-Forwarded-For` entry — the
    /// address the proxy in front appended, i.e. the client it accepted
    /// the connection from — instead of the peer address. Enable only
    /// behind a trusted proxy. The last entry is the right one whether
    /// the proxy overwrites the header or (as nginx, Caddy, Traefik and
    /// HAProxy do by default) appends to whatever the client sent; the
    /// first entry is client-written and would hand every request a
    /// fresh budget. With more than one proxy hop the budget keys by the
    /// nearest hop's client, not the origin client.
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
    /// SEC1). Read at startup and again on each reload (`SIGHUP`), which
    /// swaps in renewed material only when the pair validates.
    pub key: Option<PathBuf>,
    /// Oldest protocol version accepted: `"1.2"` or `"1.3"`. Unset means
    /// the floor, TLS 1.2, which is what a public endpoint wants;
    /// `"1.3"` is for a closed set of clients known to speak it.
    ///
    /// The floor cannot be lowered. TLS 1.0 and 1.1 are deprecated
    /// (RFC 8996) and are not settings this server offers under any
    /// spelling — see [`TLS_MIN_VERSIONS`].
    pub min_version: Option<String>,
    /// Deadline for the TLS handshake itself, in milliseconds. Unset
    /// means `min(header_read_ms, 10s)` — and when `[limits]
    /// header_read_ms` is `0` (disabled), simply 10 s. `0` here is a
    /// startup error, never "unbounded": the handshake happens before
    /// hyper's header machinery exists, so a stalled `ClientHello` holds
    /// a connection slot the header deadline can never reclaim, and 1024
    /// of them close the listener. The header read and the handshake are
    /// different waits on different protocol phases; a streaming
    /// deployment that relaxes the first says nothing about the second.
    pub handshake_ms: Option<u64>,
}

/// Every protocol version `[tls] min_version` may name, weakest first.
///
/// `"1.2"` is the floor and the default: TLS 1.0 and 1.1 are deprecated
/// by RFC 8996, rustls implements neither, and accepting the spelling
/// would promise a downgrade no build here can — or should — keep. This
/// list is the whole vocabulary; a name outside it is a startup refusal,
/// not a silent fallback.
pub(crate) const TLS_MIN_VERSIONS: [&str; 2] = ["1.2", "1.3"];
