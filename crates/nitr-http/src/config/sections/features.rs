// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Sections configuring builtin features: `[fetch]`, `[static]`,
//! `[templating]`, `[cookies]`, `[multipart]`, `[cache]`, `[compression]`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
    /// Serve files and directories whose name starts with `.` (default
    /// `false`). `.well-known/` is served regardless.
    pub dotfiles: bool,
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

/// When cookies Nitr builds carry the `Secure` attribute
/// (`[cookies] secure`).
///
/// Tri-state rather than a bool because the most common Nitr deployment —
/// a loopback bind behind a terminating proxy — needs `Secure` cookies
/// while `[tls] enabled = false` is the correct setting for this process.
/// A bool cannot express that without reading as a contradiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CookieSecure {
    /// `Secure` when `[tls] enabled = true`. Warns at boot when it
    /// resolves to *not* secure, since this cannot see a proxy in front.
    #[default]
    Auto,
    /// Always `Secure`: TLS is terminated in front of this process.
    Always,
    /// Never `Secure`: plain-HTTP development.
    Never,
}

impl CookieSecure {
    /// Resolves the policy against whether this process terminates TLS.
    pub fn resolve(self, tls_enabled: bool) -> bool {
        match self {
            Self::Auto => tls_enabled,
            Self::Always => true,
            Self::Never => false,
        }
    }
}

/// Cookie defaults (`[cookies]` section).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CookiesConfig {
    /// Default `Secure` attribute for cookies Nitr builds — the session
    /// and CSRF cookies, and anything through `res.cookies:set` /
    /// `:set_signed` — when the caller's own options table does not set
    /// `secure`. An explicit `secure` from Lua always wins, in both
    /// directions.
    ///
    /// This reaches only cookies Nitr *builds*. A handler that writes the
    /// header itself (`headers = { ["Set-Cookie"] = "a=1" }`) is converted
    /// straight through and never passes the serializer, so that cookie's
    /// attributes are the script's own responsibility.
    ///
    /// Deliberately not forced the way `HttpOnly` is: a `Secure` cookie
    /// sent over plain `http` is dropped by the browser without a word, so
    /// forcing it would break local development with a failure mode far
    /// worse than a startup line.
    pub secure: CookieSecure,
}

/// Filesystem policy for multipart uploads (`[multipart]` section).
///
/// The byte caps stay in [`LimitsConfig`] with every other byte cap; a
/// directory belongs beside `[static] dir` and `[templating] dir`.
///
/// Parsed in every build, including one without the `multipart` feature —
/// the same reason `FormLimits` carries its values there. A configuration
/// file that stops being readable depending on how the binary was compiled
/// is not portable.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MultipartConfig {
    /// Root directory that every `part:save(path)` resolves inside.
    ///
    /// Unset leaves `part:save` unavailable, the same call `[templating]
    /// dir` makes: there is no safe directory to guess, and an upload
    /// written somewhere nobody chose is worse than a startup error.
    /// Relative paths resolve against the working directory. Must exist
    /// and be writable at startup.
    ///
    /// Paths handed to `part:save` are relative to this directory;
    /// absolute paths and anything climbing out with `..` are refused
    /// rather than re-rooted, so the on-disk location always follows from
    /// the source.
    pub upload_dir: Option<PathBuf>,
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
