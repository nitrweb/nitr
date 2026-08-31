// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Plain-data configuration types shared with the server layer.
//!
//! These live outside the modules that implement them, and outside every
//! Cargo feature, on purpose: the shape of `nitr.toml` must not depend on
//! which builtins a particular build compiled in. A server built without
//! the `db` feature still parses a `[database]` section — it just refuses
//! to enable the builtin, with a message saying so, instead of failing to
//! recognize the configuration at all.

use std::time::Duration;

/// Policy and limits applied to every outbound `fetch` request.
///
/// None of this is reachable from Lua: a script declares intent (a timeout,
/// a retry count) but cannot widen its own policy or uncap its budget.
#[derive(Debug, Clone)]
pub struct FetchOptions {
    /// When set, only these exact host names may be fetched (compared
    /// case-insensitively; applies to every redirect hop).
    pub allowed_hosts: Option<Vec<String>>,
    /// Allow requests to loopback/private/link-local addresses. Off by
    /// default; enable for trusted internal aggregation.
    pub allow_private_networks: bool,
    /// Maximum response body size accumulated by `resp:text()` /
    /// `resp:json()`, in bytes.
    pub max_response_bytes: u64,
    /// Maximum concurrent requests per `await_all(...)` call.
    pub max_concurrent: usize,
    /// Maximum outbound requests one inbound request may make in total.
    /// `0` removes the cap.
    pub max_per_request: u32,
    /// How long to wait for a TCP/TLS connection to an upstream.
    pub connect_timeout: Duration,
    /// Default total budget per outbound request.
    pub timeout: Duration,
    /// Idle connections kept per upstream host.
    pub pool_max_idle_per_host: usize,
    /// Ceiling on the `retry.attempts` a call may ask for.
    pub max_retries: u32,
    /// Explicit proxy URL; `None` uses the environment variables unless
    /// [`no_proxy`](Self::no_proxy) is set.
    pub proxy: Option<String>,
    /// Ignore the proxy environment variables.
    pub no_proxy: bool,
    /// Forward a W3C `traceparent` derived from the inbound request id.
    pub propagate_trace_context: bool,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            allowed_hosts: None,
            allow_private_networks: false,
            max_response_bytes: 8 * 1024 * 1024, // 8 MiB
            max_concurrent: 8,
            max_per_request: 32,
            connect_timeout: Duration::from_secs(10),
            timeout: Duration::from_secs(30),
            pool_max_idle_per_host: 8,
            max_retries: 5,
            proxy: None,
            no_proxy: false,
            propagate_trace_context: false,
        }
    }
}

/// Read policy for the `nitr.env` builtin.
///
/// The builtin itself is opt-in (`[std] features`); this narrows what an
/// enabled one may see. `NITR_*` variables are hidden from scripts
/// unconditionally — they configure the server, not the application.
#[derive(Debug, Clone, Default)]
pub struct EnvOptions {
    /// Names scripts may read: exact names, or prefixes written with a
    /// trailing `_` (`"APP_"`). `None` allows every non-`NITR_*` variable.
    pub allow: Option<Vec<String>>,
}

/// The pragma set applied to a connection when it is opened.
#[derive(Debug, Clone)]
pub struct SqlitePragmas {
    /// `"wal"`, `"delete"`, any other SQLite journal mode, or `"keep"` to
    /// leave whatever the database already uses.
    pub journal_mode: String,
    /// Milliseconds to wait on a locked database before failing.
    pub busy_timeout: u64,
    /// `synchronous` pragma (`"off"`, `"normal"`, `"full"`, `"extra"`).
    pub synchronous: String,
    /// Enforce foreign-key constraints.
    pub foreign_keys: bool,
    /// `cache_size` per connection; negative values are KiB.
    pub cache_size: i64,
}

impl Default for SqlitePragmas {
    fn default() -> Self {
        Self {
            journal_mode: "wal".into(),
            busy_timeout: 5_000,
            synchronous: "normal".into(),
            foreign_keys: true,
            cache_size: -2_000,
        }
    }
}

/// Upper bound on a password handed to `password_hash`/`password_verify`,
/// in bytes — the argon2 input cap, checked before any hashing work.
///
/// Defined here, outside the `crypto` feature, for the same reason the
/// configuration types are: the *shape* of the surface (the CLI's stdin
/// cap, `nitr.crypto.max_password_bytes` as data) must not depend on
/// which features a binary compiled in. The full rationale for the value
/// lives on the `crypto::password` module that enforces it.
pub const MAX_PASSWORD_BYTES: usize = 1024;
