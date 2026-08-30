// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

// Lint policy comes from `[workspace.lints]` in the root Cargo.toml.
// `unwrap_used`/`expect_used` are denied here (not in the workspace table,
// which would also hit test and bench targets); unit tests are exempt, and
// the few documented-invariant `expect()`s carry targeted allows.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Nitr: a Rust web server embedding Lua for fast, efficient and safe
//! dynamic backends.
//!
//! This crate is the facade over the Nitr workspace and the usual single
//! dependency for applications and embedders:
//!
//! - [`nitr-core`](nitr_core) — the sandboxed Lua runtime and pool,
//! - [`nitr-std`](stdlib) — the built-in `nitr.*` standard library
//!   (`nitr.json`, `nitr.fetch`, `nitr.db`, …),
//! - [`nitr-http`](nitr_http) — the hyper server, configuration, and the
//!   HTTP/Lua bridge.

// Extern crates
pub use nitr_core::diag;
pub use nitr_std as stdlib;

pub use nitr_http::service;
pub use nitr_http::testing;

// Re-exports
pub use nitr_core::{
    DeadlineHandle, Error, ModuleFn, Result, Runtime, RuntimeGuard, RuntimeOpts, RuntimePool,
    mount, nitr_table,
};
pub use nitr_http::{
    CacheConfig, CompressionConfig, Config, CorsConfig, DatabaseConfig, FetchConfig, HealthConfig,
    LimitsConfig, LogConfig, LogFormat, LuaConfig, MultipartConfig, RateLimitConfig, Server,
    ServerBuilder, ShutdownConfig, StdConfig, TlsConfig,
};
pub use nitr_std::{Builtins, BuiltinsEnv};
