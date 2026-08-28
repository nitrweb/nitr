// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The Nitr HTTP server layer: hyper server and builder, configuration,
//! and the request/response bridge between HTTP and the Lua runtime.

// Lint policy comes from `[workspace.lints]` in the root Cargo.toml.
// `unwrap_used`/`expect_used` are denied here (not in the workspace table,
// which would also hit test and bench targets); unit tests are exempt, and
// the few documented-invariant `expect()`s carry targeted allows.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub(crate) mod app;
pub(crate) mod compress;
pub(crate) mod config;
pub(crate) mod cors;
pub(crate) mod handler;
pub(crate) mod health;
#[cfg(feature = "multipart")]
pub(crate) mod multipart;
pub(crate) mod protect;
pub(crate) mod range;
pub(crate) mod request;
pub(crate) mod server;
pub(crate) mod static_files;
pub(crate) mod stream;
pub(crate) mod watch;

pub mod testing;

/// Internal functions exposed for the fuzz targets in `fuzz/` only.
/// Not part of the public API; no stability promise applies here.
#[doc(hidden)]
pub mod fuzzing {
    pub use crate::compress::{Compression, Encoding, parse_accept_encoding};
    #[cfg(feature = "multipart")]
    pub use crate::multipart::consume_for_fuzzing as consume_multipart;
    pub use crate::range::{
        Resolved, if_range_matches, parse as parse_range, resolve as resolve_range,
    };
    pub use crate::request::is_fresh;
    pub use crate::static_files::{StaticMount, resolve_for_fuzzing as resolve_static};
}

/// The hyper `Service` dispatching requests to the Lua pool.
pub mod service;

pub use config::{
    CacheConfig, CompressionConfig, Config, CorsConfig, DatabaseConfig, FetchConfig, HealthConfig,
    LimitsConfig, LogConfig, LogFormat, LuaConfig, RateLimitConfig, ShutdownConfig, StaticConfig,
    StdConfig,
};
pub use server::{Server, ServerBuilder};
