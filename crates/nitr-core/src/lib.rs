// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The resource-controlled Lua runtime at the heart of Nitr: sandboxed
//! states with memory/execution limits and the fixed runtime pool.
//!
//! This crate is deliberately free of HTTP, database, and template
//! dependencies so it can be embedded on its own; the `nitr` facade crate
//! is the usual entrypoint for applications.

// Lint policy comes from `[workspace.lints]` in the root Cargo.toml.
// `unwrap_used`/`expect_used` are denied here (not in the workspace table,
// which would also hit test and bench targets); unit tests are exempt, and
// the few documented-invariant `expect()`s carry targeted allows.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod diag;
mod error;
pub mod ns;
mod runtime;

pub use error::{Error, ErrorInfo, Result, message_token, source_snippet};
pub use ns::{ModuleFn, mount, nitr_table};
pub use runtime::{DeadlineHandle, Runtime, RuntimeGuard, RuntimeOpts, RuntimePool};
