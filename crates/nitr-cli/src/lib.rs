// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Library side of the `nitr` binary.
//!
//! Exists so the API-description module compiles once and is shared by the
//! binary and its drift test as an ordinary dependency — previously the
//! test `#[path]`-included the source file, compiling it twice and forcing
//! `#[allow(dead_code)]` on whichever half each target did not use.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

// Internal single source for the generated `nitr.*` API artifacts; not a
// public API of the `nitr-cli` crate (no stability promise applies).
#[doc(hidden)]
pub mod apidef;
