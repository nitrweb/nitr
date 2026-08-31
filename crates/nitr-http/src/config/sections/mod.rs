// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The per-section configuration structs of `nitr.toml` and their
//! defaults; everything except `[database]`, which has its own module.

mod features;
mod runtime;
mod server;

pub use features::*;
pub use runtime::*;
pub use server::*;
