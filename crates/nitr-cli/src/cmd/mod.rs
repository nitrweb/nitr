// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! One module per `nitr` subcommand implementation; `main.rs` keeps only
//! argument parsing, configuration loading, and dispatch.

pub(crate) mod check;
pub(crate) mod migrate;
pub(crate) mod test;
