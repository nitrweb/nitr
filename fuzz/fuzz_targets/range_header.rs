// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The hand-written `Range` header parser, resolved against a length.
//!
//! Invariants: parsing is total (never panics), and every range it
//! accepts lies entirely within the representation — a `Partial` outside
//! `0..len` would make the static file server slice out of bounds.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nitr_http::fuzzing::{parse_range, Resolved};

fuzz_target!(|input: (&str, u64)| {
    let (header, len) = input;
    match parse_range(header, len) {
        Resolved::Partial { start, end } => {
            assert!(start <= end, "inverted range {start}..={end}");
            assert!(end < len, "range {start}..={end} beyond length {len}");
        }
        Resolved::Full | Resolved::Unsatisfiable => {}
    }
});
