// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The multipart layer over arbitrary bodies and content types: boundary
//! extraction, the part-count cap, and the per-field byte cap applied
//! while reading — the same loop `req:multipart()` runs, minus Lua and
//! disk (see `consume_for_fuzzing`).
//!
//! Invariants: never panic, never hang (libfuzzer's timeout would say
//! so), and when the walk succeeds the part count respects the cap.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
    })
}

fuzz_target!(|input: (&str, &[u8])| {
    let (content_type, body) = input;
    const MAX_PARTS: usize = 4;
    const MAX_FIELD_BYTES: u64 = 256;

    let body = bytes::Bytes::copy_from_slice(body);
    let outcome = runtime().block_on(nitr_http::fuzzing::consume_multipart(
        Some(content_type),
        body,
        MAX_PARTS,
        MAX_FIELD_BYTES,
    ));
    if let Ok(parts) = outcome {
        assert!(parts <= MAX_PARTS, "{parts} parts admitted past the cap");
    }
});
