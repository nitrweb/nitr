// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The JSON↔Lua boundary, both directions, depth guard included.
//!
//! Invariants: arbitrary bytes either decode or error (never panic, never
//! recurse to an abort — serde_json's deserialization recursion limit is
//! load-bearing); anything that *did* decode re-encodes successfully
//! (its depth is within the shared bound by construction); and a chain of
//! arbitrary depth either encodes (≤ 128) or reports the depth error —
//! the phase-24 guard that closed a script-reachable stack-overflow
//! SIGABRT.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mlua::ObjectLike as _;

thread_local! {
    // One state per thread, reused across runs: building a Lua VM per
    // input caps throughput at a few hundred execs/s. Collect between
    // runs so decoded garbage cannot masquerade as a leak.
    static LUA: mlua::Lua = mlua::Lua::new();
}

fuzz_target!(|input: (&[u8], u16)| {
    let (bytes, depth) = input;
    LUA.with(|lua| {
        let json = nitr_std::fuzzing::create_json_fn(lua).expect("json userdata");

        // Decode direction: parse-or-error over arbitrary bytes.
        let text = lua.create_string(bytes).expect("byte string");
        if let Ok(decoded) = json.call_method::<mlua::Value>("decode", text) {
            // What decoded is bounded, so it must encode.
            json.call_method::<String>("encode", decoded)
                .expect("a decoded value must re-encode");
        }

        // Encode direction: a nested chain of arbitrary depth is either fine
        // or the depth error — never anything else, never a crash.
        // 1..=256 crosses the 128 boundary from both sides without paying
        // for thousands of tables per run.
        let depth = usize::from(depth) % 256 + 1;
        let root = lua.create_table().expect("table");
        let mut cur = root.clone();
        for _ in 1..depth {
            let next = lua.create_table().expect("table");
            cur.set("x", next.clone()).expect("set");
            cur = next;
        }
        match json.call_method::<String>("encode", mlua::Value::Table(root)) {
            Ok(_) => assert!(depth <= 128, "depth {depth} must have been refused"),
            Err(err) => {
                assert!(depth > 128, "depth {depth} must encode, got: {err}");
                assert!(
                    err.to_string().contains("nested deeper"),
                    "wrong error at depth {depth}: {err}"
                );
            }
        }
        lua.gc_collect().expect("gc");
    });
});
