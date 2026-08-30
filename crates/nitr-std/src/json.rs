// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use mlua::{
    AnyUserData, ExternalResult, Lua, LuaSerdeExt, LuaString, MetaMethod, Table, UserData,
    UserDataMethods, Value,
};
use serde_json::Value as SerdeValue;

#[derive(Default)]
pub(crate) struct LuaJson;

impl UserData for LuaJson {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method_mut("encode", |lua, _, input: Value| {
            crate::utils::check_json_bounds(&input)?;
            let s = serde_json::to_string(&input).into_lua_err()?;
            lua.to_value(&s)
        });

        methods.add_method_mut("decode", |lua, _, input: LuaString| {
            // serde_json's default recursion limit (128) is load-bearing
            // here: it is what stops hostile deeply nested input from
            // overflowing the stack, with an ordinary error, before
            // `lua.to_value` walks the tree. It also mirrors
            // `MAX_JSON_DEPTH` on the encode side, so the two directions
            // share one bound. Never enable `serde_json`'s
            // `unbounded_depth` / disable that limit; a regression test
            // pins the 129-deep rejection.
            let v = serde_json::from_slice::<SerdeValue>(&input.as_bytes()).into_lua_err()?;
            lua.to_value(&v)
        });

        // Calling the userdata itself — `json({ ... })` — is the JSON
        // response helper: it returns a `{status, headers, body}` table.
        methods.add_meta_method(
            MetaMethod::Call,
            |lua, _, (value, status): (Value, Option<u16>)| {
                crate::utils::check_json_bounds(&value)?;
                let body = serde_json::to_string(&value).into_lua_err()?;
                let table = crate::http::response_table(lua, status.unwrap_or(200))?;
                table
                    .get::<Table>("headers")?
                    .set("Content-Type", "application/json")?;
                table.set("body", body)?;
                Ok(table)
            },
        );
    }
}

/// JSON encode function via Serde.
pub fn create_json_fn(lua: &Lua) -> mlua::Result<AnyUserData> {
    lua.create_userdata(LuaJson)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::ObjectLike as _;

    #[test]
    fn encodes_decodes_and_builds_responses() {
        let lua = Lua::new();
        let json = create_json_fn(&lua).expect("json");
        let decoded: Table = json
            .call_method("decode", r#"{"a": 1, "b": [true, "x"]}"#)
            .expect("decode");
        assert_eq!(decoded.get::<i64>("a").expect("a"), 1);
        let encoded: String = json.call_method("encode", decoded).expect("encode");
        let value: SerdeValue = serde_json::from_str(&encoded).expect("parse");
        assert_eq!(value["b"][1], "x");

        // `json(value, status?)` is the response helper.
        let resp: Table = json
            .call((lua.create_table().expect("t"), 201))
            .expect("call");
        assert_eq!(resp.get::<u16>("status").expect("status"), 201);
    }

    /// A JSON tree without the shapes Lua cannot represent faithfully:
    /// no nulls (nil erases table entries) and no empty containers (an
    /// empty Lua table is ambiguous between `{}` and `[]`).
    fn json_value() -> impl proptest::prelude::Strategy<Value = SerdeValue> {
        use proptest::prelude::*;
        let leaf = prop_oneof![
            any::<bool>().prop_map(SerdeValue::from),
            // The full i64 domain: Lua 5.4 integers are 64-bit, so the
            // extremes must survive the trip exactly.
            any::<i64>().prop_map(SerdeValue::from),
            // Arbitrary Unicode, not just printable ASCII: JSON escapes,
            // multi-byte sequences, and control characters all ride
            // through Lua strings (which are plain byte strings).
            "\\PC{0,20}".prop_map(SerdeValue::from),
        ];
        leaf.prop_recursive(3, 24, 4, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 1..4).prop_map(SerdeValue::from),
                proptest::collection::btree_map("[a-z]{1,6}", inner, 1..4)
                    .prop_map(|m| SerdeValue::Object(m.into_iter().collect())),
            ]
        })
    }

    /// A chain of `depth` nested Lua tables (the root included).
    fn deep_table(lua: &Lua, depth: usize) -> Value {
        let root = lua.create_table().expect("table");
        let mut cur = root.clone();
        for _ in 1..depth {
            let next = lua.create_table().expect("table");
            cur.set("x", next.clone()).expect("set");
            cur = next;
        }
        Value::Table(root)
    }

    /// The abort this pins: encoding used to recurse without limit, and a
    /// deep-enough table chain overflowed the Rust stack — a process
    /// kill no panic boundary can contain (verified as SIGABRT at
    /// ~30,000 levels before the guard existed).
    #[test]
    fn encode_rejects_values_nested_beyond_the_depth_bound() {
        let lua = Lua::new();
        let json = create_json_fn(&lua).expect("json");

        let ok: String = json
            .call_method("encode", deep_table(&lua, 128))
            .expect("128 levels encode");
        assert!(ok.starts_with('{'));

        for depth in [129usize, 4096] {
            let err = json
                .call_method::<String>("encode", deep_table(&lua, depth))
                .expect_err("too deep");
            assert!(
                err.to_string().contains("nested deeper than 128 levels"),
                "depth {depth}: {err}"
            );
        }

        // The JSON response helper shares the guard.
        let err = json
            .call::<Table>((deep_table(&lua, 129), 200))
            .expect_err("deep response body");
        assert!(err.to_string().contains("nested deeper"), "got: {err}");
    }

    /// serde_json's default deserialization recursion limit is a
    /// load-bearing part of the contract (see the comment at `decode`):
    /// 128 levels parse, 129 fail with an ordinary error.
    #[test]
    fn decode_depth_limit_is_load_bearing() {
        let lua = Lua::new();
        let json = create_json_fn(&lua).expect("json");

        let ok = format!("{}1{}", "[".repeat(127), "]".repeat(127));
        json.call_method::<Value>("decode", ok).expect("127 deep");

        let too_deep = format!("{}1{}", "[".repeat(129), "]".repeat(129));
        let err = json
            .call_method::<Value>("decode", too_deep)
            .expect_err("129 deep");
        assert!(err.to_string().contains("recursion limit"), "got: {err}");
    }

    proptest::proptest! {
        /// Property: decode(encode(decode(json))) is a fixed point — a
        /// JSON document survives the trip through Lua values.
        #[test]
        fn prop_json_round_trips_through_lua(tree in json_value()) {
            // `prop_assert!` throughout (not `expect`), so a failing input
            // shrinks to a minimal counterexample instead of panicking on
            // the first monster proptest generated.
            let lua = Lua::new();
            let json = create_json_fn(&lua).expect("json");
            let text = serde_json::to_string(&tree).expect("serialize");
            let decoded = json.call_method::<Value>("decode", text);
            proptest::prop_assert!(decoded.is_ok(), "decode failed: {:?}", decoded.err());
            let encoded = json.call_method::<String>("encode", decoded.expect("checked"));
            proptest::prop_assert!(encoded.is_ok(), "encode failed: {:?}", encoded.err());
            let back = serde_json::from_str::<SerdeValue>(&encoded.expect("checked"));
            proptest::prop_assert!(back.is_ok(), "re-parse failed: {:?}", back.err());
            proptest::prop_assert_eq!(back.expect("checked"), tree);
        }

        /// Property: for any depth, encoding either succeeds (within the
        /// bound) or fails with the depth error (beyond it) — never
        /// anything else, and never a crash.
        #[test]
        fn prop_encode_depth_boundary_is_total(depth in 1usize..=160) {
            let lua = Lua::new();
            let json = create_json_fn(&lua).expect("json");
            let result = json.call_method::<String>("encode", deep_table(&lua, depth));
            if depth <= 128 {
                proptest::prop_assert!(result.is_ok(), "depth {} must encode", depth);
            } else {
                let err = result.expect_err("beyond the bound");
                proptest::prop_assert!(
                    err.to_string().contains("nested deeper than 128 levels"),
                    "depth {}: {}", depth, err
                );
            }
        }

    }

    // Its own block so it can carry its own case count. Cost here is
    // dominated by the top of the range — each high-level case walks the
    // full million-visit budget — and at proptest's default 256 cases
    // this single property ran for 63 seconds, long enough that proptest
    // logs a "running for over 60 seconds" warning and long enough to
    // make `cargo test` look hung. 32 cases still straddles the boundary
    // in both directions, which is what the property is about.
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

        /// Property: a shared-subtree value — shallow, but exponential in
        /// the work a tree walk does — either encodes or is refused by the
        /// node budget, never anything else and never a hang. The depth
        /// bound cannot be what refuses these: 22 levels is far inside it.
        #[test]
        fn prop_encode_shared_subtrees_are_total(levels in 1usize..=21) {
            let lua = Lua::new();
            let json = create_json_fn(&lua).expect("json");
            let result = json.call_method::<String>("encode", crate::utils::dag_table(&lua, levels));
            if let Err(err) = result {
                proptest::prop_assert!(
                    err.to_string().contains("expands to more than"),
                    "levels {}: {}", levels, err
                );
            }
        }
    }
}
