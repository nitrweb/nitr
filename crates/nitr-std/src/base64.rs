// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Base64 encoding and decoding for Lua handlers: `nitr.base64`.
//!
//! One careful implementation instead of one per application: scripts
//! meet base64 constantly (Authorization headers, webhook payloads, data
//! URLs, binary values that must travel in JSON), and a hand-rolled
//! decoder is where padding and alphabet bugs live.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use mlua::{Lua, Table, Value};

/// Whether the call asked for the URL-safe alphabet (`{ url = true }`).
fn wants_url(opts: Option<&Table>) -> mlua::Result<bool> {
    Ok(match opts {
        Some(opts) => opts.get::<Option<bool>>("url")?.unwrap_or(false),
        None => false,
    })
}

/// Builds the `nitr.base64` table.
pub(crate) fn create_base64_table(lua: &Lua) -> mlua::Result<Table> {
    let base64 = lua.create_table()?;

    // encode(data, { url = true }?) — standard alphabet with padding by
    // default; the URL-safe variant is unpadded, matching how it is used
    // in cookies, JWTs and URLs.
    base64.set(
        "encode",
        lua.create_function(|lua, (data, opts): (mlua::LuaString, Option<Table>)| {
            let encoded = if wants_url(opts.as_ref())? {
                URL_SAFE_NO_PAD.encode(data.as_bytes())
            } else {
                STANDARD.encode(data.as_bytes())
            };
            lua.create_string(encoded)
        })?,
    )?;

    // decode(value, { url = true }?) -> data, nil | nil, reason
    //
    // Forgiving about padding (real-world producers disagree on it), never
    // about the alphabet.
    base64.set(
        "decode",
        lua.create_function(|lua, (value, opts): (mlua::LuaString, Option<Table>)| {
            let value = value.as_bytes();
            let decoded = if wants_url(opts.as_ref())? {
                URL_SAFE_NO_PAD
                    .decode(&*value)
                    .or_else(|_| URL_SAFE.decode(&*value))
            } else {
                STANDARD
                    .decode(&*value)
                    .or_else(|_| STANDARD_NO_PAD.decode(&*value))
            };
            match decoded {
                Ok(decoded) => Ok((Value::String(lua.create_string(decoded)?), Value::Nil)),
                Err(_) => Ok((
                    Value::Nil,
                    Value::String(lua.create_string("invalid base64")?),
                )),
            }
        })?,
    )?;

    Ok(base64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(lua: &Lua) -> Table {
        create_base64_table(lua).expect("table")
    }

    #[test]
    fn encodes_and_decodes_both_alphabets() {
        let lua = Lua::new();
        let b64 = table(&lua);
        let encode: mlua::Function = b64.get("encode").expect("fn");
        let decode: mlua::Function = b64.get("decode").expect("fn");
        let url_opts = || -> Table { lua.load("{ url = true }").eval().expect("opts") };

        let encoded: String = encode.call("hello world").expect("encode");
        assert_eq!(encoded, "aGVsbG8gd29ybGQ=");
        let (decoded, err): (Option<String>, Option<String>) =
            decode.call(encoded).expect("decode");
        assert_eq!((decoded.as_deref(), err), (Some("hello world"), None));

        // The URL-safe variant is unpadded and swaps `+/` for `-_`.
        let binary = lua.create_string(b"\xfb\xff\xbe").expect("bytes");
        let encoded: String = encode.call((&binary, url_opts())).expect("encode");
        assert_eq!(encoded, "-_--");
        let (decoded, _): (Option<mlua::LuaString>, Option<String>) =
            decode.call((encoded, url_opts())).expect("decode");
        assert_eq!(
            decoded.expect("decoded").as_bytes().as_ref(),
            b"\xfb\xff\xbe"
        );

        // The empty string round-trips in both directions.
        let encoded: String = encode.call("").expect("encode");
        assert_eq!(encoded, "");
        let (decoded, err): (Option<String>, Option<String>) = decode.call("").expect("decode");
        assert_eq!((decoded.as_deref(), err), (Some(""), None));

        // The alphabets are not interchangeable: standard `+/` output is
        // rejected under `{ url = true }` and vice versa.
        let binary = lua.create_string(b"\xfb\xff\xbe").expect("bytes");
        let standard: String = encode.call(&binary).expect("encode");
        assert_eq!(standard, "+/++");
        let (decoded, _): (Option<String>, Option<String>) =
            decode.call((standard, url_opts())).expect("decode");
        assert_eq!(decoded, None);
        let (decoded, _): (Option<String>, Option<String>) = decode.call("-_--").expect("decode");
        assert_eq!(decoded, None);

        // Padding is forgiven on decode, the alphabet is not.
        let (decoded, _): (Option<String>, Option<String>) =
            decode.call("aGVsbG8").expect("decode");
        assert_eq!(decoded.as_deref(), Some("hello"));
        let (decoded, err): (Option<String>, Option<String>) =
            decode.call("not base64!").expect("decode");
        assert_eq!(decoded, None);
        assert_eq!(err.as_deref(), Some("invalid base64"));
    }

    proptest::proptest! {
        /// Property: decode(encode(bytes)) is the identity for arbitrary
        /// bytes, in both alphabets.
        #[test]
        fn prop_bytes_round_trip_in_both_alphabets(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
            url in proptest::prelude::any::<bool>(),
        ) {
            let lua = Lua::new();
            let b64 = table(&lua);
            let encode: mlua::Function = b64.get("encode").expect("fn");
            let decode: mlua::Function = b64.get("decode").expect("fn");
            let input = lua.create_string(&data).expect("bytes");
            let opts: Table = lua.create_table().expect("opts");
            opts.set("url", url).expect("set");
            let encoded: String = encode.call((&input, &opts)).expect("encode");
            let (decoded, err): (Option<mlua::LuaString>, Option<String>) =
                decode.call((encoded, &opts)).expect("decode");
            proptest::prop_assert_eq!(err, None);
            let decoded = decoded.expect("decoded");
            let bytes = decoded.as_bytes();
            proptest::prop_assert_eq!(bytes.as_ref(), &data[..]);
        }
    }
}
