// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! URL utilities for Lua handlers: `nitr.url`.
//!
//! Percent-encoding, query strings, and a lexical URL splitter — the
//! pieces scripts otherwise hand-roll with `string.gsub` and get subtly
//! wrong (the `+`-versus-`%20` distinction, double-decoding, forgetting
//! that a fragment is not sent to the server).
//!
//! `parse` is an RFC 3986 *splitter*: it separates the components of a
//! well-formed URL and does not normalize, resolve, or validate hosts the
//! way a browser (WHATWG) parser would. For fetching, `nitr.fetch`
//! performs its own strict parsing; this is for reading and building.

use mlua::{Lua, LuaString, Table, Value};
use percent_encoding::{
    AsciiSet, NON_ALPHANUMERIC, percent_decode, percent_encode, utf8_percent_encode,
};

/// Component encoding: everything except ASCII alphanumerics and the RFC
/// 3986 unreserved marks `-_.~` — the `encodeURIComponent` behavior.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Decodes one `application/x-www-form-urlencoded` token: `+` is a space,
/// then percent-decoding. Bytes, as `decode` gives them: a Lua string is
/// bytes, and a value that is not UTF-8 is still the value.
fn form_decode(s: &[u8]) -> Vec<u8> {
    let plus_replaced: Vec<u8> = s
        .iter()
        .map(|&b| if b == b'+' { b' ' } else { b })
        .collect();
    percent_decode(&plus_replaced).collect()
}

/// Splits `authority` into (userinfo, host, port text), tolerating IPv6
/// bracket notation. The port is the digits after the last colon when
/// there are any; the caller decides whether they are a port.
fn split_authority(authority: &str) -> (Option<&str>, &str, Option<&str>) {
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((user, rest)) => (Some(user), rest),
        None => (None, authority),
    };
    // `[::1]:8080` — the colon that matters is after the bracket.
    let (host, port) = if let Some(rest) = host_port.strip_prefix('[') {
        match rest.split_once(']') {
            Some((host, "")) => (host, None),
            Some((host, port)) => match port.strip_prefix(':') {
                Some(port) if port.chars().all(|c| c.is_ascii_digit()) => (host, Some(port)),
                _ => (host_port, None),
            },
            None => (host_port, None),
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => (host, Some(port)),
            _ => (host_port, None),
        }
    };
    (userinfo, host, port.filter(|p| !p.is_empty()))
}

/// Builds the `nitr.url` table.
pub fn create_url_table(lua: &Lua) -> mlua::Result<Table> {
    let url = lua.create_table()?;

    // Component encoding/decoding. `decode` does not treat `+` as a
    // space — that is a form/query convention, applied by `query_parse`.
    url.set(
        "encode",
        lua.create_function(|lua, value: String| {
            lua.create_string(utf8_percent_encode(&value, COMPONENT).to_string())
        })?,
    )?;
    url.set(
        "decode",
        lua.create_function(|lua, value: String| {
            lua.create_string(percent_decode(value.as_bytes()).collect::<Vec<u8>>())
        })?,
    )?;

    // query_parse("a=1&b=x+y") -> { a = "1", b = "x y" }; repeated keys
    // keep the last value, matching `req.query`.
    url.set(
        "query_parse",
        lua.create_function(|lua, query: LuaString| {
            let table = lua.create_table()?;
            let query = query.as_bytes();
            let query = query.strip_prefix(b"?").unwrap_or(&query);
            for pair in query.split(|&b| b == b'&').filter(|p| !p.is_empty()) {
                let (key, value) = match pair.iter().position(|&b| b == b'=') {
                    Some(at) => (&pair[..at], &pair[at + 1..]),
                    None => (pair, &b""[..]),
                };
                table.set(
                    lua.create_string(form_decode(key))?,
                    lua.create_string(form_decode(value))?,
                )?;
            }
            Ok(table)
        })?,
    )?;

    // query_build({ a = 1, b = "x y" }) -> "a=1&b=x%20y", keys sorted so
    // the output is deterministic (cacheable, comparable in tests).
    url.set(
        "query_build",
        lua.create_function(|_, params: Table| {
            let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            for pair in params.pairs::<Value, Value>() {
                let (key, value) = pair?;
                let key = match key {
                    Value::String(s) => s.as_bytes().to_vec(),
                    Value::Integer(n) => n.to_string().into_bytes(),
                    Value::Number(n) => n.to_string().into_bytes(),
                    other => {
                        return Err(mlua::Error::RuntimeError(format!(
                            "query keys must be strings or numbers, got {}",
                            other.type_name()
                        )));
                    }
                };
                let value = match value {
                    Value::String(s) => s.as_bytes().to_vec(),
                    Value::Integer(n) => n.to_string().into_bytes(),
                    Value::Number(n) => n.to_string().into_bytes(),
                    Value::Boolean(b) => b.to_string().into_bytes(),
                    other => {
                        return Err(mlua::Error::RuntimeError(format!(
                            "query values must be strings, numbers or booleans, got {}",
                            other.type_name()
                        )));
                    }
                };
                pairs.push((key, value));
            }
            pairs.sort();
            Ok(pairs
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}={}",
                        percent_encode(k, COMPONENT),
                        percent_encode(v, COMPONENT)
                    )
                })
                .collect::<Vec<_>>()
                .join("&"))
        })?,
    )?;

    // parse(url) -> { scheme?, userinfo?, host?, port?, path, query?,
    //   fragment? } | nil, reason
    url.set(
        "parse",
        lua.create_function(|lua, value: String| {
            if value.is_empty() {
                return Ok((Value::Nil, Value::String(lua.create_string("empty URL")?)));
            }
            let out = lua.create_table()?;
            let mut rest = value.as_str();

            // scheme ":" — a letter followed by [a-z0-9+.-], per RFC 3986.
            if let Some((scheme, after)) = rest.split_once(':')
                && scheme
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
            {
                out.set("scheme", scheme.to_ascii_lowercase())?;
                rest = after;
            }

            if let Some(after) = rest.strip_prefix("//") {
                let end = after.find(['/', '?', '#']).unwrap_or(after.len());
                let (userinfo, host, port) = split_authority(&after[..end]);
                if let Some(userinfo) = userinfo {
                    out.set("userinfo", userinfo)?;
                }
                out.set("host", host)?;
                if let Some(port) = port {
                    let Ok(port) = port.parse::<u16>() else {
                        return Ok((
                            Value::Nil,
                            Value::String(lua.create_string("port out of range")?),
                        ));
                    };
                    out.set("port", port)?;
                }
                rest = &after[end..];
            }

            if let Some((before, fragment)) = rest.split_once('#') {
                out.set("fragment", fragment)?;
                rest = before;
            }
            if let Some((path, query)) = rest.split_once('?') {
                out.set("query", query)?;
                rest = path;
            }
            out.set("path", rest)?;
            Ok((Value::Table(out), Value::Nil))
        })?,
    )?;

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(lua: &Lua) -> Table {
        create_url_table(lua).expect("table")
    }

    #[test]
    fn component_encoding_round_trips() {
        let lua = Lua::new();
        let url = table(&lua);
        let encode: mlua::Function = url.get("encode").expect("fn");
        let decode: mlua::Function = url.get("decode").expect("fn");

        let encoded: String = encode.call("a b/c?d=ñ").expect("encode");
        assert_eq!(encoded, "a%20b%2Fc%3Fd%3D%C3%B1");
        let decoded: String = decode.call(encoded).expect("decode");
        assert_eq!(decoded, "a b/c?d=ñ");
        // Unreserved marks pass through.
        let encoded: String = encode.call("a-b_c.d~e").expect("encode");
        assert_eq!(encoded, "a-b_c.d~e");
        // decode leaves `+` alone: that is a form convention.
        let decoded: String = decode.call("a+b").expect("decode");
        assert_eq!(decoded, "a+b");
    }

    #[test]
    fn query_strings_parse_and_build() {
        let lua = Lua::new();
        let url = table(&lua);
        let parse: mlua::Function = url.get("query_parse").expect("fn");
        let build: mlua::Function = url.get("query_build").expect("fn");

        let parsed: Table = parse.call("?a=1&b=x+y&c=%C3%B1&flag").expect("parse");
        assert_eq!(parsed.get::<String>("a").unwrap(), "1");
        assert_eq!(parsed.get::<String>("b").unwrap(), "x y");
        assert_eq!(parsed.get::<String>("c").unwrap(), "ñ");
        assert_eq!(parsed.get::<String>("flag").unwrap(), "");

        let params: Table = lua
            .load(r#"{ b = "x y", a = 1, ok = true }"#)
            .eval()
            .expect("params");
        let built: String = build.call(params).expect("build");
        assert_eq!(built, "a=1&b=x%20y&ok=true");
    }

    /// A Lua string is bytes: a key or value that is not UTF-8 is
    /// percent-encoded as its bytes and decoded back to them, as `decode`
    /// does, never replaced with U+FFFD.
    #[test]
    fn non_utf8_bytes_survive_query_build_and_parse() {
        let lua = Lua::new();
        lua.globals()
            .set("url", create_url_table(&lua).expect("url"))
            .expect("set");
        let built: String = lua
            .load(r#"return url.query_build({ ["k\xff"] = "v\xfe" })"#)
            .eval()
            .expect("build");
        assert_eq!(built, "k%FF=v%FE");
        let (key, value): (mlua::LuaString, mlua::LuaString) = lua
            .load(
                r#"local t = url.query_parse("k%FF=v%FE")
                   for k, v in pairs(t) do return k, v end"#,
            )
            .eval()
            .expect("parse");
        assert_eq!(&*key.as_bytes(), b"k\xff");
        assert_eq!(&*value.as_bytes(), b"v\xfe");
    }

    /// A port that is digits but not a port is a malformed URL, not a URL
    /// without a port.
    #[test]
    fn parse_refuses_a_port_out_of_range() {
        let lua = Lua::new();
        let url = create_url_table(&lua).expect("url");
        let parse: mlua::Function = url.get("parse").expect("fn");
        let (parsed, reason): (Value, Option<String>) =
            parse.call("http://example.com:99999/x").expect("parse");
        assert!(parsed.is_nil(), "{parsed:?}");
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("port")),
            "{reason:?}"
        );
    }

    #[test]
    fn query_build_rejects_unencodable_values() {
        let lua = Lua::new();
        let url = table(&lua);
        let build: mlua::Function = url.get("query_build").expect("fn");

        let params: Table = lua.load("{ f = function() end }").eval().expect("params");
        let err = build.call::<String>(params).expect_err("function value");
        assert!(err.to_string().contains("query values"), "got: {err}");

        // An empty table builds an empty query.
        let empty: Table = lua.load("{}").eval().expect("params");
        assert_eq!(build.call::<String>(empty).expect("build"), "");
    }

    #[test]
    fn query_parse_keeps_the_last_duplicate_and_empty_input() {
        let lua = Lua::new();
        let url = table(&lua);
        let parse: mlua::Function = url.get("query_parse").expect("fn");

        let parsed: Table = parse.call("a=1&a=2&a=3").expect("parse");
        assert_eq!(parsed.get::<String>("a").unwrap(), "3");

        let parsed: Table = parse.call("").expect("parse");
        assert_eq!(parsed.len().unwrap(), 0);
        let parsed: Table = parse.call("?").expect("parse");
        assert_eq!(parsed.len().unwrap(), 0);
    }

    #[test]
    fn parse_splits_the_components() {
        let lua = Lua::new();
        let url = table(&lua);
        let parse: mlua::Function = url.get("parse").expect("fn");

        let (parsed, err): (Table, Option<String>) = parse
            .call("https://user@api.example.com:8443/v1/items?page=2#top")
            .expect("parse");
        assert_eq!(err, None);
        assert_eq!(parsed.get::<String>("scheme").unwrap(), "https");
        assert_eq!(parsed.get::<String>("userinfo").unwrap(), "user");
        assert_eq!(parsed.get::<String>("host").unwrap(), "api.example.com");
        assert_eq!(parsed.get::<u16>("port").unwrap(), 8443);
        assert_eq!(parsed.get::<String>("path").unwrap(), "/v1/items");
        assert_eq!(parsed.get::<String>("query").unwrap(), "page=2");
        assert_eq!(parsed.get::<String>("fragment").unwrap(), "top");

        // IPv6 brackets, schemeless relative references, bare paths.
        let (parsed, _): (Table, Option<String>) =
            parse.call("http://[::1]:3000/x").expect("parse");
        assert_eq!(parsed.get::<String>("host").unwrap(), "::1");
        assert_eq!(parsed.get::<u16>("port").unwrap(), 3000);

        let (parsed, _): (Table, Option<String>) = parse.call("/just/a/path?q=1").expect("parse");
        assert!(parsed.get::<Option<String>>("scheme").unwrap().is_none());
        assert_eq!(parsed.get::<String>("path").unwrap(), "/just/a/path");
        assert_eq!(parsed.get::<String>("query").unwrap(), "q=1");

        // No-authority schemes, scheme case-folding, empty fragments.
        let (parsed, _): (Table, Option<String>) =
            parse.call("MailTo:ada@example.com").expect("parse");
        assert_eq!(parsed.get::<String>("scheme").unwrap(), "mailto");
        assert_eq!(parsed.get::<String>("path").unwrap(), "ada@example.com");
        assert!(parsed.get::<Option<String>>("host").unwrap().is_none());

        let (parsed, _): (Table, Option<String>) =
            parse.call("https://example.com#").expect("parse");
        assert_eq!(parsed.get::<String>("fragment").unwrap(), "");
        assert_eq!(parsed.get::<String>("path").unwrap(), "");

        // A non-numeric "port" stays part of the host rather than
        // silently becoming one.
        let (parsed, _): (Table, Option<String>) =
            parse.call("http://example.com:abc/x").expect("parse");
        assert_eq!(parsed.get::<String>("host").unwrap(), "example.com:abc");
        assert!(parsed.get::<Option<u16>>("port").unwrap().is_none());
        let (parsed, _): (Table, Option<String>) = parse.call("http://[::1]:abc/x").expect("parse");
        assert_eq!(parsed.get::<String>("host").unwrap(), "[::1]:abc");
        assert!(parsed.get::<Option<u16>>("port").unwrap().is_none());
        let (parsed, _): (Table, Option<String>) =
            parse.call("http://[::1]:8080/x").expect("parse");
        assert_eq!(parsed.get::<String>("host").unwrap(), "::1");
        assert_eq!(parsed.get::<u16>("port").unwrap(), 8080);

        let (parsed, err): (Value, Option<String>) = parse.call("").expect("parse");
        assert!(parsed.is_nil());
        assert_eq!(err.as_deref(), Some("empty URL"));
    }

    proptest::proptest! {
        /// Property: decode(encode(s)) is the identity, and a query built
        /// from a table parses back to the same table.
        #[test]
        fn prop_percent_and_query_round_trip(
            s in "[ -~]{0,40}",
            entries in proptest::collection::btree_map("[a-z][a-z0-9]{0,7}", "[ -~]{0,12}", 0..5),
        ) {
            let lua = Lua::new();
            let url = create_url_table(&lua).expect("table");
            let encode: mlua::Function = url.get("encode").expect("fn");
            let decode: mlua::Function = url.get("decode").expect("fn");
            let build: mlua::Function = url.get("query_build").expect("fn");
            let parse: mlua::Function = url.get("query_parse").expect("fn");

            let encoded: String = encode.call(s.as_str()).expect("encode");
            let decoded: String = decode.call(encoded).expect("decode");
            proptest::prop_assert_eq!(&decoded, &s);

            // BTreeMap keys are unique by construction: duplicates are
            // defined to collapse on parse, so they are out of scope here.
            let map = lua.create_table().expect("map");
            for (k, v) in &entries {
                map.set(k.as_str(), v.as_str()).expect("set");
            }
            let query: String = build.call(&map).expect("build");
            let parsed: Table = parse.call(query.as_str()).expect("parse");
            for (k, v) in &entries {
                let got = parsed.get::<Option<String>>(k.as_str()).expect("get");
                proptest::prop_assert_eq!(
                    got.as_deref(),
                    Some(v.as_str()),
                    "key {:?} in query {:?}", k, query
                );
            }
            for pair in parsed.pairs::<String, String>() {
                let (k, _) = pair.expect("pair");
                proptest::prop_assert!(
                    entries.contains_key(&k),
                    "parse invented key {:?}", k
                );
            }
        }
    }
}
