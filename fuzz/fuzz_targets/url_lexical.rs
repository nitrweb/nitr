// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr.url` — the query parser/builder, the percent codec, and the RFC
//! 3986 splitter, driven **through Lua** as a handler would call them
//! (`nitr_std::fuzzing::create_url_table`), so the mlua boundary is inside
//! the fuzzed path rather than bypassed.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u32 port | query \0 url
//! ```
//!
//! `port` is not text: it is spelled into a synthetic authority
//! (`//h.example:{port}/p`) so the whole `u16` range and everything past
//! it is reached in every run. A fuzzer working through the `url` field
//! alone would have to discover 65536 as a decimal numeral to cross that
//! edge. `query` and `url` are the two attacker strings; `url` is last so
//! it grows to the end of the input.
//!
//! `parse` is deliberately a *splitter*, not a WHATWG parser (see the
//! module doc of `nitr-std/src/url.rs`): it does not normalize, resolve or
//! validate. Nothing below asserts a promise it never made — every claim
//! about `parse` is a claim about *splitting*: each piece it hands back
//! came out of the input, and reassembling the pieces gives the input back.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **The differential.** `query_parse` hand-rolls `+`-as-space then
//!   percent-decoding — exactly what `url::form_urlencoded::parse`
//!   implements, and exactly what `nitr-http` uses for `req.query`. Two
//!   implementations of one parse over the same attacker bytes live in
//!   this repo, so they are run side by side and the *whole map* is
//!   compared (key set and every value, ordering deliberately not
//!   asserted, since a Lua table has none). A script reading
//!   `nitr.url.query_parse(req.query_string)` and a script reading
//!   `req.query` must not see different parameters — that difference is a
//!   parameter-smuggling primitive, and no unit test compares the two.
//! * **A leading `?` is stripped exactly once.** `strip_prefix` versus
//!   `trim_start_matches` is invisible until a query begins `??`, where
//!   the latter loses a key named `?a`.
//! * **`decode(encode(s))` is the identity**, and `encode` emits nothing
//!   outside `[A-Za-z0-9._~-]` plus well-formed `%XX`. The second half is
//!   the one with teeth: an `AsciiSet` that let `&`, `=`, `#` or `%`
//!   through would still round-trip, and would still let a value forge an
//!   extra query parameter when a script concatenates it into a URL.
//! * **`query_build` cannot forge a parameter.** Its output splits into
//!   exactly as many `&` segments as the map has keys, each with exactly
//!   one `=`. A key or value carrying `&`/`=` unescaped is the same
//!   smuggling bug seen from the building side.
//! * **`query_build` is a fixpoint of `query_parse`.** Building the parsed
//!   map and parsing it again must give back the identical map — the
//!   round-trip a script does when it edits one parameter and rebuilds the
//!   query. Sorting, re-encoding and duplicate collapse must all be
//!   information-preserving over what a parse actually yielded.
//! * **`parse` returns `nil` exactly for the empty string**, always sets
//!   `path`, and never invents characters: `host` and `userinfo` are
//!   substrings of the input, and `path`+`?query`+`#fragment` reassembles
//!   to a *suffix* of the input. A splitter that dropped, duplicated or
//!   reordered a component passes "it returned a table" and fails here.
//! * **The component separators do not leak across.** `path` never
//!   contains `?` or `#`, `query` never contains `#`, `host` never
//!   contains any of `/?#@`. A router matching on `path`, or a redirect
//!   built from `host`, is only safe if the split really happened at the
//!   first separator.
//! * **`host` implies the input contained `//`.** An authority is only
//!   ever read out of one; sniffing a host out of a bare path would let
//!   `parse("/redirect")` name a foreign origin.
//! * **The port is a `u16` and out-of-range digits are dropped, host
//!   intact.** This is characterization, not endorsement: `:99999` parses
//!   into `port.parse::<u16>().ok()`, which yields `None` while the digits
//!   are still cut off the host — so `host` says `h.example` and `port`
//!   says nothing, and a script reassembling the two silently targets the
//!   default port. `:abc` behaves differently (the text stays in `host`).
//!   Pinning it here means the inconsistency cannot change unnoticed.
#![no_main]
use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use mlua::{Function, Lua, Table, Value};
use nitr_fuzz::Input;

thread_local! {
    /// One Lua state for the whole process: `create_url_table` builds five
    /// closures and a fresh `Lua` costs far more than every call this
    /// target makes. The table is parked in the globals rather than beside
    /// the state so nothing outlives it; the garbage collected between
    /// runs keeps the strings each run leaves behind from accumulating.
    static LUA: Lua = {
        let lua = Lua::new();
        let url = nitr_std::fuzzing::create_url_table(&lua).expect("nitr.url table");
        lua.globals().set("url", url).expect("nitr.url global");
        lua
    };
}

/// One `nitr.url` member, by name.
fn member(lua: &Lua, name: &str) -> Function {
    lua.globals()
        .get::<Table>("url")
        .expect("nitr.url")
        .get(name)
        .expect("nitr.url member")
}

/// A `query_parse` result as a map. Ordering is not part of the contract —
/// a Lua table has none — so the comparison is over key and value only.
fn map_of(table: &Table, what: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in table.pairs::<String, String>() {
        let (key, value) = pair
            .unwrap_or_else(|err| panic!("{what}: query_parse produced a non-string pair: {err}"));
        out.insert(key, value);
    }
    out
}

/// The oracle: the same parse as implemented by the `url` crate, folded
/// last-write-wins because that is what writing into a Lua table does.
///
/// Both sides percent-decode with `percent_encoding` and both replace the
/// invalid UTF-8 a decode can produce (`decode_utf8_lossy` on either side),
/// so lossiness is *shared* and cannot by itself explain a divergence.
fn form_urlencoded_map(query: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        out.insert(key.into_owned(), value.into_owned());
    }
    out
}

/// Percent-encoded output must stay inside the unreserved set plus `%XX`.
fn check_encoded(encoded: &str, source: &str) {
    let bytes = encoded.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            assert!(
                i + 2 < bytes.len()
                    && bytes[i + 1].is_ascii_hexdigit()
                    && bytes[i + 2].is_ascii_hexdigit(),
                "encode({source:?}) = {encoded:?} has a truncated escape at byte {i}"
            );
            i += 3;
            continue;
        }
        assert!(
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'),
            "encode({source:?}) = {encoded:?} left {:?} unescaped; a caller concatenating \
             this into a URL can have a parameter forged under it",
            b as char
        );
        i += 1;
    }
}

/// Every claim this target makes about one `parse` result.
fn check_parse(table: &Table, input: &str) {
    let get = |key: &str| {
        table
            .get::<Option<String>>(key)
            .unwrap_or_else(|err| panic!("parse({input:?}) field `{key}` is not a string: {err}"))
    };

    // `path` is unconditional: a caller routes on it and would otherwise
    // have to guess what an absent path means.
    let path = get("path").unwrap_or_else(|| panic!("parse({input:?}) returned no path"));
    let query = get("query");
    let fragment = get("fragment");
    let host = get("host");
    let userinfo = get("userinfo");
    let port = table
        .get::<Option<u16>>("port")
        .unwrap_or_else(|err| panic!("parse({input:?}) port is not a u16: {err}"));

    // The split really happened at the first separator, so no component
    // still carries the ones that follow it.
    assert!(
        !path.contains('?') && !path.contains('#'),
        "parse({input:?}) left a query or fragment inside the path {path:?}"
    );
    if let Some(query) = &query {
        assert!(
            !query.contains('#'),
            "parse({input:?}) left a fragment inside the query {query:?}"
        );
        assert!(
            input.contains('?'),
            "parse({input:?}) invented the query {query:?}"
        );
    }
    if let Some(fragment) = &fragment {
        assert!(
            input.contains('#'),
            "parse({input:?}) invented the fragment {fragment:?}"
        );
    }

    // Reassembly. Everything from the path on is one suffix of the input
    // that was only ever cut, so putting the cuts back must land on that
    // suffix — a component dropped, duplicated or swapped shows up here
    // even though each one on its own still looks plausible.
    let tail = format!(
        "{path}{}{}",
        query
            .as_deref()
            .map(|q| format!("?{q}"))
            .unwrap_or_default(),
        fragment
            .as_deref()
            .map(|f| format!("#{f}"))
            .unwrap_or_default()
    );
    assert!(
        input.ends_with(&tail),
        "parse({input:?}) does not reassemble: path+query+fragment = {tail:?}"
    );

    if let Some(host) = &host {
        // An authority is only read out of a `//`; a host sniffed out of a
        // bare path would let `parse("/redirect")` name a foreign origin.
        assert!(
            input.contains("//"),
            "parse({input:?}) produced the host {host:?} with no authority in the input"
        );
        assert!(
            input.contains(host.as_str()),
            "parse({input:?}) invented the host {host:?}"
        );
        assert!(
            !host.contains(['/', '?', '#', '@']),
            "parse({input:?}) host {host:?} still holds a delimiter that ends an authority"
        );
    } else {
        assert!(
            port.is_none(),
            "parse({input:?}) produced port {port:?} with no host"
        );
        assert!(
            userinfo.is_none(),
            "parse({input:?}) produced userinfo {userinfo:?} with no host"
        );
    }
    if let Some(userinfo) = &userinfo {
        assert!(
            input.contains('@') && input.contains(userinfo.as_str()),
            "parse({input:?}) invented the userinfo {userinfo:?}"
        );
    }
    if let Some(scheme) = get("scheme") {
        assert!(
            scheme
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c)),
            "parse({input:?}) produced the non-RFC-3986 scheme {scheme:?}"
        );
        // Case folding is the only rewrite `parse` performs, so the scheme
        // must still sit where it was read from, colon and all.
        assert!(
            input.len() > scheme.len()
                && input[..scheme.len()].eq_ignore_ascii_case(&scheme)
                && input.as_bytes()[scheme.len()] == b':',
            "parse({input:?}) produced the scheme {scheme:?}, which is not its prefix"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let port = input.u32();
    let query = input.text();
    let url_text = input.text();

    LUA.with(|lua| {
        let encode = member(lua, "encode");
        let decode = member(lua, "decode");
        let query_parse = member(lua, "query_parse");
        let query_build = member(lua, "query_build");
        let parse = member(lua, "parse");

        // the percent codec
        for source in [&*query, &*url_text] {
            let encoded: String = encode.call(source).expect("encode");
            check_encoded(&encoded, source);
            let decoded: String = decode.call(encoded.as_str()).expect("decode");
            assert_eq!(
                decoded, source,
                "decode(encode({source:?})) = {decoded:?}: the component codec is not a round trip"
            );
        }

        // query_parse
        let parsed: Table = query_parse.call(&*query).expect("query_parse");
        let map = map_of(&parsed, "query_parse");

        // The differential, and the `?` rule that has to be neutralised
        // first: `query_parse` strips one leading `?`, `form_urlencoded`
        // strips none. Comparing on the already-stripped text keeps the
        // two honest about everything else, and holds only while stripping
        // once was enough.
        let bare = query.strip_prefix('?').unwrap_or(&query);
        if !bare.starts_with('?') {
            let bare_table: Table = query_parse.call(bare).expect("query_parse");
            let ours = map_of(&bare_table, "query_parse");
            let theirs = form_urlencoded_map(bare);
            assert_eq!(
                ours, theirs,
                "nitr.url.query_parse and url::form_urlencoded::parse disagree on {bare:?}: \
                 nitr said {ours:?}, form_urlencoded (which is what req.query uses) said {theirs:?}"
            );
            // Exactly one `?` comes off, so the stripped and unstripped
            // forms are the same query.
            assert_eq!(
                map, ours,
                "query_parse({query:?}) and query_parse({bare:?}) differ: the leading `?` was \
                 not stripped exactly once"
            );
        }

        // query_build
        let built: String = query_build.call(&parsed).expect("query_build");
        if map.is_empty() {
            assert!(
                built.is_empty(),
                "query_build of an empty query produced {built:?}"
            );
        } else {
            let segments: Vec<&str> = built.split('&').collect();
            assert_eq!(
                segments.len(),
                map.len(),
                "query_build({map:?}) = {built:?} splits into {} parameters instead of {}: a key \
                 or value smuggled an unescaped `&`",
                segments.len(),
                map.len()
            );
            for segment in segments {
                assert_eq!(
                    segment.matches('=').count(),
                    1,
                    "query_build({map:?}) = {built:?} produced the segment {segment:?}, which is \
                     not one `key=value`: a key or value smuggled an unescaped `=`"
                );
            }
        }
        // The fixpoint: building a parsed query and parsing it again is
        // what a script does to edit one parameter, so sorting, escaping
        // and duplicate collapse have to preserve everything a parse said.
        let rebuilt: Table = query_parse
            .call(built.as_str())
            .expect("query_parse of query_build");
        assert_eq!(
            map_of(&rebuilt, "query_parse of query_build"),
            map,
            "query_build({query:?} -> {built:?}) does not re-parse to the same query"
        );

        // parse
        let (value, err): (Value, Value) = parse.call(&*url_text).expect("parse");
        if url_text.is_empty() {
            let reason = err.as_string().map(|s| s.to_string_lossy());
            assert!(
                value.is_nil() && reason.as_deref() == Some("empty URL"),
                "parse(\"\") must be (nil, \"empty URL\"), got ({value:?}, {err:?})"
            );
        } else {
            assert!(
                err.is_nil(),
                "parse({url_text:?}) reported the error {err:?} alongside a result"
            );
            let table = value
                .as_table()
                .unwrap_or_else(|| panic!("parse({url_text:?}) returned {value:?}, not a table"));
            check_parse(table, &url_text);
        }

        // The port edge, reached by construction rather than by hoping the
        // fuzzer spells out a six-digit numeral. `split_authority` cuts the
        // digits off the host and then parses them as a `u16`, so anything
        // above 65535 leaves the host shortened and the port unreported.
        let synthetic = format!("//h.example:{port}/p");
        let (value, _): (Value, Value) = parse.call(synthetic.as_str()).expect("parse");
        let table = value.as_table().expect("parse of a synthetic authority");
        check_parse(table, &synthetic);
        assert_eq!(
            table
                .get::<Option<String>>("host")
                .expect("host")
                .as_deref(),
            Some("h.example"),
            "parse({synthetic:?}) did not split the authority at the port colon"
        );
        assert_eq!(
            table
                .get::<Option<String>>("path")
                .expect("path")
                .as_deref(),
            Some("/p"),
            "parse({synthetic:?}) did not split the path off the authority"
        );
        let got = table.get::<Option<u16>>("port").expect("port");
        let want = u16::try_from(port).ok();
        assert_eq!(
            got, want,
            "parse({synthetic:?}) reported port {got:?}; a port is parsed as a u16, so {port} \
             must yield {want:?} — and when it yields nothing the digits are still gone from \
             the host, which is the inconsistency this pins"
        );

        lua.gc_collect().expect("gc");
    });
});
