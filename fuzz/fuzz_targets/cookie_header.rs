// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `Cookie:` request header — `design/17` lists it first among the
//! parsers that must be fuzzed, and until now only the *signed-value* half
//! (`cookie_verify`) had a target. `RequestCookies::parse` is what stands
//! between an attacker's header bytes and `req.cookies.<name>`.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u16 pick | lookup \0 header
//! ```
//!
//! `header` is the raw header text and runs to the end of the input.
//! `lookup` is a name to index with — usually one that is *not* present,
//! which is the branch a handler hits most. `pick` selects one of the
//! parsed names to index with as well, so the lookup rule is exercised
//! against a name that really is there (and, when the header repeats a
//! name, against the duplicate).
//!
//! `parse` is a five-line adapter over `cookie::Cookie::split_parse`, so
//! there is deliberately **no differential against the `cookie` crate**:
//! comparing a wrapper with the thing it wraps proves nothing. What is
//! asserted instead is what the *adapter's callers* rely on — everything
//! below was read out of `split_parse`/`parse_inner` before being
//! asserted, not assumed.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **Totality.** Any byte string is a header; there is no reject path,
//!   so a header that yields no cookies must yield no cookies rather than
//!   an error — and one with no `=` at all must yield none.
//! * **No cookie has an empty name.** `req.cookies[""]` is not addressable
//!   from Lua and an empty name in a re-serialized header is a different
//!   cookie, so an adapter that let `=v` through would create an entry no
//!   handler can reach and no client sent.
//! * **Names and values carry no delimiter, and nothing is re-trimmed.**
//!   A name free of `;` and `=`, a value free of `;`, both already
//!   trimmed. This is cookie injection stated as an invariant: a value
//!   holding `; admin=1` would forge a second cookie the moment anything
//!   re-serializes the pair.
//! * **Nothing is invented, and header order is kept.** Every name and
//!   value is a slice of the header, and walking them left to right
//!   consumes the header monotonically — so a parser that reordered
//!   pairs, duplicated one, or synthesized a value fails, while
//!   "the right number of cookies came back" would not. Order is what
//!   makes "first occurrence wins" meaningful at all.
//! * **Re-serializing is a fixpoint.** `name=value` joined by `; ` must
//!   re-parse to the very same pairs. This is the injection assertion from
//!   the other side, and it also pins the trimming: a value that came back
//!   with an edge space would come back different the second time.
//! * **Padding a segment changes nothing.** Wrapping every `;`-separated
//!   segment in spaces must give back the identical pairs. `SplitCookies`
//!   skips a whitespace-only segment and `.trim()`s the rest, then
//!   `parse_inner` trims the name and the value again around the first
//!   `=`, so whitespace is never semantic. This is the only assertion here
//!   that can see a **dropped** cookie: every other one is an upper bound
//!   or a shape — `cookies.len() <= segments`, each name and value a slice
//!   of the header in order, the re-serialization fixpoint — and all of
//!   them still hold for a parser that silently discards a segment,
//!   because the fixpoint of a smaller list is still a fixpoint. A parser
//!   that skipped a segment beginning with a space (a plausible
//!   continuation-line rule) would keep `a=1` out of `a=1; b=2` and lose
//!   both once every segment is padded, which is exactly this comparison.
//!   (This bullet used to claim determinism instead: parse the same header
//!   twice, compare. `parse` is `split_parse().flatten().map().collect()`
//!   into a `Vec` — no map, no interning, no state — so no
//!   wrong-but-not-crashing implementation could ever have failed it,
//!   which is the vacuity the audit called out in the old
//!   `accept_negotiation`.)
//! * **Lookup resolves to the FIRST occurrence.** Duplicate cookie names
//!   are legal (RFC 6265 §5.4 permits them and gives no precedence rule),
//!   and `RequestCookies::get` uses `.iter().find(..)`, so the *earliest*
//!   wins. `req.query` handling elsewhere in the tree is last-write-wins.
//!   Both are defensible; disagreeing with each other is not, and a
//!   request-smuggling proxy pair can turn the difference into a bypass.
//!   The assertion pins the side Nitr is actually on.
//! * **A cookie named `verify` is unreachable.** mlua's generated
//!   `__index` consults the registered methods *before* the `Index`
//!   metamethod, so `req.cookies.verify` is always the method — a
//!   function, hence truthy, even when no such cookie was sent. Asserted
//!   deliberately: it is the quirk, and a change in mlua's lookup order
//!   would otherwise silently break `req.cookies:verify(..)` instead.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mlua::{Lua, ObjectLike as _, Value};
use nitr_fuzz::Input;
use nitr_std::RequestCookies;

thread_local! {
    /// One Lua state for the whole process. Only the lookup half of the
    /// target needs it — `RequestCookies` exposes its values to handlers
    /// through an `Index` metamethod, so indexing *is* the real path and
    /// `get` itself is `pub(crate)`.
    static LUA: Lua = Lua::new();
}

/// Indexes the cookies the way `req.cookies.<name>` does, and checks the
/// answer against the pairs in header order.
fn check_lookup(lua: &Lua, cookies: &[(String, String)], name: &str, header: &str) {
    let userdata = lua
        .create_userdata(RequestCookies::parse(header))
        .expect("cookie userdata");
    let got: Value = userdata.get(name).expect("cookie index");
    // First occurrence, which is what `.iter().find(..)` means.
    let want = cookies
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str());

    match &got {
        Value::Nil => assert!(
            want.is_none(),
            "req.cookies[{name:?}] is nil although {want:?} was parsed out of {header:?}"
        ),
        Value::String(text) => {
            let text = text.to_string_lossy();
            assert_eq!(
                Some(text.as_str()),
                want,
                "req.cookies[{name:?}] = {text:?} but the first cookie of that name in \
                 {header:?} is {want:?}; duplicate names must resolve to the earliest \
                 occurrence, the way `RequestCookies::get` does with `.iter().find(..)`"
            );
        }
        // mlua looks methods up before the `Index` metamethod, so the one
        // registered method shadows any cookie of the same name.
        Value::Function(_) => assert_eq!(
            name, "verify",
            "req.cookies[{name:?}] returned a function; only the `verify` method may shadow \
             a cookie name (header {header:?})"
        ),
        other => panic!("req.cookies[{name:?}] returned {other:?} for the header {header:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let pick = usize::from(input.u16());
    let lookup = input.text();
    let header = input.text();

    let cookies = RequestCookies::parse(&header).pairs().to_vec();

    // Parsing has no reject path, so the only way to report "nothing here"
    // is an empty list. A header without a single `=` cannot hold a
    // name/value pair, so it must produce exactly that.
    if !header.contains('=') {
        assert!(
            cookies.is_empty(),
            "a header with no `=` yielded {cookies:?}: {header:?}"
        );
    }
    // Cookies are `;`-separated and one segment yields at most one cookie,
    // so a parser that promoted attributes (`Path=/`, `HttpOnly`) of one
    // segment into cookies of their own would overshoot this.
    assert!(
        cookies.len() <= header.matches(';').count() + 1,
        "{} cookies out of {} `;`-separated segments: {header:?}",
        cookies.len(),
        header.matches(';').count() + 1
    );

    // Padding every segment with spaces changes nothing: a whitespace-only
    // segment is skipped either way, and every surviving one is trimmed
    // before the name/value split. The only check here that a *dropped*
    // cookie cannot pass.
    let padded = header
        .split(';')
        .map(|segment| format!(" {segment} "))
        .collect::<Vec<_>>()
        .join(";");
    assert_eq!(
        RequestCookies::parse(&padded).pairs(),
        cookies.as_slice(),
        "padding each segment of {header:?} into {padded:?} changed the cookies"
    );

    // Every name and value is a slice of the header, and they appear in
    // the order they were returned: walking left to right, each one must
    // still be findable after the previous one. Leftmost matching can only
    // ever land at or before a pair's true position, so this never fails
    // spuriously — but it does fail for a parser that reorders, repeats or
    // fabricates.
    let mut cursor = 0usize;
    for (name, value) in &cookies {
        assert!(
            !name.is_empty(),
            "an empty cookie name came out of {header:?}"
        );
        assert!(
            !name.contains(';') && !name.contains('='),
            "the cookie name {name:?} carries a delimiter: {header:?}"
        );
        assert!(
            !value.contains(';'),
            "the value of {name:?} carries a `;` ({value:?}) and would forge a second cookie \
             when re-serialized: {header:?}"
        );
        assert!(
            name.trim() == name && value.trim() == value,
            "{name:?}={value:?} came back untrimmed: {header:?}"
        );
        for text in [name, value] {
            let at = header[cursor..].find(text.as_str()).unwrap_or_else(|| {
                panic!("{text:?} is not in {header:?} at or after byte {cursor}, so it was \
                        invented or the cookies came back out of header order")
            });
            cursor += at + text.len();
        }
    }

    // The fixpoint. `name=value; name=value` is the header a client would
    // send back for these cookies, so parsing it must give them again —
    // which can only hold while no name or value can smuggle a delimiter,
    // and while the trimming has already settled.
    let reserialized = cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    assert_eq!(
        RequestCookies::parse(&reserialized).pairs(),
        cookies.as_slice(),
        "re-serializing the cookies of {header:?} as {reserialized:?} does not parse back to \
         the same pairs"
    );

    LUA.with(|lua| {
        // An arbitrary name: usually absent, which is the branch a handler
        // takes most often.
        check_lookup(lua, &cookies, &lookup, &header);
        // And one name that really is present, so the duplicate rule is
        // reached instead of only the miss.
        if !cookies.is_empty() {
            let name = cookies[pick % cookies.len()].0.clone();
            check_lookup(lua, &cookies, &name, &header);
        }

        // The method shadow, stated outright: `verify` never reaches the
        // cookie table, whatever the header says.
        let userdata = lua
            .create_userdata(RequestCookies::parse(&header))
            .expect("cookie userdata");
        let verify: Value = userdata.get("verify").expect("verify");
        assert!(
            verify.is_function(),
            "req.cookies.verify is {verify:?}, not the signed-cookie method; a cookie named \
             `verify` must not be able to displace it (header {header:?})"
        );

        lua.gc_collect().expect("gc");
    });
});
