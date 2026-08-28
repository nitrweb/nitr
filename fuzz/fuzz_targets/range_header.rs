// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `Range` and `If-Range` as `static_files::try_serve` actually uses them:
//! the header text is parsed, the validator is checked, and the answer is
//! what the server seeks and reads with.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u64 len | u64 modified_secs | range \0 if-range \0 etag-inner
//! ```
//!
//! `range` and `if-range` are attacker text and go into a real
//! `HeaderMap`, inserted whenever hyper accepts the bytes as a header
//! value — hyper takes obs-text that `to_str` then refuses, and `resolve`
//! reads a header it cannot decode as absent, so the insert is attempted
//! and its readability recorded rather than the run being thrown away.
//! `etag-inner` fills a server-shaped strong etag (`"{inner}"`): Nitr
//! derives the etag from the bytes it is about to send
//! (`static_files::etag_for`), a client never chooses it, so fuzzing its
//! *shape* would only model a server bug while fuzzing its *contents*
//! still drives every comparison below.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **An accepted range names bytes that exist.** `start <= end < len`.
//!   `try_serve` seeks to `start` and reads `end - start + 1` bytes; an
//!   inverted pair underflows that count into a near-`u64::MAX` read and
//!   an out-of-range `end` reads past the representation. This is the one
//!   invariant the previous target had, and it stays.
//! * **The advertised span round-trips.** A `Partial` is echoed to the
//!   client as `Content-Range: bytes {start}-{end}/{len}`; re-parsing that
//!   very span against the same length must give back the same span. A
//!   client re-requesting exactly what it was told it received has to get
//!   it, so any asymmetry between the suffix/open forms and the explicit
//!   form shows up here.
//! * **`resolve` is `if_range_matches` then `parse`, and nothing else.**
//!   All three are separate seams; `static_files` calls only `resolve`, so
//!   the other two could drift under it unnoticed. Checking the
//!   composition also pins the *order*: validating after parsing would let
//!   a stale request pick a branch it should never reach.
//! * **A stale validator can never yield a fragment.** Asserted with a
//!   deliberately non-matching etag and with a date one second off. This
//!   is what `If-Range` is for: stitching fresh bytes into a copy the
//!   client holds of a different representation silently corrupts the
//!   file, and it is the one failure mode here with no error to report.
//! * **The etag comparison is exact.** For any attacker text shaped like
//!   an entity tag, `if_range_matches` must agree with `==` on the trimmed
//!   value — not `starts_with`, not case-insensitive, not "`W/` stripped
//!   first". `W/"x"` matching `"x"` is precisely the weak-validator use
//!   RFC 9110 §13.1.5 forbids for `If-Range`.
//! * **A matching validator changes nothing.** Echoing the current etag
//!   back, in either the bare or the whitespace-padded form, must give the
//!   identical answer to sending no `If-Range` at all.
//! * **Dates are second-exact, in all three grammars.** Every spelling RFC
//!   9110 requires a recipient to accept (IMF-fixdate, RFC 850, asctime)
//!   must denote the same instant; one second either way must not match,
//!   because a file rewritten within the same second is a different
//!   representation; and with no modification time known, a date can never
//!   match, since the server has nothing to compare against.
//! * **An unknown unit is ignored, not rejected.** `416` is reserved for a
//!   `bytes=` request that cannot be satisfied. Answering `416` to
//!   `items=0-9` would fail a request RFC 9110 says to serve in full.
#![no_main]
use std::time::{Duration, SystemTime};

use hyper::header::{HeaderMap, HeaderName, HeaderValue, IF_RANGE, RANGE};
use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_http::fuzzing::{if_range_matches, parse_range, resolve_range, Resolved};

/// The last instant `httpdate` represents (`9999-12-31T23:59:59Z`).
/// `modified` is folded into this domain so building the `SystemTime`
/// cannot overflow, and so a formatted date exists for every value.
const MAX_HTTP_SECS: u64 = 253_402_300_799;

/// One instant per row, followed by every spelling of it a recipient must
/// accept: IMF-fixdate, the obsolete RFC 850 form, and `asctime`. Each
/// pair was checked against `httpdate` before being committed — a row that
/// silently stopped parsing would turn the assertions below into no-ops,
/// which is the failure mode this whole round exists to remove.
const DATES: &[(u64, &[&str])] = &[
    (
        784_111_777,
        &[
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ],
    ),
    // The epoch, where a subtraction that underflows would land.
    (
        0,
        &[
            "Thu, 01 Jan 1970 00:00:00 GMT",
            "Thursday, 01-Jan-70 00:00:00 GMT",
            "Thu Jan  1 00:00:00 1970",
        ],
    ),
    // A leap day: the calendar arithmetic on both sides has to agree.
    (
        1_456_747_200,
        &[
            "Mon, 29 Feb 2016 12:00:00 GMT",
            "Monday, 29-Feb-16 12:00:00 GMT",
            "Mon Feb 29 12:00:00 2016",
        ],
    ),
    (
        1_700_000_000,
        &[
            "Tue, 14 Nov 2023 22:13:20 GMT",
            "Tuesday, 14-Nov-23 22:13:20 GMT",
            "Tue Nov 14 22:13:20 2023",
        ],
    ),
    // The top of the representable range. RFC 850's two-digit year cannot
    // name it, so only the fixdate spelling appears.
    (MAX_HTTP_SECS, &["Fri, 31 Dec 9999 23:59:59 GMT"]),
];

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// Sets `name` to `value` and reports whether a reader of the map gets
/// that same text back.
///
/// Two things can go wrong, and `resolve` treats both as "no header": the
/// bytes are not a legal header value at all, or they are legal but not
/// visible ASCII, so `HeaderValue::to_str` refuses them. Assertions about
/// what the value *says* only hold when this returns `true`; when it does
/// not, the map is left in a state the caller can still reason about (the
/// header absent, or present and unreadable).
fn set(map: &mut HeaderMap, name: HeaderName, value: &str) -> bool {
    match HeaderValue::from_str(value) {
        Ok(parsed) => {
            map.insert(&name, parsed);
            map.get(&name).and_then(|v| v.to_str().ok()) == Some(value)
        }
        Err(_) => {
            map.remove(&name);
            false
        }
    }
}

/// The bounds `static_files` slices with, plus the round-trip through the
/// `Content-Range` it advertises for that slice.
fn check_partial(resolved: &Resolved, len: u64, what: &str) {
    let Resolved::Partial { start, end } = *resolved else {
        return;
    };
    assert!(start <= end, "{what}: inverted range {start}..={end}");
    assert!(
        end < len,
        "{what}: range {start}..={end} beyond length {len}"
    );
    // `Content-Range: bytes {start}-{end}/{len}` is what the client is
    // told it got, and re-requesting it must resolve to the same bytes.
    assert_eq!(
        parse_range(&format!("bytes={start}-{end}"), len),
        Resolved::Partial { start, end },
        "{what}: the advertised span bytes={start}-{end}/{len} does not re-parse to itself"
    );
}

/// Resolves, asserting the law `resolve` is supposed to satisfy: honour
/// the validator first, then parse, and never the other way round.
fn resolved(
    headers: &HeaderMap,
    len: u64,
    etag: &str,
    modified: Option<SystemTime>,
    what: &str,
) -> Resolved {
    let matches = if_range_matches(headers, etag, modified);
    let got = resolve_range(headers, len, etag, modified);
    let expected = match headers.get(RANGE).and_then(|v| v.to_str().ok()) {
        Some(spec) if matches => parse_range(spec, len),
        _ => Resolved::Full,
    };
    assert_eq!(
        got, expected,
        "{what}: resolve disagrees with if_range_matches({matches}) + parse \
         (len {len}, etag {etag:?}, headers {headers:?})"
    );
    if !matches {
        // Spelled out separately from the equality above: this is the one
        // outcome that corrupts a client's file rather than erroring.
        assert_eq!(
            got,
            Resolved::Full,
            "{what}: a stale If-Range still produced {got:?}; the client would stitch \
             fresh bytes into a copy of a different representation (headers {headers:?})"
        );
    }
    check_partial(&got, len, what);
    got
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let len = input.u64();
    let modified_secs = input.u64() % (MAX_HTTP_SECS + 1);
    let range_text = input.text();
    let if_range_text = input.text();
    let etag_inner = input.text();

    let etag = format!("\"{etag_inner}\"");
    // Same shape, one byte longer: an entity tag that cannot be this one.
    let stale = format!("\"{etag_inner}x\"");
    // The weak form of the *same* entity — forbidden for `If-Range`.
    let weak = format!("W/{etag}");
    let padded = format!("  {etag} ");
    let modified = Some(at(modified_secs));

    if std::env::var_os("NITR_FUZZ_DEBUG").is_some() {
        eprintln!(
            "DEBUG len={len} modified={modified_secs} range={range_text:?} \
             if_range={if_range_text:?} etag={etag:?}"
        );
    }

    // `parse` on its own, over the raw text: no header value round-trip
    // stands between the fuzzer and the parser here.
    let parsed = parse_range(&range_text, len);
    check_partial(&parsed, len, "parse");
    if parsed == Resolved::Unsatisfiable {
        // 416 belongs to a `bytes=` request that names nothing servable.
        // Any other unit must be ignored and the whole body sent.
        assert!(
            range_text.trim().starts_with("bytes="),
            "parse answered 416 for a non-bytes unit: {range_text:?}"
        );
    }

    // --- Range alone -------------------------------------------------
    let mut headers = HeaderMap::with_capacity(2);
    let readable = set(&mut headers, RANGE, &range_text);
    assert!(
        if_range_matches(&headers, &etag, modified),
        "an absent If-Range must not hold back a range"
    );
    let base = resolved(&headers, len, &etag, modified, "range only");
    if readable {
        assert_eq!(
            base, parsed,
            "resolve without an If-Range must agree with parse for {range_text:?} at len {len}"
        );
    } else {
        assert_eq!(
            base,
            Resolved::Full,
            "a Range header hyper cannot hand back as text must fall through to the \
             whole body, not to {base:?} ({range_text:?})"
        );
    }

    // --- The current etag echoed back --------------------------------
    if set(&mut headers, IF_RANGE, &etag) {
        assert!(
            if_range_matches(&headers, &etag, modified),
            "the current etag {etag:?} echoed back must match itself"
        );
        // An entity tag is compared on its own; the modification time is
        // not consulted and must not gate it.
        assert!(
            if_range_matches(&headers, &etag, None),
            "matching an etag must not depend on knowing a modification time ({etag:?})"
        );
        assert_eq!(
            resolved(&headers, len, &etag, modified, "matching etag"),
            base,
            "a matching If-Range must give the same answer as sending none ({etag:?})"
        );
    }
    // Surrounding whitespace is not part of the tag.
    if set(&mut headers, IF_RANGE, &padded) {
        assert_eq!(
            resolved(&headers, len, &etag, modified, "padded etag"),
            base,
            "whitespace around {etag:?} changed the outcome"
        );
    }

    // --- Validators that must never match ----------------------------
    for (label, value) in [("stale etag", &stale), ("weak etag", &weak)] {
        if !set(&mut headers, IF_RANGE, value) {
            continue;
        }
        assert!(
            !if_range_matches(&headers, &etag, modified),
            "{label} {value:?} matched the etag {etag:?}"
        );
        assert_eq!(
            resolved(&headers, len, &etag, modified, label),
            Resolved::Full,
            "{label} {value:?} still produced a fragment against {etag:?}"
        );
    }

    // --- The attacker's own If-Range ---------------------------------
    if set(&mut headers, IF_RANGE, &if_range_text) {
        let value = if_range_text.trim();
        if value.starts_with('"') || value.starts_with("W/") {
            // Entity tags compare byte for byte after trimming: no prefix
            // match, no case folding, no `W/` stripped off first.
            assert_eq!(
                if_range_matches(&headers, &etag, modified),
                value == etag,
                "If-Range {value:?} vs etag {etag:?} was not compared exactly"
            );
        }
    }
    resolved(&headers, len, &etag, modified, "attacker If-Range");

    // A date validator the server can actually verify
    // One spelling of one instant per run, both picked out of
    // `modified_secs`: each spelling stands or falls on its own, so
    // checking all of them every run would only buy the same coverage at
    // a third of the throughput.
    let (secs, forms) = DATES[(modified_secs % DATES.len() as u64) as usize];
    let form = forms[(modified_secs / DATES.len() as u64) as usize % forms.len()];
    assert!(
        set(&mut headers, IF_RANGE, form),
        "{form:?} is not a header value"
    );
    assert!(
        if_range_matches(&headers, &etag, Some(at(secs))),
        "{form:?} must denote {secs}s past the epoch"
    );
    // Not `>=`: HTTP dates carry second precision, so a file rewritten
    // inside the same second is indistinguishable from one that was not,
    // and must not be served in fragments.
    assert!(
        !if_range_matches(&headers, &etag, Some(at(secs + 1))),
        "{form:?} matched a representation modified one second later"
    );
    if secs > 0 {
        assert!(
            !if_range_matches(&headers, &etag, Some(at(secs - 1))),
            "{form:?} matched a representation modified one second earlier"
        );
    }
    // With no modification time there is nothing to compare a date
    // against, so it can never be honoured.
    assert!(
        !if_range_matches(&headers, &etag, None),
        "{form:?} matched with no modification time known"
    );
    // A matching date must be as transparent as no If-Range at all; a
    // stale one must give the whole representation back.
    assert_eq!(
        resolved(&headers, len, &etag, Some(at(secs)), "matching date"),
        base,
        "a matching date validator changed the outcome ({form:?})"
    );
    assert_eq!(
        resolved(&headers, len, &etag, Some(at(secs + 1)), "stale date"),
        Resolved::Full,
        "a one-second-stale date still produced a fragment ({form:?})"
    );
});
