// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `Range` request parsing for static files (RFC 9110 §14).
//!
//! Only `bytes` ranges are recognized, which is the only unit anything
//! sends. A single range is served as `206`; a multi-range request is
//! answered in full rather than assembled as `multipart/byteranges` —
//! legal, and the complexity of the multipart form buys nothing for the
//! media-seeking case that motivates ranges at all.

use std::time::SystemTime;

use hyper::header::{self, HeaderMap};

/// What a `Range` header asks for, once resolved against a known length.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolved {
    /// No range header, an unsupported unit, or more than one range: send
    /// the whole representation.
    Full,
    /// Serve a single byte range of the representation.
    Partial {
        /// First byte served (inclusive, within the representation).
        start: u64,
        /// Last byte served (inclusive, within the representation).
        end: u64,
    },
    /// The range is syntactically valid but cannot be satisfied: `416`.
    Unsatisfiable,
}

/// Resolves the request's `Range` against a representation of `len` bytes.
///
/// `If-Range` is honored first: when it does not match the current
/// validator the client is holding a stale copy, and stitching fresh bytes
/// into it would produce a corrupt file. In that case the whole
/// representation is sent instead, which is exactly what `If-Range` is for.
pub(crate) fn resolve(
    headers: &HeaderMap,
    len: u64,
    etag: &str,
    modified: Option<SystemTime>,
) -> Resolved {
    let Some(range) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) else {
        return Resolved::Full;
    };
    if !if_range_matches(headers, etag, modified) {
        return Resolved::Full;
    }
    parse(range, len)
}

/// Whether a present `If-Range` validator still matches. Absent means yes.
fn if_range_matches(headers: &HeaderMap, etag: &str, modified: Option<SystemTime>) -> bool {
    let Some(value) = headers.get(header::IF_RANGE).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let value = value.trim();
    // An entity tag is quoted; anything else is an HTTP date.
    if value.starts_with('"') || value.starts_with("W/") {
        return value == etag;
    }
    match (httpdate::parse_http_date(value).ok(), modified) {
        // HTTP dates carry second precision, so an exact match is required:
        // a file modified within the same second may still have changed.
        (Some(since), Some(modified)) => secs(modified) == secs(since),
        _ => false,
    }
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Parses a `Range` header value against a representation length.
pub fn parse(value: &str, len: u64) -> Resolved {
    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        // An unknown unit must be ignored, not rejected.
        return Resolved::Full;
    };
    let mut parts = spec.split(',');
    let (Some(first), None) = (parts.next(), parts.next()) else {
        // Zero or multiple ranges: send everything.
        return Resolved::Full;
    };
    let Some((start, end)) = first.trim().split_once('-') else {
        return Resolved::Full;
    };
    let (start, end) = (start.trim(), end.trim());

    // An empty representation can satisfy no range at all.
    if len == 0 {
        return Resolved::Unsatisfiable;
    }
    let last = len - 1;

    match (start.is_empty(), end.is_empty()) {
        // `-N`: the final N bytes.
        (true, false) => match end.parse::<u64>() {
            Ok(0) => Resolved::Unsatisfiable,
            Ok(suffix) => Resolved::Partial {
                start: len.saturating_sub(suffix),
                end: last,
            },
            Err(_) => Resolved::Full,
        },
        // `N-`: from N to the end.
        (false, true) => match start.parse::<u64>() {
            Ok(start) if start <= last => Resolved::Partial { start, end: last },
            Ok(_) => Resolved::Unsatisfiable,
            Err(_) => Resolved::Full,
        },
        // `N-M`: an explicit span, clamped to the representation.
        (false, false) => match (start.parse::<u64>(), end.parse::<u64>()) {
            (Ok(start), Ok(end)) if start <= end && start <= last => Resolved::Partial {
                start,
                end: end.min(last),
            },
            (Ok(_), Ok(_)) => Resolved::Unsatisfiable,
            _ => Resolved::Full,
        },
        (true, true) => Resolved::Full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, value.parse().expect("header value"));
        }
        map
    }

    fn partial(start: u64, end: u64) -> Resolved {
        Resolved::Partial { start, end }
    }

    #[test]
    fn parses_the_three_range_forms() {
        assert_eq!(parse("bytes=0-99", 1000), partial(0, 99));
        assert_eq!(parse("bytes=500-", 1000), partial(500, 999));
        assert_eq!(parse("bytes=-100", 1000), partial(900, 999));
        // A span past the end is clamped, not rejected.
        assert_eq!(parse("bytes=990-2000", 1000), partial(990, 999));
        // A suffix larger than the file is the whole file.
        assert_eq!(parse("bytes=-5000", 1000), partial(0, 999));
    }

    #[test]
    fn rejects_only_what_cannot_be_satisfied() {
        assert_eq!(parse("bytes=1000-", 1000), Resolved::Unsatisfiable);
        assert_eq!(parse("bytes=99-1", 1000), Resolved::Unsatisfiable);
        assert_eq!(parse("bytes=-0", 1000), Resolved::Unsatisfiable);
        assert_eq!(parse("bytes=0-0", 0), Resolved::Unsatisfiable);
    }

    #[test]
    fn ignores_what_it_does_not_understand() {
        // Unknown units and malformed values fall back to the full body
        // rather than failing the request.
        assert_eq!(parse("items=0-99", 1000), Resolved::Full);
        assert_eq!(parse("bytes=abc-def", 1000), Resolved::Full);
        assert_eq!(parse("bytes=0-99, 200-299", 1000), Resolved::Full);
        assert_eq!(parse("bytes=-", 1000), Resolved::Full);
    }

    #[test]
    fn a_stale_if_range_falls_back_to_the_whole_file() {
        let etag = "\"abc\"";
        let fresh = headers(&[("range", "bytes=0-9"), ("if-range", etag)]);
        assert_eq!(resolve(&fresh, 100, etag, None), partial(0, 9));

        let stale = headers(&[("range", "bytes=0-9"), ("if-range", "\"old\"")]);
        assert_eq!(resolve(&stale, 100, etag, None), Resolved::Full);
    }

    #[test]
    fn an_if_range_date_must_match_exactly() {
        let modified = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let same = httpdate::fmt_http_date(modified);
        let older = httpdate::fmt_http_date(modified - std::time::Duration::from_secs(60));

        let matching = headers(&[("range", "bytes=0-9"), ("if-range", &same)]);
        assert_eq!(
            resolve(&matching, 100, "\"e\"", Some(modified)),
            partial(0, 9)
        );

        let mismatched = headers(&[("range", "bytes=0-9"), ("if-range", &older)]);
        assert_eq!(
            resolve(&mismatched, 100, "\"e\"", Some(modified)),
            Resolved::Full
        );
    }

    proptest::proptest! {
        /// Property: parsing is total over arbitrary header text, and any
        /// range it accepts lies entirely within the representation — a
        /// `Partial` out of bounds would slice the static file server out
        /// of its buffer.
        #[test]
        fn prop_parse_is_total_and_accepted_ranges_are_in_bounds(
            header in "[ -~]{0,40}",
            len in 0u64..100_000,
        ) {
            match parse(&header, len) {
                Resolved::Partial { start, end } => {
                    proptest::prop_assert!(start <= end, "inverted {start}..={end}");
                    proptest::prop_assert!(end < len, "{start}..={end} beyond {len}");
                }
                Resolved::Full | Resolved::Unsatisfiable => {}
            }
        }

        /// Property: a syntactically valid single range inside the
        /// representation resolves to exactly itself.
        #[test]
        fn prop_valid_single_ranges_resolve_exactly(
            start in 0u64..1000,
            span in 0u64..1000,
            slack in 1u64..1000,
        ) {
            let end = start + span;
            let len = end + slack; // strictly beyond `end`
            let header = format!("bytes={start}-{end}");
            proptest::prop_assert_eq!(
                parse(&header, len),
                Resolved::Partial { start, end }
            );
        }
    }
}
