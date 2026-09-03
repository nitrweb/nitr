// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Conditional-request freshness: `If-None-Match` / `If-Modified-Since`
//! evaluation shared by static serving and `req:fresh()`.

/// Whether the client's cached copy is still current.
///
/// `If-None-Match` wins over `If-Modified-Since` when both are present,
/// which is what RFC 9110 requires: an entity tag is an exact identifier
/// and a date is a heuristic.
pub fn is_fresh(
    headers: &hyper::HeaderMap,
    etag: Option<&str>,
    last_modified: Option<i64>,
) -> bool {
    if let Some(candidates) = headers
        .get(hyper::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        let Some(etag) = etag else {
            return false;
        };
        let etag = strip_weak(etag);
        return candidates.split(',').any(|candidate| {
            let candidate = candidate.trim();
            // `*` matches any existing representation — as the bare member
            // only. It is checked *before* the weak prefix comes off: `W/*`
            // is not the wildcard (RFC 9110 has no weak wildcard), it is a
            // malformed tag compared like any other. The fuzzer found the
            // difference through the upper-cased near miss of a handler
            // tag `w/*`, which used to certify every resource as unchanged.
            if candidate == "*" {
                return true;
            }
            // The weak/strong prefix is not part of the comparison this
            // header calls for. A tag the compression layer derived for an
            // encoded variant (`"abc-gzip"`) names the same bytes as
            // `"abc"`: a client that cached the gzip form must revalidate
            // as fresh, or every conditional request of a compressed
            // response is a full 200 plus a recompress.
            let candidate = strip_weak(candidate);
            candidate == etag
                || strip_encoding_suffix(candidate).is_some_and(|base| base == etag)
        });
    }

    let (Some(since), Some(modified)) = (
        headers
            .get(hyper::header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok()),
        last_modified,
    ) else {
        return false;
    };
    let since = since
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    // HTTP dates have second precision, so compare truncated.
    modified <= since
}

fn strip_weak(etag: &str) -> &str {
    etag.strip_prefix("W/").unwrap_or(etag)
}

/// `"abc-gzip"` → `"abc"`, for the tokens `crate::compress` can append
/// (see `weaken_etag` there); anything else is `None`.
fn strip_encoding_suffix(tag: &str) -> Option<String> {
    let inner = tag.strip_prefix('"')?.strip_suffix('"')?;
    ["gzip", "br"].iter().find_map(|token| {
        inner
            .strip_suffix(token)
            .and_then(|s| s.strip_suffix('-'))
            .map(|base| format!("\"{base}\""))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Found by the `conditional_headers` fuzz target: `W/*` weak-stripped
    /// to `*` and matched everything. Only the bare `*` member is the
    /// wildcard; `W/*` is a tag like any other and matches only itself.
    #[test]
    fn a_weak_prefixed_star_is_not_the_wildcard() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("if-none-match", "W/*".parse().expect("value"));
        assert!(!is_fresh(&headers, Some("\"abc\""), None));
        assert!(!is_fresh(&headers, Some("w/*"), None));
        // The exact input the fuzzer reported.
        headers.insert(
            "if-none-match",
            "w/*x, W/w/*x, w/, W/*".parse().expect("value"),
        );
        assert!(!is_fresh(&headers, Some("w/*"), None));
        // The bare wildcard still matches, alone and inside a list, and
        // still needs a tag to match against.
        for list in ["*", " * ", "\"aaa\", *, W/\"bbb\""] {
            headers.insert("if-none-match", list.parse().expect("value"));
            assert!(is_fresh(&headers, Some("\"abc\""), None), "{list:?}");
            assert!(!is_fresh(&headers, None, None), "{list:?}");
        }
    }

    #[test]
    fn encoded_variant_tags_revalidate_against_the_identity_tag() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("if-none-match", "W/\"abc-gzip\"".parse().expect("value"));
        assert!(is_fresh(&headers, Some("\"abc\""), None));
        assert!(!is_fresh(&headers, Some("\"abd\""), None));
        // Only a known token is a suffix; an application tag that happens
        // to end in `-gzip` is compared verbatim.
        headers.insert("if-none-match", "\"x-gzip\"".parse().expect("value"));
        assert!(is_fresh(&headers, Some("\"x-gzip\""), None));
        assert!(!is_fresh(&headers, Some("\"x-zip\""), None));
        assert_eq!(strip_encoding_suffix("\"a-br\"").as_deref(), Some("\"a\""));
        assert_eq!(strip_encoding_suffix("\"a-zstd\""), None);
        assert_eq!(
            strip_encoding_suffix("abc-gzip"),
            None,
            "unquoted is not a tag"
        );
    }
}
