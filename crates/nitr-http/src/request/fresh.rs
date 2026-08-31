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
        return candidates.split(',').any(|candidate| {
            let candidate = candidate.trim();
            // `*` matches any existing representation, and the weak/strong
            // prefix is not part of the comparison this header calls for.
            candidate == "*" || strip_weak(candidate) == strip_weak(etag)
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
