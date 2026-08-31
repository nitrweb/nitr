// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The error response: a curt production 500, and the development page
//! with the classified error rendered in context.

use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper::{Response, header};

use super::HttpResponse;
use nitr_core::{Error, ErrorInfo, Result};

/// A generic 500 that never leaks internals to clients; in development mode
/// the classified error is rendered in context for fast iteration.
pub(super) fn error_response(err: &Error, dev_mode: bool) -> Result<HttpResponse> {
    error_page_with_source(&ErrorInfo::from_error(err), dev_mode, false, None)
}

/// Whether the client would rather see HTML than plain text.
pub(super) fn accepts_html(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

/// The error response body.
///
/// Production is deliberately curt: a generic `500` with no source, no
/// traceback, no internal paths — the structured log line is where the
/// diagnosis lives. Development mode renders the error in context: the
/// concise headline, the failing source with the line marked, the bounded
/// traceback and cause chain — as HTML when the client accepts it. The
/// source snippet reads from disk, which only development mode pays.
pub(super) fn error_page_with_source(
    info: &ErrorInfo,
    dev_mode: bool,
    html: bool,
    script: Option<&std::path::Path>,
) -> Result<HttpResponse> {
    if !dev_mode {
        return Ok(Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from("Internal Server Error")).boxed())?);
    }

    let mut text = format!("Internal Server Error\n\n{}", info.concise());
    if let (Some(source), Some(line)) = (&info.source, info.line)
        && let Some(path) = resolve_source_path(source, script)
        && let Some(snippet) =
            nitr_core::source_snippet(&path, line, 2, nitr_core::message_token(&info.message))
    {
        text.push_str("\n\n");
        text.push_str(&snippet);
    }
    if let Some(traceback) = &info.traceback {
        text.push_str("\nstack traceback:\n");
        text.push_str(traceback);
        text.push('\n');
    }
    for cause in &info.cause {
        text.push_str(&format!("caused by: {cause}\n"));
    }

    let (content_type, body) = if html {
        (
            "text/html; charset=utf-8",
            format!(
                "<!doctype html><html><head><title>Internal Server Error</title></head>\
                 <body><h1>Internal Server Error</h1><pre>{}</pre></body></html>",
                escape_html(text.trim_start_matches("Internal Server Error\n\n"))
            ),
        )
    } else {
        ("text/plain; charset=utf-8", text)
    };
    Ok(Response::builder()
        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .body(Full::new(Bytes::from(body)).boxed())?)
}

/// Maps an error's `source` chunk name back to a readable file. Lua bounds
/// chunk names (`LUA_IDSIZE`), so a long script path arrives truncated with
/// a `...` prefix; the known script path covers that case when its tail
/// matches.
fn resolve_source_path(
    source: &str,
    script: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    let direct = std::path::Path::new(source);
    if direct.is_file() {
        return Some(direct.to_path_buf());
    }
    let script = script?;
    let tail = source.trim_start_matches("...");
    script
        .to_string_lossy()
        .ends_with(tail)
        .then(|| script.to_path_buf())
}

pub(super) fn escape_html(text: &str) -> String {
    // Quotes included: the snippet is rendered in element context today,
    // but escaping is the wrong place to depend on that staying true.
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
