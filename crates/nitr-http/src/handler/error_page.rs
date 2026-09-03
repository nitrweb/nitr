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
            .body(Full::new(Bytes::from_static(b"Internal Server Error")).boxed())?);
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

/// Maps an error's `source` chunk name back to a readable file: the
/// handler script itself, or a module inside the script's directory
/// (where `require` is confined). Lua bounds chunk names (`LUA_IDSIZE`),
/// so a long script path arrives truncated with a `...` prefix; the known
/// script path covers that case when its tail matches.
///
/// Nothing else is ever read. The position prefix is parsed out of the
/// error *text*, and a script can raise text it took from a request
/// (`error(req.query.q, 0)`, `assert(ok, err)`), so an unconfined lookup
/// was a file-read oracle: `?q=/etc/shadow:1:%20x` put lines 1–3 of that
/// file in the development error page.
fn resolve_source_path(
    source: &str,
    script: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    let script = script?;
    let tail = source.trim_start_matches("...");
    if script.to_string_lossy().ends_with(tail) {
        return Some(script.to_path_buf());
    }
    let root = script
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."))
        .canonicalize()
        .ok()?;
    // Only Lua: `require` can load nothing else, and the script directory
    // also holds `nitr.toml`, `.env` and, in the scaffold's layout, the
    // TLS key.
    let candidate = std::path::Path::new(source).canonicalize().ok()?;
    let is_lua = candidate.extension().is_some_and(|ext| ext == "lua");
    (is_lua && candidate.is_file() && candidate.starts_with(&root)).then_some(candidate)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the script and files beside it resolve; a path smuggled in
    /// through error text does not, however readable it is.
    #[test]
    fn source_snippets_come_only_from_the_script_directory() {
        let dir = std::env::temp_dir().join(format!("nitr-errpage-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("lib")).expect("mkdir");
        let script = dir.join("app.lua");
        std::fs::write(&script, "return 1\n").expect("write");
        let module = dir.join("lib/util.lua");
        std::fs::write(&module, "return 2\n").expect("write");
        let outside =
            std::env::temp_dir().join(format!("nitr-errpage-outside-{}", std::process::id()));
        std::fs::write(&outside, "secret\n").expect("write");
        // Beside the script but not a module: the env file and a key.
        std::fs::write(dir.join(".env"), "SECRET=1\n").expect("write");
        std::fs::write(dir.join("key.pem"), "-----BEGIN\n").expect("write");

        let script_str = script.to_string_lossy().to_string();
        assert_eq!(
            resolve_source_path(&script_str, Some(&script)),
            Some(script.clone())
        );
        // A `LUA_IDSIZE`-truncated chunk name still maps to the script.
        let tail = format!("...{}", &script_str[script_str.len() - 10..]);
        assert_eq!(
            resolve_source_path(&tail, Some(&script)),
            Some(script.clone())
        );
        assert_eq!(
            resolve_source_path(&module.to_string_lossy(), Some(&script)),
            Some(module.canonicalize().expect("canonical"))
        );
        for hostile in [
            outside.to_string_lossy().to_string(),
            "/etc/passwd".into(),
            dir.join(".env").to_string_lossy().to_string(),
            dir.join("key.pem").to_string_lossy().to_string(),
        ] {
            assert_eq!(
                resolve_source_path(&hostile, Some(&script)),
                None,
                "{hostile}"
            );
        }
        assert_eq!(
            resolve_source_path(&script_str, None),
            None,
            "no script, no reads"
        );

        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
