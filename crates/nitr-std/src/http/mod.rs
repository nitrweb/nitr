// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! HTTP ergonomics for Lua handlers: response helpers (`nitr.text`,
//! `nitr.html`, `nitr.redirect`, `nitr.status`, `nitr.error`),
//! request/response cookies with HMAC-SHA256 signed variants, and content
//! negotiation (`nitr.negotiate`).
//!
//! Helpers build plain `{status, headers, body}` response tables — they are
//! sugar, not a new type — plus a `cookies` builder consumed by the server
//! when the response is converted.

use mlua::{ExternalResult as _, Function, Lua, ObjectLike as _, Table, Value};
use sha2::Sha256;

mod cookies;

pub use cookies::{CookieDefaults, RequestCookies, ResponseCookies, sign, verify};
pub(crate) use cookies::{attach_cookie, build_cookie, merge_cookie_opts};

/// Builds the skeleton of a helper response table: status, empty headers,
/// and an attached [`ResponseCookies`] builder.
pub(crate) fn response_table(lua: &Lua, status: u16) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set("status", status)?;
    table.set("headers", lua.create_table()?)?;
    table.set("cookies", ResponseCookies::default())?;
    Ok(table)
}

fn set_content_type(table: &Table, value: &str) -> mlua::Result<()> {
    table.get::<Table>("headers")?.set("Content-Type", value)
}

/// Registers the HTTP ergonomics helpers on the `nitr` namespace table:
/// `nitr.text`, `nitr.html`, `nitr.redirect`, `nitr.status`,
/// `nitr.negotiate`, `nitr.sse`, and `nitr.error`.
pub(crate) fn register(lua: &Lua, nitr: &Table) -> mlua::Result<()> {
    nitr.set(
        "text",
        lua.create_function(|lua, (body, status): (mlua::LuaString, Option<u16>)| {
            let table = response_table(lua, status.unwrap_or(200))?;
            set_content_type(&table, "text/plain; charset=utf-8")?;
            table.set("body", body)?;
            Ok(table)
        })?,
    )?;

    nitr.set(
        "html",
        lua.create_function(|lua, (body, status): (mlua::LuaString, Option<u16>)| {
            let table = response_table(lua, status.unwrap_or(200))?;
            set_content_type(&table, "text/html; charset=utf-8")?;
            table.set("body", body)?;
            Ok(table)
        })?,
    )?;

    nitr.set(
        "redirect",
        lua.create_function(|lua, (location, status): (String, Option<u16>)| {
            let table = response_table(lua, status.unwrap_or(302))?;
            table.get::<Table>("headers")?.set("Location", location)?;
            Ok(table)
        })?,
    )?;

    nitr.set(
        "status",
        lua.create_function(|lua, code: u16| response_table(lua, code))?,
    )?;

    // Server-Sent Events: `sse(function(send) ... end)` builds a streaming
    // response whose body hands the user function a `send(event, data)`
    // formatter over the raw stream writer.
    nitr.set(
        "sse",
        lua.create_function(|lua, handler: Function| {
            let table = response_table(lua, 200)?;
            let headers = table.get::<Table>("headers")?;
            headers.set("Content-Type", "text/event-stream")?;
            headers.set("Cache-Control", "no-cache")?;

            let body = lua.create_async_function(move |lua, writer: mlua::AnyUserData| {
                let handler = handler.clone();
                async move {
                    let send =
                        lua.create_async_function(move |_, (event, data): (String, Value)| {
                            let writer = writer.clone();
                            async move {
                                writer
                                    .call_async_method::<()>("write", format_event(&event, data)?)
                                    .await
                            }
                        })?;
                    handler.call_async::<()>(send).await
                }
            })?;
            table.set("body", body)?;
            Ok(table)
        })?,
    )?;

    nitr.set(
        "negotiate",
        lua.create_async_function(|lua, (req, offers): (Value, Table)| async move {
            negotiate(&lua, req, offers).await
        })?,
    )?;

    nitr.set(
        "error",
        lua.create_function(|lua, (code, body): (u16, Option<Value>)| {
            let table = response_table(lua, code)?;
            match body {
                None => {}
                Some(Value::String(s)) => {
                    set_content_type(&table, "text/plain; charset=utf-8")?;
                    table.set("body", s)?;
                }
                // A table body renders as JSON, e.g. `{ code = "NOT_FOUND" }`.
                Some(Value::Table(t)) => {
                    let t = Value::Table(t);
                    crate::utils::check_json_bounds(&t)?;
                    let body = serde_json::to_string(&t).into_lua_err()?;
                    set_content_type(&table, "application/json")?;
                    table.set("body", body)?;
                }
                Some(other) => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "nitr.error body must be a string or a table, got {}",
                        other.type_name()
                    )));
                }
            }
            Ok(table)
        })?,
    )?;

    // nitr.etag(value) — a validator for a dynamic response.
    //
    // Static files get conditional requests for free; dynamic ones cannot,
    // because only the application knows what identifies a resource. This
    // turns whatever it names — a row version, an updated_at, a rendered
    // body — into a well-formed entity tag, so `req:fresh()` has something
    // exact to compare against.
    nitr.set(
        "etag",
        lua.create_function(|lua, (value, weak): (Value, Option<bool>)| {
            let bytes = match &value {
                Value::String(s) => s.as_bytes().to_vec(),
                Value::Integer(n) => n.to_string().into_bytes(),
                Value::Number(n) => n.to_string().into_bytes(),
                other => {
                    crate::utils::check_json_bounds(other)?;
                    serde_json::to_vec(other).into_lua_err()?
                }
            };
            // Hashed rather than embedded verbatim: the input may contain
            // anything, and a header value may not.
            let digest = <Sha256 as sha2::Digest>::digest(&bytes);
            let tag = digest[..8].iter().fold(String::new(), |mut acc, byte| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{byte:02x}");
                acc
            });
            let prefix = if weak.unwrap_or(false) { "W/" } else { "" };
            lua.create_string(format!("{prefix}\"{tag}\""))
        })?,
    )?;

    Ok(())
}

/// Formats one Server-Sent Event: string data is taken verbatim (split
/// into one `data:` line per line break, per the SSE wire format); any
/// other value is JSON-encoded.
///
/// The event stream grammar ends a line at `\r\n`, `\n` *or a bare `\r`*,
/// so data is split on all three — a `\r` left inside a `data:` line would
/// let request text start a `retry:` or `event:` field of its own. The
/// event name is one line by definition and is refused if it is not.
fn format_event(event: &str, data: Value) -> mlua::Result<String> {
    if event.contains(['\r', '\n']) {
        return Err(mlua::Error::RuntimeError(
            "an SSE event name cannot contain a line break".into(),
        ));
    }
    let data = match data {
        Value::String(s) => s.to_string_lossy().to_string(),
        other => {
            crate::utils::check_json_bounds(&other)?;
            serde_json::to_string(&other).into_lua_err()?
        }
    };
    let mut out = format!("event: {event}\n");
    for line in data.replace("\r\n", "\n").split(['\r', '\n']) {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    Ok(out)
}

/// Picks the entry of `offers` whose key best matches the request's
/// `Accept` header. A function value is called with the request; any other
/// value is returned as-is. No acceptable entry yields a plain 406.
async fn negotiate(lua: &Lua, req: Value, offers: Table) -> mlua::Result<Value> {
    // Read the Accept header through the request's `headers` field so any
    // request-like object (userdata or plain table) works.
    let headers: Option<Table> = match &req {
        Value::UserData(ud) => ud.get("headers").ok(),
        Value::Table(t) => t.get("headers").ok(),
        _ => None,
    };
    let accept = headers
        .and_then(|h| h.get::<Option<String>>("accept").ok().flatten())
        .unwrap_or_else(|| "*/*".to_string());

    let mut offered = Vec::new();
    let mut values = Vec::new();
    for pair in offers.pairs::<String, Value>() {
        let (media_type, value) = pair?;
        offered.push(media_type);
        values.push(value);
    }

    let offered_refs: Vec<&str> = offered.iter().map(String::as_str).collect();
    match best_match(&accept, &offered_refs) {
        Some(i) => match values.swap_remove(i) {
            Value::Function(f) => f.call_async(req).await,
            value => Ok(value),
        },
        None => {
            let table = response_table(lua, 406)?;
            set_content_type(&table, "text/plain; charset=utf-8")?;
            table.set("body", "Not Acceptable")?;
            Ok(Value::Table(table))
        }
    }
}

/// Picks the best of `offered` media types for an `Accept` header value,
/// honoring q-values and `type/*` / `*/*` wildcards. More specific ranges
/// win at equal quality; ties go to the earlier offer.
pub fn best_match(accept: &str, offered: &[&str]) -> Option<usize> {
    // (index, quality, specificity)
    let mut best: Option<(usize, f32, u8)> = None;
    for item in accept.split(',') {
        let mut parts = item.trim().split(';');
        let range = match parts.next() {
            Some(r) if !r.trim().is_empty() => r.trim(),
            _ => continue,
        };
        let mut q = 1.0_f32;
        for param in parts {
            if let Some(v) = param.trim().strip_prefix("q=") {
                q = v.trim().parse().unwrap_or(0.0);
            }
        }
        if q <= 0.0 {
            continue;
        }
        for (i, offer) in offered.iter().enumerate() {
            let specificity = if range.eq_ignore_ascii_case(offer) {
                2
            } else if range == "*/*" {
                0
            } else if let Some(main) = range.strip_suffix("/*") {
                match offer.split('/').next() {
                    Some(offer_main) if offer_main.eq_ignore_ascii_case(main) => 1,
                    _ => continue,
                }
            } else {
                continue;
            };
            let better = match best {
                None => true,
                Some((bi, bq, bs)) => {
                    q > bq || (q == bq && (specificity > bs || (specificity == bs && i < bi)))
                }
            };
            if better {
                best = Some((i, q, specificity));
            }
        }
    }
    best.map(|(i, _, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every line terminator the SSE grammar knows splits data, so no
    /// value can inject a field; the event name is a single line.
    #[test]
    fn sse_framing_cannot_be_broken_out_of() {
        let lua = Lua::new();
        let data = |s: &str| Value::String(lua.create_string(s).expect("string"));
        assert_eq!(
            format_event("msg", data("hi\rretry: 1\revent: admin")).expect("event"),
            "event: msg\ndata: hi\ndata: retry: 1\ndata: event: admin\n\n"
        );
        assert_eq!(
            format_event("msg", data("a\r\nb\nc")).expect("event"),
            "event: msg\ndata: a\ndata: b\ndata: c\n\n"
        );
        assert!(format_event("x\nretry: 1", data("d")).is_err());
        assert!(format_event("x\r", data("d")).is_err());
    }

    #[test]
    fn accept_header_negotiation_honors_quality_and_wildcards() {
        let offers = &["application/json", "text/html"];
        // Explicit match wins over wildcard.
        assert_eq!(best_match("text/html, */*;q=0.5", offers), Some(1));
        // Quality ordering.
        assert_eq!(
            best_match("application/json;q=0.2, text/html;q=0.9", offers),
            Some(1)
        );
        // type/* wildcard.
        assert_eq!(best_match("text/*", offers), Some(1));
        // */* falls back to the first offer.
        assert_eq!(best_match("*/*", offers), Some(0));
        // q=0 removes a candidate entirely.
        assert_eq!(best_match("text/html;q=0", offers), None);
        assert_eq!(best_match("image/png", offers), None);
    }
}
