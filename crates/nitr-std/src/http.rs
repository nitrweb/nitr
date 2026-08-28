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

use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, Mac as _};
use mlua::{
    ExternalResult as _, Function, Lua, MetaMethod, ObjectLike as _, Table, UserData,
    UserDataMethods, Value,
};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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
                    crate::utils::check_json_depth(&t)?;
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
                    crate::utils::check_json_depth(other)?;
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
/// into one `data:` line per newline, per the SSE wire format); any other
/// value is JSON-encoded.
fn format_event(event: &str, data: Value) -> mlua::Result<String> {
    let data = match data {
        Value::String(s) => s.to_string_lossy().to_string(),
        other => {
            crate::utils::check_json_depth(&other)?;
            serde_json::to_string(&other).into_lua_err()?
        }
    };
    let mut out = format!("event: {event}\n");
    for line in data.split('\n') {
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

/// Cookies parsed from a request's `Cookie` header: values via indexing
/// (`req.cookies.session`) and signed-cookie verification via
/// `req.cookies:verify(name, secret)`.
pub struct RequestCookies(Vec<(String, String)>);

impl RequestCookies {
    /// Parses a `Cookie` request header (an empty string yields no cookies).
    pub fn parse(header: &str) -> Self {
        Self(
            cookie::Cookie::split_parse(header)
                .flatten()
                .map(|c| (c.name().to_string(), c.value().to_string()))
                .collect(),
        )
    }

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

impl UserData for RequestCookies {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::Index, |lua, this, name: Value| {
            let Value::String(name) = name else {
                return Ok(Value::Nil);
            };
            match this.get(&name.to_string_lossy()) {
                Some(v) => Ok(Value::String(lua.create_string(v)?)),
                None => Ok(Value::Nil),
            }
        });

        // Returns the verified value of a signed cookie, or nil when the
        // cookie is missing, malformed, or its signature does not match.
        methods.add_method(
            "verify",
            |lua, this, (name, secret): (String, String)| match this
                .get(&name)
                .and_then(|raw| verify(&name, raw, &secret))
            {
                Some(v) => Ok(Value::String(lua.create_string(v)?)),
                None => Ok(Value::Nil),
            },
        );
    }
}

/// Builder for response `Set-Cookie` headers, attached as the `cookies`
/// field of helper-built response tables. The server serializes each entry
/// into its own `Set-Cookie` header.
#[derive(Default)]
pub struct ResponseCookies(Mutex<Vec<String>>);

impl ResponseCookies {
    /// The serialized `Set-Cookie` values collected so far.
    pub fn values(&self) -> Vec<String> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }

    fn push(&self, value: String) -> mlua::Result<()> {
        self.0
            .lock()
            .map_err(|_| mlua::Error::RuntimeError("the cookie list lock is poisoned".into()))?
            .push(value);
        Ok(())
    }
}

impl UserData for ResponseCookies {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method(
            "set",
            |_, this, (name, value, opts): (String, String, Option<Table>)| {
                this.push(build_cookie(&name, &value, opts.as_ref())?)
            },
        );

        // Signs the value with HMAC-SHA256 so `req.cookies:verify(name,
        // secret)` can authenticate it on later requests.
        methods.add_method(
            "set_signed",
            |_, this, (name, value, secret, opts): (String, String, String, Option<Table>)| {
                this.push(build_cookie(
                    &name,
                    &sign(&name, &value, &secret),
                    opts.as_ref(),
                )?)
            },
        );
    }
}

/// Attaches a serialized `Set-Cookie` value to a handler response table:
/// through its `cookies` builder when present (helper-built responses), or
/// by creating one (hand-built plain tables), so the server's response
/// conversion picks it up either way.
pub(crate) fn attach_cookie(resp: &Table, cookie: String) -> mlua::Result<()> {
    match resp.raw_get::<Value>("cookies")? {
        Value::UserData(ud) => {
            let cookies = ud.borrow::<ResponseCookies>().map_err(|_| {
                mlua::Error::RuntimeError(
                    "the response `cookies` field is not a cookie builder".into(),
                )
            })?;
            cookies.push(cookie)
        }
        Value::Nil => {
            let cookies = ResponseCookies::default();
            cookies.push(cookie)?;
            resp.set("cookies", cookies)
        }
        other => Err(mlua::Error::RuntimeError(format!(
            "invalid `cookies` field of type `{}` in the response table",
            other.type_name()
        ))),
    }
}

/// Serializes one cookie, applying the recognized options: `http_only`,
/// `secure`, `path`, `domain`, `max_age` (seconds), `same_site`
/// (`"Strict"` / `"Lax"` / `"None"`).
pub(crate) fn build_cookie(name: &str, value: &str, opts: Option<&Table>) -> mlua::Result<String> {
    let mut builder = cookie::Cookie::build((name.to_owned(), value.to_owned()));
    if let Some(opts) = opts {
        if opts.get::<Option<bool>>("http_only")?.unwrap_or(false) {
            builder = builder.http_only(true);
        }
        if opts.get::<Option<bool>>("secure")?.unwrap_or(false) {
            builder = builder.secure(true);
        }
        if let Some(path) = opts.get::<Option<String>>("path")? {
            builder = builder.path(path);
        }
        if let Some(domain) = opts.get::<Option<String>>("domain")? {
            builder = builder.domain(domain);
        }
        if let Some(secs) = opts.get::<Option<i64>>("max_age")? {
            builder = builder.max_age(cookie::time::Duration::seconds(secs));
        }
        if let Some(same_site) = opts.get::<Option<String>>("same_site")? {
            builder = builder.same_site(match same_site.to_ascii_lowercase().as_str() {
                "strict" => cookie::SameSite::Strict,
                "lax" => cookie::SameSite::Lax,
                "none" => cookie::SameSite::None,
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "invalid same_site value `{other}`: expected Strict, Lax or None"
                    )));
                }
            });
        }
    }
    Ok(builder.build().to_string())
}

/// Encodes and signs a cookie value: `b64(value) . b64(hmac)`, with the
/// cookie name bound into the MAC so values cannot be swapped between
/// cookies.
pub fn sign(name: &str, value: &str, secret: &str) -> String {
    let payload = B64.encode(value);
    format!(
        "{payload}.{}",
        B64.encode(mac_bytes(name, &payload, secret))
    )
}

/// Verifies a value produced by [`sign()`]; the MAC comparison is
/// constant-time (`hmac::Mac::verify_slice`).
pub fn verify(name: &str, signed: &str, secret: &str) -> Option<String> {
    let (payload, sig) = signed.rsplit_once('.')?;
    let sig = B64.decode(sig).ok()?;
    new_mac(name, payload, secret).verify_slice(&sig).ok()?;
    String::from_utf8(B64.decode(payload).ok()?).ok()
}

fn new_mac(name: &str, payload: &str, secret: &str) -> HmacSha256 {
    let mut mac: HmacSha256 = crate::utils::new_hmac(secret.as_bytes());
    mac.update(name.as_bytes());
    mac.update(b"=");
    mac.update(payload.as_bytes());
    mac
}

fn mac_bytes(name: &str, payload: &str, secret: &str) -> Vec<u8> {
    new_mac(name, payload, secret)
        .finalize()
        .into_bytes()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_cookies_round_trip_and_reject_tampering() {
        let signed = sign("session", "user-42", "s3cret");
        assert_eq!(
            verify("session", &signed, "s3cret").as_deref(),
            Some("user-42")
        );

        // Wrong secret, wrong name (cookie swapping), tampered payload.
        assert_eq!(verify("session", &signed, "other"), None);
        assert_eq!(verify("tracking", &signed, "s3cret"), None);
        let tampered = format!("x{signed}");
        assert_eq!(verify("session", &tampered, "s3cret"), None);
        assert_eq!(verify("session", "garbage", "s3cret"), None);
    }

    #[test]
    fn cookies_serialize_their_options() {
        let lua = mlua::Lua::new();
        let opts: Table = lua
            .load(r#"{ http_only = true, secure = true, same_site = "Lax", max_age = 3600, path = "/" }"#)
            .eval()
            .expect("opts table");
        let cookie = build_cookie("session", "abc", Some(&opts)).expect("cookie");
        for part in [
            "session=abc",
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
            "Max-Age=3600",
            "Path=/",
        ] {
            assert!(cookie.contains(part), "`{cookie}` should contain `{part}`");
        }
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

    proptest::proptest! {
        /// Property: sign/verify round-trips arbitrary printable inputs,
        /// and flipping any single character of the signed value breaks
        /// it — as do the wrong secret and a swapped cookie name.
        #[test]
        fn prop_signed_cookies_round_trip_and_any_tamper_fails(
            name in "[ -~]{1,16}",
            value in "[ -~]{0,48}",
            secret in "[ -~]{1,32}",
            pos in proptest::prelude::any::<proptest::sample::Index>(),
        ) {
            let signed = sign(&name, &value, &secret);
            let verified = verify(&name, &signed, &secret);
            proptest::prop_assert_eq!(verified.as_deref(), Some(value.as_str()));

            // One changed character anywhere — payload or MAC — must fail.
            // The index is taken over the collected chars, not the byte
            // length: the two only coincide while the signed encoding
            // stays pure ASCII, and the test must not depend on that.
            let mut tampered: Vec<char> = signed.chars().collect();
            let pos = pos.index(tampered.len());
            tampered[pos] = if tampered[pos] == 'A' { 'B' } else { 'A' };
            let tampered: String = tampered.into_iter().collect();
            proptest::prop_assert_eq!(verify(&name, &tampered, &secret), None);

            proptest::prop_assert_eq!(verify(&name, &signed, "other-secret"), None);
            proptest::prop_assert_eq!(verify("other-name", &signed, &secret), None);
        }
    }
}
