// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! [`TestRequest`]: one request as a test describes it, read from the
//! options table `nitr.test.request` and `nitr.test.fake_request` share.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;
use hyper::body::Bytes;
use mlua::{Table, Value};

/// One test request: what [`TestClient::send`](super::TestClient::send)
/// dispatches.
#[derive(Debug, Clone, Default)]
pub struct TestRequest {
    /// The method, any case.
    pub method: String,
    /// The path, with any query string.
    pub path: String,
    /// Header lines in order; a name may repeat.
    pub headers: Vec<(String, String)>,
    /// The body, when there is one.
    pub body: Option<Bytes>,
    /// The peer the server sees; `127.0.0.1:0` when unset.
    pub remote_addr: Option<SocketAddr>,
    /// Bounds the whole exchange from the client side.
    pub timeout: Option<Duration>,
}

/// The options that each set the body; a request has one body, so giving
/// two is an error rather than a silent last-writer-wins.
const BODY_OPTIONS: &[&str] = &["body", "json", "form", "multipart"];

fn refuse(message: String) -> mlua::Error {
    mlua::Error::RuntimeError(message)
}

/// A Lua scalar as text: numbers and booleans the way a browser would
/// send them.
fn scalar_text(key: &str, value: Value) -> mlua::Result<String> {
    Ok(match value {
        Value::String(s) => s.to_string_lossy().to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Boolean(b) => b.to_string(),
        other => {
            return Err(refuse(format!(
                "`{key}` values must be strings, numbers or booleans, got {}",
                other.type_name()
            )));
        }
    })
}

/// `{ k = v, tags = { "a", "b" } }` as ordered pairs: keys sorted (a Lua
/// table has no order, a test's expectations need one), a list repeating
/// its key.
fn pairs(option: &str, table: &Table) -> mlua::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for pair in table.pairs::<String, Value>() {
        let (key, value) = pair?;
        match value {
            Value::Table(list) => {
                for item in list.sequence_values::<Value>() {
                    out.push((key.clone(), scalar_text(option, item?)?));
                }
            }
            other => out.push((key, scalar_text(option, other)?)),
        }
    }
    // Stable: repeated values keep their list order.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

impl TestRequest {
    /// Reads a request from `method`, `path` and the options table:
    /// `headers`, `query`, `cookies`, `auth`, one of `body`/`json`/`form`/
    /// `multipart`, `remote_addr`, `timeout`. Unknown keys are ignored;
    /// wrong types raise.
    ///
    /// # Errors
    ///
    /// Two body options, a malformed option, or a value that does not
    /// encode.
    pub fn from_lua(method: &str, path: &str, opts: Option<&Table>) -> mlua::Result<Self> {
        let mut req = TestRequest {
            method: method.to_string(),
            path: path.to_string(),
            ..Default::default()
        };
        let Some(opts) = opts else {
            return Ok(req);
        };

        if let Some(headers) = opts.get::<Option<Table>>("headers")? {
            for (name, value) in pairs("headers", &headers)? {
                req.headers.push((name.to_ascii_lowercase(), value));
            }
        }
        let has_header = |req: &TestRequest, name: &str| {
            req.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(name))
        };

        if let Some(query) = opts.get::<Option<Table>>("query")? {
            let mut encoder = url::form_urlencoded::Serializer::new(String::new());
            for (key, value) in pairs("query", &query)? {
                encoder.append_pair(&key, &value);
            }
            let encoded = encoder.finish();
            if !encoded.is_empty() {
                let joiner = if req.path.contains('?') { '&' } else { '?' };
                req.path = format!("{}{joiner}{encoded}", req.path);
            }
        }

        if let Some(cookies) = opts.get::<Option<Table>>("cookies")? {
            let line = pairs("cookies", &cookies)?
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            if !line.is_empty() {
                req.headers.push(("cookie".into(), line));
            }
        }

        if let Some(auth) = opts.get::<Option<Table>>("auth")? {
            if has_header(&req, "authorization") {
                return Err(refuse(
                    "`auth` and an `authorization` header both given; a request carries one \
                     credential"
                        .into(),
                ));
            }
            let value = if let Some(token) = auth.get::<Option<String>>("bearer")? {
                format!("Bearer {token}")
            } else if let Some(basic) = auth.get::<Option<Table>>("basic")? {
                let user: String = basic.get(1)?;
                let pass: String = basic.get(2)?;
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
                )
            } else {
                return Err(refuse(
                    "`auth` takes { bearer = token } or { basic = { user, password } }".into(),
                ));
            };
            req.headers.push(("authorization".into(), value));
        }

        let given: Vec<&str> = BODY_OPTIONS
            .iter()
            .copied()
            .filter(|key| opts.contains_key(*key).unwrap_or(false))
            .collect();
        if let [first, second, ..] = given.as_slice() {
            return Err(refuse(format!(
                "`{first}` and `{second}` both given; a request has one body"
            )));
        }
        let content_type = match given.first().copied() {
            Some("body") => {
                let raw: mlua::LuaString = opts.get("body")?;
                req.body = Some(Bytes::copy_from_slice(&raw.as_bytes()));
                None
            }
            Some("json") => {
                let value: Value = opts.get("json")?;
                req.body = Some(Bytes::from(nitr_std::json_encode(&value)?));
                Some("application/json".to_string())
            }
            Some("form") => {
                let form: Table = opts.get("form")?;
                let mut encoder = url::form_urlencoded::Serializer::new(String::new());
                for (key, value) in pairs("form", &form)? {
                    encoder.append_pair(&key, &value);
                }
                req.body = Some(Bytes::from(encoder.finish()));
                Some("application/x-www-form-urlencoded".to_string())
            }
            Some("multipart") => {
                let parts: Table = opts.get("multipart")?;
                let (content_type, body) = multipart_body(&parts)?;
                req.body = Some(Bytes::from(body));
                Some(content_type)
            }
            _ => None,
        };
        // Only when the caller did not set one: a test of a wrong or
        // parameterized content type must be able to say so.
        if let Some(content_type) = content_type
            && !has_header(&req, "content-type")
        {
            req.headers.push(("content-type".into(), content_type));
        }

        if let Some(addr) = opts.get::<Option<String>>("remote_addr")? {
            req.remote_addr = Some(super::parse_peer(&addr).ok_or_else(|| {
                refuse(format!(
                    "`remote_addr` must be an IP address or ip:port, got {addr:?}"
                ))
            })?);
        }
        if let Some(secs) = opts.get::<Option<f64>>("timeout")? {
            req.timeout = Some(super::seconds("timeout", secs)?);
        }
        Ok(req)
    }
}

/// Encodes a `multipart` option table: a string value is a text part; a
/// table `{ filename, content_type, data }` is a file part (`filename =
/// ""` with empty `data` reproduces an empty browser file input). Parts
/// go in name order.
fn multipart_body(parts: &Table) -> mlua::Result<(String, Vec<u8>)> {
    let boundary = format!("----nitr-test-{}", uuid::Uuid::now_v7().simple());
    let mut body = Vec::new();
    let mut entries: Vec<(String, Value)> = Vec::new();
    for pair in parts.pairs::<String, Value>() {
        entries.push(pair?);
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in entries {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match value {
            Value::Table(file) => {
                let filename: String = file.get::<Option<String>>("filename")?.unwrap_or_default();
                let content_type: Option<String> = file.get("content_type")?;
                let data: mlua::LuaString = file.get("data")?;
                body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                    )
                    .as_bytes(),
                );
                if let Some(ct) = content_type {
                    body.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
                }
                body.extend_from_slice(b"\r\n");
                body.extend_from_slice(&data.as_bytes());
            }
            other => {
                body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
                );
                body.extend_from_slice(scalar_text("multipart", other)?.as_bytes());
            }
        }
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok((format!("multipart/form-data; boundary={boundary}"), body))
}
