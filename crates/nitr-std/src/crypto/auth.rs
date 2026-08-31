// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr.auth`: Basic/Bearer `Authorization` header parsing.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mlua::{Lua, ObjectLike as _, Table, Value};

/// Builds the `nitr.auth` table: `basic(req)` returns `user, pass` (or
/// `nil`) and `bearer(req)` returns the token (or `nil`). Both accept the
/// request object or the raw `Authorization` header value.
pub fn create_auth_table(lua: &Lua) -> mlua::Result<Table> {
    let auth = lua.create_table()?;

    auth.set(
        "basic",
        lua.create_function(|lua, source: Value| {
            let header = authorization(&source)?;
            let Some(encoded) = header.as_deref().and_then(|h| scheme_value(h, "basic")) else {
                return Ok(mlua::MultiValue::new());
            };
            let Some((user, pass)) = B64
                .decode(encoded)
                .ok()
                .and_then(|raw| String::from_utf8(raw).ok())
                .and_then(|creds| {
                    creds
                        .split_once(':')
                        .map(|(u, p)| (u.to_string(), p.to_string()))
                })
            else {
                return Ok(mlua::MultiValue::new());
            };
            let mut out = mlua::MultiValue::new();
            out.push_back(Value::String(lua.create_string(&user)?));
            out.push_back(Value::String(lua.create_string(&pass)?));
            Ok(out)
        })?,
    )?;

    auth.set(
        "bearer",
        lua.create_function(|lua, source: Value| {
            let header = authorization(&source)?;
            match header
                .as_deref()
                .and_then(|h| scheme_value(h, "bearer"))
                .filter(|t| !t.is_empty())
            {
                Some(token) => Ok(Value::String(lua.create_string(token)?)),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    Ok(auth)
}

/// Extracts the `Authorization` header from a request-like value (userdata
/// or table with a `headers` field) or accepts the header string directly.
fn authorization(source: &Value) -> mlua::Result<Option<String>> {
    let headers: Option<Table> = match source {
        Value::String(s) => return Ok(Some(s.to_string_lossy().to_string())),
        Value::UserData(ud) => ud.get("headers").ok(),
        Value::Table(t) => t.get("headers").ok(),
        _ => None,
    };
    Ok(headers.and_then(|h| h.get::<Option<String>>("authorization").ok().flatten()))
}

/// Returns the value part of an `Authorization` header when its scheme
/// matches (case-insensitively), e.g. `Bearer <value>`.
pub(super) fn scheme_value<'a>(header: &'a str, scheme: &str) -> Option<&'a str> {
    let (found, value) = header.trim().split_once(' ')?;
    found
        .eq_ignore_ascii_case(scheme)
        .then(|| value.trim())
        .filter(|v| !v.is_empty())
}
