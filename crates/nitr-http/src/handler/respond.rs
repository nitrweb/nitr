// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Conversion of the Lua response table `{status, headers, body}` into an
//! HTTP response, with the framing rules enforced.

use std::convert::Infallible;

use http_body_util::{BodyExt as _, Empty, Full, combinators::BoxBody};
use hyper::body::Bytes;
use hyper::{Response, StatusCode, header};
use mlua::{LuaString, Table as LuaTable, Value as LuaValue};

use super::HttpResponse;
use nitr_core::{Error, Result};

/// A response with no body at all (not even a zero-length one), for the
/// statuses where a body is forbidden.
pub(crate) fn empty_response(status: StatusCode) -> Result<HttpResponse> {
    Ok(Response::builder()
        .status(status)
        .body(Empty::<Bytes>::new().boxed())?)
}

pub(crate) fn plain_response(status: StatusCode, body: &'static str) -> Result<HttpResponse> {
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())).boxed())?)
}

/// Converts the Lua response table `{status, headers, body}` into an HTTP
/// response. Bodies are binary-safe (Lua strings are byte strings); header
/// values may be a string or an array of strings (multi-value headers such
/// as `Set-Cookie`).
pub(super) fn to_response(lua_resp: LuaTable) -> Result<HttpResponse> {
    let body = lua_resp.raw_get::<Option<LuaString>>("body")?;
    let len = body.as_ref().map_or(0, |b| b.as_bytes().len());
    let body = body
        .map(|b| Full::new(Bytes::copy_from_slice(&b.as_bytes())).boxed())
        .unwrap_or_else(|| Empty::<Bytes>::new().boxed());
    let resp = build_response(&lua_resp, body)?;
    reject_forbidden_body(resp.status(), len)?;
    Ok(resp)
}

/// Rejects a response whose status forbids a body.
///
/// A `204` or `304` carrying bytes is not a cosmetic problem: the framing
/// rules say there is no body there, so a client that believes the status
/// reads those bytes as the start of the *next* response on a keep-alive
/// connection. Better to fail the response than desynchronize the
/// connection.
fn reject_forbidden_body(status: StatusCode, len: usize) -> Result {
    if len == 0 {
        return Ok(());
    }
    if status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || status.is_informational()
    {
        return Err(Error::Script(format!(
            "a {status} response must not carry a body ({len} bytes given): \
             the status says there is nothing to read, and a client that \
             believes it would parse the body as the next response"
        )));
    }
    Ok(())
}

/// Builds an HTTP response from the table's status/headers/cookies around
/// an already-materialized body (static or streaming).
pub(crate) fn build_response(
    lua_resp: &LuaTable,
    body: BoxBody<Bytes, Infallible>,
) -> Result<HttpResponse> {
    use hyper::header::{HeaderName, HeaderValue};

    let status = lua_resp
        .raw_get::<Option<u16>>("status")?
        .unwrap_or(hyper::StatusCode::OK.as_u16());

    // Invalid status codes surface here.
    let mut resp = Response::builder().status(status).body(body)?;

    if let Some(headers) = lua_resp.raw_get::<Option<LuaTable>>("headers")? {
        // Insert into the header map directly (`for_each` avoids the pairs
        // iterator machinery and the response-builder indirection).
        let map = resp.headers_mut();
        let invalid_value = |name: &HeaderName| {
            mlua::Error::RuntimeError(format!("invalid value for header `{name}`"))
        };
        headers.for_each(|name: LuaString, value: LuaValue| {
            let name = HeaderName::from_bytes(&name.as_bytes()).map_err(|_| {
                mlua::Error::RuntimeError(format!("invalid header name `{}`", name.display()))
            })?;
            match value {
                LuaValue::String(v) => {
                    let v =
                        HeaderValue::from_bytes(&v.as_bytes()).map_err(|_| invalid_value(&name))?;
                    map.append(name, v);
                }
                LuaValue::Integer(v) => {
                    map.append(name, HeaderValue::from(v));
                }
                LuaValue::Table(values) => {
                    for v in values.sequence_values::<LuaString>() {
                        let v = HeaderValue::from_bytes(&v?.as_bytes())
                            .map_err(|_| invalid_value(&name))?;
                        map.append(name.clone(), v);
                    }
                }
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "invalid value type `{}` for header `{name}`: \
                         expected a string, an integer or an array of strings",
                        other.type_name()
                    )));
                }
            }
            Ok(())
        })?;
    }

    // Helper-built responses carry a `cookies` builder; each collected
    // entry becomes its own `Set-Cookie` header.
    match lua_resp.raw_get::<LuaValue>("cookies")? {
        LuaValue::Nil => {}
        LuaValue::UserData(ud) => {
            let cookies = ud.borrow::<nitr_std::ResponseCookies>().map_err(|_| {
                Error::Script("the response `cookies` field is not a cookie builder".into())
            })?;
            for value in cookies.values() {
                // The name only: the value is a signed session payload or
                // a CSRF token, and this message reaches the error log and
                // the development error page.
                let value = HeaderValue::from_str(&value).map_err(|_| {
                    let name = value.split('=').next().unwrap_or_default();
                    Error::Script(format!(
                        "invalid Set-Cookie value for cookie `{name}` (a control character \
                         in one of its attributes?)"
                    ))
                })?;
                resp.headers_mut().append(hyper::header::SET_COOKIE, value);
            }
        }
        other => {
            return Err(Error::Script(format!(
                "invalid `cookies` field of type `{}` in the response table",
                other.type_name()
            )));
        }
    }

    Ok(resp)
}
