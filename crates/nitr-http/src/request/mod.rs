// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use http_body_util::BodyExt as _;
use http_body_util::combinators::BoxBody;
use hyper::Request;
use hyper::body::Bytes;

/// The request body type: boxed so both real (`hyper::body::Incoming`) and
/// synthetic (test client) bodies flow through the same dispatch.
pub(crate) type IncomingBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
use mlua::{ExternalResult, LuaSerdeExt, UserData, UserDataFields, UserDataMethods};
use serde_json::Value as SerdeValue;

mod body;
mod fresh;
#[cfg(test)]
mod tests;

pub(crate) use body::BodyGuards;
use body::{LimitedBody, StalledBody};
pub use fresh::is_fresh;

/// Wrapper around the incoming request that implements UserData.
pub(crate) struct LuaRequest {
    pub(crate) peer_addr: SocketAddr,
    pub(crate) req: Request<IncomingBody>,
    /// Path parameters captured by the router (empty for the catch-all).
    pub(crate) params: Vec<(String, String)>,
    /// The request id: generated per request (UUIDv7), or taken from a
    /// trusted inbound `X-Request-ID` header.
    pub(crate) id: String,
    /// Body-parsing bounds, copied from `[limits]` when the request is
    /// dispatched. Carried on the request because the Lua-facing parsers
    /// need them and Lua must not be able to raise them.
    pub(crate) limits: FormLimits,
    /// The parsed urlencoded form, kept after the first `req:form()` so a
    /// middleware (e.g. `nitr.csrf`) and the handler can both read it —
    /// the body itself can only be consumed once.
    pub(crate) cached_form: Option<Vec<(String, String)>>,
    /// The effective `[limits] max_body_bytes`, recorded by
    /// [`guard_body`](Self::guard_body) so the sized `req:read(n)` branch
    /// can clamp a Lua-supplied size *at the allocation* instead of
    /// relying on the limiter installed in another file. `u64::MAX` until
    /// the guard runs (nothing to clamp against yet).
    pub(crate) body_limit: u64,
}

/// Bounds applied while parsing a request body into Lua values.
///
/// Only multipart reads these today, so a build without that feature
/// carries the values without using them; keeping the struct whole means
/// `[limits]` parses identically either way.
#[derive(Debug, Clone)]
pub(crate) struct FormLimits {
    #[cfg_attr(not(feature = "multipart"), allow(dead_code))]
    pub(crate) max_parts: usize,
    #[cfg_attr(not(feature = "multipart"), allow(dead_code))]
    pub(crate) max_field_bytes: u64,
    #[cfg_attr(not(feature = "multipart"), allow(dead_code))]
    pub(crate) max_file_bytes: u64,
    /// `[multipart] upload_dir`: the root every `part:save` resolves
    /// inside. `None` leaves `save` unavailable. Shared rather than
    /// cloned per request — it is set once at startup and never changes.
    #[cfg_attr(not(feature = "multipart"), allow(dead_code))]
    pub(crate) upload_root: Option<std::sync::Arc<std::path::PathBuf>>,
}

impl Default for FormLimits {
    fn default() -> Self {
        let defaults = crate::config::LimitsConfig::default();
        Self {
            max_parts: defaults.max_form_parts,
            max_field_bytes: defaults.max_field_bytes,
            max_file_bytes: defaults.max_file_bytes,
            upload_root: None,
        }
    }
}

impl LuaRequest {
    /// Caps this request's body at `limit` bytes *as it arrives*.
    ///
    /// The `Content-Length` check in
    /// [`Protection`](crate::protect::Protection) only sees what the client
    /// declared; a chunked body declares nothing and a dishonest one declares
    /// the wrong thing. This counts what actually shows up and fails the
    /// stream the moment it passes the ceiling, so an oversized upload is cut
    /// mid-flight instead of being buffered in full.
    ///
    /// The violations are also recorded in the returned flags, because by
    /// the time either failure surfaces it has crossed into Lua and become
    /// an opaque error value. The flags let the handler answer `413` (too
    /// large) or `408` (stalled) instead of a generic `500`.
    pub(crate) fn guard_body(
        &mut self,
        limit: u64,
        stall: Option<std::time::Duration>,
    ) -> BodyGuards {
        let guards = BodyGuards {
            oversized: Arc::new(AtomicBool::new(false)),
            stalled: Arc::new(AtomicBool::new(false)),
        };
        // Recorded for `req:read(n)`'s clamp, so the bound is readable at
        // the point that allocates.
        self.body_limit = limit;
        let inner = std::mem::take(self.req.body_mut());
        let limited = LimitedBody {
            inner,
            limit,
            read: 0,
            exceeded: guards.oversized.clone(),
        };
        // The stall timer wraps the byte counter so its budget covers the
        // whole read; when disabled the counter is installed alone.
        *self.req.body_mut() = match stall {
            Some(budget) => StalledBody {
                inner: limited.boxed(),
                budget,
                deadline: None,
                stalled: guards.stalled.clone(),
            }
            .boxed(),
            None => limited.boxed(),
        };
        guards
    }

    /// Releases the unread remainder of the body.
    ///
    /// The request outlives the response as a Lua userdata — unreachable,
    /// but not collected until the state's next GC — and with it hyper's
    /// `Incoming`, which keeps the exchange open on the connection. A
    /// handler that never read the body, or stopped half-way (an oversized
    /// upload), would otherwise stall that connection until an unrelated
    /// collection happened to run.
    pub(crate) fn discard_body(&mut self) {
        *self.req.body_mut() = BoxBody::default();
    }
}

/// Clamps the sized `req:read(n)` argument — a Lua-supplied `usize` — to
/// the effective body limit **plus one**.
///
/// The `+ 1` is what keeps `LimitedBody` able to trip. The limiter flags
/// `oversized` only once *cumulative* `read > limit` (`body.rs`), and the
/// handler turns that flag into the `413`. Clamped to `limit` exactly, the
/// read loop would stop the moment `buf.len() >= limit`, so an over-limit
/// body whose frames happen to sum to the limit at a frame boundary would
/// never be pulled one frame further, never trip the limiter, and get the
/// application's `200` instead of a `413` — and 1 MiB is a multiple of
/// typical frame sizes, so "happen to" means "usually". The one extra
/// frame is the one that errors; its bytes are never appended, so the
/// buffer still never exceeds `limit`.
fn clamp_want(want: usize, limit: u64) -> usize {
    // Saturating twice: `limit + 1` must not wrap at `u64::MAX`, and the
    // cast must not wrap on a 32-bit `usize`.
    let ceiling = usize::try_from(limit.saturating_add(1)).unwrap_or(usize::MAX);
    want.min(ceiling)
}

impl UserData for LuaRequest {
    fn add_fields<'lua, F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("remote_addr", |_, req| Ok(req.peer_addr.to_string()));
        fields.add_field_method_get("method", |_, req| Ok(req.req.method().to_string()));
        fields.add_field_method_get("path", |_, req| Ok(req.req.uri().path().to_string()));
        fields.add_field_method_get("query", |lua, req| {
            // Query string parsed (and percent-decoded) into a table; for
            // repeated keys the last value wins.
            let table = lua.create_table()?;
            if let Some(query) = req.req.uri().query() {
                for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
                    table.set(k.as_ref(), v.as_ref())?;
                }
            }
            Ok(table)
        });
        fields.add_field_method_get("id", |_, req| Ok(req.id.clone()));
        fields.add_field_method_get("params", |lua, req| {
            // Path parameters captured by the router, e.g. `id` for a route
            // registered as `/users/:id`.
            let table = lua.create_table()?;
            for (k, v) in &req.params {
                table.set(k.as_str(), v.as_str())?;
            }
            Ok(table)
        });
        fields.add_field_method_get("uri", |lua, req| {
            let table = lua.create_table()?;
            let uri = req.req.uri();
            table.set("scheme", uri.scheme_str().unwrap_or_default())?;
            table.set("host", uri.host().unwrap_or_default())?;
            table.set("port", uri.port().map_or(0, |v| v.as_u16()))?;
            table.set("path", uri.path())?;
            table.set("authority", uri.authority().map_or("", |a| a.as_str()))?;
            table.set("query", uri.query().unwrap_or_default())?;
            Ok(table)
        });
        fields.add_field_method_get("headers", |lua, req| {
            // One value per name: for a repeated header the last value
            // wins. That collapse is a written decision, not an
            // accident, and each security-relevant name has its own
            // answer: `Authorization` never gets here repeated (two or
            // more are refused with a 400 in `Protection::check`, since
            // a collapsed credential can desync from a proxy in front);
            // `Cookie` is joined below, because a joined cookie string
            // is still a valid cookie string; `X-Forwarded-For` is only
            // trusted when `[rate_limit] trust_forwarded_for` says so,
            // and the limiter parses the header itself rather than this
            // table; `Content-Length` and `Transfer-Encoding` are
            // enforced by hyper before a request exists. A non-UTF-8
            // value becomes `""` — fail-closed, indistinguishable from
            // absent, and kept that way because distinguishing the two
            // would change the type of every header value a script reads.
            let headers = req.req.headers();
            let table = lua.create_table()?;
            for (k, v) in headers.iter() {
                table.set(k.as_str(), v.to_str().unwrap_or_default())?;
            }
            Ok(table)
        });
        fields.add_field_method_get("cookies", |_, req| {
            // All `Cookie` headers, joined so multi-header clients work.
            let header = req
                .req
                .headers()
                .get_all(hyper::header::COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join("; ");
            Ok(nitr_std::RequestCookies::parse(&header))
        });
    }

    fn add_methods<'lua, M: UserDataMethods<Self>>(methods: &mut M) {
        // Returns the best match among the given media types for the
        // request's `Accept` header, or nil when none is acceptable.
        methods.add_method("accepts", |_, req, offers: mlua::Variadic<String>| {
            let accept = req
                .req
                .headers()
                .get(hyper::header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("*/*");
            let refs: Vec<&str> = offers.iter().map(String::as_str).collect();
            Ok(nitr_std::best_match(accept, &refs).map(|i| offers[i].clone()))
        });

        // req:read()  — the next chunk as it arrives off the socket.
        // req:read(n) — at least n bytes, or fewer at the end of the body.
        //
        // The size argument is what lets a handler process an upload larger
        // than its own memory limit: the request-side mirror of a streaming
        // response. `nil` marks the end of the body.
        // `n` is taken as a full Lua integer, not `usize`: a Lua integer
        // is 64-bit on every platform while `usize` is not, and on a
        // 32-bit target a script asking for more than 4 GiB would fail
        // the conversion — an error on one platform for what is a plain
        // "read everything" on another. The saturation below (with the
        // clamp after it) keeps the pointer width invisible to scripts.
        methods.add_async_method_mut("read", |lua, mut req, n: Option<i64>| async move {
            let body_limit = req.body_limit;
            let reader = req.req.body_mut();
            let Some(want) = n else {
                while let Some(frame) = reader.frame().await {
                    // Trailer frames carry no data; keep reading.
                    if let Some(bytes) = frame.into_lua_err()?.data_ref() {
                        return Some(lua.create_string(bytes)).transpose();
                    }
                }
                return Ok(None);
            };

            if want < 0 {
                return Err(mlua::Error::RuntimeError(format!(
                    "req:read(n) requires a non-negative size, got {want}"
                )));
            }
            // The limiter installed by `guard_body` already bounds what the
            // body can deliver; the clamp makes that bound local and keeps
            // the loop's termination readable here, without trusting `want`.
            let want = clamp_want(usize::try_from(want).unwrap_or(usize::MAX), body_limit);
            let mut buf = Vec::new();
            while buf.len() < want {
                let Some(frame) = reader.frame().await else {
                    break;
                };
                if let Some(bytes) = frame.into_lua_err()?.data_ref() {
                    buf.extend_from_slice(bytes);
                }
            }
            if buf.is_empty() {
                return Ok(None);
            }
            Some(lua.create_string(buf)).transpose()
        });

        // req:form() — an `application/x-www-form-urlencoded` body as a
        // table. Percent-decoding and `+`-as-space are HTTP details worth
        // exactly one careful implementation, not one per application.
        // Repeated keys keep the last value, matching `req.query`.
        methods.add_async_method_mut("form", |lua, mut req, ()| async move {
            if req.cached_form.is_none() {
                let body = req
                    .req
                    .body_mut()
                    .collect()
                    .await
                    .into_lua_err()?
                    .to_bytes();
                req.cached_form = Some(
                    url::form_urlencoded::parse(&body)
                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                        .collect(),
                );
            }
            let table = lua.create_table()?;
            for (k, v) in req.cached_form.as_deref().unwrap_or_default() {
                table.set(k.as_str(), v.as_str())?;
            }
            Ok(table)
        });

        // req:multipart(fn) — invokes `fn` once per part, in arrival order.
        // See `crate::multipart` for why parts stream instead of being
        // collected. Returns the number of parts seen.
        #[cfg(feature = "multipart")]
        methods.add_async_method_mut("multipart", |lua, mut req, cb: mlua::Function| async move {
            let content_type = req
                .req
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let boundary = crate::multipart::boundary(content_type.as_deref())?;
            let limits = req.limits.clone();

            let body = std::mem::take(req.req.body_mut());
            let mut parser = multer::Multipart::new(body.into_data_stream(), boundary);

            let mut count = 0usize;
            loop {
                let Some(field) = parser.next_field().await.into_lua_err()? else {
                    break;
                };
                count += 1;
                if count > limits.max_parts {
                    return Err(mlua::Error::RuntimeError(format!(
                        "multipart body has more than {} parts",
                        limits.max_parts
                    )));
                }
                let part = lua.create_userdata(crate::multipart::LuaPart::new(
                    field,
                    limits.max_field_bytes,
                    limits.max_file_bytes,
                    limits.upload_root.clone(),
                ))?;
                let outcome = cb.call_async::<()>(&part).await;

                // The parser cannot advance while a field is alive, so the
                // part is reclaimed and drained whatever the callback did
                // with it — including nothing, and including failing.
                if let Ok(part) = part.borrow::<crate::multipart::LuaPart>()
                    && let Some(mut field) = part.reclaim()
                {
                    while field.chunk().await.into_lua_err()?.is_some() {}
                }
                outcome?;
            }
            Ok(count)
        });

        // req:fresh(etag, last_modified?) — whether the client's cached
        // copy is still current. Rust compares the validators; Lua decides
        // what identifies the resource, which is application knowledge.
        methods.add_method(
            "fresh",
            |_, req, (etag, last_modified): (Option<String>, Option<i64>)| {
                Ok(is_fresh(req.req.headers(), etag.as_deref(), last_modified))
            },
        );

        methods.add_async_method_mut("text", |lua, mut req, ()| async move {
            let reader = req.req.body_mut();
            let body = reader.collect().await.into_lua_err()?;
            lua.create_string(body.to_bytes())
        });

        methods.add_async_method_mut("json", |lua, mut req, ()| async move {
            let reader = req.req.body_mut();
            let collected = reader.collect().await.into_lua_err()?;
            let buf = collected.to_bytes();
            if buf.is_empty() {
                return Err(mlua::Error::external(
                    "Unexpected end of JSON input, probably request body is empty or already consumed",
                ));
            }
            let json = serde_json::from_slice::<SerdeValue>(&buf).into_lua_err()?;
            lua.to_value(&json)
        });
    }
}
