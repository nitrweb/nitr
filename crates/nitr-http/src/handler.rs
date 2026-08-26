// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use std::convert::Infallible;

use http_body_util::{BodyExt as _, Empty, Full, combinators::BoxBody};
use hyper::body::Bytes;
use hyper::{Method, Response, StatusCode, header};
use mlua::{AnyUserData, Function, LuaString, Table as LuaTable, Value as LuaValue};

use futures_util::FutureExt as _;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::Instrument as _;

use crate::app::{self, AppState};
use crate::protect::Protection;
use crate::request::LuaRequest;
use crate::static_files::{self, StaticMount};
use crate::stream;
use nitr_core::{Error, ErrorInfo, Result, Runtime, RuntimeGuard, RuntimePool};

pub(crate) type HttpResponse = Response<BoxBody<Bytes, Infallible>>;

/// What a request resolves to after Rust-side routing.
enum Target {
    /// A static asset resolved by a mount (already served).
    Static(Result<HttpResponse>),
    /// A matched route: the composed middleware+handler chain.
    Chain {
        chain: Function,
        params: Vec<(String, String)>,
        error_fn: Option<Function>,
    },
    NotFound,
    /// An `OPTIONS` on a known path with no `options` route: answered with
    /// `Allow` rather than handed to the application.
    Options(Vec<Method>),
    MethodNotAllowed(Vec<Method>),
}

/// Serves one request: protection checks, dispatch, and the `X-Request-ID`
/// echo on every response.
///
/// The whole call is wrapped in a panic boundary: a panic in Rust code
/// (Nitr's or an extension module's) becomes a 500 and recycles the Lua
/// state instead of killing the connection.
///
/// This boundary is the last line of Nitr's error-handling hierarchy, not
/// an exception mechanism. Every *recoverable* failure — a Lua error, a
/// timeout, a memory limit, I/O, invalid input — travels as a `Result`
/// from the failing call to `ErrorInfo` to a response, and must never be
/// rerouted through here. `catch_unwind` exists solely to contain genuine
/// bugs (a panic is always a bug, ours or a module's), and this is the one
/// such boundary: do not add more. The containment is only real because
/// `[profile.release]` keeps the default `panic = "unwind"` — see the
/// profile comment in the workspace `Cargo.toml`.
pub(crate) async fn handle(
    pool: &RuntimePool,
    req: LuaRequest,
    streams: Arc<Semaphore>,
    protection: Arc<Protection>,
) -> Result<HttpResponse> {
    let id = req.id.clone();
    let dev_mode = protection.dev_mode();
    // Kept for the response phase, which runs after the request has been
    // moved into the Lua state.
    let head = RequestHead::of(&req);

    let served = AssertUnwindSafe(handle_inner(pool, req, streams, protection.clone()))
        .catch_unwind()
        .await;

    let mut resp = match served {
        Ok(result) => result?,
        Err(payload) => {
            // The guard held by `handle_inner` was dropped during the unwind,
            // which the pool treats as damage and recycles.
            let err = Error::Panic(panic_message(&payload));
            tracing::error!("{err}");
            error_response(&err, dev_mode)?
        }
    };
    // Completes the `request` span: its close line now reads as an access
    // log entry (id, method, path, status, timing).
    tracing::Span::current().record("status", resp.status().as_u16());
    if let Ok(value) = header::HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", value);
    }
    if let Some(cors) = protection.cors() {
        cors.apply(&head.headers, resp.headers_mut());
    }
    let encoding = protection.compression().negotiate(head.accept_encoding());
    resp = protection.compression().apply(resp, encoding);
    // Last: HEAD is defined as GET with the body removed, so it must see
    // every header the GET would have had, compression included.
    if head.method == Method::HEAD {
        resp = strip_body(resp);
    }
    Ok(resp)
}

/// The parts of a request the response phase still needs after the request
/// itself has been handed to Lua.
struct RequestHead {
    method: Method,
    headers: header::HeaderMap,
}

impl RequestHead {
    fn of(req: &LuaRequest) -> Self {
        Self {
            method: req.req.method().clone(),
            headers: req.req.headers().clone(),
        }
    }

    fn accept_encoding(&self) -> Option<&header::HeaderValue> {
        self.headers.get(header::ACCEPT_ENCODING)
    }
}

/// Drops the body of a `HEAD` response while keeping every header, so the
/// response is byte-identical to the `GET` apart from the body itself.
///
/// The length the `GET` would have reported is pinned into an explicit
/// `Content-Length` first: hyper derives that header from the body, and an
/// emptied body would otherwise advertise `0` — a `HEAD` that lies about
/// the size of the resource it describes.
fn strip_body(resp: HttpResponse) -> HttpResponse {
    use hyper::body::Body as _;

    let (mut parts, body) = resp.into_parts();
    if !parts.headers.contains_key(header::CONTENT_LENGTH)
        && let Some(len) = body.size_hint().exact()
    {
        parts.headers.insert(header::CONTENT_LENGTH, len.into());
    }
    HttpResponse::from_parts(parts, Empty::<Bytes>::new().boxed())
}

/// Best-effort text of a panic payload (`panic!("...")` produces a `&str`
/// or `String`; anything else is opaque).
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "non-string panic payload".to_string()
}

async fn handle_inner(
    pool: &RuntimePool,
    mut req: LuaRequest,
    streams: Arc<Semaphore>,
    protection: Arc<Protection>,
) -> Result<HttpResponse> {
    // Rust-side protection runs before a Lua state is even checked out.
    if let Some(rejection) = protection.check(&req) {
        return rejection;
    }
    // A preflight carries no body and calls no handler: answering it here
    // keeps a pooled Lua state free for a request that needs one.
    if let Some(cors) = protection.cors()
        && let Some(resp) = cors.preflight(&req.req)
    {
        return resp;
    }
    // `check` only compared the *declared* length; from here the bytes are
    // counted — and their arrival clocked — as the handler reads them.
    let guards = req.guard_body(protection.max_body_bytes(), protection.body_read_timeout());
    req.limits = protection.form_limits();

    // Bounded wait for a state: past the budget the request is shed rather
    // than queued behind an overloaded pool. Nothing Lua-side has run yet,
    // so shedding is cheap.
    let Some(mut rt) = pool.get_timeout(protection.pool_wait()).await else {
        tracing::warn!("request shed: no Lua state available within the pool wait budget");
        let mut resp = plain_response(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")?;
        resp.headers_mut()
            .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
        return Ok(resp);
    };
    // Dev-mode hot reload happens in the serve loop (a notify watcher
    // driving the pool rebuild), not here: the request path stays free of
    // per-request stat calls, and a save is noticed when it happens rather
    // than by the next request.
    let dev_mode = rt.dev_mode();

    // A state serves one request at a time, so "this request" is
    // unambiguous: the outbound budget starts fresh here, and outbound
    // calls can carry a `traceparent` derived from this request's id.
    nitr_std::reset_outbound_budget(rt.lua());
    nitr_std::set_trace_context(rt.lua(), &req.id);

    let target = match resolve(&rt, &req, protection.compression()).await {
        Ok(target) => target,
        Err(err) => {
            tracing::error!("failed to resolve the request route: {err}");
            return error_response(&err, dev_mode);
        }
    };

    match target {
        Target::Static(resp) => resp,
        Target::NotFound => plain_response(StatusCode::NOT_FOUND, "Not Found"),
        // An `OPTIONS` on a path that exists is a question about the
        // resource, not a request the application should have to answer;
        // RFC 9110 wants `Allow`, not `405`.
        Target::Options(allowed) => {
            let mut resp = empty_response(StatusCode::NO_CONTENT)?;
            resp.headers_mut()
                .insert(header::ALLOW, crate::cors::allow_header(&allowed));
            Ok(resp)
        }
        Target::MethodNotAllowed(allowed) => {
            let mut resp = plain_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")?;
            resp.headers_mut()
                .insert(header::ALLOW, crate::cors::allow_header(&allowed));
            Ok(resp)
        }
        Target::Chain {
            chain,
            params,
            error_fn,
        } => {
            req.params = params;
            // Read before the request moves into Lua: the dev error page
            // honors `Accept` (a curl user does not want markup).
            let wants_html = dev_mode && accepts_html(req.req.headers());
            // The request becomes a Lua value up front so the error handler
            // can receive the same object the handler saw.
            let req_ud = rt.lua().create_userdata(req)?;
            // The `lua_handler` span: how long the script itself ran, with
            // any `nitr.log` lines it emits nested inside. DEBUG so the
            // decomposition is opt-in via the level filter.
            let span = tracing::debug_span!("lua_handler", elapsed_ms = tracing::field::Empty);
            let started = std::time::Instant::now();
            let called = rt
                .call_function::<LuaTable>(chain, &req_ud)
                .instrument(span.clone())
                .await;
            span.record("elapsed_ms", started.elapsed().as_millis() as u64);
            let err = match called {
                // `finish` releases the body itself: a streaming body may
                // still be reading from the request.
                Ok(lua_resp) => return finish(rt, lua_resp, &streams, dev_mode, &req_ud),
                Err(err) => err,
            };

            // An oversized body is a rejection, not an application failure:
            // answer it in Rust and skip the app's error handler, which
            // would only see an opaque read error.
            if guards.oversized.load(std::sync::atomic::Ordering::Relaxed) {
                tracing::debug!("request rejected: body exceeded max_body_bytes");
                discard_body(&req_ud);
                return plain_response(StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large");
            }
            // A stalled body likewise: the client is the culprit, and the
            // connection is closed with the response — keep-alive would
            // hand a misbehaving client a fresh slot.
            if guards.stalled.load(std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!("request rejected: body read stalled beyond [limits] body_read_ms");
                discard_body(&req_ud);
                let mut resp = plain_response(StatusCode::REQUEST_TIMEOUT, "Request Timeout")?;
                resp.headers_mut().insert(
                    header::CONNECTION,
                    header::HeaderValue::from_static("close"),
                );
                return Ok(resp);
            }

            // Classified once, on the error path only; the structured
            // fields make the failure greppable without the dev page.
            let info = ErrorInfo::from_error(&err);
            tracing::error!(
                error.kind = info.kind,
                error.source = info.source.as_deref(),
                error.line = info.line,
                error.module = info.module.as_deref(),
                "handler failed: {}",
                info.message
            );
            if dev_mode && let Some(traceback) = info.traceback.as_deref() {
                tracing::debug!("stack traceback:{traceback}");
            }

            let mut handled = None;
            if let Some(error_fn) = error_fn {
                let err_value = nitr_std::error_lua_value(rt.lua(), &info)?;
                match rt
                    .call_function::<LuaTable>(error_fn, (err_value, &req_ud))
                    .await
                {
                    Ok(lua_resp) => match to_response(lua_resp) {
                        Ok(resp) => handled = Some(resp),
                        Err(err) => tracing::error!("invalid error-handler response: {err}"),
                    },
                    Err(err) => tracing::error!("the app error handler failed: {err}"),
                }
            }
            discard_body(&req_ud);
            match handled {
                Some(resp) => Ok(resp),
                None => {
                    // The script path backs up the error's own `source` for
                    // the dev snippet: Lua truncates long chunk names.
                    let script = dev_mode.then(|| app::script_path(rt.lua())).flatten();
                    error_page_with_source(&info, dev_mode, wants_html, script.as_deref())
                }
            }
        }
    }
}

/// Releases the unread remainder of the request body once nothing will read
/// it again, so hyper can finish the exchange without waiting on a GC.
fn discard_body(req_ud: &AnyUserData) {
    match req_ud.borrow_mut::<LuaRequest>() {
        Ok(mut req) => req.discard_body(),
        // Only reachable if a script stashed a live borrow; the body is then
        // released at the next collection instead.
        Err(err) => tracing::debug!("could not release the request body: {err}"),
    }
}

/// Completes a successful handler call: a function body becomes a
/// streaming response (moving the runtime into the producer task, subject
/// to the `max_streams` cap); anything else converts as a static response.
fn finish(
    rt: RuntimeGuard,
    lua_resp: LuaTable,
    streams: &Arc<Semaphore>,
    dev_mode: bool,
    req_ud: &AnyUserData,
) -> Result<HttpResponse> {
    match lua_resp.raw_get::<LuaValue>("body") {
        // The streaming producer keeps running after this returns and may
        // still read from the request, so its body stays alive.
        Ok(LuaValue::Function(body_fn)) => {
            let permit = match streams.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    tracing::warn!("streaming response rejected: max_streams reached");
                    return plain_response(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable");
                }
            };
            match stream::stream_response(rt, &lua_resp, body_fn, permit) {
                Ok(resp) => Ok(resp),
                Err(err) => {
                    tracing::error!("invalid streaming response: {err}");
                    error_response(&err, dev_mode)
                }
            }
        }
        Ok(_) => {
            discard_body(req_ud);
            match to_response(lua_resp) {
                Ok(resp) => Ok(resp),
                Err(err) => {
                    tracing::error!("invalid handler response: {err}");
                    error_response(&err, dev_mode)
                }
            }
        }
        Err(err) => {
            discard_body(req_ud);
            let err = Error::from(err);
            tracing::error!("invalid handler response: {err}");
            error_response(&err, dev_mode)
        }
    }
}

/// Routes the request in Rust against this state's compiled dispatch
/// table. Static mounts are consulted after a router miss.
async fn resolve(
    rt: &Runtime,
    req: &LuaRequest,
    compression: &crate::compress::Compression,
) -> Result<Target> {
    let ud = app::state(rt.lua())?;
    let (target, statics): (Target, Arc<Vec<StaticMount>>) = {
        let state = ud.borrow::<AppState>()?;
        let app = &state.dispatch.0;
        let method = req.req.method();
        let target = match app.router.at(req.req.uri().path()) {
            Ok(matched) => {
                // `HEAD` is `GET` without the body, so a `GET` route serves
                // it; the body is dropped once the response is complete.
                // An explicit `head` route still wins.
                let route = matched.value.get(method).or_else(|| {
                    (*method == Method::HEAD)
                        .then(|| matched.value.get(&Method::GET))
                        .flatten()
                });
                match route {
                    Some(&idx) => Target::Chain {
                        chain: app.chains[idx].fns.clone(),
                        params: matched
                            .params
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect(),
                        // Resolved at compile time: the route's own handler
                        // first, the app-wide one as fallback.
                        error_fn: app.chains[idx].error_fn.clone(),
                    },
                    None if *method == Method::OPTIONS => {
                        Target::Options(matched.value.keys().cloned().collect())
                    }
                    None => Target::MethodNotAllowed(matched.value.keys().cloned().collect()),
                }
            }
            Err(_) => Target::NotFound,
        };
        (target, state.statics.clone())
    };

    Ok(match target {
        Target::NotFound if !statics.is_empty() => {
            match static_files::try_serve(&statics, req, compression).await {
                Some(resp) => Target::Static(resp),
                None => target,
            }
        }
        other => other,
    })
}

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
fn to_response(lua_resp: LuaTable) -> Result<HttpResponse> {
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
                let value = HeaderValue::from_str(&value)
                    .map_err(|_| Error::Script(format!("invalid Set-Cookie value `{value}`")))?;
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

/// A generic 500 that never leaks internals to clients; in development mode
/// the classified error is rendered in context for fast iteration.
fn error_response(err: &Error, dev_mode: bool) -> Result<HttpResponse> {
    error_page_with_source(&ErrorInfo::from_error(err), dev_mode, false, None)
}

/// Whether the client would rather see HTML than plain text.
fn accepts_html(headers: &hyper::HeaderMap) -> bool {
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
fn error_page_with_source(
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

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::Lua;

    fn eval_table(lua: &Lua, src: &str) -> LuaTable {
        lua.load(src).eval().expect("eval response table")
    }

    async fn body_bytes(resp: HttpResponse) -> Bytes {
        resp.into_body()
            .collect()
            .await
            .expect("collect")
            .to_bytes()
    }

    #[tokio::test]
    async fn defaults_to_200_and_empty_body() {
        let lua = Lua::new();
        let resp = to_response(eval_table(&lua, "{}")).expect("response");
        assert_eq!(resp.status(), 200);
        assert!(body_bytes(resp).await.is_empty());
    }

    #[tokio::test]
    async fn preserves_binary_bodies() {
        let lua = Lua::new();
        let table = eval_table(
            &lua,
            r#"{ status = 201, body = string.char(0, 255, 1) .. "x" }"#,
        );
        let resp = to_response(table).expect("response");
        assert_eq!(resp.status(), 201);
        assert_eq!(&body_bytes(resp).await[..], &[0, 255, 1, b'x']);
    }

    #[tokio::test]
    async fn supports_multi_value_and_integer_headers() {
        let lua = Lua::new();
        let table = eval_table(
            &lua,
            r#"{
                headers = {
                    ["Set-Cookie"] = { "a=1", "b=2" },
                    ["X-Limit"] = 42,
                    ["Content-Type"] = "text/plain",
                },
            }"#,
        );
        let resp = to_response(table).expect("response");
        let cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().collect();
        assert_eq!(cookies, ["a=1", "b=2"]);
        assert_eq!(resp.headers()["x-limit"], "42");
        assert_eq!(resp.headers()["content-type"], "text/plain");
    }

    #[tokio::test]
    async fn rejects_invalid_headers_gracefully() {
        let lua = Lua::new();
        let bad_name = eval_table(&lua, r#"{ headers = { ["bad name"] = "x" } }"#);
        assert!(to_response(bad_name).is_err());

        let bad_type = eval_table(&lua, r#"{ headers = { ok = function() end } }"#);
        assert!(to_response(bad_type).is_err());
    }

    #[tokio::test]
    async fn error_responses_hide_details_unless_dev_mode() {
        let err = Error::Script("secret traceback".into());
        let prod = error_response(&err, false).expect("prod response");
        assert_eq!(prod.status(), 500);
        assert_eq!(&body_bytes(prod).await[..], b"Internal Server Error");

        let dev = error_response(&err, true).expect("dev response");
        let body = body_bytes(dev).await;
        assert!(String::from_utf8_lossy(&body).contains("secret traceback"));
    }
}
