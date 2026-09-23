// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use std::convert::Infallible;

use http_body_util::{BodyExt as _, Empty, combinators::BoxBody};
use hyper::body::Bytes;
use hyper::{Method, Response, StatusCode, header};
use mlua::{AnyUserData, Function, Table as LuaTable, Value as LuaValue};

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

#[cfg(feature = "swagger")]
pub(crate) use error_page::escape_html;

/// What a request resolves to after Rust-side routing.
enum Target {
    /// A static asset resolved by a mount (already served).
    Static(Result<HttpResponse>),
    /// A matched route: the composed middleware+handler chain.
    Chain {
        chain: Function,
        params: Vec<(String, String)>,
        error_fn: Option<Function>,
        /// The route's `input` declaration, when it has one.
        input: Option<(Arc<crate::validation::InputSchemas>, AnyUserData)>,
        invalid_fn: Option<Function>,
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
        cors.apply(head.origin.as_ref(), resp.headers_mut());
    }
    // Negotiated only when on-the-fly compression can act on the answer:
    // with `[compression] enabled = false` (the default) the parse was
    // pure waste on every request that carried the header. The static
    // path negotiates for itself — sidecars are served regardless.
    let compression = protection.compression();
    if compression.negotiates() {
        let encoding = compression.negotiate(head.accept_encoding.as_ref());
        resp = compression.apply(resp, encoding);
    }
    // Last: HEAD is defined as GET with the body removed, so it must see
    // every header the GET would have had, compression included.
    if head.method == Method::HEAD {
        resp = strip_body(resp);
    }
    Ok(resp)
}

/// The parts of a request the response phase still needs after the request
/// itself has been handed to Lua.
///
/// Only the two header values that phase reads are kept — each a
/// refcounted `Bytes` clone — rather than a copy of the whole map, which
/// cost two allocations and a walk of every header on every request.
struct RequestHead {
    method: Method,
    accept_encoding: Option<header::HeaderValue>,
    origin: Option<header::HeaderValue>,
}

impl RequestHead {
    fn of(req: &LuaRequest) -> Self {
        let headers = req.req.headers();
        Self {
            method: req.req.method().clone(),
            accept_encoding: headers.get(header::ACCEPT_ENCODING).cloned(),
            origin: headers.get(header::ORIGIN).cloned(),
        }
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
    // The OpenAPI document and the Swagger UI page: prebuilt bytes served
    // after protection (so the rate limiter counts them) and before a Lua
    // state is checked out (so serving the bundle never occupies one).
    #[cfg(feature = "openapi")]
    if let Some(docs) = protection.docs()
        && let Some(resp) = docs.serve(&req)
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
            input,
            invalid_fn,
        } => {
            req.params = params;
            // Read before the request moves into Lua: the dev error page
            // honors `Accept` (a curl user does not want markup).
            let wants_html = dev_mode && accepts_html(req.req.headers());
            // A body the route does not accept is refused before any Lua
            // runs and before the body is read.
            let content = match &input {
                Some((schemas, _)) => match schemas.negotiate(req.req.headers()) {
                    Ok(content) => content,
                    Err(accepted) => {
                        tracing::debug!("request rejected: unsupported media type");
                        return unsupported_media_type(&accepted);
                    }
                },
                None => None,
            };
            // Uploads spool under the request's own directory, removed
            // with this guard when the request ends — whatever ended it.
            #[cfg(feature = "multipart")]
            let _spool = match (&input, &req.limits.upload_root) {
                (Some((schemas, _)), Some(root)) if schemas.needs_spool(content) => {
                    let spool = crate::validation::spool::SpoolDir::new(root, &req.id);
                    req.spool_dir = Some(spool.path().to_path_buf());
                    Some(spool)
                }
                _ => None,
            };
            #[cfg(not(feature = "multipart"))]
            let _ = content;
            // The request becomes a Lua value up front so the error handler
            // can receive the same object the handler saw.
            let req_ud = rt.lua().create_userdata(req)?;
            // Validation first, under the same budget as the handler; a
            // failure answers here, through `on_invalid` when there is one.
            let validated = match &input {
                Some((_, holder)) => {
                    let validate = app::validate_fn(rt.lua())?;
                    rt.call_function::<LuaValue>(validate, (holder, &req_ud))
                        .await
                }
                None => Ok(LuaValue::Nil),
            };
            let called = match validated {
                Ok(LuaValue::Nil) => {
                    // The `lua_handler` span: how long the script itself
                    // ran, with any `nitr.log` lines it emits nested
                    // inside. DEBUG so the decomposition is opt-in via the
                    // level filter.
                    let span =
                        tracing::debug_span!("lua_handler", elapsed_ms = tracing::field::Empty);
                    // The clock is read only when the span is enabled; a
                    // disabled span records nothing.
                    let started = (!span.is_disabled()).then(std::time::Instant::now);
                    let called = rt
                        .call_function::<LuaTable>(chain, &req_ud)
                        .instrument(span.clone())
                        .await;
                    if let Some(started) = started {
                        span.record("elapsed_ms", started.elapsed().as_millis() as u64);
                    }
                    called
                }
                Ok(LuaValue::Table(failure)) => {
                    tracing::debug!("request rejected: input validation failed");
                    let hooked = match invalid_fn {
                        Some(hook) => {
                            match rt
                                .call_function::<LuaTable>(hook, (failure.clone(), &req_ud))
                                .await
                            {
                                Ok(lua_resp) => match to_response(lua_resp) {
                                    Ok(resp) => Some(resp),
                                    Err(err) => {
                                        tracing::error!("invalid on_invalid response: {err}");
                                        None
                                    }
                                },
                                Err(err) => {
                                    tracing::error!("the on_invalid handler failed: {err}");
                                    None
                                }
                            }
                        }
                        None => None,
                    };
                    discard_body(&req_ud);
                    return match hooked {
                        Some(resp) => Ok(resp),
                        None => unprocessable(rt.lua(), failure),
                    };
                }
                Ok(other) => Err(Error::Script(format!(
                    "input validation returned {}, expected nil or a table",
                    other.type_name()
                ))),
                Err(err) => Err(err),
            };
            let err = match called {
                // `finish` releases the body itself: a streaming body may
                // still be reading from the request.
                Ok(lua_resp) => return finish(rt, lua_resp, &streams, dev_mode, &req_ud),
                Err(err) => err,
            };

            // An oversized body is a rejection, not an application failure:
            // answer it in Rust and skip the app's error handler, which
            // would only see an opaque read error.
            if guards.oversized() {
                tracing::debug!("request rejected: body exceeded max_body_bytes");
                discard_body(&req_ud);
                return plain_response(StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large");
            }
            // A stalled body likewise: the client is the culprit, and the
            // connection is closed with the response — keep-alive would
            // hand a misbehaving client a fresh slot.
            if guards.stalled() {
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
                Some(resp) => Ok(with_failure(resp, info, true)),
                None => {
                    // The script path backs up the error's own `source` for
                    // the dev snippet: Lua truncates long chunk names.
                    let script = dev_mode.then(|| app::script_path(rt.lua())).flatten();
                    error_page_with_source(&info, dev_mode, wants_html, script.as_deref())
                        .map(|resp| with_failure(resp, info, false))
                }
            }
        }
    }
}

/// The 415 for a body the route's `input` does not accept, naming what it
/// does.
fn unsupported_media_type(accepted: &str) -> Result<HttpResponse> {
    let body = serde_json::json!({
        "code": "UNSUPPORTED_MEDIA_TYPE",
        "message": format!("unsupported media type; accepted: {accepted}"),
        "accepted": accepted.split(", ").collect::<Vec<_>>(),
    });
    let mut resp = json_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, &body)?;
    if let Ok(value) = header::HeaderValue::from_str(accepted) {
        resp.headers_mut().insert(header::ACCEPT, value);
    }
    Ok(resp)
}

/// The default 422: the validation failure table as JSON.
fn unprocessable(lua: &mlua::Lua, failure: LuaTable) -> Result<HttpResponse> {
    use mlua::LuaSerdeExt as _;
    let body: serde_json::Value = lua.from_value(LuaValue::Table(failure))?;
    json_response(StatusCode::UNPROCESSABLE_ENTITY, &body)
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Result<HttpResponse> {
    use http_body_util::Full;
    let bytes = serde_json::to_vec(body).map_err(|err| Error::Script(err.to_string()))?;
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(bytes)).boxed())?)
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
        // `HEAD` is `GET` without the body, so a `GET` route serves it
        // (see `lookup`); the body is dropped once the response is
        // complete.
        let target = match app.lookup(req.req.method(), req.req.uri().path()) {
            app::Lookup::Route { index, params } => Target::Chain {
                chain: app.chains[index].fns.clone(),
                params,
                // Resolved at compile time: the route's own handler first,
                // the app-wide one as fallback.
                error_fn: app.chains[index].error_fn.clone(),
                input: app.chains[index].input.clone(),
                invalid_fn: app.chains[index].invalid_fn.clone(),
            },
            app::Lookup::Options(allowed) => Target::Options(allowed),
            app::Lookup::MethodNotAllowed(allowed) => Target::MethodNotAllowed(allowed),
            app::Lookup::NotFound => Target::NotFound,
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

mod error_page;
mod respond;
#[cfg(test)]
mod tests;

use error_page::{accepts_html, error_page_with_source, error_response, with_failure};
use respond::to_response;
pub(crate) use respond::{build_response, empty_response, plain_response};
