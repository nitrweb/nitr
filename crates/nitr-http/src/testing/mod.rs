// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! In-process testing: dispatch requests through the full protection /
//! router / middleware / handler path without binding a socket. This is
//! the foundation of `nitr test` and of Rust-level integration tests.
//!
//! Also here, because they need crate-private types: the request options
//! `nitr.test.request` understands ([`TestRequest`]), the fake request and
//! the in-state application `nitr test` unit tests use ([`fake_request`],
//! [`load_app`]), the server-sent-events parser behind `resp:sse()`
//! ([`parse_sse`]), and the watcher behind `nitr test --watch`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, Uri};
use tokio::sync::Semaphore;
use tracing::Instrument as _;

use crate::handler;
use crate::protect::Protection;
use crate::request::LuaRequest;
use crate::server::current_pool;
use nitr_core::{Error, ErrorInfo, Result, RuntimePool};

mod request;
mod sse;
mod unit;

pub use request::TestRequest;
pub use sse::{SseEvent, parse_sse};
pub use unit::{fake_request, load_app};

/// The peer a request comes from when the test does not say.
const DEFAULT_PEER: ([u8; 4], u16) = ([127, 0, 0, 1], 0);

/// An in-process client for a built [`Server`](crate::Server); obtained
/// via [`Server::test_client()`](crate::Server::test_client).
#[derive(Clone)]
pub struct TestClient {
    pool: Arc<RwLock<Arc<RuntimePool>>>,
    streams: Arc<Semaphore>,
    protection: Arc<Protection>,
}

/// Why a request answered with the error path: the classified failure the
/// handler raised, and whether the application's `on_error` produced the
/// response.
///
/// The handler attaches it to the response as an `http::Extensions`
/// value. Hyper never serializes extensions, so a real client receives
/// exactly the bytes it always did; [`TestClient`] lifts it into
/// [`TestResponse::error`], which is how `nitr test` explains a `500`
/// without dev mode.
#[derive(Debug, Clone)]
pub struct HandlerFailure {
    /// The classified error: kind, message, source, line, traceback.
    pub info: ErrorInfo,
    /// Whether the app's `on_error` handled it.
    pub handled: bool,
}

/// A fully collected response from [`TestClient::request`].
#[derive(Debug)]
pub struct TestResponse {
    /// HTTP status code.
    pub status: u16,
    /// Header pairs in response order (repeated names appear repeatedly).
    pub headers: Vec<(String, String)>,
    /// The collected response body.
    pub body: Bytes,
    /// The handler's failure, when the request took the error path.
    pub error: Option<HandlerFailure>,
}

impl TestClient {
    pub(crate) fn new(
        pool: Arc<RwLock<Arc<RuntimePool>>>,
        streams: Arc<Semaphore>,
        protection: Arc<Protection>,
    ) -> Self {
        Self {
            pool,
            streams,
            protection,
        }
    }

    /// Performs one request through the real dispatch path and collects
    /// the response (streaming bodies included).
    pub async fn request(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &[(String, String)],
        body: Option<Bytes>,
    ) -> Result<TestResponse> {
        self.send(TestRequest {
            method: method.to_string(),
            path: path_and_query.to_string(),
            headers: headers.to_vec(),
            body,
            remote_addr: None,
            timeout: None,
        })
        .await
    }

    /// Performs a [`TestRequest`]: its peer address is what the protection
    /// layer (the rate limiter above all) sees, and its timeout bounds the
    /// whole exchange from the client side, body collection included — so
    /// a stream that never ends fails the test instead of hanging the run.
    ///
    /// The exchange runs inside a `request` span shaped like the one the
    /// live service opens, so log lines carry the request id, method and
    /// path, and the span's close line is the access-log entry a real
    /// request would produce.
    pub async fn send(&self, spec: TestRequest) -> Result<TestResponse> {
        let method: Method =
            spec.method.to_uppercase().parse().map_err(|_| {
                Error::Config(format!("invalid test request method `{}`", spec.method))
            })?;
        let uri: Uri = spec
            .path
            .parse()
            .map_err(|_| Error::Config(format!("invalid test request path `{}`", spec.path)))?;

        let mut builder = Request::builder().method(method.clone()).uri(uri.clone());
        for (name, value) in &spec.headers {
            builder = builder.header(name, value);
        }
        let req = builder.body(
            Full::new(spec.body.unwrap_or_default())
                .map_err(|never| match never {})
                .boxed(),
        )?;

        let id = self.protection.request_id_for_parts(req.headers());
        let span = tracing::info_span!(
            "request",
            id = %id,
            method = %method,
            path = %uri.path(),
            status = tracing::field::Empty,
        );
        let peer = spec.remote_addr.unwrap_or_else(|| DEFAULT_PEER.into());
        let req = LuaRequest::synthetic(req, peer, id.into());

        let pool = current_pool(&self.pool);
        let streams = self.streams.clone();
        let protection = self.protection.clone();
        let exchange = async move {
            let resp = handler::handle(&pool, req, streams, protection).await?;
            collect(resp).await
        }
        .instrument(span);
        match spec.timeout {
            None => exchange.await,
            Some(limit) => tokio::time::timeout(limit, exchange).await.map_err(|_| {
                Error::Script(format!(
                    "the test request {method} {} did not complete within {} s (its \
                         `timeout` option); a streaming body that never ends?",
                    uri.path(),
                    limit.as_secs_f64()
                ))
            })?,
        }
    }
}

/// Reads a response into a [`TestResponse`].
async fn collect(resp: handler::HttpResponse) -> Result<TestResponse> {
    let status = resp.status().as_u16();
    let error = resp.extensions().get::<HandlerFailure>().cloned();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let body = match resp.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        // The response body error type is Infallible.
        Err(never) => match never {},
    };
    Ok(TestResponse {
        status,
        headers,
        body,
        error,
    })
}

impl TestResponse {
    /// The first value of a (case-insensitive) header, if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Resolves a fixture file a test names (`t.db.seed("fixtures/x.sql")`)
/// under `root`, the tests directory: the static server's lexical rule
/// (no `..`, no absolute path, no NUL), then canonical containment, and
/// it must be a regular file.
///
/// # Errors
///
/// A path that could name something outside `root`, or that is not a
/// regular file there.
pub fn fixture_path(root: &Path, rel: &str) -> Result<PathBuf> {
    let refuse = |why: &str| {
        Error::Script(format!(
            "fixture `{rel}` {why}: fixtures are regular files under [testing] dir {}",
            root.display()
        ))
    };
    let joined =
        crate::safe_path::safe_join(root, rel).map_err(|_| refuse("is not a relative path"))?;
    let (Ok(canonical), Ok(root_canonical)) = (joined.canonicalize(), root.canonicalize()) else {
        return Err(refuse("does not exist"));
    };
    if !canonical.starts_with(&root_canonical) {
        return Err(refuse("resolves outside the tests directory"));
    }
    if !canonical.is_file() {
        return Err(refuse("is not a regular file"));
    }
    Ok(canonical)
}

/// Keeps the `nitr test --watch` watcher alive; dropping it stops the
/// watcher thread.
pub struct TestWatch {
    _guard: crate::watch::WatchGuard,
}

/// Watches what `nitr dev` watches (the handler's directory, the
/// configuration script, the templates) plus `extra` (the tests
/// directory), sending on `changed` after each debounced burst of changes
/// to a Lua source or a template. `None` when there is nothing to watch
/// or the platform watcher is unavailable.
pub fn watch_tests(
    cfg: &crate::Config,
    extra: &[PathBuf],
    changed: tokio::sync::mpsc::Sender<()>,
) -> Option<TestWatch> {
    crate::watch::spawn(cfg, extra, changed).map(|guard| TestWatch { _guard: guard })
}

/// Parses a `remote_addr` option: an IP, or an `ip:port`.
pub(crate) fn parse_peer(text: &str) -> Option<SocketAddr> {
    text.parse::<SocketAddr>().ok().or_else(|| {
        text.parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 0))
    })
}

/// A duration option in seconds (`timeout = 5`): finite, positive, and at
/// most a day — `Duration::from_secs_f64` would panic on the rest.
pub(crate) fn seconds(name: &str, secs: f64) -> mlua::Result<Duration> {
    Duration::try_from_secs_f64(secs)
        .ok()
        .filter(|d| !d.is_zero() && *d <= Duration::from_secs(86_400))
        .ok_or_else(|| {
            mlua::Error::RuntimeError(format!(
                "`{name}` must be a number of seconds between 0 and 86400, got {secs}"
            ))
        })
}

#[cfg(test)]
mod tests;
