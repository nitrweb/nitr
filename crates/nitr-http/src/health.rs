// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Health and readiness endpoints, answered entirely in Rust.
//!
//! Liveness never touches a Lua state: a probe that queued behind a
//! saturated pool would trigger the restart it exists to prevent.
//! Readiness reports whether the server should receive traffic — `true`
//! from the moment the pool is built and the handler compiled (both are
//! preconditions of the server existing at all, and pending migrations
//! refuse the boot), flipping to `false` the instant a graceful drain
//! starts, before any request can fail. An application cannot influence
//! either answer.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Method, Response, StatusCode};

use crate::config::HealthConfig;

/// The state a health endpoint answers from, shared with the accept loop.
pub(crate) struct HealthState {
    pub(crate) cfg: HealthConfig,
    pub(crate) ready: Arc<AtomicBool>,
}

fn plain(status: StatusCode, body: &'static str) -> Response<BoxBody<Bytes, Infallible>> {
    use http_body_util::BodyExt as _;
    let mut resp =
        Response::new(http_body_util::Full::new(Bytes::from_static(body.as_bytes())).boxed());
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    // Probe answers must never be cached: a stale "ok" defeats the probe.
    resp.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    resp
}

impl HealthState {
    /// Answers a health request, or `None` when the path is neither
    /// endpoint. Only `GET` and `HEAD` are recognized — a `POST /healthz`
    /// belongs to the application, not the prober.
    pub(crate) fn answer(
        &self,
        method: &Method,
        path: &str,
    ) -> Option<Response<BoxBody<Bytes, Infallible>>> {
        if !matches!(*method, Method::GET | Method::HEAD) {
            return None;
        }
        if path == self.cfg.liveness {
            return Some(plain(StatusCode::OK, "ok"));
        }
        if path == self.cfg.readiness {
            return Some(if self.ready.load(Ordering::Relaxed) {
                plain(StatusCode::OK, "ok")
            } else {
                plain(StatusCode::SERVICE_UNAVAILABLE, "draining")
            });
        }
        None
    }
}

/// A hyper service that answers *only* the health endpoints — everything
/// else is 404. Served on the separate `[health] bind` listener, so the
/// operational port exposes nothing but the probes.
pub(crate) async fn serve_probes(listener: tokio::net::TcpListener, state: Arc<HealthState>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let svc =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let state = state.clone();
                    async move {
                        Ok::<_, Infallible>(
                            state
                                .answer(req.method(), req.uri().path())
                                .unwrap_or_else(|| plain(StatusCode::NOT_FOUND, "not found")),
                        )
                    }
                });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(ready: bool) -> HealthState {
        HealthState {
            cfg: HealthConfig::default(),
            ready: Arc::new(AtomicBool::new(ready)),
        }
    }

    #[test]
    fn probes_answer_and_everything_else_passes_through() {
        let s = state(true);
        let resp = s.answer(&Method::GET, "/healthz").expect("liveness");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["cache-control"], "no-store");
        let resp = s.answer(&Method::HEAD, "/readyz").expect("readiness");
        assert_eq!(resp.status(), StatusCode::OK);

        // Not a probe: the application's routes are untouched.
        assert!(s.answer(&Method::GET, "/health").is_none());
        assert!(s.answer(&Method::GET, "/").is_none());
        // A POST to the probe path belongs to the application too.
        assert!(s.answer(&Method::POST, "/healthz").is_none());
    }

    #[test]
    fn readiness_flips_with_the_drain_while_liveness_stays_up() {
        let s = state(false);
        let resp = s.answer(&Method::GET, "/readyz").expect("readiness");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // The process is still alive — that is the whole distinction.
        let resp = s.answer(&Method::GET, "/healthz").expect("liveness");
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
