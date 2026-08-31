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

/// The main listener's guards, ported onto the probe listener: plain
/// values rather than a `Config`, so [`serve_probes`] stays testable in
/// isolation. `header_read` and `max_buf_size` are `[limits]`'s own —
/// "how long may a client take to say what it wants?" has one answer per
/// process — while the connection cap is `[health] max_connections`,
/// deliberately far below the main listener's.
#[derive(Clone, Copy)]
pub(crate) struct ProbeGuards {
    /// `[health] max_connections`; clamped to at least 1.
    pub(crate) max_connections: usize,
    /// `[limits] header_read_ms` as a duration; `None` disables the
    /// deadline, exactly as it does on the main listener.
    pub(crate) header_read: Option<std::time::Duration>,
    /// `[limits] max_header_bytes`, already clamped to hyper's 8 KiB floor.
    pub(crate) max_buf_size: usize,
}

/// A hyper service that answers *only* the health endpoints — everything
/// else is 404. Served on the separate `[health] bind` listener, so the
/// operational port exposes nothing but the probes.
///
/// The loop carries the same four guards as the main accept loop in
/// `server/serve.rs` — a connection cap acquired *before* `accept()`, a
/// complete-headers deadline, a bounded read buffer, and a classified,
/// backed-off accept error. The probe port answers two fixed paths, but
/// "narrow" is not "bounded": without these, held-open connections and a
/// persistent `EMFILE` were an unmetered descriptor hole and a 100% CPU
/// spin.
///
/// Probe connections are watched, not detached: each one is registered
/// with this loop's own `GracefulShutdown`, and when `stop` fires (after
/// the main drain — readiness must be observable as "draining" while it
/// happens) the loop stops accepting and finishes any in-flight probe
/// answer before returning.
pub(crate) async fn serve_probes(
    listener: tokio::net::TcpListener,
    state: Arc<HealthState>,
    guards: ProbeGuards,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use hyper_util::server::graceful::GracefulShutdown;
    use tokio::sync::Semaphore;

    let slots = Arc::new(Semaphore::new(guards.max_connections.max(1)));
    // Identical for every connection: built once, cloned per accept.
    let http = {
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(guards.header_read)
            .max_buf_size(guards.max_buf_size);
        builder
    };
    let graceful = GracefulShutdown::new();

    loop {
        let accepted = tokio::select! {
            accepted = async {
                // Acquire before accept — the ordering is what stops the
                // loop from taking a connection it has no slot for.
                // Invariant: acquire fails only on a closed semaphore,
                // and nothing ever closes this one.
                #[allow(clippy::expect_used)]
                let permit = slots
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("probe connection semaphore is never closed");
                (permit, listener.accept().await)
            } => accepted,
            _ = &mut stop => break,
        };
        let (permit, accepted) = accepted;
        let stream = match accepted {
            Ok((stream, _peer)) => stream,
            Err(err) => {
                crate::server::accept_error_backoff("probe listener", &err).await;
                continue;
            }
        };
        let state = state.clone();
        let http = http.clone();
        // Subscribed at accept time, like the main loop: a drain that
        // starts mid-connection is seen by this connection rather than
        // arriving one version late.
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            // Held until the connection closes: the cap bounds live
            // connections, not merely concurrent accepts.
            let _permit = permit;
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
            let conn = http.serve_connection(TokioIo::new(stream), svc);
            let _ = watcher.watch(conn).await;
        });
    }

    // Stop accepting (releasing the port), then finish what is in flight.
    drop(listener);
    graceful.shutdown().await;
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
