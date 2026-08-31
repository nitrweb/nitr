// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The serving half of [`Server`]: the accept loop with its connection
//! cap and TLS handshake, zero-downtime reloads, and the graceful drain.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::service::Svc;
use nitr_core::{Error, Result};

use super::Server;
use super::pool::current_pool;

impl Server {
    /// Serves until a shutdown signal arrives, then drains gracefully.
    ///
    /// The signal contract:
    ///
    /// | Signal | Meaning |
    /// | ------ | ------- |
    /// | `SIGTERM` | Graceful shutdown (what containers and systemd send) |
    /// | `SIGINT` | Graceful shutdown (ctrl-c) |
    /// | `SIGHUP` | Reload the runtime pool, keeping connections alive |
    ///
    /// On Windows only ctrl-c is available; the others are not wired.
    pub async fn serve(self) -> Result {
        self.serve_with_shutdown(shutdown_signal()).await
    }

    /// Serves until the given future resolves, then shuts down gracefully:
    /// the listener stops accepting and in-flight requests get a grace
    /// period to complete.
    pub async fn serve_with_shutdown(mut self, shutdown: impl Future<Output = ()>) -> Result {
        // Read once, at build time; here it is only an `Arc` to clone.
        #[cfg(feature = "tls")]
        let tls_acceptor = self.tls.clone();
        let listener = match self.listener.take() {
            // A pre-bound listener arrives blocking; tokio requires
            // non-blocking before it will adopt it.
            Some(std_listener) => std_listener
                .set_nonblocking(true)
                .and_then(|()| TcpListener::from_std(std_listener))
                .map_err(|err| {
                    Error::Config(format!("unable to adopt the given listener: {err}"))
                })?,
            None => TcpListener::bind(self.cfg.listen).await.map_err(|err| {
                Error::Config(format!("unable to listen on {}: {err}", self.cfg.listen))
            })?,
        };
        let graceful = GracefulShutdown::new();
        let mut shutdown = std::pin::pin!(shutdown);

        // SIGHUP triggers a zero-downtime pool swap (Unix only; the
        // channel simply stays silent elsewhere). The stream is created
        // HERE, synchronously, so that by the time the "listening" line is
        // logged the default disposition (terminate!) is gone — a reload
        // sent the moment the server looks up must never kill it.
        let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(1);
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let tx = reload_tx.clone();
            match signal(SignalKind::hangup()) {
                Ok(mut hangup) => {
                    tokio::spawn(async move {
                        while hangup.recv().await.is_some() {
                            let _ = tx.try_send(());
                        }
                    });
                }
                Err(err) => tracing::warn!("failed to install the SIGHUP reload handler: {err}"),
            }
        }
        // Dev mode: a notify-based watcher feeds the same reload channel a
        // SIGHUP does, so a save rebuilds the pool immediately instead of
        // being discovered by the next request.
        let _watcher = self
            .cfg
            .dev_mode
            .then(|| crate::watch::spawn(&self.cfg, reload_tx.clone()))
            .flatten();
        let _reload_tx = reload_tx;

        // The listener's own address, not `cfg.listen`: with a pre-bound
        // listener (or port 0) the config value is not where we serve.
        let bound = listener.local_addr().unwrap_or(self.cfg.listen);
        // The scheme is part of what an operator checks this line for:
        // saying `http://` on a TLS listener would send the first curl of
        // every deployment to the wrong URL.
        let scheme = if self.cfg.tls.enabled {
            "https"
        } else {
            "http"
        };
        tracing::info!(
            "listening on {scheme}://{} with {} Lua state(s)",
            bound,
            current_pool(&self.pool).size()
        );

        // hyper enforces a floor of 8 KiB on its read buffer.
        let max_buf_size = self.cfg.limits.max_header_bytes.max(8 * 1024);
        // Complete-headers deadline (`[limits] header_read_ms`); `None`
        // disables it. Enforced by hyper per connection: an expired one
        // is simply closed — no request exists yet to answer. Under TLS it
        // also bounds the handshake: the same question ("how long may a
        // client take to say what it wants?"), asked one layer down.
        let header_read = match self.cfg.limits.header_read_ms {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        };

        // Health endpoints: on the main listener by default, or on their
        // own address so the probes stay off the public port.
        let health_state = self.cfg.health.enabled.then(|| {
            Arc::new(crate::health::HealthState {
                cfg: self.cfg.health.clone(),
                ready: self.ready.clone(),
            })
        });
        // The probe listener carries the main listener's guards — its own
        // (smaller) connection cap, and the same header deadline and read
        // buffer, because "how long may a client take to say what it
        // wants?" has one answer per process.
        let probe_guards = crate::health::ProbeGuards {
            max_connections: self.cfg.health.max_connections,
            header_read,
            max_buf_size,
        };
        // The probe transport is a decision, not an accident: the probe
        // port stays plaintext even under `[tls]`, because a prober that
        // must complete a TLS handshake fails exactly when liveness must
        // still answer — during certificate trouble. The startup line says
        // so instead of implying it with a bare `http://`; the decision
        // and its threat-model entry belong to the TLS-surface work
        // (audits/3-remediation, T-6). One closure serves both listener
        // branches, so their wording cannot drift apart.
        let tls_enabled = self.cfg.tls.enabled;
        let log_probe_endpoint = move |addr: &str| {
            if tls_enabled {
                tracing::info!(
                    "health endpoints on http://{addr} (plaintext; TLS terminates on the \
                     main listener only)"
                );
            } else {
                tracing::info!("health endpoints on http://{addr}");
            }
        };
        let mut probe_task = None;
        let mut probe_stop = None;
        let main_health = match (&health_state, self.health_listener.take()) {
            // An adopted probe listener wins over binding `[health] bind`
            // ourselves — the same rule the main listener follows — so the
            // port was never released between choosing it and serving.
            (Some(state), Some(std_listener)) => {
                let probe_listener = std_listener
                    .set_nonblocking(true)
                    .and_then(|()| TcpListener::from_std(std_listener))
                    .map_err(|err| {
                        Error::Config(format!("unable to adopt the given health listener: {err}"))
                    })?;
                let addr = probe_listener
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "<unknown>".into());
                log_probe_endpoint(&addr);
                let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
                probe_stop = Some(stop_tx);
                probe_task = Some(tokio::spawn(crate::health::serve_probes(
                    probe_listener,
                    state.clone(),
                    probe_guards,
                    stop_rx,
                )));
                None
            }
            (Some(state), None) => match self.cfg.health.bind {
                Some(addr) => {
                    let probe_listener = TcpListener::bind(addr).await.map_err(|err| {
                        Error::Config(format!("unable to bind [health] bind = {addr}: {err}"))
                    })?;
                    // The bound address, not the configured one: with a
                    // port-0 bind the config value is not where we serve —
                    // the same rule the main listener's line follows.
                    let bound = probe_listener
                        .local_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| addr.to_string());
                    log_probe_endpoint(&bound);
                    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
                    probe_stop = Some(stop_tx);
                    probe_task = Some(tokio::spawn(crate::health::serve_probes(
                        probe_listener,
                        state.clone(),
                        probe_guards,
                        stop_rx,
                    )));
                    None
                }
                None => Some(state.clone()),
            },
            (None, _) => None,
        };

        // Connection cap: the listener stops accepting while at the limit
        // instead of queueing unbounded connections.
        let conn_slots = Arc::new(Semaphore::new(self.cfg.limits.max_connections.max(1)));
        // Identical for every connection, so it is built once and cloned
        // into each task rather than rebuilt per accept.
        let http = {
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(header_read)
                .max_buf_size(max_buf_size);
            builder
        };

        loop {
            tokio::select! {
                accepted = async {
                    // Wait for a free connection slot before accepting; the
                    // whole future is dropped (releasing nothing) on
                    // shutdown. The semaphore is never closed.
                    // Invariant: acquire fails only on a closed
                    // semaphore, and nothing ever closes this one.
                    #[allow(clippy::expect_used)]
                    let permit = conn_slots
                        .clone()
                        .acquire_owned()
                        .await
                        .expect("connection semaphore is never closed");
                    (permit, listener.accept().await)
                } => {
                    let (permit, accepted) = accepted;
                    let (stream, peer_addr) = match accepted {
                        Ok(x) => x,
                        Err(err) => {
                            accept_error_backoff("listener", &err).await;
                            continue;
                        }
                    };

                    // Small responses must not wait on Nagle's algorithm.
                    let _ = stream.set_nodelay(true);

                    let svc = Svc::new(
                        self.pool.clone(),
                        self.streams.clone(),
                        self.protection.clone(),
                        main_health.clone(),
                        peer_addr,
                    );
                    let http = http.clone();
                    // Subscribed here rather than inside the task:
                    // `watcher()` takes its version at accept time, so a
                    // drain that starts while a handshake is still running
                    // is seen by this connection instead of arriving one
                    // version late.
                    let watcher = graceful.watcher();
                    #[cfg(feature = "tls")]
                    let acceptor = tls_acceptor.clone();
                    tokio::spawn(async move {
                        // Held until the connection closes.
                        let _permit = permit;
                        // The TLS handshake happens HERE, in the
                        // connection's own task — never in the accept loop
                        // above. A `ClientHello` that arrives one byte a
                        // minute then costs this connection and nothing
                        // else; handshaking before the spawn would let one
                        // hostile client stall every other.
                        #[cfg(feature = "tls")]
                        if let Some(acceptor) = acceptor {
                            let Some(stream) =
                                tls_handshake(&acceptor, stream, header_read, peer_addr).await
                            else {
                                return;
                            };
                            let conn = http.serve_connection(TokioIo::new(stream), svc);
                            if let Err(err) = watcher.watch(conn).await {
                                // `debug`, not `error`, and the plaintext
                                // arm below stays at `error` on purpose.
                                // TLS adds a shutdown handshake that a
                                // client is free to skip: curl and every
                                // browser routinely close the socket
                                // without a `close_notify`, which arrives
                                // here as "error shutting down
                                // connection". At `error` that is one log
                                // line per request on a healthy server —
                                // noise that buries the failures an
                                // operator is actually looking for.
                                tracing::debug!(
                                    "TLS connection from {peer_addr} ended with: {err}"
                                );
                            }
                            return;
                        }
                        let conn = http.serve_connection(TokioIo::new(stream), svc);
                        if let Err(err) = watcher.watch(conn).await {
                            tracing::error!("error serving connection: {err}");
                        }
                    });
                }
                Some(()) = reload_rx.recv() => self.reload().await,
                _ = &mut shutdown => break,
            }
        }

        // Step 1 happened by leaving the accept loop: the listener is
        // dropped below and no new connection is taken. The probe listener
        // stays up through the drain — readiness must be observable as
        // "draining" while it happens — and dies with the process.
        drop(listener);
        // Step 2: stop advertising readiness *before* requests can fail, so
        // a load balancer drains us on its own terms. Responses issued from
        // here on also carry `Connection: close`.
        self.ready.store(false, Ordering::Relaxed);

        let grace = self.cfg.shutdown.grace();
        let total = self.cfg.shutdown.total_grace();
        tracing::info!(
            "draining: waiting up to {grace:?} for in-flight requests \
             ({stream_grace:?} more for streaming bodies)",
            stream_grace = total.saturating_sub(grace),
        );

        // Steps 3-5: in-flight requests finish, idle keep-alive connections
        // close (hyper marks them `Connection: close` as it drains), and the
        // pool states they hold come back with them. Streaming bodies get
        // the extra budget before anything is cut.
        // Step 6 follows from the drain: dropping the watcher (and with it
        // the last connection tasks) closes every Lua state, which
        // checkpoints the SQLite WAL of each connection.
        let deadline = drain_deadline(&self.streams, self.max_streams, grace, total);
        let drained = tokio::select! {
            _ = graceful.shutdown() => true,
            _ = deadline => false,
        };

        // The probe listener stayed up through the drain — readiness had
        // to be observable as "draining" while it happened — and drains
        // now: `serve_probes` watches every in-flight probe connection
        // with its own `GracefulShutdown`, so stopping it finishes open
        // probe answers instead of severing them. The deadline is tight
        // because a probe response is one fixed-body round trip.
        if let Some(mut task) = probe_task {
            if let Some(stop) = probe_stop.take() {
                let _ = stop.send(());
            }
            if tokio::time::timeout(Duration::from_secs(1), &mut task)
                .await
                .is_err()
            {
                // Aborting kills the accept/drain task only; the
                // per-connection tasks are independent spawns and simply
                // run to completion on their own (in the binary, until
                // process exit moments later).
                tracing::warn!("probe listener did not drain within 1s, abandoning the drain");
                task.abort();
            }
        }

        if drained {
            tracing::info!("drained cleanly, shutting down");
            Ok(())
        } else {
            // A truncated shutdown means somebody's request was cut. Report
            // it as an error so a supervisor can surface it, rather than
            // exiting 0 and hiding it.
            tracing::warn!("drain deadline of {total:?} expired, aborting remaining connections");
            Err(Error::ShutdownTimeout)
        }
    }
}

/// How long an accept loop pauses after a non-client accept failure.
///
/// Fixed rather than exponential on purpose: the failure this exists for
/// is descriptor exhaustion (`EMFILE`/`ENFILE`), which clears when a
/// descriptor frees, not on a schedule — and exponential backoff adds
/// state to a loop whose whole virtue is having none.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Classifies, logs, and (for one class) backs off one `accept()` failure.
/// Both accept loops — the main listener's and the probe listener's — go
/// through here, so the level split and the delay cannot drift apart.
///
/// Exactly two classes, deliberately. `ConnectionAborted`,
/// `ConnectionReset` and `Interrupted` are client-caused and self-clearing
/// (the peer gave up between the kernel completing the handshake and this
/// process accepting it): `debug`, retry at once. *Everything else* is
/// treated as resource trouble and paced: Rust has no stable `ErrorKind`
/// for `EMFILE`/`ENFILE` — they surface as an uncategorized kind plus a
/// raw OS error — so they cannot be named directly, and without the sleep
/// a persistent one busy-spins the accept loop at 100% CPU. If this match
/// ever grows a third case, it has stopped being insurance.
pub(crate) async fn accept_error_backoff(listener: &str, err: &std::io::Error) {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::Interrupted => {
            tracing::debug!("{listener}: client gone before accept: {err}");
        }
        _ => {
            tracing::warn!("{listener}: failed to accept connection: {err}");
            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
        }
    }
}

/// One connection's TLS handshake, run inside that connection's own task.
///
/// Returns `None` when the connection is finished with — the stream is
/// dropped, closing it, and nothing else is affected. Failures are logged
/// at `debug`, not `error`: on a public port a failed handshake is
/// ordinary traffic (a plaintext client, a scanner, a client with no
/// cipher suite in common), and an `error` per probe would drown the log
/// an operator actually needs.
///
/// `deadline` is `[limits] header_read_ms`. Without it a client can hold a
/// connection slot — and, during a drain, the graceful watcher — open
/// forever by never finishing its `ClientHello`.
#[cfg(feature = "tls")]
async fn tls_handshake(
    acceptor: &tokio_rustls::TlsAcceptor,
    stream: tokio::net::TcpStream,
    deadline: Option<Duration>,
    peer: std::net::SocketAddr,
) -> Option<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    let accepting = acceptor.accept(stream);
    let handshake = match deadline {
        Some(limit) => match tokio::time::timeout(limit, accepting).await {
            Ok(handshake) => handshake,
            Err(_) => {
                tracing::debug!("TLS handshake from {peer} did not finish within {limit:?}");
                return None;
            }
        },
        None => accepting.await,
    };
    match handshake {
        Ok(stream) => Some(stream),
        Err(err) => {
            tracing::debug!("TLS handshake from {peer} failed: {err}");
            None
        }
    }
}

/// Resolves when the drain has run out of time.
///
/// Ordinary requests get `grace`. A streaming body legitimately outlives any
/// request-shaped budget, so when one is still live at that point the drain
/// waits until `total` instead — the extra budget is spent only on the case
/// it exists for, rather than delaying every shutdown by it.
async fn drain_deadline(streams: &Semaphore, max_streams: usize, grace: Duration, total: Duration) {
    tokio::time::sleep(grace).await;
    if streams.available_permits() < max_streams {
        tracing::info!("streaming bodies still live, extending the drain to {total:?}");
        tokio::time::sleep(total.saturating_sub(grace)).await;
    }
}

/// Resolves when the process is asked to stop: `SIGTERM` (containers and
/// systemd) or `SIGINT` (ctrl-c). On non-Unix targets only ctrl-c exists.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(sig) => sig,
            Err(err) => {
                tracing::warn!("failed to install the SIGTERM handler: {err}");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => tracing::info!("received SIGTERM"),
            _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received ctrl-c");
    }
}
