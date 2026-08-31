// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The HTTP server and its builder: the main entrypoint for consuming Nitr.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use nitr_core::ModuleFn;
use tokio::sync::Semaphore;

use crate::config::Config;
use crate::protect::Protection;
use nitr_core::RuntimePool;
use nitr_std::Builtins;

/// A closure that customizes each pooled Lua state (advanced escape hatch;
/// prefer [`ServerBuilder::module()`] for extensions).
type SetupFn = Box<dyn Fn(&mlua::Lua) -> mlua::Result<()> + Send + Sync>;

/// A named Rust extension module, mounted at `nitr.<name>` in every state.
type Module = (String, Arc<ModuleFn>);

/// The Nitr HTTP server: a pool of Lua runtimes behind a shared listener.
///
/// Built via [`Server::builder()`]; run via [`serve()`](Self::serve).
pub struct Server {
    cfg: Config,
    builtins: Builtins,
    setup_fns: Arc<Vec<SetupFn>>,
    modules: Arc<Vec<Module>>,
    /// The current pool, swappable as a whole for zero-downtime reloads.
    pool: Arc<RwLock<Arc<RuntimePool>>>,
    /// Streaming-response slots: one permit per live streaming body.
    streams: Arc<Semaphore>,
    /// The permit count `streams` was created with, so the drain can tell
    /// whether any streaming body is still live.
    max_streams: usize,
    /// Pre-Lua protection: rate limiting, size limits, request ids.
    protection: Arc<Protection>,
    /// A caller-supplied, already-bound listener (see
    /// [`ServerBuilder::listener`]); when absent, `serve` binds
    /// `cfg.listen` itself.
    listener: Option<std::net::TcpListener>,
    /// A caller-supplied, already-bound listener for the health probes
    /// (see [`ServerBuilder::health_listener`]); when absent and
    /// `[health] bind` is set, `serve` binds that address itself.
    health_listener: Option<std::net::TcpListener>,
    /// Cleared as soon as a drain starts, so a load balancer can stop
    /// routing before requests begin to fail. Read by
    /// [`is_ready()`](Self::is_ready), which a readiness probe surfaces.
    ready: Arc<AtomicBool>,
    /// The shared `nitr.cache`, held here so a reload hands the new pool
    /// the same storage rather than starting cold.
    cache: Option<nitr_std::Cache>,
    /// The TLS acceptor built from `[tls] cert`/`key`, or `None` on a
    /// plaintext listener. Built in [`ServerBuilder::build`] — so a
    /// broken pair fails the build rather than every handshake on an
    /// already-bound port — and held behind a lock so a `SIGHUP` can
    /// swap in renewed material without a restart: the accept loop reads
    /// the slot per accepted connection, never from the filesystem.
    #[cfg(feature = "tls")]
    tls: Arc<RwLock<Option<tokio_rustls::TlsAcceptor>>>,
}

mod builder;
mod pool;
mod serve;

pub use builder::ServerBuilder;
pub(crate) use pool::current_pool;
use pool::{build_runtimes, new_pool};
pub(crate) use serve::accept_error_backoff;

impl Server {
    /// Creates a [`ServerBuilder`] with default configuration.
    pub fn builder() -> ServerBuilder {
        ServerBuilder::default()
    }

    /// The pool of Lua runtimes currently serving requests.
    pub fn pool(&self) -> Arc<RuntimePool> {
        current_pool(&self.pool)
    }

    /// Whether the server is accepting traffic. Cleared at the start of a
    /// graceful shutdown, before in-flight requests are drained.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// An in-process client that dispatches requests through the full
    /// router/middleware/handler path without binding a socket — the
    /// foundation for `nitr test` and Rust-level integration tests.
    pub fn test_client(&self) -> crate::testing::TestClient {
        crate::testing::TestClient::new(
            self.pool.clone(),
            self.streams.clone(),
            self.protection.clone(),
        )
    }

    /// Builds a complete replacement pool (re-running the configuration
    /// script) and atomically swaps it in; in-flight requests finish on
    /// the old pool, which is dropped when its last guard returns. On any
    /// error the old pool stays. With `[tls]` enabled the certificate and
    /// key are re-read too, each half independent: a failed TLS re-read
    /// keeps the old acceptor while the pool still reloads, and vice
    /// versa.
    ///
    /// What a reload deliberately does **not** refresh, so the boundary
    /// is written down rather than discovered: `nitr.toml` itself is
    /// never re-read (`self.cfg` is fixed at build), and with it every
    /// compiled policy — `Protection` (limits, rate limit, request-id
    /// trust), the CORS and compression policies, the cache and its
    /// capacity, the listen address and worker count. A reload re-runs
    /// the configuration *script* and re-reads the certificate *files*;
    /// everything else needs a restart.
    async fn reload(&self) {
        #[cfg(feature = "tls")]
        self.reload_tls();
        tracing::info!("reload requested: rebuilding the runtime pool");
        match build_runtimes(
            &self.cfg,
            self.builtins,
            &self.setup_fns,
            &self.modules,
            self.cache.as_ref(),
        )
        .await
        {
            Ok(runtimes) => {
                let fresh = Arc::new(new_pool(
                    runtimes,
                    &self.cfg,
                    self.builtins,
                    &self.setup_fns,
                    &self.modules,
                    self.cache.clone(),
                ));
                match self.pool.write() {
                    Ok(mut pool) => {
                        *pool = fresh;
                        tracing::info!("reload complete: new runtime pool is live");
                    }
                    Err(_) => tracing::error!("reload failed: pool lock is poisoned"),
                }
            }
            Err(err) => {
                tracing::error!("reload failed, keeping the current pool: {err}");
            }
        }
    }

    /// Re-reads `[tls] cert`/`key` from their configured paths and swaps
    /// the acceptor — validate first, swap only on success: a server that
    /// stops terminating TLS because certbot wrote a half-file is
    /// strictly worse than a stale certificate. Connections already
    /// established keep the acceptor they handshook with.
    #[cfg(feature = "tls")]
    fn reload_tls(&self) {
        // `enabled` cannot change here: a reload re-reads the certificate
        // files, not `nitr.toml`, so a plaintext listener has nothing to
        // swap — and saying so beats silently doing nothing.
        if !self.cfg.tls.enabled {
            tracing::debug!("reload: [tls] is disabled, no certificate to re-read");
            return;
        }
        match crate::tls::load(&self.cfg.tls) {
            Ok(loaded) => {
                let acceptor = tokio_rustls::TlsAcceptor::from(loaded.config);
                match self.tls.write() {
                    Ok(mut slot) => {
                        *slot = Some(acceptor);
                        tracing::info!(
                            "reload complete: TLS material re-read ({} certificate(s))",
                            loaded.certs
                        );
                    }
                    // Unreachable in practice: the lock is only ever held
                    // to clone or replace the acceptor.
                    Err(_) => tracing::error!("TLS reload failed: the acceptor lock is poisoned"),
                }
            }
            Err(err) => {
                tracing::warn!("TLS reload failed, keeping the current certificate: {err}");
            }
        }
    }
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("cfg", &self.cfg)
            .field("builtins", &self.builtins)
            .finish_non_exhaustive()
    }
}
