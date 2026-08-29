// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The HTTP server and its builder: the main entrypoint for consuming Nitr.

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use mlua::AnyUserData;
use nitr_core::ModuleFn;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::app;
use crate::config::Config;
use crate::protect::Protection;
use crate::service::Svc;
use nitr_core::{Error, Result};
use nitr_core::{Runtime, RuntimePool};
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
    /// plaintext listener. Built once, in [`ServerBuilder::build`], so
    /// every connection clones an `Arc` instead of reading the
    /// filesystem — and so a broken pair fails the build rather than
    /// every handshake on an already-bound port.
    #[cfg(feature = "tls")]
    tls: Option<tokio_rustls::TlsAcceptor>,
}

/// Refuses to start while a migration is pending.
///
/// The alternative — applying them at boot — is how two instances of a
/// rolling deployment race to change the same schema, each believing it is
/// the only one. Making it an explicit step means somebody chose when it
/// happened.
#[cfg(not(feature = "db"))]
fn check_migrations(_cfg: &Config) -> Result {
    // Without the `db` builtin there is no connection to check against;
    // `register_builtins` is what reports the misconfiguration.
    Ok(())
}

#[cfg(feature = "db")]
fn check_migrations(cfg: &Config) -> Result {
    let Some(db) = &cfg.database else {
        return Ok(());
    };
    let Some(dir) = db.migrations() else {
        return Ok(());
    };
    let conn = nitr_std::db_open(&db.path, &db.pragmas())?;
    let pending = nitr_std::migrate::pending(&conn, &dir)?;
    if pending.is_empty() {
        return Ok(());
    }
    Err(Error::Config(format!(
        "{} migration(s) pending ({}). Run `nitr migrate` first.",
        pending.len(),
        pending.join(", ")
    )))
}

/// Builder for [`Server`].
///
/// Individual setters override values from [`config()`](Self::config).
#[derive(Default)]
pub struct ServerBuilder {
    cfg: Config,
    builtins: Option<Builtins>,
    setup_fns: Vec<SetupFn>,
    modules: Vec<Module>,
    listener: Option<std::net::TcpListener>,
    health_listener: Option<std::net::TcpListener>,
}

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
    /// error the old pool stays.
    async fn reload(&self) {
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

        // Health endpoints: on the main listener by default, or on their
        // own address so the probes stay off the public port.
        let health_state = self.cfg.health.enabled.then(|| {
            Arc::new(crate::health::HealthState {
                cfg: self.cfg.health.clone(),
                ready: self.ready.clone(),
            })
        });
        let mut probe_task = None;
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
                tracing::info!("health endpoints on http://{addr}");
                probe_task = Some(tokio::spawn(crate::health::serve_probes(
                    probe_listener,
                    state.clone(),
                )));
                None
            }
            (Some(state), None) => match self.cfg.health.bind {
                Some(addr) => {
                    let probe_listener = TcpListener::bind(addr).await.map_err(|err| {
                        Error::Config(format!("unable to bind [health] bind = {addr}: {err}"))
                    })?;
                    tracing::info!("health endpoints on http://{addr}");
                    probe_task = Some(tokio::spawn(crate::health::serve_probes(
                        probe_listener,
                        state.clone(),
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
                            tracing::error!("failed to accept connection: {err}");
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

        if let Some(task) = probe_task {
            task.abort();
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

impl ServerBuilder {
    /// Bulk-applies a loaded [`Config`] (e.g. from `nitr.toml`).
    /// Setters called afterwards override it.
    pub fn config(mut self, cfg: Config) -> Self {
        self.cfg = cfg;
        self
    }

    /// Address the server binds to.
    pub fn listen(mut self, addr: std::net::SocketAddr) -> Self {
        self.cfg.listen = addr;
        self
    }

    /// Serves on an already-bound listener instead of binding
    /// [`listen`](Self::listen).
    ///
    /// This closes the window between choosing a port and binding it: a
    /// caller can bind port 0 (the OS picks a free one), read the real
    /// address, and hand the listener over — nothing else can take the
    /// port in between. That makes it the right tool for tests and for
    /// socket-activation setups where the supervisor owns the socket.
    pub fn listener(mut self, listener: std::net::TcpListener) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Serves the health probes on an already-bound listener instead of
    /// binding `[health] bind`.
    ///
    /// The probe-port counterpart of [`listener`](Self::listener), closing
    /// the same choose-then-bind window: reserve port 0, read the real
    /// address, hand the listener over. Ignored when `[health] enabled`
    /// is off.
    pub fn health_listener(mut self, listener: std::net::TcpListener) -> Self {
        self.health_listener = Some(listener);
        self
    }

    /// Lua script executed once per request.
    pub fn handler_script(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.handler_script = path.into();
        self
    }

    /// Lua script executed exactly once at startup; its returned table is
    /// passed to the handler on every request.
    pub fn config_script(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.config_script = Some(path.into());
        self
    }

    /// Directory for the `template` builtin (`[templating] dir`).
    pub fn templates_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.cfg.templating.dir = Some(path.into());
        self
    }

    /// SQLite database file for the `conn` builtin.
    pub fn database(mut self, path: impl Into<PathBuf>) -> Self {
        match &mut self.cfg.database {
            Some(db) => db.path = path.into(),
            None => self.cfg.database = Some(crate::config::DatabaseConfig::new(path)),
        }
        self
    }

    /// Standard library (`nitr.*`) features to expose; overrides the
    /// `[std] features` list from the configuration file. Without either,
    /// the minimal default set ([`Builtins::minimal()`]) is enabled.
    pub fn builtins(mut self, builtins: Builtins) -> Self {
        self.builtins = Some(builtins);
        self
    }

    /// Number of pooled Lua states (max concurrently executing handlers).
    pub fn workers(mut self, n: usize) -> Self {
        self.cfg.workers = n;
        self
    }

    /// Development mode: hot-reload the handler script on change.
    pub fn dev_mode(mut self, on: bool) -> Self {
        self.cfg.dev_mode = on;
        self
    }

    /// Registers a Rust extension module: the closure runs once per pooled
    /// state (and again on every reload) and its returned table is mounted
    /// at `nitr.ext.<name>` — one level below the standard library, so a
    /// module can never collide with a builtin (present or future).
    /// Registration fails at build time when two modules share a name.
    ///
    /// ```ignore
    /// // Scripts call it as nitr.ext.greet.hello("world").
    /// Server::builder().module("greet", |lua| {
    ///     let t = lua.create_table()?;
    ///     t.set("hello", lua.create_function(|_, name: String| {
    ///         Ok(format!("Hello, {name}!"))
    ///     })?)?;
    ///     Ok(t)
    /// })
    /// ```
    pub fn module<F>(mut self, name: impl Into<String>, f: F) -> Self
    where
        F: Fn(&mlua::Lua) -> mlua::Result<mlua::Table> + Send + Sync + 'static,
    {
        self.modules.push((name.into(), Arc::new(f)));
        self
    }

    /// Registers a closure that customizes each pooled Lua state — the
    /// low-level escape hatch behind [`module()`](Self::module). It runs
    /// once per state, before the configuration script and handler are
    /// loaded.
    pub fn setup<F>(mut self, f: F) -> Self
    where
        F: Fn(&mlua::Lua) -> mlua::Result<()> + Send + Sync + 'static,
    {
        self.setup_fns.push(Box::new(f));
        self
    }

    /// Builds the server: creates the runtime pool, runs the configuration
    /// script exactly once, snapshots its result into every state, and
    /// compiles the handler. Fails fast on any configuration or script error.
    pub async fn build(self) -> Result<Server> {
        let cfg = self.cfg;
        // A contradictory policy fails the boot rather than surfacing later
        // as a header combination a browser quietly ignores.
        cfg.validate()?;
        let builtins = match self.builtins {
            Some(b) => b,
            None => cfg.builtins()?,
        };
        let setup_fns = Arc::new(self.setup_fns);
        let modules = Arc::new(self.modules);

        // Pending migrations stop the boot. Applying them here instead
        // would mean two instances rolling out at once race to change the
        // schema, each believing it is alone.
        check_migrations(&cfg)?;

        // Built once and shared by every state, including states built by
        // a later reload: a cache that empties whenever the handler script
        // changes is a cache that never warms.
        let cache = builtins
            .contains(nitr_std::Builtins::CACHE)
            .then(|| nitr_std::Cache::new(cfg.cache_options()));

        let runtimes = build_runtimes(&cfg, builtins, &setup_fns, &modules, cache.as_ref()).await?;
        let pool = new_pool(
            runtimes,
            &cfg,
            builtins,
            &setup_fns,
            &modules,
            cache.clone(),
        );

        // Streaming responses hold a pooled state for their lifetime; by
        // default keep at least one state free for short requests.
        let max_streams = cfg
            .max_streams
            .unwrap_or_else(|| cfg.workers.max(1).saturating_sub(1).max(1));

        // The certificate and key are read exactly here: once, before a
        // port exists, so a broken pair is a build failure (`nitr check`
        // catches it) instead of a listener that accepts TCP and then
        // fails every handshake — which from the outside is
        // indistinguishable from a network fault.
        #[cfg(feature = "tls")]
        let tls = load_tls(&cfg.tls)?;

        Ok(Server {
            protection: Arc::new(Protection::new(&cfg)),
            cfg,
            builtins,
            setup_fns,
            modules,
            pool: Arc::new(RwLock::new(Arc::new(pool))),
            streams: Arc::new(Semaphore::new(max_streams)),
            max_streams,
            listener: self.listener,
            health_listener: self.health_listener,
            ready: Arc::new(AtomicBool::new(true)),
            cache,
            #[cfg(feature = "tls")]
            tls,
        })
    }
}

/// Builds the shared TLS acceptor from `[tls]`, or `None` when the
/// listener is plaintext.
///
/// The whole certificate/key read happens in this one call, so every
/// connection afterwards clones an `Arc` rather than touching the
/// filesystem. The material is therefore fixed for the life of the
/// process: a renewed certificate needs a restart, not a `SIGHUP` (which
/// swaps the Lua pool and nothing else).
#[cfg(feature = "tls")]
fn load_tls(cfg: &crate::config::TlsConfig) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    if !cfg.enabled {
        return Ok(None);
    }
    let loaded = crate::tls::load(cfg)?;
    tracing::info!(
        "TLS enabled: {} certificate(s), minimum version {}, ALPN {:?}",
        loaded.certs,
        cfg.min_version.as_deref().unwrap_or("1.2"),
        crate::tls::ALPN_PROTOCOLS.map(String::from_utf8_lossy),
    );
    Ok(Some(tokio_rustls::TlsAcceptor::from(loaded.config)))
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("cfg", &self.cfg)
            .field("builtins", &self.builtins)
            .finish_non_exhaustive()
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

/// The currently-live pool (poisoning is unreachable: the lock is only
/// held to clone/replace an `Arc`).
pub(crate) fn current_pool(pool: &Arc<RwLock<Arc<RuntimePool>>>) -> Arc<RuntimePool> {
    pool.read()
        .map(|p| p.clone())
        .unwrap_or_else(|e| e.into_inner().clone())
}

/// Wraps the runtimes in a pool that can recycle a damaged state.
///
/// The rebuild closure reproduces exactly what `build_runtimes` produces for
/// a non-bootstrap state: builtins, extension modules, the configuration
/// snapshot, and the compiled handler. The configuration *script* is never
/// re-run — its snapshot is captured once, so a recycle has no side effects.
fn new_pool(
    runtimes: Vec<Runtime>,
    cfg: &Config,
    builtins: Builtins,
    setup_fns: &Arc<Vec<SetupFn>>,
    modules: &Arc<Vec<Module>>,
    cache: Option<nitr_std::Cache>,
) -> RuntimePool {
    // A rebuilt state needs the same configuration snapshot the others got.
    let snapshot = runtimes
        .first()
        .and_then(|rt| rt.cfg_snapshot().ok().flatten());
    let cfg = cfg.clone();
    let setup_fns = setup_fns.clone();
    let modules = modules.clone();
    RuntimePool::with_rebuild(runtimes, move || {
        let base_statics = crate::static_files::base_mounts(&cfg);
        let mut rt = new_runtime(&cfg, builtins, &setup_fns, &modules, cache.as_ref())?;
        if let Some(snapshot) = &snapshot {
            rt.set_cfg_snapshot(snapshot)?;
        }
        set_nitr_cfg(&rt)?;
        app::load(&rt, &cfg.handler_script, &base_statics)?;
        Ok(rt)
    })
}

/// Builds the full set of pooled runtimes: a bootstrap state runs the
/// configuration script exactly once and its snapshot is injected into the
/// rest. Also used by reloads, so the configuration script's side effects
/// run once per (re)build.
async fn build_runtimes(
    cfg: &Config,
    builtins: Builtins,
    setup_fns: &[SetupFn],
    modules: &[Module],
    cache: Option<&nitr_std::Cache>,
) -> Result<Vec<Runtime>> {
    let workers = cfg.workers.max(1);
    let base_statics = crate::static_files::base_mounts(cfg);
    let base_statics = base_statics.as_slice();

    // Bootstrap state: runs the configuration script exactly once.
    let mut bootstrap = new_runtime(cfg, builtins, setup_fns, modules, cache)?;
    let snapshot = match &cfg.config_script {
        Some(conf_src) => {
            // Pass the database connection to the config script when available.
            // Invariant: `nitr_name` is `None` only for combined or
            // multi-field flags; DATABASE is neither.
            #[allow(clippy::expect_used)]
            let db_name = Builtins::DATABASE
                .nitr_name()
                .expect("DATABASE is a single builtin flag");
            let db = nitr_core::nitr_table(bootstrap.lua())?.get::<Option<AnyUserData>>(db_name)?;
            bootstrap.register_cfg_fn(conf_src, db).await?;
            bootstrap.cfg_snapshot()?
        }
        None => None,
    };
    set_nitr_cfg(&bootstrap)?;
    app::load(&bootstrap, &cfg.handler_script, base_statics)?;

    // Remaining states: inject the snapshot instead of re-running the
    // configuration script, so its side effects happen exactly once.
    let mut runtimes = Vec::with_capacity(workers);
    runtimes.push(bootstrap);
    for _ in 1..workers {
        let mut rt = new_runtime(cfg, builtins, setup_fns, modules, cache)?;
        if let Some(snapshot) = &snapshot {
            rt.set_cfg_snapshot(snapshot)?;
        }
        set_nitr_cfg(&rt)?;
        app::load(&rt, &cfg.handler_script, base_statics)?;
        runtimes.push(rt);
    }
    Ok(runtimes)
}

fn new_runtime(
    cfg: &Config,
    builtins: Builtins,
    setup_fns: &[SetupFn],
    modules: &[Module],
    cache: Option<&nitr_std::Cache>,
) -> Result<Runtime> {
    let rt = Runtime::new_with(cfg.runtime_opts()?)?;
    let env = nitr_std::BuiltinsEnv {
        templates_dir: cfg.templating.dir.clone(),
        database: cfg.database.as_ref().map(|db| db.path.clone()),
        sqlite: cfg
            .database
            .as_ref()
            .map(|db| db.pragmas())
            .unwrap_or_default(),
        fetch: cfg.fetch.options(),
        env: cfg.env_options(),
        cache: cache.cloned(),
    };
    nitr_std::register_builtins(rt.lua(), builtins, &env)?;
    app::register_nitr_app(rt.lua())?;
    // Extension modules mount under `nitr.ext`; two modules sharing a
    // name is caught here, at build time.
    for (name, module) in modules {
        rt.register_module(name, module.as_ref())?;
    }
    for setup in setup_fns {
        setup(rt.lua())?;
    }
    Ok(rt)
}

/// Exposes the state's configuration table to scripts as `nitr.cfg`, so
/// app-style handlers (which only receive the request) can reach it.
fn set_nitr_cfg(rt: &Runtime) -> Result {
    if let Some(cfg) = rt.cfg() {
        let nitr: mlua::Table = rt.lua().globals().get("nitr")?;
        nitr.set("cfg", cfg.clone())?;
    }
    Ok(())
}
