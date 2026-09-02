// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! [`ServerBuilder`]: configuration of a [`Server`] and the build-time
//! checks (config validation, pending migrations, TLS material).

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use tokio::sync::Semaphore;

use crate::config::Config;
use crate::protect::Protection;
#[cfg(feature = "db")]
use nitr_core::Error;
use nitr_core::Result;
use nitr_std::Builtins;

use super::pool::{build_runtimes, new_pool};
use super::{Module, Server, SetupFn};

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
        let tls = Arc::new(RwLock::new(load_tls(&cfg.tls)?));

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
            reloading: Arc::new(std::sync::atomic::AtomicU8::new(0)),
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
/// filesystem. Renewed material arrives by `SIGHUP`: the reload path
/// re-runs this same loading routine against the same paths and swaps
/// the acceptor only when the new pair validates.
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
