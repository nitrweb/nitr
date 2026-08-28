// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The shared integration-test harness: one way to stand up a real Nitr
//! server per test.
//!
//! Convention: new integration tests use [`TestServer::builder`]. Raw
//! spawning is reserved for tests whose *subject* is the spawn path
//! itself (watcher, shutdown, reload). The one rule with no exceptions:
//! every file a test writes lands in its own [`TestDir`] — never the
//! shared system temp directory, which the dev-mode watcher once
//! recursively registered, reacting to *other* tests' churn.
//!
//! Each test binary compiles its own copy of this module (`mod harness;`)
//! and uses a subset of it, hence:
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// The suite's flake budget, in one place.
//
// Every timing tolerance the harness grants lives here: how long a spawn
// may take to answer, how long a drain may take, how long the pool may
// take to reflect a checkout or a recycle. Tests inherit these instead of
// inventing their own margins, so when CI slows down there is exactly one
// screw to turn — and one diff to review when someone turns it.

/// Graceful-drain deadline configured on every test server (seconds).
/// Generous enough for a real drain, short enough that a hung drain fails
/// the test rather than idling toward the CI timeout.
const SHUTDOWN_GRACE_SECS: u64 = 5;

/// How long [`TestServer::stop`]/[`shutdown`](TestServer::shutdown) waits
/// for the serve task to finish before declaring the server hung.
const JOIN_DEADLINE: Duration = Duration::from_secs(10);

/// Readiness poll for a spawned server: attempts × interval bounds how
/// long a server may take to answer its first TCP connect.
const READINESS_ATTEMPTS: u32 = 200;
const READINESS_INTERVAL: Duration = Duration::from_millis(10);

/// How long pool state (checkouts, recycles, refills) may lag the event
/// that caused it before [`TestServer::wait_until_available`] and the
/// post-stop leak check give up.
const POOL_SETTLE_DEADLINE: Duration = Duration::from_secs(5);
const POOL_SETTLE_INTERVAL: Duration = Duration::from_millis(10);

/// A scratch directory private to one test.
///
/// Every test runs as a thread of the same process, so a directory keyed
/// only on the pid would be shared by all of them — and `fs::write`
/// truncates before it writes, so one test rewriting `app.lua` while
/// another's server reads it hands that server an empty file. The counter
/// keeps every test on its own tree.
///
/// The directory is removed on drop when the test passed, and kept — with
/// its path printed — when the test panicked, for post-mortem.
pub struct TestDir {
    path: PathBuf,
}

impl TestDir {
    /// Creates a fresh private directory. `label` names the test binary
    /// in the path, purely for post-mortem readability.
    pub fn new(label: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("nitr-{label}-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create test dir");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A path inside the directory (not created).
    pub fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.path.join(name)
    }

    /// Writes a file inside the directory, creating parent directories as
    /// needed, and returns its path.
    pub fn write(&self, name: impl AsRef<Path>, content: impl AsRef<[u8]>) -> PathBuf {
        let path = self.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(&path, content).expect("write test file");
        path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Loud failure: leave the evidence where the panic message
            // can point at it.
            eprintln!("[harness] test failed; keeping {}", self.path.display());
        } else {
            // Silent success.
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Binds port 0 (the OS picks a free port) and keeps the listener alive.
/// The server adopts it via `.listener(...)`, so the port can never be
/// taken by another test between choosing it and serving on it.
pub fn reserve_addr() -> (std::net::TcpListener, SocketAddr) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind port 0");
    let addr = listener.local_addr().expect("local addr");
    (listener, addr)
}

/// Waits until a TCP connect to `addr` succeeds. With an adopted listener
/// this is near-instant (the socket is bound before the server task even
/// starts); the loop guards the day that stops being true.
pub async fn wait_until_listening(addr: SocketAddr) {
    for _ in 0..READINESS_ATTEMPTS {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(READINESS_INTERVAL).await;
    }
    panic!("nothing came up on {addr}");
}

/// Builder for a [`TestServer`]: typed config overrides over a default
/// minimal [`nitr::Config`], scripts and databases placed in the test's
/// private directory, readiness waited for, teardown bounded.
type ModuleFn = Box<dyn Fn(&mlua::Lua) -> mlua::Result<mlua::Table> + Send + Sync + 'static>;
type SetupFn = Box<dyn Fn(&mlua::Lua) -> mlua::Result<()> + Send + Sync + 'static>;

pub struct Builder {
    dir: TestDir,
    cfg: nitr::Config,
    handler: Option<String>,
    config_script: Option<String>,
    builtins: Option<nitr::Builtins>,
    modules: Vec<(String, ModuleFn)>,
    setup_fns: Vec<SetupFn>,
    seed_sql: Vec<String>,
    db_path: Option<PathBuf>,
    listener: Option<std::net::TcpListener>,
    health_listener: Option<std::net::TcpListener>,
}

impl TestServer {
    /// Starts a builder with its own fresh [`TestDir`]. `label` names the
    /// test binary in temp paths kept after a failure.
    pub fn builder(label: &str) -> Builder {
        let mut cfg = nitr::Config::default();
        // Tests want prompt teardown: a graceful drain deadline that
        // fails the test, not the CI job, and no stream grace.
        cfg.shutdown.grace = SHUTDOWN_GRACE_SECS;
        cfg.shutdown.stream_grace = 0;
        Builder {
            dir: TestDir::new(label),
            cfg,
            handler: None,
            config_script: None,
            builtins: None,
            modules: Vec::new(),
            setup_fns: Vec::new(),
            seed_sql: Vec::new(),
            db_path: None,
            listener: None,
            health_listener: None,
        }
    }
}

impl Builder {
    /// The test's private directory, for deriving paths to hand to
    /// [`Builder::config`] before spawning.
    pub fn dir(&self) -> &TestDir {
        &self.dir
    }

    /// The handler script content; the builder owns its placement.
    pub fn handler(mut self, script: impl Into<String>) -> Self {
        self.handler = Some(script.into());
        self
    }

    /// A `config.lua` content whose returned table becomes `nitr.cfg`.
    pub fn config_script(mut self, script: impl Into<String>) -> Self {
        self.config_script = Some(script.into());
        self
    }

    /// Typed overrides on the [`nitr::Config`] under construction, so
    /// fixtures track struct changes at compile time instead of rotting
    /// as TOML strings. May be called several times.
    pub fn config(mut self, tune: impl FnOnce(&mut nitr::Config)) -> Self {
        tune(&mut self.cfg);
        self
    }

    /// Enables the listed `[std] features`.
    pub fn std_features(mut self, features: &[&str]) -> Self {
        self.cfg.std.features = Some(features.iter().map(|f| (*f).to_string()).collect());
        self
    }

    /// The builtin set, for tests driving the bit-flag builder path.
    pub fn builtins(mut self, builtins: nitr::Builtins) -> Self {
        self.builtins = Some(builtins);
        self
    }

    /// A Rust extension module mounted at `nitr.ext.<name>` in every
    /// state, exactly as [`nitr::ServerBuilder::module`] mounts it.
    pub fn module(
        mut self,
        name: &str,
        f: impl Fn(&mlua::Lua) -> mlua::Result<mlua::Table> + Send + Sync + 'static,
    ) -> Self {
        self.modules.push((name.to_string(), Box::new(f)));
        self
    }

    /// Configures a SQLite database at `name` inside the test directory.
    pub fn database(mut self, name: &str) -> Self {
        let path = self.dir.join(name);
        self.cfg.database = Some(nitr::DatabaseConfig::new(&path));
        self.db_path = Some(path);
        self
    }

    /// A per-state setup closure, the [`nitr::ServerBuilder::setup`]
    /// escape hatch.
    pub fn setup(
        mut self,
        f: impl Fn(&mlua::Lua) -> mlua::Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.setup_fns.push(Box::new(f));
        self
    }

    /// Reserves the server's address before [`Builder::spawn`], for
    /// handler scripts that must know their own base URL (a self-calling
    /// `fetch` aggregation, say). The listener is kept and adopted by the
    /// server, so the port cannot be taken in between.
    pub fn reserve(&mut self) -> SocketAddr {
        let (listener, addr) = reserve_addr();
        self.cfg.listen = addr;
        self.listener = Some(listener);
        addr
    }

    /// Reserves a separate probe address for `[health] bind` the same way
    /// [`reserve`](Self::reserve) reserves the main one: the listener is
    /// kept and adopted by the server, so — unlike a bind-drop-rebind —
    /// nothing can take the port in between. This is what makes a
    /// separate-bind health test race-free.
    pub fn reserve_health(&mut self) -> SocketAddr {
        let (listener, addr) = reserve_addr();
        self.cfg.health.bind = Some(addr);
        self.health_listener = Some(listener);
        addr
    }

    /// A SQL batch executed against the configured database before the
    /// server builds (so boot-time checks see the seeded schema).
    pub fn seed_sql(mut self, batch: impl Into<String>) -> Self {
        self.seed_sql.push(batch.into());
        self
    }

    /// Writes scripts and seeds the database, then hands back the
    /// finished [`nitr::Server`] builder — shared by spawn and try_build.
    fn prepare(&mut self) -> nitr::ServerBuilder {
        let handler = self
            .dir
            .write("app.lua", self.handler.as_deref().unwrap_or_default());
        self.cfg.handler_script = handler;
        if let Some(script) = &self.config_script {
            let path = self.dir.write("config.lua", script);
            self.cfg.config_script = Some(path);
        }
        if !self.seed_sql.is_empty() {
            let path = self.db_path.as_ref().expect("seed_sql requires database");
            let conn = rusqlite::Connection::open(path).expect("open database");
            for batch in &self.seed_sql {
                conn.execute_batch(batch).expect("seed database");
            }
        }
        let mut builder = nitr::Server::builder().config(self.cfg.clone());
        if let Some(builtins) = self.builtins {
            builder = builder.builtins(builtins);
        }
        for (name, f) in std::mem::take(&mut self.modules) {
            builder = builder.module(&name, f);
        }
        for f in std::mem::take(&mut self.setup_fns) {
            builder = builder.setup(f);
        }
        builder
    }

    /// The database path configured via [`Builder::database`], for
    /// seeding or applying migrations by hand before building.
    pub fn db_path(&self) -> &Path {
        self.db_path.as_deref().expect("no database configured")
    }

    /// Builds without serving and returns the outcome — for tests whose
    /// subject is startup validation. `&mut self` so the same builder can
    /// try again after the test repairs the refusal (say, by applying the
    /// pending migration).
    pub async fn try_build(&mut self) -> Result<(), nitr::Error> {
        // `build()` never binds, so the placeholder in the config is fine.
        self.prepare().build().await.map(drop)
    }

    /// Spawns the server and waits until it answers on its port.
    pub async fn spawn(mut self) -> TestServer {
        let (listener, addr) = match self.listener.take() {
            Some(listener) => {
                let addr = self.cfg.listen;
                (listener, addr)
            }
            None => {
                let (listener, addr) = reserve_addr();
                self.cfg.listen = addr;
                (listener, addr)
            }
        };
        let mut builder = self.prepare().listener(listener);
        if let Some(health) = self.health_listener.take() {
            builder = builder.health_listener(health);
        }
        let server = builder.build().await.expect("build server");

        let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let pool = server.pool();
        let served = tokio::spawn(server.serve_with_shutdown(async {
            let _ = stop_rx.await;
        }));
        wait_until_listening(addr).await;

        TestServer {
            addr,
            pool,
            // No automatic decompression and no redirect following:
            // integration tests assert on the bytes and headers actually
            // sent.
            client: reqwest::Client::builder()
                .no_gzip()
                .no_brotli()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client"),
            stop: Some(stop),
            served: Some(served),
            db_path: self.db_path,
            dir: self.dir,
        }
    }
}

/// A running server plus everything needed to talk to it and stop it.
///
/// Field order matters: the serve task is aborted (via [`Drop`]) before
/// `dir` — declared last — removes the tree out from under it.
pub struct TestServer {
    addr: SocketAddr,
    client: reqwest::Client,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    served: Option<tokio::task::JoinHandle<nitr::Result>>,
    pool: std::sync::Arc<nitr::RuntimePool>,
    db_path: Option<PathBuf>,
    dir: TestDir,
}

impl TestServer {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The runtime pool serving requests, for assertions on its size and
    /// refill behavior after a state is damaged.
    pub fn pool(&self) -> &nitr::RuntimePool {
        &self.pool
    }

    /// Polls until `available()` states remain in the pool (bounded, 5 s).
    ///
    /// The deterministic replacement for "sleep and hope": a test that
    /// needs an in-flight request to have checked its state out (or given
    /// it back) waits for the observable fact instead of a margin.
    pub async fn wait_until_available(&self, want: usize) {
        let deadline = std::time::Instant::now() + POOL_SETTLE_DEADLINE;
        while self.pool.available() != want {
            assert!(
                std::time::Instant::now() < deadline,
                "the pool never reached {want} available state(s) \
                 (size {}, available {})",
                self.pool.size(),
                self.pool.available()
            );
            tokio::time::sleep(POOL_SETTLE_INTERVAL).await;
        }
    }

    /// Whether the serve task has already exited — a server that failed
    /// to come up (say, a stolen port for a secondary bind) rather than
    /// one still serving.
    pub fn serve_finished(&self) -> bool {
        self.served.as_ref().is_some_and(|task| task.is_finished())
    }

    /// The raw client, for requests the conveniences below don't cover.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The test's private directory (uploads, databases, scripts).
    pub fn dir(&self) -> &TestDir {
        &self.dir
    }

    /// The database path configured via [`Builder::database`].
    pub fn db_path(&self) -> &Path {
        self.db_path.as_deref().expect("no database configured")
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// GET returning the raw response; panics on transport errors only.
    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .send()
            .await
            .unwrap_or_else(|err| panic!("GET {path}: {err}"))
    }

    /// GET asserting success and returning the parsed JSON body.
    pub async fn json(&self, path: &str) -> serde_json::Value {
        let resp = self.get(path).await;
        let status = resp.status();
        let text = resp.text().await.expect("body");
        assert!(status.is_success(), "GET {path} -> {status}: {text}");
        serde_json::from_str(&text).unwrap_or_else(|err| panic!("GET {path} json: {err}: {text}"))
    }

    /// Graceful shutdown with a deadline: a hung server fails the test,
    /// not the CI job. Takes `&mut self` so the test directory outlives
    /// the shutdown — post-stop assertions (a rolled-back database, an
    /// uploaded file) still have their evidence.
    pub async fn stop(&mut self) {
        self.shutdown().await.expect("clean shutdown");
        // Leak accounting: after a clean drain, every Lua state must be
        // back in the pool. A missing one means something checked a state
        // out and never returned it — a leak nothing else in the suite
        // would notice, since the next test gets a fresh server. Bounded
        // poll rather than an instant assert: guards return their states
        // a beat after the drain resolves, and a recycled state's rebuild
        // lands off the request path.
        let size = self.pool.size();
        let deadline = std::time::Instant::now() + POOL_SETTLE_DEADLINE;
        while self.pool.available() != size {
            assert!(
                std::time::Instant::now() < deadline,
                "leak: only {} of {size} Lua state(s) returned to the pool \
                 after a clean shutdown",
                self.pool.available(),
            );
            tokio::time::sleep(POOL_SETTLE_INTERVAL).await;
        }
    }

    /// Like [`stop`](Self::stop), but hands back the serve result instead
    /// of asserting on it — for tests whose subject is the shutdown
    /// outcome itself (an expired drain deadline reports an error).
    pub async fn shutdown(&mut self) -> nitr::Result {
        let _ = self.stop.take().expect("not stopped").send(());
        let served = self.served.take().expect("not stopped");
        match tokio::time::timeout(JOIN_DEADLINE, served).await {
            Ok(task) => task.expect("server task"),
            Err(_) => panic!("the server did not shut down within 10s"),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Reached without `stop()` only when the test already failed:
        // don't leave the serve task running into other tests.
        if let Some(served) = self.served.take() {
            served.abort();
        }
    }
}
