// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for phase 12: SQLite that behaves under concurrency,
//! migrations, the shared cache, and a `fetch` that can retry, be bounded,
//! and be correlated.

mod harness;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use harness::{TestDir, TestServer, wait_until_listening};

/// Every server in this file wants real concurrency: the SQLite tests
/// exist to prove pooled states writing at once do not collide.
fn builder(script: &str) -> harness::Builder {
    TestServer::builder("data-io")
        .handler(script)
        .config(|cfg| cfg.workers = 4)
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS counters (id INTEGER PRIMARY KEY, value TEXT);
     CREATE TABLE IF NOT EXISTS parents (id INTEGER PRIMARY KEY);
     CREATE TABLE IF NOT EXISTS children (
         id INTEGER PRIMARY KEY,
         parent_id INTEGER REFERENCES parents(id)
     );";

fn db_builder(script: &str) -> harness::Builder {
    builder(script)
        .std_features(&["json", "http", "db"])
        .database("app.db")
        .seed_sql(SCHEMA)
}

/// A stub upstream for the `fetch` tests.
///
/// Records what it received and can be told to fail the first N requests,
/// which is what makes retry behavior observable rather than assumed.
#[derive(Clone, Default)]
struct Upstream {
    requests: Arc<AtomicUsize>,
    fail_first: Arc<AtomicUsize>,
    traceparents: Arc<Mutex<Vec<Option<String>>>>,
}

impl Upstream {
    async fn start(&self) -> SocketAddr {
        use http_body_util::Full;
        use hyper::body::Bytes;
        use hyper::service::service_fn;
        use hyper::{Response, StatusCode};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let addr = listener.local_addr().expect("upstream addr");
        let state = self.clone();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let state = state.clone();
                        async move {
                            state.requests.fetch_add(1, Ordering::SeqCst);
                            state.traceparents.lock().expect("lock").push(
                                req.headers()
                                    .get("traceparent")
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_string),
                            );
                            // Fail the first N, then succeed: a retry that
                            // works has to be visible as a later success.
                            let remaining = state.fail_first.load(Ordering::SeqCst);
                            if remaining > 0 {
                                state.fail_first.store(remaining - 1, Ordering::SeqCst);
                                return Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Full::new(Bytes::from_static(b"nope")))
                                        .expect("response"),
                                );
                            }
                            Ok(Response::new(Full::new(Bytes::from_static(
                                b"{\"ok\":true}",
                            ))))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        wait_until_listening(addr).await;
        addr
    }

    fn seen(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------

const DB_SCRIPT: &str = r#"
local app = nitr.app()

app:get("/pragmas", function(req)
    local journal = nitr.db:query_row("PRAGMA journal_mode")
    local fk = nitr.db:query_row("PRAGMA foreign_keys")
    local busy = nitr.db:query_row("PRAGMA busy_timeout")
    return nitr.json({
        journal_mode = journal.journal_mode,
        foreign_keys = fk.foreign_keys,
        busy_timeout = busy.timeout,
    })
end)

-- Every request writes; with the default rollback journal and no busy
-- timeout, concurrent calls to this would fail with SQLITE_BUSY.
app:get("/write", function(req)
    nitr.db:execute("INSERT INTO counters (value) VALUES (?)", { req.id })
    local row = nitr.db:query_row("SELECT COUNT(*) AS n FROM counters")
    return nitr.json({ n = row.n })
end)

-- The footgun: using the outer handle inside a transaction body.
app:get("/footgun", function(req)
    local ok, err = pcall(function()
        nitr.db:transaction(function(tx)
            tx:execute("INSERT INTO counters (value) VALUES ('inside')")
            -- This would silently join the transaction.
            nitr.db:execute("INSERT INTO counters (value) VALUES ('escaped')")
        end)
    end)
    return nitr.json({ ok = ok, err = tostring(err) })
end)

-- A foreign key that SQLite would ignore without the pragma.
app:get("/foreign-key", function(req)
    local ok, err = pcall(function()
        nitr.db:execute("INSERT INTO children (parent_id) VALUES (9999)")
    end)
    return nitr.json({ ok = ok, err = tostring(err) })
end)

return app
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_runs_with_the_pragmas_a_server_needs() {
    let mut srv = db_builder(DB_SCRIPT).spawn().await;

    let body = srv.json("/pragmas").await;
    assert_eq!(body["journal_mode"], "wal");
    assert_eq!(body["foreign_keys"], 1);
    assert_eq!(body["busy_timeout"], 5000);

    // Foreign keys are actually enforced, which SQLite does not do by
    // default however the schema is written.
    let body = srv.json("/foreign-key").await;
    assert_eq!(body["ok"], false, "the constraint must be enforced");
    assert!(
        body["err"].as_str().expect("err").contains("FOREIGN KEY"),
        "{}",
        body["err"]
    );

    srv.stop().await;
}

/// The failure mode this phase exists to remove: several pooled states
/// writing at once. On the old defaults one of them gets `SQLITE_BUSY`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_do_not_collide() {
    let mut srv = db_builder(DB_SCRIPT).spawn().await;

    let mut requests = Vec::new();
    for _ in 0..40 {
        let client = srv.client().clone();
        let url = srv.url("/write");
        requests.push(tokio::spawn(async move {
            client.get(url).send().await?.status().as_u16().pipe_ok()
        }));
    }
    for handle in requests {
        let status = handle.await.expect("task").expect("request");
        assert_eq!(status, 200, "a concurrent write failed");
    }

    let body = srv.json("/write").await;
    assert_eq!(body["n"], 41, "every write must have landed");

    srv.stop().await;
}

/// Small helper so the concurrency test above reads cleanly.
trait PipeOk: Sized {
    fn pipe_ok(self) -> reqwest::Result<Self> {
        Ok(self)
    }
}
impl PipeOk for u16 {}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_outer_handle_refuses_to_run_inside_a_transaction() {
    let mut srv = db_builder(DB_SCRIPT).spawn().await;

    let body = srv.json("/footgun").await;
    assert_eq!(body["ok"], false, "the escape must be an error now");
    let err = body["err"].as_str().expect("err");
    assert!(err.contains("transaction is open"), "{err}");

    srv.stop().await;

    // The transaction rolled back, so neither row is there — including the
    // one the body wrote before the mistake. (The harness keeps the test
    // directory alive through `stop`, so the database is still on disk.)
    let conn = rusqlite::Connection::open(srv.db_path()).expect("open");
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM counters", [], |row| row.get(0))
        .expect("count");
    assert_eq!(count, 0);
}

// ---------------------------------------------------------------------------

#[test]
fn migrations_apply_and_the_ledger_is_readable() {
    let dir = TestDir::new("data-io-migrations");
    dir.write(
        "migrations/001_create_notes.sql",
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);",
    );
    dir.write(
        "migrations/002_add_index.sql",
        "CREATE INDEX notes_body ON notes (body);",
    );
    let migrations = dir.join("migrations");

    let pragmas = nitr::stdlib::SqlitePragmas::default();
    let conn = nitr::stdlib::db_open(&dir.join("migrated.db"), &pragmas).expect("open");

    assert_eq!(
        nitr::stdlib::migrate::pending(&conn, &migrations).expect("pending"),
        vec!["001_create_notes.sql", "002_add_index.sql"]
    );
    let applied = nitr::stdlib::migrate::run(&conn, &migrations).expect("run");
    assert_eq!(applied.len(), 2);
    assert!(
        nitr::stdlib::migrate::pending(&conn, &migrations)
            .expect("pending")
            .is_empty()
    );

    conn.execute("INSERT INTO notes (body) VALUES ('hi')", [])
        .expect("the schema really exists");
}

/// Applying schema changes at boot is how a rolling deployment races
/// itself, so a pending migration stops the server instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_migration_refuses_the_boot() {
    let b = builder(DB_SCRIPT)
        .std_features(&["json", "http", "db"])
        .database("pending.db");
    let migrations = b.dir().write(
        "migrations/001_create_things.sql",
        "CREATE TABLE things (id INTEGER PRIMARY KEY);",
    );
    let migrations = migrations.parent().expect("dir").to_path_buf();
    let mig = migrations.clone();
    let mut b = b.config(move |cfg| {
        cfg.database.as_mut().expect("database").migrations_dir = Some(mig);
    });

    let err = b.try_build().await.expect_err("must refuse to start");
    let message = err.to_string();
    assert!(message.contains("001_create_things.sql"), "{message}");
    assert!(message.contains("nitr migrate"), "{message}");

    // Once applied, the same configuration starts.
    let pragmas = nitr::stdlib::SqlitePragmas::default();
    let conn = nitr::stdlib::db_open(b.db_path(), &pragmas).expect("open");
    nitr::stdlib::migrate::run(&conn, &migrations).expect("migrate");
    drop(conn);

    b.try_build()
        .await
        .expect("starts once the schema is current");
}

// ---------------------------------------------------------------------------

const CACHE_SCRIPT: &str = r#"
local app = nitr.app()

-- Counts how often the expensive function actually ran *in this state*.
local computed = 0

app:get("/remember", function(req)
    local value = nitr.cache:remember("rates", { ttl = 60 }, function()
        computed = computed + 1
        return { usd = 1.0, eur = 0.92 }
    end)
    return nitr.json({ value = value, computed_here = computed })
end)

app:get("/set", function(req)
    nitr.cache:set("shared", { who = req.query.who }, { ttl = 60 })
    return nitr.json({ ok = true })
end)

app:get("/get", function(req)
    return nitr.json({ value = nitr.cache:get("shared") })
end)

app:get("/stats", function(req)
    return nitr.json(nitr.cache:stats())
end)

app:get("/uncacheable", function(req)
    local ok, err = pcall(function()
        nitr.cache:set("fn", function() end)
    end)
    return nitr.json({ ok = ok, err = tostring(err) })
end)

return app
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cache_is_shared_across_states_and_bounded() {
    let mut srv = builder(CACHE_SCRIPT)
        .std_features(&["json", "http", "cache"])
        .spawn()
        .await;

    // Written by whichever state served this, read back by (very likely) a
    // different one: the whole point is that they share the storage.
    srv.json("/set?who=alice").await;
    for _ in 0..8 {
        let body = srv.json("/get").await;
        assert_eq!(body["value"]["who"], "alice");
    }

    // `remember` runs the function once for the whole pool, not once per
    // state, because the value is in the shared cache after the first call.
    let mut total_computed = 0;
    for _ in 0..12 {
        let body = srv.json("/remember").await;
        assert_eq!(body["value"]["eur"], 0.92);
        total_computed += body["computed_here"].as_u64().expect("computed");
    }
    let stats = srv.json("/stats").await;
    assert!(
        stats["hits"].as_u64().expect("hits") > 0,
        "the second and later reads must be hits: {stats}"
    );
    assert!(
        total_computed <= 12,
        "the expensive function must not run every time"
    );

    // A function cannot be cached: entries are plain data, which is what
    // keeps one state from reaching into another's heap.
    let body = srv.json("/uncacheable").await;
    assert_eq!(body["ok"], false);
    assert!(
        body["err"].as_str().expect("err").contains("plain data"),
        "{}",
        body["err"]
    );

    srv.stop().await;
}

// ---------------------------------------------------------------------------

const FETCH_SCRIPT: &str = r#"
local app = nitr.app()

app:get("/retry", function(req)
    local resp = nitr.fetch("get", nitr.cfg.upstream, {
        retry = { attempts = 4, backoff = "constant" },
    }):send()
    return nitr.json({ status = resp.status, body = resp:json() })
end)

-- POST is never repeated automatically, whatever the caller asks for.
app:get("/retry-post", function(req)
    local ok, err = pcall(function()
        return nitr.fetch("post", nitr.cfg.upstream, {
            body = "x",
            retry = { attempts = 4 },
        }):send()
    end)
    return nitr.json({ ok = ok, err = tostring(err) })
end)

app:get("/budget", function(req)
    local made, err = 0, nil
    for _ = 1, 10 do
        local ok, e = pcall(function()
            nitr.fetch("get", nitr.cfg.upstream):send()
        end)
        if not ok then err = tostring(e) break end
        made = made + 1
    end
    return nitr.json({ made = made, err = tostring(err) })
end)

app:get("/traced", function(req)
    local resp = nitr.fetch("get", nitr.cfg.upstream):send()
    return nitr.json({ status = resp.status })
end)

app:get("/private", function(req)
    local ok, err = pcall(function()
        nitr.fetch("get", "http://localhost:9/"):send()
    end)
    return nitr.json({ ok = ok, err = tostring(err) })
end)

return app
"#;

async fn fetch_server(upstream: SocketAddr, tune: impl FnOnce(&mut nitr::Config)) -> TestServer {
    builder(FETCH_SCRIPT)
        .std_features(&["json", "http", "fetch"])
        .config_script(format!("return {{ upstream = \"http://{upstream}/\" }}"))
        // The stub upstream is on loopback, which the SSRF policy forbids
        // by default — exactly as it should.
        .config(|cfg| cfg.fetch.allow_private_networks = true)
        .config(tune)
        .spawn()
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idempotent_requests_retry_and_others_do_not() {
    let upstream = Upstream::default();
    let addr = upstream.start().await;
    upstream.fail_first.store(2, Ordering::SeqCst);

    let mut srv = fetch_server(addr, |_| {}).await;

    let body = srv.json("/retry").await;
    assert_eq!(body["status"], 200, "the third attempt must succeed");
    assert_eq!(body["body"]["ok"], true);
    assert_eq!(upstream.seen(), 3, "two failures plus the success");

    // A POST is sent exactly once even though the caller asked for four
    // attempts: repeating it is how a customer gets charged twice.
    upstream.fail_first.store(3, Ordering::SeqCst);
    let before = upstream.seen();
    srv.json("/retry-post").await;
    assert_eq!(
        upstream.seen() - before,
        1,
        "a POST must never be repeated automatically"
    );

    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_inbound_request_has_a_bounded_outbound_cost() {
    let upstream = Upstream::default();
    let addr = upstream.start().await;

    let mut srv = fetch_server(addr, |cfg| cfg.fetch.max_per_request = 3).await;

    let body = srv.json("/budget").await;
    assert_eq!(body["made"], 3, "the fourth call must be refused");
    assert!(
        body["err"]
            .as_str()
            .expect("err")
            .contains("max_per_request"),
        "{}",
        body["err"]
    );

    // The next inbound request starts with a fresh budget.
    let body = srv.json("/budget").await;
    assert_eq!(body["made"], 3);

    srv.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trace_context_is_forwarded_when_enabled() {
    let upstream = Upstream::default();
    let addr = upstream.start().await;

    let mut srv = fetch_server(addr, |cfg| cfg.fetch.propagate_trace_context = true).await;
    srv.json("/traced").await;
    srv.stop().await;

    let seen = upstream.traceparents.lock().expect("lock").clone();
    let traceparent = seen
        .last()
        .expect("one request")
        .clone()
        .expect("traceparent must be present");
    // version-traceid-spanid-flags, with the ids the documented widths.
    let parts: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(parts.len(), 4, "malformed traceparent `{traceparent}`");
    assert_eq!(parts[0], "00");
    assert_eq!(parts[1].len(), 32, "trace id must be 16 bytes");
    assert_eq!(parts[2].len(), 16, "span id must be 8 bytes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ssrf_policy_still_refuses_loopback_by_default() {
    let upstream = Upstream::default();
    let addr = upstream.start().await;

    // Note the override is *off* here, unlike the other fetch tests.
    let mut srv = fetch_server(addr, |cfg| cfg.fetch.allow_private_networks = false).await;
    let body = srv.json("/private").await;
    assert_eq!(body["ok"], false);
    assert!(
        body["err"].as_str().expect("err").contains("private"),
        "{}",
        body["err"]
    );
    srv.stop().await;
}

// ---------------------------------------------------------------------------

const AWAIT_SCRIPT: &str = r#"
local app = nitr.app()

app:get("/combined", function(req)
    -- A query and an HTTP call at the same time, rather than one after the
    -- other: this is what db:query_async exists for.
    local rows, resp = nitr.await_all(
        nitr.db:query_async("SELECT value FROM counters ORDER BY id"),
        nitr.fetch("get", nitr.cfg.upstream)
    )
    return nitr.json({ rows = rows, upstream = resp:json() })
end)

app:get("/reuse", function(req)
    local handle = nitr.db:query_async("SELECT 1 AS n")
    nitr.await_all(handle)
    local ok, err = pcall(function() nitr.await_all(handle) end)
    return nitr.json({ ok = ok, err = tostring(err) })
end)

return app
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_and_a_fetch_can_run_together() {
    let upstream = Upstream::default();
    let addr = upstream.start().await;

    let mut srv = builder(AWAIT_SCRIPT)
        .std_features(&["json", "http", "db", "fetch"])
        .database("await.db")
        .seed_sql(SCHEMA)
        .seed_sql("INSERT INTO counters (value) VALUES ('one');")
        .config_script(format!("return {{ upstream = \"http://{addr}/\" }}"))
        .config(|cfg| cfg.fetch.allow_private_networks = true)
        .spawn()
        .await;

    let body = srv.json("/combined").await;
    assert_eq!(body["rows"][0]["value"], "one");
    assert_eq!(body["upstream"]["ok"], true);

    // A handle is one-shot: awaiting it twice is a mistake worth naming.
    let body = srv.json("/reuse").await;
    assert_eq!(body["ok"], false);
    assert!(
        body["err"].as_str().expect("err").contains("already"),
        "{}",
        body["err"]
    );

    srv.stop().await;
}
