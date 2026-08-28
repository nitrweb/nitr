// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for what Nitr does when things go wrong.
//!
//! Load shedding, panic containment, failure isolation between concurrent
//! requests, the sandbox budgets (instructions and memory), request-body
//! counting and stall bounds, client disconnects, and the
//! graceful-shutdown drain — each asserted through the real server.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use std::time::Duration;

use harness::TestServer;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const APP_SCRIPT: &str = r#"
local app = nitr.app()

app:get("/ok", function(req)
    return nitr.text("ok")
end)

-- Suspends without burning instructions, so the state stays checked out.
app:get("/slow", function(req)
    nitr.ext.testutil.sleep(3000)
    return nitr.text("slow")
end)

-- A panic raised in Rust, on the far side of the extension boundary.
app:get("/panic", function(req)
    nitr.ext.testutil.boom()
    return nitr.text("unreachable")
end)

-- The sandbox escape phase 10 closes: a hot loop inside a coroutine the
-- script created itself, which a per-thread hook would never see.
app:get("/coroutine-spin", function(req)
    local spin = coroutine.wrap(function()
        while true do end
    end)
    spin()
    return nitr.text("unreachable")
end)

app:post("/echo", function(req)
    return nitr.text(req:text())
end)

-- Phase 24: serializing a deep table chain must be a catchable error,
-- not the stack-overflow abort it used to be.
app:get("/deep-json", function(req)
    local root = {}
    local cur = root
    for i = 1, 2000 do
        local n = {}
        cur.x = n
        cur = n
    end
    local ok, err = pcall(function() return nitr.json:encode(root) end)
    if ok then
        return nitr.text("encoded")
    end
    return nitr.text("caught: " .. tostring(err))
end)

return app
"#;

/// A Lua-visible module that can do the two things no sandboxed script can:
/// suspend on a real timer, and panic in Rust.
fn testutil(lua: &mlua::Lua) -> mlua::Result<mlua::Table> {
    let t = lua.create_table()?;
    t.set(
        "sleep",
        lua.create_async_function(|_, ms: u64| async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok(())
        })?,
    )?;
    t.set(
        "boom",
        lua.create_function(|_, ()| -> mlua::Result<()> {
            panic!("boom from a Rust extension module")
        })?,
    )?;
    Ok(t)
}

/// A running server with the shared app script and the testutil module;
/// `tune` adjusts workers, limits, and shutdown timing.
async fn start(tune: impl FnOnce(&mut nitr::Config)) -> TestServer {
    TestServer::builder("resilience")
        .handler(APP_SCRIPT)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .module("testutil", testutil)
        // Keep the drain short so shutdown assertions do not idle for 35s.
        .config(|cfg| {
            cfg.shutdown.grace = 1;
            cfg.shutdown.stream_grace = 0;
        })
        .config(tune)
        .spawn()
        .await
}

// ---------------------------------------------------------------------------

/// A single state, one slow request holding it: the next request must be shed
/// with 503 + `Retry-After` instead of queueing behind the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_saturated_pool_sheds_instead_of_queueing() {
    let mut h = start(|cfg| {
        cfg.workers = 1;
        cfg.limits.pool_wait_ms = 200;
    })
    .await;
    let client = h.client().clone();

    // Occupy the only state for 3s.
    let slow = tokio::spawn({
        let client = client.clone();
        let url = h.url("/slow");
        async move { client.get(url).send().await }
    });
    // Wait for the fact, not a guessed interval: the slow request has
    // checked the only state out once nothing is available.
    h.wait_until_available(0).await;

    let resp = h.get("/ok").await;
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.headers()["retry-after"], "1");

    // The slow request itself is unaffected.
    let slow = slow.await.expect("slow task").expect("slow response");
    assert_eq!(slow.status(), 200);
    assert_eq!(slow.text().await.expect("slow body"), "slow");

    // And the state is back in circulation afterwards.
    let resp = h.get("/ok").await;
    assert_eq!(resp.status(), 200);

    h.stop().await;
}

/// The shipped release profile must unwind, because everything the test
/// below proves depends on it.
///
/// This has to be asserted statically, against the manifest, and cannot be
/// folded into the runtime test: Cargo *ignores* `panic` for the `test` and
/// `bench` profiles (the harness needs to unwind to report failures), so a
/// test binary always unwinds no matter what `[profile.release]` says —
/// even under `cargo test --release`. Confirmed by inspection: the test
/// target is compiled with no `-C panic` flag at all, while the `nitr`
/// binary under the same profile gets `-C panic=abort`. So a run of
/// `a_panic_becomes_a_500_and_recycles_the_state` proves the boundary works
/// in *some* build; only this test proves it is the shipped one.
#[test]
fn the_release_profile_unwinds_so_the_panic_boundary_is_real() {
    // Walk up to the workspace manifest. Outside a workspace checkout
    // (a packaged crate, say) there is no profile to check and nothing to
    // assert, so skip rather than fail — the same convention the
    // cross-compiled CLI tests use.
    let mut dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = loop {
        let candidate = dir.join("Cargo.toml");
        if std::fs::read_to_string(&candidate).is_ok_and(|text| text.contains("[workspace]")) {
            break candidate;
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => {
                eprintln!("skipping: no workspace manifest above this crate");
                return;
            }
        }
    };

    let text = std::fs::read_to_string(&manifest).expect("read the workspace manifest");
    let parsed: toml::Value = text.parse().expect("parse the workspace manifest");
    let panic_setting = parsed
        .get("profile")
        .and_then(|profiles| profiles.get("release"))
        .and_then(|release| release.get("panic"))
        .and_then(|value| value.as_str());

    // Absent is correct: the default is `unwind`. An explicit "unwind" is
    // equally fine; anything else disarms the boundary.
    assert!(
        matches!(panic_setting, None | Some("unwind")),
        "[profile.release] sets panic = {panic_setting:?} in {}.\n\
         Aborting on panic makes the request panic boundary in \
         nitr-http's `handle()` dead code: a panic in any request-reachable \
         Rust code would kill the process and every in-flight connection \
         instead of becoming a 500 with a recycled Lua state.",
        manifest.display()
    );
}

/// A panic in Rust code called from Lua becomes a 500 instead of killing the
/// connection, and the damaged state is recycled so the pool keeps its size.
///
/// Note that this proves the boundary works, but not that the *shipped*
/// binary has it — see the static profile check above for why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_panic_becomes_a_500_and_recycles_the_state() {
    let mut h = start(|cfg| cfg.workers = 1).await;

    let resp = h.get("/panic").await;
    assert_eq!(resp.status(), 500);

    // The state was dropped and rebuilt off the request path; wait for the
    // replacement rather than assuming an ordering.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while h.pool().available() == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(h.pool().size(), 1, "the pool must not shrink");

    // And the server keeps serving on the replacement.
    let resp = h.get("/ok").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body"), "ok");

    h.stop().await;
}

/// The audit's draft invariant, asserted directly: a failure in one
/// request — here the worst kind, a Rust panic that damages its state —
/// must not disturb unrelated requests running concurrently on other
/// states, and the pool must refill to full strength afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_panic_does_not_disturb_concurrent_requests_on_other_states() {
    let mut h = start(|cfg| cfg.workers = 4).await;
    let client = h.client().clone();

    // Three in-flight requests, each holding its own state for 3s.
    let inflight: Vec<_> = (0..3)
        .map(|_| {
            tokio::spawn({
                let client = client.clone();
                let url = h.url("/slow");
                async move { client.get(url).send().await }
            })
        })
        .collect();
    // Wait until all three have checked their states out: on four workers
    // that leaves exactly one free — the one the panic will use.
    h.wait_until_available(1).await;

    // The fourth state panics mid-request.
    let resp = h.get("/panic").await;
    assert_eq!(resp.status(), 500);

    // Every concurrent request completes untouched.
    for task in inflight {
        let resp = task
            .await
            .expect("in-flight task")
            .expect("a neighbor's panic must not cut this connection");
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.expect("body"), "slow");
    }

    // The damaged state is replaced: the pool refills to all four.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while h.pool().available() < 4 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(h.pool().size(), 4, "the pool must refill, not shrink");

    let resp = h.get("/ok").await;
    assert_eq!(resp.status(), 200);

    h.stop().await;
}

/// The Lua memory limit actually fires: the failure is classified
/// `memory` (visible to `on_error`), the poisoned state is recycled, and
/// the next request runs on a fresh one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_memory_limit_fires_and_the_state_is_recycled() {
    let mut h = TestServer::builder("resilience-memory")
        .handler(
            r#"
local app = nitr.app()

app:get("/ok", function(req)
    return nitr.text("ok")
end)

app:get("/hog", function(req)
    local t = {}
    local i = 0
    while true do
        i = i + 1
        t[i] = string.rep("x", 8192) .. tostring(i)
    end
end)

app:on_error(function(err, req)
    return { status = 500, body = "kind=" .. err.kind }
end)

return app
"#,
        )
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| {
            cfg.workers = 1;
            // Small enough to hit fast, large enough for the app itself.
            cfg.lua.memory_limit = 4 * 1024 * 1024;
            cfg.shutdown.grace = 1;
            cfg.shutdown.stream_grace = 0;
        })
        .spawn()
        .await;

    let resp = h.get("/hog").await;
    assert_eq!(resp.status(), 500);
    assert_eq!(
        resp.text().await.expect("body"),
        "kind=memory",
        "the classification must name the memory limit, not a script bug"
    );

    // The poisoned state is dropped and rebuilt off the request path.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while h.pool().available() == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(h.pool().size(), 1, "the pool must not shrink");

    // And the replacement state has a fresh heap.
    let resp = h.get("/ok").await;
    assert_eq!(resp.status(), 200);

    h.stop().await;
}

/// The execution budget reaches inside a coroutine the script created, which
/// a per-thread hook would let run forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_coroutine_cannot_escape_the_execution_budget() {
    let mut h = start(|cfg| {
        cfg.workers = 1;
        cfg.lua.exec_timeout_ms = 1_000;
        // Config validation refuses a pool wait above the request budget.
        cfg.limits.pool_wait_ms = 1_000;
    })
    .await;
    let client = h.client().clone();

    let started = std::time::Instant::now();
    let resp = tokio::time::timeout(
        Duration::from_secs(10),
        client.get(h.url("/coroutine-spin")).send(),
    )
    .await
    .expect("the spinning coroutine must be stopped, not run forever")
    .expect("response");
    assert_eq!(resp.status(), 500);
    // Tight against the 1s budget (real time is ~1.1s), not the 10s outer
    // timeout: a regression that let the coroutine spin for, say, 4s would
    // slip under a 5s bound but not this one.
    assert!(
        started.elapsed() < Duration::from_millis(2_500),
        "stopped after {:?}, well past the 1s budget",
        started.elapsed()
    );

    // The state recovers and serves the next request.
    let resp = h.get("/ok").await;
    assert_eq!(resp.status(), 200);

    h.stop().await;
}

/// A chunked body declares no length, so the ceiling has to be enforced on
/// the bytes that actually arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_chunked_body_is_rejected_with_413() {
    let mut h = start(|cfg| {
        cfg.workers = 1;
        cfg.limits.max_body_bytes = 1024;
    })
    .await;

    // A chunked body carries no Content-Length, so the declared-size check
    // cannot see it: only the running count can. Written on a raw socket
    // because the test client always sets a length.
    let mut sock = tokio::net::TcpStream::connect(h.addr())
        .await
        .expect("connect");
    sock.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await
        .expect("write headers");
    // 4 KiB in 512-byte chunks, four times the 1 KiB ceiling. The writes are
    // best-effort: the server is entitled to answer and hang up part-way
    // through, which is the whole point of counting as bytes arrive.
    for _ in 0..8 {
        if sock.write_all(b"200\r\n").await.is_err()
            || sock.write_all(&[b'x'; 512]).await.is_err()
            || sock.write_all(b"\r\n").await.is_err()
        {
            break;
        }
    }
    let _ = sock.write_all(b"0\r\n\r\n").await;

    // Read just the status line: the connection may stay open afterwards.
    let mut raw = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut raw))
        .await
        .expect("the server must answer, not hang")
        .expect("read response");
    let head = String::from_utf8_lossy(&raw[..n]);
    assert!(head.starts_with("HTTP/1.1 413"), "got: {head}");

    // An honest small body still passes.
    let resp = h
        .client()
        .post(h.url("/echo"))
        .body("small")
        .send()
        .await
        .expect("small response");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body"), "small");

    h.stop().await;
}

/// When the client hangs up mid-request, the handler future is dropped and
/// the state it held goes back to the pool — it is not held for the full
/// handler duration serving a response nobody will read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_disconnect_releases_the_pooled_state() {
    let mut h = start(|cfg| {
        cfg.workers = 1;
        cfg.limits.pool_wait_ms = 500;
    })
    .await;

    // Raw socket: send the request, then hang up while the handler sleeps.
    let mut sock = tokio::net::TcpStream::connect(h.addr())
        .await
        .expect("connect");
    sock.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write request");
    // The handler has checked the only state out.
    h.wait_until_available(0).await;
    drop(sock);
    // Wait for hyper to notice the peer is gone, drop the handler future,
    // and return the state to the pool — the release under test.
    h.wait_until_available(1).await;

    // The 3s handler is long gone; if the state were still checked out this
    // would exceed the 500ms wait budget and come back 503.
    let resp = h.get("/ok").await;
    assert_eq!(
        resp.status(),
        200,
        "the abandoned request must not keep holding the only Lua state"
    );

    h.stop().await;
}

/// An in-flight request finishes after the shutdown signal, and the server
/// reports a clean drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_drains_in_flight_requests() {
    let mut h = start(|cfg| {
        cfg.workers = 2;
        // The slow handler needs 3s; give the drain room to finish it.
        cfg.shutdown.grace = 10;
    })
    .await;
    let client = h.client().clone();
    let addr = h.addr();

    let inflight = tokio::spawn({
        let client = client.clone();
        let url = h.url("/slow");
        async move { client.get(url).send().await }
    });
    // On two workers, the in-flight /slow leaves one state free.
    h.wait_until_available(1).await;

    // Signal shutdown while the request is still running; `shutdown`
    // resolves only after the drain, so run it concurrently with the
    // in-flight request's completion.
    let drained = tokio::spawn(async move { h.shutdown().await });

    let resp = inflight
        .await
        .expect("in-flight task")
        .expect("the in-flight request must complete, not be cut");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body"), "slow");

    drained
        .await
        .expect("shutdown task")
        .expect("a drained shutdown is not an error");

    // The listener is closed after the drain: a *fresh TCP connection* is
    // refused. The old assertion was a disjunction — connect fails OR the
    // request fails — which passed on any client-side error at all (a pool
    // hiccup, a reused dead connection). This discriminates: a brand-new
    // connect must be refused. Polled briefly because dropping the accept
    // loop races this line by microseconds.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Err(_) => break,
            Ok(_) => assert!(
                std::time::Instant::now() < deadline,
                "the server must stop accepting new connections after the drain"
            ),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(client);
}

/// A request that outlives the drain deadline is cut, and the server says so
/// rather than exiting as if nothing happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_drain_deadline_is_reported() {
    // 1s of grace (the suite default) against a 3s handler.
    let mut h = start(|cfg| cfg.workers = 2).await;
    let client = h.client().clone();

    let inflight = tokio::spawn({
        let url = h.url("/slow");
        async move { client.get(url).send().await }
    });
    // The in-flight /slow has checked its state out (two workers, one busy).
    h.wait_until_available(1).await;

    let err = h
        .shutdown()
        .await
        .expect_err("a truncated shutdown must surface");
    assert!(matches!(err, nitr::Error::ShutdownTimeout), "got: {err:?}");

    // The abandoned request was cut rather than answered.
    let _ = inflight.await;
}

/// Phase 24: encoding a deeply nested table is an ordinary catchable Lua
/// error. It used to recurse per level and overflow the Rust stack — a
/// SIGABRT no panic boundary can contain (verified empirically at ~30,000
/// levels before the guard existed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deep_json_serialization_is_a_catchable_error_not_an_abort() {
    let mut h = start(|cfg| cfg.workers = 1).await;

    let resp = h.get("/deep-json").await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("nested deeper than 128 levels"),
        "got: {body}"
    );

    // And the state is unharmed: no recycling was needed, the next
    // request runs on the same pool.
    let resp = h.get("/ok").await;
    assert_eq!(resp.status(), 200);

    h.stop().await;
}

/// A client that stops sending its body mid-way is answered `408` with
/// `Connection: close`, instead of holding a pooled state until the
/// compute budget notices.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_body_is_answered_408_and_the_connection_is_closed() {
    let mut h = start(|cfg| {
        cfg.workers = 1;
        cfg.limits.body_read_ms = 200;
    })
    .await;

    let mut sock = tokio::net::TcpStream::connect(h.addr())
        .await
        .expect("connect");
    sock.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nabc")
        .await
        .expect("write partial body");
    // ...and then nothing: the stall bound must answer, not wait for the
    // remaining 7 bytes.
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut raw))
        .await
        .expect("the server must answer within the stall budget")
        .expect("read response");
    let head = String::from_utf8_lossy(&raw).to_lowercase();
    assert!(head.starts_with("http/1.1 408"), "got: {head}");
    assert!(head.contains("connection: close"), "got: {head}");
    // `read_to_end` returning proves the close was real, not just a header.

    // The pool is intact: a fresh connection is served immediately.
    let resp = h.get("/ok").await;
    assert_eq!(resp.status(), 200);

    h.stop().await;
}

/// The stall bound clocks progress, not total transfer: a trickled body
/// whose every gap stays under the budget completes, however long the
/// whole upload takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_but_moving_body_is_not_punished() {
    let mut h = start(|cfg| {
        cfg.workers = 1;
        cfg.limits.body_read_ms = 300;
    })
    .await;

    let mut sock = tokio::net::TcpStream::connect(h.addr())
        .await
        .expect("connect");
    sock.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n")
        .await
        .expect("write headers");
    // Ten bytes, one every 80 ms: 800 ms total against a 300 ms budget —
    // fine, because no single gap exceeds it.
    for byte in b"0123456789" {
        sock.write_all(&[*byte]).await.expect("trickle a byte");
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    let mut raw = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut raw))
        .await
        .expect("the server must answer")
        .expect("read response");
    let head = String::from_utf8_lossy(&raw[..n]);
    assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");
    assert!(
        head.contains("0123456789"),
        "the echo must be whole: {head}"
    );

    h.stop().await;
}

/// A header block larger than `[limits] max_header_bytes` is refused
/// before any handler runs — the guard was wired to hyper's `max_buf_size`
/// but exercised by nothing. Sent on a raw socket because no HTTP client
/// will emit a header block this size on request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_header_block_is_rejected() {
    let mut h = start(|cfg| {
        cfg.workers = 1;
        // The effective buffer is `max(this, 8 KiB)`; 16 KiB so the 64 KiB
        // block below clearly overruns it.
        cfg.limits.max_header_bytes = 16 * 1024;
    })
    .await;

    let mut sock = tokio::net::TcpStream::connect(h.addr())
        .await
        .expect("connect");
    // A single 64 KiB header value, four times the buffer.
    let mut req = b"GET /ok HTTP/1.1\r\nHost: localhost\r\nX-Big: ".to_vec();
    req.extend(std::iter::repeat_n(b'A', 64 * 1024));
    req.extend_from_slice(b"\r\n\r\n");
    // The write may not fully land before the server hangs up — that is
    // itself the guard firing, so the write is best-effort.
    let _ = sock.write_all(&req).await;

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut raw))
        .await
        .expect("the server must answer or close, not hang on the huge header")
        .expect("read response");
    let head = String::from_utf8_lossy(&raw).to_lowercase();
    assert!(
        head.starts_with("http/1.1 431"),
        "an over-limit header block must answer 431: {head}"
    );
    assert!(head.contains("connection: close"), "got: {head}");
    // `read_to_end` returning proves the close was real.

    // The positive control: a header block just under the buffer is
    // ordinary traffic — the 431 above is the limit firing, not the
    // server rejecting big-ish headers wholesale.
    let mut sock = tokio::net::TcpStream::connect(h.addr())
        .await
        .expect("connect again");
    let mut req = b"GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Big: ".to_vec();
    req.extend(std::iter::repeat_n(b'A', 8 * 1024));
    req.extend_from_slice(b"\r\n\r\n");
    sock.write_all(&req).await.expect("write in-limit request");
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut raw))
        .await
        .expect("the server must answer")
        .expect("read response");
    let head = String::from_utf8_lossy(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");

    h.stop().await;
}

/// The header deadline is configurable now (it was a hardcoded 30 s): a
/// connection that never completes its request headers is cut at
/// `[limits] header_read_ms`, not half a minute later.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_incomplete_header_read_is_cut_at_the_configured_deadline() {
    let mut h = start(|cfg| {
        cfg.workers = 1;
        cfg.limits.header_read_ms = 300;
    })
    .await;

    let started = std::time::Instant::now();
    let mut sock = tokio::net::TcpStream::connect(h.addr())
        .await
        .expect("connect");
    sock.write_all(b"GET /ok HT")
        .await
        .expect("partial request");
    // The server must end the connection on its own; hyper may send a 408
    // or nothing at all — the contract under test is the deadline.
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut raw))
        .await
        .expect("the connection must be cut at the deadline, not at 30 s")
        .expect("read until close");
    // Bounded well under the old hardcoded 30s but *also* well under the
    // 5s outer timeout, so this assertion carries its own weight instead
    // of merely restating a timeout that already succeeded. Real time is
    // ~0.3s (the configured deadline).
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the header deadline (300ms) did not fire promptly: took {:?}",
        started.elapsed()
    );
    let head = String::from_utf8_lossy(&raw);
    assert!(
        !head.contains("200 OK"),
        "no request existed to answer: {head}"
    );

    h.stop().await;
}
