// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for phase 15: health/readiness endpoints answered in
//! Rust, on the main listener or a separate bind.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::TestServer;

const APP: &str = r#"
local app = nitr.app()
app:get("/hello", function(req)
    return nitr.json({ ok = true })
end)
return app
"#;

async fn start(tune: impl FnOnce(&mut nitr::Config)) -> TestServer {
    TestServer::builder("operations")
        .handler(APP)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| cfg.workers = 1)
        .config(tune)
        .spawn()
        .await
}

/// The default: probes answer on the main listener, in Rust, and the
/// application's own routes are untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_endpoints_answer_on_the_main_listener() {
    let mut h = start(|_| {}).await;

    let resp = h.get("/healthz").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert_eq!(resp.text().await.expect("body"), "ok");

    let resp = h.get("/readyz").await;
    assert_eq!(resp.status(), 200);

    // The application still owns everything else — including a POST to
    // the probe path, which is not a probe.
    let resp = h.get("/hello").await;
    assert_eq!(resp.status(), 200);
    let resp = h
        .client()
        .post(h.url("/healthz"))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 404);

    h.stop().await;
}

/// `[health] enabled = false` removes the endpoints entirely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_health_passes_through_to_the_app() {
    let mut h = start(|cfg| cfg.health.enabled = false).await;
    let resp = h.get("/healthz").await;
    assert_eq!(resp.status(), 404);
    h.stop().await;
}

/// `[health] bind` moves the probes to their own address: the public port
/// no longer answers them, and the probe port answers nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn separate_bind_keeps_probes_off_the_public_port() {
    // `reserve_health()` pre-binds the probe port and the server adopts
    // the listener — the same no-release handoff the main listener uses —
    // so there is no window for another test to take the port, and no
    // retry loop covering for one. (This used to be the one genuinely
    // racy construct in the suite: reserve, release, hope to rebind.)
    let mut builder = TestServer::builder("operations")
        .handler(APP)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| cfg.workers = 1);
    let probe_addr = builder.reserve_health();
    let mut h = builder.spawn().await;
    let client = h.client().clone();

    // Probes on the probe port; the app never answers there.
    let probe = format!("http://{probe_addr}");
    let resp = client
        .get(format!("{probe}/healthz"))
        .send()
        .await
        .expect("liveness");
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{probe}/readyz"))
        .send()
        .await
        .expect("readiness");
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{probe}/hello"))
        .send()
        .await
        .expect("app path");
    assert_eq!(resp.status(), 404);

    // And the public port no longer serves the probes.
    let resp = h.get("/healthz").await;
    assert_eq!(resp.status(), 404);
    let resp = h.get("/hello").await;
    assert_eq!(resp.status(), 200);

    h.stop().await;
}

/// The probe listener carries the main listener's guards (audit 3,
/// phase 4, M-1): a connection cap acquired *before* accept, and the
/// complete-headers deadline. Deleting either the semaphore or the
/// `header_read_timeout` line in `serve_probes` fails this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_listener_caps_connections_and_times_out_headers() {
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut builder = TestServer::builder("operations")
        .handler(APP)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| {
            cfg.workers = 1;
            // A cap of 2 is observable; the default 64 is not.
            cfg.health.max_connections = 2;
            // Short enough to watch the close; long enough that the held
            // connections below outlive the cap probe.
            cfg.limits.header_read_ms = 1_000;
        });
    let probe_addr = builder.reserve_health();
    let mut h = builder.spawn().await;

    // Two silent connections fill the cap...
    let hold1 = tokio::net::TcpStream::connect(probe_addr)
        .await
        .expect("hold 1");
    let _hold2 = tokio::net::TcpStream::connect(probe_addr)
        .await
        .expect("hold 2");
    // ...give the accept loop a moment to take both slots.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A third connection completes its TCP handshake either way (the
    // kernel backlog does that without the process accepting), so the
    // observable fact is "no response while the cap is full".
    let mut third = tokio::net::TcpStream::connect(probe_addr)
        .await
        .expect("third connection");
    third
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let mut buf = [0u8; 64];
    let unanswered = tokio::time::timeout(Duration::from_millis(300), third.read(&mut buf)).await;
    assert!(
        unanswered.is_err(),
        "the cap is full: the third connection must not be answered yet"
    );

    // Freeing one slot lets the queued accept through, and the *same*
    // connection is answered — the permit was held for the connection's
    // life, not dropped at spawn.
    drop(hold1);
    let n = tokio::time::timeout(Duration::from_secs(5), third.read(&mut buf))
        .await
        .expect("a freed slot must let the waiting connection through")
        .expect("read response");
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(head.starts_with("HTTP/1.1 200"), "got: {head}");

    // The header deadline: connect, send nothing, and the server closes
    // the connection at ~header_read_ms instead of holding it forever.
    let started = Instant::now();
    let mut idle = tokio::net::TcpStream::connect(probe_addr)
        .await
        .expect("idle connection");
    let n = tokio::time::timeout(Duration::from_secs(5), idle.read(&mut buf))
        .await
        .expect("an idle probe connection must be closed at the header deadline, not held")
        .expect("read close");
    assert_eq!(n, 0, "the close arrives as EOF, not data");
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "closed before the deadline could plausibly have fired: {:?}",
        started.elapsed()
    );

    // And the probes still answer normally afterwards.
    let resp = h
        .client()
        .get(format!("http://{probe_addr}/healthz"))
        .send()
        .await
        .expect("liveness");
    assert_eq!(resp.status(), 200);

    h.stop().await;
}
