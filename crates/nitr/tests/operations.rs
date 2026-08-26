// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for phase 15: health/readiness endpoints answered in
//! Rust, on the main listener or a separate bind.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::{TestServer, reserve_addr};

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
    // Reserving a port and releasing it for the server to rebind is a
    // race: another test (or process) can take it in between. Retry with
    // a fresh port instead of hoping — resilience beats a lucky draw.
    let mut attempt = 0;
    let (mut h, probe_addr) = loop {
        attempt += 1;
        let probe_addr = {
            let (listener, addr) = reserve_addr();
            drop(listener);
            addr
        };
        let h = start(|cfg| cfg.health.bind = Some(probe_addr)).await;
        // The probe listener comes up with the server; if something stole
        // the port, the serve task has already failed — start over.
        let mut listening = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(probe_addr).await.is_ok() {
                listening = true;
                break;
            }
            if h.serve_finished() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        if listening {
            break (h, probe_addr);
        }
        // A failed spawn cannot shut down cleanly; dropping aborts it.
        drop(h);
        assert!(
            attempt < 5,
            "no probe port could be bound in {attempt} attempts"
        );
    };
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
