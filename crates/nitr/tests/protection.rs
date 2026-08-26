// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for phase-5 observability + protection: request ids
//! (generated and trusted), the `nitr.log` builtin, rate limiting, and the
//! URI/body size limits.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::TestServer;

const APP_SCRIPT: &str = r#"
local app = nitr.app()

app:get("/", function(req)
    nitr.log.info("handling request", { path = req.path })
    return nitr.json({ id = req.id })
end)

app:post("/upload", function(req)
    return nitr.text("ok")
end)

return app
"#;

/// The builtin set every test here runs with.
fn builder(label: &str) -> harness::Builder {
    TestServer::builder(label)
        .handler(APP_SCRIPT)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP | nitr::Builtins::LOG)
        .config(|cfg| cfg.workers = 1)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_ids_and_size_limits() {
    let mut server = builder("protect-ids")
        .config(|cfg| {
            cfg.limits.max_uri_bytes = 128;
            cfg.limits.max_body_bytes = 1024;
        })
        .spawn()
        .await;

    // Every response carries a generated X-Request-ID; ids are unique, the
    // handler sees the same id (via req.id), and an inbound id is ignored
    // by default (untrusted).
    let resp = server
        .client()
        .get(server.url("/"))
        .header("x-request-id", "spoofed-id")
        .send()
        .await
        .expect("GET /");
    let id1 = resp.headers()["x-request-id"]
        .to_str()
        .expect("id header")
        .to_string();
    assert_ne!(id1, "spoofed-id");
    let body: serde_json::Value = resp.json().await.expect("body");
    assert_eq!(body["id"], id1.as_str());

    let resp = server.get("/").await;
    let id2 = resp.headers()["x-request-id"].to_str().expect("id header");
    assert_ne!(id1, id2);

    // Protection responses carry an id too.
    let resp = server.get(&format!("/?q={}", "x".repeat(200))).await;
    assert_eq!(resp.status(), 414);
    assert!(resp.headers().contains_key("x-request-id"));

    // Declared body above the limit → 413, before Lua runs.
    let resp = server
        .client()
        .post(server.url("/upload"))
        .body(vec![0u8; 4096])
        .send()
        .await
        .expect("big upload");
    assert_eq!(resp.status(), 413);

    // At/below the limit passes.
    let resp = server
        .client()
        .post(server.url("/upload"))
        .body(vec![0u8; 512])
        .send()
        .await
        .expect("small upload");
    assert_eq!(resp.status(), 200);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_request_ids_pass_through() {
    let mut server = builder("protect-trusted")
        .config(|cfg| cfg.trust_request_id = true)
        .spawn()
        .await;

    let resp = server
        .client()
        .get(server.url("/"))
        .header("x-request-id", "req-from-proxy-1")
        .send()
        .await
        .expect("GET /");
    assert_eq!(resp.headers()["x-request-id"], "req-from-proxy-1");

    // Malformed inbound ids are replaced, not echoed.
    let resp = server
        .client()
        .get(server.url("/"))
        .header("x-request-id", "bad id with spaces")
        .send()
        .await
        .expect("GET /");
    assert_ne!(resp.headers()["x-request-id"], "bad id with spaces");

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limiting_answers_429_with_retry_after() {
    let mut server = builder("protect-rate")
        .config(|cfg| {
            cfg.rate_limit.enabled = true;
            cfg.rate_limit.requests = 3;
            cfg.rate_limit.window = 60;
        })
        .spawn()
        .await;

    for i in 1..=3 {
        let resp = server.get("/").await;
        assert_eq!(resp.status(), 200, "request {i} should pass");
    }
    let resp = server.get("/").await;
    assert_eq!(resp.status(), 429);
    let retry: u64 = resp.headers()["retry-after"]
        .to_str()
        .expect("retry-after")
        .parse()
        .expect("retry-after seconds");
    assert!((1..=60).contains(&retry));

    server.stop().await;
}
