// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for the phase-7 platform features: static file
//! serving (conditional requests, traversal protection, SPA fallback,
//! `app:static` and `[static]` config), and the in-process test client.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::{TestDir, TestServer};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_files_and_spa_end_to_end() {
    let builder = TestServer::builder("platform-static")
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| cfg.workers = 1);

    // Site layout inside the test's own directory: index.html +
    // assets/app.js, plus an SPA mount.
    builder.dir().write("site/index.html", "<h1>home</h1>");
    builder
        .dir()
        .write("site/assets/app.js", "console.log('hi')");
    builder.dir().write("spa/index.html", "<div id=app></div>");
    let site = builder.dir().join("site");
    let spa = builder.dir().join("spa");

    // `{:?}` renders the path as a quoted, escaped literal: Windows paths
    // contain backslashes, which a bare `display()` inside a double-quoted
    // Lua string would turn into invalid escape sequences (`"C:\Users"`).
    // Rust's debug escaping doubles them, which is exactly Lua's syntax too.
    let app = format!(
        r#"
local app = nitr.app()
app:static("/", {site:?})
app:static("/spa", {spa:?}, {{ spa = true }})
app:get("/api/ping", function(req) return nitr.json({{ pong = true }}) end)
return app
"#,
        site = site.to_string_lossy(),
        spa = spa.to_string_lossy(),
    );

    let mut server = builder.handler(app).spawn().await;

    // Directory index + content type.
    let resp = server.get("/").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "text/html");
    let etag = resp.headers()["etag"].to_str().expect("etag").to_string();
    assert!(resp.headers().contains_key("last-modified"));
    assert_eq!(resp.text().await.expect("body"), "<h1>home</h1>");

    // Conditional revalidation with the returned ETag.
    let resp = server
        .client()
        .get(server.url("/"))
        .header("if-none-match", &etag)
        .send()
        .await
        .expect("conditional");
    assert_eq!(resp.status(), 304);
    assert!(resp.text().await.expect("empty body").is_empty());

    // Nested asset with a JS content type.
    let resp = server.get("/assets/app.js").await;
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .expect("ct")
            .contains("javascript")
    );

    // Traversal attempts never leave the mount.
    for path in [
        "/../Cargo.toml",
        "/%2e%2e/Cargo.toml",
        "/assets/../../etc/passwd",
    ] {
        let resp = server.get(path).await;
        assert_eq!(resp.status(), 404, "{path} must be rejected");
    }

    // Lua routes still win over the root static mount.
    let resp = server.get("/api/ping").await;
    assert_eq!(resp.headers()["content-type"], "application/json");

    // SPA fallback serves the index for unknown paths under its mount.
    let resp = server.get("/spa/some/client/route").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("spa body"), "<div id=app></div>");

    // Unknown path outside any mount is still a 404.
    let resp = server.get("/missing.txt").await;
    assert_eq!(resp.status(), 404);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_client_dispatches_in_process() {
    // The in-process TestClient is the subject here, so the server is
    // built by hand — but its script still lives in a private TestDir.
    let dir = TestDir::new("platform-testclient");
    let handler = dir.write(
        "app.lua",
        r#"
        local app = nitr.app()
        app:get("/hello/:name", function(req)
            return nitr.json({ hello = req.params.name, ua = req.headers["user-agent"] })
        end)
        app:post("/echo", function(req)
            return nitr.text(req:text(), 201)
        end)
        return app
        "#,
    );

    // No listen address is ever bound: the client dispatches in-process.
    let server = nitr::Server::builder()
        .handler_script(&handler)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .workers(1)
        .build()
        .await
        .expect("build server");
    let client = server.test_client();

    let resp = client
        .request(
            "get",
            "/hello/nitr",
            &[("user-agent".into(), "nitr-test".into())],
            None,
        )
        .await
        .expect("request");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("content-type"), Some("application/json"));
    assert!(resp.header("x-request-id").is_some());
    let body: serde_json::Value = serde_json::from_slice(&resp.body).expect("json");
    assert_eq!(body["hello"], "nitr");
    assert_eq!(body["ua"], "nitr-test");

    let resp = client
        .request("POST", "/echo", &[], Some("payload".into()))
        .await
        .expect("post");
    assert_eq!(resp.status, 201);
    assert_eq!(&resp.body[..], b"payload");

    // Router misses stay router misses in-process.
    let resp = client
        .request("GET", "/nope", &[], None)
        .await
        .expect("404");
    assert_eq!(resp.status, 404);
}
