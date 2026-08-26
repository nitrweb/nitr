// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end test: build a real server with the builder API, serve over a
//! TCP socket, exercise the Lua handler, and shut down gracefully.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::TestServer;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_lua_handlers_end_to_end() {
    let mut server = TestServer::builder("server-e2e")
        .handler(
            r#"
        local app = nitr.app()

        app:get("/binary", function(req)
            return {
                status = 200,
                headers = { ["Set-Cookie"] = { "a=1", "b=2" } },
                body = string.char(0, 255) .. "end",
            }
        end)

        app:get("/boom", function(req)
            error("kaboom")
        end)

        app:get("/hello", function(req)
            return {
                status = 200,
                headers = { ["Content-Type"] = "application/json" },
                body = nitr.json:encode({
                    path = req.path,
                    name = req.query.name,
                    greeting = greet(req.query.name or "world"),
                    from_cfg = nitr.cfg.motto,
                }),
            }
        end)

        return app
        "#,
        )
        .config_script("return { motto = 'fast and safe' }")
        .builtins(nitr::Builtins::JSON)
        .config(|cfg| cfg.workers = 2)
        .setup(|lua| {
            let greet = lua.create_function(|_, name: String| Ok(format!("Hello, {name}!")))?;
            lua.globals().set("greet", greet)
        })
        .spawn()
        .await;

    // JSON route: query parsing, custom setup() global, config snapshot.
    let resp = server.get("/hello?name=Jos%C3%A9").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/json");
    let json: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(json["path"], "/hello");
    assert_eq!(json["name"], "José");
    assert_eq!(json["greeting"], "Hello, José!");
    assert_eq!(json["from_cfg"], "fast and safe");

    // Binary body and multi-value headers survive.
    let resp = server.get("/binary").await;
    let cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().collect();
    assert_eq!(cookies, ["a=1", "b=2"]);
    let body = resp.bytes().await.expect("binary body");
    assert_eq!(&body[..], &[0, 255, b'e', b'n', b'd']);

    // Script errors become a generic 500 without leaking details.
    let resp = server.get("/boom").await;
    assert_eq!(resp.status(), 500);
    let body = resp.text().await.expect("error body");
    assert_eq!(body, "Internal Server Error");

    // Graceful shutdown.
    server.stop().await;
}
