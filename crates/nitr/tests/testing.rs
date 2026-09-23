// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The in-process testing surface `nitr test` stands on: the handler's
//! failure riding the response as an extension (and never as bytes), the
//! test client's peer address and timeout, the configuration snapshot,
//! the fake request, and the seams being inert outside the runner.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use harness::{TestDir, TestServer};
use nitr::testing::TestRequest;

const FAILING_APP: &str = r#"
local app = nitr.app()
app:get("/ok", function(req) return nitr.text("fine") end)
app:get("/boom", function(req) local x = nil; return x.field end)
app:get("/handled", function(req) error("the cause") end, {
    on_error = function(err, req)
        return nitr.text(string.rep("an explanation long enough to compress ", 40), 503)
    end,
})
app:get("/invalid", function(req) return { status = "not a status" } end)
app:get("/panic", function(req) return nitr.ext.explode.now() end)
return app
"#;

async fn failing_server(dir: &TestDir, tune: impl FnOnce(&mut nitr::Config)) -> nitr::Server {
    let handler = dir.write("app.lua", FAILING_APP);
    let mut cfg = nitr::Config {
        handler_script: handler,
        workers: 1,
        ..Default::default()
    };
    tune(&mut cfg);
    nitr::Server::builder()
        .config(cfg)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .module("explode", |lua| {
            let table = lua.create_table()?;
            table.set(
                "now",
                // A module bug, which the handler's panic boundary contains.
                lua.create_function(|_, ()| -> mlua::Result<()> { panic!("module exploded") })?,
            )?;
            Ok(table)
        })
        .build()
        .await
        .expect("build")
}

/// Every 500 site attaches the classified failure, `handled` says whether
/// `on_error` answered, and a success carries nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_error_path_attaches_its_failure_to_the_response() {
    let dir = TestDir::new("testing-failure-sites");
    let server = failing_server(&dir, |_| {}).await;
    let client = server.test_client();
    let get = |path: &'static str| {
        let client = client.clone();
        async move { client.request("GET", path, &[], None).await.expect(path) }
    };

    let ok = get("/ok").await;
    assert_eq!(ok.status, 200);
    assert!(ok.error.is_none(), "a success carries no failure");

    let boom = get("/boom").await;
    assert_eq!(boom.status, 500);
    let failure = boom.error.expect("raised");
    assert_eq!(failure.info.kind, "lua");
    assert!(
        failure
            .info
            .message
            .contains("attempt to index a nil value")
    );
    assert!(!failure.handled);
    assert_eq!(
        &boom.body[..],
        b"Internal Server Error",
        "no dev mode, no details"
    );

    let handled = get("/handled").await;
    assert_eq!(handled.status, 503);
    let failure = handled.error.expect("handled");
    assert!(failure.handled);
    assert!(failure.info.message.contains("the cause"));

    let invalid = get("/invalid").await;
    assert_eq!(invalid.status, 500);
    assert!(
        invalid.error.is_some(),
        "an invalid response table is a failure too"
    );

    let panicked = get("/panic").await;
    assert_eq!(panicked.status, 500);
    let failure = panicked.error.expect("panic");
    assert_eq!(failure.info.kind, "panic");
    assert!(failure.info.message.contains("module exploded"));
}

/// The extension rides through `HEAD` stripping, which takes the
/// response apart and rebuilds it without its body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_failure_survives_head() {
    let dir = TestDir::new("testing-failure-head");
    let server = failing_server(&dir, |_| {}).await;
    let head = server
        .test_client()
        .request("HEAD", "/boom", &[], None)
        .await
        .expect("head");
    assert_eq!(head.status, 500);
    assert!(head.body.is_empty());
    assert_eq!(head.error.expect("through HEAD").info.kind, "lua");
}

/// And through compression, which rebuilds the response around an
/// encoded body.
#[cfg(feature = "compression")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_failure_survives_compression() {
    let dir = TestDir::new("testing-failure-gzip");
    let server = failing_server(&dir, |cfg| {
        cfg.compression.enabled = true;
        cfg.compression.min_size = 16;
    })
    .await;
    let gzip = [("accept-encoding".to_string(), "gzip".to_string())];
    let compressed = server
        .test_client()
        .request("GET", "/handled", &gzip, None)
        .await
        .expect("gzip");
    assert_eq!(compressed.header("content-encoding"), Some("gzip"));
    assert!(compressed.error.expect("through compression").handled);
}

/// Adversarial row A5: the failure is an extension, never bytes. Over a
/// real socket a failing handler answers exactly the curt production 500
/// — no traceback, no extra header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_client_never_receives_the_failure() {
    let mut server = TestServer::builder("testing-failure-socket")
        .handler(FAILING_APP)
        .module("explode", |lua| lua.create_table())
        .spawn()
        .await;
    let resp = server.get("/boom").await;
    assert_eq!(resp.status(), 500);
    let mut names: Vec<String> = resp.headers().keys().map(|k| k.to_string()).collect();
    names.sort();
    assert_eq!(
        names,
        ["content-length", "content-type", "date", "x-request-id"],
        "the header set of the production 500"
    );
    assert_eq!(
        resp.text().await.expect("body"),
        "Internal Server Error",
        "the body of the production 500"
    );
    server.stop().await;
}

/// `remote_addr` is the peer the protection layer sees: one client's
/// budget does not throttle another's, and the default peer is shared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_test_client_peer_address_reaches_the_rate_limiter() {
    let dir = TestDir::new("testing-peer");
    let server = failing_server(&dir, |cfg| {
        cfg.rate_limit.enabled = true;
        cfg.rate_limit.requests = 1;
        cfg.rate_limit.window = 60;
    })
    .await;
    let client = server.test_client();
    let from = |addr: &str| TestRequest {
        method: "GET".into(),
        path: "/ok".into(),
        remote_addr: Some(addr.parse().expect("addr")),
        ..Default::default()
    };
    assert_eq!(
        client.send(from("10.0.0.1:0")).await.expect("first").status,
        200
    );
    assert_eq!(
        client
            .send(from("10.0.0.1:0"))
            .await
            .expect("second")
            .status,
        429
    );
    assert_eq!(
        client.send(from("10.0.0.2:0")).await.expect("other").status,
        200
    );
}

/// The client-side timeout bounds a stream that never ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_test_client_timeout_bounds_an_endless_stream() {
    let dir = TestDir::new("testing-timeout");
    let handler = dir.write(
        "app.lua",
        r#"
        local app = nitr.app()
        app:get("/forever", function(req)
            return nitr.sse(function(send) while true do send("tick", "x") end end)
        end)
        return app
        "#,
    );
    let server = nitr::Server::builder()
        .handler_script(&handler)
        .builtins(nitr::Builtins::HTTP)
        .workers(2)
        .build()
        .await
        .expect("build");
    let err = server
        .test_client()
        .send(TestRequest {
            method: "GET".into(),
            path: "/forever".into(),
            timeout: Some(std::time::Duration::from_millis(200)),
            ..Default::default()
        })
        .await
        .expect_err("never completes");
    assert!(
        err.to_string().contains("did not complete within 0.2 s"),
        "got: {err}"
    );
}

/// The configuration script's snapshot is the server's `nitr.cfg`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_server_exposes_its_configuration_snapshot() {
    let dir = TestDir::new("testing-cfg");
    let handler = dir.write(
        "app.lua",
        "local app = nitr.app()\napp:get('/', function() return nitr.text('x') end)\nreturn app\n",
    );
    let config = dir.write("config.lua", "return { secret = 'abc', n = 2 }\n");
    let with = nitr::Server::builder()
        .handler_script(&handler)
        .config_script(&config)
        .builtins(nitr::Builtins::HTTP)
        .build()
        .await
        .expect("build");
    assert_eq!(
        with.cfg_snapshot(),
        Some(&serde_json::json!({ "secret": "abc", "n": 2 }))
    );
    let without = nitr::Server::builder()
        .handler_script(&handler)
        .builtins(nitr::Builtins::HTTP)
        .build()
        .await
        .expect("build");
    assert_eq!(without.cfg_snapshot(), None);
}

/// The snapshot is the configuration script's result, taken before the
/// handler loads: a handler that hangs a function (or anything JSON
/// cannot carry) off `nitr.cfg` still boots, and the snapshot does not
/// grow what the handler added.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handler_extending_nitr_cfg_still_boots() {
    let dir = TestDir::new("testing-cfg-mutated");
    let handler = dir.write(
        "app.lua",
        "nitr.cfg.helper = function(x) return x end\nnitr.cfg.extra = 1\nlocal app = nitr.app()\napp:get('/', function() return nitr.text(tostring(nitr.cfg.extra)) end)\nreturn app\n",
    );
    let config = dir.write("config.lua", "return { secret = 'abc' }\n");
    let server = nitr::Server::builder()
        .handler_script(&handler)
        .config_script(&config)
        .builtins(nitr::Builtins::HTTP)
        .workers(2)
        .build()
        .await
        .expect("a handler extending nitr.cfg must not fail the boot");
    assert_eq!(
        server.cfg_snapshot(),
        Some(&serde_json::json!({ "secret": "abc" }))
    );
    let resp = server
        .test_client()
        .request("GET", "/", &[], None)
        .await
        .expect("request");
    assert_eq!(
        &resp.body[..],
        b"1",
        "every state ran the handler's own additions"
    );
}

/// Adversarial row A1: outside the runner nothing carries a double — no
/// `nitr.test` in a handler, no `Doubles` app data in any state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_built_without_the_runner_has_no_test_surface() {
    let saw_doubles = Arc::new(AtomicBool::new(false));
    let probe = saw_doubles.clone();
    let mut server = TestServer::builder("testing-inert")
        .handler(
            r#"
            local app = nitr.app()
            app:get("/", function(req) return nitr.json({ test = nitr.test == nil }) end)
            return app
            "#,
        )
        .setup(move |lua| {
            if lua
                .app_data_ref::<Arc<nitr::stdlib::testing::Doubles>>()
                .is_some()
            {
                probe.store(true, Ordering::Relaxed);
            }
            Ok(())
        })
        .spawn()
        .await;
    assert_eq!(server.json("/").await, serde_json::json!({ "test": true }));
    assert!(!saw_doubles.load(Ordering::Relaxed));
    server.stop().await;
}

/// A fake request reads, field by field, like the request the client
/// dispatches from the same options.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fake_request_reads_like_a_dispatched_one() {
    const ECHO: &str = r#"
        return function(req)
            return {
                method = req.method, path = req.path, page = req.query.page,
                key = req.headers["x-api-key"], sid = req.cookies.sid,
                id = req.params.id, peer = req.remote_addr,
                text = req:json().text, auth = req.headers["authorization"],
            }
        end
    "#;
    const SPEC: &str = r#"{ method = "POST", path = "/items/7", query = { page = 2 },
        headers = { ["X-Api-Key"] = "k" }, cookies = { sid = "s1" },
        auth = { bearer = "t0k" }, json = { text = "hi" }, remote_addr = "10.0.0.7" }"#;

    let dir = TestDir::new("testing-fake");
    let handler = dir.write(
        "app.lua",
        format!(
            "local echo = (function() {ECHO} end)()\nlocal app = nitr.app()\napp:post('/items/:id', function(req) return nitr.json(echo(req)) end)\nreturn app\n"
        ),
    );
    let server = nitr::Server::builder()
        .handler_script(&handler)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .build()
        .await
        .expect("build");

    let lua = mlua::Lua::new();
    let spec: mlua::Table = lua.load(SPEC).eval().expect("spec");
    let request = TestRequest::from_lua("POST", "/items/7", Some(&spec)).expect("request");
    let dispatched = server.test_client().send(request).await.expect("send");
    let dispatched: serde_json::Value =
        serde_json::from_slice(&dispatched.body).expect("json body");

    nitr::stdlib::register_builtins(&lua, nitr::Builtins::JSON, &Default::default())
        .expect("builtins");
    lua.globals()
        .set(
            "fake_request",
            lua.create_function(|lua, spec: mlua::Table| {
                nitr::testing::fake_request(lua, Some(spec))
            })
            .expect("fn"),
        )
        .expect("global");
    let faked: mlua::Table = lua
        .load(format!(
            "local spec = {SPEC}\nspec.params = {{ id = \"7\" }}\nlocal echo = (function() {ECHO} end)()\nreturn echo(fake_request(spec))"
        ))
        .eval()
        .expect("fake");
    use mlua::LuaSerdeExt as _;
    let faked: serde_json::Value = lua.from_value(mlua::Value::Table(faked)).expect("to json");

    assert_eq!(faked["peer"], "10.0.0.7:0");
    assert_eq!(dispatched["peer"], "10.0.0.7:0");
    assert_eq!(
        faked, dispatched,
        "the fake request reads like the real one"
    );
    assert_eq!(faked["auth"], "Bearer t0k");
    assert_eq!(faked["page"], "2");
}
