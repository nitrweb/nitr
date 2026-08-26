// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for the `nitr.app()` router/middleware model: Rust-side
//! matching (404/405), path parameters, middleware composition and
//! short-circuiting, the app error handler, and `nitr.cfg`.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::TestServer;

const APP_SCRIPT: &str = r#"
local app = nitr.app()

-- Global middleware: tags every routed response.
app:use(function(next)
    return function(req)
        local res = next(req)
        res.headers = res.headers or {}
        res.headers["X-Global"] = "1"
        return res
    end
end)

local function auth(next)
    return function(req)
        if req.headers["authorization"] ~= "secret" then
            return { status = 401, body = "Unauthorized" }
        end
        return next(req)
    end
end

app:get("/", function(req)
    return { status = 200, body = "home" }
end)

app:get("/users/:id", function(req)
    return { status = 200, body = "user " .. req.params.id }
end)

app:post("/users", function(req)
    return { status = 201, body = "created" }
end)

app:get("/admin", auth, function(req)
    return { status = 200, body = "admin" }
end)

app:get("/files/*", function(req)
    return { status = 200, body = req.params.splat }
end)

app:get("/boom", function(req)
    error("kaboom")
end)

app:get("/cfg", function(req)
    return { status = 200, body = nitr.cfg and nitr.cfg.name or "no cfg" }
end)

app:on_error(function(err, req)
    return {
        status = 500,
        headers = { ["X-Err"] = "handled" },
        body = "handled: " .. req.path,
    }
end)

return app
"#;

const CFG_SCRIPT: &str = r#"
return { name = "from-config" }
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_middleware_and_errors_end_to_end() {
    let mut server = TestServer::builder("router")
        .handler(APP_SCRIPT)
        .config_script(CFG_SCRIPT)
        .builtins(nitr::Builtins::JSON)
        .config(|cfg| cfg.workers = 2)
        .spawn()
        .await;

    // Plain route + global middleware tag.
    let resp = server.get("/").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["x-global"], "1");
    assert_eq!(resp.text().await.expect("body"), "home");

    // Path parameters.
    let resp = server.get("/users/42").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body"), "user 42");

    // Method routing.
    let resp = server
        .client()
        .post(server.url("/users"))
        .send()
        .await
        .expect("POST /users");
    assert_eq!(resp.status(), 201);

    // 405 with an Allow header for a known path with the wrong method.
    let resp = server
        .client()
        .delete(server.url("/users/42"))
        .send()
        .await
        .expect("DELETE /users/42");
    assert_eq!(resp.status(), 405);
    // HEAD and OPTIONS are advertised because Nitr answers them itself,
    // without the route having to be registered.
    assert_eq!(resp.headers()["allow"], "GET, HEAD, OPTIONS");

    // 404 for an unregistered path: Lua is never invoked.
    let resp = server.get("/nope").await;
    assert_eq!(resp.status(), 404);

    // Per-route middleware short-circuits without auth...
    let resp = server.get("/admin").await;
    assert_eq!(resp.status(), 401);
    // ...but the global middleware still wrapped the response.
    assert_eq!(resp.headers()["x-global"], "1");

    // ...and passes through with credentials.
    let resp = server
        .client()
        .get(server.url("/admin"))
        .header("authorization", "secret")
        .send()
        .await
        .expect("GET /admin authorized");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body"), "admin");

    // Trailing catch-all captures the rest of the path.
    let resp = server.get("/files/a/b.txt").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body"), "a/b.txt");

    // A handler error reaches app:on_error with the same request object.
    let resp = server.get("/boom").await;
    assert_eq!(resp.status(), 500);
    assert_eq!(resp.headers()["x-err"], "handled");
    assert_eq!(resp.text().await.expect("body"), "handled: /boom");

    // The config snapshot is reachable as nitr.cfg.
    let resp = server.get("/cfg").await;
    assert_eq!(resp.text().await.expect("body"), "from-config");

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn use_after_a_route_fails_at_startup() {
    let mut builder = TestServer::builder("router-use-after")
        .handler(
            r#"
            local app = nitr.app()
            app:get("/", function(req) return { status = 200 } end)
            app:use(function(next) return next end)
            return app
            "#,
        )
        .builtins(nitr::Builtins::JSON)
        .config(|cfg| cfg.workers = 1);
    let err = builder
        .try_build()
        .await
        .expect_err("app:use after a route must fail the build");
    assert!(
        err.to_string().contains("before registering routes"),
        "got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_routes_fail_at_startup() {
    let mut builder = TestServer::builder("router-duplicate")
        .handler(
            r#"
            local app = nitr.app()
            app:get("/x", function(req) return { status = 200 } end)
            app:get("/x", function(req) return { status = 200 } end)
            return app
            "#,
        )
        .builtins(nitr::Builtins::JSON)
        .config(|cfg| cfg.workers = 1);
    let err = builder
        .try_build()
        .await
        .expect_err("duplicate route must fail the build");
    assert!(err.to_string().contains("duplicate route"), "got: {err}");
}
