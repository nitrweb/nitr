// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Route groups (`app:group`) and per-route rate limits.

#![allow(dead_code)]

mod harness;

use harness::TestServer;

const APP: &str = r#"
local app = nitr.app()

local function tag(name)
    return function(next)
        return function(req)
            local resp = next(req)
            resp.headers["x-trail"] = (resp.headers["x-trail"] or "") .. name .. ","
            return resp
        end
    end
end

local function require_auth(next)
    return function(req)
        if req.headers["x-auth"] ~= "yes" then
            return nitr.json({ code = "UNAUTHORIZED" }, 401)
        end
        return next(req)
    end
end

app:use(tag("app"))

app:get("/", function() return nitr.text("root") end)

app:group("/api", function(g)
    g:use(require_auth)
    g:use(tag("api"))
    g:get("/", function() return nitr.text("api root") end)
    g:get("/items", tag("route"), function(req) return nitr.json({ items = nitr.json.array({}) }) end)
    g:group("/v2", function(v)
        v:use(tag("v2"))
        v:get("/items/:id", function(req) return nitr.json({ id = req.params.id }) end)
    end)
end)

local admin = app:group("/admin")
admin:get("/stats", function() return nitr.text("stats") end)

app:get("/limited", function() return nitr.text("ok") end, {
    rate_limit = { requests = 2, window = 60 },
})

return app
"#;

/// A group prefixes its routes and runs its middleware after the app's,
/// in registration order, before the route's own; nesting composes.
#[tokio::test(flavor = "multi_thread")]
async fn groups_prefix_paths_and_layer_middleware() {
    let mut server = TestServer::builder("groups").handler(APP).spawn().await;
    let resp = server.get("/api/items").await;
    assert_eq!(resp.status(), 401, "the group's auth guards its routes");
    let resp = server.get("/").await;
    assert_eq!(
        resp.headers()["x-trail"],
        "app,",
        "the root is outside the group"
    );

    let get = |path: &str| {
        server
            .client()
            .get(server.url(path))
            .header("x-auth", "yes")
            .send()
    };
    let resp = get("/api").await.expect("api root");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body"), "api root");
    let resp = get("/api/items").await.expect("items");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["x-trail"], "route,api,app,");
    assert_eq!(resp.text().await.expect("body"), r#"{"items":[]}"#);
    let resp = get("/api/v2/items/7").await.expect("nested");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["x-trail"], "v2,api,app,");
    assert_eq!(resp.text().await.expect("body"), r#"{"id":"7"}"#);
    let resp = server.get("/admin/stats").await;
    assert_eq!(resp.text().await.expect("body"), "stats");
    server.stop().await;
}

/// A group's middleware must precede its routes, like the app's.
#[tokio::test(flavor = "multi_thread")]
async fn a_group_refuses_middleware_after_its_routes() {
    let mut b = TestServer::builder("groups-late-use").handler(
        r#"
local app = nitr.app()
app:group("/api", function(g)
    g:get("/x", function() return nitr.text("x") end)
    g:use(function(next) return next end)
end)
return app
"#,
    );
    let err = b.try_build().await.expect_err("late use").to_string();
    assert!(err.contains("use() must be called before"), "{err}");
}

/// A route's own limit is counted per client and per route: the third
/// call in the window is a 429 with `Retry-After`, while other routes
/// stay open.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_can_carry_its_own_rate_limit() {
    let mut server = TestServer::builder("groups-rate")
        .handler(APP)
        .spawn()
        .await;
    for _ in 0..2 {
        assert_eq!(server.get("/limited").await.status(), 200);
    }
    let resp = server.get("/limited").await;
    assert_eq!(resp.status(), 429);
    let retry: u64 = resp.headers()["retry-after"]
        .to_str()
        .expect("ascii")
        .parse()
        .expect("seconds");
    assert!((1..=60).contains(&retry), "{retry}");
    assert_eq!(
        server.get("/").await.status(),
        200,
        "other routes are not limited"
    );
    server.stop().await;
}
