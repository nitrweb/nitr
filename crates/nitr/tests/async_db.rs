// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for phase 6: `nitr.await_all` concurrency, `nitr.fetch` options,
//! SSRF policy (default-deny, allow-list), policy-checked redirects, and
//! SQLite transactions (commit, rollback, savepoint nesting).

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::TestServer;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn await_all_fetch_options_redirects_and_transactions() {
    let mut builder = TestServer::builder("p6-aggregate")
        .builtins(
            nitr::Builtins::JSON
                | nitr::Builtins::HTTP
                | nitr::Builtins::FETCH
                | nitr::Builtins::DATABASE,
        )
        .config(|cfg| {
            cfg.workers = 3;
            // Local aggregation: this test talks to itself over loopback.
            cfg.fetch.allow_private_networks = true;
        })
        .database("t.db");
    let addr = builder.reserve();

    let app = format!(
        r#"
local BASE = "http://{addr}"
local app = nitr.app()

app:get("/api/a", function(req) return nitr.json({{ name = "a" }}) end)
app:get("/api/b", function(req) return nitr.json({{ name = "b" }}) end)

-- Concurrent aggregation of two local endpoints.
app:get("/combined", function(req)
    local ra, rb = nitr.await_all(
        nitr.fetch("GET", BASE .. "/api/a"),
        nitr.fetch("GET", BASE .. "/api/b")
    )
    return nitr.json({{ first = ra:json().name, second = rb:json().name }})
end)

-- Echo endpoint + a fetch using the options table.
app:post("/echo", function(req)
    return nitr.json({{
        x = req.query.x,
        ct = req.headers["content-type"],
        body = req:json(),
    }})
end)

app:get("/opts", function(req)
    local resp = nitr.fetch("POST", BASE .. "/echo", {{
        query = {{ x = "42" }},
        json = {{ n = 7 }},
        timeout = 5,
    }}):send()
    return nitr.json(resp:json())
end)

-- Redirects are followed by the client (up to 5 hops), re-checked per hop.
app:get("/redir", function(req) return nitr.redirect("/target") end)
app:get("/target", function(req) return nitr.text("landed") end)
app:get("/follow", function(req)
    local resp = nitr.fetch("GET", BASE .. "/redir"):send()
    return nitr.json({{ status = resp.status, body = resp:text() }})
end)

-- Transactions: commit, rollback on error, savepoint nesting.
app:get("/tx", function(req)
    nitr.db:execute("DELETE FROM t")

    nitr.db:transaction(function(tx)
        tx:execute("INSERT INTO t (v) VALUES (?)", {{ "committed" }})
    end)

    local ok = pcall(function()
        nitr.db:transaction(function(tx)
            tx:execute("INSERT INTO t (v) VALUES (?)", {{ "rolled-back" }})
            error("boom")
        end)
    end)

    nitr.db:transaction(function(tx)
        tx:execute("INSERT INTO t (v) VALUES (?)", {{ "outer" }})
        pcall(function()
            tx:transaction(function(tx2)
                tx2:execute("INSERT INTO t (v) VALUES (?)", {{ "inner" }})
                error("inner boom")
            end)
        end)
    end)

    local rows = nitr.db:query("SELECT v FROM t ORDER BY v")
    local values = {{}}
    for i, row in ipairs(rows) do values[i] = row.v end
    return nitr.json({{ failed_tx_ok = ok, values = values }})
end)

return app
"#
    );
    let mut server = builder
        .handler(app)
        .config_script(
            r#"
        local db = ...
        db:execute("CREATE TABLE IF NOT EXISTS t (v TEXT)")
        return {}
        "#,
        )
        .spawn()
        .await;

    let base = server.url("");
    let client = server.client().clone();

    // nitr.await_all preserves argument order.
    let body: serde_json::Value = client
        .get(format!("{base}/combined"))
        .send()
        .await
        .expect("combined")
        .json()
        .await
        .expect("combined body");
    assert_eq!(body["first"], "a");
    assert_eq!(body["second"], "b");

    // Options table: query params, JSON body + content type, timeout.
    let body: serde_json::Value = client
        .get(format!("{base}/opts"))
        .send()
        .await
        .expect("opts")
        .json()
        .await
        .expect("opts body");
    assert_eq!(body["x"], "42");
    assert_eq!(body["ct"], "application/json");
    assert_eq!(body["body"]["n"], 7);

    // Manual redirect following.
    let body: serde_json::Value = client
        .get(format!("{base}/follow"))
        .send()
        .await
        .expect("follow")
        .json()
        .await
        .expect("follow body");
    assert_eq!(body["status"], 200);
    assert_eq!(body["body"], "landed");

    // Transactions: committed + outer survive; rolled-back + inner don't.
    let body: serde_json::Value = client
        .get(format!("{base}/tx"))
        .send()
        .await
        .expect("tx")
        .json()
        .await
        .expect("tx body");
    assert_eq!(body["failed_tx_ok"], false);
    assert_eq!(
        body["values"],
        serde_json::json!(["committed", "outer"]),
        "got: {body}"
    );

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_policy_blocks_private_and_unlisted_hosts() {
    const APP: &str = r#"
local app = nitr.app()

app:get("/try", function(req)
    local ok, err = pcall(function()
        return nitr.fetch("GET", req.query.url):send()
    end)
    return nitr.json({ ok = ok, err = ok and "" or tostring(err) })
end)

return app
"#;

    // Default policy: private/loopback addresses are refused.
    let mut server = TestServer::builder("p6-deny")
        .handler(APP)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP | nitr::Builtins::FETCH)
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;
    let client = server.client().clone();

    let body: serde_json::Value = client
        .get(server.url("/try"))
        .query(&[("url", "http://127.0.0.1:9/internal")])
        .send()
        .await
        .expect("try loopback")
        .json()
        .await
        .expect("body");
    assert_eq!(body["ok"], false);
    assert!(
        body["err"]
            .as_str()
            .expect("err string")
            .contains("private or local"),
        "got: {body}"
    );

    // Metadata-endpoint style link-local addresses are refused too.
    let body: serde_json::Value = client
        .get(server.url("/try"))
        .query(&[("url", "http://169.254.169.254/latest/meta-data/")])
        .send()
        .await
        .expect("try metadata")
        .json()
        .await
        .expect("body");
    assert_eq!(body["ok"], false);

    server.stop().await;

    // Allow-list: hosts outside fetch.allowed_hosts are refused even with
    // private networks allowed.
    let mut server = TestServer::builder("p6-allowlist")
        .handler(APP)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP | nitr::Builtins::FETCH)
        .config(|cfg| {
            cfg.workers = 1;
            cfg.fetch.allowed_hosts = Some(vec!["api.example.com".into()]);
            cfg.fetch.allow_private_networks = true;
        })
        .spawn()
        .await;

    let target = server.url("/whatever");
    let body: serde_json::Value = client
        .get(server.url("/try"))
        .query(&[("url", target)])
        .send()
        .await
        .expect("try unlisted")
        .json()
        .await
        .expect("body");
    assert_eq!(body["ok"], false);
    assert!(
        body["err"]
            .as_str()
            .expect("err string")
            .contains("allowed_hosts"),
        "got: {body}"
    );

    server.stop().await;
}
