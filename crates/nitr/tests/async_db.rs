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

    // Metadata-endpoint style link-local addresses are refused too — and
    // the refusal must be the *policy* speaking, not a connect timeout to
    // an unroutable address (which would pass even with the SSRF filter
    // removed). Asserting the policy message pins that distinction.
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
    assert!(
        body["err"]
            .as_str()
            .expect("err string")
            .contains("private or local"),
        "the metadata address must be refused by the SSRF policy, not a \
         network error: {body}"
    );

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

/// The documented contract that had no negative test: `check_url` runs on
/// every redirect hop, so a redirect **cannot cross the trust boundary**.
/// The only prior redirect test followed a hop to an *allowed* target and
/// asserted 200 — it would pass with the per-hop re-validation removed.
///
/// Loopback forces the shape of the test: to fetch its own address at all
/// the server must allow private networks, so the boundary under test is
/// `allowed_hosts`, re-checked on the hop. The initial request goes to the
/// one listed host and succeeds; the redirect it follows points off the
/// list and must be refused mid-chain, not connected to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_redirects_are_revalidated_against_the_policy_per_hop() {
    let mut builder = TestServer::builder("p6-redirect-policy")
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP | nitr::Builtins::FETCH)
        .config(|cfg| {
            // Several workers: the handler fetches the server's own routes,
            // so the request holding a state needs *another* free state to
            // answer the self-call — one worker would shed it as a 503.
            cfg.workers = 3;
            cfg.fetch.allow_private_networks = true;
            // Only the server's own loopback host is reachable.
            cfg.fetch.allowed_hosts = Some(vec!["127.0.0.1".into()]);
        });
    let addr = builder.reserve();

    let app = format!(
        r#"
local BASE = "http://{addr}"
local app = nitr.app()

-- Redirects that leave the allowed host: an unlisted public name and the
-- cloud-metadata address (unlisted here, so caught as an unlisted host on
-- the hop rather than needing a resolution).
app:get("/to-unlisted", function(req)
    return nitr.redirect("http://unlisted.example.com/secret")
end)
app:get("/to-metadata", function(req)
    return nitr.redirect("http://169.254.169.254/latest/meta-data/")
end)

-- A same-host redirect stays inside the boundary and is followed.
app:get("/to-self", function(req) return nitr.redirect("/landed") end)
app:get("/landed", function(req) return nitr.text("landed") end)

app:get("/follow", function(req)
    local ok, res = pcall(function()
        return nitr.fetch("GET", BASE .. req.query.path):send()
    end)
    return nitr.json({{
        ok = ok,
        err = ok and "" or tostring(res),
        status = ok and res.status or 0,
    }})
end)

-- Follows the redirect and reports what it landed on, for the positive case.
app:get("/follow-ok", function(req)
    local resp = nitr.fetch("GET", BASE .. "/to-self"):send()
    return nitr.json({{ status = resp.status, body = resp:text() }})
end)

return app
"#
    );
    let mut server = builder.handler(app).spawn().await;
    let client = server.client().clone();

    // A redirect off the allowed host is refused on the hop, naming the
    // policy — proof the block is the re-check, not a failed connection to
    // unlisted.example.com (which would surface a DNS/connect error).
    for path in ["/to-unlisted", "/to-metadata"] {
        let body: serde_json::Value = client
            .get(server.url("/follow"))
            .query(&[("path", path)])
            .send()
            .await
            .expect("follow redirect")
            .json()
            .await
            .expect("body");
        assert_eq!(body["ok"], false, "{path} must be refused: {body}");
        assert!(
            body["err"]
                .as_str()
                .expect("err string")
                .contains("allowed_hosts"),
            "{path} must be refused by the per-hop policy check: {body}"
        );
    }

    // The positive control: a redirect that stays on the allowed host is
    // followed to completion, so the negatives above are the boundary
    // firing, not redirects being broken outright.
    let body: serde_json::Value = client
        .get(server.url("/follow-ok"))
        .send()
        .await
        .expect("follow same-host redirect")
        .json()
        .await
        .expect("body");
    assert_eq!(body["status"], 200);
    assert_eq!(body["body"], "landed");

    server.stop().await;
}

/// A failing statement must not carry its own text — or its bind values —
/// into the error a handler receives, because that error is logged by the
/// server *and* reachable from Lua through `nitr.errinfo`, which a handler
/// can forward anywhere. The `db_query` span has excluded SQL text since it
/// was written; the error path did not, ten lines below the comment saying
/// why it must.
///
/// Reverting `db/mod.rs`'s message to the interpolated
/// `format!("SQL statement `{sql}` failed: …")` must make this fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn database_errors_carry_no_statement_text() {
    let mut server = TestServer::builder("p6-sql-redaction")
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP | nitr::Builtins::DATABASE)
        .config(|cfg| cfg.workers = 1)
        .database("t.db")
        .seed_sql("CREATE TABLE t (v TEXT)")
        .handler(
            r#"
local app = nitr.app()

-- Every statement below embeds a distinctive literal and names a table
-- that does not exist, so each one fails inside rusqlite with the secret
-- in scope.
app:get("/leak", function(req)
    local out = {}
    local function attempt(name, fn)
        local ok, err = pcall(fn)
        out[name] = tostring(err)
    end
    attempt("execute", function()
        return nitr.db:execute("insert into missing (t) values ('tok_live_SEEKRET')")
    end)
    attempt("query", function()
        return nitr.db:query("select 'tok_live_SEEKRET' from missing")
    end)
    attempt("query_row", function()
        return nitr.db:query_row("select 'tok_live_SEEKRET' from missing")
    end)
    attempt("query_one", function()
        return nitr.db:query_one("select 'tok_live_SEEKRET' from missing")
    end)
    attempt("params", function()
        return nitr.db:execute("insert into missing (t) values (?1)", { "tok_live_SEEKRET" })
    end)
    -- Prepare-time failures are the sharp case: rusqlite's own
    -- SqlInputError renders as "{msg} in {sql} at offset {n}", so an
    -- error *type* — not our format string — puts the whole statement
    -- back. "no such table" carries no offset and never sees this, which
    -- is exactly why it cannot be the only case tested.
    attempt("syntax", function()
        return nitr.db:query("select 'tok_live_SEEKRET' frm t")
    end)
    -- A prepare-time failure whose secret sits in a quoted literal: the
    -- shape the redaction owns. (An *unquoted* secret would come back
    -- inside SQLite's own "no such column: …" text, which redaction
    -- cannot remove without discarding the diagnostic entirely — and a
    -- value reaching SQL unquoted is a SQL-injection bug in the handler,
    -- not this one. See `redact` in nitr-std/src/db/mod.rs.)
    attempt("unknown_column", function()
        return nitr.db:query("select nope from t where v = 'tok_live_SEEKRET'")
    end)
    attempt("tx", function()
        return nitr.db:transaction(function(tx)
            return tx:execute("insert into missing (t) values ('tok_live_SEEKRET')")
        end)
    end)
    -- Two failures of the *same* statement must carry the same tag, which
    -- is what makes the correlator useful at all.
    attempt("repeat1", function()
        return nitr.db:execute("insert into missing (t) values ('tok_live_SEEKRET')")
    end)
    attempt("repeat2", function()
        return nitr.db:execute("insert into missing (t) values ('tok_live_SEEKRET')")
    end)
    return nitr.json(out)
end)

return app
"#,
        )
        .spawn()
        .await;

    let body: serde_json::Value = server.json("/leak").await;

    for channel in [
        "execute",
        "query",
        "query_row",
        "query_one",
        "params",
        "tx",
        "syntax",
        "unknown_column",
    ] {
        let message = body[channel].as_str().unwrap_or_default();
        assert!(
            !message.is_empty() && message != "nil",
            "`{channel}` was expected to fail, got: {message:?}"
        );
        // What must never appear: the literal a statement embedded, the
        // bind value, and the statement text itself.
        for leaked in ["tok_live_seekret", "insert into", "select '", "values ("] {
            assert!(
                !message.to_ascii_lowercase().contains(leaked),
                "`{channel}` leaked `{leaked}`: {message}"
            );
        }
        // What deliberately *does* appear: rusqlite's own reason, which
        // names the schema object it could not find ("no such table:
        // missing"). That is the diagnostic — without it the message is
        // "execute failed (stmt 50f29299)" and nobody can act on it — and
        // a schema name is not a secret the way an embedded literal is.
        // The phase's design sketch keeps it for exactly this reason; its
        // attack-replay wording, which also listed the table name, is the
        // looser of the two and is not what this pins.
        // …but the rusqlite reason survives, or the message is useless.
        assert!(
            message.contains("stmt "),
            "`{channel}` must carry a correlator: {message}"
        );
    }

    // The same statement, twice, gets the same tag.
    let tag = |key: &str| {
        let msg = body[key].as_str().unwrap_or_default().to_string();
        let at = msg.find("stmt ").expect("a tag");
        msg[at + 5..at + 13].to_string()
    };
    assert_eq!(
        tag("repeat1"),
        tag("repeat2"),
        "the correlator must group repeated failures of one statement"
    );

    server.stop().await;
}
