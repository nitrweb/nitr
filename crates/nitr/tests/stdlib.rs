// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for the phase-14 standard library completion:
//! `nitr.time`, `nitr.validate`, `nitr.base64`, `nitr.path`, `nitr.url`,
//! CSRF middleware, signed-cookie sessions, and the `nitr.crypto`
//! AEAD/JWT additions.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::TestServer;

/// The cookie pair (`name=value`) from a `Set-Cookie` header, ready to
/// send back in a `Cookie` request header.
fn cookie_pair(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("set-cookie")
        .expect("a Set-Cookie header")
        .to_str()
        .expect("cookie header")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string()
}

/// `nitr.time`, `nitr.base64`, `nitr.path` and `nitr.url` — the pure
/// utilities, exercised through a live handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pure_utilities_work_end_to_end() {
    let mut server = TestServer::builder("std14-utils")
        .handler(
            r#"
local app = nitr.app()

app:get("/utils", function(req)
    local ts = 784887151
    local parsed = nitr.url.parse("https://api.example.com:8443/v1?x=1")
    local decoded = nitr.base64.decode(nitr.base64.encode("round trip"))
    return nitr.json({
        formatted = nitr.time.format(ts, "%Y-%m-%d %H:%M:%S"),
        iso = nitr.time.iso8601(ts),
        http_date = nitr.time.http(ts),
        reparsed = nitr.time.parse_http(nitr.time.http(ts)),
        now_plausible = nitr.time.now() > 1700000000,
        monotonic_moves = nitr.time.monotonic() >= 0,
        b64 = decoded,
        joined = nitr.path.join("/srv", "app", "logo.png"),
        ext = nitr.path.extension("C:\\files\\report.pdf"),
        normalized = nitr.path.normalize("/a/b/../c"),
        host = parsed.host,
        port = parsed.port,
        query = nitr.url.query_build({ b = "x y", a = 1 }),
    })
end)

return app
"#,
        )
        .builtins(
            nitr::Builtins::JSON
                | nitr::Builtins::TIME
                | nitr::Builtins::BASE64
                | nitr::Builtins::PATH
                | nitr::Builtins::URL,
        )
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;

    let body = server.json("/utils").await;
    assert_eq!(body["formatted"], "1994-11-15 08:12:31");
    assert_eq!(body["iso"], "1994-11-15T08:12:31Z");
    assert_eq!(body["http_date"], "Tue, 15 Nov 1994 08:12:31 GMT");
    assert_eq!(body["reparsed"], 784887151);
    assert_eq!(body["now_plausible"], true);
    assert_eq!(body["monotonic_moves"], true);
    assert_eq!(body["b64"], "round trip");
    assert_eq!(body["joined"], "/srv/app/logo.png");
    assert_eq!(body["ext"], "pdf");
    assert_eq!(body["normalized"], "/a/c");
    assert_eq!(body["host"], "api.example.com");
    assert_eq!(body["port"], 8443);
    assert_eq!(body["query"], "a=1&b=x%20y");

    server.stop().await;
}

/// `nitr.validate`: a compiled schema accepts good input, reports each bad
/// field, and strips undeclared fields.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_guards_a_json_endpoint() {
    let mut server = TestServer::builder("std14-validate")
        .handler(
            r#"
local app = nitr.app()

local schema = nitr.validate.schema({
    email = { type = "string", format = "email", required = true },
    age = { type = "integer", min = 0, max = 150 },
    tags = { type = "array", items = { type = "string" }, max_items = 2 },
})

app:post("/users", function(req)
    local data, err = schema:check(req:json())
    if not data then
        return nitr.error(422, { code = "VALIDATION_FAILED", fields = err.fields })
    end
    return nitr.json({ ok = true, email = data.email, role = data.role })
end)

return app
"#,
        )
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP | nitr::Builtins::VALIDATE)
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;

    let resp = server
        .client()
        .post(server.url("/users"))
        .header("content-type", "application/json")
        .body(r#"{"email":"ada@example.com","age":36,"role":"admin"}"#)
        .send()
        .await
        .expect("valid");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["ok"], true);
    assert_eq!(body["email"], "ada@example.com");
    // Undeclared input never reaches the handler's validated data.
    assert!(body["role"].is_null());

    let resp = server
        .client()
        .post(server.url("/users"))
        .header("content-type", "application/json")
        .body(r#"{"age":-1,"tags":["a","b","c"]}"#)
        .send()
        .await
        .expect("invalid");
    assert_eq!(resp.status(), 422);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["code"], "VALIDATION_FAILED");
    assert_eq!(body["fields"]["email"], "is required");
    assert_eq!(body["fields"]["age"], "must be >= 0");
    assert_eq!(body["fields"]["tags"], "must have at most 2 items");

    server.stop().await;
}

/// The CSRF middleware: safe methods pass and get a token cookie, unsafe
/// methods need the token back (header or form field), and the comparison
/// rejects a missing or wrong token with 403.
/// A partial `cookie_opts` **extends** the CSRF defaults; it used to
/// replace them, so `cookie_opts = { path = "/admin" }` shipped the token
/// cookie with no `HttpOnly` and no `SameSite`, silently — on the more
/// security-sensitive of the two cookie modules, while sessions merged
/// correctly for the same job.
///
/// Asserted per attribute rather than against the whole header: the
/// `cookie` crate's emission order is not this phase's contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_cookie_options_extend_the_defaults_instead_of_replacing_them() {
    let mut server = TestServer::builder("std14-csrf-opts")
        .handler(
            r#"
local app = nitr.app()

-- Partial on purpose: only `path`. Everything else must survive.
app:use(nitr.csrf({
    secret = "csrf-secret-0123456789",
    cookie_opts = { path = "/admin" },
}))

app:get("/form", function(req)
    return nitr.json({ token = nitr.csrf.token(req) })
end)

return app
"#,
        )
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;

    let resp = server.get("/form").await;
    assert_eq!(resp.status(), 200);
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .expect("a token cookie")
        .to_str()
        .expect("ascii")
        .to_string();

    assert!(
        set_cookie.contains("Path=/admin"),
        "the caller's own option must be applied: {set_cookie}"
    );
    for kept in ["HttpOnly", "SameSite=Lax"] {
        assert!(
            set_cookie.contains(kept),
            "a partial cookie_opts must keep `{kept}`: {set_cookie}"
        );
    }

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_middleware_protects_unsafe_methods() {
    let mut server = TestServer::builder("std14-csrf")
        .handler(
            r#"
local app = nitr.app()

app:use(nitr.csrf({ secret = "csrf-secret-0123456789" }))

app:get("/form", function(req)
    return nitr.json({ token = nitr.csrf.token(req) })
end)

app:post("/submit", function(req)
    return nitr.json({ ok = true, field = req:form().name })
end)

return app
"#,
        )
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;

    // A safe request passes, yields the token and its signed cookie.
    let resp = server.get("/form").await;
    assert_eq!(resp.status(), 200);
    let cookie = cookie_pair(&resp);
    let body: serde_json::Value = resp.json().await.expect("json");
    let token = body["token"].as_str().expect("token").to_string();

    // No token: refused, and a token cookie is still issued for retry.
    let resp = server
        .client()
        .post(server.url("/submit"))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 403);
    assert!(resp.headers().get("set-cookie").is_some());

    // Cookie without the echoed token: refused.
    let resp = server
        .client()
        .post(server.url("/submit"))
        .header("cookie", cookie.clone())
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 403);

    // Cookie plus the token in the header: accepted.
    let resp = server
        .client()
        .post(server.url("/submit"))
        .header("cookie", cookie.clone())
        .header("x-csrf-token", token.clone())
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 200);

    // The `_csrf` form field works too, and the handler can still read
    // the form afterwards (the parse is cached, the body is not re-read).
    let resp = server
        .client()
        .post(server.url("/submit"))
        .header("cookie", cookie.clone())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("name=ada&_csrf={token}"))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["field"], "ada");

    // A forged token of the right shape: refused.
    let resp = server
        .client()
        .post(server.url("/submit"))
        .header("cookie", cookie)
        .header("x-csrf-token", "A".repeat(token.len()))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 403);

    server.stop().await;
}

/// Sessions: the whole session lives in a signed cookie — set on save,
/// read back on the next request, deleted when cleared, and rejected when
/// tampered with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_round_trip_through_the_signed_cookie() {
    let mut server = TestServer::builder("std14-session")
        .handler(
            r#"
local app = nitr.app()
local OPTS = { secret = "session-secret-0123456789" }

app:post("/login", function(req)
    local session = nitr.session(req, OPTS)
    session.user_id = 42
    session.name = "ada"
    local resp = nitr.json({ ok = true })
    session:save(resp)
    return resp
end)

app:get("/me", function(req)
    local session = nitr.session(req, OPTS)
    return nitr.json({ user_id = session.user_id, name = session.name })
end)

app:post("/logout", function(req)
    local session = nitr.session(req, OPTS)
    session:clear()
    local resp = nitr.json({ ok = true })
    session:save(resp)
    return resp
end)

return app
"#,
        )
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;

    let resp = server
        .client()
        .post(server.url("/login"))
        .send()
        .await
        .expect("login");
    assert_eq!(resp.status(), 200);
    let set_cookie = resp.headers()["set-cookie"]
        .to_str()
        .expect("cookie")
        .to_string();
    assert!(set_cookie.contains("HttpOnly"), "got: {set_cookie}");
    let cookie = cookie_pair(&resp);

    let resp = server
        .client()
        .get(server.url("/me"))
        .header("cookie", cookie.clone())
        .send()
        .await
        .expect("me");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["user_id"], 42);
    assert_eq!(body["name"], "ada");

    // Without the cookie there is no session.
    let body = server.json("/me").await;
    assert!(body["user_id"].is_null());

    // A tampered cookie verifies to nothing.
    let resp = server
        .client()
        .get(server.url("/me"))
        .header("cookie", format!("{cookie}x"))
        .send()
        .await
        .expect("me");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["user_id"].is_null());

    // Logout writes an expiring, empty cookie.
    let resp = server
        .client()
        .post(server.url("/logout"))
        .header("cookie", cookie)
        .send()
        .await
        .expect("logout");
    let set_cookie = resp.headers()["set-cookie"].to_str().expect("cookie");
    assert!(set_cookie.contains("Max-Age=0"), "got: {set_cookie}");

    server.stop().await;
}

/// `nitr.crypto.seal`/`open` and `nitr.crypto.jwt` through a live handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aead_and_jwt_work_from_lua() {
    let mut server = TestServer::builder("std14-crypto")
        .handler(
            r#"
local app = nitr.app()
local KEY = string.rep("k", 32)

app:get("/aead", function(req)
    local sealed = nitr.crypto.seal(KEY, "the plan", "user:42")
    return nitr.json({
        opened = nitr.crypto.open(KEY, sealed, "user:42"),
        wrong_aad = nitr.crypto.open(KEY, sealed, "user:7") == nil,
        tampered = nitr.crypto.open(KEY, "AAAA" .. sealed, "user:42") == nil,
    })
end)

app:get("/jwt", function(req)
    local token = nitr.crypto.jwt.sign({ sub = "42", exp = 4000000000 }, "jwt-secret")
    local claims = nitr.crypto.jwt.verify(token, "jwt-secret", { algorithms = { "HS256" } })
    local _, why = nitr.crypto.jwt.verify(token, "other-secret", { algorithms = { "HS256" } })
    return nitr.json({ sub = claims.sub, forged = why })
end)

return app
"#,
        )
        .builtins(nitr::Builtins::JSON | nitr::Builtins::CRYPTO)
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;

    let body = server.json("/aead").await;
    assert_eq!(body["opened"], "the plan");
    assert_eq!(body["wrong_aad"], true);
    assert_eq!(body["tampered"], true);

    let body = server.json("/jwt").await;
    assert_eq!(body["sub"], "42");
    assert_eq!(body["forged"], "invalid signature");

    server.stop().await;
}
