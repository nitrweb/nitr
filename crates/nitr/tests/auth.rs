// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! HTTP Basic authentication end to end: the `Authorization` header
//! through `nitr.auth.basic`, the stored argon2id hash through
//! `nitr.crypto.password_verify`, and the equal-cost unknown-user path
//! through `nitr.crypto.password_verify_dummy`.
//!
//! The handler below is the pattern `examples/basic-auth` documents, run
//! against a real server so the wiring is tested rather than described.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use std::time::{Duration, Instant};

use harness::TestServer;

/// Standard base64 with padding, written out rather than pulled in as a
/// dev-dependency: this is the *client* side of the parser under test, so
/// an independent implementation is worth more here than a shared one.
/// Pinned against RFC 4648's vectors below.
fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = u32::from(chunk[0]) << 16
            | u32::from(chunk.get(1).copied().unwrap_or(0)) << 8
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for shift in [18, 12, 6, 0].into_iter().take(chunk.len() + 1) {
            out.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
        }
        for _ in chunk.len()..3 {
            out.push('=');
        }
    }
    out
}

/// `user:pass` as an `Authorization: Basic` header value.
fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", b64(format!("{user}:{pass}").as_bytes()))
}

#[test]
fn the_test_encoder_agrees_with_rfc_4648() {
    for (input, expected) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
        ("ada:lovelace", "YWRhOmxvdmVsYWNl"),
    ] {
        assert_eq!(b64(input.as_bytes()), expected, "for {input:?}");
    }
}

/// A login handler exercising the whole Basic-auth surface.
///
/// Two things in it are the point. The credential store holds one real
/// argon2id hash and one bcrypt row of the kind a migration leaves
/// behind — `password_verify` must tell those apart. And the
/// no-such-user branch calls `password_verify_dummy` instead of
/// returning early, so both branches cost one argon2 hash.
///
/// One deliberate difference from the reference pattern in
/// `examples/basic-auth`: the verify *reason* is surfaced in the 401 body
/// so the tests can assert on it. That is instrumentation, not the
/// pattern — a reason in the body tells an unauthenticated client that
/// the account exists (an unknown user gets `""`), reopening in the body
/// the oracle the dummy verify closes in time. Real handlers log the
/// reason and answer every failure with the same body, as the example
/// does.
const LOGIN_HANDLER: &str = r#"
local app = nitr.app()

local users = {
    ada = nitr.crypto.password_hash("lovelace"),
    -- Not re-hashed during the migration from the old app. Every login as
    -- `grace` fails; before password_verify grew a reason, nothing
    -- anywhere said why.
    grace = "$2b$12$K3JNi5tR9lHnKKfKzXBDUuJ7dK1nGVX8UEcqfQe5NRaTZY0aWkNSe",
}

local function unauthorized(reason)
    local res = nitr.json({ error = "unauthorized", reason = reason or "" }, 401)
    res.headers["WWW-Authenticate"] = 'Basic realm="nitr", charset="UTF-8"'
    return res
end

app:get("/private", function(req)
    local user, pass = nitr.auth.basic(req)
    if not user then
        return unauthorized()
    end

    local stored = users[user]
    local ok, why
    if stored then
        ok, why = nitr.crypto.password_verify(pass, stored)
    else
        -- No such user. Spend the same argon2 work anyway: returning here
        -- is what turns a login form into a query over the user list.
        ok = nitr.crypto.password_verify_dummy(pass)
    end

    if not ok then
        return unauthorized(why)
    end
    return nitr.json({ user = user })
end)

return app
"#;

async fn login_server(label: &str) -> TestServer {
    TestServer::builder(label)
        .handler(LOGIN_HANDLER)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::CRYPTO)
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await
}

/// GET /private with an optional `Authorization` header, returning the
/// status and the parsed body.
async fn attempt(server: &TestServer, header: Option<&str>) -> (u16, serde_json::Value) {
    let mut req = server.client().get(server.url("/private"));
    if let Some(header) = header {
        req = req.header("authorization", header);
    }
    let resp = req.send().await.expect("GET /private");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    let body = serde_json::from_str(&text).unwrap_or_else(|err| panic!("{err}: {text}"));
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic_credentials_are_accepted_and_every_other_shape_is_refused() {
    let mut server = login_server("auth-basic").await;

    let (status, body) = attempt(&server, Some(&basic("ada", "lovelace"))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["user"], "ada");

    // A wrong password and an unknown user answer identically — no
    // reason, because nothing was wrong with the stored hash.
    for header in [
        basic("ada", "not-lovelace"),
        basic("ada", ""),
        basic("nobody", "lovelace"),
        basic("", ""),
        // The user field is everything before the *first* colon, so a
        // colon in the password does not shift the split.
        basic("ada", "love:lace"),
    ] {
        let (status, body) = attempt(&server, Some(&header)).await;
        assert_eq!(status, 401, "{header} -> {body}");
        assert_eq!(body["reason"], "", "{header} -> {body}");
    }

    // Malformed or absent credentials never reach the verifier at all.
    for header in [
        None,
        Some("Basic"),
        Some("Basic "),
        Some("Basic !!!not-base64!!!"),
        // Valid base64 with no colon: not a credential pair.
        Some("Basic YWRh"),
        // Valid base64 of invalid UTF-8.
        Some("Basic /w=="),
        Some("Bearer YWRhOmxvdmVsYWNl"),
        Some("Digest username=\"ada\""),
        Some("YWRhOmxvdmVsYWNl"),
        Some(""),
    ] {
        let (status, body) = attempt(&server, header).await;
        assert_eq!(status, 401, "{header:?} -> {body}");
    }

    // The challenge a Basic-auth 401 owes the client.
    let resp = server.get("/private").await;
    assert_eq!(resp.status(), 401);
    assert_eq!(
        resp.headers()["www-authenticate"],
        "Basic realm=\"nitr\", charset=\"UTF-8\""
    );

    // A lowercase scheme is legal (RFC 9110 says the scheme is
    // case-insensitive) and must still authenticate.
    let lower = basic("ada", "lovelace").replacen("Basic", "basic", 1);
    let (status, _) = attempt(&server, Some(&lower)).await;
    assert_eq!(status, 200);

    // An over-cap password through a handler with NO length check:
    // `password_verify` answers it as an ordinary miss before argon2
    // runs, so the naive handler is a 401 — never a 500, and never a
    // worker pinned hashing the excess. Both branches: a known user and
    // an unknown one (the dummy verify). Sized past the 1 KiB cap but
    // well inside `[limits] max_header_bytes`, so it reaches the handler
    // rather than being cut off at the header guard one layer up.
    for user in ["ada", "no-such-user"] {
        let huge = basic(user, &"x".repeat(2 * 1024));
        let (status, body) = attempt(&server, Some(&huge)).await;
        assert_eq!(status, 401, "{user}: {body}");
        assert_eq!(
            body["reason"], "",
            "an oversized password must be an ordinary miss, not a reasoned one: {body}"
        );
    }

    server.stop().await;
}

/// The migration case: a stored hash in a format Nitr cannot verify is a
/// 401 like any other failure, but it now says so — instead of being an
/// unexplained permanent "wrong password" for that account only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsupported_stored_hash_names_itself() {
    let mut server = login_server("auth-badhash").await;

    // Even with the right password, a bcrypt row cannot verify.
    for password in ["hopper", "", "anything at all"] {
        let (status, body) = attempt(&server, Some(&basic("grace", password))).await;
        assert_eq!(status, 401, "{body}");
        assert_eq!(
            body["reason"], "unsupported hash format",
            "a bcrypt row must be distinguishable from a wrong password: {body}"
        );
    }

    // …while a real credential in the same table is unaffected.
    let (status, _) = attempt(&server, Some(&basic("ada", "lovelace"))).await;
    assert_eq!(status, 200);

    server.stop().await;
}

/// The user-enumeration oracle, closed.
///
/// Asserted as a floor rather than a ratio between the two paths: the
/// naive handler answers an unknown user in microseconds, so *any*
/// argon2-shaped latency there is the whole property. 5 ms is orders of
/// magnitude under one argon2id pass at 19 MiB (~26 ms optimized, far
/// more in a test build) and orders of magnitude over a table miss, so
/// the assertion cannot flake in either direction. The ratio check that
/// follows is deliberately loose for the same reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_user_costs_the_same_as_a_wrong_password() {
    let mut server = login_server("auth-timing").await;

    /// Best of three: the minimum is the sample least polluted by
    /// scheduling noise, and a floor assertion wants the *cheapest*
    /// observation, not the average.
    async fn best_of_three(server: &TestServer, header: &str) -> Duration {
        let mut best = Duration::MAX;
        for _ in 0..3 {
            let started = Instant::now();
            let (status, _) = attempt(server, Some(header)).await;
            assert_eq!(status, 401);
            best = best.min(started.elapsed());
        }
        best
    }

    // The decoy hash is built on first use, so the very first
    // unknown-user request pays for two hashes. Warm it before measuring.
    attempt(&server, Some(&basic("nobody", "x"))).await;

    let known = best_of_three(&server, &basic("ada", "wrong")).await;
    let unknown = best_of_three(&server, &basic("no-such-user", "wrong")).await;

    let floor = Duration::from_millis(5);
    assert!(
        unknown >= floor,
        "an unknown user answered in {unknown:?}: the no-such-user branch \
         skipped the hash, and the response time now names every valid user"
    );
    assert!(known >= floor, "a known user answered in {known:?}");

    let (fast, slow) = (known.min(unknown), known.max(unknown));
    assert!(
        slow <= fast * 20,
        "the two login paths cost {known:?} and {unknown:?}: a gap that size \
         is measurable over a network"
    );

    server.stop().await;
}
