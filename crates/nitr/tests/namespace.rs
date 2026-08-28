// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for the phase-8 extension boundary: the `nitr.*`
//! namespace is the only surface Nitr exposes to Lua, Rust extension
//! modules mount beside the builtins, and the crypto/auth primitives.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::TestServer;

/// Nitr contributes exactly one global — `nitr` — and every builtin hangs
/// off it. Nothing is intermixed with the Lua standard library.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_nitr_global_is_registered() {
    let mut server = TestServer::builder("ns-globals")
        .handler(
            r#"
local app = nitr.app()

app:get("/globals", function(req)
    -- Every name Nitr could have leaked as a bare global.
    local leaked = {}
    for _, name in ipairs({
        "json", "fetch", "await_all", "template", "conn", "db", "dbg",
        "text", "html", "redirect", "status", "negotiate", "sse",
        "http", "log", "crypto", "auth", "test",
    }) do
        if _G[name] ~= nil then
            table.insert(leaked, name)
        end
    end
    -- And the Lua-side sandbox: the ambient-authority libraries and the
    -- file-executing base functions must be absent in a default server.
    local ambient = {}
    for _, name in ipairs({ "io", "os", "debug", "dofile", "loadfile" }) do
        if _G[name] ~= nil then
            table.insert(ambient, name)
        end
    end
    return nitr.json({ leaked = leaked, ambient = ambient })
end)

app:get("/members", function(req)
    local members = {}
    for _, name in ipairs({
        "app", "json", "text", "html", "redirect", "status",
        "negotiate", "sse", "error", "log", "dbg", "crypto", "auth",
    }) do
        members[name] = type(nitr[name])
    end
    return nitr.json(members)
end)

return app
"#,
        )
        .builtins(
            nitr::Builtins::JSON
                | nitr::Builtins::HTTP
                | nitr::Builtins::LOG
                | nitr::Builtins::DEBUG
                | nitr::Builtins::CRYPTO,
        )
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;

    let body = server.json("/globals").await;
    // An empty Lua table encodes as `{}`, so treat both shapes as empty.
    let leaked = body["leaked"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    assert!(
        leaked.is_empty(),
        "Nitr must not register bare globals, found: {leaked:?}"
    );
    // The default sandbox holds through the whole server stack, not just
    // the runtime unit test: no filesystem/process/debug entry points.
    let ambient = body["ambient"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    assert!(
        ambient.is_empty(),
        "the default sandbox must not expose ambient authority, found: {ambient:?}"
    );

    // …and everything is reachable through the namespace instead.
    let members = server.json("/members").await;
    for name in [
        "app",
        "json",
        "text",
        "html",
        "redirect",
        "status",
        "negotiate",
        "sse",
        "error",
        "log",
        "dbg",
        "crypto",
        "auth",
    ] {
        let kind = members[name].as_str().unwrap_or("nil");
        assert_ne!(kind, "nil", "nitr.{name} must exist");
    }
    // `nitr.json` is callable userdata (helper + codec); the rest are
    // functions or tables.
    assert_eq!(members["json"], "userdata");
    assert_eq!(members["log"], "table");
    assert_eq!(members["text"], "function");

    server.stop().await;
}

/// The handler script must return a `nitr.app()`: the legacy
/// `function(cfg, req)` catch-all style is gone, and the failure is a
/// startup error, not a per-request surprise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_function_handlers_are_rejected() {
    let mut builder = TestServer::builder("ns-legacy")
        .handler("return function(cfg, req) return { status = 200, body = 'legacy' } end")
        .builtins(nitr::Builtins::JSON)
        .config(|cfg| cfg.workers = 1);
    let err = builder
        .try_build()
        .await
        .expect_err("a plain function handler must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("must return a nitr.app()"),
        "unexpected error: {msg}"
    );
}

/// Rust extension modules mount at `nitr.ext.<name>` in every pooled state
/// and are indistinguishable from builtins on the Lua side.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_modules_mount_on_the_namespace() {
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let shared = counter.clone();
    let mut server = TestServer::builder("ns-module")
        .handler(
            r#"
local app = nitr.app()

app:get("/greet/:name", function(req)
    return nitr.json({
        greeting = nitr.ext.demo.greet(req.params.name),
        counter = nitr.ext.demo.next(),
        kind = type(nitr.ext.demo),
    })
end)

return app
"#,
        )
        .builtins(nitr::Builtins::JSON)
        .module("demo", move |lua| {
            let table = lua.create_table()?;
            table.set(
                "greet",
                lua.create_function(|_, name: String| Ok(format!("Hello, {name}!")))?,
            )?;
            let shared = shared.clone();
            table.set(
                "next",
                lua.create_function(move |_, ()| {
                    Ok(shared.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1)
                })?,
            )?;
            Ok(table)
        })
        // Two states: the module closure must run for each of them.
        .config(|cfg| cfg.workers = 2)
        .spawn()
        .await;

    let body = server.json("/greet/nitr").await;
    assert_eq!(body["greeting"], "Hello, nitr!");
    assert_eq!(body["kind"], "table");

    // The Rust-side state is shared across pooled states.
    let body = server.json("/greet/again").await;
    assert_eq!(body["counter"], 2);

    server.stop().await;
}

/// Modules live in `nitr.ext.*`, so a module may share a builtin's name —
/// the std surface can never collide with user code — while two modules
/// with the same name still fail at build time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_names_are_isolated_from_the_std() {
    const COLLIDE_SCRIPT: &str = "local app = nitr.app()\n\
         app:get('/', function(req)\n\
             return nitr.json({ std = type(nitr.json), ext = nitr.ext.json.kind })\n\
         end)\nreturn app";

    // A module named `json` coexists with the `nitr.json` builtin: it
    // mounts at `nitr.ext.json`, one level away from the std.
    let mut server = TestServer::builder("ns-collide")
        .handler(COLLIDE_SCRIPT)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .module("json", |lua| {
            let t = lua.create_table()?;
            t.set("kind", "extension")?;
            Ok(t)
        })
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;
    let body = server.json("/").await;
    assert_eq!(body["std"], "userdata");
    assert_eq!(body["ext"], "extension");
    server.stop().await;

    // Two modules with the same name collide with each other too.
    let mut builder = TestServer::builder("ns-collide-twice")
        .handler(COLLIDE_SCRIPT)
        .builtins(nitr::Builtins::HTTP)
        .module("twice", |lua| lua.create_table())
        .module("twice", |lua| lua.create_table())
        .config(|cfg| cfg.workers = 1);
    let err = builder
        .try_build()
        .await
        .expect_err("duplicate module names must be rejected");
    assert!(err.to_string().contains("already exists"), "got: {err}");
}

/// `nitr.crypto` and `nitr.auth`: hashing, HMAC, randomness, constant-time
/// comparison, argon2id passwords, and Authorization header parsing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crypto_and_auth_primitives() {
    let mut server = TestServer::builder("ns-crypto")
        .handler(
            r#"
local app = nitr.app()

app:get("/digest", function(req)
    local token = nitr.crypto.random_bytes(32)
    return nitr.json({
        sha256 = nitr.crypto.sha256("abc"),
        hmac = nitr.crypto.hmac_sha256("key", "abc"),
        random_len = #token,
        random_differs = nitr.crypto.random_bytes(32) ~= token,
        eq_same = nitr.crypto.constant_time_eq("secret", "secret"),
        eq_diff = nitr.crypto.constant_time_eq("secret", "secrez"),
    })
end)

app:post("/password", function(req)
    local hash = nitr.crypto.password_hash("hunter2")
    return nitr.json({
        prefix = hash:sub(1, 10),
        ok = nitr.crypto.password_verify("hunter2", hash),
        bad = nitr.crypto.password_verify("hunter3", hash),
        garbage = nitr.crypto.password_verify("hunter2", "not-a-hash"),
    })
end)

app:get("/auth", function(req)
    local user, pass = nitr.auth.basic(req)
    return nitr.json({
        bearer = nitr.auth.bearer(req) or "none",
        user = user or "none",
        pass = pass or "none",
    })
end)

return app
"#,
        )
        .builtins(nitr::Builtins::JSON | nitr::Builtins::CRYPTO)
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;

    let body = server.json("/digest").await;
    assert_eq!(
        body["sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        body["hmac"],
        "9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab"
    );
    assert_eq!(body["random_len"], 32);
    assert_eq!(body["random_differs"], true);
    assert_eq!(body["eq_same"], true);
    assert_eq!(body["eq_diff"], false);

    let resp = server
        .client()
        .post(server.url("/password"))
        .send()
        .await
        .expect("password");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["prefix"], "$argon2id$");
    assert_eq!(body["ok"], true);
    assert_eq!(body["bad"], false);
    assert_eq!(body["garbage"], false);

    // Bearer and Basic parsing off the live request object.
    let resp = server
        .client()
        .get(server.url("/auth"))
        .header("authorization", "Bearer t0ken")
        .send()
        .await
        .expect("bearer");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["bearer"], "t0ken");
    assert_eq!(body["user"], "none");

    // "ada:lovelace" base64-encoded.
    let resp = server
        .client()
        .get(server.url("/auth"))
        .header("authorization", "Basic YWRhOmxvdmVsYWNl")
        .send()
        .await
        .expect("basic");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["user"], "ada");
    assert_eq!(body["pass"], "lovelace");
    assert_eq!(body["bearer"], "none");

    server.stop().await;
}
