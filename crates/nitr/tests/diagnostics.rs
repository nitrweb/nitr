// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for phase 13: the error model and diagnostics.
//!
//! Structured error values in `on_error`, per-route error handlers,
//! classification, the dev/production presentation split, and load-time
//! diagnostics that point at the offending line.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::{TestDir, TestServer};

/// The handler script: `/boom` fails at a known line, and the app-wide
/// `on_error` reports every structured field back as JSON so tests can
/// assert on them from outside.
const APP_SCRIPT: &str = r#"
local app = nitr.app()

app:get("/ok", function(req)
    return nitr.text("ok")
end)

app:get("/boom", function(req)
    local user = nil
    return nitr.text(user.name)
end)

app:get("/spin", function(req)
    while true do end
end)

app:get("/routed", function(req)
    error("routed failure")
end, { on_error = function(err, req)
    return { status = 500, body = "route handled: " .. err.kind }
end })

-- `nitr.errinfo` classifies whatever pcall caught: a Lua error (a string
-- with a position prefix) and a Rust builtin error (full chain) alike.
app:get("/caught", function(req)
    local ok1, lua_err = pcall(function() local x = nil; return x.y end)
    local ok2, rust_err = pcall(function() return nitr.json:decode("{not json") end)
    assert(not ok2, "decode of invalid JSON must fail")
    local le = nitr.errinfo(lua_err)
    local re = nitr.errinfo(rust_err)
    return nitr.json({
        lua_kind = le.kind,
        lua_line = le.line,
        lua_source = le.source,
        rust_kind = re.kind,
        rust_message = re.message,
        concat = ("prefix: " .. le),
        pretty = le.pretty,
    })
end)

app:on_error(function(err, req)
    return {
        status = 500,
        headers = { ["Content-Type"] = "application/json" },
        body = nitr.json:encode({
            message = err.message,
            kind = err.kind,
            source = err.source,
            line = err.line,
            has_traceback = err.traceback ~= nil,
            as_string = tostring(err),
        }),
    }
end)

return app
"#;

/// In-process `tracing` capture for the M-3 level assertion. This crate
/// already inherits `tracing-subscriber`; `nitr-http` deliberately does
/// not (phase 1 of the audit-3 remediation rejected a log-capture
/// dev-dependency there), which is why the log-level contract is pinned
/// here rather than beside `fs_ok`.
mod logcap {
    use std::fmt::Write as _;
    use std::sync::Mutex;

    use tracing_subscriber::layer::SubscriberExt as _;

    /// One captured event: its level and the flattened `field=value` text.
    #[derive(Clone)]
    pub struct Event {
        pub level: tracing::Level,
        pub text: String,
    }

    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

    struct Capture;

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _cx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Collect(String);
            impl tracing::field::Visit for Collect {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    let _ = write!(self.0, " {}={:?}", field.name(), value);
                }
            }
            let mut collect = Collect(String::new());
            event.record(&mut collect);
            EVENTS.lock().expect("event log").push(Event {
                level: *event.metadata().level(),
                text: collect.0,
            });
        }
    }

    /// Installs the capturing subscriber process-wide, once. Every test
    /// in this binary shares the list, so assertions filter by their own
    /// marker text rather than assuming exclusivity.
    pub fn install() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let subscriber = tracing_subscriber::registry().with(Capture);
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
    }

    pub fn events() -> Vec<Event> {
        EVENTS.lock().expect("event log").clone()
    }
}

/// Removes ANSI SGR sequences (`ESC [ … m`), leaving the visible text.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip to the terminating `m` of the escape sequence.
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A one-state server for a diagnostics script. The harness gives each
/// test a private directory, which dev mode requires: the watcher
/// registers the handler's parent tree recursively, and a shared temp
/// dir here once meant watching the whole runner's churn (a CI hang).
async fn start(script: &str, dev_mode: bool, tune: impl FnOnce(&mut nitr::Config)) -> TestServer {
    TestServer::builder("diagnostics")
        .handler(script)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| cfg.workers = 1)
        .config(|cfg| cfg.dev_mode = dev_mode)
        .config(tune)
        .spawn()
        .await
}

// ---------------------------------------------------------------------------

/// `on_error` receives the classified error as a table: message, kind,
/// source, line, and traceback — and it still stringifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_error_receives_structured_fields() {
    let mut h = start(APP_SCRIPT, false, |_| {}).await;
    let client = h.client().clone();

    let resp = client.get(h.url("/boom")).send().await.expect("GET /boom");
    assert_eq!(resp.status(), 500);
    let err: serde_json::Value = resp.json().await.expect("error json");

    assert_eq!(err["kind"], "lua");
    assert!(
        err["message"]
            .as_str()
            .expect("message")
            .contains("attempt to index a nil value"),
        "unexpected message: {err}"
    );
    // The source is the handler script (its chunk is named after the file),
    // and the line is where `/boom` dereferences nil.
    assert!(
        err["source"].as_str().expect("source").contains("app.lua"),
        "unexpected source: {err}"
    );
    assert_eq!(err["line"], 10);
    assert_eq!(err["has_traceback"], true);
    // tostring(err) keeps string-shaped usage working, in the concise form.
    let as_string = err["as_string"].as_str().expect("as_string");
    assert!(as_string.starts_with("lua:"), "got: {as_string}");
    assert!(as_string.contains("app.lua:10"), "got: {as_string}");

    h.stop().await;
}

/// A per-route `on_error` wins over the app-wide handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_route_on_error_overrides_app_handler() {
    let mut h = start(APP_SCRIPT, false, |_| {}).await;
    let client = h.client().clone();

    let resp = client
        .get(h.url("/routed"))
        .send()
        .await
        .expect("GET /routed");
    assert_eq!(resp.status(), 500);
    assert_eq!(resp.text().await.expect("body"), "route handled: lua");

    h.stop().await;
}

/// A CPU-bound overrun is classified `timeout`, not a script bug.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn budget_overruns_are_classified_as_timeouts() {
    let mut h = start(APP_SCRIPT, false, |cfg| {
        cfg.lua.exec_timeout_ms = 200;
        // Config validation refuses a pool wait above the request budget.
        cfg.limits.pool_wait_ms = 200;
    })
    .await;
    let client = h.client().clone();

    let resp = client.get(h.url("/spin")).send().await.expect("GET /spin");
    assert_eq!(resp.status(), 500);
    let err: serde_json::Value = resp.json().await.expect("error json");
    assert_eq!(err["kind"], "timeout", "got: {err}");

    h.stop().await;
}

/// `nitr.errinfo` classifies pcall-caught errors — Lua strings and Rust
/// builtin errors alike — and the value concatenates as the concise line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errinfo_classifies_caught_errors() {
    let mut h = start(APP_SCRIPT, false, |_| {}).await;
    let client = h.client().clone();

    let resp = client
        .get(h.url("/caught"))
        .send()
        .await
        .expect("GET /caught");
    assert_eq!(resp.status(), 200);
    let out: serde_json::Value = resp.json().await.expect("json");

    // The Lua error keeps its position through the string round trip.
    assert_eq!(out["lua_kind"], "lua", "got: {out}");
    assert!(
        out["lua_source"]
            .as_str()
            .expect("lua_source")
            .contains("app.lua"),
        "got: {out}"
    );
    assert!(
        out["lua_line"].as_u64().is_some_and(|l| l > 0),
        "got: {out}"
    );
    // The Rust builtin error is classified as a boundary failure.
    assert_eq!(out["rust_kind"], "nitr", "got: {out}");
    // `__concat` renders the concise form directly into a string.
    let concat = out["concat"].as_str().expect("concat");
    assert!(concat.starts_with("prefix: lua:"), "got: {concat}");
    assert!(concat.contains("app.lua"), "got: {concat}");
    // `pretty` is the concise form, ANSI-colored exactly when the server
    // process writes to a terminal with NO_COLOR unset. The server runs in
    // this test process, so compute the same gate here instead of assuming
    // one environment: `cargo test` in an interactive terminal keeps the
    // real stdout fd, so the gate is genuinely open there.
    use std::io::IsTerminal as _;
    let colored = std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let pretty = out["pretty"].as_str().expect("pretty");
    assert_eq!(pretty.contains('\u{1b}'), colored, "got: {pretty:?}");
    let plain = strip_ansi(pretty);
    assert!(plain.starts_with("lua:"), "got: {plain}");
    assert!(plain.contains("app.lua"), "got: {plain}");

    h.stop().await;
}

/// Production responses stay curt: no source paths, no tracebacks, no
/// internal detail — the structured log line is where the diagnosis lives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_responses_leak_no_source() {
    // No on_error handler, so the built-in error response answers.
    let script = r#"
local app = nitr.app()
app:get("/boom", function(req)
    local user = nil
    return nitr.text(user.name)
end)
return app
"#;
    let mut h = start(script, false, |_| {}).await;
    let client = h.client().clone();

    let resp = client.get(h.url("/boom")).send().await.expect("GET /boom");
    assert_eq!(resp.status(), 500);
    let body = resp.text().await.expect("body");
    assert_eq!(body, "Internal Server Error");

    h.stop().await;
}

/// Development mode renders the error in context: the failing line marked
/// in its source, the traceback, and the concise headline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dev_mode_shows_the_failing_source_line() {
    let script = r#"
local app = nitr.app()
app:get("/boom", function(req)
    local user = nil
    return nitr.text(user.name)
end)
return app
"#;
    let mut h = start(script, true, |_| {}).await;
    let client = h.client().clone();

    let resp = client.get(h.url("/boom")).send().await.expect("GET /boom");
    assert_eq!(resp.status(), 500);
    let body = resp.text().await.expect("body");
    assert!(body.contains("attempt to index a nil value"), "got: {body}");
    assert!(body.contains("app.lua:5"), "got: {body}");
    // The source snippet marks the failing line.
    assert!(
        body.contains("5 |     return nitr.text(user.name)"),
        "got: {body}"
    );
    assert!(body.contains("stack traceback:"), "got: {body}");

    // A browser gets the same content as HTML.
    let resp = client
        .get(h.url("/boom"))
        .header("accept", "text/html")
        .send()
        .await
        .expect("GET /boom html");
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .expect("content type")
            .starts_with("text/html"),
    );
    let body = resp.text().await.expect("html body");
    assert!(body.contains("<pre>"), "got: {body}");
    assert!(body.contains("attempt to index a nil value"), "got: {body}");

    h.stop().await;
}

/// A duplicate route names both registration sites: knowing only the
/// second means hunting the file for the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_routes_name_both_sites() {
    let script = r#"
local app = nitr.app()
app:get("/x", function(req) return { status = 200 } end)
app:get("/x", function(req) return { status = 200 } end)
return app
"#;
    let dir = TestDir::new("diagnostics-dup");
    let handler = dir.write("dup.lua", script);
    let err = nitr::Server::builder()
        .listen("127.0.0.1:0".parse().expect("addr"))
        .handler_script(&handler)
        .builtins(nitr::Builtins::JSON)
        .workers(1)
        .build()
        .await
        .expect_err("duplicate route must fail the build");
    let message = err.to_string();
    assert!(message.contains("duplicate route `GET /x`"), "{message}");
    assert!(message.contains("first registered here"), "{message}");
    assert!(message.contains("registered again here"), "{message}");
    // Both sites carry the line numbers of the two app:get calls.
    assert!(message.contains(":3"), "{message}");
    assert!(message.contains(":4"), "{message}");
}

/// A syntax error points at the line, with the source rendered around it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn syntax_errors_point_at_the_line() {
    let script = "local app = nitr.app()\nlocal x =\nreturn app\n";
    let dir = TestDir::new("diagnostics-syntax");
    let handler = dir.write("syntax.lua", script);
    let err = nitr::Server::builder()
        .listen("127.0.0.1:0".parse().expect("addr"))
        .handler_script(&handler)
        .builtins(nitr::Builtins::JSON)
        .workers(1)
        .build()
        .await
        .expect_err("syntax error must fail the build");
    let message = err.to_string();
    assert!(message.contains("-->"), "{message}");
    assert!(message.contains("syntax.lua"), "{message}");
    // The gutter renders the offending source line.
    assert!(message.contains("| return app"), "{message}");
}

/// M-3 (audit 3, phase 4): a request-manufactured filesystem error on the
/// static-serving path logs at `debug` — never `warn` or above — with the
/// path escaped, so an unauthenticated URI can neither spam the
/// operator's log nor forge a line in it. The client answer stays a
/// uniform 404 throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_fs_errors_log_at_debug_with_the_path_escaped() {
    logcap::install();

    let dir = harness::TestDir::new("diagnostics-static");
    std::fs::write(dir.path().join("ok.txt"), "ok").expect("write file");
    let app = format!(
        "local app = nitr.app()\napp:static(\"/assets\", {:?})\nreturn app\n",
        dir.path().to_string_lossy(),
    );
    let mut server = TestServer::builder("diagnostics")
        .handler(app)
        .builtins(nitr::Builtins::HTTP)
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;

    // A component past NAME_MAX with an embedded newline: it passes the
    // lexical path rules, so `metadata` itself fails (`ENAMETOOLONG`) —
    // the class an unauthenticated URI can still manufacture — and the
    // newline rides on an error that is actually logged. (A `%00` never
    // reaches the filesystem any more: `safe_join` rejects NUL lexically,
    // so that probe is a silent 404 — the phase plan's NUL vector
    // predates that rule.)
    let hostile = format!("/assets/{}%0A%20WARN%20forged", "B".repeat(300));
    let resp = server
        .client()
        .get(server.url(&hostile))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404, "the client answer stays a uniform 404");
    // Control: the mount itself works, so the 404 above was the error
    // path and not a dead mount.
    let resp = server.get("/assets/ok.txt").await;
    assert_eq!(resp.status(), 200);

    server.stop().await;

    let events: Vec<_> = logcap::events()
        .into_iter()
        .filter(|e| e.text.contains("static file access failed"))
        .collect();
    assert!(
        !events.is_empty(),
        "the probe must reach fs_ok and be logged (at debug)"
    );
    for event in &events {
        assert_eq!(
            event.level,
            tracing::Level::DEBUG,
            "a request-derived path must never steer the log above debug: {}",
            event.text
        );
        assert!(
            event.text.contains("kind="),
            "the ErrorKind field is part of the contract: {}",
            event.text
        );
        assert!(
            !event.text.contains('\n'),
            "a request newline must arrive escaped, not verbatim: {}",
            event.text
        );
        assert!(
            event.text.contains("\\n"),
            "the escaped newline should still be visible in the quoted path: {}",
            event.text
        );
    }
}
