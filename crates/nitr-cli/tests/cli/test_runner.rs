// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr test` end to end: the framework's structure and matchers, the
//! per-test budget, the client and its response, the doubles, the
//! fixtures, the unit-testing tools, and the runner's flags — each
//! asserted on the exact lines a developer reads.

use std::path::Path;

// The last three are what `require_runnable_binary!` expands to.
use super::{Scratch, binary_runs, foreign_machine, machine_name, nitr};

/// A scratch application: the given files, written under a fresh
/// directory.
fn app(name: &str, files: &[(&str, &str)]) -> Scratch {
    let dir = Scratch::new(name);
    for (rel, content) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&path, content).expect("write app file");
    }
    dir
}

struct Outcome {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Runs `nitr <args>` in `dir`.
fn run_in(dir: &Path, args: &[&str]) -> Outcome {
    let out = nitr()
        .current_dir(dir)
        .args(args)
        .env_remove("RUST_LOG")
        .env("NO_COLOR", "1")
        .output()
        .expect("run nitr");
    Outcome {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn assert_has(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            haystack.contains(needle),
            "expected {needle:?} in the output:\n{haystack}"
        );
    }
}

const MINIMAL_TOML: &str = r#"handler_script = "app.lua"

[lua]
exec_timeout_ms = 500

[limits]
pool_wait_ms = 400
"#;

const MINIMAL_APP: &str = r#"local app = nitr.app()
app:get("/hello", function(req) return nitr.json({ hello = "world" }) end)
app:get("/text", function(req) return nitr.text("plain") end)
app:get("/boom", function(req) local x = nil; return x.field end)
app:get("/log", function(req)
    nitr.log.debug("debug detail", { n = 1 })
    nitr.log.warn("quota low", { used = 9 })
    return nitr.text("logged")
end)
app:get("/stream-logs", function(req)
    return nitr.sse(function(send)
        for i = 1, 3 do
            send("tick", tostring(i))
            nitr.log.info("chunk sent", { i = i })
        end
    end)
end)
return app
"#;

const STRUCTURE_TEST: &str = r#"local t = nitr.test
local calls = {}
local function log(x) calls[#calls + 1] = x end

t.before_all(function() log("root before_all") end)
t.before_each(function() log("root before_each") end)
t.after_each(function() log("root after_each") end)
t.after_all(function() log("root after_all") end)

t.describe("outer", function()
    t.before_all(function() log("outer before_all") end)
    t.before_each(function() log("outer before_each") end)
    t.after_each(function() log("outer after_each") end)
    t.after_all(function() log("outer after_all") end)
    t.it("first", function() log("first") end)
    t.describe("inner", function()
        t.before_each(function() log("inner before_each") end)
        t.it("second", function() log("second") end)
    end)
end)

t.it("hooks run outer to inner, once per group", function()
    t.expect(calls).to_equal({
        "root before_all", "outer before_all",
        "root before_each", "outer before_each", "first", "outer after_each", "root after_each",
        "root before_each", "outer before_each", "inner before_each", "second",
        "outer after_each", "root after_each", "outer after_all",
        "root before_each",
    })
end)

t.describe("snapshot", function()
    local seen = {}
    t.it("registered before the hook", function() t.expect(seen.hook).to_be_nil() end)
    t.before_each(function() seen.hook = true end)
    t.it("registered after the hook", function() t.expect(seen.hook).to_be_truthy() end)
end)

t.describe("broken", function()
    t.it("registered before the throw", function() end)
    error("setup exploded")
end)
t.it("still runs after a broken describe", function() end)

t.each({ { 1, 2, 3 }, { 2, 2, 4 } })("adds %d + %d = %d", function(a, b, sum)
    t.expect(a + b).to_equal(sum)
end)
t.each({ { name = "named case", input = "x" } })("case: %s", function(case)
    t.expect(case.input).to_equal("x")
end)

t.skip("skipped one", function() error("never runs") end)
t.todo("write later")

t.it("spins forever", function() while true do end end)
t.it("runs after the spin", function() end)
t.it("advancing the clock does not trip the budget", function()
    t.clock.advance(3600)
    local n = 0
    for i = 1, 100000 do n = n + i end
    t.expect(n).to_be_greater_than(0)
end)
t.it("fails on purpose", function()
    t.fail("unreachable branch")
end)
t.each({ { nil, "X" } })("nil input %s gives %s", function(input, code)
    t.expect(input).to_be_nil()
    t.expect(code).to_equal("X")
end)
t.describe("slow setup", function()
    t.before_all(function() while true do end end)
    t.it("first pays the budget", function() end)
    t.it("second is told why", function() end)
end)
"#;

const MATCHERS_TEST: &str = r#"local t = nitr.test

t.it("m to_be_false", function() t.expect(nil).to_be_false() end)
t.it("m to_be_a", function() t.expect(1.5).to_be_a("integer") end)
t.it("m to_have_length", function() t.expect({ 1, 2 }).to_have_length(3) end)
t.it("m to_be_greater_than", function() t.expect(1).to_be_greater_than(2) end)
t.it("m to_be_less_than_or_equal", function() t.expect(3).to_be_less_than_or_equal(2) end)
t.it("m to_have_key", function() t.expect({ a = 1 }).to_have_key("b") end)
t.it("m to_match_object", function()
    t.expect({ { text = "hi", id = 1 } }).to_match_object({ { text = "ho" } })
end)
t.it("m to_throw", function() t.expect(function() end).to_throw() end)
t.it("m to_throw pattern", function() t.expect(function() error("boom") end).to_throw("bang") end)
t.it("m to_not_throw", function() t.expect(function() error("boom") end).to_not_throw() end)
t.it("m to_not_match", function() t.expect("abc").to_not_match("b") end)
t.it("m to_not_contain", function() t.expect({ 1, 2 }).to_not_contain(2) end)
t.it("m to_not_be_nil", function() t.expect(nil).to_not_be_nil() end)
t.it("m to_have_status", function() t.expect(t.get("/boom")).to_have_status(200) end)
t.it("m to_have_header", function() t.expect(t.get("/hello")).to_have_header("x-missing") end)
t.it("m to_have_json", function() t.expect(t.get("/text")).to_have_json({ a = 1 }) end)
t.it("m to_contain_log", function()
    t.get("/log")
    t.expect(t.logs()).to_contain_log({ message = "absent" })
end)
t.it("m render cap", function() t.expect(("x"):rep(1000)).to_equal("y") end)

t.it("every matcher passes on the positive case", function()
    t.expect(false).to_be_false()
    t.expect(3).to_be_a("integer")
    t.expect(1.5).to_be_a("float")
    t.expect("s").to_be_a("string")
    t.expect("abc").to_have_length(3)
    t.expect(2).to_be_greater_than(1)
    t.expect(2).to_be_greater_than_or_equal(2)
    t.expect(1).to_be_less_than(2)
    t.expect(2).to_be_less_than_or_equal(2)
    t.expect({ a = 1 }).to_have_key("a")
    t.expect({ { text = "hi", id = 1 }, 2 }).to_match_object({ { text = "hi" } })
    t.expect(function() error("boom") end).to_throw("boom")
    t.expect(function() end).to_not_throw()
    t.expect("abc").to_not_match("z")
    t.expect({ 1 }).to_not_contain(2)
    t.expect(0).to_not_be_nil()
    local resp = t.get("/hello")
    t.expect(resp).to_have_status(200)
    t.expect(resp).to_have_header("content-type", "application/json")
    t.expect(resp).to_have_json({ hello = "world" })
    t.get("/log")
    t.expect(t.logs()).to_contain_log({ level = "debug", message = "debug detail", fields = { n = 1 } })
    t.expect(t.logs()).to_contain_log({ level = "warn", target = "lua", fields = { used = 9 } })
    t.logs.clear()
    t.expect(#t.logs()).to_equal(0)
end)
"#;

/// The framework's structure: scoped hooks and `before_all`/`after_all`
/// in order, hook snapshots at registration, a protected `describe`,
/// `each` naming, `skip`/`todo`, a per-test budget that fails one test
/// and lets the next run, a clock advance that does not trip the budget,
/// and `t.fail`.
#[test]
fn the_framework_structures_runs_and_reports_each_test() {
    require_runnable_binary!();
    let dir = app(
        "framework",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            ("tests/a_structure_test.lua", STRUCTURE_TEST),
        ],
    );
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(1), "{}", out.stdout);
    assert_has(
        &out.stdout,
        &[
            "ok   outer > first",
            "ok   outer > inner > second",
            "ok   hooks run outer to inner, once per group",
            "ok   snapshot > registered before the hook",
            "ok   snapshot > registered after the hook",
            "FAIL broken > registered before the throw",
            "the enclosing describe body failed: tests/a_structure_test.lua:41: setup exploded",
            "FAIL broken (describe body)",
            "ok   still runs after a broken describe",
            "ok   adds 1 + 2 = 3",
            "ok   adds 2 + 2 = 4",
            "ok   case: named case",
            "skip skipped one (skipped)",
            "todo write later",
            "FAIL spins forever",
            "the test exceeded its time budget ([lua] exec_timeout_ms = 500 ms)",
            "ok   runs after the spin",
            "ok   advancing the clock does not trip the budget",
            "FAIL fails on purpose",
            "tests/a_structure_test.lua:64: unreachable branch",
            "ok   nil input nil gives X",
            "FAIL slow setup > first pays the budget",
            "FAIL slow setup > second is told why",
            "before_all did not complete (it ran out of the first test's budget)",
            "12 passed, 6 failed, 1 skipped, 1 todo (1 file(s),",
        ],
    );
    assert!(!out.stdout.contains("never runs"), "{}", out.stdout);
}

/// Every matcher's failure message names what was expected and what
/// arrived — and for a response, the body and the handler's error.
#[test]
fn every_matcher_explains_its_failure() {
    require_runnable_binary!();
    let dir = app(
        "matchers",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            ("tests/b_matchers_test.lua", MATCHERS_TEST),
        ],
    );
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(1), "{}", out.stdout);
    assert_has(
        &out.stdout,
        &[
            "b_matchers_test.lua:3: expected nil to be false",
            "b_matchers_test.lua:4: expected 1.5 to be a integer, got a float",
            "expected length 3, got 2: { [1] = 1, [2] = 2 }",
            "b_matchers_test.lua:6: expected 1 to be greater than 2",
            "b_matchers_test.lua:7: expected 3 to be less than or equal to 2",
            r#"expected { a = 1 } to have key "b""#,
            r#"to match { [1] = { text = "ho" } }"#,
            "expected the function to throw, but it did not throw",
            r#"expected the error to contain "bang", got "tests/b_matchers_test.lua:13: boom""#,
            "expected the function not to throw, but it threw",
            r#"expected "abc" not to match "b""#,
            "expected { [1] = 1, [2] = 2 } not to contain 2",
            "expected a value, got nil",
            "expected status 200, got 500",
            "body: Internal Server Error",
            "lua: ",
            "attempt to index a nil value",
            "expected header x-missing, but it is absent",
            "expected a JSON body, but it does not decode",
            r#"expected a log entry matching { message = "absent" } among 2 entries"#,
            r#"xxxxxxxxxx"... to equal "y""#,
            "ok   every matcher passes on the positive case",
            "1 passed, 18 failed",
        ],
    );
    // The render cap: a 1000-byte string is cut at 256.
    assert!(!out.stdout.contains(&"x".repeat(300)), "{}", out.stdout);
    // Captured logs print under the failed test that produced them.
    assert_has(&out.stdout, &["logs:", "WARN lua: quota low {\"used\":9}"]);
}

/// A `t.only` focuses its file, and the run fails while it is there.
#[test]
fn an_only_left_in_place_fails_the_run() {
    require_runnable_binary!();
    let dir = app(
        "only",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            (
                "tests/c_only_test.lua",
                "local t = nitr.test\nt.it(\"other\", function() end)\nt.only(\"focused\", function() end)\n",
            ),
        ],
    );
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(1), "{}", out.stdout);
    assert_has(
        &out.stdout,
        &[
            "skip other (only)",
            "ok   focused",
            "1 passed, 0 failed, 1 skipped",
            "t.only is left in c_only_test.lua: the run fails until it is removed",
        ],
    );
    // Listing runs nothing, so it does not fail; it marks the focus.
    let list = run_in(dir.as_ref(), &["test", "--list"]);
    assert_eq!(list.code, Some(0), "{}", list.stdout);
    assert_has(
        &list.stdout,
        &[
            "  other  tests/c_only_test.lua:2  [skip: only]",
            "  focused  tests/c_only_test.lua:3  [only]",
        ],
    );
}

/// `--list` registers without running; `--bail` stops at the first
/// failure and says what it skipped; the JSON and JUnit reports carry
/// every test; `--nocapture` streams the log lines.
#[test]
fn runner_flags_list_bail_report_and_stream() {
    require_runnable_binary!();
    let dir = app(
        "flags",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            (
                "tests/a_test.lua",
                "local t = nitr.test\nt.it(\"passes\", function() end)\nt.it(\"<&\\\"'> fails\", function() error(\"bad\\0byte\") end)\nt.it(\"after\", function() end)\nt.todo(\"later\")\n",
            ),
            (
                "tests/b_test.lua",
                "local t = nitr.test\nt.it(\"logs\", function() nitr.test.get(\"/log\") end)\n",
            ),
        ],
    );
    let list = run_in(dir.as_ref(), &["test", "--list"]);
    assert_eq!(list.code, Some(0), "{}", list.stdout);
    assert_has(
        &list.stdout,
        &[
            "a_test.lua\n  passes  tests/a_test.lua:2\n",
            "  later  tests/a_test.lua:5  [todo]",
            "b_test.lua\n  logs  tests/b_test.lua:2",
        ],
    );
    assert!(!list.stdout.contains("passed"), "--list runs nothing");

    let bail = run_in(dir.as_ref(), &["test", "--bail"]);
    assert_eq!(bail.code, Some(1));
    assert_has(
        &bail.stdout,
        &[
            "ok   passes",
            "FAIL <&\"'> fails",
            "stopped after the first failure (--bail); 1 more test(s) in that file and 1 file(s) not run",
        ],
    );
    assert!(!bail.stdout.contains("ok   after"), "{}", bail.stdout);

    let json = run_in(dir.as_ref(), &["test", "--reporter", "json"]);
    assert_eq!(json.code, Some(1));
    let doc: serde_json::Value =
        serde_json::from_str(&json.stdout).expect("stdout is one JSON document");
    assert_eq!(doc["summary"]["passed"], 3);
    assert_eq!(doc["summary"]["failed"], 1);
    assert_eq!(doc["summary"]["todo"], 1);
    assert_eq!(doc["files"][0]["tests"][1]["status"], "failed");
    assert_eq!(doc["files"][0]["tests"][1]["site"], "tests/a_test.lua:3");

    let junit = run_in(
        dir.as_ref(),
        &[
            "test",
            "--reporter",
            "junit",
            "--output",
            "reports/ci/report.xml",
        ],
    );
    assert_eq!(junit.code, Some(1));
    assert_has(&junit.stdout, &["ok   passes", "3 passed, 1 failed"]);
    // The report's directory is made for it.
    let xml = std::fs::read_to_string(dir.join("reports/ci/report.xml")).expect("report written");
    assert_has(
        &xml,
        &[
            r#"<testsuites name="nitr test" tests="5" failures="1" skipped="1""#,
            r#"<testcase name="&lt;&amp;&quot;&apos;&gt; fails" classname="a_test.lua""#,
            r#"file="tests/a_test.lua" line="3""#,
            "<failure message=\"tests/a_test.lua:3: badbyte\">",
            r#"<skipped message="todo"/>"#,
            "WARN lua: quota low",
        ],
    );
    assert!(
        !xml.bytes()
            .any(|b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r')),
        "no control characters in the XML"
    );

    // `--output` without a machine reporter would write nothing: refused.
    let pretty_output = run_in(dir.as_ref(), &["test", "--output", "report.txt"]);
    assert_eq!(pretty_output.code, Some(1));
    assert_has(
        &pretty_output.stderr,
        &["needs --reporter json or --reporter junit"],
    );
    // A listing is for reading, whatever the reporter.
    let listed = run_in(dir.as_ref(), &["test", "--list", "--reporter", "json"]);
    assert_eq!(listed.code, Some(0));
    assert_has(
        &listed.stdout,
        &["a_test.lua\n  passes  tests/a_test.lua:2"],
    );

    let streamed = run_in(dir.as_ref(), &["test", "--nocapture", "--filter", "logs"]);
    assert_eq!(streamed.code, Some(0), "{}", streamed.stdout);
    assert_has(&streamed.stdout, &["quota low", "ok   logs"]);
    let captured = run_in(dir.as_ref(), &["test", "--filter", "logs"]);
    assert!(
        !captured.stdout.contains("quota low"),
        "{}",
        captured.stdout
    );
}

#[cfg(all(feature = "db", feature = "fetch"))]
const DOUBLES_TOML: &str = r#"handler_script = "app.lua"
config_script = "config.lua"
workers = 1

[database]
path = "data/app.db"

[std]
features = ["json", "http", "log", "time", "validate", "db", "fetch", "cache", "env"]

[env]
allow = ["APP_"]

[rate_limit]
enabled = true
requests = 60
window = 60

[lua]
exec_timeout_ms = 1500
memory_limit = 8388608

[limits]
pool_wait_ms = 1000
"#;

#[cfg(all(feature = "db", feature = "fetch"))]
const DOUBLES_APP: &str = r#"local notes = require("lib.notes")
local app = nitr.app()

app:get("/cookies", function(req)
    local resp = nitr.text("ok")
    resp.cookies:set("a", "1", { path = "/" })
    resp.cookies:set("b", "2", { max_age = 60, http_only = true })
    return resp
end)

app:get("/boom", function(req) local x = nil; return x.field end)

app:get("/handled", function(req) error("handled failure") end, {
    on_error = function(err, req) return nitr.error(503, { code = "DOWN" }) end,
})

app:get("/stream", function(req)
    return nitr.sse(function(send)
        local i = 0
        while true do i = i + 1; send("tick", tostring(i)) end
    end)
end)

app:get("/events", function(req)
    return nitr.sse(function(send)
        send("greet", "hello")
        send("greet", "again")
    end)
end)

app:post("/api/notes", function(req)
    local body = req:json()
    local ok, err = notes.validate(body)
    if not ok then return nitr.error(422, err) end
    nitr.db:execute("INSERT INTO notes (text) VALUES (?)", { body.text })
    local hook = nitr.fetch("POST", "https://hooks.example/notes", { json = { text = body.text } }):send()
    nitr.log.warn("published", { status = hook.status })
    return nitr.json({ ok = true, hook = hook.status }, 201)
end)

app:get("/api/notes", function(req)
    return nitr.json(nitr.db:query("SELECT id, text FROM notes ORDER BY id"))
end)

app:post("/login", function(req)
    local form = req:form()
    if form.user ~= "ann" or form.pass ~= "secret" then return nitr.status(401) end
    local session = nitr.session(req, { secret = nitr.cfg.session_secret, max_age = 86400 })
    session.user = form.user
    local resp = nitr.redirect("/me", 303)
    session:save(resp)
    return resp
end)

app:get("/me", function(req)
    local session = nitr.session(req, { secret = nitr.cfg.session_secret })
    if not session.user then return nitr.status(401) end
    return nitr.json({ user = session.user })
end)

app:get("/rate", function(req)
    local cached = nitr.cache:get("rate")
    if cached then return nitr.json(cached) end
    local rate = nitr.fetch("GET", "https://fx.example/eur"):send():json()
    nitr.cache:set("rate", rate, { ttl = 300 })
    return nitr.json(rate)
end)

app:get("/env", function(req)
    return nitr.json({ key = nitr.env.get("APP_KEY"), home = nitr.env.get("HOME") })
end)

app:get("/notes/:id", function(req)
    if req.params.id == "999" then return nitr.error(404, { code = "NOT_FOUND" }) end
    return nitr.json({ id = req.params.id, q = req.query.expand, role = req.headers["x-role"] })
end)

app:get("/private", function(req)
    return nitr.json({ via = nitr.fetch("GET", "http://10.0.0.1/b"):send().status })
end)

app:get("/hog", function(req)
    local t = {}
    for i = 1, 1e8 do t[i] = ("x"):rep(1024 * 1024) end
    return nitr.text("unreachable")
end)

app:post("/auth/login", function(req)
    local resp = nitr.text("in")
    resp.cookies:set("scoped", "1")
    return resp
end)
app:get("/auth/check", function(req) return nitr.json({ scoped = req.cookies.scoped }) end)
app:get("/whoami", function(req) return nitr.json({ scoped = req.cookies.scoped }) end)
app:post("/two-paths", function(req)
    local resp = nitr.text("x")
    resp.cookies:set("sid", "root", { path = "/" })
    resp.cookies:set("sid", "admin", { path = "/admin" })
    return resp
end)
app:post("/logout-both", function(req)
    local resp = nitr.text("x")
    resp.cookies:set("sid", "", { path = "/", max_age = 0 })
    resp.cookies:set("sid", "", { path = "/admin", max_age = 0 })
    return resp
end)
app:get("/admin/sid", function(req) return nitr.json({ sid = req.cookies.sid }) end)

app:get("/hook", function(req)
    return nitr.json({ status = nitr.fetch("GET", "https://hooks.example/ping"):send().status })
end)

return app
"#;

#[cfg(all(feature = "db", feature = "fetch"))]
const DOUBLES_TEST: &str = r#"local t = nitr.test
local notes = require("lib.notes")
local creds = require("helpers.auth")

t.describe("client", function()
    t.it("keeps every Set-Cookie", function()
        local resp = t.get("/cookies")
        t.expect(#resp:headers("set-cookie")).to_equal(2)
        t.expect(#resp.raw_headers).to_be_greater_than(2)
        t.expect(resp.cookies.b.http_only).to_be_truthy()
        t.expect(resp.cookies.b.max_age).to_equal(60)
        t.expect(resp.cookies.a.path).to_equal("/")
        t.expect(resp:header("set-cookie")).to_match("^a=1")
        t.expect(resp:text()).to_equal("ok")
    end)
    t.it("explains a 500 without dev mode", function()
        local resp = t.get("/boom")
        t.expect(resp.status).to_equal(500)
        t.expect(resp.body).to_equal("Internal Server Error")
        t.expect(resp.error.kind).to_equal("lua")
        t.expect(resp.error.message).to_contain("attempt to index a nil value")
        t.expect(resp.error.handled).to_be_false()
        t.expect(t.get("/cookies").error).to_be_nil()
    end)
    t.it("keeps the cause of a handled failure", function()
        local resp = t.get("/handled")
        t.expect(resp.status).to_equal(503)
        t.expect(resp.error.handled).to_be_truthy()
        t.expect(resp.error.message).to_contain("handled failure")
    end)
    t.it("parses server-sent events", function()
        t.expect(t.get("/events"):sse()).to_match_object({ { event = "greet", data = "hello" }, { data = "again" } })
    end)
    t.it("times out an endless stream", function()
        t.expect(function() t.get("/stream", { timeout = 0.3 }) end).to_throw("did not complete within 0.3 s")
    end)
    t.it("refuses two bodies", function()
        t.expect(function() t.post("/api/notes", { json = {}, form = {} }) end).to_throw("`json` and `form` both given")
    end)
    t.it("logs in and ages the session with the jar", function()
        local api = t.client({ cookies = true })
        t.expect(api:post("/login", { form = creds })).to_have_status(303)
        t.expect(api.jar:get("session").http_only).to_be_truthy()
        t.expect(api:get("/me"):json().user).to_equal("ann")
        t.clock.advance(86400 + 1)
        t.expect(api:get("/me")).to_have_status(401)
    end)
    t.it("forges sessions with and without the secret", function()
        local api = t.client({ cookies = true })
        api.jar:set("session", t.session_cookie({ user = "ann" }, { secret = nitr.cfg.session_secret }))
        t.expect(api:get("/me")).to_have_json({ user = "ann" })
        api.jar:set("session", nitr.cookie.sign("session", '{"user":"root"}', "wrong-secret-xxxxxxxx"))
        t.expect(api:get("/me")).to_have_status(401)
    end)
    t.it("scopes a cookie without Path to its directory and deletes per path", function()
        local api = t.client({ cookies = true })
        api:post("/auth/login")
        t.expect(api:get("/auth/check"):json().scoped).to_equal("1")
        t.expect(api:get("/whoami"):json().scoped).to_be_nil()
        api:post("/two-paths")
        t.expect(api:get("/admin/sid"):json().sid).to_equal("admin")
        api:post("/logout-both")
        t.expect(api.jar:get("sid")).to_be_nil()
    end)
    t.it("rate limits by remote_addr", function()
        for _ = 1, 60 do t.expect(t.get("/env", { remote_addr = "10.9.9.9" })).to_have_status(200) end
        t.expect(t.get("/env", { remote_addr = "10.9.9.9" })).to_have_status(429)
        t.expect(t.get("/env", { remote_addr = "10.9.9.8" })).to_have_status(200)
        t.clock.advance(61)
        t.expect(t.get("/env", { remote_addr = "10.9.9.9" })).to_have_status(200)
    end)
end)

t.describe("doubles", function()
    t.before_each(t.db.reset)
    t.it("mocks the webhook and records the call", function()
        t.fetch.mock({ method = "POST", url = "https://hooks.example/notes", status = 202 })
        t.expect(t.post("/api/notes", { json = { text = "ping" } })).to_have_json({ ok = true, hook = 202 })
        local calls = t.fetch.calls()
        t.expect(#calls).to_equal(1)
        t.expect(calls[1].json.text).to_equal("ping")
        t.expect(calls[1].headers["content-type"]).to_equal("application/json")
        t.expect(t.logs()).to_contain_log({ level = "warn", message = "published", fields = { status = 202 } })
        local entries = t.logs()
        t.expect(entries[#entries].request_id).to_be_a("string")
    end)
    t.it("strict mode refuses what no rule matches", function()
        t.fetch.mock({ url = "https://fx.example/eur", json = { rate = 1.1 }, times = 1 })
        t.fetch.strict(true)
        t.get("/rate"); t.get("/rate")
        t.expect(#t.fetch.calls()).to_equal(1)
        t.clock.advance(301)
        local resp = t.get("/rate")
        t.expect(resp.status).to_equal(500)
        t.expect(resp.error.message).to_contain("no fetch mock matched GET https://fx.example/eur")
    end)
    t.it("a mock does not widen the fetch policy", function()
        t.fetch.mock({ url = "http://10.0.0.1/a" })
        local resp = t.get("/private")
        t.expect(resp.status).to_equal(500)
        t.expect(resp.error.message).to_contain("private")
    end)
    t.it("prefix rules are normalized like the client's URL", function()
        t.fetch.mock({ url = "https://HOOKS.example:443/*", status = 204 })
        t.expect(t.get("/hook")).to_have_json({ status = 204 })
    end)
    t.it("doubles are reset between tests", function()
        t.expect(#t.fetch.calls()).to_equal(0)
    end)
    t.it("env overrides obey the allow list", function()
        t.env.set("APP_KEY", "sk_test_1")
        t.env.set("HOME", "/leak")
        t.expect(t.get("/env"):json()).to_equal({ key = "sk_test_1" })
    end)
    t.it("seeds, truncates and resets", function()
        t.db.seed("fixtures/notes.sql")
        t.db.seed({ notes = { { text = "row" } } })
        t.expect(#t.get("/api/notes"):json()).to_equal(3)
        t.db.truncate()
        t.expect(t.get("/api/notes"):json()).to_equal({})
        t.expect(function() t.db.seed("../nitr.toml") end).to_throw("is not a relative path")
        t.expect(function() t.db.seed("fixtures") end).to_throw("is not a regular file")
    end)
    t.it("a poisoned state is rebuilt with the doubles", function()
        t.expect(t.get("/hog")).to_have_status(500)
        t.fetch.mock({ url = "https://hooks.example/ping", status = 204 })
        t.expect(t.get("/hook")).to_have_json({ status = 204 })
    end)
end)

t.describe("unit", function()
    local app = t.app()
    t.it("pure modules load from the app and helpers from the tests", function()
        t.expect(notes.validate({ text = "" })).to_be_false()
        t.expect(creds.user).to_equal("ann")
    end)
    t.it("calls a handler with a fake request", function()
        local handler = app:handler("GET", "/notes/:id")
        t.expect(handler(t.fake_request({ params = { id = "999" } })).status).to_equal(404)
        local resp = handler(t.fake_request({ params = { id = "7" }, query = { expand = "1" }, headers = { ["X-Role"] = "admin" } }))
        t.expect(resp.body).to_match('"q":"1"')
        t.expect(resp.body).to_match('"role":"admin"')
        -- The response matchers read a handler's own table as well.
        t.expect(resp).to_have_json({ id = "7", q = "1" })
        t.expect(resp).to_have_header("content-type", "application/json")
    end)
    t.it("dispatches through the router", function()
        local resp = app:dispatch("GET", "/notes/7", t.fake_request({ path = "/notes/7" }))
        t.expect(resp.body).to_match('"id":"7"')
        t.expect(app:dispatch("DELETE", "/notes/7", t.fake_request()).status).to_equal(405)
        t.expect(app:dispatch("GET", "/nope", t.fake_request()).status).to_equal(404)
        t.expect(app:routes()[1]).to_match_object({ method = "GET", path = "/cookies", file = "app.lua" })
    end)
    t.it("a route registered in the test state is not served", function()
        local extra = nitr.app()
        require("helpers.extra_routes")(extra)
        t.expect(t.get("/only-in-test")).to_have_status(404)
    end)
    t.it("reads the handler's nitr.cfg", function()
        t.expect(nitr.cfg.session_secret).to_equal("0123456789abcdef-secret")
    end)
end)
"#;

/// The client, the doubles, the fixtures and the unit tools against a
/// real application with a database, `fetch`, the cache and `env`.
#[cfg(all(feature = "db", feature = "fetch"))]
#[test]
fn the_client_doubles_fixtures_and_unit_tools_hold_end_to_end() {
    require_runnable_binary!();
    let dir = app(
        "doubles",
        &[
            ("nitr.toml", DOUBLES_TOML),
            (
                "config.lua",
                "return { session_secret = \"0123456789abcdef-secret\" }\n",
            ),
            (
                "migrations/001_init.sql",
                "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL);\n",
            ),
            (
                "lib/notes.lua",
                "local M = {}\nfunction M.validate(d)\n  if type(d) ~= \"table\" then error(\"table expected\", 2) end\n  if d.text == nil or d.text == \"\" then return false, { code = \"TEXT_REQUIRED\" } end\n  return true\nend\nreturn M\n",
            ),
            ("app.lua", DOUBLES_APP),
            (
                "tests/helpers/auth.lua",
                "return { user = \"ann\", pass = \"secret\" }\n",
            ),
            (
                "tests/helpers/extra_routes.lua",
                "return function(app) app:get(\"/only-in-test\", function() return nitr.text(\"x\") end) end\n",
            ),
            (
                "tests/fixtures/notes.sql",
                "INSERT INTO notes (text) VALUES ('one'), ('two');\n",
            ),
            ("tests/doubles_test.lua", DOUBLES_TEST),
        ],
    );
    std::fs::create_dir_all(dir.join("data")).expect("data dir");
    let migrate = run_in(dir.as_ref(), &["migrate"]);
    assert_eq!(migrate.code, Some(0), "{}", migrate.stderr);
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(0), "{}\n{}", out.stdout, out.stderr);
    assert_has(&out.stdout, &["23 passed, 0 failed"]);
    // The helper directory is a require root, never a test file.
    assert!(!out.stdout.contains("auth.lua"), "{}", out.stdout);
}

/// The clock and the cache never carry over from one file to the next.
#[test]
fn the_clock_and_cache_reset_between_files() {
    require_runnable_binary!();
    let dir = app(
        "clock-files",
        &[
            (
                "nitr.toml",
                "handler_script = \"app.lua\"\n[std]\nfeatures = [\"json\", \"http\", \"time\", \"cache\"]\n",
            ),
            ("app.lua", MINIMAL_APP),
            (
                "tests/a_test.lua",
                r#"local t = nitr.test
t.it("caches while the clock is a day ahead", function()
  t.clock.advance(86400)
  nitr.cache:set("aged", 1, { ttl = 60 })
  t.expect(nitr.cache:get("aged")).to_equal(1)
end)
t.it("does not inherit an entry from a day that never came", function()
  t.expect(nitr.cache:get("aged")).to_be_nil()
end)
t.it("leaves the clock set", function()
  nitr.cache:set("k", 1)
  t.clock.set(1000)
  t.expect(nitr.time.now()).to_equal(1000)
end)
"#,
            ),
            (
                "tests/b_test.lua",
                "local t = nitr.test\nt.it(\"reads the real clock and an empty cache\", function()\n  t.expect(nitr.time.now()).to_be_greater_than(1700000000)\n  t.expect(nitr.cache:get(\"k\")).to_be_nil()\nend)\n",
            ),
        ],
    );
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(0), "{}", out.stdout);
    assert_has(&out.stdout, &["4 passed, 0 failed"]);
}

/// The snapshot `t.db.reset()` restores is the database as the
/// application boots into it: a table the configuration script creates
/// (no migrations at all) survives a reset, and rows a test wrote do not.
#[cfg(feature = "db")]
#[test]
fn a_reset_keeps_what_the_config_script_created() {
    require_runnable_binary!();
    let dir = app(
        "config-schema",
        &[
            (
                "nitr.toml",
                "handler_script = \"app.lua\"\nconfig_script = \"config.lua\"\n[database]\npath = \"data/app.db\"\n[std]\nfeatures = [\"json\", \"http\", \"db\"]\n",
            ),
            (
                "config.lua",
                "local db = ...\ndb:execute(\"CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT)\")\nreturn {}\n",
            ),
            (
                "app.lua",
                "local app = nitr.app()\napp:get(\"/count\", function() return nitr.json(nitr.db:query_row(\"SELECT count(*) AS n FROM items\")) end)\nreturn app\n",
            ),
            (
                "tests/reset_test.lua",
                r#"local t = nitr.test
t.it("writes a row", function()
  t.db.seed({ items = { { name = "a" } } })
  t.expect(t.get("/count"):json().n).to_equal(1)
end)
t.it("resets to an empty but existing table", function()
  t.db.reset()
  t.expect(t.get("/count")).to_have_json({ n = 0 })
end)
"#,
            ),
        ],
    );
    std::fs::create_dir_all(dir.join("data")).expect("data dir");
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(0), "{}\n{}", out.stdout, out.stderr);
    assert_has(&out.stdout, &["2 passed, 0 failed"]);
}

/// An upload directory inside the tests directory would make an upload a
/// loadable module in test states: `nitr test` refuses to start.
#[test]
fn an_upload_dir_inside_the_tests_directory_is_refused() {
    require_runnable_binary!();
    let dir = app(
        "upload-in-tests",
        &[
            (
                "nitr.toml",
                "handler_script = \"app/app.lua\"\n[multipart]\nupload_dir = \"tests/uploads\"\n",
            ),
            ("app/app.lua", MINIMAL_APP),
            (
                "tests/a_test.lua",
                "local t = nitr.test\nt.it(\"x\", function() end)\n",
            ),
        ],
    );
    std::fs::create_dir_all(dir.join("tests/uploads")).expect("uploads");
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(1));
    assert_has(
        &out.stderr,
        &["is inside [testing] dir", "loadable Lua module"],
    );
}

/// Every name the framework puts under `nitr.test` is described in
/// `nitr-api.toml`, so the generated types and reference cover it.
#[test]
fn every_nitr_test_entry_is_described() {
    require_runnable_binary!();
    let dir = app(
        "api-walk",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            (
                "tests/walk_test.lua",
                r#"local function walk(prefix, tbl, seen)
    for k, v in pairs(tbl) do
        if type(k) == "string" and k:sub(1, 1) ~= "_" then
            print("API " .. prefix .. "." .. k)
            if type(v) == "table" and not seen[v] then
                seen[v] = true
                walk(prefix .. "." .. k, v, seen)
            end
        end
    end
end
walk("nitr.test", nitr.test, {})
"#,
            ),
        ],
    );
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(0), "{}", out.stdout);
    let known = nitr_cli::apidef::parse().expect("api").known_paths();
    let missing: Vec<&str> = out
        .stdout
        .lines()
        .filter_map(|line| line.strip_prefix("API "))
        .filter(|path| !known.contains(*path))
        .collect();
    assert!(
        out.stdout.contains("API nitr.test.fetch.mock"),
        "the walk ran: {}",
        out.stdout
    );
    assert!(
        missing.is_empty(),
        "nitr.test entries missing from nitr-api.toml: {missing:?}"
    );
}

/// Adversarial row D5: a group whose tests `--filter` removed runs
/// neither its `before_all` nor its `after_all`.
#[test]
fn a_filtered_group_runs_no_group_hooks() {
    require_runnable_binary!();
    let dir = app(
        "filtered-hooks",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            (
                "tests/hooks_test.lua",
                r#"local t = nitr.test
local ran = {}
t.describe("group", function()
    t.before_all(function() ran[#ran + 1] = "before_all" end)
    t.after_all(function() ran[#ran + 1] = "after_all" end)
    t.it("filtered away", function() end)
end)
t.it("kept sees no group hook", function()
    t.expect(ran).to_equal({})
end)
"#,
            ),
        ],
    );
    let out = run_in(dir.as_ref(), &["test", "--filter", "kept"]);
    assert_eq!(out.code, Some(0), "{}", out.stdout);
    assert_has(
        &out.stdout,
        &[
            "ok   kept sees no group hook",
            "1 passed, 0 failed, 1 filtered out",
        ],
    );
}

/// Adversarial row B4: a fake request's body is what the test wrote, and
/// the request's own parsers keep their bounds on it.
#[test]
fn a_fake_request_body_keeps_the_parser_bounds() {
    require_runnable_binary!();
    let dir = app(
        "fake-bounds",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            (
                "tests/fake_test.lua",
                r#"local t = nitr.test
t.it("a deep JSON body is an error, not a crash", function()
    local deep = string.rep("[", 5000) .. string.rep("]", 5000)
    local req = t.fake_request({ method = "POST", body = deep })
    t.expect(function() return req:json() end).to_throw("recursion limit")
end)
"#,
            ),
        ],
    );
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(0), "{}", out.stdout);
    assert_has(&out.stdout, &["1 passed, 0 failed"]);
}

/// A bare-assert file shows the logs of the request that failed it, a
/// file whose top level exhausts the memory limit fails alone, and the
/// files after it still run. The hog takes 1 MiB a step so the 8 MiB limit
/// trips in a few steps, far inside the 500 ms budget: with 64-byte steps
/// it took about 200 ms here, and a slower machine timed out first, which
/// is a different failure (the file's registered test then runs).
#[test]
fn a_broken_file_fails_alone_and_shows_its_logs() {
    require_runnable_binary!();
    let dir = app(
        "broken-files",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            (
                "tests/a_bare_test.lua",
                "local r = nitr.test.request(\"GET\", \"/boom\")\nassert(r.status == 200, \"bare status \" .. r.status)\n",
            ),
            (
                "tests/b_hog_test.lua",
                "nitr.test.it(\"never registered in time\", function() end)\nhog = {}\nfor i = 1, 1e8 do hog[i] = (\"x\"):rep(1024 * 1024) end\n",
            ),
            (
                "tests/c_after_test.lua",
                "nitr.test.it(\"still runs\", function() end)\n",
            ),
        ],
    );
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(1), "{}", out.stdout);
    assert_has(
        &out.stdout,
        &[
            "FAIL a_bare_test.lua",
            "bare status 500",
            "logs:",
            "ERROR nitr_http::handler: handler failed",
            "b_hog_test.lua (outside any test)",
            "c_after_test.lua\n  ok   still runs",
            "1 passed, 2 failed (3 file(s),",
        ],
    );
}

/// A named `[testing] database` is recreated at the start of every run,
/// so a keyed seed applies cleanly each time (it failed, or doubled, on a
/// file carried over), the file is kept afterwards for inspection, and
/// pointing it at `[database] path` is refused.
#[cfg(feature = "db")]
#[test]
fn a_named_test_database_is_seeded_once_and_never_the_live_one() {
    require_runnable_binary!();
    let dir = app(
        "named-db",
        &[
            (
                "nitr.toml",
                "handler_script = \"app.lua\"\n[database]\npath = \"data/app.db\"\n[testing]\ndatabase = \"data/test.db\"\nseed = \"tests/fixtures/seed.sql\"\n[std]\nfeatures = [\"json\", \"http\", \"db\"]\n",
            ),
            (
                "migrations/001_items.sql",
                "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);\n",
            ),
            (
                "tests/fixtures/seed.sql",
                "INSERT INTO items (id, name) VALUES (1, 'ann');\n",
            ),
            (
                "app.lua",
                "local app = nitr.app()\napp:get(\"/count\", function() return nitr.json(nitr.db:query_row(\"SELECT count(*) AS n FROM items\")) end)\nreturn app\n",
            ),
            (
                "tests/seed_test.lua",
                "local t = nitr.test\nt.it(\"sees the seeded row once\", function()\n  t.expect(t.get(\"/count\")).to_have_json({ n = 1 })\nend)\n",
            ),
        ],
    );
    std::fs::create_dir_all(dir.join("data")).expect("data dir");
    for run in 1..=2 {
        let out = run_in(dir.as_ref(), &["test"]);
        assert_eq!(
            out.code,
            Some(0),
            "run {run}: {}\n{}",
            out.stdout,
            out.stderr
        );
        assert_has(&out.stdout, &["1 passed, 0 failed"]);
        assert!(dir.join("data/test.db").is_file(), "kept after run {run}");
    }

    let toml = dir.join("nitr.toml");
    let cfg = std::fs::read_to_string(&toml).expect("read");
    std::fs::write(&toml, cfg.replace("data/test.db", "data/../data/app.db")).expect("write");
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(1));
    assert_has(&out.stderr, &["is [database] path"]);
}

/// Adversarial row C3: a streaming body is collected to its end inside
/// `t.request`, so the producer's log lines belong to the test that read
/// the stream, and none of them reach the next test.
#[test]
fn a_streams_log_lines_belong_to_the_test_that_read_it() {
    require_runnable_binary!();
    let dir = app(
        "stream-logs",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            (
                "tests/stream_test.lua",
                r#"local t = nitr.test
local function chunk_lines()
    local n = 0
    for _, entry in ipairs(t.logs()) do
        if entry.message == "chunk sent" then n = n + 1 end
    end
    return n
end
t.it("reads the stream", function()
    t.expect(#t.get("/stream-logs"):sse()).to_equal(3)
    t.expect(chunk_lines()).to_equal(3)
end)
t.it("starts with none of its lines", function()
    t.expect(chunk_lines()).to_equal(0)
end)
"#,
            ),
        ],
    );
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(0), "{}", out.stdout);
    assert_has(&out.stdout, &["2 passed, 0 failed"]);
}

/// Adversarial row C4: `before_all` runs inside the first test's call, so
/// a slow but healthy setup is charged to that test (and marked `slow`)
/// rather than killed or hidden; the group's other tests do not pay it.
#[test]
fn a_slow_before_all_is_charged_to_the_first_test() {
    require_runnable_binary!();
    let dir = app(
        "slow-before-all",
        &[
            (
                "nitr.toml",
                &format!("{MINIMAL_TOML}\n[testing]\nslow_ms = 100\n"),
            ),
            ("app.lua", MINIMAL_APP),
            (
                "tests/setup_test.lua",
                r#"local t = nitr.test
t.describe("heavy setup", function()
    t.before_all(function()
        local started = nitr.time.monotonic()
        while nitr.time.monotonic() - started < 0.2 do end
    end)
    t.it("pays for the setup", function() end)
    t.it("does not", function() end)
end)
"#,
            ),
        ],
    );
    let out = run_in(dir.as_ref(), &["test"]);
    assert_eq!(out.code, Some(0), "{}", out.stdout);
    let line = |name: &str| {
        out.stdout
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("no line for {name:?}:\n{}", out.stdout))
            .to_string()
    };
    let first = line("pays for the setup");
    assert!(
        first.starts_with("  ok   ") && first.ends_with(" ms, slow)"),
        "{first}"
    );
    let ms: u64 = first
        .rsplit_once('(')
        .and_then(|(_, t)| t.split(' ').next())
        .and_then(|n| n.parse().ok())
        .expect("a duration");
    assert!(ms >= 200, "the setup's time is in the first test: {first}");
    let second = line("does not");
    assert!(
        second.starts_with("  ok   ") && !second.contains("slow"),
        "{second}"
    );
}

/// With a machine reporter on stdout, `--watch` keeps its own chatter on
/// stderr: stdout stays one parseable document per run.
#[cfg(unix)]
#[test]
fn watch_keeps_a_json_stdout_clean() {
    require_runnable_binary!();
    let dir = app(
        "watch-json",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            (
                "tests/one_test.lua",
                "local t = nitr.test\nt.it(\"passes\", function() t.expect(1).to_equal(1) end)\n",
            ),
        ],
    );
    let out_path = dir.join("stdout.log");
    let err_path = dir.join("stderr.log");
    let mut child = nitr()
        .current_dir(dir.as_ref())
        .args(["test", "--watch", "--reporter", "json"])
        .env_remove("RUST_LOG")
        .env("NO_COLOR", "1")
        .stdout(std::fs::File::create(&out_path).expect("stdout file"))
        .stderr(std::fs::File::create(&err_path).expect("stderr file"))
        .spawn()
        .expect("spawn nitr test --watch");
    let read = |path: &Path| std::fs::read_to_string(path).unwrap_or_default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !(read(&out_path) + &read(&err_path)).contains("watching for changes") {
        assert!(
            std::time::Instant::now() < deadline,
            "first run: {}",
            read(&out_path)
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    super::signal(child.id(), "-INT");
    let _ = child.wait();
    let stdout = read(&out_path);
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "stdout must be the JSON report alone:\n{stdout}"
    );
    assert!(read(&err_path).contains("watching for changes"));
}

/// A Ctrl-C pressed while `--watch` re-runs the suite stops the session
/// there, with exit 0. Tokio's SIGINT handler stays installed after the
/// first wait, so a listener made only for the waits used to swallow a
/// press that landed mid-run: the run finished and the session waited on.
#[cfg(unix)]
#[test]
fn watch_stops_on_ctrl_c_during_a_rerun() {
    require_runnable_binary!();
    // Six tests of 250 ms each: a run is a window of about 1.5 s.
    let slow = "local t = nitr.test\nfor i = 1, 6 do\n  t.it(\"spins \" .. i, function()\n    local started = nitr.time.monotonic()\n    while nitr.time.monotonic() - started < 0.25 do end\n  end)\nend\n";
    let dir = app(
        "watch-ctrl-c",
        &[
            ("nitr.toml", MINIMAL_TOML),
            ("app.lua", MINIMAL_APP),
            ("tests/slow_test.lua", slow),
        ],
    );
    let log_path = dir.join("watch.log");
    let log = std::fs::File::create(&log_path).expect("log file");
    let mut child = nitr()
        .current_dir(dir.as_ref())
        .args(["test", "--watch"])
        .env_remove("RUST_LOG")
        .env("NO_COLOR", "1")
        .stdout(log)
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn nitr test --watch");
    let read = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let deadline = |secs| std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let poll = std::time::Duration::from_millis(50);

    let first_done = deadline(30);
    while !read().contains("watching for changes") {
        assert!(
            std::time::Instant::now() < first_done,
            "first run: {}",
            read()
        );
        std::thread::sleep(poll);
    }
    // Re-save inside the loop: one write can be lost on a slow runner.
    let rerun = deadline(30);
    let mut saves = 0u32;
    while read().matches("slow_test.lua\n").count() < 2 {
        assert!(std::time::Instant::now() < rerun, "no re-run: {}", read());
        saves += 1;
        std::fs::write(
            dir.join("tests/slow_test.lua"),
            format!("{slow}-- save {saves}\n"),
        )
        .expect("re-save");
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    super::signal(child.id(), "-INT");

    let stopped = deadline(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if std::time::Instant::now() >= stopped {
            let _ = child.kill();
            let _ = child.wait();
            panic!("Ctrl-C during a re-run was lost:\n{}", read());
        }
        std::thread::sleep(poll);
    };
    assert_eq!(status.code(), Some(0), "{}", read());
    assert_eq!(
        read().matches(" passed, ").count(),
        1,
        "the interrupted re-run printed no verdict:\n{}",
        read()
    );
}
