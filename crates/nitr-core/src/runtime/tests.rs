// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;

fn write_temp_script(name: &str, content: &str) -> PathBuf {
    // `fs::write` truncates before writing, so a path two tests share is
    // a race; the counter keeps every call on its own file.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("nitr-rt-test-{}-{id}-{name}", std::process::id()));
    std::fs::write(&path, content).expect("write temp script");
    path
}

fn test_runtime(exec_timeout: Option<Duration>) -> Runtime {
    Runtime::new_with(RuntimeOpts {
        libs: StdLib::MATH | StdLib::TABLE | StdLib::STRING,
        memory_limit: 8 * 1024 * 1024,
        dev_mode: false,
        exec_timeout,
        package_dir: None,
    })
    .expect("runtime")
}

fn eval_function(rt: &Runtime, src: &str) -> Function {
    rt.lua().load(src).eval().expect("eval handler function")
}

#[test]
fn expression_form_typos_report_the_real_line() {
    // An expression-form script (`function(...) ... end`, no `return`)
    // with a typo mid-body. mlua's own `eval` would report its block
    // fallback — "<name> expected" at the `function(` line — masking
    // the actual position; the dual-parse must surface line 4.
    let rt = Runtime::new().expect("runtime");
    let path = write_temp_script(
        "expr-typo.lua",
        "-- comment\nfunction(db)\n    local ok = 1\n    lodcal users = 2\n    return {}\nend",
    );
    let err = rt.eval_script(&path).expect_err("typo must fail the load");
    let message = err.to_string();
    assert!(message.contains("expr-typo.lua:4"), "{message}");
    assert!(message.contains("near 'users'"), "{message}");
    // The caret spans the token the parser stopped at (`users`, five
    // wide); exact column alignment is covered by the snippet unit test.
    assert!(message.contains("^^^^^"), "{message}");
    std::fs::remove_file(&path).ok();
}

#[test]
fn both_script_forms_still_evaluate() {
    let rt = Runtime::new().expect("runtime");
    // Expression form.
    let path = write_temp_script("expr-ok.lua", "function(x)\n    return x\nend");
    assert!(matches!(
        rt.eval_script(&path).expect("expression form"),
        Value::Function(_)
    ));
    std::fs::remove_file(&path).ok();
    // Statement-block form (handler scripts).
    let path = write_temp_script("block-ok.lua", "local t = { ok = true }\nreturn t");
    assert!(matches!(
        rt.eval_script(&path).expect("block form"),
        Value::Table(_)
    ));
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn function_calls_round_trip() {
    let mut rt = test_runtime(Some(Duration::from_secs(5)));
    let f = eval_function(
        &rt,
        "return function(req) return { status = 200, body = req } end",
    );

    // The cached coroutine must keep working across calls.
    for _ in 0..3 {
        let resp = rt
            .call_function::<Table>(f.clone(), "ping")
            .await
            .expect("call function");
        assert_eq!(resp.get::<String>("body").expect("body"), "ping");
    }
}

#[tokio::test]
async fn cpu_bound_loops_hit_the_instruction_hook() {
    let mut rt = test_runtime(Some(Duration::from_millis(100)));
    let looping = eval_function(&rt, "return function() while true do end end");

    let err = rt
        .call_function::<Table>(looping, Value::Nil)
        .await
        .expect_err("must time out");
    assert!(err.to_string().contains("time budget"), "got: {err}");

    // The state must survive and serve the next call after a reset.
    let ok = eval_function(&rt, "return function() return { body = 'alive' } end");
    let resp = rt
        .call_function::<Table>(ok, Value::Nil)
        .await
        .expect("recovered");
    assert_eq!(resp.get::<String>("body").expect("body"), "alive");
}

/// The default library set is the sandbox: nothing that reaches the
/// filesystem, the process, or the VM internals may exist as a global.
/// This is the test that makes flipping a bit in the default `StdLib`
/// set a visible failure instead of an invisible policy change.
#[test]
fn the_default_library_set_carries_no_ambient_authority() {
    let rt = Runtime::new().expect("runtime");
    let globals = rt.lua().globals();

    // Filesystem, process, and debug-introspection entry points, plus the
    // base-library functions that read arbitrary files.
    for name in ["io", "os", "debug", "dofile", "loadfile"] {
        let value: Value = globals.get(name).expect("read global");
        assert!(
            value.is_nil(),
            "`{name}` must not be exposed by the default sandbox, got a {}",
            value.type_name()
        );
    }

    // The safe computational set is present — the sandbox is a policy,
    // not an accident of loading nothing.
    for name in [
        "math",
        "table",
        "string",
        "utf8",
        "coroutine",
        "require",
        "pcall",
    ] {
        let value: Value = globals.get(name).expect("read global");
        assert!(!value.is_nil(), "`{name}` must be available by default");
    }
}

/// `require` confinement (`RuntimeOpts::package_dir`): `package.path` is
/// pinned to the configured directory, `package.cpath` is emptied (no
/// native modules), modules inside load, and every escape shape misses.
#[tokio::test]
async fn require_is_confined_to_the_package_dir() {
    // A package dir with one module, and a would-be target right above it.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("nitr-rt-confine-{}-{id}", std::process::id()));
    let pkg = root.join("pkg");
    std::fs::create_dir_all(&pkg).expect("mkdir pkg");
    std::fs::write(pkg.join("inside.lua"), "return { where = 'inside' }").expect("write inside");
    std::fs::write(root.join("outside.lua"), "return { where = 'outside' }")
        .expect("write outside");

    let rt = Runtime::new_with(RuntimeOpts {
        libs: StdLib::MATH | StdLib::TABLE | StdLib::STRING | StdLib::PACKAGE,
        memory_limit: 8 * 1024 * 1024,
        dev_mode: false,
        exec_timeout: None,
        package_dir: Some(pkg.clone()),
    })
    .expect("runtime");
    let lua = rt.lua();

    // The pinned search path and the emptied native-module path.
    let dir = pkg.to_string_lossy();
    let path: String = lua
        .load("return package.path")
        .eval()
        .expect("package.path");
    assert_eq!(path, format!("{dir}/?.lua;{dir}/?/init.lua"));
    let cpath: String = lua
        .load("return package.cpath")
        .eval()
        .expect("package.cpath");
    assert_eq!(cpath, "", "native module loading must be disabled");

    // A module inside the directory loads.
    let inside: String = lua
        .load("return require('inside').where")
        .eval()
        .expect("require inside");
    assert_eq!(inside, "inside");

    // Escape shapes: the sibling exists on disk, so a hole in the
    // confinement would *succeed* here rather than 404 into a false pass.
    for escape in ["outside", "../outside", "..outside", "pkg/../../outside"] {
        let result = lua
            .load(format!("return require('{escape}').where"))
            .eval::<String>();
        assert!(
            result.is_err(),
            "require({escape:?}) must not reach outside the package dir"
        );
    }

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn modules_mount_under_nitr_ext_and_reject_collisions() {
    let rt = test_runtime(None);
    rt.register_module("greet", |lua| {
        let t = lua.create_table()?;
        t.set(
            "hello",
            lua.create_function(|_, name: String| Ok(format!("hi {name}")))?,
        )?;
        Ok(t)
    })
    .expect("register module");

    let out: String = rt
        .lua()
        .load("return nitr.ext.greet.hello('nitr')")
        .eval()
        .expect("call module");
    assert_eq!(out, "hi nitr");

    // A second mount under the same name must fail loudly.
    let err = rt
        .register_module("greet", |lua| lua.create_table())
        .expect_err("collision");
    assert!(err.to_string().contains("already exists"), "got: {err}");
}

#[tokio::test]
async fn config_accepts_plain_script() {
    // Handler-style shape: top-level statements, args via `...`,
    // trailing `return { ... }` — no `function(...)` wrapper.
    let cfg_script = write_temp_script(
        "cfg_plain.lua",
        "local greeting = ...\n\
             local upper = greeting:upper()\n\
             return { greeting = greeting, upper = upper }",
    );
    let mut rt = test_runtime(None);
    rt.register_cfg_fn(&cfg_script, "hi")
        .await
        .expect("run plain config script");
    std::fs::remove_file(&cfg_script).ok();

    let cfg = rt.cfg().expect("cfg table");
    assert_eq!(cfg.get::<String>("greeting").expect("greeting"), "hi");
    assert_eq!(cfg.get::<String>("upper").expect("upper"), "HI");
}

#[tokio::test]
async fn config_rejects_non_table_result() {
    let cfg_script = write_temp_script("cfg_bad.lua", "return 42");
    let mut rt = test_runtime(None);
    let err = rt
        .register_cfg_fn(&cfg_script, Value::Nil)
        .await
        .expect_err("number is not a valid configuration");
    std::fs::remove_file(&cfg_script).ok();
    assert!(
        err.to_string().contains("must return a table"),
        "got: {err}"
    );
}

#[tokio::test]
async fn config_rejects_the_dropped_wrapper_form() {
    // The old `function(db) ... end` shape must fail with a message
    // that points migrations at the plain-script form.
    let cfg_script = write_temp_script(
        "cfg_wrapped.lua",
        "function(db)\n    return { ok = true }\nend",
    );
    let mut rt = test_runtime(None);
    let err = rt
        .register_cfg_fn(&cfg_script, Value::Nil)
        .await
        .expect_err("wrapper form is no longer supported");
    std::fs::remove_file(&cfg_script).ok();
    let message = err.to_string();
    assert!(message.contains("no longer supported"), "got: {message}");
    assert!(message.contains("local db = ..."), "got: {message}");
}

#[tokio::test]
async fn config_snapshot_round_trips() {
    let cfg_script = write_temp_script("cfg.lua", "return { greeting = 'hi', nested = { n = 7 } }");
    let mut source = test_runtime(None);
    source
        .register_cfg_fn(&cfg_script, Value::Nil)
        .await
        .expect("run config script");
    std::fs::remove_file(&cfg_script).ok();

    let snapshot = source
        .cfg_snapshot()
        .expect("snapshot")
        .expect("config present");
    let mut target = test_runtime(None);
    target.set_cfg_snapshot(&snapshot).expect("inject snapshot");
    let cfg = target.cfg().expect("cfg table");
    assert_eq!(cfg.get::<String>("greeting").expect("greeting"), "hi");
    let nested: Table = cfg.get("nested").expect("nested");
    assert_eq!(nested.get::<i64>("n").expect("n"), 7);
}
