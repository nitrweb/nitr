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
        memory_limit: MEMORY_LIMIT,
        dev_mode: false,
        exec_timeout,
        package_dir: None,
    })
    .expect("runtime")
}

/// A `package`-bearing state, confined when a directory is given — the
/// single home for the options both `package` tests build on, so they
/// cannot drift apart in which libraries they enable.
fn package_runtime(package_dir: Option<PathBuf>) -> Runtime {
    Runtime::new_with(RuntimeOpts {
        libs: StdLib::MATH | StdLib::TABLE | StdLib::STRING | StdLib::PACKAGE,
        memory_limit: MEMORY_LIMIT,
        dev_mode: false,
        exec_timeout: None,
        package_dir,
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

#[test]
fn a_bare_call_script_evaluates_as_an_expression() {
    // `f()` is valid as an expression *and* as a call statement. The
    // expression parse must stay first for this shape: as a block the
    // chunk would compile fine and evaluate to nothing.
    let rt = Runtime::new().expect("runtime");
    let path = write_temp_script("call-expr.lua", "-- comment\nstring.rep('ab', 2)");
    let value = rt.eval_script(&path).expect("call expression");
    std::fs::remove_file(&path).ok();
    match value {
        Value::String(s) => assert_eq!(s.to_str().expect("utf-8").as_ref(), "abab"),
        other => panic!("expected the call's result, got {}", other.type_name()),
    }
}

#[test]
fn block_form_typos_report_the_real_line() {
    // A handler-shaped script (leading comment, then `local`): the
    // expression parse is skipped for it, and the diagnostic must still be
    // the block parse's own — line 3, the typo — exactly as when both
    // parses ran and the furthest error won.
    let rt = Runtime::new().expect("runtime");
    let path = write_temp_script(
        "block-typo.lua",
        "-- comment\nlocal ok = 1\nlodcal users = 2\nreturn {}",
    );
    let err = rt.eval_script(&path).expect_err("typo must fail the load");
    std::fs::remove_file(&path).ok();
    let message = err.to_string();
    assert!(message.contains("block-typo.lua:3"), "{message}");
    assert!(message.contains("near 'users'"), "{message}");
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

    // Filesystem, process, and debug-introspection entry points, the
    // base-library functions that read arbitrary files, and the collector
    // control. `package` is absent from the default set entirely, so
    // `require` cannot reach a search path nothing pinned.
    for name in [
        "io",
        "os",
        "debug",
        "dofile",
        "loadfile",
        "collectgarbage",
        "package",
        "require",
    ] {
        let value: Value = globals.get(name).expect("read global");
        assert!(
            value.is_nil(),
            "`{name}` must not be exposed by the default sandbox, got a {}",
            value.type_name()
        );
    }

    // The safe computational set is present — the sandbox is a policy,
    // not an accident of loading nothing.
    for name in ["math", "table", "string", "utf8", "coroutine", "pcall"] {
        let value: Value = globals.get(name).expect("read global");
        assert!(!value.is_nil(), "`{name}` must be available by default");
    }

    // `load` is a deliberate keep, not an oversight: a *text* chunk runs
    // under the same instruction hook and memory limit as the code that
    // compiled it, so it grants no authority the caller lacks. Asserted
    // positively so a later tidy-up cannot quietly remove it.
    let compiled: i64 = rt
        .lua()
        .load("return load('return 41 + 1')()")
        .eval()
        .expect("load compiles and runs a chunk");
    assert_eq!(compiled, 42, "`load` must remain available");

    // Bytecode is the exception: Lua 5.4 does not verify it, so a binary
    // chunk is a VM escape. The mode is pinned to text whatever the caller
    // passes, and `string.dump` — the way to produce bytecode — is gone.
    let (ok, err): (bool, String) = rt
        .lua()
        .load(
            r#"local f, err = load("\27LuaT\0\25\147\r\n\26\n", "bc", "b")
               return f ~= nil, tostring(err)"#,
        )
        .eval()
        .expect("eval");
    assert!(!ok, "a binary chunk must not load: {err}");
    assert!(err.contains("binary"), "the refusal must say why: {err}");
    let dump: Value = rt.lua().load("return string.dump").eval().expect("eval");
    assert!(dump.is_nil(), "`string.dump` must not be exposed");

    // The wrapper keeps `load`'s argument shape: an explicit environment
    // still applies, and an explicit `nil` environment still means "no
    // globals" rather than "the default globals".
    let (with_env, no_env): (i64, bool) = rt
        .lua()
        .load(
            r#"local f = load("return x", "chunk", "t", { x = 7 })
               local g = load("return math.pi", "chunk", "t", nil)
               local ok = pcall(g)
               return f(), not ok"#,
        )
        .eval()
        .expect("eval");
    assert_eq!(with_env, 7, "an explicit environment must be honored");
    assert!(
        no_env,
        "an explicit nil environment must not become the globals"
    );
}

/// The budget error must not be catchable: the hook's count restarts at
/// every fire, so a loop that `pcall`s a spinning closure catches every
/// trip inside the closure and never trips on its own. Without the
/// `pcall`/`xpcall`/`coroutine.resume` wrappers this test never returns.
#[tokio::test]
async fn the_execution_budget_cannot_be_caught_and_ignored() {
    for body in [
        "while true do pcall(function() while true do end end) end",
        "while true do xpcall(function() while true do end end, function(e) return e end) end",
        "while true do coroutine.resume(coroutine.create(function() while true do end end)) end",
        // The honest variant: a retry loop that can never succeed once
        // the budget is gone.
        "repeat local ok = pcall(function() while true do end end) until ok",
    ] {
        let mut rt = Runtime::new_with(RuntimeOpts {
            libs: StdLib::MATH | StdLib::TABLE | StdLib::STRING | StdLib::COROUTINE,
            memory_limit: MEMORY_LIMIT,
            dev_mode: false,
            exec_timeout: Some(Duration::from_millis(100)),
            package_dir: None,
        })
        .expect("runtime");
        let looping = eval_function(&rt, &format!("return function() {body} end"));
        let started = Instant::now();
        let err = tokio::time::timeout(
            Duration::from_secs(10),
            rt.call_function::<Value>(looping, Value::Nil),
        )
        .await
        .unwrap_or_else(|_| panic!("`{body}` escaped the budget and never returned"))
        .expect_err("must trip the budget");
        assert!(err.to_string().contains("time budget"), "`{body}`: {err}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "`{body}` took {:?} to trip a 100 ms budget",
            started.elapsed()
        );

        // A caught error *before* the deadline is still an ordinary
        // caught error: the wrappers only bite once the budget is gone.
        let caught: String = rt
            .lua()
            .load("local ok, e = pcall(error, 'plain') return tostring(ok) .. ':' .. e")
            .eval()
            .expect("eval");
        assert_eq!(caught, "false:plain");
    }
}

/// A handler that stalls in an async builtin past the budget: the outer
/// timeout fires, and the state must come back clean — the suspended
/// coroutine reset and its pending future dropped *now*, not at some
/// later collection — so the next request on the same state does not
/// inherit the previous one's in-flight work.
#[tokio::test]
async fn an_async_stall_times_out_and_the_state_recovers() {
    let mut rt = test_runtime(Some(Duration::from_millis(100)));
    // A future whose drop is observable, standing in for a fetch or a
    // database transaction left mid-flight.
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    struct Flag(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Flag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let flag = dropped.clone();
    let stall = rt
        .lua()
        .create_async_function(move |_, ()| {
            let flag = Flag(flag.clone());
            async move {
                let _held = flag;
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(())
            }
        })
        .expect("stall fn");
    rt.lua().globals().set("stall", stall).expect("set");

    let handler = eval_function(&rt, "return function() stall() return 'unreachable' end");
    let err = rt
        .call_function::<Value>(handler, Value::Nil)
        .await
        .expect_err("must time out");
    assert!(matches!(err, Error::Timeout), "got: {err}");
    assert!(
        dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the stalled future must be dropped when the call times out"
    );
    assert!(!rt.is_poisoned(), "a timeout is recoverable, not poison");

    let ok = eval_function(&rt, "return function() return 'alive' end");
    let alive: String = rt
        .call_function(ok, Value::Nil)
        .await
        .expect("the state serves the next call");
    assert_eq!(alive, "alive");
}

/// `package.loadlib` is a confinement escape that ignores `package.cpath`:
/// it takes an absolute path and calls straight into arbitrary native code.
/// It must be gone from *every* `package`-bearing state — including the
/// unconfined `package_dir: None` shape, which is the one a
/// `package_dir`-conditional scrub would leave open.
#[test]
fn package_states_cannot_load_native_modules() {
    for package_dir in [None, Some(std::env::temp_dir())] {
        let confined = package_dir.is_some();
        let rt = package_runtime(package_dir);
        let lua = rt.lua();

        let package: Table = lua.globals().get("package").expect("package table");

        let loadlib: Value = package.get("loadlib").expect("read loadlib");
        assert!(
            loadlib.is_nil(),
            "`package.loadlib` must be nil (confined: {confined}), got a {}",
            loadlib.type_name()
        );

        let cpath: String = package.get("cpath").expect("read cpath");
        assert_eq!(
            cpath, "",
            "`package.cpath` must be empty (confined: {confined})"
        );

        // `searchpath` is a filesystem existence oracle with its own
        // template argument; confinement of `package.path` never reached
        // it.
        let searchpath: Value = package.get("searchpath").expect("read searchpath");
        assert!(
            searchpath.is_nil(),
            "`package.searchpath` must be nil (confined: {confined})"
        );
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

    let rt = package_runtime(Some(pkg.clone()));
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

    // Reassigning `package.path` must not widen the search: the searcher
    // owns the directory, the string is informational.
    let widened = lua
        .load(format!(
            "package.path = '{}/?.lua' return require('outside').where",
            root.to_string_lossy()
        ))
        .eval::<String>();
    assert!(
        widened.is_err(),
        "a script must not be able to point `require` elsewhere"
    );

    // A module that is bytecode is refused: `require` compiles text only,
    // like `load` and the script loader.
    std::fs::write(pkg.join("compiled.lua"), b"\x1bLuaT\0\x19\x93\r\n\x1a\n")
        .expect("write bytecode");
    let err = lua
        .load("return require('compiled')")
        .eval::<Value>()
        .expect_err("bytecode module");
    assert!(err.to_string().contains("binary"), "got: {err}");

    // Dotted names map to directories, and `init.lua` resolves.
    std::fs::create_dir_all(pkg.join("nested/deep")).expect("mkdir nested");
    std::fs::write(
        pkg.join("nested/deep/init.lua"),
        "return { where = 'init' }",
    )
    .expect("write init");
    let init: String = lua
        .load("return require('nested.deep').where")
        .eval()
        .expect("require init");
    assert_eq!(init, "init");

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
