// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr test`: run the application's Lua tests against an in-process
//! server.

use std::path::PathBuf;

use anyhow::{Context as _, bail};
use nitr::{BuiltinsEnv, Config, Runtime, Server};

/// Runs `*.lua` files from the tests directory against an in-process
/// server: each file gets a fresh sandboxed state with the configured
/// builtins plus a `test` global whose `test.request(method, path, opts?)`
/// dispatches through the real router/middleware/handler path.
/// The Lua test framework (`t.describe`/`t.it`/`t.expect`/hooks), loaded
/// into each test state before its file runs.
const TEST_FRAMEWORK: &str = include_str!("../test_framework.lua");

/// One `t.it(...)` outcome, read back from the state after the file ran.
struct TestOutcome {
    name: String,
    ok: bool,
    skipped: bool,
    err: Option<String>,
}

/// Reads `nitr.test._results` from a finished test state.
fn collect_outcomes(lua: &mlua::Lua) -> anyhow::Result<Vec<TestOutcome>> {
    let results: mlua::Table = nitr::nitr_table(lua)?
        .get::<mlua::Table>("test")?
        .get("_results")?;
    let mut out = Vec::new();
    for entry in results.sequence_values::<mlua::Table>() {
        let entry = entry?;
        out.push(TestOutcome {
            name: entry.get("name")?,
            ok: entry.get::<Option<bool>>("ok")?.unwrap_or(false),
            skipped: entry.get::<Option<bool>>("skipped")?.unwrap_or(false),
            err: entry.get("err")?,
        });
    }
    Ok(out)
}

pub(crate) async fn run_tests(cfg: Config, filter: Option<&str>) -> anyhow::Result<usize> {
    let tests_dir = cfg.testing.dir.clone();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&tests_dir)
        .with_context(|| format!("cannot read the tests directory {}", tests_dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "lua"))
        .collect();
    files.sort();
    if files.is_empty() {
        bail!("no *.lua test files in {}", tests_dir.display());
    }

    let builtins = cfg.builtins()?;
    let env = BuiltinsEnv {
        templates_dir: cfg.templating.dir.clone(),
        database: cfg.database.as_ref().map(|db| db.path.clone()),
        sqlite: cfg
            .database
            .as_ref()
            .map(|db| db.pragmas())
            .unwrap_or_default(),
        fetch: cfg.fetch.options(),
        env: cfg.env_options(),
        // Tests get their own cache: a test file must not see entries a
        // previous one left behind.
        cache: Some(nitr::stdlib::Cache::new(cfg.cache_options())),
    };
    let opts = cfg.runtime_opts()?;

    let server = Server::builder().config(cfg).build().await?;
    let client = server.test_client();

    let (mut passed, mut failed, mut skipped) = (0usize, 0usize, 0usize);
    for file in &files {
        // A fresh state per file: tests are isolated from each other but
        // share the server (and its database) like real requests do.
        let mut rt = Runtime::new_with(runtime_opts_like(&opts)?)?;
        nitr::stdlib::register_builtins(rt.lua(), builtins, &env)?;
        register_test_global(rt.lua(), client.clone())?;

        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file.display().to_string());

        // The framework rides on `nitr.test`, with the runner's filter and
        // the file name injected before it loads.
        let test_table: mlua::Table = nitr::nitr_table(rt.lua())?.get("test")?;
        test_table.set("_filter", filter.unwrap_or_default())?;
        test_table.set("_file", name.as_str())?;
        rt.lua()
            .load(TEST_FRAMEWORK)
            .set_name("@nitr-test-framework")
            .exec()
            .context("cannot load the test framework")?;

        let source = std::fs::read(file)
            .with_context(|| format!("cannot read test file {}", file.display()))?;
        // Named after the real file, so assertion failures point at it.
        let chunk = match rt
            .lua()
            .load(source)
            .set_name(format!("@{}", file.display()))
            .into_function()
        {
            Ok(chunk) => chunk,
            Err(err) => {
                failed += 1;
                println!("{} {name}\n     {err}", nitr::diag::console_fail("FAIL"));
                continue;
            }
        };
        let file_err = rt.call_function::<mlua::Value>(chunk, ()).await.err();

        let outcomes = collect_outcomes(rt.lua())?;
        if outcomes.is_empty() {
            // The pre-framework style: a bare script of asserts. It passes
            // by running to completion.
            match file_err {
                None => {
                    passed += 1;
                    println!("{} {name}", nitr::diag::console_ok("PASS"));
                }
                Some(err) => {
                    failed += 1;
                    println!("{} {name}\n     {err}", nitr::diag::console_fail("FAIL"));
                }
            }
            continue;
        }
        println!("{name}");
        for outcome in outcomes {
            if outcome.skipped {
                skipped += 1;
                continue;
            }
            if outcome.ok {
                passed += 1;
                println!("  {}   {}", nitr::diag::console_ok("ok"), outcome.name);
            } else {
                failed += 1;
                println!("  {} {}", nitr::diag::console_fail("FAIL"), outcome.name);
                if let Some(err) = outcome.err {
                    for line in err.lines() {
                        println!("       {line}");
                    }
                }
            }
        }
        // A file that also failed outside any `it` (e.g. in `describe`
        // setup) is its own failure, on top of whatever tests recorded.
        if let Some(err) = file_err {
            failed += 1;
            println!(
                "  {} {name} (outside any test)\n     {err}",
                nitr::diag::console_fail("FAIL")
            );
        }
    }
    // The verdict at a glance: green when everything passed, the failure
    // count red when anything did not.
    let passed_part = nitr::diag::console_ok(&format!("{passed} passed"));
    let failed_part = match failed {
        0 => format!("{failed} failed"),
        _ => nitr::diag::console_fail(&format!("{failed} failed")),
    };
    match skipped {
        0 => println!("\n{passed_part}, {failed_part} ({} file(s))", files.len()),
        _ => println!(
            "\n{passed_part}, {failed_part}, {skipped} filtered out ({} file(s))",
            files.len()
        ),
    }
    Ok(failed)
}

/// `RuntimeOpts` is not `Clone`; rebuild an equivalent one.
fn runtime_opts_like(opts: &nitr::RuntimeOpts) -> anyhow::Result<nitr::RuntimeOpts> {
    Ok(nitr::RuntimeOpts {
        libs: opts.libs,
        memory_limit: opts.memory_limit,
        dev_mode: opts.dev_mode,
        exec_timeout: opts.exec_timeout,
        package_dir: opts.package_dir.clone(),
    })
}

/// Mounts `nitr.test` for test scripts: `nitr.test.request(method, path,
/// opts?)` with opts `{ headers = {...}, body = "..." }` returning
/// `{ status, headers, body }`.
fn register_test_global(lua: &mlua::Lua, client: nitr::testing::TestClient) -> anyhow::Result<()> {
    let test = lua.create_table()?;
    test.set(
        "request",
        lua.create_async_function(
            move |lua, (method, path, opts): (String, String, Option<mlua::Table>)| {
                let client = client.clone();
                async move {
                    use mlua::ExternalResult as _;
                    let mut headers = Vec::new();
                    let mut body = None;
                    if let Some(opts) = opts {
                        if let Some(header_table) = opts.get::<Option<mlua::Table>>("headers")? {
                            for pair in header_table.pairs::<String, String>() {
                                let (k, v) = pair?;
                                headers.push((k, v));
                            }
                        }
                        if let Some(raw) = opts.get::<Option<mlua::LuaString>>("body")? {
                            body = Some(bytes::Bytes::copy_from_slice(&raw.as_bytes()));
                        }
                        // `json = <value>` encodes the body and sets the
                        // content type, so tests stop hand-encoding both.
                        let json = opts.get::<mlua::Value>("json")?;
                        if !json.is_nil() {
                            let encoded = serde_json::to_vec(&json).into_lua_err()?;
                            body = Some(bytes::Bytes::from(encoded));
                            if !headers
                                .iter()
                                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                            {
                                headers.push(("content-type".into(), "application/json".into()));
                            }
                        }
                    }
                    let resp = client
                        .request(&method, &path, &headers, body)
                        .await
                        .into_lua_err()?;

                    let table = lua.create_table()?;
                    table.set("status", resp.status)?;
                    let header_table = lua.create_table()?;
                    for (k, v) in &resp.headers {
                        header_table.set(k.as_str(), v.as_str())?;
                    }
                    table.set("headers", header_table)?;
                    table.set("body", lua.create_string(&resp.body)?)?;
                    // resp:json() — the decoded body, so a test reads
                    // `resp:json().name` instead of decoding by hand.
                    table.set(
                        "json",
                        lua.create_function(|lua, this: mlua::Table| {
                            let body: mlua::LuaString = this.get("body")?;
                            let value =
                                serde_json::from_slice::<serde_json::Value>(&body.as_bytes())
                                    .into_lua_err()?;
                            use mlua::LuaSerdeExt as _;
                            lua.to_value(&value)
                        })?,
                    )?;
                    Ok(table)
                }
            },
        )?,
    )?;
    nitr::nitr_table(lua)?.set("test", test)?;
    Ok(())
}
