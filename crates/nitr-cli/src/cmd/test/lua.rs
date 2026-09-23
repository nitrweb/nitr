// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The Rust half of `nitr.test`, mounted only in the runner's test
//! states: the request client and its response table, the doubles'
//! setters (`fetch`, `clock`, `env`), the log view, the database fixtures,
//! the fake request, the in-state app, and the `_site` hook the framework
//! registers tests with.
//!
//! Doubles cross into the server's states as data (rules, an offset,
//! strings) through the shared [`Doubles`] app data — never as Lua
//! functions, which cannot cross states.

#[cfg(feature = "db")]
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "db")]
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use mlua::{ExternalResult as _, Lua, LuaSerdeExt as _, Table, Value, Variadic};
use nitr::stdlib::testing::{Doubles, FetchRule, UrlMatch};
use nitr::testing::{TestClient, TestRequest, TestResponse};

use super::capture;

/// Named registry slots for the shared metatables.
const RESPONSE_MT: &str = "nitr::test::response_mt";
const HEADERS_MT: &str = "nitr::test::headers_mt";

/// The name the framework chunk is loaded under; `_site` skips its frames.
pub(super) const FRAMEWORK_CHUNK: &str = "@nitr-test-framework";

/// The database behind `t.db`, when the application has one.
#[cfg(feature = "db")]
pub(super) struct DbFixture {
    pub(super) path: PathBuf,
    pub(super) pragmas: nitr::stdlib::SqlitePragmas,
    pub(super) snapshot: Arc<nitr::stdlib::db_fixtures::Snapshot>,
}

/// What the test namespace needs from the run.
pub(super) struct Context {
    pub(super) client: TestClient,
    pub(super) cfg: Arc<nitr::Config>,
    pub(super) doubles: Arc<Doubles>,
    /// Where `t.db.seed(path)` resolves fixture files.
    #[cfg(feature = "db")]
    pub(super) tests_dir: PathBuf,
    /// `t.request`'s default `timeout`: the configured execution budget.
    pub(super) default_timeout: Option<Duration>,
    #[cfg(feature = "db")]
    pub(super) db: Option<Arc<DbFixture>>,
    /// Set by `t.db.isolate()`: restore the database after every test of
    /// this file.
    #[cfg(feature = "db")]
    pub(super) isolate: Arc<AtomicBool>,
}

fn runtime_error(message: impl Into<String>) -> mlua::Error {
    mlua::Error::RuntimeError(message.into())
}

/// Mounts `nitr.test` with everything the framework and the tests use.
pub(super) fn register(lua: &Lua, ctx: Context) -> mlua::Result<()> {
    let ctx = Arc::new(ctx);
    let test = lua.create_table()?;
    register_response_metatables(lua)?;

    {
        let ctx = ctx.clone();
        test.set(
            "request",
            lua.create_async_function(
                move |lua, (method, path, opts): (String, String, Option<Table>)| {
                    let ctx = ctx.clone();
                    async move {
                        let mut spec = TestRequest::from_lua(&method, &path, opts.as_ref())?;
                        if spec.timeout.is_none() {
                            spec.timeout = ctx.default_timeout;
                        }
                        let resp = ctx.client.send(spec).await.into_lua_err()?;
                        response_table(&lua, resp)
                    }
                },
            )?,
        )?;
    }

    test.set(
        "_site",
        lua.create_function(|lua, ()| Ok(caller_site(lua)))?,
    )?;

    // The decoder behind `to_have_json` for a table a handler returned
    // (which has a body but no `:json()`): the same one `resp:json()` uses.
    test.set(
        "_decode_json",
        lua.create_function(|lua, body: mlua::LuaString| decode_json(lua, &body.as_bytes()))?,
    )?;

    test.set(
        "fake_request",
        lua.create_function(|lua, spec: Option<Table>| nitr::testing::fake_request(lua, spec))?,
    )?;

    {
        let ctx = ctx.clone();
        test.set(
            "_load_app",
            lua.create_function(move |lua, ()| {
                nitr::testing::load_app(lua, &ctx.cfg).map_err(|err| runtime_error(err.to_string()))
            })?,
        )?;
    }

    test.set(
        "_session_value",
        lua.create_function(
            |_, (data, name, secret, max_age): (Table, String, Option<String>, Option<i64>)| {
                let secret = secret
                    .ok_or_else(|| runtime_error("t.session_cookie needs the app's `secret`"))?;
                nitr::stdlib::testing::session_cookie_value(&data, &name, &secret, max_age)
            },
        )?,
    )?;

    test.set("fetch", fetch_table(lua, &ctx.doubles)?)?;
    test.set("clock", clock_table(lua)?)?;
    test.set("env", env_table(lua, &ctx.doubles)?)?;
    test.set("logs", logs_table(lua)?)?;
    test.set("db", db_table(lua, &ctx)?)?;

    nitr::nitr_table(lua)
        .map_err(|err| runtime_error(err.to_string()))?
        .set("test", test)
}

/// The script frame that registered a test (`file:line`): the first Lua
/// frame outside the framework itself. The `debug` library is not loaded
/// in any state, so this is the only way a test learns where it lives.
///
/// The path is the chunk's full name, not Lua's `short_src`: that one is
/// cut to 60 bytes with a leading `...`, and a truncated path in a JUnit
/// `file=` attribute is one CI cannot resolve.
fn caller_site(lua: &Lua) -> Option<String> {
    for level in 1..=32 {
        let frame = lua.inspect_stack(level, |dbg| {
            let source = dbg.source();
            let own = source.source.as_deref() == Some(FRAMEWORK_CHUNK);
            let lua_frame = matches!(source.what, "Lua" | "main");
            let file = match source.source.as_deref().and_then(|s| s.strip_prefix('@')) {
                Some(path) => Some(path.to_string()),
                None => source.short_src.map(|s| s.into_owned()),
            };
            (own || !lua_frame, file.zip(dbg.current_line()))
        })?;
        match frame {
            (true, _) => continue,
            (false, Some((file, line))) => return Some(format!("{file}:{line}")),
            (false, None) => return None,
        }
    }
    None
}

/// The metatables every response shares: methods on the response, and
/// `resp:headers(name)` through the headers table's `__call`.
fn register_response_metatables(lua: &Lua) -> mlua::Result<()> {
    let methods = lua.create_table()?;
    methods.set(
        "json",
        lua.create_function(|lua, this: Table| {
            let body: mlua::LuaString = this.raw_get("body")?;
            decode_json(lua, &body.as_bytes())
        })?,
    )?;
    methods.set(
        "text",
        lua.create_function(|_, this: Table| this.raw_get::<mlua::LuaString>("body"))?,
    )?;
    methods.set(
        "header",
        lua.create_function(|_, (this, name): (Table, String)| {
            Ok(header_values(&this, &name)?.into_iter().next())
        })?,
    )?;
    methods.set(
        "sse",
        lua.create_function(|lua, this: Table| {
            let body: mlua::LuaString = this.raw_get("body")?;
            let list = lua.create_table()?;
            for event in nitr::testing::parse_sse(&body.as_bytes()) {
                let entry = lua.create_table()?;
                entry.set("event", event.event)?;
                entry.set("data", event.data)?;
                entry.set("id", event.id)?;
                entry.set("retry", event.retry)?;
                list.push(entry)?;
            }
            Ok(list)
        })?,
    )?;
    let response_mt = lua.create_table()?;
    response_mt.set("__index", methods)?;
    lua.set_named_registry_value(RESPONSE_MT, response_mt)?;

    let headers_mt = lua.create_table()?;
    headers_mt.set(
        "__call",
        lua.create_function(|lua, (_, this, name): (Table, Table, String)| {
            lua.create_sequence_from(header_values(&this, &name)?)
        })?,
    )?;
    lua.set_named_registry_value(HEADERS_MT, headers_mt)?;
    Ok(())
}

/// A response body decoded as JSON (serde_json's own nesting limit
/// bounds it).
fn decode_json(lua: &Lua, body: &[u8]) -> mlua::Result<Value> {
    let value = serde_json::from_slice::<serde_json::Value>(body)
        .map_err(|err| runtime_error(format!("the response body is not JSON: {err}")))?;
    lua.to_value(&value)
}

/// Every value of one header, in response order.
fn header_values(resp: &Table, name: &str) -> mlua::Result<Vec<String>> {
    let name = name.to_ascii_lowercase();
    let raw: Table = resp.raw_get("raw_headers")?;
    let mut out = Vec::new();
    for pair in raw.sequence_values::<Table>() {
        let pair = pair?;
        if pair.get::<String>(1)? == name {
            out.push(pair.get(2)?);
        }
    }
    Ok(out)
}

/// Converts a collected response into the table a test reads:
/// `status`, `headers` (last value per name), `raw_headers` (every line,
/// in order), `body`, `cookies` (parsed from every `Set-Cookie`, the last
/// per name), and `error` when the handler raised. `_set_cookies` keeps
/// every parsed line in order for the client's jar, which stores one name
/// at several paths.
fn response_table(lua: &Lua, resp: TestResponse) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set("status", resp.status)?;
    let headers = lua.create_table()?;
    let raw = lua.create_table()?;
    let cookies = lua.create_table()?;
    let lines = lua.create_table()?;
    for (name, value) in &resp.headers {
        headers.set(name.as_str(), value.as_str())?;
        raw.push(lua.create_sequence_from([name.as_str(), value.as_str()])?)?;
        if name == "set-cookie"
            && let Some(cookie) = nitr::stdlib::parse_set_cookie(value)
        {
            let entry = lua.create_table()?;
            entry.set("name", cookie.name.as_str())?;
            entry.set("value", cookie.value)?;
            entry.set("path", cookie.path)?;
            entry.set("domain", cookie.domain)?;
            entry.set("max_age", cookie.max_age)?;
            entry.set("expires", cookie.expires)?;
            entry.set("secure", cookie.secure)?;
            entry.set("http_only", cookie.http_only)?;
            entry.set("same_site", cookie.same_site)?;
            lines.push(entry.clone())?;
            cookies.set(cookie.name, entry)?;
        }
    }
    table.set("_set_cookies", lines)?;
    headers.set_metatable(Some(lua.named_registry_value::<Table>(HEADERS_MT)?))?;
    table.set("headers", headers)?;
    table.set("raw_headers", raw)?;
    table.set("cookies", cookies)?;
    table.set("body", lua.create_string(&resp.body)?)?;
    if let Some(failure) = resp.error {
        let error = nitr::stdlib::error_lua_value(lua, &failure.info)?;
        error.set("handled", failure.handled)?;
        table.set("error", error)?;
    }
    table.set_metatable(Some(lua.named_registry_value::<Table>(RESPONSE_MT)?))?;
    Ok(table)
}

/// Header pairs from an options table, names lowercased, sorted.
fn header_pairs(table: Option<Table>) -> mlua::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    if let Some(table) = table {
        for pair in table.pairs::<String, String>() {
            let (name, value) = pair?;
            out.push((name.to_ascii_lowercase(), value));
        }
    }
    out.sort();
    Ok(out)
}

/// One `t.fetch.mock` rule.
fn fetch_rule(rule: &Table) -> mlua::Result<FetchRule> {
    let url: String = rule
        .get::<Option<String>>("url")?
        .ok_or_else(|| runtime_error("t.fetch.mock: every rule needs a `url`"))?;
    // A trailing `*` is a prefix; anything else is exact. Either is
    // compared with the URL as the client serializes it (scheme and host
    // lowercased, a default port dropped), so both are normalized the same
    // way when they parse.
    let normalize = |text: &str| {
        url::Url::parse(text)
            .map(|parsed| parsed.to_string())
            .unwrap_or_else(|_| text.to_string())
    };
    let url = match url.strip_suffix('*') {
        Some(prefix) => UrlMatch::Prefix(normalize(prefix)),
        None => UrlMatch::Exact(normalize(&url)),
    };
    let status = rule.get::<Option<i64>>("status")?.unwrap_or(200);
    let status = u16::try_from(status)
        .ok()
        .filter(|s| (100..=999).contains(s))
        .ok_or_else(|| {
            runtime_error(format!(
                "t.fetch.mock: `status` {status} is not an HTTP status"
            ))
        })?;
    let mut headers = header_pairs(rule.get("headers")?)?;
    let json: Value = rule.get("json")?;
    let body = if !json.is_nil() {
        if rule.contains_key("body")? {
            return Err(runtime_error("t.fetch.mock: `json` and `body` both given"));
        }
        if !headers.iter().any(|(name, _)| name == "content-type") {
            headers.push(("content-type".into(), "application/json".into()));
        }
        nitr::stdlib::json_encode(&json)?
    } else {
        rule.get::<Option<mlua::LuaString>>("body")?
            .map(|body| body.as_bytes().to_vec())
            .unwrap_or_default()
    };
    let times = match rule.get::<Option<i64>>("times")? {
        None => None,
        Some(n) => Some(u32::try_from(n).map_err(|_| {
            runtime_error(format!("t.fetch.mock: `times` must be a count, got {n}"))
        })?),
    };
    Ok(FetchRule {
        method: rule
            .get::<Option<String>>("method")?
            .map(|m| m.to_ascii_uppercase()),
        url,
        status,
        headers,
        body,
        times,
    })
}

/// `t.fetch`: canned responses for `nitr.fetch`, answered in Rust before
/// the policy and the resolver; an unmatched request goes out unchanged
/// (or is refused under `strict`).
fn fetch_table(lua: &Lua, doubles: &Arc<Doubles>) -> mlua::Result<Table> {
    let fetch = lua.create_table()?;
    {
        let doubles = doubles.clone();
        fetch.set(
            "mock",
            lua.create_function(move |_, rules: Variadic<Table>| {
                let parsed = rules
                    .iter()
                    .map(fetch_rule)
                    .collect::<mlua::Result<Vec<_>>>()?;
                let mut mock = doubles.fetch()?;
                for rule in parsed {
                    mock.add(rule);
                }
                Ok(())
            })?,
        )?;
    }
    {
        let doubles = doubles.clone();
        fetch.set(
            "strict",
            lua.create_function(move |_, on: Option<bool>| {
                doubles.fetch()?.set_strict(on.unwrap_or(true));
                Ok(())
            })?,
        )?;
    }
    {
        let doubles = doubles.clone();
        fetch.set(
            "calls",
            lua.create_function(move |lua, ()| {
                let mock = doubles.fetch()?;
                let list = lua.create_table()?;
                for call in mock.calls() {
                    let entry = lua.create_table()?;
                    entry.set("method", call.method.as_str())?;
                    entry.set("url", call.url.as_str())?;
                    let headers = lua.create_table()?;
                    for (name, value) in &call.headers {
                        headers.set(name.as_str(), value.as_str())?;
                    }
                    entry.set("headers", headers)?;
                    entry.set("mocked", call.mocked)?;
                    if let Some(body) = &call.body {
                        entry.set("body", lua.create_string(body)?)?;
                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
                            entry.set("json", lua.to_value(&json)?)?;
                        }
                    }
                    list.push(entry)?;
                }
                Ok(list)
            })?,
        )?;
    }
    {
        let doubles = doubles.clone();
        fetch.set(
            "reset",
            lua.create_function(move |_, ()| {
                *doubles.fetch()? = Default::default();
                Ok(())
            })?,
        )?;
    }
    Ok(fetch)
}

/// `t.clock`: the standard library's clock (`nitr.time`, sessions, JWT,
/// cache TTLs, the rate limiter), never the runtime's own deadlines.
fn clock_table(lua: &Lua) -> mlua::Result<Table> {
    use nitr::stdlib::clock;
    let table = lua.create_table()?;
    table.set(
        "set",
        lua.create_function(|_, ts: f64| clock::set(ts).map_err(runtime_error))?,
    )?;
    table.set(
        "advance",
        lua.create_function(|_, secs: f64| clock::advance(secs).map_err(runtime_error))?,
    )?;
    table.set(
        "reset",
        lua.create_function(|_, ()| {
            clock::reset();
            Ok(())
        })?,
    )?;
    table.set("now", lua.create_function(|_, ()| Ok(clock::now_unix()))?)?;
    Ok(table)
}

/// `t.env`: overrides `nitr.env` reads, under the `[env]` policy.
fn env_table(lua: &Lua, doubles: &Arc<Doubles>) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    {
        let doubles = doubles.clone();
        table.set(
            "set",
            lua.create_function(move |_, (name, value): (String, String)| {
                doubles.set_env(&name, Some(value));
                Ok(())
            })?,
        )?;
    }
    {
        let doubles = doubles.clone();
        table.set(
            "unset",
            lua.create_function(move |_, name: String| {
                doubles.set_env(&name, None);
                Ok(())
            })?,
        )?;
    }
    {
        let doubles = doubles.clone();
        table.set(
            "reset",
            lua.create_function(move |_, ()| {
                doubles.reset_env();
                Ok(())
            })?,
        )?;
    }
    Ok(table)
}

/// `t.logs()` (the current test's entries) and `t.logs.clear()`.
fn logs_table(lua: &Lua) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set(
        "clear",
        lua.create_function(|_, ()| {
            capture::clear();
            Ok(())
        })?,
    )?;
    let mt = lua.create_table()?;
    mt.set(
        "__call",
        lua.create_function(|lua, _: Value| {
            let list = lua.create_table()?;
            for entry in capture::snapshot() {
                let item = lua.create_table()?;
                item.set("level", entry.level.as_str().to_ascii_lowercase())?;
                item.set("target", entry.target)?;
                item.set("message", entry.message)?;
                if let Some(fields) = entry.fields {
                    match serde_json::from_str::<serde_json::Value>(&fields) {
                        Ok(value @ serde_json::Value::Object(_)) => {
                            item.set("fields", lua.to_value(&value)?)?
                        }
                        _ => item.set("fields", fields)?,
                    }
                }
                item.set("request_id", entry.request_id)?;
                list.push(item)?;
            }
            Ok(list)
        })?,
    )?;
    table.set_metatable(Some(mt))?;
    Ok(table)
}

/// `t.db`: fixtures over the test database — restore the post-migration
/// snapshot, truncate, seed from a file under the tests directory or from
/// rows. Every call runs on the blocking pool.
#[cfg(feature = "db")]
fn db_table(lua: &Lua, ctx: &Arc<Context>) -> mlua::Result<Table> {
    use nitr::stdlib::db_fixtures;

    fn fixture(ctx: &Context) -> mlua::Result<Arc<DbFixture>> {
        ctx.db.clone().ok_or_else(|| {
            runtime_error("t.db needs a [database]: this application has none configured")
        })
    }
    async fn blocking<F>(f: F) -> mlua::Result<()>
    where
        F: FnOnce() -> nitr::Result<()> + Send + 'static,
    {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|err| runtime_error(format!("the database fixture task failed: {err}")))?
            .map_err(|err| runtime_error(err.to_string()))
    }

    let table = lua.create_table()?;
    {
        let ctx = ctx.clone();
        table.set(
            "reset",
            lua.create_async_function(move |_, ()| {
                let ctx = ctx.clone();
                async move {
                    let db = fixture(&ctx)?;
                    blocking(move || db_fixtures::restore(&db.snapshot, &db.path, &db.pragmas))
                        .await
                }
            })?,
        )?;
    }
    {
        let ctx = ctx.clone();
        table.set(
            "truncate",
            lua.create_async_function(move |_, tables: Option<Vec<String>>| {
                let ctx = ctx.clone();
                async move {
                    let db = fixture(&ctx)?;
                    blocking(move || {
                        db_fixtures::truncate(&db.path, &db.pragmas, tables.as_deref())
                    })
                    .await
                }
            })?,
        )?;
    }
    {
        let ctx = ctx.clone();
        table.set(
            "seed",
            lua.create_async_function(move |_, spec: Value| {
                let ctx = ctx.clone();
                async move {
                    let db = fixture(&ctx)?;
                    match spec {
                        Value::String(rel) => {
                            let rel = rel.to_str()?.to_string();
                            let path = nitr::testing::fixture_path(&ctx.tests_dir, &rel)
                                .map_err(|err| runtime_error(err.to_string()))?;
                            blocking(move || {
                                let sql = std::fs::read_to_string(&path).map_err(|err| {
                                    nitr::Error::Script(format!(
                                        "cannot read the fixture {}: {err}",
                                        path.display()
                                    ))
                                })?;
                                db_fixtures::seed_sql(&db.path, &db.pragmas, &sql)
                            })
                            .await
                        }
                        Value::Table(rows) => {
                            let rows = db_fixtures::SeedRows::from_lua(&rows)?;
                            blocking(move || db_fixtures::seed_rows(&db.path, &db.pragmas, &rows))
                                .await
                        }
                        other => Err(runtime_error(format!(
                            "t.db.seed takes a fixture path or {{ table = rows }}, got {}",
                            other.type_name()
                        ))),
                    }
                }
            })?,
        )?;
    }
    {
        let ctx = ctx.clone();
        table.set(
            "isolate",
            lua.create_function(move |_, ()| {
                fixture(&ctx)?;
                ctx.isolate
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            })?,
        )?;
    }
    Ok(table)
}

/// Without the `db` feature `t.db` still exists, so a test file reads the
/// same everywhere; every call says what is missing.
#[cfg(not(feature = "db"))]
fn db_table(lua: &Lua, _ctx: &Arc<Context>) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    for name in ["reset", "truncate", "seed", "isolate"] {
        table.set(
            name,
            lua.create_function(move |_, _: Variadic<Value>| -> mlua::Result<()> {
                Err(runtime_error(format!(
                    "t.db.{name} needs the `db` feature, which this binary was built without"
                )))
            })?,
        )?;
    }
    Ok(table)
}
