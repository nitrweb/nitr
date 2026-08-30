// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use mlua::{Function, Lua, Value};

/// Builds an HMAC instance from a key of any length.
///
/// The single home of the "HMAC accepts any key length" invariant:
/// `new_from_slice` is fallible only for fixed-key-length algorithms,
/// which HMAC is not, so the `expect` cannot fire. Every MAC in the crate
/// (signed cookies, `nitr.crypto.hmac_sha256`, JWT) constructs through
/// here so key handling has one auditable site.
pub(crate) fn new_hmac<M: hmac::digest::KeyInit>(key: &[u8]) -> M {
    // Invariant: `new_from_slice` fails only for fixed-key-length
    // algorithms, which HMAC is not.
    #[allow(clippy::expect_used)]
    <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length")
}

/// The deepest nesting a Lua value may have before it is serialized to
/// JSON, deliberately mirroring serde_json's *deserialization* recursion
/// limit so the two directions share one documented bound.
///
/// The limit exists because serialization has none of its own: serde_json
/// recurses once per nesting level, and a script can build a table chain
/// deep enough to overflow the Rust stack well within its Lua memory
/// budget (verified empirically: ~30,000 levels aborts the process with
/// SIGABRT on a default tokio worker stack). A stack overflow is an
/// abort, not a panic — the containment boundary cannot catch
/// it, so the bound must hold *before* a serializer recurses.
pub(crate) const MAX_JSON_DEPTH: usize = 128;

/// The most nodes a Lua value may expand to on the way to a serializer.
///
/// Depth alone is not a bound on *work*. A script can build
/// `t = {a = prev, b = prev}` sixty times over: that value is sixty levels
/// deep, so it passes [`MAX_JSON_DEPTH`] comfortably, but it is a DAG that
/// a tree walk sees as 2^60 nodes. Neither execution budget covers the
/// result — the walk is a tight Rust loop, so the instruction-count hook
/// never fires (no Lua executes) and the async timeout never fires
/// (nothing yields), which leaves a tokio worker wedged for good.
///
/// Counting *visits* rather than distinct nodes is the point: the visit
/// count is precisely the work `serde_json` is about to redo, so a value
/// that passes has a bounded serialization cost too.
///
/// What a full budget actually costs, measured rather than estimated:
/// **~145 ms release, ~620 ms debug** for the cheapest shape that fills
/// it. That is the ceiling on one request's unyieldable synchronous walk,
/// and it is well above the ~10 ms this was first assumed to be — worth
/// knowing, because `workers` concurrent requests can each spend it. It
/// still does the job it exists for: turning an unbounded wedge (2^60
/// visits, a worker gone for good) into a bounded pause with a catchable
/// error. Lowering it would tighten that ceiling at the cost of refusing
/// large-but-honest documents — a 1M-visit value is already a
/// multi-megabyte response — so the number stays until a real workload
/// argues otherwise. A const rather than a knob, for the same reason
/// [`MAX_JSON_DEPTH`] is one.
pub(crate) const MAX_JSON_NODES: usize = 1_000_000;

/// Refuses a value that is nested deeper than [`MAX_JSON_DEPTH`] or
/// expands to more than [`MAX_JSON_NODES`] nodes, with an ordinary
/// catchable error, before any serializer recurses over it.
///
/// Every Lua-value-to-serializer site in the crate calls this first:
/// `nitr.json` encoding and the JSON response helper, `cache:set` /
/// `cache:remember`, `fetch` JSON bodies, JWT claims, sessions, SSE data,
/// `nitr.etag`, `nitr.error` table bodies, `template:render` contexts, and
/// log fields — so the bound has one auditable home. The walk itself
/// recurses, but its depth is capped by the very bound it enforces; a
/// cyclic table is infinitely deep and reports the depth error instead of
/// hanging.
pub(crate) fn check_json_bounds(value: &Value) -> mlua::Result<()> {
    let mut budget = MAX_JSON_NODES;
    depth_walk(value, MAX_JSON_DEPTH, &mut budget)
}

fn depth_walk(value: &Value, remaining: usize, budget: &mut usize) -> mlua::Result<()> {
    // Charged for every visit, scalars included, and a shared subtree
    // counted once per path that reaches it — because that is what the
    // serializer will do too.
    if *budget == 0 {
        return Err(mlua::Error::RuntimeError(format!(
            "json value expands to more than {MAX_JSON_NODES} nodes (a shared subtree \
             counts once per path to it)"
        )));
    }
    *budget -= 1;
    let Value::Table(table) = value else {
        return Ok(());
    };
    if remaining == 0 {
        return Err(mlua::Error::RuntimeError(format!(
            "json value nested deeper than {MAX_JSON_DEPTH} levels"
        )));
    }
    // Raw iteration, matching what serialization will walk; keys can be
    // tables too, and a deep key must not slip past the check.
    table.for_each(|key: Value, item: Value| {
        depth_walk(&key, remaining - 1, budget)?;
        depth_walk(&item, remaining - 1, budget)
    })
}

/// A chain of `depth` nested tables (the root included).
///
/// Test-only, and deliberately shared rather than copied: the guard's own
/// boundary tests and the per-site ones (`json`, `template`) must build
/// the same shape, or a site can pass its test against a value the guard
/// would never have seen.
#[cfg(test)]
pub(crate) fn deep_table(lua: &Lua, depth: usize) -> Value {
    let root = lua.create_table().expect("table");
    let mut cur = root.clone();
    for _ in 1..depth {
        let next = lua.create_table().expect("table");
        cur.set("x", next.clone()).expect("set");
        cur = next;
    }
    Value::Table(root)
}

/// A shared-subtree DAG: `t = {a = prev, b = prev}` applied `levels`
/// times. Shallow (`levels + 1` deep) but `2^(levels + 1) - 1` table
/// *visits*, which is the shape [`MAX_JSON_NODES`] exists to bound.
#[cfg(test)]
pub(crate) fn dag_table(lua: &Lua, levels: usize) -> Value {
    let mut cur = lua.create_table().expect("table");
    for _ in 0..levels {
        let next = lua.create_table().expect("table");
        next.set("a", cur.clone()).expect("set");
        next.set("b", cur.clone()).expect("set");
        cur = next;
    }
    Value::Table(cur)
}

/// `nitr.dbg(value)`: pretty-prints a Lua value at debug level.
///
/// Bounded by the same guard as every serializing builtin, because
/// `{value:#?}` is a serializer too. mlua's pretty `Debug` recurses once
/// per nesting level and carries only a *cycle* guard (a visited set of
/// table pointers), which a chain of distinct tables never trips — so a
/// deep enough value overflows the Rust stack, and that abort is not
/// something the per-request `catch_unwind` can contain. Verified: a
/// 30,000-deep table through `{:#?}` is a SIGABRT.
///
/// Degrades to a placeholder rather than raising, following
/// [`crate::log`]: a diagnostic that fails the request it was added to
/// diagnose is worse than one that says it could not render.
pub(crate) fn create_debug_fn(lua: &Lua) -> mlua::Result<Function> {
    lua.create_function(|_, value: Value| {
        if check_json_bounds(&value).is_err() {
            tracing::debug!("[lua] <value too deeply nested to print>");
            return Ok(());
        }
        tracing::debug!("[lua] {value:#?}");
        Ok(())
    })
}

/// Builds the structured error value the error model hands to Lua: the
/// table `on_error` receives and `nitr.errinfo` returns. A plain table (it
/// serializes to JSON for free) that stringifies — and concatenates — as
/// the concise `kind: message (source:line)` form via a cached metatable.
pub fn error_lua_value(lua: &Lua, info: &nitr_core::ErrorInfo) -> mlua::Result<mlua::Table> {
    let t = lua.create_table()?;
    t.raw_set("message", info.message.as_str())?;
    t.raw_set("kind", info.kind)?;
    if let Some(source) = &info.source {
        t.raw_set("source", source.as_str())?;
    }
    if let Some(line) = info.line {
        t.raw_set("line", line)?;
    }
    if let Some(module) = &info.module {
        t.raw_set("module", module.as_str())?;
    }
    if let Some(traceback) = &info.traceback {
        t.raw_set("traceback", traceback.as_str())?;
    }
    if !info.cause.is_empty() {
        let causes = lua.create_table_from(
            info.cause
                .iter()
                .enumerate()
                .map(|(i, c)| (i + 1, c.as_str())),
        )?;
        t.raw_set("cause", causes)?;
    }
    t.raw_set("__concise", info.concise())?;
    // For console prints: ANSI-colored on a terminal, identical to the
    // concise form otherwise. `tostring`/`..` stay plain deliberately —
    // those strings may end up in HTTP bodies and log files.
    let pretty = if console_wants_color() {
        info.concise_colored()
    } else {
        info.concise()
    };
    t.raw_set("pretty", pretty)?;
    t.set_metatable(Some(error_metatable(lua)?))?;
    Ok(t)
}

/// Whether `print`-style console output should carry color: stdout is a
/// terminal and `NO_COLOR` is unset.
fn console_wants_color() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
}

/// The shared metatable for error values, built once per state:
/// `__tostring` for `tostring(err)` and `__concat` so `"prefix: " .. err`
/// works directly in a log line.
fn error_metatable(lua: &Lua) -> mlua::Result<mlua::Table> {
    if let Ok(mt) = lua.named_registry_value::<mlua::Table>("nitr.error_mt") {
        return Ok(mt);
    }
    let mt = lua.create_table()?;
    mt.set(
        "__tostring",
        lua.create_function(|_, t: mlua::Table| t.raw_get::<String>("__concise"))?,
    )?;
    // Either operand may be the error value; Lua's own `tostring` applies
    // the `__tostring` above for whichever side is.
    mt.set(
        "__concat",
        lua.create_function(|lua, (a, b): (Value, Value)| {
            let tostring: Function = lua.globals().get("tostring")?;
            let a: String = tostring.call(a)?;
            let b: String = tostring.call(b)?;
            Ok(a + &b)
        })?,
    )?;
    lua.set_named_registry_value("nitr.error_mt", &mt)?;
    Ok(mt)
}

/// `nitr.errinfo(err)`: classifies whatever `pcall` caught into the same
/// structured error value `on_error` receives. A Rust-side error arrives
/// with its full chain (`Value::Error`); a Lua error arrives as a
/// position-prefixed string; anything else is stringified. Idempotent on
/// values that are already structured.
pub(crate) fn create_errinfo_fn(lua: &Lua) -> mlua::Result<Function> {
    lua.create_function(|lua, value: Value| {
        let info = match &value {
            Value::Error(err) => {
                nitr_core::ErrorInfo::from_error(&nitr_core::Error::Lua((**err).clone()))
            }
            Value::String(s) => nitr_core::ErrorInfo::from_message(&s.to_string_lossy()),
            Value::Table(t) if t.raw_get::<Option<String>>("__concise")?.is_some() => {
                return Ok(t.clone());
            }
            other => {
                let tostring: Function = lua.globals().get("tostring")?;
                let text: String = tostring.call(other)?;
                nitr_core::ErrorInfo::from_message(&text)
            }
        };
        error_lua_value(lua, &info)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_values_stringify_and_concatenate_as_the_concise_form() {
        let lua = Lua::new();
        let info = nitr_core::ErrorInfo::from_message("app.lua:7: boom");
        let err = error_lua_value(&lua, &info).expect("value");
        lua.globals().set("err", err).expect("set");

        let (text, concat, message, line): (String, String, String, u32) = lua
            .load(r#"return tostring(err), "got: " .. err, err.message, err.line"#)
            .eval()
            .expect("eval");
        assert!(text.contains("boom"), "tostring: {text}");
        assert!(text.contains("app.lua:7"), "tostring: {text}");
        assert_eq!(concat, format!("got: {text}"));
        assert_eq!(message, "boom");
        assert_eq!(line, 7);
    }

    #[test]
    fn errinfo_classifies_and_is_idempotent() {
        let lua = Lua::new();
        lua.globals()
            .set("errinfo", create_errinfo_fn(&lua).expect("fn"))
            .expect("set");
        let (message, kind, twice_same): (String, String, bool) = lua
            .load(
                // `error(msg, 0)`: no position prefix, so the message is
                // exactly what the script raised.
                r#"local ok, caught = pcall(function() error("nope", 0) end)
                   assert(not ok)
                   local info = errinfo(caught)
                   local again = errinfo(info)
                   return info.message, info.kind, rawequal(info, again)"#,
            )
            .eval()
            .expect("eval");
        assert_eq!(message, "nope");
        assert_eq!(kind, "lua");
        assert!(twice_same, "a structured value passes through unchanged");
    }

    #[test]
    fn json_depth_boundary_is_exact() {
        let lua = Lua::new();
        assert!(check_json_bounds(&deep_table(&lua, MAX_JSON_DEPTH)).is_ok());
        let err = check_json_bounds(&deep_table(&lua, MAX_JSON_DEPTH + 1)).expect_err("129 deep");
        assert!(
            err.to_string().contains("nested deeper than 128 levels"),
            "got: {err}"
        );
        // Scalars and shallow values pass untouched.
        assert!(check_json_bounds(&Value::Integer(7)).is_ok());
    }

    /// A cyclic table is infinitely deep: the walk must report the depth
    /// error, not hang or overflow.
    #[test]
    fn a_cyclic_table_reports_depth_instead_of_hanging() {
        let lua = Lua::new();
        let t = lua.create_table().expect("table");
        t.set("me", t.clone()).expect("set");
        let err = check_json_bounds(&Value::Table(t)).expect_err("cycle");
        assert!(err.to_string().contains("nested deeper"), "got: {err}");
    }

    /// A shared subtree is shallow but expensive: 21 levels of
    /// `{a = prev, b = prev}` is 22 deep — nowhere near the depth bound —
    /// yet ~4.2 million table visits, which is the work the node budget
    /// exists to refuse.
    ///
    /// The level count is chosen so this test *terminates either way*:
    /// with the budget in place it stops after a million visits (~0.6 s
    /// in the unoptimized profile `cargo test` uses), and with the budget
    /// reverted it walks all ~4.2 M visits and fails in a few seconds
    /// (measured ~3–5 s) rather than hanging. That distinction is the
    /// whole point of picking 21 — a 60-level DAG, the shape an attacker
    /// would actually send, never returns at all, and a test that hangs
    /// on revert teaches nobody anything.
    #[test]
    fn a_shared_subtree_is_refused_by_node_count_not_depth() {
        let lua = Lua::new();
        let err = check_json_bounds(&dag_table(&lua, 21)).expect_err("21-level DAG");
        assert!(
            err.to_string().contains("expands to more than"),
            "the node budget must be what refuses a DAG, not the depth bound: {err}"
        );

        // A DAG small enough to fit the budget still passes: the guard
        // bounds work, it does not ban sharing.
        check_json_bounds(&dag_table(&lua, 10)).expect("a 10-level DAG is ~2047 visits");
    }

    /// `nitr.dbg` formats with `{:#?}`, which is a serializer like any
    /// other: mlua's pretty `Debug` recurses per nesting level behind only
    /// a cycle guard, so an unguarded deep value is a stack overflow —
    /// an abort, which `catch_unwind` cannot contain.
    ///
    /// Deleting the guard in `create_debug_fn` turns this test into a
    /// SIGABRT that takes the whole test binary with it, which is exactly
    /// the failure being prevented.
    #[test]
    fn dbg_does_not_abort_on_a_deep_value() {
        let lua = Lua::new();
        let dbg = create_debug_fn(&lua).expect("dbg");
        // Far past anything the guard admits, and past what the Rust
        // stack survives being formatted.
        dbg.call::<()>(deep_table(&lua, 30_000))
            .expect("dbg must degrade, not abort and not raise");
        // A value within the bound still prints normally.
        dbg.call::<()>(deep_table(&lua, 8))
            .expect("an ordinary value still prints");
    }

    /// Lua table keys can be tables too; a deep *key* must not slip past
    /// the check and recurse in the serializer instead.
    #[test]
    fn deep_table_keys_are_bounded_too() {
        let lua = Lua::new();
        let outer = lua.create_table().expect("table");
        outer
            .set(deep_table(&lua, MAX_JSON_DEPTH), true)
            .expect("set");
        assert!(check_json_bounds(&Value::Table(outer)).is_err());
    }
}
