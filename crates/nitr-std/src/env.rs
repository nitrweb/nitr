// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr.env`: read-only access to environment variables.
//!
//! Opt-in and deliberately narrow: getters only, no setter, and no way to
//! enumerate the environment — a script can ask for a name it knows, never
//! discover what else is there. `NITR_*` variables are hidden
//! unconditionally (they configure the server, not the application), and
//! the operator can narrow the readable set further with `[env] allow`.

use mlua::{Lua, Table, Value};

use crate::config::EnvOptions;

/// Builds the `nitr.env` table.
pub(crate) fn create_env_table(lua: &Lua, opts: &EnvOptions) -> mlua::Result<Table> {
    let env = lua.create_table()?;

    let policy = opts.clone();
    env.set(
        "get",
        lua.create_function(move |lua, (name, default): (String, Option<Value>)| {
            match read(lua, &policy, &name) {
                Some(v) => Ok(Value::String(lua.create_string(&v)?)),
                None => Ok(default.unwrap_or(Value::Nil)),
            }
        })?,
    )?;

    let policy = opts.clone();
    env.set(
        "has",
        // Existence without the value; a name the policy hides reports
        // `false` rather than leaking that it is set.
        lua.create_function(move |lua, name: String| Ok(read(lua, &policy, &name).is_some()))?,
    )?;

    let policy = opts.clone();
    env.set(
        "number",
        lua.create_function(move |lua, (name, default): (String, Option<Value>)| {
            match read(lua, &policy, &name).and_then(|v| v.trim().parse::<f64>().ok()) {
                Some(n) => Ok(Value::Number(n)),
                None => Ok(default.unwrap_or(Value::Nil)),
            }
        })?,
    )?;

    let policy = opts.clone();
    env.set(
        "bool",
        lua.create_function(move |lua, (name, default): (String, Option<Value>)| {
            match read(lua, &policy, &name).as_deref().and_then(parse_bool) {
                Some(b) => Ok(Value::Boolean(b)),
                None => Ok(default.unwrap_or(Value::Nil)),
            }
        })?,
    )?;

    Ok(env)
}

/// Reads one variable under the policy; `None` for unset *and* for hidden,
/// so callers cannot distinguish the two.
///
/// A test's override (`nitr.test.env`, installed as
/// [`Doubles`](crate::testing::Doubles) app data) is consulted only
/// *after* the policy: an override of a hidden name stays hidden, so a
/// test exercises the real `[env]` rules rather than a way around them.
fn read(lua: &Lua, opts: &EnvOptions, name: &str) -> Option<String> {
    if !visible(opts, name) {
        return None;
    }
    if let Some(doubles) = crate::testing::installed(lua)
        && let Some(overridden) = doubles.env_override(name)
    {
        return overridden;
    }
    std::env::var(name).ok()
}

/// Whether the policy lets scripts see this name.
fn visible(opts: &EnvOptions, name: &str) -> bool {
    if name.starts_with("NITR_") {
        return false;
    }
    match &opts.allow {
        None => true,
        Some(allow) => allow.iter().any(|entry| {
            // A trailing `_` marks a prefix, anything else an exact name —
            // so `"APP_"` cannot accidentally admit `"APP_SECRET"`'s
            // sibling `"APPLE"`.
            match entry.strip_suffix('_') {
                Some(_) => name.starts_with(entry.as_str()),
                None => name == entry,
            }
        }),
    }
}

/// Conventional truthiness for environment flags. Unrecognized text is
/// `None` — the caller's default answers, not a guess.
fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" | "" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nitr_internals_are_always_hidden() {
        let open = EnvOptions::default();
        assert!(!visible(&open, "NITR_DATABASE_PATH"));
        assert!(!visible(&open, "NITR_ANYTHING"));
        assert!(visible(&open, "HOME"));
    }

    #[test]
    fn the_allow_list_matches_prefixes_and_exact_names() {
        let opts = EnvOptions {
            allow: Some(vec!["APP_".into(), "API_TOKEN".into()]),
        };
        assert!(visible(&opts, "APP_NAME"));
        assert!(visible(&opts, "API_TOKEN"));
        assert!(!visible(&opts, "API_TOKEN_2"), "exact means exact");
        assert!(!visible(&opts, "APPLE"), "prefix requires the underscore");
        assert!(!visible(&opts, "HOME"));
        // The unconditional rule wins over any allow entry.
        let opts = EnvOptions {
            allow: Some(vec!["NITR_".into()]),
        };
        assert!(!visible(&opts, "NITR_LISTEN"));
    }

    #[test]
    fn env_flags_parse_conventionally() {
        for yes in ["1", "true", "YES", "On", " true "] {
            assert_eq!(parse_bool(yes), Some(true), "{yes}");
        }
        for no in ["0", "false", "NO", "off", ""] {
            assert_eq!(parse_bool(no), Some(false), "{no}");
        }
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn lua_getters_answer_defaults_for_unset_names() {
        let lua = mlua::Lua::new();
        let table = create_env_table(&lua, &EnvOptions::default()).expect("table");
        lua.globals().set("env", table).expect("set");
        // Certainly-unset names take the default (or nil); no process
        // environment is mutated — `set_var` is unsafe in edition 2024.
        let (a, b, c, d): (Value, String, f64, bool) = lua
            .load(
                r#"return env.get("NITR_STD_SURELY_UNSET"),
                          env.get("NITR_STD_SURELY_UNSET", "fallback"),
                          env.number("NITR_STD_SURELY_UNSET", 42),
                          env.bool("NITR_STD_SURELY_UNSET", true)"#,
            )
            .eval()
            .expect("eval");
        assert!(a.is_nil());
        assert_eq!(b, "fallback");
        assert_eq!(c, 42.0);
        assert!(d);
    }

    /// A test's override answers only for names the policy lets scripts
    /// see: overriding a hidden name must not become a way to read it,
    /// and an explicit unset reads as unset even when the process has it.
    #[test]
    fn overrides_obey_the_policy() {
        let lua = mlua::Lua::new();
        let doubles = crate::testing::Doubles::new();
        lua.set_app_data(doubles.clone());
        let opts = EnvOptions {
            allow: Some(vec!["APP_".into(), "PATH".into()]),
        };
        let table = create_env_table(&lua, &opts).expect("table");
        lua.globals().set("env", table).expect("set");

        doubles.set_env("APP_KEY", Some("sk_test_1".into()));
        doubles.set_env("SECRET", Some("leaked".into()));
        doubles.set_env("NITR_LISTEN", Some("leaked".into()));
        // PATH is set in every test environment; the override unsets it.
        doubles.set_env("PATH", None);
        let (key, secret, internal, path, has_path): (String, Value, Value, Value, bool) = lua
            .load(
                r#"return env.get("APP_KEY"), env.get("SECRET"), env.get("NITR_LISTEN"),
                          env.get("PATH"), env.has("PATH")"#,
            )
            .eval()
            .expect("eval");
        assert_eq!(key, "sk_test_1");
        assert!(secret.is_nil(), "outside the allow list stays hidden");
        assert!(internal.is_nil(), "NITR_* stays hidden");
        assert!(path.is_nil() && !has_path, "an explicit unset wins");

        doubles.reset();
        let path: Value = lua.load(r#"return env.get("PATH")"#).eval().expect("eval");
        assert!(!path.is_nil(), "reset restores the process environment");
    }
}
