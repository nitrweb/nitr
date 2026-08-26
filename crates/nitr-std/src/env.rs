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
            match read(&policy, &name) {
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
        lua.create_function(move |_, name: String| Ok(read(&policy, &name).is_some()))?,
    )?;

    let policy = opts.clone();
    env.set(
        "number",
        lua.create_function(move |_, (name, default): (String, Option<Value>)| {
            match read(&policy, &name).and_then(|v| v.trim().parse::<f64>().ok()) {
                Some(n) => Ok(Value::Number(n)),
                None => Ok(default.unwrap_or(Value::Nil)),
            }
        })?,
    )?;

    let policy = opts.clone();
    env.set(
        "bool",
        lua.create_function(move |_, (name, default): (String, Option<Value>)| {
            match read(&policy, &name).as_deref().and_then(parse_bool) {
                Some(b) => Ok(Value::Boolean(b)),
                None => Ok(default.unwrap_or(Value::Nil)),
            }
        })?,
    )?;

    Ok(env)
}

/// Reads one variable under the policy; `None` for unset *and* for hidden,
/// so callers cannot distinguish the two.
fn read(opts: &EnvOptions, name: &str) -> Option<String> {
    visible(opts, name).then(|| std::env::var(name).ok())?
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
}
