// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! A route's trailing options table, and the registration-site
//! bookkeeping load-time diagnostics name.

use mlua::{Function, Lua, Value};

use super::Site;

/// The keys a route's trailing options table may carry.
const ROUTE_OPTION_KEYS: &[&str] = &["on_error", "on_invalid", "input", "doc"];

/// What `app:<method>(path, ..., { ... })` may set.
#[derive(Default)]
pub(super) struct RouteOptions {
    pub(super) error_fn: Option<Function>,
    pub(super) invalid_fn: Option<Function>,
    pub(super) input: Option<mlua::Table>,
    pub(super) doc: Option<mlua::Table>,
}

/// The script frame that called into a registration method, for load-time
/// diagnostics. Costs one stack inspection at registration — never on the
/// request path.
pub(super) fn caller_site(lua: &Lua) -> Site {
    lua.inspect_stack(1, |dbg| {
        let source = dbg.source().short_src?;
        Some((source.into_owned(), dbg.current_line()? as u32))
    })?
}

/// Renders a registration site for an error message.
pub(super) fn site_label(site: &Site) -> String {
    match site {
        Some((source, line)) => format!("{source}:{line}"),
        None => "unknown location".into(),
    }
}

/// Reads a route's trailing options table. Unknown keys are refused
/// naming the allowed ones: a misspelt `on_invalid` must not become a
/// route without one.
pub(super) fn route_options(
    name: &str,
    path: &str,
    opts: &mlua::Table,
) -> mlua::Result<RouteOptions> {
    for pair in opts.pairs::<Value, Value>() {
        let (key, _) = pair?;
        let key = match key {
            Value::String(s) => s.to_string_lossy().to_string(),
            _ => {
                return Err(mlua::Error::RuntimeError(format!(
                    "app:{name}(\"{path}\", ...): option keys must be strings"
                )));
            }
        };
        if !ROUTE_OPTION_KEYS.contains(&key.as_str()) {
            return Err(mlua::Error::RuntimeError(format!(
                "app:{name}(\"{path}\", ...): unknown option `{key}` (allowed: {})",
                ROUTE_OPTION_KEYS.join(", ")
            )));
        }
    }
    let table = |key: &str| -> mlua::Result<Option<mlua::Table>> {
        match opts.get::<Value>(key)? {
            Value::Nil => Ok(None),
            Value::Table(t) => Ok(Some(t)),
            other => Err(mlua::Error::RuntimeError(format!(
                "app:{name}(\"{path}\", ...): `{key}` must be a table, got {}",
                other.type_name()
            ))),
        }
    };
    Ok(RouteOptions {
        error_fn: opts.get::<Option<Function>>("on_error")?,
        invalid_fn: opts.get::<Option<Function>>("on_invalid")?,
        input: table("input")?,
        doc: table("doc")?,
    })
}
