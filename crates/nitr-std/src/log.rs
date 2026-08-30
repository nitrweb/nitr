// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Structured logging for Lua handlers: `log.info(msg, fields?)` and
//! friends, backed by `tracing`. Events fire inside the per-request span,
//! so they automatically carry the request id, method, and path.

use mlua::{Lua, Table, Value};

/// Serializes the optional fields table to one JSON string; `tracing`
/// requires statically-known field names, so dynamic Lua fields travel as a
/// single `fields` value.
fn fields_json(fields: Option<Table>) -> Option<String> {
    let fields = Value::Table(fields?);
    // Logging is infallible by contract: a value the serializer cannot
    // take — too deep included, which would otherwise overflow the stack
    // — degrades to a placeholder instead of failing the request.
    if crate::utils::check_json_bounds(&fields).is_err() {
        return Some("\"<unserializable fields>\"".to_string());
    }
    Some(
        serde_json::to_string(&fields)
            .unwrap_or_else(|_| "\"<unserializable fields>\"".to_string()),
    )
}

/// Creates the `log` global table with `debug`/`info`/`warn`/`error`.
pub(crate) fn create_log_table(lua: &Lua) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    for level in ["debug", "info", "warn", "error"] {
        table.set(
            level,
            lua.create_function(move |_, (msg, fields): (String, Option<Table>)| {
                match (level, fields_json(fields)) {
                    ("debug", Some(f)) => tracing::debug!(target: "lua", fields = %f, "{msg}"),
                    ("debug", None) => tracing::debug!(target: "lua", "{msg}"),
                    ("info", Some(f)) => tracing::info!(target: "lua", fields = %f, "{msg}"),
                    ("info", None) => tracing::info!(target: "lua", "{msg}"),
                    ("warn", Some(f)) => tracing::warn!(target: "lua", fields = %f, "{msg}"),
                    ("warn", None) => tracing::warn!(target: "lua", "{msg}"),
                    ("error", Some(f)) => tracing::error!(target: "lua", fields = %f, "{msg}"),
                    ("error", None) => tracing::error!(target: "lua", "{msg}"),
                    _ => unreachable!("unknown log level"),
                }
                Ok(())
            })?,
        )?;
    }
    Ok(table)
}
