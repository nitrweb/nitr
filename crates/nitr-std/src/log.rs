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
    // The plain bound: a binary field serializes as a byte array here,
    // which is more useful in a log line than a placeholder for the
    // whole table.
    if crate::utils::check_value_bounds(&fields).is_err() {
        return Some("\"<unserializable fields>\"".to_string());
    }
    Some(
        serde_json::to_string(&fields)
            .unwrap_or_else(|_| "\"<unserializable fields>\"".to_string()),
    )
}

/// Escapes control characters in a message before it reaches a text log.
///
/// The message is whatever the script passed — often request data — and
/// the text subscriber writes it verbatim, so a `\n` in a request path
/// would forge a whole log line and a `\r` would overwrite one on a
/// terminal. The JSON subscriber escapes on its own; this keeps the text
/// form honest too. Tabs stay: they are formatting, not line structure.
fn sanitize(msg: &str) -> std::borrow::Cow<'_, str> {
    if !msg.chars().any(|c| c.is_control() && c != '\t') {
        return std::borrow::Cow::Borrowed(msg);
    }
    std::borrow::Cow::Owned(
        msg.chars()
            .flat_map(|c| {
                if c.is_control() && c != '\t' {
                    c.escape_default().collect::<Vec<_>>()
                } else {
                    vec![c]
                }
            })
            .collect(),
    )
}

/// The four Lua-facing log levels, as a closed enum so the dispatch below
/// is exhaustive by type — no name is re-matched, nothing to declare
/// unreachable. (`tracing::event!` needs a const level per call site, so
/// a dynamic `tracing::Level` cannot replace the dispatch.)
#[derive(Clone, Copy)]
enum LuaLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Creates the `log` global table with `debug`/`info`/`warn`/`error`.
pub(crate) fn create_log_table(lua: &Lua) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    for (name, level) in [
        ("debug", LuaLevel::Debug),
        ("info", LuaLevel::Info),
        ("warn", LuaLevel::Warn),
        ("error", LuaLevel::Error),
    ] {
        table.set(
            name,
            lua.create_function(move |_, (msg, fields): (String, Option<Table>)| {
                let msg = sanitize(&msg);
                match (level, fields_json(fields)) {
                    (LuaLevel::Debug, Some(f)) => {
                        tracing::debug!(target: "lua", fields = %f, "{msg}")
                    }
                    (LuaLevel::Debug, None) => tracing::debug!(target: "lua", "{msg}"),
                    (LuaLevel::Info, Some(f)) => {
                        tracing::info!(target: "lua", fields = %f, "{msg}")
                    }
                    (LuaLevel::Info, None) => tracing::info!(target: "lua", "{msg}"),
                    (LuaLevel::Warn, Some(f)) => {
                        tracing::warn!(target: "lua", fields = %f, "{msg}")
                    }
                    (LuaLevel::Warn, None) => tracing::warn!(target: "lua", "{msg}"),
                    (LuaLevel::Error, Some(f)) => {
                        tracing::error!(target: "lua", fields = %f, "{msg}")
                    }
                    (LuaLevel::Error, None) => tracing::error!(target: "lua", "{msg}"),
                }
                Ok(())
            })?,
        )?;
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_cannot_forge_log_lines() {
        assert_eq!(sanitize("plain"), "plain");
        assert_eq!(sanitize("a\tb"), "a\tb", "tabs are formatting");
        assert_eq!(
            sanitize("GET /x\n2026-01-01 ERROR forged\r\u{1b}[31m"),
            "GET /x\\n2026-01-01 ERROR forged\\r\\u{1b}[31m"
        );
    }
}
