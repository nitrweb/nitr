// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Schema compilation: a Lua rule table becomes a [`Rule`] tree once at
//! load time, with typos and contradictions rejected there.

use mlua::{Table, Value};

use super::format::{FORMATS, Format};
use super::{Kind, Literal, Rule};

/// Raises a schema-compilation error naming the field it is about.
pub(super) fn bad_schema(path: &str, msg: impl std::fmt::Display) -> mlua::Error {
    mlua::Error::RuntimeError(format!("invalid schema for `{path}`: {msg}"))
}

/// Which rule keys apply to which type — anything else in a rule table is
/// an error, so a typo (`requird`, `maxlen`) fails at load time instead of
/// silently validating nothing.
pub(super) fn allowed_keys(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::String => &["type", "required", "min_len", "max_len", "format", "one_of"],
        Kind::Number | Kind::Integer => &["type", "required", "min", "max", "one_of"],
        Kind::Boolean => &["type", "required"],
        Kind::Array => &["type", "required", "items", "min_items", "max_items"],
        Kind::Table => &["type", "required", "fields"],
    }
}

pub(super) fn compile_rule(rule: &Table, path: &str) -> mlua::Result<Rule> {
    let type_name: String = rule
        .get::<Option<String>>("type")?
        .ok_or_else(|| bad_schema(path, "missing `type`"))?;
    let kind = Kind::parse(&type_name).ok_or_else(|| {
        bad_schema(
            path,
            format!(
                "unknown type `{type_name}` (expected string, number, integer, boolean, array or table)"
            ),
        )
    })?;

    for pair in rule.pairs::<Value, Value>() {
        let (key, _) = pair?;
        let Value::String(key) = key else {
            return Err(bad_schema(path, "rule keys must be strings"));
        };
        let key = key.to_string_lossy();
        if !allowed_keys(kind).contains(&key.as_ref()) {
            return Err(bad_schema(
                path,
                format!(
                    "unknown rule `{key}` for type `{}` (allowed: {})",
                    kind.name(),
                    allowed_keys(kind).join(", ")
                ),
            ));
        }
    }

    let format = match rule.get::<Option<String>>("format")? {
        Some(name) => Some(Format::parse(&name).ok_or_else(|| {
            let known: Vec<&str> = FORMATS.iter().map(|(n, _)| *n).collect();
            bad_schema(
                path,
                format!(
                    "unknown format `{name}` (expected one of: {})",
                    known.join(", ")
                ),
            )
        })?),
        None => None,
    };

    let one_of = match rule.get::<Option<Table>>("one_of")? {
        Some(list) => {
            let mut literals = Vec::new();
            for value in list.sequence_values::<Value>() {
                literals.push(match value? {
                    Value::String(s) => Literal::String(s.to_string_lossy().to_string()),
                    Value::Integer(n) => Literal::Number(n as f64),
                    Value::Number(n) => Literal::Number(n),
                    other => {
                        return Err(bad_schema(
                            path,
                            format!(
                                "`one_of` entries must be strings or numbers, got {}",
                                other.type_name()
                            ),
                        ));
                    }
                });
            }
            if literals.is_empty() {
                return Err(bad_schema(path, "`one_of` must not be empty"));
            }
            Some(literals)
        }
        None => None,
    };

    let items = match rule.get::<Option<Table>>("items")? {
        Some(items) => Some(Box::new(compile_rule(&items, &format!("{path}[]"))?)),
        None if kind == Kind::Array => {
            return Err(bad_schema(path, "type `array` requires `items`"));
        }
        None => None,
    };

    let fields = match rule.get::<Option<Table>>("fields")? {
        Some(fields) => Some(compile_fields(&fields, path)?),
        None if kind == Kind::Table => {
            return Err(bad_schema(path, "type `table` requires `fields`"));
        }
        None => None,
    };

    Ok(Rule {
        kind,
        required: rule.get::<Option<bool>>("required")?.unwrap_or(false),
        min: rule.get("min")?,
        max: rule.get("max")?,
        min_len: rule.get("min_len")?,
        max_len: rule.get("max_len")?,
        format,
        one_of,
        items,
        min_items: rule.get("min_items")?,
        max_items: rule.get("max_items")?,
        fields,
    })
}

/// Compiles a `{ name = rule, ... }` map, sorted so error output and
/// validation order are deterministic.
pub(super) fn compile_fields(fields: &Table, path: &str) -> mlua::Result<Vec<(String, Rule)>> {
    let mut compiled = Vec::new();
    for pair in fields.pairs::<Value, Value>() {
        let (name, rule) = pair?;
        let Value::String(name) = name else {
            return Err(bad_schema(path, "field names must be strings"));
        };
        let name = name.to_string_lossy().to_string();
        let field_path = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}.{name}")
        };
        let Value::Table(rule) = rule else {
            return Err(bad_schema(&field_path, "the rule must be a table"));
        };
        compiled.push((name, compile_rule(&rule, &field_path)?));
    }
    compiled.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(compiled)
}
