// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The per-type rule keys: strings, numbers, arrays, tables and maps.

use std::sync::Arc;

use mlua::{Lua, Table, Value};

use super::getters::{
    get_bool, get_count, get_f64, get_literal, get_literals, get_size, get_string, get_time_bound,
};
use super::{bad_schema, compile_rule_value, compile_schema_at};
use crate::validate::format::{self, FormatRule};
use crate::validate::{Case, Kind, Rule, schema_of};

pub(super) fn compile_string(
    lua: &Lua,
    rule: &Table,
    out: &mut Rule,
    path: &str,
) -> mlua::Result<()> {
    out.trim = get_bool(rule, "trim", path)?.unwrap_or(false);
    out.case = match get_string(rule, "case", path)?.as_deref() {
        None => None,
        Some("lower") => Some(Case::Lower),
        Some("upper") => Some(Case::Upper),
        Some(other) => {
            return Err(bad_schema(
                path,
                format!("`case` must be \"lower\" or \"upper\", got \"{other}\""),
            ));
        }
    };
    out.min_len = get_count(rule, "min_len", path)?;
    out.max_len = get_count(rule, "max_len", path)?;
    out.len = get_count(rule, "len", path)?;
    if let (Some(min), Some(max)) = (out.min_len, out.max_len)
        && min > max
    {
        return Err(bad_schema(path, "`min_len` is greater than `max_len`"));
    }
    out.format = match get_string(rule, "format", path)? {
        Some(name) => Some(FormatRule::resolve(lua, &name).ok_or_else(|| {
            bad_schema(
                path,
                format!(
                    "unknown format `{name}` (expected one of: {})",
                    format::all_format_names(lua).join(", ")
                ),
            )
        })?),
        None => None,
    };
    for (key, target) in [
        ("starts_with", &mut out.starts_with),
        ("ends_with", &mut out.ends_with),
        ("contains", &mut out.contains),
        ("does_not_contain", &mut out.does_not_contain),
    ] {
        *target = get_string(rule, key, path)?;
        if target.as_deref() == Some("") {
            return Err(bad_schema(path, format!("`{key}` must not be empty")));
        }
    }
    out.after = get_time_bound(rule, "after", path, out.format.as_ref())?;
    out.before = get_time_bound(rule, "before", path, out.format.as_ref())?;
    Ok(())
}

pub(super) fn compile_number(rule: &Table, out: &mut Rule, path: &str) -> mlua::Result<()> {
    out.min = get_f64(rule, "min", path)?;
    out.max = get_f64(rule, "max", path)?;
    out.exclusive_min = get_f64(rule, "exclusive_min", path)?;
    out.exclusive_max = get_f64(rule, "exclusive_max", path)?;
    out.multiple_of = get_f64(rule, "multiple_of", path)?;
    if let (Some(min), Some(max)) = (out.min, out.max)
        && min > max
    {
        return Err(bad_schema(path, "`min` is greater than `max`"));
    }
    if out.multiple_of.is_some_and(|step| step <= 0.0) {
        return Err(bad_schema(path, "`multiple_of` must be positive"));
    }
    if out.kind == Kind::Number {
        out.decimals = get_count(rule, "decimals", path)?.map(|d| d.min(20) as u32);
    }
    Ok(())
}

pub(super) fn compile_array(
    lua: &Lua,
    rule: &Table,
    out: &mut Rule,
    path: &str,
    depth: usize,
) -> mlua::Result<()> {
    let items = match rule.get::<Value>("items")? {
        Value::Nil => return Err(bad_schema(path, "type `array` requires `items`")),
        value => compile_rule_value(lua, value, &format!("{path}[]"), depth + 1)?,
    };
    let item_kind = items.kind;
    out.items = Some(Arc::new(items));
    out.min_items = get_count(rule, "min_items", path)?;
    out.max_items = get_count(rule, "max_items", path)?;
    if let (Some(min), Some(max)) = (out.min_items, out.max_items)
        && min > max
    {
        return Err(bad_schema(path, "`min_items` is greater than `max_items`"));
    }
    out.unique = get_bool(rule, "unique", path)?.unwrap_or(false);
    // Literal keys on an array describe its items.
    out.contains_item = get_literal(rule, "contains", item_kind, path)?;
    out.contains_any = get_literals(rule, "contains_any", item_kind, path)?;
    out.contains_all = get_literals(rule, "contains_all", item_kind, path)?;
    out.max_total_bytes = get_size(rule, "max_total_bytes", path)?;
    if out.max_total_bytes.is_some() && item_kind != Kind::File {
        return Err(bad_schema(
            path,
            "`max_total_bytes` applies to an array of `file` rules",
        ));
    }
    Ok(())
}

pub(super) fn compile_table(
    lua: &Lua,
    rule: &Table,
    out: &mut Rule,
    path: &str,
    depth: usize,
) -> mlua::Result<()> {
    out.fields = Some(match rule.get::<Value>("fields")? {
        Value::Nil => return Err(bad_schema(path, "type `table` requires `fields`")),
        Value::Table(fields) => Arc::new(compile_schema_at(lua, &fields, None, path, depth + 1)?),
        Value::UserData(ud) => schema_of(&ud)
            .ok_or_else(|| bad_schema(path, "`fields` must be a table of rules or a schema"))?,
        other => {
            return Err(bad_schema(
                path,
                format!(
                    "`fields` must be a table of rules, got {}",
                    other.type_name()
                ),
            ));
        }
    });
    Ok(())
}

pub(super) fn compile_map(
    lua: &Lua,
    rule: &Table,
    out: &mut Rule,
    path: &str,
    depth: usize,
) -> mlua::Result<()> {
    out.keys = match rule.get::<Value>("keys")? {
        Value::Nil => None,
        value => {
            let key_rule = compile_rule_value(lua, value, &format!("{path}{{key}}"), depth + 1)?;
            if key_rule.kind != Kind::String {
                return Err(bad_schema(
                    path,
                    "`keys` must be a `string` rule (JSON keys are strings)",
                ));
            }
            Some(Arc::new(key_rule))
        }
    };
    out.values = match rule.get::<Value>("values")? {
        Value::Nil => return Err(bad_schema(path, "type `map` requires `values`")),
        value => Some(Arc::new(compile_rule_value(
            lua,
            value,
            &format!("{path}{{}}"),
            depth + 1,
        )?)),
    };
    out.min_keys = get_count(rule, "min_keys", path)?;
    out.max_keys = get_count(rule, "max_keys", path)?;
    if out.max_keys.is_none() {
        return Err(bad_schema(
            path,
            "type `map` requires `max_keys`: an unbounded map is an unbounded allocation",
        ));
    }
    Ok(())
}
