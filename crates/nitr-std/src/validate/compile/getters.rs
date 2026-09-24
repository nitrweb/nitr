// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Typed readers for rule-table keys: each refuses the wrong type with a
//! message naming the key, so a rule table is validated as strictly as
//! the input it will validate.

use mlua::{Table, Value};

use super::bad_schema;
use crate::validate::format::{Format, FormatRule};
use crate::validate::{Kind, Literal, TimeBound};

pub(super) fn describe_value(value: &Value) -> String {
    match value {
        Value::Integer(i) => i.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::String(s) => format!("\"{}\"", s.to_string_lossy()),
        other => other.type_name().to_string(),
    }
}

pub(super) fn get_string(rule: &Table, key: &str, path: &str) -> mlua::Result<Option<String>> {
    match rule.get::<Value>(key)? {
        Value::Nil => Ok(None),
        Value::String(s) => Ok(Some(s.to_string_lossy().to_string())),
        other => Err(bad_schema(
            path,
            format!("`{key}` must be a string, got {}", other.type_name()),
        )),
    }
}

pub(super) fn get_bool(rule: &Table, key: &str, path: &str) -> mlua::Result<Option<bool>> {
    match rule.get::<Value>(key)? {
        Value::Nil => Ok(None),
        Value::Boolean(b) => Ok(Some(b)),
        other => Err(bad_schema(
            path,
            format!("`{key}` must be true or false, got {}", other.type_name()),
        )),
    }
}

pub(super) fn get_f64(rule: &Table, key: &str, path: &str) -> mlua::Result<Option<f64>> {
    match rule.get::<Value>(key)? {
        Value::Nil => Ok(None),
        Value::Integer(i) => Ok(Some(i as f64)),
        Value::Number(n) if n.is_finite() => Ok(Some(n)),
        other => Err(bad_schema(
            path,
            format!("`{key}` must be a number, got {}", other.type_name()),
        )),
    }
}

/// A non-negative count (`min_len`, `max_items`, …).
pub(super) fn get_count(rule: &Table, key: &str, path: &str) -> mlua::Result<Option<usize>> {
    match rule.get::<Value>(key)? {
        Value::Nil => Ok(None),
        Value::Integer(i) if i >= 0 => Ok(Some(usize::try_from(i).unwrap_or(usize::MAX))),
        Value::Number(n) if n >= 0.0 && n.fract() == 0.0 => Ok(Some(n as usize)),
        other => Err(bad_schema(
            path,
            format!(
                "`{key}` must be a non-negative integer, got {}",
                describe_value(&other)
            ),
        )),
    }
}

/// A byte size: an integer, or `"512kb"`/`"2mb"`/`"1gb"`.
pub(crate) fn parse_size(raw: &str) -> Option<u64> {
    let raw = raw.trim().to_ascii_lowercase();
    let (digits, unit) = raw
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .map_or((raw.as_str(), ""), |i| raw.split_at(i));
    let value: f64 = digits.parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let mult: f64 = match unit.trim() {
        "" | "b" => 1.0,
        "kb" | "k" => 1024.0,
        "mb" | "m" => 1024.0 * 1024.0,
        "gb" | "g" => 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    let bytes = value * mult;
    (bytes <= u64::MAX as f64).then_some(bytes as u64)
}

pub(super) fn get_size(rule: &Table, key: &str, path: &str) -> mlua::Result<Option<u64>> {
    let hint = || format!("`{key}` must be a size like 512, \"512kb\" or \"2mb\"");
    match rule.get::<Value>(key)? {
        Value::Nil => Ok(None),
        Value::Integer(i) if i >= 0 => Ok(Some(i as u64)),
        Value::String(s) => parse_size(&s.to_string_lossy())
            .map(Some)
            .ok_or_else(|| bad_schema(path, hint())),
        other => Err(bad_schema(
            path,
            format!("{}, got {}", hint(), describe_value(&other)),
        )),
    }
}

fn literal_of(value: Value, key: &str, path: &str) -> mlua::Result<Literal> {
    Ok(match value {
        Value::String(s) => Literal::Str(s.to_string_lossy().to_string()),
        Value::Integer(n) => Literal::Num(n as f64),
        Value::Number(n) if n.is_finite() => Literal::Num(n),
        Value::Boolean(b) => Literal::Bool(b),
        other => {
            return Err(bad_schema(
                path,
                format!(
                    "`{key}` entries must be strings, numbers or booleans, got {}",
                    other.type_name()
                ),
            ));
        }
    })
}

/// A literal must fit the rule's type: `one_of = { 1, 2 }` on a string
/// rule could never match anything. Text that spells a value of the type
/// is that value: shorthand types an array's `contains:3` by the array,
/// not by the items it cannot see.
fn fit_literal(lit: Literal, kind: Kind, key: &str, path: &str) -> mlua::Result<Literal> {
    let lit = match (lit, kind) {
        (Literal::Str(text), Kind::Number | Kind::Integer) => match text.parse::<f64>() {
            Ok(n) if n.is_finite() => Literal::Num(n),
            _ => Literal::Str(text),
        },
        (Literal::Str(text), Kind::Boolean) => match text.as_str() {
            "true" => Literal::Bool(true),
            "false" => Literal::Bool(false),
            _ => Literal::Str(text),
        },
        (lit, _) => lit,
    };
    check_literal_kind(&lit, kind, key, path)?;
    Ok(lit)
}

fn check_literal_kind(lit: &Literal, kind: Kind, key: &str, path: &str) -> mlua::Result<()> {
    let ok = matches!(
        (lit, kind),
        (Literal::Str(_), Kind::String)
            | (Literal::Num(_), Kind::Number | Kind::Integer)
            | (Literal::Bool(_), Kind::Boolean)
            | (_, Kind::Any)
    );
    if ok {
        Ok(())
    } else {
        Err(bad_schema(
            path,
            format!(
                "`{key}` holds a value that a `{}` field can never equal",
                kind.name()
            ),
        ))
    }
}

pub(super) fn get_literal(
    rule: &Table,
    key: &str,
    kind: Kind,
    path: &str,
) -> mlua::Result<Option<Literal>> {
    match rule.get::<Value>(key)? {
        Value::Nil => Ok(None),
        value => Ok(Some(fit_literal(
            literal_of(value, key, path)?,
            kind,
            key,
            path,
        )?)),
    }
}

pub(super) fn get_literals(
    rule: &Table,
    key: &str,
    kind: Kind,
    path: &str,
) -> mlua::Result<Option<Vec<Literal>>> {
    match rule.get::<Option<Table>>(key)? {
        None => Ok(None),
        Some(list) => {
            let mut literals = Vec::new();
            for value in list.sequence_values::<Value>() {
                let lit = literal_of(value?, key, path)?;
                literals.push(fit_literal(lit, kind, key, path)?);
            }
            if literals.is_empty() {
                return Err(bad_schema(path, format!("`{key}` must not be empty")));
            }
            Ok(Some(literals))
        }
    }
}

pub(super) fn get_strings(
    rule: &Table,
    key: &str,
    path: &str,
) -> mlua::Result<Option<Vec<String>>> {
    match rule.get::<Value>(key)? {
        Value::Nil => Ok(None),
        Value::Table(list) => {
            let mut out = Vec::new();
            for value in list.sequence_values::<Value>() {
                match value? {
                    Value::String(s) => out.push(s.to_string_lossy().to_string()),
                    other => {
                        return Err(bad_schema(
                            path,
                            format!("`{key}` entries must be strings, got {}", other.type_name()),
                        ));
                    }
                }
            }
            if out.is_empty() {
                return Err(bad_schema(path, format!("`{key}` must not be empty")));
            }
            Ok(Some(out))
        }
        other => Err(bad_schema(
            path,
            format!(
                "`{key}` must be a list of strings, got {}",
                other.type_name()
            ),
        )),
    }
}

/// An `after`/`before` bound, which needs a temporal format to compare in.
pub(super) fn get_time_bound(
    rule: &Table,
    key: &str,
    path: &str,
    format: Option<&FormatRule>,
) -> mlua::Result<Option<TimeBound>> {
    let Some(raw) = get_string(rule, key, path)? else {
        return Ok(None);
    };
    let temporal = match format {
        Some(FormatRule::Builtin(f @ (Format::Date | Format::Datetime | Format::Time))) => f,
        _ => {
            return Err(bad_schema(
                path,
                format!("`{key}` needs `format = \"date\"`, `\"datetime\"` or `\"time\"`"),
            ));
        }
    };
    if raw == "now" {
        return Ok(Some(TimeBound::Now));
    }
    if !temporal.check(&raw) {
        return Err(bad_schema(
            path,
            format!("`{key}` must be \"now\" or a value in the field's format, got \"{raw}\""),
        ));
    }
    Ok(Some(TimeBound::Literal(raw)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_units_and_refuse_nonsense() {
        assert_eq!(parse_size("512"), Some(512));
        assert_eq!(parse_size("512kb"), Some(512 * 1024));
        assert_eq!(parse_size("2 MB"), Some(2 * 1024 * 1024));
        assert_eq!(parse_size("1.5mb"), Some(1536 * 1024));
        assert_eq!(parse_size("1g"), Some(1 << 30));
        for bad in ["", "-1", "2pb", "mb", "1e3", "nan"] {
            assert_eq!(parse_size(bad), None, "{bad}");
        }
    }

    #[test]
    fn literals_must_fit_the_rule_type() {
        let lua = mlua::Lua::new();
        let t: Table = lua.load(r#"{ one_of = { 1, "a" } }"#).eval().unwrap();
        assert!(get_literals(&t, "one_of", Kind::Number, "x").is_err());
        let t: Table = lua.load(r#"{ one_of = { 1, 2 } }"#).eval().unwrap();
        assert_eq!(
            get_literals(&t, "one_of", Kind::Integer, "x")
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        let t: Table = lua.load(r#"{ one_of = {} }"#).eval().unwrap();
        assert!(get_literals(&t, "one_of", Kind::String, "x").is_err());
    }
}
