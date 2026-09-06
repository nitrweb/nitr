// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Text inputs — a query string, a form, path parameters, headers — are
//! strings; the schema says what they mean. This turns the raw pairs into
//! the typed table the checker expects: `integer`/`number`/`boolean`
//! parsed strictly, repeated keys collected for `array` rules, blank
//! optional non-string fields treated as absent, `name[]` as `name`.
//!
//! A value that does not parse is left as the string it was, so the
//! checker's own type rule reports it — one message for one mistake.

use mlua::{AnyUserData, Lua, Table, Value};

use super::{Kind, Rule, SchemaDef};

/// One text-part value: a string field, or a spooled upload.
#[derive(Debug)]
pub enum TextValue {
    /// A form field, query parameter, path parameter or header value.
    Text(String),
    /// A validated upload (`nitr.File` userdata), for multipart parts.
    File(AnyUserData),
}

/// Strict decimal integer: the text must be the integer's own spelling —
/// no `+`, no whitespace, no exponent, no leading zeros, no `-0`, no
/// overflow. Spelled as one relation (`parsed.to_string() == text`) so
/// the rule cannot drift from its list.
fn parse_integer(text: &str) -> Option<i64> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>()
        .ok()
        .filter(|parsed| parsed.to_string() == text)
}

fn parse_number(text: &str) -> Option<f64> {
    if text.is_empty() || text.starts_with('+') || text.trim() != text {
        return None;
    }
    if text.contains(['x', 'X', 'n', 'N', 'i', 'I', 'e', 'E']) {
        // `0x10`, `nan`, `inf`, `1e3`: a form never means those.
        return None;
    }
    text.parse::<f64>().ok().filter(|n| n.is_finite())
}

fn parse_boolean(text: &str) -> Option<bool> {
    match text {
        "true" | "1" | "on" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

/// Coerces one text value to the rule's scalar kind, or leaves it as the
/// string it was so the checker names the type mismatch.
fn coerce_scalar(lua: &Lua, rule: &Rule, text: &str) -> mlua::Result<Value> {
    Ok(match rule.kind {
        Kind::Integer => match parse_integer(text) {
            Some(i) => Value::Integer(i),
            None => Value::String(lua.create_string(text)?),
        },
        Kind::Number => match parse_number(text) {
            Some(n) if n.fract() == 0.0 && n.abs() < 9.0e15 => Value::Integer(n as i64),
            Some(n) => Value::Number(n),
            None => Value::String(lua.create_string(text)?),
        },
        Kind::Boolean => match parse_boolean(text) {
            Some(b) => Value::Boolean(b),
            None => Value::String(lua.create_string(text)?),
        },
        _ => Value::String(lua.create_string(text)?),
    })
}

/// Whether a blank text value means "not given" for this rule: every
/// kind but `string`, where the empty string is a value and `min_len`
/// decides.
fn blank_is_absent(rule: &Rule, text: &str) -> bool {
    rule.kind != Kind::String && text.trim().is_empty()
}

/// Builds the typed table for the checker from raw text pairs.
pub(super) fn build_table(
    lua: &Lua,
    schema: &SchemaDef,
    pairs: Vec<(String, TextValue)>,
) -> mlua::Result<Table> {
    let out = lua.create_table()?;
    // Group by normalized name, keeping arrival order within a name.
    let mut grouped: Vec<(String, Vec<TextValue>)> = Vec::new();
    for (name, value) in pairs {
        let name = name.strip_suffix("[]").unwrap_or(&name).to_string();
        match grouped.iter_mut().find(|(n, _)| *n == name) {
            Some((_, values)) => values.push(value),
            None => grouped.push((name, vec![value])),
        }
    }
    for (name, values) in grouped {
        match schema.rule(&name) {
            Some(rule) if rule.kind == Kind::Array => {
                // Invariant: schema compilation only builds an array rule
                // with its `items` present.
                #[allow(clippy::expect_used)]
                let items = rule.items.as_ref().expect("array rules carry `items`");
                let list = lua.create_table_with_capacity(values.len(), 0)?;
                let mut n = 0;
                for value in values {
                    let item = match value {
                        TextValue::Text(text) => {
                            if blank_is_absent(items, &text) {
                                continue;
                            }
                            coerce_scalar(lua, items, &text)?
                        }
                        TextValue::File(ud) => Value::UserData(ud),
                    };
                    n += 1;
                    list.raw_set(n, item)?;
                }
                out.set(name.as_str(), list)?;
            }
            Some(rule) => {
                // Last value wins, like `req.query`.
                let Some(last) = values.into_iter().last() else {
                    continue;
                };
                let value = match last {
                    TextValue::Text(text) => {
                        if blank_is_absent(rule, &text) {
                            continue;
                        }
                        coerce_scalar(lua, rule, &text)?
                    }
                    TextValue::File(ud) => Value::UserData(ud),
                };
                out.set(name.as_str(), value)?;
            }
            None => {
                // Undeclared: kept as raw text so `strict` can report it;
                // the checker strips it otherwise.
                let Some(last) = values.into_iter().last() else {
                    continue;
                };
                let value = match last {
                    TextValue::Text(text) => Value::String(lua.create_string(&text)?),
                    TextValue::File(ud) => Value::UserData(ud),
                };
                out.set(name.as_str(), value)?;
            }
        }
    }
    Ok(out)
}

/// Exposed for the `validate-coerce` fuzz target: the three strict parsers
/// over arbitrary text.
#[doc(hidden)]
pub fn coerce_for_fuzzing(text: &str) -> (Option<i64>, Option<f64>, Option<bool>) {
    (parse_integer(text), parse_number(text), parse_boolean(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_parse_strictly() {
        for ok in ["0", "42", "-7", "9223372036854775807"] {
            assert!(parse_integer(ok).is_some(), "{ok}");
        }
        for bad in [
            "",
            "+5",
            " 5",
            "5 ",
            "1e3",
            "0x10",
            "1.0",
            "007",
            "-0",
            "99999999999999999999",
            "٣",
        ] {
            assert!(parse_integer(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn numbers_and_booleans_parse_the_form_way() {
        assert_eq!(parse_number("1.5"), Some(1.5));
        assert_eq!(parse_number("-2"), Some(-2.0));
        for bad in ["", "+1", "1e3", "1e400", "inf", "nan", "0x1", " 1"] {
            assert!(parse_number(bad).is_none(), "{bad}");
        }
        assert_eq!(parse_boolean("on"), Some(true));
        assert_eq!(parse_boolean("0"), Some(false));
        assert_eq!(parse_boolean("yes"), None);
    }
}
