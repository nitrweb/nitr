// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The pipe shorthand for a rule: `"string|trim|min_len:1|required"`.
//!
//! Not a second vocabulary — every token is a rule key with the same
//! meaning — only a second spelling. The parser turns the string into the
//! rule *table* the key would have been written as, and the table
//! compiler does the rest, so a typo fails with the same message either
//! way and `nitr.validate.expand` can show what a string means.

use mlua::{Lua, Table, Value};

/// Keys whose value is a comma-separated list.
const LIST_KEYS: &[&str] = &[
    "one_of",
    "not_one_of",
    "contains_any",
    "contains_all",
    "types",
    "extensions",
];

/// Keys whose value is a number.
const NUMBER_KEYS: &[&str] = &[
    "min",
    "max",
    "exclusive_min",
    "exclusive_max",
    "multiple_of",
    "decimals",
    "min_len",
    "max_len",
    "len",
    "min_items",
    "max_items",
    "min_keys",
    "max_keys",
    "min_width",
    "max_width",
    "min_height",
    "max_height",
    "max_pixels",
];

/// Keys that are `true` when given without a value.
const FLAG_KEYS: &[&str] = &[
    "required",
    "trim",
    "unique",
    "utf8",
    "allow_executables",
    "match_extension",
];

/// Keys whose literal is typed by the rule's own type (`default:3` on an
/// integer is a number, on a string it is text).
const TYPED_KEYS: &[&str] = &["default", "equals", "contains"];

/// The types that make the typed keys numeric.
const NUMERIC_TYPES: &[&str] = &["integer", "number"];

fn bad(shorthand: &str, msg: &str) -> mlua::Error {
    mlua::Error::RuntimeError(format!("invalid rule shorthand `{shorthand}`: {msg}"))
}

/// Splits on `sep`, honoring the `\<sep>` escape. Any other backslash
/// sequence is kept for a later pass: a `\,` inside a `|`-split token
/// must still be an escape when that token's list is split on `,`.
fn split_escaped(text: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&sep) {
            cur.push(sep);
            chars.next();
        } else if c == sep {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

/// A value nobody splits on `,` still honours the escape.
fn unescape(raw: &str) -> String {
    raw.replace("\\,", ",")
}

fn parse_number(shorthand: &str, key: &str, raw: &str) -> mlua::Result<Value> {
    if let Ok(i) = raw.parse::<i64>() {
        return Ok(Value::Integer(i));
    }
    match raw.parse::<f64>() {
        Ok(n) if n.is_finite() => Ok(Value::Number(n)),
        _ => Err(bad(
            shorthand,
            &format!("`{key}` needs a number, got `{raw}`"),
        )),
    }
}

fn parse_bool(shorthand: &str, key: &str, raw: &str) -> mlua::Result<Value> {
    match raw {
        "true" => Ok(Value::Boolean(true)),
        "false" => Ok(Value::Boolean(false)),
        _ => Err(bad(
            shorthand,
            &format!("`{key}` needs true or false, got `{raw}`"),
        )),
    }
}

/// A literal typed by the rule's own type.
fn parse_typed(
    lua: &Lua,
    shorthand: &str,
    key: &str,
    kind: &str,
    raw: &str,
) -> mlua::Result<Value> {
    if NUMERIC_TYPES.contains(&kind) {
        return parse_number(shorthand, key, raw);
    }
    if kind == "boolean" {
        return parse_bool(shorthand, key, raw);
    }
    Ok(Value::String(lua.create_string(raw)?))
}

/// Expands a shorthand string into the rule table it stands for.
pub(crate) fn expand(lua: &Lua, shorthand: &str) -> mlua::Result<Table> {
    if shorthand.len() > 4096 {
        return Err(bad("…", "longer than 4096 bytes"));
    }
    let tokens = split_escaped(shorthand, '|');
    let table = lua.create_table()?;
    let mut kind: Option<String> = None;
    let mut seen: Vec<String> = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let token = token.trim();
        if token.is_empty() {
            return Err(bad(shorthand, "empty token (a stray `|`?)"));
        }
        if i == 0 {
            // The type comes first, bare.
            if token.contains(':') {
                return Err(bad(shorthand, "the first token must be the type"));
            }
            table.set("type", token)?;
            kind = Some(token.to_string());
            continue;
        }
        let (key, raw) = match token.split_once(':') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (token, None),
        };
        if !key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            || key.is_empty()
        {
            return Err(bad(shorthand, &format!("bad token `{token}`")));
        }
        if seen.iter().any(|s| s == key) {
            return Err(bad(shorthand, &format!("`{key}` given twice")));
        }
        seen.push(key.to_string());
        let kind = kind.as_deref().unwrap_or_default();
        let value: Value = match raw {
            None if FLAG_KEYS.contains(&key) => Value::Boolean(true),
            None => {
                return Err(bad(
                    shorthand,
                    &format!("`{key}` needs a value (`{key}:…`)"),
                ));
            }
            Some(raw) if FLAG_KEYS.contains(&key) => parse_bool(shorthand, key, raw)?,
            Some(raw) if NUMBER_KEYS.contains(&key) => parse_number(shorthand, key, raw)?,
            Some(raw) if LIST_KEYS.contains(&key) => {
                let list = lua.create_table()?;
                for (n, item) in split_escaped(raw, ',').iter().enumerate() {
                    let item = item.trim();
                    if item.is_empty() {
                        return Err(bad(shorthand, &format!("`{key}` has an empty entry")));
                    }
                    let typed = if key == "types" || key == "extensions" {
                        Value::String(lua.create_string(item)?)
                    } else {
                        parse_typed(lua, shorthand, key, kind, item)?
                    };
                    list.raw_set(n + 1, typed)?;
                }
                Value::Table(list)
            }
            Some(raw) if TYPED_KEYS.contains(&key) => {
                parse_typed(lua, shorthand, key, kind, &unescape(raw))?
            }
            Some(raw) => Value::String(lua.create_string(unescape(raw))?),
        };
        table.set(key, value)?;
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn shorthand_expands_to_the_table_form() {
        let lua = Lua::new();
        let t = expand(
            &lua,
            "string|trim|min_len:1|max_len:500|required|one_of:a,b",
        )
        .expect("ok");
        assert_eq!(t.get::<String>("type").unwrap(), "string");
        assert!(t.get::<bool>("trim").unwrap());
        assert_eq!(t.get::<i64>("min_len").unwrap(), 1);
        assert!(t.get::<bool>("required").unwrap());
        let one_of: Table = t.get("one_of").unwrap();
        assert_eq!(one_of.get::<String>(2).unwrap(), "b");

        let t = expand(&lua, "integer|min:13|default:3|one_of:1,2").expect("ok");
        assert_eq!(t.get::<i64>("default").unwrap(), 3);
        let one_of: Table = t.get("one_of").unwrap();
        assert_eq!(one_of.get::<i64>(1).unwrap(), 1);

        let t = expand(&lua, r"string|contains:a\|b|starts_with:x\,y").expect("ok");
        assert_eq!(t.get::<String>("contains").unwrap(), "a|b");
        assert_eq!(t.get::<String>("starts_with").unwrap(), "x,y");
        // A key with a digit is a key.
        let t = expand(&lua, "file|utf8|max_bytes:10").expect("ok");
        assert!(t.get::<bool>("utf8").unwrap());
        // An escaped comma inside a list entry survives both splits.
        let t = expand(&lua, r"string|one_of:a\,b,c\|d").expect("ok");
        let one_of: Table = t.get("one_of").unwrap();
        assert_eq!(one_of.get::<String>(1).unwrap(), "a,b");
        assert_eq!(one_of.get::<String>(2).unwrap(), "c|d");
        assert_eq!(one_of.len().unwrap(), 2);
    }

    #[test]
    fn malformed_shorthand_is_refused_by_name() {
        let lua = Lua::new();
        for (bad, needle) in [
            ("|||", "empty token"),
            ("string|min_len", "needs a value"),
            ("string|min_len:abc", "needs a number"),
            ("string|min_len:1|min_len:2", "given twice"),
            ("string|Min_len:1", "bad token"),
            ("string|min-len:1", "bad token"),
            ("string|one_of:a,,b", "empty entry"),
            ("string|min_len:1e309", "needs a number"),
            ("type:string", "first token must be the type"),
        ] {
            let err = expand(&lua, bad).expect_err(bad).to_string();
            assert!(err.contains(needle), "{bad}: {err}");
        }
    }

    fn escaped(item: &str) -> String {
        item.replace('|', "\\|").replace(',', "\\,")
    }

    proptest::proptest! {
        /// A well-formed shorthand expands to exactly the keys it names,
        /// with the separators it escaped intact.
        #[test]
        fn expansion_keeps_every_token(
            max_len in 0i64..100_000,
            flag in proptest::sample::select(FLAG_KEYS.to_vec()),
            items in proptest::collection::vec("[a-z|,]{1,6}", 1..4),
            prefix in "[a-z|,:]{1,10}",
        ) {
            let lua = Lua::new();
            let list = items.iter().map(|i| escaped(i)).collect::<Vec<_>>().join(",");
            let shorthand = format!(
                "string|max_len:{max_len}|{flag}|one_of:{list}|starts_with:{}",
                escaped(&prefix)
            );
            let t = expand(&lua, &shorthand).expect("well-formed");
            prop_assert_eq!(t.get::<String>("type").unwrap(), "string");
            prop_assert_eq!(t.get::<i64>("max_len").unwrap(), max_len);
            prop_assert!(t.get::<bool>(flag).unwrap());
            prop_assert_eq!(t.get::<String>("starts_with").unwrap(), prefix);
            let one_of: Table = t.get("one_of").unwrap();
            prop_assert_eq!(one_of.len().unwrap() as usize, items.len());
            for (i, item) in items.iter().enumerate() {
                prop_assert_eq!(&one_of.get::<String>(i + 1).unwrap(), item);
            }
        }

        /// Any string is either expanded or refused; a refusal names the
        /// shorthand, and an expansion always carries the type.
        #[test]
        fn hostile_shorthand_never_panics(text in "[a-z|,:\\\\ ]{0,40}") {
            let lua = Lua::new();
            match expand(&lua, &text) {
                Ok(t) => prop_assert!(t.contains_key("type").unwrap()),
                Err(err) => prop_assert!(err.to_string().contains("shorthand")),
            }
        }
    }
}
