// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Small pure helpers the checker leans on: canonical equality, decimal
//! counting, the type a replacement must have, and the contract a custom
//! check's return values follow.

use mlua::Value;

use super::super::Kind;

/// How many digits follow the decimal point in the shortest
/// round-tripping decimal form of `n`.
pub(super) fn fraction_digits(n: f64) -> u32 {
    let text = format!("{n}");
    match text.split_once('.') {
        Some((_, frac)) => frac.trim_end_matches('0').len() as u32,
        None => 0,
    }
}

/// A canonical string for equality (`unique`, `equal_fields`): scalars by
/// type and value, tables by their JSON, anything else by identity.
pub(super) fn canonical(value: &Value) -> mlua::Result<String> {
    Ok(match value {
        Value::String(s) => format!("s:{}", s.to_string_lossy()),
        // The float form where it is exact, so `1` equals `1.0`; above
        // 2^53 it is not, and distinct integers would collide.
        Value::Integer(i) if *i as f64 as i128 == *i as i128 => format!("n:{}", *i as f64),
        Value::Integer(i) => format!("n:{i}"),
        Value::Number(n) => format!("n:{n}"),
        Value::Boolean(b) => format!("b:{b}"),
        Value::Table(_) => {
            crate::utils::check_json_bounds(value)?;
            match crate::bounded::to_json_string(value) {
                Ok(json) => format!("t:{json}"),
                Err(_) => format!("p:{:?}", value.to_pointer()),
            }
        }
        other => format!("p:{:?}", other.to_pointer()),
    })
}

/// Whether `t` is a list: its keys are exactly `1..=#t`. A JSON object
/// arrives as a Lua table too, and has no array part.
pub(super) fn is_sequence(t: &mlua::Table) -> mlua::Result<bool> {
    let len = t.raw_len() as i64;
    for pair in t.pairs::<Value, Value>() {
        match pair?.0 {
            Value::Integer(key) if (1..=len).contains(&key) => {}
            _ => return Ok(false),
        }
    }
    Ok(true)
}

/// Whether a replacement a check returned has the type its rule demands.
pub(super) fn matches_kind(value: &Value, kind: Kind) -> bool {
    match kind {
        Kind::String => matches!(value, Value::String(_)),
        Kind::Integer => matches!(value, Value::Integer(_)),
        Kind::Number => matches!(value, Value::Integer(_) | Value::Number(_)),
        Kind::Boolean => matches!(value, Value::Boolean(_)),
        Kind::Array | Kind::Table | Kind::Map => matches!(value, Value::Table(_)),
        Kind::Any => true,
        Kind::File => matches!(value, Value::UserData(_)),
    }
}

/// What a check returned: `true` (a second value is ignored) or
/// `false|nil, reason`. Anything else is a caller bug and raises.
pub(super) enum Verdict {
    Pass,
    Fail(Option<Value>),
}

pub(super) fn verdict(results: mlua::MultiValue, what: &str) -> mlua::Result<Verdict> {
    let mut iter = results.into_iter();
    let first = iter.next().unwrap_or(Value::Nil);
    let second = iter.next().filter(|v| !v.is_nil());
    match first {
        Value::Boolean(true) => Ok(Verdict::Pass),
        Value::Boolean(false) | Value::Nil => Ok(Verdict::Fail(second)),
        other => Err(mlua::Error::RuntimeError(format!(
            "{what} must return true, or false/nil and a reason; got {}",
            other.type_name()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::Lua;

    #[test]
    fn decimals_count_the_shortest_form() {
        assert_eq!(fraction_digits(1.0), 0);
        assert_eq!(fraction_digits(1.5), 1);
        assert_eq!(fraction_digits(19.99), 2);
        assert_eq!(fraction_digits(0.1 + 0.2), 17);
    }

    #[test]
    fn canonical_forms_separate_types_and_unify_numbers() {
        let lua = Lua::new();
        let s = |v: Value| canonical(&v).unwrap();
        assert_ne!(
            s(Value::Integer(1)),
            s(Value::String(lua.create_string("1").unwrap()))
        );
        assert_eq!(s(Value::Integer(1)), s(Value::Number(1.0)));
        let t: Value = lua.load("{ a = 1 }").eval().unwrap();
        let u: Value = lua.load("{ a = 1 }").eval().unwrap();
        assert_eq!(s(t), s(u));
        // A mixed table is not its list part: two that differ only in a
        // named key are two values.
        let t: Value = lua.load("{ 'a', x = 1 }").eval().unwrap();
        let u: Value = lua.load("{ 'a', x = 2 }").eval().unwrap();
        assert_ne!(s(t), s(u));
    }

    #[test]
    fn verdicts_follow_the_nil_reason_idiom() {
        let lua = Lua::new();
        let ok = mlua::MultiValue::from_vec(vec![Value::Boolean(true)]);
        assert!(matches!(verdict(ok, "x").unwrap(), Verdict::Pass));
        let fail = mlua::MultiValue::from_vec(vec![
            Value::Nil,
            Value::String(lua.create_string("why").unwrap()),
        ]);
        assert!(matches!(
            verdict(fail, "x").unwrap(),
            Verdict::Fail(Some(Value::String(_)))
        ));
        let bad = mlua::MultiValue::from_vec(vec![Value::Integer(1)]);
        assert!(verdict(bad, "x").is_err());
        assert!(matches_kind(&Value::Integer(1), Kind::Number));
        assert!(!matches_kind(&Value::Number(1.5), Kind::Integer));
    }
}
