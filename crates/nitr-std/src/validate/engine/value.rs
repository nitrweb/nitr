// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! One value against one rule: the type check and coercion-independent
//! rules per kind, in the documented order — type, transforms, the common
//! rules, the kind's own rules, the format — with script checks deferred.

use std::sync::Arc;

use mlua::{LuaSerdeExt, Value};

use super::path::FieldPath;
use super::util::{canonical, fraction_digits, is_sequence};
use super::{Ctx, Pending, PendingCheck, Slot};
use crate::validate::file::LuaFile;
use crate::validate::format::{Format, FormatRule, parse_time};
use crate::validate::message::Param;
use crate::validate::{Case, Kind, Literal, Rule, SchemaDef, TimeBound};

fn choices(list: &[Literal]) -> Param {
    Param::List(list.iter().map(Literal::param).collect())
}

impl Ctx<'_> {
    /// Validates one value against a rule. On success returns the value to
    /// place in the output (tables are rebuilt with only declared fields,
    /// strings transformed); on failure records the message and returns
    /// `None`.
    pub(super) fn check_value(
        &mut self,
        rule: &Arc<Rule>,
        owner: &Arc<SchemaDef>,
        value: Value,
        path: &FieldPath<'_>,
        slot: Slot,
    ) -> mlua::Result<Option<Value>> {
        let field = path.field_name();
        macro_rules! fail {
            ($rule:expr, $params:expr) => {{
                let p = path.render();
                self.fail(
                    &p,
                    field,
                    $rule,
                    rule.kind,
                    $params,
                    Some(rule),
                    owner,
                    None,
                    None,
                );
                return Ok(None);
            }};
        }
        macro_rules! common_rules {
            ($value:expr) => {
                if let Some(expected) = &rule.equals
                    && !expected.matches(&$value)
                {
                    fail!("equals", vec![("expected", expected.param())]);
                }
                if let Some(list) = &rule.one_of
                    && !list.iter().any(|l| l.matches(&$value))
                {
                    fail!("one_of", vec![("choices", choices(list))]);
                }
                if let Some(list) = &rule.not_one_of
                    && list.iter().any(|l| l.matches(&$value))
                {
                    fail!("not_one_of", vec![("choices", choices(list))]);
                }
            };
        }
        let type_params = || vec![("type", Param::Str(rule.kind.name().into()))];

        let checked: Value = match rule.kind {
            Kind::String => {
                let Value::String(s) = &value else {
                    fail!("type", type_params());
                };
                let mut s = s.to_string_lossy().to_string();
                if rule.trim {
                    s = s.trim().to_string();
                }
                match rule.case {
                    Some(Case::Lower) => s = s.to_lowercase(),
                    Some(Case::Upper) => s = s.to_uppercase(),
                    None => {}
                }
                let value = Value::String(self.lua.create_string(&s)?);
                common_rules!(value);
                let len = s.chars().count();
                if let Some(min) = rule.min_len
                    && len < min
                {
                    fail!("min_len", vec![("min", Param::Num(min as f64))]);
                }
                if let Some(max) = rule.max_len
                    && len > max
                {
                    fail!("max_len", vec![("max", Param::Num(max as f64))]);
                }
                if let Some(exact) = rule.len
                    && len != exact
                {
                    fail!("len", vec![("len", Param::Num(exact as f64))]);
                }
                let literal_rules: [(&str, &Option<String>, bool); 4] = [
                    (
                        "starts_with",
                        &rule.starts_with,
                        s.starts_with(rule.starts_with.as_deref().unwrap_or_default()),
                    ),
                    (
                        "ends_with",
                        &rule.ends_with,
                        s.ends_with(rule.ends_with.as_deref().unwrap_or_default()),
                    ),
                    (
                        "contains",
                        &rule.contains,
                        s.contains(rule.contains.as_deref().unwrap_or_default()),
                    ),
                    (
                        "does_not_contain",
                        &rule.does_not_contain,
                        !s.contains(rule.does_not_contain.as_deref().unwrap_or_default()),
                    ),
                ];
                for (name, literal, holds) in literal_rules {
                    if let Some(text) = literal
                        && !holds
                    {
                        fail!(name, vec![("text", Param::Str(text.clone()))]);
                    }
                }
                match &rule.format {
                    Some(FormatRule::Builtin(format)) => {
                        if !format.check(&s) {
                            fail!(
                                "format",
                                vec![("format", Param::Str(format.describe().into()))]
                            );
                        }
                        for (key, bound, after) in [
                            ("after", &rule.after, true),
                            ("before", &rule.before, false),
                        ] {
                            if let Some(bound) = bound
                                && !self.within_bound(*format, &s, bound, after)
                            {
                                let limit = match bound {
                                    TimeBound::Now => "now".to_string(),
                                    TimeBound::Literal(l) => l.clone(),
                                };
                                fail!(key, vec![("limit", Param::Str(limit))]);
                            }
                        }
                    }
                    Some(FormatRule::Custom(custom)) => self.pending.push(Pending::Field {
                        slot: Slot {
                            table: slot.table.clone(),
                            key: slot.key.clone(),
                        },
                        path: path.render(),
                        field: field.to_string(),
                        rule: rule.clone(),
                        owner: owner.clone(),
                        value: value.clone(),
                        check: PendingCheck::Format(custom.clone()),
                    }),
                    None => {}
                }
                value
            }
            Kind::Number | Kind::Integer => {
                let n = match &value {
                    Value::Integer(n) => *n as f64,
                    Value::Number(n) => *n,
                    _ => fail!("type", type_params()),
                };
                if !n.is_finite() || (rule.kind == Kind::Integer && n.fract() != 0.0) {
                    fail!("type", type_params());
                }
                common_rules!(value);
                if let Some(min) = rule.min
                    && n < min
                {
                    fail!("min", vec![("min", Param::Num(min))]);
                }
                if let Some(max) = rule.max
                    && n > max
                {
                    fail!("max", vec![("max", Param::Num(max))]);
                }
                if let Some(min) = rule.exclusive_min
                    && n <= min
                {
                    fail!("exclusive_min", vec![("min", Param::Num(min))]);
                }
                if let Some(max) = rule.exclusive_max
                    && n >= max
                {
                    fail!("exclusive_max", vec![("max", Param::Num(max))]);
                }
                if let Some(step) = rule.multiple_of {
                    let quotient = n / step;
                    if (quotient - quotient.round()).abs() > 1e-9 * quotient.abs().max(1.0) {
                        fail!("multiple_of", vec![("step", Param::Num(step))]);
                    }
                }
                if let Some(decimals) = rule.decimals
                    && fraction_digits(n) > decimals
                {
                    fail!(
                        "decimals",
                        vec![("decimals", Param::Num(f64::from(decimals)))]
                    );
                }
                value
            }
            Kind::Boolean => {
                let Value::Boolean(_) = value else {
                    fail!("type", type_params());
                };
                common_rules!(value);
                value
            }
            Kind::Array => {
                let Value::Table(t) = &value else {
                    fail!("type", type_params());
                };
                if !is_sequence(t)? {
                    fail!("type", type_params());
                }
                let len = t.raw_len();
                if let Some(min) = rule.min_items
                    && len < min
                {
                    fail!("min_items", vec![("min", Param::Num(min as f64))]);
                }
                if let Some(max) = rule.max_items
                    && len > max
                {
                    fail!("max_items", vec![("max", Param::Num(max as f64))]);
                }
                // Invariant: schema compilation only builds an array rule
                // with its `items` present.
                #[allow(clippy::expect_used)]
                let items = rule.items.as_ref().expect("array rules carry `items`");
                let out = self.lua.create_table_with_capacity(len, 0)?;
                let mut ok = true;
                let mut seen: Vec<String> = Vec::new();
                let mut total_bytes: u64 = 0;
                for i in 1..=len {
                    let item: Value = t.raw_get(i)?;
                    if rule.unique {
                        let canon = canonical(&item)?;
                        if seen.contains(&canon) {
                            fail!("unique", Vec::new());
                        }
                        seen.push(canon);
                    }
                    if let Value::UserData(ud) = &item
                        && let Ok(file) = ud.borrow::<LuaFile>()
                    {
                        total_bytes = total_bytes.saturating_add(file.info().size);
                    }
                    let item_slot = Slot {
                        table: out.clone(),
                        key: Value::Integer(i as i64),
                    };
                    match self.check_value(items, owner, item, &path.index(i), item_slot)? {
                        Some(item) => out.raw_set(i, item)?,
                        None => ok = false,
                    }
                }
                if !ok {
                    return Ok(None);
                }
                if let Some(max) = rule.max_total_bytes
                    && total_bytes > max
                {
                    fail!("max_total_bytes", vec![("max", Param::Size(max))]);
                }
                let has = |lit: &Literal| -> mlua::Result<bool> {
                    for i in 1..=len {
                        if lit.matches(&out.raw_get::<Value>(i)?) {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                };
                if let Some(item) = &rule.contains_item
                    && !has(item)?
                {
                    fail!("contains", vec![("item", item.param())]);
                }
                if let Some(list) = &rule.contains_any {
                    let mut any = false;
                    for lit in list {
                        any |= has(lit)?;
                    }
                    if !any {
                        fail!("contains_any", vec![("choices", choices(list))]);
                    }
                }
                if let Some(list) = &rule.contains_all {
                    for lit in list {
                        if !has(lit)? {
                            fail!("contains_all", vec![("choices", choices(list))]);
                        }
                    }
                }
                Value::Table(out)
            }
            Kind::Table => {
                let Value::Table(t) = &value else {
                    fail!("type", type_params());
                };
                if t.raw_len() > 0 {
                    fail!("type", type_params());
                }
                // Invariant: schema compilation only builds a table rule
                // with its `fields` present.
                #[allow(clippy::expect_used)]
                let schema = rule.fields.as_ref().expect("table rules carry `fields`");
                let out = self.lua.create_table()?;
                if !self.check_fields(schema, t, path, &out)? {
                    return Ok(None);
                }
                Value::Table(out)
            }
            Kind::Map => {
                let Value::Table(t) = &value else {
                    fail!("type", type_params());
                };
                let mut count = 0usize;
                for pair in t.pairs::<Value, Value>() {
                    let _ = pair?;
                    count += 1;
                }
                if let Some(min) = rule.min_keys
                    && count < min
                {
                    fail!("min_keys", vec![("min", Param::Num(min as f64))]);
                }
                if let Some(max) = rule.max_keys
                    && count > max
                {
                    fail!("max_keys", vec![("max", Param::Num(max as f64))]);
                }
                // Invariant: schema compilation only builds a map rule with
                // its `values` present.
                #[allow(clippy::expect_used)]
                let values = rule.values.as_ref().expect("map rules carry `values`");
                let out = self.lua.create_table()?;
                let mut ok = true;
                for pair in t.pairs::<Value, Value>() {
                    let (key, item) = pair?;
                    let Value::String(key_str) = &key else {
                        let p = path.render();
                        self.fail(
                            &p,
                            field,
                            "keys",
                            rule.kind,
                            Vec::new(),
                            Some(rule),
                            owner,
                            None,
                            Some("keys must be strings"),
                        );
                        ok = false;
                        continue;
                    };
                    let key_text = key_str.to_string_lossy().to_string();
                    let entry_path = path.key(&key_text);
                    let checked_key = match &rule.keys {
                        Some(key_rule) => {
                            let key_slot = Slot {
                                table: self.lua.create_table()?,
                                key: Value::Integer(1),
                            };
                            match self.check_value(
                                key_rule,
                                owner,
                                key.clone(),
                                &entry_path,
                                key_slot,
                            )? {
                                Some(k) => k,
                                None => {
                                    ok = false;
                                    continue;
                                }
                            }
                        }
                        None => key.clone(),
                    };
                    let item_slot = Slot {
                        table: out.clone(),
                        key: checked_key.clone(),
                    };
                    match self.check_value(values, owner, item, &entry_path, item_slot)? {
                        Some(item) => out.set(checked_key, item)?,
                        None => ok = false,
                    }
                }
                if !ok {
                    return Ok(None);
                }
                Value::Table(out)
            }
            Kind::Any => {
                crate::utils::check_json_bounds(&value)?;
                // Invariant: schema compilation requires `max_bytes` on `any`.
                #[allow(clippy::expect_used)]
                let max = rule.max_bytes.expect("any rules carry `max_bytes`");
                let json: serde_json::Value = self.lua.from_value(value.clone())?;
                let size = serde_json::to_vec(&json)
                    .map(|v| v.len() as u64)
                    .unwrap_or(u64::MAX);
                if size > max {
                    fail!("max_bytes", vec![("max", Param::Size(max))]);
                }
                value
            }
            Kind::File => {
                let Value::UserData(ud) = &value else {
                    fail!("type", type_params());
                };
                let Ok(file) = ud.borrow::<LuaFile>() else {
                    fail!("type", type_params());
                };
                if let Some((rule_name, params)) = self.check_file(rule, file.info())? {
                    let p = path.render();
                    self.fail(
                        &p,
                        field,
                        rule_name,
                        rule.kind,
                        params,
                        Some(rule),
                        owner,
                        None,
                        None,
                    );
                    return Ok(None);
                }
                drop(file);
                value
            }
        };

        let deferred = [
            rule.check.as_ref().map(|f| PendingCheck::Custom(f.clone())),
            rule.transform
                .as_ref()
                .map(|f| PendingCheck::Transform(f.clone())),
        ];
        for check in deferred.into_iter().flatten() {
            self.pending.push(Pending::Field {
                slot: Slot {
                    table: slot.table.clone(),
                    key: slot.key.clone(),
                },
                path: path.render(),
                field: field.to_string(),
                rule: rule.clone(),
                owner: owner.clone(),
                value: checked.clone(),
                check,
            });
        }
        Ok(Some(checked))
    }

    /// `after`/`before` against a literal or the clock.
    fn within_bound(
        &mut self,
        format: Format,
        value: &str,
        bound: &TimeBound,
        after: bool,
    ) -> bool {
        let ordering = match format {
            Format::Date => {
                let Ok(v) = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d") else {
                    return false;
                };
                let limit = match bound {
                    TimeBound::Now => self.now().date_naive(),
                    TimeBound::Literal(l) => match chrono::NaiveDate::parse_from_str(l, "%Y-%m-%d")
                    {
                        Ok(d) => d,
                        Err(_) => return false,
                    },
                };
                v.cmp(&limit)
            }
            Format::Datetime => {
                let Ok(v) = chrono::DateTime::parse_from_rfc3339(value) else {
                    return false;
                };
                let limit = match bound {
                    TimeBound::Now => self.now().fixed_offset(),
                    TimeBound::Literal(l) => match chrono::DateTime::parse_from_rfc3339(l) {
                        Ok(d) => d,
                        Err(_) => return false,
                    },
                };
                v.cmp(&limit)
            }
            _ => {
                let Some(v) = parse_time(value) else {
                    return false;
                };
                let limit = match bound {
                    TimeBound::Now => self.now().time(),
                    TimeBound::Literal(l) => match parse_time(l) {
                        Some(t) => t,
                        None => return false,
                    },
                };
                v.cmp(&limit)
            }
        };
        if after {
            ordering == std::cmp::Ordering::Greater
        } else {
            ordering == std::cmp::Ordering::Less
        }
    }
}
