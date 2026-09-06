// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The declarative cross-field rules, applied to a table's validated
//! output once every field of it passed: `at_least_one`,
//! `mutually_exclusive`, `dependent_required`, `equal_fields`, `ordered`.

use std::sync::Arc;

use mlua::{Table, Value};

use super::path::FieldPath;
use super::util::canonical;
use super::{Ctx, Params};
use crate::validate::format::{Format, FormatRule, parse_time};
use crate::validate::message::Param;
use crate::validate::{Group, Kind, SchemaDef};

/// A value an `ordered` group can compare.
#[derive(Debug, PartialEq, PartialOrd)]
pub(super) enum Comparable {
    Num(f64),
    Date(chrono::NaiveDate),
    Datetime(chrono::DateTime<chrono::FixedOffset>),
    Time(chrono::NaiveTime),
}

pub(super) fn comparable(value: &Value, format: Option<&FormatRule>) -> Option<Comparable> {
    match value {
        Value::Integer(i) => Some(Comparable::Num(*i as f64)),
        Value::Number(n) => Some(Comparable::Num(*n)),
        Value::String(s) => {
            let s = s.to_string_lossy();
            match format {
                Some(FormatRule::Builtin(Format::Date)) => {
                    chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d")
                        .ok()
                        .map(Comparable::Date)
                }
                Some(FormatRule::Builtin(Format::Datetime)) => {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(Comparable::Datetime)
                }
                Some(FormatRule::Builtin(Format::Time)) => parse_time(&s).map(Comparable::Time),
                _ => None,
            }
        }
        _ => None,
    }
}

fn fields_param(group: &Group) -> Params {
    vec![(
        "fields",
        Param::List(group.fields.iter().map(|f| Param::Str(f.clone())).collect()),
    )]
}

fn last(group: &Group) -> String {
    group.fields.last().cloned().unwrap_or_default()
}

impl Ctx<'_> {
    /// The declarative cross-field rules, on the validated output. Returns
    /// whether every group held.
    pub(super) fn check_cross(
        &mut self,
        schema: &Arc<SchemaDef>,
        out: &Table,
        path: &FieldPath<'_>,
    ) -> mlua::Result<bool> {
        let mut ok = true;
        let present = |name: &str| -> mlua::Result<bool> { Ok(!out.get::<Value>(name)?.is_nil()) };

        for group in &schema.at_least_one {
            let mut any = false;
            for name in &group.fields {
                any |= present(name)?;
            }
            if !any {
                ok = false;
                let field = last(group);
                let p = path.field(&field).render();
                self.fail(
                    &p,
                    &field,
                    "at_least_one",
                    Kind::Any,
                    fields_param(group),
                    None,
                    schema,
                    group.message.as_ref(),
                    None,
                );
            }
        }
        for group in &schema.mutually_exclusive {
            let mut count = 0;
            for name in &group.fields {
                if present(name)? {
                    count += 1;
                }
            }
            if count > 1 {
                ok = false;
                let field = last(group);
                let p = path.field(&field).render();
                self.fail(
                    &p,
                    &field,
                    "mutually_exclusive",
                    Kind::Any,
                    fields_param(group),
                    None,
                    schema,
                    group.message.as_ref(),
                    None,
                );
            }
        }
        for (field, group) in &schema.dependent_required {
            if !present(field)? {
                continue;
            }
            let mut missing = Vec::new();
            for dep in group.fields.iter().skip(1) {
                if !present(dep)? {
                    missing.push(Param::Str(dep.clone()));
                }
            }
            if !missing.is_empty() {
                ok = false;
                let p = path.field(field).render();
                self.fail(
                    &p,
                    field,
                    "dependent_required",
                    Kind::Any,
                    vec![("fields", Param::List(missing))],
                    None,
                    schema,
                    group.message.as_ref(),
                    None,
                );
            }
        }
        for group in &schema.equal_fields {
            let mut first: Option<(String, String)> = None;
            for name in &group.fields {
                let value: Value = out.get(name.as_str())?;
                if value.is_nil() {
                    continue;
                }
                let canon = canonical(self.lua, &value)?;
                match &first {
                    None => first = Some((name.clone(), canon)),
                    Some((other, expected)) if *expected != canon => {
                        ok = false;
                        let p = path.field(name).render();
                        self.fail(
                            &p,
                            name,
                            "equal_fields",
                            Kind::Any,
                            vec![("field", Param::Str(other.clone()))],
                            None,
                            schema,
                            group.message.as_ref(),
                            None,
                        );
                        break;
                    }
                    Some(_) => {}
                }
            }
        }
        for group in &schema.ordered {
            let mut prev: Option<(String, Comparable)> = None;
            for name in &group.fields {
                let value: Value = out.get(name.as_str())?;
                if value.is_nil() {
                    continue;
                }
                let format = schema.rule(name).and_then(|r| r.format.clone());
                let Some(current) = comparable(&value, format.as_ref()) else {
                    continue;
                };
                if let Some((other, before)) = &prev
                    && before.partial_cmp(&current) != Some(std::cmp::Ordering::Less)
                {
                    ok = false;
                    let p = path.field(name).render();
                    self.fail(
                        &p,
                        name,
                        "ordered",
                        Kind::Any,
                        vec![("field", Param::Str(other.clone()))],
                        None,
                        schema,
                        group.message.as_ref(),
                        None,
                    );
                    break;
                }
                prev = Some((name.clone(), current));
            }
        }
        Ok(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparables_follow_their_format() {
        let lua = mlua::Lua::new();
        let s = |t: &str| Value::String(lua.create_string(t).unwrap());
        let date = Some(FormatRule::Builtin(Format::Date));
        assert!(
            comparable(&s("2030-01-01"), date.as_ref())
                < comparable(&s("2030-01-02"), date.as_ref())
        );
        assert_eq!(comparable(&s("2030-01-01"), None), None);
        assert!(comparable(&Value::Integer(1), None) < comparable(&Value::Number(1.5), None));
        let time = Some(FormatRule::Builtin(Format::Time));
        assert!(comparable(&s("09:00"), time.as_ref()) < comparable(&s("17:30:00"), time.as_ref()));
    }
}
