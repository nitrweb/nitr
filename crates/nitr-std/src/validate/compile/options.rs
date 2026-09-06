// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Schema options: `title`, `strict`, `messages`, the declarative
//! cross-field groups, and `checks` — plus the consistency rules every
//! group must satisfy (declared fields only, comparable `ordered`).

use mlua::{Lua, Table, Value};

use super::getters::{get_bool, get_string};
use crate::validate::message::{self, Template, rule_params};
use crate::validate::{CheckDef, Group, Kind, SchemaDef};

const OPTION_KEYS: &[&str] = &[
    "title",
    "strict",
    "messages",
    "at_least_one",
    "mutually_exclusive",
    "dependent_required",
    "equal_fields",
    "ordered",
    "checks",
];

fn option_error(what: &str, msg: impl std::fmt::Display) -> mlua::Error {
    mlua::Error::RuntimeError(format!("{what}: {msg}"))
}

/// An optional `message` on a group or check entry.
fn group_message(table: &Table, rule: &str, what: &str) -> mlua::Result<Option<Template>> {
    match table.get::<Value>("message")? {
        Value::Nil => Ok(None),
        Value::String(s) => Ok(Some(Template::compile(
            &s.to_string_lossy(),
            rule_params(rule),
            &format!("{what} (`{rule}`)"),
        )?)),
        _ => Err(option_error(
            what,
            format!("a `{rule}` message must be a string"),
        )),
    }
}

/// A `{ "a", "b", message = "..." }` group.
fn compile_group(value: Value, key: &str, what: &str) -> mlua::Result<Group> {
    let Value::Table(t) = value else {
        return Err(option_error(
            what,
            format!("`{key}` entries must be lists of field names"),
        ));
    };
    let mut fields = Vec::new();
    for v in t.sequence_values::<Value>() {
        match v? {
            Value::String(s) => fields.push(s.to_string_lossy().to_string()),
            other => {
                return Err(option_error(
                    what,
                    format!(
                        "`{key}` entries must be field names, got {}",
                        other.type_name()
                    ),
                ));
            }
        }
    }
    if fields.len() < 2 {
        return Err(option_error(
            what,
            format!("a `{key}` group needs at least two fields"),
        ));
    }
    let message = group_message(&t, key, what)?;
    Ok(Group { fields, message })
}

fn compile_dependent(map: &Table, what: &str) -> mlua::Result<Vec<(String, Group)>> {
    let mut out = Vec::new();
    for pair in map.pairs::<Value, Value>() {
        let (field, deps) = pair?;
        let Value::String(field) = field else {
            return Err(option_error(
                what,
                "`dependent_required` keys must be field names",
            ));
        };
        let field = field.to_string_lossy().to_string();
        let Value::Table(deps) = deps else {
            return Err(option_error(
                what,
                format!("`dependent_required.{field}` must be a list of field names"),
            ));
        };
        let mut names = vec![field.clone()];
        for v in deps.sequence_values::<String>() {
            names.push(v?);
        }
        if names.len() < 2 {
            return Err(option_error(
                what,
                format!("`dependent_required.{field}` needs at least one field"),
            ));
        }
        let message = group_message(&deps, "dependent_required", what)?;
        out.push((
            field,
            Group {
                fields: names,
                message,
            },
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn compile_checks(list: &Table, what: &str) -> mlua::Result<Vec<CheckDef>> {
    let mut checks = Vec::new();
    for entry in list.sequence_values::<Table>() {
        let entry = entry?;
        let description = get_string(&entry, "description", what)?.ok_or_else(|| {
            option_error(
                what,
                "every entry of `checks` needs a `description` saying what it enforces",
            )
        })?;
        let func: mlua::Function =
            entry
                .get::<Option<mlua::Function>>("check")?
                .ok_or_else(|| {
                    option_error(what, "every entry of `checks` needs a `check` function")
                })?;
        let message = group_message(&entry, "check", what)?;
        checks.push(CheckDef {
            description,
            func,
            message,
        });
    }
    Ok(checks)
}

/// Applies (or replaces) the schema options on a definition.
pub(crate) fn apply_options(
    lua: &Lua,
    def: &mut SchemaDef,
    opts: &Table,
    what: &str,
) -> mlua::Result<()> {
    let _ = lua;
    for pair in opts.pairs::<Value, Value>() {
        let (key, _) = pair?;
        let Value::String(key) = key else {
            return Err(option_error(what, "option keys must be strings"));
        };
        let key = key.to_string_lossy();
        if !OPTION_KEYS.contains(&key.as_ref()) {
            return Err(option_error(
                what,
                format!(
                    "unknown option `{key}` (allowed: {})",
                    OPTION_KEYS.join(", ")
                ),
            ));
        }
    }
    if let Some(title) = get_string(opts, "title", what)? {
        def.title = Some(title);
    }
    if let Some(strict) = get_bool(opts, "strict", what)? {
        def.strict = strict;
    }
    if let Some(messages) = opts.get::<Option<Table>>("messages")? {
        def.messages = message::compile_messages(&messages, what)?;
    }
    for (key, target) in [
        ("at_least_one", &mut def.at_least_one),
        ("mutually_exclusive", &mut def.mutually_exclusive),
        ("equal_fields", &mut def.equal_fields),
        ("ordered", &mut def.ordered),
    ] {
        if let Some(list) = opts.get::<Option<Table>>(key)? {
            let mut groups = Vec::new();
            for group in list.sequence_values::<Value>() {
                groups.push(compile_group(group?, key, what)?);
            }
            *target = groups;
        }
    }
    if let Some(map) = opts.get::<Option<Table>>("dependent_required")? {
        def.dependent_required = compile_dependent(&map, what)?;
    }
    if let Some(list) = opts.get::<Option<Table>>("checks")? {
        def.checks = compile_checks(&list, what)?;
    }
    check_groups(def, what)
}

/// Every cross-field group must name declared fields, and `ordered`
/// groups must be comparable.
pub(crate) fn check_groups(def: &SchemaDef, what: &str) -> mlua::Result<()> {
    let groups = def
        .at_least_one
        .iter()
        .map(|g| ("at_least_one", g))
        .chain(
            def.mutually_exclusive
                .iter()
                .map(|g| ("mutually_exclusive", g)),
        )
        .chain(def.equal_fields.iter().map(|g| ("equal_fields", g)))
        .chain(def.ordered.iter().map(|g| ("ordered", g)))
        .chain(
            def.dependent_required
                .iter()
                .map(|(_, g)| ("dependent_required", g)),
        );
    for (key, group) in groups {
        for name in &group.fields {
            if def.rule(name).is_none() {
                return Err(option_error(
                    what,
                    format!("`{key}` names an unknown field `{name}`"),
                ));
            }
        }
    }
    for group in &def.ordered {
        let kinds: Vec<(Kind, Option<String>)> = group
            .fields
            .iter()
            .filter_map(|n| def.rule(n))
            .map(|r| (r.kind, r.format.as_ref().map(|f| f.name().to_string())))
            .collect();
        let numeric = |k: Kind| matches!(k, Kind::Number | Kind::Integer);
        let comparable = kinds.iter().all(|(k, f)| {
            numeric(*k)
                || (*k == Kind::String
                    && matches!(f.as_deref(), Some("date" | "datetime" | "time")))
        }) && kinds
            .windows(2)
            .all(|w| (numeric(w[0].0) && numeric(w[1].0)) || w[0].1 == w[1].1);
        if !comparable {
            return Err(option_error(
                what,
                "an `ordered` group needs numbers, or strings sharing a date, datetime or time format",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::compile::compile_schema;

    fn compile(lua: &Lua, fields: &str, opts: &str) -> mlua::Result<SchemaDef> {
        let fields: Table = lua.load(fields).eval().unwrap();
        let opts: Table = lua.load(opts).eval().unwrap();
        compile_schema(lua, &fields, Some(&opts), "the schema")
    }

    #[test]
    fn options_are_checked_against_the_fields() {
        let lua = Lua::new();
        let fields = r#"{ a = "integer", b = "integer", d = "string|format:date", t = "string|format:time" }"#;
        let ok = compile(&lua, fields, r#"{ ordered = { { "a", "b" } }, equal_fields = { { "a", "b", message = "{field} again" } } }"#).unwrap();
        assert_eq!(ok.ordered.len(), 1);
        assert!(ok.equal_fields[0].message.is_some());
        for (opts, needle) in [
            (r#"{ ordered = { { "a", "zz" } } }"#, "unknown field `zz`"),
            (
                r#"{ ordered = { { "d", "t" } } }"#,
                "needs numbers, or strings sharing",
            ),
            (r#"{ ordered = { { "a" } } }"#, "at least two fields"),
            (r#"{ strict = "yes" }"#, "must be true or false"),
            (r#"{ titel = "x" }"#, "unknown option `titel`"),
            (
                r#"{ checks = { { check = function() end } } }"#,
                "needs a `description`",
            ),
            (
                r#"{ dependent_required = { a = {} } }"#,
                "needs at least one field",
            ),
        ] {
            let err = compile(&lua, fields, opts).expect_err(opts).to_string();
            assert!(err.contains(needle), "{opts}: {err}");
        }
    }
}
