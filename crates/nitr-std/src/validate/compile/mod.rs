// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Schema compilation: a Lua rule table (or shorthand string, or compiled
//! schema) becomes a [`Rule`] tree once at load time, with typos and
//! contradictions rejected there.
//!
//! [`getters`] reads typed keys, [`file`] the `file`-only keys,
//! [`options`] the schema options, [`formats`] registers custom formats.

use std::collections::BTreeMap;
use std::sync::Arc;

use mlua::{Lua, Table, Value};

mod file;
mod formats;
mod getters;
mod kinds;
mod options;

pub(crate) use formats::register_format;
use getters::{get_bool, get_literal, get_literals, get_size, get_string};
pub(crate) use options::{apply_options, check_groups};

use super::message::{self, Template, rule_params};
use super::{Kind, Rule, SchemaDef, schema_of, shorthand};

/// Deepest rule nesting accepted: compilation, the checker and the
/// API-description export all recurse through `items`/`fields`/`values`,
/// and a stack overflow is an abort no boundary contains.
pub(super) const MAX_DEPTH: usize = 32;

/// Raises a schema-compilation error naming the field it is about.
pub(super) fn bad_schema(path: &str, msg: impl std::fmt::Display) -> mlua::Error {
    mlua::Error::RuntimeError(format!("invalid schema for `{path}`: {msg}"))
}

/// Keys every type accepts.
const COMMON_KEYS: &[&str] = &[
    "type",
    "required",
    "default",
    "equals",
    "one_of",
    "not_one_of",
    "description",
    "example",
    "label",
    "message",
    "messages",
    "check",
    "transform",
];

/// Which rule keys apply to which type — anything else in a rule table is
/// an error, so a typo (`requird`, `maxlen`) fails at load time instead of
/// silently validating nothing.
pub(super) fn allowed_keys(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::String => &[
            "trim",
            "case",
            "min_len",
            "max_len",
            "len",
            "format",
            "starts_with",
            "ends_with",
            "contains",
            "does_not_contain",
            "after",
            "before",
        ],
        Kind::Number => &[
            "min",
            "max",
            "exclusive_min",
            "exclusive_max",
            "multiple_of",
            "decimals",
        ],
        Kind::Integer => &[
            "min",
            "max",
            "exclusive_min",
            "exclusive_max",
            "multiple_of",
        ],
        Kind::Boolean => &[],
        Kind::Array => &[
            "items",
            "min_items",
            "max_items",
            "unique",
            "contains",
            "contains_any",
            "contains_all",
            "max_total_bytes",
        ],
        Kind::Table => &["fields"],
        Kind::Map => &["keys", "values", "min_keys", "max_keys"],
        Kind::Any => &["max_bytes"],
        Kind::File => &[
            "max_bytes",
            "min_bytes",
            "types",
            "allow_executables",
            "extensions",
            "match_extension",
            "filename",
            "min_width",
            "max_width",
            "min_height",
            "max_height",
            "max_pixels",
            "aspect",
            "utf8",
        ],
    }
}

/// The placeholders a field-wide `message` may use: everything its
/// declared rules expose, plus `{type}`.
fn field_placeholders(rule: &Table) -> mlua::Result<Vec<&'static str>> {
    let mut names: Vec<&'static str> = vec!["type"];
    for pair in rule.pairs::<Value, Value>() {
        let (key, _) = pair?;
        if let Value::String(key) = key {
            for name in rule_params(&key.to_string_lossy()) {
                if !names.contains(name) {
                    names.push(name);
                }
            }
        }
    }
    Ok(names)
}

fn empty_rule(kind: Kind) -> Rule {
    Rule {
        kind,
        required: false,
        default: None,
        equals: None,
        one_of: None,
        not_one_of: None,
        label: None,
        message: None,
        messages: BTreeMap::new(),
        check: None,
        transform: None,
        description: None,
        trim: false,
        case: None,
        min_len: None,
        max_len: None,
        len: None,
        format: None,
        starts_with: None,
        ends_with: None,
        contains: None,
        does_not_contain: None,
        after: None,
        before: None,
        min: None,
        max: None,
        exclusive_min: None,
        exclusive_max: None,
        multiple_of: None,
        decimals: None,
        items: None,
        min_items: None,
        max_items: None,
        unique: false,
        contains_item: None,
        contains_any: None,
        contains_all: None,
        max_total_bytes: None,
        fields: None,
        keys: None,
        values: None,
        min_keys: None,
        max_keys: None,
        max_bytes: None,
        file: None,
    }
}

/// A compiled schema nested as a field: a `table` rule with its fields.
fn nested_schema_rule(schema: Arc<SchemaDef>) -> Rule {
    let mut rule = empty_rule(Kind::Table);
    rule.fields = Some(schema);
    rule
}

/// Compiles one field rule from whatever spelling the script used: a
/// table, a shorthand string, the mixed `{ "<shorthand>", ... }` form,
/// or a compiled schema.
pub(crate) fn compile_rule_value(
    lua: &Lua,
    value: Value,
    path: &str,
    depth: usize,
) -> mlua::Result<Rule> {
    if depth > MAX_DEPTH {
        return Err(bad_schema(
            path,
            format!("nested deeper than {MAX_DEPTH} levels"),
        ));
    }
    match value {
        Value::String(shorthand) => {
            let table = shorthand::expand(lua, &shorthand.to_string_lossy())
                .map_err(|err| bad_schema(path, err))?;
            compile_rule(lua, &table, path, depth)
        }
        Value::Table(table) => match table.raw_get::<Value>(1)? {
            Value::Nil => compile_rule(lua, &table, path, depth),
            Value::String(shorthand) => {
                let base = shorthand::expand(lua, &shorthand.to_string_lossy())
                    .map_err(|err| bad_schema(path, err))?;
                for pair in table.pairs::<Value, Value>() {
                    let (key, value) = pair?;
                    if matches!(key, Value::Integer(1)) {
                        continue;
                    }
                    let Value::String(key) = key else {
                        return Err(bad_schema(path, "rule keys must be strings"));
                    };
                    base.set(key, value)?;
                }
                compile_rule(lua, &base, path, depth)
            }
            other => Err(bad_schema(
                path,
                format!(
                    "a rule table may start with a shorthand string only, got {}",
                    other.type_name()
                ),
            )),
        },
        Value::UserData(ud) => match schema_of(&ud) {
            Some(schema) => Ok(nested_schema_rule(schema)),
            None => Err(bad_schema(
                path,
                "the rule must be a table, a shorthand string or a schema",
            )),
        },
        other => Err(bad_schema(
            path,
            format!(
                "the rule must be a table, a shorthand string or a schema, got {}",
                other.type_name()
            ),
        )),
    }
}

/// Refuses keys the type does not accept.
fn check_keys(rule: &Table, kind: Kind, path: &str) -> mlua::Result<()> {
    for pair in rule.pairs::<Value, Value>() {
        let (key, _) = pair?;
        let Value::String(key) = key else {
            return Err(bad_schema(path, "rule keys must be strings"));
        };
        let key = key.to_string_lossy();
        if !COMMON_KEYS.contains(&key.as_ref()) && !allowed_keys(kind).contains(&key.as_ref()) {
            let mut allowed: Vec<&str> = COMMON_KEYS.to_vec();
            allowed.extend(allowed_keys(kind));
            return Err(bad_schema(
                path,
                format!(
                    "unknown rule `{key}` for type `{}` (allowed: {})",
                    kind.name(),
                    allowed.join(", ")
                ),
            ));
        }
    }
    Ok(())
}

/// The keys every type shares.
fn compile_common(lua: &Lua, rule: &Table, out: &mut Rule, path: &str) -> mlua::Result<()> {
    let _ = lua;
    let kind = out.kind;
    out.required = get_bool(rule, "required", path)?.unwrap_or(false);
    out.label = get_string(rule, "label", path)?;
    out.description = get_string(rule, "description", path)?;
    if matches!(
        rule.get::<Value>("example")?,
        Value::Function(_) | Value::UserData(_) | Value::Thread(_)
    ) {
        return Err(bad_schema(path, "`example` must be a plain value"));
    }
    out.equals = get_literal(rule, "equals", kind, path)?;
    out.one_of = get_literals(rule, "one_of", kind, path)?;
    out.not_one_of = get_literals(rule, "not_one_of", kind, path)?;
    out.default = get_literal(rule, "default", kind, path)?;
    if out.default.is_some() && out.required {
        return Err(bad_schema(
            path,
            "`default` and `required` contradict each other",
        ));
    }
    match rule.get::<Value>("check")? {
        Value::Nil => {}
        Value::Function(f) => {
            if out.description.is_none() {
                return Err(bad_schema(
                    path,
                    "a `check` needs a `description` saying what it enforces",
                ));
            }
            out.check = Some(f);
        }
        other => {
            return Err(bad_schema(
                path,
                format!("`check` must be a function, got {}", other.type_name()),
            ));
        }
    }
    match rule.get::<Value>("transform")? {
        Value::Nil => {}
        Value::Function(f) => out.transform = Some(f),
        other => {
            return Err(bad_schema(
                path,
                format!("`transform` must be a function, got {}", other.type_name()),
            ));
        }
    }
    if let Some(messages) = rule.get::<Option<Table>>("messages")? {
        out.messages = message::compile_messages(&messages, &format!("`{path}`"))?;
        if out.messages.contains_key("summary") {
            return Err(bad_schema(
                path,
                "`summary` is an app-level message, not a field one",
            ));
        }
    }
    if let Some(text) = get_string(rule, "message", path)? {
        let allowed = field_placeholders(rule)?;
        out.message = Some(Template::compile(&text, &allowed, &format!("`{path}`"))?);
    }
    Ok(())
}

pub(super) fn compile_rule(
    lua: &Lua,
    rule: &Table,
    path: &str,
    depth: usize,
) -> mlua::Result<Rule> {
    let type_name =
        get_string(rule, "type", path)?.ok_or_else(|| bad_schema(path, "missing `type`"))?;
    let kind = Kind::parse(&type_name).ok_or_else(|| {
        bad_schema(
            path,
            format!(
                "unknown type `{type_name}` (expected string, number, integer, boolean, array, \
                 table, map, any or file)"
            ),
        )
    })?;
    check_keys(rule, kind, path)?;
    let mut out = empty_rule(kind);
    compile_common(lua, rule, &mut out, path)?;
    match kind {
        Kind::String => kinds::compile_string(lua, rule, &mut out, path)?,
        Kind::Number | Kind::Integer => kinds::compile_number(rule, &mut out, path)?,
        Kind::Boolean => {}
        Kind::Array => kinds::compile_array(lua, rule, &mut out, path, depth)?,
        Kind::Table => kinds::compile_table(lua, rule, &mut out, path, depth)?,
        Kind::Map => kinds::compile_map(lua, rule, &mut out, path, depth)?,
        Kind::Any => {
            out.max_bytes = get_size(rule, "max_bytes", path)?;
            if out.max_bytes.is_none() {
                return Err(bad_schema(
                    path,
                    "type `any` requires `max_bytes`: a value the schema does not describe must \
                     say how large it may be",
                ));
            }
        }
        Kind::File => {
            out.max_bytes = get_size(rule, "max_bytes", path)?;
            if out.max_bytes.is_none() {
                return Err(bad_schema(path, "type `file` requires `max_bytes`"));
            }
            out.file = Some(file::compile_file_rule(lua, rule, path, depth)?);
        }
    }
    Ok(out)
}

/// Compiles a `{ name = rule, ... }` map, sorted so error output and
/// validation order are deterministic.
pub(super) fn compile_fields(
    lua: &Lua,
    fields: &Table,
    path: &str,
    depth: usize,
) -> mlua::Result<Vec<(String, Arc<Rule>)>> {
    if depth > MAX_DEPTH {
        return Err(bad_schema(
            path,
            format!("nested deeper than {MAX_DEPTH} levels"),
        ));
    }
    let mut compiled = Vec::new();
    for pair in fields.pairs::<Value, Value>() {
        let (name, rule) = pair?;
        let Value::String(name) = name else {
            return Err(bad_schema(path, "field names must be strings"));
        };
        let name = name.to_string_lossy().to_string();
        if name.is_empty() || name.contains(['.', '[', ']']) {
            return Err(bad_schema(
                path,
                format!("`{name}` is not a valid field name"),
            ));
        }
        let field_path = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}.{name}")
        };
        compiled.push((
            name,
            Arc::new(compile_rule_value(lua, rule, &field_path, depth)?),
        ));
    }
    compiled.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(compiled)
}

/// Compiles a schema: fields plus options. `what` names the site for
/// errors raised outside a field (`the schema` is the plain call).
pub(crate) fn compile_schema(
    lua: &Lua,
    fields: &Table,
    opts: Option<&Table>,
    what: &str,
) -> mlua::Result<SchemaDef> {
    compile_schema_at(lua, fields, opts, "", 0).map_err(|err| match err {
        mlua::Error::RuntimeError(msg) if what != "the schema" => {
            mlua::Error::RuntimeError(format!("{what}: {msg}"))
        }
        other => other,
    })
}

pub(super) fn compile_schema_at(
    lua: &Lua,
    fields: &Table,
    opts: Option<&Table>,
    path: &str,
    depth: usize,
) -> mlua::Result<SchemaDef> {
    let mut def = SchemaDef {
        fields: compile_fields(lua, fields, path, depth)?,
        title: None,
        strict: false,
        messages: BTreeMap::new(),
        at_least_one: Vec::new(),
        mutually_exclusive: Vec::new(),
        dependent_required: Vec::new(),
        equal_fields: Vec::new(),
        ordered: Vec::new(),
        checks: Vec::new(),
    };
    if let Some(opts) = opts {
        apply_options(lua, &mut def, opts, "the schema options")?;
    }
    Ok(def)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(lua: &Lua, def: &str) -> mlua::Result<Rule> {
        let value: Value = lua.load(def).eval().unwrap();
        compile_rule_value(lua, value, "f", 0)
    }

    #[test]
    fn every_spelling_compiles_to_the_same_rule() {
        let lua = Lua::new();
        let table = compile(
            &lua,
            r#"{ type = "string", trim = true, min_len = 1, required = true }"#,
        )
        .unwrap();
        let short = compile(&lua, r#""string|trim|min_len:1|required""#).unwrap();
        let mixed = compile(&lua, r#"{ "string|trim|min_len:1", required = true }"#).unwrap();
        for rule in [&short, &mixed] {
            assert_eq!(rule.kind, table.kind);
            assert_eq!(rule.trim, table.trim);
            assert_eq!(rule.min_len, table.min_len);
            assert_eq!(rule.required, table.required);
        }
    }

    #[test]
    fn contradictions_and_typos_fail_by_name() {
        let lua = Lua::new();
        for (def, needle) in [
            (
                r#"{ type = "string", requird = true }"#,
                "unknown rule `requird`",
            ),
            (
                r#"{ type = "string", required = true, default = "x" }"#,
                "contradict",
            ),
            (r#"{ type = "string", contains = "" }"#, "must not be empty"),
            (r#"{ type = "string", case = "title" }"#, "`case` must be"),
            (
                r#"{ type = "array", items = "string", max_total_bytes = "1mb" }"#,
                "array of `file` rules",
            ),
            (
                r#"{ type = "map", keys = "integer", values = "string", max_keys = 1 }"#,
                "must be a `string` rule",
            ),
            (
                r#"{ type = "table", fields = "nope" }"#,
                "must be a table of rules",
            ),
            (r#"{ type = "file" }"#, "requires `max_bytes`"),
            (r#"42"#, "must be a table, a shorthand string or a schema"),
            (r#"{ 42 }"#, "shorthand string only"),
        ] {
            let err = compile(&lua, def).expect_err(def).to_string();
            assert!(err.contains(needle), "{def}: {err}");
        }
    }
}
