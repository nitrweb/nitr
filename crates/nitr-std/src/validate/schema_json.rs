// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! JSON Schema (2020-12) export of a compiled schema: the document view
//! of what the checker enforces, for the OpenAPI generator.
//!
//! Every rule key maps to its standard keyword where one exists and to an
//! `x-nitr-*` extension otherwise, so nothing the checker does is
//! invisible in the document and nothing the document claims is
//! unenforced. Literal text rules become regex-escaped `pattern`s, so a
//! downstream validator matches the literal, never a metacharacter.
//! Custom checks cannot be serialized: their mandatory `description` is
//! their representation, marked `x-nitr-enforced: "custom"`.
//!
//! Output is deterministic: `serde_json::Map` is a `BTreeMap` in this
//! workspace (`preserve_order` is off), and every list keeps the order the
//! schema declared.

use std::collections::BTreeMap;

use serde_json::{Map, Value as Json, json};

use super::format::{Format, FormatRule};
use super::{Group, Kind, Literal, Rule, SchemaDef, TimeBound, TypePattern};

/// Named component schemas collected while exporting: a titled schema
/// is emitted once under `components/schemas/<title>` and referenced
/// everywhere else.
pub type Components = BTreeMap<String, Json>;

/// The `$ref` a titled component is reached through.
fn reference(title: &str) -> Json {
    json!({ "$ref": format!("#/components/schemas/{title}") })
}

/// Exports a schema, registering it and any titled schema nested in it
/// in `components`. A titled schema comes back as a `$ref`, an untitled
/// one inline. Two *different* schemas sharing a title cannot share a
/// component name, and the title is the script author's choice, so the
/// later one takes a numbered suffix (`Note_2`) rather than failing a
/// build that may not even serve the document. Deterministic: the order
/// is the route order the generator walks.
pub(crate) fn export(def: &SchemaDef, components: &mut Components) -> Result<Json, String> {
    let object = object_schema(def, components)?;
    let Some(title) = &def.title else {
        return Ok(object);
    };
    let mut name = title.clone();
    let mut n = 1;
    loop {
        match components.get(&name) {
            Some(existing) if *existing == object => return Ok(reference(&name)),
            Some(_) => {
                n += 1;
                name = format!("{title}_{n}");
            }
            None => {
                let mut object = object;
                if let Some(map) = object.as_object_mut() {
                    map.insert("title".into(), json!(name));
                }
                components.insert(name.clone(), object);
                return Ok(reference(&name));
            }
        }
    }
}

/// The object schema of a `SchemaDef`, without the `$ref` indirection.
fn object_schema(def: &SchemaDef, components: &mut Components) -> Result<Json, String> {
    let mut out = Map::new();
    out.insert("type".into(), json!("object"));
    if let Some(title) = &def.title {
        out.insert("title".into(), json!(title));
    }
    let mut properties = Map::new();
    let mut required = Vec::new();
    for (name, rule) in &def.fields {
        properties.insert(name.clone(), rule_schema(rule, components)?);
        if rule.required {
            required.push(json!(name));
        }
    }
    out.insert("properties".into(), Json::Object(properties));
    if !required.is_empty() {
        out.insert("required".into(), Json::Array(required));
    }
    // Truthful: `check_fields` strips undeclared fields (or reports them
    // in strict mode); either way an extra property is never data.
    out.insert("additionalProperties".into(), json!(false));

    cross_field(def, &mut out);

    if !def.checks.is_empty() {
        let mut description = String::from("Constraints:");
        let mut list = Vec::with_capacity(def.checks.len());
        for check in &def.checks {
            description.push_str("\n- ");
            description.push_str(&check.description);
            list.push(json!(check.description));
        }
        out.insert("description".into(), json!(description));
        out.insert("x-nitr-checks".into(), Json::Array(list));
        out.insert("x-nitr-enforced".into(), json!("custom"));
    }
    Ok(Json::Object(out))
}

/// The declarative cross-field rules: standard keywords where JSON Schema
/// has them, extensions where it does not.
fn cross_field(def: &SchemaDef, out: &mut Map<String, Json>) {
    let names = |group: &Group| -> Vec<Json> { group.fields.iter().map(|f| json!(f)).collect() };
    // "At least one of a, b" is `anyOf` over single `required`s; several
    // groups combine under `allOf`, since `anyOf` can only appear once.
    let any_ofs: Vec<Json> = def
        .at_least_one
        .iter()
        .map(|group| {
            json!({ "anyOf": group.fields.iter().map(|f| json!({ "required": [f] })).collect::<Vec<_>>() })
        })
        .collect();
    match any_ofs.len() {
        0 => {}
        1 => {
            if let Some(Json::Object(one)) = any_ofs.into_iter().next() {
                out.extend(one);
            }
        }
        _ => {
            out.insert("allOf".into(), Json::Array(any_ofs));
        }
    }
    if !def.dependent_required.is_empty() {
        let mut map = Map::new();
        // The group carries the trigger field itself first; the keyword
        // lists only what it requires.
        for (field, group) in &def.dependent_required {
            let deps: Vec<Json> = group
                .fields
                .iter()
                .filter(|f| *f != field)
                .map(|f| json!(f))
                .collect();
            map.insert(field.clone(), Json::Array(deps));
        }
        out.insert("dependentRequired".into(), Json::Object(map));
    }
    for (key, groups) in [
        ("x-nitr-mutually-exclusive", &def.mutually_exclusive),
        ("x-nitr-equal-fields", &def.equal_fields),
        ("x-nitr-ordered", &def.ordered),
    ] {
        if !groups.is_empty() {
            out.insert(
                key.into(),
                Json::Array(groups.iter().map(|g| Json::Array(names(g))).collect()),
            );
        }
    }
}

/// One rule as a JSON Schema.
fn rule_schema(rule: &Rule, components: &mut Components) -> Result<Json, String> {
    let mut out = Map::new();
    match rule.kind {
        Kind::String => {
            out.insert("type".into(), json!("string"));
        }
        Kind::Number => {
            out.insert("type".into(), json!("number"));
        }
        Kind::Integer => {
            out.insert("type".into(), json!("integer"));
        }
        Kind::Boolean => {
            out.insert("type".into(), json!("boolean"));
        }
        Kind::Array => {
            out.insert("type".into(), json!("array"));
        }
        Kind::Table => {
            // A nested compiled schema keeps its own title, so it may
            // become a `$ref` of its own; a bare field table inlines.
            if let Some(fields) = &rule.fields {
                let nested = export(fields, components)?;
                match nested {
                    Json::Object(map) => out.extend(map),
                    other => return Ok(with_common(other, rule)),
                }
            } else {
                out.insert("type".into(), json!("object"));
            }
        }
        Kind::Map => {
            out.insert("type".into(), json!("object"));
            if let Some(keys) = &rule.keys {
                out.insert("propertyNames".into(), rule_schema(keys, components)?);
            }
            if let Some(values) = &rule.values {
                out.insert(
                    "additionalProperties".into(),
                    rule_schema(values, components)?,
                );
            }
        }
        // `{}` accepts anything; the size bound is what the checker adds.
        Kind::Any => {}
        Kind::File => file_schema(rule, components, &mut out)?,
    }

    if let Some(v) = &rule.default {
        out.insert("default".into(), literal(v, rule.kind));
    }
    if let Some(v) = &rule.equals {
        out.insert("const".into(), literal(v, rule.kind));
    }
    if let Some(list) = &rule.one_of {
        out.insert("enum".into(), literals(list, rule.kind));
    }
    if let Some(list) = &rule.not_one_of {
        out.insert("not".into(), json!({ "enum": literals(list, rule.kind) }));
    }

    // Strings.
    let mut transforms = Vec::new();
    if rule.trim {
        transforms.push(json!("trim"));
    }
    match rule.case {
        Some(super::Case::Lower) => transforms.push(json!("lower")),
        Some(super::Case::Upper) => transforms.push(json!("upper")),
        None => {}
    }
    if rule.transform.is_some() {
        transforms.push(json!("custom"));
    }
    if !transforms.is_empty() {
        out.insert("x-nitr-transform".into(), Json::Array(transforms));
    }
    if let Some(n) = rule.len {
        out.insert("minLength".into(), json!(n));
        out.insert("maxLength".into(), json!(n));
    }
    if let Some(n) = rule.min_len {
        out.insert("minLength".into(), json!(n));
    }
    if let Some(n) = rule.max_len {
        out.insert("maxLength".into(), json!(n));
    }
    if let Some(format) = &rule.format {
        format_keywords(format, &mut out);
    }
    patterns(rule, &mut out);
    if let Some(bound) = &rule.after {
        out.insert("x-nitr-after".into(), time_bound(bound));
    }
    if let Some(bound) = &rule.before {
        out.insert("x-nitr-before".into(), time_bound(bound));
    }

    // Numbers.
    for (key, value) in [
        ("minimum", rule.min),
        ("maximum", rule.max),
        ("exclusiveMinimum", rule.exclusive_min),
        ("exclusiveMaximum", rule.exclusive_max),
        ("multipleOf", rule.multiple_of),
    ] {
        if let Some(n) = value {
            out.insert(key.into(), number(n, rule.kind));
        }
    }
    if let Some(n) = rule.decimals {
        out.insert("x-nitr-decimals".into(), json!(n));
    }

    // Arrays.
    if let Some(items) = &rule.items {
        out.insert("items".into(), rule_schema(items, components)?);
    }
    if let Some(n) = rule.min_items {
        out.insert("minItems".into(), json!(n));
    }
    if let Some(n) = rule.max_items {
        out.insert("maxItems".into(), json!(n));
    }
    if rule.unique {
        out.insert("uniqueItems".into(), json!(true));
    }
    let item_kind = rule.items.as_ref().map_or(Kind::Any, |i| i.kind);
    let mut contains = Vec::new();
    if let Some(v) = &rule.contains_item {
        contains.push(json!({ "contains": { "const": literal(v, item_kind) } }));
    }
    if let Some(list) = &rule.contains_any {
        contains.push(json!({ "contains": { "enum": literals(list, item_kind) } }));
    }
    if let Some(list) = &rule.contains_all {
        for v in list {
            contains.push(json!({ "contains": { "const": literal(v, item_kind) } }));
        }
    }
    merge_all_of(contains, &mut out);
    if let Some(n) = rule.max_total_bytes {
        out.insert("x-nitr-max-total-bytes".into(), json!(n));
    }

    // Maps.
    if let Some(n) = rule.min_keys {
        out.insert("minProperties".into(), json!(n));
    }
    if let Some(n) = rule.max_keys {
        out.insert("maxProperties".into(), json!(n));
    }
    if let Some(n) = rule.max_bytes
        && rule.kind != Kind::File
    {
        out.insert("x-nitr-max-bytes".into(), json!(n));
    }

    Ok(with_common(Json::Object(out), rule))
}

/// `title`, `description` and the custom-check marker, added last so a
/// nested `$ref` still carries the field's own prose.
fn with_common(schema: Json, rule: &Rule) -> Json {
    let Json::Object(mut out) = schema else {
        return schema;
    };
    if let Some(label) = &rule.label {
        out.insert("title".into(), json!(label));
    }
    if let Some(description) = &rule.description {
        // A custom format's description was merged first; the field's own
        // words lead.
        let merged = match out.get("description").and_then(Json::as_str) {
            Some(existing) if existing != description => {
                format!("{description}\n\n{existing}")
            }
            _ => description.clone(),
        };
        out.insert("description".into(), json!(merged));
    }
    if rule.check.is_some() {
        out.insert("x-nitr-enforced".into(), json!("custom"));
    }
    Json::Object(out)
}

/// A built-in format maps to the OpenAPI/JSON Schema format name when a
/// standard one exists; everything else, and every custom format, is an
/// `x-nitr-format` with the custom format's documentation beside it.
fn format_keywords(format: &FormatRule, out: &mut Map<String, Json>) {
    match format {
        FormatRule::Builtin(builtin) => match standard_format(*builtin) {
            Some(name) => {
                out.insert("format".into(), json!(name));
            }
            None => {
                out.insert("x-nitr-format".into(), json!(builtin.name()));
            }
        },
        FormatRule::Custom(custom) => {
            out.insert("x-nitr-format".into(), json!(custom.name));
            out.insert("description".into(), json!(custom.description));
            if let Some(pattern) = &custom.pattern {
                out.insert("pattern".into(), json!(pattern));
            }
            if let Some(example) = &custom.example {
                out.insert("example".into(), json!(example));
            }
            out.insert("x-nitr-enforced".into(), json!("custom"));
        }
    }
}

/// The formats OpenAPI 3.1 / JSON Schema name themselves.
pub(crate) fn standard_format(format: Format) -> Option<&'static str> {
    Some(match format {
        Format::Email => "email",
        Format::Uuid => "uuid",
        Format::Url => "uri",
        Format::Datetime => "date-time",
        Format::Date => "date",
        Format::Time => "time",
        Format::Ipv4 => "ipv4",
        Format::Ipv6 => "ipv6",
        Format::Hostname => "hostname",
        _ => return None,
    })
}

/// The literal text rules as anchored, escaped patterns.
fn patterns(rule: &Rule, out: &mut Map<String, Json>) {
    let mut all = Vec::new();
    if let Some(s) = &rule.starts_with {
        all.push(format!("^{}", regex_escape(s)));
    }
    if let Some(s) = &rule.ends_with {
        all.push(format!("{}$", regex_escape(s)));
    }
    if let Some(s) = &rule.contains {
        all.push(regex_escape(s));
    }
    let not = rule
        .does_not_contain
        .as_ref()
        .map(|s| json!({ "not": { "pattern": regex_escape(s) } }));
    match (all.len(), not) {
        (0, None) => {}
        (1, None) => {
            out.insert("pattern".into(), json!(all[0]));
        }
        (_, not) => {
            let mut parts: Vec<Json> = all.into_iter().map(|p| json!({ "pattern": p })).collect();
            parts.extend(not);
            merge_all_of(parts, out);
        }
    }
}

/// Adds clauses to an `allOf`, creating or extending it.
fn merge_all_of(clauses: Vec<Json>, out: &mut Map<String, Json>) {
    if clauses.is_empty() {
        return;
    }
    match out.get_mut("allOf") {
        Some(Json::Array(existing)) => existing.extend(clauses),
        _ => {
            out.insert("allOf".into(), Json::Array(clauses));
        }
    }
}

/// Escapes every regex metacharacter so a literal stays a literal.
pub fn regex_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(
            c,
            '\\' | '.'
                | '+'
                | '*'
                | '?'
                | '('
                | ')'
                | '|'
                | '['
                | ']'
                | '{'
                | '}'
                | '^'
                | '$'
                | '/'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn time_bound(bound: &TimeBound) -> Json {
    match bound {
        TimeBound::Now => json!("now"),
        TimeBound::Literal(s) => json!(s),
    }
}

/// A literal rendered for the rule's kind: an integer rule's `3` is `3`,
/// not `3.0`.
fn literal(value: &Literal, kind: Kind) -> Json {
    match value {
        Literal::Str(s) => json!(s),
        Literal::Num(n) => number(*n, kind),
        Literal::Bool(b) => json!(b),
    }
}

fn literals(values: &[Literal], kind: Kind) -> Json {
    Json::Array(values.iter().map(|v| literal(v, kind)).collect())
}

fn number(n: f64, kind: Kind) -> Json {
    if kind == Kind::Integer && n.fract() == 0.0 && n.abs() < 9.0e15 {
        return json!(n as i64);
    }
    json!(n)
}

/// A `file` rule: a binary string, typed by its media types.
fn file_schema(
    rule: &Rule,
    components: &mut Components,
    out: &mut Map<String, Json>,
) -> Result<(), String> {
    // Invariant: a `file` rule always carries its file part (the
    // compiler builds them together).
    let Some(file) = &rule.file else {
        out.insert("type".into(), json!("string"));
        out.insert("format".into(), json!("binary"));
        return Ok(());
    };
    out.insert("type".into(), json!("string"));
    let mut names: Vec<Json> = Vec::new();
    let mut single: Option<&str> = None;
    for pattern in &file.types {
        match pattern {
            TypePattern::Any => names.push(json!("*/*")),
            TypePattern::Family(f) => names.push(json!(format!("{f}/*"))),
            TypePattern::Exact(name) => {
                single = Some(name);
                names.push(json!(name));
            }
        }
    }
    match (names.len(), single) {
        (1, Some(exact)) => {
            out.insert("contentMediaType".into(), json!(exact));
        }
        _ => {
            out.insert("format".into(), json!("binary"));
            if !names.is_empty() {
                out.insert("x-nitr-types".into(), Json::Array(names));
            }
        }
    }
    if let Some(n) = rule.max_bytes {
        out.insert("x-nitr-max-bytes".into(), json!(n));
    }
    if file.min_bytes > 0 {
        out.insert("x-nitr-min-bytes".into(), json!(file.min_bytes));
    }
    if !file.extensions.is_empty() {
        out.insert("x-nitr-extensions".into(), json!(file.extensions));
    }
    if file.match_extension {
        out.insert("x-nitr-match-extension".into(), json!(true));
    }
    if file.allow_executables {
        out.insert("x-nitr-allow-executables".into(), json!(true));
    }
    for (key, value) in [
        ("x-nitr-min-width", file.min_width),
        ("x-nitr-max-width", file.max_width),
        ("x-nitr-min-height", file.min_height),
        ("x-nitr-max-height", file.max_height),
    ] {
        if let Some(n) = value {
            out.insert(key.into(), json!(n));
        }
    }
    if let Some(n) = file.max_pixels {
        out.insert("x-nitr-max-pixels".into(), json!(n));
    }
    if let Some(aspect) = &file.aspect {
        out.insert("x-nitr-aspect".into(), json!(aspect.label));
    }
    if file.utf8 {
        out.insert("x-nitr-utf8".into(), json!(true));
    }
    if let Some(filename) = &file.filename {
        out.insert("x-nitr-filename".into(), rule_schema(filename, components)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::tests::schema;
    use mlua::Lua;
    use serde_json::json;

    fn export_of(source: &str) -> (Json, Components) {
        let lua = Lua::new();
        let s = schema(&lua, source);
        let compiled = crate::validate::compile_schema(&lua, mlua::Value::UserData(s), "test")
            .expect("compiles");
        let mut components = Components::new();
        let out = compiled.json_schema(&mut components).expect("exports");
        (out, components)
    }

    #[test]
    fn every_rule_key_has_its_keyword_or_extension() {
        let (out, _) = export_of(
            r#"{
                name = { type = "string", required = true, trim = true, case = "lower",
                         min_len = 1, max_len = 20, format = "email", label = "Name",
                         description = "who" },
                nick = { type = "string", default = "x" },
                code = { type = "string", starts_with = "N-", ends_with = "x", contains = ".",
                         does_not_contain = " " },
                n = { type = "integer", min = 1, max = 5, multiple_of = 1, default = 3, one_of = { 1, 2, 3 } },
                f = { type = "number", exclusive_min = 0, exclusive_max = 1, decimals = 2 },
                on = { type = "boolean", equals = true },
                tags = { type = "array", items = { type = "string", format = "slug" }, min_items = 1,
                         max_items = 5, unique = true, contains = "a", contains_any = { "b", "c" },
                         contains_all = { "d" } },
                meta = { type = "map", keys = { type = "string", max_len = 8 }, values = { type = "integer" },
                         min_keys = 0, max_keys = 10 },
                blob = { type = "any", max_bytes = 100 },
                role = { type = "string", not_one_of = { "root" } },
                due = { type = "string", format = "date", after = "now", before = "2030-01-01" },
                len = { type = "string", len = 4 },
            }"#,
        );
        let p = &out["properties"];
        assert_eq!(out["type"], "object");
        assert_eq!(out["required"], json!(["name"]));
        assert_eq!(out["additionalProperties"], false);
        assert_eq!(p["name"]["format"], "email");
        assert_eq!(p["name"]["x-nitr-transform"], json!(["trim", "lower"]));
        assert_eq!(p["name"]["minLength"], 1);
        assert_eq!(p["name"]["maxLength"], 20);
        assert_eq!(p["name"]["title"], "Name");
        assert_eq!(p["name"]["description"], "who");
        assert_eq!(p["nick"]["default"], "x");
        assert_eq!(
            p["code"]["allOf"],
            json!([
                { "pattern": "^N-" },
                { "pattern": "x$" },
                { "pattern": "\\." },
                { "not": { "pattern": " " } }
            ])
        );
        assert_eq!(p["n"]["minimum"], 1);
        assert_eq!(p["n"]["maximum"], 5);
        assert_eq!(p["n"]["multipleOf"], 1);
        assert_eq!(p["n"]["default"], 3);
        assert_eq!(p["n"]["enum"], json!([1, 2, 3]));
        assert_eq!(p["f"]["exclusiveMinimum"], 0.0);
        assert_eq!(p["f"]["exclusiveMaximum"], 1.0);
        assert_eq!(p["f"]["x-nitr-decimals"], 2);
        assert_eq!(p["on"]["const"], true);
        assert_eq!(p["tags"]["items"]["x-nitr-format"], "slug");
        assert_eq!(p["tags"]["minItems"], 1);
        assert_eq!(p["tags"]["maxItems"], 5);
        assert_eq!(p["tags"]["uniqueItems"], true);
        assert_eq!(
            p["tags"]["allOf"],
            json!([
                { "contains": { "const": "a" } },
                { "contains": { "enum": ["b", "c"] } },
                { "contains": { "const": "d" } }
            ])
        );
        assert_eq!(p["meta"]["propertyNames"]["maxLength"], 8);
        assert_eq!(p["meta"]["additionalProperties"]["type"], "integer");
        assert_eq!(p["meta"]["minProperties"], 0);
        assert_eq!(p["meta"]["maxProperties"], 10);
        assert_eq!(p["blob"], json!({ "x-nitr-max-bytes": 100 }));
        assert_eq!(p["role"]["not"], json!({ "enum": ["root"] }));
        assert_eq!(p["due"]["format"], "date");
        assert_eq!(p["due"]["x-nitr-after"], "now");
        assert_eq!(p["due"]["x-nitr-before"], "2030-01-01");
        assert_eq!(p["len"]["minLength"], 4);
        assert_eq!(p["len"]["maxLength"], 4);
    }

    #[test]
    fn every_builtin_format_is_named_once() {
        for (name, format) in crate::validate::format::FORMATS {
            let (out, _) = export_of(&format!(
                r#"{{ v = {{ type = "string", format = "{name}" }} }}"#
            ));
            let v = &out["properties"]["v"];
            match standard_format(*format) {
                Some(std) => {
                    assert_eq!(v["format"], std, "{name}");
                    assert!(v.get("x-nitr-format").is_none(), "{name}");
                }
                None => {
                    assert_eq!(v["x-nitr-format"], *name, "{name}");
                    assert!(v.get("format").is_none(), "{name}");
                }
            }
        }
    }

    #[test]
    fn metacharacters_in_literals_are_escaped() {
        let (out, _) = export_of(
            r#"{ a = { type = "string", starts_with = "(", ends_with = "$", contains = ".*+?[]{}|^/\\" } }"#,
        );
        assert_eq!(
            out["properties"]["a"]["allOf"],
            json!([
                { "pattern": "^\\(" },
                { "pattern": "\\$$" },
                { "pattern": "\\.\\*\\+\\?\\[\\]\\{\\}\\|\\^\\/\\\\" }
            ])
        );
    }

    #[test]
    fn titled_schemas_become_components_and_nest_by_reference() {
        let lua = Lua::new();
        let inner = schema(&lua, r#"{ id = { type = "integer", required = true } }"#);
        lua.globals().set("Inner", inner).unwrap();
        let s = lua
            .load(
                r#"nitr.validate.schema({
                    item = { type = "table", fields = Inner, required = true },
                    items = { type = "array", items = { type = "table", fields = Inner } },
                }, { title = "Outer" })"#,
            )
            .eval::<mlua::AnyUserData>()
            .expect("outer");
        let compiled =
            crate::validate::compile_schema(&lua, mlua::Value::UserData(s), "test").unwrap();
        let mut components = Components::new();
        let out = compiled.json_schema(&mut components).unwrap();
        assert_eq!(out, json!({ "$ref": "#/components/schemas/Outer" }));
        let outer = &components["Outer"];
        assert_eq!(outer["title"], "Outer");
        // Untitled inner schemas inline.
        assert_eq!(outer["properties"]["item"]["type"], "object");
        assert_eq!(
            outer["properties"]["items"]["items"]["properties"]["id"]["type"],
            "integer"
        );
        assert_eq!(components.len(), 1);
    }

    #[test]
    fn a_title_shared_by_two_schemas_gets_a_suffix() {
        let lua = Lua::new();
        let a = schema(&lua, r#"{ a = { type = "string" } }"#);
        lua.globals().set("A", a).unwrap();
        let s = lua
            .load(r#"nitr.validate.schema({ b = { type = "string" } }, { title = "Dup" })"#)
            .eval::<mlua::AnyUserData>()
            .unwrap();
        let t = lua
            .load(r#"nitr.validate.schema({ c = { type = "string" } }, { title = "Dup" })"#)
            .eval::<mlua::AnyUserData>()
            .unwrap();
        let mut components = Components::new();
        let mut refs = Vec::new();
        for ud in [s, t] {
            let compiled =
                crate::validate::compile_schema(&lua, mlua::Value::UserData(ud), "test").unwrap();
            refs.push(compiled.json_schema(&mut components).unwrap());
        }
        assert_eq!(refs[0], json!({ "$ref": "#/components/schemas/Dup" }));
        assert_eq!(refs[1], json!({ "$ref": "#/components/schemas/Dup_2" }));
        assert_eq!(components["Dup"]["properties"]["b"]["type"], "string");
        assert_eq!(components["Dup_2"]["properties"]["c"]["type"], "string");
        assert_eq!(components["Dup_2"]["title"], "Dup_2");
        // The same schema again reuses its component.
        let again = crate::validate::compile_schema(
            &lua,
            lua.load(r#"nitr.validate.schema({ b = { type = "string" } }, { title = "Dup" })"#)
                .eval::<mlua::Value>()
                .unwrap(),
            "test",
        )
        .unwrap();
        assert_eq!(
            again.json_schema(&mut components).unwrap(),
            json!({ "$ref": "#/components/schemas/Dup" })
        );
        assert_eq!(components.len(), 2);
    }

    #[test]
    fn custom_checks_and_formats_are_marked_and_described() {
        let lua = Lua::new();
        crate::validate::tests::validate(&lua);
        lua.load(
            r#"nitr.validate.format("note_ref", {
                description = "A note reference", pattern = "^N-[0-9]+$", example = "N-1",
                check = function(s) return s:match("^N%-%d+$") ~= nil end,
            })"#,
        )
        .exec()
        .unwrap();
        let s = lua
            .load(
                r#"nitr.validate.schema({
                    r = { type = "string", format = "note_ref", description = "which note" },
                    pw = { type = "string", description = "not common", check = function(s) return true end },
                    t = { type = "string", transform = function(s) return s end },
                    a = { type = "string" }, b = { type = "string" }, c = { type = "string" },
                    lo = { type = "integer" }, hi = { type = "integer" },
                }, {
                    at_least_one = { { "a", "b" } },
                    mutually_exclusive = { { "a", "c" } },
                    dependent_required = { a = { "b" } },
                    equal_fields = { { "b", "c" } },
                    ordered = { { "lo", "hi" } },
                    checks = { { description = "the pair is unique", check = function() return true end } },
                })"#,
            )
            .eval::<mlua::AnyUserData>()
            .unwrap();
        let compiled =
            crate::validate::compile_schema(&lua, mlua::Value::UserData(s), "test").unwrap();
        let out = compiled.json_schema(&mut Components::new()).unwrap();
        let p = &out["properties"];
        assert_eq!(p["r"]["x-nitr-format"], "note_ref");
        assert_eq!(p["r"]["pattern"], "^N-[0-9]+$");
        assert_eq!(p["r"]["example"], "N-1");
        assert_eq!(p["r"]["x-nitr-enforced"], "custom");
        assert_eq!(p["r"]["description"], "which note\n\nA note reference");
        assert_eq!(p["pw"]["x-nitr-enforced"], "custom");
        assert_eq!(p["pw"]["description"], "not common");
        assert_eq!(p["t"]["x-nitr-transform"], json!(["custom"]));
        assert_eq!(
            out["anyOf"],
            json!([{ "required": ["a"] }, { "required": ["b"] }])
        );
        assert_eq!(out["x-nitr-mutually-exclusive"], json!([["a", "c"]]));
        assert_eq!(out["dependentRequired"], json!({ "a": ["b"] }));
        assert_eq!(out["x-nitr-equal-fields"], json!([["b", "c"]]));
        assert_eq!(out["x-nitr-ordered"], json!([["lo", "hi"]]));
        assert_eq!(out["x-nitr-checks"], json!(["the pair is unique"]));
        assert_eq!(out["description"], "Constraints:\n- the pair is unique");
        assert_eq!(out["x-nitr-enforced"], "custom");
    }

    #[test]
    fn file_rules_render_as_binary_strings_with_their_bounds() {
        let lua = Lua::new();
        crate::validate::tests::validate(&lua);
        let s = lua
            .load(
                r#"nitr.validate.schema({
                    one = { type = "file", types = { "image/png" }, max_bytes = 1024, min_bytes = 1,
                            extensions = { "png" }, max_width = 100, max_pixels = 1000, aspect = "1:1" },
                    many = { type = "file", types = { "image/*", "application/pdf" }, max_bytes = 2048,
                             allow_executables = true, utf8 = true, filename = { type = "string", max_len = 20 } },
                    any = { type = "file", types = { "*/*" }, max_bytes = 10 },
                })"#,
            )
            .eval::<mlua::AnyUserData>()
            .unwrap();
        let compiled =
            crate::validate::compile_schema(&lua, mlua::Value::UserData(s), "test").unwrap();
        let out = compiled.json_schema(&mut Components::new()).unwrap();
        let p = &out["properties"];
        assert_eq!(p["one"]["type"], "string");
        assert_eq!(p["one"]["contentMediaType"], "image/png");
        assert!(p["one"].get("format").is_none());
        assert_eq!(p["one"]["x-nitr-max-bytes"], 1024);
        assert_eq!(p["one"]["x-nitr-min-bytes"], 1);
        assert_eq!(p["one"]["x-nitr-extensions"], json!(["png"]));
        assert_eq!(p["one"]["x-nitr-max-width"], 100);
        assert_eq!(p["one"]["x-nitr-max-pixels"], 1000);
        assert_eq!(p["one"]["x-nitr-aspect"], "1:1");
        assert_eq!(p["many"]["format"], "binary");
        assert_eq!(
            p["many"]["x-nitr-types"],
            json!(["image/*", "application/pdf"])
        );
        assert_eq!(p["many"]["x-nitr-allow-executables"], true);
        assert_eq!(p["many"]["x-nitr-utf8"], true);
        assert_eq!(p["many"]["x-nitr-filename"]["maxLength"], 20);
        assert_eq!(p["any"]["x-nitr-types"], json!(["*/*"]));
    }

    #[test]
    fn export_is_deterministic_across_states() {
        let source = r#"{
            z = { type = "string" }, a = { type = "integer", one_of = { 3, 1, 2 } },
            m = { type = "map", keys = { type = "string" }, values = { type = "string" }, max_keys = 2 },
        }"#;
        let first = serde_json::to_string(&export_of(source).0).unwrap();
        for _ in 0..3 {
            assert_eq!(serde_json::to_string(&export_of(source).0).unwrap(), first);
        }
        assert!(first.find("\"a\"").unwrap() < first.find("\"z\"").unwrap());
    }
}
