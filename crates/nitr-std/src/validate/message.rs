// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Validation messages: the default sentence for every rule, the
//! placeholder templates that override them, and the parameters a rule
//! exposes to a template.
//!
//! A template is compiled at load and rendered by substitution only. The
//! placeholders a rule offers are its own parameters (`{min}`, `{choices}`
//! …) plus `{label}` and `{path}`; there is no `{value}`, so a message can
//! never echo the input — by construction rather than by convention.

use std::collections::BTreeMap;

use mlua::Value;

/// The longest template accepted at load: a message reaches the 422 body
/// and the log line, and 500 characters is already a paragraph.
pub(super) const MAX_TEMPLATE_CHARS: usize = 500;

/// Longest reason a custom check may return, and the cap applied to every
/// rendered message before it leaves the engine.
pub(super) const MAX_REASON_CHARS: usize = 200;

/// A parameter of a failed rule, as the template renderer and the
/// `errors[].params` entry see it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Param {
    Str(String),
    Num(f64),
    Bool(bool),
    /// A byte count, rendered humanized (`2 MB`), serialized as bytes.
    Size(u64),
    /// A list of literals, rendered `"a", "b", 3`.
    List(Vec<Param>),
}

impl Param {
    /// Renders for a message.
    pub(crate) fn render(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Num(n) => fmt_num(*n),
            Self::Bool(b) => b.to_string(),
            Self::Size(bytes) => fmt_size(*bytes),
            Self::List(items) => items
                .iter()
                .map(|item| match item {
                    Self::Str(s) => format!("\"{s}\""),
                    other => other.render(),
                })
                .collect::<Vec<_>>()
                .join(", "),
        }
    }

    /// The JSON-safe form for `errors[].params`.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Str(s) => serde_json::Value::String(s.clone()),
            Self::Num(n) => serde_json::Number::from_f64(*n)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            Self::Bool(b) => serde_json::Value::Bool(*b),
            Self::Size(bytes) => serde_json::Value::from(*bytes),
            Self::List(items) => {
                serde_json::Value::Array(items.iter().map(Self::to_json).collect())
            }
        }
    }

    /// The Lua form for `errors[].params`.
    pub(crate) fn to_lua(&self, lua: &mlua::Lua) -> mlua::Result<Value> {
        Ok(match self {
            Self::Str(s) => Value::String(lua.create_string(s)?),
            Self::Num(n) if n.fract() == 0.0 && n.abs() < 9.0e15 => Value::Integer(*n as i64),
            Self::Num(n) => Value::Number(*n),
            Self::Bool(b) => Value::Boolean(*b),
            Self::Size(bytes) => Value::Integer(i64::try_from(*bytes).unwrap_or(i64::MAX)),
            Self::List(items) => {
                let t = lua.create_table_with_capacity(items.len(), 0)?;
                for (i, item) in items.iter().enumerate() {
                    t.raw_set(i + 1, item.to_lua(lua)?)?;
                }
                Value::Table(t)
            }
        })
    }
}

/// Numbers print without a trailing `.0` when they are whole.
pub(crate) fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1.0e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// Byte counts print in the unit a person would pick: `512 B`, `2 KB`,
/// `1.5 MB`, `3 GB`.
pub fn fmt_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 3] = [("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)];
    for (unit, size) in UNITS {
        if bytes >= size {
            let value = bytes as f64 / size as f64;
            return if value.fract() == 0.0 {
                format!("{} {unit}", value as u64)
            } else {
                format!("{value:.1} {unit}")
            };
        }
    }
    format!("{bytes} B")
}

/// The placeholders every template may use, whatever the rule.
const COMMON_PLACEHOLDERS: &[&str] = &["label", "path"];

/// The placeholders a rule exposes, by rule code.
///
/// `contains` is both a string rule (`{text}`) and an array rule
/// (`{item}`); the union is allowed so one template can serve either.
pub(crate) fn rule_params(rule: &str) -> &'static [&'static str] {
    match rule {
        "type" => &["type"],
        "min_len" | "min" | "exclusive_min" | "min_items" | "min_keys" | "min_bytes"
        | "min_width" | "min_height" => &["min"],
        "max_len" | "max" | "exclusive_max" | "max_items" | "max_keys" | "max_bytes"
        | "max_total_bytes" | "max_width" | "max_height" | "max_pixels" => &["max"],
        "len" => &["len"],
        "multiple_of" => &["step"],
        "decimals" => &["decimals"],
        "format" => &["format"],
        "one_of" | "not_one_of" | "contains_any" | "contains_all" => &["choices"],
        "equals" => &["expected"],
        "starts_with" | "ends_with" | "does_not_contain" => &["text"],
        "contains" => &["text", "item"],
        "after" | "before" => &["limit"],
        "types" => &["types"],
        "extensions" => &["extensions"],
        "filename" => &["text"],
        "aspect" => &["aspect"],
        "at_least_one" | "mutually_exclusive" | "dependent_required" => &["fields"],
        "equal_fields" | "ordered" => &["field"],
        _ => &[],
    }
}

/// Every rule code a `messages` table may name. Unknown codes fail at
/// load like unknown rule keys do: a typo must not silently override
/// nothing.
/// Every rule code an `errors[].rule` may carry, for the document's
/// `ValidationError` component.
pub fn rule_codes() -> &'static [&'static str] {
    RULE_CODES
}

pub(crate) const RULE_CODES: &[&str] = &[
    "type",
    "required",
    "min_len",
    "max_len",
    "len",
    "min",
    "max",
    "exclusive_min",
    "exclusive_max",
    "multiple_of",
    "decimals",
    "format",
    "one_of",
    "not_one_of",
    "equals",
    "starts_with",
    "ends_with",
    "contains",
    "does_not_contain",
    "after",
    "before",
    "min_items",
    "max_items",
    "unique",
    "contains_any",
    "contains_all",
    "min_keys",
    "max_keys",
    "max_bytes",
    "min_bytes",
    "max_total_bytes",
    "types",
    "extensions",
    "match_extension",
    "executable",
    "filename",
    "min_width",
    "max_width",
    "min_height",
    "max_height",
    "max_pixels",
    "aspect",
    "dimensions",
    "utf8",
    "at_least_one",
    "mutually_exclusive",
    "dependent_required",
    "equal_fields",
    "ordered",
    "unknown",
    "keys",
    "check",
    "json",
    "multipart",
    "body",
];

/// The built-in sentence for a rule, given its parameters and the kind of
/// value it applied to (a few rules read differently per kind).
pub(crate) fn default_message(rule: &str, kind: &str, params: &BTreeMap<&str, Param>) -> String {
    let p = |name: &str| params.get(name).map(Param::render).unwrap_or_default();
    match rule {
        "type" => match kind {
            "string" => "must be a string".into(),
            "integer" => "must be an integer".into(),
            "number" => "must be a number".into(),
            "boolean" => "must be a boolean".into(),
            "array" => "must be a list".into(),
            "table" | "map" => "must be an object".into(),
            "file" => "must be a file".into(),
            _ => format!("must be a {kind}"),
        },
        "required" => "is required".into(),
        "min_len" => format!("must be at least {} characters", p("min")),
        "max_len" => format!("must be at most {} characters", p("max")),
        "len" => format!("must be exactly {} characters", p("len")),
        "min" => format!("must be at least {}", p("min")),
        "max" => format!("must be at most {}", p("max")),
        "exclusive_min" => format!("must be greater than {}", p("min")),
        "exclusive_max" => format!("must be less than {}", p("max")),
        "multiple_of" => format!("must be a multiple of {}", p("step")),
        "decimals" => format!("must have at most {} decimal places", p("decimals")),
        // The format's own description is passed as the `format` param
        // already phrased ("an email address").
        "format" => format!("must be {}", p("format")),
        "one_of" => format!("must be one of: {}", p("choices")),
        "not_one_of" => format!("must not be one of: {}", p("choices")),
        "equals" => format!("must be {}", p("expected")),
        "starts_with" => format!("must start with {}", p("text")),
        "ends_with" => format!("must end with {}", p("text")),
        "contains" if kind == "array" => format!("must include {}", p("item")),
        "contains" => format!("must contain {}", p("text")),
        "does_not_contain" => format!("must not contain {}", p("text")),
        "after" if params.get("limit") == Some(&Param::Str("now".into())) => {
            "must be in the future".into()
        }
        "before" if params.get("limit") == Some(&Param::Str("now".into())) => {
            "must be in the past".into()
        }
        "after" => format!("must be after {}", p("limit")),
        "before" => format!("must be before {}", p("limit")),
        "min_items" => format!("must have at least {} items", p("min")),
        "max_items" => format!("must have at most {} items", p("max")),
        "unique" => "must not contain duplicates".into(),
        "contains_any" => format!("must include one of: {}", p("choices")),
        "contains_all" => format!("must include all of: {}", p("choices")),
        "min_keys" => format!("must have at least {} entries", p("min")),
        "max_keys" => format!("must have at most {} entries", p("max")),
        "max_bytes" if kind == "file" => format!("must be at most {}", p("max")),
        "max_bytes" => format!("must be at most {} in size", p("max")),
        "min_bytes" => format!("must be at least {}", p("min")),
        "max_total_bytes" => format!("must be at most {} in total", p("max")),
        "types" => format!("must be {}", p("types")),
        "extensions" => format!("must have one of these extensions: {}", p("extensions")),
        "match_extension" => "must have an extension that matches its content".into(),
        "executable" => "must not be an executable".into(),
        "min_width" => format!("must be at least {} px wide", p("min")),
        "max_width" => format!("must be at most {} px wide", p("max")),
        "min_height" => format!("must be at least {} px tall", p("min")),
        "max_height" => format!("must be at most {} px tall", p("max")),
        "max_pixels" => format!("must be at most {} pixels", p("max")),
        "aspect" => format!("must have a {} aspect ratio", p("aspect")),
        "dimensions" => "must have readable image dimensions".into(),
        "utf8" => "must be UTF-8 text".into(),
        "at_least_one" => format!("at least one of {} is required", p("fields")),
        "mutually_exclusive" => format!("only one of {} may be given", p("fields")),
        "dependent_required" => format!("requires {}", p("fields")),
        "equal_fields" => format!("must equal {}", p("field")),
        "ordered" => format!("must be after {}", p("field")),
        "unknown" => "is not a known field".into(),
        "keys" => "must have string keys".into(),
        "filename" if params.contains_key("text") => {
            format!("must have a valid name: {}", p("text"))
        }
        "filename" => "must have a name".into(),
        "check" => "is invalid".into(),
        "json" => "must be valid JSON".into(),
        "multipart" => "must be a well-formed multipart body".into(),
        "body" => "must be an object".into(),
        other => format!("failed the {other} rule"),
    }
}

/// One piece of a compiled template.
#[derive(Debug, Clone, PartialEq)]
enum Seg {
    Lit(String),
    Var(String),
}

/// A message template compiled at load: literal text and placeholders.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Template {
    segs: Vec<Seg>,
}

impl Template {
    /// Compiles `text`, accepting only the placeholders in `allowed` (plus
    /// `{label}` and `{path}`). `what` names the site for the error.
    pub(crate) fn compile(text: &str, allowed: &[&str], what: &str) -> mlua::Result<Self> {
        let bad =
            |msg: String| mlua::Error::RuntimeError(format!("invalid message for {what}: {msg}"));
        if text.chars().count() > MAX_TEMPLATE_CHARS {
            return Err(bad(format!("longer than {MAX_TEMPLATE_CHARS} characters")));
        }
        if text.chars().any(|c| c.is_control()) {
            return Err(bad("contains a control character".into()));
        }
        let mut segs = Vec::new();
        let mut lit = String::new();
        let mut rest = text;
        while let Some(start) = rest.find('{') {
            lit.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let Some(end) = after.find('}') else {
                return Err(bad("unbalanced `{`".into()));
            };
            let name = &after[..end];
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                return Err(bad(format!("bad placeholder `{{{name}}}`")));
            }
            if !allowed.contains(&name) && !COMMON_PLACEHOLDERS.contains(&name) {
                let mut names: Vec<&str> = allowed.to_vec();
                names.extend(COMMON_PLACEHOLDERS);
                return Err(bad(format!(
                    "unknown placeholder `{{{name}}}` (allowed: {})",
                    names
                        .iter()
                        .map(|n| format!("{{{n}}}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            if !lit.is_empty() {
                segs.push(Seg::Lit(std::mem::take(&mut lit)));
            }
            segs.push(Seg::Var(name.to_string()));
            rest = &after[end + 1..];
        }
        if rest.contains('}') {
            return Err(bad("unbalanced `}`".into()));
        }
        lit.push_str(rest);
        if !lit.is_empty() {
            segs.push(Seg::Lit(lit));
        }
        Ok(Self { segs })
    }

    /// Renders with the rule's parameters; `label` and `path` are always
    /// available.
    pub(crate) fn render(&self, params: &BTreeMap<&str, Param>, label: &str, path: &str) -> String {
        let mut out = String::new();
        for seg in &self.segs {
            match seg {
                Seg::Lit(s) => out.push_str(s),
                Seg::Var(name) => match name.as_str() {
                    "label" => out.push_str(label),
                    "path" => out.push_str(path),
                    other => {
                        out.push_str(&params.get(other).map(Param::render).unwrap_or_default())
                    }
                },
            }
        }
        out
    }
}

/// Caps a rendered or returned message and strips control characters, so
/// nothing a check returns can forge a log line or bloat a response.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_CHARS)
        .collect()
}

/// Compiles a `messages = { rule = "template" }` table, refusing unknown
/// rule codes and placeholders the rule does not offer.
pub(crate) fn compile_messages(
    table: &mlua::Table,
    what: &str,
) -> mlua::Result<BTreeMap<String, Template>> {
    let mut out = BTreeMap::new();
    for pair in table.pairs::<Value, Value>() {
        let (key, value) = pair?;
        let Value::String(key) = key else {
            return Err(mlua::Error::RuntimeError(format!(
                "invalid messages for {what}: keys must be rule names"
            )));
        };
        let rule = key.to_string_lossy().to_string();
        if rule != "summary" && !RULE_CODES.contains(&rule.as_str()) {
            return Err(mlua::Error::RuntimeError(format!(
                "invalid messages for {what}: unknown rule `{rule}`"
            )));
        }
        let Value::String(text) = value else {
            return Err(mlua::Error::RuntimeError(format!(
                "invalid messages for {what}: the message for `{rule}` must be a string"
            )));
        };
        let template = Template::compile(
            &text.to_string_lossy(),
            rule_params(&rule),
            &format!("{what} (rule `{rule}`)"),
        )?;
        out.insert(rule, template);
    }
    Ok(out)
}

/// The app-wide message overrides, one table per Lua state, set at load
/// through `nitr.validate.messages(...)`.
#[derive(Debug, Default)]
pub(crate) struct AppMessages {
    pub(crate) rules: BTreeMap<String, Template>,
    pub(crate) summary: Option<String>,
    /// Set once the application has compiled: a later call raises, so one
    /// request can never change the wording another sees.
    pub(crate) frozen: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_substitute_only_known_placeholders() {
        let t = Template::compile("{label} must be at least {min}", &["min"], "x").expect("ok");
        let params = BTreeMap::from([("min", Param::Num(3.0))]);
        assert_eq!(
            t.render(&params, "Age", "body.age"),
            "Age must be at least 3"
        );
        for bad in ["{value}", "{min", "min}", "{Min}", "{}"] {
            assert!(Template::compile(bad, &["min"], "x").is_err(), "{bad}");
        }
    }

    #[test]
    fn sizes_and_numbers_render_for_people() {
        assert_eq!(fmt_size(512), "512 B");
        assert_eq!(fmt_size(2 * 1024 * 1024), "2 MB");
        assert_eq!(fmt_size(1536 * 1024), "1.5 MB");
        assert_eq!(fmt_num(3.0), "3");
        assert_eq!(fmt_num(0.5), "0.5");
        assert_eq!(
            Param::List(vec![Param::Str("a".into()), Param::Num(2.0)]).render(),
            "\"a\", 2"
        );
    }

    #[test]
    fn sanitize_caps_and_strips_control_characters() {
        let long = "x".repeat(400);
        assert_eq!(sanitize(&long).chars().count(), MAX_REASON_CHARS);
        assert_eq!(sanitize("a\nb\x1bc"), "abc");
    }
}
