// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Declarative request validation: `nitr.validate.schema({...})` compiles
//! a schema once at load time; `schema:check(value)` then validates
//! untrusted input in Rust, per request, and reports every failing field.
//!
//! Deliberately not JSON Schema: a closed declarative vocabulary — every
//! key with one meaning, a typo a load-time error — plus three escape
//! hatches for what no closed set expresses (custom formats, a per-field
//! `check`, schema-level `checks`), each carrying a description so the
//! API description can say what is enforced. The engine runs the Rust
//! rules first and reaches script code last, inside the request's budget.
//!
//! This file holds the data model and the server-facing API; [`lua`] is
//! the Lua surface, [`compile`] the compiler, [`engine`] the checker,
//! [`coerce`] text input, [`media`] and [`file`] uploads, [`message`]
//! the messages, [`shorthand`] the pipe notation, [`presets`] the file
//! presets.

use std::collections::BTreeMap;
use std::sync::Arc;

use mlua::{AnyUserData, Function, Lua, Table, Value};

mod coerce;
mod compile;
mod engine;
pub(crate) mod file;
pub(crate) mod format;
mod lua;
pub(crate) mod media;
pub(crate) mod message;
mod presets;
mod shorthand;
#[cfg(test)]
mod tests;

pub use coerce::{TextValue, coerce_for_fuzzing};
pub use engine::{ErrorEntry, ValidationError};
pub use file::{FileInfo, LuaFile, SaveResolver};
use format::FormatRule;
pub(crate) use lua::{LuaSchema, create_validate_table};
use message::{AppMessages, Param, Template};

/// The value types a rule can require.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Table,
    Map,
    Any,
    File,
}

impl Kind {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "string" => Self::String,
            "number" => Self::Number,
            "integer" => Self::Integer,
            "boolean" => Self::Boolean,
            "array" => Self::Array,
            "table" => Self::Table,
            "map" => Self::Map,
            "any" => Self::Any,
            "file" => Self::File,
            _ => None?,
        })
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Array => "array",
            Self::Table => "table",
            Self::Map => "map",
            Self::Any => "any",
            Self::File => "file",
        }
    }
}

/// A literal a rule can compare against (`one_of`, `equals`, `default`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Literal {
    Str(String),
    Num(f64),
    Bool(bool),
}

impl Literal {
    fn matches(&self, value: &Value) -> bool {
        match (self, value) {
            (Self::Str(s), Value::String(v)) => v.as_bytes().as_ref() == s.as_bytes(),
            (Self::Num(n), Value::Integer(i)) => *n == *i as f64,
            (Self::Num(n), Value::Number(f)) => n == f,
            (Self::Bool(b), Value::Boolean(v)) => b == v,
            _ => false,
        }
    }

    fn param(&self) -> Param {
        match self {
            Self::Str(s) => Param::Str(s.clone()),
            Self::Num(n) => Param::Num(*n),
            Self::Bool(b) => Param::Bool(*b),
        }
    }

    fn to_lua(&self, lua: &Lua) -> mlua::Result<Value> {
        self.param().to_lua(lua)
    }
}

/// The `case` transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Case {
    Lower,
    Upper,
}

/// An `after`/`before` bound: a literal in the field's format, or `"now"`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TimeBound {
    Now,
    Literal(String),
}

/// A media type a `file` rule accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypePattern {
    /// `*/*`
    Any,
    /// `image/*`
    Family(String),
    Exact(String),
}

/// An `aspect` bound on `width / height`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Aspect {
    min: f64,
    max: f64,
    label: String,
}

/// The `file`-only part of a rule.
#[derive(Debug, Clone)]
pub(crate) struct FileRule {
    min_bytes: u64,
    types: Vec<TypePattern>,
    allow_executables: bool,
    extensions: Vec<String>,
    match_extension: bool,
    filename: Option<Arc<Rule>>,
    min_width: Option<u32>,
    max_width: Option<u32>,
    min_height: Option<u32>,
    max_height: Option<u32>,
    max_pixels: Option<u64>,
    aspect: Option<Aspect>,
    utf8: bool,
}

impl FileRule {
    fn wants_dimensions(&self) -> bool {
        self.min_width.is_some()
            || self.max_width.is_some()
            || self.min_height.is_some()
            || self.max_height.is_some()
            || self.max_pixels.is_some()
            || self.aspect.is_some()
    }
}

/// One compiled field rule.
#[derive(Debug, Clone)]
pub(crate) struct Rule {
    kind: Kind,
    required: bool,
    default: Option<Literal>,
    equals: Option<Literal>,
    one_of: Option<Vec<Literal>>,
    not_one_of: Option<Vec<Literal>>,
    label: Option<String>,
    /// The per-field override for every rule.
    message: Option<Template>,
    /// Per-field, per-rule overrides.
    messages: BTreeMap<String, Template>,
    check: Option<Function>,
    /// Normalization applied after the field's checks passed; must return
    /// a value of the rule's type.
    transform: Option<Function>,
    /// Documentation only; carried for the API description.
    #[allow(dead_code)]
    description: Option<String>,
    // Strings.
    trim: bool,
    case: Option<Case>,
    min_len: Option<usize>,
    max_len: Option<usize>,
    len: Option<usize>,
    format: Option<FormatRule>,
    starts_with: Option<String>,
    ends_with: Option<String>,
    contains: Option<String>,
    does_not_contain: Option<String>,
    after: Option<TimeBound>,
    before: Option<TimeBound>,
    // Numbers.
    min: Option<f64>,
    max: Option<f64>,
    exclusive_min: Option<f64>,
    exclusive_max: Option<f64>,
    multiple_of: Option<f64>,
    decimals: Option<u32>,
    // Arrays.
    items: Option<Arc<Rule>>,
    min_items: Option<usize>,
    max_items: Option<usize>,
    unique: bool,
    contains_item: Option<Literal>,
    contains_any: Option<Vec<Literal>>,
    contains_all: Option<Vec<Literal>>,
    max_total_bytes: Option<u64>,
    // Nested tables.
    fields: Option<Arc<SchemaDef>>,
    // Maps.
    keys: Option<Arc<Rule>>,
    values: Option<Arc<Rule>>,
    min_keys: Option<usize>,
    max_keys: Option<usize>,
    // `any` and `file`.
    max_bytes: Option<u64>,
    file: Option<FileRule>,
}

/// A group of field names for a cross-field rule, with its message.
#[derive(Debug, Clone)]
pub(crate) struct Group {
    fields: Vec<String>,
    message: Option<Template>,
}

/// One schema-level custom check.
#[derive(Debug, Clone)]
pub(crate) struct CheckDef {
    description: String,
    func: Function,
    message: Option<Template>,
}

/// A compiled schema: the field rules and the cross-field rules.
#[derive(Debug, Clone)]
pub(crate) struct SchemaDef {
    fields: Vec<(String, Arc<Rule>)>,
    /// The component name for the API description.
    #[allow(dead_code)]
    title: Option<String>,
    strict: bool,
    messages: BTreeMap<String, Template>,
    at_least_one: Vec<Group>,
    mutually_exclusive: Vec<Group>,
    dependent_required: Vec<(String, Group)>,
    equal_fields: Vec<Group>,
    ordered: Vec<Group>,
    checks: Vec<CheckDef>,
}

impl SchemaDef {
    fn rule(&self, name: &str) -> Option<&Arc<Rule>> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, r)| r)
    }

    fn has_file_rules(&self) -> bool {
        self.fields.iter().any(|(_, r)| r.mentions_file())
    }
}

impl Rule {
    fn mentions_file(&self) -> bool {
        self.kind == Kind::File
            || self.items.as_ref().is_some_and(|r| r.mentions_file())
            || self.fields.as_ref().is_some_and(|s| s.has_file_rules())
    }
}

/// A compiled schema as the server sees it: the handle route `input`
/// declarations are compiled into.
#[derive(Debug, Clone)]
pub struct CompiledSchema(Arc<SchemaDef>);

impl CompiledSchema {
    /// Whether any field (at any depth) is a `file` rule.
    pub fn has_file_rules(&self) -> bool {
        self.0.has_file_rules()
    }

    /// The declared top-level field names.
    pub fn field_names(&self) -> Vec<&str> {
        self.0.fields.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// Whether a top-level field is an array (repeated text keys collect
    /// into it).
    pub fn is_array_field(&self, name: &str) -> bool {
        self.0.rule(name).is_some_and(|r| r.kind == Kind::Array)
    }

    /// Whether a top-level field (or an array of them) is a `file` rule.
    pub fn is_file_field(&self, name: &str) -> bool {
        self.0.rule(name).is_some_and(|r| {
            r.kind == Kind::File || r.items.as_ref().is_some_and(|i| i.kind == Kind::File)
        })
    }

    /// The `max_bytes` of a top-level `file` rule (or of the items of an
    /// array of files), so the spooler can stop at the rule's own bound.
    pub fn file_max_bytes(&self, name: &str) -> Option<u64> {
        let rule = self.0.rule(name)?;
        match rule.kind {
            Kind::File => rule.max_bytes,
            Kind::Array => rule.items.as_ref().and_then(|i| i.max_bytes),
            _ => None,
        }
    }

    /// Whether the schema reports undeclared fields.
    pub fn strict(&self) -> bool {
        self.0.strict
    }

    /// Validates a Lua value (a decoded JSON body, say). The outer `Result`
    /// is a raised error — a custom check that failed as code; the inner
    /// one is the verdict.
    pub async fn check(
        &self,
        lua: &Lua,
        value: Value,
        strict: Option<bool>,
    ) -> mlua::Result<Result<Table, ValidationError>> {
        engine::run(lua, &self.0, value, strict).await
    }

    /// Validates text input (a query string, a form, path parameters,
    /// headers): the pairs are coerced by the schema, then checked.
    pub async fn check_text(
        &self,
        lua: &Lua,
        pairs: Vec<(String, TextValue)>,
        strict: Option<bool>,
    ) -> mlua::Result<Result<Table, ValidationError>> {
        let value = coerce::build_table(lua, &self.0, pairs)?;
        engine::run(lua, &self.0, Value::Table(value), strict).await
    }
}

/// Compiles a schema from what a script may hand a route: a field table
/// (rules as tables, shorthand strings or compiled schemas), or a compiled
/// `nitr.validate.schema` value. `what` names the site for errors.
pub fn compile_schema(lua: &Lua, value: Value, what: &str) -> mlua::Result<CompiledSchema> {
    match value {
        Value::UserData(ud) if ud.is::<LuaSchema>() => {
            Ok(CompiledSchema(ud.borrow::<LuaSchema>()?.0.clone()))
        }
        Value::Table(fields) => Ok(CompiledSchema(Arc::new(compile::compile_schema(
            lua, &fields, None, what,
        )?))),
        other => Err(mlua::Error::RuntimeError(format!(
            "{what} must be a schema or a table of rules, got {}",
            other.type_name()
        ))),
    }
}

/// Like [`compile_schema`], for a part whose values arrive as text (query,
/// params, headers): nested kinds are refused, since a query string has no
/// nesting.
pub fn compile_text_schema(lua: &Lua, value: Value, what: &str) -> mlua::Result<CompiledSchema> {
    let schema = compile_schema(lua, value, what)?;
    for (name, rule) in &schema.0.fields {
        let nested = match rule.kind {
            Kind::Table | Kind::Map | Kind::Any | Kind::File => true,
            Kind::Array => rule.items.as_ref().is_some_and(|i| {
                matches!(
                    i.kind,
                    Kind::Table | Kind::Map | Kind::Any | Kind::File | Kind::Array
                )
            }),
            _ => false,
        };
        if nested {
            return Err(mlua::Error::RuntimeError(format!(
                "{what}: field `{name}` has type `{}`, which text input cannot carry \
                 (a query string, form field or header is a string or a list of them)",
                rule.kind.name()
            )));
        }
    }
    Ok(schema)
}

/// Compiles one `file` rule for a `"raw"` body (`input.body = { file = … }`)
/// as a one-field schema whose field is named `file`.
pub fn compile_file_rule(lua: &Lua, value: Value, what: &str) -> mlua::Result<CompiledSchema> {
    let fields = lua.create_table()?;
    fields.set("file", value)?;
    let schema = compile::compile_schema(lua, &fields, None, what)?;
    match schema.rule("file") {
        Some(rule) if rule.kind == Kind::File => Ok(CompiledSchema(Arc::new(schema))),
        _ => Err(mlua::Error::RuntimeError(format!(
            "{what} must be a `file` rule"
        ))),
    }
}

/// Marks the state's app-wide messages as frozen: the application has
/// compiled, and a `nitr.validate.messages` call from a handler raises.
pub fn freeze_messages(lua: &Lua) {
    if let Some(mut app) = lua.app_data_mut::<AppMessages>() {
        app.frozen = true;
    } else {
        lua.set_app_data(AppMessages {
            frozen: true,
            ..Default::default()
        });
    }
}

/// A schema handed around as a `nitr.validate.schema` value: used by the
/// compiler when a compiled schema is nested as a field rule.
fn schema_of(ud: &AnyUserData) -> Option<Arc<SchemaDef>> {
    ud.borrow::<LuaSchema>().ok().map(|s| s.0.clone())
}
