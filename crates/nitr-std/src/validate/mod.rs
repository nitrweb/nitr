// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Declarative request validation: `nitr.validate.schema({...})` compiles
//! a schema once at load time; `schema:check(value)` then validates
//! untrusted input in Rust, per request, and reports every failing field.
//!
//! Deliberately not JSON Schema: a small declarative subset covers what a
//! small API needs, and validating input is exactly the "predictable,
//! fast, secure" work that belongs on the Rust side of the boundary.

use mlua::{Lua, Table, UserData, UserDataMethods, Value};

mod compile;
pub(crate) mod format;
#[cfg(test)]
mod tests;

use compile::compile_fields;
use format::Format;

/// The value types a rule can require.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Table,
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
            _ => None?,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Array => "array",
            Self::Table => "table",
        }
    }
}

/// A literal a `one_of` list can hold.
#[derive(Debug, Clone, PartialEq)]
enum Literal {
    String(String),
    Number(f64),
}

impl std::fmt::Display for Literal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "\"{s}\""),
            Self::Number(n) => write!(f, "{n}"),
        }
    }
}

/// One compiled field rule.
#[derive(Debug)]
struct Rule {
    kind: Kind,
    required: bool,
    // Numbers.
    min: Option<f64>,
    max: Option<f64>,
    // Strings.
    min_len: Option<usize>,
    max_len: Option<usize>,
    format: Option<Format>,
    // Strings and numbers.
    one_of: Option<Vec<Literal>>,
    // Arrays.
    items: Option<Box<Rule>>,
    min_items: Option<usize>,
    max_items: Option<usize>,
    // Nested tables.
    fields: Option<Vec<(String, Rule)>>,
}

/// Validates one value against a rule. On success returns the value to
/// place in the output (tables are rebuilt with only declared fields); on
/// failure records a message under `path` and returns `None`.
fn check_value(
    lua: &Lua,
    rule: &Rule,
    value: Value,
    path: &str,
    errors: &Table,
) -> mlua::Result<Option<Value>> {
    let fail = |msg: String| -> mlua::Result<Option<Value>> {
        errors.set(path, msg)?;
        Ok(None)
    };

    match rule.kind {
        Kind::String => {
            let Value::String(s) = &value else {
                return fail(format!("must be a string, got {}", value.type_name()));
            };
            let s = s.to_string_lossy().to_string();
            let len = s.chars().count();
            if let Some(min) = rule.min_len
                && len < min
            {
                return fail(format!("must be at least {min} characters"));
            }
            if let Some(max) = rule.max_len
                && len > max
            {
                return fail(format!("must be at most {max} characters"));
            }
            if let Some(format) = rule.format
                && !format.check(&s)
            {
                return fail(format!("must be {}", format.describe()));
            }
            if let Some(one_of) = &rule.one_of
                && !one_of.contains(&Literal::String(s.clone()))
            {
                return fail(format!("must be one of: {}", literals(one_of)));
            }
            Ok(Some(value))
        }
        Kind::Number | Kind::Integer => {
            let n = match &value {
                Value::Integer(n) => *n as f64,
                Value::Number(n) => *n,
                other => {
                    return fail(format!("must be a number, got {}", other.type_name()));
                }
            };
            if rule.kind == Kind::Integer && n.fract() != 0.0 {
                return fail("must be an integer".into());
            }
            if let Some(min) = rule.min
                && n < min
            {
                return fail(format!("must be >= {min}"));
            }
            if let Some(max) = rule.max
                && n > max
            {
                return fail(format!("must be <= {max}"));
            }
            if let Some(one_of) = &rule.one_of
                && !one_of.contains(&Literal::Number(n))
            {
                return fail(format!("must be one of: {}", literals(one_of)));
            }
            Ok(Some(value))
        }
        Kind::Boolean => match value {
            Value::Boolean(_) => Ok(Some(value)),
            other => fail(format!("must be a boolean, got {}", other.type_name())),
        },
        Kind::Array => {
            let Value::Table(t) = &value else {
                return fail(format!("must be an array, got {}", value.type_name()));
            };
            let len = t.raw_len();
            if let Some(min) = rule.min_items
                && len < min
            {
                return fail(format!("must have at least {min} items"));
            }
            if let Some(max) = rule.max_items
                && len > max
            {
                return fail(format!("must have at most {max} items"));
            }
            // Invariant: schema compilation only builds an array rule with
            // its `items` present.
            #[allow(clippy::expect_used)]
            let items = rule.items.as_ref().expect("array rules carry `items`");
            let out = lua.create_table_with_capacity(len, 0)?;
            let mut ok = true;
            for i in 1..=len {
                let item: Value = t.raw_get(i)?;
                match check_value(lua, items, item, &format!("{path}[{i}]"), errors)? {
                    Some(item) => out.raw_set(i, item)?,
                    None => ok = false,
                }
            }
            Ok(ok.then_some(Value::Table(out)))
        }
        Kind::Table => {
            let Value::Table(t) = &value else {
                return fail(format!("must be a table, got {}", value.type_name()));
            };
            // Invariant: schema compilation only builds a table rule with
            // its `fields` present.
            #[allow(clippy::expect_used)]
            let fields = rule.fields.as_ref().expect("table rules carry `fields`");
            check_fields(lua, fields, t, path, errors).map(|v| v.map(Value::Table))
        }
    }
}

/// Validates a table against a field map, building the output table with
/// only the declared fields — undeclared input never passes through, so a
/// handler cannot be mass-assigned a field the schema never mentioned.
fn check_fields(
    lua: &Lua,
    fields: &[(String, Rule)],
    input: &Table,
    path: &str,
    errors: &Table,
) -> mlua::Result<Option<Table>> {
    let out = lua.create_table()?;
    let mut ok = true;
    for (name, rule) in fields {
        let field_path = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}.{name}")
        };
        let value: Value = input.get(name.as_str())?;
        if value.is_nil() {
            if rule.required {
                errors.set(field_path, "is required")?;
                ok = false;
            }
            continue;
        }
        match check_value(lua, rule, value, &field_path, errors)? {
            Some(value) => out.set(name.as_str(), value)?,
            None => ok = false,
        }
    }
    Ok(ok.then_some(out))
}

fn literals(list: &[Literal]) -> String {
    list.iter()
        .map(Literal::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A compiled schema: the field rules live in Rust, so `check` walks the
/// input once with no per-request compilation.
struct LuaSchema {
    fields: Vec<(String, Rule)>,
}

impl UserData for LuaSchema {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // schema:check(value) -> data, nil | nil, { message, fields }
        //
        // `data` contains only the declared fields; `fields` maps each
        // failing field path (`email`, `address.city`, `tags[2]`) to its
        // message, ready to serialize into a 422 body.
        methods.add_method("check", |lua, this, value: Value| {
            let errors = lua.create_table()?;
            let checked = match &value {
                Value::Table(input) => check_fields(lua, &this.fields, input, "", &errors)?,
                other => {
                    errors.set("$", format!("must be a table, got {}", other.type_name()))?;
                    None
                }
            };
            match checked {
                Some(data) => Ok((Value::Table(data), Value::Nil)),
                None => {
                    let err = lua.create_table()?;
                    err.set("message", "validation failed")?;
                    err.set("fields", errors)?;
                    Ok((Value::Nil, Value::Table(err)))
                }
            }
        });
    }
}

/// Builds the `nitr.validate` table.
pub(crate) fn create_validate_table(lua: &Lua) -> mlua::Result<Table> {
    let validate = lua.create_table()?;
    validate.set(
        "schema",
        lua.create_function(|_, fields: Table| {
            Ok(LuaSchema {
                fields: compile_fields(&fields, "")?,
            })
        })?,
    )?;
    Ok(validate)
}
