// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The checker: one synchronous walk that applies every Rust rule and
//! collects the script-side checks it must run, then those checks in
//! order — so a value that fails a Rust rule never costs a Lua call, and
//! the Lua that does run is bounded by the caller's budget.
//!
//! Split by concern: [`errors`] is the verdict, [`path`] the position
//! type, [`value`] one value against one rule, [`cross`] the cross-field
//! rules, [`file`] the upload rules, [`util`] the pure helpers. This file
//! holds the context, the table walk, and the deferred-check runner.

use std::collections::BTreeMap;
use std::sync::Arc;

use mlua::{Function, Lua, Table, Value};

mod cross;
mod errors;
mod file;
mod path;
mod util;
mod value;

pub use errors::{ErrorEntry, ValidationError};
use path::FieldPath;
use util::{Verdict, matches_kind, verdict};

use super::format::CustomFormat;
use super::message::{self, AppMessages, Param, Template, default_message};
use super::{Kind, Rule, SchemaDef};

/// Unknown fields listed per table under `strict`; past this one entry
/// gives the remainder, so a hostile body cannot inflate the response.
const MAX_UNKNOWN_LISTED: usize = 32;

/// Every parameter list is tiny; a `Vec` of pairs keeps insertion order
/// for `errors[].params` and a map view for templates.
type Params = Vec<(&'static str, Param)>;

fn params_map(params: &Params) -> BTreeMap<&str, Param> {
    params.iter().map(|(k, v)| (*k, v.clone())).collect()
}

/// Where a checked value landed in the output, so a custom check can
/// replace it.
struct Slot {
    table: Table,
    key: Value,
}

/// A script-side check the sync walk deferred.
enum Pending {
    Field {
        slot: Slot,
        path: String,
        field: String,
        rule: Arc<Rule>,
        owner: Arc<SchemaDef>,
        value: Value,
        check: PendingCheck,
    },
    Schema {
        table: Table,
        prefix: String,
        schema: Arc<SchemaDef>,
        index: usize,
    },
}

enum PendingCheck {
    Custom(Function),
    Format(Arc<CustomFormat>),
    Transform(Function),
}

/// One validation's state.
struct Ctx<'a> {
    lua: &'a Lua,
    strict: bool,
    errors: Vec<ErrorEntry>,
    pending: Vec<Pending>,
    /// One instant per check, read the first time `"now"` is compared.
    now: Option<chrono::DateTime<chrono::Utc>>,
}

impl<'a> Ctx<'a> {
    /// A scratch context for a nested check (the filename rule) that must
    /// not record into the parent.
    fn child(parent: &Ctx<'a>) -> Self {
        Self {
            lua: parent.lua,
            strict: false,
            errors: Vec::new(),
            pending: Vec::new(),
            now: parent.now,
        }
    }

    /// The instant `"now"` bounds compare against: read once per check
    /// through the standard clock (`chrono` is built without its clock
    /// feature), so a request sees one instant.
    fn now(&mut self) -> chrono::DateTime<chrono::Utc> {
        *self.now.get_or_insert_with(|| {
            chrono::DateTime::<chrono::Utc>::from(crate::clock::now_system())
        })
    }

    /// Resolves the message for a failed rule: field per-rule → field-wide
    /// → schema per-rule → app per-rule → `reason` (a custom check's) →
    /// `fallback` (a custom format's or group's own template) → default.
    #[allow(clippy::too_many_arguments)]
    fn resolve(
        &self,
        rule: &str,
        kind: Kind,
        params: &Params,
        field_rule: Option<&Rule>,
        owner: &SchemaDef,
        path: &str,
        fallback: Option<&Template>,
        reason: Option<&str>,
    ) -> String {
        let label = field_rule
            .and_then(|r| r.label.as_deref())
            .map(str::to_string)
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path).to_string());
        let map = params_map(params);
        let render = |t: &Template| t.render(&map, &label, path);
        if let Some(t) = field_rule.and_then(|r| r.messages.get(rule)) {
            return message::sanitize(&render(t));
        }
        if let Some(t) = field_rule.and_then(|r| r.message.as_ref()) {
            return message::sanitize(&render(t));
        }
        if let Some(t) = owner.messages.get(rule) {
            return message::sanitize(&render(t));
        }
        if let Some(app) = self.lua.app_data_ref::<AppMessages>()
            && let Some(t) = app.rules.get(rule)
        {
            return message::sanitize(&render(t));
        }
        if let Some(reason) = reason {
            return message::sanitize(reason);
        }
        if let Some(t) = fallback {
            return message::sanitize(&render(t));
        }
        message::sanitize(&default_message(rule, kind.name(), &map))
    }

    #[allow(clippy::too_many_arguments)]
    fn fail(
        &mut self,
        path: &str,
        field: &str,
        rule: &str,
        kind: Kind,
        params: Params,
        field_rule: Option<&Rule>,
        owner: &SchemaDef,
        fallback: Option<&Template>,
        reason: Option<&str>,
    ) {
        let message = self.resolve(
            rule, kind, &params, field_rule, owner, path, fallback, reason,
        );
        self.errors.push(ErrorEntry {
            path: path.to_string(),
            field: field.to_string(),
            rule: rule.to_string(),
            message,
            params: params
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            label: field_rule.and_then(|r| r.label.clone()),
        });
    }

    /// Validates a table against a field map, building the output table
    /// with only the declared fields — undeclared input never passes
    /// through, so a handler cannot be mass-assigned a field the schema
    /// never mentioned. Returns whether every field passed.
    fn check_fields(
        &mut self,
        schema: &Arc<SchemaDef>,
        input: &Table,
        path: &FieldPath<'_>,
        out: &Table,
    ) -> mlua::Result<bool> {
        let mut ok = true;
        for (name, rule) in &schema.fields {
            let field_path = path.field(name);
            let mut value: Value = input.get(name.as_str())?;
            if value.is_nil()
                && let Some(default) = &rule.default
            {
                value = default.to_lua(self.lua)?;
            }
            if value.is_nil() {
                if rule.required {
                    let p = field_path.render();
                    self.fail(
                        &p,
                        name,
                        "required",
                        rule.kind,
                        Vec::new(),
                        Some(rule),
                        schema,
                        None,
                        None,
                    );
                    ok = false;
                }
                continue;
            }
            let slot = Slot {
                table: out.clone(),
                key: Value::String(self.lua.create_string(name)?),
            };
            match self.check_value(rule, schema, value, &field_path, slot)? {
                Some(value) => out.set(name.as_str(), value)?,
                None => ok = false,
            }
        }
        if self.strict || schema.strict {
            ok &= self.report_unknown(schema, input, path)?;
        }
        if ok {
            ok = self.check_cross(schema, out, path)?;
        }
        if ok && !schema.checks.is_empty() {
            for index in 0..schema.checks.len() {
                self.pending.push(Pending::Schema {
                    table: out.clone(),
                    prefix: path.render(),
                    schema: schema.clone(),
                    index,
                });
            }
        }
        Ok(ok)
    }

    /// `strict`: every undeclared key is an error, bounded in number.
    fn report_unknown(
        &mut self,
        schema: &Arc<SchemaDef>,
        input: &Table,
        path: &FieldPath<'_>,
    ) -> mlua::Result<bool> {
        let mut ok = true;
        let mut listed = 0usize;
        let mut extra = 0usize;
        for pair in input.pairs::<Value, Value>() {
            let (key, _) = pair?;
            let Value::String(key) = key else { continue };
            let key = key.to_string_lossy().to_string();
            if schema.rule(&key).is_some() {
                continue;
            }
            ok = false;
            if listed < MAX_UNKNOWN_LISTED {
                listed += 1;
                let p = path.key(&key).render();
                self.fail(
                    &p,
                    &key,
                    "unknown",
                    Kind::Any,
                    Vec::new(),
                    None,
                    schema,
                    None,
                    None,
                );
            } else {
                extra += 1;
            }
        }
        if extra > 0 {
            self.errors.push(ErrorEntry {
                path: path.render(),
                field: path.field_name().to_string(),
                rule: "unknown".into(),
                message: format!("has {extra} more unknown fields"),
                params: vec![("count".into(), Param::Num(extra as f64))],
                label: None,
            });
        }
        Ok(ok)
    }
}

/// Runs the deferred field-level checks (custom `check`s and custom
/// formats), in arrival order.
async fn run_field_checks(ctx: &mut Ctx<'_>, pending: Vec<Pending>) -> mlua::Result<Vec<Pending>> {
    let mut schema_checks = Vec::new();
    let mut failed: std::collections::HashSet<String> = std::collections::HashSet::new();
    for item in pending {
        let Pending::Field {
            slot,
            path,
            field,
            rule,
            owner,
            value,
            check,
        } = item
        else {
            schema_checks.push(item);
            continue;
        };
        if let PendingCheck::Transform(func) = &check {
            // A transform runs only for a field whose checks all passed.
            if failed.contains(&path) {
                continue;
            }
            let replacement = func.call_async::<Value>(value.clone()).await?;
            if !matches_kind(&replacement, rule.kind) {
                return Err(mlua::Error::RuntimeError(format!(
                    "the transform for `{path}` returned a {}, but the field is a `{}`",
                    replacement.type_name(),
                    rule.kind.name()
                )));
            }
            slot.table.set(slot.key, replacement)?;
            continue;
        }
        let (func, what, rule_name) = match &check {
            PendingCheck::Transform(_) => continue,
            PendingCheck::Custom(f) => (f.clone(), format!("the check for `{path}`"), "check"),
            PendingCheck::Format(c) => (
                c.check.clone(),
                format!("the format `{}` check for `{path}`", c.name),
                "format",
            ),
        };
        let results = func.call_async::<mlua::MultiValue>(value.clone()).await?;
        match verdict(results, &what)? {
            Verdict::Pass => {}
            Verdict::Fail(reason) => {
                failed.insert(path.clone());
                let reason = match reason {
                    None => None,
                    Some(Value::String(s)) => Some(s.to_string_lossy().to_string()),
                    Some(other) => {
                        return Err(mlua::Error::RuntimeError(format!(
                            "{what} returned a reason of type {}; a reason is a string",
                            other.type_name()
                        )));
                    }
                };
                let (params, fallback): (Params, Option<&Template>) = match &check {
                    PendingCheck::Custom(_) | PendingCheck::Transform(_) => (Vec::new(), None),
                    PendingCheck::Format(c) => (
                        vec![("format", Param::Str(format!("a valid {}", c.name)))],
                        c.message.as_ref(),
                    ),
                };
                ctx.fail(
                    &path,
                    &field,
                    rule_name,
                    rule.kind,
                    params,
                    Some(&rule),
                    &owner,
                    fallback,
                    reason.as_deref(),
                );
            }
        }
    }
    Ok(schema_checks)
}

/// Runs the schema-level checks, only reached when nothing else failed.
async fn run_schema_checks(ctx: &mut Ctx<'_>, pending: Vec<Pending>) -> mlua::Result<()> {
    for item in pending {
        let Pending::Schema {
            table,
            prefix,
            schema,
            index,
        } = item
        else {
            continue;
        };
        let check = &schema.checks[index];
        let what = format!("schema check {} (\"{}\")", index + 1, check.description);
        let results = check
            .func
            .call_async::<mlua::MultiValue>(table.clone())
            .await?;
        let Verdict::Fail(reason) = verdict(results, &what)? else {
            continue;
        };
        let root = if prefix == "$" {
            String::new()
        } else {
            prefix.clone()
        };
        match reason {
            None => ctx.fail(
                &prefix,
                "",
                "check",
                Kind::Table,
                Vec::new(),
                None,
                &schema,
                check.message.as_ref(),
                None,
            ),
            Some(Value::String(s)) => {
                let s = s.to_string_lossy().to_string();
                ctx.fail(
                    &prefix,
                    "",
                    "check",
                    Kind::Table,
                    Vec::new(),
                    None,
                    &schema,
                    check.message.as_ref(),
                    Some(&s),
                );
            }
            Some(Value::Table(map)) => {
                for pair in map.pairs::<Value, Value>() {
                    let (key, reason) = pair?;
                    let (Value::String(key), Value::String(reason)) = (key, reason) else {
                        return Err(mlua::Error::RuntimeError(format!(
                            "{what} returned a reason table whose entries are not field = \"reason\""
                        )));
                    };
                    let field = key.to_string_lossy().to_string();
                    let Some(rule) = schema.rule(&field) else {
                        return Err(mlua::Error::RuntimeError(format!(
                            "{what} named `{field}`, which is not a field of the schema"
                        )));
                    };
                    let path = if root.is_empty() {
                        field.clone()
                    } else {
                        format!("{root}.{field}")
                    };
                    let reason = reason.to_string_lossy().to_string();
                    ctx.fail(
                        &path,
                        &field,
                        "check",
                        rule.kind,
                        Vec::new(),
                        Some(rule),
                        &schema,
                        check.message.as_ref(),
                        Some(&reason),
                    );
                }
            }
            Some(other) => {
                return Err(mlua::Error::RuntimeError(format!(
                    "{what} returned a reason of type {}; a reason is a string or a table",
                    other.type_name()
                )));
            }
        }
    }
    Ok(())
}

/// How deep validations may nest through their own script checks. A
/// `check` that calls `schema:check` on the schema it belongs to would
/// otherwise recurse until the Rust stack gives out — Lua's C-stack
/// bound does not fire first across the async boundary — and a stack
/// overflow aborts the process instead of unwinding into a 500.
const MAX_NESTING: u32 = 8;

/// The live nesting depth of validation runs on one Lua state. Runs on a
/// state are strictly nested (one request at a time, an inner
/// `schema:check` awaited by the outer), so one counter is exact.
#[derive(Default)]
struct Nesting(u32);

/// Decrements the depth however the run ends.
struct NestingGuard<'a>(&'a Lua);

impl Drop for NestingGuard<'_> {
    fn drop(&mut self) {
        if let Some(mut n) = self.0.app_data_mut::<Nesting>() {
            n.0 = n.0.saturating_sub(1);
        }
    }
}

fn enter(lua: &Lua) -> mlua::Result<NestingGuard<'_>> {
    if lua.app_data_ref::<Nesting>().is_none() {
        lua.set_app_data(Nesting::default());
    }
    let mut n = lua.app_data_mut::<Nesting>().ok_or_else(|| {
        mlua::Error::RuntimeError("the validation nesting counter is borrowed".into())
    })?;
    if n.0 >= MAX_NESTING {
        return Err(mlua::Error::RuntimeError(format!(
            "validation nested deeper than {MAX_NESTING} levels: does a `check` call \
             `schema:check` on a schema whose own check calls it back?"
        )));
    }
    n.0 += 1;
    Ok(NestingGuard(lua))
}

/// Runs one validation: the sync walk, then the deferred script checks.
pub(super) async fn run(
    lua: &Lua,
    schema: &Arc<SchemaDef>,
    value: Value,
    strict: Option<bool>,
) -> mlua::Result<Result<Table, ValidationError>> {
    let _nesting = enter(lua)?;
    let mut ctx = Ctx {
        lua,
        strict: strict.unwrap_or(false),
        errors: Vec::new(),
        pending: Vec::new(),
        now: None,
    };
    let out = lua.create_table()?;
    match &value {
        Value::Table(input) => {
            ctx.check_fields(schema, input, &FieldPath::ROOT, &out)?;
        }
        other => {
            let p = FieldPath::ROOT.render();
            ctx.fail(
                &p,
                "",
                "body",
                Kind::Table,
                vec![("type", Param::Str(other.type_name().into()))],
                None,
                schema,
                None,
                None,
            );
        }
    }

    // Field-level script checks first (in arrival order), then schema
    // checks — and those only when nothing else failed, so a check can
    // trust the shape it receives.
    let pending = std::mem::take(&mut ctx.pending);
    let schema_checks = run_field_checks(&mut ctx, pending).await?;
    if ctx.errors.is_empty() {
        run_schema_checks(&mut ctx, schema_checks).await?;
    }

    if ctx.errors.is_empty() {
        return Ok(Ok(out));
    }
    let mut entries = std::mem::take(&mut ctx.errors);
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let summary = lua
        .app_data_ref::<AppMessages>()
        .and_then(|app| app.summary.clone())
        .unwrap_or_else(|| "validation failed".into());
    Ok(Err(ValidationError {
        message: summary,
        entries,
    }))
}
