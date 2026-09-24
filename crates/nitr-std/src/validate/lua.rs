// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The Lua surface: the `nitr.validate` table and the compiled-schema
//! userdata with its `check` and derivations.

use std::collections::BTreeMap;
use std::sync::Arc;

use mlua::{Lua, Table, UserData, UserDataMethods, Value};

use super::message::{self, AppMessages};
use super::{Rule, SchemaDef, compile, engine, format, media, presets, shorthand};

/// The compiled schema as a Lua value: `schema:check(value)` and the
/// derivations.
pub(crate) struct LuaSchema(pub(super) Arc<SchemaDef>);

impl LuaSchema {
    /// A derived schema with the fields replaced.
    fn derive(&self, fields: Vec<(String, Arc<Rule>)>) -> mlua::Result<Self> {
        let mut def = (*self.0).clone();
        def.fields = fields;
        compile::check_groups(&def, "a derived schema")?;
        Ok(Self(Arc::new(def)))
    }
}

impl UserData for LuaSchema {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // schema:check(value) -> data, nil | nil, { message, fields, errors }
        //
        // `data` contains only the declared fields; `fields` maps each
        // failing field path (`email`, `address.city`, `tags[2]`) to its
        // message, ready to serialize into a 422 body; `errors` is the
        // same list with rule codes and parameters.
        methods.add_async_method("check", |lua, this, value: Value| async move {
            match engine::run(&lua, &this.0, value, None).await? {
                Ok(data) => Ok((Value::Table(data), Value::Nil)),
                Err(err) => Ok((Value::Nil, Value::Table(err.to_lua(&lua)?))),
            }
        });

        // schema:partial() — every top-level field optional, and none
        // defaulted: a PATCH body omits what it leaves as stored.
        methods.add_method("partial", |_, this, ()| {
            let fields = this
                .0
                .fields
                .iter()
                .map(|(name, rule)| {
                    let mut rule = (**rule).clone();
                    rule.required = false;
                    rule.default = None;
                    (name.clone(), Arc::new(rule))
                })
                .collect();
            this.derive(fields)
        });

        // schema:pick({ "a", "b" }) / schema:omit({ "c" })
        for (name, keep) in [("pick", true), ("omit", false)] {
            methods.add_method(name, move |_, this, names: Vec<String>| {
                for wanted in &names {
                    if this.0.rule(wanted).is_none() {
                        return Err(mlua::Error::RuntimeError(format!(
                            "schema:{name}(): unknown field `{wanted}`"
                        )));
                    }
                }
                let fields = this
                    .0
                    .fields
                    .iter()
                    .filter(|(n, _)| names.contains(n) == keep)
                    .cloned()
                    .collect();
                this.derive(fields)
            });
        }

        // schema:extend({ field = rule, ... }) — adds or replaces fields; a
        // `false` removes one (Lua tables cannot carry nil values).
        methods.add_method("extend", |lua, this, extra: Table| {
            let mut fields = this.0.fields.clone();
            for pair in extra.pairs::<Value, Value>() {
                let (key, value) = pair?;
                let Value::String(key) = key else {
                    return Err(mlua::Error::RuntimeError(
                        "schema:extend(): field names must be strings".into(),
                    ));
                };
                let name = key.to_string_lossy().to_string();
                fields.retain(|(n, _)| *n != name);
                if matches!(value, Value::Boolean(false)) {
                    continue;
                }
                let rule = compile::compile_rule_value(lua, value, &name, 0)?;
                fields.push((name, Arc::new(rule)));
            }
            fields.sort_by(|a, b| a.0.cmp(&b.0));
            this.derive(fields)
        });

        // schema:with({ title = ..., strict = ..., messages = ... })
        methods.add_method("with", |lua, this, opts: Table| {
            let mut def = (*this.0).clone();
            compile::apply_options(lua, &mut def, &opts, "schema:with()")?;
            Ok(LuaSchema(Arc::new(def)))
        });

        // schema:fields() — the declared field names, sorted.
        methods.add_method("fields", |lua, this, ()| {
            let names: Vec<&str> = this.0.fields.iter().map(|(n, _)| n.as_str()).collect();
            lua.create_sequence_from(names)
        });
    }
}

/// `nitr.validate.messages({ rule = "template", summary = "..." })`.
fn set_messages(lua: &Lua, table: Table) -> mlua::Result<()> {
    let frozen = lua
        .app_data_ref::<AppMessages>()
        .is_some_and(|app| app.frozen);
    if frozen {
        return Err(mlua::Error::RuntimeError(
            "nitr.validate.messages() must be called at load, before the \
             application is compiled — never from a handler"
                .into(),
        ));
    }
    let mut rules = message::compile_messages(&table, "nitr.validate.messages")?;
    let summary = rules
        .remove("summary")
        .map(|t| t.render(&BTreeMap::new(), "", ""));
    let mut app = lua.app_data_mut::<AppMessages>().unwrap_or_else(|| {
        lua.set_app_data(AppMessages::default());
        // Invariant: just set.
        #[allow(clippy::expect_used)]
        lua.app_data_mut::<AppMessages>()
            .expect("app messages just set")
    });
    app.rules.extend(rules);
    if summary.is_some() {
        app.summary = summary;
    }
    Ok(())
}

/// Builds the `nitr.validate` table.
pub(crate) fn create_validate_table(lua: &Lua) -> mlua::Result<Table> {
    let validate = lua.create_table()?;

    // nitr.validate.schema(fields, opts?) -> Schema
    validate.set(
        "schema",
        lua.create_function(|lua, (fields, opts): (Table, Option<Table>)| {
            let def = compile::compile_schema(lua, &fields, opts.as_ref(), "the schema")?;
            Ok(LuaSchema(Arc::new(def)))
        })?,
    )?;

    // nitr.validate.format(name, { description, check, message?, pattern?, example? })
    validate.set(
        "format",
        lua.create_function(|lua, (name, spec): (String, Table)| {
            compile::register_format(lua, &name, &spec)
        })?,
    )?;

    // nitr.validate.formats() -> { "alpha", ... } (built in and custom)
    validate.set(
        "formats",
        lua.create_function(|lua, ()| lua.create_sequence_from(format::all_format_names(lua)))?,
    )?;

    // nitr.validate.messages({ rule = "template", summary = "..." })
    validate.set(
        "messages",
        lua.create_function(|lua, table: Table| set_messages(lua, table))?,
    )?;

    // nitr.validate.expand("string|min_len:1") -> the table form
    validate.set(
        "expand",
        lua.create_function(|lua, shorthand: String| shorthand::expand(lua, &shorthand))?,
    )?;

    // nitr.validate.media_types() -> { ["image/png"] = { extensions, family, tier }, ... }
    validate.set(
        "media_types",
        lua.create_function(|lua, ()| media::media_types_table(lua))?,
    )?;

    presets::register(lua, &validate)?;
    Ok(validate)
}
