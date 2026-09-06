// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Tests of the validation engine through its Lua surface, one file per
//! concern: [`schema`] compilation, [`rules`] the declarative vocabulary,
//! [`messages`] the message model, [`custom`] script-side checks,
//! [`compose`] derivations, [`text`] coercion and the error shape,
//! [`presets`] the file presets.

use mlua::ObjectLike as _;

use super::*;

mod compose;
mod custom;
mod messages;
mod presets;
mod rules;
mod schema;
mod text;

/// Mounts `nitr.validate` in a fresh state and returns it.
pub(super) fn validate(lua: &Lua) -> Table {
    let validate = create_validate_table(lua).expect("table");
    let nitr = lua.create_table().expect("nitr");
    nitr.set("validate", validate.clone()).expect("mount");
    lua.globals().set("nitr", nitr).expect("global");
    validate
}

/// Compiles a schema from a Lua field-table literal.
pub(super) fn schema(lua: &Lua, def: &str) -> mlua::AnyUserData {
    let validate = validate(lua);
    let fields: Table = lua.load(def).eval().expect("schema table");
    validate
        .get::<mlua::Function>("schema")
        .expect("fn")
        .call(fields)
        .expect("compile")
}

/// Compiles a schema with options.
pub(super) fn schema_with(lua: &Lua, def: &str, opts: &str) -> mlua::AnyUserData {
    let validate = validate(lua);
    let fields: Table = lua.load(def).eval().expect("schema table");
    let opts: Table = lua.load(opts).eval().expect("opts table");
    validate
        .get::<mlua::Function>("schema")
        .expect("fn")
        .call((fields, opts))
        .expect("compile")
}

/// `schema:check(<lua literal>)`.
pub(super) async fn check(lua: &Lua, schema: &mlua::AnyUserData, input: &str) -> (Value, Value) {
    let value: Value = lua.load(input).eval().expect("input");
    let f: mlua::Function = schema.get("check").expect("method");
    f.call_async((schema, value)).await.expect("check")
}

pub(super) fn fields_of(err: &Value) -> Table {
    let Value::Table(err) = err else {
        panic!("expected error table, got {err:?}");
    };
    err.get("fields").expect("fields")
}

/// The message recorded for a path, or a panic naming what was recorded.
pub(super) fn field(err: &Value, path: &str) -> String {
    fields_of(err)
        .get::<Option<String>>(path)
        .expect("get")
        .unwrap_or_else(|| panic!("no error for `{path}`: {err:?}"))
}

pub(super) fn data_table(data: Value) -> Table {
    let Value::Table(data) = data else {
        panic!("expected data table, got {data:?}");
    };
    data
}
