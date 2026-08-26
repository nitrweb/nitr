// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `nitr` namespace table: the single place where every Nitr API is
//! exposed to Lua. Builtins, the application object, and the configuration
//! snapshot mount as fields of the global `nitr` table; user-defined Rust
//! extension modules mount one level down, under `nitr.ext.*`, so the
//! standard library and user code can never collide. There are no other
//! Nitr-provided globals.

use mlua::{IntoLua, Lua, Table, Value};

use crate::error::{Error, Result};

/// Returns the global `nitr` namespace table, creating it on first use.
///
/// Every crate that exposes an API to Lua mounts it here, so the table is
/// shared: callers must only add their own fields.
pub fn nitr_table(lua: &Lua) -> Result<Table> {
    let globals = lua.globals();
    match globals.get::<Value>("nitr")? {
        Value::Table(t) => Ok(t),
        Value::Nil => {
            let t = lua.create_table()?;
            globals.set("nitr", &t)?;
            Ok(t)
        }
        other => Err(Error::Script(format!(
            "the global `nitr` must be the namespace table, found {}",
            other.type_name()
        ))),
    }
}

/// The reserved subtable user-defined modules mount under.
///
/// Extensions live in `nitr.ext.*`, one level below the standard library,
/// so the std surface can grow without ever colliding with a user module
/// — and a script can tell at the call site whether `nitr.time` is Nitr's
/// or `nitr.ext.time` is the application's.
pub const EXT_TABLE: &str = "ext";

/// Returns `nitr.ext`, creating it on first use.
pub fn ext_table(lua: &Lua) -> Result<Table> {
    let nitr = nitr_table(lua)?;
    match nitr.get::<Value>(EXT_TABLE)? {
        Value::Table(t) => Ok(t),
        Value::Nil => {
            let t = lua.create_table()?;
            nitr.set(EXT_TABLE, &t)?;
            Ok(t)
        }
        other => Err(Error::Script(format!(
            "`nitr.{EXT_TABLE}` must be the extension table, found {}",
            other.type_name()
        ))),
    }
}

/// Mounts a value under `nitr.ext.<name>`, failing when the name is
/// already taken so extensions cannot silently shadow each other.
pub fn mount(lua: &Lua, name: &str, value: impl IntoLua) -> Result {
    let ext = ext_table(lua)?;
    if ext.get::<Value>(name)? != Value::Nil {
        return Err(Error::Script(format!(
            "cannot register the module `{name}`: `nitr.{EXT_TABLE}.{name}` already exists"
        )));
    }
    ext.set(name, value)?;
    Ok(())
}

/// A Rust extension module: runs once per Lua state and returns the value
/// mounted at `nitr.ext.<name>` (a table, by Lua module convention).
pub type ModuleFn = dyn Fn(&Lua) -> mlua::Result<Table> + Send + Sync;
