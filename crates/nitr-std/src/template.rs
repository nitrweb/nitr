// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use std::path::Path;
use std::sync::Arc;

use minijinja::{Environment, path_loader};
use mlua::{AnyUserData, ExternalResult, Lua, LuaSerdeExt, Table, UserData, UserDataMethods};

pub(crate) struct LuaTemplate<'a>(Arc<Environment<'a>>);

impl UserData for LuaTemplate<'_> {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method_mut("render", |lua, templ, args: (String, Option<Table>)| {
            let file_path = args.0;
            let data = args.1;
            let templ_store = templ.0.clone();
            let templ = templ_store
                .get_template(file_path.as_str())
                .into_lua_err()?;
            let content = templ.render(data).into_lua_err()?;
            lua.to_value(&content)
        });
    }
}

/// Templating function support.
pub(crate) fn create_template_fn(lua: &Lua, dir: &Path) -> mlua::Result<AnyUserData> {
    let mut env = Environment::new();
    env.set_loader(path_loader(dir));

    let env = Arc::new(env);
    lua.create_userdata(LuaTemplate(env))
}
