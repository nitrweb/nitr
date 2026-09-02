// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use std::path::Path;
use std::sync::Arc;

use minijinja::{Environment, path_loader};
use mlua::{
    AnyUserData, ExternalResult, Lua, LuaSerdeExt, Table, UserData, UserDataMethods, Value,
};

pub(crate) struct LuaTemplate<'a>(Arc<Environment<'a>>);

impl UserData for LuaTemplate<'_> {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method_mut("render", |lua, templ, args: (String, Option<Table>)| {
            let file_path = args.0;
            let data = args.1;
            // The context crosses into minijinja's `Serialize` bridge,
            // which recurses per nesting level exactly as serde_json does
            // and has no bound of its own — so this is the same guard
            // every other serializing builtin runs, for the same reason:
            // a deep enough table overflows the Rust stack, and an abort
            // is not something the per-request `catch_unwind` can catch.
            if let Some(data) = &data {
                crate::utils::check_json_bounds(&Value::Table(data.clone()))?;
            }
            let templ_store = templ.0.clone();
            let templ = templ_store
                .get_template(file_path.as_str())
                .into_lua_err()?;
            let content = templ.render(data).into_lua_err()?;
            lua.to_value(&content)
        });
    }
}

/// Whether a template name renders with HTML auto-escaping.
///
/// minijinja's default escapes only `.html`/`.htm`/`.xml` (after stripping
/// a trailing `.j2`), so `hello.j2` — the shape the scaffold and every
/// example teach — rendered `{{ name }}` verbatim: the first request field
/// or database row that reached a template was reflected or stored XSS.
/// The default here is the other way round: everything escapes unless
/// the name says plain text.
fn auto_escape_for(name: &str) -> minijinja::AutoEscape {
    let stem = name
        .strip_suffix(".j2")
        .or_else(|| name.strip_suffix(".jinja"))
        .or_else(|| name.strip_suffix(".jinja2"))
        .unwrap_or(name);
    let plain = [
        ".txt", ".text", ".md", ".csv", ".json", ".yaml", ".yml", ".toml",
    ];
    if plain.iter().any(|ext| stem.ends_with(ext)) {
        minijinja::AutoEscape::None
    } else {
        minijinja::AutoEscape::Html
    }
}

/// Templating function support.
pub(crate) fn create_template_fn(lua: &Lua, dir: &Path) -> mlua::Result<AnyUserData> {
    let mut env = Environment::new();
    env.set_loader(path_loader(dir));
    env.set_auto_escape_callback(auto_escape_for);

    let env = Arc::new(env);
    lua.create_userdata(LuaTemplate(env))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{MAX_JSON_DEPTH, deep_table};

    /// Builds a `LuaTemplate` over one in-memory template, with no
    /// filesystem loader — the bound under test is on the *context*, not
    /// on template lookup.
    fn template_userdata(lua: &Lua) -> AnyUserData {
        let mut env = Environment::new();
        env.add_template("t.html", "{{ x }}")
            .expect("add the test template");
        lua.create_userdata(LuaTemplate(Arc::new(env)))
            .expect("template userdata")
    }

    /// `render` must enforce the same boundary as every other serializing
    /// builtin: 128 levels through, 129 refused with a catchable error
    /// rather than an abort inside minijinja's serializer.
    #[test]
    fn render_bounds_its_context_at_the_shared_depth() {
        use mlua::ObjectLike as _;

        let lua = Lua::new();
        let templ = template_userdata(&lua);

        let Value::Table(ok) = deep_table(&lua, MAX_JSON_DEPTH) else {
            panic!("deep_table returns a table");
        };
        templ
            .call_method::<String>("render", ("t.html", ok))
            .expect("a context at the bound still renders");

        let Value::Table(too_deep) = deep_table(&lua, MAX_JSON_DEPTH + 1) else {
            panic!("deep_table returns a table");
        };
        let err = templ
            .call_method::<String>("render", ("t.html", too_deep))
            .expect_err("a context past the bound must be refused");
        assert!(
            err.to_string().contains("nested deeper than 128 levels"),
            "got: {err}"
        );
    }

    /// HTML escaping is the default for any name that is not plain text,
    /// `.j2`-suffixed or not.
    #[test]
    fn templates_escape_html_unless_named_as_plain_text() {
        use mlua::ObjectLike as _;

        let lua = Lua::new();
        let mut env = Environment::new();
        env.set_auto_escape_callback(auto_escape_for);
        for name in ["page.j2", "page.html", "page", "mail.html.j2"] {
            env.add_template(name, "{{ x }}").expect("add");
        }
        env.add_template("mail.txt.j2", "{{ x }}").expect("add");
        env.add_template("data.json", "{{ x }}").expect("add");
        let templ = lua
            .create_userdata(LuaTemplate(Arc::new(env)))
            .expect("userdata");
        let ctx = lua.create_table().expect("table");
        ctx.set("x", "<b>&</b>").expect("set");

        for name in ["page.j2", "page.html", "page", "mail.html.j2"] {
            let out: String = templ.call_method("render", (name, &ctx)).expect("render");
            assert_eq!(out, "&lt;b&gt;&amp;&lt;&#x2f;b&gt;", "{name} must escape");
        }
        for name in ["mail.txt.j2", "data.json"] {
            let out: String = templ.call_method("render", (name, &ctx)).expect("render");
            assert_eq!(out, "<b>&</b>", "{name} is plain text");
        }
    }

    /// The node budget reaches `render` too: a shared-subtree context is
    /// shallow, so only the work bound can refuse it.
    #[test]
    fn render_bounds_its_context_by_node_count() {
        use mlua::ObjectLike as _;

        let lua = Lua::new();
        let templ = template_userdata(&lua);
        let Value::Table(dag) = crate::utils::dag_table(&lua, 21) else {
            panic!("dag_table returns a table");
        };
        let err = templ
            .call_method::<String>("render", ("t.html", dag))
            .expect_err("a DAG context must be refused");
        assert!(
            err.to_string().contains("expands to more than"),
            "got: {err}"
        );
    }
}
