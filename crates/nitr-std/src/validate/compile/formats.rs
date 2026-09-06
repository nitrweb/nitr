// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr.validate.format(name, {...})`: registering a script-defined
//! format in the state's registry, before the schemas that use it.

use std::sync::Arc;

use mlua::{Lua, Table, Value};

use super::getters::get_string;
use crate::validate::format::{CustomFormat, Format, FormatRegistry};
use crate::validate::message::{Template, rule_params};

const SPEC_KEYS: &[&str] = &["description", "check", "message", "pattern", "example"];

pub(crate) fn register_format(lua: &Lua, name: &str, spec: &Table) -> mlua::Result<()> {
    let what = format!("nitr.validate.format(\"{name}\")");
    let fail = |msg: &str| mlua::Error::RuntimeError(format!("{what}: {msg}"));
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(fail(
            "a format name is lowercase letters, digits and underscores",
        ));
    }
    if Format::parse(name).is_some() {
        return Err(fail(&format!(
            "`{name}` is a built-in format and cannot be replaced"
        )));
    }
    for pair in spec.pairs::<Value, Value>() {
        let (key, _) = pair?;
        let key = match key {
            Value::String(s) => s.to_string_lossy().to_string(),
            _ => return Err(fail("keys must be strings")),
        };
        if !SPEC_KEYS.contains(&key.as_str()) {
            return Err(fail(&format!("unknown key `{key}`")));
        }
    }
    let description = get_string(spec, "description", &what)?
        .ok_or_else(|| fail("a custom format needs a `description`"))?;
    let check: mlua::Function = spec
        .get::<Option<mlua::Function>>("check")?
        .ok_or_else(|| fail("a custom format needs a `check` function"))?;
    let message = match get_string(spec, "message", &what)? {
        Some(text) => Some(Template::compile(&text, rule_params("format"), &what)?),
        None => None,
    };
    let format = Arc::new(CustomFormat {
        name: name.to_string(),
        description,
        message,
        check,
        pattern: get_string(spec, "pattern", &what)?,
        example: get_string(spec, "example", &what)?,
    });
    let mut registry = lua.app_data_mut::<FormatRegistry>().unwrap_or_else(|| {
        lua.set_app_data(FormatRegistry::default());
        // Invariant: just set.
        #[allow(clippy::expect_used)]
        lua.app_data_mut::<FormatRegistry>()
            .expect("registry just set")
    });
    if registry.formats.contains_key(name) {
        return Err(fail("the format is already registered"));
    }
    registry.formats.insert(name.to_string(), format);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_validates_the_spec() {
        let lua = Lua::new();
        let spec = |def: &str| -> Table { lua.load(def).eval().unwrap() };
        let good = r#"{ description = "x", check = function() return true end }"#;
        register_format(&lua, "plate", &spec(good)).unwrap();
        for (name, def, needle) in [
            ("plate", good, "already registered"),
            ("email", good, "built-in format"),
            ("Bad-Name", good, "lowercase letters"),
            (
                "nodesc",
                r#"{ check = function() end }"#,
                "needs a `description`",
            ),
            ("nocheck", r#"{ description = "x" }"#, "needs a `check`"),
            (
                "extra",
                r#"{ description = "x", check = function() end, regex = "x" }"#,
                "unknown key `regex`",
            ),
            (
                "badmsg",
                r#"{ description = "x", check = function() end, message = "{value}" }"#,
                "unknown placeholder",
            ),
        ] {
            let err = register_format(&lua, name, &spec(def))
                .expect_err(name)
                .to_string();
            assert!(err.contains(needle), "{name}: {err}");
        }
    }
}
