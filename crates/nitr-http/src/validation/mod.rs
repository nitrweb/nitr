// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Route `input` declarations: what a route accepts (`body`, `query`,
//! `params`, `headers`), compiled at load and enforced in Rust before the
//! handler runs. [`run`] is the enforcement; [`spool`], [`multipart`] and
//! [`raw`] handle uploads (behind the `multipart` feature).

use std::sync::Arc;

use hyper::header::{CONTENT_TYPE, HeaderMap};
use mlua::{Lua, Table, UserData, Value};
use nitr_std::validation::{
    CompiledSchema, compile_file_rule, compile_schema, compile_text_schema,
};

#[cfg(feature = "multipart")]
mod multipart;
#[cfg(feature = "multipart")]
mod raw;
pub(crate) mod run;
#[cfg(feature = "multipart")]
pub(crate) mod spool;

/// The media types a body declaration may accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Content {
    /// `application/json` (also a body with no `Content-Type` at all).
    Json,
    /// `application/x-www-form-urlencoded`.
    Form,
    /// `multipart/form-data`.
    Multipart,
    /// Anything: the whole body is one file.
    Raw,
}

impl Content {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "json" => Self::Json,
            "form" => Self::Form,
            "multipart" => Self::Multipart,
            "raw" => Self::Raw,
            _ => None?,
        })
    }

    /// The media type named in a 415.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Form => "application/x-www-form-urlencoded",
            Self::Multipart => "multipart/form-data",
            Self::Raw => "*/*",
        }
    }

    fn accepts(self, media_type: Option<&str>) -> bool {
        match self {
            Self::Json => matches!(media_type, None | Some("application/json")),
            Self::Form => media_type == Some("application/x-www-form-urlencoded"),
            Self::Multipart => media_type == Some("multipart/form-data"),
            Self::Raw => true,
        }
    }
}

/// What the body is validated against.
#[derive(Debug, Clone)]
pub(crate) enum BodyRule {
    /// A schema over the decoded fields (JSON, form, multipart).
    Schema(CompiledSchema),
    /// One `file` rule over the whole body (`"raw"`). Only a build with
    /// the `multipart` feature can reach it (the declaration is refused
    /// at load otherwise), so the schema is read only there.
    File(#[cfg_attr(not(feature = "multipart"), allow(dead_code))] CompiledSchema),
}

/// What the deployment allows, for load-time checks.
#[derive(Debug, Clone, Default)]
pub(crate) struct InputEnv {
    /// `[multipart] upload_dir`: needed by any `file` rule.
    pub(crate) upload_root: Option<std::sync::Arc<std::path::PathBuf>>,
}

/// A route's compiled input declaration.
#[derive(Debug, Clone)]
pub(crate) struct InputSchemas {
    pub(crate) body: Option<(BodyRule, Vec<Content>)>,
    pub(crate) query: Option<CompiledSchema>,
    pub(crate) params: Option<CompiledSchema>,
    pub(crate) headers: Option<CompiledSchema>,
    /// The route-level `strict` override.
    pub(crate) strict: Option<bool>,
}

/// The per-state userdata a compiled chain points at, so the budgeted
/// validation function can reach its schemas from Lua arguments.
pub(crate) struct InputHolder(pub(crate) Arc<InputSchemas>);

impl UserData for InputHolder {}

const INPUT_KEYS: &[&str] = &["body", "query", "params", "headers", "strict"];

fn site_error(site: &str, msg: impl std::fmt::Display) -> mlua::Error {
    mlua::Error::RuntimeError(format!("{site}: {msg}"))
}

/// The parameter names a route pattern captures (`:id` → `id`, a
/// trailing `*rest` → `rest`, a bare `*` → `splat`).
pub(crate) fn param_names(path: &str) -> Vec<String> {
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len().saturating_sub(1);
    segments
        .iter()
        .enumerate()
        .filter_map(|(i, seg)| match *seg {
            "*" if i == last => Some("splat".to_string()),
            s if s.starts_with(':') && s.len() > 1 => Some(s[1..].to_string()),
            s if s.starts_with('*') && s.len() > 1 && i == last => Some(s[1..].to_string()),
            _ => None,
        })
        .collect()
}

fn compile_body(
    lua: &Lua,
    value: Value,
    env: &InputEnv,
    site: &str,
) -> mlua::Result<(BodyRule, Vec<Content>)> {
    let what = format!("{site}: input.body");
    let (schema_value, file_value, content) = match &value {
        // `{ schema = S, content = {...} }` or `{ file = R, content = {...} }`:
        // a table with those keys and no rule `type`.
        Value::Table(t)
            if t.get::<Value>("type")?.is_nil()
                && (!t.get::<Value>("schema")?.is_nil()
                    || !t.get::<Value>("file")?.is_nil()
                    || !t.get::<Value>("content")?.is_nil()) =>
        {
            for pair in t.pairs::<Value, Value>() {
                let (key, _) = pair?;
                let key = match key {
                    Value::String(s) => s.to_string_lossy().to_string(),
                    _ => return Err(site_error(&what, "keys must be strings")),
                };
                if !["schema", "file", "content"].contains(&key.as_str()) {
                    return Err(site_error(
                        &what,
                        format!("unknown key `{key}` (allowed: schema, file, content)"),
                    ));
                }
            }
            let content: Option<Vec<String>> = t.get("content")?;
            (t.get::<Value>("schema")?, t.get::<Value>("file")?, content)
        }
        other => (other.clone(), Value::Nil, None),
    };
    let contents: Vec<Content> = match content {
        None => vec![Content::Json, Content::Form],
        Some(names) => {
            if names.is_empty() {
                return Err(site_error(&what, "`content` must not be empty"));
            }
            let mut out = Vec::new();
            for name in names {
                let content = Content::parse(&name).ok_or_else(|| {
                    site_error(
                        &what,
                        format!("unknown content `{name}` (expected json, form, multipart or raw)"),
                    )
                })?;
                if !out.contains(&content) {
                    out.push(content);
                }
            }
            out
        }
    };
    let rule = match (schema_value, file_value) {
        (Value::Nil, Value::Nil) => {
            return Err(site_error(&what, "needs a `schema` or a `file` rule"));
        }
        (schema, Value::Nil) => BodyRule::Schema(compile_schema(lua, schema, &what)?),
        (Value::Nil, file) => {
            if contents != [Content::Raw] {
                return Err(site_error(
                    &what,
                    "a `file` body needs `content = { \"raw\" }`",
                ));
            }
            BodyRule::File(compile_file_rule(lua, file, &what)?)
        }
        _ => {
            return Err(site_error(
                &what,
                "`schema` and `file` are alternatives; give one",
            ));
        }
    };
    let has_files = match &rule {
        BodyRule::Schema(s) => s.has_file_rules(),
        BodyRule::File(_) => true,
    };
    if matches!(rule, BodyRule::Schema(_)) && contents.contains(&Content::Raw) {
        return Err(site_error(
            &what,
            "`content = { \"raw\" }` takes a `file` rule, not a schema",
        ));
    }
    if has_files
        && !contents
            .iter()
            .any(|c| matches!(c, Content::Multipart | Content::Raw))
    {
        return Err(site_error(
            &what,
            "a `file` rule needs `content = { \"multipart\" }` (or \"raw\"), which is opt-in",
        ));
    }
    let needs_uploads = contents
        .iter()
        .any(|c| matches!(c, Content::Multipart | Content::Raw));
    if needs_uploads {
        if cfg!(not(feature = "multipart")) {
            return Err(site_error(
                &what,
                "multipart and raw bodies need the `multipart` Cargo feature: rebuild with `--features multipart` (or `all`)",
            ));
        }
        if has_files && env.upload_root.is_none() {
            return Err(site_error(
                &what,
                "a `file` rule needs `[multipart] upload_dir`: set it to the directory validated uploads are spooled and saved under",
            ));
        }
    }
    Ok((rule, contents))
}

impl InputSchemas {
    /// Compiles a route's `input = { ... }` table. `site` names the route
    /// and its registration line for errors.
    pub(crate) fn parse(
        lua: &Lua,
        table: &Table,
        route_params: &[String],
        env: &InputEnv,
        site: &str,
    ) -> mlua::Result<Self> {
        for pair in table.pairs::<Value, Value>() {
            let (key, _) = pair?;
            let key = match key {
                Value::String(s) => s.to_string_lossy().to_string(),
                _ => return Err(site_error(site, "input keys must be strings")),
            };
            if !INPUT_KEYS.contains(&key.as_str()) {
                return Err(site_error(
                    site,
                    format!(
                        "unknown input key `{key}` (allowed: {})",
                        INPUT_KEYS.join(", ")
                    ),
                ));
            }
        }
        let body = match table.get::<Value>("body")? {
            Value::Nil => None,
            value => Some(compile_body(lua, value, env, site)?),
        };
        let text_part = |name: &str| -> mlua::Result<Option<CompiledSchema>> {
            match table.get::<Value>(name)? {
                Value::Nil => Ok(None),
                value => Ok(Some(compile_text_schema(
                    lua,
                    value,
                    &format!("{site}: input.{name}"),
                )?)),
            }
        };
        let query = text_part("query")?;
        let params = text_part("params")?;
        let headers = text_part("headers")?;
        if let Some(params) = &params {
            for name in params.field_names() {
                if !route_params.iter().any(|p| p == name) {
                    return Err(site_error(
                        site,
                        format!(
                            "input.params names `{name}`, which the route pattern does not capture (captured: {})",
                            if route_params.is_empty() {
                                "none".to_string()
                            } else {
                                route_params.join(", ")
                            }
                        ),
                    ));
                }
            }
        }
        if let Some(headers) = &headers {
            for name in headers.field_names() {
                if name != name.to_ascii_lowercase() {
                    return Err(site_error(
                        site,
                        format!(
                            "input.headers names `{name}`: header names are lowercase (`{}`)",
                            name.to_ascii_lowercase()
                        ),
                    ));
                }
            }
        }
        let strict = match table.get::<Value>("strict")? {
            Value::Nil => None,
            Value::Boolean(b) => Some(b),
            other => {
                return Err(site_error(
                    site,
                    format!(
                        "input.strict must be true or false, got {}",
                        other.type_name()
                    ),
                ));
            }
        };
        Ok(Self {
            body,
            query,
            params,
            headers,
            strict,
        })
    }

    /// Which body media type the request carries, or the list a 415 names.
    pub(crate) fn negotiate(&self, headers: &HeaderMap) -> Result<Option<Content>, String> {
        let Some((_, contents)) = &self.body else {
            return Ok(None);
        };
        let media_type = headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                s.split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
            });
        for content in contents {
            if content.accepts(media_type.as_deref()) {
                return Ok(Some(*content));
            }
        }
        Err(contents
            .iter()
            .map(|c| c.label())
            .collect::<Vec<_>>()
            .join(", "))
    }

    /// Whether any part declares a `file` rule.
    pub(crate) fn has_file_rules(&self) -> bool {
        matches!(&self.body, Some((BodyRule::File(_), _)))
            || matches!(&self.body, Some((BodyRule::Schema(s), _)) if s.has_file_rules())
    }

    /// Whether this request may spool uploads (multipart or raw bodies).
    #[cfg_attr(not(feature = "multipart"), allow(dead_code))]
    pub(crate) fn needs_spool(&self, content: Option<Content>) -> bool {
        matches!(content, Some(Content::Multipart | Content::Raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_patterns_yield_their_parameter_names() {
        assert_eq!(param_names("/users/:id/posts/:post"), vec!["id", "post"]);
        assert_eq!(param_names("/files/*"), vec!["splat"]);
        assert_eq!(param_names("/files/*rest"), vec!["rest"]);
        assert!(param_names("/").is_empty());
    }

    #[test]
    fn content_negotiation_ignores_parameters_and_names_the_accepted_types() {
        let lua = Lua::new();
        let fields: Table = lua.load(r#"{ a = "string" }"#).eval().unwrap();
        let input = lua.create_table().unwrap();
        input.set("body", fields).unwrap();
        let schemas =
            InputSchemas::parse(&lua, &input, &[], &InputEnv::default(), "route").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "application/json; charset=utf-8".parse().unwrap(),
        );
        assert_eq!(schemas.negotiate(&headers).unwrap(), Some(Content::Json));
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());
        assert_eq!(
            schemas.negotiate(&headers).unwrap_err(),
            "application/json, application/x-www-form-urlencoded"
        );
        assert_eq!(
            schemas.negotiate(&HeaderMap::new()).unwrap(),
            Some(Content::Json)
        );
    }

    #[test]
    fn input_declarations_are_checked_at_load() {
        let lua = Lua::new();
        let parse = |def: &str, params: &[&str]| -> Result<InputSchemas, String> {
            let table: Table = lua.load(def).eval().unwrap();
            let params: Vec<String> = params.iter().map(|p| (*p).to_string()).collect();
            InputSchemas::parse(
                &lua,
                &table,
                &params,
                &InputEnv::default(),
                "POST /x (app.lua:1)",
            )
            .map_err(|e| e.to_string())
        };
        assert!(parse(r#"{ params = { id = "integer" } }"#, &["id"]).is_ok());
        for (def, needle) in [
            (r#"{ params = { id = "integer" } }"#, "does not capture"),
            (
                r#"{ headers = { ["X-Team"] = "string" } }"#,
                "header names are lowercase",
            ),
            (
                r#"{ bodyy = { a = "string" } }"#,
                "unknown input key `bodyy`",
            ),
            (
                r#"{ body = { schema = { a = "string" }, content = { "xml" } } }"#,
                "unknown content `xml`",
            ),
            (
                r#"{ body = { schema = { a = "string" }, content = { "raw" } } }"#,
                "takes a `file` rule",
            ),
            (
                r#"{ body = { content = { "json" } } }"#,
                "needs a `schema` or a `file`",
            ),
            (
                r#"{ body = { schema = { f = { type = "file", max_bytes = 1 } } } }"#,
                "needs `content = { \"multipart\" }`",
            ),
            (
                r#"{ query = { a = { type = "any", max_bytes = 1 } } }"#,
                "text input cannot carry",
            ),
            (r#"{ strict = "yes" }"#, "must be true or false"),
        ] {
            let err = parse(def, &[]).expect_err(def);
            assert!(err.contains(needle), "{def}: {err}");
        }
    }
}
