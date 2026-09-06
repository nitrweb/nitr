// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `doc` tables: `app:doc({...})` for the document and `{ doc = {...}
//! }` on a route. Parsed with a closed key set so a typo is a load-time
//! error naming the route and its registration site, never a silently
//! undocumented operation.
//!
//! `doc` describes; it never validates. A request schema under `doc`
//! (`body`, `query`, `params`, `headers`) is refused with a pointer at
//! `input`, so the document can never claim an enforcement the server
//! does not perform.

use std::collections::BTreeMap;

use mlua::{Lua, Table, Value};
use serde_json::Value as Json;

use nitr_std::validation::{DocSchema, compile_doc_schema};

const API_KEYS: &[&str] = &[
    "title",
    "version",
    "description",
    "terms_of_service",
    "contact",
    "license",
    "tags",
    "security",
    "external_docs",
];

const ROUTE_KEYS: &[&str] = &[
    "summary",
    "description",
    "tags",
    "operation_id",
    "responses",
    "security",
    "deprecated",
    "hidden",
];

/// The keys that belong to `input`, named in the error a `doc` carrying
/// one gets.
const INPUT_KEYS: &[&str] = &["body", "query", "params", "headers"];

const RESPONSE_KEYS: &[&str] = &["description", "schema", "content"];

/// Longest prose the document accepts in one field; the whole document
/// is bounded separately, this keeps one description from being it.
const MAX_TEXT: usize = 64 * 1024;

fn err(site: &str, msg: impl std::fmt::Display) -> mlua::Error {
    mlua::Error::RuntimeError(format!("{site}: {msg}"))
}

/// Refuses unknown keys, naming the allowed ones.
fn check_keys(table: &Table, allowed: &[&str], site: &str, what: &str) -> mlua::Result<()> {
    for pair in table.pairs::<Value, Value>() {
        let (key, _) = pair?;
        let Value::String(key) = key else {
            return Err(err(site, format!("{what} keys must be strings")));
        };
        let key = key.to_string_lossy();
        if INPUT_KEYS.contains(&key.as_ref()) && what == "doc" {
            return Err(err(
                site,
                format!(
                    "doc.{key} is not a documentation key: request schemas are declared \
                     under `input`, which both enforces and documents them"
                ),
            ));
        }
        if !allowed.contains(&key.as_ref()) {
            return Err(err(
                site,
                format!(
                    "unknown {what} key `{key}` (allowed: {})",
                    allowed.join(", ")
                ),
            ));
        }
    }
    Ok(())
}

fn text(table: &Table, key: &str, site: &str, what: &str) -> mlua::Result<Option<String>> {
    match table.get::<Value>(key)? {
        Value::Nil => Ok(None),
        Value::String(s) => {
            let s = s.to_str()?;
            if s.len() > MAX_TEXT {
                return Err(err(
                    site,
                    format!("{what}.{key} is longer than {MAX_TEXT} bytes"),
                ));
            }
            Ok(Some(s.to_string()))
        }
        other => Err(err(
            site,
            format!("{what}.{key} must be a string, got {}", other.type_name()),
        )),
    }
}

fn boolean(table: &Table, key: &str, site: &str, what: &str) -> mlua::Result<bool> {
    match table.get::<Value>(key)? {
        Value::Nil => Ok(false),
        Value::Boolean(b) => Ok(b),
        other => Err(err(
            site,
            format!(
                "{what}.{key} must be true or false, got {}",
                other.type_name()
            ),
        )),
    }
}

fn strings(table: &Table, key: &str, site: &str, what: &str) -> mlua::Result<Option<Vec<String>>> {
    match table.get::<Value>(key)? {
        Value::Nil => Ok(None),
        Value::Table(list) => {
            let mut out = Vec::new();
            for item in list.sequence_values::<Value>() {
                match item? {
                    Value::String(s) => out.push(s.to_str()?.to_string()),
                    other => {
                        return Err(err(
                            site,
                            format!(
                                "{what}.{key} must be a list of strings, got a {}",
                                other.type_name()
                            ),
                        ));
                    }
                }
            }
            Ok(Some(out))
        }
        other => Err(err(
            site,
            format!("{what}.{key} must be a list, got {}", other.type_name()),
        )),
    }
}

/// A free-form table (`contact`, `license`, a security scheme) carried
/// into the document as JSON.
fn object(table: &Table, key: &str, site: &str, what: &str) -> mlua::Result<Option<Json>> {
    match table.get::<Value>(key)? {
        Value::Nil => Ok(None),
        value @ Value::Table(_) => Ok(Some(to_json(&value, site, &format!("{what}.{key}"))?)),
        other => Err(err(
            site,
            format!("{what}.{key} must be a table, got {}", other.type_name()),
        )),
    }
}

fn to_json(value: &Value, site: &str, what: &str) -> mlua::Result<Json> {
    serde_json::to_value(value).map_err(|e| err(site, format!("{what} is not plain data: {e}")))
}

/// One tag of `app:doc`.
#[derive(Debug, Clone)]
// Parsed in every build for the load-time checks; read only by the
// generator, which the feature gates.
#[cfg_attr(not(feature = "openapi"), allow(dead_code))]
pub(crate) struct TagDoc {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
}

/// What `app:doc({...})` declared about the document as a whole.
#[derive(Debug, Clone)]
// Parsed in every build; read only by the feature-gated generator.
#[cfg_attr(not(feature = "openapi"), allow(dead_code))]
pub(crate) struct ApiDoc {
    pub(crate) title: String,
    pub(crate) version: String,
    pub(crate) description: Option<String>,
    pub(crate) terms_of_service: Option<String>,
    pub(crate) contact: Option<Json>,
    pub(crate) license: Option<Json>,
    pub(crate) tags: Vec<TagDoc>,
    /// Security schemes by name, as plain data.
    pub(crate) security: BTreeMap<String, Json>,
    pub(crate) external_docs: Option<Json>,
}

impl ApiDoc {
    /// Parses the `app:doc` table. `site` names the call for errors.
    pub(crate) fn parse(table: &Table, site: &str) -> mlua::Result<Self> {
        check_keys(table, API_KEYS, site, "app:doc")?;
        let what = "app:doc";
        let title = text(table, "title", site, what)?.unwrap_or_else(|| "API".into());
        let version = text(table, "version", site, what)?.unwrap_or_else(|| "0.0.0".into());
        let mut tags = Vec::new();
        match table.get::<Value>("tags")? {
            Value::Nil => {}
            Value::Table(list) => {
                for item in list.sequence_values::<Value>() {
                    let Value::Table(tag) = item? else {
                        return Err(err(
                            site,
                            "app:doc.tags must be a list of `{ name, description }` tables",
                        ));
                    };
                    check_keys(&tag, &["name", "description"], site, "app:doc.tags[]")?;
                    let Some(name) = text(&tag, "name", site, "app:doc.tags[]")? else {
                        return Err(err(site, "app:doc.tags[] needs a `name`"));
                    };
                    let description = text(&tag, "description", site, "app:doc.tags[]")?;
                    tags.push(TagDoc { name, description });
                }
            }
            other => {
                return Err(err(
                    site,
                    format!("app:doc.tags must be a list, got {}", other.type_name()),
                ));
            }
        }
        let mut security = BTreeMap::new();
        match table.get::<Value>("security")? {
            Value::Nil => {}
            Value::Table(schemes) => {
                for pair in schemes.pairs::<Value, Value>() {
                    let (name, scheme) = pair?;
                    let Value::String(name) = name else {
                        return Err(err(site, "app:doc.security keys are scheme names"));
                    };
                    let name = name.to_str()?.to_string();
                    let Value::Table(_) = scheme else {
                        return Err(err(
                            site,
                            format!(
                                "app:doc.security.{name} must be a table describing the scheme"
                            ),
                        ));
                    };
                    let json = to_json(&scheme, site, &format!("app:doc.security.{name}"))?;
                    if json.get("type").and_then(Json::as_str).is_none() {
                        return Err(err(
                            site,
                            format!(
                                "app:doc.security.{name} needs a `type` (http, apiKey, oauth2, openIdConnect)"
                            ),
                        ));
                    }
                    security.insert(name, json);
                }
            }
            other => {
                return Err(err(
                    site,
                    format!(
                        "app:doc.security must be a table, got {}",
                        other.type_name()
                    ),
                ));
            }
        }
        Ok(Self {
            title,
            version,
            description: text(table, "description", site, what)?,
            terms_of_service: text(table, "terms_of_service", site, what)?,
            contact: object(table, "contact", site, what)?,
            license: object(table, "license", site, what)?,
            tags,
            security,
            external_docs: object(table, "external_docs", site, what)?,
        })
    }
}

/// One documented response.
#[derive(Debug, Clone)]
// Parsed in every build; read only by the feature-gated generator.
#[cfg_attr(not(feature = "openapi"), allow(dead_code))]
pub(crate) struct ResponseDoc {
    pub(crate) description: String,
    /// Documentation only: never enforced.
    pub(crate) schema: Option<DocSchema>,
    /// Media types the response may carry; `application/json` when
    /// omitted and a schema is given.
    pub(crate) content: Vec<String>,
}

/// What a route's `doc = {...}` declared.
#[derive(Debug, Clone, Default)]
// Parsed in every build; `hidden` and `operation_id` are read everywhere,
// the rest only by the feature-gated generator.
#[cfg_attr(not(feature = "openapi"), allow(dead_code))]
pub(crate) struct RouteDoc {
    pub(crate) summary: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) operation_id: Option<String>,
    pub(crate) responses: BTreeMap<u16, ResponseDoc>,
    /// Security scheme names; `None` leaves the operation open.
    pub(crate) security: Option<Vec<String>>,
    pub(crate) deprecated: bool,
    pub(crate) hidden: bool,
}

impl RouteDoc {
    /// Parses a route's `doc` table. `site` names the route and its
    /// registration line; `api` is the `app:doc` the security names are
    /// checked against.
    pub(crate) fn parse(
        lua: &Lua,
        table: &Table,
        site: &str,
        api: Option<&ApiDoc>,
    ) -> mlua::Result<Self> {
        check_keys(table, ROUTE_KEYS, site, "doc")?;
        let what = "doc";
        let mut responses = BTreeMap::new();
        match table.get::<Value>("responses")? {
            Value::Nil => {}
            Value::Table(list) => {
                for pair in list.pairs::<Value, Value>() {
                    let (code, response) = pair?;
                    let code = match code {
                        Value::Integer(n) if (100..=599).contains(&n) => n as u16,
                        Value::Integer(n) => {
                            return Err(err(
                                site,
                                format!("doc.responses[{n}]: a status code is 100..599"),
                            ));
                        }
                        other => {
                            return Err(err(
                                site,
                                format!(
                                    "doc.responses keys are integer status codes, got {}",
                                    other.type_name()
                                ),
                            ));
                        }
                    };
                    let Value::Table(response) = response else {
                        return Err(err(site, format!("doc.responses[{code}] must be a table")));
                    };
                    let what = format!("doc.responses[{code}]");
                    check_keys(&response, RESPONSE_KEYS, site, &what)?;
                    let description = text(&response, "description", site, &what)?
                        .unwrap_or_else(|| default_description(code).to_string());
                    let schema = match response.get::<Value>("schema")? {
                        Value::Nil => None,
                        value => Some(compile_doc_schema(
                            lua,
                            value,
                            &format!("{site}: {what}.schema"),
                        )?),
                    };
                    let content = strings(&response, "content", site, &what)?
                        .unwrap_or_else(|| vec!["application/json".into()]);
                    responses.insert(
                        code,
                        ResponseDoc {
                            description,
                            schema,
                            content,
                        },
                    );
                }
            }
            other => {
                return Err(err(
                    site,
                    format!("doc.responses must be a table, got {}", other.type_name()),
                ));
            }
        }
        let security = strings(table, "security", site, what)?;
        if let Some(names) = &security {
            for name in names {
                let known = api.is_some_and(|api| api.security.contains_key(name));
                if !known {
                    return Err(err(
                        site,
                        format!(
                            "doc.security names `{name}`, which app:doc does not declare (known: {})",
                            api.map(|api| api
                                .security
                                .keys()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", "))
                                .filter(|s| !s.is_empty())
                                .unwrap_or_else(|| "none".into())
                        ),
                    ));
                }
            }
        }
        let operation_id = text(table, "operation_id", site, what)?;
        if let Some(id) = &operation_id
            && (id.is_empty()
                || !id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
        {
            return Err(err(
                site,
                format!("doc.operation_id `{id}` must be letters, digits, `_`, `-` or `.`"),
            ));
        }
        Ok(Self {
            summary: text(table, "summary", site, what)?,
            description: text(table, "description", site, what)?,
            tags: strings(table, "tags", site, what)?.unwrap_or_default(),
            operation_id,
            responses,
            security,
            deprecated: boolean(table, "deprecated", site, what)?,
            hidden: boolean(table, "hidden", site, what)?,
        })
    }
}

/// The reason phrase of a status code, for a response documented
/// without a description.
pub(crate) fn default_description(code: u16) -> &'static str {
    hyper::StatusCode::from_u16(code)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("Response")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lua() -> Lua {
        let lua = Lua::new();
        nitr_std::register_builtins(&lua, nitr_std::Builtins::minimal(), &Default::default())
            .expect("builtins");
        lua
    }

    fn table(lua: &Lua, source: &str) -> Table {
        lua.load(source).eval().expect("table")
    }

    #[test]
    fn api_docs_parse_and_refuse_typos() {
        let lua = lua();
        let api = ApiDoc::parse(
            &table(
                &lua,
                r#"{ title = "Notes", version = "1.0", tags = { { name = "notes", description = "CRUD" } },
                     security = { team = { type = "apiKey", ["in"] = "header", name = "x-team" } },
                     contact = { name = "Ada" } }"#,
            ),
            "app:doc (app.lua:3)",
        )
        .expect("parses");
        assert_eq!(api.title, "Notes");
        assert_eq!(api.tags[0].name, "notes");
        assert_eq!(api.security["team"]["name"], "x-team");
        assert_eq!(api.contact.unwrap()["name"], "Ada");
        for (bad, needle) in [
            (r#"{ titel = "x" }"#, "unknown app:doc key `titel`"),
            (
                r#"{ tags = { "notes" } }"#,
                "list of `{ name, description }`",
            ),
            (
                r#"{ security = { team = { scheme = "bearer" } } }"#,
                "needs a `type`",
            ),
            (r#"{ title = 3 }"#, "app:doc.title must be a string"),
        ] {
            let e = ApiDoc::parse(&table(&lua, bad), "app:doc (app.lua:3)")
                .expect_err(bad)
                .to_string();
            assert!(e.contains(needle), "{bad}: {e}");
            assert!(e.contains("app.lua:3"), "{e}");
        }
    }

    #[test]
    fn route_docs_parse_responses_and_point_request_schemas_at_input() {
        let lua = lua();
        let api = ApiDoc::parse(
            &table(
                &lua,
                r#"{ security = { bearer = { type = "http", scheme = "bearer" } } }"#,
            ),
            "app:doc",
        )
        .unwrap();
        let doc = RouteDoc::parse(
            &lua,
            &table(
                &lua,
                r#"{ summary = "List", tags = { "notes" }, operation_id = "listNotes",
                     responses = { [200] = { description = "ok", schema = { type = "array", items = { type = "string" } } },
                                   [404] = {} },
                     security = { "bearer" }, deprecated = true }"#,
            ),
            "route `GET /x` (app.lua:9)",
            Some(&api),
        )
        .expect("parses");
        assert_eq!(doc.summary.as_deref(), Some("List"));
        assert_eq!(doc.operation_id.as_deref(), Some("listNotes"));
        assert_eq!(doc.responses[&404].description, "Not Found");
        assert_eq!(doc.responses[&200].content, vec!["application/json"]);
        assert!(doc.responses[&200].schema.is_some());
        assert!(doc.deprecated && !doc.hidden);
        for (bad, needle) in [
            (r#"{ body = {} }"#, "doc.body is not a documentation key"),
            (r#"{ sumary = "x" }"#, "unknown doc key `sumary`"),
            (
                r#"{ responses = { [777] = {} } }"#,
                "status code is 100..599",
            ),
            (r#"{ responses = { ok = {} } }"#, "integer status codes"),
            (
                r#"{ responses = { [200] = { shema = {} } } }"#,
                "unknown doc.responses[200] key `shema`",
            ),
            (
                r#"{ security = { "basic" } }"#,
                "which app:doc does not declare (known: bearer)",
            ),
            (
                r#"{ operation_id = "has space" }"#,
                "must be letters, digits",
            ),
            (r#"{ hidden = "yes" }"#, "doc.hidden must be true or false"),
        ] {
            let e = RouteDoc::parse(
                &lua,
                &table(&lua, bad),
                "route `GET /x` (app.lua:9)",
                Some(&api),
            )
            .expect_err(bad)
            .to_string();
            assert!(e.contains(needle), "{bad}: {e}");
            assert!(e.contains("app.lua:9"), "{e}");
        }
    }
}
