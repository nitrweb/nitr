// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The OpenAPI 3.1 document generator.
//!
//! Determinism is a requirement, not a nicety: `nitr openapi --check`
//! diffs bytes and Lua `pairs` order differs between states. Every map
//! here is a `serde_json::Map` (a `BTreeMap` in this workspace), paths
//! sort, methods follow the router's declaration order, custom formats
//! sort by name, and the document is built from the bootstrap state
//! only.
//!
//! Nothing in the document claims an enforcement the server does not
//! perform: request bodies and parameters carry `x-nitr-enforced: true`
//! (`"custom"` where a script check adds to the Rust rules), responses
//! `x-nitr-enforced: false`.

use serde_json::{Map, Value as Json, json};

use nitr_std::validation::{CompiledSchema, Components, custom_formats, rule_codes};

use super::{AppMeta, RouteMeta, to_openapi_path};
use crate::config::OpenApiConfig;
use crate::validation::{BodyRule, Content};

/// The largest document a build accepts. The size of a spec is a
/// property of the application, so an oversized one fails at boot,
/// never at request time.
pub(crate) const MAX_SPEC_BYTES: usize = 1024 * 1024;

/// The document, built from what the bootstrap state compiled.
pub(crate) fn build(lua: &mlua::Lua, meta: &AppMeta, cfg: &OpenApiConfig) -> Result<Json, String> {
    let mut components = Components::new();
    let mut paths: Map<String, Json> = Map::new();
    let mut operations = 0usize;
    for route in &meta.routes {
        let documented = route.doc.is_some();
        if route.doc.as_ref().is_some_and(|d| d.hidden) {
            continue;
        }
        if !documented && !cfg.include_undocumented {
            continue;
        }
        let (template, path_params) = to_openapi_path(&route.path)?;
        let operation = operation(route, &path_params, &mut components)?;
        let method = route.method.as_str().to_ascii_lowercase();
        let entry = paths
            .entry(template)
            .or_insert_with(|| Json::Object(Map::new()));
        if let Json::Object(item) = entry {
            item.insert(method, operation);
        }
        operations += 1;
    }

    let mut doc = Map::new();
    doc.insert("openapi".into(), json!("3.1.0"));
    doc.insert("info".into(), info(meta));
    if !cfg.servers.is_empty() {
        doc.insert(
            "servers".into(),
            Json::Array(cfg.servers.iter().map(|u| json!({ "url": u })).collect()),
        );
    }
    if let Some(api) = &meta.api {
        if !api.tags.is_empty() {
            doc.insert(
                "tags".into(),
                Json::Array(
                    api.tags
                        .iter()
                        .map(|t| {
                            let mut tag = Map::new();
                            tag.insert("name".into(), json!(t.name));
                            if let Some(d) = &t.description {
                                tag.insert("description".into(), json!(d));
                            }
                            Json::Object(tag)
                        })
                        .collect(),
                ),
            );
        }
        if let Some(external) = &api.external_docs {
            doc.insert("externalDocs".into(), external.clone());
        }
    }
    doc.insert("paths".into(), Json::Object(paths));

    let mut comps = Map::new();
    components.insert("ValidationError".into(), validation_error_schema());
    components.insert(
        "UnsupportedMediaType".into(),
        unsupported_media_type_schema(),
    );
    comps.insert(
        "schemas".into(),
        Json::Object(components.into_iter().collect()),
    );
    comps.insert(
        "responses".into(),
        json!({
            "ValidationError": {
                "description": "The request failed validation",
                "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ValidationError" } } }
            },
            "UnsupportedMediaType": {
                "description": "The request body carries a media type the route does not accept",
                "content": { "application/json": { "schema": { "$ref": "#/components/schemas/UnsupportedMediaType" } } }
            }
        }),
    );
    if let Some(api) = &meta.api
        && !api.security.is_empty()
    {
        comps.insert(
            "securitySchemes".into(),
            Json::Object(
                api.security
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ),
        );
    }
    doc.insert("components".into(), Json::Object(comps));

    let formats = custom_formats(lua);
    if !formats.is_empty() {
        let mut map = Map::new();
        for f in formats {
            let mut entry = Map::new();
            entry.insert("description".into(), json!(f.description));
            if let Some(p) = f.pattern {
                entry.insert("pattern".into(), json!(p));
            }
            if let Some(e) = f.example {
                entry.insert("example".into(), json!(e));
            }
            map.insert(f.name, Json::Object(entry));
        }
        doc.insert("x-nitr-formats".into(), Json::Object(map));
    }
    doc.insert("x-nitr-operations".into(), json!(operations));
    Ok(Json::Object(doc))
}

fn info(meta: &AppMeta) -> Json {
    let mut info = Map::new();
    match &meta.api {
        Some(api) => {
            info.insert("title".into(), json!(api.title));
            info.insert("version".into(), json!(api.version));
            if let Some(d) = &api.description {
                info.insert("description".into(), json!(d));
            }
            if let Some(t) = &api.terms_of_service {
                info.insert("termsOfService".into(), json!(t));
            }
            if let Some(c) = &api.contact {
                info.insert("contact".into(), c.clone());
            }
            if let Some(l) = &api.license {
                info.insert("license".into(), l.clone());
            }
        }
        None => {
            info.insert("title".into(), json!("API"));
            info.insert("version".into(), json!("0.0.0"));
        }
    }
    Json::Object(info)
}

/// One operation: prose from `doc`, parameters and body from `input`,
/// the automatic responses.
fn operation(
    route: &RouteMeta,
    path_params: &[super::PathParam],
    components: &mut Components,
) -> Result<Json, String> {
    let mut op = Map::new();
    let doc = route.doc.as_ref();
    op.insert("operationId".into(), json!(route.operation_id));
    if let Some(doc) = doc {
        if let Some(s) = &doc.summary {
            op.insert("summary".into(), json!(s));
        }
        if let Some(d) = &doc.description {
            op.insert("description".into(), json!(d));
        }
        if !doc.tags.is_empty() {
            op.insert("tags".into(), json!(doc.tags));
        }
        if doc.deprecated {
            op.insert("deprecated".into(), json!(true));
        }
        if let Some(names) = &doc.security {
            op.insert(
                "security".into(),
                Json::Array(names.iter().map(|n| json!({ n: [] })).collect()),
            );
        }
    }

    // Parameters: the path ones come from the pattern (typed by
    // `input.params` when declared), then query and headers.
    let mut parameters = Vec::new();
    let input = route.input.as_deref();
    let declared_params = match input.and_then(|i| i.params.as_ref()) {
        Some(schema) => Some(part_object(schema, components)?),
        None => None,
    };
    for param in path_params {
        let (schema, description) = declared_params
            .as_ref()
            .and_then(|(props, _)| props.get(&param.name))
            .map(|prop| split_description(prop.clone()))
            .unwrap_or_else(|| (json!({ "type": "string" }), None));
        let mut p = Map::new();
        p.insert("name".into(), json!(param.name));
        p.insert("in".into(), json!("path"));
        p.insert("required".into(), json!(true));
        if let Some(d) = description {
            p.insert("description".into(), json!(d));
        }
        p.insert("x-nitr-enforced".into(), json!(declared_params.is_some()));
        if param.catch_all {
            p.insert("x-nitr-catch-all".into(), json!(true));
        }
        p.insert("schema".into(), schema);
        parameters.push(Json::Object(p));
    }
    for (location, schema) in [
        ("query", input.and_then(|i| i.query.as_ref())),
        ("header", input.and_then(|i| i.headers.as_ref())),
    ] {
        let Some(schema) = schema else { continue };
        let (props, required) = part_object(schema, components)?;
        for (name, prop) in props {
            let (schema, description) = split_description(prop);
            let mut p = Map::new();
            p.insert("name".into(), json!(name));
            p.insert("in".into(), json!(location));
            p.insert("required".into(), json!(required.contains(&name)));
            if let Some(d) = description {
                p.insert("description".into(), json!(d));
            }
            p.insert("x-nitr-enforced".into(), enforced_marker(&schema));
            p.insert("schema".into(), schema);
            parameters.push(Json::Object(p));
        }
    }
    if !parameters.is_empty() {
        op.insert("parameters".into(), Json::Array(parameters));
    }

    // The request body: one entry per accepted media type, all the same
    // schema.
    if let Some((rule, contents)) = input.and_then(|i| i.body.as_ref()) {
        op.insert(
            "requestBody".into(),
            request_body(rule, contents, components)?,
        );
    }

    // Responses: the documented ones, then what validation adds.
    let mut responses = Map::new();
    if let Some(doc) = doc {
        for (code, response) in &doc.responses {
            let mut r = Map::new();
            r.insert("description".into(), json!(response.description));
            r.insert("x-nitr-enforced".into(), json!(false));
            if let Some(schema) = &response.schema {
                let exported = schema.json_schema(components)?;
                let mut content = Map::new();
                for media_type in &response.content {
                    content.insert(media_type.clone(), json!({ "schema": exported.clone() }));
                }
                r.insert("content".into(), Json::Object(content));
            }
            responses.insert(code.to_string(), Json::Object(r));
        }
    }
    if input.is_some() {
        responses
            .entry("422".to_string())
            .or_insert_with(|| json!({ "$ref": "#/components/responses/ValidationError" }));
    }
    if input.is_some_and(|i| i.body.is_some()) {
        responses
            .entry("415".to_string())
            .or_insert_with(|| json!({ "$ref": "#/components/responses/UnsupportedMediaType" }));
    }
    if responses.is_empty() {
        responses.insert("200".into(), json!({ "description": "OK" }));
    }
    op.insert("responses".into(), Json::Object(responses));
    Ok(Json::Object(op))
}

/// Whether a property schema is enforced by Rust rules alone or also by
/// a script check.
fn enforced_marker(schema: &Json) -> Json {
    match schema.get("x-nitr-enforced") {
        Some(Json::String(s)) if s == "custom" => json!("custom"),
        _ => json!(true),
    }
}

/// Moves a property's `description` up to the parameter that carries it,
/// where Swagger UI shows it.
fn split_description(mut schema: Json) -> (Json, Option<String>) {
    let description = schema
        .as_object_mut()
        .and_then(|o| o.remove("description"))
        .and_then(|d| d.as_str().map(str::to_string));
    (schema, description)
}

/// The properties and required names of a text-part schema, resolved
/// through `components` when the schema is titled.
fn part_object(
    schema: &CompiledSchema,
    components: &mut Components,
) -> Result<(Map<String, Json>, Vec<String>), String> {
    let exported = schema.json_schema(components)?;
    let object = match exported.get("$ref").and_then(Json::as_str) {
        Some(reference) => {
            let title = reference.rsplit('/').next().unwrap_or_default();
            components
                .get(title)
                .cloned()
                .ok_or_else(|| format!("component `{title}` was referenced before being defined"))?
        }
        None => exported,
    };
    let props = object
        .get("properties")
        .and_then(Json::as_object)
        .cloned()
        .unwrap_or_default();
    let required = object
        .get("required")
        .and_then(Json::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok((props, required))
}

fn request_body(
    rule: &BodyRule,
    contents: &[Content],
    components: &mut Components,
) -> Result<Json, String> {
    let mut body = Map::new();
    body.insert("required".into(), json!(true));
    let mut content = Map::new();
    match rule {
        BodyRule::Schema(schema) => {
            let exported = schema.json_schema(components)?;
            body.insert("x-nitr-enforced".into(), json!(true));
            for c in contents {
                let media_type = match c {
                    Content::Json => "application/json",
                    Content::Form => "application/x-www-form-urlencoded",
                    Content::Multipart => "multipart/form-data",
                    Content::Raw => continue,
                };
                let mut entry = Map::new();
                entry.insert("schema".into(), exported.clone());
                if *c == Content::Multipart {
                    let encoding = file_encodings(&exported, components);
                    if !encoding.is_empty() {
                        entry.insert("encoding".into(), Json::Object(encoding));
                    }
                }
                content.insert(media_type.into(), Json::Object(entry));
            }
        }
        BodyRule::File(schema) => {
            body.insert("x-nitr-enforced".into(), json!(true));
            // The one-field wrapper's `file` property is the body itself.
            let exported = schema.json_schema(components)?;
            let file = exported
                .get("properties")
                .and_then(|p| p.get("file"))
                .cloned()
                .unwrap_or_else(|| json!({ "type": "string", "format": "binary" }));
            for media_type in raw_media_types(&file) {
                content.insert(media_type, json!({ "schema": file.clone() }));
            }
        }
    }
    body.insert("content".into(), Json::Object(content));
    Ok(Json::Object(body))
}

/// `encoding` entries for the file fields of a multipart schema: the
/// media types each file may carry.
fn file_encodings(schema: &Json, components: &Components) -> Map<String, Json> {
    let object = match schema.get("$ref").and_then(Json::as_str) {
        Some(reference) => {
            let title = reference.rsplit('/').next().unwrap_or_default();
            components.get(title).cloned().unwrap_or(Json::Null)
        }
        None => schema.clone(),
    };
    let mut encoding = Map::new();
    let Some(props) = object.get("properties").and_then(Json::as_object) else {
        return encoding;
    };
    for (name, prop) in props {
        // A file field, or an array of them.
        let file = if prop.get("type").and_then(Json::as_str) == Some("array") {
            prop.get("items").unwrap_or(prop)
        } else {
            prop
        };
        let types = file_media_types(file);
        if !types.is_empty() {
            encoding.insert(name.clone(), json!({ "contentType": types.join(", ") }));
        }
    }
    encoding
}

/// The media types a file property declares (`contentMediaType` for one
/// exact type, `x-nitr-types` for several), or nothing for a non-file.
fn file_media_types(file: &Json) -> Vec<String> {
    if let Some(one) = file.get("contentMediaType").and_then(Json::as_str) {
        return vec![one.to_string()];
    }
    if file.get("format").and_then(Json::as_str) != Some("binary") {
        return Vec::new();
    }
    file.get("x-nitr-types")
        .and_then(Json::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_else(|| vec!["application/octet-stream".into()])
}

/// The `requestBody.content` keys of a raw body: exact types as they
/// are, a family expanded to its known members, `*/*` as the octet
/// stream a generated client would send.
fn raw_media_types(file: &Json) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for pattern in file_media_types(file) {
        match pattern.strip_suffix("/*") {
            Some("*") => out.push("application/octet-stream".into()),
            Some(family) => {
                for media in nitr_std::validation::MEDIA_TYPES {
                    if media.name.starts_with(family)
                        && media.name.as_bytes().get(family.len()) == Some(&b'/')
                        && !nitr_std::validation::is_active_content(media.name)
                    {
                        out.push(media.name.to_string());
                    }
                }
            }
            None => out.push(pattern),
        }
    }
    if out.is_empty() {
        out.push("application/octet-stream".into());
    }
    out.sort();
    out.dedup();
    out
}

/// The shared component describing a 422: both halves of the body, with
/// the rule codes as an enum so a client can switch on them.
fn validation_error_schema() -> Json {
    json!({
        "type": "object",
        "required": ["code", "message", "fields", "errors"],
        "description": "The request failed its route's `input` declaration. Text inputs (query strings, forms, path parameters, headers) are coerced before checking: a blank optional field is absent, `on`/`true`/`1` are booleans, a `name[]` key collects into `name`, and a repeated scalar key keeps its last value.",
        "properties": {
            "code": { "type": "string", "const": "VALIDATION_FAILED" },
            "message": { "type": "string" },
            "fields": {
                "type": "object",
                "description": "Each failing path (`body.email`, `query.limit[2]`) to its message; a bare part name for a schema-level failure.",
                "additionalProperties": { "type": "string" }
            },
            "errors": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["path", "part", "field", "rule", "message"],
                    "properties": {
                        "path": { "type": "string" },
                        "part": { "type": "string", "enum": ["body", "query", "params", "headers"] },
                        "field": { "type": "string" },
                        "rule": { "type": "string", "enum": rule_codes() },
                        "message": { "type": "string" },
                        "params": { "type": "object" },
                        "label": { "type": "string" }
                    }
                }
            }
        }
    })
}

fn unsupported_media_type_schema() -> Json {
    json!({
        "type": "object",
        "required": ["code", "message", "accepted"],
        "properties": {
            "code": { "type": "string", "const": "UNSUPPORTED_MEDIA_TYPE" },
            "message": { "type": "string" },
            "accepted": { "type": "array", "items": { "type": "string" } }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::doc::{ApiDoc, RouteDoc};
    use crate::validation::{InputEnv, InputSchemas, param_names};
    use hyper::Method;
    use mlua::Lua;
    use std::sync::Arc;

    fn lua() -> Lua {
        let lua = Lua::new();
        nitr_std::register_builtins(&lua, nitr_std::Builtins::minimal(), &Default::default())
            .expect("builtins");
        lua
    }

    fn route(
        lua: &Lua,
        method: Method,
        path: &str,
        input: Option<&str>,
        doc: Option<&str>,
    ) -> RouteMeta {
        let input = input.map(|src| {
            let table: mlua::Table = lua.load(src).eval().expect("input");
            let env = InputEnv {
                upload_root: Some(Arc::new(std::env::temp_dir())),
                ..Default::default()
            };
            Arc::new(
                InputSchemas::parse(lua, &table, &param_names(path), &env, "test").expect("input"),
            )
        });
        let doc = doc.map(|src| {
            let table: mlua::Table = lua.load(src).eval().expect("doc");
            RouteDoc::parse(lua, &table, "test", None).expect("doc")
        });
        let operation_id = doc
            .as_ref()
            .and_then(|d| d.operation_id.clone())
            .unwrap_or_else(|| crate::openapi::default_operation_id(&method, path));
        RouteMeta {
            method,
            path: path.into(),
            doc,
            input,
            operation_id,
        }
    }

    fn example(lua: &Lua) -> AppMeta {
        lua.load(
            r#"nitr.validate.format("note_ref", { description = "A note reference", pattern = "^N-[0-9]+$",
                 check = function(s) return true end })
               Note = nitr.validate.schema({ id = { type = "integer", required = true }, text = "string|required" }, { title = "Note" })
               NoteInput = nitr.validate.schema({
                   text = { "string|trim|min_len:1|required", description = "the body", check = function(s) return true end },
                   refs = { "array|max_items:3", items = "string|format:note_ref" },
               }, { title = "NoteInput" })"#,
        )
        .exec()
        .expect("schemas");
        let api = ApiDoc::parse(
            &lua.load(r#"{ title = "Notes", version = "1.0.0", tags = { { name = "notes" } },
                          security = { team = { type = "apiKey", ["in"] = "header", name = "x-team" } } }"#)
                .eval()
                .unwrap(),
            "app:doc",
        )
        .unwrap();
        AppMeta {
            api: Some(api),
            routes: vec![
                route(
                    lua,
                    Method::GET,
                    "/api/notes",
                    Some(
                        r#"{ query = { limit = "integer|min:1|max:100|default:20", tag = { "string|format:slug", description = "filter" } }, headers = { ["x-team"] = "string|required" } }"#,
                    ),
                    Some(
                        r#"{ summary = "List", tags = { "notes" }, responses = { [200] = { description = "page", schema = { type = "array", items = Note } } } }"#,
                    ),
                ),
                route(
                    lua,
                    Method::POST,
                    "/api/notes",
                    Some(r#"{ body = NoteInput }"#),
                    Some(
                        r#"{ operation_id = "createNote", responses = { [201] = { schema = Note } } }"#,
                    ),
                ),
                route(
                    lua,
                    Method::GET,
                    "/api/notes/:id",
                    Some(r#"{ params = { id = "integer|min:1" } }"#),
                    None,
                ),
                route(
                    lua,
                    Method::GET,
                    "/internal",
                    None,
                    Some(r#"{ hidden = true }"#),
                ),
                route(lua, Method::DELETE, "/files/*rest", None, None),
            ],
        }
    }

    #[test]
    fn the_example_app_documents_what_it_enforces() {
        let lua = lua();
        let meta = example(&lua);
        let spec = build(&lua, &meta, &OpenApiConfig::default()).expect("builds");
        assert_eq!(spec["openapi"], "3.1.0");
        assert_eq!(spec["info"]["title"], "Notes");
        assert_eq!(spec["tags"][0]["name"], "notes");
        assert!(
            spec["paths"].get("/internal").is_none(),
            "hidden routes are absent"
        );

        let list = &spec["paths"]["/api/notes"]["get"];
        assert_eq!(list["operationId"], "get_api_notes");
        assert_eq!(list["summary"], "List");
        let params = list["parameters"].as_array().unwrap();
        let names: Vec<(&str, &str)> = params
            .iter()
            .map(|p| (p["name"].as_str().unwrap(), p["in"].as_str().unwrap()))
            .collect();
        assert_eq!(
            names,
            vec![("limit", "query"), ("tag", "query"), ("x-team", "header")]
        );
        assert_eq!(params[0]["schema"]["maximum"], 100);
        assert_eq!(params[0]["required"], false);
        assert_eq!(params[0]["x-nitr-enforced"], true);
        assert_eq!(params[1]["description"], "filter");
        assert_eq!(params[1]["schema"]["x-nitr-format"], "slug");
        assert_eq!(params[2]["required"], true);
        assert_eq!(list["responses"]["200"]["x-nitr-enforced"], false);
        assert_eq!(
            list["responses"]["200"]["content"]["application/json"]["schema"]["items"]["$ref"],
            "#/components/schemas/Note"
        );
        assert_eq!(
            list["responses"]["422"]["$ref"],
            "#/components/responses/ValidationError"
        );
        assert!(list["responses"].get("415").is_none(), "no body, no 415");

        let create = &spec["paths"]["/api/notes"]["post"];
        assert_eq!(create["operationId"], "createNote");
        assert_eq!(create["requestBody"]["required"], true);
        assert_eq!(create["requestBody"]["x-nitr-enforced"], true);
        assert_eq!(
            create["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/NoteInput"
        );
        assert_eq!(
            create["requestBody"]["content"]["application/x-www-form-urlencoded"]["schema"]["$ref"],
            "#/components/schemas/NoteInput"
        );
        assert_eq!(create["responses"]["201"]["description"], "Created");
        assert!(create["responses"].get("415").is_some());

        let one = &spec["paths"]["/api/notes/{id}"]["get"];
        assert_eq!(one["operationId"], "get_api_notes_id");
        assert_eq!(one["parameters"][0]["in"], "path");
        assert_eq!(one["parameters"][0]["required"], true);
        assert_eq!(one["parameters"][0]["schema"]["type"], "integer");
        assert_eq!(one["parameters"][0]["x-nitr-enforced"], true);

        let files = &spec["paths"]["/files/{rest}"]["delete"];
        assert_eq!(files["parameters"][0]["x-nitr-catch-all"], true);
        assert_eq!(files["parameters"][0]["x-nitr-enforced"], false);
        assert_eq!(files["responses"]["200"]["description"], "OK");

        let comps = &spec["components"]["schemas"];
        assert_eq!(
            comps["NoteInput"]["properties"]["text"]["x-nitr-enforced"],
            "custom"
        );
        assert_eq!(
            comps["NoteInput"]["properties"]["refs"]["items"]["x-nitr-format"],
            "note_ref"
        );
        assert_eq!(
            comps["ValidationError"]["properties"]["code"]["const"],
            "VALIDATION_FAILED"
        );
        assert!(
            comps["ValidationError"]["properties"]["errors"]["items"]["properties"]["rule"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "required")
        );
        assert_eq!(
            spec["components"]["securitySchemes"]["team"]["name"],
            "x-team"
        );
        assert_eq!(spec["x-nitr-formats"]["note_ref"]["pattern"], "^N-[0-9]+$");
        assert_eq!(spec["x-nitr-operations"], 4);
    }

    #[test]
    fn undocumented_routes_can_be_left_out() {
        let lua = lua();
        let meta = example(&lua);
        let cfg = OpenApiConfig {
            include_undocumented: false,
            servers: vec!["https://api.example.com".into()],
            ..Default::default()
        };
        let spec = build(&lua, &meta, &cfg).unwrap();
        assert!(spec["paths"].get("/api/notes/{id}").is_none());
        assert!(spec["paths"].get("/files/{rest}").is_none());
        assert!(spec["paths"]["/api/notes"].get("get").is_some());
        assert_eq!(spec["servers"][0]["url"], "https://api.example.com");
        assert_eq!(spec["x-nitr-operations"], 2);
    }

    #[test]
    fn the_document_is_byte_identical_across_states() {
        let mut first: Option<String> = None;
        for _ in 0..3 {
            let lua = lua();
            let meta = example(&lua);
            let spec = build(&lua, &meta, &OpenApiConfig::default()).unwrap();
            let text = serde_json::to_string(&spec).unwrap();
            match &first {
                Some(f) => assert_eq!(&text, f),
                None => first = Some(text),
            }
        }
    }

    #[test]
    fn multipart_and_raw_bodies_name_their_media_types() {
        let lua = lua();
        let upload = route(
            &lua,
            Method::POST,
            "/profile",
            Some(
                r#"{ body = { schema = { name = "string", avatar = { type = "file", types = { "image/png", "image/jpeg" }, max_bytes = 1024 },
                                        docs = { type = "array", items = { type = "file", types = { "application/pdf" }, max_bytes = 1024 } } },
                              content = { "multipart", "json" } } }"#,
            ),
            None,
        );
        let raw = route(
            &lua,
            Method::PUT,
            "/blob",
            Some(
                r#"{ body = { file = { type = "file", types = { "image/*", "application/zip" }, max_bytes = 1024 }, content = { "raw" } } }"#,
            ),
            None,
        );
        let any = route(
            &lua,
            Method::PUT,
            "/any",
            Some(
                r#"{ body = { file = { type = "file", types = { "*/*" }, max_bytes = 1024 }, content = { "raw" } } }"#,
            ),
            None,
        );
        let meta = AppMeta {
            api: None,
            routes: vec![upload, raw, any],
        };
        let spec = build(&lua, &meta, &OpenApiConfig::default()).unwrap();
        let body = &spec["paths"]["/profile"]["post"]["requestBody"];
        let multipart = &body["content"]["multipart/form-data"];
        assert_eq!(
            multipart["schema"]["properties"]["avatar"]["format"],
            "binary"
        );
        assert_eq!(
            multipart["encoding"]["avatar"]["contentType"],
            "image/png, image/jpeg"
        );
        assert_eq!(
            multipart["encoding"]["docs"]["contentType"],
            "application/pdf"
        );
        assert!(multipart["encoding"].get("name").is_none());
        assert!(body["content"].get("application/json").is_some());

        let raw = &spec["paths"]["/blob"]["put"]["requestBody"]["content"];
        let keys: Vec<&String> = raw.as_object().unwrap().keys().collect();
        assert!(keys.iter().any(|k| *k == "application/zip"), "{keys:?}");
        assert!(keys.iter().any(|k| *k == "image/png"), "{keys:?}");
        assert!(
            !keys.iter().any(|k| *k == "image/svg+xml"),
            "active content is not a family member: {keys:?}"
        );
        assert_eq!(raw["image/png"]["schema"]["format"], "binary");
        assert_eq!(raw["image/png"]["schema"]["x-nitr-max-bytes"], 1024);

        let any = &spec["paths"]["/any"]["put"]["requestBody"]["content"];
        assert_eq!(any.as_object().unwrap().len(), 1);
        assert!(any.get("application/octet-stream").is_some());
    }
}
