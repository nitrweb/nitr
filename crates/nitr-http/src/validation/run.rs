// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The enforcement step: runs after the route resolved and before its
//! chain, inside the request's budget (it is called through the
//! runtime's `call_function`, so a custom check spends the same
//! instruction and time allowance a handler would).

use http_body_util::BodyExt as _;
use mlua::{AnyUserData, Lua, LuaSerdeExt, Table, Value};
use nitr_std::validation::{CompiledSchema, TextValue, ValidationError};

use super::{BodyRule, Content, InputHolder, InputSchemas};
use crate::request::LuaRequest;

/// Records one part's failures.
fn record(failures: &mut Option<ValidationError>, part: &str, mut err: ValidationError) {
    err.prefix(part);
    match failures {
        Some(all) => all.merge(err),
        None => *failures = Some(err),
    }
}

/// Checks one text part and stores the outcome.
async fn text_part(
    lua: &Lua,
    schema: &CompiledSchema,
    pairs: Vec<(String, TextValue)>,
    strict: Option<bool>,
    part: &str,
    valid: &Table,
    failures: &mut Option<ValidationError>,
) -> mlua::Result<()> {
    match schema.check_text(lua, pairs, strict).await? {
        Ok(data) => valid.set(part, data)?,
        Err(err) => record(failures, part, err),
    }
    Ok(())
}

fn text_pairs<'a>(iter: impl Iterator<Item = (&'a str, String)>) -> Vec<(String, TextValue)> {
    iter.map(|(k, v)| (k.to_string(), TextValue::Text(v)))
        .collect()
}

/// The body as bytes, kept on the request so `req:json()`/`req:form()`
/// still work afterwards.
async fn buffered_body(req: &mut LuaRequest) -> mlua::Result<bytes::Bytes> {
    use mlua::ExternalResult as _;
    if let Some(cached) = &req.cached_body {
        return Ok(cached.clone());
    }
    let bytes = req
        .req
        .body_mut()
        .collect()
        .await
        .into_lua_err()?
        .to_bytes();
    req.cached_body = Some(bytes.clone());
    Ok(bytes)
}

async fn body_part(
    lua: &Lua,
    input: &InputSchemas,
    req: &mut LuaRequest,
    content: Content,
    valid: &Table,
    failures: &mut Option<ValidationError>,
) -> mlua::Result<()> {
    let Some((rule, _)) = &input.body else {
        return Ok(());
    };
    let strict = input.strict;
    match (rule, content) {
        (BodyRule::Schema(schema), Content::Json) => {
            let bytes = buffered_body(req).await?;
            // An empty body is an empty object: `is required` per field
            // reads better than `must be valid JSON` for a bare POST.
            let value = if bytes.iter().all(u8::is_ascii_whitespace) {
                Value::Table(lua.create_table()?)
            } else {
                match serde_json::from_slice::<serde_json::Value>(&bytes) {
                    Ok(json) => lua.to_value(&json)?,
                    Err(_) => {
                        record(
                            failures,
                            "body",
                            ValidationError::single("json", "must be valid JSON"),
                        );
                        return Ok(());
                    }
                }
            };
            match schema.check(lua, value, strict).await? {
                Ok(data) => valid.set("body", data)?,
                Err(err) => record(failures, "body", err),
            }
        }
        (BodyRule::Schema(schema), Content::Form) => {
            let bytes = buffered_body(req).await?;
            let pairs: Vec<(String, TextValue)> = url::form_urlencoded::parse(&bytes)
                .map(|(k, v)| (k.into_owned(), TextValue::Text(v.into_owned())))
                .collect();
            text_part(lua, schema, pairs, strict, "body", valid, failures).await?;
        }
        #[cfg(feature = "multipart")]
        (BodyRule::Schema(schema), Content::Multipart) => {
            let pairs = match super::multipart::read(lua, req, schema).await? {
                Ok(pairs) => pairs,
                Err(err) => {
                    record(failures, "body", err);
                    return Ok(());
                }
            };
            text_part(lua, schema, pairs, strict, "body", valid, failures).await?;
        }
        #[cfg(feature = "multipart")]
        (BodyRule::File(schema), Content::Raw) => {
            let file = super::raw::read(lua, req).await?;
            let pairs = vec![("file".to_string(), TextValue::File(file))];
            match schema.check_text(lua, pairs, None).await? {
                Ok(data) => valid.set("body", data.get::<Value>("file")?)?,
                Err(mut err) => {
                    // The one-field schema's `file` path is the body itself.
                    for entry in &mut err.entries {
                        entry.path = entry
                            .path
                            .trim_start_matches("file")
                            .trim_start_matches('.')
                            .to_string();
                        if entry.path.is_empty() {
                            entry.path = "$".into();
                        }
                        entry.field.clear();
                    }
                    record(failures, "body", err);
                }
            }
        }
        // Negotiation never yields these pairs; without the feature the
        // declaration was refused at load.
        _ => {
            return Err(mlua::Error::RuntimeError(
                "unsupported body declaration reached validation".into(),
            ));
        }
    }
    Ok(())
}

/// The budgeted validation function: `(input holder, request) ->
/// nil | error table`. On success `req.valid` is populated.
pub(crate) async fn validate(
    lua: Lua,
    (holder, req_ud): (AnyUserData, AnyUserData),
) -> mlua::Result<Value> {
    let input = holder.borrow::<InputHolder>()?.0.clone();
    let mut req = req_ud.borrow_mut::<LuaRequest>()?;
    let valid = lua.create_table()?;
    let mut failures: Option<ValidationError> = None;

    if let Some(schema) = &input.params {
        let pairs = text_pairs(req.params.iter().map(|(k, v)| (k.as_str(), v.clone())));
        text_part(
            &lua,
            schema,
            pairs,
            input.strict,
            "params",
            &valid,
            &mut failures,
        )
        .await?;
    }
    if let Some(schema) = &input.query {
        let pairs: Vec<(String, TextValue)> = match req.req.uri().query() {
            Some(query) => url::form_urlencoded::parse(query.as_bytes())
                .map(|(k, v)| (k.into_owned(), TextValue::Text(v.into_owned())))
                .collect(),
            None => Vec::new(),
        };
        text_part(
            &lua,
            schema,
            pairs,
            input.strict,
            "query",
            &valid,
            &mut failures,
        )
        .await?;
    }
    if let Some(schema) = &input.headers {
        // Every line of a repeated header, in order: a scalar rule keeps
        // the last, an array rule collects them.
        let mut pairs = Vec::new();
        for name in schema.field_names() {
            for value in req.req.headers().get_all(name) {
                pairs.push((
                    name.to_string(),
                    TextValue::Text(String::from_utf8_lossy(value.as_bytes()).into_owned()),
                ));
            }
        }
        text_part(&lua, schema, pairs, None, "headers", &valid, &mut failures).await?;
    }
    if let Ok(Some(content)) = input.negotiate(req.req.headers()) {
        body_part(&lua, &input, &mut req, content, &valid, &mut failures).await?;
    }

    match failures {
        Some(err) => Ok(Value::Table(err.to_lua(&lua)?)),
        None => {
            req.valid = Some(valid);
            Ok(Value::Nil)
        }
    }
}
