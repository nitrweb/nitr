// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use bytes::BytesMut;
use mlua::{ExternalResult, LuaSerdeExt, UserData, UserDataFields, UserDataMethods};
use reqwest::Response;
use serde_json::Value as SerdeValue;

pub(crate) struct LuaResponse {
    resp: Response,
    /// Cap on the body size accumulated by `text()`/`json()`.
    max_bytes: u64,
}

impl LuaResponse {
    pub(crate) fn new(resp: Response, max_bytes: u64) -> Self {
        Self { resp, max_bytes }
    }

    pub(crate) fn status(&self) -> reqwest::StatusCode {
        self.resp.status()
    }
}

/// Reads the whole body into memory, enforcing the response-size cap.
async fn collect_body(resp: &mut LuaResponse) -> mlua::Result<bytes::Bytes> {
    let len = resp.resp.content_length().unwrap_or_default() as usize;
    let mut buf = BytesMut::with_capacity(len.min(resp.max_bytes as usize));
    while let Some(chunk) = resp.resp.chunk().await.into_lua_err()? {
        if (buf.len() + chunk.len()) as u64 > resp.max_bytes {
            return Err(mlua::Error::RuntimeError(format!(
                "response body exceeds fetch.max_response_bytes ({} bytes)",
                resp.max_bytes
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

impl UserData for LuaResponse {
    fn add_fields<'lua, F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("status", |_, resp| Ok(resp.resp.status().as_u16()));

        fields.add_field_method_get("url", |lua, resp| {
            let table = lua.create_table()?;
            let url = resp.resp.url();

            table
                .set("scheme", url.scheme().to_string())
                .into_lua_err()?;
            table
                .set("host", url.host_str().unwrap_or_default())
                .into_lua_err()?;
            table
                .set("port", url.port().unwrap_or_default())
                .into_lua_err()?;
            table.set("path", url.path()).into_lua_err()?;
            table
                .set("authority", url.authority().to_string())
                .into_lua_err()?;
            table
                .set("query", url.query().unwrap_or_default())
                .into_lua_err()?;

            Ok(table)
        });

        fields.add_field_method_get("headers", |lua, resp| {
            let headers = resp.resp.headers();
            let table = lua.create_table().into_lua_err()?;
            for (k, v) in headers.iter() {
                table
                    .set(k.as_str(), v.to_str().unwrap_or_default())
                    .into_lua_err()?;
            }
            Ok(table)
        });

        fields.add_field_method_get("content_length", |_, resp| Ok(resp.resp.content_length()));
    }

    fn add_methods<'lua, M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_async_method_mut("read", |lua, mut resp, ()| async move {
            if let Some(chunk) = resp.resp.chunk().await.into_lua_err()? {
                return Some(lua.create_string(chunk)).transpose();
            }
            Ok(None)
        });

        methods.add_async_method_mut("json", |lua, mut resp, ()| async move {
            let buf = collect_body(&mut resp).await?;
            if buf.is_empty() {
                return Err(mlua::Error::external(
                    "Unexpected end of JSON input, probably response body is empty or already consumed",
                ));
            }
            let json = serde_json::from_slice::<SerdeValue>(&buf).into_lua_err()?;
            lua.to_value(&json)
        });

        methods.add_async_method_mut("text", |lua, mut resp, ()| async move {
            let buf = collect_body(&mut resp).await?;
            lua.create_string(buf)
        });
    }
}
