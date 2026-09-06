// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `multipart/form-data` for a validated route: text parts become form
//! fields, file parts matching a `file` rule spool to the request's
//! directory, anything undeclared is drained and dropped.

use http_body_util::BodyExt as _;
use mlua::{ExternalResult as _, Lua};
use nitr_std::validation::{CompiledSchema, LuaFile, TextValue, ValidationError};

use super::spool::{Spooler, resolver};
use crate::request::LuaRequest;

/// Reads every part, spooling declared files.
pub(super) async fn read(
    lua: &Lua,
    req: &mut LuaRequest,
    schema: &CompiledSchema,
) -> mlua::Result<Result<Vec<(String, TextValue)>, ValidationError>> {
    let content_type = req
        .req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let boundary = crate::multipart::boundary(content_type.as_deref())?;
    let limits = req.limits.clone();
    let Some(root) = limits.upload_root.clone() else {
        return Err(mlua::Error::RuntimeError(
            "validated uploads need `[multipart] upload_dir`".into(),
        ));
    };
    let spool_dir = req
        .spool_dir
        .clone()
        .ok_or_else(|| mlua::Error::RuntimeError("no spool directory for this request".into()))?;
    req.body_consumed = true;

    let body = std::mem::take(req.req.body_mut());
    let mut parser = multer::Multipart::new(body.into_data_stream(), boundary);
    let mut out = Vec::new();
    let mut count = 0usize;
    let mut index = 0usize;
    while let Some(mut field) = match parser.next_field().await {
        Ok(field) => field,
        // The body stream failing is the read guard's verdict (408, 413)
        // or a disconnect: not the client's syntax.
        Err(err @ (multer::Error::StreamReadFailed(_) | multer::Error::LockFailure)) => {
            return Err(err).into_lua_err();
        }
        // Anything else is a malformed body: a rule failure on the body
        // itself, like invalid JSON, never a handler error.
        Err(_) => {
            return Ok(Err(ValidationError::single(
                "multipart",
                "must be a well-formed multipart body",
            )));
        }
    } {
        count += 1;
        if count > limits.max_parts {
            return Err(mlua::Error::RuntimeError(format!(
                "multipart body has more than {} parts",
                limits.max_parts
            )));
        }
        let name = field.name().unwrap_or_default().to_string();
        let filename = field.file_name().map(str::to_string);
        let declared = field.content_type().map(|m| m.to_string());
        let Some(filename) = filename else {
            // A text field, bounded like `part:text()`.
            let mut buf = Vec::new();
            let mut over = false;
            while let Some(chunk) = field.chunk().await.into_lua_err()? {
                if buf.len() as u64 + chunk.len() as u64 > limits.max_field_bytes {
                    over = true;
                    continue;
                }
                buf.extend_from_slice(&chunk);
            }
            if over {
                return Err(crate::multipart::too_large(
                    &name,
                    "field",
                    limits.max_field_bytes,
                ));
            }
            out.push((
                name,
                TextValue::Text(String::from_utf8_lossy(&buf).into_owned()),
            ));
            continue;
        };
        if !schema.is_file_field(&name) {
            // Undeclared: drained, never stored (anti-mass-assignment for
            // files).
            while field.chunk().await.into_lua_err()?.is_some() {}
            continue;
        }
        index += 1;
        let cap = schema
            .file_max_bytes(&name)
            .unwrap_or(limits.max_file_bytes)
            .min(limits.max_file_bytes);
        let mut spooler = Spooler::create(&spool_dir, index, cap).await?;
        while let Some(chunk) = field.chunk().await.into_lua_err()? {
            spooler.push(&chunk).await?;
        }
        // An empty `<input type="file">` still sends a part: no name, no
        // bytes. That is "absent", not an empty file.
        if filename.is_empty() && spooler.size() == 0 {
            let (path, _) = spooler.finish(None, None).await?;
            let _ = tokio::fs::remove_file(path).await;
            continue;
        }
        let (path, info) = spooler
            .finish(Some(filename).filter(|f| !f.is_empty()), declared)
            .await?;
        let file = LuaFile::new(info, path, resolver(root.clone()), limits.max_field_bytes);
        out.push((name, TextValue::File(lua.create_userdata(file)?)));
    }
    Ok(Ok(out))
}
