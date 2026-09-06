// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! A `"raw"` body: the whole request body is one file, spooled like a
//! multipart part. The declared `Content-Type` is the part's header; a
//! `Content-Disposition: attachment; filename=…` names it when present.

use http_body_util::BodyExt as _;
use mlua::{AnyUserData, ExternalResult as _, Lua};
use nitr_std::validation::LuaFile;

use super::spool::{Spooler, resolver};
use crate::request::LuaRequest;

/// The `filename` parameter of a `Content-Disposition` header, unquoted.
fn disposition_filename(value: &str) -> Option<String> {
    value
        .split(';')
        .map(str::trim)
        .find_map(|param| param.strip_prefix("filename="))
        .map(|name| name.trim_matches('"').to_string())
        .filter(|name| !name.is_empty())
}

/// Spools the body and returns the `nitr.File` handle.
pub(super) async fn read(lua: &Lua, req: &mut LuaRequest) -> mlua::Result<AnyUserData> {
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
    let declared = req
        .req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|s| !s.is_empty());
    let filename = req
        .req
        .headers()
        .get(hyper::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .and_then(disposition_filename);
    req.body_consumed = true;

    let mut spooler = Spooler::create(&spool_dir, 1, limits.max_file_bytes).await?;
    let body = req.req.body_mut();
    while let Some(frame) = body.frame().await {
        if let Some(bytes) = frame.into_lua_err()?.data_ref() {
            spooler.push(bytes).await?;
        }
    }
    let (path, info) = spooler.finish(filename, declared).await?;
    let file = LuaFile::new(info, path, resolver(root), limits.max_field_bytes);
    lua.create_userdata(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_filenames_are_unquoted() {
        assert_eq!(
            disposition_filename("attachment; filename=\"a b.pdf\""),
            Some("a b.pdf".into())
        );
        assert_eq!(disposition_filename("inline"), None);
        assert_eq!(disposition_filename("attachment; filename=\"\""), None);
    }
}
