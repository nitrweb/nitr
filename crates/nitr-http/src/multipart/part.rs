// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! [`LuaPart`]: the one-shot part handle handed to the Lua callback —
//! `text`, `save` (streaming socket → disk), and `discard`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hyper::body::Bytes;
use mlua::{ExternalResult as _, UserData, UserDataFields, UserDataMethods};

use super::upload::{resolve_upload_path, safe_filename};

/// A `multipart/form-data` part handed to the Lua callback.
///
/// The field is taken on first use: a part is a one-shot stream, not a
/// buffer that can be read twice.
pub(crate) struct LuaPart {
    name: String,
    filename: Option<String>,
    safe_filename: Option<String>,
    content_type: Option<String>,
    /// `None` once the part has been consumed by `text`/`save`/draining.
    field: Mutex<Option<multer::Field<'static>>>,
    max_field_bytes: u64,
    max_file_bytes: u64,
    /// The configured `[multipart] upload_dir`; `None` leaves `save`
    /// unavailable.
    upload_root: Option<Arc<PathBuf>>,
}

impl LuaPart {
    pub(crate) fn new(
        field: multer::Field<'static>,
        max_field_bytes: u64,
        max_file_bytes: u64,
        upload_root: Option<Arc<PathBuf>>,
    ) -> Self {
        let filename = field.file_name().map(str::to_string);
        Self {
            name: field.name().unwrap_or_default().to_string(),
            safe_filename: filename.as_deref().map(safe_filename),
            filename,
            content_type: field.content_type().map(|m| m.to_string()),
            field: Mutex::new(Some(field)),
            max_field_bytes,
            max_file_bytes,
            upload_root,
        }
    }

    /// Resolves a Lua-supplied path to the file `save` may open, or
    /// refuses it by name.
    ///
    /// Runs *before* the field is taken, so a rejected path leaves the
    /// part unconsumed: the handler can catch the error and still
    /// `discard()` it or retry with `safe_filename`.
    async fn resolve_target(&self, rel: &str) -> mlua::Result<PathBuf> {
        let Some(root) = &self.upload_root else {
            return Err(mlua::Error::RuntimeError(
                "part:save() requires an upload directory: set [multipart] upload_dir in \
                 nitr.toml to the root every saved file must land inside"
                    .into(),
            ));
        };
        resolve_upload_path(root, rel).await
    }
}

impl LuaPart {
    /// Takes the field out, leaving the part consumed.
    fn take(&self) -> mlua::Result<multer::Field<'static>> {
        self.field
            .lock()
            .map_err(|_| mlua::Error::RuntimeError("the multipart part lock is poisoned".into()))?
            .take()
            .ok_or_else(|| {
                mlua::Error::RuntimeError(format!(
                    "multipart part `{}` has already been read: a part is a stream, \
                     not a buffer, and can only be consumed once",
                    self.name
                ))
            })
    }

    /// Reclaims the field so the parser can move on, whether or not the
    /// callback consumed it.
    pub(crate) fn reclaim(&self) -> Option<multer::Field<'static>> {
        self.field.lock().ok()?.take()
    }
}

impl UserData for LuaPart {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("name", |_, part| Ok(part.name.clone()));
        // `nil` for an ordinary field; a string for a file upload. This is
        // the documented way to tell the two apart.
        fields.add_field_method_get("filename", |_, part| Ok(part.filename.clone()));
        // The same name reduced to something that can only ever name a
        // file directly inside the upload root: `nil` exactly when
        // `filename` is, so `if part.safe_filename then` remains the same
        // "is this a file?" test.
        fields.add_field_method_get("safe_filename", |_, part| Ok(part.safe_filename.clone()));
        fields.add_field_method_get("content_type", |_, part| Ok(part.content_type.clone()));
    }

    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // part:text() — the whole part as a Lua string, bounded by
        // `[limits] max_field_bytes`. Meant for ordinary fields; reading a
        // large upload this way is what the limit exists to prevent.
        methods.add_async_method("text", |lua, part, ()| async move {
            let mut field = part.take()?;
            let limit = part.max_field_bytes;
            let mut buf = Vec::new();
            while let Some(chunk) = field.chunk().await.into_lua_err()? {
                if buf.len() as u64 + chunk.len() as u64 > limit {
                    return Err(too_large(&part.name, "field", limit));
                }
                buf.extend_from_slice(&chunk);
            }
            lua.create_string(buf)
        });

        // part:save(path) — streams the part to disk without it ever
        // entering the Lua heap. `path` is relative to
        // `[multipart] upload_dir` and cannot escape it. Returns the
        // number of bytes written.
        methods.add_async_method("save", |_, part, rel: String| async move {
            // Containment first: a refused path must not consume the part
            // and must not have created anything.
            let target = part.resolve_target(&rel).await?;
            let path = target.display().to_string();
            let mut field = part.take()?;
            let limit = part.max_file_bytes;
            let mut file = tokio::fs::File::create(&target).await.map_err(|err| {
                mlua::Error::RuntimeError(format!("failed to create `{rel}`: {err}"))
            })?;

            let mut written: u64 = 0;
            let result = async {
                while let Some(chunk) = field.chunk().await.into_lua_err()? {
                    written += chunk.len() as u64;
                    if written > limit {
                        return Err(too_large(&part.name, "file", limit));
                    }
                    write_all(&mut file, &chunk, &path).await?;
                }
                flush(&mut file, &path).await
            }
            .await;

            if let Err(err) = result {
                // A failed upload must not leave a truncated file behind
                // for the application to trip over later. This runs only
                // for a path that already passed containment, so the
                // unlink cannot reach outside the upload root.
                drop(file);
                let _ = tokio::fs::remove_file(&target).await;
                return Err(err);
            }
            Ok(written)
        });

        // part:discard() — skip a part the handler does not want, without
        // reading it into memory.
        methods.add_async_method("discard", |_, part, ()| async move {
            let mut field = part.take()?;
            let mut skipped: u64 = 0;
            while let Some(chunk) = field.chunk().await.into_lua_err()? {
                skipped += chunk.len() as u64;
            }
            Ok(skipped)
        });
    }
}

pub(super) fn too_large(name: &str, kind: &str, limit: u64) -> mlua::Error {
    mlua::Error::RuntimeError(format!(
        "multipart {kind} `{name}` exceeds the {limit} byte limit"
    ))
}

async fn write_all(file: &mut tokio::fs::File, chunk: &Bytes, path: &str) -> mlua::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    file.write_all(chunk)
        .await
        .map_err(|err| mlua::Error::RuntimeError(format!("failed writing to `{path}`: {err}")))
}

async fn flush(file: &mut tokio::fs::File, path: &str) -> mlua::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    file.flush()
        .await
        .map_err(|err| mlua::Error::RuntimeError(format!("failed writing to `{path}`: {err}")))
}
