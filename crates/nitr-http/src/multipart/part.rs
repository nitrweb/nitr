// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! [`LuaPart`]: the one-shot part handle handed to the Lua callback —
//! `text`, `save` (streaming socket → disk), and `discard`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hyper::body::Bytes;
use mlua::{ExternalResult as _, UserData, UserDataFields, UserDataMethods};

use super::upload::{resolve_upload_path, safe_filename};
use crate::validation::spool::SPOOL_DIR;

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
        resolve_upload_path(self.upload_root()?, rel).await
    }

    fn upload_root(&self) -> mlua::Result<&Path> {
        self.upload_root
            .as_deref()
            .map(PathBuf::as_path)
            .ok_or_else(|| {
                mlua::Error::RuntimeError(
                    "part:save() requires an upload directory: set [multipart] upload_dir in \
                 nitr.toml to the root every saved file must land inside"
                        .into(),
                )
            })
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
            // Streaming into `target` itself would truncate an existing
            // file before the upload is known to succeed; a failed upload
            // then destroys what it was meant to replace.
            let spool = part.upload_root()?.join(SPOOL_DIR);
            let (pending, mut file) = PendingFile::create(&spool).await.map_err(|err| {
                mlua::Error::RuntimeError(format!("failed to create `{rel}`: {err}"))
            })?;

            let mut written: u64 = 0;
            let streamed = async {
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
            drop(file);
            if let Err(err) = streamed {
                pending.discard().await;
                return Err(err);
            }
            pending.persist(&target).await.map_err(|err| {
                mlua::Error::RuntimeError(format!("failed to save `{rel}`: {err}"))
            })?;
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

/// A part staged in the upload root's spool and renamed into place.
/// Settled by `persist` or `discard`, which finish before they return;
/// dropped unsettled, because the budget dropped the whole save, it
/// removes itself. A process killed mid-save leaves it to the spool sweep
/// at the next boot.
struct PendingFile {
    path: PathBuf,
    settled: bool,
}

impl PendingFile {
    /// The spool is inside the upload root, like the target, so the rename
    /// stays on one filesystem (as `File:save`'s does).
    async fn create(spool: &Path) -> std::io::Result<(Self, tokio::fs::File)> {
        tokio::fs::create_dir_all(spool).await?;
        let path = spool.join(format!("save-{}", uuid::Uuid::now_v7().simple()));
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await?;
        let pending = Self {
            path,
            settled: false,
        };
        Ok((pending, file))
    }

    async fn persist(mut self, target: &Path) -> std::io::Result<()> {
        let renamed = tokio::fs::rename(&self.path, target).await;
        if renamed.is_err() {
            let _ = tokio::fs::remove_file(&self.path).await;
        }
        self.settled = true;
        renamed
    }

    async fn discard(mut self) {
        let _ = tokio::fs::remove_file(&self.path).await;
        self.settled = true;
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let path = std::mem::take(&mut self.path);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(move || std::fs::remove_file(path));
            }
            Err(_) => {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

pub(crate) fn too_large(name: &str, kind: &str, limit: u64) -> mlua::Error {
    mlua::Error::external(LimitExceeded(format!(
        "multipart {kind} `{name}` exceeds the {limit} byte limit"
    )))
}

pub(crate) fn too_many_parts(max_parts: usize) -> mlua::Error {
    mlua::Error::external(LimitExceeded(format!(
        "multipart body has more than {max_parts} parts"
    )))
}

/// A multipart limit the request crossed. The client's doing: uncaught, it
/// answers 413 like `[limits] max_body_bytes`, not as a handler failure.
#[derive(Debug)]
pub(crate) struct LimitExceeded(String);

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LimitExceeded {}

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
