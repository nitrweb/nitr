// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr.File`: a validated upload. The bytes live in a temporary file the
//! server spooled; Lua holds a handle with what detection learned and can
//! keep the file (`save`), read a small one (`text`), hash it, or drop it.
//! A file neither saved nor discarded is removed when the handle goes.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use mlua::{ExternalResult as _, UserData, UserDataFields, UserDataMethods};

use super::media::{self, Detection};

/// Resolves a Lua-supplied relative path to the file `save` may rename
/// the temporary to — the server's containment rule, injected so this
/// module knows nothing about upload roots.
pub type SaveResolver = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = mlua::Result<PathBuf>> + Send>> + Send + Sync,
>;

/// What the spooler learned about an upload.
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// The client's file name, raw.
    pub filename: Option<String>,
    /// The name reduced to one safe path segment.
    pub safe_filename: Option<String>,
    /// The lowercase last suffix of the safe name, without the dot.
    pub extension: Option<String>,
    /// The `Content-Type` the client declared for the part.
    pub declared_type: Option<String>,
    /// What the first bytes said.
    pub detected: Detection,
    /// Whether the declared text subtype's structure was present.
    pub text_subtype_ok: bool,
    /// Bytes spooled.
    pub size: u64,
    /// Image dimensions when the header carried them.
    pub width: Option<u32>,
    /// See `width`.
    pub height: Option<u32>,
    /// Whether every byte was valid UTF-8 (`None` when not checked).
    pub utf8: Option<bool>,
}

impl FileInfo {
    /// The media type this file is treated as: the detected type when
    /// there is one; for text, the declared subtype when it is a text type
    /// whose structure matched, else `text/plain`; otherwise the declared
    /// header only when nothing in the table would have detected it.
    pub fn effective_type(&self) -> &str {
        match self.detected {
            Detection::Detected(media) => media.name,
            Detection::Executable => media::EXECUTABLE_TYPE,
            Detection::Text => match self.declared_type.as_deref() {
                Some(declared)
                    if media::lookup(declared).is_some_and(|m| m.tier == media::Tier::Text)
                        && self.text_subtype_ok =>
                {
                    declared
                }
                _ => "text/plain",
            },
            Detection::Unknown => match self.declared_type.as_deref() {
                Some(declared)
                    if media::lookup(declared).is_some_and(|m| m.tier == media::Tier::Header) =>
                {
                    declared
                }
                _ => media::UNKNOWN_TYPE,
            },
        }
    }

    /// Whether the file is an executable by bytes or by extension.
    pub fn is_executable(&self) -> bool {
        self.detected == Detection::Executable
            || self
                .extension
                .as_deref()
                .is_some_and(media::executable_extension)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Spooled,
    Saved,
    Discarded,
}

/// The `nitr.File` userdata.
pub struct LuaFile {
    info: FileInfo,
    path: PathBuf,
    state: Mutex<State>,
    resolver: SaveResolver,
    max_text_bytes: u64,
}

impl LuaFile {
    /// A handle over a spooled temporary.
    pub fn new(info: FileInfo, path: PathBuf, resolver: SaveResolver, max_text_bytes: u64) -> Self {
        Self {
            info,
            path,
            state: Mutex::new(State::Spooled),
            resolver,
            max_text_bytes,
        }
    }

    /// What detection learned.
    pub fn info(&self) -> &FileInfo {
        &self.info
    }

    fn state(&self) -> State {
        self.state.lock().map(|s| *s).unwrap_or(State::Discarded)
    }

    fn set_state(&self, state: State) {
        if let Ok(mut s) = self.state.lock() {
            *s = state;
        }
    }

    fn require_spooled(&self) -> mlua::Result<()> {
        match self.state() {
            State::Spooled => Ok(()),
            State::Saved => Err(mlua::Error::RuntimeError(
                "the file was already saved; read it from where it was saved".into(),
            )),
            State::Discarded => Err(mlua::Error::RuntimeError(
                "the file was already discarded".into(),
            )),
        }
    }
}

impl Drop for LuaFile {
    fn drop(&mut self) {
        // Best effort: the server's per-request guard removes the whole
        // spool directory as well.
        if self.state() == State::Spooled {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl UserData for LuaFile {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("filename", |_, f| Ok(f.info.filename.clone()));
        fields.add_field_method_get("safe_filename", |_, f| Ok(f.info.safe_filename.clone()));
        fields.add_field_method_get("extension", |_, f| Ok(f.info.extension.clone()));
        fields.add_field_method_get("content_type", |_, f| {
            Ok(f.info.effective_type().to_string())
        });
        fields.add_field_method_get("size", |_, f| Ok(f.info.size));
        fields.add_field_method_get("width", |_, f| Ok(f.info.width));
        fields.add_field_method_get("height", |_, f| Ok(f.info.height));
    }

    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // file:save(rel) -> path: renames the temporary into the upload
        // root (atomic on the same filesystem), through the server's
        // containment rule.
        methods.add_async_method("save", |_, file, rel: String| async move {
            file.require_spooled()?;
            let target = (file.resolver)(rel.clone()).await?;
            tokio::fs::rename(&file.path, &target)
                .await
                .map_err(|err| {
                    mlua::Error::RuntimeError(format!("failed to save `{rel}`: {err}"))
                })?;
            file.set_state(State::Saved);
            Ok(target.display().to_string())
        });

        // file:text() -> string: the contents, only for a small file.
        methods.add_async_method("text", |lua, file, ()| async move {
            file.require_spooled()?;
            if file.info.size > file.max_text_bytes {
                return Err(mlua::Error::RuntimeError(format!(
                    "file:text() reads at most {} bytes ([limits] max_field_bytes); this file has {}",
                    file.max_text_bytes, file.info.size
                )));
            }
            let bytes = tokio::fs::read(&file.path).await.into_lua_err()?;
            lua.create_string(bytes)
        });

        // file:hash(algo?) -> hex: streamed from disk; sha256 only today.
        methods.add_async_method("hash", |_, file, algo: Option<String>| async move {
            file.require_spooled()?;
            if let Some(algo) = &algo
                && algo != "sha256"
            {
                return Err(mlua::Error::RuntimeError(format!(
                    "file:hash(): unknown algorithm `{algo}` (supported: sha256)"
                )));
            }
            use sha2::Digest as _;
            use tokio::io::AsyncReadExt as _;
            let mut reader = tokio::fs::File::open(&file.path).await.into_lua_err()?;
            let mut hasher = sha2::Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buf).await.into_lua_err()?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex(&hasher.finalize()))
        });

        // file:discard(): drop the temporary now.
        methods.add_async_method("discard", |_, file, ()| async move {
            file.require_spooled()?;
            let _ = tokio::fs::remove_file(&file.path).await;
            file.set_state(State::Discarded);
            Ok(())
        });
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
