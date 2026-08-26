// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `multipart/form-data` parsing, with the parser and every limit on the
//! Rust side.
//!
//! The invariant that shapes this API: **an uploaded file never passes
//! through the Lua state's heap.** A state has an 8 MiB memory limit by
//! default, so a buffered-then-handed-over design would make "upload a
//! file" mean "crash the state". `part:save(path)` streams socket → disk in
//! Rust and Lua only ever holds a handle.
//!
//! That is also why parts are delivered to a callback rather than collected
//! into a table first. Collecting would mean either buffering everything
//! (the thing we are avoiding) or spooling to temp files, which needs a
//! reaper and a disk-space policy. Streaming each part as it arrives needs
//! neither, at the cost of the handler seeing parts in the order the client
//! sent them.

use std::sync::Mutex;

use hyper::body::Bytes;
use mlua::{ExternalResult as _, UserData, UserDataFields, UserDataMethods};

/// A `multipart/form-data` part handed to the Lua callback.
///
/// The field is taken on first use: a part is a one-shot stream, not a
/// buffer that can be read twice.
pub(crate) struct LuaPart {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    /// `None` once the part has been consumed by `text`/`save`/draining.
    field: Mutex<Option<multer::Field<'static>>>,
    max_field_bytes: u64,
    max_file_bytes: u64,
}

impl LuaPart {
    pub(crate) fn new(
        field: multer::Field<'static>,
        max_field_bytes: u64,
        max_file_bytes: u64,
    ) -> Self {
        Self {
            name: field.name().unwrap_or_default().to_string(),
            filename: field.file_name().map(str::to_string),
            content_type: field.content_type().map(|m| m.to_string()),
            field: Mutex::new(Some(field)),
            max_field_bytes,
            max_file_bytes,
        }
    }

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
        // entering the Lua heap. Returns the number of bytes written.
        methods.add_async_method("save", |_, part, path: String| async move {
            let mut field = part.take()?;
            let limit = part.max_file_bytes;
            let mut file = tokio::fs::File::create(&path).await.map_err(|err| {
                mlua::Error::RuntimeError(format!("failed to create `{path}`: {err}"))
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
                // A rejected or failed upload must not leave a truncated
                // file behind for the application to trip over later.
                drop(file);
                let _ = tokio::fs::remove_file(&path).await;
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

fn too_large(name: &str, kind: &str, limit: u64) -> mlua::Error {
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

/// Drives the whole multipart parse over an in-memory body the way
/// `req:multipart()` does — boundary extraction, part counting against
/// `max_parts`, and the per-field byte cap applied while reading — but
/// without a Lua state or disk writes. Exposed for the fuzz target only;
/// the Lua-facing `LuaPart` methods are covered by the integration tests.
#[doc(hidden)]
pub async fn consume_for_fuzzing(
    content_type: Option<&str>,
    body: bytes::Bytes,
    max_parts: usize,
    max_field_bytes: u64,
) -> mlua::Result<usize> {
    let boundary = boundary(content_type)?;
    let stream = futures_util::stream::once(async move { Ok::<_, std::convert::Infallible>(body) });
    let mut parser = multer::Multipart::new(stream, boundary);
    let mut count = 0usize;
    while let Some(mut field) = parser.next_field().await.into_lua_err()? {
        count += 1;
        if count > max_parts {
            return Err(mlua::Error::RuntimeError(format!(
                "multipart body has more than {max_parts} parts"
            )));
        }
        let mut read = 0u64;
        while let Some(chunk) = field.chunk().await.into_lua_err()? {
            read += chunk.len() as u64;
            if read > max_field_bytes {
                return Err(too_large("field", "field", max_field_bytes));
            }
        }
    }
    Ok(count)
}

/// The `boundary` parameter of a `multipart/form-data` content type.
pub(crate) fn boundary(content_type: Option<&str>) -> mlua::Result<String> {
    let content_type = content_type.ok_or_else(|| {
        mlua::Error::RuntimeError("req:multipart() requires a Content-Type header".into())
    })?;
    multer::parse_boundary(content_type).map_err(|_| {
        mlua::Error::RuntimeError(format!(
            "req:multipart() requires a multipart/form-data body, got `{content_type}`"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_extracts_and_rejects() {
        assert_eq!(
            boundary(Some("multipart/form-data; boundary=XyZ09")).expect("boundary"),
            "XyZ09"
        );
        assert!(boundary(None).is_err());
        assert!(boundary(Some("application/json")).is_err());
        assert!(
            boundary(Some("multipart/form-data")).is_err(),
            "no boundary parameter"
        );
    }

    proptest::proptest! {
        /// Property: boundary extraction is total over arbitrary header
        /// text — the content type is fully attacker-controlled.
        #[test]
        fn prop_boundary_parsing_is_total(content_type in "[ -~]{0,60}") {
            let _ = boundary(Some(&content_type));
        }

        /// Property: a well-formed content type round-trips its boundary
        /// token back out exactly. (Unquoted parameter values are HTTP
        /// tokens, so the alphabet stays inside token characters.)
        #[test]
        fn prop_wellformed_boundaries_round_trip(token in "[A-Za-z0-9][A-Za-z0-9._+-]{0,29}") {
            let content_type = format!("multipart/form-data; boundary={token}");
            proptest::prop_assert_eq!(boundary(Some(&content_type)).expect("boundary"), token);
        }
    }
}
