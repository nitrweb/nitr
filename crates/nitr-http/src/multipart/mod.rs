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
//!
//! # Where a saved file may land
//!
//! `part:save(path)` is the only filesystem *write* Lua can reach, and
//! both of its inputs are attacker-influenced: the path is a Lua string
//! built by the handler, and `part.filename` is a header the client chose.
//! So the path is resolved against the configured `[multipart]
//! upload_dir` and never escapes it — the lexical rule is shared with
//! static serving ([`crate::safe_path`]), and the parent is canonicalized
//! so a symlinked directory cannot lead out either. With no `upload_dir`
//! configured, `save` is unavailable rather than unconstrained.
//!
//! Two residuals are documented rather than closed. Both need an
//! attacker who *already* has write access inside the upload root — a
//! separate local process, not an HTTP client — so they are a hardening
//! gap, not a way in:
//!
//! - **A symlink swapped between check and open.** `symlink_metadata`
//!   runs before `File::create`, and nothing holds the directory still in
//!   between. `O_NOFOLLOW` (or `FILE_FLAG_OPEN_REPARSE_POINT`) would close
//!   it, which means a `libc`/`rustix` dependency the workspace does not
//!   carry.
//! - **A pre-existing hardlink.** A hardlink inside the root pointing at
//!   an inode outside it reports as an ordinary regular file — there is
//!   nothing in its metadata to distinguish it — so it passes the
//!   `is_file` check and `File::create` truncates through it. Note this
//!   one is *not* covered by `O_NOFOLLOW`: closing it needs writing to a
//!   fresh temporary name and renaming into place, or an `st_nlink`/
//!   `st_dev` check on the opened descriptor.

use mlua::ExternalResult as _;
mod part;
#[cfg(test)]
mod tests;
mod upload;

pub(crate) use part::LuaPart;
use part::too_large;
pub use upload::{resolve_upload_path, safe_filename};

/// What a fuzzed multipart walk observed: how many parts were admitted,
/// and the largest number of bytes any single field yielded.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipartWalk {
    /// Parts admitted (never above `max_parts`).
    pub parts: usize,
    /// The largest single field, in bytes (never above
    /// `max_field_bytes`).
    pub largest_field: u64,
}

/// Drives the whole multipart parse over an in-memory body the way
/// `req:multipart()` does — boundary extraction, part counting against
/// `max_parts`, and the per-field byte cap applied while reading — but
/// without a Lua state or disk writes. Exposed for the fuzz target only;
/// the Lua-facing `LuaPart` methods are covered by the integration tests.
///
/// `chunk_size` splits the body into that many bytes per stream frame
/// (`0` means one frame for the whole body). A real body arrives from
/// hyper as many frames, and multer carries boundary-matching state
/// across them — the delimiter, and the CRLF before it, can straddle a
/// frame edge. Feeding one frame would leave that state machine, the
/// most intricate part of the parser, entirely unexercised.
#[doc(hidden)]
pub async fn consume_for_fuzzing(
    content_type: Option<&str>,
    body: bytes::Bytes,
    chunk_size: usize,
    max_parts: usize,
    max_field_bytes: u64,
) -> mlua::Result<MultipartWalk> {
    let boundary = boundary(content_type)?;
    let frames: Vec<bytes::Bytes> = match chunk_size {
        0 => vec![body],
        n => body.chunks(n).map(bytes::Bytes::copy_from_slice).collect(),
    };
    let stream = futures_util::stream::iter(
        frames
            .into_iter()
            .map(Ok::<_, std::convert::Infallible>)
            .collect::<Vec<_>>(),
    );
    let mut parser = multer::Multipart::new(stream, boundary);
    let mut walk = MultipartWalk {
        parts: 0,
        largest_field: 0,
    };
    while let Some(mut field) = parser.next_field().await.into_lua_err()? {
        walk.parts += 1;
        if walk.parts > max_parts {
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
        walk.largest_field = walk.largest_field.max(read);
    }
    Ok(walk)
}

/// The `boundary` parameter of a `multipart/form-data` content type.
pub(crate) fn boundary(content_type: Option<&str>) -> mlua::Result<String> {
    let content_type = content_type.ok_or_else(|| {
        mlua::Error::RuntimeError("req:multipart() requires a Content-Type header".into())
    })?;
    let boundary = multer::parse_boundary(content_type).map_err(|_| {
        mlua::Error::RuntimeError(format!(
            "req:multipart() requires a multipart/form-data body, got `{content_type}`"
        ))
    })?;
    // The mime parser accepts `boundary=` (and `boundary=""`) with an
    // empty value; RFC 2046 requires 1–70 characters, and an empty
    // delimiter would make every `--` line a part separator. Refuse it
    // rather than hand the parser a degenerate delimiter.
    if boundary.is_empty() {
        return Err(mlua::Error::RuntimeError(format!(
            "req:multipart() requires a non-empty boundary parameter, got `{content_type}`"
        )));
    }
    Ok(boundary)
}
