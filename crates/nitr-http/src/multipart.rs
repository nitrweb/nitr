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

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hyper::body::Bytes;
use mlua::{ExternalResult as _, UserData, UserDataFields, UserDataMethods};

use crate::safe_path::{Rejected, safe_join};

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

/// The whole containment rule for `part:save`, as a free function so the
/// `upload_resolve` fuzz target can drive it without a live multipart
/// field — and so the one invariant that matters ("every path this
/// returns is inside the canonicalized root") has a single home to state
/// it in.
#[doc(hidden)]
pub async fn resolve_upload_path(root: &std::path::Path, rel: &str) -> mlua::Result<PathBuf> {
    let joined = safe_join(root, rel).map_err(|why| {
        let detail = match why {
            Rejected::Traversal => "it climbs out of the upload directory",
            Rejected::Absolute => {
                "it is an absolute path, and paths are relative to the upload directory"
            }
            Rejected::Nul => "it contains a NUL byte",
        };
        mlua::Error::RuntimeError(format!(
            "part:save() refused `{rel}`: {detail} ({})",
            root.display()
        ))
    })?;
    if joined == root {
        return Err(mlua::Error::RuntimeError(format!(
            "part:save() refused `{rel}`: it names the upload directory itself, not a \
             file inside it"
        )));
    }

    // The file does not exist yet, so the containment check
    // canonicalizes its *parent* — which does — and re-checks the
    // prefix there. This is what catches a symlinked intermediate
    // directory pointing out of the root, which the lexical rule
    // alone cannot see.
    let (parent, name) = match (joined.parent(), joined.file_name()) {
        (Some(parent), Some(name)) => (parent, name.to_os_string()),
        _ => {
            return Err(mlua::Error::RuntimeError(format!(
                "part:save() refused `{rel}`: it is not a file name"
            )));
        }
    };
    let canonical_root = tokio::fs::canonicalize(root).await.map_err(|err| {
        mlua::Error::RuntimeError(format!(
            "part:save() cannot resolve the upload directory {}: {err}",
            root.display()
        ))
    })?;
    // Missing intermediate directories are an error, not an implicit
    // `create_dir_all`: deciding the on-disk shape of an upload tree
    // is the application's job, and materializing directories from
    // attacker-influenced strings is not a favour.
    let canonical_parent = tokio::fs::canonicalize(parent).await.map_err(|err| {
        mlua::Error::RuntimeError(format!(
            "part:save() cannot write `{rel}`: its directory is not usable: {err}"
        ))
    })?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(mlua::Error::RuntimeError(format!(
            "part:save() refused `{rel}`: its directory resolves outside the upload \
             directory {}",
            root.display()
        )));
    }

    // The final component is checked with `symlink_metadata` (which
    // does not follow) *before* the open, because `File::create`
    // truncates whatever it lands on: a link checked afterwards has
    // already been written through.
    let target = canonical_parent.join(&name);
    match tokio::fs::symlink_metadata(&target).await {
        Ok(meta) if meta.file_type().is_symlink() => Err(mlua::Error::RuntimeError(format!(
            "part:save() refused `{rel}`: it is a symlink, and following one would write \
             through the upload directory"
        ))),
        Ok(meta) if !meta.is_file() => Err(mlua::Error::RuntimeError(format!(
            "part:save() refused `{rel}`: it already exists and is not a regular file"
        ))),
        Ok(_) => Ok(target),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(target),
        Err(err) => Err(mlua::Error::RuntimeError(format!(
            "part:save() cannot inspect `{rel}`: {err}"
        ))),
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

/// The longest a single path component may be on the filesystems Nitr
/// targets (`NAME_MAX`).
const NAME_MAX: usize = 255;

/// The fallback when nothing survives sanitizing.
///
/// A fixed string rather than `nil`: an empty or absent name would push an
/// emptiness check into every handler, which is the same "the application
/// must remember" failure the raw filename already is.
const FALLBACK_NAME: &str = "upload";

/// Reduces a client-sent filename to something that can only ever name a
/// file directly inside the upload root.
///
/// `part.filename` stays raw on purpose — it is what the client sent, and
/// applications legitimately record it — so this is a second value, not a
/// replacement. By construction the result contains no path separator, so
/// `part:save(part.safe_filename)` is safe on its own and the upload root
/// is a backstop rather than the only defense.
#[doc(hidden)]
pub fn safe_filename(raw: &str) -> String {
    // Only the last segment is a name; a client may send a whole path,
    // and both separators count because the sender's OS is not ours.
    let last = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    // C0/C1 controls and NUL: a name the OS would refuse opaquely, or
    // that would truncate a log line.
    let cleaned: String = last.chars().filter(|c| !c.is_control()).collect();
    // Leading dots hide the file; trailing dots and spaces are silently
    // dropped by some filesystems, which makes two names collide. Both
    // classes are trimmed in one pass rather than chained — `". . "`
    // alternates, so `trim().trim_matches('.').trim()` leaves a dot
    // behind on the second alternation.
    let trimmed = cleaned.trim_matches(|c: char| c == '.' || c.is_whitespace());

    let mut out = String::new();
    for ch in trimmed.chars() {
        if out.len() + ch.len_utf8() > NAME_MAX {
            break;
        }
        out.push(ch);
    }
    if out.is_empty() || out == "." || out == ".." {
        return FALLBACK_NAME.to_string();
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `safe_filename`'s whole contract: whatever the client sent, the
    /// result names a plain file and nothing else. The upload root is the
    /// backstop for `part:save(anything)`; this is what makes
    /// `part:save(part.safe_filename)` safe on its own.
    #[test]
    fn safe_filename_always_yields_a_plain_name() {
        // The ordinary case is left alone.
        assert_eq!(safe_filename("report.pdf"), "report.pdf");
        // Only the last segment survives, for both separators — the
        // sender's OS is not necessarily ours.
        assert_eq!(safe_filename("../../etc/passwd"), "passwd");
        assert_eq!(safe_filename("C:\\Windows\\evil.exe"), "evil.exe");
        assert_eq!(safe_filename("/absolute/name.txt"), "name.txt");
        // Control characters and NUL cannot survive into a path.
        assert_eq!(safe_filename("a\0b\u{7}c.txt"), "abc.txt");
        // Leading dots (hidden files) and trailing dots/spaces (silently
        // dropped by some filesystems, so two names would collide).
        assert_eq!(safe_filename(".hidden"), "hidden");
        assert_eq!(safe_filename("name.txt. . "), "name.txt");
        // Nothing survives: a fixed name, never an empty string, because
        // an empty name is a write to the directory itself.
        for empty in ["", "   ", "...", "..", ".", "/", "\\", "\0"] {
            assert_eq!(safe_filename(empty), FALLBACK_NAME, "input: {empty:?}");
        }
        // Truncated to NAME_MAX on a character boundary, never mid-glyph.
        let long = safe_filename(&"é".repeat(500));
        assert!(long.len() <= NAME_MAX, "{} bytes", long.len());
        assert!(
            std::str::from_utf8(long.as_bytes()).is_ok(),
            "truncation split a character"
        );
        // The invariant every caller leans on.
        for raw in [
            "../../etc/passwd",
            "C:\\Windows\\evil.exe",
            "a\0b",
            "...",
            "sub/dir/file",
        ] {
            let safe = safe_filename(raw);
            assert!(!safe.contains('/') && !safe.contains('\\'), "{safe:?}");
            assert!(!safe.is_empty(), "{raw:?} produced an empty name");
        }
    }

    /// The containment rule, against a real directory: every shape from
    /// the phase's decision table, each refused for its own stated reason.
    #[tokio::test]
    async fn upload_paths_resolve_inside_the_root_or_are_refused() {
        let root = std::env::temp_dir().join(format!("nitr-upload-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("img")).expect("mkdir");
        let canonical = root.canonicalize().expect("canonicalize");

        // Accepted: a plain name, and a nested one whose directory exists.
        for ok in ["a.png", "img/a.png", "./img/a.png"] {
            let resolved = resolve_upload_path(&root, ok)
                .await
                .unwrap_or_else(|err| panic!("`{ok}` must resolve: {err}"));
            assert!(
                resolved.starts_with(&canonical),
                "`{ok}` resolved outside the root: {}",
                resolved.display()
            );
        }

        // Refused, each naming the rule it hit.
        for (bad, expected) in [
            ("../../etc/cron.d/x", "climbs out"),
            ("img/../../x", "climbs out"),
            ("/etc/cron.d/x", "absolute path"),
            ("a\0b", "NUL byte"),
            ("", "names the upload directory itself"),
            (".", "names the upload directory itself"),
            ("..", "climbs out"),
            ("missing/a.png", "directory is not usable"),
            ("img", "not a regular file"),
        ] {
            let err = resolve_upload_path(&root, bad)
                .await
                .expect_err(&format!("`{bad}` must be refused"));
            assert!(
                err.to_string().contains(expected),
                "`{bad}` must be refused as `{expected}`, got: {err}"
            );
        }

        // A symlink out of the root is refused as the final component and
        // as an intermediate directory: the lexical rule cannot see
        // either, only the canonicalized checks can.
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside =
                std::env::temp_dir().join(format!("nitr-upload-out-{}", std::process::id()));
            std::fs::create_dir_all(&outside).expect("mkdir outside");
            symlink(&outside, root.join("link-dir")).expect("symlink dir");
            symlink(outside.join("target.txt"), root.join("link-file")).expect("symlink file");

            let err = resolve_upload_path(&root, "link-file")
                .await
                .expect_err("a symlinked final component must be refused");
            assert!(err.to_string().contains("symlink"), "got: {err}");

            let err = resolve_upload_path(&root, "link-dir/a.png")
                .await
                .expect_err("a symlinked parent must be refused");
            assert!(err.to_string().contains("outside the upload"), "got: {err}");
            let _ = std::fs::remove_dir_all(&outside);
        }

        let _ = std::fs::remove_dir_all(&root);
    }

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
        // Found by the boundary proptest: the mime parser hands back an
        // *empty* boundary for these, which RFC 2046 forbids and which
        // would make every `--` line a delimiter.
        assert!(
            boundary(Some("multipart/form-data;boundary=")).is_err(),
            "empty boundary value"
        );
        assert!(
            boundary(Some(r#"multipart/form-data; boundary="""#)).is_err(),
            "empty quoted boundary"
        );
    }

    /// The parameter-syntax corners an attacker actually controls: quoted
    /// values (with spaces and `;` inside the quotes), duplicate
    /// `boundary=` parameters, and surrounding parameter noise.
    #[test]
    fn boundary_handles_quoting_and_duplicate_parameters() {
        // A quoted value comes back unquoted.
        assert_eq!(
            boundary(Some(r#"multipart/form-data; boundary="XyZ09""#)).expect("quoted"),
            "XyZ09"
        );
        // Quoting admits characters a bare token cannot carry.
        assert_eq!(
            boundary(Some(r#"multipart/form-data; boundary="a b;c""#)).expect("quoted specials"),
            "a b;c"
        );
        // Other parameters around the boundary do not confuse extraction.
        assert_eq!(
            boundary(Some("multipart/form-data; charset=utf-8; boundary=B1; x=y"))
                .expect("with neighbors"),
            "B1"
        );
        // Duplicate boundary parameters must not smuggle a second value
        // past whichever one the server picked: the outcome is pinned so
        // a behavior change here is a visible diff, not a silent one.
        let dup = boundary(Some("multipart/form-data; boundary=first; boundary=second"));
        assert_eq!(dup.expect("duplicate params"), "first");
    }

    /// The Rust-side byte caps fire while *reading*, before anything is
    /// handed to Lua: an oversized field is refused at `max_field_bytes`
    /// and an over-count body at `max_parts`, both with the limit named.
    #[tokio::test]
    async fn field_and_part_caps_fire_while_reading() {
        fn part(name: &str, payload: &str) -> String {
            format!("--B\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{payload}\r\n")
        }
        let ct = Some("multipart/form-data; boundary=B");

        // Within both caps: parses, counting every part.
        let ok = format!("{}{}--B--\r\n", part("a", "small"), part("b", "tiny"));
        let walk = consume_for_fuzzing(ct, Bytes::from(ok.clone()), 0, 4, 64)
            .await
            .expect("well-formed body within the caps");
        assert_eq!(walk.parts, 2);
        assert_eq!(walk.largest_field, 5, "`small` is the larger field");

        // The same body split into single-byte frames must parse
        // identically: the delimiter and its leading CRLF then straddle
        // frame edges, which is where multer's boundary state machine
        // lives.
        let chunked = consume_for_fuzzing(ct, Bytes::from(ok.clone()), 1, 4, 64)
            .await
            .expect("a frame-split body parses the same");
        assert_eq!(chunked, walk, "framing must not change the parse");

        // One field over the byte cap: refused, and the limit is named so
        // the operator knows which knob was hit.
        let big = format!("{}--B--\r\n", part("a", &"x".repeat(100)));
        let err = consume_for_fuzzing(ct, Bytes::from(big), 0, 4, 32)
            .await
            .expect_err("an oversized field must be refused");
        assert!(
            err.to_string().contains("exceeds the 32 byte limit"),
            "got: {err}"
        );

        // One part over the count cap: refused, naming the count.
        let err = consume_for_fuzzing(ct, Bytes::from(ok), 0, 1, 64)
            .await
            .expect_err("a third part beyond max_parts must be refused");
        assert!(err.to_string().contains("more than 1 parts"), "got: {err}");
    }

    proptest::proptest! {
        /// Property: boundary extraction is total over arbitrary header
        /// text — the content type is fully attacker-controlled — and any
        /// boundary it *does* accept came from a multipart content type
        /// that actually carried a boundary parameter. (The second half is
        /// what makes this a property rather than a smoke test: a
        /// `boundary()` that returned something for `application/json`
        /// would fail here.)
        #[test]
        fn prop_boundary_parsing_is_total_and_only_multipart_yields(
            content_type in proptest::prop_oneof![
                // Unstructured attacker input.
                "[ -~]{0,60}",
                // Near-miss mutations that keep the parser in its
                // interesting states instead of bailing at the type check.
                "multipart/(form-data|mixed|x)([;,][ -~]{0,40})?",
                "multipart/form-data; ?boundary=[ -~]{0,35}",
            ],
        ) {
            if let Ok(b) = boundary(Some(&content_type)) {
                let ct = content_type.trim_start().to_ascii_lowercase();
                proptest::prop_assert!(
                    ct.starts_with("multipart/"),
                    "`{content_type}` is not multipart but yielded `{b}`"
                );
                proptest::prop_assert!(
                    ct.contains("boundary"),
                    "`{content_type}` names no boundary but yielded `{b}`"
                );
                proptest::prop_assert!(!b.is_empty(), "`{content_type}` yielded an empty boundary");
            }
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
