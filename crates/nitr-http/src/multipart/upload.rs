// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Where a saved upload may land and what it may be called: the
//! containment rule for `part:save` paths and the client-filename
//! sanitizer. See the module doc in `multipart` for the threat model.

use std::path::PathBuf;

use crate::safe_path::{Rejected, safe_join};

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

/// The longest a single path component may be on the filesystems Nitr
/// targets (`NAME_MAX`).
pub(super) const NAME_MAX: usize = 255;

/// The fallback when nothing survives sanitizing.
///
/// A fixed string rather than `nil`: an empty or absent name would push an
/// emptiness check into every handler, which is the same "the application
/// must remember" failure the raw filename already is.
pub(super) const FALLBACK_NAME: &str = "upload";

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
