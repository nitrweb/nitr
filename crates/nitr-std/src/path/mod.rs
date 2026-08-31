// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Lexical path manipulation for Lua handlers: `nitr.path`.
//!
//! Foundation string operations on paths — URL paths, mount points, file
//! names in multipart uploads. Both POSIX (`/`) and Windows (`\`, drive
//! letters, UNC) styles are understood: separators are recognized in
//! either form, and outputs keep the input's separator style.
//!
//! Parsing is hand-written over a canonicalized (`\` → `/`, root split
//! off) form of the input rather than delegated to [`std::path::Path`],
//! because `std::path` recognizes backslashes, root markers and drive
//! prefixes only when *compiled for* Windows — so the same input would
//! split differently depending on the server's OS, and a Lua script must
//! get the same answer from either. (`///a` and a `C:x` segment after a
//! UNC root are the cases that actually diverge; the normalize
//! idempotence property found them on Windows CI.) Lexical `..`
//! resolution has no std equivalent anyway: `canonicalize` reads the
//! filesystem, which is off-limits here.
//!
//! Everything here is pure text: nothing reads the filesystem, so the
//! sandbox story is unchanged, and `normalize` makes prefix checks on
//! untrusted input safe against dot-dot escapes.
//!
//! That guarantee is *lexical*, and lexical only. Win32 filename
//! canonicalization rewrites names before the filesystem sees them —
//! trailing dots and spaces are stripped (so the segment `".. "`, a
//! legitimate POSIX filename `normalize` rightly preserves, opens as
//! `..` on Windows) and a colon addresses an NTFS alternate data stream.
//! A prefix check over `normalize` output is therefore sound for URL
//! routing and mount matching, but code that hands the result to a real
//! Windows filesystem must additionally reject segments with trailing
//! dots or spaces and any colon past the drive prefix, or check
//! containment after the OS resolves the path — as Nitr's own static
//! file server does (`fs::canonicalize` on both sides of its prefix
//! check, so the filesystem's rewriting happens *before* the check).

use mlua::{Lua, Table, Value};

/// Whether the path is Windows-styled (backslashes or a drive prefix), so
/// outputs can keep the input's separator.
pub fn is_windows_style(path: &str) -> bool {
    path.contains('\\') || (!path.contains('/') && drive(path).is_some())
}

fn restyle(canonical: String, windows: bool) -> String {
    if windows {
        canonical.replace('/', "\\")
    } else {
        canonical
    }
}

/// The byte length of a leading `C:` drive prefix, if present.
fn drive(path: &str) -> Option<usize> {
    let mut chars = path.chars();
    (chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.next() == Some(':'))
        .then_some(2)
}

/// Splits a path into its root (`/`, `C:\`, `C:`, `\\` for UNC, or empty)
/// and the rest, both canonicalized to `/` separators. The root is split
/// off by hand because `std::path` only parses drive/UNC prefixes when
/// compiled for Windows.
pub fn split_root(path: &str) -> (String, String) {
    let canonical = path.replace('\\', "/");
    let root_len = if canonical.starts_with("//") {
        // UNC: both leading separators are the root marker.
        2
    } else {
        match drive(&canonical) {
            Some(d) if canonical[d..].starts_with('/') => d + 1,
            Some(d) => d,
            None if canonical.starts_with('/') => 1,
            None => 0,
        }
    };
    let (root, rest) = canonical.split_at(root_len);
    (root.to_string(), rest.to_string())
}

/// Splits a root-free, `/`-canonicalized path into its components,
/// following the rules `std::path::Components` documents — duplicate
/// separators collapse, and `.` is dropped except as the very first
/// component — but textually, so the answer never depends on the OS the
/// server was compiled for.
fn components(rest: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = Vec::new();
    for segment in rest.split('/') {
        if segment.is_empty() || (segment == "." && !parts.is_empty()) {
            continue;
        }
        parts.push(segment);
    }
    parts
}

/// Whether a root from [`split_root`] anchors the path — the single
/// definition [`is_absolute`] and `..` resolution share, so a path can
/// never be relative for one and rooted for the other.
fn root_is_anchor(root: &str) -> bool {
    // A bare drive (`C:`) is drive-relative, not absolute: it resolves
    // against that drive's current directory, so it is no floor.
    !root.is_empty() && !(root.len() == 2 && root.ends_with(':'))
}

/// Whether the path is absolute (`/x`, `C:\x`, or UNC).
pub fn is_absolute(path: &str) -> bool {
    root_is_anchor(&split_root(path).0)
}

/// Splits off the final component, e.g. `"/a/b/c.txt"` → `"c.txt"`.
pub fn basename(path: &str) -> String {
    let (_, rest) = split_root(path);
    match components(&rest).last() {
        // `.` and `..` name a directory, not a file — as with
        // `Path::file_name`, there is no basename to give.
        Some(name) if *name != "." && *name != ".." => (*name).to_string(),
        _ => String::new(),
    }
}

/// The directory part, without the trailing separator: `"/a/b/c"` →
/// `"/a/b"`, `"c"` → `"."`, `"/c"` → `"/"`, `"C:\\x"` → `"C:\\"`.
pub fn dirname(path: &str) -> String {
    let windows = is_windows_style(path);
    let (root, rest) = split_root(path);
    let parts = components(&rest);
    let out = match parts.split_last() {
        Some((_, parent)) if parent.is_empty() && root.is_empty() => ".".into(),
        Some((_, parent)) => format!("{root}{}", parent.join("/")),
        // No components: the rest was empty, so the root is all there is.
        None if root.is_empty() => ".".into(),
        None => root,
    };
    restyle(out, windows)
}

/// The extension of the final component, without the dot; nil when there
/// is none. Split at the last dot that is not the first character, so
/// dotfiles (`.env`) have no extension — the rule `Path::extension` uses.
fn extension(path: &str) -> Option<String> {
    match basename(path).rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => Some(ext.to_string()),
        _ => None,
    }
}

/// Joins segments with exactly one separator at each joint, in the style
/// of the first segment. A later absolute segment does NOT reset the
/// result (unlike `std::path::Path::join`): joining untrusted input
/// should never silently discard the base.
pub fn join(segments: &[String]) -> String {
    let windows = segments
        .iter()
        .find(|s| !s.is_empty())
        .is_some_and(|s| is_windows_style(s));
    let mut out = String::new();
    for segment in segments {
        if segment.is_empty() {
            continue;
        }
        let canonical = segment.replace('\\', "/");
        if out.is_empty() {
            out.push_str(&canonical);
        } else {
            // No separator after a bare drive: `C:` is drive-relative,
            // and inserting one would silently promote the base to the
            // anchored root `C:/` — against which a later `normalize`
            // then swallows `..` segments the caller meant to keep.
            // (`std::path::PathBuf::push` makes the same exception.)
            let bare_drive = out.len() == 2 && drive(&out).is_some();
            if !out.ends_with('/') && !bare_drive {
                out.push('/');
            }
            out.push_str(canonical.trim_start_matches('/'));
        }
    }
    restyle(out, windows)
}

/// Resolves `.` and `..` lexically, collapsing duplicate separators into
/// the path's own style. `..` never climbs above the root of an absolute
/// path (or drive) or the start of a relative one, which is what makes
/// the result safe to hand to a mount: after `normalize`, a checked
/// prefix cannot be escaped with dot-dot segments.
pub fn normalize(path: &str) -> String {
    let windows = is_windows_style(path);
    let (root, rest) = split_root(path);
    let rooted = !root.is_empty();
    // Only an anchoring root is a floor `..` may be dropped against. A
    // bare drive is not: swallowing the `..` in `C:..\x` would rewrite it
    // to a different directory rather than refuse an escape.
    let anchored = root_is_anchor(&root);
    let mut parts: Vec<&str> = Vec::new();
    for segment in components(&rest) {
        match segment {
            "." => {}
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if !anchored {
                    // A relative path keeps the `..`s it cannot resolve.
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    let out = match (rooted, joined.is_empty()) {
        (true, _) => format!("{root}{joined}"),
        (false, true) => ".".into(),
        // A relative result whose first segment looks like a drive prefix
        // ("C:.." out of "./C:..") would re-parse as drive-relative — a
        // different path, whose `..` then resolves against the drive. The
        // explicit `./` pins it as the plain relative name it is (found by
        // the normalize-is-idempotent property test).
        (false, false) if !split_root(&joined).0.is_empty() => format!("./{joined}"),
        (false, false) => joined,
    };
    restyle(out, windows)
}

/// Builds the `nitr.path` table.
pub(crate) fn create_path_table(lua: &Lua) -> mlua::Result<Table> {
    let path = lua.create_table()?;

    path.set(
        "join",
        lua.create_function(|_, segments: mlua::Variadic<String>| Ok(join(&segments)))?,
    )?;
    path.set(
        "basename",
        lua.create_function(|_, path: String| Ok(basename(&path)))?,
    )?;
    path.set(
        "dirname",
        lua.create_function(|_, path: String| Ok(dirname(&path)))?,
    )?;
    path.set(
        "extension",
        lua.create_function(|lua, path: String| match extension(&path) {
            Some(ext) => Ok(Value::String(lua.create_string(ext)?)),
            None => Ok(Value::Nil),
        })?,
    )?;
    path.set(
        "normalize",
        lua.create_function(|_, path: String| Ok(normalize(&path)))?,
    )?;
    path.set(
        "is_absolute",
        lua.create_function(|_, path: String| Ok(is_absolute(&path)))?,
    )?;

    Ok(path)
}

#[cfg(test)]
mod tests;
