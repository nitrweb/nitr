// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The lexical half of path containment, shared by the two places a
//! caller-supplied relative path is joined onto a server-configured root:
//! static file serving (a percent-decoded URL path) and multipart uploads
//! (a Lua string).
//!
//! One rule, one home. The alternative — a second traversal filter written
//! beside the first — is how the two drift until only one of them rejects
//! the shape that matters.
//!
//! This is only the lexical half. Neither caller is safe on this alone: a
//! symlink *inside* the root can still point out of it, so both follow the
//! join with a `canonicalize`-and-prefix check against the real filesystem
//! ([`static_files::resolve`](crate::static_files) on the file itself,
//! [`multipart`](crate::multipart) on the parent, because the file it is
//! about to create does not exist yet).

use std::path::{Component, Path, PathBuf};

/// Why [`safe_join`] refused a relative path.
///
/// A reason rather than a bare `None` so a caller that reports to a human
/// — `part:save()` does, to the Lua author — can say which rule was hit
/// instead of "invalid path".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rejected {
    /// A `..`, a Windows drive prefix, or any other non-`Normal`
    /// component.
    Traversal,
    /// Rooted at the filesystem rather than at the configured directory.
    Absolute,
    /// An interior NUL byte. The OS refuses these at open time with an
    /// opaque `InvalidInput`, so they are named here instead.
    Nul,
}

/// Joins `rel` onto `root`, refusing anything that could name a file
/// outside it.
///
/// Every component must be a plain name: `..`, absolute paths, drive
/// prefixes and NUL bytes are refused rather than normalized away.
/// Empty and `.` components are skipped, so `"a//b"` and `"./a"` are the
/// paths they obviously mean — which also means a `rel` of `""` or `"."`
/// yields `root` itself. That is deliberate (the static server serves a
/// directory's `index.html` that way); a caller for which the root is not
/// a valid answer must reject that case itself.
pub(crate) fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, Rejected> {
    if rel.contains('\0') {
        return Err(Rejected::Nul);
    }
    // Checked before the loop because splitting on `/` turns a leading
    // separator into an empty first segment, which the loop skips: an
    // absolute path would otherwise be silently re-rooted under `root`
    // rather than refused. `has_root` catches `\x` on Windows, which is
    // rooted without being absolute.
    if Path::new(rel).is_absolute() || Path::new(rel).has_root() {
        return Err(Rejected::Absolute);
    }
    let mut path = root.to_path_buf();
    for part in rel.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        // The equality is the load-bearing half: `Component::Normal` alone
        // would accept `a\b` on Unix as one component while Windows reads
        // it as two, so the platform that parses a separator out of the
        // segment is the platform that rejects it.
        match Path::new(part).components().next() {
            Some(Component::Normal(component)) if component == part => path.push(part),
            None => continue,
            _ => return Err(Rejected::Traversal),
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn join(rel: &str) -> Result<PathBuf, Rejected> {
        safe_join(Path::new("/srv/root"), rel)
    }

    #[test]
    fn plain_relative_paths_join_under_the_root() {
        assert_eq!(
            join("a.png").expect("plain"),
            PathBuf::from("/srv/root/a.png")
        );
        assert_eq!(
            join("img/a.png").expect("nested"),
            PathBuf::from("/srv/root/img/a.png")
        );
        // Empty and `.` segments are noise, not structure.
        assert_eq!(
            join("./img//a.png").expect("noisy"),
            PathBuf::from("/srv/root/img/a.png")
        );
    }

    #[test]
    fn traversal_absolute_and_nul_are_refused_by_name() {
        assert_eq!(join("../x").expect_err("parent"), Rejected::Traversal);
        assert_eq!(
            join("a/../../x").expect_err("escape after a valid segment"),
            Rejected::Traversal
        );
        assert_eq!(join("..").expect_err("bare parent"), Rejected::Traversal);
        assert_eq!(
            join("/etc/passwd").expect_err("absolute"),
            Rejected::Absolute
        );
        assert_eq!(join("a\0b").expect_err("interior nul"), Rejected::Nul);
        // A NUL anywhere counts, including in a segment that would
        // otherwise pass the component check.
        assert_eq!(
            join("ok/../\0").expect_err("nul past a traversal"),
            Rejected::Nul
        );
    }

    /// `..` written with a backslash is a separator on Windows and an
    /// ordinary character on Unix. The component-equality check refuses it
    /// on Windows; on Unix it stays one (weird, contained) file name.
    #[test]
    fn backslash_segments_never_escape() {
        let joined = join("a\\..\\..\\x");
        match joined {
            Ok(path) => assert!(
                path.starts_with("/srv/root"),
                "a backslash segment must stay inside the root: {}",
                path.display()
            ),
            Err(why) => assert_eq!(why, Rejected::Traversal),
        }
    }

    /// The root itself is a legal result — the static server relies on it
    /// to reach a directory's `index.html`.
    #[test]
    fn empty_and_dot_yield_the_root() {
        assert_eq!(join("").expect("empty"), PathBuf::from("/srv/root"));
        assert_eq!(join(".").expect("dot"), PathBuf::from("/srv/root"));
        assert_eq!(join("./.").expect("dots"), PathBuf::from("/srv/root"));
    }

    /// A rooted path is refused rather than silently re-rooted, even
    /// though the component loop would have skipped its empty first
    /// segment and produced a perfectly contained result. Callers whose
    /// input is a URL path (where a leading separator is punctuation, not
    /// a filesystem root) strip it before calling — see
    /// `static_files::resolve`.
    #[test]
    fn rooted_paths_are_refused_rather_than_re_rooted() {
        assert_eq!(join("/a.png").expect_err("rooted"), Rejected::Absolute);
        assert_eq!(join("//").expect_err("separators only"), Rejected::Absolute);
        assert_eq!(
            safe_join(Path::new("/srv/root"), "a.png").expect("a bare name is unaffected"),
            PathBuf::from("/srv/root/a.png")
        );
    }
}
