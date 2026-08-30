// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The upload containment rule, over a real tree: the lexical component
//! filter shared with static serving, then a canonicalized prefix check on
//! the *parent* and a symlink check on the final component. This is what
//! `part:save(path)` runs before it opens anything
//! (`multipart::resolve_upload_path`), minus the streaming.
//!
//! The sibling of `static_resolve`, and deliberately not folded into it:
//! the two callers share only the lexical half. The static side
//! percent-decodes a URL and canonicalizes a file that already exists; the
//! upload side takes a Lua string verbatim (a Lua string is not a URL, and
//! a decode step here would *invent* the `%2e%2e` escape it pretended to
//! defend) and canonicalizes a parent, because the file it is about to
//! create does not exist yet.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u8 mode | path…
//! ```
//!
//! `mode` picks which root the path is resolved against: the upload
//! directory itself, or its `sub/` child — so a path is exercised both at
//! the root and one level down, where a single `..` is enough to reach the
//! root and two escape it. The rest of the input is the raw path taken
//! verbatim to the end, NUL bytes and invalid UTF-8 included: those are
//! traversal classics, and a rule can only be shown to survive them if the
//! input format does not eat them first.
//!
//! The tree is built once per process under a `TempDir` kept alive for the
//! life of the process:
//!
//! ```text
//! <base>/secret.txt          prey one level above the root
//! <base>/outside/            a directory one level above the root
//! <base>/uploads/            THE UPLOAD ROOT
//! <base>/uploads/sub/        an existing subdirectory (a legal target)
//! <base>/uploads/existing.txt   a regular file (may be overwritten)
//! <base>/uploads/escape      -> ../secret.txt  (unix, must NOT resolve)
//! <base>/uploads/escape-dir  -> ../outside     (unix, must NOT resolve)
//! ```
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **Whatever comes back is inside the canonical upload root.** The
//!   invariant the whole feature rests on: every escape — `..`, absolute,
//!   backslashed, NUL-bearing, or through a symlink — either returns an
//!   error or lands here as a crash naming the path that did it.
//! * **…and containment holds on a canonical path.** `starts_with`
//!   compares components, so `/root/../../etc/passwd` starts with `/root`
//!   by that test alone. The result is therefore also required to carry no
//!   `.`/`..` component and to have a canonical parent — without which an
//!   implementation that skipped `canonicalize` and prefix-checked the raw
//!   join would still satisfy the containment assertion while opening
//!   `/etc/passwd`.
//! * **…and it is never an existing symlink.** `File::create` truncates
//!   what it opens, so a link that survived this far would be written
//!   *through*, which is the arbitrary-write primitive again with one more
//!   step.
//! * **The known-good paths still resolve** (checked once per process): a
//!   rule that refused everything would be perfectly safe, accept no
//!   upload at all, and satisfy every assertion above.
//! * **`safe_filename` is a name, always.** Whatever bytes arrive, it
//!   carries no separator, is never empty, and is never `.` or `..` — the
//!   property that makes `part:save(part.safe_filename)` safe on its own.

#![no_main]

use std::path::{Component, PathBuf};
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_http::fuzzing::{resolve_upload, safe_filename};

/// One current-thread runtime for the whole process: `resolve_upload` is
/// async but only ever awaits the filesystem.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
    })
}

struct Tree {
    /// Kept alive for the process: dropping it would delete the tree and
    /// every run would then fail on a missing root instead of exercising
    /// the rule.
    _tmp: tempfile::TempDir,
    /// The upload root as configured (not canonicalized), the way
    /// `[multipart] upload_dir` holds it.
    dir: PathBuf,
    /// Its canonical form: the floor no resolved path may go above.
    root: PathBuf,
    /// The `sub/` child, used as a second root so one `..` reaches the
    /// upload root and two leave it.
    sub: PathBuf,
}

fn tree() -> &'static Tree {
    static TREE: OnceLock<Tree> = OnceLock::new();
    TREE.get_or_init(build_tree)
}

fn build_tree() -> Tree {
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let base = tmp.path();
    let dir = base.join("uploads");

    // Prey for a successful escape: without a real file and a real
    // directory above the root, a rule that walked out would only ever
    // meet a benign "no such file".
    std::fs::write(base.join("secret.txt"), b"outside").expect("write secret");
    std::fs::create_dir_all(base.join("outside")).expect("mkdir outside");

    std::fs::create_dir_all(dir.join("sub")).expect("mkdir upload root");
    std::fs::write(dir.join("existing.txt"), b"existing").expect("write existing");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        // Both must be refused: the first as a final component that would
        // be written through, the second as a parent that leads out.
        let _ = symlink("../secret.txt", dir.join("escape"));
        let _ = symlink("../outside", dir.join("escape-dir"));
    }

    let root = dir.canonicalize().expect("canonicalize the upload root");
    let sub = dir.join("sub");
    Tree {
        _tmp: tmp,
        dir,
        root,
        sub,
    }
}

/// The paths that must keep resolving, so a rule that refuses everything
/// cannot pass. Checked once per process.
fn check_known_good(tree: &Tree) {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        for good in ["a.png", "sub/inner.bin", "existing.txt", "./a.png"] {
            let resolved = runtime()
                .block_on(resolve_upload(&tree.dir, good))
                .unwrap_or_else(|err| panic!("`{good}` must resolve, got: {err}"));
            assert!(
                resolved.starts_with(&tree.root),
                "`{good}` resolved outside the root: {}",
                resolved.display()
            );
        }
        // …and the shapes that must always be refused, so a rule that
        // accepted everything cannot pass either.
        for bad in ["../secret.txt", "/etc/passwd", "", ".", "..", "a\0b"] {
            assert!(
                runtime().block_on(resolve_upload(&tree.dir, bad)).is_err(),
                "`{bad}` must be refused"
            );
        }
        #[cfg(unix)]
        for bad in ["escape", "escape-dir/leak.txt"] {
            assert!(
                runtime().block_on(resolve_upload(&tree.dir, bad)).is_err(),
                "the symlink `{bad}` must be refused"
            );
        }
    });
}

fuzz_target!(|data: &[u8]| {
    let tree = tree();
    check_known_good(tree);

    let mut input = Input::new(data);
    let mode = input.u8();
    // Lossy rather than a UTF-8 gate: a Lua string is bytes, and the
    // interesting inputs (invalid UTF-8, NUL) are exactly the ones a
    // stricter decode would drop before the rule ever saw them.
    let path = String::from_utf8_lossy(input.rest()).into_owned();
    let path = path.as_str();

    let root = if mode % 2 == 0 { &tree.dir } else { &tree.sub };
    let Ok(resolved) = runtime().block_on(resolve_upload(root, path)) else {
        // A refusal is always an acceptable answer; the target is about
        // what an *acceptance* may be.
        return;
    };

    // The one invariant: an accepted path is inside the canonical root.
    assert!(
        resolved.starts_with(&tree.root),
        "`{path}` (root mode {mode}) resolved outside the upload root: {}",
        resolved.display()
    );

    // Containment must have been decided on a canonical path — a raw join
    // would satisfy `starts_with` while still naming `/etc/passwd`.
    assert!(
        !resolved
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "`{path}` resolved to a non-normalized path: {}",
        resolved.display()
    );
    let parent = resolved.parent().expect("a resolved target has a parent");
    assert_eq!(
        parent,
        parent
            .canonicalize()
            .expect("the parent exists, it was canonicalized during resolution"),
        "`{path}` resolved under a non-canonical parent: {}",
        resolved.display()
    );

    // Never an existing symlink: `File::create` truncates, so one that
    // survived would be written through.
    if let Ok(meta) = std::fs::symlink_metadata(&resolved) {
        assert!(
            !meta.file_type().is_symlink(),
            "`{path}` resolved onto a symlink: {}",
            resolved.display()
        );
        assert!(
            meta.is_file(),
            "`{path}` resolved onto something that is not a regular file: {}",
            resolved.display()
        );
    }

    // `safe_filename` is a name whatever it is handed: the property that
    // lets a handler pass it straight to `save`.
    let safe = safe_filename(path);
    assert!(!safe.is_empty(), "safe_filename returned an empty name");
    assert!(
        !safe.contains('/') && !safe.contains('\\'),
        "safe_filename kept a separator: {safe:?}"
    );
    assert!(safe != "." && safe != "..", "safe_filename returned {safe:?}");
    assert!(
        !safe.contains('\0'),
        "safe_filename kept a NUL byte: {safe:?}"
    );
    assert!(
        safe.len() <= 255,
        "safe_filename exceeded NAME_MAX: {} bytes",
        safe.len()
    );
    // …and what it produces is never refused by `save` *for being
    // unsafe*. It may still fail for an ordinary filesystem reason — the
    // name can collide with an existing directory or symlink, which is
    // the application's problem and not a containment one — so the
    // assertion is on the refusal's kind, not on success. (Stated as
    // `is_ok()` this fails on the first input that sanitizes to `sub`,
    // which is how the distinction was found rather than assumed.)
    match runtime().block_on(resolve_upload(&tree.dir, &safe)) {
        Ok(resolved) => assert!(
            resolved.starts_with(&tree.root),
            "safe_filename produced a name resolving outside the root: {safe:?}"
        ),
        Err(err) => {
            let msg = err.to_string();
            for containment in [
                "climbs out of the upload directory",
                "absolute path",
                "NUL byte",
                "names the upload directory itself",
                "resolves outside the upload directory",
            ] {
                assert!(
                    !msg.contains(containment),
                    "safe_filename produced a name refused as unsafe ({containment}): \
                     {safe:?} — it is supposed to be safe by construction"
                );
            }
        }
    }
});
