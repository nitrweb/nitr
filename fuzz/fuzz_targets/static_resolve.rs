// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The static-serving traversal defense, over a real tree: percent-decode
//! → mount prefix → component filter → canonicalized containment. This is
//! the chain `try_serve` runs for every `GET` of a static asset
//! (`static_files::resolve_for_fuzzing`, kept beside it so the two cannot
//! drift), minus hyper and the file body.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u8 mount | url-path…
//! ```
//!
//! `mount` picks one of `/`, `/public`, `/assets`, all three serving the
//! *same* directory — so the mount is exercised as what it is, a URL
//! prefix unrelated to the directory name, and both branches of
//! `StaticMount::relative` (the root fast path, and `strip_prefix`) are
//! reachable. The rest of the input is the raw, still-encoded URL path
//! taken verbatim to the end, NUL bytes and invalid UTF-8 included: `%00`
//! and over-long UTF-8 are traversal classics, and a decoder can only be
//! shown to survive them if the input format does not eat them first.
//!
//! The tree is built once per process under a `TempDir` that is kept alive
//! for the life of the process:
//!
//! ```text
//! <root>/secret.txt         a file one level up, so an escape finds prey
//! <root>/outside/leak.txt   a directory one level up
//! <root>/public/            THE MOUNT
//! <root>/public/index.html  where a directory request must land
//! <root>/public/ok.txt
//! <root>/public/sub/inner.txt
//! <root>/public/sub/index.html
//! <root>/public/escape.txt  -> ../secret.txt   (unix, must NOT resolve)
//! <root>/public/escape-dir  -> ../outside      (unix, must NOT resolve)
//! <root>/public/alias.txt   -> ok.txt          (unix, must resolve)
//! ```
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **Whatever comes back is inside the canonical mount.** The one
//!   invariant the whole feature rests on: every escape — `..`,
//!   percent-encoded, double-encoded, backslashed, NUL-terminated,
//!   absolute, unicode, or through a symlink — either resolves to `None`
//!   or lands here as a crash with the URL that did it.
//! * **…and containment is checked on a canonical path.** `starts_with`
//!   compares *components*, so `/root/../../etc/passwd` starts with
//!   `/root` by that test alone. The result is therefore also required to
//!   be a fixpoint of `canonicalize` and to carry no `.`/`..` component —
//!   without these two, an implementation that dropped the `canonicalize`
//!   and prefix-checked the raw join would still pass the containment
//!   assertion while serving `/etc/passwd`.
//! * **…and it is a regular file that exists.** A directory or a dangling
//!   link reaching `serve_file` is a 500 or a directory listing, not a
//!   404.
//! * **The exact file, by an independent oracle.** The decode, the
//!   traversal filter, the directory→`index.html` step and the symlink
//!   policy are recomputed here from the raw URL with `std::fs`, and the
//!   two answers must be equal. Equality (not just "is safe") is what
//!   catches the failures a containment check cannot see: a `resolve` that
//!   answers `None` for everything, one that serves a *different* file
//!   than the one requested, one that stopped following the `index.html`
//!   step, and one that started refusing the legitimate in-mount symlink.
//! * **The mount prefix cannot change the answer.** The same path resolved
//!   under the root mount and under `/public` must give the same file —
//!   `relative()` takes two entirely different routes to produce them
//!   (`trim_start_matches` vs `strip_prefix` plus a separator check), and
//!   an off-by-one in either would let `/publicX` match, or eat the first
//!   character of the file name.
//! * **The known-good paths still resolve** (checked once per process,
//!   where a constant answer is worth exactly one check): a `resolve` that
//!   returns `None` unconditionally is perfectly safe, serves nothing, and
//!   would satisfy every assertion above.
#![no_main]

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_http::fuzzing::{StaticMount, resolve_static};

/// The URL prefixes the fuzzer chooses between. All three serve the same
/// directory.
const MOUNTS: [&str; 3] = ["/", "/public", "/assets"];

/// One current-thread runtime for the whole process: `resolve_static` is
/// async but only ever awaits the filesystem, so a runtime per run would
/// be pure setup cost.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
    })
}

/// The tree every run resolves against.
struct Tree {
    /// Kept alive for the process: dropping it would delete the files the
    /// target resolves against, and every run would then see `None`.
    _tmp: tempfile::TempDir,
    /// The mount directory as configured (not canonicalized) — what a
    /// `[static] dir` in `nitr.toml` would hold.
    dir: PathBuf,
    /// The canonicalized mount directory: the floor no resolved path may
    /// go above.
    root: PathBuf,
    mounts: [StaticMount; MOUNTS.len()],
}

fn tree() -> &'static Tree {
    static TREE: OnceLock<Tree> = OnceLock::new();
    TREE.get_or_init(build_tree)
}

fn build_tree() -> Tree {
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let base = tmp.path();
    let dir = base.join("public");

    // Prey for a successful escape: a real file and a real directory one
    // level above the mount. Without them a broken `resolve` that walked
    // out would only ever meet a benign "no such file".
    std::fs::write(base.join("secret.txt"), b"outside").expect("write secret");
    std::fs::create_dir_all(base.join("outside")).expect("mkdir outside");
    std::fs::write(base.join("outside/leak.txt"), b"leak").expect("write leak");

    std::fs::create_dir_all(dir.join("sub")).expect("mkdir mount");
    std::fs::write(dir.join("index.html"), b"<html>index</html>").expect("write index");
    std::fs::write(dir.join("ok.txt"), b"ok").expect("write ok");
    std::fs::write(dir.join("sub/inner.txt"), b"inner").expect("write inner");
    std::fs::write(dir.join("sub/index.html"), b"<html>sub</html>").expect("write sub index");

    // Symlinks are the escape the lexical filter cannot see: `escape.txt`
    // is a perfectly normal component that only leaves the mount once the
    // kernel resolves it, which is why the containment check is made after
    // `canonicalize`. `alias.txt` is the control — a link that stays
    // inside and must keep working.
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(base.join("secret.txt"), dir.join("escape.txt")).expect("escaping file link");
        symlink(base.join("outside"), dir.join("escape-dir")).expect("escaping dir link");
        symlink(dir.join("ok.txt"), dir.join("alias.txt")).expect("in-mount link");
        // A link that points nowhere: `metadata` fails rather than
        // reporting a file, and the answer must be a quiet `None`.
        symlink(base.join("nothing-here"), dir.join("dangling.txt")).expect("dangling link");
    }

    let root = std::fs::canonicalize(&dir).expect("canonical mount");
    let mounts = [
        StaticMount::new(MOUNTS[0], &dir, false, None),
        StaticMount::new(MOUNTS[1], &dir, false, None),
        StaticMount::new(MOUNTS[2], &dir, false, None),
    ];
    let tree = Tree {
        _tmp: tmp,
        dir,
        root,
        mounts,
    };
    liveness(&tree);
    tree
}

/// The paths that must keep working, checked once when the tree is built.
///
/// These inputs are constants, so re-running them on every fuzz input
/// would buy nothing but syscalls — but without them the entire target is
/// satisfied by a `resolve` that answers `None` to everything, which is
/// both perfectly safe and completely broken.
fn liveness(tree: &Tree) {
    let canonical = |rel: &str| std::fs::canonicalize(tree.dir.join(rel)).expect("canonical");
    let ok = canonical("ok.txt");
    let index = canonical("index.html");

    for (prefix, mount) in MOUNTS.iter().zip(&tree.mounts) {
        let url = |rel: &str| match *prefix {
            "/" => format!("/{rel}"),
            other => format!("{other}/{rel}"),
        };
        assert_eq!(
            resolve(mount, &url("ok.txt")),
            Some(ok.clone()),
            "the mount {prefix} stopped serving its own files"
        );
        assert_eq!(
            resolve(mount, &url("sub/inner.txt")),
            Some(canonical("sub/inner.txt")),
            "the mount {prefix} stopped serving nested files"
        );
        // A directory resolves to its index, including the mount root
        // itself — the trailing-slash and empty-relative cases.
        assert_eq!(
            resolve(mount, &url("")),
            Some(index.clone()),
            "the mount {prefix} stopped resolving its root to index.html"
        );
        assert_eq!(
            resolve(mount, &url("sub")),
            Some(canonical("sub/index.html")),
            "the mount {prefix} stopped resolving a directory to index.html"
        );
        // Percent-decoding happens, once: the encoded name is the same
        // file, and the encoded traversal is not a traversal.
        assert_eq!(
            resolve(mount, &url("%6fk.txt")),
            Some(ok.clone()),
            "the mount {prefix} stopped percent-decoding"
        );
    }
    // A prefix mount is a *path* prefix, not a string prefix.
    assert_eq!(
        resolve(&tree.mounts[1], "/publicfoo/ok.txt"),
        None,
        "/publicfoo must not match the mount /public"
    );

    #[cfg(unix)]
    {
        let root_mount = &tree.mounts[0];
        assert_eq!(
            resolve(root_mount, "/alias.txt"),
            Some(ok),
            "a symlink that stays inside the mount must still resolve"
        );
        assert_eq!(
            resolve(root_mount, "/escape.txt"),
            None,
            "a symlink out of the mount must not resolve"
        );
        assert_eq!(
            resolve(root_mount, "/escape-dir/leak.txt"),
            None,
            "a directory symlink out of the mount must not resolve"
        );
        assert_eq!(
            resolve(root_mount, "/dangling.txt"),
            None,
            "a dangling symlink must not resolve"
        );
    }
}

/// One resolution, exactly as `try_serve` performs it.
fn resolve(mount: &StaticMount, url_path: &str) -> Option<PathBuf> {
    runtime().block_on(resolve_static(mount, url_path))
}

/// A second percent-decoder, written from the grammar rather than shared
/// with the `percent_encoding` crate `try_serve` uses: `%` plus two hex
/// digits is a byte, anything else is literal, and the result must be
/// UTF-8 or the path is refused. Two implementations of one decode is what
/// makes the oracle below a differential rather than a copy — and
/// percent-decoding is where traversal bypasses live (`%2e%2e`, `%2f`,
/// `%252e`, `%00`, over-long forms).
fn percent_decode(url: &str) -> Option<String> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = url.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push((high << 4) | low);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// What the resolution must come out as, computed independently of
/// `static_files`: filter the decoded relative path to its normal
/// components, follow a directory to its `index.html`, canonicalize, and
/// require the result to be a file inside the canonical mount.
///
/// The component filter is spelled out textually (empty and `.` are
/// skipped, `..` refuses the whole path, everything else is a name)
/// because that is what `std::path::Component` means on the unix host the
/// fuzzer builds for — and the point of an oracle is not to re-run the
/// implementation's own reasoning.
fn oracle(dir: &Path, root: &Path, rel: &str) -> Option<PathBuf> {
    let mut path = dir.to_path_buf();
    for segment in rel.split('/') {
        match segment {
            "" | "." => continue,
            ".." => return None,
            name => path.push(name),
        }
    }
    let file = match std::fs::metadata(&path) {
        Ok(meta) if meta.is_dir() => {
            let index = path.join("index.html");
            match std::fs::metadata(&index) {
                Ok(meta) if meta.is_file() => index,
                _ => return None,
            }
        }
        Ok(meta) if meta.is_file() => path,
        _ => return None,
    };
    // The symlink policy, applied where the implementation applies it:
    // after the kernel has resolved the path.
    std::fs::canonicalize(file)
        .ok()
        .filter(|canonical| canonical.starts_with(root))
}

fuzz_target!(|data: &[u8]| {
    let tree = tree();
    let mut input = Input::new(data);
    let pick = usize::from(input.u8()) % MOUNTS.len();
    let prefix = MOUNTS[pick];
    let mount = &tree.mounts[pick];
    // The whole tail is the URL path, so NULs and invalid UTF-8 reach the
    // decoder instead of being cut off at a field boundary.
    let url = String::from_utf8_lossy(input.rest()).into_owned();

    let got = resolve(mount, &url);

    if let Some(file) = &got {
        // THE invariant: nothing outside the mount is ever served.
        assert!(
            file.starts_with(&tree.root),
            "escaped the mount {prefix}: {url:?} resolved to {file:?}, \
             which is not under {:?}",
            tree.root
        );
        // `starts_with` compares components, so `<root>/../../etc/passwd`
        // would pass it. These two are what make the check above mean
        // "inside": the answer must be canonical, and canonical paths
        // contain no `.` or `..`.
        assert!(
            file.components().all(|c| matches!(
                c,
                Component::RootDir | Component::Normal(_) | Component::Prefix(_)
            )),
            "{url:?} resolved to a non-canonical path with dot components: {file:?}"
        );
        assert_eq!(
            std::fs::canonicalize(file).ok().as_ref(),
            Some(file),
            "{url:?} resolved to {file:?}, which is not its own canonical form"
        );
        // Anything else reaching `serve_file` is a 500 or a listing.
        assert!(
            std::fs::metadata(file).is_ok_and(|meta| meta.is_file()),
            "{url:?} resolved to {file:?}, which is not a regular file"
        );
    }

    // The exact answer, from the independent decode + filter above.
    match percent_decode(&url) {
        // A path whose escapes do not decode to UTF-8 cannot name a file:
        // `decode_utf8` refuses it before the mount is consulted.
        None => assert!(
            got.is_none(),
            "{url:?} does not percent-decode to UTF-8, yet resolved to {got:?}"
        ),
        Some(decoded) => match mount.relative(&decoded) {
            // Outside the mount prefix entirely.
            None => assert!(
                got.is_none(),
                "{url:?} is not under the mount {prefix}, yet resolved to {got:?}"
            ),
            Some(rel) => {
                // A `..` segment refuses the whole path — decoded once,
                // never twice: `%252e%252e` decodes to the *name*
                // `%2e%2e`, which is not traversal and must not be
                // treated as such.
                if rel.split('/').any(|segment| segment == "..") {
                    assert!(
                        got.is_none(),
                        "{url:?} carries a `..` segment ({rel:?}) yet resolved to {got:?}"
                    );
                }
                assert_eq!(
                    got,
                    oracle(&tree.dir, &tree.root, rel),
                    "resolve disagrees with the oracle for {url:?} under mount {prefix} \
                     (relative path {rel:?})"
                );
            }
        },
    }

    // The mount prefix is a URL prefix and nothing else: the same path
    // served at `/` and at `/public` must resolve to the same file. The
    // two go through different halves of `relative()`, so an off-by-one in
    // either — `/publicX` matching, or the first character of the name
    // being eaten — shows up as a disagreement here.
    let tail = url.trim_start_matches('/');
    assert_eq!(
        resolve(&tree.mounts[0], &format!("/{tail}")),
        resolve(&tree.mounts[1], &format!("/public/{tail}")),
        "the mount prefix changed the answer for {tail:?}"
    );
});
