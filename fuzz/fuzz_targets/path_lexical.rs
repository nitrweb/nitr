// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Lexical path handling (`nitr.path`): `normalize` is what makes a prefix
//! check on untrusted input safe against dot-dot escapes, and
//! `basename`/`dirname` are what a handler uses to place an uploaded file
//! or walk up a tree. Parsing is hand-written rather than delegated to
//! `std::path` — which recognizes backslashes, drive prefixes and root
//! markers only when *compiled for* Windows — so every property below is
//! about text and holds identically on every host OS.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! path \0 path
//! ```
//!
//! Two independent paths: the first stands for one a handler already
//! holds, the second for untrusted input that gets joined under a trusted
//! base. Nothing is length-prefixed, so a mutation inside either path
//! stays inside it — under the old `Arbitrary` tuple the lengths came from
//! the *tail* of the buffer, and the three seeds committed for this target
//! never landed in the fields they were written for.
//!
//! The same normalize invariants run on every `cargo test` as the
//! `prop_normalize_*` proptest and the exhaustive short-path test in
//! `crates/nitr-std/src/path.rs`; this target explores the same contract
//! with arbitrary bytes and no strategy bias.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches, beyond the normalize contract documented inline below:
//!
//! * **`basename` is always a single, literal component of the input.** No
//!   separator in either style, never `.` or `..`, and a substring of what
//!   was passed in. This is the property that makes
//!   `join(upload_dir, basename(user_supplied_name))` safe: a `basename`
//!   that delegated to `Path::file_name` would hand back the *whole*
//!   `..\..\etc\passwd` on a unix host, because std sees no separator
//!   there — and the escape would be reassembled by the join.
//! * **`dirname` never changes the root and never grows.** A `dirname`
//!   that promoted the drive-relative `C:` to the anchored `C:\`, or the
//!   UNC `\\` to `\`, would silently move the caller to a different
//!   directory — and against an anchored root a later `normalize` starts
//!   swallowing the `..` segments that made the path suspicious.
//! * **A parent walk terminates.** `while p != dirname(p)` is how a caller
//!   climbs to the root; a `dirname` that ever oscillated or grew would
//!   hang the handler.
//! * **`dirname` and `basename` really split the path.** Rejoining them
//!   normalizes back to the input, so neither may drop, duplicate or
//!   reorder a component.
//! * **A `basename` survives being joined under a base**, and lands
//!   directly in that base — `dirname(join(base, name)) == base`. A join
//!   that swallowed the last segment of the base, or that inserted no
//!   separator, would place the file somewhere else entirely.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_std::fuzzing as path;

/// The trusted bases untrusted input is joined under, as a mount would.
const BASES: [&str; 3] = ["/srv/app", r"C:\srv\app", r"\\srv\app"];

/// `\` and `/` are the same separator to this parser, and `dirname` drops
/// the style along with the last separator when nothing is left to restyle
/// (`dirname(":\\:")` is `":"`, which reads as POSIX). Comparisons about
/// *structure* rather than style are therefore made on this form.
fn posix(path: &str) -> String {
    path.replace('\\', "/")
}

/// Every invariant `normalize` promises, checked for one input.
fn check(input: &str) -> String {
    let normalized = path::normalize(input);

    if path::is_absolute(&normalized) {
        assert!(
            !posix(&normalized).split('/').any(|seg| seg == ".."),
            "normalize left a dot-dot in an absolute path: {input:?} -> {normalized:?}"
        );
    }
    // Idempotence. Without it the output means something different when it
    // is re-parsed, so a check made on the first pass proves nothing about
    // what a later consumer sees.
    assert_eq!(
        path::normalize(&normalized),
        normalized,
        "normalize is not idempotent for {input:?}"
    );
    // Rootedness is preserved in both directions: gaining a root would let
    // a relative path address a filesystem root, losing one would drop a
    // path out of the base a caller checked it against. The root *string*
    // is compared, not just `is_absolute` — swapping one anchored root for
    // another (`//` -> `/`) would pass the boolean check.
    assert_eq!(
        path::split_root(&normalized).0,
        path::split_root(input).0,
        "normalize changed the root of {input:?} -> {normalized:?}"
    );
    assert_eq!(
        path::is_absolute(&normalized),
        path::is_absolute(input),
        "normalize changed rootedness of {input:?} -> {normalized:?}"
    );
    // Separator style is kept, never invented — the parse must not depend
    // on the OS this was compiled for.
    assert!(
        input.contains('\\') || !normalized.contains('\\'),
        "normalize invented a backslash: {input:?} -> {normalized:?}"
    );
    assert!(
        !path::is_windows_style(input) || !normalized.contains('/'),
        "normalize mixed separator styles: {input:?} -> {normalized:?}"
    );
    // Normalizing only ever removes: every component of the output is a
    // component of the input, and every separator it emits replaces at
    // least one it was given. A normalize that duplicated a component (or
    // re-expanded one it had resolved) would be longer than its input.
    assert!(
        input.is_empty() || normalized.len() <= input.len(),
        "normalize grew the path: {input:?} -> {normalized:?}"
    );
    // Duplicate separators collapse, so the output splits into the same
    // components a later consumer will see. An empty component surviving
    // here would shift every index a caller derived from the split.
    assert!(
        !posix(&normalized)
            .split_at(path::split_root(&normalized).0.len())
            .1
            .contains("//"),
        "normalize left an empty component: {input:?} -> {normalized:?}"
    );
    normalized
}

/// What `basename` and `dirname` promise about one input.
///
/// Only identities the implementation actually guarantees are asserted:
/// `basename` is *not* a fixpoint of `normalize` (`basename("/C:.")` is
/// `"C:."`, which normalizes to `"C:"`), it is not stable across
/// `normalize` (`basename(":/:/..")` is empty, but the normalized
/// `":/:/.."` is `":"`), and the split/join round trip below holds only
/// modulo separator style. Each of those was checked exhaustively over the
/// alphabet that drives this parser before being left out.
fn check_naming(input: &str) {
    let base = path::basename(input);
    let dir = path::dirname(input);

    // A basename is one component, literally taken from the input: no
    // separator in either style, never a dot component, never rewritten.
    // This is what makes it safe to join under a directory.
    assert!(
        !base.contains('/') && !base.contains('\\'),
        "basename kept a separator: {input:?} -> {base:?}"
    );
    assert!(
        base != "." && base != "..",
        "basename returned a dot component: {input:?} -> {base:?}"
    );
    assert!(
        base.is_empty() || input.contains(&base),
        "basename invented text not in the input: {input:?} -> {base:?}"
    );
    assert!(
        !path::is_absolute(&base),
        "basename returned an absolute path: {input:?} -> {base:?}"
    );

    // `dirname` always names *something* joinable: an empty answer would
    // turn `join(dirname(p), name)` into a bare relative name, silently
    // relocating the file to the process's working directory.
    assert!(!dir.is_empty(), "dirname returned nothing for {input:?}");
    // It stays on the same root — `C:` must not become the anchored `C:\`,
    // and the UNC `\\` must not become `\`.
    assert_eq!(
        path::split_root(&dir).0,
        path::split_root(input).0,
        "dirname changed the root of {input:?} -> {dir:?}"
    );
    // Going up never adds text.
    assert!(
        input.is_empty() || dir.len() <= input.len(),
        "dirname grew the path: {input:?} -> {dir:?}"
    );

    // A parent walk terminates: `while p != dirname(p)` is how a caller
    // climbs to the root, and each step either shortens the path or has
    // arrived. The walk is quadratic in the path length, so it is run on
    // the short inputs — a long path is the same shapes repeated.
    if input.len() <= 256 {
        let mut current = dir.clone();
        let mut settled = false;
        for _ in 0..input.matches(['/', '\\']).count() + 3 {
            let parent = path::dirname(&current);
            assert!(
                parent.len() <= current.len(),
                "a parent walk grew the path: {input:?}: {current:?} -> {parent:?}"
            );
            if parent == current {
                settled = true;
                break;
            }
            current = parent;
        }
        assert!(
            settled,
            "a parent walk from {input:?} never reached a fixpoint (stopped at {current:?})"
        );
    }

    if !base.is_empty() {
        // The two halves really are a split of the path: rejoining them
        // normalizes back to the same thing, so `dirname` cannot have
        // dropped or duplicated a component and `basename` cannot be off
        // by one. Compared modulo separator style, because a `dirname`
        // with no separator left to restyle comes back POSIX-shaped
        // (`dirname(":\\:") == ":"`).
        let rejoined = path::join(&[dir.clone(), base.clone()]);
        assert_eq!(
            posix(&path::normalize(&rejoined)),
            posix(&path::normalize(input)),
            "dirname + basename is not the path: {input:?} -> {dir:?} + {base:?}"
        );

        // The upload pattern: a name taken off untrusted input and joined
        // under a directory lands in that directory, under that name.
        for mount in BASES {
            let under = path::join(&[mount.to_string(), base.clone()]);
            assert_eq!(
                path::basename(&under),
                base,
                "joining {base:?} under {mount} mangled the name: {under:?}"
            );
            assert_eq!(
                posix(&path::dirname(&under)),
                posix(mount),
                "joining {base:?} under {mount} placed it elsewhere: {under:?}"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let held = input.text().into_owned();
    let untrusted = input.text().into_owned();

    for candidate in [held.as_str(), untrusted.as_str()] {
        check(candidate);
        check_naming(candidate);
    }

    // The mount pattern: untrusted input joined under a trusted base. The
    // join must not let the second segment discard the base, and whatever
    // normalize returns must be safe to prefix-check.
    check(&path::join(&[held.clone(), untrusted.clone()]));
    for base in BASES {
        let under = check(&path::join(&[base.to_string(), untrusted.clone()]));
        assert!(
            !under.is_empty(),
            "joining under {base} produced nothing for {untrusted:?}"
        );
        // The base's root survives whatever was joined onto it: unlike
        // `std::path::Path::join`, an absolute second segment must not
        // reset the result to itself.
        assert!(
            path::is_absolute(&under),
            "joining {untrusted:?} under {base} discarded the base: {under:?}"
        );
    }
    // A drive-relative base must stay drive-relative: join must not
    // promote `C:` to the anchored `C:\`, whose root would then swallow
    // `..` segments the caller meant to keep.
    let under_drive = check(&path::join(&["C:".to_string(), untrusted.clone()]));
    assert!(
        !path::is_absolute(&under_drive),
        "join promoted the bare drive for {untrusted:?}: {under_drive:?}"
    );
});
