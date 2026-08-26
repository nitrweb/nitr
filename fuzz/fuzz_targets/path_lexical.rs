// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Lexical path handling: `normalize` is used to sanitize untrusted path
//! input, so the properties a prefix check depends on are asserted under
//! fuzzing — no `..` survives in an absolute path, normalizing again
//! changes nothing, rootedness is neither gained nor lost, and the
//! separator style of the input is never traded for another.
//!
//! The same invariants run on every `cargo test` as the `prop_normalize_*`
//! proptest in `crates/nitr-std/src/path.rs`; this target explores the
//! same space with arbitrary bytes and no strategy bias.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nitr_std::fuzzing as path;

/// Every invariant `normalize` promises, checked for one input.
fn check(input: &str) -> String {
    let normalized = path::normalize(input);

    if path::is_absolute(&normalized) {
        let posix = normalized.replace('\\', "/");
        assert!(
            !posix.split('/').any(|seg| seg == ".."),
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
    normalized
}

fuzz_target!(|input: (&str, &str)| {
    let (a, b) = input;
    let _ = path::basename(a);
    let _ = path::dirname(a);

    check(a);
    check(b);

    // The mount pattern: untrusted input joined under a trusted base. The
    // join must not let `b` discard the base, and whatever normalize
    // returns must be safe to prefix-check.
    let joined = path::join(&[a.to_string(), b.to_string()]);
    check(&joined);
    for base in ["/srv/app", r"C:\srv\app", r"\\srv\app"] {
        let under = check(&path::join(&[base.to_string(), b.to_string()]));
        assert!(
            !under.is_empty(),
            "joining under {base} produced nothing for {b:?}"
        );
    }
    // A drive-relative base must stay drive-relative: join must not
    // promote `C:` to the anchored `C:\`, whose root would then swallow
    // `..` segments the caller meant to keep.
    let under_drive = check(&path::join(&["C:".to_string(), b.to_string()]));
    assert!(
        !path::is_absolute(&under_drive),
        "join promoted the bare drive for {b:?}: {under_drive:?}"
    );
});
