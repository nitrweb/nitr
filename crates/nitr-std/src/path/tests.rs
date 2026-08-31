// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;

#[test]
fn components_split_like_posix() {
    assert_eq!(basename("/a/b/c.txt"), "c.txt");
    assert_eq!(basename("/a/b/"), "b");
    assert_eq!(basename("plain"), "plain");
    assert_eq!(basename("/"), "");

    assert_eq!(dirname("/a/b/c"), "/a/b");
    assert_eq!(dirname("/a/b/"), "/a");
    assert_eq!(dirname("/c"), "/");
    assert_eq!(dirname("c"), ".");
    assert_eq!(dirname("/"), "/");

    assert_eq!(extension("a/b.tar.gz").as_deref(), Some("gz"));
    assert_eq!(extension("a/.env"), None);
    assert_eq!(extension("a/no_ext"), None);
}

#[test]
fn windows_paths_are_understood() {
    assert_eq!(basename(r"C:\Users\ada\file.txt"), "file.txt");
    assert_eq!(basename(r"C:\Users\ada\"), "ada");
    assert_eq!(dirname(r"C:\Users\ada"), r"C:\Users");
    assert_eq!(dirname(r"C:\Users"), r"C:\");
    assert_eq!(dirname(r"C:\"), r"C:\");
    assert_eq!(extension(r"C:\a\b.TXT").as_deref(), Some("TXT"));

    assert!(is_absolute(r"C:\Users"));
    assert!(is_absolute("C:/Users"));
    assert!(is_absolute(r"\\server\share"));
    assert!(is_absolute(r"\windows-root-relative"));
    assert!(!is_absolute("C:relative"));
    assert!(!is_absolute(r"relative\file"));

    // Mixed separators split correctly.
    assert_eq!(basename(r"C:\a/b\c.txt"), "c.txt");
}

#[test]
fn join_never_discards_the_base() {
    let s = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };
    assert_eq!(join(&s(&["/srv", "app", "file.txt"])), "/srv/app/file.txt");
    assert_eq!(join(&s(&["/srv/", "/app/"])), "/srv/app/");
    // An absolute later segment joins instead of resetting.
    assert_eq!(join(&s(&["/srv", "/etc/passwd"])), "/srv/etc/passwd");
    assert_eq!(join(&s(&["a", "", "b"])), "a/b");
    assert_eq!(join(&s(&["/"])), "/");
    // The first segment picks the separator style.
    assert_eq!(
        join(&s(&[r"C:\Users", "ada", "x.txt"])),
        r"C:\Users\ada\x.txt"
    );
    assert_eq!(join(&s(&[r"C:\srv", r"\etc\passwd"])), r"C:\srv\etc\passwd");

    // A bare drive stays drive-relative: no separator is inserted
    // after it, so joining cannot promote `C:` to the anchored root
    // `C:\` — which would let a later normalize swallow the `..`.
    assert_eq!(join(&s(&["C:", "x"])), "C:x");
    assert_eq!(join(&s(&["C:", "..", "x"])), r"C:..\x");
    assert!(!is_absolute(&join(&s(&["C:", "x"]))));
    assert_eq!(normalize(&join(&s(&["C:", "..", "x"]))), r"C:..\x");
    // Only a *bare* drive gets the exception; a drive-relative name
    // still receives its separator.
    assert_eq!(join(&s(&["C:x", "y"])), r"C:x\y");
}

#[test]
fn degenerate_inputs_hold_up() {
    // Empty and separator-only inputs.
    assert_eq!(join(&[]), "");
    assert_eq!(join(&["".into(), "".into()]), "");
    assert_eq!(basename(""), "");
    assert_eq!(dirname(""), ".");
    assert_eq!(extension(""), None);
    assert!(!is_absolute(""));
    assert_eq!(normalize("//"), "//");

    // Trailing separators do not create phantom components.
    assert_eq!(normalize("/a/b/"), "/a/b");
    assert_eq!(normalize(r"C:\a\"), r"C:\a");

    // A bare drive keeps its (drive-relative) meaning.
    assert_eq!(normalize("C:x"), "C:x");
    assert_eq!(dirname(r"C:x"), "C:");

    // UNC dirname walks down to the root marker, not past it.
    assert_eq!(dirname(r"\\server\share"), r"\\server");
    assert_eq!(dirname(r"\\server"), r"\\");

    // Parsing is textual, so these answer the same on every host OS —
    // `std::path` would read the extra separator as a second root and
    // `C:x` as a drive prefix, but only when compiled for Windows.
    assert_eq!(normalize("///ax/y"), "//ax/y");
    assert_eq!(normalize("//C:x/.."), "//");
    assert_eq!(basename("//C:x"), "C:x");
    assert_eq!(dirname("//C:x/y"), "//C:x");

    // A hostile depth of `..` cannot climb out, however long.
    let attack = format!("/base/{}etc/passwd", "../".repeat(1000));
    assert_eq!(normalize(&attack), "/etc/passwd");
    let relative_attack = "../".repeat(500) + "x";
    assert_eq!(
        normalize(&relative_attack),
        format!("{}x", "../".repeat(500))
    );
}

#[test]
fn normalize_resolves_dots_without_escaping_the_root() {
    assert_eq!(normalize("/a/b/../c/./d"), "/a/c/d");
    assert_eq!(normalize("/a/../../etc"), "/etc");
    assert_eq!(normalize("a//b///c"), "a/b/c");
    assert_eq!(normalize("./x"), "x");
    assert_eq!(normalize("../x"), "../x");
    assert_eq!(normalize("a/.."), ".");
    assert_eq!(normalize("/"), "/");
    assert_eq!(normalize(""), ".");
    // Windows: the drive root cannot be escaped either, and the
    // output keeps the backslash style.
    assert_eq!(normalize(r"C:\a\..\..\etc"), r"C:\etc");
    assert_eq!(normalize(r"C:\a\.\b"), r"C:\a\b");
    assert_eq!(normalize(r"C:/mixed\style/x"), r"C:\mixed\style\x");
    assert_eq!(normalize(r"\\server\share\..\other"), r"\\server\other");
}

/// The security contract, exercised in both separator styles: after
/// `normalize`, a prefix check against a trusted base is sound —
/// nothing that survives the check can still climb out of it, and
/// every attempt to climb out is *visible* to the check rather than
/// silently contained somewhere else.
#[test]
fn traversal_is_defeated_in_both_path_styles() {
    // Untrusted input joined under a base, the way a mount does it.
    let under = |base: &str, untrusted: &str| normalize(&join(&[base.into(), untrusted.into()]));

    for (base, sep) in [
        ("/srv/app", "/"),
        (r"C:\srv\app", "\\"),
        (r"\\srv\app", "\\"),
    ] {
        let inside = format!("{base}{sep}");
        // Plain traversal, in whichever style the attacker sends: the
        // result is no longer under the base, so the prefix check
        // rejects it instead of serving another directory's file.
        for attack in [
            "../../../../etc/passwd",
            r"..\..\..\..\etc\passwd",
            r"../..\../..\etc/passwd",
            "..//..///../x",
            "a/../../../../x",
            "./../../x",
        ] {
            let out = under(base, attack);
            assert!(
                !out.starts_with(&inside),
                "{base} + {attack:?} must not pass a prefix check: {out}"
            );
            // Whatever it resolved to keeps no `..` to expand later.
            assert!(
                !out.replace('\\', "/").split('/').any(|s| s == ".."),
                "{base} + {attack:?} left a `..`: {out}"
            );
        }

        // Traversal that stays inside is still served, and the
        // separator style of the base is preserved throughout.
        for benign in ["a/b/../c", r"a\b\..\c", "./a/b/../c", "a//b/././../c"] {
            assert_eq!(
                under(base, benign),
                format!("{inside}a{sep}c"),
                "{benign:?}"
            );
        }

        // A later absolute segment cannot reset the base away.
        assert!(under(base, "/etc/passwd").starts_with(&inside));
        assert!(under(base, r"\etc\passwd").starts_with(&inside));
        assert!(under(base, "C:/etc").starts_with(&inside));
    }

    // Lookalike segments are names, not traversal: `...`, `..a` and a
    // dot-dot with a trailing space must not be treated as `..`.
    assert_eq!(normalize("/base/.../..a/x"), "/base/.../..a/x");
    assert_eq!(normalize("/base/.. /x"), "/base/.. /x");
    assert_eq!(normalize(r"C:\base\...\x"), r"C:\base\...\x");

    // The root itself is the floor for every rooted style.
    assert_eq!(normalize("/../../etc"), "/etc");
    assert_eq!(normalize(r"C:\..\..\etc"), r"C:\etc");
    assert_eq!(normalize(r"\\srv\..\..\etc"), r"\\etc");
    assert_eq!(normalize(r"\..\..\etc"), r"\etc");
    // A bare drive is drive-relative, so it is *not* a floor a prefix
    // check may rely on — `..` survives, and `is_absolute` says false.
    assert_eq!(normalize(r"C:..\x"), r"C:..\x");
    assert!(!is_absolute(r"C:..\x"));
}

/// Every invariant `normalize` promises, for one input. Shared by the
/// exhaustive and property tests below and mirrored by the
/// `path_lexical` fuzz target, so all three check the same contract.
fn assert_normalize_invariants(input: &str) {
    let normalized = normalize(input);
    if is_absolute(&normalized) {
        assert!(
            !normalized
                .replace('\\', "/")
                .split('/')
                .any(|seg| seg == ".."),
            "{input:?} -> {normalized:?} kept a dot-dot in an absolute path"
        );
    }
    // Idempotence: without it, the output means something else when a
    // later consumer re-parses it, so a check made now proves nothing.
    assert_eq!(
        normalize(&normalized),
        normalized,
        "normalize is not idempotent for {input:?}"
    );
    // Rootedness is neither gained (a relative path must not become
    // able to address a filesystem root) nor lost (which would drop a
    // path out of the base it was checked against).
    assert_eq!(
        split_root(&normalized).0,
        split_root(input).0,
        "{input:?} -> {normalized:?} changed the root"
    );
    assert_eq!(
        is_absolute(&normalized),
        is_absolute(input),
        "{input:?} -> {normalized:?} changed rootedness"
    );
    // Separator style is kept, never invented.
    assert!(
        input.contains('\\') || !normalized.contains('\\'),
        "{input:?} -> {normalized:?} invented a backslash"
    );
    assert!(
        !is_windows_style(input) || !normalized.contains('/'),
        "{input:?} -> {normalized:?} mixed separator styles"
    );
}

/// Exhaustive proof for short inputs: every string up to `LEN`
/// characters over the alphabet that drives path parsing (both
/// separators, dot, drive colon, a plain name character, and a space)
/// satisfies the contract. Fuzzing and proptest sample this space;
/// this covers it completely, which is what makes the Windows-shaped
/// corners — `//`, `C:`, `C:..`, `\\`, mixed styles — impossible to
/// miss. Since parsing is textual, passing here means passing on every
/// host OS.
#[test]
fn normalize_holds_for_every_short_path() {
    const ALPHABET: [char; 6] = ['/', '\\', '.', ':', 'C', ' '];
    // 6^6 + … ≈ 56k inputs — long enough to spell out a full drive
    // traversal (`C:..\C`), and still under a second in a debug build,
    // so it runs on every `cargo test`.
    const LEN: usize = 6;

    let mut input = String::new();
    for len in 0..=LEN {
        // An odometer of `len` digits over the alphabet enumerates
        // every string of that length exactly once.
        let mut digits = vec![0usize; len];
        loop {
            input.clear();
            input.extend(digits.iter().map(|&d| ALPHABET[d]));
            assert_normalize_invariants(&input);

            let mut place = len;
            let mut wrapped = true;
            while place > 0 {
                place -= 1;
                digits[place] += 1;
                if digits[place] < ALPHABET.len() {
                    wrapped = false;
                    break;
                }
                digits[place] = 0;
            }
            // Carried past the first place (or there are no places at
            // all): this length is exhausted.
            if wrapped {
                break;
            }
        }
    }
}

proptest::proptest! {
    /// Property (mirrors the fuzz target on every `cargo test` run): a
    /// normalized absolute path never keeps a `..` component, and
    /// normalize is idempotent.
    #[test]
    fn prop_normalize_never_leaves_dotdot_and_is_idempotent(
        pieces in proptest::collection::vec(
            proptest::prelude::prop_oneof![
                proptest::prelude::Just("a"),
                proptest::prelude::Just("bb"),
                proptest::prelude::Just(".."),
                proptest::prelude::Just("."),
                proptest::prelude::Just(""),
                proptest::prelude::Just("/"),
                proptest::prelude::Just("\\"),
                proptest::prelude::Just("C:"),
                proptest::prelude::Just("C:\\"),
                proptest::prelude::Just("x/y"),
                proptest::prelude::Just("..."),
                proptest::prelude::Just("..a"),
                proptest::prelude::Just(" "),
            ],
            0..8,
        ),
        // 0 = no separator, 1 = POSIX, 2 = Windows, so both styles
        // (and mixtures of them) are generated.
        separators in proptest::collection::vec(0u8..3, 0..8),
    ) {
        let mut input = String::new();
        for (i, piece) in pieces.iter().enumerate() {
            input.push_str(piece);
            match separators.get(i).copied().unwrap_or(0) {
                1 => input.push('/'),
                2 => input.push('\\'),
                _ => {}
            }
        }
        // The same contract the exhaustive test and the fuzz target
        // check; proptest reaches the longer, structured inputs
        // exhaustion cannot.
        assert_normalize_invariants(&input);

        // Joined under a trusted base, the mount pattern: whatever
        // comes back is still safe to prefix-check.
        for base in ["/srv/app", r"C:\srv\app", r"\\srv\app"] {
            let under = join(&[base.to_string(), input.clone()]);
            assert_normalize_invariants(&under);
            proptest::prop_assert!(
                is_absolute(&normalize(&under)),
                "{:?} under {} lost its root", input, base
            );
        }

        // And under a drive-relative base: joining must not promote
        // `C:` to the anchored `C:\` (which would both change what
        // the path names and let normalize swallow `..` segments).
        let under_drive = join(&["C:".to_string(), input.clone()]);
        assert_normalize_invariants(&under_drive);
        proptest::prop_assert!(
            !is_absolute(&normalize(&under_drive)),
            "{:?} under C: became anchored: {:?}", input, under_drive
        );
    }
}
