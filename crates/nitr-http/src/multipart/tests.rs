// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use hyper::body::Bytes;

use super::upload::{FALLBACK_NAME, NAME_MAX};
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
        let outside = std::env::temp_dir().join(format!("nitr-upload-out-{}", std::process::id()));
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
