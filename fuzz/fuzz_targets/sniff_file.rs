// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The one client-facing byte parser validated uploads add: media-type
//! detection over an upload's first bytes and the header-only image
//! dimension readers (`nitr_std::fuzzing::{sniff_file, sniff_dimensions}`).
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! prefix…
//! ```
//!
//! The whole input is the prefix the spooler would have sniffed. These
//! readers index into attacker bytes by offsets they read from those same
//! bytes (ZIP local headers, JPEG segment lengths, TIFF IFD offsets), so
//! the crash surface is real here, unlike the format checkers; every read
//! must be bounds-checked. Beyond "never panics", what is asserted:
//!
//! * **Detection is a prefix judgement**: an executable stays an
//!   executable with more bytes — the executable magics are the shortest
//!   signatures and are tested first — and a detected type may be refined
//!   by more bytes within its family (or out of a ZIP container) but never
//!   moved to another family.
//! * **Text means text**: a `Text` verdict implies the prefix decodes as
//!   UTF-8 up to at most three trailing bytes and carries no NUL.
//! * **Dimensions are only claimed for image types with a reader**, and a
//!   claimed dimension came from the bytes, so reading the same prefix
//!   twice agrees (no state, no allocation growth with the claimed size —
//!   a 100 000 × 100 000 header is two numbers, not a buffer).

#![no_main]

use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_std::fuzzing::{sniff_dimensions, sniff_file};
use nitr_std::validation::Detection;

fuzz_target!(|data: &[u8]| {
    let prefix = Input::new(data).rest();
    let verdict = sniff_file(prefix);

    // Stable under appending: the signature lives in the first bytes.
    let mut longer = prefix.to_vec();
    longer.extend_from_slice(b"\0\0\0\0trailing");
    match (verdict, sniff_file(&longer)) {
        (Detection::Detected(a), Detection::Detected(b)) => {
            // More bytes may refine a type within its family (matroska →
            // webm, wav is RIFF) or resolve a ZIP container (zip → docx);
            // they never move it to another family.
            let family = |name: &str| name.split('/').next().unwrap_or(name).to_string();
            assert!(
                a == b || a.name == "application/zip" || family(a.name) == family(b.name),
                "{} became {}",
                a.name,
                b.name
            );
        }
        (Detection::Executable, other) => assert_eq!(other, Detection::Executable),
        (Detection::Text, _) | (Detection::Unknown, _) => {}
        (Detection::Detected(a), other) => panic!("{} became {other:?} with more bytes", a.name),
    }

    if verdict == Detection::Text {
        assert!(!prefix.contains(&0), "text has no NUL");
        let body = prefix.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(prefix);
        match std::str::from_utf8(body) {
            Ok(_) => {}
            Err(err) => assert!(
                err.error_len().is_none() && body.len() - err.valid_up_to() <= 3,
                "text verdict on invalid UTF-8 at {}",
                err.valid_up_to()
            ),
        }
    }

    if let Detection::Detected(media) = verdict {
        let dims = sniff_dimensions(media, prefix);
        if !media.has_dimensions() {
            assert!(dims.is_none(), "{} has no dimension reader", media.name);
        }
        assert_eq!(dims, sniff_dimensions(media, prefix), "reading twice agrees");
        // Executables are a family that never matches a type list; a
        // detected type is never one of them.
        assert!(!media.name.contains("executable"));
    }
});
