// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The text coercion behind validated query strings, forms, path
//! parameters and headers: `integer`, `number` and `boolean` parsed from
//! the exact text a client sends (`nitr_std::fuzzing::coerce_for_fuzzing`).
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! value…
//! ```
//!
//! The whole input is the value, as with `validate-formats`. The parsers
//! are `str::parse` behind a few refusals, so a crash-only target proves
//! little; what is asserted is the contract the checker relies on:
//!
//! * An accepted integer **round-trips**: `text == parsed.to_string()`.
//!   That is exactly the strictness rule — no `+`, no whitespace, no
//!   leading zeros beyond `0` itself (`007` does not round-trip), no
//!   exponent — spelled as one relation instead of a list.
//! * An accepted number is **finite** and not written with an exponent,
//!   a hex prefix or a sign the form never means.
//! * `boolean` accepts exactly the five spellings a form can produce.
//! * Whatever the integer parser accepts, the number parser accepts too
//!   with the same value as an `f64` (an `integer` rule is a subset of
//!   `number`; past 2^53 both sides round the same way).

#![no_main]

use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_std::fuzzing::coerce_for_fuzzing;

fuzz_target!(|data: &[u8]| {
    let text = Input::new(data).text();
    let (int, num, boolean) = coerce_for_fuzzing(&text);

    if let Some(i) = int {
        assert_eq!(i.to_string(), &*text, "an accepted integer round-trips");
        // Both sides round the same decimal to the nearest f64, so this
        // holds past 2^53 too, where `as i64` would not.
        assert_eq!(
            num,
            Some(i as f64),
            "integer text is number text with the same value"
        );
    }
    if let Some(n) = num {
        assert!(n.is_finite(), "no infinities from text");
        for forbidden in ['e', 'E', 'x', 'X', '+', 'n', 'N', 'i', 'I', ' ', '\t'] {
            assert!(!text.contains(forbidden), "{forbidden:?} in accepted number {text:?}");
        }
        assert_eq!(text.trim(), &*text, "no surrounding whitespace");
    }
    match boolean {
        Some(true) => assert!(matches!(&*text, "true" | "1" | "on")),
        Some(false) => assert!(matches!(&*text, "false" | "0")),
        None => assert!(!matches!(&*text, "true" | "1" | "on" | "false" | "0")),
    }
});
