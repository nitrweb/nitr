// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Signed cookies: `sign` / `verify` (HMAC-SHA256 over `name "=" payload`,
//! `base64url` no-pad on both halves). `req.cookies:verify(name, secret)`
//! is an authentication decision made on a string the client chose, so the
//! interesting question is never "does it crash" but "what else, besides
//! the genuine article, does it accept".
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u16 tamper | u16 cut | name \0 secret \0 other_secret \0 hostile \0 value
//! ```
//!
//! Two positions come off the front so libFuzzer can steer *where* the
//! signed string is damaged instead of only what goes into it: `tamper`
//! picks the character to corrupt, `cut` a truncation point. `hostile` is
//! a signed string the fuzzer wrote itself — the forgery attempt — and
//! doubles as an alternative cookie name, which is the adversarial input
//! the name-binding claim actually needs (`format!("x{name}")` only ever
//! probes one shape). `value` is last so it grows to the end of the input.
//!
//! Note on the two "different key" assertions: HMAC collapses keys longer
//! than its 64-byte block through SHA-256, and pads shorter ones with
//! zeros, so two *distinct* secrets can address one key. Neither route is
//! reachable here — a NUL cannot occur in a NUL-separated field, and a raw
//! SHA-256 digest is not text — so the assertions are safe as written.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **The signed value is a legal cookie octet string.** Every byte of
//!   `sign`'s output is `[A-Za-z0-9._-]` with exactly one `.`. This goes
//!   straight into a `Set-Cookie` header via `cookies:set_signed`; a
//!   codec change that emitted `;`, `,`, a space or a quote would be
//!   header injection, and would still round-trip perfectly.
//! * **The MAC is whole and so is the payload.** The signature is 43
//!   characters — `base64url` of a full 32-byte SHA-256 — and the payload
//!   is exactly `ceil(4n/3)` characters for an `n`-byte value. A MAC
//!   silently truncated to 8 bytes, or a payload capped at some length,
//!   round-trips and verifies and is much weaker; only a length check
//!   notices.
//! * **Round trip.** What `sign` produced, `verify` returns intact.
//! * **A different secret is refused, and does not even produce the same
//!   string.** Signing under one secret and verifying under another must
//!   fail, and the two signatures must differ — an implementation that
//!   ignored the secret entirely would pass a round-trip test and fail
//!   both of these. The secret is the fuzzer's, not the literal
//!   `"other-secret"` the proptest in `nitr-std/src/http.rs` uses.
//! * **A different name is refused.** The name is bound into the MAC so a
//!   value cannot be moved between cookies (`session` <- `tracking`).
//!   Probed with the fuzzer's own second name, not a fixed mutation.
//! * **One character is enough to break it.** Every position of the signed
//!   string — payload, separator, signature — is fair game, indexed over
//!   *characters* so the target can never slice through a UTF-8 boundary,
//!   matching what `prop_signed_cookies_round_trip_and_any_tamper_fails`
//!   in `nitr-std/src/http.rs` deliberately does. A MAC compared on a
//!   prefix, or taken over the decoded rather than the encoded payload,
//!   survives a round-trip test and dies here.
//! * **No strict prefix verifies.** Truncation is the other half of
//!   tampering, and the cuts that matter — nothing, the payload alone, the
//!   payload plus the separator, one character short — are always checked,
//!   so an empty signature can never be read as a match.
//! * **A forgery that verifies must be the genuine signing of what it
//!   decodes to.** The hostile string's result is *used*, not discarded:
//!   if it verifies, re-signing the value it yielded has to reproduce it
//!   byte for byte. `base64url` no-pad decoding rejects non-canonical
//!   trailing bits, so this holds — and were it to fail, that is signature
//!   malleability: one authenticated value with two accepted spellings.
#![no_main]
use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_std::fuzzing::{sign, verify};

/// `base64url` of a 32-byte SHA-256, unpadded.
const SIG_CHARS: usize = 43;

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let tamper = usize::from(input.u16());
    let cut = usize::from(input.u16());
    let name = input.text();
    let secret = input.text();
    let other_secret = input.text();
    let hostile = input.text();
    let value = input.text();

    let signed = sign(&name, &value, &secret);

    // --- the shape of what goes into Set-Cookie -------------------------
    assert!(
        signed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "sign({name:?}, {value:?}) = {signed:?} is not a legal cookie value; it is written \
         verbatim into a Set-Cookie header"
    );
    assert_eq!(
        signed.matches('.').count(),
        1,
        "sign({name:?}, {value:?}) = {signed:?} does not have exactly one payload/signature \
         separator"
    );
    let dot = signed.find('.').expect("separator");
    assert_eq!(
        signed.len() - dot - 1,
        SIG_CHARS,
        "sign({name:?}, {value:?}) = {signed:?} carries a {}-character signature, not the {} of \
         a whole SHA-256; a truncated MAC still round-trips and is far cheaper to forge",
        signed.len() - dot - 1,
        SIG_CHARS
    );
    // Unpadded base64 of n bytes is ceil(4n/3) characters, so this pins
    // that the entire value went into the payload.
    assert_eq!(
        dot,
        (value.len() * 4 + 2) / 3,
        "sign({name:?}, {value:?}) = {signed:?} encoded a {}-byte value into a {dot}-character \
         payload",
        value.len()
    );

    // --- round trip ------------------------------------------------------
    assert_eq!(
        verify(&name, &signed, &secret).as_deref(),
        Some(&*value),
        "verify did not return the value sign was given: name={name:?} value={value:?} \
         secret={secret:?} signed={signed:?}"
    );

    // --- a different secret ----------------------------------------------
    if other_secret != secret {
        let elsewhere = sign(&name, &value, &other_secret);
        assert_ne!(
            elsewhere, signed,
            "sign produced the same string under {secret:?} and {other_secret:?}: the secret is \
             not reaching the MAC (name={name:?} value={value:?})"
        );
        assert_eq!(
            verify(&name, &signed, &other_secret),
            None,
            "a cookie signed with {secret:?} verified under {other_secret:?}: name={name:?} \
             value={value:?} signed={signed:?}"
        );
    }

    // --- a different cookie name ------------------------------------------
    if hostile != name {
        assert_ne!(
            sign(&hostile, &value, &secret),
            signed,
            "sign produced the same string for the cookies {name:?} and {hostile:?}: the name is \
             not reaching the MAC (value={value:?})"
        );
        assert_eq!(
            verify(&hostile, &signed, &secret),
            None,
            "the value of the cookie {name:?} verified as the cookie {hostile:?}, so a signed \
             value can be moved between cookies: value={value:?} signed={signed:?}"
        );
    }

    // --- one character changed ---------------------------------------------
    // Over characters, not bytes: `sign`'s output is ASCII (asserted
    // above), but indexing it as bytes is the bug the proptest version
    // carries, and a target must not repeat it.
    let chars: Vec<char> = signed.chars().collect();
    let at = tamper % chars.len(); // never empty: `.` plus 43 signature characters
    let original = chars[at];
    let replacement = if original == 'A' { 'B' } else { 'A' };
    let tampered: String = chars
        .iter()
        .enumerate()
        .map(|(i, c)| if i == at { replacement } else { *c })
        .collect();
    assert_eq!(
        verify(&name, &tampered, &secret),
        None,
        "changing character {at} of {signed:?} from {original:?} to {replacement:?} still \
         verified: name={name:?} secret={secret:?}"
    );

    // --- truncation ---------------------------------------------------------
    // Every character boundary for a short signed value; otherwise the four
    // structural cuts (nothing at all, the payload alone, the payload plus
    // its separator, one character short) and one the fuzzer chooses.
    let boundaries: Vec<usize> = signed.char_indices().map(|(i, _)| i).collect();
    let mut cuts: BTreeSet<usize> = [0, dot, dot + 1, signed.len() - 1].into_iter().collect();
    if boundaries.len() <= 64 {
        cuts.extend(boundaries.iter().copied());
    } else {
        cuts.insert(boundaries[cut % boundaries.len()]);
    }
    for cut in cuts {
        let prefix = &signed[..cut];
        assert_eq!(
            verify(&name, prefix, &secret),
            None,
            "the {cut}-character prefix {prefix:?} of {signed:?} verified: name={name:?} \
             secret={secret:?}"
        );
    }

    // --- the fuzzer's own signed string --------------------------------------
    if let Some(recovered) = verify(&name, &hostile, &secret) {
        // It verified, so it is not a forgery — it is the genuine signing
        // of `recovered`, and must be spelled the one canonical way.
        assert_eq!(
            sign(&name, &recovered, &secret),
            hostile,
            "{hostile:?} verified as {recovered:?} under the cookie {name:?}, but signing \
             {recovered:?} gives {:?}: one authenticated value has two accepted spellings",
            sign(&name, &recovered, &secret)
        );
        if other_secret != secret {
            assert_eq!(
                verify(&name, &hostile, &other_secret),
                None,
                "{hostile:?} verified under both {secret:?} and {other_secret:?}"
            );
        }
    }
});
