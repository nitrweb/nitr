// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Signed-cookie verification: attacker-controlled cookie values must
//! never panic, and only a genuine signature may verify.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&str, &str, &str, &str)| {
    let (name, raw, secret, value) = input;
    // Hostile raw value: never panics, and never verifies under a secret
    // that did not sign it (forgery would need an HMAC break).
    let _ = nitr_std::fuzzing::verify(name, raw, secret);

    // Round trip: what `sign` produced, `verify` must accept — and a
    // different name (cookie swapping) must not.
    let signed = nitr_std::fuzzing::sign(name, value, secret);
    assert_eq!(
        nitr_std::fuzzing::verify(name, &signed, secret).as_deref(),
        Some(value)
    );
    if !name.is_empty() {
        let other = format!("x{name}");
        assert_eq!(nitr_std::fuzzing::verify(&other, &signed, secret), None);
    }
});
