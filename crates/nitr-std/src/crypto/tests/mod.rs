// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `nitr.crypto` table itself: digests, AEAD, and `nitr.auth` parsing.

mod jwt;
mod passwords;

// `base64::Engine` for `B64.encode` arrives through `use super::*`: the
// crypto module imports the trait, and an underscore trait import
// propagates through a glob — spelling it again here is flagged as a
// duplicate by newer toolchains.
use base64::engine::general_purpose::STANDARD as B64;

use super::auth::scheme_value;
use super::*;

#[test]
fn scheme_parsing_is_case_insensitive_and_strict() {
    assert_eq!(scheme_value("Bearer abc", "bearer"), Some("abc"));
    assert_eq!(scheme_value("bearer abc", "bearer"), Some("abc"));
    assert_eq!(
        scheme_value("  Basic dXNlcg==  ", "basic"),
        Some("dXNlcg==")
    );
    assert_eq!(scheme_value("Bearer", "bearer"), None);
    assert_eq!(scheme_value("Bearer ", "bearer"), None);
    assert_eq!(scheme_value("Basic abc", "bearer"), None);
}

/// `password_hash`, `password_verify` and `password_verify_dummy` off

#[test]
fn seal_and_open_round_trip_and_reject_tampering() {
    let lua = Lua::new();
    let crypto = create_crypto_table(&lua).expect("crypto table");
    let seal: mlua::Function = crypto.get("seal").expect("fn");
    let open: mlua::Function = crypto.get("open").expect("fn");
    let key = "0123456789abcdef0123456789abcdef"; // 32 bytes

    let sealed: String = seal.call((key, "top secret", "ctx")).expect("seal");
    let opened: Option<String> = open.call((key, sealed.clone(), "ctx")).expect("open");
    assert_eq!(opened.as_deref(), Some("top secret"));

    // Wrong key, wrong aad, tampered ciphertext, garbage: all nil.
    let other_key = "ffffffffffffffffffffffffffffffff";
    // The tamper must actually change a byte: the nonce is random, so a
    // fixed replacement character is a 1-in-64 no-op when the first
    // base64 char already is that character (a real flake seen in CI).
    let tampered = match sealed.strip_prefix('A') {
        Some(rest) => format!("B{rest}"),
        None => format!("A{}", &sealed[1..]),
    };
    for (k, sealed, aad) in [
        (other_key, sealed.clone(), Some("ctx")),
        (key, sealed.clone(), Some("other")),
        (key, sealed.clone(), None),
        (key, tampered, Some("ctx")),
        (key, "garbage".to_string(), Some("ctx")),
    ] {
        let opened: Option<String> = open.call((k, sealed, aad)).expect("open");
        assert_eq!(opened, None);
    }

    // Same plaintext seals differently every time (random nonce).
    let a: String = seal.call((key, "x", Value::Nil)).expect("seal");
    let b: String = seal.call((key, "x", Value::Nil)).expect("seal");
    assert_ne!(a, b);

    // A short key is an error, not a silently weak derivation.
    assert!(seal.call::<String>(("short", "x", Value::Nil)).is_err());
}

#[test]
fn seal_handles_degenerate_inputs() {
    let lua = Lua::new();
    let crypto = create_crypto_table(&lua).expect("crypto table");
    let seal: mlua::Function = crypto.get("seal").expect("fn");
    let open: mlua::Function = crypto.get("open").expect("fn");
    let key = "0123456789abcdef0123456789abcdef";

    // Empty plaintext is legal and still authenticated.
    let sealed: String = seal.call((key, "", Value::Nil)).expect("seal");
    let opened: Option<String> = open.call((key, sealed, Value::Nil)).expect("open");
    assert_eq!(opened.as_deref(), Some(""));

    // Truncated/garbage boxes come back nil, never a panic: shorter
    // than a nonce, valid base64 of nothing, raw garbage.
    for garbage in ["", "AAAA", "!!!not-base64!!!"] {
        let opened: Option<String> = open.call((key, garbage, Value::Nil)).expect("open");
        assert_eq!(opened, None, "accepted {garbage:?}");
    }

    // Unicode plaintext and AAD round-trip byte-exactly.
    let sealed: String = seal.call((key, "ñandú 🦤", "ctx-ñ")).expect("seal");
    let opened: Option<String> = open.call((key, sealed, "ctx-ñ")).expect("open");
    assert_eq!(opened.as_deref(), Some("ñandú 🦤"));
}

#[test]
fn digests_are_hex_and_deterministic() {
    let lua = Lua::new();
    let crypto = create_crypto_table(&lua).expect("crypto table");
    let sha256: mlua::Function = crypto.get("sha256").expect("fn");
    assert_eq!(
        sha256.call::<String>("abc").expect("digest"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // The empty input, whose digest every implementation publishes —
    // a nibble table is exactly where an off-by-one hides, and this is
    // the known answer that catches one.
    assert_eq!(
        sha256.call::<String>("").expect("digest"),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // A single byte, chosen so both its nibbles differ and neither is
    // zero: `0x61` must render as "61", not "16", "6" or "061".
    assert_eq!(
        sha256.call::<String>("a").expect("digest"),
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    );
    // Two characters per byte, lowercase, nothing else.
    for input in ["", "a", "abc"] {
        let digest = sha256.call::<String>(input).expect("digest");
        assert_eq!(digest.len(), 64, "sha256 of {input:?} is 32 bytes");
        assert!(
            digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "hex must be lowercase and complete: {digest}"
        );
    }

    // `hex` is shared with the MAC, so pin that caller too rather than
    // leaving one of the two encoders untested.
    let hmac: mlua::Function = crypto.get("hmac_sha256").expect("fn");
    let mac = hmac.call::<String>(("key", "abc")).expect("mac");
    assert_eq!(mac.len(), 64);
    assert!(
        mac.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );

    let eq: mlua::Function = crypto.get("constant_time_eq").expect("fn");
    assert!(eq.call::<bool>(("same", "same")).expect("eq"));
    assert!(!eq.call::<bool>(("same", "diff")).expect("eq"));
    assert!(!eq.call::<bool>(("same", "longer-value")).expect("eq"));
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    /// Property: a `Basic` header round-trips to exactly the
    /// credentials it encodes, and every other scheme yields nothing
    /// — the scheme is matched whole and case-insensitively, never as
    /// a prefix.
    #[test]
    fn prop_basic_is_scheme_bound_and_round_trips(
        scheme in proptest::sample::select(vec![
            "Basic", "basic", "BASIC", "BaSiC",
            "Bearer", "bearer", "Digest", "Negotiate", "", "Basicx", "asic",
        ]),
        user in "[^:\u{0}]{0,16}",
        pass in "[ -~]{0,24}",
        lead in proptest::sample::select(vec!["", " ", "  ", "\t"]),
    ) {
        let lua = Lua::new();
        let auth = create_auth_table(&lua).expect("auth table");
        let basic: mlua::Function = auth.get("basic").expect("basic");

        let encoded = B64.encode(format!("{user}:{pass}"));
        let header = format!("{lead}{scheme} {encoded}");
        let (got_user, got_pass): (Option<String>, Option<String>) =
            basic.call(header.as_str()).expect("basic never raises");

        if scheme.eq_ignore_ascii_case("basic") {
            proptest::prop_assert_eq!(got_user.as_deref(), Some(user.as_str()));
            proptest::prop_assert_eq!(got_pass.as_deref(), Some(pass.as_str()));
        } else {
            proptest::prop_assert_eq!(got_user, None);
            proptest::prop_assert_eq!(got_pass, None);
        }
    }

    /// Property: `nitr.auth.basic` is total over arbitrary header
    /// bytes — it never raises, never returns half a credential pair,
    /// and whatever it does return really is the base64 the header
    /// carried, under a scheme spelled `basic`.
    #[test]
    fn prop_arbitrary_authorization_headers_never_yield_credentials(
        header in "[\u{0}-\u{7f}]{0,64}",
    ) {
        let lua = Lua::new();
        let auth = create_auth_table(&lua).expect("auth table");
        let basic: mlua::Function = auth.get("basic").expect("basic");
        let bearer: mlua::Function = auth.get("bearer").expect("bearer");

        let (user, pass): (Option<String>, Option<String>) = basic
            .call(header.as_str())
            .expect("basic never raises");
        proptest::prop_assert_eq!(
            user.is_some(),
            pass.is_some(),
            "half a credential pair for {:?}",
            header
        );

        // The value a caller would have to trust, recomputed here:
        // scheme split, trim, base64 decode, first-colon split.
        let value = header
            .trim()
            .split_once(' ')
            .filter(|(found, _)| found.eq_ignore_ascii_case("basic"))
            .map(|(_, value)| value.trim());
        if let (Some(user), Some(pass)) = (&user, &pass) {
            let reencoded = B64.encode(format!("{user}:{pass}"));
            proptest::prop_assert_eq!(
                value,
                Some(reencoded.as_str()),
                "credentials that are not the header's own base64: {:?}",
                header
            );
        }

        // The sibling parser must not answer for a `Basic` header.
        let token: Option<String> = bearer
            .call(header.as_str())
            .expect("bearer never raises");
        if token.is_some() {
            proptest::prop_assert!(
                header.trim().to_ascii_lowercase().starts_with("bearer "),
                "a bearer token out of {:?}",
                header
            );
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]
    /// Property: seal/open round-trips arbitrary binary plaintexts and
    /// aads, and a single changed character at any position — or the
    /// wrong key — never opens.
    #[test]
    fn prop_seal_open_round_trips_and_rejects_tampering(
        plaintext in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
        aad in proptest::option::of("[ -~]{1,16}"),
        pos in proptest::prelude::any::<proptest::sample::Index>(),
    ) {
        let lua = Lua::new();
        let crypto = create_crypto_table(&lua).expect("crypto table");
        let seal: mlua::Function = crypto.get("seal").expect("fn");
        let open: mlua::Function = crypto.get("open").expect("fn");
        let key = "0123456789abcdef0123456789abcdef";
        let other_key = "ffffffffffffffff0000000000000000";
        let input = lua.create_string(&plaintext).expect("bytes");

        let sealed: String = seal.call((key, &input, aad.as_deref())).expect("seal");
        let opened: Option<mlua::LuaString> = open
            .call((key, sealed.as_str(), aad.as_deref()))
            .expect("open");
        let opened = opened.expect("opened");
        let opened_bytes = opened.as_bytes();
        proptest::prop_assert_eq!(opened_bytes.as_ref(), &plaintext[..]);

        proptest::prop_assert_eq!(
            open.call::<Option<String>>((other_key, sealed.as_str(), aad.as_deref()))
                .expect("open"),
            None
        );

        // Flip one character at any position to a different one.
        let pos = pos.index(sealed.len());
        let mut tampered: Vec<char> = sealed.chars().collect();
        tampered[pos] = if tampered[pos] == 'A' { 'B' } else { 'A' };
        let tampered: String = tampered.into_iter().collect();
        proptest::prop_assert_eq!(
            open.call::<Option<String>>((key, tampered, aad.as_deref()))
                .expect("open"),
            None
        );
    }
}
