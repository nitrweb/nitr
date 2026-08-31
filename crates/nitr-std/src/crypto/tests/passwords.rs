// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `password_hash` / `password_verify` / `password_verify_dummy`.

use mlua::Lua;

use crate::crypto::VERIFY_REASONS;
use crate::crypto::create_crypto_table;
use crate::crypto::password::{DECOY_HASH, MAX_PASSWORD_BYTES, hash_ident, parse_stored_hash};

/// one crypto table, for the tests below.
fn password_fns(lua: &Lua) -> (mlua::Function, mlua::Function, mlua::Function) {
    let crypto = create_crypto_table(lua).expect("crypto table");
    (
        crypto.get("password_hash").expect("password_hash"),
        crypto.get("password_verify").expect("password_verify"),
        crypto
            .get("password_verify_dummy")
            .expect("password_verify_dummy"),
    )
}

/// Drives one async Lua call to completion on a throwaway runtime.
///
/// The three password functions offload argon2 to `spawn_blocking`, so
/// they are async and need a reactor. A helper rather than
/// `#[tokio::test]` on each test because the proptest block below is
/// sync by construction and needs the same path — and because argon2
/// itself dwarfs the cost of building a current-thread runtime.
fn pw<R: mlua::FromLuaMulti + 'static>(
    f: &mlua::Function,
    args: impl mlua::IntoLuaMulti,
) -> mlua::Result<R> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(f.call_async::<R>(args))
}

#[test]
fn passwords_hash_and_verify() {
    let lua = Lua::new();
    let (hash_fn, verify, _) = password_fns(&lua);
    let hash: String = pw(&hash_fn, "hunter2").expect("hash");
    assert!(hash.starts_with("$argon2id$"), "got: {hash}");

    // A correct password verifies, with no reason attached.
    let (ok, why): (bool, Option<String>) = pw(&verify, ("hunter2", hash.clone())).expect("verify");
    assert!(ok);
    assert_eq!(why, None);

    // A wrong password against a usable hash is `false, nil`: the
    // absent reason is what says "the hash was fine".
    let (ok, why): (bool, Option<String>) = pw(&verify, ("wrong", hash)).expect("verify");
    assert!(!ok);
    assert_eq!(why, None);

    // The old single-value call shape still works — callers written
    // against `local ok = password_verify(...)` must not break.
    let hash: String = pw(&hash_fn, "hunter2").expect("hash");
    assert!(pw::<bool>(&verify, ("hunter2", hash)).expect("verify"));
}

/// Every stored hash Nitr cannot verify names *why*, instead of being
/// reported as a wrong password forever. The bcrypt/md5crypt/
/// sha512crypt rows are the migration case that motivated this.
#[test]
fn an_unusable_stored_hash_is_distinguishable_from_a_wrong_password() {
    let lua = Lua::new();
    let (_, verify, _) = password_fns(&lua);

    for (stored, expected) in [
        // bcrypt: `$2b$`/`$2y$` never reach the argon2 verifier —
        // PHC parsing rejects the salt segment first.
        (
            "$2b$12$K3JNi5tR9lHnKKfKzXBDUuJ7dK1nGVX8UEcqfQe5NRaTZY0aWkNSe",
            "unsupported hash format",
        ),
        (
            "$2y$10$abcdefghijklmnopqrstuv0123456789012345678901234567890",
            "unsupported hash format",
        ),
        ("$1$salt$qJH7.N4xYta3aEG/dfqo/0", "unsupported hash format"),
        (
            "$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.",
            "unsupported hash format",
        ),
        ("not-a-hash", "unsupported hash format"),
        ("", "unsupported hash format"),
        // Parses as PHC, names an algorithm this verifier is not.
        (
            "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CmdRSCdEBsjjJxD+iCs5E",
            "unsupported hash algorithm",
        ),
        // Well-formed argon2id, but the salt/output segments are gone.
        // The blanket `PasswordVerifier` impl reports this as
        // `Error::Password` — i.e. as a wrong password — which is
        // exactly the silent dead end this check exists to stop.
        ("$argon2id$v=19$m=19456,t=2,p=1", "incomplete hash"),
        (
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ",
            "incomplete hash",
        ),
        // A row that would ask the verifier for 4 GiB before it could
        // answer "wrong password".
        (
            "$argon2id$v=19$m=4194304,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "hash parameters out of range",
        ),
        (
            "$argon2id$v=19$m=19456,t=4294967295,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "hash parameters out of range",
        ),
        // An unknown PHC parameter name, and an unknown version.
        (
            "$argon2id$v=19$m=19456,t=2,p=1,zz=9$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "unusable hash",
        ),
        (
            "$argon2id$v=99$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "unusable hash",
        ),
    ] {
        let (ok, why): (bool, Option<String>) = pw(&verify, ("hunter2", stored)).expect("verify");
        assert!(!ok, "{stored:?} verified");
        assert_eq!(why.as_deref(), Some(expected), "for {stored:?}");
        assert!(
            VERIFY_REASONS.contains(&expected),
            "{expected:?} is not in VERIFY_REASONS"
        );
    }

    // The other side of the line: a *usable* argon2 hash at the
    // format's minimum cost is a wrong password (`false, nil`), not a
    // complaint about the hash. Weak parameters are a policy question
    // for whoever wrote the row, not a verification failure — and the
    // fuzz target leans on this entry to reach the KDF cheaply.
    let (ok, why): (bool, Option<String>) = pw(
        &verify,
        (
            "hunter2",
            "$argon2id$v=19$m=8,t=1,p=1$mHVoGfzni7/d60QmEsVJlw$\
             7rFvapCGZeh96Zf4R2I/pEVmV2YRWxfl6xo5yGL3F6Q",
        ),
    )
    .expect("verify");
    assert!(!ok);
    assert_eq!(why, None);

    // The identifier that goes into the log line, and nothing else.
    assert_eq!(
        hash_ident("$argon2id$v=19$m=8,t=1,p=1$c2E$aGFzaA"),
        "argon2id"
    );
    assert_eq!(hash_ident("$2b$12$xxxx"), "2b");
    assert_eq!(hash_ident("not-a-hash"), "unknown");
    assert_eq!(hash_ident("$$empty"), "unknown");
    assert_eq!(hash_ident(&format!("${}$x", "a".repeat(33))), "unknown");
    assert_eq!(hash_ident("$argon2 id$x"), "unknown");
}

/// The cap exists so a login form cannot be used as a CPU/memory
/// amplifier. Checked at the boundary and one byte past it, on every
/// entry point that hashes.
#[test]
fn oversized_passwords_are_refused_before_any_argon2_work() {
    let lua = Lua::new();
    let (hash_fn, verify, dummy) = password_fns(&lua);

    let at_cap = "x".repeat(MAX_PASSWORD_BYTES);
    let over_cap = "x".repeat(MAX_PASSWORD_BYTES + 1);

    let hash: String = pw(&hash_fn, at_cap.clone()).expect("a 1 KiB password hashes");
    assert!(pw::<bool>(&verify, (at_cap.clone(), hash)).expect("verify"));
    assert!(!pw::<bool>(&dummy, at_cap).expect("dummy"));

    let err = pw::<String>(&hash_fn, over_cap.clone()).expect_err("1 KiB + 1 byte must not hash");
    assert!(
        err.to_string().contains("at most 1024 bytes"),
        "unhelpful error: {err}"
    );
    // Verification and the decoy verify are capped too — an attacker
    // reaches those without ever registering — but they *answer*
    // rather than raise, so the naive login handler is safe out of
    // the box: an oversized POST is a 401, not a 500. And they answer
    // `false, nil`, not a reason: the reason channel means "the row
    // is at fault, log it", and this trigger is attacker input. The
    // stored hash here is malformed on purpose — the length check
    // must win, or an oversized password would still warn about the
    // row.
    let (ok, why): (bool, Option<String>) = pw(&verify, (over_cap.clone(), "$argon2id$"))
        .expect("an over-cap password answers, it does not raise");
    assert!(!ok);
    assert_eq!(why, None, "an over-cap password is an ordinary miss");
    assert!(!pw::<bool>(&dummy, over_cap).expect("dummy answers false"));

    // The cap is data a script can read, and it matches the enforced
    // constant — a drifted copy would send registration forms a 400
    // at the wrong boundary.
    let published: usize = create_crypto_table(&lua)
        .expect("crypto table")
        .get("max_password_bytes")
        .expect("max_password_bytes");
    assert_eq!(published, MAX_PASSWORD_BYTES);
}

/// The equal-cost unknown-user path. The value assertion is cheap; the
/// timing property it exists for is argued in `dummy_verify`'s docs
/// and demonstrated in `examples/basic-auth`.
#[test]
fn the_dummy_verify_is_always_false_and_costs_a_real_hash() {
    let lua = Lua::new();
    let (_, _, dummy) = password_fns(&lua);

    for password in ["", "hunter2", "\0\u{feff}ñ", &"x".repeat(512)] {
        assert!(!pw::<bool>(&dummy, password).expect("dummy"));
    }

    // The decoy is one process-wide hash with the same parameters a
    // real credential gets — that identity is what makes the two login
    // branches cost the same.
    let decoy = DECOY_HASH.get().expect("built by the calls above");
    assert!(
        decoy.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
        "{decoy}"
    );
    assert!(parse_stored_hash(decoy).is_ok());
}

proptest::proptest! {
    // Eight cases, not the 48 the cheap properties use: every case
    // runs argon2id three times at 19 MiB and ~26 ms each. The
    // invariant is not statistical — one wrong answer would be a
    // catastrophe, not a rare event — so what matters is that odd
    // inputs (empty, NUL-bearing, non-UTF-8, at the cap) reach it at
    // all. The fuzz target supplies the volume.
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(8))]

    /// Property: every password within the cap verifies against its
    /// own hash and against no other password's, with no reason
    /// attached either way — a reason means the *hash* was at fault,
    /// and a hash this module just produced never is.
    #[test]
    fn prop_password_round_trips_and_rejects_every_other_password(
        password in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..96),
        other in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..96),
    ) {
        let lua = Lua::new();
        let (hash_fn, verify, dummy) = password_fns(&lua);
        let secret = lua.create_string(&password).expect("bytes");

        let hash: String = pw(&hash_fn, &secret).expect("hash");
        proptest::prop_assert!(hash.starts_with("$argon2id$"), "got: {}", hash);

        let (ok, why): (bool, Option<String>) =
            pw(&verify, (&secret, hash.clone())).expect("verify");
        proptest::prop_assert!(ok, "a password did not verify against its own hash");
        proptest::prop_assert_eq!(why, None);

        if other != password {
            let wrong = lua.create_string(&other).expect("bytes");
            let (ok, why): (bool, Option<String>) =
                pw(&verify, (&wrong, hash)).expect("verify");
            proptest::prop_assert!(!ok, "a different password verified");
            proptest::prop_assert_eq!(why, None);
        }

        // The unknown-user path answers false for anything.
        proptest::prop_assert!(!pw::<bool>(&dummy, &secret).expect("dummy"));
    }
}
