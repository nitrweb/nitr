// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The whole Basic-auth credential path — `nitr.auth.basic`'s scheme
//! split, base64 decode, UTF-8 check and first-colon split, then
//! `nitr.crypto.password_verify` over an arbitrary *stored* hash, plus
//! the length cap and the equal-cost `password_verify_dummy` — driven
//! **through Lua** (`nitr_std::fuzzing::create_crypto_table`) exactly as a
//! login handler drives it, so the mlua boundary is inside the fuzzed
//! path rather than bypassed.
//!
//! Both halves of the path are attacker-supplied in the real world. The
//! header is obvious. The stored hash is the subtler one: it is whatever
//! the users table happens to hold — a bcrypt row a migration left
//! behind, a truncated column, a parameter set naming 4 GiB of scratch
//! memory — and `verify_password` takes its cost parameters from the hash
//! rather than from `Argon2::default()`.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u8 work | u8 mutate | u8 hash | user \0 password \0 stored-hash \0 header
//! ```
//!
//! `work` gates the expensive assertions (see below), `mutate` picks the
//! byte flipped for the wrong-password check, `hash` selects a stored hash
//! from [`STORED`] or — one past its end — the fuzzer's own `stored-hash`
//! field. `user` and `password` are raw bytes (a credential is not text),
//! and `header` is the last field, so it grows to the end of the input and
//! is what a corpus entry is really about.
//!
//! ## Cost
//!
//! One argon2id hash at Nitr's parameters is ~26 ms and 19 MiB — and
//! ~240 ms measured under the sanitizer build this runs in, four orders of
//! magnitude past a header parse. A KDF is in this path by construction,
//! so three things keep one input from eating the whole budget:
//!
//! * the round trip that needs a full-cost hash runs on 1 execution in 32
//!   (`work % 32`);
//! * [`too_expensive_to_run`] keeps a fuzzer-built hash that *declares* a
//!   large cost away from the verifier — a stored hash may legally ask for
//!   256 MiB and eight passes, which would run past libFuzzer's
//!   `-timeout=25` and be reported as a hang that is not a bug;
//! * the dictionary carries no default-parameter hash, only
//!   [`MIN_COST_HASH`]. That last part is not a detail: with
//!   `m=19456,t=2,p=1` among its tokens the fuzzer assembles a full-cost
//!   hash within seconds and the target settles at ~14 exec/s, spending
//!   its budget inside the KDF rather than in the parsers this target is
//!   about.
//!
//! What none of that skips: every *parsing* verdict, including the cost
//! ceilings, which are refused before any KDF pass and are asserted
//! deterministically through [`STORED`]. Nitr's own parameters are covered
//! by the sampled round trip, by the `argon2-correct-password` seed, and
//! deterministically by the `nitr-std` property tests.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **Credentials come back only for the `Basic` scheme, and they are
//!   the header's own base64.** Re-encoding `user:pass` must reproduce the
//!   header's value byte for byte, which pins the scheme match, the trim,
//!   the base64 decode, the UTF-8 check *and* the first-colon split in one
//!   assertion — over arbitrary bytes. A prefix-matched scheme, a lenient
//!   base64 config, a last-colon split, or a lossy UTF-8 conversion all
//!   land here.
//! * **The pair is all-or-nothing.** One value and not the other would
//!   silently authenticate `user, nil` in `local u, p = nitr.auth.basic(req)`.
//! * **No non-argon2 hash ever verifies.** `verify` returning true means
//!   the stored hash is a PHC argon2 string. bcrypt, md5crypt,
//!   sha512crypt, scrypt, garbage, and a valid argon2 hash of a different
//!   password all have to answer false.
//! * **A rejection is either "wrong password" or a *named* reason.**
//!   `false, nil` means the hash was fine; `false, reason` means it was
//!   not, and the reason is in the real `VERIFY_REASONS` list rather than a
//!   copy of it. A true never carries a reason: a handler writes
//!   `local ok, why = password_verify(...)` and cannot have both.
//! * **The cost ceilings hold.** A stored hash naming 4 GiB, or t=2^32-1,
//!   is refused *as* a parameter problem — not by trying it.
//! * **The length cap is exact, and only the hash side raises.**
//!   `password_hash` raises above [`MAX_PASSWORD_BYTES`] — a credential
//!   that cannot be stored must fail loudly at registration. The verify
//!   side *answers* a plain `false, nil`, decided by a length comparison
//!   before argon2: on input any stranger controls, a raise is a 500
//!   where a 401 was meant, and a *reason* would be a log-spam lever
//!   through the `if problem then log` pattern. Nothing raises at or
//!   below the cap, whatever the hash looks like.
//! * **`password_verify_dummy` is total and always false.** It is the
//!   unknown-user branch of every login handler; if it could raise, the
//!   equal-cost pattern would be a liability, and if it could return true
//!   it would be an authentication bypass.
//! * **Round trip (sampled).** A fresh hash starts with Nitr's exact
//!   parameter string, verifies against its own password with no reason,
//!   and refuses any other password.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mlua::{Function, Lua, LuaString, Table, Value};
use nitr_fuzz::Input;

/// Mirrors `nitr_std::crypto::MAX_PASSWORD_BYTES`. Stated here rather
/// than imported so a change to the cap has to be made deliberately in
/// both places — the number is a compatibility promise to every stored
/// credential, not an implementation detail.
const MAX_PASSWORD_BYTES: usize = 1024;

/// The exact parameter prefix `password_hash` must keep producing:
/// argon2id, v19, m=19456 KiB, t=2, p=1 — OWASP's second recommended
/// configuration. A silent downgrade here would weaken every credential
/// minted afterwards and break nothing visible.
const HASH_PREFIX: &str = "$argon2id$v=19$m=19456,t=2,p=1$";

/// Nitr's own cost, and the ceilings it honors in a stored hash. Mirrored
/// from `nitr_std::crypto` for [`too_expensive_to_run`] only — the
/// verdicts themselves are asserted through [`STORED`], never computed
/// from these.
const NITR_M_COST: u32 = 19456;
const NITR_T_COST: u32 = 2;
const MAX_HASH_MEMORY_KIB: u32 = 256 * 1024;
const MAX_HASH_TIME_COST: u32 = 8;

/// Stored hashes with a known verdict. Everything here must answer
/// `false`, and the ones that cannot be used at all must say why.
///
/// `None` means "a wrong password, and the hash was fine" (`false, nil`);
/// `Some(reason)` means the row is unusable and must name itself.
const STORED: &[(&str, Option<&str>)] = &[
    // The migration case: bcrypt in either spelling. Neither reaches the
    // argon2 verifier — PHC parsing rejects the salt segment first.
    (
        "$2b$12$K3JNi5tR9lHnKKfKzXBDUuJ7dK1nGVX8UEcqfQe5NRaTZY0aWkNSe",
        Some("unsupported hash format"),
    ),
    (
        "$2y$10$abcdefghijklmnopqrstuv0123456789012345678901234567890",
        Some("unsupported hash format"),
    ),
    // md5crypt and sha512crypt, straight out of an /etc/shadow import.
    ("$1$salt$qJH7.N4xYta3aEG/dfqo/0", Some("unsupported hash format")),
    (
        "$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.",
        Some("unsupported hash format"),
    ),
    ("", Some("unsupported hash format")),
    ("not-a-hash", Some("unsupported hash format")),
    // Valid PHC, an algorithm this verifier is not.
    (
        "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CmdRSCdEBsjjJxD+iCs5E",
        Some("unsupported hash algorithm"),
    ),
    // A truncated column. The `PasswordVerifier` blanket impl reports a
    // hash with no output as `Error::Password` — i.e. as a wrong password
    // — so this is the case most likely to regress into silence.
    ("$argon2id$v=19$m=19456,t=2,p=1", Some("incomplete hash")),
    (
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ",
        Some("incomplete hash"),
    ),
    // Rows that name their own cost. Refused as parameters, never run:
    // the first would ask for 4 GiB of scratch memory before it could
    // answer "wrong password".
    (
        "$argon2id$v=19$m=4194304,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        Some("hash parameters out of range"),
    ),
    (
        "$argon2id$v=19$m=19456,t=4294967295,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        Some("hash parameters out of range"),
    ),
    // An unknown parameter name and an unknown version: usable syntax,
    // unusable hash.
    (
        "$argon2id$v=19$m=19456,t=2,p=1,zz=9$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        Some("unusable hash"),
    ),
    (
        "$argon2id$v=99$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        Some("unusable hash"),
    ),
    (MIN_COST_HASH, None),
];

/// A real argon2id hash at the format's minimum cost (m=8 KiB, t=1, p=1).
///
/// The one entry that actually runs the KDF on every execution, and it
/// does so in microseconds: the parsing path above would otherwise never
/// reach the comparison it exists to feed. It is a wrong password, not a
/// broken hash — weak parameters are a policy question for whoever wrote
/// the row, not a verification failure.
const MIN_COST_HASH: &str =
    "$argon2id$v=19$m=8,t=1,p=1$mHVoGfzni7/d60QmEsVJlw$7rFvapCGZeh96Zf4R2I/pEVmV2YRWxfl6xo5yGL3F6Q";

thread_local! {
    /// One Lua state for the whole process: `create_crypto_table` builds a
    /// dozen closures plus the JWT sub-table, and a fresh `Lua` costs far
    /// more than every call this target makes. Parked in the globals so
    /// nothing outlives the state; collected between runs.
    static LUA: Lua = {
        let lua = Lua::new();
        let crypto = nitr_std::fuzzing::create_crypto_table(&lua).expect("nitr.crypto table");
        let auth = nitr_std::fuzzing::create_auth_table(&lua).expect("nitr.auth table");
        lua.globals().set("crypto", crypto).expect("nitr.crypto global");
        lua.globals().set("auth", auth).expect("nitr.auth global");
        lua
    };

    /// One current-thread runtime for the whole process.
    ///
    /// `password_hash`, `password_verify` and `password_verify_dummy`
    /// offload their argon2 work to `spawn_blocking`, so they are async
    /// Lua functions and need a reactor: calling them with `Function::call`
    /// under libFuzzer panics with "there is no reactor running" on *every*
    /// input, which silently reduces this target — the one carrying the
    /// password and auth contract assertions — to zero coverage.
    static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fuzz runtime");
}

/// Drives one async Lua call to completion on the per-process runtime.
///
/// The same shape `crypto.rs`'s own test helper uses. Only the three
/// password functions need it; `auth.basic`/`auth.bearer` stay synchronous.
fn pw<R: mlua::FromLuaMulti + 'static>(
    f: &Function,
    args: impl mlua::IntoLuaMulti,
) -> mlua::Result<R> {
    RT.with(|rt| rt.block_on(f.call_async::<R>(args)))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding — the `Authorization: Basic` encoding.
///
/// Written out rather than pulled in as a dependency, and then checked
/// against the real thing: it is the oracle for the parser under test, so
/// a shared implementation would let one bug cancel the other. The RFC
/// 4648 vectors below pin it.
fn b64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = u32::from(chunk[0]) << 16
            | u32::from(chunk.get(1).copied().unwrap_or(0)) << 8
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for shift in [18, 12, 6, 0].into_iter().take(chunk.len() + 1) {
            out.push(char::from(B64[((n >> shift) & 63) as usize]));
        }
        for _ in chunk.len()..3 {
            out.push('=');
        }
    }
    out
}

/// The largest value a PHC `k=v` parameter named `name` takes in `hash`.
///
/// A guard, not a parser: it over-detects rather than under-detects, and
/// the verdict on any hash still comes from the implementation.
fn phc_param(hash: &str, name: &str) -> Option<u32> {
    hash.split(['$', ','])
        .filter_map(|field| field.strip_prefix(name))
        .filter_map(|value| value.parse().ok())
        .max()
}

/// Whether handing `hash` to the verifier can cost more than one hash at
/// Nitr's own parameters.
///
/// Not a throughput tweak. A stored hash may legally name m=256 MiB and
/// t=8 — inside the ceilings, so the KDF genuinely runs — and one pass at
/// Nitr's own parameters already costs ~240 ms in this target's sanitizer
/// build. libFuzzer's `ChangeASCIIInt` mutator turns the dictionary's
/// `m=8` into `m=800000` within seconds, so without this a single input
/// would run past `-timeout=25` and be reported as a hang that is not a
/// bug.
///
/// Anything *above* the ceilings is deliberately not filtered: those are
/// refused as parameters before any KDF pass, which is exactly the
/// behavior worth fuzzing. `p` is ignored — argon2 divides one memory
/// budget among its lanes, so parallelism does not multiply the work.
fn too_expensive_to_run(hash: &str) -> bool {
    let m = phc_param(hash, "m=").unwrap_or(0);
    let t = phc_param(hash, "t=").unwrap_or(0);
    let refused = m > MAX_HASH_MEMORY_KIB || t > MAX_HASH_TIME_COST;
    !refused && (m > NITR_M_COST || t > NITR_T_COST)
}

/// The value part of an `Authorization` header under `scheme`, or `None`
/// — the caller-side model of what `nitr.auth` must be doing.
fn scheme_value<'a>(header: &'a str, scheme: &str) -> Option<&'a str> {
    let (found, value) = header.trim().split_once(' ')?;
    found
        .eq_ignore_ascii_case(scheme)
        .then(|| value.trim())
        .filter(|v| !v.is_empty())
}

/// `auth.basic`, with the all-or-nothing contract checked.
fn parse_basic(basic: &Function, header: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let (user, pass): (Option<LuaString>, Option<LuaString>) = basic
        .call(header)
        .unwrap_or_else(|err| panic!("auth.basic raised for {header:?}: {err}"));
    match (user, pass) {
        (Some(user), Some(pass)) => {
            Some((user.as_bytes().to_vec(), pass.as_bytes().to_vec()))
        }
        (None, None) => None,
        (user, pass) => panic!(
            "auth.basic returned half a credential pair ({}, {}) for {header:?}: \
             `local u, p = nitr.auth.basic(req)` would authenticate with a nil password",
            user.is_some(),
            pass.is_some()
        ),
    }
}

/// Everything `auth.basic` must satisfy for one header, whatever it says.
/// Returns what it parsed, so a caller with a stronger expectation can
/// add to this rather than parse twice.
fn check_basic(basic: &Function, header: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let (user, pass) = parse_basic(basic, header)?;
    let value = scheme_value(header, "basic").unwrap_or_else(|| {
        panic!("auth.basic produced credentials for {header:?}, which is not a Basic header")
    });
    // Everything the parser did, undone: the credentials really are this
    // header's own base64, split at its own first colon.
    let mut creds = user.clone();
    creds.push(b':');
    creds.extend_from_slice(&pass);
    assert_eq!(
        b64(&creds),
        value,
        "auth.basic returned {user:?}/{pass:?} for {header:?}, which does not re-encode \
         to the header's own value"
    );
    assert!(
        !user.contains(&b':'),
        "auth.basic split {header:?} at a colon that is not the first one"
    );
    // Nitr requires the decoded credentials to be text. RFC 7617 leaves
    // the charset to the server, and a byte-string credential nobody can
    // spell is not worth the surprise.
    assert!(
        std::str::from_utf8(&creds).is_ok(),
        "auth.basic returned credentials that are not UTF-8 for {header:?}"
    );
    Some((user, pass))
}

/// `password_verify`, with the boolean-xor-reason contract checked.
///
/// Returns the boolean. A raised error is a failure in itself for a
/// password within the cap: the outcome must be something a handler can
/// branch on, not a 500.
fn verify(f: &Function, password: &LuaString, stored: &str, problems: &[&str]) -> (bool, Option<String>) {
    let (ok, reason): (bool, Option<String>) = pw(f, (password, stored))
        .unwrap_or_else(|err| panic!("password_verify raised for {stored:?}: {err}"));
    if ok {
        assert_eq!(
            reason, None,
            "password_verify accepted {stored:?} *and* gave the reason {reason:?}; \
             `local ok, why = password_verify(...)` cannot tell those apart"
        );
        assert!(
            stored.starts_with("$argon2d$")
                || stored.starts_with("$argon2i$")
                || stored.starts_with("$argon2id$"),
            "password_verify accepted {stored:?}, which is not an argon2 PHC hash"
        );
    }
    if let Some(reason) = &reason {
        assert!(
            problems.contains(&reason.as_str()),
            "password_verify rejected {stored:?} with the undeclared reason {reason:?}"
        );
        assert!(!ok);
    }
    (ok, reason)
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let work = input.u8();
    let mutate = input.u8();
    let hash_sel = input.u8();
    let user_bytes = input.field().to_vec();
    let password_bytes = input.field().to_vec();
    let stored_text = input.text().into_owned();
    let header_text = input.text().into_owned();

    // The oracle every header assertion rests on, checked against RFC
    // 4648 before it is trusted — free, and it cannot silently rot.
    assert_eq!(b64(b""), "");
    assert_eq!(b64(b"f"), "Zg==");
    assert_eq!(b64(b"fo"), "Zm8=");
    assert_eq!(b64(b"foo"), "Zm9v");
    assert_eq!(b64(b"ada:lovelace"), "YWRhOmxvdmVsYWNl");

    LUA.with(|lua| {
        let crypto: Table = lua.globals().get("crypto").expect("nitr.crypto");
        let hasher: Function = crypto.get("password_hash").expect("password_hash");
        let verifier: Function = crypto.get("password_verify").expect("password_verify");
        let dummy: Function = crypto
            .get("password_verify_dummy")
            .expect("password_verify_dummy");
        let auth: Table = lua.globals().get("auth").expect("nitr.auth");
        let basic: Function = auth.get("basic").expect("auth.basic");
        let bearer: Function = auth.get("bearer").expect("auth.bearer");
        let problems = nitr_std::fuzzing::VERIFY_REASONS;

        // the header parser
        // The fuzzer's own header first: this is the one an attacker
        // actually sends.
        check_basic(&basic, &header_text);
        let token: Option<String> = bearer
            .call(header_text.as_str())
            .unwrap_or_else(|err| panic!("auth.bearer raised for {header_text:?}: {err}"));
        assert_eq!(
            token.as_deref(),
            scheme_value(&header_text, "bearer"),
            "auth.bearer disagreed with the scheme split on {header_text:?}"
        );

        // Then constructed headers, so the parser is reached with input it
        // cannot refuse at the first byte: every scheme spelling that must
        // *not* match, over credentials the fuzzer chose.
        let mut creds = user_bytes.clone();
        creds.push(b':');
        creds.extend_from_slice(&password_bytes);
        let encoded = b64(&creds);
        // Credentials only come back when the scheme matches *and* the
        // decoded bytes are text — the second condition is Nitr's, and
        // stating it here keeps it deliberate.
        let decodable = std::str::from_utf8(&creds).is_ok();
        // One leading-whitespace variant per execution rather than the
        // cross product: every mlua round trip costs real time under ASan,
        // and the fuzzer covers all four across runs anyway.
        let lead = ["", " ", "\t", "  "][usize::from(mutate) % 4];
        for scheme in [
            "Basic", "basic", "BASIC", "BaSiC", "Bearer", "bearer", "Digest", "Negotiate",
            "Basicx", "asic", "",
        ] {
            let header = format!("{lead}{scheme} {encoded}");
            let got = check_basic(&basic, &header);
            assert_eq!(
                got.is_some(),
                scheme.eq_ignore_ascii_case("basic") && decodable,
                "the scheme {scheme:?} was matched as {}",
                got.is_some()
            );
            if let Some((user, pass)) = got {
                // The split is at the *first* colon, so a colon in the user
                // field moves it — model that here rather than assuming the
                // fields came back unchanged.
                let cut = creds.iter().position(|&b| b == b':').expect("a colon");
                assert_eq!(user, creds[..cut], "wrong user out of {header:?}");
                assert_eq!(pass, creds[cut + 1..], "wrong password out of {header:?}");
            }
        }

        // the stored hash
        let password = lua.create_string(&password_bytes).expect("password");
        let stored = match STORED.get(usize::from(hash_sel) % (STORED.len() + 1)) {
            Some((stored, expected)) => {
                let (ok, reason) = verify(&verifier, &password, stored, problems);
                assert!(!ok, "the known-bad hash {stored:?} verified");
                assert_eq!(
                    reason.as_deref(),
                    *expected,
                    "the verdict on {stored:?} changed"
                );
                (*stored).to_string()
            }
            // One past the table: the fuzzer's own hash, the arbitrary
            // case the assertions inside `verify` are written for.
            None => stored_text.clone(),
        };
        if password_bytes.len() > MAX_PASSWORD_BYTES {
            // Over the cap the length answer decides in a comparison, so
            // the expense guard is irrelevant: the KDF never runs. The
            // answer must be `false, nil` — winning over every complaint
            // about the stored hash — because the reason channel means
            // "the row is at fault, log it", and this trigger is the
            // attacker's own input.
            let (ok, reason) = verify(&verifier, &password, &stored, problems);
            assert!(!ok, "an over-cap password verified against {stored:?}");
            assert_eq!(
                reason, None,
                "an over-cap password must be an ordinary miss, got {reason:?} for {stored:?}"
            );
        } else if !too_expensive_to_run(&stored) {
            verify(&verifier, &password, &stored, problems);
            // Only when it is a different string: a verification against a
            // hash the fuzzer built to be valid is the one call here that
            // can cost a full KDF pass, and doing it twice halves the
            // execution rate for nothing.
            if stored != stored_text && !too_expensive_to_run(&stored_text) {
                verify(&verifier, &password, &stored_text, problems);
            }
        }

        // the length cap
        // Exactly at the cap must work everywhere; one byte over splits
        // by entry point: the hash side raises (registration must be
        // told), the verify side answers false (a raise on login input is
        // a 500 where a 401 was meant). The at-cap check runs against the
        // minimum-cost hash rather than the fuzzer's: the subject is the
        // length check, and paying for a KDF pass to reach it would trade
        // execution rate for nothing.
        let at_cap = lua
            .create_string(vec![b'x'; MAX_PASSWORD_BYTES])
            .expect("string");
        let over_cap = lua
            .create_string(vec![b'x'; MAX_PASSWORD_BYTES + 1])
            .expect("string");
        verify(&verifier, &at_cap, MIN_COST_HASH, problems);
        assert!(
            pw::<Value>(&hasher, &over_cap).is_err(),
            "password_hash accepted a password of {} bytes",
            MAX_PASSWORD_BYTES + 1
        );
        assert!(
            !pw::<bool>(&dummy, &over_cap)
                .expect("password_verify_dummy must answer an over-cap password, not raise"),
            "password_verify_dummy returned true for an over-cap password"
        );
        let (ok, reason) = verify(&verifier, &over_cap, MIN_COST_HASH, problems);
        assert!(!ok, "an over-cap password verified");
        assert_eq!(
            reason, None,
            "one byte over the cap must be an ordinary miss, not a reason"
        );
        if password_bytes.len() > MAX_PASSWORD_BYTES {
            assert!(
                pw::<Value>(&hasher, &password).is_err(),
                "password_hash accepted {} bytes",
                password_bytes.len()
            );
        }

        // the round trip
        // Sampled: this branch is four argon2id passes at 19 MiB apiece.
        if work % 32 == 0 && password_bytes.len() <= MAX_PASSWORD_BYTES {
            let fresh: String = pw(&hasher, &password).expect("password_hash");
            assert!(
                fresh.starts_with(HASH_PREFIX),
                "password_hash produced {fresh:?}, not {HASH_PREFIX}…"
            );
            let (ok, reason) = verify(&verifier, &password, &fresh, problems);
            assert!(ok, "a password did not verify against its own fresh hash");
            assert_eq!(reason, None);

            // One flipped byte is a different password. (An empty password
            // has no byte to flip, so it gets a non-empty one instead.)
            let mut other = password_bytes.clone();
            match other.is_empty() {
                true => other.push(b'x'),
                false => {
                    let i = usize::from(mutate) % other.len();
                    other[i] = other[i].wrapping_add(1);
                }
            }
            let other = lua.create_string(&other).expect("string");
            let (ok, reason) = verify(&verifier, &other, &fresh, problems);
            assert!(!ok, "a mutated password verified against {fresh:?}");
            assert_eq!(
                reason, None,
                "a wrong password was blamed on the hash: {reason:?}"
            );

            // The unknown-user branch of every login handler: total, and
            // false for anything.
            let decoyed: bool = pw(&dummy, &password)
                .expect("password_verify_dummy never raises within the cap");
            assert!(!decoyed, "password_verify_dummy returned true");
        }

        lua.gc_collect().expect("gc");
    });
});
