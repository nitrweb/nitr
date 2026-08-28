// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr.crypto.jwt` — the compact-serialization split, the base64url
//! decode, `serde_json` over an attacker's header, the algorithm
//! allow-list and the MAC comparison — driven **through Lua**
//! (`nitr_std::fuzzing::create_crypto_table`) exactly as a handler calls
//! it, so the mlua boundary is inside the fuzzed path rather than
//! bypassed.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u8 alg | u8 sig | u8 allow | u8 tamper | key \0 alg-text \0 payload \0 token
//! ```
//!
//! `alg` indexes [`ALGS`] — the algorithm spellings that make JWT
//! verification a recurring CVE, `none` and the case variants included —
//! and one past its end means "use the `alg-text` field", so the fuzzer
//! can name an algorithm nobody thought of. `sig` picks which signature
//! the constructed token carries, `allow` picks the caller's allow-list,
//! `tamper` picks where a byte gets flipped. `key` and `payload` are raw
//! bytes (a JWT key is a secret, not text, and a payload segment is
//! whatever base64url decoded to); `token` is the last field, so it grows
//! to the end of the input and is the one a corpus entry is really about.
//!
//! Tokens are **constructed**, not hoped for. A fuzzer starting from
//! random bytes will not synthesize `<b64(header)>.<b64(payload)>.<mac>`
//! with a valid MAC in any budget, so the alg-confusion cases are built
//! here: the header is spelled with the chosen algorithm and signed with
//! a real HMAC-SHA256 taken from `nitr.crypto.hmac_sha256`.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **A token that verifies carries the HMAC of its own
//!   `header.payload` under the key.** The whole target in one line, and
//!   the only assertion that has to hold for *arbitrary* attacker text:
//!   whatever a hostile token does, if `verify` hands back claims then
//!   its third segment is HMAC-SHA256 over its first two. `alg: none`
//!   accepted, an unsigned token accepted, a prefix-compared MAC, a
//!   signature checked over the payload only — all of them land here.
//! * **`none` and case variants never verify.** Spelled out separately
//!   from the rule above so a crash artifact says which CVE it is.
//!   `hs256` matching `HS256` would mean the allow-list is compared with
//!   `eq_ignore_ascii_case`, and `alg: none` with an empty signature is
//!   the original JWT downgrade.
//! * **Only an allow-listed algorithm verifies.** A token signed HS256
//!   and verified with `algorithms = { "HS384" }` must be refused: the
//!   list is the caller's decision, not the token's.
//! * **An allow-list naming an unsupported algorithm is an error, not a
//!   quiet pass.** `verify` raises iff the list is not a subset of the
//!   supported set — including `{ "none" }` and `{ }` — so a typo cannot
//!   silently disable verification.
//! * **`sign` is exactly the RFC 7515 compact serialization.** The whole
//!   token is compared against `b64url(header).b64url(claims).b64url(mac)`
//!   rebuilt here from `hmac_sha256`. This pins the header bytes, the
//!   claims serialization and *what the MAC covers* — and it doubles as
//!   the proof that the base64url encoder in this file agrees with the
//!   `base64` crate, which is what the assertion above rests on.
//! * **Round-trip.** `verify(sign(claims, key), key, { algorithms = { alg } })`
//!   gives the claims back, for every supported algorithm.
//! * **One flipped character anywhere breaks it.** In the signature and
//!   in the payload the reason must be exactly `invalid signature`: a MAC
//!   that covered less than `header.payload` would let the payload move.
//! * **Claims and reason are exclusive.** A caller writes
//!   `local claims, err = jwt.verify(...)`; returning both, or neither,
//!   breaks every such caller. Every rejection names a known reason.
//! * **`verify` never raises for a well-formed allow-list.** Any token,
//!   any bytes: a raised error becomes a 500 where a 401 was meant.
//! * **Expiry is enforced by default and `leeway` is opt-in**, in both
//!   directions (`exp` behind, `nbf` ahead).
#![no_main]
use libfuzzer_sys::fuzz_target;
use mlua::{Function, Lua, LuaString, Table, Value};
use nitr_fuzz::Input;

/// The algorithms `nitr.crypto.jwt` implements. Anything else in an
/// allow-list is an error, and anything else in a token header is a
/// rejection.
const SUPPORTED: &[&str] = &["HS256", "HS384", "HS512"];

/// Algorithm spellings for the constructed token. Everything past the
/// first three must be refused; the interesting half is *why* each one
/// would be accepted by an implementation that got it wrong.
const ALGS: &[&str] = &[
    "HS256", "HS384", "HS512",
    // Case: the allow-list is compared with `==`, and must stay that way.
    "hs256", "Hs256", "HS256 ", " HS256",
    // The downgrade the `alg` header exists to enable.
    "none", "None", "NONE", "nOnE",
    // Asymmetric names: an implementation that looked up a key by
    // algorithm family, or fell through to HMAC, verifies these with the
    // public key as the MAC secret.
    "RS256", "ES256", "PS256",
    // Prefix and suffix of a supported name, for a `starts_with` compare.
    "HS", "HS2560", "",
];

/// Caller allow-lists. Every one is a subset of [`SUPPORTED`], so
/// `verify` must not raise for any of them.
const ALLOW: &[&[&str]] = &[&["HS256"], &["HS384"], &["HS256", "HS512"], &["HS512"]];

/// Every reason `verify` is allowed to give. A rejection outside this set
/// means the failure path grew a case nobody wrote down.
const REASONS: &[&str] = &[
    "malformed token",
    "malformed header",
    "algorithm not allowed",
    "invalid signature",
    "malformed claims",
    "token expired",
    "token not yet valid",
];

/// A far-future instant, in seconds. Used both as an `nbf` that has not
/// arrived and as a `leeway` wide enough to forgive anything.
const FAR_FUTURE: i64 = 4_000_000_000;

thread_local! {
    /// One Lua state for the whole process: `create_crypto_table` builds
    /// a dozen closures plus the JWT sub-table, and a fresh `Lua` costs
    /// far more than every call this target makes. Parked in the globals
    /// so nothing outlives the state; collected between runs.
    static LUA: Lua = {
        let lua = Lua::new();
        let crypto = nitr_std::fuzzing::create_crypto_table(&lua).expect("nitr.crypto table");
        lua.globals().set("crypto", crypto).expect("nitr.crypto global");
        lua
    };
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding, the JWS encoding.
///
/// Written out rather than pulled in as a dependency, and then checked
/// against the real thing: `sign`'s own output is compared byte for byte
/// with a token rebuilt through this function, at a length the fuzzer
/// chooses, so a bug here cannot quietly weaken the oracle below.
fn b64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            u32::from(chunk[0]),
            u32::from(chunk.get(1).copied().unwrap_or(0)),
            u32::from(chunk.get(2).copied().unwrap_or(0)),
        ];
        let n = (b[0] << 16) | (b[1] << 8) | b[2];
        // 3 bytes -> 4 characters, 2 -> 3, 1 -> 2. No padding.
        for shift in [18, 12, 6, 0].into_iter().take(chunk.len() + 1) {
            out.push(char::from(B64URL[((n >> shift) & 63) as usize]));
        }
    }
    out
}

/// The bytes behind `nitr.crypto.hmac_sha256`'s lowercase hex.
fn unhex(text: &str) -> Vec<u8> {
    assert!(
        text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()),
        "hmac_sha256 returned {text:?}, which is not a 32-byte lowercase hex digest"
    );
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ascii");
            u8::from_str_radix(text, 16).expect("hex digit pair")
        })
        .collect()
}

/// The signature segment a correct HS256 token carries over `data`.
fn mac(hmac: &Function, key: &LuaString, data: &str) -> String {
    let hex: String = hmac.call((key, data)).expect("hmac_sha256");
    b64url(&unhex(&hex))
}

/// A JSON string body: enough escaping that the header this goes into
/// parses, so the algorithm `verify` reads back is the one chosen here.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// One character of `text` replaced by a different one.
fn flip(text: &str, at: u8) -> String {
    let mut bytes = text.as_bytes().to_vec();
    if bytes.is_empty() {
        return "A".into();
    }
    let i = usize::from(at) % bytes.len();
    // Never a no-op, and never a character outside base64url: in the
    // signature the change either names different bytes or leaves
    // non-zero trailing bits, and both must be refused.
    bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).expect("ascii in, ascii out")
}

/// `{ algorithms = { … }, leeway? }`.
fn allow_list(lua: &Lua, algorithms: &[&str], leeway: Option<i64>) -> Table {
    let opts = lua.create_table().expect("table");
    let list = lua.create_table().expect("table");
    for (i, alg) in algorithms.iter().enumerate() {
        list.set(i + 1, *alg).expect("allow-list entry");
    }
    opts.set("algorithms", list).expect("algorithms");
    if let Some(leeway) = leeway {
        opts.set("leeway", leeway).expect("leeway");
    }
    opts
}

/// `verify`, with the claims-xor-reason contract checked.
///
/// Returns the claims on success and `None` on a rejection. A raised
/// error is a failure in itself: the allow-lists this target passes are
/// all valid, so every outcome must be a value a handler can branch on.
fn verify(f: &Function, token: &str, key: &LuaString, opts: Table, what: &str) -> Option<Value> {
    let (claims, reason): (Value, Option<String>) = f
        .call((token, key, opts))
        .unwrap_or_else(|err| panic!("{what}: verify raised for {token:?}: {err}"));
    match (claims.is_nil(), reason) {
        (false, None) => Some(claims),
        (true, Some(reason)) => {
            assert!(
                REASONS.contains(&reason.as_str()),
                "{what}: verify rejected {token:?} with the unknown reason {reason:?}"
            );
            None
        }
        (true, None) => panic!("{what}: verify returned neither claims nor a reason for {token:?}"),
        (false, Some(reason)) => panic!(
            "{what}: verify returned claims *and* the reason {reason:?} for {token:?}; \
             `local claims, err = jwt.verify(...)` cannot tell those apart"
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let alg_sel = input.u8();
    let sig_sel = input.u8();
    let allow_sel = input.u8();
    let tamper = input.u8();
    let key_bytes = input.field();
    let alg_text = input.text().into_owned();
    let payload_bytes = input.field();
    let token_text = input.text().into_owned();

    LUA.with(|lua| {
        let crypto: Table = lua.globals().get("crypto").expect("nitr.crypto");
        let jwt: Table = crypto.get("jwt").expect("nitr.crypto.jwt");
        let sign: Function = jwt.get("sign").expect("jwt.sign");
        let verifier: Function = jwt.get("verify").expect("jwt.verify");
        let hmac: Function = crypto.get("hmac_sha256").expect("hmac_sha256");
        let key = lua.create_string(key_bytes).expect("key");

        // The algorithm under test. One past the table is the fuzzer's own
        // spelling, so nothing here caps what it can try.
        let alg = ALGS
            .get(usize::from(alg_sel) % (ALGS.len() + 1))
            .copied()
            .unwrap_or(alg_text.as_str());
        let allowed = ALLOW[usize::from(allow_sel) % ALLOW.len()];

        if std::env::var_os("NITR_FUZZ_DEBUG").is_some() {
            eprintln!(
                "DEBUG alg={alg:?} sig_sel={} allow={allowed:?} tamper={tamper} \
                 key={key_bytes:?} payload={payload_bytes:?} token={token_text:?}",
                sig_sel % 5
            );
        }

        // sign is the compact serialization, exactly
        // The claims value is drawn from the payload bytes but folded into
        // `[0-9a-z]`: with one unescaped key the serialized claims are
        // predictable to the byte, which is what makes the whole-token
        // comparison — and therefore the base64url encoder in this file —
        // checkable against the real implementation.
        let sub: String = payload_bytes
            .iter()
            .take(24)
            .map(|b| char::from(b"0123456789abcdefghijklmnopqrstuvwxyz"[usize::from(b % 36)]))
            .collect();
        let claims = lua.create_table().expect("claims");
        claims.set("sub", sub.as_str()).expect("sub");

        let token: String = sign.call((&claims, &key)).expect("sign");
        let head = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
        let body = b64url(format!(r#"{{"sub":"{sub}"}}"#).as_bytes());
        let signing_input = format!("{head}.{body}");
        assert_eq!(
            token,
            format!("{signing_input}.{}", mac(&hmac, &key, &signing_input)),
            "sign did not produce b64url(header).b64url(claims).b64url(HMAC of both) \
             for sub={sub:?}"
        );

        // round-trip, per supported algorithm
        let signed_alg = SUPPORTED[usize::from(alg_sel) % SUPPORTED.len()];
        let other_alg = SUPPORTED[(usize::from(alg_sel) + 1) % SUPPORTED.len()];
        let sign_opts = lua.create_table().expect("table");
        sign_opts.set("alg", signed_alg).expect("alg");
        let signed: String = sign
            .call((&claims, &key, &sign_opts))
            .expect("sign with an explicit algorithm");

        let back = verify(
            &verifier,
            &signed,
            &key,
            allow_list(lua, &[signed_alg], None),
            "round-trip",
        )
        .unwrap_or_else(|| panic!("a {signed_alg} token did not verify under its own algorithm"));
        let back = back
            .as_table()
            .unwrap_or_else(|| panic!("verify returned {back:?}, not a claims table"));
        assert_eq!(
            back.get::<String>("sub").expect("sub"),
            sub,
            "the claims did not survive sign/verify under {signed_alg}"
        );

        // The allow-list is the caller's decision: the token's own header
        // must not be able to overrule it.
        assert!(
            verify(
                &verifier,
                &signed,
                &key,
                allow_list(lua, &[other_alg], None),
                "allow-list",
            )
            .is_none(),
            "a {signed_alg} token verified under an allow-list of only {other_alg}"
        );
        // A different key is a different token.
        let other_key = lua.create_string(b"a-different-key").expect("key");
        if key_bytes != b"a-different-key".as_slice() {
            assert!(
                verify(
                    &verifier,
                    &signed,
                    &other_key,
                    allow_list(lua, &[signed_alg], None),
                    "wrong key",
                )
                .is_none(),
                "a {signed_alg} token verified under a key it was not signed with"
            );
        }

        // one flipped character
        let segments: Vec<&str> = signed.split('.').collect();
        assert_eq!(
            segments.len(),
            3,
            "sign produced {signed:?}, which is not three segments"
        );
        let tamper_at = |part: usize| -> String {
            let flipped = flip(segments[part], tamper);
            let mut parts = segments.clone();
            parts[part] = flipped.as_str();
            parts.join(".")
        };
        for (part, what) in [(2usize, "signature"), (1, "payload")] {
            let tampered = tamper_at(part);
            let (claims, reason): (Value, Option<String>) = verifier
                .call((
                    tampered.as_str(),
                    &key,
                    allow_list(lua, &[signed_alg], None),
                ))
                .expect("verify");
            assert!(
                claims.is_nil() && reason.as_deref() == Some("invalid signature"),
                "a token with one character flipped in its {what} verified as \
                 ({claims:?}, {reason:?}): {tampered:?}"
            );
        }
        // The header carries the algorithm, so its rejection reason depends
        // on what the flip broke; only the refusal itself is fixed.
        let tampered = tamper_at(0);
        assert!(
            verify(
                &verifier,
                &tampered,
                &key,
                allow_list(lua, &[signed_alg], None),
                "header tamper",
            )
            .is_none(),
            "a token with one character flipped in its header verified: {tampered:?}"
        );

        // the allow-list itself
        // Raising is the contract for an algorithm `nitr.crypto.jwt` cannot
        // implement: a typo (or `none`) must not silently become "verify
        // nothing".
        let raised = verifier
            .call::<(Value, Value)>((signed.as_str(), &key, allow_list(lua, &[alg], None)))
            .is_err();
        assert_eq!(
            raised,
            !SUPPORTED.contains(&alg),
            "an allow-list of {alg:?} {} raise",
            if raised { "must not" } else { "must" }
        );
        // No allow-list at all is an error, not a default.
        assert!(
            verifier
                .call::<(Value, Value)>((signed.as_str(), &key, lua.create_table().expect("table")))
                .is_err(),
            "verify accepted a call with no `algorithms` allow-list"
        );
        // An empty allow-list allows nothing.
        assert!(
            verify(
                &verifier,
                &signed,
                &key,
                allow_list(lua, &[], None),
                "empty allow-list",
            )
            .is_none(),
            "a token verified under an empty allow-list"
        );

        // expiry, and the leeway that forgives it
        for (field, value, reason) in [
            ("exp", 1i64, "token expired"),
            ("nbf", FAR_FUTURE, "token not yet valid"),
        ] {
            let timed = lua.create_table().expect("claims");
            timed.set("sub", sub.as_str()).expect("sub");
            timed.set(field, value).expect("time claim");
            let token: String = sign.call((&timed, &key)).expect("sign");
            let (claims, got): (Value, Option<String>) = verifier
                .call((token.as_str(), &key, allow_list(lua, &["HS256"], None)))
                .expect("verify");
            assert!(
                claims.is_nil() && got.as_deref() == Some(reason),
                "a token with {field}={value} verified as ({claims:?}, {got:?})"
            );
            assert!(
                verify(
                    &verifier,
                    &token,
                    &key,
                    allow_list(lua, &["HS256"], Some(FAR_FUTURE)),
                    "leeway",
                )
                .is_some(),
                "leeway of {FAR_FUTURE}s did not forgive {field}={value}"
            );
        }

        // the constructed token: algorithm confusion
        let header = b64url(format!(r#"{{"alg":"{}","typ":"JWT"}}"#, escape(alg)).as_bytes());
        let payload = b64url(payload_bytes);
        let signing_input = format!("{header}.{payload}");
        let correct = mac(&hmac, &key, &signing_input);
        let signature = match sig_sel % 5 {
            0 => correct.clone(),
            // The unsigned token: `alg: none`'s natural companion.
            1 => String::new(),
            2 => mac(&hmac, &other_key, &signing_input),
            3 => payload.clone(),
            _ => flip(&correct, tamper),
        };
        let forged = format!("{signing_input}.{signature}");

        // The MAC is HMAC-SHA256 whatever the header claims, so a token can
        // only be verifiable when its header says HS256, that spelling is
        // allow-listed, and the signature really is that MAC.
        let verifiable = allowed.contains(&"HS256") && alg == "HS256" && signature == correct;
        let outcome = verifier
            .call::<(Value, Option<String>)>((
                forged.as_str(),
                &key,
                allow_list(lua, allowed, None),
            ))
            .expect("verify never raises for a valid allow-list");
        if verifiable {
            // It may still be refused — the payload is raw fuzzer bytes, so
            // it can be unparseable or carry its own `exp` — but never for a
            // reason about the algorithm or the signature.
            if let (Value::Nil, Some(reason)) = &outcome {
                assert!(
                    matches!(
                        reason.as_str(),
                        "malformed claims" | "token expired" | "token not yet valid"
                    ),
                    "a correctly signed HS256 token was refused with {reason:?}: {forged:?}"
                );
            }
        } else {
            assert!(
                outcome.0.is_nil(),
                "alg={alg:?} allow-list={allowed:?} signature={signature:?} verified: \
                 {forged:?} (the correct MAC is {correct:?})"
            );
        }
        // Spelled out, so a crash artifact names the CVE rather than the
        // rule that subsumes it.
        if alg.eq_ignore_ascii_case("none") {
            assert!(
                outcome.0.is_nil(),
                "an `alg: {alg}` token verified: {forged:?}"
            );
        }
        if alg != "HS256" && alg.trim().eq_ignore_ascii_case("HS256") {
            assert!(
                outcome.0.is_nil(),
                "the algorithm spelling {alg:?} was matched against HS256: {forged:?}"
            );
        }

        // the fuzzer's own token
        // The one assertion that has to hold for arbitrary bytes: if it
        // verified, its signature is the HMAC of its own header and payload.
        if verify(
            &verifier,
            &token_text,
            &key,
            allow_list(lua, &["HS256"], None),
            "hostile",
        )
        .is_some()
        {
            let parts: Vec<&str> = token_text.split('.').collect();
            assert_eq!(
                parts.len(),
                3,
                "verify accepted {token_text:?}, which is not three segments"
            );
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            assert_eq!(
                parts[2],
                mac(&hmac, &key, &signing_input),
                "verify accepted {token_text:?}, whose signature is not HMAC-SHA256 of \
                 its own header.payload under this key"
            );
        }

        lua.gc_collect().expect("gc");
    });
});
