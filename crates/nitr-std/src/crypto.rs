// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Crypto and auth primitives for Lua handlers: `nitr.crypto` (hashing,
//! HMAC, random bytes, constant-time comparison, argon2id passwords) and
//! `nitr.auth` (Basic/Bearer `Authorization` header parsing).
//!
//! Primitives, not a framework: everything is implemented in Rust
//! (RustCrypto), and scripts compose them into their own auth flows.

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac as _};
use mlua::{Lua, LuaString, ObjectLike as _, Table, Value};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq as _;

/// Upper bound for `nitr.crypto.random_bytes(n)`: large enough for any
/// key/nonce/token, small enough that a script cannot use it as an
/// allocation amplifier.
const MAX_RANDOM_BYTES: usize = 64 * 1024;

/// The RNG/password-hash error types have no `std::error::Error` impl
/// here, so their `Display` is carried over manually.
fn rng_err(err: getrandom::Error) -> mlua::Error {
    mlua::Error::RuntimeError(format!("failed to read OS entropy: {err}"))
}

fn pw_err(err: argon2::password_hash::Error) -> mlua::Error {
    mlua::Error::RuntimeError(format!("password hashing failed: {err}"))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Builds the `nitr.crypto` table.
pub(crate) fn create_crypto_table(lua: &Lua) -> mlua::Result<Table> {
    let crypto = lua.create_table()?;

    // Digest and MAC results are lowercase hex strings: printable, easy to
    // compare and log, and what most wire formats expect.
    crypto.set(
        "sha256",
        lua.create_function(|_, data: LuaString| Ok(hex(&Sha256::digest(data.as_bytes()))))?,
    )?;

    crypto.set(
        "hmac_sha256",
        lua.create_function(|_, (key, data): (LuaString, LuaString)| {
            let mut mac: Hmac<Sha256> = crate::utils::new_hmac(&key.as_bytes());
            mac.update(&data.as_bytes());
            Ok(hex(&mac.finalize().into_bytes()))
        })?,
    )?;

    // Raw bytes (a binary Lua string) from the OS entropy source.
    crypto.set(
        "random_bytes",
        lua.create_function(|lua, n: usize| {
            if n == 0 || n > MAX_RANDOM_BYTES {
                return Err(mlua::Error::RuntimeError(format!(
                    "random_bytes(n) requires 1 <= n <= {MAX_RANDOM_BYTES}, got {n}"
                )));
            }
            let mut buf = vec![0u8; n];
            getrandom::getrandom(&mut buf).map_err(rng_err)?;
            lua.create_string(&buf)
        })?,
    )?;

    // The comparison Lua apps always get wrong: `==` on secrets leaks
    // timing. Length differences still return early — hide lengths by
    // comparing digests when they may vary.
    crypto.set(
        "constant_time_eq",
        lua.create_function(|_, (a, b): (LuaString, LuaString)| {
            let (a, b) = (a.as_bytes(), b.as_bytes());
            Ok(a.len() == b.len() && bool::from(a.ct_eq(&b)))
        })?,
    )?;

    crypto.set(
        "password_hash",
        lua.create_function(|_, password: LuaString| {
            let mut salt = [0u8; 16];
            getrandom::getrandom(&mut salt).map_err(rng_err)?;
            let salt = SaltString::encode_b64(&salt).map_err(pw_err)?;
            let hash = Argon2::default()
                .hash_password(&password.as_bytes(), &salt)
                .map_err(pw_err)?;
            Ok(hash.to_string())
        })?,
    )?;

    // AEAD (XChaCha20-Poly1305): authenticated encryption for data handed
    // to a client. `seal` returns a printable token; `open` returns nil on
    // any tampering — with the ciphertext, the nonce, or the optional
    // associated data.
    crypto.set(
        "seal",
        lua.create_function(
            |lua, (key, plaintext, aad): (LuaString, LuaString, Option<LuaString>)| {
                let cipher = aead_cipher(&key)?;
                let mut nonce = [0u8; 24];
                getrandom::getrandom(&mut nonce).map_err(rng_err)?;
                let nonce = XNonce::from(nonce);
                let aad = aad
                    .as_ref()
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();
                let ciphertext = cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: &plaintext.as_bytes(),
                            aad: &aad,
                        },
                    )
                    .map_err(|_| mlua::Error::RuntimeError("encryption failed".into()))?;
                let mut sealed = nonce.to_vec();
                sealed.extend_from_slice(&ciphertext);
                lua.create_string(B64URL.encode(sealed))
            },
        )?,
    )?;

    crypto.set(
        "open",
        lua.create_function(
            |lua, (key, sealed, aad): (LuaString, LuaString, Option<LuaString>)| {
                let cipher = aead_cipher(&key)?;
                let aad = aad
                    .as_ref()
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();
                let Ok(raw) = B64URL.decode(&*sealed.as_bytes()) else {
                    return Ok(Value::Nil);
                };
                if raw.len() < 24 {
                    return Ok(Value::Nil);
                }
                let (nonce, ciphertext) = raw.split_at(24);
                match cipher.decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                ) {
                    Ok(plaintext) => Ok(Value::String(lua.create_string(plaintext)?)),
                    Err(_) => Ok(Value::Nil),
                }
            },
        )?,
    )?;

    crypto.set("jwt", create_jwt_table(lua)?)?;

    crypto.set(
        "password_verify",
        lua.create_function(|_, (password, hash): (LuaString, String)| {
            let Ok(parsed) = PasswordHash::new(&hash) else {
                return Ok(false);
            };
            Ok(Argon2::default()
                .verify_password(&password.as_bytes(), &parsed)
                .is_ok())
        })?,
    )?;

    Ok(crypto)
}

/// Builds the AEAD cipher, insisting on a full-strength key. Deriving a
/// key from a short passphrase here would hide the mistake; the error
/// tells the caller how to make a real one.
fn aead_cipher(key: &LuaString) -> mlua::Result<XChaCha20Poly1305> {
    let key = key.as_bytes();
    if key.len() != 32 {
        return Err(mlua::Error::RuntimeError(format!(
            "seal/open take a 32-byte key, got {} bytes — generate one with \
             nitr.crypto.random_bytes(32) or derive one with nitr.crypto.sha256",
            key.len()
        )));
    }
    // Fully qualified: importing `KeyInit` would make the `Hmac`
    // constructors ambiguous (`Mac` supplies its own `new_from_slice`).
    Ok(<XChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(
        key.as_ref().into(),
    ))
}

/// The HMAC algorithms `nitr.crypto.jwt` supports. Asymmetric algorithms
/// (and `none`) are deliberately absent: a format needs a key-management
/// story before RS256 helps anyone, and `alg: none` is the classic CVE.
const JWT_ALGORITHMS: &[&str] = &["HS256", "HS384", "HS512"];

/// Both callers validate `alg` against [`JWT_ALGORITHMS`] first, but the
/// value originates in the attacker-supplied JWT header, so an unknown
/// algorithm is an error here too — defense in depth, not a load-bearing
/// invariant two hops away.
fn jwt_mac(alg: &str, key: &[u8], data: &[u8]) -> mlua::Result<Vec<u8>> {
    match alg {
        "HS256" => {
            let mut mac: Hmac<Sha256> = crate::utils::new_hmac(key);
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "HS384" => {
            let mut mac: Hmac<Sha384> = crate::utils::new_hmac(key);
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "HS512" => {
            let mut mac: Hmac<Sha512> = crate::utils::new_hmac(key);
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        other => Err(mlua::Error::RuntimeError(format!(
            "unsupported JWT algorithm `{other}` (supported: {})",
            JWT_ALGORITHMS.join(", ")
        ))),
    }
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// `verify`'s failure path: `nil` plus a reason, so callers can
/// distinguish "expired" from "forged" when deciding what to log.
fn jwt_reject(lua: &Lua, reason: &str) -> mlua::Result<(Value, Value)> {
    Ok((Value::Nil, Value::String(lua.create_string(reason)?)))
}

/// Builds `nitr.crypto.jwt`: verification first, signing second.
fn create_jwt_table(lua: &Lua) -> mlua::Result<Table> {
    let jwt = lua.create_table()?;

    jwt.set(
        "sign",
        lua.create_function(
            |lua, (claims, key, opts): (Table, LuaString, Option<Table>)| {
                let alg = match &opts {
                    Some(opts) => opts
                        .get::<Option<String>>("alg")?
                        .unwrap_or_else(|| "HS256".into()),
                    None => "HS256".into(),
                };
                if !JWT_ALGORITHMS.contains(&alg.as_str()) {
                    return Err(mlua::Error::RuntimeError(format!(
                        "unsupported JWT algorithm `{alg}` (supported: {})",
                        JWT_ALGORITHMS.join(", ")
                    )));
                }
                let header = B64URL.encode(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#));
                let claims = Value::Table(claims);
                crate::utils::check_json_depth(&claims)?;
                let payload = serde_json::to_string(&claims)
                    .map_err(|err| {
                        mlua::Error::RuntimeError(format!(
                            "JWT claims must be JSON-serializable: {err}"
                        ))
                    })
                    .map(|json| B64URL.encode(json))?;
                let signing_input = format!("{header}.{payload}");
                let sig = B64URL.encode(jwt_mac(&alg, &key.as_bytes(), signing_input.as_bytes())?);
                lua.create_string(format!("{signing_input}.{sig}"))
            },
        )?,
    )?;

    // jwt.verify(token, key, { algorithms = {...}, leeway? }) ->
    //   claims, nil | nil, reason
    //
    // The explicit `algorithms` allow-list is required, and the algorithm
    // named by the token's own header is honored only if the list contains
    // it — the two properties whose absence makes hand-rolled JWT
    // verification a recurring CVE. Expiry and not-before are checked by
    // default.
    jwt.set(
        "verify",
        lua.create_function(|lua, (token, key, opts): (LuaString, LuaString, Table)| {
            let allowed: Vec<String> =
                opts.get::<Option<Vec<String>>>("algorithms")?
                    .ok_or_else(|| {
                        mlua::Error::RuntimeError(
                            "jwt.verify requires an `algorithms` allow-list, e.g. \
                             { algorithms = { \"HS256\" } }"
                                .into(),
                        )
                    })?;
            for alg in &allowed {
                if !JWT_ALGORITHMS.contains(&alg.as_str()) {
                    return Err(mlua::Error::RuntimeError(format!(
                        "unsupported JWT algorithm `{alg}` in the allow-list \
                             (supported: {})",
                        JWT_ALGORITHMS.join(", ")
                    )));
                }
            }
            let leeway: f64 = opts.get::<Option<f64>>("leeway")?.unwrap_or(0.0);

            let token = token.to_string_lossy().to_string();
            let mut parts = token.split('.');
            let (Some(header), Some(payload), Some(sig), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return jwt_reject(lua, "malformed token");
            };

            let Some(header_json) = B64URL
                .decode(header)
                .ok()
                .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
            else {
                return jwt_reject(lua, "malformed header");
            };
            // The header's algorithm is checked against the caller's
            // list, never trusted on its own.
            let alg = header_json
                .get("alg")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !allowed.iter().any(|a| a == alg) {
                return jwt_reject(lua, "algorithm not allowed");
            }

            let signing_input = format!("{header}.{payload}");
            let expected = jwt_mac(alg, &key.as_bytes(), signing_input.as_bytes())?;
            let ok = B64URL
                .decode(sig)
                .is_ok_and(|sig| sig.len() == expected.len() && bool::from(sig.ct_eq(&expected)));
            if !ok {
                return jwt_reject(lua, "invalid signature");
            }

            let Some(claims) = B64URL
                .decode(payload)
                .ok()
                .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
            else {
                return jwt_reject(lua, "malformed claims");
            };
            let now = unix_now();
            if let Some(exp) = claims.get("exp").and_then(|v| v.as_f64())
                && now > exp + leeway
            {
                return jwt_reject(lua, "token expired");
            }
            if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_f64())
                && now < nbf - leeway
            {
                return jwt_reject(lua, "token not yet valid");
            }

            use mlua::LuaSerdeExt as _;
            Ok((lua.to_value(&claims)?, Value::Nil))
        })?,
    )?;

    Ok(jwt)
}

/// Builds the `nitr.auth` table: `basic(req)` returns `user, pass` (or
/// `nil`) and `bearer(req)` returns the token (or `nil`). Both accept the
/// request object or the raw `Authorization` header value.
pub(crate) fn create_auth_table(lua: &Lua) -> mlua::Result<Table> {
    let auth = lua.create_table()?;

    auth.set(
        "basic",
        lua.create_function(|lua, source: Value| {
            let header = authorization(&source)?;
            let Some(encoded) = header.as_deref().and_then(|h| scheme_value(h, "basic")) else {
                return Ok(mlua::MultiValue::new());
            };
            let Some((user, pass)) = B64
                .decode(encoded)
                .ok()
                .and_then(|raw| String::from_utf8(raw).ok())
                .and_then(|creds| {
                    creds
                        .split_once(':')
                        .map(|(u, p)| (u.to_string(), p.to_string()))
                })
            else {
                return Ok(mlua::MultiValue::new());
            };
            let mut out = mlua::MultiValue::new();
            out.push_back(Value::String(lua.create_string(&user)?));
            out.push_back(Value::String(lua.create_string(&pass)?));
            Ok(out)
        })?,
    )?;

    auth.set(
        "bearer",
        lua.create_function(|lua, source: Value| {
            let header = authorization(&source)?;
            match header
                .as_deref()
                .and_then(|h| scheme_value(h, "bearer"))
                .filter(|t| !t.is_empty())
            {
                Some(token) => Ok(Value::String(lua.create_string(token)?)),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    Ok(auth)
}

/// Extracts the `Authorization` header from a request-like value (userdata
/// or table with a `headers` field) or accepts the header string directly.
fn authorization(source: &Value) -> mlua::Result<Option<String>> {
    let headers: Option<Table> = match source {
        Value::String(s) => return Ok(Some(s.to_string_lossy().to_string())),
        Value::UserData(ud) => ud.get("headers").ok(),
        Value::Table(t) => t.get("headers").ok(),
        _ => None,
    };
    Ok(headers.and_then(|h| h.get::<Option<String>>("authorization").ok().flatten()))
}

/// Returns the value part of an `Authorization` header when its scheme
/// matches (case-insensitively), e.g. `Bearer <value>`.
fn scheme_value<'a>(header: &'a str, scheme: &str) -> Option<&'a str> {
    let (found, value) = header.trim().split_once(' ')?;
    found
        .eq_ignore_ascii_case(scheme)
        .then(|| value.trim())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn passwords_hash_and_verify() {
        let lua = Lua::new();
        let crypto = create_crypto_table(&lua).expect("crypto table");
        let hash: String = crypto
            .get::<mlua::Function>("password_hash")
            .expect("fn")
            .call("hunter2")
            .expect("hash");
        assert!(hash.starts_with("$argon2id$"), "got: {hash}");

        let verify: mlua::Function = crypto.get("password_verify").expect("fn");
        assert!(verify.call::<bool>(("hunter2", hash.clone())).expect("ok"));
        assert!(!verify.call::<bool>(("wrong", hash)).expect("ok"));
        assert!(
            !verify
                .call::<bool>(("hunter2", "not-a-hash".to_string()))
                .expect("ok")
        );
    }

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
    fn jwt_signs_and_verifies_with_an_allow_list() {
        let lua = Lua::new();
        let crypto = create_crypto_table(&lua).expect("crypto table");
        let jwt: Table = crypto.get("jwt").expect("jwt");
        let sign: mlua::Function = jwt.get("sign").expect("fn");
        let verify: mlua::Function = jwt.get("verify").expect("fn");
        let far_future = 4_000_000_000i64;

        let claims: Table = lua
            .load(format!("{{ sub = \"42\", exp = {far_future} }}"))
            .eval()
            .expect("claims");
        let token: String = sign.call((claims, "s3cret-key")).expect("sign");
        assert_eq!(token.split('.').count(), 3);

        let allow: Table = lua
            .load(r#"{ algorithms = { "HS256" } }"#)
            .eval()
            .expect("opts");
        let (claims, err): (Value, Option<String>) = verify
            .call((token.clone(), "s3cret-key", allow))
            .expect("verify");
        assert_eq!(err, None);
        let Value::Table(claims) = claims else {
            panic!("expected claims table");
        };
        assert_eq!(claims.get::<String>("sub").expect("sub"), "42");

        // Wrong key, tampered payload, algorithm not in the list.
        for (token, key, opts) in [
            (
                token.clone(),
                "wrong-key",
                r#"{ algorithms = { "HS256" } }"#,
            ),
            (
                format!("{token}x"),
                "s3cret-key",
                r#"{ algorithms = { "HS256" } }"#,
            ),
            (
                token.clone(),
                "s3cret-key",
                r#"{ algorithms = { "HS384" } }"#,
            ),
        ] {
            let opts: Table = lua.load(opts).eval().expect("opts");
            let (claims, err): (Value, Option<String>) =
                verify.call((token, key, opts)).expect("verify");
            assert!(claims.is_nil());
            assert!(err.is_some());
        }

        // The allow-list is mandatory, and `none` is not an algorithm.
        let empty: Table = lua.load("{}").eval().expect("opts");
        assert!(
            verify
                .call::<(Value, Value)>((token.clone(), "s3cret-key", empty))
                .is_err()
        );
        let none: Table = lua
            .load(r#"{ algorithms = { "none" } }"#)
            .eval()
            .expect("opts");
        assert!(
            verify
                .call::<(Value, Value)>((token, "s3cret-key", none))
                .is_err()
        );

        // Expired tokens are rejected by default; leeway is opt-in.
        let expired: Table = lua
            .load("{ sub = \"42\", exp = 1000000 }")
            .eval()
            .expect("claims");
        let token: String = sign.call((expired, "s3cret-key")).expect("sign");
        let allow: Table = lua
            .load(r#"{ algorithms = { "HS256" } }"#)
            .eval()
            .expect("opts");
        let (claims, err): (Value, Option<String>) =
            verify.call((token, "s3cret-key", allow)).expect("verify");
        assert!(claims.is_nil());
        assert_eq!(err.as_deref(), Some("token expired"));
    }

    #[test]
    fn jwt_time_claims_honor_nbf_and_leeway() {
        let lua = Lua::new();
        let crypto = create_crypto_table(&lua).expect("crypto table");
        let jwt: Table = crypto.get("jwt").expect("jwt");
        let sign: mlua::Function = jwt.get("sign").expect("fn");
        let verify: mlua::Function = jwt.get("verify").expect("fn");
        let allow = |extra: &str| -> Table {
            lua.load(format!(r#"{{ algorithms = {{ "HS256" }}{extra} }}"#))
                .eval()
                .expect("opts")
        };

        // Not valid yet…
        let future_nbf: Table = lua
            .load("{ sub = \"42\", nbf = 4000000000 }")
            .eval()
            .expect("claims");
        let token: String = sign.call((future_nbf, "key")).expect("sign");
        let (claims, err): (Value, Option<String>) = verify
            .call((token.clone(), "key", allow("")))
            .expect("verify");
        assert!(claims.is_nil());
        assert_eq!(err.as_deref(), Some("token not yet valid"));

        // …unless the caller opts into enough leeway.
        let (claims, err): (Value, Option<String>) = verify
            .call((token, "key", allow(", leeway = 4000000000")))
            .expect("verify");
        assert!(err.is_none(), "got: {err:?}");
        assert!(!claims.is_nil());

        // Leeway also forgives a just-expired token.
        let expired: Table = lua
            .load("{ sub = \"42\", exp = 1000000 }")
            .eval()
            .expect("claims");
        let token: String = sign.call((expired, "key")).expect("sign");
        let (claims, err): (Value, Option<String>) = verify
            .call((token, "key", allow(", leeway = 4000000000")))
            .expect("verify");
        assert!(err.is_none(), "got: {err:?}");
        assert!(!claims.is_nil());
    }

    #[test]
    fn jwt_survives_hostile_tokens_without_panicking() {
        let lua = Lua::new();
        let crypto = create_crypto_table(&lua).expect("crypto table");
        let jwt: Table = crypto.get("jwt").expect("jwt");
        let verify: mlua::Function = jwt.get("verify").expect("fn");
        let allow: Table = lua
            .load(r#"{ algorithms = { "HS256" } }"#)
            .eval()
            .expect("opts");

        // The classic `alg: none` downgrade: a matching header with an
        // empty signature must not verify.
        let none_token = format!(
            "{}.{}.",
            B64URL.encode(r#"{"alg":"none","typ":"JWT"}"#),
            B64URL.encode(r#"{"sub":"42"}"#)
        );

        for hostile in [
            "".to_string(),
            "a".to_string(),
            "a.b".to_string(),
            "a.b.c.d".to_string(),
            "!!!.###.$$$".to_string(),
            "e30.e30.e30".to_string(), // `{}` header: no alg at all
            none_token,
            format!("{}.x.y", B64URL.encode("[1,2]")), // non-object header
            "\u{feff}garbage\u{0000}".to_string(),
        ] {
            let (claims, err): (Value, Option<String>) = verify
                .call((hostile.clone(), "key", &allow))
                .unwrap_or_else(|e| panic!("panicked on {hostile:?}: {e}"));
            assert!(claims.is_nil(), "accepted {hostile:?}");
            assert!(err.is_some(), "no reason for {hostile:?}");
        }
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

        let eq: mlua::Function = crypto.get("constant_time_eq").expect("fn");
        assert!(eq.call::<bool>(("same", "same")).expect("eq"));
        assert!(!eq.call::<bool>(("same", "diff")).expect("eq"));
        assert!(!eq.call::<bool>(("same", "longer-value")).expect("eq"));
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
}
