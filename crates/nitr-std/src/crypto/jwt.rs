// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr.crypto.jwt`: HMAC-signed JWTs — signing, and verification with a
//! mandatory algorithm allow-list.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hmac::{Hmac, Mac as _};
use mlua::{Lua, LuaString, Table, Value};
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq as _;

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
///
/// # What `verify` does not check
///
/// It enforces the signature, the mandatory `algorithms` allow-list, and
/// `exp`/`nbf`. It checks **no registered claim beyond those**, and the
/// omissions are invisible at the call site, so they are written down
/// here and in `docs-feat/jwt.md`:
///
/// - **`iss` and `aud` are never read.** A token minted for another
///   audience, or by another issuer, verifies here exactly like one minted
///   for you. Comparing them is the caller's job.
/// - **`typ` is written on sign and never verified.** `sign` sets
///   `typ: "JWT"` in the header; `verify` does not look at it. The
///   asymmetry is the trap: the field's presence suggests a check that
///   does not exist.
/// - **`exp` and `nbf` are checked only when present.** A token carrying
///   neither never expires. Nothing requires them, so "the signature is
///   valid" and "the token is still good" are different questions.
///
/// Shipping primitives rather than a framework is deliberate — a claim
/// policy belongs to the application — but an undocumented omission is a
/// defect regardless of that. See `docs-feat/jwt.md` for the caller-side
/// checks to write, including the `aud`-is-a-string-or-an-array edge
/// (RFC 7519 §4.1.3).
pub(super) fn create_jwt_table(lua: &Lua) -> mlua::Result<Table> {
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
                let payload = crate::bounded::to_json_string(&claims)
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
            // NaN makes both time comparisons false and infinity makes
            // them vacuous: either silently turns expiry off.
            if !leeway.is_finite() || leeway < 0.0 {
                return Err(mlua::Error::RuntimeError(format!(
                    "jwt.verify `leeway` must be a finite number of seconds >= 0, got {leeway}"
                )));
            }

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
            // A present-but-non-numeric `exp`/`nbf` is not "absent": RFC
            // 7519 requires a NumericDate, and treating `"exp": "soon"` as
            // no expiry would verify a token its issuer meant to expire.
            let numeric_date = |name: &str| -> Result<Option<f64>, ()> {
                match claims.get(name) {
                    None => Ok(None),
                    Some(value) => value.as_f64().map(Some).ok_or(()),
                }
            };
            let (Ok(exp), Ok(nbf)) = (numeric_date("exp"), numeric_date("nbf")) else {
                return jwt_reject(lua, "malformed claims");
            };
            let now = unix_now();
            if let Some(exp) = exp
                && now > exp + leeway
            {
                return jwt_reject(lua, "token expired");
            }
            if let Some(nbf) = nbf
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
