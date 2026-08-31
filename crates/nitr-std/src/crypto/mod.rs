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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac as _};
use mlua::{Lua, LuaString, Table, Value};
use sha2::{Digest as _, Sha256};
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

/// Lowercase hex digits, indexed by nibble.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex, two characters per byte.
///
/// A nibble lookup rather than `format!("{b:02x}")` per byte: the old form
/// ran the whole `core::fmt` machinery and allocated a temporary `String`
/// for every byte of every digest. The table is 16 bytes — one cache line
/// — and the output is byte-identical, which is the entire safety
/// argument for the change.
///
/// This encodes digest and MAC *outputs*, never a value being compared:
/// comparison has its own primitive (`constant_time_eq`), so a
/// data-dependent table index introduces no property the `format!` did
/// not already have.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_DIGITS[(b >> 4) as usize] as char);
        out.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Builds the `nitr.crypto` table.
pub fn create_crypto_table(lua: &Lua) -> mlua::Result<Table> {
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
    //
    // `n` is a full Lua integer, not `usize`: a Lua integer is 64-bit on
    // every platform, and taking `usize` would turn an out-of-range `n`
    // into a conversion error on 32-bit targets but this range message on
    // 64-bit ones. The range check itself is the only bound that matters.
    crypto.set(
        "random_bytes",
        lua.create_function(|lua, n: i64| {
            if n < 1 || n > MAX_RANDOM_BYTES as i64 {
                return Err(mlua::Error::RuntimeError(format!(
                    "random_bytes(n) requires 1 <= n <= {MAX_RANDOM_BYTES}, got {n}"
                )));
            }
            let mut buf = vec![0u8; n as usize];
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

    // Argon2 is deliberately expensive — ~19 MiB of scratch and tens of
    // milliseconds — and none of that is interruptible: it is synchronous
    // Rust, so the instruction hook never fires and the async timeout
    // never fires. Run inline it holds a tokio *worker* for its whole
    // duration, and with `workers` of them busy the executor cannot even
    // answer `/healthz`. So all three argon2 doors offload to the blocking
    // pool, the shape `db/mod.rs` already uses: only plain `Send` data
    // crosses, never a Lua handle.
    //
    // Concurrency is bounded by the state pool, not by anything here: one
    // pooled state serves one request at a time and no builtin fans a
    // state out over several hashes (`nitr.await_all`'s job set is a
    // closed enum of fetch and db work). Worst case is `workers`
    // concurrent blocking tasks against a 512-thread default pool — which
    // is why there is no semaphore. That invariant becomes load-bearing
    // the day `await_all` grows a hashing job.
    crypto.set(
        "password_hash",
        lua.create_async_function(|_, password: LuaString| async move {
            let password = password.as_bytes().to_vec();
            // Before the offload: an over-cap password must cost a length
            // comparison, not a blocking-pool slot.
            check_password_len(&password)?;
            tokio::task::spawn_blocking(move || hash_password(&password))
                .await
                .map_err(mlua::Error::external)?
        })?,
    )?;

    // The cap, as data, so a registration form can size its field with
    // `#password > nitr.crypto.max_password_bytes` instead of copying a
    // magic 1024 that would silently drift if the cap ever changed.
    crypto.set("max_password_bytes", MAX_PASSWORD_BYTES)?;

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

    // password_verify(password, hash) -> ok, nil | false, reason
    //
    // The boolean is the answer a caller branches on and stays the same
    // shape it always was. The second value is the diagnostic that was
    // missing: `false, nil` is a wrong password, `false, reason` is a
    // stored hash that can *never* verify — a bcrypt row pasted in during
    // a migration, a truncated column, a parameter set that would
    // allocate the machine away. Without it those are the same 401
    // forever, with nothing anywhere saying why. Same precedent as
    // `jwt.verify`: nil-plus-reason on the failure path.
    crypto.set(
        "password_verify",
        lua.create_async_function(|lua, (password, hash): (LuaString, String)| async move {
            let password = password.as_bytes().to_vec();
            // Over the cap is answered, not raised: no stored hash was
            // ever minted from a password this long (`password_hash`
            // refuses them), so it is a credential that cannot match —
            // decided by a length comparison before argon2 ever runs,
            // which is the DoS guard. Answering keeps the naive handler
            // correct out of the box; raising here turned every oversized
            // login POST into a 500 unless the handler pre-checked the
            // length itself.
            //
            // `false, nil`, not `false, <reason>`: the reason channel's
            // contract is "the stored row is at fault, log it" — a length
            // overrun is attacker input, and a reason here would turn the
            // taught `if problem then log` pattern into a free log-spam
            // primitive. Debug tracing covers the one legitimate case (a
            // user with a genuinely enormous passphrase) without giving
            // strangers a lever.
            if password.len() > MAX_PASSWORD_BYTES {
                tracing::debug!(
                    bytes = password.len(),
                    "password_verify: over the {MAX_PASSWORD_BYTES}-byte cap, answered false \
                     before hashing"
                );
                return Ok((false, Value::Nil));
            }
            // Both the parse (which enforces the stored-parameter
            // ceilings) and the verification run on the blocking pool.
            // The parse has to go with it: `PasswordHash` borrows the hash
            // string, so splitting them would either send a borrow across
            // the boundary or re-parse on the worker.
            let owned = hash.clone();
            let outcome = tokio::task::spawn_blocking(move || verify_stored(&password, &owned))
                .await
                .map_err(mlua::Error::external)?;
            match outcome {
                VerifyOutcome::Matched => Ok((true, Value::Nil)),
                VerifyOutcome::Mismatch => Ok((false, Value::Nil)),
                // Logging the rejection needs `&Lua`, so it stays on this
                // side of the boundary — the blocking half returns a
                // plain reason and touches nothing Lua.
                VerifyOutcome::Rejected(reason) => reject_hash(&lua, &hash, reason),
            }
        })?,
    )?;

    // The other half of a login: what to do when the *user* does not
    // exist. See `dummy_verify` for why a handler that skips the hash
    // comparison in that case leaks its user list.
    crypto.set(
        "password_verify_dummy",
        lua.create_async_function(|_, password: LuaString| async move {
            let password = password.as_bytes().to_vec();
            // Before the offload, and symmetric with `password_verify`'s
            // over-cap answer, so the two branches of a login still cost
            // the same and leak nothing about which one ran.
            if password.len() > MAX_PASSWORD_BYTES {
                return Ok(false);
            }
            // The first call in a process mints the decoy, so it pays for
            // two hashes — which is exactly why it belongs off the worker
            // rather than on it.
            tokio::task::spawn_blocking(move || dummy_verify(&password))
                .await
                .map_err(mlua::Error::external)?
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

mod auth;
mod jwt;
mod password;
#[cfg(test)]
mod tests;

pub use auth::create_auth_table;
use jwt::create_jwt_table;
pub use password::VERIFY_REASONS;
use password::{
    MAX_PASSWORD_BYTES, VerifyOutcome, check_password_len, dummy_verify, hash_password,
    reject_hash, verify_stored,
};
