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

use std::sync::OnceLock;

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

/// Upper bound on a password handed to `password_hash`/`password_verify`,
/// in the same spirit as [`MAX_RANDOM_BYTES`]: a bound a real credential
/// never notices and a hostile caller cannot step over.
///
/// Argon2 hashes its input in full, so without a cap any login form is a
/// remote amplifier — one POST body of a few megabytes buys an attacker a
/// worker thread pinned at 19 MiB of scratch memory plus a full pass over
/// those megabytes, and nothing about it looks like an attack. The cap is
/// checked *before* any argon2 work, so an oversized password costs a
/// length comparison.
///
/// 1 KiB is deliberately generous. NIST SP 800-63B asks that verifiers
/// accept passwords of at least 64 characters; a 1024-byte passphrase is
/// an order of magnitude past that and still far below anything worth
/// spending CPU on. (This is *not* a bcrypt-style truncation guard —
/// bcrypt hashes cannot reach this verifier at all, since `$2b$`/`$2y$`
/// fails PHC parsing. Nothing here silently shortens a password.)
///
/// The two sides of the cap answer differently, on purpose.
/// `password_hash` raises — a credential that cannot be stored must fail
/// loudly, at registration, where the user is present to be told.
/// `password_verify` and the dummy verify answer a plain `false, nil` —
/// no stored hash was ever minted from a password this long, so it is
/// simply a credential that cannot match; raising there made every
/// oversized login POST a 500 unless the handler pre-checked the length
/// itself, and a *reason* there would hand strangers a log-spam lever
/// through the `if problem then log` pattern. Scripts that want a
/// pre-check anyway read the cap as `nitr.crypto.max_password_bytes`.
const MAX_PASSWORD_BYTES: usize = 1024;

/// Ceilings on the argon2 parameters Nitr honors in a *stored* hash.
///
/// A PHC hash is data, and it names the cost of its own verification:
/// `$argon2id$v=19$m=4194304,t=2,p=1$…` asks the verifier for 4 GiB before
/// it can answer "wrong password". The format's own limits are no help —
/// `Params::MAX_M_COST` is `u32::MAX` KiB (4 TiB) and `MAX_T_COST` is
/// `u32::MAX` — and the parameters come from the hash, not from
/// `Argon2::default()`, so whatever is in the row is what runs.
///
/// Nitr's own hashes are m=19456, t=2, p=1. These ceilings are ~13x that
/// memory and 4x that time — well past every OWASP-recommended argon2id
/// configuration (the strongest is m=47104, t=1), so a deployment that
/// migrates to stronger parameters still verifies — while bounding one
/// verification at roughly 256 MiB and a few seconds instead of letting a
/// database row decide. RFC 9106's 2 GiB variant is deliberately outside
/// this: a per-request login check cannot afford it, and refusing it with
/// a reason beats discovering it as an OOM.
const MAX_HASH_MEMORY_KIB: u32 = 256 * 1024;
const MAX_HASH_TIME_COST: u32 = 8;
const MAX_HASH_LANES: u32 = 8;

/// The RNG/password-hash error types have no `std::error::Error` impl
/// here, so their `Display` is carried over manually.
fn rng_err(err: getrandom::Error) -> mlua::Error {
    mlua::Error::RuntimeError(format!("failed to read OS entropy: {err}"))
}

fn pw_err(err: argon2::password_hash::Error) -> mlua::Error {
    mlua::Error::RuntimeError(format!("password hashing failed: {err}"))
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

/// Every reason `password_verify` can return as its second value. A
/// closed set, like `jwt.verify`'s: a reason outside it means the failure
/// path grew a case nobody wrote down. Re-exported through
/// `nitr_std::fuzzing` so the fuzz target checks the real list rather
/// than a copy of it.
///
/// Every entry means the *stored hash* can never verify anything — the
/// contract of the reason channel is "the row is at fault; log it". An
/// over-cap *submitted* password is deliberately NOT in this set: it
/// answers a plain `false, nil` (see [`MAX_PASSWORD_BYTES`]), because a
/// reason a stranger can trigger at will would turn the natural
/// `if problem then log` handler into a log-spam primitive.
pub const VERIFY_REASONS: &[&str] = &[
    "unsupported hash format",
    "incomplete hash",
    "unsupported hash algorithm",
    "hash parameters out of range",
    "unusable hash",
];

/// Refuses a password past [`MAX_PASSWORD_BYTES`] before any argon2 work.
///
/// The *hash-side* guard: minting is the one place over-long must be an
/// error, because silently truncating would weaken a credential nobody
/// asked to weaken, and a `nil` would surface as a confusing failure two
/// calls later. Registration handlers that would rather answer 400 than
/// 500 pre-check against `nitr.crypto.max_password_bytes`. The verify
/// side does not use this — see [`MAX_PASSWORD_BYTES`] for why it answers
/// `false` instead.
fn check_password_len(password: &[u8]) -> mlua::Result<()> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(mlua::Error::RuntimeError(format!(
            "password must be at most {MAX_PASSWORD_BYTES} bytes, got {} — argon2 \
             hashes the whole input, so check the field length (nitr.validate) \
             before hashing and answer 400 instead of burning a worker",
            password.len()
        )));
    }
    Ok(())
}

/// Hashes a password with `Argon2::default()`: argon2id, v19, m=19456 KiB,
/// t=2, p=1, 32-byte output — OWASP's second recommended configuration.
///
/// The single place those parameters are chosen. `nitr hash-password`
/// reaches this through the same Lua function a handler calls, so an
/// operator-generated credential cannot drift from what the server
/// verifies.
fn hash_password(password: &[u8]) -> mlua::Result<String> {
    check_password_len(password)?;
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(rng_err)?;
    let salt = SaltString::encode_b64(&salt).map_err(pw_err)?;
    Ok(Argon2::default()
        .hash_password(password, &salt)
        .map_err(pw_err)?
        .to_string())
}

/// What a stored-hash verification concluded, as plain `Send` data.
///
/// The boundary type for the blocking offload: the verification runs on
/// the blocking pool, which cannot touch a `Lua`, so it reports an outcome
/// and the caller does the Lua-side logging.
enum VerifyOutcome {
    /// The password matches the stored hash.
    Matched,
    /// A well-formed argon2 hash this password does not match — the one
    /// benign failure.
    Mismatch,
    /// The stored row is at fault, with the reason to log.
    Rejected(&'static str),
}

/// The blocking half of `password_verify`: parse the stored hash (which
/// enforces the parameter ceilings) and verify against it.
///
/// Note what this does *not* do. The ceilings cap a single verification;
/// they do not make an at-ceiling row cheap. A stored hash at m=262144,
/// t=8, p=8 is accepted by design, and verifying it can still buy roughly
/// 256 MiB and seconds of a blocking-pool slot — the offload relocates
/// that cost off the async worker, it does not bound it. That is
/// acceptable because the ceiling caps one verification, the state pool
/// caps concurrency at `workers`, and the hashes come from the
/// deployment's own database rather than from an attacker.
fn verify_stored(password: &[u8], hash: &str) -> VerifyOutcome {
    match parse_stored_hash(hash) {
        Err(reason) => VerifyOutcome::Rejected(reason),
        Ok(parsed) => match Argon2::default().verify_password(password, &parsed) {
            Ok(()) => VerifyOutcome::Matched,
            // `Error::Password` is the one benign outcome: a well-formed
            // argon2 hash that this password does not match. Everything
            // else is the hash's fault, and `parse_stored_hash` has
            // already ruled out the cases the verifier reports as
            // `Password`.
            Err(argon2::password_hash::Error::Password) => VerifyOutcome::Mismatch,
            Err(_) => VerifyOutcome::Rejected("unusable hash"),
        },
    }
}

/// Parses a stored hash, or names why it can never verify anything.
///
/// The checks the verifier does not do for us, in order:
///
/// * PHC parsing. bcrypt (`$2b$`, `$2y$`), md5crypt (`$1$`) and
///   sha512crypt (`$6$`) all fail here — the exact case an operator hits
///   mid-migration.
/// * A missing salt or output segment. This one matters most: the
///   `PasswordVerifier` blanket impl answers `Error::Password` for a hash
///   with no output, so a truncated column would otherwise be reported as
///   "wrong password" forever.
/// * The algorithm identifier: a PHC string naming scrypt or pbkdf2
///   parses fine and is not something this verifier can check.
/// * The cost parameters, against the ceilings above.
fn parse_stored_hash(hash: &str) -> Result<PasswordHash<'_>, &'static str> {
    let parsed = PasswordHash::new(hash).map_err(|_| "unsupported hash format")?;
    if parsed.salt.is_none() || parsed.hash.is_none() {
        return Err("incomplete hash");
    }
    argon2::Algorithm::try_from(parsed.algorithm).map_err(|_| "unsupported hash algorithm")?;
    let params = argon2::Params::try_from(&parsed).map_err(|_| "unusable hash")?;
    if params.m_cost() > MAX_HASH_MEMORY_KIB
        || params.t_cost() > MAX_HASH_TIME_COST
        || params.p_cost() > MAX_HASH_LANES
    {
        return Err("hash parameters out of range");
    }
    Ok(parsed)
}

/// Logs an unusable stored hash and returns `false` plus its reason.
///
/// The hash never reaches the log — only its PHC algorithm identifier,
/// which is public metadata (`2b`, `scrypt`, `argon2id`) and the one
/// piece that tells an operator which migration left the row behind.
fn reject_hash(lua: &Lua, hash: &str, reason: &'static str) -> mlua::Result<(bool, Value)> {
    debug_assert!(
        VERIFY_REASONS.contains(&reason),
        "undeclared password_verify reason {reason:?}"
    );
    tracing::warn!(
        reason,
        algorithm = hash_ident(hash),
        "password_verify: the stored hash cannot be verified, so this login can \
         never succeed — re-hash the credential with nitr.crypto.password_hash \
         (or `nitr hash-password`)"
    );
    Ok((false, Value::String(lua.create_string(reason)?)))
}

/// The PHC algorithm identifier of a stored hash, for the log line.
/// Bounded and filtered: the value is whatever the database held, and a
/// log field is not the place to find that out.
fn hash_ident(hash: &str) -> &str {
    match hash.split('$').nth(1) {
        Some(ident)
            if (1..=32).contains(&ident.len())
                && ident
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-') =>
        {
            ident
        }
        _ => "unknown",
    }
}

/// The decoy hash [`dummy_verify`] compares against.
///
/// Built once per process from OS entropy and never stored anywhere, so
/// no caller can supply the password that matches it: the dummy verify is
/// structurally incapable of returning true.
static DECOY_HASH: OnceLock<String> = OnceLock::new();

/// Spends the same argon2 work a real verification costs, and answers
/// `false`.
///
/// This closes the user-enumeration oracle, which is compositional rather
/// than a flaw in any primitive here. The natural handler —
///
/// ```lua
/// local row = nitr.db:query_row("select ... where email = ?", { email })
/// if not row then return unauthorized() end
/// if not nitr.crypto.password_verify(pass, row.password_hash) then ... end
/// ```
///
/// — answers in microseconds for an address nobody registered and in
/// ~26 ms for one that exists. That thousandfold gap is measurable across
/// a network by an unauthenticated client, and it turns a login form into
/// a query interface over the user list. Calling this on the
/// no-such-user path makes both branches cost one argon2 hash.
///
/// The *submitted* password is hashed, not a fixed placeholder: argon2's
/// cost grows with the input, so hashing anything else would leave a
/// smaller version of the same difference behind.
///
/// The decoy is built lazily, so the first unknown-user request in a
/// process pays for two hashes instead of one. That is one sample of
/// noise, not an oracle — and the alternative, an unconditional 26 ms at
/// every state build, is a real cost for every deployment that never
/// calls this.
fn dummy_verify(password: &[u8]) -> mlua::Result<bool> {
    // Symmetric with `password_verify`'s over-cap answer: `false` before
    // any argon2 work. The short-circuit depends only on the submitted
    // password's own length, and it fires identically on the known-user
    // and no-such-user branches of a login, so it leaks nothing about
    // which branch ran.
    if password.len() > MAX_PASSWORD_BYTES {
        return Ok(false);
    }
    let decoy = match DECOY_HASH.get() {
        Some(decoy) => decoy.as_str(),
        None => {
            let mut secret = [0u8; 32];
            getrandom::getrandom(&mut secret).map_err(rng_err)?;
            let hash = hash_password(&secret)?;
            DECOY_HASH.get_or_init(|| hash).as_str()
        }
    };
    let parsed = PasswordHash::new(decoy).map_err(pw_err)?;
    // Always false: matching would mean guessing 32 bytes of OS entropy
    // that never left this process.
    Ok(Argon2::default().verify_password(password, &parsed).is_ok())
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
                crate::utils::check_json_bounds(&claims)?;
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
pub fn create_auth_table(lua: &Lua) -> mlua::Result<Table> {
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

    /// `password_hash`, `password_verify` and `password_verify_dummy` off
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
        let (ok, why): (bool, Option<String>) =
            pw(&verify, ("hunter2", hash.clone())).expect("verify");
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
            let (ok, why): (bool, Option<String>) =
                pw(&verify, ("hunter2", stored)).expect("verify");
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

        let err =
            pw::<String>(&hash_fn, over_cap.clone()).expect_err("1 KiB + 1 byte must not hash");
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
        // The empty input, whose digest is the one every implementation
        // publishes — a nibble table is exactly where an off-by-one hides,
        // and this is the known answer that catches one.
        assert_eq!(
            sha256.call::<String>("").expect("digest"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // A single byte, chosen so both nibbles differ and neither is
        // zero: `0x61` must render as "61", not "16", "6" or "061".
        assert_eq!(
            sha256.call::<String>("a").expect("digest"),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
        // Every nibble value appears across those three, and each digest
        // is exactly two characters per byte.
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
}
