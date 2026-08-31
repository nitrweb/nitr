// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The argon2id password surface: the caps, minting, stored-hash
//! verification with its closed reason set, and the enumeration-closing
//! dummy verify.

use std::sync::OnceLock;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use mlua::{Lua, Value};

use super::rng_err;

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
pub(super) const MAX_PASSWORD_BYTES: usize = 1024;

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

/// The password-hash error type has no `std::error::Error` impl here, so
/// its `Display` is carried over manually.
fn pw_err(err: argon2::password_hash::Error) -> mlua::Error {
    mlua::Error::RuntimeError(format!("password hashing failed: {err}"))
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
pub(super) fn check_password_len(password: &[u8]) -> mlua::Result<()> {
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
pub(super) fn hash_password(password: &[u8]) -> mlua::Result<String> {
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
pub(super) enum VerifyOutcome {
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
pub(super) fn verify_stored(password: &[u8], hash: &str) -> VerifyOutcome {
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
pub(super) fn parse_stored_hash(hash: &str) -> Result<PasswordHash<'_>, &'static str> {
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
pub(super) fn reject_hash(
    lua: &Lua,
    hash: &str,
    reason: &'static str,
) -> mlua::Result<(bool, Value)> {
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
pub(super) fn hash_ident(hash: &str) -> &str {
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
pub(super) static DECOY_HASH: OnceLock<String> = OnceLock::new();

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
pub(super) fn dummy_verify(password: &[u8]) -> mlua::Result<bool> {
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
