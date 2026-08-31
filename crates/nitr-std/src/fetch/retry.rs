// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Retry policy for outbound requests: which statuses are worth repeating,
//! the caller's retry intent, and jittered exponential backoff.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use mlua::Table;
use reqwest::StatusCode;

/// Base delay for the first retry; each further attempt doubles it.
const RETRY_BASE_DELAY: Duration = Duration::from_millis(100);

/// Ceiling on a single backoff wait, so a long backoff cannot outlive the
/// inbound request it belongs to.
const RETRY_MAX_DELAY: Duration = Duration::from_secs(5);

/// Per-call retry intent, from the Lua options table.
#[derive(Debug, Clone, Copy)]
pub(super) struct Retry {
    pub(super) attempts: u32,
    pub(super) exponential: bool,
}

/// Statuses worth trying again: the upstream is saying "not now" rather
/// than "no". A `404` or a `400` would return the same answer forever, so
/// repeating those only wastes the budget.
pub(super) fn is_retryable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504)
}

/// Exponential backoff with jitter.
///
/// The jitter matters more than the curve: without it, every request that
/// failed together retries together, and the upstream that just fell over
/// gets a synchronized second wave.
pub(super) fn backoff(attempt: u32, exponential: bool) -> Duration {
    let base = if exponential {
        RETRY_BASE_DELAY.saturating_mul(1u32 << (attempt - 1).min(10))
    } else {
        RETRY_BASE_DELAY
    }
    .min(RETRY_MAX_DELAY);

    // Full jitter over [base/2, base]. A counter-seeded xorshift is plenty:
    // this decorrelates retries, it does not need to be unpredictable.
    static SEED: AtomicU32 = AtomicU32::new(0x9e37_79b9);
    let mut x = SEED.fetch_add(0x9e37_79b9, Ordering::Relaxed) | 1;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    let half = base / 2;
    half + half.mul_f64(f64::from(x % 1000) / 1000.0)
}

/// `retry = { attempts = 3, backoff = "exponential" }`.
pub(super) fn parse_retry(table: &Table) -> mlua::Result<Retry> {
    let attempts = table.get::<Option<u32>>("attempts")?.unwrap_or(3);
    let exponential = match table.get::<Option<String>>("backoff")?.as_deref() {
        None | Some("exponential") => true,
        Some("constant") => false,
        Some(other) => {
            return Err(mlua::Error::RuntimeError(format!(
                "unknown retry backoff `{other}`: expected \"exponential\" or \"constant\""
            )));
        }
    };
    Ok(Retry {
        attempts,
        exponential,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_stays_jittered_within_bounds() {
        for attempt in 1..=4u32 {
            let base = RETRY_BASE_DELAY * (1 << (attempt - 1));
            for _ in 0..20 {
                let delay = backoff(attempt, true);
                assert!(
                    delay >= base / 2 && delay <= base,
                    "attempt {attempt}: {delay:?} outside [{:?}, {:?}]",
                    base / 2,
                    base
                );
            }
        }
        // Constant backoff ignores the attempt number.
        let delay = backoff(8, false);
        assert!(delay <= RETRY_BASE_DELAY);
        // And nothing ever waits longer than the ceiling.
        assert!(backoff(30, true) <= RETRY_MAX_DELAY);
    }
}
