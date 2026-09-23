// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The one clock the standard library reads, with an override for
//! `nitr test` (`nitr.test.clock`).
//!
//! Every wall-clock or elapsed-time read whose answer a script can observe
//! goes through here: `nitr.time.now`/`monotonic`, session and JWT expiry,
//! the `after`/`before` validation rules, cache TTLs, and the rate
//! limiter's window. A test can then age a session or expire a cache entry
//! by saying so, instead of sleeping.
//!
//! What deliberately does **not** read this clock: the runtime's execution
//! deadline, every `tokio::time` timeout, and the body-stall timers. They
//! measure real time by design — routed through the override,
//! `t.clock.advance(3600)` would trip the budget of the very test that
//! called it.
//!
//! The override is process-global, because several readers (the rate
//! limiter, the cache) have no Lua state to find a per-state value in.
//! That is sound only because nothing sets it but the `nitr test` runner,
//! which runs files and tests strictly one after another and resets the
//! override after every test and every file. A production process never
//! calls [`set`] or [`advance`], and then every read costs one relaxed
//! atomic load on top of the real clock. The standard library's own unit
//! tests exercise a private `Clock` instance, never the global one.

use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The first second past year 9999: the bound every other date consumer
/// in the standard library (HTTP dates above all) already respects.
const MAX_TIMESTAMP: f64 = 253_402_300_800.0;

/// The most a test may move the clock forward in total: a century is far
/// past any TTL worth testing and far from any `Instant` overflow.
const MAX_ADVANCE: Duration = Duration::from_secs(100 * 366 * 24 * 60 * 60);

/// What the wall clock answers while an override is installed.
#[derive(Debug, Clone, Copy)]
enum Wall {
    /// `set(ts)`: time stands still at this instant (plus any later
    /// `advance`), so an assertion on `nitr.time.now()` cannot race a
    /// second boundary.
    Frozen(SystemTime),
    /// `advance(d)` without a `set`: the real clock, shifted forward.
    Shifted(Duration),
}

#[derive(Debug, Clone, Copy)]
struct Override {
    wall: Wall,
    /// Added to every monotonic reading: an `Instant` cannot move
    /// backwards, so only `advance` touches it.
    elapsed: Duration,
}

/// A clock with an optional override. The global one backs the free
/// functions below; tests build their own.
struct Clock {
    /// The fast path: false means no override, and the lock is never
    /// taken.
    active: AtomicBool,
    /// Set by every `set`/`advance`, cleared by [`take_touched`]: whether
    /// anything may have stored an instant from the overridden clock.
    touched: AtomicBool,
    state: RwLock<Option<Override>>,
}

impl Clock {
    const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            touched: AtomicBool::new(false),
            state: RwLock::new(None),
        }
    }

    fn current(&self) -> Option<Override> {
        if !self.active.load(Ordering::Relaxed) {
            return None;
        }
        // Poisoning needs a panic while the lock is held, and nothing
        // below can panic; the real clock is the safe answer regardless.
        self.state.read().ok().and_then(|state| *state)
    }

    fn system(&self) -> SystemTime {
        let real = SystemTime::now();
        match self.current().map(|o| o.wall) {
            None => real,
            Some(Wall::Frozen(at)) => at,
            Some(Wall::Shifted(by)) => real.checked_add(by).unwrap_or(real),
        }
    }

    fn instant(&self) -> Instant {
        let real = Instant::now();
        match self.current() {
            None => real,
            Some(o) => real.checked_add(o.elapsed).unwrap_or(real),
        }
    }

    fn set(&self, ts: f64) -> Result<(), String> {
        if !ts.is_finite() || !(0.0..MAX_TIMESTAMP).contains(&ts) {
            return Err(format!(
                "clock.set({ts}): the timestamp must be unix seconds between 0 and year 9999"
            ));
        }
        let at = Duration::try_from_secs_f64(ts)
            .map(|since| UNIX_EPOCH + since)
            .map_err(|err| format!("clock.set({ts}): {err}"))?;
        self.update(|current| Override {
            wall: Wall::Frozen(at),
            elapsed: current.map_or(Duration::ZERO, |o| o.elapsed),
        })
    }

    fn advance(&self, secs: f64) -> Result<(), String> {
        let by = Duration::try_from_secs_f64(secs)
            .ok()
            .filter(|_| secs.is_finite())
            .ok_or_else(|| {
                format!("clock.advance({secs}): the step must be a non-negative number of seconds")
            })?;
        let too_far = || {
            format!(
                "clock.advance({secs}): the clock may move at most {} days forward in total",
                MAX_ADVANCE.as_secs() / 86_400
            )
        };
        let current = self.current();
        let elapsed = current
            .map_or(Duration::ZERO, |o| o.elapsed)
            .checked_add(by)
            .filter(|total| *total <= MAX_ADVANCE)
            .ok_or_else(too_far)?;
        let wall = match current.map(|o| o.wall) {
            None => Wall::Shifted(by),
            Some(Wall::Shifted(shift)) => Wall::Shifted(
                shift
                    .checked_add(by)
                    .filter(|total| *total <= MAX_ADVANCE)
                    .ok_or_else(too_far)?,
            ),
            Some(Wall::Frozen(at)) => {
                let moved = at.checked_add(by).ok_or_else(too_far)?;
                let limit = UNIX_EPOCH + Duration::from_secs(MAX_TIMESTAMP as u64);
                if moved >= limit {
                    return Err(too_far());
                }
                Wall::Frozen(moved)
            }
        };
        self.update(|_| Override { wall, elapsed })
    }

    fn update(&self, next: impl FnOnce(Option<Override>) -> Override) -> Result<(), String> {
        let mut state = self
            .state
            .write()
            .map_err(|_| "the clock override lock is poisoned".to_string())?;
        *state = Some(next(*state));
        self.active.store(true, Ordering::Relaxed);
        self.touched.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn reset(&self) {
        self.active.store(false, Ordering::Relaxed);
        if let Ok(mut state) = self.state.write() {
            *state = None;
        }
    }
}

static CLOCK: Clock = Clock::new();

/// The wall clock.
pub fn now_system() -> SystemTime {
    CLOCK.system()
}

/// The wall clock as whole unix seconds (`0` before the epoch).
pub fn now_unix() -> i64 {
    now_system()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The wall clock as fractional unix seconds (`0.0` before the epoch).
pub fn now_unix_f64() -> f64 {
    now_system()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// The monotonic clock, moved forward by [`advance`].
pub fn now_instant() -> Instant {
    CLOCK.instant()
}

/// Freezes the wall clock at `ts` unix seconds. Monotonic time keeps
/// flowing: an `Instant` cannot be moved backwards. For `nitr test` only.
///
/// # Errors
///
/// A timestamp that is not finite, negative, or past year 9999.
pub fn set(ts: f64) -> Result<(), String> {
    CLOCK.set(ts)
}

/// Moves wall and monotonic time forward together by `secs` — what a TTL
/// or a rate-limit window needs to see. For `nitr test` only.
///
/// # Errors
///
/// A negative or non-finite step, or a total past a century.
pub fn advance(secs: f64) -> Result<(), String> {
    CLOCK.advance(secs)
}

/// Removes any override: every reader sees the real clock again.
pub fn reset() {
    CLOCK.reset();
}

/// Whether the clock was set or advanced since the last call — even if
/// it has been reset since. Anything that stored an instant meanwhile (a
/// cache entry's expiry) carries the overridden time: the runner clears
/// such state when this says so.
pub fn take_touched() -> bool {
    CLOCK.touched.swap(false, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix(clock: &Clock) -> f64 {
        clock
            .system()
            .duration_since(UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs_f64()
    }

    #[test]
    fn without_an_override_the_real_clock_answers() {
        let clock = Clock::new();
        let before = SystemTime::now();
        let read = clock.system();
        assert!(read >= before && read <= SystemTime::now());
        let before = Instant::now();
        let read = clock.instant();
        assert!(read >= before && read <= Instant::now());
    }

    #[test]
    fn set_freezes_the_wall_clock_and_leaves_elapsed_time_alone() {
        let clock = Clock::new();
        clock.set(1_735_689_600.0).expect("set");
        assert_eq!(unix(&clock), 1_735_689_600.0);
        assert_eq!(unix(&clock), 1_735_689_600.0, "frozen, not flowing");
        let before = Instant::now();
        let read = clock.instant();
        assert!(read >= before && read <= Instant::now() + Duration::from_millis(50));
    }

    #[test]
    fn advance_moves_wall_and_elapsed_time_together() {
        let clock = Clock::new();
        clock.set(1_000.0).expect("set");
        clock.advance(3_600.0).expect("advance");
        assert_eq!(unix(&clock), 4_600.0);
        let lead = clock.instant().duration_since(Instant::now());
        assert!(lead > Duration::from_secs(3_599), "elapsed moved: {lead:?}");

        // Without a `set`, advancing shifts the real wall clock.
        let shifted = Clock::new();
        let real = SystemTime::now();
        shifted.advance(86_400.0).expect("advance");
        let ahead = shifted.system().duration_since(real).expect("ahead");
        assert!(ahead >= Duration::from_secs(86_400) && ahead < Duration::from_secs(86_460));
    }

    #[test]
    fn reset_restores_the_real_clock() {
        let clock = Clock::new();
        assert!(!clock.touched.load(Ordering::Relaxed));
        clock.set(5.0).expect("set");
        clock.advance(10.0).expect("advance");
        clock.reset();
        assert!(
            clock.touched.swap(false, Ordering::Relaxed),
            "a reset keeps the record that the clock moved"
        );
        let now = SystemTime::now();
        let read = clock.system();
        assert!(read.duration_since(now).unwrap_or_default() < Duration::from_secs(1));
        assert!(clock.instant() <= Instant::now());
    }

    #[test]
    fn out_of_range_steps_are_refused_without_moving_the_clock() {
        let clock = Clock::new();
        for bad in [f64::NAN, f64::INFINITY, -1.0, 253_402_300_800.0, 1e300] {
            let err = clock.set(bad).expect_err("bad set");
            assert!(err.contains("year 9999"), "{bad}: {err}");
        }
        for bad in [f64::NAN, f64::INFINITY, -1.0, 1e300] {
            clock.advance(bad).expect_err("bad advance");
        }
        let err = clock
            .advance(MAX_ADVANCE.as_secs_f64() + 1.0)
            .expect_err("too far");
        assert!(err.contains("at most"), "{err}");
        assert!(clock.current().is_none(), "a refused step installs nothing");

        // Frozen near the end of time, a step past year 9999 is refused.
        clock.set(253_402_300_000.0).expect("set");
        clock.advance(1_000.0).expect_err("past year 9999");
        assert_eq!(unix(&clock), 253_402_300_000.0);
    }
}
