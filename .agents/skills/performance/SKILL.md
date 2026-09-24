---
name: performance
description: Performance work in Nitr — measure before and after, the hot-path rules for the request path, pool and streaming, and the limits that are safety bounds rather than tuning knobs. Use before optimizing anything or touching the request path, the pool, a cache, or a limit.
---

# Performance (Nitr)

Performance is the third priority. A faster path that weakens a bound,
skips a check, or moves blocking work onto the async runtime is a
regression.

## Measure, or do not claim

- **Benchmarks:** `crates/nitr/benches/` (`runtime.rs`, `dispatch.rs`,
  `stdlib.rs`, and the shared `common/mod.rs`), on divan through the
  `codspeed-divan-compat` alias. Run them locally with
  `cargo bench --features all`; CI uses CodSpeed.
- **A performance change reports before-and-after numbers** from the same
  bench on the same machine. "This is expensive" and "this is faster" are
  claims (`investigate`): back them with a number, or drop them.
- **Profiling:** `cargo build --profile profiling` keeps symbols with the
  release code shape. Profile a live binary under load when bench
  harnesses distort the picture.
- **Feature-gated bench groups are `cfg`-ed out,** so a minimal build
  stays measurable. Keep new groups the same way.

## Hot-path rules (the request path, the pool, streaming)

- **Nothing blocking on a tokio worker.** SQLite, argon2, templates and
  file reads go through `spawn_blocking` or the async filesystem API.
- **The accept loop** takes no lock and does no I/O beyond accepting. A
  reload runs on its own task.
- **Per-request work stays bounded and boring.** Clone `Arc`s, not data.
  No `format!` in a loop. Prepared statements come from the cache.
- **At most one shared lock per request,** with a bounded, allocation-free
  critical section. The rate limiter is the model: purging is time-gated
  and the map is capped. A `retain` under a global mutex on every request
  is a denial of service waiting for traffic.
- **Channels are bounded.** Streaming bodies use capacity 2; backpressure
  is the design.
- **Lua states are reused.** A rebuild happens only after poisoning or a
  reload.

## Bounds, not knobs

These limits exist for safety:

- `[limits]` (body, URI, headers, connections, pool wait, read timeouts);
- `[database] max_rows`;
- the JSON depth and node budget;
- the rate limiter's purge interval and bucket cap;
- `max_response_bytes`, and the outbound budget for `fetch`;
- the session cookie size.

Raising one is a security decision. State the attack it admits, and get
it reviewed as one.

## Do not

- Micro-optimize without a bench that shows the path is hot.
- Use `unsafe`, `mem::forget`, or a hand-rolled allocator.
- Cache request-derived data across requests without a bound on entries
  and bytes and an eviction policy (`cache.rs` is the model).
- Widen a timeout to make a slow test pass. Find the stall.
