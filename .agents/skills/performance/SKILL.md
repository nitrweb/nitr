---
name: performance
description: Performance work in Nitr — measure first, the hot-path rules, and the bounds that exist by design. Read before optimizing anything or touching the request path, the pool, or a limit.
---

# Performance (Nitr)

Third priority, after safety and security. A faster path that weakens a
bound, skips a check, or moves work onto the async runtime is a
regression, not an optimization.

## Measure first

- Benchmarks: `crates/nitr/benches/` (`runtime.rs`, `dispatch.rs`,
  `stdlib.rs`, shared `common/mod.rs`) on divan through the
  `codspeed-divan-compat` alias; `cargo bench --features all` locally,
  CodSpeed in CI. A perf change carries a bench and its before/after
  numbers in the report.
- Profiling: `cargo build --profile profiling` keeps symbols with the
  release code shape.
- Feature-gated bench groups are `cfg`-ed out, so a minimal build stays
  measurable; keep new groups the same way.
- Claims like "this is expensive" are verified with a number or dropped.

## Hot-path rules (the request path, the pool, streaming)

- Nothing blocking on a tokio worker: SQLite, argon2, template loading
  and rendering, file reads over a few KiB go through `spawn_blocking`
  or the async filesystem API.
- The accept loop takes no lock and does no I/O beyond accepting; a
  rebuild (reload) runs on its own task.
- Per-request allocation is bounded and boring: clone `Arc`s, not data;
  no `format!` in a loop; prepared statements come from the cache.
- One shared lock per request at most, held for a bounded, allocation-
  free critical section (the rate limiter is the model: purge time-gated,
  map capped). A `retain` under a global mutex on every request is a
  denial of service waiting for traffic.
- Channels are bounded (streaming bodies use capacity 2); backpressure
  is the design, not a bug.
- Lua states are reused, not rebuilt; a rebuild is for poison only.

## Bounded by design

These exist for safety and are not tuning knobs: `[limits]` (body, URI,
headers, connections, pool wait, read timeouts), `[database] max_rows`,
the JSON depth and node budget, the rate limiter's purge interval and
bucket cap, `max_response_bytes` and the outbound budget for `fetch`,
the session cookie size. Raising one is a security decision: state the
attack it admits and get it reviewed as such.

## What not to do

- No micro-optimization without a bench showing the path is hot.
- No `unsafe`, no `mem::forget`, no hand-rolled allocators.
- No caching of request-derived data across requests without a bound and
  an eviction policy (`cache.rs` is the model: entries and bytes, keys
  counted, TTL clamped).
- Do not widen a timeout to make a slow test pass; find the stall.
