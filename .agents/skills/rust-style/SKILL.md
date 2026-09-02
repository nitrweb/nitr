---
name: rust-style
description: Rust and Lua-facing conventions for the Nitr codebase — errors, async, API shape, comments, and the nitr.* Lua contract. Read before writing or reviewing code in this repo.
---

# Rust style (Nitr)

When in doubt, match the surrounding code. Every file starts with the
four-line SPDX header used everywhere in `crates/`.

## Errors

- Library code returns the crate's typed error via its `Result`; never
  `panic!`/`unwrap`/`expect` on a path reachable at runtime. An allowed
  `expect` states the invariant in a comment above it.
- Prefer `?` with `From`; use `map_err` only to add context the source
  lacks (a path, a setting name).
- Lua-facing helpers return `mlua::Result`; convert foreign errors with
  `into_lua_err()`.
- Messages name the setting and the remedy (`[limits] max_body_bytes`,
  "add a LIMIT or raise [database] max_rows"). They reach logs and, in
  dev mode, the client: never interpolate secrets, SQL text, cookie
  values, tokens or request bodies. A name or a hash is enough.
- Data problems on the Lua side return `nil, reason`; caller bugs raise.

## Async

- Nothing blocking on the runtime: no synchronous I/O, `std::thread::sleep`,
  argon2, SQLite, template loading or rendering — `tokio::task::spawn_blocking`.
- Lua values never cross threads. Convert to plain data (JSON, `Vec<u8>`,
  a `minijinja::Value`) on the Lua thread, then move.
- Do not hold a lock across `.await`; if the design requires it, say so
  in a comment. Never `block_on` inside the runtime.
- A function that awaits nothing is not `async`.

## API shape

- `pub(crate)` by default; `pub` only for the surface re-exported from
  `lib.rs`. `missing_docs` is denied: every public item has `///`.
- Borrow in signatures (`&str`, `&Path`, `impl Into<_>`) unless ownership
  is needed. Clone `Arc`s, not data.
- One home per invariant. Before adding a check, grep for the existing
  one (`check_json_bounds`, `safe_join`, `new_hmac`, `merge_cookie_opts`,
  `run_blocking`) and route through it.
- Edition 2024 idioms are in use: `let … else`, let-chains, `is_none_or`.

## Comments

- Explain the why and the invariant, not the next line. A bound or a
  scrub says what attack it closes in a few words.
- A scoped `#[allow(clippy::…)]` always carries the reason on the line
  above it. Dead code is denied: delete, don't allow.
- After `cargo fmt`, re-grep anything you anchored on: rustfmt reflows.

## Lua-facing conventions (`nitr.*`)

- Options are a trailing table; unknown keys are ignored, wrong types
  raise. Request header keys are lowercase.
- Every builtin, option and return shape is documented in
  `crates/nitr-cli/src/nitr-api.toml`; regenerate `resources/` after.
- Anything a script hands to Rust is untrusted: sizes are `i64` and
  range-checked before `as usize`; durations from floats go through
  `try_from_secs_f64`; strings may be non-UTF-8 bytes.
- Never expose a raw filesystem, process or network primitive; the
  sandbox is the product (`security-safety`).

## Diagnostics

- `tracing` macros only. Error-level lines are for the operator: a
  request-derived string is `{:?}`-quoted or at `debug`, never at `warn`
  with `display()` (a `\n` in a path forges a log line).
