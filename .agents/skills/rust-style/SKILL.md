---
name: rust-style
description: Rust conventions in the Nitr codebase — errors and messages, async and blocking work, API shape, comments, diagnostics. Use before writing or reviewing Rust in this repo (for anything Lua-facing also read lua-api).
---

# Rust style (Nitr)

When in doubt, match the surrounding code. Every file in `crates/` starts
with the four-line SPDX header.

## Errors

- **Library code returns the crate's typed error.** A `panic!`, `unwrap`
  or `expect` must be unreachable. An allowed `expect` has a comment above
  it stating the invariant, and a scoped `#[allow(clippy::expect_used)]`.
- **Use `?` with `From`.** Add `map_err` only to add context the source
  lacks: a path, a setting name.
- **Lua-facing code returns `mlua::Result`.** Convert foreign errors with
  `into_lua_err()`.
- **Messages name the setting and the remedy**, for example
  "`[limits] max_body_bytes`" or "add a LIMIT or raise
  `[database] max_rows`".
  - Advice in a message must work. If it tells the user to call
    something, check what that call returns.
  - Messages reach logs and, in dev mode, clients. Never interpolate
    secrets, SQL text, cookie values, tokens or bodies; a name or a hash
    is enough.

## Async

- **Nothing blocks a tokio worker.** SQLite, argon2, template loading and
  rendering, and large file reads go through
  `tokio::task::spawn_blocking` or the async filesystem API.
- **Lua values never cross threads.** Convert to plain data first (JSON,
  `Vec<u8>`, `minijinja::Value`), then move it.
- **No lock and no Lua borrow is held across `.await`.** Never
  `block_on` inside the runtime.
- **CPU-bound Lua can finish inside one poll.** Racing it in a `select!`
  never sees the other branch. Spawn it when something must interrupt it.
- **A function that awaits nothing is not `async`.**

## API shape

- **`pub(crate)` by default.** `pub` only for the surface re-exported from
  `lib.rs`. `missing_docs` is denied, so every public item has `///`.
- **Borrow in signatures** (`&str`, `&Path`, `impl Into<_>`) unless
  ownership is needed. Clone `Arc`s, not data.
- **One home per invariant.** Grep for the existing helper before adding a
  check (`check_json_bounds`, `safe_join`, `new_hmac`,
  `merge_cookie_opts`, `run_blocking`) and route through it.
- **Edition 2024 idioms:** `let … else`, let-chains, `is_none_or`.
- **Beware the eager `then_some(x)`:** it builds `x` even when the
  condition is false, which runs `x`'s `Drop` at once. Use `then(|| x)`
  for anything with side effects.

## Comments

Code explains itself. Names, types, small functions and a clear control
flow carry the meaning; a comment is for what the code cannot say.

- **Doc comments (`///`, `//!`) are the contract, and they stay.**
  `missing_docs` is denied, so every public item has one. It says what the
  item does and promises, not how it works.
- **An inline comment (`//`) is allowed for exactly three things:**
  - an invariant the code relies on but cannot express (the comment above
    an allowed `expect`, a bound that must not be raised);
  - the attack or failure a bound, a scrub or an order of operations
    closes;
  - a why that lives outside the code: a library quirk (say where in the
    vendored source), or a measurement (say the number).
- **Everything else is deleted before review:**
  - a comment that narrates the next line, or repeats a name;
  - a comment that explains how the code works;
  - section banners, `Note:` and `Important:` prefixes;
  - change-log comments (`added`, `fixed`, `refactored`), and `TODO`s.
    Finish the work, or name what is left in your report.
- **A comment that explains how is a signal, not a solution.** Code that
  needs prose to be understood is code that may hide a bug. Before
  writing the comment, rename, extract a function, or split the branch.
  If the code is still hard to follow, keep it simple enough that one
  short comment names the invariant.
- **A comment is a claim.** When the code changes, update it or delete it.
  A comment promising something the code does not do is a bug.
- **One developer's voice.** New code follows this rule even where the
  file around it is chattier. When you touch an older comment that only
  restates the code, trim it. Never add a comment to match the density
  nearby.
- **The same rule covers Lua** (`test_framework.lua`, the runtime
  prelude). The one exception is teaching material: examples and the
  `nitr init` scaffold explain the pattern they show, in a sentence, and
  nothing more.
- **A scoped `#[allow(...)]` carries its reason** on the line above. Dead
  code is denied: delete it.
- **After `cargo fmt`, re-read what you anchored on.** Rustfmt reflows
  lines.

## Diagnostics

- **Library crates use `tracing` macros only.** Output meant for the user
  belongs to `nitr-cli`.
- **Error-level lines are for the operator.** Quote a request-derived
  string with `{:?}`, or log it at `debug`. A `\n` in a path forges a log
  line.
