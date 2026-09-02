---
name: rust-testing
description: Testing in the Nitr workspace — which kind of test goes where, regression-test rules, proptest, fuzzing, integration harness, the feature matrix and clippy. Read before adding or changing any test.
---

# Testing (Nitr)

A change without a test is unfinished. A fix without a test that fails
before the fix is a guess.

## Kinds and where they live

- **Unit**: `#[cfg(test)] mod tests` in the module. Test the module's
  boundary (parser edge, guard, error message), not its internals.
- **Property** (`proptest!`, names `prop_*`): parsers, encoders, crypto
  round-trips. Existing examples: `crates/nitr-std/src/url.rs`,
  `path/tests.rs`, `http/cookies.rs`, `crates/nitr-http/src/range.rs`.
  A property asserts a relation (round-trip, idempotence, containment),
  not "does not panic".
- **Fuzz**: `fuzz/fuzz_targets/*.rs` (nightly, excluded from the
  workspace). Inputs come through `fuzz/src/lib.rs::Input` (fixed-width
  numbers first, then NUL-separated fields) — never `Arbitrary` tuples,
  whose length prefixes made hand-written seeds dead on arrival. Each
  target has `fuzz/seeds/<target>/` (curated, human-readable) and usually
  `fuzz/dicts/<target>.dict`. Internal entry points are exposed as
  `_for_fuzzing` functions under `#[doc(hidden)] pub mod fuzzing` in the
  crate root. Adding a target means: `fuzz/Cargo.toml` `[[bin]]`, the
  `Makefile` `FUZZ_TARGETS` list, `.github/workflows/fuzz.yml` matrix
  entry — `make fuzz-check` fails on drift. Run one with
  `cd fuzz && cargo +nightly fuzz run --target x86_64-unknown-linux-gnu <target>`.
- **Integration**: `crates/nitr/tests/*.rs` through
  `crates/nitr/tests/harness/mod.rs` (`TestServer::builder`, `TestDir`,
  `reserve_addr`). Every file a test writes goes in its own `TestDir`,
  never the shared system temp directory (the dev watcher once reacted to
  other tests' churn there). Handler in its own directory for dev-mode
  tests. An upload root goes through `Builder::upload_dir()` so it sits
  outside the `require` root, or validation refuses to boot.
- **Release profile**: `cargo test -p nitr --release --features all
  --test resilience` — the only run that sees `overflow-checks` and LTO.
- **CLI end-to-end**: `crates/nitr-cli/tests/cli.rs`; spawn-based tests
  start with `require_runnable_binary!()` (cross-compiled runners cannot
  exec the child).
- **Examples are not tested.** After touching one, build and run it,
  then hit its routes with curl.

## Regression tests

- Reproduce first: a failing test (or a live reproduction) before the fix.
- Prove it fails without the fix: revert, or sabotage in a way that still
  compiles, and watch it fail for the asserted reason. Say which.
- Assert the exact outcome — the message, the count, the header — never a
  bare `is_err()`/`is_some()`. A wrong-but-safe implementation must fail.
- No sleep-based timing; drive clocks through an explicit instant seam
  (`check_at`) or poll a deadline. A test that hangs without the fix says
  so in its doc comment.
- Feature-gated behaviour gets its test in a module that is itself
  gated, so `--no-default-features` compiles.

## The matrix

- `cargo test --workspace --features all` and
  `cargo test --workspace --no-default-features` both green. Gated test
  modules vanish silently in the second; that is expected, not coverage.
- `cargo test` stops at the first failing test binary. Fix it, rerun the
  whole set; a later binary may hide a second failure.
- Clippy: `cargo clippy --workspace --features all --all-targets -- -D warnings`
  and the `--no-default-features` twin. Denied on purpose: `unwrap_used`/
  `expect_used` outside tests, `dbg_macro`, `todo`, `unimplemented`,
  `unreachable`, `mem_forget`, dead code, missing docs. Clippy also lints
  tests: an `expect("…")` in a test is fine, a `#[allow]` in one is not.

## Test hygiene

- Temp paths are per-test (counter + pid), removed on success, kept and
  printed on panic. Never a fixed name in `/tmp`.
- Tests that need a port bind port 0 and keep the listener.
- Async tests that drive a Lua state use `#[tokio::test]`; blocking work
  inside the code under test needs `flavor = "multi_thread"`.
- A test's name is a sentence: what must hold, not what function it pokes.
