---
name: rust-testing
description: Testing in the Nitr workspace — which kind of test goes where, what a regression test must prove, proptest, fuzz targets, the integration harness, CLI end-to-end tests, and the feature matrix. Use before adding or changing any test, and with investigate when a test is the reproduction.
---

# Testing (Nitr)

A change without a test is unfinished. A fix whose test was never seen
failing is unproven.

## Where each test goes

| Kind | Location | Notes |
|---|---|---|
| Unit | `#[cfg(test)] mod tests` in the module | test the module's boundary: a parser edge, a guard, an exact message |
| Lua-level stdlib | unit test with `mlua::Lua` and `register_builtins` | exercises what a script sees, not only the helper |
| Property (`prop_*`) | beside the code (see `url.rs`, `http/cookies.rs`, `range.rs`) | asserts a relation (round trip, idempotence, containment), not "does not panic" |
| Integration | `crates/nitr/tests/*.rs` via `harness/mod.rs` | `TestServer::builder`, `TestDir`, `reserve_addr`; `Server::test_client()` for in-process |
| Runtime and sandbox | `crates/nitr-core/src/runtime/tests.rs` | small `exec_timeout`, wrapped in an outer `tokio::time::timeout` |
| CLI end-to-end | `crates/nitr-cli/tests/cli.rs`; `nitr test` in `tests/cli/test_runner.rs` | spawn-based tests start with `require_runnable_binary!()` |
| Fuzz | `fuzz/fuzz_targets/*.rs` (nightly, outside the workspace) | see below |
| Release profile | `cargo test -p nitr --release --features all --test resilience` | the only run that sees fat LTO and the release panic setup |

Examples and the `nitr init` scaffold have no tests. After touching one,
build it, run it, and exercise its routes.

## A regression test must

- **Fail before the fix, for the asserted reason.** Read the failure
  message.
- **Fail again when the fix is sabotaged** while it still compiles, then
  pass once the fix is restored. Say how you sabotaged it.
- **Assert the exact outcome:** the message, the count, the header, the
  bytes. A bare `is_err()`/`is_some()` lets a wrong-but-safe
  implementation pass.
- **Stay bounded.**
  - No fixed sleeps. Drive time through `check_at` or `nitr_std::clock`,
    or poll a deadline.
  - A test that would hang without the fix runs under a timeout, and its
    doc comment says so.
- **Have a sentence for a name**: what must hold, not which function it
  pokes.

## Flaky tests

A test that passes here and fails on a slower machine is a wrong test.
CI runs on macOS, Windows and emulated targets, several times slower than
a dev box.

- **Never race two limits.** A test that needs limit A to fire makes it
  fire far inside every other limit that could fire first. A memory hog
  takes 1 MiB a step, not 64 bytes a step against a 500 ms budget.
- **Measure the margin, then keep it at 10× or more.** Time the work on
  your machine; a 2× margin is a macOS failure waiting to happen.
- **Reproduce a speed-dependent failure by shrinking the budget** until
  the slow path wins, then check the fix holds at that budget.
- **Assert the contract, not a schedule.** "At most N in flight", not
  "exactly N". An elapsed-time check sits below the least time the wrong
  behaviour must take (the sum of the backoff floors), with room to spare.
- **Effects on another thread are polled to a deadline.** A cleanup in
  `spawn_blocking` or a `Drop` elsewhere lands after the response; assert
  it inside a bounded poll, never right after the call.

## Hygiene

- **Own every file you write.** Use a per-test `TestDir` or `Scratch`
  (counter plus pid); never a fixed name in the shared temp dir. It is
  removed on success, and kept and printed on failure.
- **Ports:** bind port 0 and keep the listener.
- **Async tests** that drive Lua use `#[tokio::test]`. Blocking work
  inside the code under test needs `flavor = "multi_thread"`.
- **Upload roots** go through `Builder::upload_dir()`, so they sit outside
  the `require` root.
- **A test for a gated feature lives in a gated module**, so
  `--no-default-features` still compiles.
- **Clippy lints tests too.**
  - `expect("…")` is fine in a test.
  - Any `#[allow]` carries its reason. The standing case is the shared
    harness's `#![allow(dead_code)]`, because each test binary uses a
    subset of it.
- **Proptest regression files** (`proptest-regressions/`) are tracked.
  Keep them.

## Fuzz targets

- **Inputs** come through `fuzz/src/lib.rs::Input` (fixed-width numbers
  first, then NUL-separated fields), never `Arbitrary` tuples.
- **Internal entry points** are exposed as `_for_fuzzing` functions under
  `#[doc(hidden)] pub mod fuzzing` in the crate root.
- **A new target** means updating the `fuzz/Cargo.toml` `[[bin]]` (a
  kebab-case name), the `Makefile` `FUZZ_TARGETS`, and the
  `.github/workflows/fuzz.yml` matrix. `make fuzz-check` fails on drift.
  Add curated seeds in `fuzz/seeds/<target>/` and, usually,
  `fuzz/dicts/<target>.dict`.
- **Assertions state properties** a wrong-but-crash-free parser would
  break (round trip, containment, fixpoint), not only "no panic".
- **Oracles pin behaviour, so a behaviour change updates them.** Before
  changing what a function returns or refuses, grep `fuzz/fuzz_targets/`
  for it. Pinned outputs, allowed-error lists and "asserted as it
  behaves" rows move with the fix in the same change; CI finds them
  otherwise.
- **Read Lua strings as bytes** (`LuaString`) in an oracle unless the
  contract promises UTF-8; a `String` conversion panics on the first
  non-UTF-8 input the fuzzer makes.
- **A lossy view can merge distinct inputs.** When an oracle compares
  through one (lossy UTF-8, case folding, a map keyed on the result),
  two inputs can collapse into one; accept any of them there, and keep
  exact equality everywhere else.
- **Replay a CI crash** from its base64 line: decode it into a file under
  `target/`, then `cargo +nightly fuzz run --target
  x86_64-unknown-linux-gnu <target> <file>`.
- **Run one** with
  `cd fuzz && cargo +nightly fuzz run --target x86_64-unknown-linux-gnu <target> <scratch-corpus>`.
  Never point it at `fuzz/seeds/<target>`: libFuzzer writes into the
  corpus directory.

## The matrix

- **Both must be green:** `cargo test --workspace --features all` and
  `cargo test --workspace --no-default-features`. In the second, gated
  modules vanish; that is expected, not coverage.
- **`cargo test` stops at the first failing binary.** Use `--no-fail-fast`
  when surveying, and rerun the whole set after a fix.
- **Clippy is denied on purpose for:**
  - `unwrap_used`/`expect_used` outside tests (crate-level);
  - `dbg_macro`, `todo`, `unimplemented`, `unreachable` and `mem_forget`
    (workspace);
  - dead code and missing docs (rustc lints).
