---
name: verify
description: The verification ladder for Nitr changes — format, lint, tests in both feature sets, generated docs, fuzz seams, dependencies, and a live smoke. Run after any change and before declaring a task done or preparing a commit.
---

# Verify (Nitr)

Run from the repository root, in order, and stop at the first failure.
A partial run proves nothing about the steps it skipped.

1. **Format** — `cargo fmt --all`
   Then re-grep any comment or anchor you edited: rustfmt reflows lines.
2. **Lint** — `make lint`
   Runs the format check, clippy with `--features all` and with
   `--no-default-features` (both `--all-targets -- -D warnings`), and
   `fuzz-check` (fuzz target list and seed directory drift).
3. **Test** — `make test`
   `cargo test --features all`, `cargo test --no-default-features`, and the
   release-profile resilience test. `cargo test` stops at the first failing
   binary: after a fix, run the full set again.
4. **Generated docs** — when `crates/nitr-cli/src/nitr-api.toml` changed:
   `NITR_API_REGEN=1 cargo test -p nitr-cli --test api`
   then commit `resources/nitr-types.lua` and `resources/nitr-api.md`
   with it. Without the variable the same test fails on drift.
5. **Fuzz seams** — when anything under `pub mod fuzzing` or `fuzz/` changed:
   `cd fuzz && RUSTFLAGS="--cfg fuzzing" cargo +nightly check`
   and, for a target you touched,
   `cargo +nightly fuzz run --target x86_64-unknown-linux-gnu <target> -- -max_total_time=60`.
   Never point a run at `fuzz/seeds/<target>`; libFuzzer writes into the
   directory it is given.
6. **Dependencies** — when `Cargo.toml`/`Cargo.lock` changed:
   `cargo deny check` (licenses, advisories, sources; see `deny.toml`).
7. **Live smoke** — build and run what you touched: an example
   (`cargo run --example <name> --features all`, then curl its routes),
   or the CLI flow (`cargo build -p nitr-cli --features all`, then
   `nitr init` → `nitr migrate` → `nitr check` → `nitr test` in a scratch
   directory). Tests do not cover examples; nothing else exercises them.

Then the final adversarial self-review (`security-safety`, `code-quality`).

## Notes

- If the user's cargo config carries nightly-only flags, prefix stable
  commands with `RUSTFLAGS=""` (the `Makefile` already does).
- The first build is slow: mlua vendors Lua 5.4, rusqlite bundles SQLite.
- `cargo fuzz` needs `cargo +nightly` and the explicit `--target`; ASan
  and a musl default target do not mix.
- `target/debug/nitr` is stale until `cargo build -p nitr-cli`; the test
  runner and e2e tests build their own copy.
- `.claude` is a symlink to `.agents`; edit either, it is one tree.
- Port 3000 is often occupied locally; examples take `PORT=<n>`.
