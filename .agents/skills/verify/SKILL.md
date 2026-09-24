---
name: verify
description: The verification ladder for a Nitr change — format, lint, tests in both feature sets, generated API docs, fuzz seams, dependencies, and a live smoke run — plus how to report which steps ran. Use after any change and before declaring a task done or preparing a commit.
---

# Verify (Nitr)

Run from the repository root, in this order, and stop at the first
failure. A step you skipped is reported as skipped, never as passed.

| # | Step | Command | When |
|---|---|---|---|
| 1 | Format | `cargo fmt --all` | always |
| 2 | Lint | `make lint` | always |
| 3 | Test | `make test` | always |
| 4 | API docs | `NITR_API_REGEN=1 cargo test -p nitr-cli --test api` | `nitr-api.toml` changed |
| 5 | Fuzz | `make fuzz FUZZ_TIME=30` | `pub mod fuzzing`, `fuzz/`, or behaviour a target asserts changed |
| 6 | Dependencies | `cargo deny check` | `Cargo.toml` or a `Cargo.lock` changed |
| 7 | Live smoke | build it and run it | always, for what you touched |

What each step covers:

1. **Format.** After it runs, re-read any comment or anchor you edited:
   rustfmt reflows lines.
2. **Lint.** The format check, clippy with `--features all` and with
   `--no-default-features` (both `--all-targets -- -D warnings`), and
   `fuzz-check` (the target lists and the seed directories agree).
3. **Test.** `cargo test --features all`, then `--no-default-features`,
   then the release-profile `resilience` test.
   - `cargo test` stops at the first failing binary. After a fix, rerun
     the full set.
   - When surveying failures, use `--no-fail-fast`.
4. **API docs.** Regenerates `resources/nitr-types.lua` and
   `resources/nitr-api.md`. They travel in the same commit as the TOML.
   Without the variable, the same test fails on drift.
5. **Fuzz.** Every target, seeded like CI, into the untracked
   `fuzz/corpus/`. It catches a stale oracle before CI does: grep
   `fuzz/fuzz_targets/` for any function whose output you changed. Never
   run a target against `fuzz/seeds/`.
6. **Dependencies.** Licences, advisories and sources (`deny.toml`). An
   advisory in a crate you did not touch is still reported. Fix it in its
   own change.
7. **Live smoke.**
   - An example: `cargo run --example <name> --features all`, then `curl`
     its routes (use `PORT=<n>` when 3000 is taken).
   - The CLI: `cargo build -p nitr-cli --features all`, then `nitr init`,
     `nitr migrate`, `nitr check` and `nitr test` in a scratch directory.
   - The request path: the real binary, and `curl -i`.

After the ladder: the adversarial review (`security-safety`) and the
self-review (`code-quality`).

## Notes

- **Run one cargo job at a time.** Release (fat LTO), bench and fuzz
  builds are memory-heavy. Use `-j2` on small machines.
- **`target/debug/nitr` is stale** until `cargo build -p nitr-cli`. The
  CLI tests build their own copy.
- **The first build is slow:** mlua vendors Lua, and rusqlite bundles
  SQLite.
- **Nightly-only flags:** if a user-level cargo config carries them,
  prefix stable commands with `RUSTFLAGS=""`. The `Makefile` already does.
- **`cargo fuzz`** needs `+nightly` and the explicit `--target`. ASan and
  a musl default target do not mix.

## Reporting

For each step, say it passed, failed (with the output), or was skipped
(with the reason). Test counts beat "all green". A step is never
described as passing on the strength of a different step, or of an
earlier run made before your last edit.
