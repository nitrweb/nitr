# Nitr — read this before any task

Nitr is a Lua-scripted HTTP server in Rust. The workspace crates:

- `nitr-core`: the Lua 5.4 runtime, the sandbox and the state pool.
- `nitr-std`: the `nitr.*` Lua standard library.
- `nitr-http`: the hyper server, configuration and request protection.
- `nitr`: the facade crate.
- `nitr-cli`: the `nitr` binary.

Requests run in a pool of sandboxed Lua states, one request per state at a
time.

## What "correct" means

Nitr's intended behaviour is written down. The code must match it.

- **The contract** is:
  - `README.md`.
  - The annotated `nitr.toml`.
  - `crates/nitr-cli/src/nitr-api.toml`: every `nitr.*` name, option and
    return shape.
  - Doc comments in the code.
- **When code and contract disagree**, one of them is a bug.
  - Decide which with evidence: the tests, the doc comment's stated
    reason, how other callers use it.
  - Fix both in the same change. Never leave them disagreeing.
- **Undocumented behaviour** is not a contract. Do not invent one. Ask, or
  document the actual behaviour as part of the change.

## Trust model

- HTTP clients are hostile. Every byte of a request is attacker-controlled.
- Lua scripts are semi-trusted. They are written by the operator, but they
  must not reach the filesystem, the process, or VM internals beyond what
  the configuration grants. `io` and `os` are opt-in.
- Configuration (`nitr.toml`, the environment) is operator-controlled. It
  is validated at startup: a wrong value is a refused boot with a message
  naming the key.

## Priorities, in order

1. **Safety:** no panic reaches a client, and no abort reaches the process.
2. **Security:** the sandbox and every request-path bound hold.
3. **Performance:** only after 1 and 2, and never traded against them.

## Evidence before claims

This is the rule every other rule rests on. Any statement about behaviour
needs evidence, and you state which level it has. That covers "this is a
bug", "this is safe", "this is slow", "the test covers it" and "it works".

- **Reproduced:** observed by running code. A failing test, or a command
  and its output.
- **Traced:** both sides read in the current tree at `file:line`. Library
  behaviour is read in the vendored source under `~/.cargo/registry/src/`
  (mlua, the Lua C sources, rusqlite, hyper, reqwest, tokio, minijinja),
  never recalled from memory.
- **Unverified:** say so, and say what would settle it.

Never present a traced claim as reproduced, or an unverified one as fact.
Drop a claim that does not reproduce, or report it as not reproduced. Line
numbers drift: re-read a line before quoting it. A finding from another
agent or a reviewer is unverified until you check it yourself.

How to reproduce, trace and report: the `investigate` skill.

## Workspace facts

- Edition 2024, MSRV `1.88.0`.
- Lints live in `[workspace.lints]` of the root `Cargo.toml`. Warnings are
  errors and `unsafe` is forbidden.
- Where tests live:
  - Unit tests: in-module.
  - Integration tests: `crates/nitr/tests/`, using `harness/mod.rs`.
  - CLI end-to-end tests: `crates/nitr-cli/tests/`.
  - Fuzz targets: `fuzz/`. It is excluded from the workspace and needs
    nightly.
- `resources/nitr-types.lua` and `resources/nitr-api.md` are generated from
  `crates/nitr-cli/src/nitr-api.toml`. Edit the TOML, then regenerate.
- Examples (`crates/nitr/examples/`) and the `nitr init` scaffold have no
  tests. Run them after touching them.
- `.claude` is a symlink to `.agents`: one directory, two names.
- Run one cargo build at a time. Release (fat LTO), fuzz and bench builds
  are memory-heavy.

## Non-negotiables

- No `unwrap`/`expect` outside tests. An allowed site carries a comment
  stating the invariant that makes it unreachable.
- No `println!`/`eprintln!` in library crates. Use `tracing`.
- Code explains itself. An inline comment states an invariant, the attack
  a bound closes, or a why the code cannot carry; nothing else. Code that
  needs a comment to be understood gets simplified instead (`rust-style`).
- A bug fix starts from a reproduction. It ships a regression test, and
  you have seen that test fail without the fix.
- Both feature sets stay green: `--features all` and
  `--no-default-features`.
- No CHANGELOG before the first release. Never commit unless asked.
- `fuzz/seeds/` holds curated seeds only. A running corpus never lands
  there.

## Definition of done

1. The `verify` ladder is green, and every step you skipped is named.
2. You have done an adversarial review of your own diff (`security-safety`,
   `code-quality`): attack the change, and look for the regression it
   causes.
3. The code and the contract agree. Docs, `nitr-api.toml` (with
   `resources/` regenerated) and examples are updated in the same change.
4. The commit message follows `commits`.
5. The report gives the outcome first, then what was verified and how,
   what was not, and failing tests as failing.

## Skills (`.agents/skills/<name>/SKILL.md`)

- `investigate`: proving a bug, vulnerability or contradiction. Evidence
  levels, reproduction recipes and the report format.
- `security-safety`: the sandbox contract, the panic policy, recurring bug
  shapes, and the adversarial review.
- `lua-api`: anything a script can call or read. The contract rules, the
  mlua and Lua conversion traps, and bounds on script input.
- `rust-style`: errors, async, API shape, comments and diagnostics.
- `rust-testing`: which test goes where, regression tests, proptest, fuzz,
  and the feature matrix.
- `code-quality`: the final self-review checklist.
- `performance`: measure first, the hot-path rules, and the bounds that
  exist by design.
- `verify`: the command ladder.
- `commits`: message format and hygiene.
