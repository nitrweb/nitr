# Nitr — read this before any task

Nitr is a Lua-scripted HTTP server in Rust: `nitr-core` (Lua 5.4 runtime,
sandbox, state pool), `nitr-std` (the `nitr.*` Lua stdlib), `nitr-http`
(hyper server, config, protection), `nitr` (facade), `nitr-cli` (the
`nitr` binary). Scripts run in a pool of sandboxed Lua states, one request
per state at a time.

## Trust model

- HTTP clients are hostile. Every byte of a request is attacker-controlled.
- Lua scripts are semi-trusted: operator-written, but they must never
  reach the filesystem, the process, or the VM internals beyond what the
  configuration grants (`io`/`os` are opt-in; bytecode never loads).
- Configuration (`nitr.toml`, env) is operator-controlled and validated at
  startup; a wrong value is a refused boot with a message naming the key.

## Priorities, in order

1. **Safety** — no panic reaches a client; no abort reaches the process.
2. **Security** — the sandbox and every request-path bound hold.
3. **Performance** — only after 1 and 2; never traded against them.

## Verify, never guess

Before writing code: read the code path, the test that covers it, and the
doc comment or `README.md` line that promises the behaviour. Library
behaviour (mlua, rusqlite, hyper, minijinja, reqwest) is checked in the
vendored sources under `~/.cargo/registry/src/`, not recalled from memory.
A rule you cannot point at in the code is an assumption; say so.

## Workspace facts

- Edition 2024, MSRV `1.88.0`, lint policy in `[workspace.lints]` of the
  root `Cargo.toml`; `unsafe` is forbidden, warnings are errors.
- Unit tests live in-module; integration tests in `crates/nitr/tests/`
  (use `harness/mod.rs`); CLI end-to-end in `crates/nitr-cli/tests/`;
  fuzz targets in `fuzz/` (excluded from the workspace, nightly only).
- `.claude` is a symlink to `.agents`: one directory, two names.
- `resources/nitr-types.lua` and `resources/nitr-api.md` are generated
  from `crates/nitr-cli/src/nitr-api.toml`; edit the TOML, regenerate.
- Examples in `crates/nitr/examples/` are not covered by tests.

## Non-negotiables

- No `unwrap`/`expect` outside tests; an allowed site carries a comment
  stating the invariant that makes it unreachable.
- No `println!`/`eprintln!` in library code — `tracing` only.
- Every bug fix ships a regression test that fails without the fix.
- Both feature sets stay green: `--features all` and
  `--no-default-features`.
- No CHANGELOG before the first release. Never commit unless asked.
- `fuzz/seeds/` holds curated seeds only; a running corpus never lands
  there.

## Definition of done

1. The `verify` ladder is green (format, lint, tests, feature matrix).
2. A **final adversarial review of your own diff** (`security-safety`
   procedure, `code-quality` checklist): attack the change, look for the
   regression it causes, verify the test proves the fix.
3. A commit message per `commits`.
4. Report faithfully: what was verified, what was not, failing tests as
   failing.

## Skills (`.agents/skills/<name>/SKILL.md`)

- `rust-style` — errors, async, API and comment conventions, Lua-side rules.
- `rust-testing` — which test kind where; proptest, fuzz, integration,
  regression, feature matrix, clippy.
- `security-safety` — the sandbox contract, the adversarial review
  procedure, panic policy, secrets and files.
- `code-quality` — the final self-review checklist.
- `commits` — message format.
- `performance` — measure first, hot-path rules, what is bounded by design.
- `verify` — the command ladder to run before declaring anything done.
