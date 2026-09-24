---
name: investigate
description: How to prove a bug, vulnerability, regression or doc/code contradiction in Nitr before claiming it or fixing it — evidence levels, where the intended behaviour is written, reproduction recipes per layer, how to prove a fix, and the finding report format. Use before saying anything is broken, safe, fixed or slow, when triaging a report, and at the start of every bug fix.
---

# Investigate (Nitr)

A finding is a claim plus its proof. Without the proof, it is a question.

## 1. Pin down the intended behaviour

Read what Nitr promises before deciding something is wrong:

- The `README.md` section for the feature.
- The annotated `nitr.toml`.
- The entry in `crates/nitr-cli/src/nitr-api.toml`.
- The doc comment at the code.

Quote the promise, with `file:line`. When the sources disagree with each
other, that disagreement is itself the finding. If nothing documents the
behaviour, ask. Do not invent an intent.

## 2. Evidence levels

Every claim carries exactly one level, stated out loud:

| Level | Means | Proof you record |
|---|---|---|
| **Reproduced** | observed by running code | the test name or command, and the observed output |
| **Traced** | the path from input to outcome was followed in the current tree, with library code read in `~/.cargo/registry/src/` | both sides quoted at `file:line`, and the runtime condition the trace relies on |
| **Unverified** | plausible, not checked | what would settle it |

- A trace that depends on runtime behaviour (hooks, scheduling, a library's
  error path) stays Traced until it is run.
- Library behaviour is read, never recalled: mlua, the vendored Lua C
  sources, rusqlite and SQLite, hyper, reqwest, tokio, minijinja.
- Findings from subagents, reviewers or earlier sessions start as
  Unverified. Re-read the lines and re-run the reproduction.

## 3. Reproduce with the smallest harness on the real path

| The claim is about | Reproduce with |
|---|---|
| a pure function or parser | a unit test in the module |
| a `nitr.*` builtin as Lua sees it | a unit test that builds `mlua::Lua`, calls `register_builtins`, and evaluates the snippet |
| the request path (routing, limits, validation, uploads, headers, errors) | `crates/nitr/tests/` with `harness::TestServer` (a real socket), or `Server::test_client()` (in-process) |
| the runtime budget or sandbox | `crates/nitr-core/src/runtime/tests.rs` with a small `exec_timeout`, wrapped in an outer `tokio::time::timeout` |
| the CLI (`check`, `test`, `migrate`, `build`, `openapi`, `init`) | `crates/nitr-cli/tests/cli.rs` (`Scratch`, `require_runnable_binary!`), or a scratch directory with `target/debug/nitr` after `cargo build -p nitr-cli` |
| a live server (signals, drain, TLS, real headers) | the built binary on a free port, `curl -i`, `kill -<SIG>` |
| robustness over many inputs | a proptest (`prop_*`), or the fuzz target |

Rules:

- **Assert the exact wrong outcome:** the status, message, bytes or count.
  `is_err()`/`is_some()` proves nothing: a wrong-but-safe implementation
  passes it.
- **Bound every run.**
  - A suspected hang is reproduced under a timeout, so it fails instead of
    hanging the suite.
  - A suspected crash is reproduced in a child process or test binary,
    never in a session you need.
- **No fixed sleeps.** Drive time through the seams: `check_at`,
  `nitr_std::clock`, polling a deadline.
- **Keep the repo clean.** Throwaway reproductions go in a scratch
  directory, or are deleted when done. A reproduction that becomes the
  regression test stays.
- **Record the proof.** Write down the command and what it printed. "It
  failed" is not a record.
- **Retry once.** If it does not reproduce, check your setup and try again
  once. Then say "not reproduced" and stop. Do not reshape the claim until
  something matches.

## 4. Trace when a run is not possible yet

- Follow the input through every call, including into vendored library
  code, until you reach the outcome.
- Quote each hop that matters at `file:line`.
- Name what a run would have to confirm, and mark the claim Traced.

## 5. Prove a fix

1. Start from a test that fails for the asserted reason, and read the
   failure message.
2. Apply the fix. The test passes.
3. Sabotage the fix while keeping it compilable (revert one line, or flip
   one condition). The test fails again. Restore the fix.
4. Run the `verify` ladder.

If step 3 cannot make the test fail, the test does not cover the fix.
Rewrite the test.

## 6. Report

For each finding, give:

- **Severity:**
  - High: security, a sandbox or budget escape, data loss, a crash or
    abort, a pinned worker.
  - Medium: wrong behaviour a user will hit.
  - Low: a misleading doc, message or example.
- **The promise:** the contract text, quoted at `file:line`.
- **The behaviour:** the code, quoted at `file:line`.
- **Scenario:** a concrete input and the outcome it produces.
- **Evidence:** the level, and the proof.
- **Minimal fix:** and where it goes (code, `nitr-api.toml` with
  `resources/` regenerated, README, `nitr.toml`, an example).

Lead with the outcome. List what was not verified. Report failing tests as
failing, with their output.

## Anti-patterns

- "Should work", "probably fine", "looks correct": none of these is
  evidence.
- Extrapolating from a partial run: one green crate is not a green
  workspace.
- Treating a reviewer's or subagent's finding as confirmed.
- Quoting a line number you did not re-read.
- Widening a timeout, loosening an assertion or deleting a test to get to
  green.
- Fixing before reproducing. The fix then proves nothing about the bug.
