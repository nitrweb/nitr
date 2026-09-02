---
name: code-quality
description: The final self-review checklist for a Nitr change — correctness, tests, docs, duplication, scope, and an honest report. Run it on your own diff before declaring any task done.
---

# Code quality (Nitr)

Done means reviewed, and the reviewer is you, reading the diff as an
adversary first and as the maintainer second. Nothing here is optional.

## Read the diff as an attacker

Follow the `security-safety` procedure on every hunk that touches request
handling, the Lua runtime, the stdlib, files, or configuration. Write down
the input that would break it. If you changed a check, find the input the
old check caught that the new one does not.

## Read the diff as the maintainer

- Every new branch, error path and boundary has a test that fails
  without it (`rust-testing`). "Covered by an existing test" is a claim
  to verify by reading that test's assertions.
- The fix is in the one place the invariant lives. Grep for the existing
  helper (`check_json_bounds`, `safe_join`, `new_hmac`,
  `merge_cookie_opts`, `run_blocking`, `resolve_in`) before adding a
  second copy of a rule; two copies drift.
- Behaviour changes are documented where users read: the doc comment,
  `crates/nitr-cli/src/nitr-api.toml` (then regenerate `resources/`),
  `nitr.toml`'s commented example, `README.md`. A default that changed is
  called out, not implied.
- Comments carry the why. Stale comments are bugs: after `cargo fmt`,
  re-grep every anchor you edited around; reflowed lines hide misses.
- Dead code is denied: remove it, never `#[allow(dead_code)]`. A scoped
  allow of any lint has its reason on the line above.
- No scope creep. Unrelated cleanups go in their own change; a security
  fix diff should read as a security fix.
- Examples and scaffolds are teaching material: an insecure pattern in
  one is a defect, and no test catches it — run it.

## Verify the claims you are about to make

- Run the `verify` ladder; do not extrapolate from a partial run. A
  passing crate does not vouch for the workspace, and `cargo test` stops
  at the first failing binary.
- If you could not verify something (a platform, a proxy, a timing), say
  so in the report rather than describing it as done.
- Smoke-run the binary or example you touched and record what you did.

## The report

- Lead with the outcome. State what was verified and what was not.
- Failing tests are reported as failing, with the output.
- A concern about the task as specified is one sentence, then the work.
- Name the follow-ups you deliberately left, so they are not mistaken for
  oversights.
