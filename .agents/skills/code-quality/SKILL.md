---
name: code-quality
description: The final self-review of a Nitr change — read the diff as an attacker, then as the maintainer, check that code and contract agree, verify every claim in the report. Use on your own diff before declaring any task done.
---

# Code quality (Nitr)

Done means reviewed, and the reviewer is you. Read the diff as an attacker
first and as the maintainer second. Nothing here is optional.

## As an attacker

Follow the `security-safety` adversarial review for every hunk that
touches request handling, the Lua runtime, the stdlib, files or
configuration.

- Write down the input that would break the change.
- If you changed a check, find the input the old check caught that the
  new one does not.
- Find the legitimate input the new check now refuses.

## As the maintainer

- **Tests prove the change.** Every new branch, error path and boundary
  has a test you saw fail without it (`rust-testing`). "Covered by an
  existing test" is a claim: open that test and point at the assertion.
- **Code and contract agree.** Anything that changes behaviour updates, in
  the same diff:
  - the doc comment;
  - `crates/nitr-cli/src/nitr-api.toml`, with `resources/` regenerated;
  - the annotated `nitr.toml`;
  - `README.md`;
  - any example that shows the behaviour.

  A changed default is called out, not implied.
- **Messages tell the truth.** An error that suggests a remedy was checked:
  the remedy works.
- **One home per invariant.** No second copy of a rule that already has a
  helper.
- **The code reads without its comments.** Cover each `//` comment in the
  diff and ask whether the code still makes sense. If it does, the comment
  goes; if it does not, simplify the code first (`rust-style`,
  "Comments"). Then re-read the comments around every edit after
  `cargo fmt`.
- **No dead code, no unexplained `#[allow]`.**
- **No scope creep.** An unrelated cleanup is a separate change, and a
  security fix reads as one.
- **Examples and the scaffold are teaching material.** An insecure
  pattern there is a defect, and no test catches it: run them.

## Before you write the report

- **Run the `verify` ladder.** Do not extrapolate from a partial run: a
  green crate does not vouch for the workspace.
- **Every claim in the report has its evidence level** (`investigate`).
  Name what you could not verify: a platform, a proxy, a timing, a step
  you skipped.
- **Smoke-run what you touched,** and say what you ran.

## The report

- **Lead with the outcome.** Then say what was verified and how, and what
  was not.
- **Report failing tests as failing,** with their output.
- **Raise a concern about the task as specified in one sentence,** then
  do the work.
- **Name the follow-ups you deliberately left,** so they are not mistaken
  for oversights.
