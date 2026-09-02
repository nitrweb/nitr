---
name: commits
description: Commit message format and commit hygiene for the Nitr repository. Read before writing a commit message or preparing a change for commit.
---

# Commits (Nitr)

Never commit unless asked. When asked, the working tree is green
(`make all`) first.

## Subject

- `type: lowercase imperative summary`, at most 72 characters, no period.
- Types: `fix`, `feat`, `refactor`, `chore`, `docs`, `test`, `perf`.
- A release commit is the bare version (`v0.0.0-beta.3`), no type, no body.
- No scope parentheses unless the change is confined to one tool
  (`chore(ci): …` is fine; `fix(nitr-std/csrf): …` is not — say it in the
  body).

## Body

- Optional for a one-thing change. Required when the diff touches more
  than one area.
- One bullet per area, `- area: what changed`, area being the module or
  crate concern (`db:`, `csrf:`, `runtime:`, `reload:`, `cli:`,
  `examples:`, `docs:`). Lowercase, no trailing period, continuation
  lines indented two spaces.
- Say what changed and, when it is not obvious, why (the attack closed,
  the regression avoided). Not how; the diff shows how.
- No trailers: no `Signed-off-by`, no AI co-author lines, no issue
  references unless the repository tracks one for the change.

## Hygiene

- One logical change per commit. A security fix and an unrelated cleanup
  are two commits.
- Regenerated files travel with their source: a `nitr-api.toml` edit and
  the `resources/` it produces are one commit.
- Generated corpora, temp files, and anything under a per-run directory
  never enter a commit.
- Do not rewrite history the user did not ask to rewrite; do not amend a
  commit you did not just create.

## Example

```
fix: close the review gaps in the sandbox and database layers

- db: deny non-literal ATTACH/DETACH in the SQL authorizer
- db: refuse outer query_async handles inside a transaction
- runtime: remove package.searchpath; nitr test compiles text-only chunks
- rate limit: key by the last entry of the last X-Forwarded-For line
- docs: nitr.toml and regenerated API reference
```
