---
name: security-safety
description: Nitr's safety and security contract — the sandbox boundaries, the panic policy, the adversarial review procedure every change ends with, and the bug shapes that recur. Read before touching a request path, the Lua runtime, the stdlib, or before declaring any change done.
---

# Security and safety (Nitr)

Safety first, security second, performance third. A change that weakens a
bound to go faster is refused. Verify every claim below in the code before
relying on it; the files named are where the invariant lives.

## The sandbox contract (what is enforced, where)

- Lua loads text only: `load` is wrapped, `string.dump` removed, `require`
  uses a confined searcher, `package.searchpath`/`loadlib` are gone —
  Lua 5.4 does not verify bytecode (`crates/nitr-core/src/runtime/mod.rs`).
- CPU budget: an instruction hook with a wall-clock deadline; `pcall`,
  `xpcall` and `coroutine.resume` re-raise once it has passed, so a budget
  error cannot be caught in a loop. Memory: the allocator limit.
- Timeouts reset and collect the coroutine so pending futures (a SQLite
  transaction, a fetch) are dropped now, not at a later GC.
- Every Lua value that reaches a serializer passes `check_json_bounds`
  (`crates/nitr-std/src/utils.rs`): deep nesting is a stack overflow,
  which is an abort, which no `catch_unwind` can contain.
- SQL: a statement authorizer denies `ATTACH`/`DETACH` including the
  non-literal forms (`crates/nitr-std/src/db/pragmas.rs`); `max_rows`
  bounds results; an abandoned transaction is rolled back before the next
  outer statement (`db/mod.rs`).
- Outbound HTTP: the DNS resolver wired into the client is the SSRF
  boundary (`crates/nitr-std/src/fetch/policy.rs`); redirects re-check per
  hop and drop credentials across origins; a proxy needs an allow-list.
- Static files: lexical rule in `crates/nitr-http/src/safe_path.rs`, then
  canonical containment; dotfiles hidden by default.
- Cookies/CSRF/sessions: RFC 6265 validation, `HttpOnly` forced, `Secure`
  from `[cookies]`, signed payloads carry their expiry.
- Rate limiter keys by the last entry of the last `X-Forwarded-For` line
  only when trusted; IPv6 by /64; bucket map capped.

What is deliberately not defended: which directories the operator mounts,
`io`/`os` when opted in, the configuration file itself. Do not "fix" those.

## Panic policy

- `panic = "unwind"` stays; a request panic is caught per request and the
  Lua state rebuilt. Never set abort. `overflow-checks` are on in release.
- A stack overflow is an abort: bound recursion *before* the recursion
  (depth, node count, input size). Recursive Lua-to-Rust conversion is
  the usual place.
- Lua-supplied numbers reach `Instant + Duration`, `Duration::from_secs_f64`,
  `httpdate::fmt_http_date`, `Semaphore::new`, allocations: range-check
  first, clamp or refuse with a message.

## Recurring bug shapes (check for each)

- Check-then-use: a guard that runs once (at creation, at first request,
  at config load) while the thing it guards changes later.
- Multi-valued headers: `HeaderMap::get` returns the first line; proxies
  may append a second one.
- Literal-only checks: an authorizer or filter that sees the literal form
  but not the bound-parameter, expression or subquery form.
- Fixed names in shared directories, write-then-chmod, symlink-following
  `fs::write`: use `create_new`, 0700/0600 at creation, per-run names.
- Secrets in `Debug`, logs, error text, or the dev error page.
- A future dropped mid-await: what did it hold (a lock, a flag, a
  transaction)? Guards must be RAII, and their `Drop` must not call into
  Lua.
- A fix that breaks a legitimate flow (a `SameSite=None` form, a `.`
  segment, an alias directory). Every fix has a false-positive side.

## Adversarial review procedure

Required for any change on a request path or in the runtime, and as the
final self-review of every change before it is declared done:

1. List the attacker's inputs to the changed code: bytes, headers, Lua
   values, files, timing, concurrency.
2. Write the bypass before the fix: the exact input that defeats the
   current code. If you cannot, you do not understand the bug yet.
3. Attack the fix from the other side: the alternate encoding, the second
   header line, the non-literal form, the timeout mid-way, the legitimate
   user it now refuses.
4. Trace library behaviour in the vendored sources; do not assume what
   mlua, rusqlite, hyper or reqwest do.
5. Run the real thing: build the binary or example and drive it with
   curl; a unit test that passes is not the same as a server that holds.
6. Report each finding with severity, `file:line`, the concrete scenario
   (input → outcome), and the minimal fix. Then fix, test, and re-review.
