---
name: security-safety
description: Nitr's safety and security contract — what the sandbox actually enforces and where, the panic policy, the bug shapes that keep recurring, and the adversarial review every change ends with. Use before touching a request path, the Lua runtime, the stdlib, file or network access, and before declaring any change done.
---

# Security and safety (Nitr)

Safety comes first, then security, then performance. A change that weakens
a bound to go faster is refused.

Each rule below names the code that enforces it. Read that code before
relying on the rule: a guarantee you have not seen in the current tree is
an assumption (see `investigate`).

## What the sandbox enforces, and where

`crates/nitr-core/src/runtime/mod.rs` unless noted:

- **Text only.**
  - `load` is wrapped to mode `"t"`.
  - `string.dump` is removed.
  - `require` goes through a confined searcher that loads text only.
  - `package.searchpath` and `package.loadlib` are removed.
  - With `io` off, `dofile` and `loadfile` are removed. With `io` opted in,
    the stock `dofile` and `loadfile` return and accept bytecode (Lua 5.4
    does not verify bytecode).
- **CPU budget.**
  - An instruction-count hook checks a wall-clock deadline.
  - `pcall`, `xpcall`, `coroutine.resume` and `load` (whose reader
    function runs in protected mode) are wrapped to re-raise once the
    deadline has passed.
  - `setmetatable` refuses a `__gc` field: Lua runs finalizers with hooks
    off, out of the budget's reach.
  - An outer tokio timeout covers time spent suspended in I/O.
  - On a timeout, the coroutine is reset and a garbage collection runs, so
    pending futures are dropped at once.
  - Any other way Lua runs code in protected mode, or with hooks off,
    escapes the budget unless you have proven otherwise.
  - Startup (`config.lua` and the handler's top level) runs with no
    deadline.
- **Memory:** the allocator limit set by `[lua] memory_limit`. mlua
  treats `0` as no limit, so startup refuses it.
- **Serialization:** every Lua value that reaches a serializer passes
  `check_json_bounds` or `json_encode` (`crates/nitr-std/src/utils.rs`,
  `bounded.rs`). Deep nesting is a stack overflow, and a stack overflow
  aborts the process.
- **SQL** (`crates/nitr-std/src/db/`):
  - The authorizer denies `ATTACH`/`DETACH`, in their non-literal forms
    too.
  - `max_rows` bounds results.
  - An abandoned transaction is rolled back before the next outer
    statement.
- **Outbound HTTP** (`crates/nitr-std/src/fetch/`):
  - The guarded DNS resolver is the SSRF boundary.
  - Redirects are re-checked on every hop, and credentials are dropped
    when a hop crosses origins.
  - A proxy needs an allow-list.
- **Files:**
  - Static files: the lexical rule in `crates/nitr-http/src/safe_path.rs`,
    then canonical containment. Dotfiles are hidden by default.
  - Uploads resolve under `[multipart] upload_dir`.
- **Cookies, CSRF and sessions:**
  - Cookies are validated against RFC 6265, with `HttpOnly` forced.
  - `Secure` follows `[cookies]`.
  - Signed payloads carry their expiry.
- **Rate limiter** (`crates/nitr-http/src/protect.rs`):
  - When `X-Forwarded-For` is trusted, it keys by the last entry of the
    last line.
  - IPv6 is keyed by /64.
  - The bucket map is capped.

Deliberately not defended, so do not "fix" these: which directories the
operator mounts, `io`/`os` once they are opted in, and the configuration
file itself.

## Panic policy

- `panic = "unwind"` stays: never `abort`.
- A request panic is caught at the handler boundary, and the Lua state is
  rebuilt.
- `overflow-checks` are on in release.
- Recursion is bounded before it starts (depth, node count, input size),
  because no `catch_unwind` contains a stack overflow.
- Range-check a Lua-supplied number before it reaches `Duration`,
  `Instant` arithmetic, `Semaphore::new`, an allocation or
  `httpdate::fmt_http_date`.

## Recurring bug shapes

Check your change against each of these:

- **Check-then-use:** a guard that runs once (at creation, config load or
  first request) while the thing it guards keeps changing.
- **Count vs content:** a limit enforced on what was counted, while fewer
  bytes were actually kept or written. Every limit must fail loudly, never
  truncate silently.
- **Client-controlled names:** a request value (an id, a filename, a
  header) that becomes a path, a key or a directory name. Sanitizing can
  map two values to one, or to the empty string.
- **Destroying existing data on failure:** truncate-then-write, or unlink
  on error, over a file that already existed. Write to a temporary file
  and rename it.
- **Multi-valued inputs:** `HeaderMap::get` returns the first line, and a
  proxy may append another.
- **Literal-only filters:** an authorizer or check that sees the literal
  form but not the bound-parameter, expression or subquery form.
- **Files:** fixed names in shared directories, write-then-chmod, or a
  symlink-following write. Use `create_new`, per-run names, and 0600/0700
  at creation.
- **Secrets** in `Debug` output, logs, error text or the dev error page.
- **A future dropped mid-await** that held a lock, a flag or a
  transaction. Guards must be RAII, and a `Drop` never calls into Lua.
- **Bad defaults:** an unvalidated setting whose zero or empty value
  silently disables a bound.
- **The legitimate-user side:** every fix refuses something. Name the
  valid input it now refuses (a `SameSite=None` form, a `.` path segment,
  an alias directory).

## Adversarial review (last step of every change)

1. **List the attacker's inputs** to the changed code: bytes, headers, Lua
   values, files, config values, timing, concurrency.
2. **Write the bypass before the fix:** the exact input that defeats the
   current code. If you cannot, you do not understand the bug yet.
3. **Attack the fix from the other side:** the alternate encoding, the
   second header line, the non-literal form, a timeout midway, the zero
   or empty value, the legitimate user it now refuses.
4. **Read library behaviour** in the vendored sources.
5. **Prove it** (`investigate`):
   - reproduce the bypass;
   - show the regression test failing without the fix;
   - run the real binary or example for anything on the request path.
6. **Report** each finding with severity, `file:line`, the scenario, the
   evidence level and the minimal fix. Then fix it, test it, and review it
   again.
