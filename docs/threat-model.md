# Threat model

Nitr's pitch is *semi-trusted logic with explicit boundaries*: application
Lua is assumed to be buggy, not hostile — but the sandbox is built so that
most classes of hostile script fail anyway. This document states, in one
place, where those boundaries actually are. The honest version is more
useful than a reassuring one.

## What the sandbox defends against

| Threat | Defense |
| --- | --- |
| CPU exhaustion (`while true do end`) | Per-request execution budget enforced by an instruction-count hook installed globally on the state — user coroutines inherit it — plus an async timeout for slow I/O. |
| Memory exhaustion | Per-state Lua memory limit (default 8 MiB); a state that hits it is poisoned, dropped, and rebuilt — it never serves another request. |
| Filesystem / process access from Lua | `io` and `os` are excluded from the stdlib by default (and nothing in `nitr.*` needs them: `nitr.time` covers dates, `nitr.path` is lexical only); native Lua modules cannot be loaded; `require` is confined to the handler script's directory. |
| Request-smuggling-sized inputs | Rust-enforced limits before Lua runs: URI, header, body (counted as it arrives, not trusted from `Content-Length`), form parts/field/file sizes, connection cap, per-IP rate limit. |
| SSRF from `nitr.fetch` | Private/loopback/link-local/CGNAT ranges refused by default; the filtering happens inside the resolver the connector actually uses (DNS rebinding does not bypass it); every redirect hop is re-checked; per-request outbound budget. |
| Path traversal out of static mounts | Percent-decode → component whitelist → canonicalize-prefix check (symlinks included); `nitr.path.normalize` cannot be climbed with `..`. Both are fuzzed: `static_resolve` asserts every path the static server returns is inside the canonicalized mount, and `path_lexical` asserts the lexical invariants. |
| Cross-state data leakage | Pooled states share nothing Lua-visible; the shared cache and config snapshot carry plain serialized data only, never live Lua values. |
| Forged cookies / sessions / tokens | HMAC-SHA256 signatures with constant-time verification, cookie names bound into the MAC; JWT verification requires an explicit algorithm allow-list and structurally cannot accept `alg: none`. |
| A wedged or draining instance receiving traffic | Rust-owned `/readyz` flips before requests can fail; an application cannot report itself healthy through a broken handler. |
| Damaged states after a panic or memory hit | Per-request `catch_unwind`; poisoned states are recycled, not reused. |

## What it does not defend against

- **A malicious Rust extension module.** `ServerBuilder::module` code is
  unsandboxed by design — it is your process. The boundary is for Lua.
- **OS-level resource exhaustion**: file descriptors, disk space, kernel
  memory. Run Nitr under a supervisor with OS limits (see
  [deploy/](../deploy/) for hardened systemd settings).
- **Side channels between states** (timing, cache effects) and inference
  from shared-cache hit patterns.
- **A Lua VM escape** via a vulnerability in Lua 5.4 or mlua. The sandbox
  narrows the attack surface (no `io`/`os`/native loading); it does not
  patch the VM.
- **Denial of service by a legitimate key**: the rate limiter is
  per-client-IP and fixed-window; a distributed attacker or one behind a
  shared NAT is bounded only by the connection and pool limits.

## Known weaker-than-it-should-be

Tracked deliberately rather than glossed over:

- The **rate limiter is a fixed window**, so bursts at a window boundary
  can briefly double the intended rate (parked for a sliding-window
  revisit; see the design set's "Parked" list).
- **Sessions cannot be invalidated server-side** before their cookie
  expires — that is the documented cost of stateless sessions; rotating
  the secret invalidates everything at once.
- **No metrics endpoint** yet, so abuse is visible in logs but not on a
  dashboard (parked with phase 5).

## Reporting

Security reports: open a private advisory on the repository rather than a
public issue.
