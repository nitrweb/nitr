<div>
  <div align="center">
    <a href="https://nitrweb.com" title="Nitr website">
      <img src="https://avatars.githubusercontent.com/u/321541693?s=400&u=9bbbe39f0ffbcea9c39acf23f005f930d0dfc084&v=4" height="100" width="100"
    /></a>
  </div>

<h1 align="center">Nitr</h1>

<h4 align="center">
    A Rust web server embedding <a href="https://www.lua.org/" title="Lua">Lua</a> for fast, efficient and safe lightweight dynamic backends.
  </h4>

<div align="center">
    <a href="https://github.com/nitrweb/nitr/actions/workflows/devel.yml" title="devel ci"><img src="https://github.com/nitrweb/nitr/actions/workflows/devel.yml/badge.svg?branch=master"></a> 
    <a href="https://app.codspeed.io/nitrweb/nitr?utm_source=badge" title="CodSpeed performance benchmarks"><img src="https://img.shields.io/endpoint?url=https://codspeed.io/badge.json" alt="CodSpeed"/></a> 
    
  </div>
</div>

> [!NOTE]
> Nitr is in **early development** and not ready for production use yet. Feel free to try it out and contribute.

## Overview

Nitr serves HTTP requests with Lua 5.4 scripts. An application is two files: an optional `config.lua` that runs **once per build** of the Lua pool (at startup and on every reload), and an `app.lua` that builds the application (routes and middleware) once per Lua state. The server keeps a fixed pool of independent Lua states (one per CPU core by default), so requests execute in parallel without locking, and every script runs under configurable safety limits (restricted stdlib, memory cap, execution timeout).

Everything Nitr exposes to Lua lives on one global namespace table, `nitr` — `nitr.app()`, `nitr.json`, `nitr.db`, `nitr.crypto`, and so on. Nitr registers no other globals, so scripts never collide with the Lua standard library, and your own Rust extensions mount on the same namespace under `nitr.ext.*` — separated from the standard library, so nothing Nitr ships can ever collide with your modules.

Nitr is both a **binary** (`nitr`, configured via `nitr.toml`) and a **library crate** (embed the server and register your own Rust modules as `nitr.*` APIs).

## Features

- **Pool of Lua states over a multi-thread runtime:** one request per state, no global locks, natural backpressure.
- **Safety by default**: `io`/`os` excluded from the stdlib (opt-in), 8 MiB memory limit per state, 30 s execution budget enforced by an instruction-count hook (stops `while true do end`; `__gc` finalizers, which would run outside it, are refused) plus an async timeout, `require` confined to the scripts directory, no native Lua modules.
- **One namespaced standard library:** `nitr.json`, `nitr.fetch` (HTTP client with SSRF policy, opt-in retries and a per-request outbound budget), `nitr.template` (minijinja), `nitr.db` (SQLite in WAL mode, runs off the async threads), `nitr.cache` (bounded, shared across states), `nitr.log`, `nitr.crypto`/`nitr.auth`, `nitr.dbg`.
- **Data you can deploy:** SQLite with WAL, a busy timeout and foreign keys on by default; plain-SQL migrations applied by `nitr migrate` and a server that refuses to start with a pending one.
- **Rust-side routing (`nitr.app()`):** path parameters, middleware chains composed once at load, per-app error handler, 404/405 answered without entering Lua.
- **HTTP correctness:** binary-safe request/response bodies, multi-value headers (`Set-Cookie`), parsed query strings, `HEAD`/`OPTIONS` answered without a route, conditional requests, graceful shutdown, no Lua tracebacks leaked to clients (unless dev mode).
- **The rest of HTTP, in Rust:** range requests (`206`/`416`, `If-Range`), response compression (brotli/gzip plus precompressed `.br`/`.gz` sidecars), CORS policy with preflights answered before Lua runs, `req:form()` for urlencoded bodies, and `req:multipart()` uploads that stream to disk without ever entering the Lua heap.
- **TLS without a proxy in front:** three lines of `[tls]` terminate HTTPS in-process with rustls (`ring` provider, TLS 1.2 floor, ALPN pinned to what the server actually speaks). The certificate and key are read once at startup, so a broken or mismatched pair refuses to boot rather than failing every handshake; the handshake itself runs in the connection's own task, so a stalled `ClientHello` costs one connection and not the accept loop.
- **Easy configuration:** `nitr.toml` configuration with `NITR_*` environment overrides and CLI flags; unknown keys, contradictions, and missing paths refuse to start, and `nitr check --print-config` prints the effective result of the layering.
- **Operable:** Rust-owned `/healthz` + `/readyz` probes (readiness flips before a drain can fail a request, optionally on a separate port), JSON log output (`[log] format = "json"`), pidfile + `nitr reload` for scripted zero-downtime reloads, and reference [systemd/Docker deployments](deploy/).
- **One-file deploys:** `nitr build --output myapp` appends the whole application (config, Lua, templates, static files, migrations) to the binary — copy one executable; the database stays external.
- **Dev mode (`--dev`)**: instant hot reload (a `notify` watcher rebuilds on save — scripts, `routes/`, templates) and error details in responses.
- **Editor completion for everything:** `nitr init` writes generated LuaCATS type definitions (`nitr-types.lua`) covering the whole `nitr.*` surface — completion, signatures and inline docs in any editor with the Lua Language Server. Generated from the same [single API description](resources/nitr-api.md) as the reference docs; a test fails if an undocumented builtin ships.
- **A test framework worth using:** `nitr test` runs unit tests of plain modules, integration tests through the real router with a cookie-keeping client, and handlers in isolation with a fake request. Every test gets its own budget, duration, captured logs and fresh doubles — canned `nitr.fetch` responses, a movable clock, environment overrides — and database fixtures reset what a test wrote (`t.db.reset`, `t.db.isolate`). A failed request shows its status, body and the handler's error; `--bail`, `--list`, `--watch` and JUnit/JSON reports are built in. See [Testing](#testing).
- **Extensible:** `ServerBuilder::module("name", ...)` mounts a Rust table at `nitr.ext.name` in every Lua state — user modules live under `nitr.ext.*`, one level below the std, so no future builtin can ever collide with them, third-party extension crates need no fork.

## Cargo features

Optional builtins are Cargo features, so a build only carries the
dependencies it uses. Nothing is enabled by default in the **library**; the
`nitr` **binary** enables `all`, because someone installing a server expects
every builtin to be there.

| Feature | Enables | Heaviest dependency |
| --- | --- | --- |
| `fetch` | `nitr.fetch`, `nitr.await_all` | `reqwest` |
| `db` | `nitr.db`, migrations, `nitr migrate` | `rusqlite` (bundles SQLite) |
| `template` | `nitr.template` | `minijinja` |
| `crypto` | `nitr.crypto`, `nitr.auth` | `argon2` |
| `compression` | on-the-fly brotli/gzip responses | `brotli`, `flate2` |
| `multipart` | `req:multipart(fn)` file uploads | `multer` |
| `tls` | inbound TLS termination (`[tls]`) | `rustls` (the `ring` provider) |
| `openapi` | the OpenAPI document (`[openapi]`, `nitr openapi`) | — (pure `cfg`) |
| `swagger` | the Swagger UI page (`[swagger]`), vendored, no CDN; implies `openapi` | — (≈1.7 MiB of assets) |
| `all` | every feature above | — |

`json`, `http`, `log`, `cache`, `dbg`, `time`, `validate`, `base64`,
`path` and `url` are always compiled in: they need nothing the server does
not already depend on, so gating them would save nothing. Precompressed `.br`/`.gz` sidecars are also served without the
`compression` feature — serving an already-compressed file needs no encoder.

```sh
cargo add nitr                                   # minimal
cargo add nitr --features db,template            # plus SQLite and templates
cargo add nitr --features all                    # everything
```

Configuring a builtin that was not compiled in is a startup error naming the
feature to enable, rather than a mysterious "unknown std feature".

## Quick start (binary)

```sh
cargo run
```

With no configuration, Nitr listens on `127.0.0.1:3000` and executes `scripts/handler.lua`. Add a `nitr.toml` to change anything (see [Configuration](#configuration)). `nitr init` scaffolds a complete application; `nitr check` validates it, `nitr test` runs its Lua tests in-process, and `nitr openapi` prints its OpenAPI document (`--check` is a CI drift gate, `--ui DIR` writes a static Swagger UI site).

### The handler script

Returns the application built with `nitr.app()`. The script runs once per Lua state; routes and middleware are compiled at load time, and only matching requests reach Lua:

```lua
-- scripts/handler.lua
local app = nitr.app()

-- Middleware wraps the next handler; composed once, not per request.
app:use(function(next)
    return function(req)
        nitr.log.info("request", { path = req.path })
        return next(req)
    end
end)

app:get("/users/:id", function(req)
    return nitr.json({
        message = "Hello, Nitr!",
        id = req.params.id,                  -- path parameter
        name = req.query.name,               -- parsed query string
        served_since = nitr.cfg.started_at,  -- data from config.lua
    })
end)

app:on_error(function(err, req)
    return nitr.error(500, { code = "INTERNAL" })
end)

return app
```

### The configuration script (optional)

Runs **once per build** of the Lua pool: at startup, before requests are served, and again on every reload (`SIGHUP`, `nitr reload`, and each save in dev mode). Keep it idempotent (`CREATE TABLE IF NOT EXISTS`, not a bare `INSERT`); the returned table is available to handlers as `nitr.cfg`. It must return plain data (tables, strings, numbers, booleans) — it is snapshotted and shared with every Lua state. The database connection arrives as the script's vararg.

```lua
-- scripts/config.lua
local db = ...
db:execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
return { started_at = nitr.time.iso8601(nitr.time.now()) }
```

## Lua API

Every Nitr API is a field of the global `nitr` table; nothing else is registered.

### Application (`nitr.app()`)

| Method | Description |
| --- | --- |
| `app:get/post/put/delete/patch/head/options(path, ...fns)` | Register a route; `:name` captures a parameter, a trailing `*` captures the rest. All but the last function are route middleware |
| `app:use(fn)` | Global middleware, `function(next) return function(req) ... end end`; must precede routes |
| `app:on_error(fn)` | `function(err, req)` — the app-wide error response |
| `app:doc({ title, version, description, tags, security, ... })` | Document-level information for the generated OpenAPI document (once per app) |
| `app:get(path, handler, { doc = {...} })` | Describes the operation in the document: `summary`, `description`, `tags`, `operation_id`, `responses = { [201] = { description, schema } }` (documentation only), `security`, `deprecated`, `hidden`. Request schemas stay under `input`, which both enforces and documents them |
| `app:on_invalid(fn)` | `function(err, req)` — the app-wide answer when a route's `input` fails (default: a JSON 422 with `fields` and `errors`) |
| `app:post(path, handler, { input = {...} })` | Validated input: `body` (JSON or form; `{ schema = S, content = { "multipart" } }` for uploads with `file` rules, `{ file = R, content = { "raw" } }` for a single-file body), `query`, `params`, `headers` — checked in Rust before the handler, coerced from text, exposed as `req.valid.{body,query,params,headers}` |
| `app:static(mount, dir, opts?)` | Serve files from Rust (`{ spa = true, cache_control = "..." }`) |
| `nitr.cfg` | The configuration script's snapshot |

### Request (`req`)

| Field / method | Description |
| --- | --- |
| `req.method`, `req.path`, `req.remote_addr` | Strings |
| `req.query` | Table of percent-decoded query parameters |
| `req.headers` | Table of request headers |
| `req.uri` | Table: `scheme`, `host`, `port`, `path`, `query`, `authority` |
| `req.params` | Table of path parameters |
| `req.id` | Request id (UUIDv7, echoed as `X-Request-ID`) |
| `req.cookies` | `req.cookies.name`, `req.cookies:verify(name, secret)` |
| `req:text()`, `req:json()`, `req:form()`, `req:read(n?)`, `req:accepts(...)` | Body as string, decoded JSON, urlencoded form table, bounded chunks; content negotiation |
| `req:multipart(fn)` | Uploads: `fn(part)` per part, with `part:save(path)` streaming to disk without entering the Lua heap |
| `req:fresh(etag, last_modified?)` | Whether the client's cached copy is current (`If-None-Match` / `If-Modified-Since`) |

### Response (returned table)

`status` (number, default 200), `headers` (value: string, integer, or array of strings), `body` (string; binary-safe, or a function for a streaming body). The helpers below build these tables for you.

| Helper | Description |
| --- | --- |
| `nitr.json(v, status?)` | JSON response; `resp.cookies:set(...)` / `:set_signed(...)` attach cookies |
| `nitr.text(s, status?)`, `nitr.html(s, status?)` | Plain-text / HTML responses |
| `nitr.redirect(location, status?)`, `nitr.status(code)` | Redirects and bare status responses |
| `nitr.error(code, body?)` | Error response; a table body is rendered as JSON |
| `nitr.negotiate(req, offers)` | Content negotiation over the `Accept` header (406 when nothing matches) |
| `nitr.etag(value, weak?)` | A validator for a dynamic response, to pair with `req:fresh()` |
| `nitr.sse(fn)` | Server-Sent Events stream; `fn(send)` calls `send(event, data)` |

### Standard library

The `nitr.*` standard library provides building blocks — enable the features you need via `[std] features` in `nitr.toml` (default: the minimal `json`, `http`, `log`, `time`, `validate`, `base64`, `path`, `url` set), or replace them with your own modules:

| Module | Description |
| --- | --- |
| `nitr.json:encode(v)` / `nitr.json:decode(s)` | JSON codec (serde); callable as the response helper above |
| `nitr.fetch(method, url, opts?)` → `client:send()` | HTTP client (shared pool, timeouts, SSRF policy with a guarded resolver, per-hop redirect checks, opt-in `retry = { attempts, backoff }` on idempotent methods, per-request outbound budget). Response: `.status`, `.headers`, `.raw_headers`, `.url`, `:text()`, `:json()`, `:read()` |
| `nitr.cache:get/set/delete/clear/remember/stats` | Bounded TTL+LRU cache shared by every state. Entries are plain data, so no Lua value crosses between states; per-process, so not a session store |
| `nitr.await_all(h1, h2, ...)` | Run several `fetch` (or `query_async`) handles concurrently, capped by `fetch.max_concurrent` |
| `nitr.template:render(name, data?)` | minijinja templates from `[templating] dir` |
| `nitr.db:execute/query/query_row/query_one(sql, params?)` | SQLite (`database` file); queries run on a blocking thread pool with a prepared-statement cache |
| `nitr.db:transaction(fn)` | Atomic transaction (nestable via savepoints); rolls back on error. Use the `tx` handle inside the body — the outer `nitr.db` refuses to run while a transaction is open, rather than silently joining it |
| `nitr.db:query_async(sql, params?, kind?)` | An unsent query, so `nitr.await_all` can run it alongside a `fetch` instead of in series |
| `nitr.log.debug/info/warn/error(msg, fields?)` | Structured logging into the request span |
| `nitr.crypto.*` | `sha256`, `hmac_sha256`, `random_bytes`, `constant_time_eq`, `password_hash`/`password_verify` (argon2id), `seal`/`open` (XChaCha20-Poly1305 AEAD) |
| `nitr.crypto.jwt.sign/verify` | HMAC JWTs; `verify` requires an explicit `algorithms` allow-list and checks `exp`/`nbf` by default |
| `nitr.auth.basic(req)` / `nitr.auth.bearer(req)` | Parse `Authorization` credentials |
| `nitr.time.*` | `now`, `monotonic`, strftime `format`/`parse` (UTC), `http`/`parse_http`, `iso8601` — so scripts never need the `os` Lua library for a date |
| `nitr.validate.schema({...})` → `schema:check(v)` | Declarative validation compiled once, checked in Rust: 9 types, 36 formats, shorthand rules (`"string\|trim\|min_len:1\|required"`), custom formats/checks, cross-field rules, per-field messages with placeholders; `:partial/:pick/:omit/:extend` derivations. Declared on a route as `input = {...}` it runs before the handler (see below) |
| `nitr.csrf({ secret })` / `nitr.csrf.token(req)` | CSRF middleware (signed double-submit cookie, constant-time, unsafe methods only) |
| `nitr.session(req, { secret })` | Stateless signed-cookie session: assign fields, `session:save(resp)`, `session:clear()` |
| `nitr.base64.encode/decode` | Base64, standard and URL-safe (`{ url = true }`) alphabets |
| `nitr.path.*` | Lexical path ops (`join`, `basename`, `dirname`, `extension`, `normalize`, `is_absolute`) for POSIX and Windows styles; no filesystem access |
| `nitr.url.*` | `encode`/`decode` (percent-encoding), `query_parse`/`query_build`, lexical `parse` |
| `nitr.dbg(value)` | Debug-print a Lua value to the log |

## Configuration

`nitr.toml` (see the [annotated example](nitr.toml)), overridable via `NITR_*` env vars and CLI flags (`--config <path>`, `--dev`). Precedence: flags > env > file > defaults.

```toml
listen = "127.0.0.1:3000"
handler_script = "scripts/handler.lua"
config_script = "scripts/config.lua"    # optional
workers = 4                             # Lua states; default: CPU cores
dev_mode = false                        # hot reload + error details

[database]
path = "scripts/file.db"                # enables `nitr.db`

[templating]
dir = "scripts/templates"               # enables `nitr.template`

[openapi]                               # needs the `openapi` Cargo feature; off by default
enabled = true                          # serve the generated document at `path`
path = "/openapi.json"
servers = ["https://api.example.com"]
output = "openapi.json"                 # dev mode: rewritten when the document changes

[swagger]                               # needs the `swagger` Cargo feature; off by default
enabled = true                          # the vendored Swagger UI page at `path`
path = "/docs"
try_it_out = true

[tls]                                   # needs the `tls` Cargo feature
enabled = true
cert = "/etc/nitr/tls/fullchain.pem"    # leaf first, then intermediates
key = "/etc/nitr/tls/privkey.pem"       # PKCS#8, PKCS#1 or SEC1
# min_version = "1.2"                   # "1.2" (default) or "1.3"

[std]
# `nitr.*` standard library features; default: ["json", "http", "log",
# "time", "validate", "base64", "path", "url"]
features = ["dbg", "fetch", "template", "json", "db", "http", "log", "crypto"]

[lua]
stdlib = ["math", "table", "string", "utf8", "coroutine", "package"]  # "io"/"os" are opt-in
memory_limit = 8388608                  # bytes, per state
exec_timeout_ms = 30000                 # 0 disables the execution budget

[testing]                               # `nitr test`
dir = "tests"                           # *.lua test files (not recursive)
# database = "test.db"                  # recreated each run; default: a private file per run
seed = "tests/fixtures/seed.sql"        # applied after the migrations
capture = true                          # logs shown under a failed test only
slow_ms = 1000                          # tests slower than this are marked `slow`
```

## Testing

`nitr test` runs the `*.lua` files in `[testing] dir` against an in-process server — the real router, middleware, validation and handlers, on a fresh private database file with the migrations applied (never `[database] path`; `[testing] database` names a file to keep instead). Files and tests run one after another; each file gets a fresh Lua state.

```lua
-- tests/notes_test.lua
local t = nitr.test
local notes = require("lib.notes")        -- the app's own module (resolved from the app directory)
local fixtures = require("helpers.notes") -- tests/helpers/notes.lua: a helper, never run as a test

t.describe("lib.notes (unit)", function()
    t.it("normalizes text", function()
        t.expect(notes.normalize("  hi  ")).to_equal("hi")
    end)
    t.each({ { "", "TEXT_REQUIRED" }, { ("x"):rep(501), "TEXT_TOO_LONG" } })
    ("rejects %q with %s", function(text, code)
        local ok, err = notes.validate({ text = text })
        t.expect(ok).to_be_false()
        t.expect(err.code).to_equal(code)
    end)
end)

t.describe("notes API (integration)", function()
    local api = t.client({ base = "/api", cookies = true })
    t.before_each(t.db.reset)

    t.it("creates and lists", function()
        t.expect(api:post("/notes", { json = fixtures.note })).to_have_status(201)
        t.expect(api:get("/notes"):json()).to_match_object({ { text = "hi" } })
    end)

    t.it("publishes to the webhook once", function()
        t.fetch.mock({ method = "POST", url = "https://hooks.example/notes", status = 202 })
        api:post("/notes", { json = { text = "ping" } })
        t.expect(t.fetch.calls()[1].json.text).to_equal("ping")
    end)
end)
```

The rule of thumb: *if a function does not take `req`, unit test it; if it does, go through `t.request`.* What a test file has, under `nitr.test` (all of it absent from every state that serves requests):

- **Structure.** `describe`/`it`, hooks scoped to their `describe` (`before_each`/`after_each`, `before_all`/`after_all`), `skip`, `todo`, `only` (the run fails while one is left in place), `each` for table-driven cases, `fail`. A throw inside a `describe` body fails that group and the file carries on. Each test runs under its own `[lua] exec_timeout_ms` budget, so one `while true do end` fails one test.
- **Matchers.** `to_equal`, `to_match_object` (a subset, recursively), `to_throw`, `to_be_false`, `to_be_a`, `to_have_length`, the comparisons, `to_have_key`, the `to_not_*` negatives — and for responses `to_have_status`, `to_have_header`, `to_have_json`, whose failure shows a body excerpt and the handler's error.
- **The client.** `t.request(method, path, opts)` and `t.get`/`post`/…: `query`, `cookies`, `auth`, one of `json`/`form`/`multipart`/`body`, `remote_addr` (the peer the rate limiter sees), `timeout`. The response has `status`, `headers`, `raw_headers` (every line, in order), `cookies` (parsed), `body`, `:json()`, `:sse()`, and `error` — the handler's classified error when it raised, without `--dev`. `t.client({ cookies = true })` keeps a jar across calls.
- **Doubles, as data.** A test's state and the server's states are separate Lua universes, so nothing is monkey-patched: `t.fetch.mock` answers `nitr.fetch` in the handlers (before the `[fetch]` policy, which unmatched requests still meet; `t.fetch.strict()` refuses them), `t.clock.set/advance` moves `nitr.time`, sessions, JWT expiry, cache TTLs and the rate limiter (never the execution budget), `t.env.set` overrides `nitr.env` under the `[env]` policy, and `t.logs()` returns the test's captured log entries. All of them reset before every test.
- **Database fixtures.** Every state owns its SQLite connection, so a test cannot wrap a handler in a transaction; instead `t.db.reset()` restores the database as it was after the migrations and `[testing] seed`, `t.db.truncate()` empties tables, `t.db.seed("fixtures/x.sql" | { table = rows })` loads data, `t.db.isolate()` resets after every test of the file.
- **Unit tools.** `t.fake_request({...})` builds a real request object (sessions, CSRF and `nitr.auth` accept it) without protection, body limits or validation; `t.app()` loads the application into the test state for `app:handler(method, path)`, `app:dispatch(...)` (router and middleware only) and `app:routes()`; `t.session_cookie(data, { secret })` forges what `session:save` would write. `schema:check(v)` runs route validation rules outside a route. `nitr.cfg` is the handler's configuration snapshot.

```sh
nitr test --filter checkout --bail                       # the red one, stop at the first failure
nitr test --list                                         # every test with its file:line, nothing run
nitr test --watch                                        # re-run on every saved Lua file or template
nitr test --reporter junit --output target/junit.xml     # CI annotations (also --reporter json)
nitr test --nocapture                                    # stream log lines instead of capturing them
```

The complete reference is `nitr.test` in [resources/nitr-api.md](resources/nitr-api.md).

## Library usage

```rust
use nitr::{Builtins, Server};

#[tokio::main]
async fn main() -> nitr::Result {
    Server::builder()
        .listen(([127, 0, 0, 1], 3000).into())
        .handler_script("scripts/handler.lua")
        .builtins(Builtins::JSON | Builtins::FETCH)
        // Expose your own Rust code as `nitr.ext.greet` in every Lua state:
        .module("greet", |lua| {
            let t = lua.create_table()?;
            t.set("hello", lua.create_function(|_, name: String| {
                Ok(format!("Hello, {name}!"))
            })?)?;
            Ok(t)
        })
        .build()
        .await?
        .serve() // SIGTERM/ctrl-c drains gracefully; see serve_with_shutdown()
        .await
}
```

Modules are the extension boundary: the closure runs once per pooled state (and on every reload), mounting at `nitr.ext.<name>` — separate from the standard library, so no builtin can ever collide with a user module — and two modules sharing a name fail at build time. See [examples/extension](crates/nitr/examples/extension) for a stateful module shared across states, and [examples/stdlib](crates/nitr/examples/stdlib) for a tour of `nitr.*`.

For lower-level embedding, `nitr::Runtime` exposes the Lua state, `register_module()`, script loading, and the budgeted `call_function()` directly — no HTTP involved. Errors are a typed `nitr::Error` enum.

## Documentation

Current references: the [`nitr.*` API](resources/nitr-api.md) (generated), the [error-handling guide](docs/errors.md), the [passwords and Basic auth guide](docs/passwords.md), the [stability policy](docs/stability.md) and the [threat model](docs/threat-model.md). The original proposal documents are archived in [.docs/](.docs/).

## Benchmarks

Benchmarks live in [crates/nitr/benches](crates/nitr/benches) and are written with [divan](https://github.com/nvzqz/divan), through the CodSpeed compatibility layer. Three targets, all dispatching through the same in-process client `nitr test` uses:

| Target | What it measures |
| --- | --- |
| `runtime` | Sandboxed state creation, script compilation, one call into Lua, server startup |
| `dispatch` | Route matching, path parameters, middleware, 404/405, JSON in and out, response compression |
| `stdlib` | The `nitr.*` builtins: json, base64, url, path, time, validate, cache, cookies, crypto, template, db |

```sh
cargo bench --features all                  # locally, wall-clock
cargo bench --features all --bench dispatch # one target
```

Every push and pull request runs them on [CodSpeed](https://app.codspeed.io/joseluisq/nitr) under CPU simulation, so a regression shows up as a diff on the pull request instead of as a surprise in production.

## Fuzzing

The parsers an attacker fully controls are fuzzed with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz): signed cookies and
the `Cookie` header, `Accept` and `Accept-Encoding` negotiation,
conditional-request headers, `Range` headers, multipart bodies, the
JSON-Lua boundary and its depth guard, lexical paths, static path
resolution (the traversal defense), URL and query splitting, JWT
verification, the declarative validators, and the TLS certificate/key PEM
the server loads at startup from whatever an ACME client or a mounted
secret wrote.

Targets assert behavior, not just absence of crashes — round-trips,
idempotence, tamper rejection, and the bounds a caller depends on (a
served static path is always inside its mount; an accepted byte range
always lies inside the representation).

```sh
make fuzz               # every target, bounded time, seeded like CI
make fuzz FUZZ_TIME=300 # longer
```

Needs a nightly toolchain and `cargo install cargo-fuzz`, which is why it
is not part of `make all`. Every pull request runs 90 seconds per target;
a nightly job runs an hour per target, where the depth actually comes
from. Seeds are committed under [fuzz/seeds](fuzz/seeds) — see its README
for the input format each target decodes, and how to check that a seed
reaches the code it was written for.

## Name origins

*Niter* or *nitre* is the mineral form of potassium nitrate, KNO3. It is a soft, white, highly soluble mineral found primarily in arid climates or cave deposits.
> https://en.wikipedia.org/wiki/Niter

## Contributions

Unless you explicitly state otherwise, any contribution you intentionally submitted for inclusion in current work, as defined in the Apache-2.0 license, shall be dual licensed as described below, without any additional terms or conditions.

Feel free to submit a [pull request](https://github.com/nitrweb/nitr/pulls) or file an [issue](https://github.com/nitrweb/nitr/issues).

## Third-party notices

The `swagger` feature embeds [Swagger UI](https://github.com/swagger-api/swagger-ui)
(© SmartBear Software, Apache License 2.0) from the `swagger-ui-dist` npm
package, pinned and checksum-verified by `crates/nitr-http/assets/swagger-ui/update.sh`;
its licence text ships beside it.

## License

This work is primarily distributed under the terms of both the [MIT license](LICENSE-MIT) and the [Apache License (Version 2.0)](LICENSE-APACHE).

© 2024-present [Jose Quintana](https://joseluisq.net)
