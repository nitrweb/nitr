-- A tour of the `nitr.*` standard library: the namespace table is the one
-- and only surface Nitr exposes to Lua.

local app = nitr.app()

app:get("/", function(req)
    -- `nitr.json(value)` is the JSON response helper; the same userdata
    -- also carries the codec (`nitr.json:encode` / `nitr.json:decode`).
    return nitr.json({
        namespace = "nitr.*",
        helpers = { "text", "html", "json", "redirect", "status", "negotiate", "sse", "error" },
        library = {
            "log", "crypto", "auth", "fetch", "await_all", "db", "template", "dbg",
            "time", "validate", "csrf", "session", "base64", "path", "url",
        },
    })
end)

-- Crypto primitives: hashing, HMAC, and OS randomness.
app:get("/token", function(req)
    local token = nitr.crypto.sha256(nitr.crypto.random_bytes(32))
    local mac = nitr.crypto.hmac_sha256("server-secret", token)
    return nitr.json({ token = token, mac = mac })
end)

-- Password storage the right way: argon2id hashing and verification are
-- implemented in Rust; Lua only composes them.
app:post("/password", function(req)
    local password = req:text()
    if password == "" then
        return nitr.error(400, { code = "EMPTY_PASSWORD" })
    end
    local hash = nitr.crypto.password_hash(password)
    return nitr.json({
        hash = hash,
        verified = nitr.crypto.password_verify(password, hash),
        rejected = not nitr.crypto.password_verify("wrong-" .. password, hash),
    })
end)

-- Bearer-token middleware built from the `nitr.auth` primitives. The token
-- comparison is constant-time: `==` on secrets leaks timing.
local function require_bearer(next)
    return function(req)
        local token = nitr.auth.bearer(req)
        if not token or not nitr.crypto.constant_time_eq(token, "s3cret") then
            nitr.log.warn("unauthorized", { path = req.path })
            return nitr.error(401, { code = "UNAUTHORIZED" })
        end
        return next(req)
    end
end

app:get("/secure", require_bearer, function(req)
    return nitr.json({ secret = "the pool is warm" })
end)

-- Basic credentials: `nitr.auth.basic(req)` returns `user, pass` or nil.
app:get("/whoami", function(req)
    local user, pass = nitr.auth.basic(req)
    if not user then
        return nitr.error(401, "who are you?")
    end
    return nitr.json({ user = user, password_length = #pass })
end)

-- Safe time without the `os` Lua library: clocks, strftime, HTTP dates.
app:get("/now", function(req)
    local started = nitr.time.monotonic()
    local now = nitr.time.now()
    return nitr.json({
        unix = now,
        iso = nitr.time.iso8601(now),
        http = nitr.time.http(now),
        human = nitr.time.format(now, "%A, %d %B %Y at %H:%M UTC"),
        handler_seconds = nitr.time.monotonic() - started,
    })
end)

-- Declarative validation: the schema compiles once at load time and
-- checks in Rust; undeclared fields never pass through.
local signup = nitr.validate.schema({
    email = { type = "string", format = "email", required = true },
    age = { type = "integer", min = 13, max = 150 },
    interests = { type = "array", items = { type = "string", max_len = 20 }, max_items = 5 },
})

app:post("/signup", function(req)
    local data, err = signup:check(req:json())
    if not data then
        return nitr.error(422, { code = "VALIDATION_FAILED", fields = err.fields })
    end
    return nitr.json({ welcome = data.email })
end)

-- AEAD: hand a client an opaque, tamper-proof value and get it back.
--
-- The key must be the same in every pooled Lua state (a `random_bytes`
-- here would be a different key per state, so a box sealed by one state
-- would not open in another), and the AAD must be something the client
-- presents identically next time: `req.remote_addr` is `ip:port` and the
-- port changes per connection, so only the address is used.
-- `seal` wants exactly 32 key bytes; the digest is 64 hex characters, so
-- half of it is the key (a real application reads a key from `nitr.cfg`).
local VAULT_KEY = nitr.crypto.sha256("stdlib-example-vault-key"):sub(1, 32)
local function client_ip(req)
    return req.remote_addr:match("^(.*):%d+$") or req.remote_addr
end

app:get("/seal", function(req)
    local box = nitr.crypto.seal(VAULT_KEY, "flag{warm-pool}", client_ip(req))
    return nitr.json({ box = box })
end)

app:get("/open", function(req)
    -- The AAD binds the box to this client; another address gets nil.
    local opened = nitr.crypto.open(VAULT_KEY, req.query.box or "", client_ip(req))
    if not opened then
        return nitr.error(400, { code = "TAMPERED_OR_MISSING" })
    end
    return nitr.json({ contents = opened })
end)

-- JWTs, HMAC-only: verify demands an explicit algorithm allow-list and
-- checks `exp`/`nbf` by default.
app:post("/jwt", function(req)
    local token = nitr.crypto.jwt.sign(
        { sub = "ada", exp = nitr.time.now() + 3600 },
        "jwt-demo-secret"
    )
    local claims, why = nitr.crypto.jwt.verify(token, "jwt-demo-secret", {
        algorithms = { "HS256" },
    })
    return nitr.json({ token = token, sub = claims and claims.sub, error = why })
end)

-- Stateless sessions: the whole session travels in a signed cookie.
local SESSION = { secret = "session-demo-secret-0123" }

app:post("/login", function(req)
    local session = nitr.session(req, SESSION)
    session.user = "ada"
    session.visits = (session.visits or 0) + 1
    local resp = nitr.json({ user = session.user, visits = session.visits })
    session:save(resp)
    return resp
end)

app:get("/profile", function(req)
    local session = nitr.session(req, SESSION)
    if not session.user then
        return nitr.error(401, { code = "NO_SESSION" })
    end
    return nitr.json({ user = session.user, visits = session.visits })
end)

-- The pure utilities: base64, lexical paths, URLs.
app:get("/utils", function(req)
    local parsed = nitr.url.parse("https://api.example.com:8443/v1/items?page=2")
    return nitr.json({
        b64 = nitr.base64.encode("hello"),
        b64url = nitr.base64.encode("hello", { url = true }),
        upload_name = nitr.path.basename("C:\\Users\\ada\\report.pdf"),
        safe = nitr.path.normalize("/srv/files/../public/logo.png"),
        host = parsed.host,
        query = nitr.url.query_build({ page = 2, q = "warm pool" }),
    })
end)

return app
