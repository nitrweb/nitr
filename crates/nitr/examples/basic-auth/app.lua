-- HTTP Basic authentication, done in the way that does not leak.
--
-- Three things here are the point, and each of them is a mistake that
-- looks fine in review:
--
--   1. the unknown-user branch hashes anyway, so a login form cannot be
--      used to enumerate accounts;
--   2. a stored hash that cannot be verified is *logged as such*, instead
--      of being an unexplained permanent "wrong password".
--
-- What is deliberately NOT here: a password length check on the login
-- path. `password_verify` caps its input itself (1 KiB, before argon2
-- runs) and answers an oversized password with an ordinary `false`, so
-- the naive handler is already safe. Only registration checks the length
-- — to tell the user — against the cap Nitr publishes.
--
-- The hashes below came from `nitr hash-password` — never from a
-- throwaway script, and never from a plaintext column "just for now".

local app = nitr.app()

-- Stands in for `select password_hash from users where email = ?`.
--
--   $ nitr hash-password
--   Password:
--   Confirm password:
--   $argon2id$v=19$m=19456,t=2,p=1$...
local users = {
    -- `nitr hash-password` <<< lovelace
    ada = "$argon2id$v=19$m=19456,t=2,p=1$m9z1df0eQ2iTUMTMdNG9Lg$orLEhw5SZE3dVnKDfo0npcOXvrw/pBGD2eHhFVLFwMo",
    -- `nitr hash-password` <<< hopper
    grace = "$argon2id$v=19$m=19456,t=2,p=1$gecyRVQHlZLmnebHeOdkKQ$Iyo+VZm4UFqefL01MCAKKowh41iEdNrB+N8z+X+FOHk",
    -- A bcrypt row the migration from the old application forgot to
    -- re-hash. Nitr verifies argon2id only, so this account can never log
    -- in — and before `password_verify` returned a reason, the only
    -- symptom was one user insisting their password worked yesterday.
    -- Try it: `curl -u 'linus:torvalds' …` and watch the server log.
    linus = "$2b$12$K3JNi5tR9lHnKKfKzXBDUuJ7dK1nGVX8UEcqfQe5NRaTZY0aWkNSe",
}

local function challenge(status, body)
    local res = nitr.json(body, status)
    -- What makes this Basic auth rather than a bespoke 401: the client
    -- is told which scheme and realm to answer with.
    res.headers["WWW-Authenticate"] = 'Basic realm="example", charset="UTF-8"'
    return res
end

-- The one function worth copying out of this file.
--
-- `nitr.auth.basic(req)` returns `user, pass` (or nothing) after the
-- scheme match, the base64 decode and the split at the first colon —
-- there is no string parsing to get wrong here.
local function authenticate(req)
    local user, pass = nitr.auth.basic(req)
    if not user then
        return nil, "no credentials"
    end

    local stored = users[user]
    local ok, problem
    if stored then
        -- `ok` is what to branch on. `problem` is nil for an ordinary
        -- wrong password and a string when the *stored hash* is the
        -- thing at fault — a bcrypt row, a truncated column, a parameter
        -- set nothing should run.
        ok, problem = nitr.crypto.password_verify(pass, stored)
        if problem then
            -- The server already logged a warning naming the row; this
            -- adds the account it belongs to. The client is told nothing
            -- extra: "your hash is the wrong format" is a fact about the
            -- database, not about whoever is knocking.
            nitr.log.error("a stored credential cannot be verified", {
                user = user,
                problem = problem,
            })
        end
    else
        -- No such user — and this line is the whole reason the example
        -- exists.
        --
        -- Returning here instead would answer an unknown account in
        -- microseconds and a known one in ~26 ms, because only the second
        -- runs argon2. That thousandfold difference is trivially
        -- measurable across a network by someone with no account at all,
        -- so a login form quietly becomes a query interface over the user
        -- list: try an address, time the 401, learn whether it exists.
        --
        -- `password_verify_dummy` hashes the submitted password against a
        -- decoy the process generates from OS entropy, so this branch
        -- costs exactly what the branch above costs and always answers
        -- false.
        ok = nitr.crypto.password_verify_dummy(pass)
    end

    if not ok then
        return nil, "bad credentials"
    end
    return user
end

-- Wraps a handler so the check is on the route rather than inside every
-- handler that must not forget it.
--
-- A plain wrapper rather than an `app:use`-style middleware factory,
-- because the authenticated user has to reach the handler somehow and
-- `req` is Rust-side userdata with read-only fields — there is nowhere on
-- it to stash application state. Passing it as an argument is both
-- simpler and harder to forget.
local function require_login(handler)
    return function(req)
        local user, why = authenticate(req)
        if not user then
            -- Every failure answers the same 401 with the same body.
            -- "unknown user", "wrong password" and "absurdly long
            -- password" are the same thing to the client, in the body
            -- *and* in the time it took.
            nitr.log.warn("login failed", { path = req.path, reason = why })
            return challenge(401, { error = "unauthorized" })
        end
        return handler(req, user)
    end
end

app:get("/", function(req)
    return nitr.json({
        try = {
            "curl -u ada:lovelace localhost:3000/private",
            "curl -u ada:wrong localhost:3000/private",
            "curl -u nobody:wrong localhost:3000/private",
            "curl -u linus:torvalds localhost:3000/private",
        },
    })
end)

app:get(
    "/private",
    require_login(function(req, user)
        return nitr.json({ user = user, secret = "the pool is warm" })
    end)
)

-- Registration, for where the hash comes from when it is not an operator
-- at a terminal. Same function `nitr hash-password` calls.
app:post("/register", function(req)
    local body = nitr.json:decode(req:text() or "") or {}
    if type(body.user) ~= "string" or type(body.password) ~= "string" then
        return nitr.json({ error = "user and password are required" }, 400)
    end
    -- The one place a length check belongs: registration, where the user
    -- is present to be told. `password_hash` raises above the cap (a
    -- credential that cannot be stored must not half-succeed), and this
    -- turns that into the 400 it should be. The cap is Nitr's, read from
    -- Nitr, so it cannot drift.
    if #body.password > nitr.crypto.max_password_bytes then
        return nitr.json({ error = "password too long" }, 400)
    end
    -- An existing account is not overwritten: otherwise anyone could
    -- re-register a known user with a password of their choosing.
    if users[body.user] then
        return nitr.json({ error = "user already exists" }, 409)
    end
    users[body.user] = nitr.crypto.password_hash(body.password)
    -- In-memory, and therefore per pooled Lua state: a real application
    -- writes the hash to the database instead. Nothing else changes.
    return nitr.json({ user = body.user }, 201)
end)

return app
