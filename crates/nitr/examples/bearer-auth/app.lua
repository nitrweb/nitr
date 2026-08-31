-- Bearer-token authentication, done in the way worth copying.
--
-- Two things here are the point:
--
--   1. the token is compared with `nitr.crypto.constant_time_eq`, never
--      with `==`;
--   2. every failure — no header, wrong scheme, wrong token — answers
--      the same 401 with the same body, so the response says nothing
--      about *why*.
--
-- Honesty about (1): Lua interns short strings, so `==` on two interned
-- strings is a pointer compare and the practical timing leak here is
-- small. The reason to use `constant_time_eq` anyway is that the habit
-- is right — the compare stays constant-time when the token stops being
-- a short Lua literal (read from a file, concatenated, over FFI), and a
-- reader copying this file copies the safe shape.
--
-- The token below is a placeholder minted for this example. A real
-- deployment does not keep it in the handler source: read it from the
-- configuration script (which can read `nitr.env`), so the secret lives
-- in the environment and never in source control.
--
-- Both compared values here are the same length. `constant_time_eq`
-- returns early on a length mismatch — length is not hidden — so a
-- secret whose length varies must be compared as a digest
-- (`sha256(token) == sha256(secret)` via `constant_time_eq`).

local app = nitr.app()

-- Placeholder: `nitr.crypto.random_bytes(32)` hex-encoded, minted once.
local SECRET = "1f8e4c0a6b5d92e37a41c8f0d3b6a95c1e2d4f6a8b0c3e5d7f9a1b3c5d7e9f01"

local function challenge()
    local res = nitr.json({ error = "unauthorized" }, 401)
    res.headers["WWW-Authenticate"] = 'Bearer realm="example"'
    return res
end

app:get("/private", function(req)
    -- `nitr.auth.bearer(req)` returns the token after the scheme match,
    -- or nil for anything unparseable — there is no string parsing to
    -- get wrong here. The compare is the part this example exists for.
    local token = nitr.auth.bearer(req)
    if not token or not nitr.crypto.constant_time_eq(token, SECRET) then
        return challenge()
    end
    return nitr.json({ ok = true })
end)

return app
