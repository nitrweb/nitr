-- Secrets are made here, once per build of the pool, and shared by every
-- state through `nitr.cfg`: never a literal in the handler script, which
-- ends up in version control. A real application reads them from the
-- environment (`nitr.env`) or the configuration instead.
local function secret()
    return nitr.crypto.sha256(nitr.crypto.random_bytes(32))
end
return {
    mac_secret = secret(),
    jwt_secret = secret(),
    session_secret = secret(),
}
