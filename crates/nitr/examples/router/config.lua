-- Runs once at startup; the returned table is snapshotted into every Lua
-- state as `nitr.cfg`. Secrets belong here (or in the environment via
-- `nitr.env`), never as literals in the handler script. These values are
-- placeholders for the example — change them.
return {
    -- Signs the /login cookie (16 bytes minimum).
    secret = "router-example-cookie-secret",
    -- The bearer token /admin expects: `-H 'authorization: Bearer ...'`.
    api_token = "router-example-token",
}
