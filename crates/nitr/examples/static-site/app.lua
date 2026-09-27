-- Static mounts are declared by the app and served entirely in Rust;
-- only /api/* requests below ever reach Lua.

-- A relative directory is resolved against this script's directory.
local app = nitr.app()

-- The whole site at /, plus a long-cache mount for fingerprinted assets.
app:static("/", "public")
app:static("/assets", "public/assets", {
    cache_control = "public, max-age=31536000, immutable",
})

app:get("/api/time", function(req)
    return nitr.json({ now = nitr.time.now() })
end)

return app
