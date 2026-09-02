-- API aggregation with nitr.await_all + atomic updates with transactions.

local app = nitr.app()

-- Two "upstream" APIs (in real life: other services).
app:get("/api/profile", function(req)
    return nitr.json({ user = "ada", plan = "pro" })
end)

app:get("/api/stats", function(req)
    return nitr.json({ visits = 42, likes = 7 })
end)

-- The BFF endpoint: both upstreams are fetched concurrently; total wall
-- time is the slower of the two, not their sum. nitr.fetch(...) builds an
-- unsent request handle; nitr.await_all sends them together.
app:get("/dashboard", function(req)
    -- The upstream base comes from configuration, never from the request:
    -- `req.headers.host` is whatever the client sent, and building a fetch
    -- target from it turns this handler into an open proxy for any address
    -- the server can reach.
    local base = nitr.ext.example.upstream
    local profile, stats = nitr.await_all(
        nitr.fetch("GET", base .. "/api/profile"),
        nitr.fetch("GET", base .. "/api/stats", { timeout = 5 })
    )
    return nitr.json({
        app = nitr.cfg.app_name,
        profile = profile:json(),
        stats = stats:json(),
    })
end)

app:get("/accounts", function(req)
    return nitr.json(nitr.db:query("SELECT name, balance FROM accounts ORDER BY name"))
end)

-- Atomic transfer: both UPDATEs commit together or not at all. The
-- balance check inside the transaction raises to trigger the rollback.
app:post("/transfer", function(req)
    local from, to = req.query.from, req.query.to
    local amount = tonumber(req.query.amount) or 0
    -- A negative amount would move money the other way.
    if amount <= 0 or from == to then
        return nitr.error(400, { code = "INVALID_TRANSFER" })
    end

    local reason
    local ok = pcall(function()
        nitr.db:transaction(function(tx)
            tx:execute("UPDATE accounts SET balance = balance - ? WHERE name = ?", { amount, from })
            local row = tx:query_row("SELECT balance FROM accounts WHERE name = ?", { from })
            if row.balance < 0 then
                reason = "insufficient funds"
                error(reason)
            end
            tx:execute("UPDATE accounts SET balance = balance + ? WHERE name = ?", { amount, to })
        end)
    end)

    if not ok then
        return nitr.error(409, { code = "TRANSFER_FAILED", reason = reason or "internal" })
    end
    nitr.log.info("transfer done", { from = from, to = to, amount = amount })
    return nitr.json({ ok = true })
end)

app:on_error(function(err, req)
    nitr.log.error("handler failed", { error = err, path = req.path })
    return nitr.error(500, { code = "INTERNAL" })
end)

return app
