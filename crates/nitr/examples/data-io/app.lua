-- Data and outbound I/O, from the Lua side.
--
-- Rust owns the connection pragmas, the migration ledger, the cache memory
-- and its bound, retry and backoff policy, and DNS validation. Lua issues
-- queries and declares intent.

local app = nitr.app()

-- The pragmas a server needs, applied to every state's connection. WAL is
-- the one that matters: without it, two pooled states writing at the same
-- time means one of them gets SQLITE_BUSY.
app:get("/db/pragmas", function(req)
    return nitr.json({
        journal_mode = nitr.db:query_row("PRAGMA journal_mode").journal_mode,
        busy_timeout = nitr.db:query_row("PRAGMA busy_timeout").timeout,
        foreign_keys = nitr.db:query_row("PRAGMA foreign_keys").foreign_keys,
        synchronous  = nitr.db:query_row("PRAGMA synchronous").synchronous,
    })
end)

app:post("/notes", function(req)
    local form = req:form()
    if not form.body then
        return nitr.error(400, { code = "BODY_REQUIRED" })
    end
    nitr.db:execute(
        "INSERT INTO notes (author_id, body) VALUES (?, ?)",
        { tonumber(form.author_id) or 1, form.body }
    )
    return nitr.json({ created = true }, 201)
end)

app:get("/notes", function(req)
    return nitr.json(nitr.db:query([[
        SELECT notes.id, notes.body, authors.name AS author
        FROM notes JOIN authors ON authors.id = notes.author_id
        ORDER BY notes.id DESC LIMIT 50
    ]]))
end)

-- Inside a transaction, use `tx`. Reaching for `nitr.db` instead used to
-- silently join the transaction; now it is an error, because a write meant
-- to be independent would have rolled back with it.
app:post("/notes/bulk", function(req)
    local created = nitr.db:transaction(function(tx)
        tx:execute("INSERT INTO notes (author_id, body) VALUES (1, 'first')")
        tx:execute("INSERT INTO notes (author_id, body) VALUES (2, 'second')")
        return tx:query_row("SELECT COUNT(*) AS n FROM notes").n
    end)
    return nitr.json({ total = created })
end)

app:get("/footgun", function(req)
    local ok, err = pcall(function()
        nitr.db:transaction(function(tx)
            tx:execute("INSERT INTO notes (author_id, body) VALUES (1, 'inside')")
            nitr.db:execute("INSERT INTO notes (author_id, body) VALUES (1, 'escaped')")
        end)
    end)
    return nitr.json({ ok = ok, err = tostring(err) })
end)

-- The shared cache. Entries are plain data, serialized on the way in, so no
-- Lua value crosses between states -- it is shared *data*, not shared
-- *state*. Per-process: a restart empties it, and two Nitr processes have
-- two independent caches, so nothing that must be exact belongs here.
local computations = 0

app:get("/rates", function(req)
    local rates = nitr.cache:remember("rates", { ttl = 30 }, function()
        -- Stand-in for something genuinely expensive. `computations` is
        -- per state, so a low number across many requests is the cache
        -- doing its job.
        computations = computations + 1
        return { usd = 1.0, eur = 0.92, computed_by = req.id }
    end)
    return nitr.json({ rates = rates, computed_in_this_state = computations })
end)

app:get("/cache/stats", function(req)
    return nitr.json(nitr.cache:stats())
end)

-- Outbound calls: opt-in retries on idempotent methods only, with
-- exponential backoff and jitter. A POST is never repeated automatically,
-- whatever the options say -- that is how a customer gets charged twice.
app:get("/upstream", function(req)
    local resp = nitr.fetch("get", nitr.cfg.upstream, {
        timeout = 5,
        retry = { attempts = 3, backoff = "exponential" },
    }):send()
    return nitr.json({ status = resp.status, body = resp:text() })
end)

-- A query and an HTTP call at the same time rather than one after the
-- other. `await_all` accepts a fixed set of Rust-side handles, so this is
-- not a general "run arbitrary Lua concurrently" escape hatch.
app:get("/dashboard", function(req)
    local notes, upstream = nitr.await_all(
        nitr.db:query_async("SELECT COUNT(*) AS n FROM notes", nil, "query_row"),
        nitr.fetch("get", nitr.cfg.upstream, { timeout = 5 })
    )
    return nitr.json({ notes = notes.n, upstream_status = upstream.status })
end)

-- The outbound policy. This example has to reach its own upstream on
-- loopback, so `allow_private_networks` is on and the *allow-list* is what
-- refuses everything else -- including the cloud metadata endpoint.
--
-- With the usual settings (private networks off) the address check is what
-- refuses it, and the guarded DNS resolver is the backstop: a name is
-- resolved once, inside the resolution the connector actually uses, so
-- there is no second lookup for a malicious DNS server to answer
-- differently.
app:get("/ssrf", function(req)
    -- A fixed target: taking it from the query would make this route a
    -- port scanner for whatever the allow-list admits.
    local target = "http://169.254.169.254/latest/meta-data/"
    local ok, err = pcall(function() nitr.fetch("get", target):send() end)
    return nitr.json({ blocked = not ok, err = tostring(err) })
end)

return app
