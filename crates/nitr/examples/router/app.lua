-- A small application showing the nitr.app() programming model:
-- Rust-side routing, Lua middleware, response helpers, and cookies.

-- Secrets come from configuration (`nitr.cfg`, filled by config.lua),
-- never literals in the handler.
local SECRET = nitr.cfg.secret
local API_TOKEN = nitr.cfg.api_token

local app = nitr.app()

-- Global middleware runs for every routed request, in registration order.
app:use(function(next)
    return function(req)
        local res = next(req)
        res.headers = res.headers or {}
        res.headers["X-Powered-By"] = "nitr"
        return res
    end
end)

-- A per-route middleware: short-circuits without calling the handler.
-- The token is compared in constant time — `==` on a credential leaks
-- how many leading bytes matched.
local function auth(next)
    return function(req)
        local token = nitr.auth.bearer(req)
        if not token or not nitr.crypto.constant_time_eq(token, API_TOKEN) then
            return nitr.error(401, "Unauthorized")
        end
        return next(req)
    end
end

app:get("/", function(req)
    return nitr.html("<h1>Hello from nitr.app()</h1>")
end)

-- Path parameters are captured by the Rust router.
app:get("/users/:id", function(req)
    return nitr.json({ id = req.params.id })
end)

app:post("/users", function(req)
    local body = req:json()
    return nitr.json({ created = true, name = body.name }, 201)
end)

app:get("/admin", auth, function(req)
    return nitr.text("welcome, admin")
end)

-- Signed cookies: /login sets one, /whoami verifies it.
app:get("/login", function(req)
    local res = nitr.redirect("/whoami")
    res.cookies:set_signed("session", "user-42", SECRET, {
        http_only = true,
        same_site = "Lax",
        max_age = 3600,
    })
    return res
end)

app:get("/whoami", function(req)
    local user = req.cookies:verify("session", SECRET)
    if not user then
        return nitr.error(401, { code = "NO_SESSION" })
    end
    return nitr.json({ user = user })
end)

-- Content negotiation: one route serving JSON and HTML clients.
app:get("/data", function(req)
    return nitr.negotiate(req, {
        ["application/json"] = function(r)
            return nitr.json({ hello = "world" })
        end,
        ["text/html"] = function(r)
            return nitr.html("<p>hello world</p>")
        end,
    })
end)

-- Streaming (writer callback): chunks reach the client as they are
-- written; the writer suspends while the client is slow (backpressure).
app:get("/download", function(req)
    return {
        status = 200,
        headers = { ["Content-Type"] = "text/csv" },
        body = function(writer)
            writer:write("id,name\n")
            for i = 1, 5 do
                writer:write(string.format("%d,user-%d\n", i, i))
            end
        end,
    }
end)

-- Streaming (iterator): a coroutine yields one chunk per call.
app:get("/chunks", function(req)
    return {
        body = coroutine.wrap(function()
            for i = 1, 3 do
                coroutine.yield("chunk " .. i .. "\n")
            end
        end),
    }
end)

-- Server-Sent Events: send(event, data) formats the SSE wire protocol;
-- tables are JSON-encoded automatically.
app:get("/events", function(req)
    return nitr.sse(function(send)
        for i = 1, 3 do
            send("tick", { count = i })
        end
        send("done", "bye")
    end)
end)

app:on_error(function(err, req)
    nitr.log.error("handler failed", { error = err, path = req.path })
    return nitr.error(500, { code = "INTERNAL", path = req.path })
end)

return app
