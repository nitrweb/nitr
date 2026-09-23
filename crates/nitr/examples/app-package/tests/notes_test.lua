-- Run with: cargo run -p nitr-cli -- -c crates/nitr/examples/app-package/nitr.toml test
local t = nitr.test
local notes = require("lib.notes") -- the app's own module, from its directory

-- Unit: a function that does not take `req` is tested directly.
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

    t.it("refuses a non-table", function()
        t.expect(function() notes.validate("nope") end).to_throw("table expected")
    end)

    t.it("renders a note", function()
        t.expect(notes.render({ id = 7, text = "hi" })).to_equal("#7 hi")
    end)
end)

-- Integration: through the real router and handler, one double of each
-- kind — the database, the clock, the environment, outbound HTTP, logs.
t.describe("notes API (integration)", function()
    local api = t.client({ base = "/api" })
    t.before_each(t.db.reset)

    t.it("serves the static index", function()
        t.expect(t.get("/")).to_have_status(200)
    end)

    t.it("creates and lists", function()
        t.clock.set(1735689600) -- 2025-01-01T00:00:00Z
        t.expect(api:post("/notes", { json = { text = "  hi  " } })).to_have_status(201)
        t.expect(api:get("/notes"):json()).to_match_object({ { text = "hi", created_at = 1735689600 } })
        t.expect(t.get("/notes.txt"):text()).to_equal("#1 hi")
    end)

    t.it("rejects an empty note", function()
        t.expect(api:post("/notes", { json = { text = "" } })).to_have_json({ code = "TEXT_REQUIRED" })
    end)

    t.it("publishes to the webhook once", function()
        t.env.set("APP_WEBHOOK_URL", "https://hooks.example/notes")
        t.fetch.mock({ method = "POST", url = "https://hooks.example/notes", status = 202 })
        t.fetch.strict(true) -- anything else would go to the network: refuse it
        api:post("/notes", { json = { text = "ping" } })
        t.expect(#t.fetch.calls()).to_equal(1)
        t.expect(t.fetch.calls()[1].json.text).to_equal("ping")
        t.expect(t.logs()).to_contain_log({ level = "info", message = "note created" })
    end)
end)

-- A handler in isolation: no middleware, no validation layer, no server.
t.describe("handlers (unit)", function()
    local app = t.app()

    t.it("the create handler refuses an empty note before touching the database", function()
        local create = app:handler("POST", "/api/notes")
        local resp = create(t.fake_request({ method = "POST", json = { text = "" } }))
        t.expect(resp.status).to_equal(422)
    end)
end)
