local notes = require("lib.notes")
local app = nitr.app()

app:get("/api/notes", function(req)
    return nitr.json(nitr.db:query("SELECT id, text, created_at FROM notes ORDER BY id"))
end)

app:get("/notes.txt", function(req)
    local lines = {}
    for _, note in ipairs(nitr.db:query("SELECT id, text FROM notes ORDER BY id")) do
        lines[#lines + 1] = notes.render(note)
    end
    return nitr.text(table.concat(lines, "\n"))
end)

app:post("/api/notes", function(req)
    local body = req:json()
    local ok, err = notes.validate(body)
    if not ok then
        return nitr.error(422, err)
    end
    local text = notes.normalize(body.text)
    nitr.db:execute(
        "INSERT INTO notes (text, created_at) VALUES (?, ?)",
        { text, nitr.time.now() }
    )
    local note = nitr.db:query_row("SELECT id, text, created_at FROM notes ORDER BY id DESC")
    -- Tell a webhook, when one is configured (APP_WEBHOOK_URL).
    local hook = nitr.env.get("APP_WEBHOOK_URL")
    if hook then
        nitr.fetch("POST", hook, { json = note }):send()
    end
    nitr.log.info("note created", { id = note.id })
    return nitr.json(note, 201)
end)

app:on_error(function(err, req)
    nitr.log.error("handler failed", { error = err.message, kind = err.kind })
    return nitr.error(500, { code = "INTERNAL" })
end)

return app
