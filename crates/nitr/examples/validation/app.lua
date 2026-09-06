-- Route input validation: declare what a route accepts once, get it
-- enforced in Rust before the handler and documented later.
local S = nitr.validate
local app = nitr.app()

-- A custom format: the `pattern` documents, the `check` enforces.
S.format("note_ref", {
    description = "A note reference: N- followed by up to 8 digits",
    pattern = "^N-[0-9]{1,8}$",
    example = "N-42",
    check = function(s) return s:match("^N%-%d%d?%d?%d?%d?%d?%d?%d?$") ~= nil end,
})

-- App-wide message style; per-field `message`/`messages` still win.
S.messages({ summary = "Please fix the highlighted fields" })

local NoteInput = S.schema({
    text     = { "string|trim|min_len:1|max_len:500|required|format:printable",
                 description = "The note body; must contain at least one letter",
                 check = function(s) return s:match("%a") ~= nil, "must contain a letter" end },
    tags     = { "array|max_items:5|unique", items = "string|format:slug|max_len:32" },
    color    = "string|format:hex_color|case:lower",
    priority = "integer|min:1|max:5|default:3",
    due      = "string|format:date|after:now",
    refs     = { "array|max_items:10", items = "string|format:note_ref" },
    meta     = { "map|max_keys:10", keys = "string|format:alpha_dash|max_len:32", values = "string|max_len:200" },
}, { title = "NoteInput" })

-- A demo store: each Lua state keeps its own table, so a note posted on
-- one worker is not listed by another. Real data goes through `nitr.db`.
local notes, next_id = {}, 1
local team ={ ["x-team"] = "string|format:alpha_dash|required" }

app:get("/api/notes", function(req)
    local q = req.valid.query
    local page = {}
    for i = q.offset + 1, math.min(#notes, q.offset + q.limit) do
        page[#page + 1] = notes[i]
    end
    return nitr.json(page)
end, {
    input = {
        query = {
            limit  = "integer|min:1|max:100|default:20",
            offset = "integer|min:0|default:0",
            sort   = "string|one_of:id,priority,due|default:id",
        },
        headers = team,
    },
})

app:get("/api/notes/:id", function(req)
    local note = notes[req.valid.params.id]
    if not note then return nitr.error(404, { code = "NOT_FOUND" }) end
    return nitr.json(note)
end, {
    input = { params = { id = "integer|min:1" }, headers = team },
})

app:post("/api/notes", function(req)
    local data = req.valid.body            -- checked, stripped, trimmed, lowercased color
    data.id = next_id
    notes[next_id], next_id = data, next_id + 1
    return nitr.json(data, 201)
end, {
    input = { body = NoteInput, headers = team },
})

-- The same schema serves an HTML form and an upload: blank optional
-- fields are absent, checkboxes are booleans, `tags[]` is `tags`, and the
-- avatar is judged by its bytes, not its declared type.
local Profile = S.schema({
    name   = "string|trim|min_len:1|max_len:80|required",
    email  = "string|trim|case:lower|format:email|required",
    age    = "integer|min:13|max:120",
    news   = "boolean|default:false",
    tags   = { "array|max_items:5", items = "string|format:slug" },
    avatar = S.image({ max_bytes = "2mb", max_width = 4000 }),
}, { title = "Profile" })

app:post("/profile", function(req)
    local p = req.valid.body
    local saved = p.avatar and p.avatar:save("avatars/" .. req.id .. "-" .. p.avatar.safe_filename)
    return nitr.json({ name = p.name, email = p.email, age = p.age, news = p.news, tags = p.tags,
                       avatar = saved and { path = saved, type = p.avatar.content_type,
                                            width = p.avatar.width, height = p.avatar.height } })
end, {
    input = { body = { schema = Profile, content = { "form", "multipart", "json" } } },
})

app:on_invalid(function(err, req)
    nitr.log.debug("rejected", { path = req.path, fields = err.fields })
    -- JSON for scripts, plain text for a browser form post.
    if req:accepts("application/json", "text/html") == "text/html" then
        local lines = { err.message }
        for _, e in ipairs(err.errors) do lines[#lines + 1] = e.path .. ": " .. e.message end
        return nitr.text(table.concat(lines, "\n"), 422)
    end
    return nitr.error(422, { code = err.code, message = err.message, fields = err.fields, errors = err.errors })
end)

return app
