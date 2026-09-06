-- The validated notes API, documented: `input` enforces, `doc` describes,
-- and the document at /openapi.json (with the page at /docs) is generated
-- from both. Nothing in it is written by hand.
local S = nitr.validate
local app = nitr.app()

app:doc({
    title = "Notes",
    version = "1.0.0",
    description = "A small notes API, documented from its own route table.",
    tags = { { name = "notes", description = "Create and read notes" } },
    security = { team = { type = "apiKey", ["in"] = "header", name = "x-team" } },
})

-- A custom format: the `pattern` documents, the `check` enforces.
S.format("note_ref", {
    description = "A note reference: N- followed by up to 8 digits",
    pattern = "^N-[0-9]{1,8}$",
    example = "N-42",
    check = function(s) return s:match("^N%-%d%d?%d?%d?%d?%d?%d?%d?$") ~= nil end,
})

local team = { ["x-team"] = "string|format:alpha_dash|required" }

local NoteInput = S.schema({
    text     = { "string|trim|min_len:1|max_len:500|required|format:printable",
                 description = "The note body; must contain at least one letter",
                 check = function(s) return s:match("%a") ~= nil, "must contain a letter" end },
    tags     = { "array|max_items:5|unique", items = "string|format:slug|max_len:32" },
    color    = "string|format:hex_color|case:lower",
    priority = "integer|min:1|max:5|default:3",
    due      = "string|format:date|after:now",
    refs     = { "array|max_items:10", items = "string|format:note_ref" },
}, { title = "NoteInput" })

-- The response shape is documentation only: responses are never checked.
local Note = S.schema({
    id       = "integer|required",
    text     = "string|required",
    tags     = { "array", items = "string" },
    color    = "string|format:hex_color",
    priority = "integer",
    due      = "string|format:date",
    refs     = { "array", items = "string" },
}, { title = "Note" })

-- A demo store: each Lua state keeps its own table.
local notes, next_id = {}, 1

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
    doc = {
        summary = "List notes", tags = { "notes" }, security = { "team" },
        responses = { [200] = { description = "A page of notes", schema = { type = "array", items = Note } } },
    },
})

app:get("/api/notes/:id", function(req)
    local note = notes[req.valid.params.id]
    if not note then return nitr.error(404, { code = "NOT_FOUND" }) end
    return nitr.json(note)
end, {
    input = { params = { id = "integer|min:1" }, headers = team },
    doc = {
        summary = "Fetch one note", tags = { "notes" }, security = { "team" },
        responses = { [200] = { description = "The note", schema = Note },
                      [404] = { description = "No such note" } },
    },
})

app:post("/api/notes", function(req)
    local data = req.valid.body
    data.id = next_id
    notes[next_id], next_id = data, next_id + 1
    return nitr.json(data, 201)
end, {
    input = { body = NoteInput, headers = team },
    doc = {
        summary = "Create a note", tags = { "notes" }, security = { "team" },
        description = "Creates a note owned by the calling team.",
        responses = { [201] = { description = "Created", schema = Note } },
    },
})

-- Internal: present in the router, absent from the document.
app:get("/internal/metrics", function(req)
    return nitr.json({ notes = #notes })
end, { doc = { hidden = true } })

return app
