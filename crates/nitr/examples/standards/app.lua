-- HTTP standards completeness, from the Lua side.
--
-- Notice how little there is here: ranges, compression, CORS preflights,
-- form decoding, multipart parsing and the conditional-request comparison
-- all happen in Rust. What is left is the part only the application knows.

local app = nitr.app()

-- A dynamic response large enough to be worth compressing. Nothing here
-- asks for compression: the server negotiates it from Accept-Encoding.
app:get("/api/report", function(req)
    local rows = {}
    for i = 1, 200 do
        rows[i] = { id = i, label = "row " .. i, status = "ok" }
    end
    return nitr.json({ generated_at = req.id, rows = rows })
end)

-- `application/x-www-form-urlencoded`. Percent-decoding and `+`-as-space
-- are HTTP details worth exactly one careful implementation.
app:post("/api/subscribe", function(req)
    local form = req:form()
    if not form.email then
        return nitr.error(400, { code = "EMAIL_REQUIRED" })
    end
    return nitr.json({ subscribed = form.email, plan = form.plan or "free" })
end)

-- A file upload. Parts arrive one at a time, in the order the client sent
-- them, and `part:save()` streams socket → disk in Rust: a 100 MB file
-- never touches this state's 8 MiB heap.
app:post("/api/upload", function(req)
    local fields, files = {}, {}
    req:multipart(function(part)
        if part.filename then
            -- `part.filename` is whatever the client sent — a path, a
            -- traversal, control characters. `part.safe_filename` is that
            -- name reduced to a plain file name, and `part:save` resolves
            -- it inside `[multipart] upload_dir` either way, so neither
            -- the sanitizing nor the containment is this script's job.
            local name = part.safe_filename
            files[#files + 1] = { name = name, size = part:save(name) }
        else
            fields[part.name] = part:text()
        end
    end)
    return nitr.json({ fields = fields, files = files })
end)

-- Conditional requests for a dynamic resource. Rust compares the
-- validators; Lua decides what identifies the resource, because that is
-- application knowledge -- here a revision, in a real app a row version or
-- an updated_at.
local ARTICLE = {
    revision = 7,
    body = "Nitr serves the boring parts of HTTP so your handlers do not have to.",
}

app:get("/api/article", function(req)
    local etag = nitr.etag(ARTICLE.revision)
    if req:fresh(etag) then
        -- A 304 carries no body; sending one anyway is refused by the
        -- server, because a client that believes the status would read
        -- those bytes as the next response.
        local res = nitr.status(304)
        res.headers.ETag = etag
        return res
    end
    local res = nitr.text(ARTICLE.body)
    res.headers.ETag = etag
    res.headers["Cache-Control"] = "no-cache"
    return res
end)

-- Only GET and POST are registered, yet HEAD and OPTIONS both work:
-- HEAD reuses this handler and drops the body, and OPTIONS is answered
-- with `Allow` without reaching Lua at all.
app:get("/api/notes", function(req)
    return nitr.json({ notes = { "first", "second" } })
end)

app:post("/api/notes", function(req)
    return nitr.json({ created = true }, 201)
end)

return app
