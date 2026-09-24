-- Extension modules appear on the same namespace as the builtins: the
-- application cannot tell `nitr.ext.kv` (this repository's Rust code) from
-- `nitr.json` (a builtin). That is the whole point of the boundary.

local app = nitr.app()

app:use(function(next)
    return function(req)
        -- The counter lives in Rust and is shared by every pooled state,
        -- so it keeps counting no matter which worker serves the request.
        nitr.ext.kv.add("requests")
        return next(req)
    end
end)

app:get("/inventory/:item", function(req)
    return nitr.json({
        item = req.params.item,
        count = nitr.ext.kv.get(req.params.item),
        requests_served = nitr.ext.kv.get("requests"),
    })
end)

app:put("/inventory/:item", function(req)
    local delta = tonumber(req:text())
    if not delta then
        return nitr.error(400, { code = "NOT_A_NUMBER" })
    end
    -- The module refuses an overflow with an ordinary Lua error.
    local ok, count = pcall(nitr.ext.kv.add, req.params.item, delta)
    if not ok then
        return nitr.error(422, { code = "OUT_OF_RANGE" })
    end
    nitr.log.info("inventory updated", { item = req.params.item, count = count })
    return nitr.json({ item = req.params.item, count = count })
end)

app:get("/slugify", function(req)
    local title = req.query.title
    if not title then
        return nitr.error(400, { code = "MISSING_TITLE" })
    end
    return nitr.json({ title = title, slug = nitr.ext.slug.slugify(title) })
end)

return app
