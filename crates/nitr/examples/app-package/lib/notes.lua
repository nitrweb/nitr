-- The notes domain without a request in sight: plain functions the
-- routes call and the tests call directly — no server, no database.
local M = {}

M.MAX_TEXT = 500

-- Trims surrounding whitespace.
function M.normalize(text)
    return (text:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- Checks a decoded body: true, or false and an error table. A body that
-- is not a table is a caller bug, not bad input, so it raises.
function M.validate(body)
    if type(body) ~= "table" then
        error("table expected, got " .. type(body), 2)
    end
    if type(body.text) ~= "string" or M.normalize(body.text) == "" then
        return false, { code = "TEXT_REQUIRED" }
    end
    if #body.text > M.MAX_TEXT then
        return false, { code = "TEXT_TOO_LONG" }
    end
    return true
end

-- One note as a line of plain text.
function M.render(note)
    return string.format("#%d %s", note.id, note.text)
end

return M
