-- Runs exactly once at startup; the returned table becomes nitr.cfg.
-- The database connection arrives as the script's vararg.
local db = ...

db:execute([[CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL
)]])

return { app_name = "notes" }
