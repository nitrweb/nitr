-- Runs once at startup; the returned table is snapshotted into every Lua
-- state and reachable from handlers as `nitr.cfg`. The upload root is
-- `[multipart] upload_dir` (set in main.rs), which `part:save` enforces.
return {
    app_name = "standards-example",
}
