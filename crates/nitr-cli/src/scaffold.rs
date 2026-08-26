// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr init`: scaffolds a new application, matching the documented
//! package layout. The scaffold is many users' first and most-copied
//! example, so it demonstrates the patterns worth copying — middleware,
//! validation, `on_error`, a migration, a test — rather than the smallest
//! thing that runs. `--minimal` gives the four-file version.
//!
//! Route files are wired with explicit `require` in `app.lua` (no
//! auto-discovery): the application's shape stays visible in one file,
//! and a route module is plain Lua rather than magic.

use std::path::Path;

use anyhow::{Context as _, bail};

pub fn init(dir: &Path, minimal: bool) -> anyhow::Result<()> {
    let types = crate::apidef::emit_types(&crate::apidef::parse()?);
    let mut files: Vec<(&str, String)> = if minimal {
        vec![
            ("nitr.toml", MINIMAL_NITR_TOML.into()),
            ("app.lua", MINIMAL_APP_LUA.into()),
            ("public/index.html", INDEX_HTML.into()),
            ("tests/app_test.lua", MINIMAL_TEST_LUA.into()),
        ]
    } else {
        vec![
            ("nitr.toml", NITR_TOML.into()),
            ("config.lua", CONFIG_LUA.into()),
            ("app.lua", APP_LUA.into()),
            ("routes/notes.lua", ROUTES_NOTES_LUA.into()),
            ("migrations/001_init.sql", MIGRATION_SQL.into()),
            ("templates/hello.j2", TEMPLATE_J2.into()),
            ("public/index.html", INDEX_HTML.into()),
            ("tests/notes_test.lua", TEST_LUA.into()),
            (".gitignore", GITIGNORE.into()),
            ("data/.gitkeep", String::new()),
        ]
    };
    // Editor completion for the whole `nitr.*` surface, generated from
    // the same source as the documentation.
    files.push(("nitr-types.lua", types));

    for (rel, _) in &files {
        if dir.join(rel).exists() {
            bail!("refusing to overwrite existing {}", dir.join(rel).display());
        }
    }
    for (rel, content) in &files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        std::fs::write(&path, content)
            .with_context(|| format!("cannot write {}", path.display()))?;
        println!("created {}", path.display());
    }
    match minimal {
        true => println!("\nNext steps:\n  nitr check\n  nitr test\n  nitr dev"),
        false => println!("\nNext steps:\n  nitr migrate\n  nitr check\n  nitr test\n  nitr dev"),
    }
    Ok(())
}

const NITR_TOML: &str = r#"# Nitr application configuration.
# Reference: https://github.com/nitrweb/nitr (see the annotated nitr.toml)
listen = "127.0.0.1:3000"
handler_script = "app.lua"
config_script = "config.lua"

# SQLite: WAL, busy timeout and foreign keys are on by default. The data/
# directory holds mutable state and stays out of version control.
[database]
path = "data/app.db"

# Where `nitr.template` loads its minijinja templates from.
[templating]
dir = "templates"

[std]
features = ["json", "http", "log", "time", "validate", "base64", "path", "url", "db", "template"]

# Static files are served from this directory, before Lua runs.
[static]
dir = "public"
mount = "/"
"#;

const CONFIG_LUA: &str = r#"-- Runs once at startup; the returned table is snapshotted into every
-- state and exposed to handlers as `nitr.cfg`.
return {
    app_name = "my-app",
    started_at = nitr.time.iso8601(nitr.time.now()),
}
"#;

const APP_LUA: &str = r#"local app = nitr.app()

-- App-wide middleware: a factory `fn(next) -> fn(req)`, composed once at
-- load time. Must come before the routes.
app:use(function(next)
    return function(req)
        local started = nitr.time.monotonic()
        local resp = next(req)
        nitr.log.info("request", {
            path = req.path,
            status = type(resp) == "table" and resp.status or 200,
            ms = math.floor((nitr.time.monotonic() - started) * 1000),
        })
        return resp
    end
end)

-- Routes live in their own files; wiring them here keeps the app's shape
-- visible in one place.
require("routes.notes")(app)

app:get("/hello/:name", function(req)
    return nitr.html(nitr.template:render("hello.j2", {
        name = req.params.name,
        app = nitr.cfg.app_name,
    }))
end)

-- The app-wide error handler receives the structured error: kind
-- ("lua"|"nitr"|"module"|"timeout"|"memory"|"panic"), message, source,
-- line, traceback, cause.
app:on_error(function(err, req)
    nitr.log.error("handler failed", {
        error = err.message, kind = err.kind, source = err.source, line = err.line,
    })
    return nitr.error(500, { code = "INTERNAL" })
end)

return app
"#;

const ROUTES_NOTES_LUA: &str = r#"-- The notes API: a route module is a plain function taking the app.
local schema = nitr.validate.schema({
    text = { type = "string", min_len = 1, max_len = 500, required = true },
})

return function(app)
    app:get("/api/notes", function(req)
        return nitr.json(nitr.db:query("SELECT id, text, created_at FROM notes ORDER BY id"))
    end)

    app:post("/api/notes", function(req)
        local data, err = schema:check(req:json())
        if not data then
            return nitr.error(422, { code = "VALIDATION_FAILED", fields = err.fields })
        end
        nitr.db:execute(
            "INSERT INTO notes (text, created_at) VALUES (?, ?)",
            { data.text, nitr.time.now() }
        )
        local note = nitr.db:query_row("SELECT id, text, created_at FROM notes ORDER BY id DESC")
        return nitr.json(note, 201)
    end)
end
"#;

const MIGRATION_SQL: &str = r#"-- Applied by `nitr migrate`; the server refuses to start while a
-- migration is pending. Never edit an applied migration — write a new one.
CREATE TABLE notes (
    id         INTEGER PRIMARY KEY,
    text       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"#;

const TEMPLATE_J2: &str = r#"<!doctype html>
<h1>Hello, {{ name }}!</h1>
<p>Served by {{ app }}.</p>
"#;

const INDEX_HTML: &str = r#"<!doctype html>
<h1>Hello from Nitr</h1>
<p>Edit <code>public/index.html</code> and <code>app.lua</code>.</p>
"#;

const TEST_LUA: &str = r#"-- Run with: nitr test (or: nitr test --filter notes)
local t = nitr.test

t.before_each(function()
    nitr.db:execute("DELETE FROM notes")
end)

t.describe("notes API", function()
    t.it("starts empty", function()
        local resp = t.request("GET", "/api/notes")
        t.expect(resp.status).to_equal(200)
        t.expect(resp:json()).to_equal({})
    end)

    t.it("creates a note", function()
        local resp = t.request("POST", "/api/notes", { json = { text = "hi" } })
        t.expect(resp.status).to_equal(201)
        t.expect(resp:json().text).to_equal("hi")
    end)

    t.it("rejects an empty note", function()
        local resp = t.request("POST", "/api/notes", { json = {} })
        t.expect(resp.status).to_equal(422)
        t.expect(resp:json().fields.text).to_match("required")
    end)
end)
"#;

const GITIGNORE: &str = r#"data/*.db*
"#;

const MINIMAL_NITR_TOML: &str = r#"# Nitr application configuration.
listen = "127.0.0.1:3000"
handler_script = "app.lua"

# Static files are served from this directory, before Lua runs.
[static]
dir = "public"
mount = "/"
"#;

const MINIMAL_APP_LUA: &str = r#"local app = nitr.app()

app:get("/api/hello", function(req)
    return nitr.json({ hello = req.query.name or "world" })
end)

app:on_error(function(err, req)
    nitr.log.error("handler failed", { error = err.message, kind = err.kind })
    return nitr.error(500, { code = "INTERNAL" })
end)

return app
"#;

const MINIMAL_TEST_LUA: &str = r#"-- Run with: nitr test
local t = nitr.test

t.it("greets by name", function()
    local resp = t.request("GET", "/api/hello?name=nitr")
    t.expect(resp.status).to_equal(200)
    t.expect(resp:json().hello).to_equal("nitr")
end)

t.it("serves the static index", function()
    t.expect(t.request("GET", "/").status).to_equal(200)
end)
"#;
