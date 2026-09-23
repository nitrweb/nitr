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
            ("lib/notes.lua", LIB_NOTES_LUA.into()),
            ("migrations/001_init.sql", MIGRATION_SQL.into()),
            ("templates/hello.j2", TEMPLATE_J2.into()),
            ("public/index.html", INDEX_HTML.into()),
            ("tests/notes_test.lua", TEST_LUA.into()),
            ("tests/helpers/notes.lua", TEST_HELPERS_LUA.into()),
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
        false => println!(
            "\nNext steps:\n  nitr migrate\n  nitr check\n  nitr test\n  nitr dev   # then open http://127.0.0.1:3000/docs"
        ),
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

# The OpenAPI document, generated from the routes' `input` and `doc`
# tables: served at /openapi.json, and kept current in openapi.json while
# `nitr dev` runs (`nitr openapi --check` is the CI drift gate).
[openapi]
enabled = true
output = "openapi.json"

# Swagger UI at /docs, rendering the document from this binary (no CDN).
[swagger]
enabled = true
try_it_out = true
"#;

const CONFIG_LUA: &str = r#"-- Runs once at startup; the returned table is snapshotted into every
-- state and exposed to handlers as `nitr.cfg`.
return {
    app_name = "my-app",
    started_at = nitr.time.iso8601(nitr.time.now()),
}
"#;

const APP_LUA: &str = r#"local app = nitr.app()

-- Document-level information for the generated OpenAPI document.
app:doc({
    title = "My App",
    version = "0.1.0",
    tags = { { name = "notes", description = "Notes" } },
})

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

const LIB_NOTES_LUA: &str = r#"-- The notes domain without a request in sight: what the routes validate
-- with, and nothing that needs a server. Logic that does not take `req`
-- lives in a module like this one, is `require`d by the routes and by
-- the tests alike, and is unit-tested without a server.
local M = {}

M.NoteInput = nitr.validate.schema({
    text = "string|trim|min_len:1|max_len:500|required",
}, { title = "NoteInput" })

-- Documentation only: responses are never checked.
M.Note = nitr.validate.schema({
    id = "integer|required",
    text = "string|required",
    created_at = "integer|required",
}, { title = "Note" })

return M
"#;

const ROUTES_NOTES_LUA: &str = r#"-- The notes API: a route module is a plain function taking the app.
--
-- A route's `input` is validated in Rust before the handler runs: a bad
-- body answers a JSON 422 naming every failing field, and the handler
-- reads the checked, stripped values from `req.valid`. The same `input`
-- documents the operation in /openapi.json; `doc` adds the prose.
local notes = require("lib.notes")
local NoteInput, Note = notes.NoteInput, notes.Note

return function(app)
    app:get("/api/notes", function(req)
        local q = req.valid.query
        return nitr.json(nitr.db:query(
            "SELECT id, text, created_at FROM notes ORDER BY id LIMIT ?",
            { q.limit }
        ))
    end, {
        input = { query = { limit = "integer|min:1|max:100|default:50" } },
        doc = {
            summary = "List notes", tags = { "notes" },
            responses = { [200] = { description = "The newest notes", schema = { type = "array", items = Note } } },
        },
    })

    app:post("/api/notes", function(req)
        local data = req.valid.body
        nitr.db:execute(
            "INSERT INTO notes (text, created_at) VALUES (?, ?)",
            { data.text, nitr.time.now() }
        )
        local note = nitr.db:query_row("SELECT id, text, created_at FROM notes ORDER BY id DESC")
        return nitr.json(note, 201)
    end, {
        input = { body = NoteInput },
        doc = {
            summary = "Create a note", tags = { "notes" },
            responses = { [201] = { description = "The created note", schema = Note } },
        },
    })
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

const TEST_LUA: &str = r#"-- Run with: nitr test (or: nitr test --filter notes, nitr test --list)
local t = nitr.test
local notes = require("lib.notes")
-- Test helpers live under tests/ in a subdirectory: `require`-able from
-- a test file, never discovered as a test file themselves.
local fixtures = require("helpers.notes")

-- Unit: a plain module, no server. If a function does not take `req`,
-- test it here.
t.describe("lib.notes (unit)", function()
    t.it("trims the text it accepts", function()
        local data, err = notes.NoteInput:check({ text = "  hi  " })
        t.expect(err).to_be_nil()
        t.expect(data).to_equal({ text = "hi" })
    end)

    t.each({
        { name = "an empty note", input = { text = "   " }, rule = "min_len" },
        { name = "a missing note", input = {}, rule = "required" },
        { name = "a long note", input = { text = ("x"):rep(501) }, rule = "max_len" },
    })("rejects %s", function(case)
        local data, err = notes.NoteInput:check(case.input)
        t.expect(data).to_be_nil()
        t.expect(err.errors[1].rule).to_equal(case.rule)
    end)
end)

-- Integration: through the real router, validation and handler.
t.describe("notes API", function()
    local api = t.client({ base = "/api" })
    -- The database as the migrations left it, before every test.
    t.before_each(t.db.reset)

    t.it("starts empty", function()
        t.expect(api:get("/notes"):json()).to_equal({})
    end)

    t.it("creates a note", function()
        t.clock.set(1735689600) -- 2025-01-01T00:00:00Z
        local resp = api:post("/notes", { json = fixtures.note })
        t.expect(resp).to_have_status(201)
        t.expect(resp).to_have_json({ text = "hi", created_at = 1735689600 })
    end)

    t.it("lists what the fixtures seeded", function()
        t.db.seed({ notes = fixtures.rows })
        t.expect(#api:get("/notes"):json()).to_equal(#fixtures.rows)
    end)

    t.it("rejects an empty note before the handler runs", function()
        local resp = api:post("/notes", { json = {} })
        t.expect(resp).to_have_status(422)
        t.expect(resp:json().fields["body.text"]).to_equal("is required")
        t.expect(resp:json().errors[1].rule).to_equal("required")
    end)

    t.it("bounds the page size", function()
        local resp = api:get("/notes", { query = { limit = 500 } })
        t.expect(resp).to_have_status(422)
        t.expect(resp:json().fields["query.limit"]).to_equal("must be at most 100")
    end)

    t.it("publishes what it enforces", function()
        local spec = t.get("/openapi.json"):json()
        local limit = spec.paths["/api/notes"].get.parameters[1]
        t.expect(limit).to_match_object({ name = "limit", schema = { maximum = 100 } })
        t.expect(spec.components.schemas.NoteInput.required[1]).to_equal("text")
    end)
end)
"#;

const TEST_HELPERS_LUA: &str = r#"-- Shared test data: `require("helpers.notes")` from any test file.
return {
    note = { text = "  hi  " },
    rows = {
        { text = "first", created_at = 1 },
        { text = "second", created_at = 2 },
    },
}
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
