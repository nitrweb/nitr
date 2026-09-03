// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `nitr.*` standard library, exercised from Lua through real
//! requests.
//!
//! Each handler repeats its operation a fixed number of times so the
//! builtin — not the surrounding dispatch, which `dispatch.rs` measures on
//! its own — dominates the sample.

mod common;

use common::{client, get, tokio_runtime, write_file};
use nitr::Builtins;

fn main() {
    divan::main();
}

/// `nitr.json`: the codec both directions, on payloads of the size an API
/// actually exchanges.
mod json {
    use super::*;

    const APP: &str = r#"
local app = nitr.app()

local ITEMS = {}
for i = 1, 50 do
    ITEMS[i] = {
        id = i,
        name = "item-" .. i,
        tags = { "alpha", "beta", "gamma" },
        active = i % 2 == 0,
        score = i * 1.5,
    }
end
local DOC = { items = ITEMS, total = 50, page = 1 }
local ENCODED = nitr.json:encode(DOC)

app:get("/encode", function(req)
    local out
    for _ = 1, 20 do
        out = nitr.json:encode(DOC)
    end
    return nitr.text(tostring(#out))
end)

app:get("/decode", function(req)
    local out
    for _ = 1, 20 do
        out = nitr.json:decode(ENCODED)
    end
    return nitr.text(tostring(out.total))
end)

return app
"#;

    #[divan::bench]
    fn encode(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-json.lua", APP);
        let client = client(&rt, &script, Builtins::JSON | Builtins::HTTP);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/encode")));
    }

    #[divan::bench]
    fn decode(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-json.lua", APP);
        let client = client(&rt, &script, Builtins::JSON | Builtins::HTTP);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/decode")));
    }
}

/// The pure utilities: `nitr.base64`, `nitr.url`, `nitr.path`, `nitr.time`.
/// No I/O, no allocation surprises — the ones a busy handler calls without
/// thinking about it.
mod utilities {
    use super::*;

    const APP: &str = r#"
local app = nitr.app()

local BLOB = string.rep("payload bytes ", 64)

app:get("/base64", function(req)
    local out
    for _ = 1, 50 do
        out = nitr.base64.decode(nitr.base64.encode(BLOB))
    end
    return nitr.text(tostring(#out))
end)

app:get("/url", function(req)
    local out
    for _ = 1, 50 do
        local parsed = nitr.url.parse("https://api.example.com:8443/v1/users?page=3&sort=desc")
        out = parsed.host .. nitr.url.query_build({ q = "lua web server", page = 3 })
    end
    return nitr.text(out)
end)

app:get("/path", function(req)
    local out
    for _ = 1, 50 do
        out = nitr.path.normalize(nitr.path.join("/srv", "app", "../app", "public/logo.png"))
    end
    return nitr.text(out)
end)

app:get("/time", function(req)
    local out
    for _ = 1, 50 do
        out = nitr.time.parse_http(nitr.time.http(784887151))
    end
    return nitr.text(tostring(out))
end)

return app
"#;

    fn builtins() -> Builtins {
        Builtins::HTTP | Builtins::BASE64 | Builtins::URL | Builtins::PATH | Builtins::TIME
    }

    #[divan::bench]
    fn base64_roundtrip(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-utils.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/base64")));
    }

    #[divan::bench]
    fn url_parse_and_build(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-utils.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/url")));
    }

    #[divan::bench]
    fn path_join_and_normalize(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-utils.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/path")));
    }

    #[divan::bench]
    fn time_format_and_parse(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-utils.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/time")));
    }
}

/// `nitr.validate`: a schema compiled once at load, then checked per
/// request — the guard in front of every write endpoint.
mod validate {
    use super::*;

    const APP: &str = r#"
local app = nitr.app()

local schema = nitr.validate.schema({
    email = { type = "string", format = "email", required = true },
    name = { type = "string", min_len = 2, max_len = 64, required = true },
    age = { type = "integer", min = 0, max = 150 },
    tags = { type = "array", items = { type = "string" }, max_items = 4 },
})

local GOOD = { email = "ada@example.com", name = "Ada Lovelace", age = 36, tags = { "a", "b" } }
local BAD = { name = "A", age = -1, tags = { "a", "b", "c", "d", "e" } }

app:get("/accept", function(req)
    local out
    for _ = 1, 50 do
        out = schema:check(GOOD)
    end
    return nitr.text(out.email)
end)

app:get("/reject", function(req)
    local err
    for _ = 1, 50 do
        local _, e = schema:check(BAD)
        err = e
    end
    return nitr.text(err.fields.email)
end)

return app
"#;

    #[divan::bench]
    fn accepted_input(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-validate.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::VALIDATE);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/accept")));
    }

    #[divan::bench]
    fn rejected_input(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-validate.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::VALIDATE);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/reject")));
    }
}

/// `nitr.cache`: the bounded store shared by every pooled state, so both
/// directions cross the serialization boundary that keeps states isolated.
mod cache {
    use super::*;

    const APP: &str = r#"
local app = nitr.app()

local VALUE = { usd = 1.0, eur = 0.92, gbp = 0.79, jpy = 151.3, updated = "2024-01-01" }

app:get("/set", function(req)
    for i = 1, 50 do
        nitr.cache:set("rate-" .. i, VALUE, { ttl = 60 })
    end
    return nitr.text("ok")
end)

app:get("/get", function(req)
    nitr.cache:set("rates", VALUE, { ttl = 60 })
    local out
    for _ = 1, 50 do
        out = nitr.cache:get("rates")
    end
    return nitr.text(tostring(out.eur))
end)

return app
"#;

    #[divan::bench]
    fn set(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-cache.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::CACHE);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/set")));
    }

    #[divan::bench]
    fn get_hit(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-cache.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::CACHE);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/get")));
    }
}

/// Cookies and CSRF: HMAC-SHA256 signing on the request path, which every
/// session-bearing request pays.
mod cookies {
    use super::*;
    use crate::common::{dispatch, header};

    const APP: &str = r#"
local app = nitr.app()

local SECRET = "cookie-signing-secret-0123456789"

app:get("/sign", function(req)
    local res = nitr.text("ok")
    for i = 1, 20 do
        res.cookies:set_signed("session" .. i, "user-42", SECRET, { path = "/" })
    end
    return res
end)

app:get("/verify", function(req)
    local out
    for _ = 1, 20 do
        out = req.cookies:verify("session", SECRET)
    end
    return nitr.text(out or "none")
end)

return app
"#;

    #[divan::bench]
    fn sign(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-cookies.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/sign")));
    }

    #[divan::bench]
    fn verify(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-cookies.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP);

        // The signed cookie the handler verifies, produced by the server
        // itself so the benchmark measures a successful verification.
        let signed = dispatch(&rt, &client, "GET", "/sign", &[], None, 200);
        let cookie = signed
            .header("set-cookie")
            .expect("a Set-Cookie header")
            .split(';')
            .next()
            .expect("the cookie pair")
            .replace("session1=", "session=");
        let headers = [header("cookie", &cookie)];

        bencher.bench_local(|| {
            divan::black_box(dispatch(
                &rt, &client, "GET", "/verify", &headers, None, 200,
            ))
        });
    }
}

/// `nitr.crypto`: hashing, HMAC, AEAD and JWT. Password hashing is
/// deliberately absent — argon2 is tuned to be slow, and measuring it says
/// more about its parameters than about Nitr.
#[cfg(feature = "crypto")]
mod crypto {
    use super::*;

    const APP: &str = r#"
local app = nitr.app()

local KEY = string.rep("k", 32)
local BLOB = string.rep("payload bytes ", 64)

app:get("/hash", function(req)
    local out
    for _ = 1, 50 do
        out = nitr.crypto.hmac_sha256("server-secret", nitr.crypto.sha256(BLOB))
    end
    return nitr.text(out)
end)

app:get("/aead", function(req)
    local out
    for _ = 1, 20 do
        out = nitr.crypto.open(KEY, nitr.crypto.seal(KEY, BLOB, "user:42"), "user:42")
    end
    return nitr.text(tostring(#out))
end)

app:get("/jwt", function(req)
    local out
    for _ = 1, 20 do
        local token = nitr.crypto.jwt.sign({ sub = "42", exp = 4000000000 }, "jwt-secret")
        out = nitr.crypto.jwt.verify(token, "jwt-secret", { algorithms = { "HS256" } })
    end
    return nitr.text(out.sub)
end)

return app
"#;

    #[divan::bench]
    fn sha256_and_hmac(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-crypto.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::CRYPTO);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/hash")));
    }

    #[divan::bench]
    fn aead_seal_open(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-crypto.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::CRYPTO);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/aead")));
    }

    #[divan::bench]
    fn jwt_sign_verify(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-crypto.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::CRYPTO);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/jwt")));
    }
}

/// `nitr.template`: minijinja rendering, the other way to produce a
/// response body.
#[cfg(feature = "template")]
mod template {
    use super::*;
    use crate::common::{client_with, temp_dir};
    use nitr::Config;

    const APP: &str = r#"
local app = nitr.app()

local ROWS = {}
for i = 1, 50 do
    ROWS[i] = { id = i, name = "item-" .. i, score = i * 1.5 }
end

app:get("/render", function(req)
    local out
    for _ = 1, 5 do
        out = nitr.template:render("list.html", { title = "Inventory", rows = ROWS })
    end
    return nitr.html(out)
end)

return app
"#;

    const TEMPLATE: &str = r#"<!doctype html>
<html>
  <head><title>{{ title }}</title></head>
  <body>
    <h1>{{ title }}</h1>
    <table>
    {% for row in rows %}
      <tr><td>{{ row.id }}</td><td>{{ row.name|upper }}</td><td>{{ row.score }}</td></tr>
    {% endfor %}
    </table>
  </body>
</html>
"#;

    #[divan::bench]
    fn render_list(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-template.lua", APP);
        let dir = temp_dir("templates");
        std::fs::write(dir.join("list.html"), TEMPLATE).expect("write the template");
        let client = client_with(
            &rt,
            &script,
            Builtins::HTTP | Builtins::TEMPLATE,
            Config::default(),
            |builder| builder.templates_dir(&dir),
        );

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/render")));
    }
}

/// `nitr.db`: the SQLite driver, run off the async threads exactly as it is
/// under the server.
#[cfg(feature = "db")]
mod db {
    use super::*;
    use crate::common::{client_with, temp_dir};
    use nitr::Config;

    const APP: &str = r#"
local app = nitr.app()

app:get("/row", function(req)
    local out
    for i = 1, 20 do
        out = nitr.db:query_row("SELECT id, name, score FROM items WHERE id = ?", { i })
    end
    return nitr.text(out.name)
end)

app:get("/rows", function(req)
    local out
    for _ = 1, 5 do
        out = nitr.db:query("SELECT id, name, score FROM items ORDER BY id LIMIT 50")
    end
    return nitr.text(tostring(#out))
end)

app:get("/write", function(req)
    nitr.db:execute("INSERT INTO log (body) VALUES (?)", { "a log line" })
    return nitr.text("ok")
end)

return app
"#;

    /// A database with 200 rows to read back, seeded before the server is
    /// built so the schema never appears in a measurement.
    fn seeded_database() -> std::path::PathBuf {
        let path = temp_dir("db").join("bench.db");
        let conn = rusqlite::Connection::open(&path).expect("open the benchmark database");
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL, score REAL NOT NULL);
             CREATE TABLE log (id INTEGER PRIMARY KEY, body TEXT NOT NULL);",
        )
        .expect("create the benchmark schema");
        let mut stmt = conn
            .prepare("INSERT INTO items (id, name, score) VALUES (?, ?, ?)")
            .expect("prepare the seed statement");
        for i in 1..=200 {
            stmt.execute(rusqlite::params![i, format!("item-{i}"), i as f64 * 1.5])
                .expect("seed a row");
        }
        drop(stmt);
        path
    }

    fn db_client(
        rt: &tokio::runtime::Runtime,
        script: &std::path::Path,
    ) -> nitr::testing::TestClient {
        let database = seeded_database();
        client_with(
            rt,
            script,
            Builtins::HTTP | Builtins::DATABASE,
            Config::default(),
            move |builder| builder.database(database),
        )
    }

    #[divan::bench]
    fn query_row_by_id(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-db.lua", APP);
        let client = db_client(&rt, &script);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/row")));
    }

    #[divan::bench]
    fn query_fifty_rows(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-db.lua", APP);
        let client = db_client(&rt, &script);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/rows")));
    }

    #[divan::bench]
    fn insert_one_row(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-db.lua", APP);
        let client = db_client(&rt, &script);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/write")));
    }

    /// Wide rows: twenty columns, so the per-cell conversion (column name,
    /// value, table insert) dominates over SQLite itself.
    const WIDE_APP: &str = r#"
local app = nitr.app()

app:get("/wide", function(req)
    local out
    for _ = 1, 5 do
        out = nitr.db:query("SELECT * FROM wide ORDER BY id LIMIT 50")
    end
    return nitr.text(tostring(#out))
end)

-- Thirty distinct statements in rotation: more than the prepared
-- statement cache holds by default.
local STATEMENTS = {}
for i = 1, 30 do
    STATEMENTS[i] = "SELECT id, name, score FROM items WHERE id = " .. i .. " AND score >= 0"
end

app:get("/rotation", function(req)
    local out
    for i = 1, 30 do
        out = nitr.db:query_row(STATEMENTS[i])
    end
    return nitr.text(out.name)
end)

return app
"#;

    fn wide_database() -> std::path::PathBuf {
        let path = temp_dir("db-wide").join("bench.db");
        let conn = rusqlite::Connection::open(&path).expect("open the benchmark database");
        let columns: Vec<String> = (1..=19).map(|i| format!("c{i} TEXT NOT NULL")).collect();
        conn.execute_batch(&format!(
            "CREATE TABLE wide (id INTEGER PRIMARY KEY, {});
             CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL, score REAL NOT NULL);",
            columns.join(", ")
        ))
        .expect("create the benchmark schema");
        let placeholders: Vec<&str> = (1..=19).map(|_| "?").collect();
        let mut stmt = conn
            .prepare(&format!(
                "INSERT INTO wide VALUES (?, {})",
                placeholders.join(", ")
            ))
            .expect("prepare the seed statement");
        for i in 1..=100 {
            let mut values: Vec<rusqlite::types::Value> = vec![rusqlite::types::Value::Integer(i)];
            values.extend((1..=19).map(|c| rusqlite::types::Value::Text(format!("v{i}-{c}"))));
            stmt.execute(rusqlite::params_from_iter(values))
                .expect("seed a wide row");
        }
        drop(stmt);
        let mut stmt = conn
            .prepare("INSERT INTO items (id, name, score) VALUES (?, ?, ?)")
            .expect("prepare the seed statement");
        for i in 1..=50 {
            stmt.execute(rusqlite::params![i, format!("item-{i}"), i as f64 * 1.5])
                .expect("seed a row");
        }
        drop(stmt);
        path
    }

    fn wide_client(
        rt: &tokio::runtime::Runtime,
        script: &std::path::Path,
    ) -> nitr::testing::TestClient {
        let database = wide_database();
        client_with(
            rt,
            script,
            Builtins::HTTP | Builtins::DATABASE,
            Config::default(),
            move |builder| builder.database(database),
        )
    }

    #[divan::bench]
    fn query_fifty_wide_rows(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-db-wide.lua", WIDE_APP);
        let client = wide_client(&rt, &script);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/wide")));
    }

    #[divan::bench]
    fn thirty_statement_rotation(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-db-wide.lua", WIDE_APP);
        let client = wide_client(&rt, &script);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/rotation")));
    }
}

/// The JSON bounds guard (`check_json_bounds`) against the serialization it
/// runs in front of, on a bare Lua state: how much of every encode, cache
/// write, session save and template render is the guard's own walk.
mod bounds_guard {
    use mlua::Value;

    /// 500 records of three scalars: the shape of an API list.
    const FLAT: &str = "local t = {} \
        for i = 1, 500 do t[i] = { id = i, name = 'item-' .. i, ok = i % 2 == 0 } end \
        return t";
    /// A 100-deep chain: few nodes, maximal recursion.
    const DEEP: &str = "local t = {} local cur = t \
        for i = 1, 100 do cur.next = { v = i } cur = cur.next end \
        return t";

    fn value(lua: &mlua::Lua, src: &str) -> Value {
        lua.load(src).eval().expect("build the value")
    }

    fn guard_only(bencher: divan::Bencher<'_, '_>, src: &str) {
        let lua = mlua::Lua::new();
        let value = value(&lua, src);
        bencher.bench_local(|| {
            nitr::stdlib::fuzzing::check_json_bounds(&value).expect("within bounds");
        });
    }

    fn serialize_only(bencher: divan::Bencher<'_, '_>, src: &str) {
        let lua = mlua::Lua::new();
        let value = value(&lua, src);
        bencher.bench_local(|| divan::black_box(serde_json::to_string(&value).expect("serialize")));
    }

    fn both(bencher: divan::Bencher<'_, '_>, src: &str) {
        let lua = mlua::Lua::new();
        let value = value(&lua, src);
        bencher.bench_local(|| {
            nitr::stdlib::fuzzing::check_json_bounds(&value).expect("within bounds");
            divan::black_box(serde_json::to_string(&value).expect("serialize"))
        });
    }

    #[divan::bench]
    fn flat_guard_only(bencher: divan::Bencher<'_, '_>) {
        guard_only(bencher, FLAT);
    }

    #[divan::bench]
    fn flat_serialize_only(bencher: divan::Bencher<'_, '_>) {
        serialize_only(bencher, FLAT);
    }

    #[divan::bench]
    fn flat_guard_then_serialize(bencher: divan::Bencher<'_, '_>) {
        both(bencher, FLAT);
    }

    #[divan::bench]
    fn deep_guard_only(bencher: divan::Bencher<'_, '_>) {
        guard_only(bencher, DEEP);
    }

    #[divan::bench]
    fn deep_serialize_only(bencher: divan::Bencher<'_, '_>) {
        serialize_only(bencher, DEEP);
    }

    #[divan::bench]
    fn deep_guard_then_serialize(bencher: divan::Bencher<'_, '_>) {
        both(bencher, DEEP);
    }
}

/// The un-benched halves of `nitr.path` and `nitr.url`.
mod utilities_more {
    use super::*;

    const APP: &str = r#"
local app = nitr.app()

app:get("/path-parts", function(req)
    local out
    for _ = 1, 50 do
        local p = "/srv/app/public/assets/logo.png"
        out = nitr.path.dirname(p) .. nitr.path.basename(p) .. (nitr.path.extension(p) or "")
    end
    return nitr.text(out)
end)

app:get("/url-codec", function(req)
    local out
    for _ = 1, 50 do
        out = nitr.url.decode(nitr.url.encode("lua web server & friends/ü"))
    end
    return nitr.text(out)
end)

return app
"#;

    #[divan::bench]
    fn path_parts(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-utils-more.lua", APP);
        let client = client(
            &rt,
            &script,
            Builtins::HTTP | Builtins::PATH | Builtins::URL,
        );

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/path-parts")));
    }

    #[divan::bench]
    fn url_encode_decode(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-utils-more.lua", APP);
        let client = client(
            &rt,
            &script,
            Builtins::HTTP | Builtins::PATH | Builtins::URL,
        );

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/url-codec")));
    }
}

/// `nitr.log`: what a log call costs when its level is filtered out (the
/// production case for `debug`) and when it is written, to a sink.
mod log {
    use super::*;

    const APP: &str = r#"
local app = nitr.app()

local FIELDS = { user = 42, path = "/orders/17", tags = { "a", "b", "c" }, ok = true }

app:get("/debug", function(req)
    for i = 1, 50 do
        nitr.log.debug("order processed", FIELDS)
    end
    return nitr.text("ok")
end)

app:get("/debug/plain", function(req)
    for i = 1, 50 do
        nitr.log.debug("order processed")
    end
    return nitr.text("ok")
end)

return app
"#;

    /// No subscriber at all: the level filter says no before anything else
    /// happens — or should.
    #[divan::bench]
    fn debug_with_fields_disabled(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-log.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::LOG);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/debug")));
    }

    #[divan::bench]
    fn debug_plain_disabled(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-log.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::LOG);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/debug/plain")));
    }

    /// A DEBUG subscriber writing to a sink: the full cost of a line that
    /// is actually emitted, fields serialized and all.
    #[divan::bench]
    fn debug_with_fields_enabled(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-log.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::LOG);
        let subscriber = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(std::io::sink)
                .finish(),
        );

        bencher.bench_local(|| {
            tracing::dispatcher::with_default(&subscriber, || {
                divan::black_box(get(&rt, &client, "/debug"))
            })
        });
    }
}

/// The cache past its bounds, where every `set` has to evict.
mod cache_pressure {
    use super::*;
    use crate::common::client_with;
    use nitr::Config;

    const APP: &str = r#"
local app = nitr.app()

local VALUE = { usd = 1.0, eur = 0.92, gbp = 0.79, jpy = 151.3, updated = "2024-01-01" }
local n = 0

-- 100 entries fit; every set past that evicts the least recently used.
app:get("/churn", function(req)
    for _ = 1, 50 do
        n = n + 1
        nitr.cache:set("k-" .. n, VALUE, { ttl = 60 })
    end
    return nitr.text("ok")
end)

app:get("/remember", function(req)
    local out
    for _ = 1, 50 do
        out = nitr.cache:remember("rates", { ttl = 60 }, function() return VALUE end)
    end
    return nitr.text(tostring(out.eur))
end)

app:get("/stats", function(req)
    local out
    for _ = 1, 50 do
        out = nitr.cache:stats()
    end
    return nitr.text(tostring(out.hits))
end)

return app
"#;

    fn small_cache() -> Config {
        let mut cfg = Config::default();
        cfg.cache.max_entries = 100;
        cfg
    }

    /// Fifty sets into a full 100-entry cache: fifty evictions.
    #[divan::bench]
    fn set_evicting(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-cache-pressure.lua", APP);
        let client = client_with(
            &rt,
            &script,
            Builtins::HTTP | Builtins::CACHE,
            small_cache(),
            |b| b,
        );
        // Fill it first so the measured sets all evict.
        for _ in 0..3 {
            get(&rt, &client, "/churn");
        }

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/churn")));
    }

    #[divan::bench]
    fn remember_hit(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-cache-pressure.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::CACHE);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/remember")));
    }

    #[divan::bench]
    fn stats(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-cache-pressure.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::CACHE);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/stats")));
    }
}

/// The response-path serializers: the `nitr.json(...)` helper,
/// `nitr.error` with a table body, `nitr.etag` over a table. Each walks
/// its value through the JSON bounds guard and then the serializer.
mod response_helpers {
    use super::*;
    use crate::common::dispatch;

    const APP: &str = r#"
local app = nitr.app()

local ITEMS = {}
for i = 1, 50 do
    ITEMS[i] = { id = i, name = "item-" .. i, tags = { "alpha", "beta" }, active = i % 2 == 0 }
end
local DOC = { items = ITEMS, total = 50 }

app:get("/json", function(req)
    return nitr.json(DOC)
end)

app:get("/error", function(req)
    return nitr.error(422, { code = "INVALID", fields = { email = "required", name = "too short" } })
end)

app:get("/etag", function(req)
    local out
    for _ = 1, 20 do
        out = nitr.etag(DOC)
    end
    return nitr.text(out)
end)

return app
"#;

    #[divan::bench]
    fn json_helper_50_items(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-response.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::JSON);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/json")));
    }

    #[divan::bench]
    fn error_with_table_body(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-response.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::JSON);

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "GET", "/error", &[], None, 422))
        });
    }

    #[divan::bench]
    fn etag_over_table(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-response.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::JSON);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/etag")));
    }
}

/// `nitr.validate` on a nested schema: objects inside arrays, where the
/// per-field path bookkeeping multiplies.
mod validate_nested {
    use super::*;

    const APP: &str = r#"
local app = nitr.app()

local schema = nitr.validate.schema({
    order = { type = "table", required = true, fields = {
        id = { type = "integer", required = true },
        customer = { type = "table", required = true, fields = {
            email = { type = "string", format = "email", required = true },
            name = { type = "string", min_len = 2, required = true },
        } },
    } },
    lines = { type = "array", required = true, max_items = 50, items = { type = "table", fields = {
        sku = { type = "string", required = true },
        qty = { type = "integer", min = 1, required = true },
    } } },
})

local LINES = {}
for i = 1, 20 do LINES[i] = { sku = "sku-" .. i, qty = i } end
local GOOD = { order = { id = 7, customer = { email = "ada@example.com", name = "Ada" } }, lines = LINES }

app:get("/accept", function(req)
    local out
    for _ = 1, 20 do
        out = schema:check(GOOD)
    end
    return nitr.text(out.order.customer.name)
end)

return app
"#;

    #[divan::bench]
    fn accepted_nested_input(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-validate-nested.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::VALIDATE);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/accept")));
    }
}

/// `nitr.time` through strftime, the other half of the time module.
mod time_strftime {
    use super::*;

    const APP: &str = r#"
local app = nitr.app()

app:get("/strftime", function(req)
    local out
    for _ = 1, 50 do
        local s = nitr.time.format(784887151, "%Y-%m-%d %H:%M:%S")
        out = nitr.time.parse(s, "%Y-%m-%d %H:%M:%S")
    end
    return nitr.text(tostring(out))
end)

return app
"#;

    #[divan::bench]
    fn format_and_parse(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-time.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP | Builtins::TIME);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/strftime")));
    }
}

/// `nitr.csrf`: the middleware's issue path (a `GET` that mints and sets
/// the token) and its verify path (a `POST` echoing it).
mod csrf {
    use super::*;
    use crate::common::{dispatch, header};

    const APP: &str = r#"
local app = nitr.app()

app:use(nitr.csrf({ secret = "csrf-signing-secret-0123456789" }))

app:get("/form", function(req)
    return nitr.text(nitr.csrf.token(req))
end)

app:post("/submit", function(req)
    return nitr.text("ok")
end)

return app
"#;

    #[divan::bench]
    fn issue_on_get(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-csrf.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/form")));
    }

    #[divan::bench]
    fn verify_on_post(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-csrf.lua", APP);
        let client = client(&rt, &script, Builtins::HTTP);
        let issued = get(&rt, &client, "/form");
        let token = String::from_utf8(issued.body.to_vec()).expect("the token");
        let cookie = issued
            .header("set-cookie")
            .expect("the csrf cookie")
            .split(';')
            .next()
            .expect("the cookie pair")
            .to_string();
        let headers = [
            header("cookie", &cookie),
            header("x-csrf-token", &token),
            header("sec-fetch-site", "same-origin"),
        ];

        bencher.bench_local(|| {
            divan::black_box(dispatch(
                &rt, &client, "POST", "/submit", &headers, None, 200,
            ))
        });
    }
}

/// Per-request HTTP ergonomics added by phases 3 and 14: cookie-header
/// parsing (rebuilt on every `req.cookies` access), `Accept` negotiation,
/// and the full signed-cookie session round trip (verify → mutate →
/// re-sign). These run inside ordinary handlers, so their cost is paid on
/// the request path, not at load time.
mod http_request {
    use super::*;
    use common::dispatch;

    const APP: &str = r#"
local app = nitr.app()

app:get("/cookies", function(req)
    local jar = req.cookies
    return nitr.text(jar.c5 or "none")
end)

app:get("/accepts", function(req)
    return nitr.text(req:accepts("application/json", "text/html", "text/plain") or "none")
end)

app:get("/session", function(req)
    local session = nitr.session(req, { secret = "bench-secret-0123456789" })
    session.n = (session.n or 0) + 1
    local resp = nitr.text(tostring(session.n))
    session:save(resp)
    return resp
end)

return app
"#;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[divan::bench]
    fn request_cookies(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-http.lua", APP);
        let client = client(&rt, &script, Builtins::minimal());
        let cookie: String = (1..=10)
            .map(|i| format!("c{i}=value-{i}"))
            .collect::<Vec<_>>()
            .join("; ");
        let hdrs = headers(&[("cookie", &cookie)]);

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "GET", "/cookies", &hdrs, None, 200))
        });
    }

    #[divan::bench]
    fn accept_negotiation(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-http.lua", APP);
        let client = client(&rt, &script, Builtins::minimal());
        let hdrs = headers(&[(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
        )]);

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "GET", "/accepts", &hdrs, None, 200))
        });
    }

    #[divan::bench]
    fn session_roundtrip(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("stdlib-http.lua", APP);
        let client = client(&rt, &script, Builtins::minimal());
        // One unauthenticated request yields the signed cookie the
        // measured requests then carry: verify + re-sign per iteration.
        let first = get(&rt, &client, "/session");
        let cookie = first
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.split(';').next().unwrap_or_default().to_string())
            .expect("a session cookie");
        let hdrs = headers(&[("cookie", &cookie)]);

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "GET", "/session", &hdrs, None, 200))
        });
    }
}
