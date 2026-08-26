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
