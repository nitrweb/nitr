// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for the OpenAPI document and the Swagger UI page:
//! serving and caching, the reserved paths, determinism, the dev-mode
//! output file, and the page's escaping and policy.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use std::time::{Duration, Instant};

use harness::TestServer;

/// A sentinel that must reach the browser only inside the fetched JSON.
const DESCRIPTION_TOKEN: &str = "UNIQUE_DESCRIPTION_TOKEN_7f3a";

const APP: &str = r#"
local S = nitr.validate
local app = nitr.app()

app:doc({
    title = "Notes </script><script>alert(1)</script>",
    version = "1.0.0",
    description = "**Markdown** <b>and markup</b> UNIQUE_DESCRIPTION_TOKEN_7f3a",
    tags = { { name = "notes", description = "Notes CRUD" } },
    security = { team = { type = "apiKey", ["in"] = "header", name = "x-team" } },
})

local Note = S.schema({ id = "integer|required", text = "string|required" }, { title = "Note" })
local NoteInput = S.schema({
    text = { "string|trim|min_len:1|required", description = "the body",
             check = function(s) return s:match("%a") ~= nil, "needs a letter" end },
}, { title = "NoteInput" })

app:get("/api/notes", function(req)
    return nitr.json({})
end, {
    input = { query = { limit = "integer|min:1|max:100|default:20" }, headers = { ["x-team"] = "string|required" } },
    doc = { summary = "List notes", tags = { "notes" }, security = { "team" },
            responses = { [200] = { description = "A page", schema = { type = "array", items = Note } } } },
})

app:post("/api/notes", function(req)
    return nitr.json(req.valid.body, 201)
end, {
    input = { body = NoteInput },
    doc = { responses = { [201] = { schema = Note } } },
})

app:get("/internal/metrics", function(req)
    return nitr.json({ n = 0 })
end, { doc = { hidden = true } })

return app
"#;

async fn spec_of(server: &TestServer) -> serde_json::Value {
    let resp = server.get("/openapi.json").await;
    assert_eq!(resp.status(), 200);
    resp.json().await.expect("json")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_document_is_served_with_a_validator_and_answers_304() {
    let mut server = TestServer::builder("openapi")
        .handler(APP)
        .config(|cfg| cfg.openapi.enabled = true)
        .spawn()
        .await;
    let resp = server.get("/openapi.json").await;
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    assert_eq!(resp.headers()["cache-control"], "max-age=60");
    let etag = resp.headers()["etag"].to_str().unwrap().to_string();
    assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
    let length: usize = resp.headers()["content-length"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let spec: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(spec["openapi"], "3.1.0");
    assert_eq!(
        spec["info"]["title"],
        "Notes </script><script>alert(1)</script>"
    );
    assert!(spec["paths"]["/api/notes"]["get"]["parameters"].is_array());
    assert!(spec["paths"].get("/internal/metrics").is_none(), "hidden");
    assert_eq!(
        spec["components"]["schemas"]["NoteInput"]["properties"]["text"]["x-nitr-enforced"],
        "custom"
    );

    // The validator round-trips.
    let resp = server
        .client()
        .get(server.url("/openapi.json"))
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 304);
    assert_eq!(resp.headers()["etag"].to_str().unwrap(), etag);

    // HEAD: the GET's headers, no body.
    let resp = server
        .client()
        .head(server.url("/openapi.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-length"]
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        length
    );
    assert!(resp.bytes().await.unwrap().is_empty());
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_sections_are_404_and_other_methods_fall_through() {
    // Off by default: nothing at the document path.
    let mut server = TestServer::builder("openapi").handler(APP).spawn().await;
    assert_eq!(server.get("/openapi.json").await.status(), 404);
    assert_eq!(server.get("/docs").await.status(), 404);
    server.stop().await;

    let mut server = TestServer::builder("openapi")
        .handler(APP)
        .config(|cfg| cfg.openapi.enabled = true)
        .spawn()
        .await;
    for method in [
        reqwest::Method::POST,
        reqwest::Method::PUT,
        reqwest::Method::DELETE,
    ] {
        let resp = server
            .client()
            .request(method.clone(), server.url("/openapi.json"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            404,
            "{method} must reach the router, not the docs"
        );
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn routes_on_reserved_paths_refuse_to_boot_naming_the_key() {
    for (path, key, tune) in [
        (
            "/openapi.json",
            "[openapi] path",
            Box::new(|cfg: &mut nitr::Config| cfg.openapi.enabled = true)
                as Box<dyn Fn(&mut nitr::Config)>,
        ),
        (
            "/docs/x",
            "[swagger] path",
            Box::new(|cfg: &mut nitr::Config| {
                cfg.openapi.enabled = true;
                cfg.swagger.enabled = cfg!(feature = "swagger");
            }),
        ),
    ] {
        let script = format!(
            r#"local app = nitr.app()
app:get("{path}", function(req) return nitr.text("mine") end)
return app"#
        );
        let mut builder = TestServer::builder("openapi-reserved")
            .handler(script)
            .config(tune);
        let result = builder.try_build().await;
        if key == "[swagger] path" && !cfg!(feature = "swagger") {
            assert!(result.is_ok(), "no page, nothing reserved");
            continue;
        }
        let err = result.expect_err(path).to_string();
        assert!(err.contains(key), "{err}");
        assert!(err.contains("app.lua:2"), "{err}");
    }
    // Disabled sections reserve nothing: the route wins.
    let mut server = TestServer::builder("openapi-reserved")
        .handler(
            r#"local app = nitr.app()
app:get("/openapi.json", function(req) return nitr.text("mine") end)
return app"#,
        )
        .spawn()
        .await;
    assert_eq!(
        server.get("/openapi.json").await.text().await.unwrap(),
        "mine"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_doc_tables_refuse_to_boot_naming_the_site() {
    for (script, needle) in [
        (
            r#"local app = nitr.app()
app:get("/x", function(req) return nitr.text("") end, { doc = { sumary = "x" } })
return app"#,
            "unknown doc key `sumary`",
        ),
        (
            r#"local app = nitr.app()
app:get("/x", function(req) return nitr.text("") end, { doc = { body = {} } })
return app"#,
            "doc.body is not a documentation key",
        ),
        (
            r#"local app = nitr.app()
app:doc({ title = "a" })
app:doc({ title = "b" })
return app"#,
            "app:doc() called twice",
        ),
        (
            r#"local app = nitr.app()
app:get("/a", function(req) return nitr.text("") end, { doc = { operation_id = "same" } })
app:get("/b", function(req) return nitr.text("") end, { doc = { operation_id = "same" } })
return app"#,
            "operation id `same` is claimed twice",
        ),
        (
            r#"local app = nitr.app()
app:get("/a/:x/b/:x", function(req) return nitr.text("") end)
return app"#,
            "names the parameter `x` twice",
        ),
        (
            r#"local app = nitr.app()
app:get("/a", function(req) return nitr.text("") end, { doc = { security = { "nope" } } })
return app"#,
            "which app:doc does not declare",
        ),
    ] {
        let mut builder = TestServer::builder("openapi-docs").handler(script);
        let err = builder.try_build().await.expect_err(needle).to_string();
        assert!(err.contains(needle), "{err}");
        assert!(err.contains("app.lua:"), "{err}");
    }
}

/// Default operation ids are Nitr's own naming: two routes whose slugs
/// coincide (`/` and `/*`, `/files` and `/files/*`) boot, get distinct
/// ids, and only an explicit `operation_id` may collide fatally.
#[tokio::test(flavor = "multi_thread")]
async fn default_operation_ids_never_refuse_an_application() {
    let mut server = TestServer::builder("openapi-ids")
        .handler(
            r#"local app = nitr.app()
app:get("/", function(req) return nitr.text("root") end)
app:get("/*", function(req) return nitr.text("rest") end)
app:get("/files", function(req) return nitr.text("") end)
app:get("/files/*", function(req) return nitr.text("") end)
app:get("/a-b", function(req) return nitr.text("") end)
app:get("/a_b", function(req) return nitr.text("") end)
return app"#,
        )
        .config(|cfg| cfg.openapi.enabled = true)
        .spawn()
        .await;
    let spec = spec_of(&server).await;
    let ids: Vec<String> = spec["paths"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|item| item.as_object().unwrap().values())
        .map(|op| op["operationId"].as_str().unwrap().to_string())
        .collect();
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "{ids:?}");
    assert_eq!(spec["paths"]["/"]["get"]["operationId"], "get_root");
    assert_eq!(spec["paths"]["/{splat}"]["get"]["operationId"], "get_splat");
    assert_eq!(spec["paths"]["/a-b"]["get"]["operationId"], "get_a_b");
    assert_eq!(spec["paths"]["/a_b"]["get"]["operationId"], "get_a_b_2");
    server.stop().await;
}

/// `[openapi] output` may not be a rebuild input: a `.lua` name or a
/// file under `[templating] dir` would make the dev-mode watcher reload
/// on every write (W1).
#[tokio::test(flavor = "multi_thread")]
async fn output_paths_that_would_loop_the_watcher_are_refused() {
    for (name, needle, templating) in [
        ("openapi.lua", "has a `.lua` extension", false),
        ("templates/openapi.json", "is inside [templating] dir", true),
        ("missing-dir/openapi.json", "does not exist", false),
    ] {
        let mut builder = TestServer::builder("openapi-output").handler(APP);
        let dir = builder.dir().path().to_path_buf();
        if templating {
            std::fs::create_dir_all(dir.join("templates")).unwrap();
        }
        let output = dir.join(name);
        builder = builder.config(move |cfg| {
            cfg.openapi.enabled = true;
            cfg.openapi.output = Some(output.clone());
            if templating {
                cfg.templating.dir = Some(dir.join("templates"));
            }
        });
        let err = builder.try_build().await.expect_err(name).to_string();
        assert!(err.contains(needle), "{name}: {err}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_servers_produce_byte_identical_documents() {
    let mut first = TestServer::builder("openapi-a")
        .handler(APP)
        .config(|cfg| {
            cfg.openapi.enabled = true;
            cfg.workers = 3;
        })
        .spawn()
        .await;
    let mut second = TestServer::builder("openapi-b")
        .handler(APP)
        .config(|cfg| cfg.openapi.enabled = true)
        .spawn()
        .await;
    let a = first.get("/openapi.json").await.bytes().await.unwrap();
    let b = second.get("/openapi.json").await.bytes().await.unwrap();
    assert_eq!(a, b);
    first.stop().await;
    second.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn undocumented_routes_can_be_left_out_and_the_rate_limiter_counts_docs() {
    let mut server = TestServer::builder("openapi")
        .handler(
            r#"local app = nitr.app()
app:get("/bare", function(req) return nitr.text("") end)
app:get("/told", function(req) return nitr.text("") end, { doc = { summary = "told" } })
return app"#,
        )
        .config(|cfg| {
            cfg.openapi.enabled = true;
            cfg.openapi.include_undocumented = false;
            cfg.openapi.servers = vec!["https://api.example.com".into()];
            cfg.rate_limit.enabled = true;
            cfg.rate_limit.requests = 2;
            cfg.rate_limit.window = 60;
        })
        .spawn()
        .await;
    let spec = spec_of(&server).await;
    assert!(spec["paths"].get("/bare").is_none());
    assert_eq!(spec["paths"]["/told"]["get"]["summary"], "told");
    assert_eq!(spec["servers"][0]["url"], "https://api.example.com");
    assert_eq!(server.get("/openapi.json").await.status(), 200);
    assert_eq!(server.get("/openapi.json").await.status(), 429);
    server.stop().await;
}

/// The dev-mode output file: written at boot, rewritten once when a save
/// changes the document, then left alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dev_mode_writes_the_output_once_per_change() {
    let builder = TestServer::builder("openapi-dev");
    let output = builder.dir().join("openapi.json");
    let mut server = builder
        .handler(APP)
        .config(|cfg| {
            cfg.dev_mode = true;
            cfg.openapi.enabled = true;
        })
        .config(move |cfg| cfg.openapi.output = Some(output.clone()))
        .spawn()
        .await;
    let output = server.dir().join("openapi.json");
    let first = std::fs::read_to_string(&output).expect("written at boot");
    assert!(first.contains("\"List notes\""));
    assert_eq!(
        first,
        server.get("/openapi.json").await.text().await.unwrap()
    );

    // Save a changed summary and wait for the rewrite.
    let changed = APP.replace("List notes", "List every note");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        server.dir().write("app.lua", &changed);
        tokio::time::sleep(Duration::from_millis(200)).await;
        if std::fs::read_to_string(&output).is_ok_and(|s| s.contains("\"List every note\"")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the output file was never rewritten"
        );
    }
    let served = server.get("/openapi.json").await.text().await.unwrap();
    assert!(served.contains("\"List every note\""));

    // Then silence: the rebuild's own write never re-triggers, and an
    // unchanged document is not rewritten. Poll the modification time
    // until it holds still, rather than trusting one sleep.
    let modified = |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let mut last = modified(&output);
    let mut stable = 0;
    let deadline = Instant::now() + Duration::from_secs(10);
    while stable < 5 {
        assert!(Instant::now() < deadline, "the output file kept changing");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let now = modified(&output);
        if now == last {
            stable += 1;
        } else {
            last = now;
            stable = 0;
        }
    }
    server.stop().await;
}

/// The Swagger UI page: no inline script, escaped title, a policy that
/// forbids what the escaping already prevents, and assets served from a
/// fixed table that no path trick can leave.
#[cfg(feature = "swagger")]
mod page {
    use super::*;

    fn version_of(html: &str) -> String {
        let start = html.find("/docs/assets/").expect("asset base") + "/docs/assets/".len();
        let end = html[start..].find('/').unwrap() + start;
        html[start..end].to_string()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_page_carries_a_policy_and_interpolates_nothing_unescaped() {
        let mut server = TestServer::builder("swagger")
            .handler(APP)
            .config(|cfg| {
                cfg.openapi.enabled = true;
                cfg.swagger.enabled = true;
                cfg.swagger.try_it_out = true;
            })
            .spawn()
            .await;
        let resp = server.get("/docs").await;
        assert_eq!(resp.status(), 200);
        let headers = resp.headers().clone();
        assert!(
            headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("script-src 'self';"), "{csp}");
        assert!(csp.contains("connect-src 'self';"), "{csp}");
        assert_eq!(headers["cache-control"], "max-age=60");
        let html = resp.text().await.unwrap();
        assert!(!html.contains("<script>alert"), "{html}");
        assert!(html.contains("&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(
            !html.contains(DESCRIPTION_TOKEN),
            "descriptions reach the page only via the JSON"
        );
        assert!(html.contains("\"tryItOutEnabled\":true"));
        assert!(html.contains("\"url\":\"/openapi.json\""));

        let version = version_of(&html);
        let bundle = server
            .get(&format!("/docs/assets/{version}/swagger-ui-bundle.js"))
            .await;
        assert_eq!(bundle.status(), 200);
        assert_eq!(
            bundle.headers()["cache-control"],
            "public, max-age=31536000, immutable"
        );
        assert!(
            bundle.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("application/javascript")
        );
        let etag = bundle.headers()["etag"].to_str().unwrap().to_string();
        assert!(bundle.bytes().await.unwrap().len() > 1_000_000);
        let resp = server
            .client()
            .get(server.url(&format!("/docs/assets/{version}/swagger-ui-bundle.js")))
            .header("if-none-match", etag)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 304);
        assert_eq!(
            server
                .get(&format!("/docs/assets/{version}/init.js"))
                .await
                .status(),
            200
        );

        // Nothing outside the fixed table: dots, encodings, backslashes.
        for path in [
            format!("/docs/assets/{version}/../../nitr.toml"),
            format!("/docs/assets/{version}/%2e%2e/%2e%2e/nitr.toml"),
            format!("/docs/assets/{version}/..%5c..%5cnitr.toml"),
            format!("/docs/assets/{version}/swagger-ui-bundle.js/"),
            "/docs/assets/0.0.0/swagger-ui-bundle.js".to_string(),
            "/docs/".to_string(),
            "/docs/index.html".to_string(),
        ] {
            let resp = server.client().get(server.url(&path)).send().await.unwrap();
            assert_eq!(resp.status(), 404, "{path}");
        }
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn page_settings_are_validated_and_the_document_is_needed() {
        for (needle, tune) in [
            (
                "needs the document it renders",
                Box::new(|cfg: &mut nitr::Config| cfg.swagger.enabled = true)
                    as Box<dyn Fn(&mut nitr::Config)>,
            ),
            (
                "may not set `url`",
                Box::new(|cfg: &mut nitr::Config| {
                    cfg.openapi.enabled = true;
                    cfg.swagger.enabled = true;
                    cfg.swagger
                        .options
                        .insert("url".into(), toml::Value::String("https://evil/x".into()));
                }),
            ),
            (
                "is the typed setting [swagger] try_it_out",
                Box::new(|cfg: &mut nitr::Config| {
                    cfg.openapi.enabled = true;
                    cfg.swagger.enabled = true;
                    cfg.swagger
                        .options
                        .insert("tryItOutEnabled".into(), toml::Value::Boolean(true));
                }),
            ),
            (
                "is on another origin",
                Box::new(|cfg: &mut nitr::Config| {
                    cfg.openapi.enabled = true;
                    cfg.swagger.enabled = true;
                    cfg.swagger.spec_url = Some("https://other.example/spec.json".into());
                }),
            ),
            (
                "overlap",
                Box::new(|cfg: &mut nitr::Config| {
                    cfg.openapi.enabled = true;
                    cfg.swagger.enabled = true;
                    cfg.openapi.path = "/docs/openapi.json".into();
                }),
            ),
            (
                "is a [health] probe path",
                Box::new(|cfg: &mut nitr::Config| {
                    cfg.openapi.enabled = true;
                    cfg.openapi.path = "/healthz".into();
                }),
            ),
        ] {
            let mut builder = TestServer::builder("swagger-cfg").handler(APP).config(tune);
            let err = builder.try_build().await.expect_err(needle).to_string();
            assert!(err.contains(needle), "{err}");
        }
        // An allowed external document widens the policy to that origin.
        let mut server = TestServer::builder("swagger-ext")
            .handler(APP)
            .config(|cfg| {
                cfg.swagger.enabled = true;
                cfg.swagger.spec_url = Some("https://specs.example.com/api.json".into());
                cfg.swagger.allow_external_spec = true;
            })
            .spawn()
            .await;
        let resp = server.get("/docs").await;
        assert_eq!(resp.status(), 200);
        let csp = resp.headers()["content-security-policy"].to_str().unwrap();
        assert!(
            csp.contains("connect-src 'self' https://specs.example.com;"),
            "{csp}"
        );
        assert_eq!(server.get("/openapi.json").await.status(), 404);
        server.stop().await;
    }
}
