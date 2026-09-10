// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for route `input` validation: bodies (JSON, form,
//! multipart, raw), query strings, path parameters and headers checked in
//! Rust before the handler; the 422 shape and the `on_invalid` hooks;
//! the bounds and the upload spool.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use harness::TestServer;

const APP: &str = r#"
local S = nitr.validate

local NoteInput = S.schema({
    text = { "string|trim|min_len:1|max_len:20|required", messages = { max_len = "Keep it under {max}" } },
    tags = { "array|max_items:3|unique", items = "string|format:slug" },
    priority = "integer|min:1|max:5|default:3",
    email = { "string|format:email", transform = function(s) return s:lower() end },
    pw = { "string|min_len:4", description = "not common", check = function(s) return s ~= "hunter22", "is too common" end },
}, { title = "NoteInput" })

local app = nitr.app()

app:use(function(next)
    return function(req)
        if req.headers["x-auth"] == "deny" then
            return { status = 401, body = "nope" }
        end
        return next(req)
    end
end)

app:post("/notes", function(req)
    local n = req.valid.body
    -- The raw body is still readable after validation.
    local again = req:json()
    return nitr.json({ ok = true, text = n.text, priority = n.priority, email = n.email,
                       tags = n.tags, raw_text = again.text, strict = req.valid.query and req.valid.query.dry })
end, {
    input = {
        body = NoteInput,
        query = { dry = "boolean|default:false" },
        headers = { ["x-team"] = { "array", items = "string|format:alpha_dash" } },
    },
})

app:post("/strict", function(req)
    return nitr.json({ ok = true })
end, { input = { body = { a = "string" }, strict = true } })

app:get("/items/:id", function(req)
    return nitr.json({ id = req.valid.params.id, limit = req.valid.query.limit, tags = req.valid.query.tags })
end, {
    input = {
        params = { id = "integer|min:1" },
        query = { limit = "integer|min:1|max:100|default:20", tags = { "array|max_items:2", items = "string" } },
    },
})

app:post("/form", function(req)
    local f = req.valid.body
    return nitr.json({ name = f.name, age = f.age, news = f.news, tags = f.tags, form = req:form().name })
end, { input = { body = { schema = { name = "string|trim|required", age = "integer|min:13", news = "boolean|default:false", tags = { "array", items = "string" } }, content = { "form" } } } })

app:post("/hooked", function(req)
    return nitr.json({ ok = true })
end, {
    input = { body = { a = "string|required" } },
    on_invalid = function(err, req)
        return nitr.error(400, { custom = true, first = err.errors[1].rule, path = req.path })
    end,
})

app:post("/broken", function(req)
    return nitr.json({ ok = true })
end, {
    input = { body = { a = { "string", description = "boom", check = function() error("check bug") end } } },
})

app:get("/plain", function(req)
    return nitr.json({ valid = req.valid })
end)

app:post("/html", function(req)
    return nitr.json({ ok = true })
end, { input = { body = { a = { "string|max_len:2", message = "<b>too long</b> & \"quoted\"" } } } })

app:post("/many", function(req)
    return nitr.json({ n = #req.valid.body.items })
end, {
    input = { body = { items = { "array", items = { "integer", description = "slow",
        check = function(v) local s = 0 for i = 1, 200000 do s = s + i end return true end } } } },
})

app:get("/bytes", function(req)
    return nitr.json({ tags = req.valid.query.tags, q = req.valid.query.q })
end, { input = { query = { tags = { "array", items = "string|format:slug" }, q = "string" } } })

app:on_error(function(err, req)
    return nitr.error(500, { code = "HANDLER", kind = err.kind, message = err.message })
end)

return app
"#;

async fn post_json(server: &TestServer, path: &str, body: &str) -> (u16, serde_json::Value) {
    let resp = server
        .client()
        .post(server.url(path))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("post");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    let json = serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "raw": text }));
    (status, json)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_json_body_reaches_the_handler_typed_and_normalized() {
    let mut server = TestServer::builder("validation").handler(APP).spawn().await;
    let (status, json) = post_json(
        &server,
        "/notes?dry=on",
        r#"{"text":"  hi  ","tags":["a","b"],"email":"Ada@X.IO","role":"admin"}"#,
    )
    .await;
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["text"], "hi");
    assert_eq!(json["priority"], 3);
    assert_eq!(json["email"], "ada@x.io");
    assert_eq!(json["tags"], serde_json::json!(["a", "b"]));
    // `req:json()` still sees the original body.
    assert_eq!(json["raw_text"], "  hi  ");
    assert_eq!(json["strict"], true);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_body_answers_422_with_fields_and_rule_codes_before_any_lua() {
    let mut server = TestServer::builder("validation").handler(APP).spawn().await;
    let (status, json) = post_json(
        &server,
        "/notes",
        r#"{"text":"this is far too long for the rule","tags":["Bad Tag","x","x"],"pw":"hunter22"}"#,
    )
    .await;
    assert_eq!(status, 422, "{json}");
    assert_eq!(json["code"], "VALIDATION_FAILED");
    assert_eq!(json["message"], "validation failed");
    assert_eq!(json["fields"]["body.text"], "Keep it under 20");
    assert_eq!(json["fields"]["body.tags"], "must not contain duplicates");
    assert_eq!(json["fields"]["body.pw"], "is too common");
    let errors = json["errors"].as_array().expect("errors");
    assert_eq!(errors[0]["path"], "body.pw");
    assert_eq!(errors[0]["rule"], "check");
    assert_eq!(errors[1]["path"], "body.tags");
    assert_eq!(errors[2]["path"], "body.tags[1]");
    assert_eq!(errors[2]["rule"], "format");
    assert_eq!(errors[2]["field"], "tags");
    assert_eq!(errors[3]["rule"], "max_len");
    assert_eq!(errors[3]["params"]["max"], 20);
    assert_eq!(errors[3]["part"], "body");
    assert_eq!(errors[3]["field"], "text");

    // Malformed JSON is a body-level failure, not a 400 from elsewhere.
    let (status, json) = post_json(&server, "/notes", "{oops").await;
    assert_eq!(status, 422);
    assert_eq!(json["fields"]["body"], "must be valid JSON");
    assert_eq!(json["errors"][0]["rule"], "json");

    // An empty body is an empty object: the required field is named.
    let (status, json) = post_json(&server, "/notes", "").await;
    assert_eq!(status, 422);
    assert_eq!(json["fields"]["body.text"], "is required");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn validation_runs_before_middleware_and_only_for_declared_routes() {
    let mut server = TestServer::builder("validation").handler(APP).spawn().await;
    // The auth middleware would answer 401, but validation comes first.
    let resp = server
        .client()
        .post(server.url("/notes"))
        .header("content-type", "application/json")
        .header("x-auth", "deny")
        .body("{}")
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 422);
    // A valid body then meets the middleware.
    let resp = server
        .client()
        .post(server.url("/notes"))
        .header("content-type", "application/json")
        .header("x-auth", "deny")
        .body(r#"{"text":"x"}"#)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 401);
    // A route without `input` has no `req.valid`.
    let json = server.json("/plain").await;
    assert!(json["valid"].is_null());
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_media_types_get_a_415_naming_the_accepted_ones() {
    let mut server = TestServer::builder("validation").handler(APP).spawn().await;
    let resp = server
        .client()
        .post(server.url("/notes"))
        .header("content-type", "text/plain")
        .body("hello")
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 415);
    assert_eq!(
        resp.headers().get("accept").and_then(|v| v.to_str().ok()),
        Some("application/json, application/x-www-form-urlencoded")
    );
    let json: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(json["code"], "UNSUPPORTED_MEDIA_TYPE");
    // A form-only route refuses JSON.
    let resp = server
        .client()
        .post(server.url("/form"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 415);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn query_params_and_headers_are_coerced_and_bounded() {
    let mut server = TestServer::builder("validation").handler(APP).spawn().await;
    let json = server.json("/items/7?tags=a&tags[]=b").await;
    assert_eq!(json["id"], 7);
    assert_eq!(json["limit"], 20);
    assert_eq!(json["tags"], serde_json::json!(["a", "b"]));

    let resp = server
        .get("/items/abc?limit=500&tags=a&tags=b&tags=c")
        .await;
    assert_eq!(resp.status(), 422);
    let json: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(json["fields"]["params.id"], "must be an integer");
    assert_eq!(json["fields"]["query.limit"], "must be at most 100");
    assert_eq!(json["fields"]["query.tags"], "must have at most 2 items");
    assert_eq!(json["errors"][0]["part"], "params");

    // Repeated header lines collect into an array rule; a bad line fails
    // with the header's path.
    let resp = server
        .client()
        .post(server.url("/notes"))
        .header("content-type", "application/json")
        .header("x-team", "core")
        .header("x-team", "bad team")
        .body(r#"{"text":"x"}"#)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 422);
    let json: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        json["fields"]["headers.x-team[2]"],
        "must be letters, digits, hyphens or underscores"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn html_forms_coerce_blanks_checkboxes_and_bracketed_names() {
    let mut server = TestServer::builder("validation").handler(APP).spawn().await;
    let post = |body: &'static str| {
        server
            .client()
            .post(server.url("/form"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
    };
    let resp = post("name=+Ada+&age=&news=on&tags%5B%5D=a&tags%5B%5D=b")
        .await
        .expect("post");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(json["name"], "Ada");
    assert!(json["age"].is_null(), "a blank integer is absent");
    assert_eq!(json["news"], true);
    assert_eq!(json["tags"], serde_json::json!(["a", "b"]));
    // `req:form()` still works from the cached body.
    assert_eq!(json["form"], " Ada ");

    // A blank string is a value (`min_len` would decide); a number below
    // its bound is named.
    let resp = post("name=&age=12").await.expect("post");
    assert_eq!(resp.status(), 422);
    let json: serde_json::Value = resp.json().await.expect("json");
    assert!(json["fields"]["body.name"].is_null(), "{json}");
    assert_eq!(json["fields"]["body.age"], "must be at least 13");
    // Absent altogether is what `required` refuses.
    let resp = post("age=20").await.expect("post");
    let json: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(json["fields"]["body.name"], "is required");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_routes_report_unknown_fields() {
    let mut server = TestServer::builder("validation").handler(APP).spawn().await;
    let (status, json) = post_json(&server, "/strict", r#"{"a":"x","titel":1}"#).await;
    assert_eq!(status, 422, "{json}");
    assert_eq!(json["fields"]["body.titel"], "is not a known field");
    assert_eq!(json["errors"][0]["rule"], "unknown");
    let (status, _) = post_json(&server, "/strict", r#"{"a":"x"}"#).await;
    assert_eq!(status, 200);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn on_invalid_hooks_shape_the_response_and_bugs_stay_500() {
    let mut server = TestServer::builder("validation").handler(APP).spawn().await;
    let (status, json) = post_json(&server, "/hooked", "{}").await;
    assert_eq!(status, 400, "{json}");
    assert_eq!(json["custom"], true);
    assert_eq!(json["first"], "required");
    assert_eq!(json["path"], "/hooked");

    // A check that raises is a handler error, never a 422.
    let (status, json) = post_json(&server, "/broken", r#"{"a":"x"}"#).await;
    assert_eq!(status, 500, "{json}");
    assert_eq!(json["code"], "HANDLER");
    assert!(
        json["message"]
            .as_str()
            .unwrap_or_default()
            .contains("check bug")
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_validated_body_is_a_413_not_a_422() {
    let mut server = TestServer::builder("validation")
        .handler(APP)
        .config(|cfg| cfg.limits.max_body_bytes = 64)
        .spawn()
        .await;
    let big = format!(r#"{{"text":"x","tags":["{}"]}}"#, "a".repeat(200));
    let resp = server
        .client()
        .post(server.url("/notes"))
        .header("content-type", "application/json")
        .body(big)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 413);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn app_wide_messages_are_frozen_once_the_application_compiled() {
    let app = r#"
local app = nitr.app()
nitr.validate.messages({ required = "Required!" })
app:post("/x", function(req) return nitr.json({}) end, { input = { body = { a = "string|required" } } })
app:get("/late", function(req)
    nitr.validate.messages({ required = "changed" })
    return nitr.json({})
end)
app:on_error(function(err, req) return nitr.error(500, { message = err.message }) end)
return app
"#;
    let mut server = TestServer::builder("validation").handler(app).spawn().await;
    let resp = server.get("/late").await;
    assert_eq!(resp.status(), 500);
    let json: serde_json::Value = resp.json().await.expect("json");
    assert!(
        json["message"]
            .as_str()
            .unwrap_or_default()
            .contains("must be called at load"),
        "{json}"
    );
    // The wording set at load still applies afterwards.
    let (status, json) = post_json(&server, "/x", "{}").await;
    assert_eq!(status, 422);
    assert_eq!(json["fields"]["body.a"], "Required!");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_input_declaration_refuses_to_boot_naming_the_route() {
    let bad = r#"
local app = nitr.app()
app:get("/x/:id", function(req) return nitr.json({}) end, {
    input = { params = { other = "integer" } },
})
return app
"#;
    let err = TestServer::builder("validation")
        .handler(bad)
        .try_build()
        .await
        .expect_err("must not build")
        .to_string();
    assert!(err.contains("route `GET /x/:id`"), "{err}");
    assert!(err.contains("does not capture"), "{err}");

    let typo = r#"
local app = nitr.app()
app:post("/x", function(req) return nitr.json({}) end, {
    input = { body = { a = "string|min_len" } },
})
return app
"#;
    let err = TestServer::builder("validation")
        .handler(typo)
        .try_build()
        .await
        .expect_err("must not build")
        .to_string();
    assert!(err.contains("needs a value"), "{err}");
}

#[cfg(feature = "multipart")]
mod uploads {
    use super::*;

    const UPLOAD_APP: &str = r#"
local S = nitr.validate
local app = nitr.app()

app:post("/profile", function(req)
    local p = req.valid.body
    local saved = p.avatar and p.avatar:save("avatars/" .. p.avatar.safe_filename)
    local docs = {}
    for i, d in ipairs(p.docs or {}) do
        docs[i] = { type = d.content_type, size = d.size, ext = d.extension, sha = d:hash() }
    end
    return nitr.json({ name = p.name, saved = saved, width = p.avatar and p.avatar.width,
                       type = p.avatar and p.avatar.content_type, docs = docs,
                       csv = p.data and p.data:text() })
end, {
    input = { body = { schema = {
        name = "string|trim|required",
        avatar = S.image({ max_bytes = "1mb", max_width = 4000 }),
        docs = { "array|max_items:3", items = S.document({ max_bytes = "1mb" }) },
        data = S.text_file({ types = { "text/csv" }, max_bytes = "64kb" }),
    }, content = { "multipart", "json" } } },
})

app:put("/blob", function(req)
    local f = req.valid.body
    return nitr.json({ type = f.content_type, size = f.size, name = f.filename, saved = f:save("blobs/" .. (f.safe_filename or "blob.bin")) })
end, { input = { body = { file = S.archive({ max_bytes = "1mb" }), content = { "raw" } } } })

app:post("/legacy", function(req)
    local n = req:multipart(function(part) part:discard() end)
    return nitr.json({ parts = n })
end, { input = { body = { schema = { name = "string" }, content = { "multipart" } } } })

app:post("/vector", function(req)
    local f = req.valid.body.file
    return nitr.json({ type = f and f.content_type })
end, { input = { body = { schema = { file = "file|max_bytes:64kb|types:image/*" }, content = { "multipart" } } } })

app:post("/vector-named", function(req)
    local f = req.valid.body.file
    return nitr.json({ type = f and f.content_type })
end, { input = { body = { schema = { file = "file|max_bytes:64kb|types:image/svg+xml" }, content = { "multipart" } } } })

app:put("/octet", function(req)
    local f = req.valid.body
    return nitr.json({ type = f.content_type, size = f.size })
end, { input = { body = { file = { type = "file", types = { "application/octet-stream" }, max_bytes = "1mb" }, content = { "raw" } } } })

app:post("/hang", function(req)
    while true do end
end, { input = { body = { schema = { avatar = S.image({ max_bytes = "1mb" }) }, content = { "multipart" } } } })

app:on_error(function(err, req)
    return nitr.error(500, { code = "HANDLER", kind = err.kind, message = err.message })
end)

return app
"#;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x01\0\0\0\x00\x80\x08\x06\0\0\0";

    /// Builds a multipart body by hand: no client dependency, and the
    /// browser edge cases (an empty file input) need exact control.
    /// One part: field name, filename, content type, bytes.
    type Part<'a> = (&'a str, Option<&'a str>, Option<&'a str>, &'a [u8]);

    fn multipart(parts: &[Part<'_>]) -> (String, Vec<u8>) {
        let boundary = "----nitrtest7f3a";
        let mut body = Vec::new();
        for (name, filename, content_type, data) in parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            match filename {
                Some(f) => body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n"
                    )
                    .as_bytes(),
                ),
                None => body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n").as_bytes(),
                ),
            }
            if let Some(ct) = content_type {
                body.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        (format!("multipart/form-data; boundary={boundary}"), body)
    }

    async fn post_multipart(
        server: &TestServer,
        path: &str,
        parts: &[Part<'_>],
    ) -> (u16, serde_json::Value) {
        let (content_type, body) = multipart(parts);
        let resp = server
            .client()
            .post(server.url(path))
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .expect("post");
        let status = resp.status().as_u16();
        let text = resp.text().await.expect("body");
        let json =
            serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "raw": text }));
        (status, json)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn declared_files_spool_validate_and_save_while_undeclared_ones_are_dropped() {
        let mut server = TestServer::builder("validation-upload")
            .upload_dir()
            .handler(UPLOAD_APP)
            .config(|cfg| cfg.dev_mode = true)
            .spawn()
            .await;
        std::fs::create_dir_all(server.dir().join("uploads/avatars")).expect("mkdir");
        let csv = b"id,name\n1,ada\n";
        let (status, json) = post_multipart(
            &server,
            "/profile",
            &[
                ("name", None, None, b" Ada "),
                ("avatar", Some("me.png"), Some("image/png"), PNG),
                (
                    "docs",
                    Some("a.pdf"),
                    Some("application/pdf"),
                    b"%PDF-1.7 hello",
                ),
                ("data", Some("d.csv"), Some("text/csv"), csv),
                (
                    "sneaky",
                    Some("x.exe"),
                    Some("application/octet-stream"),
                    b"MZ\x90\0",
                ),
                ("empty", Some(""), Some("application/octet-stream"), b""),
            ],
        )
        .await;
        assert_eq!(status, 200, "{json}");
        assert_eq!(json["name"], "Ada");
        assert_eq!(json["width"], 256);
        assert_eq!(json["type"], "image/png");
        assert_eq!(json["docs"][0]["type"], "application/pdf");
        assert_eq!(json["docs"][0]["ext"], "pdf");
        assert_eq!(json["docs"][0]["size"], 14);
        assert_eq!(json["docs"][0]["sha"].as_str().map(str::len), Some(64));
        assert_eq!(json["csv"], "id,name\n1,ada\n");
        let saved = json["saved"].as_str().expect("saved path");
        assert!(std::path::Path::new(saved).is_file(), "{saved}");
        assert!(under(saved, &server.dir().join("uploads")), "{saved}");
        // Only the saved file remains under the upload root: the docs and
        // csv temporaries go with the request (removed off the request
        // thread, so poll briefly), the sneaky exe was never stored.
        let uploads = server.dir().join("uploads");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let names = loop {
            let mut names: Vec<String> = walk(&uploads)
                .into_iter()
                .map(|p| rel(&p, &uploads))
                .collect();
            names.sort();
            if names.iter().all(|n| !n.starts_with(".nitr-tmp"))
                || std::time::Instant::now() > deadline
            {
                break names;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        assert_eq!(names, vec!["avatars/me.png"], "{names:?}");
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn files_are_judged_by_their_bytes_not_their_headers() {
        let mut server = TestServer::builder("validation-upload")
            .upload_dir()
            .handler(UPLOAD_APP)
            .spawn()
            .await;
        // A PHP file wearing a PNG label and name.
        let (status, json) = post_multipart(
            &server,
            "/profile",
            &[
                ("name", None, None, b"x"),
                (
                    "avatar",
                    Some("shell.png"),
                    Some("image/png"),
                    b"<?php echo 1;",
                ),
            ],
        )
        .await;
        assert_eq!(status, 422, "{json}");
        assert_eq!(
            json["fields"]["body.avatar"],
            "must be an image (png, jpg, gif, webp, bmp)"
        );
        assert_eq!(json["errors"][0]["rule"], "types");

        // An executable is refused even where `*/*`-like presets allow
        // much; a PNG declared as text/plain is still a PNG.
        let (status, json) = post_multipart(
            &server,
            "/profile",
            &[
                ("name", None, None, b"x"),
                ("avatar", Some("me.png"), Some("text/plain"), PNG),
                (
                    "docs",
                    Some("evil.pdf"),
                    Some("application/pdf"),
                    b"MZ\x90\0\x03",
                ),
            ],
        )
        .await;
        assert_eq!(status, 422, "{json}");
        assert_eq!(json["fields"]["body.docs[1]"], "must not be an executable");
        assert!(json["fields"]["body.avatar"].is_null(), "{json}");

        // A text upload that is not UTF-8 fails the text_file preset.
        let (status, json) = post_multipart(
            &server,
            "/profile",
            &[
                ("name", None, None, b"x"),
                ("data", Some("d.csv"), Some("text/csv"), b"\xFF\xFEid,name"),
            ],
        )
        .await;
        assert_eq!(status, 422, "{json}");
        assert_eq!(json["fields"]["body.data"], "must be a CSV file");
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_raw_body_is_one_validated_file() {
        let mut server = TestServer::builder("validation-upload")
            .upload_dir()
            .handler(UPLOAD_APP)
            .config(|cfg| cfg.dev_mode = true)
            .spawn()
            .await;
        std::fs::create_dir_all(server.dir().join("uploads/blobs")).expect("mkdir");
        let gz = b"\x1F\x8B\x08\0\0\0\0\0\0\x03hello";
        let resp = server
            .client()
            .put(server.url("/blob"))
            .header("content-type", "application/octet-stream")
            .header(
                "content-disposition",
                "attachment; filename=\"backup.tar.gz\"",
            )
            .body(gz.to_vec())
            .send()
            .await
            .expect("put");
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.expect("json");
        assert_eq!(json["type"], "application/gzip");
        assert_eq!(json["size"], gz.len());
        assert_eq!(json["name"], "backup.tar.gz");
        // `save` returns the native path: compare by components, not by
        // separator (a `/` literal fails on Windows).
        assert!(
            std::path::Path::new(json["saved"].as_str().unwrap())
                .ends_with(std::path::Path::new("blobs").join("backup.tar.gz")),
            "{}",
            json["saved"]
        );

        let resp = server
            .client()
            .put(server.url("/blob"))
            .body(b"%PDF-1.4 not an archive".to_vec())
            .send()
            .await
            .expect("put");
        assert_eq!(resp.status(), 422);
        let json: serde_json::Value = resp.json().await.expect("json");
        assert_eq!(json["errors"][0]["path"], "body");
        assert_eq!(json["errors"][0]["rule"], "types");
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_validated_route_cannot_also_stream_the_multipart_body() {
        let mut server = TestServer::builder("validation-upload")
            .upload_dir()
            .handler(UPLOAD_APP)
            .spawn()
            .await;
        let (status, json) =
            post_multipart(&server, "/legacy", &[("name", None, None, b"x")]).await;
        assert_eq!(status, 500, "{json}");
        server.stop().await;
    }

    /// Leftovers of a crashed process are swept at startup, before the
    /// first upload could collide with them.
    #[tokio::test(flavor = "multi_thread")]
    async fn stale_spools_are_swept_at_startup() {
        let builder = TestServer::builder("validation-upload")
            .upload_dir()
            .handler(UPLOAD_APP);
        let stale = builder.dir().join("uploads/.nitr-tmp/dead-request/1");
        std::fs::create_dir_all(stale.parent().unwrap()).expect("mkdir");
        std::fs::write(&stale, b"leftover").expect("write");
        let mut server = builder.spawn().await;
        assert!(!stale.exists(), "the stale spool must be gone after boot");
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_rules_need_the_upload_root_at_load() {
        let err = TestServer::builder("validation-upload")
            .handler(UPLOAD_APP)
            .try_build()
            .await
            .expect_err("must not build")
            .to_string();
        assert!(err.contains("[multipart] upload_dir"), "{err}");
    }

    /// The shapes a browser's `FormData` produces that a hand-written
    /// client never would (F27): `append("photo", blob)` names the file
    /// `blob`, `file.type === ""` sends no part type, an empty
    /// `<input type=file>` sends an empty part with an empty filename,
    /// and filenames are whatever the OS allowed.
    #[tokio::test(flavor = "multi_thread")]
    async fn browser_form_data_shapes_are_handled() {
        let mut server = TestServer::builder("validation-upload")
            .upload_dir()
            .handler(UPLOAD_APP)
            .spawn()
            .await;
        std::fs::create_dir_all(server.dir().join("uploads/avatars")).expect("mkdir");

        // `formData.append("avatar", blob)`: the filename is `blob`.
        let (status, json) = post_multipart(
            &server,
            "/profile",
            &[
                ("name", None, None, b"Ada"),
                (
                    "avatar",
                    Some("blob"),
                    Some("application/octet-stream"),
                    PNG,
                ),
            ],
        )
        .await;
        assert_eq!(status, 422, "{json}");
        assert_eq!(json["errors"][0]["rule"], "extensions", "{json}");

        // `file.type === ""`: no part Content-Type; the bytes decide.
        let (status, json) = post_multipart(
            &server,
            "/profile",
            &[
                ("name", None, None, b"Ada"),
                ("avatar", Some("me.png"), None, PNG),
            ],
        )
        .await;
        assert_eq!(status, 200, "{json}");
        assert_eq!(json["type"], "image/png");

        // An empty `<input type=file>`: empty filename, empty body → absent.
        let (status, json) = post_multipart(
            &server,
            "/profile",
            &[
                ("name", None, None, b"Ada"),
                ("avatar", Some(""), Some("application/octet-stream"), b""),
            ],
        )
        .await;
        assert_eq!(status, 200, "{json}");
        assert!(json["saved"].is_null(), "{json}");

        // Names the OS allowed: long, traversing, with separators or a
        // right-to-left override. Each is reduced to one safe segment.
        let long = format!("{}.png", "a".repeat(4000));
        for name in [
            long.as_str(),
            "../../evil.png",
            "a/b\\c.png",
            "\u{202E}gnp.exe.png",
            " photo .png ",
        ] {
            let (status, json) = post_multipart(
                &server,
                "/profile",
                &[
                    ("name", None, None, b"Ada"),
                    ("avatar", Some(name), Some("image/png"), PNG),
                ],
            )
            .await;
            assert_eq!(status, 200, "{name:?}: {json}");
            let saved = json["saved"].as_str().expect("saved path");
            let saved_path = std::path::Path::new(saved);
            assert!(
                under(saved, &server.dir().join("uploads").join("avatars")),
                "{name:?} saved at {saved}"
            );
            let base = saved_path.file_name().unwrap().to_string_lossy();
            assert!(base.len() <= 255, "{name:?} → {} bytes", base.len());
            for forbidden in ["..", "/", "\\", "\u{202E}"] {
                assert!(!base.contains(forbidden), "{name:?} → {base}");
            }
            assert!(base.ends_with(".png"), "{name:?} → {base}");
        }

        // A NUL in a part header is not a multipart body at all: a 422 on
        // the body itself (the `multipart` rule), never a 500, and nothing
        // spooled.
        let (content_type, mut body) = multipart(&[("name", None, None, b"Ada")]);
        let boundary = content_type.split("boundary=").nth(1).unwrap().to_string();
        let tail = format!("--{boundary}--\r\n");
        body.truncate(body.len() - tail.len());
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"avatar\"; filename=\"a\0b.png\"\r\nContent-Type: image/png\r\n\r\n");
        body.extend_from_slice(PNG);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let resp = server
            .client()
            .post(server.url("/profile"))
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .expect("post");
        let status = resp.status().as_u16();
        let text = resp.text().await.expect("body");
        assert_eq!(status, 422, "{text}");
        let json: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(json["errors"][0]["rule"], "multipart", "{text}");
        assert_eq!(json["errors"][0]["path"], "body", "{text}");
        let left = spool_leftovers(&server.dir().join("uploads/.nitr-tmp")).await;
        assert!(left.is_empty(), "left behind after a 422: {left:?}");
        server.stop().await;
    }

    /// Temporaries never outlive their request (F7): a client that
    /// disconnects mid-upload, and a handler that times out after the
    /// upload validated, both leave `.nitr-tmp` empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn temporaries_are_removed_on_disconnect_and_on_handler_timeout() {
        use tokio::io::AsyncWriteExt;
        let mut server = TestServer::builder("validation-upload")
            .upload_dir()
            .handler(UPLOAD_APP)
            .config(|cfg| {
                cfg.workers = 1;
                cfg.lua.exec_timeout_ms = 500;
                cfg.limits.pool_wait_ms = 500;
                cfg.limits.body_read_ms = 300;
            })
            .spawn()
            .await;
        let tmp = server.dir().join("uploads/.nitr-tmp");

        // Headers, the name part, and the first bytes of a file part —
        // then the socket closes.
        let (content_type, full) = multipart(&[
            ("name", None, None, b"Ada"),
            (
                "avatar",
                Some("me.png"),
                Some("image/png"),
                &[PNG, &[0u8; 4096]].concat(),
            ),
        ]);
        let cut = full.len() - 2048;
        let mut sock = tokio::net::TcpStream::connect(server.addr())
            .await
            .expect("connect");
        sock.write_all(
            format!(
                "POST /profile HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
                full.len()
            )
            .as_bytes(),
        )
        .await
        .expect("write headers");
        sock.write_all(&full[..cut])
            .await
            .expect("write partial body");
        drop(sock);
        // The read guard notices within `body_read_ms`; the guard's Drop
        // removes the directory.
        let left = spool_leftovers(&tmp).await;
        assert!(left.is_empty(), "left behind after a disconnect: {left:?}");

        // A handler that spins after a valid upload: the budget answers
        // 500, and the temporaries go with the request.
        let (status, json) = post_multipart(
            &server,
            "/hang",
            &[("avatar", Some("me.png"), Some("image/png"), PNG)],
        )
        .await;
        assert_eq!(status, 500, "{json}");
        assert_eq!(json["kind"], "timeout", "{json}");
        let left = spool_leftovers(&tmp).await;
        assert!(left.is_empty(), "left behind after a timeout: {left:?}");

        // And the state is fine.
        let (status, _) =
            post_multipart(&server, "/profile", &[("name", None, None, b"Ada")]).await;
        assert_eq!(status, 200);
        server.stop().await;
    }

    /// `file:text()` is bounded by `[limits] max_field_bytes` (F13): a
    /// bigger file raises with the limit named, never fills the heap.
    #[tokio::test(flavor = "multi_thread")]
    async fn file_text_refuses_above_the_field_limit() {
        let mut server = TestServer::builder("validation-upload")
            .upload_dir()
            .handler(UPLOAD_APP)
            .config(|cfg| cfg.limits.max_field_bytes = 1024)
            .spawn()
            .await;
        let csv = "id,name\n".repeat(300);
        let (status, json) = post_multipart(
            &server,
            "/profile",
            &[
                ("name", None, None, b"Ada"),
                ("data", Some("rows.csv"), Some("text/csv"), csv.as_bytes()),
            ],
        )
        .await;
        assert_eq!(status, 500, "{json}");
        let message = json["message"].as_str().unwrap_or_default();
        assert!(message.contains("max_field_bytes"), "{json}");
        assert!(message.contains("1024"), "{json}");
        server.stop().await;
    }

    /// An SVG is active content (F24): `image/*` never matches it, only a
    /// rule naming `image/svg+xml` takes it, and the `image` preset does
    /// not.
    #[tokio::test(flavor = "multi_thread")]
    async fn svg_is_only_accepted_by_name() {
        let mut server = TestServer::builder("validation-upload")
            .upload_dir()
            .handler(UPLOAD_APP)
            .spawn()
            .await;
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
        let part: Part<'_> = ("file", Some("logo.svg"), Some("image/svg+xml"), svg);
        let (status, json) = post_multipart(&server, "/vector", &[part]).await;
        assert_eq!(status, 422, "{json}");
        assert_eq!(json["errors"][0]["rule"], "types");
        let (status, json) = post_multipart(&server, "/vector-named", &[part]).await;
        assert_eq!(status, 200, "{json}");
        assert_eq!(json["type"], "image/svg+xml");
        let (status, json) = post_multipart(
            &server,
            "/profile",
            &[
                ("name", None, None, b"Ada"),
                ("avatar", Some("logo.svg"), Some("image/svg+xml"), svg),
            ],
        )
        .await;
        assert_eq!(status, 422, "{json}");
        server.stop().await;
    }

    /// A blob with no detectable family (F26): the declared header counts
    /// only when the rule names that header; a detectable type claimed
    /// by header alone is not believed.
    #[tokio::test(flavor = "multi_thread")]
    async fn undetectable_blobs_follow_the_declared_header_only_when_named() {
        let mut server = TestServer::builder("validation-upload")
            .upload_dir()
            .handler(UPLOAD_APP)
            .spawn()
            .await;
        std::fs::create_dir_all(server.dir().join("uploads/blobs")).expect("mkdir");
        let blob: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        for (path, declared, expected) in [
            ("/octet", "application/octet-stream", 200),
            ("/octet", "application/zip", 200),
            ("/blob", "application/zip", 422),
            ("/blob", "application/octet-stream", 422),
        ] {
            let resp = server
                .client()
                .put(server.url(path))
                .header("content-type", declared)
                .body(blob.clone())
                .send()
                .await
                .expect("put");
            let status = resp.status().as_u16();
            let text = resp.text().await.expect("body");
            assert_eq!(status, expected, "{path} as {declared}: {text}");
            if expected == 200 {
                let json: serde_json::Value = serde_json::from_str(&text).expect("json");
                assert_eq!(json["type"], "application/octet-stream", "{text}");
            } else {
                assert!(text.contains("\"rule\":\"types\""), "{text}");
            }
        }
        server.stop().await;
    }

    /// Whether `saved` (what `save` returns: the canonical location) lies
    /// under `root` (a harness path, not canonical). Both sides are
    /// canonicalized first: on macOS the temp dir `/var/…` is a symlink to
    /// `/private/var/…`, on Windows it may carry an 8.3 short name, so a
    /// plain `starts_with` against the harness path fails there.
    fn under(saved: &str, root: &std::path::Path) -> bool {
        let saved = std::path::Path::new(saved)
            .canonicalize()
            .expect("the saved file exists");
        let root = root.canonicalize().expect("the root exists");
        saved.starts_with(root)
    }

    /// A path relative to `root`, spelled with `/` whatever the host
    /// separator is, so a test can compare it with a literal. Native
    /// paths (what `save` returns, what `walk` yields) must never be
    /// compared as strings against a `/`-spelled literal: that passes on
    /// Linux and fails on Windows.
    fn rel(path: &std::path::Path, root: &std::path::Path) -> String {
        path.strip_prefix(root)
            .expect("under the root")
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// The files still under `dir` once the spool has had time to go.
    /// `SpoolDir`'s Drop removes the directory on a blocking thread, so
    /// the response can reach the client a moment before the files are
    /// gone — noticeably on Windows CI. Empty means the spool was removed.
    async fn spool_leftovers(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut left = walk(dir);
        for _ in 0..100 {
            if left.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            left = walk(dir);
        }
        left
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    out.extend(walk(&path));
                } else {
                    out.push(path);
                }
            }
        }
        out
    }
}

/// The adversarial rows of the phase: what a client can learn from a 422,
/// what it can cost, and what a buggy check can do to the state.
mod adversarial {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Every value below fails a rule in some part of the request; none may
    /// come back in the 422 body — messages describe the rule, never the
    /// input (V14).
    #[tokio::test(flavor = "multi_thread")]
    async fn errors_never_echo_the_rejected_values() {
        let mut server = TestServer::builder("validation").handler(APP).spawn().await;
        let sentinels = [
            "SENTINEL_TEXT_THAT_IS_FAR_TOO_LONG",
            "SENTINEL TAG",
            "4242",
            "SENTINEL@BAD",
            "SENTINELQ",
            "SENTINEL H!",
            "hunter22",
        ];
        let resp = server
            .client()
            .post(server.url("/notes?dry=SENTINELQ"))
            .header("content-type", "application/json")
            .header("x-team", "SENTINEL H!")
            .body(
                r#"{"text":"SENTINEL_TEXT_THAT_IS_FAR_TOO_LONG","tags":["SENTINEL TAG"],"priority":4242,"email":"SENTINEL@BAD","pw":"hunter22"}"#,
            )
            .send()
            .await
            .expect("post");
        assert_eq!(resp.status(), 422);
        let text = resp.text().await.expect("body");
        let json: serde_json::Value = serde_json::from_str(&text).expect("json");
        let errors = json["errors"].as_array().expect("errors");
        for part in ["body", "query", "headers"] {
            assert!(
                errors.iter().any(|e| e["part"] == part),
                "{part} rejected nothing: {text}"
            );
        }
        for rule in ["max_len", "format", "max", "check", "type"] {
            assert!(errors.iter().any(|e| e["rule"] == rule), "{rule}: {text}");
        }
        for sentinel in sentinels {
            assert!(!text.contains(sentinel), "{sentinel} echoed in {text}");
        }
        server.stop().await;
    }

    /// The rate limiter sits before content negotiation and validation:
    /// a flood of invalid bodies is shed as 429s without parsing them.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_rate_limiter_answers_before_validation() {
        let mut server = TestServer::builder("validation")
            .handler(APP)
            .config(|cfg| {
                cfg.rate_limit.enabled = true;
                cfg.rate_limit.requests = 2;
                cfg.rate_limit.window = 60;
            })
            .spawn()
            .await;
        for _ in 0..2 {
            let (status, json) = post_json(&server, "/notes", "{}").await;
            assert_eq!(status, 422, "{json}");
        }
        for content_type in ["application/json", "text/plain"] {
            let resp = server
                .client()
                .post(server.url("/notes"))
                .header("content-type", content_type)
                .body("{")
                .send()
                .await
                .expect("post");
            assert_eq!(resp.status(), 429, "{content_type}");
            assert!(resp.headers().contains_key("retry-after"));
        }
        server.stop().await;
    }

    /// A validated body that stalls is answered 408 by the same read guard
    /// as any other body, and the connection is closed (V1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stalled_validated_body_is_a_408() {
        let mut server = TestServer::builder("validation")
            .handler(APP)
            .config(|cfg| {
                cfg.workers = 1;
                cfg.limits.body_read_ms = 200;
            })
            .spawn()
            .await;
        let mut sock = tokio::net::TcpStream::connect(server.addr())
            .await
            .expect("connect");
        sock.write_all(
            b"POST /notes HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{\"text\":",
        )
        .await
        .expect("write partial body");
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut raw))
            .await
            .expect("the server must answer within the stall budget")
            .expect("read response");
        let head = String::from_utf8_lossy(&raw).to_lowercase();
        assert!(head.starts_with("http/1.1 408"), "got: {head}");
        assert!(head.contains("connection: close"), "got: {head}");
        // The one state is free again.
        let resp = server.get("/plain").await;
        assert_eq!(resp.status(), 200);
        server.stop().await;
    }

    /// A body nested past serde_json's depth bound is a syntax error to
    /// the validated route: a 422 on `body` with the `json` rule, never a
    /// stack overflow (V2).
    #[tokio::test(flavor = "multi_thread")]
    async fn deeply_nested_json_is_a_422_on_the_body() {
        let mut server = TestServer::builder("validation").handler(APP).spawn().await;
        let body = format!("{}{}", "[".repeat(300), "]".repeat(300));
        let (status, json) = post_json(&server, "/notes", &body).await;
        assert_eq!(status, 422, "{json}");
        assert_eq!(json["errors"][0]["rule"], "json");
        assert_eq!(json["errors"][0]["path"], "body");
        server.stop().await;
    }

    /// Bytes that are not UTF-8 in a query value or a header (V6) are
    /// decoded lossily and then judged by the rule: a 422, never a panic,
    /// and nothing of them in the answer.
    #[tokio::test(flavor = "multi_thread")]
    async fn invalid_utf8_in_text_inputs_is_a_422() {
        let mut server = TestServer::builder("validation").handler(APP).spawn().await;
        let resp = server
            .client()
            .get(server.url("/bytes?tags=%FF%FEabc&q=%C3%28"))
            .send()
            .await
            .expect("get");
        assert_eq!(resp.status(), 422);
        let json: serde_json::Value = resp.json().await.expect("json");
        assert_eq!(json["errors"][0]["rule"], "format", "{json}");
        assert_eq!(json["errors"][0]["path"], "query.tags[1]", "{json}");

        let resp = server
            .client()
            .post(server.url("/notes"))
            .header("content-type", "application/json")
            .header(
                "x-team",
                reqwest::header::HeaderValue::from_bytes(b"core\xff\xfe").unwrap(),
            )
            .body(r#"{"text":"hi"}"#)
            .send()
            .await
            .expect("post");
        assert_eq!(resp.status(), 422);
        let json: serde_json::Value = resp.json().await.expect("json");
        assert_eq!(json["errors"][0]["path"], "headers.x-team[1]", "{json}");
        server.stop().await;
    }

    /// A message with HTML in it (M3) reaches the client as a JSON string
    /// under `application/json`: the encoder, not the author, keeps the
    /// document well-formed.
    #[tokio::test(flavor = "multi_thread")]
    async fn messages_with_markup_stay_json_strings() {
        let mut server = TestServer::builder("validation").handler(APP).spawn().await;
        let resp = server
            .client()
            .post(server.url("/html"))
            .header("content-type", "application/json")
            .body(r#"{"a":"long"}"#)
            .send()
            .await
            .expect("post");
        assert_eq!(resp.status(), 422);
        let content_type = resp.headers()["content-type"].to_str().unwrap().to_string();
        assert!(
            content_type.starts_with("application/json"),
            "{content_type}"
        );
        let text = resp.text().await.expect("body");
        let json: serde_json::Value = serde_json::from_str(&text).expect("well-formed json");
        assert_eq!(json["fields"]["body.a"], "<b>too long</b> & \"quoted\"");
        server.stop().await;
    }

    /// An array without `max_items` whose items each run a check (C11)
    /// is bounded by the body limit first and the budget second: a 413
    /// or a 500, never a hang.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unbounded_arrays_of_checks_hit_the_body_limit_or_the_budget() {
        let mut server = TestServer::builder("validation")
            .handler(APP)
            .config(|cfg| {
                cfg.workers = 1;
                cfg.lua.exec_timeout_ms = 500;
                cfg.limits.pool_wait_ms = 500;
                // Small on purpose: an over-limit body must still fit the
                // socket buffers, or the early 413 (the server closes
                // without draining) races the client's own write and the
                // request errors instead of carrying the status.
                cfg.limits.max_body_bytes = 4096;
            })
            .spawn()
            .await;
        let started = Instant::now();
        let body = format!("{{\"items\":[{}1]}}", "1,".repeat(1_000));
        let (status, json) = post_json(&server, "/many", &body).await;
        assert_eq!(status, 500, "{json}");
        assert_eq!(json["kind"], "timeout", "{json}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );

        let body = format!("{{\"items\":[{}1]}}", "1,".repeat(3_000));
        let (status, _) = post_json(&server, "/many", &body).await;
        assert_eq!(status, 413);

        let (status, json) = post_json(&server, "/many", r#"{"items":[1,2,3]}"#).await;
        assert_eq!(status, 200, "{json}");
        assert_eq!(json["n"], 3);
        server.stop().await;
    }

    #[cfg(feature = "fetch")]
    const BUDGET: &str = r#"
local app = nitr.app()
app:post("/probe", function(req)
    return nitr.json({ ok = true })
end, {
    input = { body = { host = { "string", description = "probes the host", check = function(h)
        local seen = {}
        for i = 1, 4 do
            local ok, err = pcall(function() return nitr.fetch("GET", "http://" .. h .. "/"):send() end)
            if not ok then seen[#seen + 1] = tostring(err) end
        end
        for _, e in ipairs(seen) do
            if e:find("max_per_request", 1, true) then return false, "budget exhausted after " .. #seen .. " errors" end
        end
        return false, "budget never applied: " .. (seen[1] or "no error")
    end } } },
})
return app
"#;

    /// `[fetch] max_per_request` applies inside a check (C2): the request's
    /// outbound allowance is what validation spends.
    #[cfg(feature = "fetch")]
    #[tokio::test(flavor = "multi_thread")]
    async fn the_fetch_budget_applies_inside_checks() {
        let mut server = TestServer::builder("validation-budget")
            .handler(BUDGET)
            .std_features(&["json", "http", "fetch"])
            .config(|cfg| {
                cfg.fetch.allow_private_networks = true;
                cfg.fetch.max_per_request = 2;
            })
            .spawn()
            .await;
        // Port 9 is discard, never listening: every send fails, and only
        // the budget can make a failure say `max_per_request`.
        let (status, json) = post_json(&server, "/probe", r#"{"host":"127.0.0.1:9"}"#).await;
        assert_eq!(status, 422, "{json}");
        assert!(
            json["fields"]["body.host"]
                .as_str()
                .unwrap_or_default()
                .starts_with("budget exhausted"),
            "{json}"
        );
        server.stop().await;
    }

    const CHECKS: &str = r#"
local S = nitr.validate
local app = nitr.app()

app:post("/spin", function(req) return nitr.json({ ok = true }) end, {
    input = { body = { a = { "string", description = "spins", check = function() while true do end end } } },
})
app:post("/yield", function(req) return nitr.json({ ok = true }) end, {
    input = { body = { a = { "string", description = "yields", check = function() coroutine.yield("x") return false, "after the yield" end } } },
})
local Rec
Rec = S.schema({
    a = { "string", description = "recurses", check = function(v)
        local data, err = Rec:check({ a = v })
        return data ~= nil, "recursed"
    end },
})
app:post("/recurse", function(req) return nitr.json({ ok = true }) end, {
    input = { body = Rec },
})
app:get("/ok", function(req) return nitr.json({ ok = true }) end)
app:on_error(function(err, req)
    return nitr.error(500, { code = "HANDLER", kind = err.kind, message = err.message })
end)
return app
"#;

    /// A check that spins is stopped by the budget; one that yields by
    /// hand is resumed at once, its yielded values ignored, so only its
    /// real return counts; one that recurses into its own schema is
    /// stopped by the Lua C-stack bound. Never a hang, never a pass by
    /// accident, and the state serves the next request (C1, C9, C12).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn checks_cannot_escape_the_budget_the_coroutine_or_the_stack() {
        let mut server = TestServer::builder("validation-checks")
            .handler(CHECKS)
            .config(|cfg| {
                cfg.workers = 1;
                cfg.lua.exec_timeout_ms = 1_000;
                cfg.limits.pool_wait_ms = 1_000;
            })
            .spawn()
            .await;
        for (path, allowed) in [
            ("/spin", &[500][..]),
            ("/yield", &[422][..]),
            ("/recurse", &[500][..]),
        ] {
            let started = Instant::now();
            let (status, json) = tokio::time::timeout(
                Duration::from_secs(10),
                post_json(&server, path, r#"{"a":"x"}"#),
            )
            .await
            .unwrap_or_else(|_| panic!("{path} must be stopped, not run forever"));
            assert!(allowed.contains(&status), "{path}: {status} {json}");
            if path == "/recurse" {
                assert!(
                    json["message"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("nested deeper than 8 levels"),
                    "{json}"
                );
            }
            assert!(
                started.elapsed() < Duration::from_millis(3_000),
                "{path} took {:?}",
                started.elapsed()
            );
            eprintln!("{path}: {status} {json}");
            let resp = server.get("/ok").await;
            assert_eq!(resp.status(), 200, "{path}: the state did not recover");
        }
        server.stop().await;
    }
}
