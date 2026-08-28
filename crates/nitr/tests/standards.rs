// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for phase 11: the parts of HTTP that applications
//! assume exist — ranges, compression, CORS, form and multipart bodies,
//! conditional dynamic responses — plus the correctness audit.

mod harness;

use std::path::PathBuf;
use std::time::Duration;

use harness::TestServer;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const APP_SCRIPT: &str = r#"
local app = nitr.app()

app:get("/hello", function(req)
    return nitr.text("hello")
end)

-- Big enough to be worth compressing, and highly compressible.
app:get("/big", function(req)
    return nitr.json({ filler = string.rep("compress me ", 500) })
end)

app:post("/echo-form", function(req)
    local form = req:form()
    return nitr.json({ email = form.email, note = form.note })
end)

-- Reads the body in bounded chunks rather than all at once, so a body
-- larger than the state's heap can still be processed.
app:post("/count", function(req)
    local total, chunks = 0, 0
    while true do
        local part = req:read(8192)
        if not part then break end
        total = total + #part
        chunks = chunks + 1
    end
    return nitr.json({ bytes = total, chunks = chunks })
end)

app:post("/upload", function(req)
    local fields, files = {}, {}
    req:multipart(function(part)
        if part.filename then
            local dest = nitr.cfg.upload_dir .. "/" .. part.filename
            local size = part:save(dest)
            files[#files + 1] = {
                name = part.name,
                filename = part.filename,
                content_type = part.content_type,
                size = size,
            }
        else
            fields[part.name] = part:text()
        end
    end)
    return nitr.json({ fields = fields, files = files })
end)

-- A dynamic resource with a validator: the second request should be a 304
-- with no body at all.
app:get("/article", function(req)
    local etag = nitr.etag("revision-7")
    if req:fresh(etag) then
        local res = nitr.status(304)
        res.headers.ETag = etag
        return res
    end
    local res = nitr.text("the article body")
    res.headers.ETag = etag
    return res
end)

-- Deliberately invalid: a 204 may not carry bytes.
app:get("/bad-204", function(req)
    return { status = 204, body = "should not be here" }
end)

-- Deliberately invalid: a header value may not contain CRLF.
app:get("/bad-header", function(req)
    local res = nitr.text("ok")
    res.headers["X-Evil"] = "a\r\nInjected: yes"
    return res
end)

return app
"#;

/// The standard app on two workers with an upload directory wired through
/// the configuration script, the way any deployment setting reaches Lua.
fn builder() -> harness::Builder {
    let b = TestServer::builder("standards")
        .handler(APP_SCRIPT)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| cfg.workers = 2);
    let uploads = b.dir().join("uploads");
    std::fs::create_dir_all(&uploads).expect("uploads dir");
    b.config_script(format!(
        "return {{ upload_dir = {:?} }}",
        uploads.to_string_lossy()
    ))
}

/// Writes a static tree with a precompressed sidecar into the builder's
/// directory and returns its path.
fn static_dir(b: &harness::Builder) -> PathBuf {
    b.dir().write(
        "public/data.txt",
        (0..1000u32)
            .map(|n| (b'a' + (n % 26) as u8) as char)
            .collect::<String>(),
    );

    // `app.js` plus a gzip sidecar whose contents differ visibly, so a test
    // can tell which one was served.
    b.dir()
        .write("public/app.js", b"console.log('identity');\n");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, b"console.log('from the sidecar');\n")
        .expect("compress");
    b.dir()
        .write("public/app.js.gz", encoder.finish().expect("finish"));
    b.dir().join("public")
}

// ---------------------------------------------------------------------------

/// A `<video>` seeking is the motivating case: a byte range must come back
/// as `206` with the matching `Content-Range`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn range_requests_serve_partial_content() {
    let b = builder();
    let dir = static_dir(&b);
    let mut srv = b
        .config(move |cfg| {
            cfg.static_files.dir = Some(dir);
            cfg.static_files.mount = Some("/assets".into());
        })
        .spawn()
        .await;

    // Whole file: ranges are advertised.
    let resp = srv.get("/assets/data.txt").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
    let full = resp.text().await.expect("body");
    assert_eq!(full.len(), 1000);

    // An explicit span.
    let resp = srv
        .client()
        .get(srv.url("/assets/data.txt"))
        .header("range", "bytes=10-19")
        .send()
        .await
        .expect("range");
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-range"], "bytes 10-19/1000");
    assert_eq!(resp.headers()["content-length"], "10");
    assert_eq!(resp.text().await.expect("body"), &full[10..20]);

    // A suffix range.
    let resp = srv
        .client()
        .get(srv.url("/assets/data.txt"))
        .header("range", "bytes=-5")
        .send()
        .await
        .expect("suffix");
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.text().await.expect("body"), &full[995..]);

    // Past the end: 416 with the true length, so the client can retry.
    let resp = srv
        .client()
        .get(srv.url("/assets/data.txt"))
        .header("range", "bytes=5000-6000")
        .send()
        .await
        .expect("unsatisfiable");
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers()["content-range"], "bytes */1000");

    // A stale If-Range must yield the whole file rather than a fragment
    // the client would splice into a different version.
    let resp = srv
        .client()
        .get(srv.url("/assets/data.txt"))
        .header("range", "bytes=0-9")
        .header("if-range", "\"stale\"")
        .send()
        .await
        .expect("stale if-range");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body").len(), 1000);

    srv.stop().await;
}

/// A `.gz` sidecar is served as-is: compressed once at build time, no
/// runtime CPU, and used even though `[compression]` is off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn precompressed_sidecars_are_served_when_accepted() {
    let b = builder();
    let dir = static_dir(&b);
    let mut srv = b
        .config(move |cfg| cfg.static_files.dir = Some(dir))
        .spawn()
        .await;

    let resp = srv
        .client()
        .get(srv.url("/app.js"))
        .header("accept-encoding", "gzip")
        .send()
        .await
        .expect("sidecar");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-encoding"], "gzip");
    // The content type comes from the logical file, not from `.gz`.
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .expect("content type")
            .contains("javascript")
    );
    assert_eq!(resp.headers()["vary"], "accept-encoding");

    let mut decoded = String::new();
    let body = resp.bytes().await.expect("bytes");
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&body[..]), &mut decoded)
        .expect("decode");
    assert_eq!(decoded, "console.log('from the sidecar');\n");

    // A client that does not accept gzip gets the identity file.
    let resp = srv
        .client()
        .get(srv.url("/app.js"))
        .header("accept-encoding", "identity")
        .send()
        .await
        .expect("identity");
    assert!(!resp.headers().contains_key("content-encoding"));
    assert_eq!(
        resp.text().await.expect("body"),
        "console.log('identity');\n"
    );

    srv.stop().await;
}

/// On-the-fly compression is off unless asked for, and correct when it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_responses_compress_only_when_enabled() {
    let mut off = builder().spawn().await;
    let resp = off
        .client()
        .get(off.url("/big"))
        .header("accept-encoding", "gzip, br")
        .send()
        .await
        .expect("uncompressed");
    assert!(
        !resp.headers().contains_key("content-encoding"),
        "compression must be opt-in"
    );
    let identity_len = resp.bytes().await.expect("bytes").len();
    off.stop().await;

    let mut on = builder()
        .config(|cfg| cfg.compression.enabled = true)
        .spawn()
        .await;

    let resp = on
        .client()
        .get(on.url("/big"))
        .header("accept-encoding", "gzip")
        .send()
        .await
        .expect("gzip");
    assert_eq!(resp.headers()["content-encoding"], "gzip");
    assert!(
        resp.headers()["vary"]
            .to_str()
            .expect("vary")
            .contains("accept-encoding")
    );
    let body = resp.bytes().await.expect("bytes");
    assert!(body.len() < identity_len, "compression must shrink it");
    let mut decoded = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&body[..]), &mut decoded)
        .expect("decode");
    assert!(decoded.contains("compress me"));

    // Server preference decides when the client accepts both.
    let resp = on
        .client()
        .get(on.url("/big"))
        .header("accept-encoding", "gzip, br")
        .send()
        .await
        .expect("br");
    assert_eq!(resp.headers()["content-encoding"], "br");

    // A short response is left alone: the encoder would cost more than it
    // saves.
    let resp = on
        .client()
        .get(on.url("/hello"))
        .header("accept-encoding", "gzip")
        .send()
        .await
        .expect("small");
    assert!(!resp.headers().contains_key("content-encoding"));

    on.stop().await;
}

/// Preflights are answered in Rust, and the policy is enforced per origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cors_preflights_never_reach_lua() {
    let mut srv = builder()
        .config(|cfg| {
            cfg.cors.origins = Some(vec!["https://app.example".into()]);
            cfg.cors.headers = Some(vec!["content-type".into()]);
            cfg.cors.max_age = Some(600);
        })
        .spawn()
        .await;

    // A preflight for a path that has no route at all still gets answered.
    let resp = srv
        .client()
        .request(reqwest::Method::OPTIONS, srv.url("/no-such-route"))
        .header("origin", "https://app.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .send()
        .await
        .expect("preflight");
    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers()["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(resp.headers()["access-control-max-age"], "600");

    // An origin outside the policy is answered, but not approved.
    let resp = srv
        .client()
        .request(reqwest::Method::OPTIONS, srv.url("/hello"))
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "GET")
        .send()
        .await
        .expect("rejected preflight");
    assert_eq!(resp.status(), 204);
    assert!(!resp.headers().contains_key("access-control-allow-origin"));

    // An ordinary cross-origin response carries the allow header.
    let resp = srv
        .client()
        .get(srv.url("/hello"))
        .header("origin", "https://app.example")
        .send()
        .await
        .expect("simple request");
    assert_eq!(
        resp.headers()["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(resp.text().await.expect("body"), "hello");

    srv.stop().await;
}

/// `origins = ["*"]` with credentials is a combination browsers reject, so
/// the server refuses to start rather than serving something that quietly
/// never works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contradictory_cors_policy_fails_at_startup() {
    let err = builder()
        .config(|cfg| {
            cfg.cors.origins = Some(vec!["*".into()]);
            cfg.cors.credentials = true;
        })
        .try_build()
        .await
        .expect_err("must refuse to start");
    assert!(
        err.to_string().contains("credentials"),
        "the error must name the problem, got: {err}"
    );
}

/// Form and multipart bodies, including an upload that never enters the
/// Lua heap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn form_and_multipart_bodies_are_parsed_in_rust() {
    // Uploads are bounded by the overall body limit too, so it has to be
    // raised alongside the per-file one.
    let mut srv = builder()
        .config(|cfg| cfg.limits.max_body_bytes = 4 * 1024 * 1024)
        .spawn()
        .await;

    // urlencoded: percent-decoding and `+`-as-space handled in Rust.
    let resp = srv
        .client()
        .post(srv.url("/echo-form"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("email=a%40b.com&note=hello+there%21")
        .send()
        .await
        .expect("form");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["email"], "a@b.com");
    assert_eq!(body["note"], "hello there!");

    // multipart: one ordinary field and one file.
    // Large enough that buffering it into the Lua heap would be a visible
    // choice rather than an accident.
    let payload = 200_000;
    let file_bytes = vec![b'z'; payload];
    let boundary = "----nitrtestboundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nMy Upload\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"doc\"; \
             filename=\"report.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(&file_bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let resp = srv
        .client()
        .post(srv.url("/upload"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await
        .expect("multipart");
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    let out: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(out["fields"]["title"], "My Upload");
    assert_eq!(out["files"][0]["filename"], "report.bin");
    assert_eq!(out["files"][0]["content_type"], "application/octet-stream");
    assert_eq!(out["files"][0]["size"], payload);

    // The bytes really landed on disk, byte for byte.
    let saved = std::fs::read(srv.dir().join("uploads").join("report.bin")).expect("saved file");
    assert_eq!(saved, file_bytes);

    srv.stop().await;
}

/// `[limits] max_field_bytes` and `max_file_bytes`, end to end — the
/// guards standing between an upload and the 8 MiB Lua state limit had no
/// test firing them. An oversized *field* is refused while `part:text()`
/// buffers it; an oversized *file* is refused mid-stream by `part:save()`,
/// and the truncated file is removed rather than left for the application
/// to trip over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multipart_field_and_file_limits_fire() {
    let b = TestServer::builder("standards-multipart-limits")
        .handler(
            r#"
local app = nitr.app()

-- pcall around the parse so the limit error comes back as data the test
-- can assert on, instead of a generic 500.
app:post("/upload", function(req)
    local ok, err = pcall(function()
        req:multipart(function(part)
            if part.filename then
                part:save(nitr.cfg.upload_dir .. "/" .. part.filename)
            else
                part:text()
            end
        end)
    end)
    return nitr.json({ ok = ok, err = ok and "" or tostring(err) })
end)

return app
"#,
        )
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| {
            cfg.workers = 1;
            cfg.limits.max_field_bytes = 64;
            cfg.limits.max_file_bytes = 1024;
        });
    let uploads = b.dir().join("uploads");
    std::fs::create_dir_all(&uploads).expect("uploads dir");
    let mut srv = b
        .config_script(format!(
            "return {{ upload_dir = {:?} }}",
            uploads.to_string_lossy()
        ))
        .spawn()
        .await;

    let boundary = "----nitrlimitboundary";
    let multipart = |parts: &[(&str, Option<&str>, Vec<u8>)]| {
        let mut body = Vec::new();
        for (name, filename, bytes) in parts {
            let disposition = match filename {
                Some(f) => format!(
                    "--{boundary}\r\nContent-Disposition: form-data; \
                     name=\"{name}\"; filename=\"{f}\"\r\n\r\n"
                ),
                None => format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
                ),
            };
            body.extend_from_slice(disposition.as_bytes());
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    };
    let post = |body: Vec<u8>| {
        srv.client()
            .post(srv.url("/upload"))
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
    };

    // Within both caps: everything parses.
    let body: serde_json::Value = post(multipart(&[
        ("note", None, vec![b'a'; 64]),
        ("doc", Some("small.bin"), vec![b'z'; 1024]),
    ]))
    .send()
    .await
    .expect("in-limit upload")
    .json()
    .await
    .expect("json");
    assert_eq!(body["ok"], true, "got: {body}");
    assert_eq!(
        std::fs::read(uploads.join("small.bin"))
            .expect("saved")
            .len(),
        1024
    );

    // One byte over the field cap: refused, naming the limit.
    let body: serde_json::Value = post(multipart(&[("note", None, vec![b'a'; 65])]))
        .send()
        .await
        .expect("oversized field")
        .json()
        .await
        .expect("json");
    assert_eq!(body["ok"], false, "got: {body}");
    assert!(
        body["err"]
            .as_str()
            .expect("err")
            .contains("exceeds the 64 byte limit"),
        "got: {body}"
    );

    // One byte over the file cap: refused mid-stream, and the truncated
    // file is cleaned up.
    let body: serde_json::Value = post(multipart(&[("doc", Some("big.bin"), vec![b'z'; 1025])]))
        .send()
        .await
        .expect("oversized file")
        .json()
        .await
        .expect("json");
    assert_eq!(body["ok"], false, "got: {body}");
    assert!(
        body["err"]
            .as_str()
            .expect("err")
            .contains("exceeds the 1024 byte limit"),
        "got: {body}"
    );
    assert!(
        !uploads.join("big.bin").exists(),
        "a rejected upload must not leave a truncated file behind"
    );

    srv.stop().await;
}

/// `req:read(n)` consumes a body in bounded pieces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incremental_reads_bound_what_lua_holds() {
    let mut srv = builder()
        .config(|cfg| cfg.limits.max_body_bytes = 1024 * 1024)
        .spawn()
        .await;

    let payload = vec![b'x'; 40_000];
    let resp = srv
        .client()
        .post(srv.url("/count"))
        .body(payload.clone())
        .send()
        .await
        .expect("count");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["bytes"], payload.len());
    // Read in pieces rather than one buffer: that is the whole point.
    assert!(
        body["chunks"].as_u64().expect("chunks") >= 2,
        "expected several bounded reads, got {}",
        body["chunks"]
    );

    srv.stop().await;
}

/// A dynamic resource can answer `304`, the same as a static file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_responses_support_conditional_requests() {
    let mut srv = builder().spawn().await;

    let resp = srv.get("/article").await;
    assert_eq!(resp.status(), 200);
    let etag = resp.headers()["etag"].to_str().expect("etag").to_string();
    assert!(etag.starts_with('"') && etag.ends_with('"'), "got {etag}");
    assert_eq!(resp.text().await.expect("body"), "the article body");

    let resp = srv
        .client()
        .get(srv.url("/article"))
        .header("if-none-match", &etag)
        .send()
        .await
        .expect("revalidate");
    assert_eq!(resp.status(), 304);
    assert!(resp.bytes().await.expect("bytes").is_empty());

    // A different validator is a miss.
    let resp = srv
        .client()
        .get(srv.url("/article"))
        .header("if-none-match", "\"something-else\"")
        .send()
        .await
        .expect("stale");
    assert_eq!(resp.status(), 200);

    srv.stop().await;
}

/// The correctness audit: the details that are easy to get subtly wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_correctness_audit() {
    let b = builder();
    let dir = static_dir(&b);
    let mut srv = b
        .config(move |cfg| {
            cfg.static_files.dir = Some(dir);
            cfg.static_files.mount = Some("/assets".into());
            cfg.limits.max_body_bytes = 512;
        })
        .spawn()
        .await;

    // HEAD works on a route that only registered GET, and reports the
    // length the GET would have sent.
    let get = srv.get("/hello").await;
    let expected_len = get.headers()["content-length"]
        .to_str()
        .expect("length")
        .to_string();
    let head = srv
        .client()
        .head(srv.url("/hello"))
        .send()
        .await
        .expect("HEAD");
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["content-length"], expected_len);
    assert_eq!(head.headers()["content-type"], "text/plain; charset=utf-8");
    assert!(head.bytes().await.expect("bytes").is_empty());

    // OPTIONS on a known path answers with Allow instead of 405.
    let resp = srv
        .client()
        .request(reqwest::Method::OPTIONS, srv.url("/hello"))
        .send()
        .await
        .expect("OPTIONS");
    assert_eq!(resp.status(), 204);
    assert_eq!(resp.headers()["allow"], "GET, HEAD, OPTIONS");

    // A 204 carrying a body is refused rather than desynchronizing the
    // connection.
    let resp = srv.get("/bad-204").await;
    assert_eq!(resp.status(), 500);

    // A CRLF in a header value cannot split the response.
    let resp = srv.get("/bad-header").await;
    assert_eq!(resp.status(), 500);
    assert!(!resp.headers().contains_key("injected"));

    // Expect: 100-continue on a body the limits would reject must be
    // refused *before* the client uploads it.
    let mut sock = tokio::net::TcpStream::connect(srv.addr())
        .await
        .expect("connect");
    sock.write_all(
        b"POST /count HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100000\r\n\
          Expect: 100-continue\r\n\r\n",
    )
    .await
    .expect("write headers");
    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .expect("the server must answer without waiting for the body")
        .expect("read");
    let status = String::from_utf8_lossy(&buf[..n]);
    let status = status.lines().next().unwrap_or_default();
    assert!(
        status.contains("413"),
        "expected an immediate 413, got: {status}"
    );
    drop(sock);

    srv.stop().await;
}
