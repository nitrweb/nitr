// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Request dispatch, end to end: the work Nitr does between an inbound
//! request and a finished response.
//!
//! The routes below are deliberately thin — a handler that returns a
//! constant makes the surrounding machinery (route matching, parameter
//! extraction, the request bridge, middleware composition, response
//! encoding) the thing being measured. The heavier `nitr.*` builtins have
//! their own benchmark target.

mod common;

use std::sync::LazyLock;

use common::{client, dispatch, get, header, post_json, tokio_runtime, write_file};
use nitr::Builtins;

fn main() {
    divan::main();
}

/// One application covering every dispatch shape, so a single Lua state is
/// built for the whole target.
const APP: &str = r#"
local app = nitr.app()

-- Response payloads are built once, at load time: what the benchmarks
-- measure is the response path, not table construction in Lua.
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

local BLOB = string.rep("nitr serves lua handlers over hyper. ", 512)

app:get("/ping", function(req)
    return nitr.text("pong")
end)

app:get("/users/:id/posts/:post", function(req)
    return nitr.text(req.params.id .. ":" .. req.params.post)
end)

app:get("/files/*", function(req)
    return nitr.text(req.params.splat)
end)

app:get("/search", function(req)
    return nitr.text((req.query.q or "") .. (req.query.page or ""))
end)

app:get("/headers", function(req)
    return nitr.text(req.headers["user-agent"] or "none")
end)

app:get("/json/small", function(req)
    return nitr.json({ ok = true, id = 42, name = "nitr" })
end)

app:get("/json/large", function(req)
    return nitr.json({ items = ITEMS })
end)

app:get("/blob", function(req)
    return nitr.text(BLOB)
end)

app:post("/echo", function(req)
    local body = req:json()
    return nitr.json({ received = #body.items })
end)

app:post("/form", function(req)
    return nitr.text(req:form().name or "none")
end)

-- Four layers of middleware, composed once at load time; a request pays
-- only for the closure calls.
local function tag(name)
    return function(next)
        return function(req)
            local res = next(req)
            res.headers["X-" .. name] = "1"
            return res
        end
    end
end

app:get("/chain", tag("A"), tag("B"), tag("C"), tag("D"), function(req)
    return nitr.text("chained")
end)

-- Five reads of the same field in one handler: each read rebuilds the
-- headers table today, so this is five times `request_headers`' table
-- work on top of one dispatch.
app:get("/headers/repeated", function(req)
    local n = 0
    for _ = 1, 5 do
        if req.headers["user-agent"] then n = n + 1 end
    end
    return nitr.text(tostring(n))
end)

local LINE = string.rep("x", 100) .. "\n"

-- Writer-callback streaming: fifty chunks through the bounded channel.
app:get("/stream/writer", function(req)
    return {
        status = 200,
        headers = { ["content-type"] = "text/plain" },
        body = function(writer)
            for _ = 1, 50 do writer:write(LINE) end
        end,
    }
end)

-- Iterator streaming: the body function is called once per chunk, so this
-- pays a coroutine reset per chunk on top of the channel.
app:get("/stream/iter", function(req)
    local i = 0
    return {
        status = 200,
        headers = { ["content-type"] = "text/plain" },
        body = function()
            i = i + 1
            if i <= 50 then return LINE end
            return nil
        end,
    }
end)

app:get("/boom", function(req)
    error("kaboom")
end)

app:on_error(function(err, req)
    return nitr.error(500, { code = "INTERNAL" })
end)

return app
"#;

/// A request body of roughly 4 KiB of JSON, the size of a form submission
/// or an API write.
static REQUEST_BODY: LazyLock<String> = LazyLock::new(|| {
    let items: Vec<String> = (0..40)
        .map(|i| {
            format!(
                r#"{{"id":{i},"name":"item-{i}","tags":["alpha","beta"],"active":{}}}"#,
                i % 2 == 0
            )
        })
        .collect();
    format!(r#"{{"items":[{}]}}"#, items.join(","))
});

/// The builtins the dispatch application needs: the JSON codec and the
/// response helpers.
fn builtins() -> Builtins {
    Builtins::JSON | Builtins::HTTP
}

/// Route matching, parameter extraction and middleware.
mod routing {
    use super::*;

    /// The floor of the whole stack: match a static route, run a handler
    /// that returns a constant, encode the response.
    #[divan::bench]
    fn static_route(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/ping")));
    }

    /// Two path parameters, extracted in Rust and handed to Lua.
    #[divan::bench]
    fn path_params(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/users/4926/posts/17")));
    }

    /// A wildcard route: the tail of the path becomes `params.splat`.
    #[divan::bench]
    fn wildcard_route(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/files/css/site/main.css")));
    }

    /// Query-string parsing, on a URL with several percent-encoded pairs.
    #[divan::bench]
    fn query_string(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| {
            divan::black_box(get(
                &rt,
                &client,
                "/search?q=lua%20web%20server&page=3&sort=desc&lang=en",
            ))
        });
    }

    /// Request headers, materialized for the Lua side.
    #[divan::bench]
    fn request_headers(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());
        let headers = [
            header("user-agent", "nitr-bench/1.0"),
            header("accept", "text/plain, */*;q=0.8"),
            header("accept-language", "en-US,en;q=0.9"),
            header("x-forwarded-for", "203.0.113.7"),
        ];

        bencher.bench_local(|| {
            divan::black_box(dispatch(
                &rt, &client, "GET", "/headers", &headers, None, 200,
            ))
        });
    }

    /// Four middleware layers around the handler; compare with
    /// `static_route` for the per-layer cost.
    #[divan::bench]
    fn middleware_chain(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/chain")));
    }

    /// An unmatched path: answered in Rust, no Lua state involved.
    #[divan::bench]
    fn not_found(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "GET", "/missing", &[], None, 404))
        });
    }

    /// A known path with the wrong method: `405`, also without Lua.
    #[divan::bench]
    fn method_not_allowed(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "DELETE", "/ping", &[], None, 405))
        });
    }

    /// A handler that raises: the error handler path, which every
    /// production application ends up exercising.
    #[divan::bench]
    fn handler_error(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "GET", "/boom", &[], None, 500))
        });
    }

    /// `static_route` with an `Accept-Encoding` header and the default
    /// configuration, where on-the-fly compression is *off*: what every
    /// browser request pays for a negotiation whose answer is discarded.
    #[divan::bench]
    fn static_route_accept_encoding(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());
        let headers = [header("accept-encoding", "gzip, deflate, br, zstd")];

        let probe = dispatch(&rt, &client, "GET", "/ping", &headers, None, 200);
        assert_eq!(probe.header("content-encoding"), None);

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "GET", "/ping", &headers, None, 200))
        });
    }

    /// The same field read five times in one handler (`req.headers`).
    #[divan::bench]
    fn repeated_header_reads(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());
        let headers = [
            header("user-agent", "nitr-bench/1.0"),
            header("accept", "text/plain, */*;q=0.8"),
            header("accept-language", "en-US,en;q=0.9"),
            header("x-forwarded-for", "203.0.113.7"),
        ];

        bencher.bench_local(|| {
            divan::black_box(dispatch(
                &rt,
                &client,
                "GET",
                "/headers/repeated",
                &headers,
                None,
                200,
            ))
        });
    }

    /// `HEAD` on a `GET` route: the whole response is built and then the
    /// body is stripped.
    #[divan::bench]
    fn head_request(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        let probe = dispatch(&rt, &client, "HEAD", "/blob", &[], None, 200);
        assert!(probe.body.is_empty());

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "HEAD", "/blob", &[], None, 200))
        });
    }
}

/// Streaming bodies: the bounded channel, the producer task, and (in
/// iterator mode) a coroutine reset per chunk. Fifty ~100-byte chunks.
mod streaming {
    use super::*;

    #[divan::bench]
    fn writer_50_chunks(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        let probe = get(&rt, &client, "/stream/writer");
        assert_eq!(probe.body.len(), 50 * 101);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/stream/writer")));
    }

    #[divan::bench]
    fn iterator_50_chunks(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        let probe = get(&rt, &client, "/stream/iter");
        assert_eq!(probe.body.len(), 50 * 101);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/stream/iter")));
    }
}

/// Static files, served entirely in Rust: mount matching, path resolution,
/// the conditional and range machinery, sidecar lookup, and the two body
/// strategies (inline below 256 KiB, streamed above).
mod static_files {
    use super::*;
    use crate::common::temp_dir;

    /// A mount directory with a 2 KiB text file (plus a `.gz` sidecar
    /// whose bytes are never decoded — the sidecar path serves them as
    /// they are), a 512 KiB binary, and an `index.html` for the SPA
    /// fallback.
    fn fixture() -> std::path::PathBuf {
        let dir = temp_dir("static");
        std::fs::write(dir.join("small.txt"), "nitr static text\n".repeat(120))
            .expect("write small.txt");
        std::fs::write(dir.join("small.txt.gz"), vec![0x1f, 0x8b, 0x08, 0x00, 0x42])
            .expect("write the sidecar");
        std::fs::write(dir.join("large.bin"), vec![0xabu8; 512 * 1024]).expect("write large.bin");
        std::fs::write(dir.join("index.html"), "<!doctype html><title>spa</title>")
            .expect("write index.html");
        dir
    }

    /// One script with a plain mount at `/assets` and an SPA mount at
    /// `/app`, both on the same directory; the route keeps the app valid.
    fn app_script(dir: &std::path::Path) -> std::path::PathBuf {
        let dir = dir.display();
        let script = format!(
            "local app = nitr.app()\n\
             app:static(\"/assets\", [[{dir}]])\n\
             app:static(\"/app\", [[{dir}]], {{ spa = true }})\n\
             app:get(\"/ping\", function(req) return nitr.text(\"pong\") end)\n\
             return app\n"
        );
        write_file("dispatch-static.lua", &script)
    }

    #[divan::bench]
    fn small_hit(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = app_script(&fixture());
        let client = client(&rt, &script, builtins());

        let probe = get(&rt, &client, "/assets/small.txt");
        assert_eq!(probe.header("content-type"), Some("text/plain"));

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/assets/small.txt")));
    }

    /// A revalidation: `If-None-Match` with the current tag → `304`.
    #[divan::bench]
    fn not_modified(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = app_script(&fixture());
        let client = client(&rt, &script, builtins());
        let etag = get(&rt, &client, "/assets/small.txt")
            .header("etag")
            .expect("an etag")
            .to_string();
        let headers = [header("if-none-match", &etag)];

        bencher.bench_local(|| {
            divan::black_box(dispatch(
                &rt,
                &client,
                "GET",
                "/assets/small.txt",
                &headers,
                None,
                304,
            ))
        });
    }

    /// The first KiB of the large file: `206`, read as one inline span.
    #[divan::bench]
    fn range_1kib(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = app_script(&fixture());
        let client = client(&rt, &script, builtins());
        let headers = [header("range", "bytes=0-1023")];

        let probe = dispatch(
            &rt,
            &client,
            "GET",
            "/assets/large.bin",
            &headers,
            None,
            206,
        );
        assert_eq!(probe.body.len(), 1024);

        bencher.bench_local(|| {
            divan::black_box(dispatch(
                &rt,
                &client,
                "GET",
                "/assets/large.bin",
                &headers,
                None,
                206,
            ))
        });
    }

    /// A precompressed sidecar (`small.txt.gz`) chosen from
    /// `Accept-Encoding`: one extra stat and a different file opened.
    #[divan::bench]
    fn sidecar_gzip(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = app_script(&fixture());
        let client = client(&rt, &script, builtins());
        let headers = [header("accept-encoding", "gzip")];

        let probe = dispatch(
            &rt,
            &client,
            "GET",
            "/assets/small.txt",
            &headers,
            None,
            200,
        );
        assert_eq!(probe.header("content-encoding"), Some("gzip"));

        bencher.bench_local(|| {
            divan::black_box(dispatch(
                &rt,
                &client,
                "GET",
                "/assets/small.txt",
                &headers,
                None,
                200,
            ))
        });
    }

    /// 512 KiB, above the inline limit: streamed in 64 KiB chunks through
    /// the bounded channel.
    #[divan::bench]
    fn large_streamed(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = app_script(&fixture());
        let client = client(&rt, &script, builtins());

        let probe = get(&rt, &client, "/assets/large.bin");
        assert_eq!(probe.body.len(), 512 * 1024);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/assets/large.bin")));
    }

    /// `HEAD`: headers only, the file is never opened.
    #[divan::bench]
    fn head(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = app_script(&fixture());
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| {
            divan::black_box(dispatch(
                &rt,
                &client,
                "HEAD",
                "/assets/small.txt",
                &[],
                None,
                200,
            ))
        });
    }

    /// An unknown path under the SPA mount: resolved, missed, then the
    /// index served instead.
    #[divan::bench]
    fn spa_fallback(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = app_script(&fixture());
        let client = client(&rt, &script, builtins());

        let probe = get(&rt, &client, "/app/some/client/route");
        assert_eq!(probe.header("content-type"), Some("text/html"));

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/app/some/client/route")));
    }
}

/// The Rust-side protection layer: CORS and the rate limiter, each on the
/// `static_route` floor so the delta is the feature's cost.
mod protection {
    use super::*;
    use crate::common::client_with;
    use nitr::Config;

    fn cors_config() -> Config {
        let mut cfg = Config::default();
        cfg.cors.origins = Some(vec!["https://app.example".into()]);
        cfg
    }

    /// A preflight: answered in Rust without a Lua state.
    #[divan::bench]
    fn cors_preflight(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client_with(&rt, &script, builtins(), cors_config(), |b| b);
        let headers = [
            header("origin", "https://app.example"),
            header("access-control-request-method", "GET"),
        ];

        let probe = rt
            .block_on(client.request("OPTIONS", "/ping", &headers, None))
            .expect("preflight");
        assert!(
            probe.header("access-control-allow-origin").is_some(),
            "preflight was not approved: {}",
            probe.status
        );
        let status = probe.status;

        bencher.bench_local(|| {
            divan::black_box(dispatch(
                &rt, &client, "OPTIONS", "/ping", &headers, None, status,
            ))
        });
    }

    /// A plain cross-origin `GET`: the handler runs and the CORS headers
    /// are applied to its response.
    #[divan::bench]
    fn cors_apply(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client_with(&rt, &script, builtins(), cors_config(), |b| b);
        let headers = [header("origin", "https://app.example")];

        let probe = dispatch(&rt, &client, "GET", "/ping", &headers, None, 200);
        assert_eq!(
            probe.header("access-control-allow-origin"),
            Some("https://app.example")
        );

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "GET", "/ping", &headers, None, 200))
        });
    }

    fn rate_limited_config() -> Config {
        let mut cfg = Config::default();
        cfg.rate_limit.enabled = true;
        // Never actually rejects: the bench measures the bookkeeping.
        cfg.rate_limit.requests = u32::MAX;
        cfg.rate_limit.window = 60;
        cfg
    }

    /// `static_route` with the limiter on: one bucket lookup under the
    /// shared mutex per request.
    #[divan::bench]
    fn rate_limited_static_route(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client_with(&rt, &script, builtins(), rate_limited_config(), |b| b);

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/ping")));
    }
}

/// Many requests in flight at once: the pool hand-off, the pool handle's
/// lock, and the rate limiter's mutex are invisible at concurrency one.
/// Eight tasks over two Lua states, twenty-five `GET /ping` each.
mod concurrency {
    use super::*;
    use crate::common::client_with;
    use nitr::Config;

    const TASKS: usize = 8;
    const REQUESTS_PER_TASK: usize = 25;

    fn saturate(rt: &tokio::runtime::Runtime, client: &nitr::testing::TestClient) {
        rt.block_on(async {
            let tasks: Vec<_> = (0..TASKS)
                .map(|_| {
                    let client = client.clone();
                    tokio::spawn(async move {
                        for _ in 0..REQUESTS_PER_TASK {
                            let resp = client
                                .request("GET", "/ping", &[], None)
                                .await
                                .expect("dispatch");
                            assert_eq!(resp.status, 200);
                        }
                    })
                })
                .collect();
            for task in tasks {
                task.await.expect("request task");
            }
        });
    }

    #[divan::bench]
    fn saturating_200_requests(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client_with(&rt, &script, builtins(), Config::default(), |b| {
            b.workers(2)
        });

        bencher.bench_local(|| saturate(&rt, &client));
    }

    /// The same with the rate limiter on: every request also takes the
    /// limiter's global mutex.
    #[divan::bench]
    fn saturating_200_requests_rate_limited(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let mut cfg = Config::default();
        cfg.rate_limit.enabled = true;
        cfg.rate_limit.requests = u32::MAX;
        cfg.rate_limit.window = 60;
        let client = client_with(&rt, &script, builtins(), cfg, |b| b.workers(2));

        bencher.bench_local(|| saturate(&rt, &client));
    }
}

/// Bodies in and out: JSON encoding, JSON decoding, form parsing.
mod payloads {
    use super::*;

    /// A small JSON response — the common API answer.
    #[divan::bench]
    fn json_response_small(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/json/small")));
    }

    /// 50 nested records: the Lua table walk plus `serde_json` encoding.
    #[divan::bench]
    fn json_response_large(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());

        bencher.bench_local(|| divan::black_box(get(&rt, &client, "/json/large")));
    }

    /// A 4 KiB JSON request body: read, decoded into Lua, answered.
    #[divan::bench]
    fn json_request(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());
        let body = REQUEST_BODY.as_str();

        bencher.bench_local(|| divan::black_box(post_json(&rt, &client, "/echo", body)));
    }

    /// A urlencoded form body, parsed in Rust for `req:form()`.
    #[divan::bench]
    fn urlencoded_form(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client(&rt, &script, builtins());
        let headers = [header("content-type", "application/x-www-form-urlencoded")];
        let body =
            "name=Ada%20Lovelace&email=ada%40example.com&subject=hello&message=a+longer+body";

        bencher.bench_local(|| {
            divan::black_box(dispatch(
                &rt,
                &client,
                "POST",
                "/form",
                &headers,
                Some(body.into()),
                200,
            ))
        });
    }
}

/// On-the-fly response compression, the one part of the response path that
/// deliberately spends CPU.
#[cfg(feature = "compression")]
mod compression {
    use super::*;
    use crate::common::client_with;
    use nitr::Config;

    /// A server with `[compression]` on for both algorithms.
    fn compressing_config() -> Config {
        let mut cfg = Config::default();
        cfg.compression.enabled = true;
        cfg.compression.algorithms = vec!["br".into(), "gzip".into()];
        cfg
    }

    #[divan::bench]
    fn gzip_19kib(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client_with(&rt, &script, builtins(), compressing_config(), |builder| {
            builder
        });
        let headers = [header("accept-encoding", "gzip")];

        // Fail loudly rather than benchmark an uncompressed response.
        let probe = dispatch(&rt, &client, "GET", "/blob", &headers, None, 200);
        assert_eq!(probe.header("content-encoding"), Some("gzip"));

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "GET", "/blob", &headers, None, 200))
        });
    }

    #[divan::bench]
    fn brotli_19kib(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let script = write_file("dispatch.lua", APP);
        let client = client_with(&rt, &script, builtins(), compressing_config(), |builder| {
            builder
        });
        let headers = [header("accept-encoding", "br")];

        let probe = dispatch(&rt, &client, "GET", "/blob", &headers, None, 200);
        assert_eq!(probe.header("content-encoding"), Some("br"));

        bencher.bench_local(|| {
            divan::black_box(dispatch(&rt, &client, "GET", "/blob", &headers, None, 200))
        });
    }
}
