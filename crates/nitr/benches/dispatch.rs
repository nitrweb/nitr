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
