// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for streaming bodies: writer callback, iterator mode,
//! SSE, the per-chunk execution budget, the `max_streams` cap, and client
//! disconnect recovery.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use std::time::Duration;

use harness::TestServer;

const APP_SCRIPT: &str = r#"
local app = nitr.app()

app:get("/plain", function(req)
    return nitr.text("plain")
end)

app:get("/stream", function(req)
    return {
        status = 200,
        headers = { ["Content-Type"] = "application/json" },
        body = function(writer)
            writer:write("[")
            for i = 1, 3 do
                if i > 1 then writer:write(",") end
                writer:write(tostring(i))
            end
            writer:write("]")
        end,
    }
end)

app:get("/iterator", function(req)
    return {
        body = coroutine.wrap(function()
            coroutine.yield("chunk1 ")
            coroutine.yield("chunk2 ")
            coroutine.yield("chunk3")
        end),
    }
end)

app:get("/events", function(req)
    return nitr.sse(function(send)
        send("message", { hello = "world" })
        send("tick", "line1\nline2")
    end)
end)

app:get("/spin", function(req)
    return {
        body = function(writer)
            writer:write("a")
            while true do end -- must be stopped by the instruction hook
        end,
    }
end)

app:get("/hold", function(req)
    return {
        body = function(writer)
            local chunk = string.rep("x", 1024)
            while true do writer:write(chunk) end
        end,
    }
end)

return app
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streaming_bodies_end_to_end() {
    let mut server = TestServer::builder("streaming")
        .handler(APP_SCRIPT)
        .builtins(nitr::Builtins::JSON | nitr::Builtins::HTTP)
        .config(|cfg| {
            cfg.workers = 2;
            cfg.max_streams = Some(1);
            cfg.lua.exec_timeout_ms = 400;
            // Config validation refuses a pool wait above the request budget.
            cfg.limits.pool_wait_ms = 400;
        })
        .spawn()
        .await;

    let base = server.url("");
    let client = server.client().clone();

    // Writer callback: chunked transfer, chunks concatenated in order.
    let resp = client
        .get(format!("{base}/stream"))
        .send()
        .await
        .expect("stream");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/json");
    assert!(resp.headers().get("content-length").is_none());
    assert_eq!(resp.text().await.expect("stream body"), "[1,2,3]");

    // Iterator mode via coroutine.wrap.
    let resp = client
        .get(format!("{base}/iterator"))
        .send()
        .await
        .expect("iterator");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.text().await.expect("iterator body"),
        "chunk1 chunk2 chunk3"
    );

    // SSE: headers and wire format (multi-line data → multiple data: lines).
    let resp = client
        .get(format!("{base}/events"))
        .send()
        .await
        .expect("events");
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    assert_eq!(resp.headers()["cache-control"], "no-cache");
    let body = resp.text().await.expect("events body");
    assert!(body.contains("event: message\ndata: {\"hello\":\"world\"}\n\n"));
    assert!(body.contains("event: tick\ndata: line1\ndata: line2\n\n"));

    // A CPU-bound loop mid-stream is stopped by the instruction hook: the
    // client sees the chunks written so far, and the state recovers.
    let resp = client
        .get(format!("{base}/spin"))
        .send()
        .await
        .expect("spin");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("spin body"), "a");
    let resp = client
        .get(format!("{base}/plain"))
        .send()
        .await
        .expect("plain after spin");
    assert_eq!(resp.status(), 200);

    // max_streams = 1: while one stream is live, a second streaming
    // response is rejected with 503 but plain requests still work.
    let held = client
        .get(format!("{base}/hold"))
        .send()
        .await
        .expect("hold");
    assert_eq!(held.status(), 200);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = client
        .get(format!("{base}/stream"))
        .send()
        .await
        .expect("stream while held");
    assert_eq!(resp.status(), 503);

    let resp = client
        .get(format!("{base}/plain"))
        .send()
        .await
        .expect("plain while held");
    assert_eq!(resp.status(), 200);

    // Dropping the client cancels the held stream, frees its slot and
    // returns its state to the pool.
    drop(held);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let resp = client
        .get(format!("{base}/stream"))
        .send()
        .await
        .expect("stream after release");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body after release"), "[1,2,3]");

    server.stop().await;
}
