// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Dev-mode hot reload, end to end: a save rebuilds the pool, and the
//! rebuild's own side effects must not re-trigger the watcher.
//!
//! The regression pinned here: the repository's own development setup
//! keeps the SQLite database inside `scripts/`, and its configuration
//! script writes it on every pool rebuild. The watcher used to treat any
//! content event under a watched root as a reason to reload, so one save
//! became rebuild → write → event → rebuild, forever, until the server
//! was killed.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use std::time::{Duration, Instant};

use harness::TestServer;

const HANDLER_V1: &str = r#"
local app = nitr.app()
app:get("/version", function(req)
    return nitr.text("v1")
end)
return app
"#;

const HANDLER_V2: &str = r#"
local app = nitr.app()
app:get("/version", function(req)
    return nitr.text("v2")
end)
return app
"#;

/// A configuration script that leaves a write inside the watched
/// directory every time it runs — the same shape as a config script
/// seeding a database that lives next to the scripts. One byte per
/// rebuild, so the file's size counts the rebuilds.
fn counting_config_script(counter: &std::path::Path) -> String {
    // A long-bracket string needs no escaping, so Windows backslashes in
    // the temp path survive intact.
    format!(
        r#"
local f = assert(io.open([[{}]], "a"))
f:write("x")
f:close()
return {{}}
"#,
        counter.display()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_save_reloads_once_and_the_rebuilds_own_writes_do_not_loop() {
    let builder = TestServer::builder("dev-reload");
    let counter = builder.dir().join("rebuilds.log");
    let server = builder
        .handler(HANDLER_V1)
        .config_script(counting_config_script(&counter))
        .config(|cfg| {
            cfg.dev_mode = true;
            // The config script needs `io` to produce its in-root write;
            // the deliberately excluded default set stays the rule for
            // real applications.
            cfg.lua.stdlib.push("io".into());
        })
        .spawn()
        .await;

    let version = server.url("/version");
    let body = |resp: reqwest::Response| async move { resp.text().await.expect("body") };
    let resp = server.client().get(&version).send().await.expect("get v1");
    assert_eq!(body(resp).await, "v1");

    // Save the new handler until the reload serves it. The rewrite loop
    // absorbs two startup races: the watcher thread registering its
    // watches after we first write, and a non-atomic write landing
    // mid-rebuild (that reload fails, the old pool stays, the next save
    // retries).
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        server.dir().write("app.lua", HANDLER_V2);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let resp = server.client().get(&version).send().await.expect("poll");
        if body(resp).await == "v2" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the dev-mode watcher never served the saved handler"
        );
    }

    // Let the trailing debounce window (from the last redundant save
    // above) fire and finish its rebuild...
    tokio::time::sleep(Duration::from_millis(700)).await;
    let settled = std::fs::metadata(&counter).expect("counter file").len();
    // ...then hold still. Before the input filter, the rebuild's own
    // write re-triggered the watcher every ~200ms, so a quiet second is
    // the loop's absence, not its slowness.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let after = std::fs::metadata(&counter).expect("counter file").len();
    assert_eq!(
        settled, after,
        "the rebuild's own writes re-triggered the watcher: \
         {settled} rebuilds grew to {after} with no file saved"
    );

    // And the reloaded application still serves.
    let resp = server.client().get(&version).send().await.expect("get v2");
    assert_eq!(body(resp).await, "v2");
}
