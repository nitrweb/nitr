// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The reload signal is owned from the moment a server is built: a
//! `SIGHUP` that arrives before `serve` (the window in which the pidfile
//! appears) must never carry its default disposition and end the process.
//! On its own binary, because a failure here is the process dying.

#![cfg(unix)]

mod harness;

use harness::TestDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hangup_between_build_and_serve_does_not_kill_the_process() {
    let dir = TestDir::new("signals-hup");
    let handler = dir.write(
        "app.lua",
        "local app = nitr.app()\napp:get('/', function() return nitr.text('ok') end)\nreturn app",
    );
    let server = nitr::Server::builder()
        .config(nitr::Config {
            listen: "127.0.0.1:0".parse().expect("addr"),
            handler_script: handler,
            workers: 1,
            ..nitr::Config::default()
        })
        .build()
        .await
        .expect("build");
    let sent = std::process::Command::new("kill")
        .args(["-HUP", &std::process::id().to_string()])
        .status()
        .expect("kill");
    assert!(sent.success());
    // The signal is asynchronous: give it every chance to land before the
    // server (and the handler it installed) goes away.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    drop(server);
}
