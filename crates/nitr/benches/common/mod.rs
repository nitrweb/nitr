// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Fixtures shared by the Nitr benchmarks: temporary Lua scripts, a fixed
//! tokio runtime, and in-process clients built from the real server.
//!
//! Every benchmark dispatches through [`nitr::testing::TestClient`], which
//! is the same path `nitr test` uses: protection, router, middleware,
//! handler and response encoding, with no socket in the way. What is left
//! out (the kernel's TCP stack, hyper's connection loop) is what a
//! benchmark cannot measure reproducibly anyway.
//!
//! Not every helper is used by every benchmark target, hence the
//! module-wide `dead_code` allowance.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use hyper::body::Bytes;
use nitr::testing::{TestClient, TestResponse};
use nitr::{Builtins, Config, Server};
use tokio::runtime::Runtime;

/// A two-worker runtime: pooled states and the blocking database calls
/// behave as they do under the real server, and the thread count is fixed
/// so a measurement never depends on the machine's core count.
pub fn tokio_runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build the benchmark tokio runtime")
}

/// Writes `content` to a unique temporary file and returns its path. The
/// counter keeps two benchmarks in the same process off the same file.
pub fn write_file(name: &str, content: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("nitr-bench-{}-{id}-{name}", std::process::id()));
    std::fs::write(&path, content).expect("write a benchmark fixture");
    path
}

/// A unique, empty temporary directory (templates, databases).
pub fn temp_dir(name: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("nitr-bench-dir-{}-{id}-{name}", std::process::id()));
    std::fs::create_dir_all(&path).expect("create a benchmark directory");
    path
}

/// Builds a single-worker server for `script` and returns its in-process
/// client. The build (Lua state creation, script compilation, router
/// construction) happens here so it stays outside the measured closure.
pub fn client(rt: &Runtime, script: &Path, builtins: Builtins) -> TestClient {
    client_with(rt, script, builtins, Config::default(), |b| b)
}

/// Same as [`client`], with a configuration and a builder hook for the
/// benchmarks that need templates or a database.
pub fn client_with(
    rt: &Runtime,
    script: &Path,
    builtins: Builtins,
    cfg: Config,
    tweak: impl FnOnce(nitr::ServerBuilder) -> nitr::ServerBuilder,
) -> TestClient {
    rt.block_on(async {
        let builder = Server::builder()
            .config(cfg)
            .handler_script(script)
            .builtins(builtins)
            .workers(1);
        let server = tweak(builder)
            .build()
            .await
            .expect("build the benchmark server");
        server.test_client()
    })
}

/// Dispatches one request and asserts the status, so a benchmark that
/// silently started measuring a 404 error path fails instead.
pub fn dispatch(
    rt: &Runtime,
    client: &TestClient,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: Option<Bytes>,
    expect: u16,
) -> TestResponse {
    let resp = rt
        .block_on(client.request(method, target, headers, body))
        .expect("dispatch a benchmark request");
    assert_eq!(resp.status, expect, "{method} {target}");
    resp
}

/// `GET target`, expecting `200`.
pub fn get(rt: &Runtime, client: &TestClient, target: &str) -> TestResponse {
    dispatch(rt, client, "GET", target, &[], None, 200)
}

/// `POST target` with a JSON body, expecting `200`.
pub fn post_json(rt: &Runtime, client: &TestClient, target: &str, body: &str) -> TestResponse {
    dispatch(
        rt,
        client,
        "POST",
        target,
        &[("content-type".into(), "application/json".into())],
        Some(Bytes::copy_from_slice(body.as_bytes())),
        200,
    )
}

/// A header pair, spelled once instead of at every call site.
pub fn header(name: &str, value: &str) -> (String, String) {
    (name.to_string(), value.to_string())
}
