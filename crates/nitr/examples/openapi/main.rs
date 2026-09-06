// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The validated notes API, documented: an OpenAPI document generated
//! from the route table and a Swagger UI page served from the binary.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --example openapi --features swagger
//!
//! curl -s 'http://127.0.0.1:3000/openapi.json' | jq .info
//! xdg-open 'http://127.0.0.1:3000/docs'
//! curl -si -X POST 'http://127.0.0.1:3000/api/notes' -H 'content-type: application/json' \
//!      -H 'x-team: core' -d '{"text":"  "}'                        # 422, fields["body.text"]
//! ```

use nitr::{Builtins, Config, Server};

#[tokio::main]
async fn main() -> nitr::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    // `PORT=8080 cargo run --example openapi` overrides the default port.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    let mut cfg = Config::default();
    cfg.openapi.enabled = true;
    cfg.openapi.servers = vec![format!("http://127.0.0.1:{port}")];
    cfg.swagger.enabled = true;
    cfg.swagger.try_it_out = true;
    Server::builder()
        .config(cfg)
        .listen(([127, 0, 0, 1], port).into())
        .handler_script("crates/nitr/examples/openapi/app.lua")
        .builtins(Builtins::minimal() | Builtins::LOG)
        .build()
        .await?
        .serve()
        .await
}
