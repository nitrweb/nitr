// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Route input validation: a schema declared once on a route is enforced
//! in Rust before the handler runs — for JSON, HTML forms and uploads —
//! and the handler reads the typed, stripped result from `req.valid`.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --example validation --features all
//!
//! # A bad body: every failing field, with its rule code.
//! curl -si -X POST 'http://127.0.0.1:3000/api/notes' -H 'content-type: application/json' \
//!      -H 'x-team: core' -d '{"text":"  ","tags":["Bad Tag","x","x"],"color":"#GGG"}'
//! # A good one: trimmed, lowercased, defaults applied.
//! curl -s -X POST 'http://127.0.0.1:3000/api/notes' -H 'content-type: application/json' \
//!      -H 'x-team: core' -d '{"text":"Buy milk","color":"#FF8800"}'
//! # Query strings and path parameters are coerced and bounded.
//! curl -s 'http://127.0.0.1:3000/api/notes?limit=500&sort=name' -H 'x-team: core'
//! curl -s 'http://127.0.0.1:3000/api/notes/abc' -H 'x-team: core'
//! # The same schema from an HTML form (blank age is absent, the checkbox
//! # is a boolean, `tags[]` is `tags`).
//! curl -si -X POST 'http://127.0.0.1:3000/profile' -d 'name=Ada&email=ADA@Example.com&age=&news=on&tags[]=math'
//! # An upload judged by its bytes, not its headers.
//! curl -si -X POST 'http://127.0.0.1:3000/profile' -F name=Ada -F email=ada@example.com \
//!      -F 'avatar=@Cargo.toml;type=image/png'
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

    // `PORT=8080 cargo run --example validation` overrides the default port.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    // Validated uploads spool under the upload root and are saved inside
    // it; the example keeps them in a scratch directory it creates.
    let uploads = std::env::temp_dir().join("nitr-example-validation-uploads");
    std::fs::create_dir_all(uploads.join("avatars"))?;
    let mut cfg = Config::default();
    cfg.multipart.upload_dir = Some(uploads);

    Server::builder()
        .config(cfg)
        .listen(([127, 0, 0, 1], port).into())
        .handler_script("crates/nitr/examples/validation/app.lua")
        .builtins(Builtins::minimal() | Builtins::LOG)
        .build()
        .await?
        .serve()
        .await
}
