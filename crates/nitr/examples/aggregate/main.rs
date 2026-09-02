//! API aggregation + transactions: `nitr.await_all` fans out concurrent
//! `nitr.fetch` requests (here against the server's own endpoints), and
//! `nitr.db:transaction` groups SQLite statements atomically.
//!
//! The fetch policy refuses private/loopback targets by default (SSRF
//! protection); this example opts in because it aggregates itself over
//! loopback.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --example aggregate
//!
//! curl 'http://127.0.0.1:3000/dashboard'      # nitr.await_all over /api/*
//! curl -X POST 'http://127.0.0.1:3000/transfer?from=alice&to=bob&amount=30'
//! curl 'http://127.0.0.1:3000/accounts'
//! curl -X POST 'http://127.0.0.1:3000/transfer?from=alice&to=bob&amount=9999'
//! ```

use nitr::{Config, Server};

#[tokio::main]
async fn main() -> nitr::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // `PORT=8080 cargo run --example aggregate` overrides the default port.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let mut cfg = Config::default();
    // This example fetches its own endpoints over loopback, which the
    // SSRF policy refuses by default — so the allow-list is what refuses
    // everything else, and the upstream base is handed to the script via
    // its configuration rather than read from the `Host` header.
    cfg.fetch.allow_private_networks = true;
    cfg.fetch.allowed_hosts = Some(vec!["127.0.0.1".into()]);
    let upstream = format!("http://127.0.0.1:{port}");

    Server::builder()
        .config(cfg)
        // `nitr.ext.example.upstream`: the base URL the dashboard fetches
        // from, decided here rather than read from the request.
        .module("example", move |lua| {
            let t = lua.create_table()?;
            t.set("upstream", upstream.as_str())?;
            Ok(t)
        })
        .listen(([127, 0, 0, 1], port).into())
        .handler_script("crates/nitr/examples/aggregate/app.lua")
        .config_script("crates/nitr/examples/aggregate/config.lua")
        .database(std::env::temp_dir().join("nitr-aggregate-example.db"))
        .build()
        .await?
        .serve()
        .await
}
