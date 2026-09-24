//! Server-Sent Events: a live ticker paced by a custom Rust `time`
//! module, mounted at `nitr.ext.time` through the `module()` extension
//! point — the same mechanism used for any custom Rust/Lua binding.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --example sse
//!
//! curl -N 'http://127.0.0.1:3000/events'
//! ```

use std::time::Duration;

use nitr::{Builtins, Server};

#[tokio::main]
async fn main() -> nitr::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // `PORT=8080 cargo run --example sse` overrides the default port.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    Server::builder()
        .listen(([127, 0, 0, 1], port).into())
        .handler_script("crates/nitr/examples/sse/app.lua")
        .builtins(Builtins::JSON | Builtins::HTTP)
        // A custom Rust module: the returned table is mounted at
        // `nitr.ext.time` in every pooled Lua state, so handlers call
        // `nitr.ext.time.sleep(ms)` — an async function that suspends the
        // Lua coroutine on the tokio timer without blocking the runtime.
        .module("time", |lua| {
            let t = lua.create_table()?;
            t.set(
                "sleep",
                lua.create_async_function(|_, ms: u64| async move {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    Ok(())
                })?,
            )?;
            Ok(t)
        })
        .build()
        .await?
        .serve()
        .await
}
