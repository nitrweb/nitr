//! Static + dynamic hybrid: files under `public/` are served entirely in
//! Rust (ETag/304, content types, traversal protection), while `/api/*`
//! routes run in Lua. A second mount shows per-mount options.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --example static-site
//!
//! curl -i 'http://127.0.0.1:3000/'                  # index.html
//! curl -i 'http://127.0.0.1:3000/assets/style.css'  # cache-control mount
//! curl -i 'http://127.0.0.1:3000/api/time'          # Lua route
//! curl -i -H 'If-None-Match: <etag>' 'http://127.0.0.1:3000/'   # 304
//! curl -i 'http://127.0.0.1:3000/../etc/passwd'     # 404, not a leak
//! ```

use nitr::{Builtins, Server};

#[tokio::main]
async fn main() -> nitr::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // `PORT=8080 cargo run --example static-site` overrides the port.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    Server::builder()
        .listen(([127, 0, 0, 1], port).into())
        .handler_script("crates/nitr/examples/static-site/app.lua")
        .builtins(Builtins::JSON | Builtins::HTTP | Builtins::LOG | Builtins::TIME)
        .build()
        .await?
        .serve()
        .await
}
