//! Router + middleware example: `nitr.app()` routes with path parameters,
//! global and per-route middleware, response helpers, signed cookies, and
//! content negotiation.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --example router
//!
//! curl 'http://127.0.0.1:3000/'
//! curl 'http://127.0.0.1:3000/users/42'
//! curl -X POST 'http://127.0.0.1:3000/users' -d '{"name":"ada"}'
//! curl 'http://127.0.0.1:3000/admin' -H 'authorization: Bearer router-example-token'
//! curl -c - 'http://127.0.0.1:3000/login'
//! curl 'http://127.0.0.1:3000/whoami' -b 'session=<value from /login>'
//! curl 'http://127.0.0.1:3000/data' -H 'accept: text/html'
//! curl 'http://127.0.0.1:3000/download'          # streamed CSV (writer)
//! curl 'http://127.0.0.1:3000/chunks'            # streamed chunks (iterator)
//! curl -N 'http://127.0.0.1:3000/events'         # Server-Sent Events
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

    // `PORT=8080 cargo run --example router` overrides the default port.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    Server::builder()
        .listen(([127, 0, 0, 1], port).into())
        .handler_script("crates/nitr/examples/router/app.lua")
        .config_script("crates/nitr/examples/router/config.lua")
        .builtins(
            Builtins::DEBUG | Builtins::JSON | Builtins::HTTP | Builtins::LOG | Builtins::CRYPTO,
        )
        .build()
        .await?
        .serve()
        .await
}
