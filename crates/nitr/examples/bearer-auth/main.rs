//! Bearer-token authentication: `nitr.auth.bearer` for the header and
//! `nitr.crypto.constant_time_eq` for the comparison — the two-line
//! pattern for protecting an internal API with a shared token.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --features crypto --example bearer-auth
//!
//! TOKEN=1f8e4c0a6b5d92e37a41c8f0d3b6a95c1e2d4f6a8b0c3e5d7f9a1b3c5d7e9f01
//! curl -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:3000/private'  # 200
//! curl -H "Authorization: Bearer wrong"  'http://127.0.0.1:3000/private'  # 401
//! curl -i 'http://127.0.0.1:3000/private'                # 401 + WWW-Authenticate
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

    // `PORT=8080 cargo run --example bearer-auth` overrides the default.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    // A token check is cheap — no argon2 here — but an auth endpoint is
    // still a guessing surface, and the limiter is configuration, not
    // code. Same shape as [rate_limit] in nitr.toml.
    let mut cfg = Config::default();
    cfg.rate_limit.enabled = true;
    cfg.rate_limit.requests = 100;
    cfg.rate_limit.window = 60;

    Server::builder()
        .config(cfg)
        .listen(([127, 0, 0, 1], port).into())
        .handler_script("crates/nitr/examples/bearer-auth/app.lua")
        // `CRYPTO` registers both `nitr.crypto` and `nitr.auth`.
        .builtins(Builtins::JSON | Builtins::LOG | Builtins::CRYPTO)
        .build()
        .await?
        .serve()
        .await
}
