//! HTTP Basic authentication end to end: `nitr.auth.basic` for the
//! header, `nitr.crypto.password_verify` for the stored argon2id hash,
//! and `nitr.crypto.password_verify_dummy` for the unknown-user branch
//! that would otherwise leak the account list through response time.
//!
//! The credentials in `app.lua` were produced by `nitr hash-password`.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --features crypto --example basic-auth
//!
//! curl -u 'ada:lovelace' 'http://127.0.0.1:3000/private'   # 200
//! curl -u 'ada:wrong'    'http://127.0.0.1:3000/private'   # 401
//! curl -u 'nobody:wrong' 'http://127.0.0.1:3000/private'   # 401, same cost
//! curl -u 'linus:torvalds' 'http://127.0.0.1:3000/private' # 401 + a server warning
//! curl -i 'http://127.0.0.1:3000/private'                  # 401 + WWW-Authenticate
//!
//! # The two paths that must cost the same. A naive handler answers the
//! # second in microseconds, and that gap is the user list.
//! curl -s -o /dev/null -w '%{time_total}\n' -u 'ada:wrong'    'http://127.0.0.1:3000/private'
//! curl -s -o /dev/null -w '%{time_total}\n' -u 'nobody:wrong' 'http://127.0.0.1:3000/private'
//!
//! # Where a hash comes from without writing any Lua:
//! cargo run --features crypto --bin nitr -- hash-password
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

    // `PORT=8080 cargo run --example basic-auth` overrides the default.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    // REQUIRED in front of any handler that calls password_verify /
    // password_verify_dummy: by design both branches cost one argon2
    // (~19 MiB, ~26 ms), so an unthrottled login lets a client with no
    // account at all hold every pooled Lua state busy and shed real
    // logins at pool_wait_ms. The same setting from nitr.toml:
    //
    //   [rate_limit]
    //   enabled  = true
    //   requests = 100
    //   window   = 60
    let mut cfg = Config::default();
    cfg.rate_limit.enabled = true;
    cfg.rate_limit.requests = 100;
    cfg.rate_limit.window = 60;

    Server::builder()
        .config(cfg)
        .listen(([127, 0, 0, 1], port).into())
        .handler_script("crates/nitr/examples/basic-auth/app.lua")
        // `CRYPTO` registers both `nitr.crypto` and `nitr.auth`.
        .builtins(Builtins::JSON | Builtins::LOG | Builtins::CRYPTO)
        .build()
        .await?
        .serve()
        .await
}
