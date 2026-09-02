//! Data and outbound I/O maturity: SQLite that behaves under concurrency,
//! SQL migrations, the shared `nitr.cache`, and a `fetch` that retries, is
//! bounded per request, and cannot be tricked into a private address.
//!
//! Run from the repository root:
//!
//! ```sh
//! # Migrations are an explicit step: the server refuses to start with a
//! # pending one, because applying them at boot means a rolling deploy has
//! # two instances racing to change the same schema.
//! cargo run -- migrate --status -c crates/nitr/examples/data-io/nitr.toml
//! cargo run -- migrate          -c crates/nitr/examples/data-io/nitr.toml
//!
//! cargo run --example data-io
//!
//! curl -s 'http://127.0.0.1:3000/db/pragmas'            # wal, 5000, 1, 1
//! curl -s -X POST 'http://127.0.0.1:3000/notes' -d 'body=hello&author_id=1'
//! curl -s 'http://127.0.0.1:3000/notes'
//! curl -s -X POST 'http://127.0.0.1:3000/notes/bulk'
//! curl -s 'http://127.0.0.1:3000/footgun'               # refused, not silent
//! curl -s 'http://127.0.0.1:3000/rates'                 # cached for 30s
//! curl -s 'http://127.0.0.1:3000/cache/stats'
//! curl -s 'http://127.0.0.1:3000/upstream'              # retried if flaky
//! curl -s 'http://127.0.0.1:3000/dashboard'             # query + fetch together
//! curl -s 'http://127.0.0.1:3000/ssrf'                  # metadata endpoint refused
//! ```
//!
//! The example runs its own flaky upstream, which fails the first request
//! of every three, so the retry path is visible rather than theoretical.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use nitr::{Builtins, Config, DatabaseConfig, Server};

const DIR: &str = "crates/nitr/examples/data-io";

#[tokio::main]
async fn main() -> nitr::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let upstream = flaky_upstream().await?;
    println!("flaky upstream listening on http://{upstream}/");

    // `PORT=8080 cargo run --example data-io` overrides the port.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let db_path = std::env::temp_dir().join("nitr-data-io-example.db");
    let migrations = PathBuf::from(format!("{DIR}/migrations"));
    let mut database = DatabaseConfig::new(&db_path);
    database.migrations_dir = Some(migrations.clone());

    // Applied here so the example is runnable in one command; a real
    // deployment runs `nitr migrate` as a separate step.
    let conn = nitr::stdlib::db_open(&db_path, &database.pragmas())?;
    let applied = nitr::stdlib::migrate::run(&conn, &migrations)?;
    if !applied.is_empty() {
        println!("applied {} migration(s)", applied.len());
    }
    drop(conn);

    // A fixed name in the shared temp directory is a file someone else
    // may have written first — and this one is *executed* as Lua. A
    // private, per-run directory instead.
    let scratch = std::env::temp_dir().join(format!("nitr-data-io-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&scratch)?;
    }
    let config_script = scratch.join("config.lua");
    std::fs::write(
        &config_script,
        format!("return {{ upstream = \"http://{upstream}/\" }}"),
    )?;

    let mut cfg = Config {
        listen: ([127, 0, 0, 1], port).into(),
        database: Some(database),
        config_script: Some(config_script),
        workers: 4,
        ..Default::default()
    };
    // The upstream is on loopback, which the SSRF policy refuses by
    // default. A real application would leave this off; here the allow-list
    // does the refusing instead, so `/ssrf` still demonstrates a genuine
    // policy rejection rather than a failed connection.
    cfg.fetch.allow_private_networks = true;
    cfg.fetch.allowed_hosts = Some(vec!["127.0.0.1".into()]);
    cfg.fetch.max_per_request = 8;
    cfg.fetch.propagate_trace_context = true;
    cfg.cache.default_ttl = 60;

    Server::builder()
        .config(cfg)
        .handler_script(format!("{DIR}/app.lua"))
        .builtins(
            Builtins::JSON
                | Builtins::HTTP
                | Builtins::LOG
                | Builtins::DATABASE
                | Builtins::CACHE
                | Builtins::FETCH,
        )
        .build()
        .await?
        .serve()
        .await
}

/// An upstream that fails one request in three, so `/upstream` exercises
/// the retry path instead of only claiming to.
async fn flaky_upstream() -> nitr::Result<std::net::SocketAddr> {
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Response, StatusCode};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let seen = Arc::new(AtomicUsize::new(0));

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_req| {
                    let n = seen.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if n.is_multiple_of(3) {
                            return Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::SERVICE_UNAVAILABLE)
                                    .body(Full::new(Bytes::from_static(b"try again")))
                                    .expect("response"),
                            );
                        }
                        Ok(Response::new(Full::new(Bytes::from(format!(
                            "upstream ok (request {n})"
                        )))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok(addr)
}
