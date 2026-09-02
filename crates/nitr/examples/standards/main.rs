//! HTTP standards completeness: range requests, response compression,
//! CORS, form and multipart bodies, and conditional dynamic responses.
//!
//! Everything here is enforced in Rust. The Lua side only declares intent:
//! which resource identity, where an upload goes.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --example standards
//!
//! # Range: a media player seeking into a file.
//! curl -i -H 'Range: bytes=0-15' 'http://127.0.0.1:3000/media/alphabet.txt'
//! curl -i -H 'Range: bytes=9999-' 'http://127.0.0.1:3000/media/alphabet.txt'  # 416
//!
//! # Precompressed sidecar: app.js.gz is served as-is, no runtime CPU.
//! curl -i --compressed 'http://127.0.0.1:3000/media/app.js'
//!
//! # On-the-fly compression of a dynamic response.
//! curl -i -H 'Accept-Encoding: br' 'http://127.0.0.1:3000/api/report'
//!
//! # CORS: a preflight answered in Rust, without a Lua state.
//! curl -i -X OPTIONS 'http://127.0.0.1:3000/api/notes' \
//!      -H 'Origin: https://app.example' \
//!      -H 'Access-Control-Request-Method: POST' \
//!      -H 'Access-Control-Request-Headers: content-type'
//!
//! # An HTML form body, parsed in Rust.
//! curl -i -X POST 'http://127.0.0.1:3000/api/subscribe' \
//!      -d 'email=me%40example.com&plan=pro'
//!
//! # A file upload that never enters the Lua heap.
//! curl -i -X POST 'http://127.0.0.1:3000/api/upload' \
//!      -F 'title=My notes' -F 'doc=@README.md'
//!
//! # Conditional dynamic response: the second request is a 304.
//! curl -i 'http://127.0.0.1:3000/api/article'
//! curl -i -H 'If-None-Match: "<the etag>"' 'http://127.0.0.1:3000/api/article'
//!
//! # HEAD and OPTIONS work without being registered as routes.
//! curl -i -I 'http://127.0.0.1:3000/api/article'
//! curl -i -X OPTIONS 'http://127.0.0.1:3000/api/notes'
//! ```

use std::io::Write as _;

use nitr::{Builtins, Config, Server};

const DIR: &str = "crates/nitr/examples/standards";

#[tokio::main]
async fn main() -> nitr::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    write_assets()?;

    // `PORT=8080 cargo run --example standards` overrides the port.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let mut cfg = Config {
        listen: ([127, 0, 0, 1], port).into(),
        ..Default::default()
    };
    cfg.static_files.dir = Some(format!("{DIR}/public").into());
    cfg.static_files.mount = Some("/media".into());

    // Compression is opt-in: it trades CPU for bandwidth, and that should
    // be a decision. Precompressed sidecars are served either way.
    cfg.compression.enabled = true;

    // One auditable policy, enforced before any Lua runs. `origins = ["*"]`
    // with `credentials = true` is refused at startup rather than producing
    // headers browsers ignore.
    cfg.cors.origins = Some(vec!["https://app.example".into()]);
    cfg.cors.methods = Some(vec!["GET".into(), "POST".into()]);
    cfg.cors.headers = Some(vec!["content-type".into()]);
    cfg.cors.max_age = Some(600);

    // Uploads are bounded twice: `max_body_bytes` covers the whole request
    // and `max_file_bytes` covers each file within it.
    cfg.limits.max_body_bytes = 16 * 1024 * 1024;
    cfg.limits.max_file_bytes = 8 * 1024 * 1024;
    // `part:save` only writes under this root; without it every file part
    // is refused. It cannot live inside the example directory: an upload
    // root under the handler's directory is refused at startup (`require`
    // is pinned there, so an uploaded `.lua` would be a loadable module).
    // A private per-run directory keeps it out of the way.
    let uploads =
        std::env::temp_dir().join(format!("nitr-standards-uploads-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&uploads);
    {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&uploads)?;
    }
    println!("uploads are saved under {}", uploads.display());
    cfg.multipart.upload_dir = Some(uploads);

    Server::builder()
        .config(cfg)
        .handler_script(format!("{DIR}/app.lua"))
        .config_script(format!("{DIR}/config.lua"))
        .builtins(Builtins::JSON | Builtins::HTTP | Builtins::LOG)
        .build()
        .await?
        .serve()
        .await
}

/// Writes the static assets the example serves, including a gzip sidecar,
/// so the repository does not have to carry generated binaries.
fn write_assets() -> nitr::Result {
    let public = std::path::Path::new(DIR).join("public");
    std::fs::create_dir_all(&public)?;

    // A file worth seeking into.
    let alphabet: String = (0..4000u32)
        .map(|n| (b'a' + (n % 26) as u8) as char)
        .collect();
    std::fs::write(public.join("alphabet.txt"), alphabet)?;

    // `app.js` plus the sidecar a build step would normally produce. The
    // two differ so it is obvious which one was served.
    std::fs::write(
        public.join("app.js"),
        b"console.log('served as identity');\n",
    )?;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(b"console.log('served from the precompressed sidecar');\n")?;
    std::fs::write(public.join("app.js.gz"), gz.finish()?)?;
    Ok(())
}
