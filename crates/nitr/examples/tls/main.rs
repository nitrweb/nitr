//! TLS termination: the same server, one `[tls]` section away from
//! speaking HTTPS.
//!
//! The example mints its own throwaway self-signed certificate on every
//! run, so there is nothing to install and no key material in this
//! repository. That is the *only* part of it that is example-specific —
//! a real deployment points `[tls] cert` and `[tls] key` at files an ACME
//! client or a certificate authority produced, and changes nothing else.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --example tls --features tls
//!
//! # `-k` because the certificate is self-signed and trusted by nobody;
//! # with a real certificate it is a plain `curl https://…`.
//! curl -k 'https://127.0.0.1:3000/'
//! curl -k 'https://127.0.0.1:3000/whoami'
//!
//! # …and the failure that matters: plaintext to a TLS port is refused,
//! # never quietly served in the clear.
//! curl 'http://127.0.0.1:3000/'
//! ```
//!
//! ## Doing this for real
//!
//! ```toml
//! [tls]
//! enabled = true
//! cert = "/etc/nitr/tls/fullchain.pem"   # leaf first, then intermediates
//! key  = "/etc/nitr/tls/privkey.pem"     # PKCS#8, PKCS#1 or SEC1
//! # min_version = "1.3"                  # default: "1.2", the floor
//! ```
//!
//! or, without touching the file, `NITR_TLS_ENABLED=true`,
//! `NITR_TLS_CERT=…`, `NITR_TLS_KEY=…`.
//!
//! Three things worth knowing before it goes anywhere real:
//!
//! * **`cert` is the chain, not just the leaf.** Clients that do not
//!   already hold your intermediate cannot build a path to a trusted
//!   root, and the failure looks like "works on my machine".
//! * **A renewed certificate takes effect on `SIGHUP`** (or
//!   `nitr reload`): the reload re-reads both files and swaps them in
//!   only when the new pair validates, keeping the old material
//!   otherwise. No restart needed.
//! * **Binding 443 needs a privilege the process should not keep.** Use a
//!   socket-activation supervisor, `CAP_NET_BIND_SERVICE`, or a reverse
//!   proxy — see `deploy/` for the systemd unit.

use std::path::PathBuf;

use nitr::{Builtins, Server};

/// Writes a fresh self-signed certificate for `localhost`/`127.0.0.1`
/// into `dir` and returns the two paths.
///
/// Self-signed and short-lived on purpose: this is a demonstration of the
/// server's TLS path, not of certificate management. Everything a real
/// deployment does differently happens *outside* the server.
fn mint(dir: &std::path::Path) -> std::io::Result<(PathBuf, PathBuf)> {
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .map_err(std::io::Error::other)?;

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, generated.cert.pem())?;
    std::fs::write(&key_path, generated.signing_key.serialize_pem())?;

    // A private key readable by every account on the box is a private key
    // in name only. The server does not enforce this — file permissions
    // are the operator's job — but an example that skipped it would be
    // teaching the wrong habit.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok((cert_path, key_path))
}

#[tokio::main]
async fn main() -> nitr::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // `PORT=8443 cargo run --example tls --features tls` overrides it.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let dir = std::env::temp_dir().join("nitr-example-tls");
    std::fs::create_dir_all(&dir)
        .map_err(|err| nitr::Error::Config(format!("cannot create {}: {err}", dir.display())))?;
    let (cert, key) = mint(&dir).map_err(|err| {
        nitr::Error::Config(format!("cannot write the example certificate: {err}"))
    })?;
    tracing::info!(
        "minted a throwaway self-signed certificate in {} — curl needs -k",
        dir.display()
    );

    let cfg = nitr::Config {
        handler_script: PathBuf::from("crates/nitr/examples/tls/app.lua"),
        listen: ([127, 0, 0, 1], port).into(),
        tls: nitr::TlsConfig {
            enabled: true,
            cert: Some(cert),
            key: Some(key),
            // Unset would mean the same thing: TLS 1.2 is the floor
            // either way, and nothing below it can be selected. Set
            // `"1.3"` instead when every client is known to speak it.
            min_version: Some("1.2".into()),
            // Unset: the handshake is bounded by min(header_read_ms, 10s)
            // either way — `[tls] handshake_ms` exists for deployments
            // that want a different number, never for "unbounded".
            handshake_ms: None,
        },
        ..nitr::Config::default()
    };

    Server::builder()
        .config(cfg)
        .builtins(Builtins::JSON)
        .build()
        .await?
        .serve()
        .await
}
