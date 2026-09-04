// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end TLS: a real handshake against a real listener, and the two
//! failure modes that matter operationally — a plaintext client hitting a
//! TLS port, and a client that does not trust the certificate.
//!
//! The certificate is minted here, at run time, by `rcgen`. Nothing in
//! the repository is key material, and nothing depends on the host's
//! trust store: the test hands its own certificate to its own client as
//! that client's only root.

// Each test binary uses a subset of the shared harness.
#![allow(dead_code)]

mod harness;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use harness::{TestDir, reserve_addr, wait_until_listening};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long the plaintext probe waits for the server to say something
/// before concluding it said nothing. Generous: the point is that no HTTP
/// response ever arrives, and a slow CI box must not turn that into a
/// pass for the wrong reason.
const PROBE_DEADLINE: Duration = Duration::from_secs(5);

/// A freshly minted self-signed identity, valid for `localhost` and
/// `127.0.0.1`, written into the test's own directory.
struct Identity {
    cert_pem: String,
    cert_path: PathBuf,
    key_path: PathBuf,
}

fn mint(dir: &TestDir) -> Identity {
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("generate a self-signed certificate");
    let cert_pem = generated.cert.pem();
    Identity {
        cert_path: dir.write("cert.pem", &cert_pem),
        key_path: dir.write("key.pem", generated.signing_key.serialize_pem()),
        cert_pem,
    }
}

/// A running TLS server plus the material a client needs to talk to it.
struct TlsServer {
    addr: SocketAddr,
    identity: Identity,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    served: Option<tokio::task::JoinHandle<nitr::Result>>,
    dir: TestDir,
}

impl TlsServer {
    /// Spawns a TLS server on a reserved port. `tune` gets the config
    /// after `[tls]` has been filled in, for tests that need to break it.
    async fn spawn(label: &str, tune: impl FnOnce(&mut nitr::Config)) -> Self {
        Self::spawn_with(
            label,
            r#"
            local app = nitr.app()
            app:get("/hello", function(req)
                return {
                    status = 200,
                    headers = { ["Content-Type"] = "text/plain" },
                    body = "over tls: " .. req.path,
                }
            end)
            return app
            "#,
            tune,
        )
        .await
    }

    /// As [`spawn`](Self::spawn), with the handler script supplied — for
    /// tests whose subject is what the handler produces rather than the
    /// transport itself.
    async fn spawn_with(label: &str, handler: &str, tune: impl FnOnce(&mut nitr::Config)) -> Self {
        let dir = TestDir::new(label);
        let identity = mint(&dir);
        let handler = dir.write("app.lua", handler);

        // Port 0, kept bound: nothing can take it between choosing it and
        // serving on it — the same rule the plaintext harness follows.
        let (listener, addr) = reserve_addr();
        let mut cfg = nitr::Config {
            listen: addr,
            handler_script: handler,
            workers: 1,
            tls: nitr::TlsConfig {
                enabled: true,
                cert: Some(identity.cert_path.clone()),
                key: Some(identity.key_path.clone()),
                min_version: None,
                handshake_ms: None,
            },
            ..nitr::Config::default()
        };
        // Prompt teardown: a drain deadline that fails the test rather
        // than the CI job, and no extra budget for streams there are none
        // of.
        cfg.shutdown.grace = 5;
        cfg.shutdown.stream_grace = 0;
        tune(&mut cfg);

        let server = nitr::Server::builder()
            .config(cfg)
            .listener(listener)
            .build()
            .await
            .expect("build a TLS server");
        let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let served = tokio::spawn(server.serve_with_shutdown(async {
            let _ = stop_rx.await;
        }));
        wait_until_listening(addr).await;

        Self {
            addr,
            identity,
            stop: Some(stop),
            served: Some(served),
            dir,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.addr)
    }

    /// A client whose only trust anchor is this server's certificate.
    /// Explicitly *without* the platform roots: a test that trusted the
    /// host's CA store would be testing the host.
    fn client(&self) -> reqwest::Client {
        let root = reqwest::Certificate::from_pem(self.identity.cert_pem.as_bytes())
            .expect("parse the test certificate");
        harness::http_client_builder()
            .tls_certs_only([root])
            .build()
            .expect("client")
    }

    async fn stop(&mut self) {
        let _ = self.stop.take().expect("not stopped").send(());
        let served = self.served.take().expect("not stopped");
        match tokio::time::timeout(Duration::from_secs(10), served).await {
            Ok(task) => task.expect("server task").expect("clean shutdown"),
            Err(_) => panic!("the TLS server did not shut down within 10s"),
        }
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        if let Some(served) = self.served.take() {
            served.abort();
        }
    }
}

/// The whole point: a real handshake, a real request, a real answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_a_real_request_over_tls() {
    let mut server = TlsServer::spawn("tls-e2e", |_| {}).await;

    let resp = server
        .client()
        .get(server.url("/hello"))
        .send()
        .await
        .expect("a TLS request must succeed");
    assert_eq!(resp.status(), 200);
    // ALPN advertises `http/1.1` and nothing else, because `http1` is the
    // only connection type the server builds. A negotiated `h2` would
    // have failed after a successful handshake.
    assert_eq!(resp.version(), reqwest::Version::HTTP_11);
    assert_eq!(resp.text().await.expect("body"), "over tls: /hello");

    // Keep-alive over the same TLS connection: the second request proves
    // the stream survives past the first response rather than the
    // connection being rebuilt behind our back.
    let client = server.client();
    for _ in 0..2 {
        let resp = client
            .get(server.url("/hello"))
            .send()
            .await
            .expect("request");
        assert_eq!(resp.status(), 200);
    }

    server.stop().await;
}

/// A plaintext HTTP request to a TLS port must be *refused*, not
/// mis-served. The failure this rules out is a listener that falls back
/// to cleartext when the handshake fails: that would answer a `GET` over
/// an unencrypted socket while every operator believes the port is
/// encrypted.
///
/// It also pins the blast radius: the connection that failed is the only
/// one affected, which the surviving TLS request afterwards asserts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plaintext_request_to_a_tls_port_is_refused_not_served() {
    let mut server = TlsServer::spawn("tls-plaintext", |_| {}).await;

    let mut socket = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    socket
        .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write a plaintext request");

    let mut answer = Vec::new();
    // The server answers a bad `ClientHello` with a TLS alert and closes;
    // some platforms reset instead, which surfaces here as a read error.
    // Either is a refusal — what matters is that no HTTP response comes
    // back.
    let _ = tokio::time::timeout(PROBE_DEADLINE, socket.read_to_end(&mut answer))
        .await
        .expect("the server must close the connection rather than hold it open");

    assert!(
        !answer.starts_with(b"HTTP/"),
        "a plaintext request was served over cleartext on a TLS port: {:?}",
        String::from_utf8_lossy(&answer)
    );
    // `GET /hello` is not a valid record, so nothing that comes back may
    // contain the handler's output either.
    assert!(
        !answer.windows(8).any(|w| w == b"over tls"),
        "the handler ran for a plaintext client: {:?}",
        String::from_utf8_lossy(&answer)
    );

    // One dropped connection, and only one: the server is still serving.
    let resp = server
        .client()
        .get(server.url("/hello"))
        .send()
        .await
        .expect("the server must survive a failed handshake");
    assert_eq!(resp.status(), 200);

    server.stop().await;
}

/// The control for [`serves_a_real_request_over_tls`]: without the
/// certificate as a trust anchor the request must fail. If this passed,
/// the end-to-end test above would prove nothing — it could be talking
/// cleartext.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_does_not_trust_the_certificate_is_rejected() {
    let mut server = TlsServer::spawn("tls-untrusted", |_| {}).await;

    // No roots at all, not even the platform's: nothing can verify.
    let stranger = harness::http_client_builder()
        .tls_certs_only(std::iter::empty())
        .build()
        .expect("client");
    let err = stranger
        .get(server.url("/hello"))
        .send()
        .await
        .expect_err("an untrusted self-signed certificate must not verify");
    assert!(
        err.to_string().to_ascii_lowercase().contains("certificate")
            || err.is_connect()
            || err.is_request(),
        "expected a certificate failure, got: {err}"
    );

    // A plain HTTP request to the same port is refused the same way.
    let err = stranger
        .get(format!("http://{}/hello", server.addr))
        .send()
        .await
        .expect_err("http:// against a TLS port must not succeed");
    assert!(!err.is_status(), "expected no HTTP response at all: {err}");

    server.stop().await;
}

/// Half a `[tls]` section must fail the *build*, before anything is
/// bound. Discovering it at the first handshake would mean a port that
/// accepts TCP and fails every connection, which is indistinguishable
/// from a network fault — and by then traffic has already been shifted
/// onto it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_half_configured_tls_section_refuses_to_build() {
    let dir = TestDir::new("tls-halfconfig");
    let identity = mint(&dir);
    let handler = dir.write(
        "app.lua",
        "local app = nitr.app()\n\
         app:get('/', function(req) return { status = 200, body = 'ok' } end)\n\
         return app\n",
    );

    let base = |tune: fn(&mut nitr::Config)| {
        let mut cfg = nitr::Config {
            handler_script: handler.clone(),
            workers: 1,
            tls: nitr::TlsConfig {
                enabled: true,
                cert: Some(identity.cert_path.clone()),
                key: Some(identity.key_path.clone()),
                min_version: None,
                handshake_ms: None,
            },
            ..nitr::Config::default()
        };
        tune(&mut cfg);
        cfg
    };

    // The control: the complete section builds.
    nitr::Server::builder()
        .config(base(|_| {}))
        .build()
        .await
        .expect("a complete [tls] section builds");

    for (what, tune) in [
        (
            "key",
            (|cfg: &mut nitr::Config| cfg.tls.key = None) as fn(&mut nitr::Config),
        ),
        ("cert", |cfg: &mut nitr::Config| cfg.tls.cert = None),
    ] {
        let err = nitr::Server::builder()
            .config(base(tune))
            .build()
            .await
            .expect_err("a half-configured [tls] must not build");
        assert!(
            err.to_string().contains(what),
            "the refusal must name the missing key `{what}`, got: {err}"
        );
    }

    // Two valid files that do not belong together: the pair is checked at
    // startup, not left to fail every handshake.
    let other =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("second identity");
    let stray = dir.write("stray.key", other.signing_key.serialize_pem());
    let mut cfg = base(|_| {});
    cfg.tls.key = Some(stray);
    let err = nitr::Server::builder()
        .config(cfg)
        .build()
        .await
        .expect_err("a mismatched pair must not build");
    assert!(
        err.to_string().to_ascii_lowercase().contains("mismatch"),
        "the refusal must say the key does not match the certificate, got: {err}"
    );
}

/// Cookies Nitr builds must carry `Secure` on a TLS server, all the way
/// from `[cookies] secure` through `BuiltinsEnv` and the per-state app
/// data to the bytes on the wire.
///
/// This is the case the unit tests structurally cannot cover: the one in
/// `http.rs` hand-sets the app data and the one in `session.rs` passes
/// `secure = true` explicitly, so both pass even with the *plumbing*
/// deleted. Verified by reverting `server.rs`'s
/// `cookie_secure: cfg.cookies.secure.resolve(cfg.tls.enabled)` to
/// `false`: every other test in the workspace stays green and only this
/// one fails.
///
/// Asserted per attribute rather than against the whole header — the
/// `cookie` crate's emission order is not this phase's contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookies_are_secure_over_tls() {
    const HANDLER: &str = r#"
local app = nitr.app()

app:use(nitr.csrf({ secret = "csrf-secret-0123456789" }))

app:get("/cookies", function(req)
    local res = nitr.text("ok")
    -- Every route a cookie leaves the process by. The bare `set` takes no
    -- options table at all, which is the shape a default that lived
    -- inside the options block would miss.
    res.cookies:set("plain", "1")
    res.cookies:set_signed("signed", "2", "cookie-secret-0123456789")
    -- An explicit `secure = false` must still win, or the escape hatch is
    -- gone.
    res.cookies:set("optout", "3", { secure = false })

    local s = nitr.session(req, { secret = "0123456789abcdef" })
    s.user = "u1"
    s:save(res)
    return res
end)

return app
"#;

    let mut server = TlsServer::spawn_with("tls-cookies", HANDLER, |_| {}).await;

    let resp = server
        .client()
        .get(server.url("/cookies"))
        .send()
        .await
        .expect("a TLS request must succeed");
    assert_eq!(resp.status(), 200);

    let cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().expect("ascii").to_string())
        .collect();

    let find = |name: &str| {
        cookies
            .iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no `{name}` cookie in {cookies:?}"))
            .clone()
    };

    // Everything Nitr serializes carries `Secure` on a TLS server…
    for name in ["plain", "signed", "session", "_csrf"] {
        let cookie = find(name);
        assert!(
            cookie.contains("Secure"),
            "`{name}` must be Secure on a TLS server: {cookie}"
        );
    }
    // …and the session and CSRF cookies keep their other attributes.
    for name in ["session", "_csrf"] {
        let cookie = find(name);
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("SameSite=Lax"), "{cookie}");
    }
    // …but an explicit opt-out still wins.
    let optout = find("optout");
    assert!(
        !optout.contains("Secure"),
        "an explicit `secure = false` must beat the default: {optout}"
    );

    server.stop().await;
}

/// T-4 (audit 3, phase 5): `[limits] header_read_ms = 0` disables hyper's
/// header deadline — and must NOT unbound the TLS handshake. The
/// handshake deadline is its own bound (`[tls] handshake_ms`, or a
/// bounded default), so stalled ClientHellos release their connection
/// slots and a real client is still served. Deleting the handshake
/// timeout fails this test: the stalled connections hold every slot
/// forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_handshake_is_dropped_even_with_header_read_disabled() {
    let mut server = TlsServer::spawn("tls-stall", |cfg| {
        cfg.limits.header_read_ms = 0;
        cfg.limits.max_connections = 4;
        cfg.tls.handshake_ms = Some(500);
    })
    .await;

    // Four connections that send one TLS record byte and then stall —
    // exactly the connection-slot budget.
    let mut stalled = Vec::new();
    for _ in 0..4 {
        let mut sock = tokio::net::TcpStream::connect(server.addr)
            .await
            .expect("connect");
        sock.write_all(&[0x16]).await.expect("one record byte");
        stalled.push(sock);
    }
    // Give the handshake deadline room to fire and the permits to return.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // A real client must be served — pre-fix (no deadline with
    // header_read_ms = 0) every slot is still held and this times out.
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        server.client().get(server.url("/hello")).send(),
    )
    .await
    .expect("the listener must not be wedged by stalled handshakes")
    .expect("a real TLS request succeeds");
    assert_eq!(resp.status(), 200);

    drop(stalled);
    server.stop().await;
}

/// T-1 (audit 3, phase 5): a reload swaps in renewed TLS material
/// without a restart. Trust is the fingerprint: a client that trusts
/// ONLY the new certificate fails before the swap and succeeds after
/// it, and a client that handshook before the swap keeps its
/// connection. A reload over a broken key file keeps the old material.
///
/// The reload is triggered through dev mode's file watcher, which feeds
/// the same channel `SIGHUP` does — a signal would hit every test in
/// this process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_swaps_the_certificate_without_dropping_connections() {
    let mut server = TlsServer::spawn("tls-reload", |cfg| {
        cfg.dev_mode = true;
    })
    .await;

    // A pre-swap connection, kept alive by the client pool.
    let old_client = server.client();
    let resp = old_client
        .get(server.url("/hello"))
        .send()
        .await
        .expect("pre-reload request");
    assert_eq!(resp.status(), 200);

    // Renewed material: a second identity written over the same paths,
    // atomically (write, rename) the way certbot does.
    let renewed =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("generate the renewed certificate");
    let new_cert_pem = renewed.cert.pem();
    let staged_cert = server.dir.write("cert.pem.new", &new_cert_pem);
    let staged_key = server
        .dir
        .write("key.pem.new", renewed.signing_key.serialize_pem());
    std::fs::rename(&staged_cert, server.identity.cert_path.as_path()).expect("swap cert");
    std::fs::rename(&staged_key, server.identity.key_path.as_path()).expect("swap key");
    // Trigger the reload: a save under the watched tree.
    server.dir.write("app.lua", TOUCHED_APP);

    // A client that trusts ONLY the renewed certificate: succeeds exactly
    // when the acceptor has been swapped.
    let root = reqwest::Certificate::from_pem(new_cert_pem.as_bytes()).expect("new root");
    let new_client = harness::http_client_builder()
        .tls_certs_only([root])
        .build()
        .expect("client");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(resp) = new_client.get(server.url("/hello")).send().await
            && resp.status() == 200
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the renewed certificate was never presented: the reload did not swap the acceptor"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // The pre-swap client's pooled connection survived the swap: an
    // established connection keeps the acceptor it handshook with.
    let resp = old_client
        .get(server.url("/hello"))
        .send()
        .await
        .expect("the pre-reload connection must survive the swap");
    assert_eq!(resp.status(), 200);

    // The failure path: a half-written key must keep the CURRENT
    // material, not stop terminating TLS.
    std::fs::write(server.identity.key_path.as_path(), "not a key any more").expect("break key");
    server.dir.write("app.lua", TOUCHED_APP_2);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let resp = new_client
        .get(server.url("/hello"))
        .send()
        .await
        .expect("a failed TLS reload must keep the old acceptor serving");
    assert_eq!(resp.status(), 200);

    server.stop().await;
}

/// The handler variants the reload test saves to trigger the watcher;
/// same routes, so either compiles and serves.
const TOUCHED_APP: &str = r#"
local app = nitr.app()
app:get("/hello", function(req)
    return { status = 200, headers = { ["Content-Type"] = "text/plain" }, body = "over tls: " .. req.path }
end)
return app
"#;
const TOUCHED_APP_2: &str = r#"
local app = nitr.app()
app:get("/hello", function(req)
    return { status = 200, headers = { ["Content-Type"] = "text/plain" }, body = "over tls: " .. req.path }
end)
-- touched again
return app
"#;

/// T-5 (audit 3, phase 5): the two recipes `docs-feat/tls.md` documents,
/// executed rather than quoted — the HSTS middleware and the
/// plaintext-to-HTTPS redirect instance (path and query preserved, the
/// canonical host from configuration and never from the request's Host
/// header).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_documented_hsts_and_redirect_recipes_work() {
    // The HSTS half, over real TLS.
    let mut server = TlsServer::spawn_with(
        "tls-hsts",
        r#"
        local app = nitr.app()
        app:use(function(next)
            return function(req)
                local res = next(req)
                res.headers["Strict-Transport-Security"] = "max-age=15552000"
                return res
            end
        end)
        app:get("/hello", function(req) return nitr.text("ok") end)
        return app
        "#,
        |_| {},
    )
    .await;
    let resp = server
        .client()
        .get(server.url("/hello"))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.headers()["strict-transport-security"],
        "max-age=15552000"
    );
    server.stop().await;

    // The redirect half, on a plaintext instance — the doc's snippet
    // verbatim, including the Host-safety property: whatever Host the
    // client sends, the target is the configured canonical origin.
    let mut plain = harness::TestServer::builder("tls-redirect")
        .handler(
            r#"
local app = nitr.app()
local CANONICAL = "https://example.com"

local function to_https(req)
    local target = CANONICAL .. req.path
    if req.uri.query ~= "" then
        target = target .. "?" .. req.uri.query
    end
    return nitr.redirect(target, 301)
end

app:get("/", to_https)
app:get("/*", to_https)

return app
"#,
        )
        .builtins(nitr::Builtins::HTTP)
        .config(|cfg| cfg.workers = 1)
        .spawn()
        .await;

    let client = harness::http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    for (path, want) in [
        ("/", "https://example.com/"),
        ("/a/b?x=1&y=2", "https://example.com/a/b?x=1&y=2"),
    ] {
        let resp = client
            .get(plain.url(path))
            // An attacker-supplied Host must not steer the target.
            .header("host", "evil.example.net")
            .send()
            .await
            .expect("request");
        assert_eq!(resp.status(), 301, "{path}");
        assert_eq!(resp.headers()["location"], want, "{path}");
    }

    plain.stop().await;
}
