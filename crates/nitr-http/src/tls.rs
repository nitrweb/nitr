// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Inbound TLS termination: PEM loading and the rustls server
//! configuration built from it.
//!
//! Everything here happens exactly once, at startup. The handshake itself
//! lives in [`crate::server`], inside the per-connection task — a slow or
//! hostile `ClientHello` must never be able to stall the accept loop.
//!
//! The crypto provider is named explicitly rather than taken from
//! rustls's process-global default. `ring` is the provider this workspace
//! builds everywhere (see the root `Cargo.toml`), and a process default
//! is a single global slot that any dependency — or an embedder's own
//! code — may have already filled with something else. Passing the
//! provider in means the server's cipher suites are a property of this
//! module, not of link order.

use std::path::Path;
use std::sync::Arc;

use nitr_core::{Error, Result};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::TlsConfig;

/// The application protocols the server advertises during the handshake.
///
/// Exactly one, because the server is exactly one: connections are served
/// by `hyper::server::conn::http1`. Advertising `h2` as well would let a
/// client negotiate a protocol nothing here can speak, turning a working
/// connection into a parse error after the handshake had already
/// succeeded.
pub const ALPN_PROTOCOLS: [&[u8]; 1] = [b"http/1.1"];

/// A loaded certificate/key pair and the rustls configuration built from
/// it.
///
/// The counts are carried alongside the configuration because they are
/// what a caller can meaningfully assert on: `ServerConfig` exposes
/// almost nothing about the material it was built from.
#[derive(Debug)]
pub struct Loaded {
    /// The finished server configuration, shared by every connection.
    pub config: Arc<ServerConfig>,
    /// Certificates parsed out of the certificate PEM (leaf plus any
    /// intermediates).
    pub certs: usize,
}

/// Loads the configured certificate and key from disk.
///
/// Called once, before the accept loop starts, so a broken pair is a
/// startup failure naming the file rather than a connection that dies
/// mid-handshake after traffic has already been pointed at the port.
pub(crate) fn load(cfg: &TlsConfig) -> Result<Loaded> {
    // Validation has already refused an enabled `[tls]` with either path
    // missing; this repeats the message rather than unwrapping, since
    // `load` is reachable from an embedder that built its `TlsConfig` by
    // hand.
    let cert_path = require(cfg.cert.as_deref(), "cert")?;
    let key_path = require(cfg.key.as_deref(), "key")?;
    let cert_pem = read(cert_path, "cert")?;
    let key_pem = read(key_path, "key")?;
    build(&cert_pem, &key_pem, cfg.min_version.as_deref()).map_err(|err| {
        Error::Config(format!(
            "[tls] cannot use {} with {}: {err}",
            cert_path.display(),
            key_path.display()
        ))
    })
}

/// Builds a server configuration from PEM bytes.
///
/// Split from [`load`] so the parsing surface — the part whose input an
/// attacker may control, if the files come from an ACME client or a
/// mounted secret — can be driven directly by tests and by the `tls_pem`
/// fuzz target, with no filesystem in the way.
pub fn build(cert_pem: &[u8], key_pem: &[u8], min_version: Option<&str>) -> Result<Loaded> {
    // The configuration is checked before the file contents, so an
    // unusable `min_version` is reported as such whatever the PEM holds.
    // The other order makes the message an operator sees depend on which
    // of two independent mistakes the parser reached first — and the
    // version name is the one they can fix without touching a key.
    let versions = protocol_versions(min_version)?;
    let certs = parse_certs(cert_pem)?;
    let count = certs.len();
    let key = parse_key(key_pem)?;
    // `ring` by name; see the module docs for why not the process default.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|err| Error::Config(format!("unsupported TLS protocol versions: {err}")))?
        .with_no_client_auth()
        // This is also the key/certificate agreement check: rustls
        // refuses a key whose public half is not the one the leaf
        // certificate carries, which is the misconfiguration that would
        // otherwise surface as every client failing the handshake.
        .with_single_cert(certs, key)
        .map_err(|err| Error::Config(format!("the certificate and key were rejected: {err}")))?;
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();
    Ok(Loaded {
        config: Arc::new(config),
        certs: count,
    })
}

/// TLS 1.2 and 1.3 — the floor, and what an unset `min_version` selects.
///
/// Spelled out instead of reaching for `rustls::ALL_VERSIONS` so the
/// weakest protocol this server will ever negotiate is a decision written
/// down here, not one inherited from whatever a future rustls chooses to
/// put in that list.
const TLS12_AND_UP: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// Only TLS 1.3, for a `[tls] min_version = "1.3"` deployment.
const TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// The rustls version list for a `[tls] min_version` name.
///
/// There is no branch below TLS 1.2 and there is not meant to be one:
/// 1.0 and 1.1 are deprecated by RFC 8996 and unimplemented by rustls, so
/// the only thing accepting their spelling could do is mislead.
fn protocol_versions(
    min_version: Option<&str>,
) -> Result<&'static [&'static rustls::SupportedProtocolVersion]> {
    match min_version {
        None | Some("1.2") => Ok(TLS12_AND_UP),
        Some("1.3") => Ok(TLS13_ONLY),
        Some(other) => Err(Error::Config(format!(
            "unknown [tls] min_version `{other}`: expected \"1.2\" or \"1.3\" \
             (TLS 1.0 and 1.1 are deprecated and not offered)"
        ))),
    }
}

/// Every `CERTIFICATE` block in the PEM, in file order (leaf first).
fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| Error::Config(format!("the certificate PEM is malformed: {err}")))?;
    if certs.is_empty() {
        return Err(Error::Config(
            "the certificate file holds no CERTIFICATE block: it must be PEM, leaf \
             certificate first, not DER and not a key"
                .into(),
        ));
    }
    Ok(certs)
}

/// The first private key in the PEM, in any of the three encodings
/// openssl and the ACME clients emit (PKCS#8, PKCS#1, SEC1).
fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|err| Error::Config(format!("the private key PEM is malformed: {err}")))?
        .ok_or_else(|| {
            Error::Config(
                "the key file holds no private key block: expected PRIVATE KEY, RSA \
                 PRIVATE KEY or EC PRIVATE KEY"
                    .into(),
            )
        })
}

fn require<'a>(path: Option<&'a Path>, key: &str) -> Result<&'a Path> {
    path.ok_or_else(|| {
        Error::Config(format!(
            "[tls] enabled = true requires `{key}`: set [tls] {key} to a PEM file"
        ))
    })
}

fn read(path: &Path, key: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|err| {
        Error::Config(format!(
            "cannot read [tls] {key} = {}: {err}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh self-signed identity. Generated per call, so nothing in
    /// this file is key material that could be committed.
    fn identity() -> (String, String) {
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate a self-signed certificate");
        (key.cert.pem(), key.signing_key.serialize_pem())
    }

    #[test]
    fn a_matching_pair_loads_and_advertises_only_http11() {
        let (cert, key) = identity();
        let loaded = build(cert.as_bytes(), key.as_bytes(), None).expect("a matching pair loads");
        assert_eq!(loaded.certs, 1);
        // The server is HTTP/1.1 only; anything else in this list is a
        // protocol the connection cannot actually speak once negotiated.
        assert_eq!(loaded.config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    /// A chain (leaf + intermediate) is kept whole and in order: a loader
    /// that stopped at the first block would ship a chain clients cannot
    /// verify, and one that reordered it would break path building.
    #[test]
    fn a_chain_keeps_every_certificate() {
        let (leaf, key) = identity();
        let (extra, _) = identity();
        let chain = format!("{leaf}{extra}");
        let loaded = build(chain.as_bytes(), key.as_bytes(), None).expect("a chain loads");
        assert_eq!(loaded.certs, 2, "both blocks must survive the parse");
    }

    #[test]
    fn a_certificate_without_its_key_is_refused() {
        let (cert, _) = identity();
        // The certificate file passed for both: a copy/paste an operator
        // makes, and one that must not silently half-work.
        let err = build(cert.as_bytes(), cert.as_bytes(), None).expect_err("no key present");
        assert!(
            err.to_string().contains("no private key block"),
            "got: {err}"
        );
    }

    #[test]
    fn a_key_without_its_certificate_is_refused() {
        let (_, key) = identity();
        let err = build(key.as_bytes(), key.as_bytes(), None).expect_err("no certificate present");
        assert!(
            err.to_string().contains("no CERTIFICATE block"),
            "got: {err}"
        );
    }

    /// The failure this check exists for: two valid files that simply do
    /// not belong together. Without it the server starts, and every
    /// client fails the handshake with an error that looks like a network
    /// fault.
    #[test]
    fn a_key_that_does_not_match_the_certificate_is_refused() {
        let (cert, _) = identity();
        let (_, other_key) = identity();
        let err = build(cert.as_bytes(), other_key.as_bytes(), None).expect_err("mismatched pair");
        let msg = err.to_string();
        assert!(msg.contains("rejected"), "got: {msg}");
        assert!(
            msg.to_ascii_lowercase().contains("mismatch"),
            "the refusal must say the key does not match, got: {msg}"
        );
    }

    #[test]
    fn malformed_pem_is_refused_rather_than_half_read() {
        let (cert, key) = identity();

        // A block that never ends: the bytes before the truncation must
        // not be accepted as a certificate.
        let truncated = &cert.as_bytes()[..cert.len() / 2];
        let err = build(truncated, key.as_bytes(), None).expect_err("truncated certificate");
        assert!(err.to_string().contains("malformed"), "got: {err}");

        // Base64 that is not base64.
        let garbled = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        let err = build(garbled.as_bytes(), key.as_bytes(), None).expect_err("bad base64");
        assert!(err.to_string().contains("malformed"), "got: {err}");

        // Well-formed PEM whose payload is not a certificate. This one
        // gets past the PEM layer entirely and has to be caught by
        // rustls.
        let not_der = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let err = build(not_der.as_bytes(), key.as_bytes(), None).expect_err("not a certificate");
        assert!(err.to_string().contains("rejected"), "got: {err}");

        // A truncated key.
        let err = build(cert.as_bytes(), &key.as_bytes()[..key.len() / 2], None)
            .expect_err("truncated key");
        assert!(err.to_string().contains("malformed"), "got: {err}");
    }

    #[test]
    fn empty_files_are_refused_and_name_which_one() {
        let (cert, key) = identity();
        let err = build(b"", key.as_bytes(), None).expect_err("empty certificate file");
        assert!(
            err.to_string().contains("no CERTIFICATE block"),
            "got: {err}"
        );
        let err = build(cert.as_bytes(), b"", None).expect_err("empty key file");
        assert!(
            err.to_string().contains("no private key block"),
            "got: {err}"
        );
        // Neither side present is still a certificate error first: the
        // chain is what the message should lead with.
        let err = build(b"", b"", None).expect_err("both empty");
        assert!(
            err.to_string().contains("no CERTIFICATE block"),
            "got: {err}"
        );
    }

    /// TLS 1.2 is the floor and no spelling lowers it.
    ///
    /// This is the invariant with the worst failure mode in the file: a
    /// server that quietly accepted `min_version = "1.0"` would negotiate
    /// a protocol RFC 8996 deprecated, and would do it while its
    /// configuration looked deliberate.
    #[test]
    fn min_version_names_are_strict_and_never_go_below_1_2() {
        let (cert, key) = identity();
        for accepted in ["1.2", "1.3"] {
            build(cert.as_bytes(), key.as_bytes(), Some(accepted))
                .unwrap_or_else(|err| panic!("min_version {accepted} must load: {err}"));
        }
        // Unset is the floor, not "whatever rustls defaults to".
        assert_eq!(
            protocol_versions(None).expect("the default version set"),
            protocol_versions(Some("1.2")).expect("1.2"),
            "an unset min_version must mean exactly TLS 1.2"
        );
        // Nothing below 1.2 is reachable, by any spelling — and the
        // refusal names the version even when the PEM is broken too,
        // because a version typo is fixable without touching a key.
        for rejected in ["1.1", "1.0", "1", "SSLv3", "TLSv1.3", "", "1.4", "0.9"] {
            for (what, cert, key) in [
                ("a good pair", cert.as_str(), key.as_str()),
                ("a broken pair", "", ""),
            ] {
                let err = build(cert.as_bytes(), key.as_bytes(), Some(rejected))
                    .expect_err("unknown min_version");
                assert!(
                    err.to_string().contains("min_version"),
                    "{what}: the refusal must name the setting, got: {err}"
                );
            }
        }
        // The version set itself, so a rustls upgrade that widened
        // `ALL_VERSIONS` could not widen this server with it.
        let names: Vec<_> = protocol_versions(None)
            .expect("versions")
            .iter()
            .map(|v| format!("{:?}", v.version))
            .collect();
        assert_eq!(names, vec!["TLSv1_3", "TLSv1_2"], "unexpected version set");
    }

    /// Loading is by path in production; the message has to say which
    /// setting pointed at the missing file.
    #[test]
    fn a_missing_file_names_the_setting_that_pointed_at_it() {
        let cfg = TlsConfig {
            enabled: true,
            cert: Some("/nonexistent/nitr/cert.pem".into()),
            key: Some("/nonexistent/nitr/key.pem".into()),
            min_version: None,
        };
        let err = load(&cfg).expect_err("missing cert file");
        assert!(err.to_string().contains("[tls] cert"), "got: {err}");

        let cfg = TlsConfig { cert: None, ..cfg };
        let err = load(&cfg).expect_err("no cert configured");
        assert!(err.to_string().contains("requires `cert`"), "got: {err}");
    }
}
