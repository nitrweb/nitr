// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `[tls] cert`/`key` loading: the PEM parse, the certificate/key
//! agreement check, and the protocol-version floor — the whole of what
//! `nitr_http::tls::build` does with two files whose bytes the server
//! does not choose.
//!
//! It does not choose them because they arrive from somewhere else: an
//! ACME client's renewal, a mounted Kubernetes secret, a config
//! management run. Any of those can hand the server a truncated file, a
//! half-written one, the wrong file, or a file from a different host —
//! and the server reads them once, at startup, on the path that decides
//! whether the port is encrypted at all.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u8 use_min | min-version \0 certificate PEM \0 key PEM
//! ```
//!
//! `use_min` decides `Some`/`None` for `min_version`, which is what makes
//! the unset branch reachable at all; the version text is fuzzer-chosen
//! so the name check is driven from both sides rather than only by the
//! two accepted spellings.
//!
//! One valid certificate/key pair is minted per process and never
//! written anywhere. A fuzzer cannot synthesize a matching pair — the
//! success path would otherwise be unreachable and every "must be
//! refused" assertion below would hold vacuously — and committing a real
//! pair as a seed would put a private key in the repository.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **The control still loads.** The minted pair must load on every
//!   single run. This is the target's own tripwire: if it ever stops, the
//!   loader has become one that refuses everything, and every negative
//!   assertion below has silently turned into a no-op.
//! * **An accepted pair really parsed a certificate.** Success implies at
//!   least one `CERTIFICATE` block was in the input, and never more
//!   certificates than the input has `BEGIN CERTIFICATE` markers — which
//!   is what a parser that re-emitted a block, or one that manufactured
//!   an empty chain, would violate.
//! * **Attacker bytes can never be paired with the server's key.**
//!   Feeding the fuzzer's certificate together with the minted *key* must
//!   fail unless the fuzzer reproduced the minted certificate verbatim.
//!   This is the key/certificate agreement check: without it the server
//!   starts and every client fails the handshake, which reads from the
//!   outside like a network fault rather than a misconfiguration.
//! * **…and the mirror image.** The minted certificate with the fuzzer's
//!   key must fail the same way.
//! * **Neither half may be empty.** An empty file is a truncated write,
//!   the most ordinary way for a renewal to go wrong, and it must be
//!   refused naming which half was empty.
//! * **TLS 1.2 is the floor.** `min_version` accepts exactly `"1.2"` and
//!   `"1.3"`; every other spelling — `"1.0"`, `"1.1"`, `"TLSv1.2"`,
//!   anything the fuzzer invents — is refused naming the setting. A
//!   loader that silently fell back to a default for an unrecognized name
//!   would let a typo downgrade the endpoint.
//! * **ALPN says only what the server can speak.** An accepted
//!   configuration advertises `http/1.1` and nothing else; `h2` in that
//!   list would let a client negotiate a protocol that fails *after* a
//!   successful handshake.
//! * **Loading is deterministic.** The same bytes twice give the same
//!   answer, so nothing here depends on allocation addresses, iteration
//!   order, or a process-global crypto provider that another dependency
//!   may have filled in first.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_http::fuzzing::{TlsLoaded, build_tls};

/// The PEM marker a certificate block opens with.
const CERT_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";

/// The `min_version` names that must be accepted, and nothing else. TLS
/// 1.0 and 1.1 are deprecated (RFC 8996) and are deliberately not here.
const ACCEPTED_VERSIONS: [&str; 2] = ["1.2", "1.3"];

/// A valid self-signed pair, minted once for the whole process.
///
/// It is the control for every negative assertion: the loader has to
/// accept *something*, or "the fuzzer's bytes were refused" means
/// nothing.
struct Control {
    cert: String,
    key: String,
}

fn control() -> &'static Control {
    static CONTROL: OnceLock<Control> = OnceLock::new();
    CONTROL.get_or_init(|| {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate the control certificate");
        Control {
            cert: generated.cert.pem(),
            key: generated.signing_key.serialize_pem(),
        }
    })
}

/// One load, reduced to what can be asserted on: `ServerConfig` says
/// almost nothing about itself, so the ALPN list and the certificate
/// count are carried out alongside it.
type Load = Result<(usize, Vec<Vec<u8>>), String>;

fn load(cert_pem: &[u8], key_pem: &[u8], min_version: Option<&str>) -> Load {
    build_tls(cert_pem, key_pem, min_version)
        .map(|loaded: TlsLoaded| (loaded.certs, loaded.config.alpn_protocols.clone()))
        .map_err(|err| err.to_string())
}

/// Whether `haystack` contains `needle` — used to spell out the one
/// theoretical way an attacker-supplied half could legitimately pair with
/// the control's other half: by reproducing it byte for byte.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack.windows(needle.len()).filter(|w| *w == needle).count()
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let use_min = input.flag();
    let version_text = input.text();
    let cert_pem = input.field();
    let key_pem = input.rest();
    let min_version = use_min.then(|| version_text.as_ref());
    let control = control();

    if std::env::var_os("NITR_FUZZ_DEBUG").is_some() {
        eprintln!(
            "DEBUG min_version={min_version:?} cert={:?} key={:?} -> {:?}",
            String::from_utf8_lossy(cert_pem),
            String::from_utf8_lossy(key_pem),
            load(cert_pem, key_pem, min_version),
        );
    }

    // --- The tripwire ------------------------------------------------
    // If this ever fails the loader has become one that refuses
    // everything, and every negative assertion below is vacuous.
    let (certs, alpn) = load(control.cert.as_bytes(), control.key.as_bytes(), None)
        .expect("the control pair must always load");
    assert_eq!(certs, 1, "the control is a single self-signed certificate");
    assert_eq!(
        alpn,
        vec![b"http/1.1".to_vec()],
        "the server speaks HTTP/1.1 only; anything else here is a protocol it \
         cannot serve once negotiated"
    );

    // --- The attacker's own bytes, both halves ------------------------
    let loaded = load(cert_pem, key_pem, min_version);

    // Deterministic: same bytes, same answer. A dependency on a
    // process-global crypto provider, or on anything an allocator
    // decides, would show up here.
    assert_eq!(
        loaded,
        load(cert_pem, key_pem, min_version),
        "loading the same PEM twice gave two different answers"
    );

    // The version floor, from both sides.
    match min_version {
        Some(name) if !ACCEPTED_VERSIONS.contains(&name) => {
            let err = loaded
                .as_ref()
                .err()
                .unwrap_or_else(|| panic!("min_version {name:?} was accepted"));
            assert!(
                err.contains("min_version"),
                "refusing min_version {name:?} must name the setting: {err}"
            );
        }
        _ => {}
    }

    if let Ok((certs, alpn)) = &loaded {
        // A configuration was built, so a certificate really was parsed
        // out of these bytes — and no more of them than the input holds.
        assert!(*certs >= 1, "an accepted chain must hold a certificate");
        assert!(
            contains(cert_pem, CERT_BEGIN),
            "a chain was accepted from bytes with no CERTIFICATE block"
        );
        assert!(
            *certs <= count(cert_pem, CERT_BEGIN),
            "{certs} certificates out of {} BEGIN markers",
            count(cert_pem, CERT_BEGIN)
        );
        assert_eq!(
            *alpn,
            vec![b"http/1.1".to_vec()],
            "an accepted configuration advertised something other than http/1.1"
        );
        // Only the two accepted spellings can have got here.
        assert!(
            min_version.is_none_or(|name| ACCEPTED_VERSIONS.contains(&name)),
            "min_version {min_version:?} was accepted"
        );
    }

    // --- One attacker half against one real half ----------------------
    // The pair has to *agree*. Reproducing the control's other half
    // verbatim is the only way an accepted answer could be honest, and a
    // fuzzer has no way to derive it — so in practice both of these are
    // "must be refused".
    let borrowed_key = load(cert_pem, control.key.as_bytes(), None);
    assert!(
        borrowed_key.is_err() || contains(cert_pem, control.cert.as_bytes()),
        "a certificate the fuzzer supplied was paired with the server's own key \
         without carrying its public half"
    );
    let borrowed_cert = load(control.cert.as_bytes(), key_pem, None);
    assert!(
        borrowed_cert.is_err() || contains(key_pem, control.key.as_bytes()),
        "a key the fuzzer supplied was accepted for the server's own certificate"
    );

    // --- A truncated write, the ordinary renewal failure --------------
    // Whatever the other half holds, an empty file can never be accepted.
    assert!(
        load(b"", key_pem, min_version).is_err(),
        "an empty certificate file was accepted"
    );
    assert!(
        load(cert_pem, b"", min_version).is_err(),
        "an empty key file was accepted"
    );
    // And each refusal names the half that was empty — checked against a
    // known-good other half, so the message under test cannot be the
    // other half's complaint instead.
    let no_cert = load(b"", control.key.as_bytes(), None).expect_err("an empty certificate file");
    assert!(
        no_cert.contains("CERTIFICATE"),
        "an empty certificate file must name the certificate: {no_cert}"
    );
    let no_key = load(control.cert.as_bytes(), b"", None).expect_err("an empty key file");
    assert!(
        no_key.contains("private key"),
        "an empty key file must name the key: {no_key}"
    );
});
