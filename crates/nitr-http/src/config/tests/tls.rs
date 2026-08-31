// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `[tls]` section: parsing, refusals, env layering.

use super::*;

/// A `[tls]` section over two files that exist. Their *contents* are
/// irrelevant here: validation is about the shape of the
/// configuration, and the PEM itself is `tls.rs`'s subject.
fn tls_base() -> (Config, PathBuf, PathBuf) {
    let cert = write_temp_config("cert.pem", "not a real certificate");
    let key = write_temp_config("key.pem", "not a real key");
    let mut cfg = valid_base();
    cfg.tls = TlsConfig {
        enabled: true,
        cert: Some(cert.clone()),
        key: Some(key.clone()),
        min_version: None,
        handshake_ms: None,
    };
    (cfg, cert, key)
}

#[test]
fn the_tls_section_parses_and_round_trips() {
    let path = write_temp_config(
        "tls.toml",
        "[tls]\nenabled = true\ncert = \"tls/fullchain.pem\"\n\
         key = \"tls/privkey.pem\"\nmin_version = \"1.3\"\n",
    );
    let cfg = Config::from_file(&path).expect("parse [tls]");
    std::fs::remove_file(&path).ok();
    assert!(cfg.tls.enabled);
    assert_eq!(
        cfg.tls.cert.as_deref(),
        Some(Path::new("tls/fullchain.pem"))
    );
    assert_eq!(cfg.tls.key.as_deref(), Some(Path::new("tls/privkey.pem")));
    assert_eq!(cfg.tls.min_version.as_deref(), Some("1.3"));

    // Off by default, and absent from a rendered config that never
    // set it — a private key path is not something to print by habit.
    assert!(!Config::default().tls.enabled);

    // `nitr check --print-config` must render a loadable file.
    let rendered = cfg.effective_toml().expect("render");
    let path = write_temp_config("tls-rt.toml", &rendered);
    let reparsed = Config::from_file(&path).expect("reparse");
    std::fs::remove_file(&path).ok();
    assert_eq!(reparsed.tls.cert, cfg.tls.cert);
    assert_eq!(reparsed.tls.key, cfg.tls.key);
    assert_eq!(reparsed.tls.min_version, cfg.tls.min_version);
}

/// Half a `[tls]` section must fail at config load, naming the key
/// that is missing — not at the first connection, which is where a
/// lazy check would surface it: after traffic has been pointed at the
/// port, looking like a network fault.
/// Without the feature there is no handshake to configure, so asking
/// for one is a startup refusal naming the feature to rebuild with —
/// the same contract a `[std] features` entry with no Cargo feature
/// behind it gets.
#[cfg(not(feature = "tls"))]
#[test]
fn an_enabled_tls_section_without_the_feature_says_so() {
    let (cfg, cert, key) = tls_base();
    let err = cfg.validate().expect_err("no tls feature compiled in");
    let msg = err.to_string();
    assert!(msg.contains("[tls]"), "got: {msg}");
    assert!(msg.contains("`tls` feature"), "got: {msg}");
    std::fs::remove_file(&cert).ok();
    std::fs::remove_file(&key).ok();
}

#[cfg(feature = "tls")]
#[test]
fn an_enabled_tls_section_needs_both_paths() {
    let (cfg, cert, key) = tls_base();
    cfg.validate().expect("a complete [tls] section validates");

    let mut half = cfg.clone();
    half.tls.key = None;
    let err = half.validate().expect_err("cert without key");
    assert!(err.to_string().contains("requires `key`"), "got: {err}");

    let mut half = cfg.clone();
    half.tls.cert = None;
    let err = half.validate().expect_err("key without cert");
    assert!(err.to_string().contains("requires `cert`"), "got: {err}");

    let mut none = cfg.clone();
    none.tls.cert = None;
    none.tls.key = None;
    let err = none.validate().expect_err("neither path");
    assert!(err.to_string().contains("[tls]"), "got: {err}");

    // A path that does not exist is refused here too, so a typo is a
    // startup error naming the setting.
    let mut missing = cfg.clone();
    missing.tls.cert = Some(PathBuf::from("/nonexistent/nitr/fullchain.pem"));
    let err = missing.validate().expect_err("missing cert file");
    assert!(err.to_string().contains("[tls] cert"), "got: {err}");

    // A directory is not a PEM file.
    let mut wrong = cfg.clone();
    wrong.tls.key = Some(std::env::temp_dir());
    let err = wrong.validate().expect_err("a directory as the key");
    assert!(err.to_string().contains("[tls] key"), "got: {err}");

    // Disabled skips every check, so a half-written section can sit
    // in a file until somebody turns it on.
    let mut off = cfg.clone();
    off.tls.enabled = false;
    off.tls.cert = Some(PathBuf::from("/nonexistent/anything"));
    off.tls.key = None;
    off.validate().expect("a disabled [tls] is not validated");

    std::fs::remove_file(&cert).ok();
    std::fs::remove_file(&key).ok();
}

#[cfg(feature = "tls")]
#[test]
fn tls_min_version_is_strict() {
    let (mut cfg, cert, key) = tls_base();
    for accepted in ["1.2", "1.3"] {
        cfg.tls.min_version = Some(accepted.into());
        cfg.validate()
            .unwrap_or_else(|err| panic!("min_version {accepted}: {err}"));
    }
    for rejected in ["1.1", "1.0", "TLSv1.2", "1.3 ", "13"] {
        cfg.tls.min_version = Some(rejected.into());
        let err = cfg.validate().expect_err("unknown min_version");
        assert!(err.to_string().contains("min_version"), "got: {err}");
        assert!(err.to_string().contains(rejected), "got: {err}");
    }
    std::fs::remove_file(&cert).ok();
    std::fs::remove_file(&key).ok();
}

/// `NITR_TLS_*` layers over the file exactly as every other section's
/// variables do — checked side by side with `NITR_COMPRESSION_ENABLED`
/// so "the same way" is asserted rather than assumed.
#[test]
fn tls_env_overrides_layer_like_every_other_section() {
    let mut cfg = Config::default();
    cfg.tls.cert = Some(PathBuf::from("from-toml.pem"));
    cfg.tls.min_version = Some("1.2".into());
    let env: [(&str, &str); 3] = [
        ("NITR_TLS_ENABLED", "true"),
        ("NITR_TLS_CERT", "from-env.pem"),
        ("NITR_TLS_KEY", "from-env.key"),
    ];
    cfg.apply_env_with(&|name| {
        env.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| (*v).to_string())
    })
    .expect("apply");
    assert!(cfg.tls.enabled, "NITR_TLS_ENABLED must win");
    assert_eq!(cfg.tls.cert.as_deref(), Some(Path::new("from-env.pem")));
    assert_eq!(cfg.tls.key.as_deref(), Some(Path::new("from-env.key")));
    // Untouched by the environment, so the file's value survives.
    assert_eq!(cfg.tls.min_version.as_deref(), Some("1.2"));

    // An empty value means "not set", the same rule the rest of the
    // layering follows, so it must not clear the file's value.
    let mut cfg = Config::default();
    cfg.tls.cert = Some(PathBuf::from("from-toml.pem"));
    cfg.apply_env_with(&|name| (name == "NITR_TLS_CERT").then(String::new))
        .expect("apply");
    assert_eq!(cfg.tls.cert.as_deref(), Some(Path::new("from-toml.pem")));

    // An unparseable boolean is refused naming its variable — the
    // same shape of failure `NITR_COMPRESSION_ENABLED` gives.
    for var in ["NITR_TLS_ENABLED", "NITR_COMPRESSION_ENABLED"] {
        let err = Config::default()
            .apply_env_with(&|name| (name == var).then(|| "yes".to_string()))
            .expect_err("not a boolean");
        assert!(err.to_string().contains(var), "got: {err}");
    }
}

proptest::proptest! {
    /// Property: validation of `[tls]` is total, and an accepted
    /// section always carries both paths.
    ///
    /// The converse is what actually matters operationally: there is
    /// no combination of settings that starts a TLS listener with a
    /// certificate but no key, or the other way round. Every refusal
    /// must also name `[tls]`, so the message points at the section
    /// to fix.
    #[test]
    fn prop_a_validating_tls_section_always_has_both_paths(
        enabled in proptest::bool::ANY,
        cert in proptest::option::of(0usize..3),
        key in proptest::option::of(0usize..3),
        min_version in proptest::option::of(
            proptest::sample::select(vec!["1.2", "1.3", "1.1", "", "tls1.3"])
        ),
    ) {
        // 0 = a real file, 1 = a directory, 2 = nothing there.
        let real = write_temp_config("prop.pem", "x");
        let pick = |slot: Option<usize>| match slot {
            Some(0) => Some(real.clone()),
            Some(1) => Some(std::env::temp_dir()),
            Some(2) => Some(PathBuf::from("/nonexistent/nitr/prop.pem")),
            _ => None,
        };
        let mut cfg = valid_base();
        cfg.tls = TlsConfig {
            enabled,
            cert: pick(cert),
            key: pick(key),
            min_version: min_version.map(String::from),
            handshake_ms: None,
        };
        let outcome = cfg.validate();
        std::fs::remove_file(&real).ok();

        match outcome {
            Ok(()) => {
                // Without the Cargo feature there is no handshake to
                // configure, so an enabled section can never validate
                // at all — the property holds from the other side.
                proptest::prop_assert!(
                    !enabled || cfg!(feature = "tls"),
                    "an enabled [tls] validated in a build with no TLS support"
                );
                proptest::prop_assert!(
                    !enabled || (cert == Some(0) && key == Some(0)),
                    "an enabled [tls] validated without two real files: \
                     cert={cert:?} key={key:?}"
                );
                proptest::prop_assert!(
                    !enabled || matches!(
                        cfg.tls.min_version.as_deref(),
                        None | Some("1.2") | Some("1.3")
                    ),
                    "an unknown min_version validated: {:?}",
                    cfg.tls.min_version
                );
            }
            Err(err) => {
                let msg = err.to_string();
                // A disabled section is never the reason for a
                // refusal, so any refusal here is about [tls] itself.
                proptest::prop_assert!(
                    enabled,
                    "a disabled [tls] caused a refusal: {msg}"
                );
                proptest::prop_assert!(
                    msg.contains("[tls]"),
                    "the refusal must name the section: {msg}"
                );
            }
        }
    }

    /// Property: `NITR_TLS_*` composes with the file the way the rest
    /// of the layering does — present-and-non-empty wins, anything
    /// else leaves the parsed value alone — and the pass is
    /// idempotent, so re-running it cannot drift.
    #[test]
    fn prop_tls_env_overrides_compose_like_the_rest(
        toml_cert in proptest::option::of("[a-z]{1,8}\\.pem"),
        env_cert in proptest::option::of("[a-z]{0,8}"),
        env_enabled in proptest::option::of(
            proptest::sample::select(vec!["true", "false", "", "TRUE"])
        ),
    ) {
        let mut cfg = Config::default();
        cfg.tls.cert = toml_cert.as_deref().map(PathBuf::from);
        let lookup = |name: &str| match name {
            "NITR_TLS_CERT" => env_cert.clone(),
            "NITR_TLS_ENABLED" => env_enabled.map(String::from),
            _ => None,
        };
        let outcome = cfg.apply_env_with(&lookup);

        // Only a value that is neither absent nor empty may speak.
        let effective_enabled = env_enabled.filter(|v| !v.is_empty());
        match outcome {
            Ok(()) => {
                proptest::prop_assert!(
                    !matches!(effective_enabled, Some("TRUE")),
                    "`TRUE` is not a Rust bool literal and must be refused"
                );
                proptest::prop_assert_eq!(
                    cfg.tls.enabled,
                    effective_enabled == Some("true"),
                    "NITR_TLS_ENABLED={:?} did not decide the value",
                    env_enabled
                );
                let effective_cert = env_cert
                    .clone()
                    .filter(|v| !v.is_empty())
                    .or(toml_cert)
                    .map(PathBuf::from);
                proptest::prop_assert_eq!(
                    cfg.tls.cert.clone(),
                    effective_cert,
                    "the env value must win only when it is set and non-empty"
                );
                // Applying the same environment again changes nothing.
                let before = cfg.clone();
                cfg.apply_env_with(&lookup).expect("second pass");
                proptest::prop_assert_eq!(
                    cfg.tls.cert,
                    before.tls.cert,
                    "the override pass is not idempotent"
                );
                proptest::prop_assert_eq!(cfg.tls.enabled, before.tls.enabled);
            }
            Err(err) => {
                let msg = err.to_string();
                proptest::prop_assert!(
                    msg.contains("NITR_TLS_ENABLED"),
                    "only an unparseable boolean can fail here: {msg}"
                );
                proptest::prop_assert!(
                    !matches!(effective_enabled, None | Some("true") | Some("false")),
                    "{:?} is a value that must parse",
                    env_enabled
                );
            }
        }
    }
}

/// `[tls] handshake_ms = 0` is a startup error, never "unbounded"
/// (audit 3, phase 5, T-4): `0` is how `[limits]` spells "disabled",
/// and it is exactly the spelling this key must refuse — the handshake
/// precedes hyper's header machinery, so nothing else can reclaim the
/// connection slot a stalled ClientHello holds.
#[cfg(feature = "tls")]
#[test]
fn a_zero_handshake_deadline_is_a_startup_error() {
    let (mut cfg, cert, key) = tls_base();
    cfg.tls.handshake_ms = Some(0);
    let err = cfg.validate().expect_err("handshake_ms = 0");
    assert!(err.to_string().contains("handshake_ms"), "got: {err}");
    assert!(err.to_string().contains("unbounded"), "got: {err}");

    // A positive value, and unset, both validate.
    cfg.tls.handshake_ms = Some(10_000);
    cfg.validate().expect("a positive deadline");
    cfg.tls.handshake_ms = None;
    cfg.validate().expect("the bounded default");
    std::fs::remove_file(&cert).ok();
    std::fs::remove_file(&key).ok();
}

/// The `[tls] key` mode predicate (audit 3, phase 5, T-2): owner-only
/// passes, any group/other bit warns — and the check is a *warning*,
/// never a refusal, so a world-readable key still boots.
#[cfg(all(unix, feature = "tls"))]
#[test]
fn a_readable_key_file_warns_and_boots_anyway() {
    use std::os::unix::fs::PermissionsExt as _;

    // The mask itself, pinned: a wrong mask (say `0o007`) passes 0640.
    for private in [0o600, 0o400, 0o100600] {
        assert!(
            super::super::validate::key_mode_is_private(private),
            "{private:o}"
        );
    }
    for exposed in [0o640, 0o644, 0o604, 0o666, 0o100644] {
        assert!(
            !super::super::validate::key_mode_is_private(exposed),
            "{exposed:o}"
        );
    }

    let (cfg, cert, key) = tls_base();
    // World-readable: warns, names the file and the mode, and validates.
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let warnings = cfg.warnings();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("644") && w.contains("key.pem")),
        "expected a key-mode warning, got: {warnings:?}"
    );
    // A wrapped literal missing its `\` continuation renders with runs
    // of spaces; the warning is operator-facing and must not.
    assert!(
        warnings.iter().all(|w| !w.contains("  ")),
        "a warning rendered with literal space runs: {warnings:?}"
    );
    cfg.validate().expect("a readable key must still boot");

    // Owner-only: silent.
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let warnings = cfg.warnings();
    assert!(
        !warnings.iter().any(|w| w.contains("key.pem")),
        "0600 must not warn: {warnings:?}"
    );
    std::fs::remove_file(&cert).ok();
    std::fs::remove_file(&key).ok();
}
