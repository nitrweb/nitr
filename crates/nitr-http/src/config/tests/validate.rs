// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Startup validation: refusals, warnings, and their wording.

use super::*;

/// Legal-but-suspicious combinations are reported as values rather than
/// logged in place, so they can be asserted without a capturing
/// subscriber.
#[test]
fn suspicious_settings_are_reported_as_warnings() {
    // The default configuration carries exactly one warning, and it is
    // load-bearing rather than noise: no TLS and `[cookies] secure =
    // "auto"` means auth cookies really will ship without `Secure`,
    // which is correct for local development and wrong behind a
    // terminating proxy — the case nothing here can detect. Asserted
    // as a set rather than as "empty" so a *new* warning on the
    // default path is still a visible failure.
    let clean = valid_base();
    let warnings = clean.warnings();
    assert_eq!(
        warnings.len(),
        1,
        "the default config must carry only the Secure-cookie warning, got: {warnings:?}"
    );
    assert!(
        warnings[0].contains("without the `Secure` attribute"),
        "got: {warnings:?}"
    );

    // …and it goes away the moment the deployment says how it
    // terminates TLS, in either direction.
    let mut secure = valid_base();
    secure.cookies.secure = CookieSecure::Always;
    assert!(
        secure.warnings().is_empty(),
        "`always` is an explicit answer: {:?}",
        secure.warnings()
    );
    let mut tls = valid_base();
    tls.tls.enabled = true;
    assert!(
        !tls.warnings().iter().any(|w| w.contains("Secure")),
        "TLS on satisfies `auto`: {:?}",
        tls.warnings()
    );
    // `dev_mode` is an explicit "I am developing" switch, so it
    // suppresses the warning; a loopback bind deliberately does not.
    let mut dev = valid_base();
    dev.dev_mode = true;
    assert!(
        dev.warnings().is_empty(),
        "dev_mode suppresses it: {:?}",
        dev.warnings()
    );

    // The full policy table, row by row. `"never"` on a plaintext
    // listener is a consistent answer and stays silent; `"never"`
    // *with* TLS is the contradiction worth naming.
    for (secure, tls, want_warning) in [
        (CookieSecure::Auto, true, false),
        (CookieSecure::Auto, false, true),
        (CookieSecure::Always, true, false),
        (CookieSecure::Always, false, false),
        (CookieSecure::Never, true, true),
        (CookieSecure::Never, false, false),
    ] {
        let mut cfg = valid_base();
        cfg.cookies.secure = secure;
        cfg.tls.enabled = tls;
        let warned = cfg
            .warnings()
            .iter()
            .any(|w| w.contains("without the `Secure` attribute"));
        assert_eq!(
            warned, want_warning,
            "[cookies] secure = {secure:?} with [tls] enabled = {tls}"
        );
    }

    // Above the execution budget, but the pool wait stays under it — the
    // pool-wait contradiction is a hard refusal and would mask this.
    let mut cfg = valid_base();
    cfg.lua.exec_timeout_ms = 5_000;
    cfg.limits.pool_wait_ms = 4_000;
    cfg.limits.body_read_ms = 9_000;
    let warnings = cfg.warnings();
    assert!(
        warnings.iter().any(|w| w.contains("body_read_ms")),
        "the body-read/exec-budget warning must survive the move: {warnings:?}"
    );
    cfg.validate().expect("a warning is never a refusal");
}

/// `"debug"` parses as a name but can never produce a state: mlua's safe
/// constructor refuses `StdLib::DEBUG` outright, so accepting it only
/// defers the failure to boot and reports it in terms of an internal
/// Rust constructor. It is refused where the names are mapped, with a
/// message an operator editing `nitr.toml` can act on.
#[test]
fn the_debug_library_is_refused_by_name() {
    let mut lua = LuaConfig::default();
    lua.stdlib.push("debug".into());
    let err = lua
        .parse_stdlib()
        .expect_err("`debug` must not map to a StdLib flag");
    let msg = err.to_string();
    assert!(
        msg.contains("[lua] stdlib") && msg.contains("debug"),
        "the refusal must name the setting and the library: {msg}"
    );
}

/// A config laid out the way a deployment is: the handler script in
/// its own `scripts/` directory, with `uploads/` a sibling rather than
/// a child.
///
/// [`valid_base`] cannot serve here — it writes the handler straight
/// into the system temp directory, which would make `require`'s root
/// `/tmp` and every upload directory on the machine "inside" it. The
/// layout is load-bearing, not incidental.
fn upload_base(label: &str) -> (Config, PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("nitr-up-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let scripts = base.join("scripts");
    let uploads = base.join("uploads");
    std::fs::create_dir_all(&scripts).expect("mkdir scripts");
    std::fs::create_dir_all(&uploads).expect("mkdir uploads");
    std::fs::write(scripts.join("app.lua"), "-- test handler").expect("write handler");
    let cfg = Config {
        handler_script: scripts.join("app.lua"),
        ..Config::default()
    };
    (cfg, base, uploads)
}

/// `[multipart] upload_dir` must exist, be a directory, and be
/// writable — checked at startup, because the alternative is a 500 on
/// the first upload that nobody can reproduce.
#[test]
fn the_upload_directory_is_validated_at_startup() {
    let (mut cfg, base, uploads) = upload_base("validated");

    // The sibling layout validates.
    cfg.multipart.upload_dir = Some(uploads.clone());
    cfg.validate().expect("a writable upload dir validates");

    // Missing entirely.
    cfg.multipart.upload_dir = Some(base.join("nope"));
    let err = cfg.validate().expect_err("a missing upload dir");
    let msg = err.to_string();
    assert!(msg.contains("[multipart] upload_dir"), "got: {msg}");
    assert!(msg.contains("does not exist"), "got: {msg}");

    // A file where a directory belongs.
    cfg.multipart.upload_dir = Some(cfg.handler_script.clone());
    let err = cfg.validate().expect_err("a file, not a directory");
    assert!(
        err.to_string().contains("must be a directory"),
        "got: {err}"
    );

    // Present but unwritable: existence is not writability, and the
    // refusal has to name the setting.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let locked = base.join("locked");
        std::fs::create_dir_all(&locked).expect("mkdir locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).expect("chmod");
        cfg.multipart.upload_dir = Some(locked.clone());
        // Running as root defeats the permission bits entirely, so the
        // assertion only holds where the mode is actually enforced.
        if std::fs::File::create(locked.join(".probe")).is_err() {
            let err = cfg.validate().expect_err("an unwritable upload dir");
            let msg = err.to_string();
            assert!(msg.contains("[multipart] upload_dir"), "got: {msg}");
            assert!(msg.contains("cannot be written to"), "got: {msg}");
        }
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700));
    }

    let _ = std::fs::remove_dir_all(&base);
}

/// An upload root under the handler script's directory is the
/// upload-to-RCE chain spelled out in TOML: `require` is pinned there,
/// so an uploaded `.lua` file becomes a loadable module. It refuses to
/// boot rather than warning.
#[test]
fn an_upload_directory_inside_the_require_root_refuses_to_boot() {
    let (mut cfg, base, _) = upload_base("rce-chain");
    // Inside `scripts/`, where `require` is pinned — an uploaded
    // `evil.lua` here is `require("evil")`.
    let inside = base.join("scripts").join("uploads");
    std::fs::create_dir_all(&inside).expect("mkdir");
    cfg.multipart.upload_dir = Some(inside);

    let err = cfg
        .validate()
        .expect_err("an upload dir inside package_dir");
    let msg = err.to_string();
    assert!(msg.contains("[multipart] upload_dir"), "got: {msg}");
    assert!(
        msg.contains("loadable Lua module"),
        "the refusal must say why it matters: {msg}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// The same refusal, for a handler script named without any
/// directory at all.
///
/// This is the shape that once slipped through: `"app.lua".parent()`
/// is `Some("")`, which fails to canonicalize, so a guard that
/// canonicalized the raw parent silently skipped itself — while
/// `runtime_opts` resolved the same empty parent to `.` and pinned
/// `require` to the working directory. The check and the runtime
/// disagreed about where modules load from, and the disagreement
/// favoured the attacker. Both now go through
/// [`Config::package_dir`].
#[test]
fn a_bare_handler_script_still_refuses_an_upload_dir_beside_it() {
    let base = std::env::temp_dir().join(format!("nitr-up-bare-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("uploads")).expect("mkdir uploads");
    std::fs::write(base.join("app.lua"), "-- handler").expect("write handler");

    // The working directory *is* the require root for a bare name, so
    // the test has to run from `base` for the layout to be the real
    // one rather than a path-string coincidence.
    let previous = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&base).expect("chdir");

    let cfg = Config {
        handler_script: PathBuf::from("app.lua"),
        multipart: MultipartConfig {
            upload_dir: Some(PathBuf::from("uploads")),
        },
        ..Config::default()
    };
    let result = cfg.validate();

    std::env::set_current_dir(&previous).expect("restore cwd");
    let _ = std::fs::remove_dir_all(&base);

    let err = result.expect_err("a bare handler name must not skip the check");
    assert!(
        err.to_string().contains("loadable Lua module"),
        "got: {err}"
    );
}

/// [`Config::package_dir`] is the single source of the `require` root,
/// and it must agree with what `runtime_opts` actually hands the
/// runtime for every way a handler path can be spelled.
#[test]
fn the_require_root_is_derived_identically_everywhere() {
    for (script, expected) in [
        ("app.lua", "."),
        ("./app.lua", "."),
        ("scripts/app.lua", "scripts"),
        ("/srv/app/scripts/app.lua", "/srv/app/scripts"),
    ] {
        let cfg = Config {
            handler_script: PathBuf::from(script),
            ..Config::default()
        };
        assert_eq!(
            cfg.package_dir(),
            Path::new(expected),
            "package_dir for {script}"
        );
        let opts = cfg.runtime_opts().expect("runtime opts");
        assert_eq!(
            opts.package_dir.as_deref(),
            Some(Path::new(expected)),
            "runtime_opts must pin `require` to the same root for {script}"
        );
    }
}

/// An upload root under `[static] dir` serves uploaded bytes back to
/// browsers. A real deployment shape, so it warns and still boots —
/// the contrast with the `package_dir` case, which refuses.
#[test]
fn an_upload_directory_inside_the_static_root_only_warns() {
    let (mut cfg, base, _) = upload_base("static-overlap");
    // `public/uploads` — served, and written by uploads.
    let public = base.join("public");
    let uploads = public.join("uploads");
    std::fs::create_dir_all(&uploads).expect("mkdir");
    cfg.static_files.dir = Some(public);
    cfg.multipart.upload_dir = Some(uploads);

    let warnings = cfg.warnings();
    assert!(
        warnings.iter().any(|w| w.contains("served back over HTTP")),
        "the overlap must be reported: {warnings:?}"
    );
    cfg.validate().expect("a warning is never a refusal");
    let _ = std::fs::remove_dir_all(&base);
}

/// The `[multipart]` section parses in every build, including one
/// without the `multipart` feature — a config file that stops being
/// readable depending on compilation flags is not portable. Plain
/// `cargo test -p nitr-http` *is* that build (`default = []`).
#[test]
fn the_multipart_section_parses_without_the_multipart_feature() {
    let toml = r#"
        handler_script = "app.lua"
        [multipart]
        upload_dir = "uploads"
    "#;
    let cfg: Config = toml::from_str(toml).expect("[multipart] must always parse");
    assert_eq!(
        cfg.multipart.upload_dir,
        Some(PathBuf::from("uploads")),
        "the value must survive the parse, not just the section"
    );
}

#[test]
fn contradictions_are_startup_errors() {
    let ok = valid_base();
    ok.validate().expect("a sane config validates");

    let mut cfg = valid_base();
    cfg.workers = 2;
    cfg.max_streams = Some(5);
    let err = cfg.validate().expect_err("max_streams > workers");
    assert!(err.to_string().contains("max_streams"), "got: {err}");

    let mut cfg = valid_base();
    cfg.limits.pool_wait_ms = 60_000;
    cfg.lua.exec_timeout_ms = 5_000;
    let err = cfg.validate().expect_err("pool_wait > exec budget");
    assert!(err.to_string().contains("pool_wait_ms"), "got: {err}");

    let mut cfg = valid_base();
    cfg.health.readiness = cfg.health.liveness.clone();
    let err = cfg.validate().expect_err("identical probe paths");
    assert!(err.to_string().contains("liveness"), "got: {err}");

    let mut cfg = valid_base();
    cfg.health.liveness = "healthz".into();
    let err = cfg.validate().expect_err("path without slash");
    assert!(err.to_string().contains("must start with"), "got: {err}");

    // Disabled health skips its checks entirely.
    let mut cfg = valid_base();
    cfg.health.enabled = false;
    cfg.health.liveness = "not-a-path".into();
    cfg.validate().expect("disabled health is not validated");
}

/// An unknown `[compression]` algorithm is a startup refusal naming
/// the offending value, not a silently un-negotiable encoding.
#[test]
fn unknown_compression_algorithms_are_startup_errors() {
    let mut cfg = valid_base();
    cfg.compression.algorithms = vec!["br".into(), "zstd".into()];
    let err = cfg.validate().expect_err("unknown algorithm");
    let msg = err.to_string();
    assert!(msg.contains("zstd"), "got: {msg}");
    assert!(msg.contains("[compression]"), "got: {msg}");

    // The two supported names still validate, in either order.
    let mut cfg = valid_base();
    cfg.compression.algorithms = vec!["gzip".into(), "br".into()];
    cfg.validate().expect("br and gzip are the supported set");
}

/// `[lua] stdlib` is strict: a misspelled library name refuses to
/// start, naming the string, instead of silently loading nothing.
#[test]
fn unknown_lua_stdlib_names_are_startup_errors() {
    let mut lua = LuaConfig::default();
    lua.stdlib.push("iio".into());
    let err = lua.parse_stdlib().expect_err("unknown stdlib name");
    assert!(err.to_string().contains("`iio`"), "got: {err}");

    // Every documented name parses, including the dangerous opt-ins.
    let all = LuaConfig {
        stdlib: [
            "coroutine",
            "table",
            "io",
            "os",
            "string",
            "utf8",
            "math",
            "package",
        ]
        .map(String::from)
        .to_vec(),
        ..LuaConfig::default()
    };
    let libs = all.parse_stdlib().expect("all loadable names");
    assert!(libs.contains(mlua::StdLib::IO));
    assert!(libs.contains(mlua::StdLib::PACKAGE));
}

#[test]
fn missing_paths_are_named_at_startup() {
    let mut cfg = valid_base();
    cfg.handler_script = PathBuf::from("/nonexistent/app.lua");
    let err = cfg.validate().expect_err("missing handler");
    assert!(err.to_string().contains("handler_script"), "got: {err}");

    let mut cfg = valid_base();
    cfg.templating.dir = Some(PathBuf::from("/nonexistent/templates"));
    let err = cfg.validate().expect_err("missing templates");
    assert!(err.to_string().contains("[templating] dir"), "got: {err}");

    // A file where a directory belongs is as wrong as nothing at all.
    let mut cfg = valid_base();
    cfg.templating.dir = Some(cfg.handler_script.clone());
    let err = cfg.validate().expect_err("file as the templating dir");
    assert!(err.to_string().contains("directory"), "got: {err}");

    // The database file may not exist yet, but its directory must.
    let mut cfg = valid_base();
    cfg.database = Some(DatabaseConfig::new("/nonexistent/dir/app.db"));
    let err = cfg.validate().expect_err("missing db dir");
    assert!(err.to_string().contains("database directory"), "got: {err}");
}

#[test]
fn unknown_keys_are_rejected_not_ignored() {
    let path = write_temp_config("typo.toml", "max_body_byte = 1\n");
    let err = Config::from_file(&path).expect_err("unknown key");
    assert!(err.to_string().contains("max_body_byte"), "got: {err}");

    // Inside a section too.
    let path = write_temp_config("typo2.toml", "[limits]\nmax_body_byte = 1\n");
    let err = Config::from_file(&path).expect_err("unknown section key");
    assert!(err.to_string().contains("max_body_byte"), "got: {err}");
    std::fs::remove_file(&path).ok();
}

proptest::proptest! {
    /// Property: over arbitrary numeric limit combinations, validation
    /// is total — it accepts, or refuses with an error naming a
    /// setting; it never panics — and the pool-wait/exec-budget
    /// contradiction is always the refusal it promises.
    #[test]
    fn prop_limit_validation_is_total_and_names_the_setting(
        workers in 1usize..8,
        max_streams in proptest::option::of(0usize..8),
        pool_wait_ms in 0u64..100_000,
        exec_timeout_ms in 0u64..100_000,
        body_read_ms in 0u64..100_000,
        header_read_ms in 0u64..100_000,
    ) {
        let mut cfg = valid_base();
        cfg.workers = workers;
        cfg.max_streams = max_streams;
        cfg.limits.pool_wait_ms = pool_wait_ms;
        cfg.limits.body_read_ms = body_read_ms;
        cfg.limits.header_read_ms = header_read_ms;
        cfg.lua.exec_timeout_ms = exec_timeout_ms;

        match cfg.validate() {
            Ok(()) => {
                proptest::prop_assert!(
                    !(pool_wait_ms > exec_timeout_ms
                        && pool_wait_ms != 0
                        && exec_timeout_ms != 0),
                    "the pool-wait contradiction must refuse"
                );
            }
            Err(err) => {
                let msg = err.to_string();
                proptest::prop_assert!(
                    msg.contains("pool_wait_ms") || msg.contains("max_streams"),
                    "a refusal must name the offending setting: {msg}"
                );
            }
        }
    }
}
