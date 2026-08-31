// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Parsing and layering: the file, env overrides, defaults, rebase.

use super::*;

#[test]
fn effective_config_prints_and_round_trips() {
    let mut cfg = valid_base();
    cfg.log.format = LogFormat::Json;
    cfg.pidfile = Some(PathBuf::from("/run/nitr.pid"));
    let rendered = cfg.effective_toml().expect("render");
    // Nones are absent, not null.
    assert!(!rendered.contains("null"), "got: {rendered}");
    assert!(rendered.contains("format = \"json\""), "got: {rendered}");
    assert!(
        rendered.contains("pidfile = \"/run/nitr.pid\""),
        "got: {rendered}"
    );
    // The output is itself a loadable configuration.
    let path = write_temp_config("effective.toml", &rendered);
    let reparsed = Config::from_file(&path).expect("reparse");
    assert_eq!(reparsed.log.format, LogFormat::Json);
    assert_eq!(reparsed.listen, cfg.listen);
    std::fs::remove_file(&path).ok();
}

#[test]
fn rebase_moves_app_paths_and_leaves_the_database() {
    let mut cfg = Config {
        handler_script: PathBuf::from("app.lua"),
        config_script: Some(PathBuf::from("config.lua")),
        templating: TemplatingConfig {
            dir: Some(PathBuf::from("templates")),
        },
        database: Some(DatabaseConfig::new("data/app.db")),
        ..Config::default()
    };
    cfg.static_files.dir = Some(PathBuf::from("public"));
    cfg.rebase(Path::new("/bundle"));
    assert_eq!(cfg.handler_script, PathBuf::from("/bundle/app.lua"));
    assert_eq!(
        cfg.config_script.as_deref(),
        Some(Path::new("/bundle/config.lua"))
    );
    assert_eq!(
        cfg.templating.dir.as_deref(),
        Some(Path::new("/bundle/templates"))
    );
    assert_eq!(
        cfg.static_files.dir.as_deref(),
        Some(Path::new("/bundle/public"))
    );
    // Mutable state stays external to the artifact.
    assert_eq!(
        cfg.database.as_ref().unwrap().path,
        PathBuf::from("data/app.db")
    );
    // Absolute paths are already anchored; rebase leaves them alone.
    let mut cfg = Config {
        handler_script: PathBuf::from("/abs/app.lua"),
        ..Config::default()
    };
    cfg.rebase(Path::new("/bundle"));
    assert_eq!(cfg.handler_script, PathBuf::from("/abs/app.lua"));
}

#[test]
fn defaults_are_sane() {
    let cfg = Config::default();
    assert_eq!(cfg.listen, SocketAddr::from(([127, 0, 0, 1], 3000)));
    assert_eq!(cfg.handler_script, PathBuf::from("scripts/handler.lua"));
    assert!(cfg.workers >= 1);
    assert!(!cfg.dev_mode);
    // No explicit list enables the minimal default feature set.
    assert_eq!(cfg.builtins().expect("builtins"), Builtins::minimal());
    // io/os are opt-in.
    assert!(!cfg.lua.stdlib.iter().any(|s| s == "io" || s == "os"));
}

#[test]
fn parses_a_full_config_file() {
    let path = write_temp_config(
        "full.toml",
        r#"
            listen = "127.0.0.1:8080"
            handler_script = "app/handler.lua"
            workers = 2
            dev_mode = true
            [database]
            path = "app.db"
            [testing]
            dir = "spec"
            [std]
            features = ["dbg", "json", "db"]
            [lua]
            stdlib = ["math", "string", "package"]
            memory_limit = 1048576
            exec_timeout_ms = 500
        "#,
    );
    let cfg = Config::from_file(&path).expect("parse config");
    std::fs::remove_file(&path).ok();

    assert_eq!(cfg.listen, SocketAddr::from(([127, 0, 0, 1], 8080)));
    assert!(cfg.dev_mode);
    // [database] takes the pragma defaults; [testing] replaces its own.
    let db = cfg.database.as_ref().expect("database");
    assert_eq!(db.path, PathBuf::from("app.db"));
    assert_eq!(db.journal_mode, "wal");
    assert!(db.foreign_keys);
    assert_eq!(cfg.testing.dir, PathBuf::from("spec"));
    assert_eq!(
        cfg.builtins().expect("builtins"),
        Builtins::DEBUG | Builtins::JSON | Builtins::DATABASE
    );
    let opts = cfg.runtime_opts().expect("runtime opts");
    assert_eq!(opts.memory_limit, 1048576);
    assert_eq!(
        opts.exec_timeout,
        Some(std::time::Duration::from_millis(500))
    );
    assert!(opts.dev_mode);
    // package.path confinement derives from the handler script location.
    assert_eq!(opts.package_dir.as_deref(), Some(Path::new("app")));
}

#[test]
fn read_timeout_limits_parse_and_default() {
    let cfg = Config::default();
    assert_eq!(cfg.limits.header_read_ms, 30_000);
    assert_eq!(cfg.limits.body_read_ms, 30_000);

    let path = write_temp_config(
        "read-timeouts.toml",
        "[limits]\nheader_read_ms = 0\nbody_read_ms = 250\n",
    );
    let cfg = Config::from_file(&path).expect("parse");
    std::fs::remove_file(&path).ok();
    assert_eq!(cfg.limits.header_read_ms, 0, "0 disables the deadline");
    assert_eq!(cfg.limits.body_read_ms, 250);
}

#[test]
fn moved_keys_fail_with_directions() {
    // Superseded spellings are refused with the new spelling named,
    // not as a bare unknown-field/type error.
    let path = write_temp_config("old-db.toml", "database = \"app.db\"\n");
    let err = Config::from_file(&path).expect_err("bare database string");
    std::fs::remove_file(&path).ok();
    assert!(err.to_string().contains("[database]"), "got: {err}");
    assert!(err.to_string().contains("path"), "got: {err}");

    let path = write_temp_config("old-tests.toml", "tests_dir = \"tests\"\n");
    let err = Config::from_file(&path).expect_err("tests_dir key");
    std::fs::remove_file(&path).ok();
    assert!(err.to_string().contains("[testing]"), "got: {err}");

    let path = write_temp_config("old-templates.toml", "templates_dir = \"templates\"\n");
    let err = Config::from_file(&path).expect_err("templates_dir key");
    std::fs::remove_file(&path).ok();
    assert!(err.to_string().contains("[templating]"), "got: {err}");
    assert!(err.to_string().contains("dir"), "got: {err}");
}

#[test]
fn the_templating_section_parses_and_round_trips() {
    let path = write_temp_config(
        "templating.toml",
        "[templating]\ndir = \"scripts/templates\"\n",
    );
    let cfg = Config::from_file(&path).expect("parse [templating]");
    std::fs::remove_file(&path).ok();
    assert_eq!(
        cfg.templating.dir.as_deref(),
        Some(Path::new("scripts/templates"))
    );

    // The section survives `nitr check --print-config`, which serializes
    // the effective configuration back to TOML.
    let rendered = cfg.effective_toml().expect("render");
    assert!(rendered.contains("[templating]"), "got: {rendered}");
    let path = write_temp_config("templating-rt.toml", &rendered);
    let reparsed = Config::from_file(&path).expect("reparse");
    std::fs::remove_file(&path).ok();
    assert_eq!(reparsed.templating.dir, cfg.templating.dir);
}

/// `template` in an explicit `[std] features` list without the section
/// it needs is a startup error naming the new spelling.
#[test]
fn the_template_feature_requires_the_templating_dir() {
    let mut cfg = valid_base();
    cfg.std.features = Some(vec!["template".into()]);
    let err = cfg.builtins().expect_err("template without a dir");
    assert!(err.to_string().contains("[templating] dir"), "got: {err}");

    cfg.templating.dir = Some(std::env::temp_dir());
    assert_eq!(cfg.builtins().expect("with a dir"), Builtins::TEMPLATE);
}

#[test]
fn env_files_load_without_overriding_and_explicit_ones_must_exist() {
    let dir = std::env::temp_dir().join(format!("nitr-envfile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(dir.join(".env"), "NITRTEST_FROM_FILE=hello\n").expect("env file");

    // Implicit `.env` next to the config loads; the value arrives in
    // the process environment.
    let cfg = Config::default();
    cfg.load_env_file(&dir).expect("implicit .env");
    assert_eq!(std::env::var("NITRTEST_FROM_FILE").as_deref(), Ok("hello"));

    // An implicit file may be absent; an explicitly named one may not.
    let empty = dir.join("sub");
    std::fs::create_dir_all(&empty).expect("dir");
    cfg.load_env_file(&empty)
        .expect("absent implicit .env is fine");
    let mut cfg = Config::default();
    cfg.env.file = Some(PathBuf::from("missing.env"));
    let err = cfg
        .load_env_file(&dir)
        .expect_err("explicit file must exist");
    assert!(err.to_string().contains("missing.env"), "got: {err}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rejects_unknown_fields() {
    let path = write_temp_config("typo.toml", "memroy_limit = 1\n");
    let err = Config::from_file(&path).expect_err("typo must fail");
    std::fs::remove_file(&path).ok();
    assert!(err.to_string().contains("memroy_limit"));
}

#[test]
fn strict_std_features_require_their_settings() {
    let mut cfg = Config {
        std: StdConfig {
            features: Some(vec!["db".into()]),
        },
        ..Config::default()
    };
    assert!(cfg.builtins().is_err());
    cfg.database = Some(DatabaseConfig::new("x.db"));
    assert_eq!(cfg.builtins().expect("builtins"), Builtins::DATABASE);

    cfg.std.features = Some(vec!["nope".into()]);
    assert!(cfg.builtins().is_err());
}

#[test]
fn exec_timeout_zero_disables_the_budget() {
    let mut cfg = Config::default();
    cfg.lua.exec_timeout_ms = 0;
    assert_eq!(cfg.runtime_opts().expect("opts").exec_timeout, None);
}

#[test]
fn unknown_stdlib_name_fails() {
    let mut cfg = Config::default();
    cfg.lua.stdlib.push("ffi".into());
    assert!(cfg.runtime_opts().is_err());
}

// -----------------------------------------------------------------
// [tls]
