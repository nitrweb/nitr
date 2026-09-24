// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr openapi`: the OpenAPI document from the CLI — printed, written,
//! compared as a CI drift gate, or laid out as a static Swagger UI site.
//!
//! Generation ignores `[openapi] enabled`: the flags gate serving, not
//! generation. The build is the one `nitr check` performs, so the
//! configuration script runs once here too, against a scratch database
//! migrated like the live one.

#[cfg(feature = "openapi")]
use std::path::Path;
use std::path::PathBuf;

#[cfg(feature = "openapi")]
use anyhow::Context as _;
use anyhow::bail;

use nitr::Config;

#[cfg(feature = "openapi")]
use crate::cmd::scratch_db::ScratchDb;

/// What `nitr openapi` was asked to do.
#[derive(Debug, Default)]
// The stub build parses the flags (the subcommand exists everywhere) and
// then refuses, so it never reads them.
#[cfg_attr(not(feature = "openapi"), allow(dead_code))]
pub(crate) struct OpenapiArgs {
    /// Write the document here instead of printing it.
    pub(crate) output: Option<PathBuf>,
    /// Compare with the file instead of writing it.
    pub(crate) check: bool,
    /// Write a self-contained Swagger UI site into this directory.
    pub(crate) ui: Option<PathBuf>,
}

/// The outcome the process exits with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// The stub build only ever fails, so it constructs neither variant.
#[cfg_attr(not(feature = "openapi"), allow(dead_code))]
pub(crate) enum Outcome {
    /// Done, or the check found no drift.
    Ok,
    /// `--check` found the committed document out of date.
    Drift,
}

#[cfg(not(feature = "openapi"))]
pub(crate) async fn run(_cfg: Config, _args: OpenapiArgs) -> anyhow::Result<Outcome> {
    bail!(
        "this build has no OpenAPI support: rebuild with the `openapi` Cargo \
         feature (or `all`) to use `nitr openapi`"
    )
}

#[cfg(feature = "openapi")]
pub(crate) async fn run(cfg: Config, args: OpenapiArgs) -> anyhow::Result<Outcome> {
    use nitr::Server;

    if args.ui.is_some() && cfg!(not(feature = "swagger")) {
        bail!(
            "this build has no Swagger UI: rebuild with the `swagger` Cargo feature \
             (or `all`) to use `nitr openapi --ui`"
        );
    }
    // The file `--check` compares against, and `--output` writes: the
    // flag, then `[openapi] output`, then the conventional name.
    let target = args
        .output
        .clone()
        .or_else(|| cfg.openapi.output.clone())
        .unwrap_or_else(|| PathBuf::from("openapi.json"));
    let ui = args.ui.clone();
    if let Some(dir) = &ui {
        refuse_bad_site_dir(dir)?;
    }

    let mut cfg = Config {
        workers: 1,
        dev_mode: false,
        ..cfg
    };
    // The document is the routes, never the data: the build runs against a
    // private, migrated copy of the schema, so a fresh CI checkout needs no
    // database and the application's own is never created or read.
    let _scratch = cfg.database.as_mut().map(|db| {
        let scratch = ScratchDb::new("openapi");
        db.path = scratch.path().to_path_buf();
        scratch
    });
    #[cfg(feature = "db")]
    crate::cmd::scratch_db::migrate(&cfg).await?;
    let server = Server::builder()
        .config(cfg)
        .build()
        .await
        .context("building the application failed")?;
    let spec = server
        .openapi_json()
        .context("the application produced no document")?;

    if args.check {
        return check(&target, &spec);
    }
    if let Some(dir) = &ui {
        write_site(&server, dir)?;
    }
    match (&args.output, ui.is_some()) {
        (Some(path), _) => {
            write_file(path, &spec)?;
            eprintln!("wrote {} ({} bytes)", path.display(), spec.len());
        }
        (None, true) => {}
        (None, false) => {
            use std::io::Write as _;
            std::io::stdout().write_all(&spec)?;
        }
    }
    Ok(Outcome::Ok)
}

/// `--check`: both sides re-serialized canonically, so an editor's
/// trailing newline or key order never fails CI, and a real difference
/// names the first path that differs.
#[cfg(feature = "openapi")]
fn check(target: &Path, spec: &[u8]) -> anyhow::Result<Outcome> {
    let committed = match std::fs::read(target) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "openapi: {} does not exist; run `nitr openapi --output {}` and commit it",
                target.display(),
                target.display()
            );
            return Ok(Outcome::Drift);
        }
        Err(err) => bail!("cannot read {}: {err}", target.display()),
    };
    let committed: serde_json::Value = serde_json::from_slice(&committed)
        .with_context(|| format!("{} is not valid JSON", target.display()))?;
    let generated: serde_json::Value =
        serde_json::from_slice(spec).context("the generated document is not valid JSON")?;
    match first_difference(&committed, &generated, "$") {
        None => {
            eprintln!("openapi: {} is up to date", target.display());
            Ok(Outcome::Ok)
        }
        Some(path) => {
            eprintln!(
                "openapi: {} is out of date: first difference at {path}; run `nitr openapi \
                 --output {}` and commit the result",
                target.display(),
                target.display()
            );
            Ok(Outcome::Drift)
        }
    }
}

/// The JSON path of the first difference between two documents, in key
/// order, or `None` when they are equal.
#[cfg(feature = "openapi")]
fn first_difference(a: &serde_json::Value, b: &serde_json::Value, path: &str) -> Option<String> {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let child = format!("{path}.{key}");
                match (x.get(key), y.get(key)) {
                    (Some(p), Some(q)) => {
                        if let Some(found) = first_difference(p, q, &child) {
                            return Some(found);
                        }
                    }
                    _ => return Some(child),
                }
            }
            None
        }
        (Value::Array(x), Value::Array(y)) => {
            for (i, (p, q)) in x.iter().zip(y.iter()).enumerate() {
                if let Some(found) = first_difference(p, q, &format!("{path}[{i}]")) {
                    return Some(found);
                }
            }
            (x.len() != y.len()).then(|| format!("{path}[{}]", x.len().min(y.len())))
        }
        _ => (a != b).then(|| path.to_string()),
    }
}

/// A site directory must be a directory (or not exist yet), never the
/// filesystem root or a file.
#[cfg(feature = "openapi")]
fn refuse_bad_site_dir(dir: &Path) -> anyhow::Result<()> {
    if dir.parent().is_none() {
        bail!(
            "`--ui {}` names the filesystem root; give a directory for the site",
            dir.display()
        );
    }
    if dir.exists() && !dir.is_dir() {
        bail!(
            "`--ui {}` is a file, not a directory; nothing written",
            dir.display()
        );
    }
    Ok(())
}

#[cfg(feature = "swagger")]
fn write_site(server: &nitr::Server, dir: &Path) -> anyhow::Result<()> {
    let files = server
        .openapi_site()
        .context("the application produced no page")?;
    for (name, bytes) in &files {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        write_file(&path, bytes)?;
    }
    eprintln!("wrote {} file(s) under {}", files.len(), dir.display());
    Ok(())
}

#[cfg(all(feature = "openapi", not(feature = "swagger")))]
fn write_site(_server: &nitr::Server, _dir: &Path) -> anyhow::Result<()> {
    // Unreachable: `run` refuses `--ui` before building on such a binary.
    bail!("this build has no Swagger UI")
}

/// A plain write that refuses to follow a planted symlink, like the
/// dev-mode writer does.
#[cfg(feature = "openapi")]
fn write_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!(
            "{} is a symbolic link; refusing to write through it",
            path.display()
        );
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

#[cfg(all(test, feature = "openapi"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_first_difference_is_named_by_path() {
        let a = json!({ "paths": { "/a": { "get": { "summary": "x" } } }, "info": { "v": 1 } });
        let same = json!({ "info": { "v": 1 }, "paths": { "/a": { "get": { "summary": "x" } } } });
        assert_eq!(first_difference(&a, &same, "$"), None);
        let b = json!({ "paths": { "/a": { "get": { "summary": "y" } } }, "info": { "v": 1 } });
        assert_eq!(
            first_difference(&a, &b, "$").as_deref(),
            Some("$.paths./a.get.summary")
        );
        let c = json!({ "paths": {}, "info": { "v": 1 } });
        assert_eq!(first_difference(&a, &c, "$").as_deref(), Some("$.paths./a"));
        let list = json!({ "tags": [1, 2, 3] });
        let shorter = json!({ "tags": [1, 2] });
        assert_eq!(
            first_difference(&list, &shorter, "$").as_deref(),
            Some("$.tags[2]")
        );
    }

    #[test]
    fn bad_site_directories_are_refused() {
        let root = if cfg!(windows) { "C:\\" } else { "/" };
        assert!(refuse_bad_site_dir(Path::new(root)).is_err());
        let file = std::env::temp_dir().join(format!("nitr-openapi-ui-{}", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        let err = refuse_bad_site_dir(&file).unwrap_err().to_string();
        assert!(err.contains("is a file"), "{err}");
        std::fs::remove_file(&file).unwrap();
        assert!(refuse_bad_site_dir(&std::env::temp_dir().join("does-not-exist-yet")).is_ok());
    }
}
