// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Guards for the single-source API description (`nitr-api.toml`):
//!
//! - completeness: every entry registered on the `nitr` namespace must be
//!   described, so adding a builtin without documenting it fails here;
//! - drift: the checked-in generated files (`nitr-types.lua`,
//!   `docs/nitr-api.md`) must match what the description generates.
//!   Regenerate with: NITR_API_REGEN=1 cargo test -p nitr-cli --test api
//!
//! The generator lives in the binary crate; tests reach it through the
//! `nitr types`-shaped internals compiled into the test via include.

use std::collections::BTreeSet;
use std::path::PathBuf;

use nitr_cli::apidef;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// Walks the registered `nitr` namespace: top-level entries plus the
/// members of plain Lua tables, recursively. Userdata members are not
/// enumerable, so their methods are covered by declaration only.
fn registered_paths(lua: &mlua::Lua) -> BTreeSet<String> {
    fn walk(prefix: &str, table: &mlua::Table, out: &mut BTreeSet<String>) {
        for pair in table.pairs::<String, mlua::Value>() {
            let Ok((key, value)) = pair else { continue };
            if key.starts_with('_') {
                continue;
            }
            let path = format!("{prefix}.{key}");
            out.insert(path.clone());
            if let mlua::Value::Table(inner) = value {
                walk(&path, &inner, out);
            }
        }
    }
    let nitr: mlua::Table = lua.globals().get("nitr").expect("nitr table");
    let mut out = BTreeSet::new();
    walk("nitr", &nitr, &mut out);
    out
}

/// Every builtin this binary was compiled with. `Builtins::all()` would
/// demand every Cargo feature: the completeness check must hold for
/// whatever feature set is actually being tested.
fn compiled_builtins() -> nitr::Builtins {
    #[allow(unused_mut)]
    let mut builtins = nitr::Builtins::minimal() | nitr::Builtins::DEBUG | nitr::Builtins::CACHE;
    #[cfg(feature = "fetch")]
    {
        builtins |= nitr::Builtins::FETCH;
    }
    #[cfg(feature = "db")]
    {
        builtins |= nitr::Builtins::DATABASE;
    }
    #[cfg(feature = "template")]
    {
        builtins |= nitr::Builtins::TEMPLATE;
    }
    #[cfg(feature = "crypto")]
    {
        builtins |= nitr::Builtins::CRYPTO;
    }
    builtins
}

#[test]
fn every_registered_entry_is_described() {
    let api = apidef::parse().expect("parse nitr-api.toml");
    let known = api.known_paths();

    // Unique per process AND per thread-safe use: nothing here may collide
    // with a concurrently running test binary.
    let db = std::env::temp_dir().join(format!("nitr-api-test-{}.db", std::process::id()));
    let lua = mlua::Lua::new();
    let env = nitr::BuiltinsEnv {
        templates_dir: Some(std::env::temp_dir()),
        database: Some(db.clone()),
        ..Default::default()
    };
    nitr::stdlib::register_builtins(&lua, compiled_builtins(), &env)
        .expect("register compiled builtins");

    let missing: Vec<String> = registered_paths(&lua)
        .into_iter()
        .filter(|path| !known.contains(path))
        .collect();
    // The state (and its SQLite connection) must close before the file is
    // removed, or the delete races the WAL checkpoint.
    drop(lua);
    for suffix in ["", "-wal", "-shm"] {
        std::fs::remove_file(std::path::Path::new(&format!("{}{suffix}", db.display()))).ok();
    }
    assert!(
        missing.is_empty(),
        "registered but not described in nitr-api.toml (document them there): {missing:?}"
    );
}

#[test]
fn generated_files_are_current() {
    let api = apidef::parse().expect("parse nitr-api.toml");
    let outputs = [
        (repo_root().join("nitr-types.lua"), apidef::emit_types(&api)),
        (
            repo_root().join("docs/nitr-api.md"),
            apidef::emit_docs(&api),
        ),
    ];

    if std::env::var_os("NITR_API_REGEN").is_some() {
        for (path, content) in &outputs {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("mkdir");
            }
            std::fs::write(path, content).expect("write generated file");
            println!("regenerated {}", path.display());
        }
        return;
    }

    for (path, expected) in &outputs {
        // A Windows checkout may carry `\r\n` (git autocrlf) while the
        // generator emits `\n`: the comparison is about content, so line
        // endings are normalized away. `.gitattributes` pins the files to
        // LF, but a runner's existing checkout may predate that.
        let on_disk = std::fs::read_to_string(path)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        assert_eq!(
            &on_disk,
            expected,
            "{} is stale — regenerate with: NITR_API_REGEN=1 cargo test -p nitr-cli --test api",
            path.display()
        );
    }
}
