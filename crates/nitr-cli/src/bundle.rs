// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr build` bundles: the application appended to the binary itself.
//!
//! Layout of a bundled executable, back to front:
//!
//! ```text
//! [ the nitr binary | tar archive | tar length (u64 LE) | b"NITRBNDL" ]
//! ```
//!
//! An appended archive was chosen over link-time embedding because it
//! needs no build toolchain on the packaging machine: `nitr build` copies
//! its own executable and appends a tar of the application. At startup the
//! trailer is detected, the archive extracted to a content-addressed cache
//! directory, and the configuration re-anchored there. The database stays
//! external — bundling mutable state into an immutable artifact would be
//! wrong — and `dev_mode` is forced off, because the files a reload would
//! watch are a temporary extraction, not the sources.

use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, bail};
use nitr::Config;

/// Trailing magic identifying a bundled executable.
const MAGIC: &[u8; 8] = b"NITRBNDL";

/// Trailer size: the u64 archive length plus the magic.
const TRAILER: u64 = 16;

/// The name the configuration file is stored under in the archive,
/// whatever it was called on disk.
const CONFIG_NAME: &str = "nitr.toml";

/// Reads the archive appended to `exe`, if any.
fn read_appended(exe: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    let mut file = std::fs::File::open(exe)
        .with_context(|| format!("cannot open the executable {}", exe.display()))?;
    let len = file.metadata()?.len();
    if len < TRAILER {
        return Ok(None);
    }
    file.seek(std::io::SeekFrom::End(-(TRAILER as i64)))?;
    let mut trailer = [0u8; TRAILER as usize];
    file.read_exact(&mut trailer)?;
    if &trailer[8..] != MAGIC {
        return Ok(None);
    }
    // Invariant: `trailer` is a fixed `TRAILER`-byte array, so its first
    // eight bytes always convert.
    #[allow(clippy::expect_used)]
    let tar_len = u64::from_le_bytes(trailer[..8].try_into().expect("8 bytes"));
    if tar_len == 0 || tar_len > len - TRAILER {
        bail!("the appended application archive is corrupt (bad length)");
    }
    file.seek(std::io::SeekFrom::End(-((TRAILER + tar_len) as i64)))?;
    let mut tar = vec![0u8; tar_len as usize];
    file.read_exact(&mut tar)?;
    Ok(Some(tar))
}

/// If this executable carries a bundle, extracts it (once — the directory
/// is content-addressed and reused) and returns the loaded configuration,
/// re-anchored to the extraction directory.
pub fn load() -> anyhow::Result<Option<Config>> {
    let exe = std::env::current_exe().context("cannot locate the running executable")?;
    let Some(tar) = read_appended(&exe)? else {
        return Ok(None);
    };

    // Content-addressed: the same bundle extracts once and is reused; a
    // different build lands in a different directory. `DefaultHasher` is
    // deterministic across runs (fixed keys) — this is a cache key, not a
    // security boundary.
    let key = {
        use std::hash::{Hash as _, Hasher as _};
        let mut h = std::hash::DefaultHasher::new();
        tar.hash(&mut h);
        h.finish()
    };
    let root = std::env::temp_dir().join(format!("nitr-app-{key:016x}"));
    let marker = root.join(".nitr-extracted");
    if !marker.is_file() {
        // Extract into a fresh directory, then rename: a crash mid-extract
        // must not leave a half-populated directory that later runs trust.
        let staging =
            std::env::temp_dir().join(format!("nitr-app-{key:016x}.{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(&staging)?;
        tar::Archive::new(tar.as_slice())
            .unpack(&staging)
            .context("cannot extract the bundled application")?;
        std::fs::File::create(staging.join(".nitr-extracted"))?;
        match std::fs::rename(&staging, &root) {
            Ok(()) => {}
            // A concurrent start won the race; its extraction is complete.
            Err(_) if marker.is_file() => {
                let _ = std::fs::remove_dir_all(&staging);
            }
            Err(err) => return Err(err).context("cannot finalize the bundle extraction"),
        }
    }

    let mut cfg = Config::from_file(&root.join(CONFIG_NAME))?;
    cfg.rebase(&root);
    // Default migrations discovery looks for `migrations/` in the working
    // directory; in a bundle they were extracted next to the config.
    if let Some(db) = &mut cfg.database
        && db.migrations_dir.is_none()
        && root.join("migrations").is_dir()
    {
        db.migrations_dir = Some(root.join("migrations"));
    }
    if cfg.dev_mode {
        // stderr, not tracing: this runs while the configuration is being
        // loaded, before the subscriber can exist (its format comes from
        // this very configuration).
        eprintln!("warning: dev_mode is forced off in a bundled build (no sources to watch)");
    }
    cfg.dev_mode = false;
    Ok(Some(cfg))
}

/// A path may enter the archive only if it stays inside the application
/// root (the working directory): relative, no `..`, no absolute prefix.
fn archivable(path: &Path, what: &str) -> anyhow::Result<()> {
    let ok = path.is_relative()
        && path
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    if !ok {
        bail!(
            "{what} points at {}, which is outside the application directory: \
             a bundle can only contain files under the directory it is built from",
            path.display()
        );
    }
    Ok(())
}

/// Appends `path` (a file) or its whole tree (a directory) to the archive
/// under its own relative name.
fn append(builder: &mut tar::Builder<Vec<u8>>, path: &Path) -> anyhow::Result<()> {
    if path.is_dir() {
        builder
            .append_dir_all(path, path)
            .with_context(|| format!("cannot archive {}", path.display()))?;
    } else {
        builder
            .append_path(path)
            .with_context(|| format!("cannot archive {}", path.display()))?;
    }
    Ok(())
}

/// Builds a single-file artifact: this executable plus the application
/// named by `cfg` (loaded from `cfg_path`), written to `output`.
pub fn build(cfg_path: &Path, cfg: &Config, output: &Path) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("cannot locate the running executable")?;
    if read_appended(&exe)?.is_some() {
        bail!("this executable already carries a bundle; build from the plain `nitr` binary");
    }

    let mut builder = tar::Builder::new(Vec::new());
    // Deterministic-ish archives: no atime/ctime noise.
    builder.mode(tar::HeaderMode::Deterministic);

    // The configuration file, under its canonical name.
    let mut header = tar::Header::new_gnu();
    let cfg_bytes =
        std::fs::read(cfg_path).with_context(|| format!("cannot read {}", cfg_path.display()))?;
    header.set_size(cfg_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, CONFIG_NAME, cfg_bytes.as_slice())?;

    // The handler's whole directory tree of Lua sources: `require` is
    // confined to it, so any of them may be loaded at runtime.
    let package_dir = cfg
        .handler_script
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    archivable(&cfg.handler_script, "handler_script")?;
    let mut seen = std::collections::BTreeSet::new();
    for lua in lua_files(&package_dir)? {
        if seen.insert(lua.clone()) {
            append(&mut builder, &lua)?;
        }
    }
    if seen.is_empty() {
        append(&mut builder, &cfg.handler_script)?;
    }

    if let Some(script) = &cfg.config_script {
        archivable(script, "config_script")?;
        if seen.iter().all(|p| p != script) {
            append(&mut builder, script)?;
        }
    }
    let migrations = cfg.database.as_ref().and_then(|db| db.migrations());
    for (what, dir) in [
        ("[templating] dir", cfg.templating.dir.as_ref()),
        ("[static] dir", cfg.static_files.dir.as_ref()),
        ("migrations", migrations.as_ref()),
    ] {
        let Some(dir) = dir else { continue };
        archivable(dir, what)?;
        append(&mut builder, dir)?;
    }

    let tar = builder.into_inner().context("cannot finish the archive")?;

    // The artifact: our own bytes, the archive, the trailer.
    let exe_bytes = std::fs::read(&exe)?;
    let mut out = std::fs::File::create(output)
        .with_context(|| format!("cannot create {}", output.display()))?;
    out.write_all(&exe_bytes)?;
    out.write_all(&tar)?;
    out.write_all(&(tar.len() as u64).to_le_bytes())?;
    out.write_all(MAGIC)?;
    drop(out);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o755))?;
    }

    println!(
        "built {} ({} file(s), {} archived)",
        output.display(),
        seen.len() + 1,
        human_size(tar.len() as u64),
    );
    println!("run it anywhere: the database path still resolves against the working directory");
    Ok(())
}

/// All `*.lua` files under `dir`, recursively, in stable order.
fn lua_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("cannot read the directory {}", dir.display()))?;
        for entry in entries {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "lua") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_paths_inside_the_root_are_archivable() {
        assert!(archivable(Path::new("app.lua"), "x").is_ok());
        assert!(archivable(Path::new("./sub/dir"), "x").is_ok());
        assert!(archivable(Path::new("../escape.lua"), "x").is_err());
        assert!(archivable(Path::new("/etc/passwd"), "x").is_err());
        assert!(archivable(Path::new("a/../../b"), "x").is_err());
    }

    #[test]
    fn trailer_detection_ignores_plain_files() {
        let dir = std::env::temp_dir();
        let plain = dir.join(format!("nitr-bundle-test-plain-{}", std::process::id()));
        std::fs::write(&plain, b"just a small file").expect("write");
        assert!(read_appended(&plain).expect("read").is_none());

        // A file that ends with the trailer yields the archive back.
        let bundled = dir.join(format!("nitr-bundle-test-tar-{}", std::process::id()));
        let payload = b"PAYLOAD-BYTES";
        let mut bytes = b"binary-part".to_vec();
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(MAGIC);
        std::fs::write(&bundled, &bytes).expect("write");
        let read = read_appended(&bundled).expect("read").expect("bundle");
        assert_eq!(read, payload);

        // A lying length is an error, not a bad slice.
        let mut corrupt = b"tiny".to_vec();
        corrupt.extend_from_slice(&u64::MAX.to_le_bytes());
        corrupt.extend_from_slice(MAGIC);
        let path = dir.join(format!("nitr-bundle-test-corrupt-{}", std::process::id()));
        std::fs::write(&path, &corrupt).expect("write");
        assert!(read_appended(&path).is_err());

        for p in [plain, bundled, path] {
            std::fs::remove_file(p).ok();
        }
    }
}
