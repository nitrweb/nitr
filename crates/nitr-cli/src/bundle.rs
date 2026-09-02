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
pub(crate) fn read_appended(exe: &Path) -> anyhow::Result<Option<Vec<u8>>> {
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
    // Reuse is only safe inside a directory this user owns and nobody
    // else can enter. The old home was `$TMPDIR/nitr-app-<key>`: the key
    // is computable by anyone who can read the executable, and a shared
    // temp directory lets any local user create that path first — with a
    // marker, their own `nitr.toml` and `app.lua` — and have the next
    // start run *their* application as the operator. So: the user's
    // cache directory (mode 0700) when there is one, and otherwise a
    // fresh private directory per run that is never looked up by name.
    let root = match cache_root() {
        Some(cache) => {
            let root = cache.join(format!("app-{key:016x}"));
            if !root.join(MARKER).is_file() {
                // Extract into a fresh directory, then rename: a crash
                // mid-extract must not leave a half-populated directory
                // that later runs trust.
                let staging = fresh_private_dir(&cache, &format!("app-{key:016x}"))?;
                extract(&tar, &staging)?;
                std::fs::File::create(staging.join(MARKER))?;
                match std::fs::rename(&staging, &root) {
                    Ok(()) => sweep_stale_staging(&cache, &format!("app-{key:016x}.")),
                    // A concurrent start won the race; its extraction is
                    // complete.
                    Err(_) if root.join(MARKER).is_file() => {
                        let _ = std::fs::remove_dir_all(&staging);
                    }
                    Err(err) => {
                        return Err(err).context("cannot finalize the bundle extraction");
                    }
                }
            }
            root
        }
        None => {
            let root = fresh_private_dir(&std::env::temp_dir(), "nitr-app")?;
            // stderr, not tracing: the subscriber does not exist yet.
            eprintln!(
                "warning: no writable cache directory ($XDG_CACHE_HOME or $HOME/.cache); \
                 extracting the bundle to {} for this run only",
                root.display()
            );
            extract(&tar, &root)?;
            root
        }
    };

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

/// Marks a completed extraction.
const MARKER: &str = ".nitr-extracted";

/// The user's private cache for extracted bundles:
/// `$XDG_CACHE_HOME/nitr/apps`, else `$HOME/.cache/nitr/apps`, created
/// mode 0700. `None` when neither variable names an absolute path or the
/// directory cannot be created.
fn cache_root() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".cache"))
                .filter(|p| p.is_absolute())
        })?;
    let root = base.join("nitr").join("apps");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&root).ok()?;
    // `recursive` tolerates a pre-existing directory; make sure the one
    // that exists is private, or the reuse guarantee is gone.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&root).ok()?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).ok()?;
        }
    }
    Some(root)
}

/// Removes staging directories an earlier run left behind (a crash
/// between extraction and rename), recognised by the finished
/// directory's name plus a dot. Best effort.
fn sweep_stale_staging(cache: &Path, prefix: &str) {
    let Ok(entries) = std::fs::read_dir(cache) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(prefix) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Creates a new directory under `parent` with a unique name, mode 0700,
/// failing rather than adopting one that already exists (that is the
/// property a shared temp directory cannot otherwise give).
fn fresh_private_dir(parent: &Path, prefix: &str) -> anyhow::Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    for attempt in 0..16u32 {
        let dir = parent.join(format!(
            "{prefix}.{}.{nanos:x}.{attempt}",
            std::process::id()
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("cannot create {} for the bundle", dir.display()));
            }
        }
    }
    bail!(
        "cannot find a free extraction directory under {}",
        parent.display()
    )
}

/// Extracts the bundle archive into `staging`, validating every entry.
///
/// A bundle is normally our own output, but the extraction must not
/// *depend* on that: anyone can append a hand-crafted archive to the
/// binary. Rather than lean on `tar`'s implicit containment (it skips
/// `..` entries *silently* and only catches symlink write-through at
/// unpack time), every entry is checked against an explicit policy and
/// anything outside it is a hard error — a tampered bundle refuses to
/// run instead of running partially:
///
/// * an entry name must be relative and made of plain path components —
///   no `..`, no root, no drive prefix;
/// * only regular files and directories may appear. `nitr build` never
///   emits link entries (its builder follows symlinks and archives their
///   contents), so a link can only come from a crafted archive — and a
///   symlink entry is the classic two-step traversal: plant
///   `link -> ..`, then write through `link/`.
///
/// [`unpack_in`](tar::Entry::unpack_in) stays underneath as the second
/// wall: it independently re-validates the destination against the
/// staging root, so even a gap in the policy above cannot escape it.
fn extract(tar: &[u8], staging: &Path) -> anyhow::Result<()> {
    let mut archive = tar::Archive::new(tar);
    let entries = archive
        .entries()
        .context("cannot read the bundled application archive")?;
    for entry in entries {
        let mut entry = entry.context("cannot read a bundle archive entry")?;
        let path = entry
            .path()
            .context("a bundle archive entry has an unreadable name")?
            .into_owned();
        if !path
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
        {
            bail!(
                "the bundled archive names `{}`, which would land outside \
                 the extraction directory; the bundle is corrupt or tampered with",
                path.display()
            );
        }
        let kind = entry.header().entry_type();
        if !matches!(kind, tar::EntryType::Regular | tar::EntryType::Directory) {
            bail!(
                "the bundled archive contains `{}` as a {kind:?} entry; a bundle \
                 holds only regular files and directories, so the bundle is \
                 corrupt or tampered with",
                path.display()
            );
        }
        let unpacked = entry
            .unpack_in(staging)
            .with_context(|| format!("cannot extract `{}`", path.display()))?;
        if !unpacked {
            // Unreachable with the checks above; kept so a future `tar`
            // semantic change fails closed instead of skipping silently.
            bail!(
                "the archive entry `{}` was refused by the extractor",
                path.display()
            );
        }
    }
    Ok(())
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
///
/// Symlinked directories are followed (a shared module tree is a
/// legitimate layout, and two names for one tree are archived under
/// both, since `require` will ask by name), but a link back into its own
/// ancestry is skipped: `ln -s . loop` in the application directory used
/// to spin the walk forever while the archive grew.
fn lua_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    // Each entry carries the canonical path of every directory on the
    // way down to it, so a cycle is recognised by the chain it closes.
    let mut stack = vec![(dir.to_path_buf(), Vec::<PathBuf>::new())];
    while let Some((dir, ancestors)) = stack.pop() {
        let real = dir
            .canonicalize()
            .with_context(|| format!("cannot resolve the directory {}", dir.display()))?;
        if ancestors.contains(&real) {
            continue;
        }
        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("cannot read the directory {}", dir.display()))?;
        let mut chain = ancestors;
        chain.push(real);
        for entry in entries {
            let path = entry?.path();
            if path.is_dir() {
                stack.push((path, chain.clone()));
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

    /// A scratch directory for one extraction test: unique, removed on
    /// success, kept (with its path printed) on panic for post-mortem.
    struct Scratch {
        root: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("nitr-bundle-{label}-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&root).expect("create scratch dir");
            Self { root }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!("[test] failed; keeping {}", self.root.display());
            } else {
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }
    }

    /// Appends a file entry with `name` written into the GNU header bytes
    /// directly — `append_data` refuses hostile names (`..`, absolute) at
    /// build time, but an attacker's tar writer has no such scruples, and
    /// the *extraction* side is what these tests probe.
    fn raw_entry(builder: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.as_gnu_mut().expect("gnu header").name[..name.len()]
            .copy_from_slice(name.as_bytes());
        header.set_cksum();
        builder.append(&header, data).expect("append raw entry");
    }

    /// A benign archive — the shape `nitr build` produces (regular files,
    /// nested directories, `./`-prefixed names) — extracts fully. The
    /// positive control for the refusal tests below.
    #[test]
    fn wellformed_archives_extract_fully() {
        let scratch = Scratch::new("extract-ok");
        let staging = scratch.root.join("staging");
        std::fs::create_dir_all(&staging).expect("mkdir");

        let mut builder = tar::Builder::new(Vec::new());
        raw_entry(&mut builder, "nitr.toml", b"listen = \"127.0.0.1:0\"");
        raw_entry(&mut builder, "./app.lua", b"return {}");
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        dir.as_gnu_mut().expect("gnu header").name[..7].copy_from_slice(b"routes/");
        dir.set_cksum();
        builder.append(&dir, &[][..]).expect("append dir");
        raw_entry(&mut builder, "routes/notes.lua", b"return {}");
        let tar = builder.into_inner().expect("finish");

        extract(&tar, &staging).expect("a well-formed bundle extracts");
        assert_eq!(
            std::fs::read(staging.join("nitr.toml")).expect("config"),
            b"listen = \"127.0.0.1:0\""
        );
        assert!(staging.join("app.lua").is_file());
        assert!(staging.join("routes/notes.lua").is_file());
    }

    /// Zip-slip: a hand-crafted archive whose entries would land outside
    /// the extraction directory is a *hard error* naming the entry — a
    /// tampered bundle refuses to run rather than running partially — and
    /// nothing may materialize outside staging.
    #[test]
    fn hostile_archives_are_refused_and_write_nothing_outside() {
        // `..` traversal in an entry name.
        {
            let scratch = Scratch::new("slip-dotdot");
            let staging = scratch.root.join("staging");
            std::fs::create_dir_all(&staging).expect("mkdir");
            let mut builder = tar::Builder::new(Vec::new());
            raw_entry(&mut builder, "ok.lua", b"return {}");
            raw_entry(&mut builder, "../escape.txt", b"pwned");
            let tar = builder.into_inner().expect("finish");

            let err = extract(&tar, &staging).expect_err("a `..` entry must refuse");
            assert!(
                err.to_string().contains("../escape.txt"),
                "the refusal must name the entry: {err}"
            );
            assert!(
                !scratch.root.join("escape.txt").exists(),
                "the traversal entry must not have landed above staging"
            );
            assert!(
                !staging.join("escape.txt").exists(),
                "the traversal entry must not have been re-rooted either"
            );
        }

        // An absolute entry name.
        {
            let scratch = Scratch::new("slip-absolute");
            let staging = scratch.root.join("staging");
            std::fs::create_dir_all(&staging).expect("mkdir");
            // A target that must never appear: unique per run, in a
            // location the archive names absolutely.
            let forbidden = std::env::temp_dir().join(format!(
                "nitr-bundle-absolute-escape-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&forbidden);

            let mut builder = tar::Builder::new(Vec::new());
            raw_entry(&mut builder, &forbidden.to_string_lossy(), b"pwned");
            let tar = builder.into_inner().expect("finish");

            extract(&tar, &staging).expect_err("an absolute entry must refuse");
            assert!(
                !forbidden.exists(),
                "an absolute entry name must never be honored as written"
            );
        }

        // A symlink pointing out of the tree, then a file written through
        // it — the two-step shape that defeats name-only validation. The
        // policy refuses at the *link entry itself*: `nitr build` never
        // emits links, so one can only mean a crafted archive.
        #[cfg(unix)]
        {
            let scratch = Scratch::new("slip-symlink");
            let staging = scratch.root.join("staging");
            std::fs::create_dir_all(&staging).expect("mkdir");
            let mut builder = tar::Builder::new(Vec::new());
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            link.set_mode(0o777);
            link.set_cksum();
            builder
                .append_link(&mut link, "link", "..")
                .expect("append symlink");
            raw_entry(&mut builder, "link/pwned.txt", b"pwned");
            let tar = builder.into_inner().expect("finish");

            let err = extract(&tar, &staging).expect_err("a symlink entry must refuse");
            assert!(
                err.to_string().contains("Symlink"),
                "the refusal must name the entry type: {err}"
            );
            assert!(
                !scratch.root.join("pwned.txt").exists(),
                "the file behind the symlink must not have landed above staging"
            );
            assert!(
                !staging.join("link").exists(),
                "the link itself must not have been created before the refusal"
            );
        }

        // A hard link to a file outside staging — same policy, same
        // refusal: only regular files and directories may appear.
        {
            let scratch = Scratch::new("slip-hardlink");
            let staging = scratch.root.join("staging");
            std::fs::create_dir_all(&staging).expect("mkdir");
            let mut builder = tar::Builder::new(Vec::new());
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Link);
            link.set_size(0);
            link.set_mode(0o644);
            link.set_cksum();
            builder
                .append_link(&mut link, "alias", "../outside.txt")
                .expect("append hard link");
            let tar = builder.into_inner().expect("finish");

            let err = extract(&tar, &staging).expect_err("a hard-link entry must refuse");
            assert!(err.to_string().contains("Link"), "got: {err}");
        }
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
