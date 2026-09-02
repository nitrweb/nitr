// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Static file serving, entirely in Rust: requests that match a static
//! mount never touch a Lua state. Supports conditional requests
//! (`ETag` / `Last-Modified` → 304), content-type detection, directory
//! `index.html`, an SPA fallback, and streamed file bodies.
//!
//! Path safety: the URL path is percent-decoded, split into components
//! (rejecting `..`, absolute and empty segments), joined under the mount
//! directory, and the final canonicalized path must stay inside the
//! canonicalized root — so symlinks cannot escape the mount either.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use http_body_util::{BodyExt as _, Empty, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Response, StatusCode};

use crate::compress::{Compression, Encoding};
use crate::handler::HttpResponse;
use crate::request::LuaRequest;
use nitr_core::Result;

/// Chunk size for streamed file bodies.
const FILE_CHUNK: usize = 64 * 1024;

/// Files up to this size are served in one piece instead of streamed.
const INLINE_LIMIT: u64 = 256 * 1024;

/// One static mount: requests under `mount` are served from `dir`.
#[derive(Debug, Clone)]
pub struct StaticMount {
    /// URL prefix, normalized to start with `/` and not end with one
    /// (except the root mount `/`).
    pub(crate) mount: String,
    pub(crate) dir: PathBuf,
    /// Serve `index.html` for unknown paths (single-page applications).
    pub(crate) spa: bool,
    /// Explicit `Cache-Control` header value for served files.
    pub(crate) cache_control: Option<String>,
    /// Serve files and directories whose name starts with `.`.
    pub(crate) dotfiles: bool,
}

impl StaticMount {
    /// A mount serving `dir` at the URL prefix `mount`.
    pub fn new(
        mount: impl Into<String>,
        dir: impl Into<PathBuf>,
        spa: bool,
        cache_control: Option<String>,
    ) -> Self {
        let mut mount = mount.into();
        if !mount.starts_with('/') {
            mount.insert(0, '/');
        }
        while mount.len() > 1 && mount.ends_with('/') {
            mount.pop();
        }
        Self {
            mount,
            dir: dir.into(),
            spa,
            cache_control,
            dotfiles: false,
        }
    }

    /// Whether dotfiles are served (default: no). `.env`, `.git/`,
    /// `.htpasswd` and their kind are exactly what lands in a served
    /// directory by accident, and nothing a browser needs starts with a
    /// dot — except `.well-known/`, which is always served.
    pub fn dotfiles(mut self, allow: bool) -> Self {
        self.dotfiles = allow;
        self
    }

    /// The request path relative to this mount, when it applies.
    pub fn relative<'p>(&self, path: &'p str) -> Option<&'p str> {
        if self.mount == "/" {
            return Some(path.trim_start_matches('/'));
        }
        let rest = path.strip_prefix(&self.mount)?;
        match rest.as_bytes().first() {
            None => Some(""),
            Some(b'/') => Some(&rest[1..]),
            _ => None, // /assetsfoo must not match mount /assets
        }
    }
}

/// The `[static]` configuration expressed as mounts (empty when no `dir`
/// is configured).
pub(crate) fn base_mounts(cfg: &crate::config::Config) -> Vec<StaticMount> {
    cfg.static_files
        .dir
        .as_ref()
        .map(|dir| {
            vec![
                StaticMount::new(
                    cfg.static_files.mount.clone().unwrap_or_else(|| "/".into()),
                    dir.clone(),
                    cfg.static_files.spa,
                    cfg.static_files.cache_control.clone(),
                )
                .dotfiles(cfg.static_files.dotfiles),
            ]
        })
        .unwrap_or_default()
}

/// Tries to serve the request from the given mounts (first match on the
/// longest mount prefix wins). `None` means "not a static asset" and the
/// caller continues its normal dispatch.
pub(crate) async fn try_serve(
    mounts: &[StaticMount],
    req: &LuaRequest,
    compression: &Compression,
) -> Option<Result<HttpResponse>> {
    if mounts.is_empty() || !matches!(*req.req.method(), Method::GET | Method::HEAD) {
        return None;
    }
    let path = req.req.uri().path();
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;

    let mut candidates: Vec<&StaticMount> = mounts
        .iter()
        .filter(|m| m.relative(&decoded).is_some())
        .collect();
    candidates.sort_by_key(|m| std::cmp::Reverse(m.mount.len()));

    for mount in candidates {
        let rel = mount.relative(&decoded)?;
        let Some(file) = resolve_in(mount, rel).await else {
            // Unknown path inside an SPA mount falls back to its index.
            if mount.spa
                && let Some(index) = resolve(&mount.dir, "index.html").await
            {
                return Some(serve_file(req, mount, &index, compression).await);
            }
            continue;
        };
        return Some(serve_file(req, mount, &file, compression).await);
    }
    None
}

/// [`resolve`] under a mount's dotfile policy: a path with a `.`-prefixed
/// component is refused before the filesystem is consulted, unless the
/// mount serves dotfiles or the path is under `.well-known/`.
async fn resolve_in(mount: &StaticMount, rel: &str) -> Option<PathBuf> {
    let rel_path = rel.trim_start_matches('/');
    // A lone `.` is the current directory, not a dotfile; `safe_join`
    // skips it the way a browser would have.
    let hidden = rel_path
        .split(['/', '\\'])
        .any(|segment| segment != "." && segment.starts_with('.'));
    if hidden && !mount.dotfiles && !is_well_known(rel_path) {
        return None;
    }
    resolve(&mount.dir, rel).await
}

/// Whether the path is `.well-known` or inside it, with nothing else in
/// it hidden (`.well-known/.secret` is refused; `.well-known/../.env` is
/// a `..`, refused by the lexical rule anyway).
fn is_well_known(rel: &str) -> bool {
    let mut segments = rel.split(['/', '\\']);
    segments.next() == Some(".well-known") && segments.all(|s| !s.starts_with('.'))
}

/// The traversal defense as one call, for the `static_resolve` fuzz
/// target: percent-decode the URL path, take it relative to the mount,
/// and resolve it — the same three steps [`try_serve`] performs, in the
/// same order, so what the fuzzer explores is the served path and not a
/// reimplementation of it.
///
/// Only the *path* handling is shared; `try_serve` additionally picks a
/// mount and serves the file, neither of which changes which paths are
/// reachable. Keep this next to `try_serve` so the two cannot drift
/// unnoticed.
#[doc(hidden)]
pub async fn resolve_for_fuzzing(mount: &StaticMount, url_path: &str) -> Option<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(url_path)
        .decode_utf8()
        .ok()?;
    let rel = mount.relative(&decoded)?;
    resolve_in(mount, rel).await
}

/// Resolves a relative URL path to a regular file inside `dir`, or `None`
/// (unsafe path, missing file, unreadable metadata). Directories resolve
/// to their `index.html`.
async fn resolve(dir: &Path, rel: &str) -> Option<PathBuf> {
    // The lexical rule (`..`, absolute segments, drive prefixes, NUL) is
    // shared with `part:save`'s upload root — see `crate::safe_path`. The
    // canonicalized containment check below is this caller's half.
    //
    // Leading separators are stripped first because a URL path always has
    // one and `StaticMount::relative` only removes it for some mounts:
    // `/assets//a.txt` comes back as `/a.txt`, which is rooted. That is
    // *not* an absolute filesystem path, it is a URL with a doubled
    // separator, and it served `<dir>/a.txt` before this rule was shared.
    // `relative`'s own root-mount branch trims exactly this way.
    let mut path = crate::safe_path::safe_join(dir, rel.trim_start_matches('/')).ok()?;

    let meta = fs_ok(tokio::fs::metadata(&path).await, &path)?;
    if meta.is_dir() {
        path.push("index.html");
        fs_ok(tokio::fs::metadata(&path).await, &path)?
            .is_file()
            .then_some(())?;
    } else if !meta.is_file() {
        return None;
    }

    // Symlink policy: the canonical target must stay inside the canonical
    // root, so links cannot escape the mount.
    let canonical = fs_ok(tokio::fs::canonicalize(&path).await, &path)?;
    let root = fs_ok(tokio::fs::canonicalize(dir).await, dir)?;
    canonical.starts_with(&root).then_some(canonical)
}

/// Filesystem access on the serving path. An absent file is normal
/// traffic; anything else (permissions, a broken mount) is a server-side
/// problem worth a diagnostic — while the client gets the same
/// non-leaking 404 either way.
///
/// The diagnostic is `debug`, not `warn`, and the path is rendered with
/// `{:?}` rather than `Path::display`, both on purpose: the path here is
/// built from the request URI, so a URI that manufactures a non-`NotFound`
/// error (`ENAMETOOLONG`, `EACCES`) was an unauthenticated log amplifier
/// at `warn`, and `display()` passes control bytes through — a `\n` in a
/// request path could forge a whole log line. `{:?}` quotes and escapes;
/// `debug` is not on in production. The operator debugging a real
/// permissions problem (a mis-chowned static root looks exactly like a
/// missing file) turns on `debug` and still gets the path and the error
/// kind.
fn fs_ok<T>(result: std::io::Result<T>, path: &Path) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            tracing::debug!(kind = ?err.kind(), "static file access failed for {path:?}: {err}");
            None
        }
    }
}

/// Serves one resolved file: precompressed sidecar selection, conditional
/// requests, and range requests.
async fn serve_file(
    req: &LuaRequest,
    mount: &StaticMount,
    path: &Path,
    compression: &Compression,
) -> Result<HttpResponse> {
    // The bytes may come from a sidecar, but the content type always comes
    // from the *logical* file: `app.js.br` is still JavaScript.
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let (source, encoding) = pick_source(req, path, compression).await;

    let meta = match tokio::fs::metadata(&source).await {
        Ok(meta) => meta,
        Err(err) => {
            tracing::error!("failed to stat static file {}: {err}", source.display());
            return not_found();
        }
    };
    let len = meta.len();
    let modified = meta.modified().ok();
    // Derived from the served bytes, so each encoding is its own
    // representation with its own validator.
    let etag = etag_for(len, modified);

    let headers = req.req.headers();
    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, mime.as_ref())
        .header(header::ETAG, &etag);
    if let Some(modified) = modified {
        builder = builder.header(header::LAST_MODIFIED, httpdate::fmt_http_date(modified));
    }
    if let Some(cache_control) = &mount.cache_control
        && let Ok(value) = HeaderValue::from_str(cache_control)
    {
        builder = builder.header(header::CACHE_CONTROL, value);
    }
    // A sidecar is looked for on every request, so which bytes come back
    // genuinely depends on this header — say so, or a shared cache will
    // hand brotli to a client that cannot read it.
    builder = builder.header(header::VARY, "accept-encoding");
    if let Some(encoding) = encoding {
        builder = builder.header(header::CONTENT_ENCODING, encoding.token());
    }

    if crate::request::is_fresh(
        headers,
        Some(&etag),
        modified.map(|m| secs_since_epoch(m) as i64),
    ) {
        return Ok(builder
            .status(StatusCode::NOT_MODIFIED)
            .body(Empty::<Bytes>::new().boxed())?);
    }

    // Ranges are offered on the representation actually being sent, which
    // is why this comes after the sidecar decision.
    builder = builder.header(header::ACCEPT_RANGES, "bytes");
    let range = crate::range::resolve(headers, len, &etag, modified);
    if range == crate::range::Resolved::Unsatisfiable {
        return Ok(builder
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{len}"))
            .body(Empty::<Bytes>::new().boxed())?);
    }
    let (start, count) = match range {
        crate::range::Resolved::Partial { start, end } => {
            builder = builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"));
            (start, end - start + 1)
        }
        _ => {
            builder = builder.status(StatusCode::OK);
            (0, len)
        }
    };

    builder = builder.header(header::CONTENT_LENGTH, count);
    if *req.req.method() == Method::HEAD {
        // Answered without touching the file: a HEAD is a question about
        // the headers.
        return Ok(builder.body(Empty::<Bytes>::new().boxed())?);
    }

    if count <= INLINE_LIMIT {
        match read_span(&source, start, count).await {
            Ok(data) => Ok(builder.body(Full::new(data).boxed())?),
            Err(err) => {
                tracing::error!("failed to read static file {}: {err}", source.display());
                not_found()
            }
        }
    } else {
        Ok(builder.body(stream_file(source, start, count).await?)?)
    }
}

/// Chooses the bytes to serve: a precompressed sidecar when the client
/// accepts its coding and the file is actually there, else the file itself.
///
/// This runs regardless of the `[compression]` section: a sidecar was
/// compressed once at build time, so serving it costs nothing and gives a
/// better ratio than anything done per request.
async fn pick_source(
    req: &LuaRequest,
    path: &Path,
    compression: &Compression,
) -> (PathBuf, Option<Encoding>) {
    let Some(encoding) = compression.negotiate(req.req.headers().get(header::ACCEPT_ENCODING))
    else {
        return (path.to_path_buf(), None);
    };
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(".");
    sidecar.push(encoding.extension());
    let sidecar = PathBuf::from(sidecar);
    match tokio::fs::metadata(&sidecar).await {
        Ok(meta) if meta.is_file() => (sidecar, Some(encoding)),
        _ => (path.to_path_buf(), None),
    }
}

/// Reads `count` bytes starting at `start`.
async fn read_span(path: &Path, start: u64, count: u64) -> std::io::Result<Bytes> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

    let mut file = tokio::fs::File::open(path).await?;
    if start > 0 {
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }
    let mut buf = Vec::with_capacity(count as usize);
    file.take(count).read_to_end(&mut buf).await?;
    Ok(Bytes::from(buf))
}

/// Streams `count` bytes from `start` through a small bounded channel (same
/// shape as streaming Lua bodies); a read error mid-stream closes the body.
async fn stream_file(
    path: PathBuf,
    start: u64,
    count: u64,
) -> Result<http_body_util::combinators::BoxBody<Bytes, Infallible>> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

    let open = async {
        let mut file = tokio::fs::File::open(&path).await?;
        if start > 0 {
            file.seek(std::io::SeekFrom::Start(start)).await?;
        }
        Ok::<_, std::io::Error>(file)
    };
    let mut file = open.await.map_err(|err| {
        nitr_core::Error::Io(std::io::Error::new(
            err.kind(),
            format!("failed to open static file {}: {err}", path.display()),
        ))
    })?;

    let (tx, rx) = async_channel::bounded::<std::result::Result<Frame<Bytes>, Infallible>>(2);
    tokio::spawn(async move {
        let mut remaining = count;
        let mut buf = vec![0u8; FILE_CHUNK];
        while remaining > 0 {
            // Clamp in `u64` first: on a 32-bit target `remaining as usize`
            // truncates, and a > 4 GiB span could clamp to a zero-length
            // read that ends the stream short of its `Content-Length`.
            let want = remaining.min(FILE_CHUNK as u64) as usize;
            match file.read(&mut buf[..want]).await {
                Ok(0) => break,
                Ok(n) => {
                    remaining -= n as u64;
                    let chunk = Bytes::copy_from_slice(&buf[..n]);
                    if tx.send(Ok(Frame::data(chunk))).await.is_err() {
                        break; // client disconnected
                    }
                }
                Err(err) => {
                    tracing::error!("static file read failed mid-stream: {err}");
                    break;
                }
            }
        }
        tx.close();
    });
    Ok(StreamBody::new(rx).boxed())
}

fn etag_for(len: u64, modified: Option<SystemTime>) -> String {
    format!("\"{len:x}-{:x}\"", modified.map_or(0, secs_since_epoch))
}

fn secs_since_epoch(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn not_found() -> Result<HttpResponse> {
    crate::handler::plain_response(StatusCode::NOT_FOUND, "Not Found")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absent files stay a quiet `None` (normal traffic); every other
    /// filesystem error also answers `None` — same non-leaking 404 — but
    /// is the case [`fs_ok`] logs for the operator, at `debug` with the
    /// path escaped (the path is request-derived, so `warn` was a log
    /// amplifier; the level is pinned end to end in
    /// `crates/nitr/tests/diagnostics.rs`).
    #[test]
    fn fs_errors_all_resolve_to_none() {
        use std::io::{Error as IoError, ErrorKind};
        let p = Path::new("x");
        assert_eq!(fs_ok(Ok(7), p), Some(7));
        assert!(fs_ok::<()>(Err(IoError::from(ErrorKind::NotFound)), p).is_none());
        assert!(fs_ok::<()>(Err(IoError::from(ErrorKind::PermissionDenied)), p).is_none());
    }

    #[test]
    fn mounts_normalize_and_match() {
        let m = StaticMount::new("assets/", "public", false, None);
        assert_eq!(m.mount, "/assets");
        assert_eq!(m.relative("/assets"), Some(""));
        assert_eq!(m.relative("/assets/app.js"), Some("app.js"));
        assert_eq!(m.relative("/assetsfoo"), None);
        assert_eq!(m.relative("/other"), None);

        let root = StaticMount::new("/", "public", false, None);
        assert_eq!(root.relative("/x/y.css"), Some("x/y.css"));
    }

    /// A private scratch directory per test: unique (counter + pid, so
    /// parallel tests never share), removed on success, and kept — with
    /// its path printed — when the test panicked, mirroring the
    /// integration harness's `TestDir` rules.
    struct TestRoot {
        path: PathBuf,
    }

    impl TestRoot {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("nitr-static-{label}-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create test dir");
            Self { path }
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!("[test] failed; keeping {}", self.path.display());
            } else {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    #[tokio::test]
    async fn traversal_and_escapes_are_rejected() {
        let root = TestRoot::new("traversal");
        let dir = root.path.join("mount");
        std::fs::create_dir_all(dir.join("sub")).expect("mkdir");
        std::fs::write(dir.join("ok.txt"), b"ok").expect("write");
        std::fs::write(dir.join("sub/inner.txt"), b"inner").expect("write");
        // A real file *outside* the mount, so a broken `resolve` that
        // walked out would find something rather than a benign 404.
        std::fs::write(root.path.join("secret.txt"), b"outside").expect("write");

        // The positive cases pin *which* file resolved, not merely that
        // something did: a resolve() returning a constant path would
        // otherwise pass.
        async fn canonical(p: PathBuf) -> PathBuf {
            tokio::fs::canonicalize(p).await.expect("canonical")
        }
        assert_eq!(
            resolve(&dir, "ok.txt").await,
            Some(canonical(dir.join("ok.txt")).await)
        );
        assert_eq!(
            resolve(&dir, "sub/inner.txt").await,
            Some(canonical(dir.join("sub/inner.txt")).await)
        );

        // Vectors aimed at the file that exists one level up.
        for hostile in [
            "../secret.txt",
            "sub/../../secret.txt",
            "sub/../../../etc/passwd",
            "/etc/passwd",
            "..",
            "sub/..\\..\\secret.txt",
        ] {
            assert_eq!(
                resolve(&dir, hostile).await,
                None,
                "{hostile} must not resolve"
            );
        }
        assert_eq!(resolve(&dir, "missing.txt").await, None);
    }

    /// Dotfiles are refused by default, `.well-known/` excepted, and a
    /// mount can opt in.
    #[tokio::test]
    async fn dotfiles_are_hidden_unless_the_mount_says_otherwise() {
        let root = TestRoot::new("dotfiles");
        let dir = root.path.join("mount");
        std::fs::create_dir_all(dir.join(".git")).expect("mkdir");
        std::fs::create_dir_all(dir.join(".well-known/acme-challenge")).expect("mkdir");
        std::fs::write(dir.join(".env"), b"SECRET=1").expect("write");
        std::fs::write(dir.join(".git/config"), b"[core]").expect("write");
        std::fs::write(dir.join(".well-known/acme-challenge/token"), b"ok").expect("write");
        std::fs::write(dir.join(".well-known/.hidden"), b"no").expect("write");
        std::fs::write(dir.join("index.html"), b"<p>").expect("write");

        let mount = StaticMount::new("/", &dir, false, None);
        for hidden in [".env", ".git/config", "/.env", ".well-known/.hidden"] {
            assert_eq!(
                resolve_in(&mount, hidden).await,
                None,
                "{hidden} must be hidden"
            );
        }
        assert!(
            resolve_in(&mount, ".well-known/acme-challenge/token")
                .await
                .is_some()
        );
        assert!(resolve_in(&mount, "index.html").await.is_some());
        assert!(
            resolve_in(&mount, "./index.html").await.is_some(),
            "a `.` segment is not a dotfile"
        );

        let open = StaticMount::new("/", &dir, false, None).dotfiles(true);
        assert!(resolve_in(&open, ".env").await.is_some());
    }

    /// Symlink policy: a link whose canonical target leaves the mount is
    /// refused; one that stays inside resolves to its target.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_cannot_escape_the_mount() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("symlink");
        let dir = root.path.join("mount");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("ok.txt"), b"ok").expect("write");
        std::fs::write(root.path.join("secret.txt"), b"outside").expect("write");
        std::fs::create_dir_all(root.path.join("outside-dir")).expect("mkdir");
        std::fs::write(root.path.join("outside-dir/leak.txt"), b"leak").expect("write");

        // A file link and a directory link, both escaping the mount.
        symlink(root.path.join("secret.txt"), dir.join("link.txt")).expect("file link");
        symlink(root.path.join("outside-dir"), dir.join("sublink")).expect("dir link");
        assert_eq!(resolve(&dir, "link.txt").await, None, "file symlink escape");
        assert_eq!(
            resolve(&dir, "sublink/leak.txt").await,
            None,
            "directory symlink escape"
        );

        // A link that stays inside the mount is legitimate and resolves
        // to its canonical target.
        symlink(dir.join("ok.txt"), dir.join("alias.txt")).expect("inside link");
        assert_eq!(
            resolve(&dir, "alias.txt").await,
            Some(
                tokio::fs::canonicalize(dir.join("ok.txt"))
                    .await
                    .expect("canonical")
            )
        );
    }
}
