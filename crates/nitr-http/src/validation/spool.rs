// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Spooling an upload to a per-request temporary under the upload root,
//! sniffing its first bytes on the way, and the guard that removes what
//! the handler did not keep. The invariant of the multipart module holds:
//! the bytes never enter the Lua heap.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use mlua::ExternalResult as _;
use nitr_std::validation::{
    Detection, FileInfo, SNIFF_BYTES, SaveResolver, detect, dimensions, text_subtype_matches,
};

use crate::multipart::{resolve_upload_path, safe_filename};

/// The directory under the upload root that holds per-request spools.
pub(crate) const SPOOL_DIR: &str = ".nitr-tmp";

/// Removes leftovers of a crashed process at startup.
pub(crate) fn sweep(upload_root: &Path) {
    let dir = upload_root.join(SPOOL_DIR);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => tracing::info!("removed stale upload spool {}", dir.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => tracing::warn!("cannot remove the upload spool {}: {err}", dir.display()),
    }
}

/// A request's spool directory: created lazily by the first upload,
/// removed — with whatever was not saved — when the request ends,
/// whether it succeeded, failed, timed out or panicked.
pub(crate) struct SpoolDir {
    path: PathBuf,
}

impl SpoolDir {
    /// The spool for one request under `upload_root`. Nothing is created
    /// yet.
    pub(crate) fn new(upload_root: &Path, request_id: &str) -> Self {
        // The id is a UUID (or a header the protection layer already
        // reduced to 64 safe ASCII chars); no separator can be in it.
        let safe: String = request_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(64)
            .collect();
        Self {
            path: upload_root.join(SPOOL_DIR).join(safe),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SpoolDir {
    fn drop(&mut self) {
        let path = self.path.clone();
        // Off the async thread when there is one; a handler that saved
        // its file leaves an empty directory, the common cheap case.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(move || {
                    let _ = std::fs::remove_dir_all(path);
                });
            }
            Err(_) => {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}

/// Tracks UTF-8 validity across chunk boundaries.
struct Utf8Tracker {
    valid: bool,
    carry: Vec<u8>,
}

impl Utf8Tracker {
    fn new() -> Self {
        Self {
            valid: true,
            carry: Vec::new(),
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        if !self.valid {
            return;
        }
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        match std::str::from_utf8(&buf) {
            Ok(_) => {}
            Err(err) if err.error_len().is_none() => {
                self.carry = buf[err.valid_up_to()..].to_vec();
            }
            Err(_) => self.valid = false,
        }
    }

    fn finish(self) -> bool {
        self.valid && self.carry.is_empty()
    }
}

/// Writes chunks to a spool file while counting, sniffing and checking
/// UTF-8; stops writing past `cap` but keeps counting so the rule can
/// report the size.
pub(crate) struct Spooler {
    file: tokio::fs::File,
    path: PathBuf,
    cap: u64,
    size: u64,
    prefix: Vec<u8>,
    utf8: Utf8Tracker,
}

impl Spooler {
    /// Opens `path` under a fresh name (never through an existing file).
    pub(crate) async fn create(dir: &Path, index: usize, cap: u64) -> mlua::Result<Self> {
        tokio::fs::create_dir_all(dir).await.into_lua_err()?;
        let path = dir.join(index.to_string());
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .into_lua_err()?;
        Ok(Self {
            file,
            path,
            cap,
            size: 0,
            prefix: Vec::with_capacity(SNIFF_BYTES.min(8 * 1024)),
            utf8: Utf8Tracker::new(),
        })
    }

    pub(crate) async fn push(&mut self, chunk: &[u8]) -> mlua::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        if self.prefix.len() < SNIFF_BYTES {
            let take = (SNIFF_BYTES - self.prefix.len()).min(chunk.len());
            self.prefix.extend_from_slice(&chunk[..take]);
        }
        self.utf8.push(chunk);
        self.size = self.size.saturating_add(chunk.len() as u64);
        if self.size <= self.cap {
            self.file.write_all(chunk).await.into_lua_err()?;
        }
        Ok(())
    }

    /// Flushes and describes what arrived.
    pub(crate) async fn finish(
        mut self,
        filename: Option<String>,
        declared_type: Option<String>,
    ) -> mlua::Result<(PathBuf, FileInfo)> {
        use tokio::io::AsyncWriteExt as _;
        self.file.flush().await.into_lua_err()?;
        let detected = detect(&self.prefix);
        let (width, height) = match detected {
            Detection::Detected(media) if media.has_dimensions() => {
                dimensions(media, &self.prefix).map_or((None, None), |(w, h)| (Some(w), Some(h)))
            }
            _ => (None, None),
        };
        let text_subtype_ok = declared_type
            .as_deref()
            .is_some_and(|d| text_subtype_matches(d, &self.prefix));
        let safe = filename.as_deref().map(safe_filename);
        let extension = safe.as_deref().and_then(|name| {
            name.rsplit_once('.')
                .map(|(_, ext)| ext.to_ascii_lowercase())
                .filter(|ext| !ext.is_empty())
        });
        let info = FileInfo {
            filename,
            safe_filename: safe,
            extension,
            declared_type,
            detected,
            text_subtype_ok,
            size: self.size,
            width,
            height,
            utf8: Some(self.utf8.finish()),
        };
        Ok((self.path, info))
    }

    /// Bytes counted so far.
    pub(crate) fn size(&self) -> u64 {
        self.size
    }
}

/// The containment rule for `file:save(rel)`: every target lands inside
/// the upload root.
pub(crate) fn resolver(root: Arc<PathBuf>) -> SaveResolver {
    Arc::new(move |rel: String| {
        let root = root.clone();
        Box::pin(async move { resolve_upload_path(&root, &rel).await })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_is_tracked_across_chunk_boundaries() {
        let bytes = "caf\u{e9} ok".as_bytes();
        let mut t = Utf8Tracker::new();
        t.push(&bytes[..4]);
        t.push(&bytes[4..]);
        assert!(t.finish());
        let mut t = Utf8Tracker::new();
        t.push(b"\xFF\xFE");
        assert!(!t.finish());
        let mut t = Utf8Tracker::new();
        t.push(&bytes[..4]);
        assert!(!t.finish(), "a dangling lead byte is not complete UTF-8");
    }

    #[test]
    fn spool_paths_are_under_the_root_and_safe() {
        let root = Path::new("/srv/uploads");
        let spool = SpoolDir::new(root, "0198c5b6-1f6a-7abc-9def-0123456789ab");
        assert!(spool.path().starts_with(root.join(SPOOL_DIR)));
        let hostile = SpoolDir::new(root, "../../etc");
        assert_eq!(hostile.path(), root.join(SPOOL_DIR).join("etc"));
        // Dropping removes a directory that was never created: a no-op.
    }
}
