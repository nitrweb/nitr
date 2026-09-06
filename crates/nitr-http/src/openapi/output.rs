// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The dev-mode output file: `[openapi] output` rewritten after a build
//! when the document changed.
//!
//! The write goes to a fresh temporary name (`create_new`, so a planted
//! file or symlink under that name fails instead of being written
//! through) and is renamed into place; a pre-existing symlink at the
//! destination is refused rather than followed. Production never calls
//! this: the caller checks `dev_mode`.

use std::path::Path;

use nitr_core::{Error, Result};

/// What a write attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Written {
    /// The file already held these bytes.
    Unchanged,
    /// The file was (re)written with this many bytes.
    Bytes(usize),
}

/// Writes `bytes` to `path` when they differ from what is there.
pub(crate) fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<Written> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(Error::Config(format!(
                "[openapi] output {} is a symbolic link; refusing to write through it",
                path.display()
            )));
        }
        Ok(meta) if !meta.is_file() => {
            return Err(Error::Config(format!(
                "[openapi] output {} exists and is not a regular file",
                path.display()
            )));
        }
        Ok(_) => {
            if std::fs::read(path).is_ok_and(|current| current == bytes) {
                return Ok(Written::Unchanged);
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(Error::Config(format!(
                "[openapi] output {}: {err}",
                path.display()
            )));
        }
    }
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "openapi.json".into());
    let temp_name = format!(
        ".{name}.{}-{}.tmp",
        std::process::id(),
        uuid::Uuid::now_v7().simple()
    );
    let temp = match dir {
        Some(dir) => dir.join(&temp_name),
        None => Path::new(&temp_name).to_path_buf(),
    };
    let write = || -> std::io::Result<()> {
        use std::io::Write as _;
        let mut file = std::fs::File::create_new(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    };
    if let Err(err) = write() {
        let _ = std::fs::remove_file(&temp);
        return Err(Error::Config(format!(
            "[openapi] output {}: {err}",
            path.display()
        )));
    }
    Ok(Written::Bytes(bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nitr-openapi-output-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writes_once_per_change_and_leaves_no_temporaries() {
        let dir = scratch("once");
        let path = dir.join("openapi.json");
        assert_eq!(write_if_changed(&path, b"{}\n").unwrap(), Written::Bytes(3));
        assert_eq!(
            write_if_changed(&path, b"{}\n").unwrap(),
            Written::Unchanged
        );
        assert_eq!(
            write_if_changed(&path, b"{\"a\":1}\n").unwrap(),
            Written::Bytes(8)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":1}\n");
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["openapi.json"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_is_refused_not_followed() {
        let dir = scratch("symlink");
        let target = dir.join("victim.txt");
        std::fs::write(&target, b"keep me").unwrap();
        let link = dir.join("openapi.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = write_if_changed(&link, b"{}\n")
            .expect_err("symlink")
            .to_string();
        assert!(err.contains("symbolic link"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_directory_at_the_output_path_is_refused() {
        let dir = scratch("dir");
        let path = dir.join("openapi.json");
        std::fs::create_dir(&path).unwrap();
        let err = write_if_changed(&path, b"{}\n")
            .expect_err("dir")
            .to_string();
        assert!(err.contains("not a regular file"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
