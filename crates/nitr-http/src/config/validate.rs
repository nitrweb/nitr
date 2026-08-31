// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Startup validation (`validate`/`validate_paths`), bundle path
//! re-anchoring (`rebase`), and the effective-config rendering.

use std::path::{Path, PathBuf};

use nitr_core::{Error, Result};

use super::Config;

impl Config {
    /// Rejects configurations that parse but cannot be honored.
    ///
    /// Called once at startup so a contradiction is a loud failure rather
    /// than a subtle runtime surprise, a browser silently ignoring a
    /// header combination is much harder to debug than a refused boot.
    pub(crate) fn validate(&self) -> Result {
        let any_origin = self
            .cors
            .origins
            .as_ref()
            .is_some_and(|o| o.iter().any(|o| o == "*"));
        if any_origin && self.cors.credentials {
            return Err(Error::Config(
                "[cors] origins = [\"*\"] cannot be combined with credentials = true: \
                 browsers reject `Access-Control-Allow-Origin: *` on a credentialed \
                 request. List the allowed origins explicitly."
                    .into(),
            ));
        }
        for name in &self.compression.algorithms {
            if !matches!(name.as_str(), "br" | "gzip") {
                return Err(Error::Config(format!(
                    "unknown [compression] algorithm `{name}`: expected \"br\" or \"gzip\""
                )));
            }
        }
        if let Some(max_streams) = self.max_streams
            && max_streams > self.workers.max(1)
        {
            return Err(Error::Config(format!(
                "max_streams = {max_streams} exceeds workers = {}: every streaming \
                 response holds a pooled Lua state, so the extra slots could never \
                 be used",
                self.workers.max(1)
            )));
        }
        // Waiting for a state longer than a handler is allowed to run means
        // the queue can only ever grow: work is admitted slower than it can
        // possibly be retired.
        if self.limits.pool_wait_ms > self.lua.exec_timeout_ms
            && self.limits.pool_wait_ms != 0
            && self.lua.exec_timeout_ms != 0
        {
            return Err(Error::Config(format!(
                "[limits] pool_wait_ms = {} exceeds [lua] exec_timeout_ms = {}: a \
                 request would wait for a state longer than any handler may run",
                self.limits.pool_wait_ms, self.lua.exec_timeout_ms
            )));
        }
        // Drained before the remaining hard checks, where the old inline
        // `warn!` sat: a config refused by a TLS or health error below still
        // logs its warnings, so the operator sees every problem in one boot.
        for warning in self.warnings() {
            tracing::warn!("{warning}");
        }
        self.validate_tls()?;
        if self.health.enabled {
            for (name, path) in [
                ("liveness", &self.health.liveness),
                ("readiness", &self.health.readiness),
            ] {
                if !path.starts_with('/') {
                    return Err(Error::Config(format!(
                        "[health] {name} = `{path}` must start with `/`"
                    )));
                }
            }
            if self.health.liveness == self.health.readiness {
                return Err(Error::Config(
                    "[health] liveness and readiness must be different paths: they \
                     answer different questions (see the [health] docs)"
                        .into(),
                ));
            }
        }
        self.validate_paths()
    }

    /// Configurations that are legal but suspicious, as values.
    ///
    /// Collected rather than logged in place so each one can be asserted in
    /// an ordinary unit test — a `tracing::warn!` is invisible to the
    /// `Result`-shaped assertions the rest of this module is tested with,
    /// and capturing it would cost a subscriber in `[dev-dependencies]`
    /// purely to read back log text. [`Config::validate`] drains this list
    /// through `tracing::warn!` at startup, so the boot output is unchanged.
    pub(crate) fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        // The stall bound still protects handlers that read the body
        // incrementally past the compute budget — but for the common
        // buffered read (`req:text()`, `req:form()`) the execution timeout
        // fires first, turning what should be a clear 408 into a
        // timeout-kind 500 that blames the handler.
        if self.limits.body_read_ms > self.lua.exec_timeout_ms
            && self.limits.body_read_ms != 0
            && self.lua.exec_timeout_ms != 0
        {
            out.push(format!(
                "[limits] body_read_ms = {} exceeds [lua] exec_timeout_ms = {}: a stalled \
                 buffered body read will surface as a handler timeout instead of a 408",
                self.limits.body_read_ms, self.lua.exec_timeout_ms
            ));
        }
        // An upload root under the static root means uploaded bytes are
        // served straight back to browsers. That is a real deployment
        // shape (user avatars), so it warns rather than refuses — but it
        // turns every upload into hosted content, which the operator has
        // to have chosen on purpose. Contrast the `package_dir` overlap,
        // which `validate_paths` refuses outright: there is no version of
        // that one an operator wants.
        if let (Some(upload), Some(static_dir)) =
            (&self.multipart.upload_dir, &self.static_files.dir)
            && let (Ok(upload), Ok(static_dir)) = (upload.canonicalize(), static_dir.canonicalize())
            && upload.starts_with(&static_dir)
        {
            out.push(format!(
                "[multipart] upload_dir {} is inside [static] dir {}: every uploaded file \
                 is served back over HTTP",
                upload.display(),
                static_dir.display()
            ));
        }
        // Auth cookies that will ship without `Secure`. Not a refusal:
        // plain-HTTP local development is legitimate, and a `Secure`
        // cookie sent over `http` is dropped by the browser silently —
        // a far worse failure than a line an operator can read.
        //
        // Deliberately *not* suppressed for a loopback bind: that is
        // precisely the terminating-proxy deployment, the one case that
        // most needs telling, and the one `"auto"` cannot see. `dev_mode`
        // is suppressed instead, because it is an explicit "I am
        // developing" switch rather than a deployment shape.
        //
        // `"never"` on a plaintext listener is silent: the operator has
        // answered the question, and the answer is consistent with the
        // transport. `"never"` *with* TLS enabled is the contradiction
        // worth naming — a server that terminates TLS and then opts its
        // cookies out of it.
        let secure_cookies = self.cookies.secure.resolve(self.tls.enabled);
        let contradiction = self.cookies.secure == super::CookieSecure::Never && self.tls.enabled;
        if !self.dev_mode
            && (contradiction
                || (!secure_cookies && self.cookies.secure != super::CookieSecure::Never))
        {
            let why = if contradiction {
                "[cookies] secure = \"never\" is set even though [tls] enabled = true"
            } else {
                "[tls] enabled = false, and [cookies] secure = \"auto\" follows it"
            };
            out.push(format!(
                "session and CSRF cookies will be sent without the `Secure` attribute: {why}. \
                 If TLS is terminated by a proxy in front of this process, set \
                 [cookies] secure = \"always\" — nothing here can detect that proxy."
            ));
        }
        // A private key other users on the box can read. A warning and
        // never a refusal: containers legitimately run as root with a
        // mounted secret, and a security check whose failure mode is "the
        // deployment does not come up" gets disabled. Ownership is
        // deliberately not examined — the operator's uid arrangement is
        // not the server's to police; the mode bits are merely mentioned.
        // Non-Unix has no comparable mode and skips the check.
        #[cfg(unix)]
        if self.tls.enabled
            && let Some(key) = &self.tls.key
            && let Ok(meta) = std::fs::metadata(key)
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = meta.permissions().mode();
            if !key_mode_is_private(mode) {
                out.push(format!(
                    "[tls] key = {} is mode {:03o}: readable beyond its owner. The server \
                     reads it regardless — protecting the file is the operator's job — \
                     but a private key usually wants 0600",
                    key.display(),
                    mode & 0o7777
                ));
            }
        }
        // `"debug"` is deliberately *not* warned about here: it is refused
        // outright by `LuaConfig::parse_stdlib`, because mlua's safe
        // constructor cannot load it at all. A warning would only precede a
        // failure.
        out
    }

    /// Rejects a `[tls]` section that cannot terminate a connection.
    ///
    /// Every check here fires at startup rather than at the first
    /// handshake: a listener that accepts TCP and then fails every
    /// connection is indistinguishable, from the outside, from a network
    /// fault, and it fails *after* a deployment has already shifted
    /// traffic onto it.
    fn validate_tls(&self) -> Result {
        if !self.tls.enabled {
            // An unused section is not held to its own rules — the same
            // way `[health]` skips its path checks when disabled — so a
            // half-written `[tls]` block can sit in a file until the day
            // somebody turns it on.
            return Ok(());
        }
        // `cfg!` rather than `#[cfg]` so the checks below are compiled —
        // and tested — in both feature configurations; only the refusal
        // is conditional.
        if cfg!(not(feature = "tls")) {
            return Err(Error::Config(
                "[tls] enabled = true, but this binary was built without the `tls` \
                 feature: rebuild with `--features tls` (or `all`)"
                    .into(),
            ));
        }
        for (key, what) in [("cert", "certificate chain"), ("key", "private key")] {
            let path = match key {
                "cert" => &self.tls.cert,
                _ => &self.tls.key,
            };
            let Some(path) = path else {
                return Err(Error::Config(format!(
                    "[tls] enabled = true requires `{key}`: set [tls] {key} to the PEM \
                     file holding the server {what}"
                )));
            };
            if !path.is_file() {
                return Err(Error::Config(format!(
                    "[tls] {key} points at {}, which is not a readable file",
                    path.display()
                )));
            }
        }
        // `0` is how `[limits]` spells "disabled", and it is exactly the
        // spelling this key must refuse: the handshake precedes hyper's
        // header machinery, so an unbounded accept would hold a
        // connection slot nothing else can reclaim. Unset (the default)
        // already means a bounded `min(header_read_ms, 10s)`.
        if self.tls.handshake_ms == Some(0) {
            return Err(Error::Config(
                "[tls] handshake_ms = 0 would leave the TLS handshake unbounded, and a \
                 stalled ClientHello holds a connection slot forever: set a positive \
                 deadline, or leave it unset for min(header_read_ms, 10s)"
                    .into(),
            ));
        }
        if let Some(version) = &self.tls.min_version
            && !super::sections::TLS_MIN_VERSIONS.contains(&version.as_str())
        {
            return Err(Error::Config(format!(
                "unknown [tls] min_version `{version}`: expected {}",
                super::sections::TLS_MIN_VERSIONS
                    .map(|v| format!("\"{v}\""))
                    .join(" or ")
            )));
        }
        Ok(())
    }

    /// Rejects paths that cannot work before any of them is opened, so a
    /// typo'd path is a startup error naming the setting, not a confusing
    /// failure minutes later.
    fn validate_paths(&self) -> Result {
        let checks: [(&str, Option<&PathBuf>, bool); 5] = [
            ("handler_script", Some(&self.handler_script), false),
            ("config_script", self.config_script.as_ref(), false),
            ("[templating] dir", self.templating.dir.as_ref(), true),
            ("[static] dir", self.static_files.dir.as_ref(), true),
            (
                "[multipart] upload_dir",
                self.multipart.upload_dir.as_ref(),
                true,
            ),
        ];
        for (name, path, want_dir) in checks {
            let Some(path) = path else { continue };
            if !path.exists() {
                return Err(Error::Config(format!(
                    "{name} points at {}, which does not exist",
                    path.display()
                )));
            }
            if want_dir != path.is_dir() {
                let (wanted, got) = if want_dir {
                    ("a directory", "a file")
                } else {
                    ("a file", "a directory")
                };
                return Err(Error::Config(format!(
                    "{name} must be {wanted}, but {} is {got}",
                    path.display()
                )));
            }
        }
        // Existence is not readability: a mis-owned static root would
        // otherwise answer every request 404 with nothing explaining why.
        // Probing with read_dir surfaces PermissionDenied at startup.
        if let Some(dir) = &self.static_files.dir
            && let Err(err) = std::fs::read_dir(dir)
        {
            return Err(Error::Config(format!(
                "[static] dir {} exists but cannot be read: {err}",
                dir.display()
            )));
        }
        // Uploads are the one thing Lua can write, so the root has to be
        // writable *now* rather than at the first upload, when the only
        // symptom is a 500 on a request nobody can reproduce. Existence
        // is not writability: a mis-owned or read-only-mounted directory
        // passes every check above.
        if let Some(dir) = &self.multipart.upload_dir {
            let probe = dir.join(format!(".nitr-write-probe-{}", std::process::id()));
            match std::fs::File::create(&probe) {
                Ok(file) => {
                    drop(file);
                    let _ = std::fs::remove_file(&probe);
                }
                Err(err) => {
                    return Err(Error::Config(format!(
                        "[multipart] upload_dir {} exists but cannot be written to: {err}",
                        dir.display()
                    )));
                }
            }
        }
        // An upload root inside the handler's own directory is the
        // upload-to-RCE chain written in configuration: `require`'s search
        // path is pinned there, so an uploaded `.lua` file becomes a
        // module the handler can load — and in dev mode the watcher may
        // reload it without being asked.
        if let Some(dir) = &self.multipart.upload_dir
            && let (Ok(upload), Ok(package)) =
                (dir.canonicalize(), self.package_dir().canonicalize())
            && upload.starts_with(&package)
        {
            return Err(Error::Config(format!(
                "[multipart] upload_dir {} is inside the handler script's directory {}: \
                 `require` is pinned there, so an uploaded file would be a loadable Lua \
                 module. Put the upload root outside it.",
                upload.display(),
                package.display()
            )));
        }
        // The database file itself may not exist yet (SQLite creates it),
        // but its parent directory must, SQLite will not create that.
        if let Some(db) = &self.database
            && let Some(parent) = db.path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.is_dir()
        {
            return Err(Error::Config(format!(
                "the database directory {} does not exist (SQLite creates the \
                 file, not its directory)",
                parent.display()
            )));
        }
        Ok(())
    }

    /// Re-anchors the application's relative paths under `root`.
    ///
    /// Used when running from a `nitr build` bundle: the scripts, templates
    /// and static files live in the extraction directory, while the
    /// database path is deliberately left alone, it is mutable state and
    /// stays external to the artifact, resolving against the working
    /// directory as usual. `[multipart] upload_dir` is left alone for the
    /// same reason — uploads outlive the bundle they were received by, and
    /// re-anchoring them inside a `nitr build` extraction directory would
    /// make them vanish on the next deploy. `[tls] cert`/`key` are left
    /// alone for the stronger version of the same reason: a private key
    /// inside a copyable one-file artifact is a private key that leaks
    /// with it.
    pub fn rebase(&mut self, root: &Path) {
        let anchor = |path: &mut PathBuf| {
            if path.is_relative() {
                *path = root.join(&path);
            }
        };
        anchor(&mut self.handler_script);
        if let Some(path) = &mut self.config_script {
            anchor(path);
        }
        if let Some(path) = &mut self.templating.dir {
            anchor(path);
        }
        if let Some(path) = &mut self.static_files.dir {
            anchor(path);
        }
        if let Some(db) = &mut self.database
            && let Some(dir) = &mut db.migrations_dir
        {
            anchor(dir);
        }
        anchor(&mut self.testing.dir);
    }

    /// The effective configuration after file, environment, and flag
    /// layering, rendered as TOML, the answer to "which value actually
    /// won?".
    pub fn effective_toml(&self) -> Result<String> {
        // Route through JSON first to drop the `None`s: TOML has no null,
        // and an absent key is exactly what an unset option means.
        let json = serde_json::to_value(self)
            .map_err(|err| Error::Config(format!("cannot serialize the configuration: {err}")))?;
        let json = strip_nulls(json);
        toml::to_string_pretty(&json)
            .map_err(|err| Error::Config(format!("cannot render the configuration: {err}")))
    }
}

/// Removes `null`s (and the entries they were) from a JSON tree, so the
/// result can render as TOML, which has no null.
fn strip_nulls(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, strip_nulls(v)))
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(strip_nulls).collect())
        }
        other => other,
    }
}

/// Whether a key file's mode keeps it to its owner: no group or other
/// bits at all. `0600`/`0400` pass; `0640`, `0644` and wider do not.
/// The predicate the `[tls] key` permission warning fires on, split out
/// so the mask is pinned by a unit test rather than implied by a log
/// line.
#[cfg(unix)]
pub(crate) fn key_mode_is_private(mode: u32) -> bool {
    mode & 0o077 == 0
}
