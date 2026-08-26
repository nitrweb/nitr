// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Dev-mode file watcher: a save triggers the pool rebuild immediately,
//! instead of being noticed by the next request's mtime check.
//!
//! Watches the handler script's directory tree (which covers `require`d
//! modules and `routes/`), the configuration script, and the templates
//! directory. Events are debounced — editors emit a burst per save — and
//! then feed the same reload channel `SIGHUP` uses, so a dev-mode save and
//! an operator reload are one code path. Static files need no watching:
//! they are read from disk per request.
//!
//! Only changes to files a rebuild actually *reads* — Lua sources and the
//! templates tree — request a reload. The watched directories also hold
//! files the application *writes*: above all the SQLite database and its
//! WAL sidecars, which the configuration script may write during the
//! rebuild itself. Reacting to those would turn one save into an endless
//! reload loop (rebuild → db write → event → rebuild …); the same filter
//! keeps editor swap/backup files and logs from causing spurious reloads.

use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::Watcher as _;

use crate::config::Config;

/// How long a burst of events must be quiet before one reload fires.
const DEBOUNCE: Duration = Duration::from_millis(150);

/// How often the watcher thread checks whether the server stopped.
const STOP_POLL: Duration = Duration::from_millis(500);

/// Keeps the watcher thread alive for as long as the server serves;
/// dropping it disconnects the stop channel, which ends the thread.
pub(crate) struct WatchGuard {
    _stop: std::sync::mpsc::Sender<()>,
}

/// The rebuild's inputs, for deciding whether a changed path matters.
struct InputFilter {
    /// The templates root, both as configured and canonicalized: event
    /// paths arrive relative to the registered root on some backends
    /// (inotify) and absolute-canonical on others (FSEvents).
    templates: Vec<PathBuf>,
}

impl InputFilter {
    fn new(cfg: &Config) -> Self {
        let mut templates = Vec::new();
        if let Some(dir) = &cfg.templating.dir {
            templates.push(dir.clone());
            if let Ok(canonical) = dir.canonicalize()
                && !templates.contains(&canonical)
            {
                templates.push(canonical);
            }
        }
        Self { templates }
    }

    /// Whether a changed path is something a rebuild reads: a Lua source
    /// (the handler, its `require`d modules, the configuration script) or
    /// anything in the templates tree. The database, its `-wal`/`-shm`
    /// sidecars, editor swap/backup files, and logs all fail this test.
    fn is_input(&self, path: &Path) -> bool {
        path.extension().is_some_and(|ext| ext == "lua")
            || self.templates.iter().any(|root| path.starts_with(root))
    }
}

/// Whether an event is worth a rebuild: a content change (reads and
/// metadata-only churn are noise) touching a file the rebuild reads
/// (writes the application makes inside a watched directory must never
/// re-trigger the reload that caused them).
fn relevant(event: &notify::Event, filter: &InputFilter) -> bool {
    use notify::EventKind;
    let content_change = matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    );
    content_change && event.paths.iter().any(|path| filter.is_input(path))
}

/// The directories dev mode should react to.
fn watch_roots(cfg: &Config) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut push = |path: Option<&Path>| {
        // A bare `app.lua` has the empty path as its parent: that is the
        // working directory.
        let path = match path {
            Some(p) if p.as_os_str().is_empty() => Some(Path::new(".")),
            other => other,
        };
        if let Some(path) = path
            && path.exists()
            && !roots.iter().any(|r| path.starts_with(r))
        {
            roots.push(path.to_path_buf());
        }
    };
    // The handler's whole directory: `require` is confined to it, so any
    // file in it can be part of the application.
    push(cfg.handler_script.parent());
    push(cfg.config_script.as_deref().and_then(Path::parent));
    push(cfg.templating.dir.as_deref());
    roots
}

/// Starts watching; changed files send on `reload` after the debounce.
/// Returns `None` when there is nothing to watch.
///
/// Everything — watcher creation, the recursive registration walk, and
/// the debounce loop — runs on its own thread: registering watches over a
/// large tree can be slow, and `serve()` must never wait on it (a CI
/// hang taught this the hard way). Dropping the returned guard stops the
/// thread and with it the watcher.
pub(crate) fn spawn(cfg: &Config, reload: tokio::sync::mpsc::Sender<()>) -> Option<WatchGuard> {
    let roots = watch_roots(cfg);
    if roots.is_empty() {
        return None;
    }
    let filter = InputFilter::new(cfg);

    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let mut watcher =
            match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res
                    && relevant(&event, &filter)
                {
                    let _ = tx.send(());
                }
            }) {
                Ok(watcher) => watcher,
                Err(err) => {
                    tracing::warn!(
                        "dev-mode file watcher unavailable ({err}); reload via SIGHUP instead"
                    );
                    return;
                }
            };

        for root in &roots {
            if let Err(err) = watcher.watch(root, notify::RecursiveMode::Recursive) {
                tracing::warn!("cannot watch {} for changes: {err}", root.display());
            }
        }
        tracing::debug!(
            "watching {} for changes",
            roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        // The debounce loop: wait for a burst to go quiet, then request
        // one reload. Interleaved with the stop signal so the thread (and
        // the watcher it owns) dies promptly when the server stops.
        loop {
            match rx.recv_timeout(STOP_POLL) {
                Ok(()) => {
                    while rx.recv_timeout(DEBOUNCE).is_ok() {}
                    // A full channel means a reload is already queued.
                    let _ = reload.try_send(());
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
            match stop_rx.try_recv() {
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                _ => return,
            }
        }
    });

    Some(WatchGuard { _stop: stop_tx })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TemplatingConfig;

    #[test]
    fn roots_deduplicate_and_skip_missing_paths() {
        let dir = std::env::temp_dir().join(format!("nitr-watch-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("templates")).expect("mkdir");
        std::fs::write(dir.join("app.lua"), "-- app").expect("write");
        std::fs::write(dir.join("config.lua"), "-- config").expect("write");

        let mut cfg = Config {
            handler_script: dir.join("app.lua"),
            config_script: Some(dir.join("config.lua")),
            templating: TemplatingConfig {
                dir: Some(dir.join("templates")),
            },
            ..Config::default()
        };
        // Config script shares the handler's directory; templates are
        // inside it too — one root covers everything.
        let roots = watch_roots(&cfg);
        assert_eq!(roots, vec![dir.clone()]);

        // A missing templates dir elsewhere is skipped rather than fatal.
        cfg.templating.dir = Some(PathBuf::from("/nonexistent/templates"));
        let roots = watch_roots(&cfg);
        assert_eq!(roots, vec![dir.clone()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    fn filter_with_templates(dir: Option<&Path>) -> InputFilter {
        let cfg = Config {
            templating: TemplatingConfig {
                dir: dir.map(Path::to_path_buf),
            },
            ..Config::default()
        };
        InputFilter::new(&cfg)
    }

    #[test]
    fn only_content_events_on_inputs_are_relevant() {
        use notify::{Event, EventKind};
        let filter = filter_with_templates(None);
        let modify = EventKind::Modify(notify::event::ModifyKind::Any);

        let content = Event::new(modify).add_path(PathBuf::from("scripts/handler.lua"));
        assert!(relevant(&content, &filter));

        // Content change, but not to a file the rebuild reads.
        let noise = Event::new(modify).add_path(PathBuf::from("scripts/file.db"));
        assert!(!relevant(&noise, &filter));

        // An input path, but a read: metadata-only churn stays noise.
        let access = Event::new(EventKind::Access(notify::event::AccessKind::Any))
            .add_path(PathBuf::from("scripts/handler.lua"));
        assert!(!relevant(&access, &filter));
    }

    /// The regression this filter exists for: the configuration script
    /// writes the SQLite database (WAL sidecars included) *inside* the
    /// watched scripts directory on every rebuild. Reacting to those
    /// writes turned one save into an endless reload loop.
    #[test]
    fn rebuild_side_effects_and_editor_noise_are_not_inputs() {
        let filter = filter_with_templates(Some(Path::new("scripts/templates")));

        for input in [
            "scripts/handler.lua",
            "scripts/config.lua",
            "scripts/routes/notes.lua",
            "scripts/templates/response.j2",
            "scripts/templates/partials/header.html",
        ] {
            assert!(filter.is_input(Path::new(input)), "must reload: {input}");
        }

        for noise in [
            "scripts/file.db",
            "scripts/file.db-wal",
            "scripts/file.db-shm",
            "scripts/.handler.lua.swp",
            "scripts/handler.lua~",
            "scripts/4913", // vim's write-check probe file
            "scripts/server.log",
        ] {
            assert!(!filter.is_input(Path::new(noise)), "must ignore: {noise}");
        }
    }

    /// FSEvents (macOS) reports absolute canonical paths no matter how the
    /// root was registered, so the templates rule must match those too.
    #[test]
    fn canonical_template_paths_are_recognized() {
        let dir = std::env::temp_dir().join(format!("nitr-watch-canon-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("templates")).expect("mkdir");
        let filter = filter_with_templates(Some(&dir.join("templates")));

        let canonical = dir
            .join("templates")
            .canonicalize()
            .expect("canonicalize")
            .join("page.html");
        assert!(filter.is_input(&canonical));

        std::fs::remove_dir_all(&dir).ok();
    }
}
