// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! End-to-end tests for the `nitr` binary: version, effective-config
//! printing, `nitr build` artifacts, and pidfile-based reload.

use std::path::{Path, PathBuf};
use std::process::Command;

fn nitr() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nitr"))
}

/// Whether the compiled `nitr` binary can actually execute here. Under a
/// cross-compiled test run (the CI's qemu matrix) the *test binary* is
/// emulated, but a child process it spawns is a foreign ELF the host
/// cannot exec — every end-to-end test would fail on the exec, not on
/// anything it means to assert. Those tests skip instead.
///
/// The skip is reserved for exactly that case: when the binary *can* be
/// spawned but `-v` fails, that is a crash-on-startup regression, and the
/// suite fails loudly instead of turning green with everything skipped.
fn binary_runs() -> bool {
    match nitr().arg("-v").output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => panic!(
            "`nitr -v` executed but failed (exit {:?}) — a startup regression, \
             not a cross-compilation skip: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ),
        // The exec itself failed: a foreign ELF the host cannot run.
        Err(_) => false,
    }
}

/// Skips the calling test (with a note) when the binary cannot run.
macro_rules! require_runnable_binary {
    () => {
        if !binary_runs() {
            eprintln!("skipping: the target binary cannot execute on this host (cross-compiled)");
            return;
        }
    };
}

/// A scratch application directory: unique per test (counter + pid, so
/// parallel runs and repeated names never collide), removed on success,
/// and kept — with its path printed — when the test panicked. The same
/// rules as the integration harness's `TestDir`; a bare temp path with a
/// trailing `remove_dir_all` leaks exactly when the evidence matters.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nitr-cli-{name}-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("[test] failed; keeping {}", self.path.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// A scratch application directory scaffolded by `nitr init`.
fn scaffold(name: &str, minimal: bool) -> Scratch {
    let dir = Scratch::new(name);
    let mut cmd = nitr();
    cmd.arg("init").arg(&dir.path);
    if minimal {
        cmd.arg("--minimal");
    }
    let out = cmd.output().expect("run nitr init");
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    dir
}

#[test]
fn version_flag_prints_the_crate_version() {
    require_runnable_binary!();
    for flag in ["-v", "--version"] {
        let out = nitr().arg(flag).output().expect("run nitr");
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            stdout.trim(),
            format!("nitr {}", env!("CARGO_PKG_VERSION")),
            "flag {flag}"
        );
    }
}

#[test]
fn check_print_config_shows_the_effective_layering() {
    require_runnable_binary!();
    let dir = scaffold("print-config", true);
    let out = nitr()
        .current_dir(&dir)
        .env("NITR_WORKERS", "3")
        .args(["check", "--print-config"])
        .output()
        .expect("run check");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The file's value…
    assert!(
        stdout.contains("listen = \"127.0.0.1:3000\""),
        "got: {stdout}"
    );
    // …and the environment override that beat the default.
    assert!(stdout.contains("workers = 3"), "got: {stdout}");
}

#[test]
fn env_files_feed_overrides_and_the_process_environment_wins() {
    require_runnable_binary!();
    let dir = scaffold("env-file", true);
    // `.env` next to nitr.toml loads implicitly; NITR_* values it carries
    // become overrides exactly as if they came from the environment.
    std::fs::write(dir.join(".env"), "NITR_WORKERS=7\nNITR_TESTING_DIR=spec\n")
        .expect("write .env");
    let out = nitr()
        .current_dir(&dir)
        .args(["check", "--print-config"])
        .output()
        .expect("run check");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("workers = 7"), "got: {stdout}");
    assert!(stdout.contains("dir = \"spec\""), "got: {stdout}");

    // The real process environment beats the file.
    let out = nitr()
        .current_dir(&dir)
        .env("NITR_WORKERS", "2")
        .args(["check", "--print-config"])
        .output()
        .expect("run check");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("workers = 2"), "got: {stdout}");

    // An explicitly configured env file must exist.
    let toml = dir.join("nitr.toml");
    let mut cfg = std::fs::read_to_string(&toml).expect("read nitr.toml");
    cfg.push_str("\n[env]\nfile = \"missing.env\"\n");
    std::fs::write(&toml, cfg).expect("write nitr.toml");
    let out = nitr()
        .current_dir(&dir)
        .args(["check"])
        .output()
        .expect("run check");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("missing.env"), "got: {stderr}");
}

#[test]
fn renamed_env_variables_fail_with_the_new_name() {
    require_runnable_binary!();
    let dir = scaffold("env-rename", true);
    for (stale, replacement) in [
        ("NITR_DATABASE", "NITR_DATABASE_PATH"),
        ("NITR_TEMPLATES_DIR", "NITR_TEMPLATING_DIR"),
    ] {
        let out = nitr()
            .current_dir(&dir)
            .env(stale, "somewhere")
            .args(["check"])
            .output()
            .expect("run check");
        assert!(
            !out.status.success(),
            "{stale} must refuse to start rather than be ignored"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(replacement), "got: {stderr}");
    }
}

/// The sectioned override follows the `NITR_<SECTION>_<OPTION>` scheme and
/// lands in `[templating] dir`.
#[test]
fn the_templating_dir_can_be_overridden_from_the_environment() {
    require_runnable_binary!();
    let dir = scaffold("env-templating", true);
    // The path must exist: a missing one is a startup error by design.
    std::fs::create_dir_all(dir.join("tpl")).expect("mkdir tpl");
    let out = nitr()
        .current_dir(&dir)
        .env("NITR_TEMPLATING_DIR", "tpl")
        .args(["check", "--print-config"])
        .output()
        .expect("run check");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[templating]"), "got: {stdout}");
    assert!(stdout.contains("dir = \"tpl\""), "got: {stdout}");
}

// The full scaffold uses the database and templates; a build without
// those features cannot run it.
#[cfg(all(feature = "db", feature = "template"))]
#[test]
fn build_produces_a_self_contained_artifact() {
    require_runnable_binary!();
    // The full scaffold: config script, routes/, templates, migrations —
    // the richest thing a bundle must carry.
    let dir = scaffold("build", false);
    let artifact = dir.join("myapp");
    let out = nitr()
        .current_dir(&dir)
        .args(["build", "--output"])
        .arg(&artifact)
        .output()
        .expect("run build");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Bigger than the plain binary: the application rides along.
    let base = std::fs::metadata(env!("CARGO_BIN_EXE_nitr"))
        .expect("meta")
        .len();
    let bundled = std::fs::metadata(&artifact).expect("meta").len();
    assert!(bundled > base, "artifact {bundled} <= binary {base}");

    // The artifact validates its own embedded application from an empty
    // working directory — no dependency on the build layout. Mutable
    // state stays external: the database directory and schema are the
    // deployment's to provide, via the artifact's own `migrate`.
    let empty = dir.join("elsewhere");
    std::fs::create_dir_all(empty.join("data")).expect("mkdir");
    let out = Command::new(&artifact)
        .current_dir(&empty)
        .arg("migrate")
        .output()
        .expect("run the artifact's migrate");
    assert!(
        out.status.success(),
        "bundled migrate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = Command::new(&artifact)
        .current_dir(&empty)
        .arg("check")
        .output()
        .expect("run the artifact");
    assert!(
        out.status.success(),
        "bundled check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok:"), "got: {stdout}");

    // Building from a bundle is refused: bundles are built from the plain
    // binary, not stacked.
    let out = Command::new(&artifact)
        .current_dir(&dir)
        .args(["build", "--output", "twice"])
        .output()
        .expect("run build on bundle");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("already carries a bundle"),
        "got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `nitr run` writes the configured pidfile, `nitr reload` signals through
/// it, and a graceful exit removes it.
/// The full scaffold's own test suite passes under the framework, and
/// `--filter` narrows the run.
#[cfg(all(feature = "db", feature = "template"))]
#[test]
fn scaffolded_app_tests_pass_and_filter() {
    require_runnable_binary!();
    let dir = scaffold("test-framework", false);
    let migrate = nitr()
        .current_dir(&dir)
        .arg("migrate")
        .output()
        .expect("run migrate");
    assert!(
        migrate.status.success(),
        "migrate failed: {}",
        String::from_utf8_lossy(&migrate.stderr)
    );

    let out = nitr()
        .current_dir(&dir)
        .arg("test")
        .output()
        .expect("run tests");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "tests failed: {stdout}");
    assert!(
        stdout.contains("ok   notes API > creates a note"),
        "got: {stdout}"
    );
    assert!(stdout.contains("3 passed, 0 failed"), "got: {stdout}");

    let out = nitr()
        .current_dir(&dir)
        .args(["test", "--filter", "rejects"])
        .output()
        .expect("run filtered");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "filtered run failed: {stdout}");
    assert!(
        stdout.contains("1 passed, 0 failed, 2 filtered out"),
        "got: {stdout}"
    );

    // A failing assertion names the expectation and the file:line.
    std::fs::write(
        dir.join("tests/failing_test.lua"),
        "local t = nitr.test\nt.it(\"fails loudly\", function()\n    t.expect(1 + 1).to_equal(3)\nend)\n",
    )
    .expect("write failing test");
    let out = nitr()
        .current_dir(&dir)
        .args(["test", "--filter", "loudly"])
        .output()
        .expect("run failing");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success());
    assert!(stdout.contains("FAIL fails loudly"), "got: {stdout}");
    assert!(stdout.contains("expected 2 to equal 3"), "got: {stdout}");
    assert!(stdout.contains("failing_test.lua:3"), "got: {stdout}");
}

#[cfg(unix)]
#[test]
fn pidfile_reload_and_cleanup() {
    require_runnable_binary!();
    let dir = scaffold("pidfile", true);
    // Port 0 so parallel test runs cannot collide; the pidfile is the
    // contract under test, not the address.
    std::fs::write(
        dir.join("nitr.toml"),
        "listen = \"127.0.0.1:0\"\nhandler_script = \"app.lua\"\npidfile = \"nitr.pid\"\n\
         [shutdown]\ngrace = 5\n",
    )
    .expect("write config");

    // tracing's fmt subscriber writes to stdout: that is where the
    // "listening" line will appear.
    let log = std::fs::File::create(dir.join("server.log")).expect("log file");
    let mut child = nitr()
        .current_dir(&dir)
        .arg("run")
        .stdout(log)
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn nitr run");

    // Wait for the "listening" line: it is logged after the SIGHUP handler
    // is installed, so a reload sent from here on cannot hit the default
    // disposition (which would terminate the process).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let logged = std::fs::read_to_string(dir.join("server.log")).unwrap_or_default();
        if logged.contains("listening on") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "server never started listening; log so far: {logged}"
        );
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "server exited early"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let pidfile = dir.join("nitr.pid");
    assert!(
        pidfile.is_file(),
        "pidfile must exist once the server is up"
    );
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .expect("read pidfile")
        .trim()
        .parse()
        .expect("pid");
    assert_eq!(pid, child.id());

    // `nitr reload` finds the server through the pidfile.
    let out = nitr()
        .current_dir(&dir)
        .arg("reload")
        .output()
        .expect("run reload");
    assert!(
        out.status.success(),
        "reload failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Exit code 0 only proves a signal was sent somewhere; the contract is
    // that the *server* received it and swapped its pool. The server logs
    // both ends of the swap — wait for the completion line.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let logged = std::fs::read_to_string(dir.join("server.log")).unwrap_or_default();
        if logged.contains("reload complete: new runtime pool is live") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the server never logged the pool swap; log so far: {logged}"
        );
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "SIGHUP must reload the server, not kill it"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    // A graceful stop (SIGTERM) removes the pidfile on the way out.
    signal(pid, "-TERM");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while child.try_wait().expect("try_wait").is_none() {
        assert!(std::time::Instant::now() < deadline, "server never exited");
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(!pidfile.exists(), "a clean exit must remove the pidfile");
}

#[cfg(unix)]
fn signal(pid: u32, sig: &str) {
    let status = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(status.success(), "kill {sig} {pid} failed");
}
