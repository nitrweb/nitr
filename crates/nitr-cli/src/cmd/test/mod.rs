// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr test`: run the application's Lua tests against an in-process
//! server.
//!
//! Every test file gets a fresh sandboxed state with the configured
//! builtins, the framework (`test_framework.lua`) and the Rust half of
//! `nitr.test` ([`lua`]). The file's chunk only *registers* tests; the
//! runner then calls each one with its own budgeted call, so every test
//! has its own instruction budget and timeout, a duration, a fresh set of
//! doubles and clock, and its own captured logs. Files and tests run
//! strictly one after another — the clock and the log capture rely on it.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context as _, bail};
use nitr::stdlib::testing::Doubles;
use nitr::{BuiltinsEnv, Config, Runtime, Server};

pub(crate) mod capture;
mod lua;
mod report;

use report::{FileReport, Report, Status, TestReport};

/// The Lua test framework (`t.describe`/`t.it`/`t.expect`/hooks/client),
/// loaded into each test state before its file runs.
const TEST_FRAMEWORK: &str = include_str!("../../test_framework.lua");

/// Output formats for the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Reporter {
    /// Human-readable lines, printed as each test finishes.
    Pretty,
    /// One JSON document.
    Json,
    /// JUnit XML, which CI systems annotate from.
    Junit,
}

/// The `nitr test` flags.
#[derive(Debug, Clone)]
pub(crate) struct TestArgs {
    pub(crate) filter: Option<String>,
    pub(crate) bail: bool,
    pub(crate) list: bool,
    pub(crate) watch: bool,
    pub(crate) reporter: Reporter,
    pub(crate) output: Option<PathBuf>,
    pub(crate) nocapture: bool,
}

impl TestArgs {
    /// Whether the pretty lines go to stdout: always with the pretty
    /// reporter, and alongside a machine report written to a file.
    fn pretty(&self) -> bool {
        self.reporter == Reporter::Pretty || self.output.is_some()
    }

    /// Refuses flag combinations that would silently do nothing, and
    /// makes the report's directory before the suite runs rather than
    /// failing after it.
    fn validate(&self) -> anyhow::Result<()> {
        let Some(output) = &self.output else {
            return Ok(());
        };
        if self.reporter == Reporter::Pretty {
            bail!(
                "--output {} needs --reporter json or --reporter junit (the pretty lines \
                 always go to standard output)",
                output.display()
            );
        }
        if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("cannot create the report directory {}", parent.display())
            })?;
        }
        Ok(())
    }
}

/// A per-run test database, removed (with its WAL sidecars) when the run
/// ends.
struct ScratchDb(PathBuf);

impl Drop for ScratchDb {
    fn drop(&mut self) {
        remove_database_files(&self.0);
    }
}

/// Removes a SQLite file and its WAL sidecars; a missing file is fine.
fn remove_database_files(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}

/// Prints to stdout unless the run's stdout is a machine report.
struct Out {
    enabled: bool,
}

impl Out {
    fn print(&self, text: &str) {
        if self.enabled {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(text.as_bytes());
            let _ = stdout.flush();
        }
    }
}

/// Everything shared by the files of one run.
struct Run {
    cfg: Arc<Config>,
    builtins: nitr::Builtins,
    env: BuiltinsEnv,
    opts: nitr::RuntimeOpts,
    doubles: Arc<Doubles>,
    cache: nitr::stdlib::Cache,
    client: nitr::testing::TestClient,
    cfg_snapshot: Option<serde_json::Value>,
    tests_dir: PathBuf,
    #[cfg(feature = "db")]
    db: Option<Arc<lua::DbFixture>>,
    /// Whether per-test logs are being captured (`[testing] capture`).
    capture: bool,
}

/// Runs the whole suite once and returns its report; never exits the
/// process (`--watch` calls it in a loop).
pub(crate) async fn run(mut cfg: Config, args: &TestArgs) -> anyhow::Result<Report> {
    let started = Instant::now();
    args.validate()?;
    cfg.validate_testing()?;
    let tests_dir = cfg.testing.dir.clone();

    // Never the configured database: see `TestingConfig::database`. The
    // private file gets the migrations the live one would have, so a test
    // sees the schema and not an empty file.
    let _scratch = match &mut cfg.database {
        Some(db) => {
            let (path, scratch) = match &cfg.testing.database {
                // A named file is recreated at the start of every run, so
                // the migrations, the seed and the snapshot always start
                // from nothing, and kept afterwards for inspection.
                // (`validate_testing` has refused `[database] path`.)
                Some(path) => {
                    remove_database_files(path);
                    (path.clone(), None)
                }
                None => {
                    let path = std::env::temp_dir().join(format!(
                        "nitr-test-{}-{:x}.db",
                        std::process::id(),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_nanos())
                    ));
                    (path.clone(), Some(ScratchDb(path)))
                }
            };
            db.path = path;
            scratch
        }
        None => {
            if cfg.testing.seed.is_some() {
                bail!("[testing] seed is set but no [database] is configured to seed");
            }
            None
        }
    };
    #[cfg(feature = "db")]
    migrate_database(&cfg).await?;

    let mut files: Vec<PathBuf> = std::fs::read_dir(&tests_dir)
        .with_context(|| format!("cannot read the tests directory {}", tests_dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|ext| ext == "lua"))
        .collect();
    files.sort();
    if files.is_empty() {
        bail!("no *.lua test files in {}", tests_dir.display());
    }

    let builtins = cfg.builtins()?;
    let doubles = Doubles::new();
    // One cache for the server's states and the test states: what a
    // handler caches is observable from a test. Emptied between files.
    let cache = nitr::stdlib::Cache::new(cfg.cache_options());
    let env = BuiltinsEnv {
        templates_dir: cfg.templating.dir.clone(),
        database: cfg.database.as_ref().map(|db| db.path.clone()),
        sqlite: cfg
            .database
            .as_ref()
            .map(|db| db.pragmas())
            .unwrap_or_default(),
        fetch: cfg.fetch.options(),
        env: cfg.env_options(),
        cache: Some(cache.clone()),
        // Resolved the way the server resolves it, not left at the
        // default: `nitr test` boots a real `Server` from this same `cfg`
        // below, so a cookie assertion written in a test file must
        // exercise the policy production will run.
        cookie_secure: cfg.cookies.secure.resolve(cfg.tls.enabled),
    };
    let opts = cfg.runtime_opts()?;

    // The doubles reach every pooled state through `setup`, the one hook
    // that also runs on a poison rebuild and a reload. A server built
    // anywhere else never carries them.
    let server = {
        let doubles = doubles.clone();
        Server::builder()
            .config(cfg.clone())
            .cache(cache.clone())
            .setup(move |lua| {
                lua.set_app_data(doubles.clone());
                Ok(())
            })
            .build()
            .await?
    };
    // After the build: the configuration script may create schema or
    // rows (`db:execute` at startup), and the snapshot must hold the
    // database as the application boots into it.
    #[cfg(feature = "db")]
    let db_fixture = seed_and_snapshot(&cfg).await?;
    let run = Run {
        builtins,
        env,
        opts,
        doubles,
        cache,
        client: server.test_client(),
        cfg_snapshot: server.cfg_snapshot().cloned(),
        tests_dir,
        #[cfg(feature = "db")]
        db: db_fixture,
        capture: cfg.testing.capture,
        cfg: Arc::new(cfg),
    };

    let out = Out {
        // A listing is for reading, whatever the reporter.
        enabled: args.pretty() || args.list,
    };
    // What the build logged went to the capture buffer, not the console:
    // a warning there (a builtin skipped for a missing setting) is still
    // the operator's to read.
    if run.capture && !args.nocapture {
        let (setup, _) = capture::take();
        for entry in setup.iter().filter(|e| e.level <= tracing::Level::WARN) {
            out.print(&format!("{}\n", entry.line()));
        }
    }
    let mut report = Report::default();
    for (index, file) in files.iter().enumerate() {
        let file_report = run_file(&run, file, args, &out).await?;
        let bailed = args.bail
            && !args.list
            && file_report
                .report
                .tests
                .iter()
                .any(|t| t.status == Status::Failed);
        let not_run = file_report.not_run;
        report.files.push(file_report.report);
        if bailed {
            report.bailed = Some(report::Bail {
                tests: not_run,
                files: files.len() - index - 1,
            });
            break;
        }
    }
    report.duration = started.elapsed();
    if !args.list {
        out.print(&format!("{}\n", report::verdict(&report)));
        emit_machine_report(&report, args)?;
    }
    Ok(report)
}

/// Gives the private test database the migrations the live one would
/// have, so a test sees the schema and not an empty file — and so the
/// server's pending-migration check passes.
#[cfg(feature = "db")]
async fn migrate_database(cfg: &Config) -> anyhow::Result<()> {
    let Some(db) = &cfg.database else {
        return Ok(());
    };
    let Some(dir) = db.migrations().filter(|dir| dir.is_dir()) else {
        return Ok(());
    };
    let path = db.path.clone();
    let pragmas = db.pragmas();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let conn = nitr::stdlib::db_open(&path, &pragmas)?;
        nitr::stdlib::migrate::run(&conn, &dir)
            .with_context(|| format!("cannot migrate the test database {}", path.display()))?;
        Ok(())
    })
    .await
    .context("the test database migration task failed")?
}

/// Applies `[testing] seed` and takes the snapshot `t.db.reset()`
/// restores.
#[cfg(feature = "db")]
async fn seed_and_snapshot(cfg: &Config) -> anyhow::Result<Option<Arc<lua::DbFixture>>> {
    let Some(db) = &cfg.database else {
        return Ok(None);
    };
    let path = db.path.clone();
    let pragmas = db.pragmas();
    let seed = cfg.testing.seed.clone();
    let fixture = tokio::task::spawn_blocking(move || -> anyhow::Result<lua::DbFixture> {
        if let Some(seed) = seed {
            let sql = std::fs::read_to_string(&seed)
                .with_context(|| format!("cannot read [testing] seed {}", seed.display()))?;
            nitr::stdlib::db_fixtures::seed_sql(&path, &pragmas, &sql)
                .with_context(|| format!("[testing] seed {} failed", seed.display()))?;
        }
        let snapshot = nitr::stdlib::db_fixtures::snapshot(&path, &pragmas)?;
        Ok(lua::DbFixture {
            path,
            pragmas,
            snapshot: Arc::new(snapshot),
        })
    })
    .await
    .context("the test database setup task failed")??;
    Ok(Some(Arc::new(fixture)))
}

/// Writes the JSON or JUnit document: to `--output`, or to stdout in
/// place of the pretty lines.
fn emit_machine_report(report: &Report, args: &TestArgs) -> anyhow::Result<()> {
    let document = match args.reporter {
        Reporter::Pretty => return Ok(()),
        Reporter::Json => report::json(report),
        Reporter::Junit => report::junit(report),
    };
    match &args.output {
        Some(path) => std::fs::write(path, document)
            .with_context(|| format!("cannot write the test report to {}", path.display())),
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(document.as_bytes())?;
            Ok(stdout.flush()?)
        }
    }
}

/// A file's report plus how many of its tests never ran because `--bail`
/// stopped the run.
struct FileOutcome {
    report: FileReport,
    not_run: usize,
}

/// `RuntimeOpts` is not `Clone`; rebuild an equivalent one, with the tests
/// directory as a second `require` root — for test states only.
fn test_runtime_opts(opts: &nitr::RuntimeOpts, tests_dir: &Path) -> nitr::RuntimeOpts {
    nitr::RuntimeOpts {
        libs: opts.libs,
        memory_limit: opts.memory_limit,
        dev_mode: opts.dev_mode,
        exec_timeout: opts.exec_timeout,
        package_dir: opts.package_dir.clone(),
        extra_package_dirs: vec![tests_dir.to_path_buf()],
    }
}

/// A failed call's message for the report: the budget in words, anything
/// else as the classified error says it.
fn call_error(err: &nitr::Error, opts: &nitr::RuntimeOpts) -> String {
    let info = nitr::ErrorInfo::from_error(err);
    if info.kind == "timeout" {
        return match opts.exec_timeout {
            Some(budget) => format!(
                "the test exceeded its time budget ([lua] exec_timeout_ms = {} ms)",
                budget.as_millis()
            ),
            None => "the test exceeded its time budget".into(),
        };
    }
    match (&info.source, info.line) {
        (Some(source), Some(line)) if !info.message.contains(&format!(":{line}:")) => {
            format!("{source}:{line}: {}", info.message)
        }
        _ => info.message,
    }
}

/// A test file's path as the runner shows it: `/`-separated on every
/// platform, so a `file:line` site, an error message and a report read the
/// same on Windows — where Lua's `%q` would also double every `\`. Only
/// Windows is rewritten: elsewhere a `\` is a legal file name byte.
fn portable_path(path: &Path) -> String {
    let shown = path.display().to_string();
    if cfg!(windows) {
        shown.replace('\\', "/")
    } else {
        shown
    }
}

async fn run_file(
    run: &Run,
    file: &Path,
    args: &TestArgs,
    out: &Out,
) -> anyhow::Result<FileOutcome> {
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file.display().to_string());
    let mut report = FileReport {
        name: name.clone(),
        path: portable_path(file),
        tests: Vec::new(),
        focused: false,
    };
    let isolate = Arc::new(AtomicBool::new(false));

    // A fresh state per file: tests are isolated from each other but
    // share the server (and its database) like real requests do.
    let mut rt = Runtime::new_with(test_runtime_opts(&run.opts, &run.tests_dir))?;
    nitr::stdlib::register_builtins(rt.lua(), run.builtins, &run.env)?;
    rt.lua().set_app_data(run.doubles.clone());
    // The handler's `nitr.cfg`, so a test reads the secret the handler
    // reads instead of duplicating it.
    if let Some(snapshot) = &run.cfg_snapshot {
        rt.set_cfg_snapshot(snapshot)?;
        if let Some(cfg) = rt.cfg() {
            nitr::nitr_table(rt.lua())?.set("cfg", cfg.clone())?;
        }
    }
    lua::register(
        rt.lua(),
        lua::Context {
            client: run.client.clone(),
            cfg: run.cfg.clone(),
            doubles: run.doubles.clone(),
            #[cfg(feature = "db")]
            tests_dir: run.tests_dir.clone(),
            default_timeout: run.opts.exec_timeout,
            #[cfg(feature = "db")]
            db: run.db.clone(),
            #[cfg(feature = "db")]
            isolate: isolate.clone(),
        },
    )?;
    let test_table: mlua::Table = nitr::nitr_table(rt.lua())?.get("test")?;
    test_table.set("_filter", args.filter.as_deref().unwrap_or_default())?;
    test_table.set("_file", name.as_str())?;
    rt.lua()
        .load(TEST_FRAMEWORK)
        .set_name(lua::FRAMEWORK_CHUNK)
        .exec()
        .context("cannot load the test framework")?;

    let source =
        std::fs::read(file).with_context(|| format!("cannot read test file {}", file.display()))?;
    // Named after the real file, so assertion failures point at it. Text
    // only, like every chunk the runtime compiles: a test file is no place
    // for unverified bytecode either.
    let chunk = match rt
        .lua()
        .load(source)
        .set_name(format!("@{}", portable_path(file)))
        .set_mode(mlua::chunk::ChunkMode::Text)
        .into_function()
    {
        Ok(chunk) => chunk,
        Err(err) => {
            let mut test = TestReport::new(name.clone(), Status::Failed);
            test.error = Some(err.to_string());
            out.print(&format!(
                "{} {name}\n     {err}\n",
                nitr::diag::console_fail("FAIL")
            ));
            report.tests.push(test);
            return Ok(FileOutcome { report, not_run: 0 });
        }
    };

    let fresh = |rt: &Runtime| {
        run.doubles.reset();
        nitr::stdlib::clock::reset();
        nitr::stdlib::reset_outbound_budget(rt.lua());
        capture::clear();
    };
    fresh(&rt);
    let file_err = rt.call_function::<mlua::Value>(chunk, ()).await.err();
    // What the file's top level logged: the first test's start clears the
    // buffer, and a top-level failure must still show it.
    let (top_logs, top_dropped) = capture::take();
    let show_logs = run.capture && !args.nocapture;
    // The plan runs in a state the top level may have left unusable (a
    // memory limit hit there leaves the hog reachable): that is this
    // file's failure, never the run's.
    let planned = if rt.is_poisoned() {
        Err(mlua::Error::RuntimeError(
            "the file's top level left the test state unusable (memory limit or panic)".into(),
        ))
    } else {
        test_table
            .get::<mlua::Function>("_plan")
            .and_then(|plan| plan.call::<mlua::Table>(()))
            .and_then(|plan| Ok((plan, test_table.get::<bool>("_focused")?)))
    };
    let (plan, focused) = match planned {
        Ok(planned) => planned,
        Err(plan_err) => {
            let mut test = TestReport::new(format!("{name} (outside any test)"), Status::Failed);
            test.error = Some(match &file_err {
                Some(err) => call_error(err, &run.opts),
                None => plan_err.to_string(),
            });
            test.logs = top_logs;
            test.logs_dropped = top_dropped;
            out.print(&format!(
                "{name}\n{}",
                report::pretty_test(&test, show_logs)
            ));
            report.tests.push(test);
            finish_file(run);
            return Ok(FileOutcome { report, not_run: 0 });
        }
    };
    // `--list` runs nothing, so a `t.only` cannot fail it (the listing
    // marks it instead).
    report.focused = !args.list && focused;

    if plan.raw_len() == 0 {
        // The pre-framework style: a bare script of asserts. It passes by
        // running to completion.
        let mut test = TestReport::new(name.clone(), Status::Passed);
        test.logs = top_logs;
        test.logs_dropped = top_dropped;
        match file_err {
            None => out.print(&format!("{} {name}\n", nitr::diag::console_ok("PASS"))),
            Some(err) => {
                let message = call_error(&err, &run.opts);
                out.print(&format!(
                    "{} {name}\n     {message}\n",
                    nitr::diag::console_fail("FAIL")
                ));
                test.status = Status::Failed;
                test.error = Some(message);
                if show_logs {
                    out.print(&report::logs_block(&test));
                }
            }
        }
        report.tests.push(test);
        finish_file(run);
        return Ok(FileOutcome { report, not_run: 0 });
    }

    if args.list {
        out.print(&format!("{name}\n"));
        for entry in plan.sequence_values::<mlua::Table>() {
            let entry = entry?;
            let test_name: String = entry.get("name")?;
            let site: Option<String> = entry.get("site")?;
            let status: String = entry.get("status")?;
            let marker = match status.as_str() {
                "todo" => "  [todo]".to_string(),
                "skipped" => format!(
                    "  [skip: {}]",
                    entry.get::<Option<String>>("reason")?.unwrap_or_default()
                ),
                "filtered" => "  [filtered out]".to_string(),
                _ if entry.get::<bool>("only")? => "  [only]".to_string(),
                _ => String::new(),
            };
            out.print(&format!(
                "  {test_name}  {}{marker}\n",
                site.as_deref().unwrap_or("?")
            ));
            report
                .tests
                .push(TestReport::new(test_name, Status::Filtered));
        }
        finish_file(run);
        return Ok(FileOutcome { report, not_run: 0 });
    }

    out.print(&format!("{name}\n"));
    let run_fn: mlua::Function = test_table.get("_run")?;
    let slow_ms = run.cfg.testing.slow_ms;
    let entries: Vec<mlua::Table> = plan
        .sequence_values::<mlua::Table>()
        .collect::<mlua::Result<_>>()?;
    let mut not_run = 0;
    let mut stopped = false;
    for (i, entry) in entries.iter().enumerate() {
        let test_name: String = entry.get("name")?;
        let status: String = entry.get("status")?;
        let mut test = TestReport::new(test_name, Status::Passed);
        test.site = entry.get("site")?;
        test.reason = entry.get("reason")?;
        match status.as_str() {
            "filtered" => test.status = Status::Filtered,
            "skipped" => test.status = Status::Skipped,
            "todo" => test.status = Status::Todo,
            "failed" => {
                test.status = Status::Failed;
                test.error = entry.get("error")?;
            }
            _ if stopped => {
                // `--bail` stopped the run: the rest of this file is
                // counted, not run.
                not_run += 1;
                continue;
            }
            _ if rt.is_poisoned() => {
                test.status = Status::Failed;
                test.error = Some(
                    "not run: an earlier test in this file left the test state unusable \
                     (memory limit or panic)"
                        .into(),
                );
            }
            _ => {
                fresh(&rt);
                let started = Instant::now();
                let outcome = rt
                    .call_function::<(bool, Option<String>)>(run_fn.clone(), i + 1)
                    .await;
                test.duration = started.elapsed();
                let (logs, dropped) = capture::take();
                test.logs = logs;
                test.logs_dropped = dropped;
                test.slow = test.duration.as_millis() > u128::from(slow_ms);
                match outcome {
                    // A passing test's entries are printed nowhere unless
                    // a JSON or JUnit report carries them; kept anyway,
                    // a long suite would hold every test's log to the end.
                    Ok((true, _)) if args.reporter == Reporter::Pretty => {
                        test.logs = Vec::new();
                        test.logs_dropped = 0;
                    }
                    Ok((true, _)) => {}
                    Ok((false, err)) => {
                        test.status = Status::Failed;
                        test.error = Some(err.unwrap_or_else(|| "failed".into()));
                    }
                    Err(err) => {
                        test.status = Status::Failed;
                        test.error = Some(call_error(&err, &run.opts));
                    }
                }
                if isolate.load(Ordering::Relaxed)
                    && let Err(err) = restore_database(run).await
                {
                    test.status = Status::Failed;
                    let previous = test
                        .error
                        .take()
                        .map(|e| format!("{e}\n"))
                        .unwrap_or_default();
                    test.error = Some(format!("{previous}t.db.isolate: {err}"));
                }
                nitr::stdlib::clock::reset();
                // Entries cached while the clock was moved carry its
                // expiry; a later test must not inherit a TTL from a day
                // that never came.
                if nitr::stdlib::clock::take_touched()
                    && let Err(err) = run.cache.clear()
                {
                    tracing::warn!("cannot clear the test cache: {err}");
                }
            }
        }
        out.print(&report::pretty_test(&test, show_logs));
        if test.status == Status::Failed && args.bail {
            stopped = true;
        }
        report.tests.push(test);
    }

    // A file that also failed outside any `it` (e.g. at its top level) is
    // its own failure, on top of whatever tests recorded.
    if let Some(err) = file_err {
        let mut test = TestReport::new(format!("{name} (outside any test)"), Status::Failed);
        test.error = Some(call_error(&err, &run.opts));
        test.logs = top_logs;
        test.logs_dropped = top_dropped;
        out.print(&report::pretty_test(&test, show_logs));
        report.tests.push(test);
    }
    finish_file(run);
    Ok(FileOutcome { report, not_run })
}

/// What no file may leave behind for the next: the cache, the clock and
/// the doubles.
fn finish_file(run: &Run) {
    if let Err(err) = run.cache.clear() {
        tracing::warn!("cannot clear the test cache between files: {err}");
    }
    nitr::stdlib::clock::reset();
    run.doubles.reset();
}

#[cfg(feature = "db")]
async fn restore_database(run: &Run) -> anyhow::Result<()> {
    let Some(db) = run.db.clone() else {
        return Ok(());
    };
    tokio::task::spawn_blocking(move || {
        nitr::stdlib::db_fixtures::restore(&db.snapshot, &db.path, &db.pragmas)
    })
    .await
    .context("the database restore task failed")??;
    Ok(())
}

#[cfg(not(feature = "db"))]
async fn restore_database(_run: &Run) -> anyhow::Result<()> {
    Ok(())
}

/// `nitr test --watch`: runs the suite, then again on every saved Lua
/// source or template (the handler's tree, the configuration script, the
/// templates, the tests directory), until Ctrl-C. Each run builds a
/// fresh server — no socket is bound, so nothing lingers — and a fresh
/// scratch database.
pub(crate) async fn watch(cfg: Config, args: &TestArgs) -> anyhow::Result<()> {
    if let Some(output) = &args.output {
        refuse_watched_output(&cfg, output)?;
    }
    args.validate()?;
    let (changed_tx, mut changed) = tokio::sync::mpsc::channel(1);
    let Some(_watch) =
        nitr::testing::watch_tests(&cfg, std::slice::from_ref(&cfg.testing.dir), changed_tx)
    else {
        bail!("--watch: there is nothing to watch, or the platform file watcher is unavailable");
    };
    let run_once = || {
        let cfg = cfg.clone();
        let args = args.clone();
        async move {
            // On a task of its own: a run is CPU-bound Lua that may finish
            // inside a single poll, and raced in place it would keep the
            // session from seeing a Ctrl-C until it was done.
            match tokio::spawn(async move { run(cfg, &args).await }).await {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => eprintln!("{err:#}"),
                Err(err) => eprintln!("the test run did not complete: {err}"),
            }
        }
    };
    watch_loop(run_once, &mut changed, tokio::signal::ctrl_c()).await
}

/// The `--watch` session: a run, a wait for the next change, again —
/// until `stop` (Ctrl-C) fires.
///
/// `stop` is one future for the whole session, polled during the runs as
/// well as the waits. Tokio installs its SIGINT handler on the first poll
/// of `ctrl_c()` and keeps it for the life of the process, so a listener
/// created fresh for each wait left every Ctrl-C pressed mid-run with no
/// one to hear it. For the race to mean anything the run must yield,
/// which is why `watch` hands each run to its own task. A closed `changed` channel means the watcher thread
/// gave up (its reason is in the log); returning `Ok` then would read as
/// a clean stop, so it is an error.
async fn watch_loop<R, Fut, S>(
    mut run_once: R,
    changed: &mut tokio::sync::mpsc::Receiver<()>,
    stop: S,
) -> anyhow::Result<()>
where
    R: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
    S: std::future::Future,
{
    tokio::pin!(stop);
    loop {
        tokio::select! {
            () = run_once() => {}
            _ = &mut stop => return Ok(()),
        }
        println!("\nwatching for changes (Ctrl-C to stop)");
        tokio::select! {
            got = changed.recv() => {
                if got.is_none() {
                    bail!(
                        "--watch: the file watcher stopped; run with --nocapture to see why"
                    );
                }
                println!();
            }
            _ = &mut stop => return Ok(()),
        }
    }
}

/// `--watch` with a report file the watcher would react to (a `.lua`
/// file, or one inside the templates directory) would re-run on its own
/// output forever; such a path is refused. Anything else — a JUnit file
/// next to the application — is fine, because the watcher only reacts to
/// what a run reads.
fn refuse_watched_output(cfg: &Config, output: &Path) -> anyhow::Result<()> {
    let in_templates = cfg.templating.dir.as_ref().is_some_and(|dir| {
        let parent = output.parent().filter(|p| !p.as_os_str().is_empty());
        match (
            parent.map_or_else(|| Path::new(".").canonicalize(), Path::canonicalize),
            dir.canonicalize(),
        ) {
            (Ok(parent), Ok(dir)) => parent.starts_with(dir),
            _ => false,
        }
    });
    if output.extension().is_some_and(|ext| ext == "lua") || in_templates {
        bail!(
            "--output {} is a file `--watch` reacts to (a .lua file, or inside [templating] \
             dir): the run would restart on its own report. Write it elsewhere.",
            output.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Adversarial row D2: `--watch` refuses a report path it would react
    /// to, and accepts one it would not — including one inside the
    /// application's directory, which is where a scaffold puts everything.
    #[test]
    fn watch_refuses_only_a_report_it_would_react_to() {
        let dir = std::env::temp_dir().join(format!("nitr-watch-out-{}", std::process::id()));
        let templates = dir.join("templates");
        std::fs::create_dir_all(&templates).expect("mkdir");
        let mut cfg = Config {
            handler_script: dir.join("app.lua"),
            ..Default::default()
        };
        cfg.templating.dir = Some(templates.clone());
        let err = refuse_watched_output(&cfg, &dir.join("report.lua")).expect_err("a .lua file");
        assert!(
            err.to_string().contains("restart on its own report"),
            "{err}"
        );
        refuse_watched_output(&cfg, &templates.join("report.xml")).expect_err("in templates");
        refuse_watched_output(&cfg, &dir.join("report.xml")).expect("beside the app");
        refuse_watched_output(&cfg, Path::new("junit.xml")).expect("a bare file name");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A watcher thread that gives up closes its channel: the session
    /// ends with an error naming it, never with a clean exit 0.
    #[tokio::test]
    async fn watch_fails_when_its_watcher_dies() {
        let (tx, mut changed) = tokio::sync::mpsc::channel(1);
        drop(tx);
        let mut runs = 0;
        let run_once = || {
            runs += 1;
            std::future::ready(())
        };
        let err = watch_loop(run_once, &mut changed, std::future::pending::<()>())
            .await
            .expect_err("a dead watcher is an error");
        assert!(
            err.to_string().contains("the file watcher stopped"),
            "{err}"
        );
        assert_eq!(runs, 1);
    }

    /// A stop raised while a run is in progress ends the session there:
    /// the one stop future is raced against the runs, not only the waits.
    /// Without that this hangs (bounded by the timeout).
    #[tokio::test]
    async fn watch_stops_in_the_middle_of_a_run() {
        let (tx, mut changed) = tokio::sync::mpsc::channel(1);
        tx.send(()).await.expect("queue a change");
        let (stop_tx, stop) = tokio::sync::oneshot::channel::<()>();
        let mut stop_tx = Some(stop_tx);
        let mut runs = 0;
        let run_once = || {
            runs += 1;
            // The second run raises the stop, then never finishes.
            let second = runs == 2;
            if second && let Some(stop_tx) = stop_tx.take() {
                let _ = stop_tx.send(());
            }
            async move {
                if second {
                    std::future::pending::<()>().await;
                }
            }
        };
        let session = watch_loop(run_once, &mut changed, stop);
        tokio::time::timeout(std::time::Duration::from_secs(5), session)
            .await
            .expect("the stop ends the run in progress")
            .expect("a stop is a clean exit");
        assert_eq!(runs, 2);
        drop(tx);
    }

    /// A test file's shown path is `/`-separated whatever the platform
    /// joined it with; a `\` inside a Unix file name is left alone.
    #[test]
    fn a_test_path_shows_with_forward_slashes() {
        let joined = Path::new("tests").join("sub").join("a_test.lua");
        assert_eq!(portable_path(&joined), "tests/sub/a_test.lua");
        #[cfg(not(windows))]
        assert_eq!(portable_path(Path::new("tests/a\\b.lua")), "tests/a\\b.lua");
    }
}
