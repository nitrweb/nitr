// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `nitr` binary: serve, develop, check, test, migrate, build, and
//! scaffold Nitr applications.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};

use nitr::{Config, Server};
use nitr_cli::apidef;
mod bundle;
mod cmd;
mod diag;
mod scaffold;

const DEFAULT_CONFIG_FILE: &str = "nitr.toml";

/// The Nitr server: drop a binary and a few Lua files onto a machine and
/// you have a complete small HTTP application.
#[derive(Parser)]
#[command(
    name = "nitr",
    disable_version_flag = true,
    after_help = "Signals:\n  SIGHUP           Zero-downtime reload: rebuilds the Lua runtime pool"
)]
struct Cli {
    /// Print the version and exit.
    #[arg(short = 'v', long = "version", global = true)]
    version: bool,
    /// Path to the TOML config file (default: ./nitr.toml).
    #[arg(short = 'c', long = "config", global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Enable development mode (hot reload).
    #[arg(long, global = true)]
    dev: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the server (the default when no command is given).
    Run,
    /// Start the server in development mode (hot reload).
    Dev,
    /// Load the configuration and scripts, then exit.
    Check {
        /// Print the effective configuration after file, environment, and
        /// flag layering — the answer to "which value actually won?".
        #[arg(long)]
        print_config: bool,
    },
    /// Run the Lua tests against an in-process server.
    Test {
        /// Run only tests whose name (or file name) contains this string.
        #[arg(long, value_name = "SUBSTRING")]
        filter: Option<String>,
    },
    /// Apply pending SQL migrations from migrations/.
    Migrate {
        /// Report what has run and what is pending, applying nothing.
        #[arg(long)]
        status: bool,
    },
    /// Scaffold a new Nitr application.
    Init {
        /// Directory to scaffold into (default: the current directory).
        dir: Option<PathBuf>,
        /// Only the bare minimum: nitr.toml, app.lua, a static page, one
        /// test — instead of the full documented layout.
        #[arg(long)]
        minimal: bool,
    },
    /// Package the application and this binary into one runnable file.
    Build {
        /// Path of the artifact to write.
        #[arg(short, long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Ask a running server (found via its `pidfile`) to reload.
    Reload,
}

fn load_config(cli: &Cli) -> anyhow::Result<Config> {
    // A bundled executable carries its own application; the config file
    // and every path in it come from the extracted archive.
    // Where a relative `env_file` (and the implicit `.env`) resolves: next
    // to the config file. A bundle's config lives in a temp extraction
    // dir, but its env file is external state like the database, so it
    // resolves against the working directory instead.
    let mut env_base = PathBuf::from(".");
    let mut cfg = match bundle::load()? {
        Some(cfg) => cfg,
        None => match &cli.config {
            Some(path) => {
                if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    env_base = parent.to_path_buf();
                }
                Config::from_file(path)?
            }
            None => {
                let default = Path::new(DEFAULT_CONFIG_FILE);
                if default.is_file() {
                    Config::from_file(default)?
                } else {
                    Config::default()
                }
            }
        },
    };
    // The env file loads first so `apply_env` sees its values — while the
    // real process environment still wins (the file never overwrites it).
    cfg.load_env_file(&env_base)?;
    cfg.apply_env()?;
    if cli.dev || matches!(cli.command, Some(Command::Dev)) {
        cfg.dev_mode = true;
    }
    Ok(cfg)
}

/// Installs the tracing subscriber per the `[log]` configuration.
/// `RUST_LOG` wins over the configured level; without either the default
/// is `info` (`debug` in dev mode).
fn init_logging(cfg: Option<&Config>, dev: bool) {
    let fallback = || {
        let configured = cfg.and_then(|c| c.log.level.clone());
        tracing_subscriber::EnvFilter::new(configured.unwrap_or_else(|| {
            if dev || cfg.is_some_and(|c| c.dev_mode) {
                "debug".into()
            } else {
                "info".into()
            }
        }))
    };
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| fallback());
    // Span close events are what make the span timings visible: the
    // `request` span's close line is an access-log entry (id, method,
    // path, status), and at debug level the inner spans (`pool_checkout`,
    // `lua_handler`, `db_query`, `fetch`) decompose where the time went.
    // See docs/logging.md for the schema.
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE);
    let json = matches!(cfg.map(|c| c.log.format), Some(nitr::LogFormat::Json));
    // One color decision drives everything: the log format (JSON must
    // never carry ANSI), the stream the subscriber writes to (stdout),
    // and the user's `NO_COLOR` preference. The same bool goes to
    // tracing's own ANSI support (level and field coloring), to the
    // diagnostic-painting event formatter (source snippets, tracebacks
    // — see `diag::PaintedFormat` for why painting must happen at the
    // formatter layer), and to the test runner's markers, so they can
    // never disagree — a terminal gets all of it, a pipe or shipper
    // gets byte-clean plain text.
    use std::io::IsTerminal as _;
    let colors = !json
        && std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    nitr::diag::set_console_colors(colors);
    if json {
        builder.json().init();
    } else if colors {
        builder
            .event_format(diag::PaintedFormat(
                tracing_subscriber::fmt::format().with_ansi(true),
            ))
            .init();
    } else {
        builder.with_ansi(false).init();
    }
}

/// Writes the pidfile on creation, removes it on drop — including the
/// error path, so a crashed server does not leave a stale pid behind for
/// `nitr reload` to signal.
struct Pidfile(PathBuf);

impl Pidfile {
    fn write(path: &Path) -> anyhow::Result<Self> {
        std::fs::write(path, format!("{}\n", std::process::id()))
            .with_context(|| format!("cannot write the pidfile {}", path.display()))?;
        Ok(Self(path.to_path_buf()))
    }
}

impl Drop for Pidfile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).ok();
    }
}

/// Sends SIGHUP to the process named by the configured `pidfile`.
fn reload(cfg: &Config) -> anyhow::Result<()> {
    let path = cfg.pidfile.as_ref().context(
        "no `pidfile` is configured: set `pidfile` in nitr.toml so `nitr reload` \
         can find the running server",
    )?;
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!(
            "cannot read the pidfile {} (is the server running?)",
            path.display()
        )
    })?;
    let pid: u32 = raw
        .trim()
        .parse()
        .with_context(|| format!("the pidfile {} does not contain a pid", path.display()))?;

    #[cfg(unix)]
    {
        let status = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .status()
            .context("cannot run `kill`")?;
        if !status.success() {
            bail!("kill -HUP {pid} failed: is the server still running?");
        }
        println!("sent SIGHUP to pid {pid}: the server is rebuilding its runtime pool");
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        bail!("`nitr reload` needs Unix signals, which this platform does not have");
    }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run_main().await {
        // Print the report ourselves instead of returning the error:
        // diagnostics get color on a terminal (plain text otherwise, same
        // bytes anyhow would have printed).
        diag::report(&err);
        std::process::exit(1);
    }
}

async fn run_main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.version {
        println!("nitr {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // `init` runs before any configuration exists; everything else loads
    // the configuration first so `[log]` can shape the subscriber.
    if let Some(Command::Init { dir, minimal }) = &cli.command {
        init_logging(None, cli.dev);
        return scaffold::init(dir.as_deref().unwrap_or(Path::new(".")), *minimal);
    }

    let cfg = match load_config(&cli) {
        Ok(cfg) => {
            init_logging(Some(&cfg), cli.dev);
            cfg
        }
        Err(err) => {
            init_logging(None, cli.dev);
            return Err(err);
        }
    };

    match cli.command.unwrap_or(Command::Run) {
        Command::Init { .. } => unreachable!("handled above"),
        Command::Run | Command::Dev => {
            let pidfile_path = cfg.pidfile.clone();
            let server = Server::builder().config(cfg).build().await?;
            // Written only once the build succeeded: a pid that never
            // served is not one `nitr reload` should be signalling.
            let pidfile = pidfile_path.as_deref().map(Pidfile::write).transpose()?;
            let result = server.serve().await;
            drop(pidfile);
            result?;
        }
        Command::Check { print_config } => {
            if print_config {
                print!("{}", cfg.effective_toml()?);
                return Ok(());
            }
            cmd::check::check(cfg).await?;
        }
        Command::Test { filter } => {
            let failures = cmd::test::run_tests(cfg, filter.as_deref()).await?;
            if failures > 0 {
                std::process::exit(1);
            }
        }
        Command::Migrate { status } => cmd::migrate::migrate(&cfg, status)?,
        Command::Build { output } => {
            let cfg_path = cli
                .config
                .as_deref()
                .unwrap_or(Path::new(DEFAULT_CONFIG_FILE));
            if !cfg_path.is_file() {
                bail!(
                    "`nitr build` needs a configuration file ({} not found): the \
                     bundle records it as the application manifest",
                    cfg_path.display()
                );
            }
            bundle::build(cfg_path, &cfg, &output)?;
        }
        Command::Reload => reload(&cfg)?,
    }
    Ok(())
}
