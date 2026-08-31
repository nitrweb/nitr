// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Sections shaping the Lua runtime: `[lua]`, `[std]`, `[env]`,
//! `[testing]`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use nitr_core::{Error, Result};

/// Default per-state Lua memory limit in bytes.
const DEFAULT_MEMORY_LIMIT: usize = 8 * 1024 * 1024; // 8 MiB

/// Default wall-clock budget per handler invocation, in milliseconds.
const DEFAULT_EXEC_TIMEOUT_MS: u64 = 30_000;

/// Standard library selection (`[std]` section): which built-in `nitr.*`
/// modules are exposed to scripts.
///
/// The standard library provides building blocks — scripts opt into the
/// features they need (or replace them with their own modules). Without an
/// explicit list only the minimal set is enabled to keep the footprint
/// small.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StdConfig {
    /// Enabled standard library features. Valid names: `"dbg"`, `"fetch"`,
    /// `"template"`, `"json"`, `"db"`, `"http"`, `"log"`, `"crypto"`,
    /// `"cache"`, `"time"`, `"validate"`, `"base64"`, `"path"`, `"url"`,
    /// `"env"`.
    /// `None` enables the minimal default set (`json`, `http`, `log`,
    /// `time`, `validate`, `base64`, `path`, `url`); an explicit list is
    /// strict —
    /// unknown names or a listed feature missing its required setting
    /// (e.g. `db` without `database`) fail at startup.
    pub features: Option<Vec<String>>,
}

/// Test runner settings (`[testing]` section).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TestingConfig {
    /// Directory `nitr test` discovers `*.lua` test files in.
    pub dir: PathBuf,
}

impl Default for TestingConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("tests"),
        }
    }
}

/// Environment handling (`[env]` section): the env file loaded at
/// startup, and the read policy for the opt-in `nitr.env` builtin
/// (`[std] features = ["env", ...]`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvConfig {
    /// Dotenv-style file loaded at startup, resolved relative to the
    /// config file. Unset loads `.env` next to `nitr.toml` when present;
    /// an explicitly named file must exist. Values never override the
    /// real process environment.
    pub file: Option<PathBuf>,
    /// Names `nitr.env` may read: exact names, or prefixes written with a
    /// trailing `_` (`"APP_"`). Unset lets an enabled `env` builtin read
    /// any variable. `NITR_*` internals are hidden from scripts either way.
    pub allow: Option<Vec<String>>,
}

/// Lua runtime settings (`[lua]` section).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LuaConfig {
    /// Lua standard libraries loaded into every state.
    ///
    /// `"io"` and `"os"` give scripts ambient filesystem/process access and
    /// are excluded by default; adding `"io"` also restores `dofile` and
    /// `loadfile`, which read and execute any file the process can reach.
    ///
    /// `"debug"` is **refused**: mlua's safe constructor cannot load it, and
    /// it would defeat the execution budget anyway, since `debug.sethook`
    /// replaces the instruction-count hook that stops CPU-bound loops.
    pub stdlib: Vec<String>,
    /// Per-state Lua memory limit in bytes.
    pub memory_limit: usize,
    /// Wall-clock budget per handler invocation, in milliseconds; `0`
    /// disables the limit. Enforced by an instruction-count hook (CPU-bound
    /// loops) and an outer async timeout (slow I/O).
    pub exec_timeout_ms: u64,
}

impl Default for LuaConfig {
    fn default() -> Self {
        Self {
            // `io` and `os` are deliberately excluded: they give scripts
            // ambient filesystem/process access. Opt in via `[lua] stdlib`.
            stdlib: ["math", "table", "string", "utf8", "coroutine", "package"]
                .map(String::from)
                .to_vec(),
            memory_limit: DEFAULT_MEMORY_LIMIT,
            exec_timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
        }
    }
}

impl LuaConfig {
    /// Parses the stdlib names into [`mlua::StdLib`] flags.
    pub fn parse_stdlib(&self) -> Result<mlua::StdLib> {
        use mlua::StdLib;
        let mut libs = StdLib::NONE;
        for name in &self.stdlib {
            libs |= match name.as_str() {
                "coroutine" => StdLib::COROUTINE,
                "table" => StdLib::TABLE,
                "io" => StdLib::IO,
                "os" => StdLib::OS,
                "string" => StdLib::STRING,
                "utf8" => StdLib::UTF8,
                "math" => StdLib::MATH,
                "package" => StdLib::PACKAGE,
                // Refused here, where the names are mapped, rather than
                // passed through: mlua would reject `StdLib::DEBUG` at boot
                // anyway, but naming an internal Rust constructor instead of
                // the `nitr.toml` setting. The full rationale is the error
                // below.
                "debug" => {
                    return Err(Error::Config(
                        "[lua] stdlib cannot include \"debug\": the Lua state is built with \
                         mlua's safe constructor, which refuses the debug library outright. \
                         It would also defeat the execution budget, since `debug.sethook` \
                         replaces the instruction-count hook that stops CPU-bound loops."
                            .into(),
                    ));
                }
                _ => {
                    return Err(Error::Config(format!(
                        "unknown Lua standard library `{name}`"
                    )));
                }
            };
        }
        Ok(libs)
    }
}
