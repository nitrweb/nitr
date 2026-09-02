// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Script loading and its diagnostics: the dual expression/block parse
//! that keeps error line numbers honest, and the load-error renderer that
//! points at the offending source line.

use std::path::Path;

use mlua::{Function, Value};

use crate::{Error, Result};

use super::Runtime;

impl Runtime {
    /// Loads and runs a chunk the way `eval` does — expression form first,
    /// statement block second — but with precise diagnostics: when *both*
    /// parses fail, the
    /// error that got further into the file wins. mlua's own `eval` reports
    /// only the block fallback, which for an expression-form script always
    /// blames the top-level `function(` line instead of the actual typo.
    ///
    /// The chunk is named after the file (`@` marks a real path) so errors
    /// report `config.lua:12` instead of an anonymous chunk.
    pub(super) fn eval_chunk(&self, data: Vec<u8>, path: &Path) -> mlua::Result<Value> {
        self.load_chunk(data, path)?.call(())
    }

    /// The compile half of [`eval_chunk`](Self::eval_chunk): the dual parse
    /// without the call, for callers that pass the chunk arguments (a
    /// loaded chunk is itself a vararg function) or must call it async.
    pub(super) fn load_chunk(&self, data: Vec<u8>, path: &Path) -> mlua::Result<Function> {
        let name = format!("@{}", path.display());
        // `return ` on the same line keeps every line number intact.
        let mut wrapped = Vec::with_capacity(data.len() + 7);
        wrapped.extend_from_slice(b"return ");
        wrapped.extend_from_slice(&data);
        // Text only, like every other chunk the runtime compiles: a script
        // file that is precompiled bytecode is refused rather than trusted
        // (see `PRELUDE` in the parent module for why bytecode is unsafe).
        let expr_err = match self
            .lua
            .load(wrapped)
            .set_name(&name)
            .set_mode(mlua::chunk::ChunkMode::Text)
            .into_function()
        {
            Ok(f) => return Ok(f),
            Err(err) => err,
        };
        match self
            .lua
            .load(data)
            .set_name(&name)
            .set_mode(mlua::chunk::ChunkMode::Text)
            .into_function()
        {
            Ok(f) => Ok(f),
            Err(block_err) => {
                let line = |err: &mlua::Error| {
                    crate::error::ErrorInfo::from_error(&Error::Lua(err.clone()))
                        .line
                        .unwrap_or(0)
                };
                if line(&expr_err) > line(&block_err) {
                    Err(expr_err)
                } else {
                    Err(block_err)
                }
            }
        }
    }

    /// Loads and evaluates a Lua script file, returning the resulting value.
    ///
    /// This does not interpret the result; callers decide what the script is
    /// expected to return (e.g. a handler function or an application object).
    pub fn eval_script(&self, path: &Path) -> Result<Value> {
        let data = std::fs::read(path).map_err(|err| {
            Error::Script(format!(
                "failed to read the Lua script {}: {err}",
                path.display()
            ))
        })?;
        self.eval_chunk(data, path)
            .map_err(|err| load_error(path, err))
    }
}

/// Converts a load-time Lua failure into a [`Error::Script`] that points at
/// the offending line, with the source rendered around it — parse errors
/// and runtime errors alike (a misspelled method carries a position the
/// same way a typo does). Runs only at startup (and on dev-mode reloads),
/// so reading the file back is fine.
pub(super) fn load_error(path: &Path, err: mlua::Error) -> Error {
    let info = crate::error::ErrorInfo::from_error(&Error::Lua(err));
    // No `error:` prefix of our own: `Error::Script` already displays as
    // `script error: ...`, and one headline is enough.
    let mut out = info.message.clone();
    match info.line {
        Some(line) => {
            let token = crate::error::message_token(&info.message);
            match crate::error::source_snippet(path, line, 2, token) {
                Some(snippet) => {
                    out.push('\n');
                    out.push_str(&snippet);
                }
                None => out.push_str(&format!("\n  --> {}:{line}", path.display())),
            };
        }
        None => out.push_str(&format!("\n  --> {}", path.display())),
    }
    // Runtime failures carry a call stack; parse errors have none. Already
    // bounded by the classifier.
    if let Some(traceback) = &info.traceback {
        out.push_str("\nstack traceback:\n");
        out.push_str(traceback);
    }
    Error::Script(out)
}
