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
    ///
    /// The expression parse is skipped when the chunk's first token can only
    /// begin a statement (`local`, `return`, a named `function`, ...): it
    /// would fail at that very token, so skipping it changes neither the
    /// result nor the diagnostic, and a handler script — which always starts
    /// that way — is parsed once instead of twice on every pooled state.
    pub(super) fn load_chunk(&self, data: Vec<u8>, path: &Path) -> mlua::Result<Function> {
        let name = format!("@{}", path.display());
        // Text only, like every other chunk the runtime compiles: a script
        // file that is precompiled bytecode is refused rather than trusted
        // (see `PRELUDE` in the parent module for why bytecode is unsafe).
        let expr_err = if starts_as_statement(&data) {
            None
        } else {
            // `return ` on the same line keeps every line number intact.
            let mut wrapped = Vec::with_capacity(data.len() + 7);
            wrapped.extend_from_slice(b"return ");
            wrapped.extend_from_slice(&data);
            match self
                .lua
                .load(wrapped)
                .set_name(&name)
                .set_mode(mlua::chunk::ChunkMode::Text)
                .into_function()
            {
                Ok(f) => return Ok(f),
                Err(err) => Some(err),
            }
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
                let Some(expr_err) = expr_err else {
                    return Err(block_err);
                };
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

/// Whether the chunk's first token can only begin a statement, so that the
/// expression form (`return <chunk>`) is guaranteed to fail *at that token*.
///
/// Skipping the expression parse in that case is observably identical to
/// running it: it cannot succeed, and the diagnostic it would produce sits
/// on the first token's line, which the block parse's error can never
/// precede — so the "furthest error wins" rule picks the block error either
/// way. Every answer of `false` means "parse both, as before"; the
/// function only ever removes a parse it can prove redundant, and an
/// unrecognized or unterminated prefix (a shebang, an unclosed long
/// comment, a vertical tab) answers `false`.
///
/// A bare call is the one shape that is valid in both forms (`nitr.app()`
/// is an expression *and* a call statement), so a leading identifier must
/// keep the expression attempt first: that is what makes such a script
/// evaluate to the call's result instead of `nil`.
fn starts_as_statement(src: &[u8]) -> bool {
    let rest = skip_trivia(src);
    let is_word = |b: &u8| b.is_ascii_alphanumeric() || *b == b'_';
    let word_end = rest.iter().position(|b| !is_word(b)).unwrap_or(rest.len());
    match &rest[..word_end] {
        b"local" | b"return" | b"if" | b"for" | b"while" | b"do" | b"repeat" | b"goto"
        | b"break" => true,
        // `function name(` is a statement; `function(` is an expression.
        b"function" => skip_trivia(&rest[word_end..])
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_'),
        // A label, `::name::`.
        _ => rest.starts_with(b"::"),
    }
}

/// Skips ASCII whitespace and comments (`--` to end of line, or a long
/// `--[==[ ... ]==]` bracket). An unterminated long comment yields the empty
/// slice, which `starts_as_statement` treats as "unknown".
fn skip_trivia(mut src: &[u8]) -> &[u8] {
    loop {
        let ws = src
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(src.len());
        src = &src[ws..];
        let Some(body) = src.strip_prefix(b"--") else {
            return src;
        };
        src = match long_bracket_level(body) {
            Some(level) => {
                let open = level + 2;
                let mut close = Vec::with_capacity(level + 2);
                close.push(b']');
                close.extend(std::iter::repeat_n(b'=', level));
                close.push(b']');
                match body[open..]
                    .windows(close.len())
                    .position(|window| window == close.as_slice())
                {
                    Some(at) => &body[open + at + close.len()..],
                    None => return &[],
                }
            }
            None => match body.iter().position(|b| *b == b'\n') {
                Some(at) => &body[at + 1..],
                None => return &[],
            },
        };
    }
}

/// The `=` count of a long bracket opening at the start of `s` (`[[` is
/// level 0, `[==[` is level 2), or `None` when `s` does not open one.
fn long_bracket_level(s: &[u8]) -> Option<usize> {
    let after_open = s.strip_prefix(b"[")?;
    let level = after_open.iter().take_while(|b| **b == b'=').count();
    (after_open.get(level) == Some(&b'[')).then_some(level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_only_prefixes_skip_the_expression_parse() {
        for src in [
            "local app = nitr.app()",
            "  \n\t-- a comment\n\nlocal x = 1",
            "--[[ multi\nline ]] return {}",
            "--[==[ a ]] inside ]==]\nfunction handler(req) end",
            "-- one\n-- two\nif x then end",
            "for i = 1, 2 do end",
            "while true do end",
            "do end",
            "repeat until true",
            "goto top",
            "break",
            "::top::",
            "return",
        ] {
            assert!(starts_as_statement(src.as_bytes()), "{src:?}");
        }
    }

    #[test]
    fn expression_capable_prefixes_keep_the_expression_parse() {
        for src in [
            "function(req) return req end",
            "function (req) return req end",
            "-- comment\nfunction(db)\n  return {}\nend",
            "{ a = 1 }",
            "nitr.app()",
            "string.rep('a', 2)",
            "localx = 1",
            "returned = 1",
            "'a string'",
            "42",
            "",
            "   ",
            "-- only a comment",
            "--[[ unterminated",
            "#!/usr/bin/lua\nlocal x = 1",
            "\x0blocal x = 1",
        ] {
            assert!(!starts_as_statement(src.as_bytes()), "{src:?}");
        }
    }

    #[test]
    fn long_brackets_parse_by_level() {
        assert_eq!(long_bracket_level(b"[[x"), Some(0));
        assert_eq!(long_bracket_level(b"[==[x"), Some(2));
        assert_eq!(long_bracket_level(b"[=x"), None);
        assert_eq!(long_bracket_level(b"x"), None);
        assert_eq!(long_bracket_level(b""), None);
        // A level-1 close does not end a level-2 comment.
        assert_eq!(skip_trivia(b"--[==[ ]=] ]==]rest"), b"rest");
    }
}
