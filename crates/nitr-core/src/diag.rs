// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Terminal painting for diagnostics.
//!
//! Error values carry plain text throughout Nitr — the same strings serve
//! HTTP dev-page bodies, log files, and `err.message` in Lua — so color
//! is applied only at a print boundary, never stored in a message. Three
//! boundaries exist: the CLI's startup report (gated on stderr being a
//! terminal), the CLI test runner's markers (gated on the
//! [`console_colors`] switch), and the tracing log stream, where the
//! CLI installs an event formatter that paints each formatted line by
//! shape. Painting *inside* the formatter is not a style choice:
//! `tracing-subscriber` (rightly) strips ANSI control sequences from
//! message content to prevent terminal injection, so escape codes can
//! only be added after an event is formatted — which also means a
//! hostile Lua error message can never smuggle its own codes past the
//! sanitizer. Library embedders that install no such formatter get plain
//! text everywhere.
//!
//! The palette mirrors rustc: red for the error headline and caret, blue
//! for the gutter, cyan for the location, dim for tracebacks, plus a
//! minimal line-local Lua highlight inside source lines.

use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) const RESET: &str = "\x1b[0m";
pub(crate) const BOLD: &str = "\x1b[1m";
pub(crate) const DIM: &str = "\x1b[2m";
pub(crate) const RED: &str = "\x1b[31m";
pub(crate) const GREEN: &str = "\x1b[32m";
pub(crate) const MAGENTA: &str = "\x1b[35m";
pub(crate) const CYAN: &str = "\x1b[36m";
pub(crate) const BLUE: &str = "\x1b[34m";

/// Whether plain `println!`-style console output (the test runner's
/// markers) should be painted. Off until someone who knows better says so.
static CONSOLE_COLORS: AtomicBool = AtomicBool::new(false);

/// Declares whether console output can carry ANSI color.
///
/// Call this once, from wherever the logging subscriber is initialized —
/// that is the one place that knows the log format (JSON must never carry
/// ANSI), the destination (a terminal, or a pipe/file), and the user's
/// `NO_COLOR` preference. Everything printed before the call stays plain.
pub fn set_console_colors(enabled: bool) {
    CONSOLE_COLORS.store(enabled, Ordering::Relaxed);
}

/// Whether [`set_console_colors`] enabled painting for the log stream.
pub fn console_colors() -> bool {
    CONSOLE_COLORS.load(Ordering::Relaxed)
}

/// Paints a success marker (bold green) when [`console_colors`] is on —
/// for CLI output like the test runner's `ok`, which shares stdout with
/// the log stream and must follow the same color decision.
pub fn console_ok(text: &str) -> String {
    if console_colors() {
        format!("{BOLD}{GREEN}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Paints a failure marker (bold red) when [`console_colors`] is on.
pub fn console_fail(text: &str) -> String {
    if console_colors() {
        format!("{BOLD}{RED}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Unconditionally paints every line of a diagnostic (see [`paint_line`]).
pub fn paint(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        out.push_str(&paint_line(line));
        if lines.peek().is_some() {
            out.push('\n');
        }
    }
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Applies the palette to one diagnostic line, recognized by shape: error
/// headlines, `--> path:line` locations, gutter and caret lines (with the
/// Lua source inside a gutter highlighted), traceback frames, and
/// `Caused by:` headers. Anything else passes through unchanged.
pub fn paint_line(line: &str) -> String {
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];

    // `Error: ...` / `error: ...` headlines (`script error:` is how
    // `Error::Script` diagnostics display).
    for prefix in ["Error:", "script error:", "error:"] {
        if let Some(message) = trimmed.strip_prefix(prefix) {
            return format!("{indent}{BOLD}{RED}{prefix}{RESET}{BOLD}{message}{RESET}");
        }
    }
    // `  --> path:line`
    if let Some(location) = trimmed.strip_prefix("--> ") {
        return format!("{indent}{BOLD}{BLUE}-->{RESET} {CYAN}{location}{RESET}");
    }
    // Caret marker: `   | ^^^^^`
    if let Some((gutter, rest)) = line.split_once('|')
        && gutter.trim().is_empty()
        && !rest.trim().is_empty()
        && rest.trim().chars().all(|c| c == '^')
    {
        return format!("{gutter}{BOLD}{BLUE}|{RESET}{BOLD}{RED}{rest}{RESET}");
    }
    // Gutter lines: `  15 | code` and the bare `     |` spacer.
    if let Some((gutter, code)) = line.split_once('|')
        && gutter.trim().chars().all(|c| c.is_ascii_digit())
    {
        return format!("{BOLD}{BLUE}{gutter}|{RESET}{}", paint_lua(code));
    }
    // Tracebacks and their tab-indented frames.
    if trimmed.starts_with("stack traceback:") || line.starts_with('\t') {
        return format!("{DIM}{line}{RESET}");
    }
    if trimmed == "Caused by:" {
        return format!("{indent}{BOLD}Caused by:{RESET}");
    }
    // A headline embedded mid-line, which is how the log stream renders
    // one ("... reload failed, keeping the current pool: script error:
    // ..."): painted from the marker on. Last, so shaped lines whose
    // *content* happens to contain the marker keep their own painting.
    if let Some(idx) = line.find("script error:") {
        let (head, tail) = line.split_at(idx);
        let message = &tail["script error:".len()..];
        return format!("{head}{BOLD}{RED}script error:{RESET}{BOLD}{message}{RESET}");
    }
    line.to_string()
}

const LUA_KEYWORDS: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in",
    "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
];

/// A single-line Lua highlight: comments dimmed, strings green, keywords
/// magenta. Line-local by design — a snippet is a few lines around one
/// error, so multi-line string/comment state is not worth carrying.
fn paint_lua(code: &str) -> String {
    let mut out = String::with_capacity(code.len() + 16);
    let bytes = code.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &code[i..];
        // A comment runs to the end of the line.
        if rest.starts_with("--") {
            out.push_str(DIM);
            out.push_str(GREEN);
            out.push_str(rest);
            out.push_str(RESET);
            break;
        }
        // A quoted string (line-local; an unterminated one just stays green
        // to the end of the line).
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote = bytes[i] as char;
            let mut end = i + 1;
            while end < bytes.len() {
                if bytes[end] == b'\\' {
                    end += 2;
                    continue;
                }
                if bytes[end] as char == quote {
                    end += 1;
                    break;
                }
                end += 1;
            }
            let end = end.min(bytes.len());
            out.push_str(GREEN);
            out.push_str(&code[i..end]);
            out.push_str(RESET);
            i = end;
            continue;
        }
        // A word: keyword or identifier.
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let mut end = i + 1;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            let word = &code[i..end];
            if LUA_KEYWORDS.contains(&word) {
                out.push_str(MAGENTA);
                out.push_str(word);
                out.push_str(RESET);
            } else {
                out.push_str(word);
            }
            i = end;
            continue;
        }
        // Invariant: every branch above advances `i` by whole-character
        // widths, so `i` always sits on a char boundary inside a non-empty
        // remainder (`i < bytes.len()` guards the loop).
        #[allow(clippy::expect_used)]
        let ch = code[i..].chars().next().expect("i is on a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headline_arrow_gutter_and_caret_are_painted() {
        assert!(paint_line("Error: script error").contains(RED));
        assert!(paint_line("script error: SQL statement failed").contains(RED));
        assert!(paint_line("  --> app.lua:15").contains(CYAN));
        assert!(paint_line("  15 |     local x = 1").starts_with(BOLD));
        assert!(paint_line("     |            ^^^^^").contains(RED));
        assert!(paint_line("stack traceback:").starts_with(DIM));
        assert!(paint_line("\tapp.lua:14: in function").starts_with(DIM));
    }

    #[test]
    fn lua_highlight_covers_keywords_strings_and_comments() {
        let painted = paint_lua("local s = \"text\" -- note");
        assert!(painted.contains(&format!("{MAGENTA}local{RESET}")));
        assert!(painted.contains(&format!("{GREEN}\"text\"{RESET}")));
        assert!(painted.contains(&format!("{DIM}{GREEN}-- note{RESET}")));
        // Identifiers that merely contain a keyword stay unpainted.
        let painted = paint_lua("ending = localize()");
        assert!(!painted.contains(MAGENTA), "got: {painted}");
    }

    /// A multi-line diagnostic in the shape `Error::Script` renders: every
    /// line kind is recognized, and line count survives painting.
    #[test]
    fn paint_covers_a_whole_script_error() {
        let diagnostic = "script error: no such table: user\n  \
                          --> scripts/config.lua:14\n     \
                          |\n  14 | db:execute(\"DELETE FROM user\")\n     \
                          | ^\nstack traceback:\n\t[C]: in local 'poll'";
        let painted = paint(diagnostic);
        assert_eq!(painted.lines().count(), diagnostic.lines().count());
        assert!(painted.contains(RED));
        assert!(painted.contains(CYAN));
        assert!(painted.contains(DIM));
        assert!(painted.contains(GREEN), "the SQL string literal is painted");
    }

    /// `console_text` is a strict pass-through until the logging boundary
    /// opts in — library embedders must never see ANSI they did not ask
    /// for. (The one test that flips the global switch, so no other test
    /// may rely on its state.)
    /// The tracing formatter hands `paint_line` a first line that carries
    /// the subscriber's own prefix before the error text: the headline is
    /// still found and painted from its marker on.
    #[test]
    fn a_mid_line_headline_is_painted_from_the_marker() {
        let line = "2026-08-21 ERROR nitr: reload failed: script error: no such table";
        let painted = paint_line(line);
        assert!(painted.starts_with("2026-08-21 ERROR nitr: reload failed: "));
        assert!(painted.contains(&format!("{BOLD}{RED}script error:{RESET}")));
    }

    /// Markers are a strict pass-through until the console boundary opts
    /// in — embedders must never see ANSI they did not ask for. (The one
    /// test that flips the global switch, so no other test may rely on
    /// its state.)
    #[test]
    fn markers_paint_only_when_console_colors_are_enabled() {
        assert_eq!(console_ok("ok"), "ok");
        assert_eq!(console_fail("FAIL"), "FAIL");
        set_console_colors(true);
        assert!(console_ok("ok").contains(GREEN));
        assert!(console_fail("FAIL").contains(RED));
        set_console_colors(false);
        assert_eq!(console_ok("ok"), "ok");
    }
}
