// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Human-facing rendering helpers: the annotated source snippet and the
//! token a Lua message points at, for caret placement.
/// Renders `line` of the file at `path` with `context` lines around it, in
/// a gutter format that points at the failing line:
///
/// ```text
///   --> app.lua:23
///    |
/// 22 |     local user = nil
/// 23 |     return user.name
///    |     ^
/// ```
///
/// Reads from disk, so callers keep it off the production request path:
/// load-time diagnostics and the development error page only. Returns
/// `None` when the file cannot be read or the line is out of range.
///
/// Lua reports no column, but a parse error names the token it stopped at
/// (`near 'users'`); when `token` is given and occurs in the line, the
/// caret sits under that occurrence instead of at the indent.
pub fn source_snippet(
    path: &std::path::Path,
    line: u32,
    context: u32,
    token: Option<&str>,
) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let line = line as usize;
    let first = line.saturating_sub(context as usize).max(1);
    let last = line + context as usize;
    let width = last.to_string().len();
    let mut out = format!("  --> {}:{line}\n  {:width$} |\n", path.display(), "");
    let mut found = false;
    for (n, content) in text.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        if n < first || n > last {
            continue;
        }
        out.push_str(&format!("  {n:width$} | {content}\n"));
        if n == line {
            found = true;
            let (prefix, caret_width) = match token
                .filter(|t| !t.is_empty())
                .and_then(|t| content.find(t).map(|at| (at, t)))
            {
                Some((at, t)) => (&content[..at], t.chars().count()),
                None => {
                    let indent = content.len() - content.trim_start().len();
                    (&content[..indent], 1)
                }
            };
            // Tabs must stay tabs so the caret lines up under the content.
            let pad: String = prefix
                .chars()
                .map(|c| if c == '\t' { '\t' } else { ' ' })
                .collect();
            let carets = "^".repeat(caret_width);
            out.push_str(&format!("  {:width$} | {pad}{carets}\n", ""));
        }
    }
    found.then_some(out)
}

/// The token a Lua error message points at, for caret placement: a parse
/// error's `near 'users'`, or the symbol a runtime error names —
/// `attempt to call a nil value (method 'eexecute')`. `near <eof>` and
/// messages without a quoted token yield `None`.
pub fn message_token(message: &str) -> Option<&str> {
    if let Some((_, tail)) = message.rsplit_once("near '") {
        return tail.split_once('\'').map(|(token, _)| token);
    }
    let end = message.rfind('\'')?;
    let start = message[..end].rfind('\'')?;
    let token = &message[start + 1..end];
    (!token.is_empty()).then_some(token)
}
