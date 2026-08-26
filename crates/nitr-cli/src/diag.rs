// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Console rendering for startup diagnostics.
//!
//! Error values carry plain text (the same strings serve HTTP dev-page
//! bodies and log files); color is applied here, at the terminal boundary
//! only — stderr must be a TTY and `NO_COLOR` unset. The layout mirrors
//! `anyhow`'s report (`Error: ...` + `Caused by:` chain) so a piped or
//! non-TTY run prints byte-identical output to the previous behavior.
//! The line painter itself is shared with the server's log stream and
//! lives in [`nitr::diag`].

use std::io::IsTerminal as _;

/// Prints an error report to stderr, colorized when it is a terminal.
pub(crate) fn report(err: &anyhow::Error) {
    let colored = std::io::stderr().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let mut out = String::new();
    push_block(&mut out, &format!("Error: {err}"), "", colored);
    let mut causes = err.chain().skip(1).peekable();
    if causes.peek().is_some() {
        out.push('\n');
        if colored {
            out.push_str(&nitr::diag::paint_line("Caused by:"));
        } else {
            out.push_str("Caused by:");
        }
        out.push('\n');
        for cause in causes {
            push_block(&mut out, &cause.to_string(), "    ", colored);
        }
    }
    eprint!("{out}");
}

/// Renders one (possibly multi-line) message, painting each line by shape.
fn push_block(out: &mut String, text: &str, indent: &str, colored: bool) {
    for line in text.lines() {
        out.push_str(indent);
        if colored {
            out.push_str(&nitr::diag::paint_line(line));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
}

/// An event formatter that paints diagnostics in the log stream.
///
/// Delegates to the wrapped formatter, then applies
/// [`nitr::diag::paint_line`] to every formatted line. This is the only
/// layer where color *can* be added: `tracing-subscriber` strips ANSI
/// control sequences from message content (terminal-injection
/// hardening), so a painted string handed to a log macro arrives as
/// literal `\x1b` text. Painting after formatting keeps that protection
/// — hostile message content is already sanitized by the time the
/// painter sees it — while dev-mode reload failures and tracebacks get
/// the same rustc-like palette as startup errors.
pub(crate) struct PaintedFormat<F>(pub(crate) F);

impl<S, N, F> tracing_subscriber::fmt::FormatEvent<S, N> for PaintedFormat<F>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
    F: tracing_subscriber::fmt::FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let mut buf = String::new();
        self.0.format_event(
            ctx,
            tracing_subscriber::fmt::format::Writer::new(&mut buf),
            event,
        )?;
        // A single-line event is the overwhelmingly common case, and its
        // one line starts with the subscriber's own (already colored)
        // prefix, which matches no diagnostic shape — skip the rebuild.
        if !buf.trim_end_matches('\n').contains('\n') {
            return writer.write_str(&buf);
        }
        let mut lines = buf.lines().peekable();
        while let Some(line) = lines.next() {
            writer.write_str(&nitr::diag::paint_line(line))?;
            if lines.peek().is_some() {
                writer.write_char('\n')?;
            }
        }
        if buf.ends_with('\n') {
            writer.write_char('\n')?;
        }
        Ok(())
    }
}
