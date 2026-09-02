// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Structured diagnostics: classification of raw Lua and Rust errors into
//! [`ErrorInfo`], parsed from what mlua already captured at raise time.

use super::{Error, is_memory_error};
/// How many Lua traceback frames survive into diagnostics. Beyond this the
/// stack is elided: deep stacks repeat the same application frames, and an
/// error firing in a loop must not turn each failure into a page of output.
pub(super) const MAX_TRACEBACK_LINES: usize = 12;

/// How many wrapped causes of an error chain survive into diagnostics.
const MAX_CAUSE_DEPTH: usize = 5;

/// The message the execution-budget instruction hook raises with. Shared
/// with classification: the hook's failure surfaces as an ordinary Lua
/// error (it fires inside the VM), and this is what identifies it as a
/// timeout rather than a script bug.
pub(crate) const EXEC_BUDGET_MSG: &str = "handler execution exceeded its time budget";

/// What Lua raises when an asynchronous builtin is called somewhere it
/// cannot suspend.
///
/// Every builtin that awaits — `nitr.fetch`, the `nitr.db` methods,
/// `nitr.crypto.password_hash` and its two siblings, `req:multipart`,
/// `req:text` — is a Lua function that yields, and a yield needs a
/// coroutine the async executor is driving. Two places do not have one: the
/// **top level** of a handler or config script (evaluated once at startup,
/// outside the executor) and a bare `coroutine.resume`/`wrap` the
/// application drives itself.
///
/// The VM's own words for that are `attempt to yield from outside a
/// coroutine`, which names neither the builtin nor the fix. Classification
/// replaces it — see [`ASYNC_OUTSIDE_HINT`].
pub(super) const LUA_YIELD_OUTSIDE: &str = "attempt to yield from outside a coroutine";

/// The explanation that replaces [`LUA_YIELD_OUTSIDE`].
///
/// Prefixed with the builtin's name when the traceback names it, or with a
/// generic phrase when it does not.
const ASYNC_OUTSIDE_HINT: &str = "is asynchronous and cannot be called here. A script's top \
     level runs once at startup, outside the async executor, and a \
     coroutine your own code resumes is not driven by it either — neither \
     has anything to suspend into. Call it from inside a handler or a \
     middleware instead. A value the script needs at load time has to be \
     computed without an async builtin: `nitr hash-password` mints a \
     password hash to paste into a table, for instance";

/// A classified view of an [`Error`]: what broke, where, and why, as
/// separate fields instead of one interpolated string.
///
/// Built on the error path only — the happy path never constructs one — by
/// parsing what mlua already captured at raise time (position-prefixed
/// messages and tracebacks), so classification adds no capture cost of its
/// own. Production diagnostics use the concise fields (`kind`, `source`,
/// `line`, `module`, `message`); the bounded `traceback` and `cause` chain
/// exist for development mode and for error handlers that ask for them.
#[derive(Debug, Clone)]
pub struct ErrorInfo {
    /// The classified failure: `"lua"` (a script error), `"nitr"` (a
    /// `nitr.*` builtin or Nitr's own boundary), `"module"` (a registered
    /// extension module), `"timeout"`, `"memory"`, or `"panic"`. The set is
    /// closed, so branching on it is stable in a way matching on message
    /// text never is — but it is *classification*, not provenance: `"nitr"`
    /// and `"timeout"` are recognized by message shape, so a script that
    /// raises `"nitr.db: ..."` or the budget message verbatim lands in
    /// those kinds too. It is fit for logging and error pages; no
    /// security decision may rest on it.
    pub kind: &'static str,
    /// The message with any position prefix and traceback stripped.
    pub message: String,
    /// The chunk that raised the error (the script path when the chunk was
    /// loaded from a file), when the message carried a position.
    pub source: Option<String>,
    /// The line within [`source`](Self::source).
    pub line: Option<u32>,
    /// The failing module (`"nitr.db"`, or an extension's mount name),
    /// when the error crossed the Rust/Lua boundary with attribution.
    pub module: Option<String>,
    /// The Lua call stack at the raise site, innermost first, bounded to
    /// [`MAX_TRACEBACK_LINES`] frames.
    pub traceback: Option<String>,
    /// The underlying Rust error chain, outermost first, bounded to
    /// [`MAX_CAUSE_DEPTH`] entries.
    pub cause: Vec<String>,
}

impl ErrorInfo {
    /// Classifies an error into its structured form.
    pub fn from_error(err: &Error) -> Self {
        match err {
            Error::Timeout => Self::plain("timeout", err.to_string()),
            Error::PoolBusy => Self::plain("nitr", err.to_string()),
            Error::Panic(msg) => Self::plain("panic", msg.clone()),
            Error::Lua(lua_err) => Self::from_lua(lua_err),
            other => Self::plain("nitr", other.to_string()),
        }
    }

    fn plain(kind: &'static str, message: String) -> Self {
        Self {
            kind,
            message,
            source: None,
            line: None,
            module: None,
            traceback: None,
            cause: Vec::new(),
        }
    }

    fn from_lua(err: &mlua::Error) -> Self {
        if is_memory_error(err) {
            return Self::plain("memory", "Lua memory limit exceeded".into());
        }

        // Walk the chain once, collecting what each layer knows: the
        // traceback mlua captured at the raise site, `WithContext` module
        // tags, and the wrapped causes.
        let mut kind: &'static str = "lua";
        let mut module = None;
        let mut traceback = None;
        let mut cause = Vec::new();
        let mut current = err;
        loop {
            match current {
                mlua::Error::CallbackError {
                    traceback: tb,
                    cause: inner,
                } => {
                    // An error raised on the Rust side of the boundary; the
                    // innermost Lua traceback is the raise site.
                    kind = "nitr";
                    traceback = Some(tb.as_str());
                    current = inner;
                }
                mlua::Error::WithContext {
                    context,
                    cause: inner,
                } => {
                    if let Some(name) = context.strip_prefix("module ") {
                        kind = "module";
                        module = Some(name.to_string());
                    } else if let Some((name, _)) = context.split_once(':')
                        && name.starts_with("nitr.")
                    {
                        module = Some(name.to_string());
                    } else if cause.len() < MAX_CAUSE_DEPTH {
                        cause.push(context.clone());
                    }
                    current = inner;
                }
                // A misused builtin (wrong argument count or type) is a
                // boundary failure too, with the real cause wrapped inside.
                mlua::Error::BadArgument { cause: inner, .. } => {
                    kind = "nitr";
                    current = inner;
                }
                mlua::Error::ExternalError(inner) => {
                    // A foreign Rust error: keep its own source chain.
                    let mut src: Option<&dyn std::error::Error> = inner.source();
                    while let Some(err) = src {
                        if cause.len() >= MAX_CAUSE_DEPTH {
                            break;
                        }
                        cause.push(err.to_string());
                        src = err.source();
                    }
                    break;
                }
                _ => break,
            }
        }

        // The innermost message may still carry the `source:line:` prefix
        // and an embedded traceback (plain Lua runtime errors do). Take the
        // raw message where the variant exposes one: `Display` prepends
        // "runtime error: ", which would corrupt the position parse.
        let text = match current {
            mlua::Error::RuntimeError(msg) | mlua::Error::MemoryError(msg) => msg.clone(),
            mlua::Error::SyntaxError { message, .. } => message.clone(),
            other => other.to_string(),
        };
        Self::from_text(kind, module, traceback, cause, &text)
    }

    /// The builtin a `yield outside a coroutine` traceback was raised from.
    ///
    /// mlua's async trampoline reports itself as an anonymous `[string "?"]`
    /// chunk, and that frame — the first one below `coroutine.yield` —
    /// carries the name the script called the builtin by:
    ///
    /// ```text
    /// [C]: in function 'coroutine.yield'
    /// [string "?"]:28: in field 'password_hash'   <- this one
    /// app.lua:5: in main chunk
    /// ```
    ///
    /// Only that frame is consulted. Every deeper frame is a *caller* of
    /// the builtin, and naming one would blame the script's own function
    /// for being asynchronous. An aliased call (`local h =
    /// nitr.crypto.password_hash`) is named by its alias — `in local 'h'` —
    /// which is the name the script knows the builtin by.
    ///
    /// Returns the bare name (`password_hash`), never a guessed path: the
    /// traceback carries the reference the call resolved through and not
    /// the table it hung off, so prefixing `nitr.` would print
    /// `nitr.password_hash` for what the script wrote as
    /// `nitr.crypto.password_hash`. `None` when the traceback has been
    /// truncated past that frame or its shape changes — the caller falls
    /// back to a generic phrase rather than inventing one.
    fn async_callee(traceback: &str) -> Option<String> {
        // Past `coroutine.yield` and any other `[C]` frames, the next frame
        // is the trampoline's own; requiring its anonymous-chunk source
        // makes a reshaped traceback yield nothing instead of a caller.
        let frame = traceback
            .lines()
            .map(str::trim_start)
            .skip_while(|frame| !frame.contains("coroutine.yield"))
            .find(|frame| !frame.starts_with("[C]"))
            .filter(|frame| frame.starts_with("[string"))?;
        // Every way Lua names a call site: a table field or method, a plain
        // function, or the local/upvalue/global an alias was bound to.
        let rest = [
            "in field '",
            "in method '",
            "in function '",
            "in local '",
            "in upvalue '",
            "in global '",
        ]
        .into_iter()
        .find_map(|pattern| frame.split_once(pattern))?
        .1;
        let name = rest.split_once('\'')?.0;
        // A dotted name is a VM-qualified frame, not what the script wrote.
        (!name.is_empty() && !name.contains('.')).then(|| name.to_string())
    }

    /// Classifies an error that arrives as bare text: what a Lua `pcall`
    /// catches from an `error()` or a runtime failure (`app.lua:21:
    /// attempt to call a nil value ...`, possibly with an appended
    /// traceback). Rust-side errors keep their full chain and should go
    /// through [`from_error`](Self::from_error) instead.
    pub fn from_message(text: &str) -> Self {
        Self::from_text("lua", None, None, Vec::new(), text)
    }

    /// The shared tail of classification: position, traceback split,
    /// module attribution by message prefix, and kind refinements.
    fn from_text(
        mut kind: &'static str,
        module: Option<String>,
        traceback: Option<&str>,
        cause: Vec<String>,
        text: &str,
    ) -> Self {
        let (headline, embedded_tb) = split_traceback(text);
        let (source, line, message) = parse_position(headline);

        // A message the application prefixed with its origin (`nitr.db:
        // database is locked`) attributes the module even without wrapping.
        let module = module.or_else(|| {
            message
                .split_once(':')
                .map(|(name, _)| name)
                .filter(|name| {
                    name.strip_prefix("nitr.").is_some_and(|rest| {
                        !rest.is_empty() && rest.chars().all(char::is_alphanumeric)
                    })
                })
                .map(str::to_string)
        });
        if module.as_deref().is_some_and(|m| m.starts_with("nitr.")) && kind == "lua" {
            kind = "nitr";
        }
        // The execution-budget hook fires inside the VM, so its failure
        // arrives as an ordinary Lua error; reclassify by its message.
        if message == EXEC_BUDGET_MSG {
            kind = "timeout";
        }

        let traceback = traceback.or(embedded_tb).map(bound_traceback);
        // A Rust-side error carries no position prefix, but its traceback's
        // first *file* frame is the call site that invoked the builtin.
        // `[C]` frames and anonymous `[string "..."]` chunks (mlua's async
        // trampoline reports itself as `[string "?"]`) are not places a
        // user can look, so they never supply a position.
        let mut source = source.map(str::to_string);
        let mut line = line;
        if source.is_none()
            && let Some(tb) = &traceback
        {
            for frame in tb.lines() {
                let frame = frame.trim_start();
                if frame.starts_with('[') {
                    continue;
                }
                if let (Some(frame_src), Some(frame_line), _) = parse_position(frame) {
                    source = Some(frame_src.to_string());
                    line = Some(frame_line);
                    break;
                }
            }
        }

        // An async builtin called where it cannot suspend. Translated last
        // because naming the builtin needs the resolved traceback, and the
        // VM's own wording ("attempt to yield from outside a coroutine")
        // names neither what was called nor what to do instead. A script
        // that *raises* the same words through `error()` keeps them: its
        // traceback shows the `error` call where the genuine failure's
        // shows the yield. Without a traceback the two cannot be told
        // apart, and the genuine failure is the one that occurs.
        let mut message = message.to_string();
        if message == LUA_YIELD_OUTSIDE
            && traceback
                .as_deref()
                .is_none_or(|tb| tb.contains("coroutine.yield"))
        {
            let what = traceback
                .as_deref()
                .and_then(Self::async_callee)
                .map_or_else(|| "this builtin".to_string(), |name| format!("`{name}`"));
            message = format!("{what} {ASYNC_OUTSIDE_HINT}");
            kind = "nitr";
        }

        Self {
            kind,
            message,
            source,
            line,
            module,
            traceback,
            cause,
        }
    }

    /// The concise single-line form used by production diagnostics:
    /// `kind: message (source:line)`.
    pub fn concise(&self) -> String {
        let mut out = format!("{}: {}", self.kind, self.message);
        if let (Some(source), Some(line)) = (&self.source, self.line) {
            out.push_str(&format!(" ({source}:{line})"));
        }
        out
    }

    /// [`concise`](Self::concise) with ANSI color: the kind bold red, the
    /// message bold, the location cyan. Callers gate on the destination
    /// being a terminal — this string must never reach an HTTP body or a
    /// log file.
    pub fn concise_colored(&self) -> String {
        const RESET: &str = "\x1b[0m";
        const BOLD: &str = "\x1b[1m";
        const RED: &str = "\x1b[31m";
        const CYAN: &str = "\x1b[36m";
        let mut out = format!(
            "{BOLD}{RED}{}:{RESET}{BOLD} {}{RESET}",
            self.kind, self.message
        );
        if let (Some(source), Some(line)) = (&self.source, self.line) {
            out.push_str(&format!(" {CYAN}({source}:{line}){RESET}"));
        }
        out
    }
}

/// Splits an error message from the traceback Lua appended to it, if any.
fn split_traceback(text: &str) -> (&str, Option<&str>) {
    match text.split_once("\nstack traceback:") {
        Some((head, tail)) => (head.trim_end(), Some(tail)),
        None => (text.trim_end(), None),
    }
}

/// Parses Lua's `source:line: message` position prefix. The source may
/// itself contain colons (Windows drive letters), so the scan looks for the
/// first `:<digits>: ` group rather than splitting on the first colon.
pub(super) fn parse_position(text: &str) -> (Option<&str>, Option<u32>, &str) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(offset) = text[i..].find(':') {
        let colon = i + offset;
        let digits_start = colon + 1;
        let mut end = digits_start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end > digits_start && bytes.get(end) == Some(&b':') {
            let source = &text[..colon];
            let line = text[digits_start..end].parse().ok();
            let message = text[end + 1..].trim_start();
            if !source.is_empty() && line.is_some() {
                return (Some(source), line, message);
            }
        }
        i = colon + 1;
    }
    (None, None, text)
}

/// Bounds a traceback to [`MAX_TRACEBACK_LINES`] frames, eliding the rest:
/// deep stacks repeat application frames, and diagnostics must stay
/// readable when an error fires in a loop.
pub(super) fn bound_traceback(tb: &str) -> String {
    // `CallbackError` tracebacks embed their own label; the stored form is
    // frames only, and renderers add the label exactly once.
    let tb = tb
        .trim_start_matches('\n')
        .trim_start_matches("stack traceback:")
        .trim_matches('\n');
    let mut lines = tb.lines();
    let kept: Vec<&str> = lines.by_ref().take(MAX_TRACEBACK_LINES).collect();
    let elided = lines.count();
    if elided == 0 {
        kept.join("\n")
    } else {
        format!("{}\n\t(... {elided} more)", kept.join("\n"))
    }
}
