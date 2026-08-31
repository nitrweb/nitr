// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::info::{LUA_YIELD_OUTSIDE, MAX_TRACEBACK_LINES, bound_traceback, parse_position};
use super::*;

#[test]
fn positions_parse_including_windows_drive_paths() {
    let (src, line, msg) = parse_position("app.lua:42: attempt to index a nil value");
    assert_eq!(src, Some("app.lua"));
    assert_eq!(line, Some(42));
    assert_eq!(msg, "attempt to index a nil value");

    // The drive-letter colon must not terminate the source scan.
    let (src, line, msg) = parse_position(r"C:\Users\me\app.lua:7: boom");
    assert_eq!(src, Some(r"C:\Users\me\app.lua"));
    assert_eq!(line, Some(7));
    assert_eq!(msg, "boom");

    let (src, line, msg) = parse_position("no position here");
    assert_eq!((src, line), (None, None));
    assert_eq!(msg, "no position here");
}

#[test]
fn tracebacks_are_bounded() {
    let deep: String = (0..40).map(|i| format!("\n\tframe {i}")).collect();
    let bounded = bound_traceback(&deep);
    assert_eq!(bounded.lines().count(), MAX_TRACEBACK_LINES + 1);
    assert!(bounded.ends_with("more)"), "got: {bounded}");

    let shallow = "\n\tframe 0\n\tframe 1";
    assert_eq!(bound_traceback(shallow), "\tframe 0\n\tframe 1");
}

/// The VM's `attempt to yield from outside a coroutine` is replaced
/// with an explanation that names the builtin, the reason and the
/// remedy — the migration surface for every async builtin, not just
/// the argon2 ones that made it reachable.
#[test]
fn a_yield_outside_a_coroutine_names_the_builtin_and_the_remedy() {
    let err = Error::Lua(mlua::Error::RuntimeError(format!(
        "app.lua:3: {LUA_YIELD_OUTSIDE}\nstack traceback:\n\t[C]: in ?\n\t\
         [C]: in function 'coroutine.yield'\n\t[string \"?\"]:28: in field \
         'password_hash'\n\tapp.lua:3: in main chunk"
    )));
    let info = ErrorInfo::from_error(&err);

    assert_eq!(info.kind, "nitr", "not the script author's bug");
    assert!(
        !info.message.contains(LUA_YIELD_OUTSIDE),
        "the raw VM wording must not survive: {}",
        info.message
    );
    // The frame below `coroutine.yield` names the call, and the name is
    // used bare: the traceback knows the field, not the table it hung
    // off, so `nitr.crypto.password_hash` cannot be reconstructed.
    assert!(
        info.message.starts_with("`password_hash`"),
        "{}",
        info.message
    );
    assert!(
        !info.message.contains("nitr.password_hash"),
        "{}",
        info.message
    );
    for expected in ["asynchronous", "top level", "handler", "nitr hash-password"] {
        assert!(
            info.message.contains(expected),
            "missing `{expected}`: {}",
            info.message
        );
    }
    // Position and traceback survive the rewrite.
    assert_eq!(info.source.as_deref(), Some("app.lua"));
    assert_eq!(info.line, Some(3));

    // With the naming frame gone (a truncated traceback, or a shape
    // change in a future mlua) the explanation still lands, generically
    // rather than by guessing a name.
    let err = Error::Lua(mlua::Error::RuntimeError(format!(
        "app.lua:3: {LUA_YIELD_OUTSIDE}"
    )));
    let info = ErrorInfo::from_error(&err);
    assert!(info.message.starts_with("this builtin"), "{}", info.message);
    assert!(info.message.contains("asynchronous"), "{}", info.message);
}

/// Only the trampoline's own frame may name the builtin. An aliased
/// call is named by its alias — the name the script knows it by — and
/// when that frame carries no name at all, the explanation stays
/// generic instead of blaming the nearest named *caller* for being
/// asynchronous.
#[test]
fn an_async_callee_comes_from_the_trampoline_frame_never_a_caller() {
    // `local h = nitr.crypto.password_hash` called inside `helper`:
    // the trampoline frame reads `in local 'h'`.
    let err = Error::Lua(mlua::Error::RuntimeError(format!(
        "app.lua:2: {LUA_YIELD_OUTSIDE}\nstack traceback:\n\t\
         [C]: in function 'coroutine.yield'\n\t\
         [string \"?\"]:28: in local 'h'\n\t\
         app.lua:2: in function 'helper'\n\tapp.lua:8: in main chunk"
    )));
    let info = ErrorInfo::from_error(&err);
    assert!(info.message.starts_with("`h`"), "{}", info.message);

    // An anonymous trampoline frame: `helper` below it called the
    // builtin, it is not the builtin, and must not be named.
    let err = Error::Lua(mlua::Error::RuntimeError(format!(
        "app.lua:2: {LUA_YIELD_OUTSIDE}\nstack traceback:\n\t\
         [C]: in function 'coroutine.yield'\n\t\
         [string \"?\"]:28: in function <[string \"?\"]:1>\n\t\
         app.lua:2: in function 'helper'\n\tapp.lua:8: in main chunk"
    )));
    let info = ErrorInfo::from_error(&err);
    assert!(info.message.starts_with("this builtin"), "{}", info.message);
    assert!(!info.message.contains("helper"), "{}", info.message);
}

/// A script that raises the VM's own wording through `error()` is a
/// script error like any other: its traceback shows the `error` call,
/// not a yield, so the message is left alone and the kind stays the
/// script author's.
#[test]
fn a_raised_lookalike_is_not_rewritten() {
    let err = Error::Lua(mlua::Error::RuntimeError(format!(
        "app.lua:7: {LUA_YIELD_OUTSIDE}\nstack traceback:\n\t\
         [C]: in function 'error'\n\tapp.lua:7: in main chunk"
    )));
    let info = ErrorInfo::from_error(&err);
    assert_eq!(info.kind, "lua", "a raised string is the script's own");
    assert_eq!(info.message, LUA_YIELD_OUTSIDE);
}

#[test]
fn lua_runtime_errors_classify_with_position_and_traceback() {
    let err = Error::Lua(mlua::Error::RuntimeError(
        "app.lua:5: oops\nstack traceback:\n\tapp.lua:5: in main chunk".into(),
    ));
    let info = ErrorInfo::from_error(&err);
    assert_eq!(info.kind, "lua");
    assert_eq!(info.message, "oops");
    assert_eq!(info.source.as_deref(), Some("app.lua"));
    assert_eq!(info.line, Some(5));
    assert!(info.traceback.is_some());
    assert_eq!(info.concise(), "lua: oops (app.lua:5)");
}

#[test]
fn callback_errors_classify_as_nitr_with_module_tags() {
    let cause = mlua::Error::WithContext {
        context: "nitr.db: query failed".into(),
        cause: std::sync::Arc::new(mlua::Error::RuntimeError("locked".into())),
    };
    let err = Error::Lua(mlua::Error::CallbackError {
        traceback: "\n\t[C]: in function 'query'".into(),
        cause: std::sync::Arc::new(cause),
    });
    let info = ErrorInfo::from_error(&err);
    assert_eq!(info.kind, "nitr");
    assert_eq!(info.module.as_deref(), Some("nitr.db"));
    assert!(info.traceback.is_some());
}

#[test]
fn module_context_classifies_as_module() {
    let cause = mlua::Error::WithContext {
        context: "module greet".into(),
        cause: std::sync::Arc::new(mlua::Error::RuntimeError("broke".into())),
    };
    let err = Error::Lua(mlua::Error::CallbackError {
        traceback: String::new(),
        cause: std::sync::Arc::new(cause),
    });
    let info = ErrorInfo::from_error(&err);
    assert_eq!(info.kind, "module");
    assert_eq!(info.module.as_deref(), Some("greet"));
}

#[test]
fn budget_and_memory_and_timeout_kinds() {
    assert_eq!(ErrorInfo::from_error(&Error::Timeout).kind, "timeout");
    let hook = Error::Lua(mlua::Error::RuntimeError(format!(
        "app.lua:3: {EXEC_BUDGET_MSG}\nstack traceback:\n\tapp.lua:3:"
    )));
    assert_eq!(ErrorInfo::from_error(&hook).kind, "timeout");
    let mem = Error::Lua(mlua::Error::MemoryError("not enough memory".into()));
    assert_eq!(ErrorInfo::from_error(&mem).kind, "memory");
    assert_eq!(
        ErrorInfo::from_error(&Error::Panic("boom".into())).kind,
        "panic"
    );
}

#[test]
fn rust_errors_take_their_position_from_the_first_lua_frame() {
    let err = Error::Lua(mlua::Error::CallbackError {
        traceback: "stack traceback:\n\t[C]: in field 'fetch'\n\tscripts/config.lua:21: in function <scripts/config.lua:20>".into(),
        cause: std::sync::Arc::new(mlua::Error::RuntimeError(
            "relative URL without a base".into(),
        )),
    });
    let info = ErrorInfo::from_error(&err);
    assert_eq!(info.kind, "nitr");
    assert_eq!(info.source.as_deref(), Some("scripts/config.lua"));
    assert_eq!(info.line, Some(21));
    assert_eq!(
        info.concise(),
        "nitr: relative URL without a base (scripts/config.lua:21)"
    );
    // The embedded label is normalized away: renderers add it once.
    assert!(
        !info
            .traceback
            .as_deref()
            .expect("tb")
            .contains("stack traceback:"),
        "got: {:?}",
        info.traceback
    );
}

#[test]
fn anonymous_chunks_never_supply_a_position() {
    // mlua's async trampoline reports itself as `[string "?"]`; its
    // line numbers belong to an internal chunk, not the user's file.
    let err = Error::Lua(mlua::Error::CallbackError {
        traceback: "stack traceback:\n\t[C]: in local 'poll'\n\t[string \"?\"]:4: in method 'query'\n\tscripts/config.lua:15: in function <scripts/config.lua:5>".into(),
        cause: std::sync::Arc::new(mlua::Error::RuntimeError(
            "error converting Lua integer to table".into(),
        )),
    });
    let info = ErrorInfo::from_error(&err);
    assert_eq!(info.source.as_deref(), Some("scripts/config.lua"));
    assert_eq!(info.line, Some(15));
}

#[test]
fn plain_messages_classify_via_from_message() {
    let info = ErrorInfo::from_message(
        "scripts/config.lua:21: attempt to call a nil value (field 'fetcah')",
    );
    assert_eq!(info.kind, "lua");
    assert_eq!(info.source.as_deref(), Some("scripts/config.lua"));
    assert_eq!(info.line, Some(21));
    assert!(info.message.starts_with("attempt to call"));
}

#[test]
fn message_tokens_come_from_near_or_quoted_symbols() {
    assert_eq!(message_token("syntax error near 'users'"), Some("users"));
    assert_eq!(
        message_token("attempt to call a nil value (method 'eexecute')"),
        Some("eexecute")
    );
    assert_eq!(message_token("unexpected symbol near <eof>"), None);
    assert_eq!(message_token("no symbol here"), None);
}

#[test]
fn snippets_render_the_marked_line() {
    let dir = std::env::temp_dir().join(format!("nitr-snippet-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("snip.lua");
    std::fs::write(&path, "line one\nline two\nline three\n").expect("write");
    let snippet = source_snippet(&path, 2, 1, None).expect("snippet");
    assert!(snippet.contains("2 | line two"), "got: {snippet}");
    assert!(snippet.contains("| ^"), "got: {snippet}");
    // A token from the parse error positions the caret under it.
    let snippet = source_snippet(&path, 2, 1, Some("two")).expect("snippet");
    assert!(snippet.contains("|      ^^^"), "got: {snippet}");
    assert!(source_snippet(&path, 99, 1, None).is_none());
    std::fs::remove_file(&path).ok();
}
