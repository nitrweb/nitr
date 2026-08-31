// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Typed error and result types for the Nitr library.

/// Errors returned by the Nitr library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error raised by the Lua runtime or a script.
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),

    /// An invalid or missing configuration value.
    #[error("configuration error: {0}")]
    Config(String),

    /// A script file could not be loaded or evaluated.
    #[error("script error: {0}")]
    Script(String),

    /// An I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// An HTTP protocol error.
    #[error("http error: {0}")]
    Http(#[from] http::Error),

    /// The handler exceeded its execution budget.
    #[error("handler execution timed out")]
    Timeout,

    /// No Lua state became available within the pool wait budget; the
    /// request is shed rather than queued indefinitely.
    #[error("no Lua state available within the pool wait budget")]
    PoolBusy,

    /// A panic was caught while running a request. The state that was in
    /// use is recycled; this is always a bug in Rust code (Nitr's or an
    /// extension module's), never in a Lua script.
    #[error("panic while handling the request: {0}")]
    Panic(String),

    /// The graceful-shutdown drain deadline expired with connections still
    /// in flight, so they were aborted. Surfaced rather than swallowed: a
    /// truncated shutdown means a client's request was cut.
    #[error("shutdown drain deadline expired with requests still in flight")]
    ShutdownTimeout,
}

impl Error {
    /// Whether this error leaves the Lua state unfit for reuse.
    ///
    /// A memory-limit hit is the clear case: the allocator refused, the
    /// state's heap sits at its ceiling, and the next request would inherit
    /// the problem. Ordinary script errors are *not* damage — Lua unwinds
    /// cleanly and the state is fine.
    pub fn poisons_state(&self) -> bool {
        match self {
            Error::Panic(_) => true,
            Error::Lua(err) => is_memory_error(err),
            _ => false,
        }
    }
}

/// Walks an mlua error chain looking for a memory error, which can be
/// wrapped in `CallbackError`/`WithContext` layers by the time it surfaces.
fn is_memory_error(err: &mlua::Error) -> bool {
    match err {
        mlua::Error::MemoryError(_) => true,
        mlua::Error::CallbackError { cause, .. } => is_memory_error(cause),
        mlua::Error::WithContext { cause, .. } => is_memory_error(cause),
        _ => false,
    }
}

/// Result type alias used across the Nitr library.
pub type Result<T = (), E = Error> = std::result::Result<T, E>;

mod info;
mod render;
#[cfg(test)]
mod tests;

pub(crate) use info::EXEC_BUDGET_MSG;
pub use info::ErrorInfo;
pub use render::{message_token, source_snippet};
