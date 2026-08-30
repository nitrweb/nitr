// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr hash-password`: print an argon2id hash for a credential, so an
//! operator can seed a config file or a users table without writing a
//! throwaway Lua script.
//!
//! There is deliberately **no** `--password` flag. A password in argv is
//! readable by every process on the box through `/proc/<pid>/cmdline` (and
//! `ps`), and the shell writes it to the history file afterwards — two
//! places a credential outlives the command that used it, neither of them
//! obvious at the moment of typing. A terminal prompt covers the
//! interactive case and a pipe covers the scripted one:
//!
//! ```sh
//! nitr hash-password                        # prompts, echo off, confirms
//! printf %s "$NEW_PASSWORD" | nitr hash-password
//! ```

use std::io::{IsTerminal as _, Read as _, Write as _};

use anyhow::{Context as _, bail};

/// Reads a password (prompt or stdin) and prints its argon2id hash.
pub(crate) async fn hash_password() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let password = if stdin.is_terminal() {
        let password = prompt("Password")?;
        // A typo here becomes a credential nobody can ever use, and the
        // only symptom is a login that always fails. Cheap to prevent.
        if prompt("Confirm password")? != password {
            bail!("the passwords do not match");
        }
        password
    } else {
        let mut raw = String::new();
        stdin
            .lock()
            .read_to_string(&mut raw)
            .context("cannot read the password from stdin")?;
        strip_eol(raw)
    };

    if password.is_empty() {
        bail!(
            "refusing to hash an empty password: pipe the password in \
             (`printf %s \"$PW\" | nitr hash-password`) or run this on a \
             terminal to be prompted"
        );
    }

    // The hash alone on stdout, so `nitr hash-password > hash.txt` and
    // `$(nitr hash-password)` both give exactly the storable string.
    println!("{}", argon2id(&password).await?);
    Ok(())
}

/// Removes the line ending the shell added, and nothing else.
///
/// `echo hunter2 | nitr hash-password` must not hash `"hunter2\n"` — that
/// hash would never verify. Only one trailing `\n` (with its optional
/// `\r`) goes: a password may legitimately end in a space or a tab, and
/// trimming those would silently produce the same unverifiable hash.
fn strip_eol(mut raw: String) -> String {
    if raw.ends_with('\n') {
        raw.pop();
        if raw.ends_with('\r') {
            raw.pop();
        }
    }
    raw
}

/// Prompts on stderr and reads one line, with terminal echo off.
///
/// The prompt goes to stderr rather than through `tracing`: it is
/// interactive UI, not a diagnostic — it must appear whatever the log
/// level is, must not be timestamped or shipped to a log collector, and
/// must stay out of the stdout the caller is capturing.
fn prompt(label: &str) -> anyhow::Result<String> {
    let echo = EchoOff::new();
    eprint!("{label}: ");
    if echo.is_visible() {
        eprint!("(warning: this terminal is echoing) ");
    }
    std::io::stderr().flush().ok();

    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    let visible = echo.is_visible();
    drop(echo);
    // With echo off the terminal never printed the user's Enter, so the
    // cursor is still on the prompt line.
    if !visible {
        eprintln!();
    }
    read.context("cannot read the password from the terminal")?;
    Ok(strip_eol(line))
}

/// Turns terminal echo off while it is alive, and back on when dropped —
/// including on the error path, so a failed read cannot leave the
/// operator's shell silently swallowing input.
///
/// The one path this cannot cover is Ctrl-C at the prompt: SIGINT's
/// default handler kills the process before any `Drop` runs, leaving the
/// terminal with echo off until `stty echo` or `reset`. Catching the
/// signal would need a handler crate or `unsafe`, and the workspace
/// forbids the latter; an annoyance with a well-known shell remedy does
/// not justify the former.
///
/// Echo is toggled by running `stty`, not by calling `tcsetattr`: the
/// workspace forbids `unsafe`, so the libc call is unavailable, and one
/// terminal flag does not justify a dependency. `nitr reload` sends its
/// signal through `kill` for the same reason. Where `stty` is missing
/// (or on a non-Unix host) the password is read with echo on and the
/// prompt says so — visibly degraded beats refusing to run.
struct EchoOff {
    disabled: bool,
}

impl EchoOff {
    fn new() -> Self {
        Self {
            disabled: set_echo(false),
        }
    }

    /// Whether the password will appear on screen as it is typed.
    fn is_visible(&self) -> bool {
        !self.disabled
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        if self.disabled {
            set_echo(true);
        }
    }
}

/// `stty` acts on its own controlling terminal, which it inherits from
/// this process.
#[cfg(unix)]
fn set_echo(on: bool) -> bool {
    std::process::Command::new("stty")
        .arg(if on { "echo" } else { "-echo" })
        .stdin(std::process::Stdio::inherit())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(not(unix))]
fn set_echo(_on: bool) -> bool {
    false
}

/// Hashes through the very `nitr.crypto.password_hash` a handler calls,
/// rather than reaching for argon2 again here.
///
/// The parameters (argon2id, m=19456, t=2, p=1) then have exactly one
/// definition in the workspace, so a credential minted by this command
/// cannot drift from what the running server verifies. On a build without
/// the `crypto` feature the builtin registration is what fails, with the
/// error that already names the Cargo feature to enable.
async fn argon2id(password: &str) -> anyhow::Result<String> {
    let lua = mlua::Lua::new();
    nitr::stdlib::register_builtins(&lua, nitr::Builtins::CRYPTO, &nitr::BuiltinsEnv::default())
        .context("`nitr hash-password` needs argon2, which this build does not have")?;
    let crypto: mlua::Table = lua
        .globals()
        .get::<mlua::Table>("nitr")
        .context("the nitr namespace")?
        .get("crypto")
        .context("the nitr.crypto table")?;
    let hash: mlua::Function = crypto.get("password_hash").context("password_hash")?;
    let password = lua.create_string(password)?;
    // Awaited rather than driven on a runtime of its own: `password_hash`
    // offloads the argon2 work to `spawn_blocking` and is therefore async,
    // and `main` is already `#[tokio::main]` — building a second runtime
    // here panics with "cannot start a runtime from within a runtime".
    Ok(hash.call_async::<String>(password).await?)
}

#[cfg(test)]
mod tests {
    use super::strip_eol;

    #[test]
    fn only_the_shells_line_ending_is_removed() {
        assert_eq!(strip_eol("hunter2\n".into()), "hunter2");
        assert_eq!(strip_eol("hunter2\r\n".into()), "hunter2");
        assert_eq!(strip_eol("hunter2".into()), "hunter2");
        // A trailing space is part of the password, not whitespace to tidy
        // away: trimming it would mint a hash that never verifies.
        assert_eq!(strip_eol("hunter2 \n".into()), "hunter2 ");
        assert_eq!(strip_eol("hunter2\t".into()), "hunter2\t");
        // Only one line ending: an embedded newline is the password's.
        assert_eq!(strip_eol("a\nb\n".into()), "a\nb");
        assert_eq!(strip_eol("\n".into()), "");
        assert_eq!(strip_eol(String::new()), "");
    }
}
