// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

mod parse;
mod tls;
mod validate;

use super::*;

fn write_temp_config(name: &str, content: &str) -> PathBuf {
    // `fs::write` truncates before writing, so a path two tests share is
    // a race; the counter keeps every call on its own file.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("nitr-test-{}-{id}-{name}", std::process::id()));
    std::fs::write(&path, content).expect("write temp config");
    path
}

/// A config whose paths exist, so `validate()` reaches the check under
/// test instead of failing on a missing default handler script.
fn valid_base() -> Config {
    let handler = write_temp_config("handler.lua", "-- test handler");
    Config {
        handler_script: handler,
        ..Config::default()
    }
}
