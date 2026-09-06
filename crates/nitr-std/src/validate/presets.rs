// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! File-rule presets: the common cases as one word, each a plain rule
//! table a developer can print, copy and edit, with every key
//! overridable through the options argument.

use mlua::{Lua, Table, Value};

use super::media::{self, Family};

/// One preset: the families or exact types it names, and its defaults.
struct Preset {
    name: &'static str,
    /// Exact media types (extensions follow from the table).
    types: &'static [&'static str],
    max_bytes: &'static str,
    max_pixels: Option<i64>,
    utf8: bool,
}

const PRESETS: &[Preset] = &[
    Preset {
        name: "image",
        // Only types with a header dimension reader: `max_pixels` is
        // the preset's bomb guard, and it cannot guard what it cannot
        // read (add `image/avif` explicitly, without dimension rules).
        types: &[
            "image/png",
            "image/jpeg",
            "image/gif",
            "image/webp",
            "image/bmp",
        ],
        max_bytes: "5mb",
        max_pixels: Some(25_000_000),
        utf8: false,
    },
    Preset {
        name: "document",
        types: &[
            "application/pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/vnd.oasis.opendocument.text",
            "application/vnd.oasis.opendocument.spreadsheet",
            "application/vnd.oasis.opendocument.presentation",
            "application/rtf",
        ],
        max_bytes: "20mb",
        max_pixels: None,
        utf8: false,
    },
    Preset {
        name: "spreadsheet",
        types: &[
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.oasis.opendocument.spreadsheet",
            "text/csv",
        ],
        max_bytes: "20mb",
        max_pixels: None,
        utf8: false,
    },
    Preset {
        name: "text_file",
        types: &[
            "text/plain",
            "text/csv",
            "text/markdown",
            "application/json",
            "application/xml",
            "application/yaml",
        ],
        max_bytes: "1mb",
        max_pixels: None,
        utf8: true,
    },
    Preset {
        name: "archive",
        types: &[
            "application/zip",
            "application/gzip",
            "application/x-tar",
            "application/x-bzip2",
            "application/x-xz",
            "application/zstd",
            "application/x-7z-compressed",
        ],
        max_bytes: "50mb",
        max_pixels: None,
        utf8: false,
    },
    Preset {
        name: "audio",
        types: &[
            "audio/mpeg",
            "audio/wav",
            "audio/ogg",
            "audio/flac",
            "audio/mp4",
        ],
        max_bytes: "50mb",
        max_pixels: None,
        utf8: false,
    },
    Preset {
        name: "video",
        types: &[
            "video/mp4",
            "video/quicktime",
            "video/webm",
            "video/x-matroska",
        ],
        max_bytes: "500mb",
        max_pixels: None,
        utf8: false,
    },
    Preset {
        name: "font",
        types: &["font/woff", "font/woff2", "font/ttf", "font/otf"],
        max_bytes: "5mb",
        max_pixels: None,
        utf8: false,
    },
];

/// Builds the rule table for a preset, then overlays the caller's options.
fn expand(lua: &Lua, preset: &Preset, opts: Option<Table>) -> mlua::Result<Table> {
    let rule = lua.create_table()?;
    rule.set("type", "file")?;
    rule.set(
        "types",
        lua.create_sequence_from(preset.types.iter().copied())?,
    )?;
    let mut extensions: Vec<&str> = Vec::new();
    for name in preset.types {
        if let Some(media) = media::lookup(name) {
            for ext in media.extensions {
                if !extensions.contains(ext) {
                    extensions.push(ext);
                }
            }
        }
    }
    rule.set("extensions", lua.create_sequence_from(extensions)?)?;
    rule.set("max_bytes", preset.max_bytes)?;
    if let Some(max_pixels) = preset.max_pixels {
        rule.set("max_pixels", max_pixels)?;
    }
    if preset.utf8 {
        rule.set("utf8", true)?;
    }
    overlay(&rule, opts)?;
    Ok(rule)
}

fn overlay(rule: &Table, opts: Option<Table>) -> mlua::Result<()> {
    if let Some(opts) = opts {
        for pair in opts.pairs::<Value, Value>() {
            let (key, value) = pair?;
            rule.set(key, value)?;
        }
    }
    Ok(())
}

/// Mounts the presets on `nitr.validate`.
pub(super) fn register(lua: &Lua, validate: &Table) -> mlua::Result<()> {
    for preset in PRESETS {
        validate.set(
            preset.name,
            lua.create_function(move |lua, opts: Option<Table>| expand(lua, preset, opts))?,
        )?;
    }
    // any_file: `*/*`, no extensions, `max_bytes` required from the caller.
    validate.set(
        "any_file",
        lua.create_function(|lua, opts: Option<Table>| {
            let rule = lua.create_table()?;
            rule.set("type", "file")?;
            rule.set("types", lua.create_sequence_from(["*/*"])?)?;
            let has_max = opts
                .as_ref()
                .map(|o| o.get::<Value>("max_bytes"))
                .transpose()?
                .is_some_and(|v| !v.is_nil());
            if !has_max {
                return Err(mlua::Error::RuntimeError(
                    "nitr.validate.any_file() needs `max_bytes` in its options".into(),
                ));
            }
            overlay(&rule, opts)?;
            Ok(rule)
        })?,
    )?;
    let _ = Family::Generic;
    Ok(())
}
