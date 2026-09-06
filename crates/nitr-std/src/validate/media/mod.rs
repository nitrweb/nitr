// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The media types a `file` rule can name, and how each is established
//! from an upload's first bytes: a signature (authoritative over the
//! declared header), the text sniffer (then the declared subtype is
//! trusted), or the header alone. Executables are a family that never
//! matches.
//!
//! [`types`] is the table, [`sniff`] the detection, [`dimensions`] the
//! header-only image readers.

use mlua::{Lua, Table};

mod dimensions;
mod sniff;
#[cfg(test)]
mod tests;
mod types;

pub use dimensions::dimensions;
pub use sniff::{detect, is_text, text_subtype_matches};
pub use types::MEDIA_TYPES;

use super::TypePattern;

/// The type reported when nothing is known: the declared header when it
/// names nothing detectable, else this.
pub(crate) const UNKNOWN_TYPE: &str = "application/octet-stream";

/// The type reported for the executable family.
pub(crate) const EXECUTABLE_TYPE: &str = "application/x-executable";

/// How many bytes detection reads.
pub const SNIFF_BYTES: usize = 64 * 1024;

/// A family of media types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Raster images.
    Image,
    /// SVG: text that is also active content.
    Vector,
    /// PDF and office documents.
    Document,
    /// Plain and structured text.
    Text,
    /// Compressed containers.
    Archive,
    /// Audio.
    Audio,
    /// Video.
    Video,
    /// Fonts.
    Font,
    /// Machine data formats.
    Data,
    /// `application/octet-stream`.
    Generic,
}

impl Family {
    fn name(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Vector => "vector",
            Self::Document => "document",
            Self::Text => "text",
            Self::Archive => "archive",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Font => "font",
            Self::Data => "data",
            Self::Generic => "generic",
        }
    }
}

/// How a type is established for a part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// A signature in the prefix; the declared header is ignored.
    Detected,
    /// The prefix passes the text sniffer; the declared subtype is trusted.
    Text,
    /// Header only.
    Header,
}

impl Tier {
    fn name(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::Text => "text",
            Self::Header => "header",
        }
    }
}

/// One entry of the media-type table.
#[derive(Debug)]
pub struct MediaType {
    /// The media type name (`image/png`).
    pub name: &'static str,
    /// Extensions this type is known by, lowercase, without the dot.
    pub extensions: &'static [&'static str],
    /// The family, for `type/*` patterns and the presets.
    pub family: Family,
    /// How it is established.
    pub tier: Tier,
    /// The short name in messages (`a PDF`, `an image`).
    pub short: &'static str,
    /// Whether a dimension reader exists for it.
    dims: bool,
}

impl MediaType {
    /// Whether the header carries readable image dimensions.
    pub fn has_dimensions(&self) -> bool {
        self.dims
    }
}

/// Entries are compared by name: the table holds each once.
impl PartialEq for MediaType {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for MediaType {}

/// What the prefix of an upload says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detection {
    /// A known signature.
    Detected(&'static MediaType),
    /// Looks like UTF-8 text.
    Text,
    /// An executable format: refused by every `types` list by default.
    Executable,
    /// Nothing recognizable.
    Unknown,
}

/// Looks a media type up by name.
pub fn lookup(name: &str) -> Option<&'static MediaType> {
    MEDIA_TYPES.iter().find(|m| m.name == name)
}

/// The family a type name belongs to (`image` for `image/png`).
fn family_name(name: &str) -> &str {
    name.split('/').next().unwrap_or(name)
}

/// Whether an extension is one this type is known by.
pub(crate) fn extension_matches(media: &MediaType, ext: &str) -> bool {
    media.extensions.contains(&ext)
}

/// Whether a filename extension marks an executable regardless of bytes.
pub fn executable_extension(ext: &str) -> bool {
    types::SCRIPT_EXTENSIONS.contains(&ext)
}

/// The phrase for a `types` list in a message: the family's short name
/// when the list is one family, the short names otherwise.
pub(crate) fn describe_types(patterns: &[TypePattern]) -> String {
    // Several exact types of one family read as that family with their
    // extensions: "an image (png, jpg, gif, webp)".
    let families: Vec<&str> = patterns
        .iter()
        .filter_map(|p| match p {
            TypePattern::Exact(name) => Some(family_name(name)),
            _ => None,
        })
        .collect();
    if families.len() > 1
        && families.len() == patterns.len()
        && families.iter().all(|f| *f == families[0])
    {
        let exts: Vec<&str> = patterns
            .iter()
            .filter_map(|p| match p {
                TypePattern::Exact(name) => {
                    lookup(name).and_then(|m| m.extensions.first().copied())
                }
                _ => None,
            })
            .collect();
        let family = families[0];
        let article = if family.starts_with(['a', 'e', 'i', 'o', 'u']) {
            "an"
        } else {
            "a"
        };
        return format!("{article} {family} ({})", exts.join(", "));
    }
    let mut parts = Vec::new();
    for pattern in patterns {
        parts.push(match pattern {
            TypePattern::Any => "any file".to_string(),
            TypePattern::Family(f) => {
                let exts: Vec<&str> = MEDIA_TYPES
                    .iter()
                    .filter(|m| family_name(m.name) == f && !m.extensions.is_empty())
                    .map(|m| m.extensions[0])
                    .collect();
                let article = if f.starts_with(['a', 'e', 'i', 'o', 'u']) {
                    "an"
                } else {
                    "a"
                };
                if exts.is_empty() {
                    format!("{article} {f} file")
                } else {
                    format!("{article} {f} ({})", exts.join(", "))
                }
            }
            TypePattern::Exact(name) => lookup(name)
                .map(|m| m.short.to_string())
                .unwrap_or_else(|| name.clone()),
        });
    }
    match parts.len() {
        0 => "a file".into(),
        1 => parts.remove(0),
        _ => {
            let last = parts.pop().unwrap_or_default();
            format!("{} or {last}", parts.join(", "))
        }
    }
}

/// `nitr.validate.media_types()`: the table as data.
pub(crate) fn media_types_table(lua: &Lua) -> mlua::Result<Table> {
    let out = lua.create_table()?;
    for media in MEDIA_TYPES {
        let entry = lua.create_table()?;
        entry.set(
            "extensions",
            lua.create_sequence_from(media.extensions.iter().copied())?,
        )?;
        entry.set("family", media.family.name())?;
        entry.set("tier", media.tier.name())?;
        entry.set("dimensions", media.dims)?;
        out.set(media.name, entry)?;
    }
    Ok(out)
}
