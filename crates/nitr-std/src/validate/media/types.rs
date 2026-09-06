// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The media-type table: every type a `types` list may name, its
//! extensions, family, tier and message noun.

use super::{Family, MediaType, Tier};

macro_rules! media {
    ($name:literal, [$($ext:literal),*], $family:ident, $tier:ident, $short:literal $(, dims = $dims:literal)?) => {
        MediaType {
            name: $name,
            extensions: &[$($ext),*],
            family: Family::$family,
            tier: Tier::$tier,
            short: $short,
            dims: false $(|| $dims)?,
        }
    };
}

/// Every type a `types` list may name.
pub const MEDIA_TYPES: &[MediaType] = &[
    media!(
        "image/png",
        ["png"],
        Image,
        Detected,
        "a PNG image",
        dims = true
    ),
    media!(
        "image/jpeg",
        ["jpg", "jpeg"],
        Image,
        Detected,
        "a JPEG image",
        dims = true
    ),
    media!(
        "image/gif",
        ["gif"],
        Image,
        Detected,
        "a GIF image",
        dims = true
    ),
    media!(
        "image/webp",
        ["webp"],
        Image,
        Detected,
        "a WebP image",
        dims = true
    ),
    media!(
        "image/bmp",
        ["bmp"],
        Image,
        Detected,
        "a BMP image",
        dims = true
    ),
    media!(
        "image/tiff",
        ["tif", "tiff"],
        Image,
        Detected,
        "a TIFF image",
        dims = true
    ),
    media!("image/x-icon", ["ico"], Image, Detected, "an icon"),
    media!("image/avif", ["avif"], Image, Detected, "an AVIF image"),
    media!(
        "image/heic",
        ["heic", "heif"],
        Image,
        Detected,
        "a HEIC image"
    ),
    media!("image/svg+xml", ["svg"], Vector, Text, "an SVG image"),
    media!("application/pdf", ["pdf"], Document, Detected, "a PDF"),
    media!(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ["docx"],
        Document,
        Detected,
        "a Word document"
    ),
    media!(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ["xlsx"],
        Document,
        Detected,
        "an Excel workbook"
    ),
    media!(
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ["pptx"],
        Document,
        Detected,
        "a PowerPoint presentation"
    ),
    media!(
        "application/vnd.oasis.opendocument.text",
        ["odt"],
        Document,
        Detected,
        "an OpenDocument text"
    ),
    media!(
        "application/vnd.oasis.opendocument.spreadsheet",
        ["ods"],
        Document,
        Detected,
        "an OpenDocument spreadsheet"
    ),
    media!(
        "application/vnd.oasis.opendocument.presentation",
        ["odp"],
        Document,
        Detected,
        "an OpenDocument presentation"
    ),
    media!(
        "application/epub+zip",
        ["epub"],
        Document,
        Detected,
        "an EPUB"
    ),
    media!(
        "application/msword",
        ["doc"],
        Document,
        Detected,
        "a legacy Word document"
    ),
    media!(
        "application/vnd.ms-excel",
        ["xls"],
        Document,
        Detected,
        "a legacy Excel workbook"
    ),
    media!(
        "application/vnd.ms-powerpoint",
        ["ppt"],
        Document,
        Detected,
        "a legacy PowerPoint presentation"
    ),
    media!(
        "application/rtf",
        ["rtf"],
        Document,
        Detected,
        "an RTF document"
    ),
    media!("text/plain", ["txt"], Text, Text, "a text file"),
    media!("text/csv", ["csv"], Text, Text, "a CSV file"),
    media!("text/markdown", ["md"], Text, Text, "a Markdown file"),
    media!("text/html", ["html", "htm"], Text, Text, "an HTML file"),
    media!("text/css", ["css"], Text, Text, "a CSS file"),
    media!("application/json", ["json"], Text, Text, "a JSON file"),
    media!("application/xml", ["xml"], Text, Text, "an XML file"),
    media!("text/xml", ["xml"], Text, Text, "an XML file"),
    media!(
        "application/yaml",
        ["yaml", "yml"],
        Text,
        Text,
        "a YAML file"
    ),
    media!("text/calendar", ["ics"], Text, Text, "a calendar file"),
    media!("text/vcard", ["vcf"], Text, Text, "a vCard"),
    media!(
        "application/x-ndjson",
        ["ndjson", "jsonl"],
        Data,
        Text,
        "a newline-delimited JSON file"
    ),
    media!(
        "application/zip",
        ["zip"],
        Archive,
        Detected,
        "a ZIP archive"
    ),
    media!(
        "application/gzip",
        ["gz", "tgz", "tar.gz"],
        Archive,
        Detected,
        "a gzip archive"
    ),
    media!(
        "application/x-tar",
        ["tar"],
        Archive,
        Detected,
        "a tar archive"
    ),
    media!(
        "application/x-bzip2",
        ["bz2"],
        Archive,
        Detected,
        "a bzip2 archive"
    ),
    media!(
        "application/x-xz",
        ["xz"],
        Archive,
        Detected,
        "an xz archive"
    ),
    media!(
        "application/zstd",
        ["zst"],
        Archive,
        Detected,
        "a zstd archive"
    ),
    media!(
        "application/x-7z-compressed",
        ["7z"],
        Archive,
        Detected,
        "a 7z archive"
    ),
    media!(
        "application/vnd.rar",
        ["rar"],
        Archive,
        Detected,
        "a RAR archive"
    ),
    media!("audio/mpeg", ["mp3"], Audio, Detected, "an MP3 file"),
    media!("audio/wav", ["wav"], Audio, Detected, "a WAV file"),
    media!(
        "audio/ogg",
        ["ogg", "oga", "opus"],
        Audio,
        Detected,
        "an Ogg audio file"
    ),
    media!("audio/flac", ["flac"], Audio, Detected, "a FLAC file"),
    media!("audio/mp4", ["m4a"], Audio, Detected, "an M4A file"),
    media!("audio/aac", ["aac"], Audio, Detected, "an AAC file"),
    media!("video/mp4", ["mp4", "m4v"], Video, Detected, "an MP4 video"),
    media!(
        "video/quicktime",
        ["mov"],
        Video,
        Detected,
        "a QuickTime video"
    ),
    media!("video/webm", ["webm"], Video, Detected, "a WebM video"),
    media!(
        "video/x-matroska",
        ["mkv"],
        Video,
        Detected,
        "a Matroska video"
    ),
    media!("video/x-msvideo", ["avi"], Video, Detected, "an AVI video"),
    media!("font/woff", ["woff"], Font, Detected, "a WOFF font"),
    media!("font/woff2", ["woff2"], Font, Detected, "a WOFF2 font"),
    media!("font/ttf", ["ttf"], Font, Detected, "a TrueType font"),
    media!("font/otf", ["otf"], Font, Detected, "an OpenType font"),
    media!(
        "application/wasm",
        ["wasm"],
        Data,
        Detected,
        "a WebAssembly module"
    ),
    media!(
        "application/vnd.sqlite3",
        ["sqlite", "db"],
        Data,
        Detected,
        "a SQLite database"
    ),
    media!(
        "application/x-parquet",
        ["parquet"],
        Data,
        Detected,
        "a Parquet file"
    ),
    media!(
        "application/octet-stream",
        [],
        Generic,
        Header,
        "a binary file"
    ),
];

/// Extensions that name scripts and shortcuts Windows executes on open.
pub(super) const SCRIPT_EXTENSIONS: &[&str] = &[
    "exe", "dll", "lnk", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "scr", "com", "msi",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_has_unique_names_and_lowercase_extensions() {
        let mut names: Vec<&str> = MEDIA_TYPES.iter().map(|m| m.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate media type name");
        for media in MEDIA_TYPES {
            for ext in media.extensions {
                assert_eq!(*ext, ext.to_ascii_lowercase(), "{}", media.name);
                assert!(!ext.starts_with('.'), "{}", media.name);
            }
            assert!(media.name.contains('/'), "{}", media.name);
        }
    }
}
