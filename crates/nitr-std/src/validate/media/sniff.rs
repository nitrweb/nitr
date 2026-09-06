// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Signature detection over an upload's first bytes, the text sniffer,
//! and the ZIP-container reader that tells an office document from a
//! plain archive. Every function reads a bounded prefix once and is
//! linear in it; none of them decodes anything.

use super::{Detection, MediaType, lookup};

fn starts(prefix: &[u8], magic: &[u8]) -> bool {
    prefix.len() >= magic.len() && &prefix[..magic.len()] == magic
}

fn at(prefix: &[u8], offset: usize, magic: &[u8]) -> bool {
    prefix.len() >= offset + magic.len() && &prefix[offset..offset + magic.len()] == magic
}

/// The `ftyp` brand of an ISO base media file, when the prefix is one.
fn ftyp_brand(prefix: &[u8]) -> Option<&[u8]> {
    if at(prefix, 4, b"ftyp") && prefix.len() >= 12 {
        Some(&prefix[8..12])
    } else {
        None
    }
}

/// A ZIP's first local-file names, from the local headers in the prefix:
/// enough to tell an office document from a plain archive.
fn zip_entry_names(prefix: &[u8]) -> Vec<&[u8]> {
    let mut names = Vec::new();
    let mut pos = 0usize;
    // Each local header: signature(4) ver(2) flag(2) method(2) time(2)
    // date(2) crc(4) csize(4) usize(4) nlen(2) xlen(2) name[nlen] extra
    // then the data (csize bytes, unless flag bit 3 defers it).
    while names.len() < 8 && prefix.len() >= pos + 30 && at(prefix, pos, b"PK\x03\x04") {
        let u16_at = |i: usize| u16::from_le_bytes([prefix[pos + i], prefix[pos + i + 1]]) as usize;
        let u32_at = |i: usize| {
            u32::from_le_bytes([
                prefix[pos + i],
                prefix[pos + i + 1],
                prefix[pos + i + 2],
                prefix[pos + i + 3],
            ]) as usize
        };
        let flags = u16_at(6);
        let csize = u32_at(18);
        let nlen = u16_at(26);
        let xlen = u16_at(28);
        let name_start = pos + 30;
        let Some(name_end) = name_start.checked_add(nlen) else {
            break;
        };
        if name_end > prefix.len() {
            break;
        }
        names.push(&prefix[name_start..name_end]);
        if flags & 0x08 != 0 {
            // Sizes deferred to a data descriptor: cannot skip reliably.
            break;
        }
        let Some(next) = name_end
            .checked_add(xlen)
            .and_then(|n| n.checked_add(csize))
        else {
            break;
        };
        pos = next;
    }
    names
}

/// Which ZIP-based type a `PK` prefix is.
fn zip_kind(prefix: &[u8]) -> &'static MediaType {
    let names = zip_entry_names(prefix);
    let first = names.first().copied().unwrap_or(b"");
    // OpenDocument and EPUB: an uncompressed `mimetype` entry whose bytes
    // are the media type, right after the header.
    if first == b"mimetype" {
        let start = 30 + first.len();
        let body = &prefix[start.min(prefix.len())..];
        for candidate in [
            "application/vnd.oasis.opendocument.text",
            "application/vnd.oasis.opendocument.spreadsheet",
            "application/vnd.oasis.opendocument.presentation",
            "application/epub+zip",
        ] {
            if starts(body, candidate.as_bytes())
                && let Some(media) = lookup(candidate)
            {
                return media;
            }
        }
    }
    let has = |needle: &[u8]| names.iter().any(|n| n.starts_with(needle));
    if names.iter().any(|n| *n == b"[Content_Types].xml") || has(b"_rels/") {
        let office = if has(b"word/") {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        } else if has(b"xl/") {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        } else if has(b"ppt/") {
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        } else {
            "application/zip"
        };
        if let Some(media) = lookup(office) {
            return media;
        }
    }
    // Invariant: the table carries `application/zip`.
    #[allow(clippy::expect_used)]
    lookup("application/zip").expect("zip is in the media table")
}

/// Whether the prefix is UTF-8 text without NUL or stray control bytes.
pub fn is_text(prefix: &[u8]) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let body = prefix.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(prefix);
    let text = match std::str::from_utf8(body) {
        Ok(text) => text,
        // A prefix may cut a multi-byte sequence: accept the valid part
        // when the cut is within the last three bytes.
        Err(err) if err.error_len().is_none() && err.valid_up_to() > 0 => {
            match std::str::from_utf8(&body[..err.valid_up_to()]) {
                Ok(text) => text,
                Err(_) => return false,
            }
        }
        Err(_) => return false,
    };
    !text
        .chars()
        .any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r')
}

/// Whether the first bytes are an executable's.
fn is_executable(prefix: &[u8]) -> bool {
    if starts(prefix, b"MZ")
        || starts(prefix, b"\x7fELF")
        || starts(prefix, b"#!")
        || starts(prefix, b"\xCA\xFE\xBA\xBE")
    {
        return true;
    }
    prefix.len() >= 4 && {
        let magic = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
        matches!(magic, 0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE)
    }
}

/// Sniffs the prefix.
pub fn detect(prefix: &[u8]) -> Detection {
    let hit = |name: &str| {
        lookup(name)
            .map(Detection::Detected)
            .unwrap_or(Detection::Unknown)
    };
    // Executables first: a polyglot that is also an executable is an
    // executable.
    if is_executable(prefix) {
        return Detection::Executable;
    }
    let signatures: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xFF\xD8\xFF", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"II*\0", "image/tiff"),
        (b"MM\0*", "image/tiff"),
        (b"\0\0\x01\0", "image/x-icon"),
        (b"%PDF-", "application/pdf"),
        (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "application/msword"),
        (b"{\\rtf", "application/rtf"),
        (b"\x1F\x8B", "application/gzip"),
        (b"BZh", "application/x-bzip2"),
        (b"\xFD7zXZ\0", "application/x-xz"),
        (b"\x28\xB5\x2F\xFD", "application/zstd"),
        (b"7z\xBC\xAF\x27\x1C", "application/x-7z-compressed"),
        (b"Rar!\x1A\x07", "application/vnd.rar"),
        (b"ID3", "audio/mpeg"),
        (b"OggS", "audio/ogg"),
        (b"fLaC", "audio/flac"),
        (b"wOFF", "font/woff"),
        (b"wOF2", "font/woff2"),
        (b"\0\x01\0\0", "font/ttf"),
        (b"true", "font/ttf"),
        (b"OTTO", "font/otf"),
        (b"\0asm", "application/wasm"),
        (b"SQLite format 3\0", "application/vnd.sqlite3"),
        (b"PAR1", "application/x-parquet"),
    ];
    for (magic, name) in signatures {
        if starts(prefix, magic) {
            return hit(name);
        }
    }
    if starts(prefix, b"RIFF") {
        if at(prefix, 8, b"WEBP") {
            return hit("image/webp");
        }
        if at(prefix, 8, b"WAVE") {
            return hit("audio/wav");
        }
        if at(prefix, 8, b"AVI ") {
            return hit("video/x-msvideo");
        }
    }
    // An ISO media file shorter than its brand says nothing yet — never
    // let the frame-sync heuristics below claim it. Tested before the
    // two-byte `BM` so `BM…ftyp` reads the same at every length.
    if at(prefix, 4, b"ftyp") && prefix.len() < 12 {
        return Detection::Unknown;
    }
    if let Some(brand) = ftyp_brand(prefix) {
        return match brand {
            b"avif" | b"avis" => hit("image/avif"),
            b"heic" | b"heix" | b"hevc" | b"mif1" | b"msf1" => hit("image/heic"),
            b"M4A " => hit("audio/mp4"),
            b"qt  " => hit("video/quicktime"),
            _ => hit("video/mp4"),
        };
    }
    // `BM` is two bytes of English; the DIB header size at offset 14
    // (one of the known header versions) is what makes it a bitmap.
    if starts(prefix, b"BM")
        && let Some(header) = prefix
            .get(14..18)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        && matches!(header, 12 | 40 | 52 | 56 | 108 | 124)
    {
        return hit("image/bmp");
    }
    if starts(prefix, b"PK\x03\x04") {
        return Detection::Detected(zip_kind(prefix));
    }
    if at(prefix, 257, b"ustar") {
        return hit("application/x-tar");
    }
    if prefix.len() >= 2 && prefix[0] == 0xFF {
        // MPEG audio frame sync (`FFE`/`FFF`) and ADTS AAC (`FFF1`/`FFF9`).
        if prefix[1] & 0xF6 == 0xF0 {
            return hit("audio/aac");
        }
        // `FF FE`/`FF FF` are byte-order marks and padding, not frames.
        if prefix[1] & 0xE0 == 0xE0 && prefix[1] < 0xFE {
            return hit("audio/mpeg");
        }
    }
    if starts(prefix, b"\x1A\x45\xDF\xA3") {
        let is_webm = prefix.windows(4).take(64).any(|w| w == b"webm");
        return hit(if is_webm {
            "video/webm"
        } else {
            "video/x-matroska"
        });
    }
    if is_text(prefix) {
        return Detection::Text;
    }
    Detection::Unknown
}

/// For a text-tier declared type, whether the prefix has the structure
/// the subtype implies (`{`/`[` for JSON, `<` for XML and HTML, `<svg`
/// for SVG); plain text subtypes accept anything the sniffer accepted.
pub fn text_subtype_matches(declared: &str, prefix: &[u8]) -> bool {
    let body = prefix.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(prefix);
    let first = body.iter().copied().find(|b| !b.is_ascii_whitespace());
    match declared {
        "application/json" => matches!(first, Some(b'{') | Some(b'[')),
        "application/xml" | "text/xml" | "text/html" => matches!(first, Some(b'<')),
        "image/svg+xml" => {
            let text = String::from_utf8_lossy(&body[..body.len().min(4096)]).to_ascii_lowercase();
            let trimmed = text.trim_start();
            trimmed.starts_with("<svg") || (trimmed.starts_with("<?xml") && text.contains("<svg"))
        }
        _ => true,
    }
}
