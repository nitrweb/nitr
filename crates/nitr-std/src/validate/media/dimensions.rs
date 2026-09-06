// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Header-only image dimensions for the formats whose header carries
//! them: the decompression-bomb guard for whatever decodes the image
//! later. Nothing is decoded; only the prefix is read.

use super::MediaType;

fn at(prefix: &[u8], offset: usize, magic: &[u8]) -> bool {
    prefix.len() >= offset + magic.len() && &prefix[offset..offset + magic.len()] == magic
}

fn be16(prefix: &[u8], i: usize) -> Option<u32> {
    prefix
        .get(i..i + 2)
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
}

fn be32(prefix: &[u8], i: usize) -> Option<u32> {
    prefix
        .get(i..i + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn le16(prefix: &[u8], i: usize) -> Option<u32> {
    prefix
        .get(i..i + 2)
        .map(|b| u32::from(u16::from_le_bytes([b[0], b[1]])))
}

fn le32(prefix: &[u8], i: usize) -> Option<u32> {
    prefix
        .get(i..i + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn png(prefix: &[u8]) -> Option<(u32, u32)> {
    if !at(prefix, 12, b"IHDR") {
        return None;
    }
    Some((be32(prefix, 16)?, be32(prefix, 20)?))
}

fn gif(prefix: &[u8]) -> Option<(u32, u32)> {
    Some((le16(prefix, 6)?, le16(prefix, 8)?))
}

fn bmp(prefix: &[u8]) -> Option<(u32, u32)> {
    let header = le32(prefix, 14)?;
    if header == 12 {
        Some((le16(prefix, 18)?, le16(prefix, 20)?))
    } else {
        let w = le32(prefix, 18)?;
        let h = le32(prefix, 22)?;
        // Height may be negative (top-down rows).
        Some((w, (h as i32).unsigned_abs()))
    }
}

/// Walks the JPEG segments to the first `SOFn` marker.
fn jpeg(prefix: &[u8]) -> Option<(u32, u32)> {
    let mut pos = 2usize;
    while pos + 9 <= prefix.len() {
        if prefix[pos] != 0xFF {
            return None;
        }
        let marker = prefix[pos + 1];
        if marker == 0xFF {
            pos += 1;
            continue;
        }
        if matches!(marker, 0xD8 | 0x01 | 0xD0..=0xD7) {
            pos += 2;
            continue;
        }
        let len = usize::from(u16::from_be_bytes([prefix[pos + 2], prefix[pos + 3]]));
        if matches!(marker, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF) {
            let h = be16(prefix, pos + 5)?;
            let w = be16(prefix, pos + 7)?;
            return Some((w, h));
        }
        if marker == 0xDA || len < 2 {
            return None;
        }
        pos += 2 + len;
    }
    None
}

fn webp(prefix: &[u8]) -> Option<(u32, u32)> {
    match prefix.get(12..16)? {
        b"VP8 " => {
            // Key frame: 3-byte frame tag, 3-byte start code, then 14-bit
            // width and height.
            if !at(prefix, 23, b"\x9d\x01\x2a") {
                return None;
            }
            Some((le16(prefix, 26)? & 0x3FFF, le16(prefix, 28)? & 0x3FFF))
        }
        b"VP8L" => {
            if prefix.get(20)? != &0x2F {
                return None;
            }
            let bits = le32(prefix, 21)?;
            Some(((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1))
        }
        b"VP8X" => {
            let u24 = |i: usize| -> Option<u32> {
                Some(
                    u32::from(*prefix.get(i)?)
                        | (u32::from(*prefix.get(i + 1)?) << 8)
                        | (u32::from(*prefix.get(i + 2)?) << 16),
                )
            };
            Some((u24(24)? + 1, u24(27)? + 1))
        }
        _ => None,
    }
}

fn tiff(prefix: &[u8]) -> Option<(u32, u32)> {
    let little = prefix.starts_with(b"II");
    let rd16 = |i: usize| -> Option<u32> {
        if little {
            le16(prefix, i)
        } else {
            be16(prefix, i)
        }
    };
    let rd32 = |i: usize| -> Option<u32> {
        if little {
            le32(prefix, i)
        } else {
            be32(prefix, i)
        }
    };
    let ifd = rd32(4)? as usize;
    let count = rd16(ifd)? as usize;
    let (mut w, mut h) = (None, None);
    for i in 0..count.min(64) {
        let entry = ifd + 2 + i * 12;
        let tag = rd16(entry)?;
        let kind = rd16(entry + 2)?;
        let value = if kind == 3 {
            rd16(entry + 8)?
        } else {
            rd32(entry + 8)?
        };
        match tag {
            256 => w = Some(value),
            257 => h = Some(value),
            _ => {}
        }
    }
    Some((w?, h?))
}

/// Header-only image dimensions, or `None` when the header does not
/// carry them (or is truncated).
pub fn dimensions(media: &MediaType, prefix: &[u8]) -> Option<(u32, u32)> {
    match media.name {
        "image/png" => png(prefix),
        "image/gif" => gif(prefix),
        "image/bmp" => bmp(prefix),
        "image/jpeg" => jpeg(prefix),
        "image/webp" => webp(prefix),
        "image/tiff" => tiff(prefix),
        _ => None,
    }
}
