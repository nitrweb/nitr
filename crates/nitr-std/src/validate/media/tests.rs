// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;

fn name_of(d: Detection) -> &'static str {
    match d {
        Detection::Detected(m) => m.name,
        Detection::Text => "<text>",
        Detection::Executable => "<executable>",
        Detection::Unknown => "<unknown>",
    }
}

/// One accept per signature family, plus the executables.
#[test]
fn signatures_detect_the_common_families() {
    let cases: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR", "image/png"),
        (b"\xFF\xD8\xFF\xE0", "image/jpeg"),
        (b"GIF89a", "image/gif"),
        (b"RIFF\0\0\0\0WEBPVP8 ", "image/webp"),
        (b"RIFF\0\0\0\0WAVEfmt ", "audio/wav"),
        (b"RIFF\0\0\0\0AVI LIST", "video/x-msvideo"),
        (b"II*\0\x08\0\0\0", "image/tiff"),
        (b"\0\0\0\x18ftypavif", "image/avif"),
        (b"\0\0\0\x18ftypisom", "video/mp4"),
        (b"\0\0\0\x18ftypM4A ", "audio/mp4"),
        (b"%PDF-1.7", "application/pdf"),
        (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "application/msword"),
        (b"{\\rtf1", "application/rtf"),
        (b"\x1F\x8B\x08", "application/gzip"),
        (b"BZh91AY", "application/x-bzip2"),
        (b"\xFD7zXZ\0", "application/x-xz"),
        (b"\x28\xB5\x2F\xFD", "application/zstd"),
        (b"7z\xBC\xAF\x27\x1C", "application/x-7z-compressed"),
        (b"Rar!\x1A\x07\x01\0", "application/vnd.rar"),
        (b"ID3\x04", "audio/mpeg"),
        (b"\xFF\xFB\x90", "audio/mpeg"),
        (b"\xFF\xF1\x50", "audio/aac"),
        (b"OggS", "audio/ogg"),
        (b"fLaC", "audio/flac"),
        (b"\x1A\x45\xDF\xA3\x01webm", "video/webm"),
        (b"\x1A\x45\xDF\xA3\x01matroska", "video/x-matroska"),
        (b"wOFF", "font/woff"),
        (b"wOF2", "font/woff2"),
        (b"OTTO", "font/otf"),
        (b"\0asm\x01", "application/wasm"),
        (b"SQLite format 3\0", "application/vnd.sqlite3"),
        (b"PAR1", "application/x-parquet"),
        (b"MZ\x90\0", "<executable>"),
        (b"\x7fELF", "<executable>"),
        (b"#!/bin/sh\n", "<executable>"),
        (b"\xCA\xFE\xBA\xBE", "<executable>"),
        (b"id,name\n1,ada\n", "<text>"),
        (b"\xEF\xBB\xBFhello", "<text>"),
        (b"", "<text>"),
        (b"\xFF\xFEh\0i\0", "<unknown>"),
        (b"h\0i", "<unknown>"),
        (b"\x00\x00\x00\x00\x00", "<unknown>"),
    ];
    for (bytes, expected) in cases {
        assert_eq!(name_of(detect(bytes)), *expected, "{bytes:?}");
    }
    // A tar's marker sits at offset 257.
    let mut tar = vec![0u8; 512];
    tar[257..262].copy_from_slice(b"ustar");
    assert_eq!(name_of(detect(&tar)), "application/x-tar");
    // A bitmap is `BM` plus a known DIB header size at offset 14; the two
    // letters alone are English.
    let mut bmp = b"BM".to_vec();
    bmp.extend_from_slice(&[0u8; 12]);
    bmp.extend_from_slice(&40u32.to_le_bytes());
    assert_eq!(name_of(detect(&bmp)), "image/bmp");
    assert_eq!(name_of(detect(b"BMW cars are fast\n")), "<text>");
    let mut bad = b"BM".to_vec();
    bad.extend_from_slice(&[0u8; 12]);
    bad.extend_from_slice(&41u32.to_le_bytes());
    assert_eq!(name_of(detect(&bad)), "<unknown>");
}

fn zip_with(entries: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for name in entries {
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[0u8; 22]);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
    }
    out
}

#[test]
fn office_documents_are_told_apart_from_plain_zips() {
    let docx = zip_with(&[b"[Content_Types].xml", b"word/document.xml"]);
    assert!(name_of(detect(&docx)).ends_with("wordprocessingml.document"));
    let xlsx = zip_with(&[b"_rels/.rels", b"xl/workbook.xml"]);
    assert!(name_of(detect(&xlsx)).ends_with("spreadsheetml.sheet"));
    let mut odt = zip_with(&[b"mimetype"]);
    odt.extend_from_slice(b"application/vnd.oasis.opendocument.text");
    assert_eq!(
        name_of(detect(&odt)),
        "application/vnd.oasis.opendocument.text"
    );
    assert_eq!(
        name_of(detect(&zip_with(&[b"readme.txt"]))),
        "application/zip"
    );
    assert_eq!(name_of(detect(b"PK\x03\x04\0\0")), "application/zip");
    // A polyglot with a PDF prefix is a PDF.
    let mut poly = b"%PDF-1.4\n".to_vec();
    poly.extend_from_slice(&zip_with(&[b"a"]));
    assert_eq!(name_of(detect(&poly)), "application/pdf");
}

#[test]
fn dimensions_come_from_headers_only() {
    let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x01\0\0\0\x02\0";
    assert_eq!(
        dimensions(lookup("image/png").unwrap(), png),
        Some((256, 512))
    );
    assert_eq!(dimensions(lookup("image/png").unwrap(), &png[..20]), None);
    let gif = b"GIF89a\x10\0\x20\0";
    assert_eq!(
        dimensions(lookup("image/gif").unwrap(), gif),
        Some((16, 32))
    );
    // SOI, APP0 (len 16), SOF0 with height 0x0100 width 0x0200.
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    jpeg.extend_from_slice(&[0u8; 14]);
    jpeg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08, 0x01, 0x00, 0x02, 0x00]);
    assert_eq!(
        dimensions(lookup("image/jpeg").unwrap(), &jpeg),
        Some((512, 256))
    );
    assert_eq!(dimensions(lookup("image/jpeg").unwrap(), &jpeg[..6]), None);
    // A bomb header is just numbers; nothing is allocated for it.
    let bomb = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\x01\x86\xA0\0\x01\x86\xA0";
    assert_eq!(
        dimensions(lookup("image/png").unwrap(), bomb),
        Some((100_000, 100_000))
    );
    // WebP VP8L: 1-bit signature then 14-bit width-1 / height-1.
    let mut webp = b"RIFF\0\0\0\0WEBPVP8L\0\0\0\0\x2F".to_vec();
    webp.extend_from_slice(&(0x0Fu32 | (0x1F << 14)).to_le_bytes());
    assert_eq!(
        dimensions(lookup("image/webp").unwrap(), &webp),
        Some((16, 32))
    );
    // BMP v3 header.
    let mut bmp = b"BM".to_vec();
    bmp.extend_from_slice(&[0u8; 12]);
    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&64u32.to_le_bytes());
    bmp.extend_from_slice(&(-48i32).to_le_bytes());
    assert_eq!(
        dimensions(lookup("image/bmp").unwrap(), &bmp),
        Some((64, 48))
    );
}

#[test]
fn text_subtypes_need_their_first_byte() {
    assert!(text_subtype_matches("application/json", b"  {\"a\":1}"));
    assert!(!text_subtype_matches("application/json", b"a,b"));
    assert!(text_subtype_matches(
        "image/svg+xml",
        b"<?xml version=\"1.0\"?><svg/>"
    ));
    assert!(!text_subtype_matches("image/svg+xml", b"<html>"));
    assert!(text_subtype_matches("text/csv", b"anything"));
    assert!(!is_text(b"\xC3"));
    assert!(is_text("caf\u{e9}".as_bytes()));
    // A prefix cut inside a multi-byte sequence is still text.
    assert!(is_text(&"caf\u{e9}".as_bytes()[..4]));
}

#[test]
fn type_descriptions_read_as_sentences() {
    use crate::validate::TypePattern;
    assert_eq!(
        describe_types(&[TypePattern::Exact("application/pdf".into())]),
        "a PDF"
    );
    assert!(
        describe_types(&[TypePattern::Family("image".into())]).starts_with("an image (png, jpg")
    );
    assert_eq!(
        describe_types(&[
            TypePattern::Exact("application/pdf".into()),
            TypePattern::Exact("text/csv".into())
        ]),
        "a PDF or a CSV file"
    );
    assert_eq!(describe_types(&[TypePattern::Any]), "any file");
    assert!(executable_extension("bat") && !executable_extension("png"));
    let gz = lookup("application/gzip").unwrap();
    assert!(extension_matches(gz, "tgz") && !extension_matches(gz, "zip"));
}
