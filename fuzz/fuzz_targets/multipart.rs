// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `multipart/form-data`: boundary extraction, the part-count cap, the
//! per-field byte cap, and — the surface only a fuzzer reaches — multer's
//! cross-frame boundary state machine. This is the same walk
//! `req:multipart()` runs, minus Lua and disk (`consume_for_fuzzing`).
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u8 have_type | u16 chunk | u8 max_parts | u16 max_field | content-type \0 body…
//! ```
//!
//! Every numeric parameter is fuzzer-chosen and folded into a range where
//! it actually fires: caps of `usize::MAX` would never be reached inside a
//! 4 KiB body, so the cap arithmetic would only ever be tested from one
//! side. `have_type` decides `Some`/`None`, which is what makes the
//! no-Content-Type branch reachable at all. `chunk` is the number of bytes
//! per stream frame (`0` = one frame for the whole body); a real body
//! arrives from hyper as many frames, and the delimiter — along with the
//! CRLF that belongs to it — can straddle a frame edge.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **Framing does not change the parse.** The same body under the
//!   fuzzer's framing and as a single frame must give the same walk, and
//!   must fail together. A boundary matcher that mis-handles a delimiter
//!   split across frames — dropping a part, duplicating a chunk, or
//!   swallowing the CRLF that precedes the delimiter — is invisible to
//!   single-frame fuzzing and loud here.
//! * **The caps are exact, not approximate.** An unbounded walk is used as
//!   an oracle: it says how many parts the body really has and how big its
//!   largest field really is, so the capped walk must succeed *exactly*
//!   when both fit, and must then report the same numbers. This pins both
//!   comparisons at their boundary — an off-by-one in either direction
//!   (`>=` for `>`, or counting a part before rejecting it) fails here,
//!   where "parts <= max_parts" alone would not.
//! * **The reported sizes are bounded by the body.** A field cannot yield
//!   more bytes than the whole body holds, which is what a chunk counted
//!   twice at a frame edge would look like.
//! * **No body parses without a Content-Type.** A boundary is never
//!   sniffed out of the payload.
//! * **Only a multipart type with a boundary parameter yields a parse** —
//!   a walk that succeeded for `application/json` would mean
//!   `req:multipart()` reads bodies it was never handed.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;

/// One current-thread runtime for the whole process. The walk is async but
/// only ever awaits an in-memory stream, so building a runtime per run
/// would be pure setup cost.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
    })
}

/// One walk, reduced to `(parts, largest_field)`: `MultipartWalk` lives in
/// a crate-private module and cannot be named here, and the pair is what
/// the comparisons below need anyway.
type Walk = Result<(usize, u64), String>;

fn walk(
    content_type: Option<&str>,
    body: &bytes::Bytes,
    chunk_size: usize,
    max_parts: usize,
    max_field_bytes: u64,
) -> Walk {
    runtime()
        .block_on(nitr_http::fuzzing::consume_multipart(
            content_type,
            body.clone(),
            chunk_size,
            max_parts,
            max_field_bytes,
        ))
        .map(|w| (w.parts, w.largest_field))
        .map_err(|err| err.to_string())
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let have_type = input.flag();
    // 0 = one frame; otherwise 1..=511 bytes per frame. Single-byte frames
    // put every delimiter across a frame edge, which is the state machine
    // this target exists to reach.
    let chunk_size = usize::from(input.u16()) % 512;
    // Small enough that a 4 KiB body routinely crosses both caps, so the
    // comparisons are exercised from both sides instead of never firing.
    let max_parts = usize::from(input.u8()) % 16;
    let max_field_bytes = u64::from(input.u16() % 1024);
    let content_type = input.text();
    let body = bytes::Bytes::copy_from_slice(input.rest());
    let ct = have_type.then(|| content_type.as_ref());

    let framed = walk(ct, &body, chunk_size, max_parts, max_field_bytes);
    let single = walk(ct, &body, 0, max_parts, max_field_bytes);

    // Framing must not change the parse. Error *text* is allowed to differ
    // (multer names a different truncation point when the body is cut at a
    // frame edge), but the outcome and every number in it may not.
    match (&framed, &single) {
        (Ok(a), Ok(b)) => assert_eq!(
            a, b,
            "framing changed the parse: {chunk_size}-byte frames gave {a:?}, \
             one frame gave {b:?}; ct={ct:?} body={body:?}"
        ),
        (Err(_), Err(_)) => {}
        _ => panic!(
            "framing changed success: {chunk_size}-byte frames gave {framed:?}, \
             one frame gave {single:?}; ct={ct:?} body={body:?}"
        ),
    }

    for (label, outcome) in [("framed", &framed), ("single", &single)] {
        let Ok((parts, largest)) = outcome else {
            continue;
        };
        assert!(
            *parts <= max_parts,
            "{label}: {parts} parts admitted past the cap of {max_parts}; body={body:?}"
        );
        assert!(
            *largest <= max_field_bytes,
            "{label}: a {largest} byte field admitted past the cap of \
             {max_field_bytes}; body={body:?}"
        );
        // A part's bytes are a slice of the body, so neither count can
        // exceed its length — a chunk emitted twice across a frame edge
        // would show up here as a field larger than everything that was fed
        // in.
        assert!(
            *largest <= body.len() as u64 && *parts <= body.len(),
            "{label}: {parts} parts / {largest} bytes out of a {} byte body; body={body:?}",
            body.len()
        );
        // `largest_field` is a maximum over the parts, so it has nothing to
        // report when there were none.
        assert!(
            *parts > 0 || *largest == 0,
            "{label}: no parts, yet a {largest} byte field; body={body:?}"
        );
    }

    // The caps, pinned exactly. An unbounded walk is the oracle for what
    // this body really contains; the capped walk must then succeed iff both
    // numbers fit, and report the very same numbers when it does.
    match walk(ct, &body, 0, usize::MAX, u64::MAX) {
        Ok((parts, largest)) => {
            let within = parts <= max_parts && largest <= max_field_bytes;
            match &single {
                Ok(capped) => {
                    assert!(
                        within,
                        "a body with {parts} parts / a {largest} byte field passed caps of \
                         {max_parts} parts / {max_field_bytes} bytes; ct={ct:?} body={body:?}"
                    );
                    assert_eq!(
                        *capped,
                        (parts, largest),
                        "the capped walk disagrees with the uncapped one; \
                         ct={ct:?} body={body:?}"
                    );
                }
                Err(err) => assert!(
                    !within,
                    "a body with {parts} parts / a {largest} byte field was refused under caps \
                     of {max_parts} parts / {max_field_bytes} bytes: {err}; \
                     ct={ct:?} body={body:?}"
                ),
            }
        }
        // Caps only ever cut a walk short, so nothing a limitless walk
        // rejects may parse once limits are added.
        Err(err) => assert!(
            single.is_err(),
            "a body the uncapped walk rejected ({err}) parsed under caps: {single:?}; \
             ct={ct:?} body={body:?}"
        ),
    }

    // Without a Content-Type there is no boundary, and a boundary is never
    // sniffed out of the body: the walk must be refused whatever the body
    // looks like.
    if !have_type {
        assert!(
            framed.is_err(),
            "a multipart walk succeeded with no Content-Type: {framed:?}; body={body:?}"
        );
    }
    // Anything that did parse came from a multipart type that really named
    // a boundary parameter.
    if framed.is_ok() {
        let ct = content_type.trim_start().to_ascii_lowercase();
        assert!(
            ct.starts_with("multipart/"),
            "`{content_type}` is not a multipart type, yet its body parsed"
        );
        assert!(
            ct.contains("boundary"),
            "`{content_type}` names no boundary, yet its body parsed"
        );
    }
});
