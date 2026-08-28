// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `Accept-Encoding`: the hand-written parser behind every compression
//! decision Nitr makes — which precompressed sidecar to serve, and which
//! coding to run a dynamic response through.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u8 q_choice | accept-encoding
//! ```
//!
//! `q_choice` picks one refusing and one accepting q-value spelling out of
//! the two tables below (`n % 8` and `n / 8 % 5`, so every pair is
//! reachable): the rewrite properties need a weight the fuzzer did not
//! also have to discover, or they would only fire on the rare input that
//! happens to spell a float. `accept-encoding` runs to the end of the
//! input and is the whole header value.
//!
//! ## What this target can and cannot reach
//!
//! `Compression::negotiate` is `parse_accept_encoding` plus a four-line
//! `find`, but it cannot be called from here: `Compression::new` is
//! `pub(crate)` and no public constructor exists, so the `Compression`
//! re-export in `nitr_http::fuzzing` is an unusable seam (reported as a
//! seam request). The predicate `negotiate` applies to the parse output —
//! `q > 0.0 && token == enc` — is therefore spelled out in [`accepts`]
//! here, and every property below is a property of the parse, which is
//! where all of the logic lives. Wiring the real `negotiate` in is a
//! one-line change once the constructor is reachable.
//!
//! ## The q-value corners this exists to pin
//!
//! The weight is a plain `f32` parse, so `q=NaN`, `q=inf` and `q=1e40` all
//! succeed. Confirmed here: a NaN weight makes the coding **unacceptable**
//! (`NaN > 0.0` is false), so a client cannot use it to force a coding the
//! server did not offer — it can only lose itself the compression. That is
//! the behaviour asserted below, and it is why the NaN spellings sit in
//! the *refusing* table. A NaN nevertheless reaches the caller inside the
//! returned vector, so any future caller that sorts by weight inherits a
//! non-total order; that, and the case-sensitive `q=` prefix, are recorded
//! as findings rather than asserted.
//!
//! Two further corners are where this parser and its sibling
//! `nitr_std::http::best_match` — the `Accept` negotiator, same parameter
//! grammar, different code — give **opposite** answers to the same bytes.
//! Both are pinned below on the side `parse_accept_encoding` is actually
//! on, and both are reported as findings:
//!
//! * **The first weight wins, not the last.** `parts.find_map(|p|
//!   p.trim().strip_prefix("q=")?.parse::<f32>().ok())` stops at the first
//!   parseable weight, while `best_match`'s loop overwrites `q` on every
//!   parameter and so keeps the last. `gzip;q=1;q=0` is fully acceptable
//!   here and a refusal there.
//! * **An unparseable weight means 1.0, not 0.0.** `.ok()` turns the parse
//!   failure into `None` and `.unwrap_or(1.0)` then makes `gzip;q=zzz`
//!   fully acceptable; `best_match` writes `.unwrap_or(0.0)` and refuses
//!   the same text. RFC 9110 §12.4.2 makes both spellings malformed, so
//!   neither answer is wrong on its own — the two *disagreeing* is the
//!   finding, and until this round neither case was reachable: `with_q`
//!   only ever wrote one well-formed weight, the default-weight check is
//!   guarded by `!entry.contains("q=")`, and the dictionary had no
//!   multi-`q` or unparseable-`q` token.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **The token list, exactly.** An oracle built without touching
//!   `Encoding::from_token` — split on `,`, take everything before the
//!   first `;`, trim, lowercase, keep `br`/`gzip` — must reproduce the
//!   parser's output codings in order and with multiplicity. This catches
//!   an entry dropped or duplicated, entries reordered, a token matched by
//!   prefix or substring (`x-gzip`, `gzipped`), case folding lost, and —
//!   because the comparison is on the token *string* the response will
//!   carry — an alias that maps some other name onto a coding, which would
//!   label the body with a `Content-Encoding` the client never asked for.
//! * **Only codings Nitr can produce come back.** `br` and `gzip`, and
//!   `Encoding::token` agrees with the name matched. The token is what
//!   goes in the response header and what the sidecar extension derives
//!   from, so a third coding here means bytes labelled as something no
//!   encoder produced.
//! * **The default weight is exactly 1.0.** An entry with no `q=` in it at
//!   all is fully acceptable. A default of `0.0` silently turns
//!   compression off for every ordinary browser header; a weight leaking
//!   from a neighbouring entry would show up here too.
//! * **A refusing weight is a refusal.** Rewriting every entry that names
//!   a coding with `q=0` (or `-1`, or `NaN`) must leave that coding
//!   unacceptable. Catches `>= 0.0` for `> 0.0`, a `q != 0.0` test, a
//!   weight that is parsed and then ignored, and it pins the NaN
//!   behaviour above.
//! * **An accepting weight keeps it.** The dual: rewriting the same
//!   entries with `q=1`, `q=0.5` or `q=0.001` must leave the coding
//!   acceptable whenever it appeared at all. Catches a weight parse that
//!   drops the entry it cannot use, and any threshold stricter than
//!   "greater than zero".
//! * **The first weight wins, and an unparseable one is 1.0.** The two
//!   divergences from `best_match` above, asserted as this parser behaves:
//!   `gzip;q=1;q=0` stays acceptable (last-wins would refuse it) and
//!   `gzip;q=zzz` stays acceptable (`unwrap_or(0.0)` would refuse it).
//!   Either rule is defensible; changing one silently is not.
//! * **Removal removes it.** Deleting every entry that names a coding must
//!   make it unacceptable. This is the phantom-match check: a parser that
//!   split on `;` before `,`, or matched a token as a substring, still
//!   finds `gzip` in a header where no entry names it — and would send a
//!   body the client cannot read.
//! * **Case and surrounding whitespace change nothing.** Rewriting each
//!   coding's token to ` BR `/` GZIP ` while leaving its parameters byte
//!   for byte must give back the identical parse, weights included
//!   (compared by bits, so a NaN is compared as a NaN). Catches a lost
//!   `trim`, a lost `to_ascii_lowercase`, and a weight computed from
//!   anything but the parameters.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use hyper::header::HeaderValue;
use nitr_http::fuzzing::{Compression, Encoding, parse_accept_encoding};

/// The codings Nitr can actually produce, paired with the token an
/// entry has to spell to name one. Written out rather than derived from
/// `Encoding::from_token`, so the oracle below never consults the parser's
/// own idea of what a token means.
const CODINGS: &[(&str, Encoding)] = &[("br", Encoding::Brotli), ("gzip", Encoding::Gzip)];

/// Weight spellings that all mean "not acceptable". `NaN` and `nan` are
/// here because `NaN > 0.0` is false: the parse succeeds, and the coding
/// is then refused exactly as `q=0` is.
const REFUSING_Q: &[&str] = &["0", "0.0", "0.000", "-0", "-1", "NaN", "nan", "-inf"];

/// Weight spellings that all mean "acceptable", including the smallest
/// weight RFC 9110 §12.4.2 allows anyone to write.
const ACCEPTING_Q: &[&str] = &["1", "1.0", "1.000", "0.5", "0.001"];

/// The token an entry names: everything before the first `;`, trimmed and
/// ASCII-lowercased. Independent of `Encoding::from_token` on purpose.
fn entry_token(entry: &str) -> String {
    entry
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// The codings the parser must return for `header`, in order and with
/// multiplicity.
fn expected_tokens(header: &str) -> Vec<String> {
    header
        .split(',')
        .map(entry_token)
        .filter(|token| CODINGS.iter().any(|(name, _)| token == name))
        .collect()
}

/// The predicate `Compression::negotiate` applies to the parse output: a
/// coding is usable when some entry names it with a weight above zero.
///
/// This is the parse-level answer. `negotiate_matches` below checks that
/// the real `negotiate` agrees with it, which is what keeps this from
/// being a copy of a rule that could drift from the rule itself.
fn accepts(header: &str, enc: Encoding) -> bool {
    parse_accept_encoding(header)
        .iter()
        .any(|(token, q)| *q > 0.0 && *token == enc)
}

/// What the real `Compression::negotiate` answers for a one-coding
/// negotiator, and what it *must* answer.
///
/// `negotiate` opens with `accept_encoding?.to_str().ok()?`, and
/// `HeaderValue::to_str` refuses every byte outside visible ASCII. RFC 9110
/// still permits obs-text (0x80-0xFF) in a field value, so a client can send
/// one and lose compression for the whole request — a valid `br;q=1` later
/// in the same header is discarded with it. That is a real degradation, so
/// it is asserted rather than skipped: the pair below pins both the
/// agreement on ordinary headers and the total refusal on obs-text ones.
fn negotiate_matches(header: &str, enc: Encoding) -> Option<(Option<Encoding>, Option<Encoding>)> {
    let value = HeaderValue::from_str(header).ok()?;
    let got = Compression::negotiator_for_fuzzing(vec![enc]).negotiate(Some(&value));
    let want = if value.to_str().is_ok() {
        accepts(header, enc).then_some(enc)
    } else {
        None
    };
    Some((got, want))
}

/// Rewrites every entry naming `name` to carry exactly `q`, leaving every
/// other entry byte for byte.
fn with_q(header: &str, name: &str, q: &str) -> String {
    header
        .split(',')
        .map(|entry| {
            if entry_token(entry) == name {
                format!("{name};q={q}")
            } else {
                entry.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Drops every entry naming `name`.
fn without(header: &str, name: &str) -> String {
    header
        .split(',')
        .filter(|entry| entry_token(entry) != name)
        .collect::<Vec<_>>()
        .join(",")
}

/// Upper-cases and pads the token of every entry that names a coding,
/// leaving that entry's parameters — and every other entry — untouched.
fn perturb(header: &str) -> String {
    header
        .split(',')
        .map(|entry| {
            let token = entry_token(entry);
            if !CODINGS.iter().any(|(name, _)| token == *name) {
                return entry.to_string();
            }
            let shouted = token.to_ascii_uppercase();
            match entry.split_once(';') {
                Some((_, params)) => format!(" {shouted} ;{params}"),
                None => format!(" {shouted} "),
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let q_choice = usize::from(input.u8());
    let header = input.text();

    let refusing = REFUSING_Q[q_choice % REFUSING_Q.len()];
    let accepting = ACCEPTING_Q[(q_choice / REFUSING_Q.len()) % ACCEPTING_Q.len()];

    if std::env::var_os("NITR_FUZZ_DEBUG").is_some() {
        eprintln!("DEBUG refusing={refusing:?} accepting={accepting:?} header={header:?}");
    }

    let parsed = parse_accept_encoding(&header);

    // The token list, against an oracle that never asks the parser
    let got: Vec<String> = parsed
        .iter()
        .map(|(enc, _)| enc.token().to_string())
        .collect();
    assert_eq!(
        got,
        expected_tokens(&header),
        "parse_accept_encoding disagrees with the entry tokens of {header:?}"
    );

    // Only codings that have an encoder, named by their own token
    for (enc, _) in &parsed {
        let token = enc.token();
        assert!(
            CODINGS
                .iter()
                .any(|(name, coding)| *name == token && coding == enc),
            "{enc:?} came back as the token {token:?}, which is not a coding Nitr can \
             produce; header={header:?}"
        );
    }

    // The default weight
    // Lined up entry by entry with the list the assertion above just
    // pinned: an entry that does not contain `q=` anywhere cannot have
    // named a weight, so its weight is the default.
    let named: Vec<&str> = header
        .split(',')
        .filter(|entry| CODINGS.iter().any(|(name, _)| entry_token(entry) == *name))
        .collect();
    for (entry, (enc, q)) in named.iter().zip(&parsed) {
        if !entry.contains("q=") {
            assert_eq!(
                *q, 1.0,
                "{entry:?} names no weight, yet {enc:?} came back with q={q}; header={header:?}"
            );
        }
    }

    for (name, enc) in CODINGS {
        let present = expected_tokens(&header).iter().any(|token| token == name);

        // The real `negotiate`, not a re-spelling of it: a one-coding
        // negotiator answers `Some(enc)` exactly when the client accepts
        // `enc` — except for a header carrying obs-text, which `to_str`
        // rejects wholesale, taking any valid entry down with it.
        if let Some((got, want)) = negotiate_matches(&header, *enc) {
            assert_eq!(
                got, want,
                "Compression::negotiate disagreed with the parse for {name}: {header:?}"
            );
        }

        // A refusing weight is a refusal
        let refused = with_q(&header, name, refusing);
        assert!(
            !accepts(&refused, *enc),
            "{name} is still acceptable when every entry naming it carries q={refusing}: \
             {refused:?} (from {header:?})"
        );

        // An accepting weight keeps it
        let wanted = with_q(&header, name, accepting);
        assert_eq!(
            accepts(&wanted, *enc),
            present,
            "{name} with q={accepting} on every entry naming it: {wanted:?} (from {header:?})"
        );

        // The first weight wins, not the last
        // `with_q` writes `gzip;q=1;q=0`: acceptable under `find_map`,
        // which stops at the first parseable weight, and a refusal under
        // `best_match`'s loop, which keeps the last one.
        let two_weights = with_q(&header, name, "1;q=0");
        assert_eq!(
            accepts(&two_weights, *enc),
            present,
            "{name} named twice with q=1 then q=0: {two_weights:?} (from {header:?}); this \
             parser takes the FIRST parseable weight, so the coding stays acceptable — \
             nitr_std::http::best_match takes the last and would refuse it"
        );

        // An unparseable weight is the default weight, not a refusal
        // `.parse::<f32>().ok()` yields None and `.unwrap_or(1.0)` then
        // makes the coding fully acceptable; `best_match` writes
        // `.unwrap_or(0.0)` and refuses the same text.
        let junk_weight = with_q(&header, name, "zzz");
        assert_eq!(
            accepts(&junk_weight, *enc),
            present,
            "{name} with an unparseable weight: {junk_weight:?} (from {header:?}); this \
             parser falls back to q=1.0, so the coding stays acceptable — \
             nitr_std::http::best_match falls back to q=0.0 and would refuse it"
        );

        // Removal removes it
        let dropped = without(&header, name);
        assert!(
            !accepts(&dropped, *enc),
            "{name} is acceptable in {dropped:?}, which names no entry for it \
             (from {header:?})"
        );
    }

    // Case and whitespace
    let shouted = perturb(&header);
    let reparsed = parse_accept_encoding(&shouted);
    // Weights are compared by bits: a NaN weight has to survive as the
    // same NaN, and `NaN == NaN` would silently pass anything.
    let bits = |pairs: &[(Encoding, f32)]| -> Vec<(Encoding, u32)> {
        pairs.iter().map(|(enc, q)| (*enc, q.to_bits())).collect()
    };
    assert_eq!(
        bits(&reparsed),
        bits(&parsed),
        "upper-casing and padding the tokens changed the parse: {shouted:?} \
         (from {header:?})"
    );
});
