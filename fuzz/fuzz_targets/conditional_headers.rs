// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `If-None-Match` and `If-Modified-Since` as `is_fresh` weighs them: the
//! function that decides whether a client is told `304 Not Modified`
//! instead of being sent a body. Both `static_files::try_serve` and the
//! Lua `req:fresh(etag, last_modified)` route through it, so a wrong
//! `true` here is not a crash — it is a client pinned to a stale copy for
//! as long as it keeps revalidating.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u64 last_modified | u8 flags | u8 pick | if-none-match \0 if-modified-since \0 etag
//! ```
//!
//! `last_modified` is read back as an `i64`, so the whole domain — including
//! the pre-epoch times a file can carry — is reachable. `flags` bit 0 says
//! the server has *no* entity tag (`etag: None`), and bit 1 wraps the etag
//! field in quotes: `static_files` always passes a strong server-built tag
//! (`"3e8-6553f100"`), but `req:fresh` passes whatever the handler wrote, so
//! both the well-formed shape and raw attacker-ish text belong in the
//! domain. `pick` chooses where the etag sits inside a synthesized list and
//! which date spelling is used, so those two axes are steerable instead of
//! having to be discovered byte by byte.
//!
//! Header values go in through `HeaderValue::from_bytes`, and when hyper
//! refuses the bytes that one insert is skipped rather than the run being
//! thrown away — the rest of the assertions still hold.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **A request with no validators is never fresh.** An empty header map,
//!   under every modification time — absent, the fuzzer's own, the epoch
//!   and `i64::MAX`. Pins the safe default; an implementation whose
//!   fall-through is `true` answers `304` to a plain `GET`.
//! * **Precedence, as a differential.** RFC 9110 §13.1.3 requires a
//!   recipient to *ignore* `If-Modified-Since` when `If-None-Match` is
//!   present. So with a readable `If-None-Match` in the map, the answer is
//!   recomputed under three modification times and four `If-Modified-Since`
//!   values — absent, the epoch, the last instant HTTP can name, and text
//!   that is no date at all — and all twelve must agree. The pair (`epoch`,
//!   `9999`) at `last_modified = 1` is genuinely discriminating: those two
//!   dates give *opposite* answers on the date path, so any leak of the
//!   date into the entity-tag decision fires here. An `||` of the two
//!   conditions — the natural wrong implementation — hands a `304` to a
//!   client whose etag did not match.
//! * **No entity tag means no match.** With `etag: None` and any readable
//!   `If-None-Match` at all, the answer is false. A resource the server
//!   cannot identify cannot be certified unchanged; treating "no tag" as
//!   "matches" (or letting `*` through) serves a stale body forever.
//! * **An etag echoed back is a match, wherever it sits in the list.** The
//!   list is synthesized with the etag at a fuzzer-chosen index among
//!   non-matching members, so an implementation that only inspects the
//!   first entry — `split(',').next()` — or only the last fails here, while
//!   a single-tag test would not.
//! * **`W/"x"` and `"x"` are the same tag, symmetrically.** `If-None-Match`
//!   is defined to use the weak comparison, so the prefix must be stripped
//!   on *both* sides: asserted with the weak form in the header against a
//!   strong server tag, and with the strong form in the header against a
//!   weak server tag. Stripping only the candidate is the easy half-fix and
//!   it fails the second direction.
//! * **`*` matches any representation the server can identify, and only
//!   those.** Alone and buried in a list, `*` is a match exactly when an
//!   etag exists.
//! * **An empty list names nothing.** A present-but-empty `If-None-Match`
//!   still outranks the date (that half is inside the precedence check),
//!   and it matches only the two degenerate tags that weak-strip to the
//!   empty string — `""` and a bare `W/`, neither of which is a tag any
//!   handler should be passing. Written out exactly rather than as
//!   "never matches", because the fuzzer found the `W/` case: an
//!   implementation that treated an empty list as an absent header would
//!   change this answer, and so would one that read it as `*`.
//! * **A tag absent from the list is not a match.** The list is built out
//!   of near misses of the real etag: one character longer, one shorter,
//!   the weak spelling of the longer one, and the upper-cased tag. That
//!   catches a `starts_with` comparison in either direction and any case
//!   folding — entity tags are opaque and compared byte for byte.
//! * **Whitespace around list members is not part of a tag.** Re-padding
//!   every member of the attacker's own list must not change the answer;
//!   catches a lost `trim()` on the candidate.
//! * **Dates are second-exact and monotone, in all three grammars.** For
//!   every spelling RFC 9110 requires a recipient to accept (IMF-fixdate,
//!   RFC 850, asctime): a copy taken at exactly that second is fresh, one
//!   second earlier is fresh, one second *later* is not — that last one is
//!   the direction that matters, since `>=` for `<=` serves a file modified
//!   after the client's copy as unchanged.
//! * **An unknown modification time is never fresh**, for any date text at
//!   all, and **no date can outrank `i64::MAX`**: an HTTP-date cannot name
//!   an instant past `9999-12-31`, so a `last_modified` of `i64::MAX` must
//!   always lose. Together with the monotonicity step below they pin the
//!   comparison's direction over attacker text, not just over the table.
//! * **The date path does not consult the entity tag.** Every date
//!   assertion runs under the fuzzer's etag, present or absent; a date is
//!   the server's own statement about the representation and gating it on
//!   an etag would drop `304`s for every resource that has no tag.
//!
//! ## A deviation this deliberately does not assert
//!
//! `is_fresh` reads `If-None-Match` through `HeaderValue::to_str`, which
//! refuses obs-text. hyper *accepts* those bytes, so a request carrying a
//! non-ASCII `If-None-Match` is treated as carrying none at all, and the
//! `If-Modified-Since` date then decides — which is exactly the precedence
//! the RFC forbids. The precedence assertion is therefore restricted to a
//! readable header, and the case is reported instead of being papered over
//! or asserted as intended behaviour. `NITR_FUZZ_DEBUG=1` prints it.
#![no_main]
use hyper::header::{HeaderMap, HeaderName, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH};
use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_http::fuzzing::is_fresh;

/// One instant per row, followed by every spelling of it a recipient must
/// accept: IMF-fixdate, the obsolete RFC 850 form, and `asctime`. Wrong
/// rows cannot hide: a spelling that stopped parsing makes the very first
/// date assertion below fail rather than silently turning it into a no-op.
const DATES: &[(i64, &[&str])] = &[
    (
        784_111_777,
        &[
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ],
    ),
    // The epoch, where a subtraction that underflows would land.
    (
        0,
        &[
            "Thu, 01 Jan 1970 00:00:00 GMT",
            "Thursday, 01-Jan-70 00:00:00 GMT",
            "Thu Jan  1 00:00:00 1970",
        ],
    ),
    // A leap day: the calendar arithmetic on both sides has to agree.
    (
        1_456_747_200,
        &[
            "Mon, 29 Feb 2016 12:00:00 GMT",
            "Monday, 29-Feb-16 12:00:00 GMT",
            "Mon Feb 29 12:00:00 2016",
        ],
    ),
    (
        1_700_000_000,
        &[
            "Tue, 14 Nov 2023 22:13:20 GMT",
            "Tuesday, 14-Nov-23 22:13:20 GMT",
            "Tue Nov 14 22:13:20 2023",
        ],
    ),
    // The top of the representable range. RFC 850's two-digit year cannot
    // name it, so only the fixdate spelling appears.
    (253_402_300_799, &["Fri, 31 Dec 9999 23:59:59 GMT"]),
];

/// The earliest and the latest instant an HTTP-date can name. Used as the
/// discriminating pair for the precedence differential: at
/// `last_modified = 1` the first says "not fresh" and the second says
/// "fresh", so an `If-Modified-Since` that leaks into the entity-tag
/// decision cannot stay hidden.
const EPOCH: &str = "Thu, 01 Jan 1970 00:00:00 GMT";
const FAR_FUTURE: &str = "Fri, 31 Dec 9999 23:59:59 GMT";

/// List members that name some other representation. None of them is `*`,
/// so the synthesized list is a match only because the etag itself is in
/// it — which is what makes the placement assertion meaningful.
const FILLERS: &[&str] = &["W/\"aaa\"", "\"bbb\"", "\"ccc\""];

/// Sets `name` to `value` and reports whether a reader of the map gets
/// that same text back.
///
/// Two things can go wrong and `is_fresh` treats both as "no header": the
/// bytes are not a legal header value, or they are legal but not visible
/// ASCII, so `HeaderValue::to_str` refuses them. Assertions about what the
/// header *says* only hold when this returns `true`.
fn set(map: &mut HeaderMap, name: HeaderName, value: &str) -> bool {
    match HeaderValue::from_bytes(value.as_bytes()) {
        Ok(parsed) => {
            map.insert(&name, parsed);
            map.get(&name).and_then(|v| v.to_str().ok()) == Some(value)
        }
        Err(_) => {
            map.remove(&name);
            false
        }
    }
}

/// The freshness of a request carrying `list` as `If-None-Match`, checked
/// against every date and every modification time that must not be able to
/// reach the answer. `None` when hyper cannot carry `list` as a readable
/// header value, which is the one case where the precedence rule below is
/// not what `is_fresh` implements (see the module docs).
fn under_inm(list: &str, etag: Option<&str>, modified: i64) -> Option<bool> {
    let mut map = HeaderMap::with_capacity(2);
    if !set(&mut map, IF_NONE_MATCH, list) {
        return None;
    }
    let answer = is_fresh(&map, etag, Some(modified));

    // An entity tag is an exact identifier and a date is a heuristic, so
    // once a tag has been offered the date is not evidence about anything.
    // `1` is in the list because it is the modification time at which
    // `EPOCH` and `FAR_FUTURE` disagree — the pair that makes a leak of
    // the date into this decision visible. Nothing arithmetic happens on
    // this path, so the saturating values buy no coverage here and are
    // left to the date section, where they do.
    for last_modified in [None, Some(1), Some(modified)] {
        for date in [None, Some(EPOCH), Some(FAR_FUTURE), Some("not-a-date")] {
            match date {
                Some(text) => assert!(
                    set(&mut map, IF_MODIFIED_SINCE, text),
                    "{text:?} is not a header value"
                ),
                None => {
                    map.remove(&IF_MODIFIED_SINCE);
                }
            }
            let got = is_fresh(&map, etag, last_modified);
            assert_eq!(
                got, answer,
                "If-Modified-Since {date:?} with last_modified {last_modified:?} changed the \
                 answer from {answer} to {got}, although If-None-Match {list:?} was present; \
                 an entity tag decides on its own (etag {etag:?})"
            );
        }
    }
    Some(answer)
}

/// Asserts what `list` must say about `etag` — and, whatever it says, that
/// it says nothing when the server has no entity tag at all.
fn expect(list: &str, etag: &str, modified: i64, fresh: bool, why: &str) {
    if let Some(got) = under_inm(list, Some(etag), modified) {
        assert_eq!(
            got, fresh,
            "If-None-Match {list:?} against the etag {etag:?} answered {got}: {why}"
        );
    }
    if let Some(got) = under_inm(list, None, modified) {
        assert!(
            !got,
            "If-None-Match {list:?} was answered {got} although the server has no entity tag \
             to compare against; the client would keep a copy of a representation the server \
             cannot identify"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let modified = input.u64() as i64;
    let flags = input.u8();
    let pick = usize::from(input.u8());
    let inm = input.text();
    let ims = input.text();
    let raw = input.text();

    // Either shape of validator: the strong tag `static_files` builds, or
    // the unconstrained string a Lua handler can hand `req:fresh`.
    let etag = if flags & 2 == 0 {
        raw.into_owned()
    } else {
        format!("\"{raw}\"")
    };
    let etag_opt = (flags & 1 == 0).then_some(etag.as_str());

    if std::env::var_os("NITR_FUZZ_DEBUG").is_some() {
        eprintln!("DEBUG modified={modified} inm={inm:?} ims={ims:?} etag={etag_opt:?}");
        // The recorded deviation, printed with real numbers when the input
        // reaches it: an If-None-Match hyper accepts but cannot hand back
        // as text is skipped, and the date decides after all.
        if let Ok(value) = HeaderValue::from_bytes(inm.as_bytes()) {
            let mut probe = HeaderMap::with_capacity(2);
            probe.insert(IF_NONE_MATCH, value);
            if probe
                .get(IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .is_none()
            {
                set(&mut probe, IF_MODIFIED_SINCE, EPOCH);
                let epoch = is_fresh(&probe, etag_opt, Some(1));
                set(&mut probe, IF_MODIFIED_SINCE, FAR_FUTURE);
                let far = is_fresh(&probe, etag_opt, Some(1));
                eprintln!(
                    "DEBUG unreadable If-None-Match {inm:?}: fresh={epoch} under {EPOCH:?}, \
                     fresh={far} under {FAR_FUTURE:?} — the date decided"
                );
            }
        }
    }

    // No validators at all
    let bare = HeaderMap::new();
    for last_modified in [None, Some(modified), Some(0), Some(i64::MAX)] {
        assert!(
            !is_fresh(&bare, etag_opt, last_modified),
            "a request carrying no conditional header was answered 304 (etag {etag_opt:?}, \
             last_modified {last_modified:?})"
        );
    }

    // The attacker's own list
    let plain = under_inm(&inm, etag_opt, modified);
    // OWS around a member belongs to the list grammar, not to the tag.
    let padded = inm
        .split(',')
        .map(|member| format!(" {member} "))
        .collect::<Vec<_>>()
        .join(",");
    if let (Some(before), Some(after)) = (plain, under_inm(&padded, etag_opt, modified)) {
        assert_eq!(
            before, after,
            "padding the members of {inm:?} into {padded:?} changed the answer from {before} \
             to {after}; whitespace is not part of an entity tag (etag {etag_opt:?})"
        );
    }

    // The wildcard
    for list in ["*", "\"aaa\", *, W/\"bbb\"", " * "] {
        let got = under_inm(list, etag_opt, modified).unwrap_or_else(|| {
            panic!("{list:?} is a legal header value");
        });
        assert_eq!(
            got,
            etag_opt.is_some(),
            "If-None-Match {list:?} answered {got} with etag {etag_opt:?}; `*` matches every \
             representation the server can identify, and no representation it cannot"
        );
    }

    // An empty list
    // Present but naming nothing: still an If-None-Match, so it still wins
    // over the date (that part is asserted inside `under_inm`), and the
    // only tags it can match are the two that weak-strip to nothing.
    let empty = under_inm("", etag_opt, modified).unwrap_or_else(|| {
        panic!("an empty header value is legal");
    });
    assert_eq!(
        empty,
        matches!(etag_opt, Some("") | Some("W/")),
        "an empty If-None-Match answered {empty} against the etag {etag_opt:?}; the empty list \
         names no tag, so it can match nothing a handler could sensibly pass"
    );

    // Lists built out of the server's own tag
    // Only for a tag that survives being spliced into a list: a `,` would
    // re-split into different tags, outer whitespace would be trimmed away
    // by the parser but not by the comparison, and a tag already carrying
    // the weak prefix makes the two-sided `W/` claim below say something
    // else (`W/W/"x"` is not an entity tag).
    if !etag.contains(',') && etag.trim() == etag && !etag.starts_with("W/") {
        expect(
            &etag,
            &etag,
            modified,
            true,
            "a tag echoed back verbatim is the client holding this very representation",
        );

        // The weak comparison, from both sides.
        let weak = format!("W/{etag}");
        expect(
            &weak,
            &etag,
            modified,
            true,
            "If-None-Match uses the weak comparison, so `W/` on the candidate is not part of it",
        );
        if let Some(got) = under_inm(&etag, Some(&weak), modified) {
            assert!(
                got,
                "the strong spelling {etag:?} did not match the server's weak tag {weak:?}; \
                 the prefix has to be stripped on both sides, not only on the candidate"
            );
        }

        // Somewhere in a list of other people's tags.
        let mut members: Vec<&str> = FILLERS.to_vec();
        members.insert(pick % (FILLERS.len() + 1), etag.as_str());
        let list = members.join(", ");
        expect(
            &list,
            &etag,
            modified,
            true,
            "every member of the list is a tag the client holds, not just the first one",
        );

        // Near misses: one longer, one shorter, one shouted.
        let mut misses = vec![format!("{etag}x"), format!("W/{etag}x")];
        if !etag.is_empty() {
            let mut shorter = etag.clone();
            shorter.pop();
            misses.push(shorter);
        }
        let shouted = etag.to_ascii_uppercase();
        if shouted != etag {
            misses.push(shouted);
        }
        // A near miss that trimmed down to the wildcard would match on
        // purpose; it is not a near miss at all.
        misses.retain(|member| member.trim() != "*");
        let list = misses.join(", ");
        expect(
            &list,
            &etag,
            modified,
            false,
            "entity tags are opaque and compared byte for byte: no prefix match, no case folding",
        );
    }

    // The date path, on every spelling of one instant
    // One row and one spelling per run, both picked out of `pick`: each
    // spelling stands or falls on its own, so checking all of them every
    // run would buy the same coverage at a fraction of the throughput.
    let (secs, forms) = DATES[pick % DATES.len()];
    let form = forms[(pick / DATES.len()) % forms.len()];
    let mut dated = HeaderMap::with_capacity(1);
    assert!(
        set(&mut dated, IF_MODIFIED_SINCE, form),
        "{form:?} is not a header value"
    );
    // The etag is carried through every one of these: with no
    // If-None-Match in the map it has nothing to say, and gating the date
    // on it would drop every 304 for a resource that has no tag.
    assert!(
        is_fresh(&dated, etag_opt, Some(secs)),
        "{form:?} did not match a representation last modified at exactly {secs}s past the \
         epoch, which is the instant it names (etag {etag_opt:?})"
    );
    assert!(
        !is_fresh(&dated, etag_opt, Some(secs + 1)),
        "{form:?} matched a representation modified one second later; the client would keep a \
         copy of the older bytes (etag {etag_opt:?})"
    );
    if secs > 0 {
        assert!(
            is_fresh(&dated, etag_opt, Some(secs - 1)),
            "{form:?} did not match a representation modified one second earlier, so an \
             unchanged file would be re-sent on every request (etag {etag_opt:?})"
        );
    }
    assert!(
        !is_fresh(&dated, etag_opt, None),
        "{form:?} matched although the server does not know when the representation last \
         changed, so there was nothing to compare it against (etag {etag_opt:?})"
    );
    assert!(
        is_fresh(&dated, etag_opt, Some(i64::MIN)),
        "{form:?} did not match a representation that predates every instant it could name \
         (etag {etag_opt:?})"
    );
    assert!(
        !is_fresh(&dated, etag_opt, Some(i64::MAX)),
        "{form:?} matched a representation modified at i64::MAX, which no HTTP-date can reach \
         (etag {etag_opt:?})"
    );

    // The date path, on the attacker's own text
    let mut hostile = HeaderMap::with_capacity(1);
    if set(&mut hostile, IF_MODIFIED_SINCE, &ims) {
        // An HTTP-date cannot name anything past 9999-12-31, so whatever
        // this text parses to — if it parses at all — it is smaller.
        assert!(
            !is_fresh(&hostile, etag_opt, Some(i64::MAX)),
            "If-Modified-Since {ims:?} matched a representation modified at i64::MAX; no date \
             can name an instant that late, so the comparison ran the wrong way \
             (etag {etag_opt:?})"
        );
        assert!(
            !is_fresh(&hostile, etag_opt, None),
            "If-Modified-Since {ims:?} matched with no modification time known \
             (etag {etag_opt:?})"
        );
        // Freshness is monotone in the modification time: a copy taken
        // earlier is at least as fresh as one taken later. A comparison
        // written as `==`, or one that overflows, breaks the step.
        if is_fresh(&hostile, etag_opt, Some(modified)) {
            assert!(
                is_fresh(&hostile, etag_opt, Some(i64::MIN)),
                "If-Modified-Since {ims:?} matched at {modified} but not at i64::MIN \
                 (etag {etag_opt:?})"
            );
            if modified > i64::MIN {
                assert!(
                    is_fresh(&hostile, etag_opt, Some(modified - 1)),
                    "If-Modified-Since {ims:?} matched at {modified} but not one second \
                     earlier (etag {etag_opt:?})"
                );
            }
        }
    }
});
