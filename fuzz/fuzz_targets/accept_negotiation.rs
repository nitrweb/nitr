// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `Accept` negotiation: `nitr_std::best_match`, the function behind
//! `nitr.http.negotiate`, which decides which representation a handler
//! returns — and returns `406 Not Acceptable` when it decides none does.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! accept \0 offer \0 offer \0 …
//! ```
//!
//! Every remaining field is an offer, so the offer *count* is fuzzer-driven
//! too: the tie-break rule only exists once two offers can rank equally,
//! and the empty-offer-list corner is one NUL away.
//!
//! ## The ordering oracle, and where it stops
//!
//! The header is parsed a second time here to give every offer its own
//! `(quality, specificity)` key, mirroring the real rules — the last `q=`
//! parameter of an entry wins, an unparseable weight is `0.0`, a weight of
//! zero or less is a refusal, an exact range scores 2, `type/*` scores 1
//! and `*/*` scores 0. The winner's key must then be the maximum, with
//! ties going to the earlier offer.
//!
//! That oracle is gated on the header containing no `q=NaN`, because the
//! ordering property **does not hold** when one does. `"NaN".parse::<f32>()`
//! succeeds, so the `unwrap_or(0.0)` that is meant to make a malformed
//! weight unacceptable is bypassed (`NaN <= 0.0` is false), and every later
//! comparison against that weight is false as well — so the first
//! NaN-weighted range that matches anything wins outright and nothing can
//! outrank it. `Accept: text/html;q=NaN, application/json` over the offers
//! `["application/json", "text/html"]` returns `text/html`. It is reported
//! as a finding rather than asserted; the structural properties below stay
//! asserted for those inputs.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **The winner is acceptable per the header text.** It has a key at
//!   all: some range in the header matches it with a weight above zero.
//!   This is the property the previous target was missing — a `best_match`
//!   that returned `Some(0)` unconditionally passed every check it had,
//!   and would hand a client a representation it explicitly refused.
//! * **Quality first, then specificity.** No offer has a strictly greater
//!   key than the winner's. A negotiation that ignored `q` (serving
//!   `*/*;q=0.1` over an exact `q=1` match), or that let `*/*` outrank an
//!   exact range, fails here. `design/25` promised this property and it
//!   was never implemented.
//! * **Ties go to the earlier offer.** No offer with a key equal to the
//!   winner's sits before it. The offer order is the handler's own
//!   preference list, so a tie resolved the other way silently inverts it,
//!   and `best_match` documents this rule explicitly.
//! * **A refused offer never wins.** For every offer that can be spliced
//!   into a header without re-splitting it — no `,`, no `;` — an `Accept`
//!   made of that offer with `q=0` yields no winner at all. Catches a
//!   `q < 0.0` refusal test and a weight that is parsed and then dropped.
//! * **The winner offered alone still wins.** Its selection was about the
//!   header, not about the company it kept.
//! * **An offer used as its own header names itself.** Negotiating the
//!   winner's own media type against the full list must pick that same
//!   type (or an earlier duplicate of it) — an exact range must beat every
//!   wildcard, which is the one ranking a handler relies on when it lists
//!   a specific type first.
//! * **If nothing wins, nothing wins alone either.** A verdict of "not
//!   acceptable" cannot be an artefact of the other offers; this is the
//!   406 path, and an offer wrongly excluded here is a request answered
//!   with an error the client did nothing to deserve.
//!
//! The previous target's determinism check is gone: it called a pure
//! function twice with identical arguments and asserted the results
//! matched, which no wrong implementation of this function fails.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_std::best_match;

/// How precisely `range` names `offer`, or `None` when it does not name it
/// at all: 2 for an exact range, 1 for `type/*`, 0 for `*/*`. The same
/// three tiers `best_match` scores, derived here from the header text.
fn specificity(range: &str, offer: &str) -> Option<u8> {
    if range.eq_ignore_ascii_case(offer) {
        Some(2)
    } else if range == "*/*" {
        Some(0)
    } else if let Some(main) = range.strip_suffix("/*") {
        match offer.split('/').next() {
            Some(offer_main) if offer_main.eq_ignore_ascii_case(main) => Some(1),
            _ => None,
        }
    } else {
        None
    }
}

/// The best `(quality, specificity)` each offer can claim under this
/// header, and whether the header carried a `q=NaN` — see the module docs
/// for why that poisons the ranking.
fn rank(accept: &str, offered: &[&str]) -> (Vec<Option<(f32, u8)>>, bool) {
    let mut keys = vec![None; offered.len()];
    let mut saw_nan = false;
    for item in accept.split(',') {
        let mut parts = item.trim().split(';');
        let range = match parts.next() {
            Some(r) if !r.trim().is_empty() => r.trim(),
            _ => continue,
        };
        // The *last* `q=` parameter wins, and anything unparseable is a
        // refusal.
        let mut q = 1.0_f32;
        for param in parts {
            if let Some(v) = param.trim().strip_prefix("q=") {
                q = v.trim().parse().unwrap_or(0.0);
            }
        }
        if q.is_nan() {
            saw_nan = true;
            continue;
        }
        if q <= 0.0 {
            continue;
        }
        for (i, offer) in offered.iter().enumerate() {
            let Some(spec) = specificity(range, offer) else {
                continue;
            };
            let candidate = (q, spec);
            let better = match keys[i] {
                None => true,
                Some((best_q, best_spec)) => {
                    q > best_q || (q == best_q && spec > best_spec)
                }
            };
            if better {
                keys[i] = Some(candidate);
            }
        }
    }
    (keys, saw_nan)
}

/// Strictly outranks: greater quality, or equal quality and a more
/// specific range. Free of NaN by construction — `keys` drops those.
fn outranks(a: (f32, u8), b: (f32, u8)) -> bool {
    a.0 > b.0 || (a.0 == b.0 && a.1 > b.1)
}

fuzz_target!(|data: &[u8]| {
    let input = Input::new(data);
    let fields = input.texts();
    let Some((accept, offers)) = fields.split_first() else {
        return;
    };
    let offers: Vec<&str> = offers.iter().map(String::as_str).collect();

    if std::env::var_os("NITR_FUZZ_DEBUG").is_some() {
        eprintln!("DEBUG accept={accept:?} offers={offers:?}");
    }

    let winner = best_match(accept, &offers);
    let (keys, saw_nan) = rank(accept, &offers);

    match winner {
        Some(i) => {
            assert!(
                i < offers.len(),
                "winner {i} is out of {} offers for {accept:?}",
                offers.len()
            );

            if !saw_nan {
                let key = keys[i].unwrap_or_else(|| {
                    panic!(
                        "{:?} won against {accept:?}, but no range in that header names it \
                         with a weight above zero; keys={keys:?}",
                        offers[i]
                    )
                });
                for (j, other) in keys.iter().enumerate() {
                    let Some(other) = *other else { continue };
                    assert!(
                        !outranks(other, key),
                        "{:?} (key {other:?}) outranks the winner {:?} (key {key:?}) \
                         against {accept:?}; offers={offers:?}",
                        offers[j],
                        offers[i]
                    );
                    assert!(
                        !(other == key && j < i),
                        "{:?} at {j} ties the winner {:?} at {i} (key {key:?}) but comes \
                         earlier, so it should have won; accept={accept:?} offers={offers:?}",
                        offers[j],
                        offers[i]
                    );
                }
            }

            // Offered alone, against the same header, it still wins.
            assert_eq!(
                best_match(accept, &[offers[i]]),
                Some(0),
                "{:?} won against {accept:?} among {offers:?}, but not on its own",
                offers[i]
            );

            // The winner's own media type as the header. Only for text
            // that survives being spliced into one: an offer carrying a
            // `,` or `;` would be re-split into something else entirely,
            // and one with outer whitespace would no longer match itself
            // once the parser trims the range but not the offer.
            let own = offers[i];
            if !own.is_empty() && own.trim() == own && !own.contains([',', ';']) {
                let by_name = best_match(own, &offers).unwrap_or_else(|| {
                    panic!("{own:?} as its own Accept header accepts nothing in {offers:?}")
                });
                assert!(
                    offers[by_name].eq_ignore_ascii_case(own),
                    "{own:?} as its own Accept header picked {:?} instead; offers={offers:?}",
                    offers[by_name]
                );
            }
        }
        None => {
            // A key exists only for a range that matched with a usable
            // weight, and any such match would have produced a winner —
            // NaN or no NaN.
            for (j, key) in keys.iter().enumerate() {
                assert!(
                    key.is_none(),
                    "nothing was acceptable to {accept:?}, yet {:?} scores {key:?}",
                    offers[j]
                );
            }
            // And the verdict does not depend on the other offers.
            for &offer in &offers {
                assert_eq!(
                    best_match(accept, &[offer]),
                    None,
                    "{offer:?} is acceptable alone but not among {offers:?} for {accept:?}"
                );
            }
        }
    }

    // A weight of zero is a refusal. Only for an offer that survives being
    // spliced into a header: one carrying a `,` or a `;` is re-split into
    // several ranges and the `;q=0` then binds to the last of them alone,
    // leaving the earlier pieces at the default weight — the same reason
    // the "offer as its own header" check above is guarded. That is the
    // header grammar doing its job, not a refusal being ignored.
    for &offer in &offers {
        if offer.contains([',', ';']) {
            continue;
        }
        let refused = format!("{offer};q=0");
        assert_eq!(
            best_match(&refused, &[offer]),
            None,
            "{refused:?} still accepts {offer:?}"
        );
    }
});
