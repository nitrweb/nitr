// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `Accept` header negotiation: a hostile header must never panic, and
//! what it picks must behave like a real preference order.
//!
//! Beyond the bounds check, three behavioral invariants: negotiation is
//! deterministic (same inputs, same winner); a winner keeps winning when
//! the losing offers are removed (the choice was about the header, not
//! the company); and an offer the header names verbatim with an explicit
//! `q=1` is never *worse* than nothing when it was already the winner.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&str, Vec<&str>)| {
    let (accept, offers) = input;
    let winner = nitr_std::best_match(accept, &offers);

    if let Some(i) = winner {
        assert!(
            i < offers.len(),
            "winner {i} out of {} offers",
            offers.len()
        );

        // Deterministic: the same negotiation picks the same offer.
        assert_eq!(
            nitr_std::best_match(accept, &offers),
            Some(i),
            "negotiation must be deterministic"
        );

        // Stable under removal of losers: offered alone, the winner is
        // still acceptable to this header.
        let alone = [offers[i]];
        assert_eq!(
            nitr_std::best_match(accept, &alone),
            Some(0),
            "winner `{}` no longer acceptable when offered alone against `{accept}`",
            offers[i]
        );
    } else {
        // No winner means no offer is acceptable; that verdict must not
        // depend on the offers' company either.
        for offer in &offers {
            let alone = [*offer];
            assert_eq!(
                nitr_std::best_match(accept, &alone),
                None,
                "`{offer}` acceptable alone but not in the full list against `{accept}`"
            );
        }
    }
});
