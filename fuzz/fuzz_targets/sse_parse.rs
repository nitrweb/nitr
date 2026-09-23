// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The event-stream parser behind `resp:sse()` in `nitr test`
//! (`nitr_http::testing::parse_sse`). It reads a body a handler under
//! test produced, and it is hand-written, so it joins the fuzz set.
//!
//! Input layout (see `nitr_fuzz::Input`): the whole input is the body.
//!
//! What is asserted, and the wrong-but-not-crashing parser each one
//! catches:
//!
//! * **Totality.** Any bytes are a body: no panic, no reject path.
//! * **Nothing is invented.** Every line of every event's data, every
//!   event name and id is text of the (lossily decoded) body — a parser
//!   that synthesized or mangled a field fails.
//! * **One event per blank line at most.** A dispatch needs a blank line,
//!   so the count of events is bounded by the count of line terminators.
//! * **No field smuggles a line.** No event name, id or data line holds
//!   `\r` or `\n`: a terminator inside a field is a second field.
//! * **Re-serializing is a fixpoint.** Writing the events back the way
//!   `nitr.sse` writes them (`event:`, `id:`, `retry:`, one `data:` per
//!   line, a blank line) parses to the same events — which pins the
//!   one-space strip, the data join, and the per-event reset.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_http::testing::{SseEvent, parse_sse};

fn serialize(events: &[SseEvent]) -> String {
    let mut out = String::new();
    for event in events {
        if let Some(name) = &event.event {
            out.push_str(&format!("event: {name}\n"));
        }
        if let Some(id) = &event.id {
            out.push_str(&format!("id: {id}\n"));
        }
        if let Some(retry) = event.retry {
            out.push_str(&format!("retry: {retry}\n"));
        }
        for line in event.data.split('\n') {
            out.push_str(&format!("data: {line}\n"));
        }
        out.push('\n');
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let body = Input::new(data).rest();
    let events = parse_sse(body);
    let text = String::from_utf8_lossy(body);

    let terminators = text.matches(['\r', '\n']).count();
    assert!(
        events.len() <= terminators,
        "{} events out of {terminators} line terminators: {text:?}",
        events.len()
    );
    for event in &events {
        let fields = event
            .event
            .iter()
            .chain(event.id.iter())
            .map(String::as_str)
            .chain(event.data.split('\n'));
        for field in fields {
            assert!(
                !field.contains(['\r', '\n']),
                "a field carries a line terminator: {field:?} in {text:?}"
            );
            assert!(
                text.contains(field),
                "{field:?} is not text of the body {text:?}: invented or mangled"
            );
        }
    }

    let again = parse_sse(serialize(&events).as_bytes());
    assert_eq!(
        again, events,
        "the events of {text:?} do not survive being written back"
    );
});
