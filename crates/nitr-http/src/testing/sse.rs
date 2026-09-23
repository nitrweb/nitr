// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! A parser for a collected `text/event-stream` body (`resp:sse()` in
//! `nitr test`), following the WHATWG event-stream interpretation rules.

/// One dispatched server-sent event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event:` field, when one was given.
    pub event: Option<String>,
    /// The `data:` lines, joined with `\n`.
    pub data: String,
    /// The `id:` field, when one was given.
    pub id: Option<String>,
    /// The `retry:` field, when it was a number.
    pub retry: Option<u64>,
}

/// Parses a whole event-stream body into its events, in order.
///
/// Lines end in `\r\n`, `\n` or `\r`; a blank line dispatches the event
/// being built, unless it has no `data` (which the spec discards); a line
/// starting with `:` is a comment; `field:value` loses one space after the
/// colon; a line without a colon is a field with an empty value; unknown
/// fields and an `id` containing NUL are ignored. A final event without
/// its blank line is not dispatched — a browser would not have seen it
/// either. Linear in the input, one pass, no recursion.
///
/// One deliberate difference from a browser, for the sake of assertions:
/// `id` and `retry` describe the event whose lines carried them, rather
/// than the stream-wide last-event-id and reconnection delay a client
/// keeps.
pub fn parse_sse(body: &[u8]) -> Vec<SseEvent> {
    let text = String::from_utf8_lossy(body);
    let mut events = Vec::new();
    let mut current = SseEvent::default();
    let mut has_data = false;
    let mut rest: &str = &text;
    // A leading byte-order mark is stripped once, per the spec.
    rest = rest.strip_prefix('\u{feff}').unwrap_or(rest);
    while !rest.is_empty() {
        let end = rest.find(['\r', '\n']).unwrap_or(rest.len());
        let line = &rest[..end];
        let mut next = &rest[end..];
        if next.starts_with("\r\n") {
            next = &next[2..];
        } else if !next.is_empty() {
            next = &next[1..];
        } else {
            // The last line had no terminator: it cannot complete an
            // event, but its fields still accumulate.
        }
        rest = next;

        if line.is_empty() {
            if has_data {
                events.push(std::mem::take(&mut current));
            } else {
                current = SseEvent::default();
            }
            has_data = false;
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            "event" => current.event = Some(value.to_string()),
            "data" => {
                if has_data {
                    current.data.push('\n');
                }
                current.data.push_str(value);
                has_data = true;
            }
            "id" if !value.contains('\0') => current.id = Some(value.to_string()),
            "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                current.retry = value.parse().ok();
            }
            _ => {}
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_parse_with_every_line_ending_and_field() {
        let body = b"retry: 1500\r\n: a comment\r\nevent: tick\nid: 7\ndata: one\rdata:two\n\ndata: {\"n\":1}\n\n";
        let events = parse_sse(body);
        assert_eq!(
            events,
            vec![
                SseEvent {
                    event: Some("tick".into()),
                    data: "one\ntwo".into(),
                    id: Some("7".into()),
                    retry: Some(1500),
                },
                SseEvent {
                    event: None,
                    data: "{\"n\":1}".into(),
                    id: None,
                    retry: None,
                },
            ]
        );
    }

    #[test]
    fn events_without_data_or_a_terminating_blank_line_are_not_dispatched() {
        assert!(
            parse_sse(b"event: ping\n\n").is_empty(),
            "no data, no event"
        );
        assert!(parse_sse(b"data: cut off").is_empty());
        assert!(parse_sse(b"").is_empty());
        let events = parse_sse(b"data\n\n");
        assert_eq!(events[0].data, "", "a bare field name has an empty value");
        let events = parse_sse(b"retry: soon\nid: a\0b\ndata: x\n\n");
        assert_eq!((events[0].retry, events[0].id.as_deref()), (None, None));
    }

    proptest::proptest! {
        /// Property: a list of events serialized the way `nitr.sse` writes
        /// them parses back to the same list.
        #[test]
        fn prop_sse_parser_events(
            events in proptest::collection::vec(
                (
                    proptest::option::of("[a-z]{1,8}"),
                    proptest::collection::vec("[ -~]{0,16}", 1..4),
                    proptest::option::of("[a-z0-9]{1,8}"),
                ),
                0..8,
            ),
            crlf in proptest::bool::ANY,
        ) {
            let nl = if crlf { "\r\n" } else { "\n" };
            let mut body = String::new();
            let mut expected = Vec::new();
            for (event, lines, id) in &events {
                if let Some(event) = event {
                    body.push_str(&format!("event: {event}{nl}"));
                }
                if let Some(id) = id {
                    body.push_str(&format!("id: {id}{nl}"));
                }
                for line in lines {
                    body.push_str(&format!("data: {line}{nl}"));
                }
                body.push_str(nl);
                expected.push(SseEvent {
                    event: event.clone(),
                    data: lines.join("\n"),
                    id: id.clone(),
                    retry: None,
                });
            }
            proptest::prop_assert_eq!(parse_sse(body.as_bytes()), expected);
        }
    }
}
