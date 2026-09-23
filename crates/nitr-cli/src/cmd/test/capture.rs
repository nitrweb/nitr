// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Per-test log capture for `nitr test`: a tracing layer that appends
//! every event into a bounded buffer, which the runner empties at each
//! test's start and drains at its end. A failed test prints its entries;
//! `t.logs()` reads them while the test runs.
//!
//! One process-wide buffer, because the subscriber is process-wide — and
//! sound because files and tests run strictly one after another, and
//! `t.request` is awaited inline, so what lands between a test's start
//! and end is that test's. A line a streaming producer emits after its
//! body was collected is attributed to whichever test is current; it is
//! shown, never fatal.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::Mutex;

use tracing::field::{Field, Visit};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Entries kept per test before the oldest are dropped: a chatty handler
/// must not grow the buffer without bound.
pub(crate) const MAX_ENTRIES: usize = 10_000;

/// One captured event.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) level: tracing::Level,
    pub(crate) target: String,
    pub(crate) message: String,
    /// `nitr.log`'s `fields` (a JSON object as text), or the event's
    /// other fields rendered as `key=value`.
    pub(crate) fields: Option<String>,
    /// The id of the `request` span the event happened inside.
    pub(crate) request_id: Option<String>,
}

impl Entry {
    /// The console form: `WARN lua: quota {"used":9}`.
    pub(crate) fn line(&self) -> String {
        let mut out = format!("{} {}: {}", self.level, self.target, self.message);
        if let Some(fields) = &self.fields {
            let _ = write!(out, " {fields}");
        }
        if let Some(id) = &self.request_id {
            let _ = write!(out, " [request {id}]");
        }
        out
    }
}

#[derive(Default)]
struct Buffer {
    entries: VecDeque<Entry>,
    dropped: u64,
}

static BUFFER: Mutex<Buffer> = Mutex::new(Buffer {
    entries: VecDeque::new(),
    dropped: 0,
});

fn with_buffer<R>(f: impl FnOnce(&mut Buffer) -> R) -> R {
    // A panic cannot happen while the lock is held (nothing below
    // panics); recover the data rather than lose every later test's logs.
    let mut guard = BUFFER.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// Empties the buffer: a test's capture starts here.
pub(crate) fn clear() {
    with_buffer(|b| {
        b.entries.clear();
        b.dropped = 0;
    });
}

/// Takes the buffer's contents and how many entries overflowed.
pub(crate) fn take() -> (Vec<Entry>, u64) {
    with_buffer(|b| {
        let entries = b.entries.drain(..).collect();
        (entries, std::mem::take(&mut b.dropped))
    })
}

/// A copy of what the current test has logged so far (`t.logs()`).
pub(crate) fn snapshot() -> Vec<Entry> {
    with_buffer(|b| b.entries.iter().cloned().collect())
}

fn push(entry: Entry) {
    with_buffer(|b| {
        if b.entries.len() >= MAX_ENTRIES {
            b.entries.pop_front();
            b.dropped += 1;
        }
        b.entries.push_back(entry);
    });
}

/// The request id a `request` span recorded, kept in its extensions.
struct RequestId(String);

#[derive(Default)]
struct Fields {
    message: String,
    fields: Option<String>,
    id: Option<String>,
    rest: Vec<(String, String)>,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record(field, format!("{value:?}"));
    }
}

impl Fields {
    fn record(&mut self, field: &Field, value: String) {
        match field.name() {
            "message" => self.message = value,
            "fields" => self.fields = Some(value),
            "id" => self.id = Some(value),
            name => self.rest.push((name.to_string(), value)),
        }
    }
}

/// The capture layer, installed beside the console layer under
/// `nitr test`.
pub(crate) struct CaptureLayer;

impl<S> tracing_subscriber::Layer<S> for CaptureLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        if attrs.metadata().name() != "request" {
            return;
        }
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        if let (Some(request_id), Some(span)) = (fields.id, ctx.span(id)) {
            span.extensions_mut().insert(RequestId(request_id));
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let request_id = ctx.event_scope(event).and_then(|scope| {
            scope
                .from_root()
                .find_map(|span| span.extensions().get::<RequestId>().map(|id| id.0.clone()))
        });
        let extra = (!fields.rest.is_empty()).then(|| {
            fields
                .rest
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ")
        });
        push(Entry {
            level: *event.metadata().level(),
            target: event.metadata().target().to_string(),
            message: fields.message,
            fields: fields.fields.or(extra),
            request_id,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: usize) -> Entry {
        Entry {
            level: tracing::Level::INFO,
            target: "lua".into(),
            message: format!("line {n}"),
            fields: None,
            request_id: None,
        }
    }

    /// Adversarial row A4: a chatty handler cannot grow the buffer past
    /// its bound; the oldest entries go, and the report says how many.
    #[test]
    fn the_capture_buffer_is_bounded_and_counts_what_it_dropped() {
        clear();
        for n in 0..MAX_ENTRIES + 5 {
            push(entry(n));
        }
        assert_eq!(snapshot().len(), MAX_ENTRIES);
        let (entries, dropped) = take();
        assert_eq!(dropped, 5);
        assert_eq!(entries.len(), MAX_ENTRIES);
        assert_eq!(entries[0].message, "line 5", "the oldest go first");
        assert!(take().0.is_empty(), "take drains");
    }
}
