// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use hyper::body::{Body, Frame};

use super::body::StalledBody;
use super::*;

/// A body that never produces anything — the stalled client.
struct NeverBody;

impl Body for NeverBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        // No waker registration needed: the stall timer is what wakes
        // the task.
        Poll::Pending
    }
}

/// A body that trickles `frames` one-byte frames, one per `delay` —
/// the slow-but-honest client.
struct TrickleBody {
    frames: usize,
    delay: std::time::Duration,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Body for TrickleBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.frames == 0 {
            return Poll::Ready(None);
        }
        let delay = this.delay;
        let sleep = this
            .sleep
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(delay)));
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => {
                this.sleep = None;
                this.frames -= 1;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"x")))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// `start_paused`: both the budget and the trickle below run on tokio
// timers, so virtual time makes these exact — the old real-clock
// margins (a 30ms trickle against an 80ms budget) rode on the
// scheduler's mood on a loaded runner.
#[tokio::test(start_paused = true)]
async fn a_stalled_body_read_fails_and_sets_the_flag() {
    let stalled = Arc::new(AtomicBool::new(false));
    let mut body = StalledBody {
        inner: NeverBody.boxed(),
        budget: std::time::Duration::from_millis(40),
        deadline: None,
        stalled: stalled.clone(),
    };
    let err = body
        .frame()
        .await
        .expect("a frame result")
        .expect_err("the stall must fail the read");
    assert!(err.to_string().contains("stalled"), "got: {err}");
    assert!(stalled.load(Ordering::Relaxed));
}

/// The budget bounds *progress*, not total transfer: a transfer whose
/// every gap stays under the budget completes no matter how long it
/// takes in total.
#[tokio::test(start_paused = true)]
async fn a_slow_but_moving_body_completes() {
    let stalled = Arc::new(AtomicBool::new(false));
    let mut body = StalledBody {
        inner: TrickleBody {
            frames: 4,
            delay: std::time::Duration::from_millis(30),
            sleep: None,
        }
        .boxed(),
        // Under 4 × 30 ms of total transfer, over any single gap.
        budget: std::time::Duration::from_millis(80),
        deadline: None,
        stalled: stalled.clone(),
    };
    let mut got = 0;
    while let Some(frame) = body.frame().await {
        frame.expect("no gap exceeds the budget");
        got += 1;
    }
    assert_eq!(got, 4);
    assert!(!stalled.load(Ordering::Relaxed));
}

fn headers(pairs: &[(&'static str, &str)]) -> hyper::HeaderMap {
    let mut map = hyper::HeaderMap::new();
    for (name, value) in pairs {
        map.insert(*name, value.parse().expect("header value"));
    }
    map
}

#[test]
fn if_none_match_compares_ignoring_weakness() {
    let h = headers(&[("if-none-match", "\"abc\"")]);
    assert!(is_fresh(&h, Some("\"abc\""), None));
    assert!(is_fresh(&h, Some("W/\"abc\""), None));
    assert!(!is_fresh(&h, Some("\"other\""), None));
    // No validator to compare against is not a match.
    assert!(!is_fresh(&h, None, None));
}

#[test]
fn if_none_match_handles_lists_and_the_wildcard() {
    let list = headers(&[("if-none-match", "\"a\", \"b\" , \"c\"")]);
    assert!(is_fresh(&list, Some("\"b\""), None));
    assert!(!is_fresh(&list, Some("\"d\""), None));

    let any = headers(&[("if-none-match", "*")]);
    assert!(is_fresh(&any, Some("\"anything\""), None));
}

#[test]
fn if_modified_since_applies_only_without_an_entity_tag() {
    let stamp = 1_700_000_000i64;
    let date = httpdate::fmt_http_date(
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(stamp as u64),
    );

    let only_date = headers(&[("if-modified-since", &date)]);
    assert!(is_fresh(&only_date, None, Some(stamp)));
    assert!(is_fresh(&only_date, None, Some(stamp - 60)));
    assert!(!is_fresh(&only_date, None, Some(stamp + 60)));

    // With both present the entity tag decides, even when the date
    // would have said "fresh".
    let both = headers(&[("if-none-match", "\"x\""), ("if-modified-since", &date)]);
    assert!(!is_fresh(&both, Some("\"y\""), Some(stamp)));
}

#[test]
fn a_request_without_validators_is_never_fresh() {
    assert!(!is_fresh(
        &hyper::HeaderMap::new(),
        Some("\"abc\""),
        Some(1)
    ));
}
