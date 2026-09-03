// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Body wrappers installed by [`LuaRequest::guard_body`]: the byte-ceiling
//! counter and the per-read stall timer, with the flags the handler reads
//! to answer `413`/`408` instead of a generic `500`.
//!
//! [`LuaRequest::guard_body`]: super::LuaRequest::guard_body

use std::future::Future as _;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use hyper::body::{Body, Bytes, Frame};

use super::IncomingBody;

pub(super) struct LimitedBody {
    pub(super) inner: IncomingBody,
    pub(super) limit: u64,
    pub(super) read: u64,
    pub(super) flags: Arc<BodyFlags>,
}

impl Body for LimitedBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        // `BoxBody` holds a pinned box, so the wrapper is `Unpin` and the
        // projection is a plain borrow.
        let this = self.get_mut();
        let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => frame,
            other => return other,
        };
        if let Some(data) = frame.data_ref() {
            this.read += data.len() as u64;
            if this.read > this.limit {
                this.flags.oversized.store(true, Ordering::Relaxed);
                return Poll::Ready(Some(Err(Box::new(BodyTooLarge(this.limit)))));
            }
        }
        Poll::Ready(Some(Ok(frame)))
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// The error a body read fails with once the ceiling is passed.
#[derive(Debug)]
struct BodyTooLarge(u64);

impl std::fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request body exceeded the {} byte limit", self.0)
    }
}

impl std::error::Error for BodyTooLarge {}

/// A body wrapper that bounds how long each read may wait for the next
/// frame — progress, not total transfer. The timer arms when a read comes
/// up empty and disarms the moment anything arrives, so a slow-but-moving
/// upload of any allowed size passes while a stalled one fails
/// deterministically instead of holding a connection slot (and a pooled
/// Lua state) until the compute budget notices.
pub(super) struct StalledBody {
    pub(super) inner: IncomingBody,
    pub(super) budget: std::time::Duration,
    /// Armed while the inner body is pending; `None` whenever it last
    /// made progress.
    pub(super) deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    pub(super) flags: Arc<BodyFlags>,
}

impl Body for StalledBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(ready) => {
                this.deadline = None;
                Poll::Ready(ready)
            }
            Poll::Pending => {
                let budget = this.budget;
                let deadline = this
                    .deadline
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(budget)));
                match deadline.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.flags.stalled.store(true, Ordering::Relaxed);
                        Poll::Ready(Some(Err(Box::new(BodyStalled(budget)))))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// The error a body read fails with when the client stops sending.
#[derive(Debug)]
struct BodyStalled(std::time::Duration);

impl std::fmt::Display for BodyStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the request body stalled: no bytes arrived within {} ms",
            self.0.as_millis()
        )
    }
}

impl std::error::Error for BodyStalled {}

/// The protection flags [`LuaRequest::guard_body`] installs: by the time
/// either violation surfaces it has crossed into Lua and become an opaque
/// error value, so the handler reads these to answer `413`/`408` instead
/// of a generic `500`.
///
/// Both flags share one allocation: the wrappers and the handler hold the
/// same `Arc`, so installing the guards costs one refcount, not two.
pub(crate) struct BodyGuards(pub(super) Arc<BodyFlags>);

/// The two violations a guarded body can record.
#[derive(Default)]
pub(super) struct BodyFlags {
    /// The body exceeded the byte ceiling.
    pub(super) oversized: AtomicBool,
    /// A body read made no progress within the stall budget.
    pub(super) stalled: AtomicBool,
}

impl BodyGuards {
    /// The body exceeded the byte ceiling.
    pub(crate) fn oversized(&self) -> bool {
        self.0.oversized.load(Ordering::Relaxed)
    }

    /// A body read made no progress within the stall budget.
    pub(crate) fn stalled(&self) -> bool {
        self.0.stalled.load(Ordering::Relaxed)
    }
}
