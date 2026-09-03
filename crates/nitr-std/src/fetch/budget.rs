// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Per-request app-data plumbing: the outbound-call budget and the W3C
//! `traceparent` derived from the inbound request id.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use mlua::Lua;
use reqwest::header::HeaderValue;

/// How many outbound requests the current inbound request has made.
///
/// Stored in the Lua state's app data rather than passed around: the state
/// handles one request at a time, so "the current request" is unambiguous,
/// and the server resets it at dispatch.
#[derive(Debug, Default)]
pub struct OutboundBudget(AtomicU32);

impl OutboundBudget {
    /// Starts a new inbound request's count.
    pub fn reset(&self) {
        self.0.store(0, Ordering::Relaxed);
    }

    /// Counts one outbound call, refusing past `limit` (`0` = unlimited).
    pub(super) fn take(&self, limit: u32) -> mlua::Result<()> {
        if limit == 0 {
            return Ok(());
        }
        if self.0.fetch_add(1, Ordering::Relaxed) >= limit {
            return Err(mlua::Error::RuntimeError(format!(
                "this request has already made {limit} outbound calls \
                 (fetch.max_per_request); a handler's outbound cost has to be bounded"
            )));
        }
        Ok(())
    }
}

/// Resets the outbound budget for a new inbound request.
///
/// Called by the server before dispatch. A no-op when `fetch` is not
/// enabled for this state.
pub fn reset_outbound_budget(lua: &Lua) {
    if let Some(budget) = lua.app_data_ref::<Arc<OutboundBudget>>() {
        budget.reset();
    }
}

/// The W3C `traceparent` for the current request, when propagation is on.
///
/// Pass-through, not a tracing SDK: the trace id is derived from the
/// request id the server generates for every request, so a request
/// crossing several Nitr services can be stitched together without any
/// pipeline.
pub(super) fn traceparent(lua: &Lua) -> Option<HeaderValue> {
    use sha2::Digest as _;

    let id = lua.app_data_ref::<TraceContext>()?;
    let digest = sha2::Sha256::digest(id.0.as_bytes());
    let hex = |bytes: &[u8]| {
        bytes.iter().fold(String::new(), |mut acc, byte| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{byte:02x}");
            acc
        })
    };
    // version-traceid(16 bytes)-spanid(8 bytes)-flags. `01` marks it
    // sampled, which is the only honest answer when we do not sample.
    HeaderValue::from_str(&format!(
        "00-{}-{}-01",
        hex(&digest[..16]),
        hex(&digest[16..24])
    ))
    .ok()
}

/// The inbound request id this state is currently serving.
#[derive(Debug, Clone)]
pub struct TraceContext(pub String);

/// Records the inbound request id so outbound calls can carry a
/// `traceparent` derived from it.
pub fn set_trace_context(lua: &Lua, request_id: &str) {
    // The slot is reused across requests: after the first one this is a
    // copy into an existing buffer, not an allocation plus a typemap
    // insert on every dispatch.
    if let Some(mut context) = lua.app_data_mut::<TraceContext>() {
        context.0.clear();
        context.0.push_str(request_id);
        return;
    }
    lua.set_app_data(TraceContext(request_id.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outbound_budget_counts_and_refuses() {
        let budget = OutboundBudget::default();
        assert!(budget.take(2).is_ok());
        assert!(budget.take(2).is_ok());
        assert!(budget.take(2).is_err(), "the third call is over budget");

        budget.reset();
        assert!(budget.take(2).is_ok(), "a new request starts fresh");

        // Zero means unlimited.
        let unlimited = OutboundBudget::default();
        for _ in 0..1000 {
            assert!(unlimited.take(0).is_ok());
        }
    }
}
