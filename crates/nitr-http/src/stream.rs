// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Streaming response bodies: a Lua handler returns `body = function(...)`
//! and the chunks it produces are forwarded to the client as they are
//! written, under backpressure from a small bounded channel.
//!
//! Two producer shapes are supported by the same dispatch:
//!
//! - **Writer callback** — `function(writer) writer:write(chunk) ... end`;
//!   `writer:write` suspends while the client is slow and raises a Lua
//!   error once the client disconnects.
//! - **Iterator** — a function returning one chunk per call and `nil` to
//!   finish (e.g. `coroutine.wrap`); detected by its first call returning a
//!   string.
//!
//! The Lua state stays checked out of the pool for the stream's lifetime:
//! the pool guard moves into the producer task and returns on completion.

use std::convert::Infallible;

use http_body_util::{BodyExt as _, StreamBody};
use hyper::body::{Bytes, Frame};
use mlua::{Function, LuaString, Table as LuaTable, UserData, UserDataMethods, Value};
use tokio::sync::OwnedSemaphorePermit;
use tracing::Instrument as _;

use crate::handler::build_response;
use nitr_core::{DeadlineHandle, Result, RuntimeGuard};

type ChunkSender = async_channel::Sender<std::result::Result<Frame<Bytes>, Infallible>>;

/// How many chunks may sit between the Lua producer and hyper before the
/// producer suspends. Small on purpose: the channel is the backpressure
/// mechanism, not a buffer.
const CHANNEL_CAPACITY: usize = 2;

/// The `writer` userdata handed to a streaming body function.
struct LuaWriter {
    tx: ChunkSender,
    deadline: DeadlineHandle,
}

impl UserData for LuaWriter {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // Suspends while the client is slower than the producer; each
        // delivered chunk grants the handler a fresh execution budget.
        methods.add_async_method("write", |_, this, chunk: LuaString| async move {
            let bytes = Bytes::copy_from_slice(&chunk.as_bytes());
            this.tx
                .send(Ok(Frame::data(bytes)))
                .await
                .map_err(|_| mlua::Error::RuntimeError("client disconnected".into()))?;
            this.deadline.extend();
            Ok(())
        });
    }
}

/// Builds the streaming response and spawns the producer task that drives
/// the Lua body function, moving the checked-out runtime into it.
pub(crate) fn stream_response(
    mut rt: RuntimeGuard,
    lua_resp: &LuaTable,
    body_fn: Function,
    permit: OwnedSemaphorePermit,
) -> Result<super::handler::HttpResponse> {
    let (tx, rx) = async_channel::bounded(CHANNEL_CAPACITY);
    let deadline = rt.deadline_handle();
    let writer = rt.lua().create_userdata(LuaWriter {
        tx: tx.clone(),
        deadline: deadline.clone(),
    })?;
    let resp = build_response(lua_resp, StreamBody::new(rx).boxed())?;

    tokio::spawn(
        async move {
            // Held for the stream's lifetime; releasing it frees a stream slot.
            let _permit = permit;
            match rt
                .call_function_streaming::<Value>(body_fn.clone(), &writer)
                .await
            {
                // The first call returned a chunk: iterator mode. Emit it and
                // keep calling until nil, granting budget per chunk.
                Ok(Value::String(first)) => {
                    let mut chunk = Bytes::copy_from_slice(&first.as_bytes());
                    loop {
                        if tx.send(Ok(Frame::data(chunk))).await.is_err() {
                            // Client disconnected: stop pulling chunks.
                            break;
                        }
                        deadline.extend();
                        match rt
                            .call_function_streaming::<Option<LuaString>>(body_fn.clone(), ())
                            .await
                        {
                            Ok(Some(next)) => chunk = Bytes::copy_from_slice(&next.as_bytes()),
                            Ok(None) => break,
                            Err(err) => {
                                tracing::error!("streaming iterator failed mid-body: {err}");
                                break;
                            }
                        }
                    }
                }
                // Writer-callback mode completed normally.
                Ok(_) => {}
                Err(err) => {
                    // A disconnect surfacing as a Lua error is normal stream
                    // teardown, not a handler bug.
                    let msg = err.to_string();
                    if msg.contains("client disconnected") {
                        tracing::debug!("stream cancelled: client disconnected");
                    } else {
                        tracing::error!("streaming body failed mid-body: {err}");
                    }
                }
            }
            // The writer userdata inside the Lua state still holds a sender
            // clone until the GC collects it, so close the channel explicitly —
            // this is what ends the response body. The runtime returns to the
            // pool when `rt` drops.
            tx.close();
        }
        .instrument(tracing::Span::current()),
    );

    Ok(resp)
}
