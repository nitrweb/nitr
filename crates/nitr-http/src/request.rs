// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use std::future::Future as _;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use http_body_util::BodyExt as _;
use http_body_util::combinators::BoxBody;
use hyper::Request;
use hyper::body::{Body, Bytes, Frame};

/// The request body type: boxed so both real (`hyper::body::Incoming`) and
/// synthetic (test client) bodies flow through the same dispatch.
pub(crate) type IncomingBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
use mlua::{ExternalResult, LuaSerdeExt, UserData, UserDataFields, UserDataMethods};
use serde_json::Value as SerdeValue;

struct LimitedBody {
    inner: IncomingBody,
    limit: u64,
    read: u64,
    exceeded: Arc<AtomicBool>,
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
                this.exceeded.store(true, Ordering::Relaxed);
                return Poll::Ready(Some(Err(Box::new(BodyTooLarge(this.limit)))));
            }
        }
        Poll::Ready(Some(Ok(frame)))
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Whether the client's cached copy is still current.
///
/// `If-None-Match` wins over `If-Modified-Since` when both are present,
/// which is what RFC 9110 requires: an entity tag is an exact identifier
/// and a date is a heuristic.
pub fn is_fresh(
    headers: &hyper::HeaderMap,
    etag: Option<&str>,
    last_modified: Option<i64>,
) -> bool {
    if let Some(candidates) = headers
        .get(hyper::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        let Some(etag) = etag else {
            return false;
        };
        return candidates.split(',').any(|candidate| {
            let candidate = candidate.trim();
            // `*` matches any existing representation, and the weak/strong
            // prefix is not part of the comparison this header calls for.
            candidate == "*" || strip_weak(candidate) == strip_weak(etag)
        });
    }

    let (Some(since), Some(modified)) = (
        headers
            .get(hyper::header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok()),
        last_modified,
    ) else {
        return false;
    };
    let since = since
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    // HTTP dates have second precision, so compare truncated.
    modified <= since
}

fn strip_weak(etag: &str) -> &str {
    etag.strip_prefix("W/").unwrap_or(etag)
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
struct StalledBody {
    inner: IncomingBody,
    budget: std::time::Duration,
    /// Armed while the inner body is pending; `None` whenever it last
    /// made progress.
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    stalled: Arc<AtomicBool>,
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
                        this.stalled.store(true, Ordering::Relaxed);
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
pub(crate) struct BodyGuards {
    /// The body exceeded the byte ceiling.
    pub(crate) oversized: Arc<AtomicBool>,
    /// A body read made no progress within the stall budget.
    pub(crate) stalled: Arc<AtomicBool>,
}

/// Wrapper around the incoming request that implements UserData.
pub(crate) struct LuaRequest {
    pub(crate) peer_addr: SocketAddr,
    pub(crate) req: Request<IncomingBody>,
    /// Path parameters captured by the router (empty for the catch-all).
    pub(crate) params: Vec<(String, String)>,
    /// The request id: generated per request (UUIDv7), or taken from a
    /// trusted inbound `X-Request-ID` header.
    pub(crate) id: String,
    /// Body-parsing bounds, copied from `[limits]` when the request is
    /// dispatched. Carried on the request because the Lua-facing parsers
    /// need them and Lua must not be able to raise them.
    pub(crate) limits: FormLimits,
    /// The parsed urlencoded form, kept after the first `req:form()` so a
    /// middleware (e.g. `nitr.csrf`) and the handler can both read it —
    /// the body itself can only be consumed once.
    pub(crate) cached_form: Option<Vec<(String, String)>>,
}

/// Bounds applied while parsing a request body into Lua values.
///
/// Only multipart reads these today, so a build without that feature
/// carries the values without using them; keeping the struct whole means
/// `[limits]` parses identically either way.
#[derive(Debug, Clone)]
pub(crate) struct FormLimits {
    #[cfg_attr(not(feature = "multipart"), allow(dead_code))]
    pub(crate) max_parts: usize,
    #[cfg_attr(not(feature = "multipart"), allow(dead_code))]
    pub(crate) max_field_bytes: u64,
    #[cfg_attr(not(feature = "multipart"), allow(dead_code))]
    pub(crate) max_file_bytes: u64,
    /// `[multipart] upload_dir`: the root every `part:save` resolves
    /// inside. `None` leaves `save` unavailable. Shared rather than
    /// cloned per request — it is set once at startup and never changes.
    #[cfg_attr(not(feature = "multipart"), allow(dead_code))]
    pub(crate) upload_root: Option<std::sync::Arc<std::path::PathBuf>>,
}

impl Default for FormLimits {
    fn default() -> Self {
        let defaults = crate::config::LimitsConfig::default();
        Self {
            max_parts: defaults.max_form_parts,
            max_field_bytes: defaults.max_field_bytes,
            max_file_bytes: defaults.max_file_bytes,
            upload_root: None,
        }
    }
}

impl LuaRequest {
    /// Caps this request's body at `limit` bytes *as it arrives*.
    ///
    /// The `Content-Length` check in
    /// [`Protection`](crate::protect::Protection) only sees what the client
    /// declared; a chunked body declares nothing and a dishonest one declares
    /// the wrong thing. This counts what actually shows up and fails the
    /// stream the moment it passes the ceiling, so an oversized upload is cut
    /// mid-flight instead of being buffered in full.
    ///
    /// The violations are also recorded in the returned flags, because by
    /// the time either failure surfaces it has crossed into Lua and become
    /// an opaque error value. The flags let the handler answer `413` (too
    /// large) or `408` (stalled) instead of a generic `500`.
    pub(crate) fn guard_body(
        &mut self,
        limit: u64,
        stall: Option<std::time::Duration>,
    ) -> BodyGuards {
        let guards = BodyGuards {
            oversized: Arc::new(AtomicBool::new(false)),
            stalled: Arc::new(AtomicBool::new(false)),
        };
        let inner = std::mem::take(self.req.body_mut());
        let limited = LimitedBody {
            inner,
            limit,
            read: 0,
            exceeded: guards.oversized.clone(),
        };
        // The stall timer wraps the byte counter so its budget covers the
        // whole read; when disabled the counter is installed alone.
        *self.req.body_mut() = match stall {
            Some(budget) => StalledBody {
                inner: limited.boxed(),
                budget,
                deadline: None,
                stalled: guards.stalled.clone(),
            }
            .boxed(),
            None => limited.boxed(),
        };
        guards
    }

    /// Releases the unread remainder of the body.
    ///
    /// The request outlives the response as a Lua userdata — unreachable,
    /// but not collected until the state's next GC — and with it hyper's
    /// `Incoming`, which keeps the exchange open on the connection. A
    /// handler that never read the body, or stopped half-way (an oversized
    /// upload), would otherwise stall that connection until an unrelated
    /// collection happened to run.
    pub(crate) fn discard_body(&mut self) {
        *self.req.body_mut() = BoxBody::default();
    }
}

impl UserData for LuaRequest {
    fn add_fields<'lua, F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("remote_addr", |_, req| Ok(req.peer_addr.to_string()));
        fields.add_field_method_get("method", |_, req| Ok(req.req.method().to_string()));
        fields.add_field_method_get("path", |_, req| Ok(req.req.uri().path().to_string()));
        fields.add_field_method_get("query", |lua, req| {
            // Query string parsed (and percent-decoded) into a table; for
            // repeated keys the last value wins.
            let table = lua.create_table()?;
            if let Some(query) = req.req.uri().query() {
                for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
                    table.set(k.as_ref(), v.as_ref())?;
                }
            }
            Ok(table)
        });
        fields.add_field_method_get("id", |_, req| Ok(req.id.clone()));
        fields.add_field_method_get("params", |lua, req| {
            // Path parameters captured by the router, e.g. `id` for a route
            // registered as `/users/:id`.
            let table = lua.create_table()?;
            for (k, v) in &req.params {
                table.set(k.as_str(), v.as_str())?;
            }
            Ok(table)
        });
        fields.add_field_method_get("uri", |lua, req| {
            let table = lua.create_table()?;
            let uri = req.req.uri();
            table.set("scheme", uri.scheme_str().unwrap_or_default())?;
            table.set("host", uri.host().unwrap_or_default())?;
            table.set("port", uri.port().map_or(0, |v| v.as_u16()))?;
            table.set("path", uri.path())?;
            table.set("authority", uri.authority().map_or("", |a| a.as_str()))?;
            table.set("query", uri.query().unwrap_or_default())?;
            Ok(table)
        });
        fields.add_field_method_get("headers", |lua, req| {
            let headers = req.req.headers();
            let table = lua.create_table()?;
            for (k, v) in headers.iter() {
                table.set(k.as_str(), v.to_str().unwrap_or_default())?;
            }
            Ok(table)
        });
        fields.add_field_method_get("cookies", |_, req| {
            // All `Cookie` headers, joined so multi-header clients work.
            let header = req
                .req
                .headers()
                .get_all(hyper::header::COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join("; ");
            Ok(nitr_std::RequestCookies::parse(&header))
        });
    }

    fn add_methods<'lua, M: UserDataMethods<Self>>(methods: &mut M) {
        // Returns the best match among the given media types for the
        // request's `Accept` header, or nil when none is acceptable.
        methods.add_method("accepts", |_, req, offers: mlua::Variadic<String>| {
            let accept = req
                .req
                .headers()
                .get(hyper::header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("*/*");
            let refs: Vec<&str> = offers.iter().map(String::as_str).collect();
            Ok(nitr_std::best_match(accept, &refs).map(|i| offers[i].clone()))
        });

        // req:read()  — the next chunk as it arrives off the socket.
        // req:read(n) — at least n bytes, or fewer at the end of the body.
        //
        // The size argument is what lets a handler process an upload larger
        // than its own memory limit: the request-side mirror of a streaming
        // response. `nil` marks the end of the body.
        methods.add_async_method_mut("read", |lua, mut req, n: Option<usize>| async move {
            let reader = req.req.body_mut();
            let Some(want) = n else {
                while let Some(frame) = reader.frame().await {
                    // Trailer frames carry no data; keep reading.
                    if let Some(bytes) = frame.into_lua_err()?.data_ref() {
                        return Some(lua.create_string(bytes)).transpose();
                    }
                }
                return Ok(None);
            };

            let mut buf = Vec::new();
            while buf.len() < want {
                let Some(frame) = reader.frame().await else {
                    break;
                };
                if let Some(bytes) = frame.into_lua_err()?.data_ref() {
                    buf.extend_from_slice(bytes);
                }
            }
            if buf.is_empty() {
                return Ok(None);
            }
            Some(lua.create_string(buf)).transpose()
        });

        // req:form() — an `application/x-www-form-urlencoded` body as a
        // table. Percent-decoding and `+`-as-space are HTTP details worth
        // exactly one careful implementation, not one per application.
        // Repeated keys keep the last value, matching `req.query`.
        methods.add_async_method_mut("form", |lua, mut req, ()| async move {
            if req.cached_form.is_none() {
                let body = req
                    .req
                    .body_mut()
                    .collect()
                    .await
                    .into_lua_err()?
                    .to_bytes();
                req.cached_form = Some(
                    url::form_urlencoded::parse(&body)
                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                        .collect(),
                );
            }
            let table = lua.create_table()?;
            for (k, v) in req.cached_form.as_deref().unwrap_or_default() {
                table.set(k.as_str(), v.as_str())?;
            }
            Ok(table)
        });

        // req:multipart(fn) — invokes `fn` once per part, in arrival order.
        // See `crate::multipart` for why parts stream instead of being
        // collected. Returns the number of parts seen.
        #[cfg(feature = "multipart")]
        methods.add_async_method_mut("multipart", |lua, mut req, cb: mlua::Function| async move {
            let content_type = req
                .req
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let boundary = crate::multipart::boundary(content_type.as_deref())?;
            let limits = req.limits.clone();

            let body = std::mem::take(req.req.body_mut());
            let mut parser = multer::Multipart::new(body.into_data_stream(), boundary);

            let mut count = 0usize;
            loop {
                let Some(field) = parser.next_field().await.into_lua_err()? else {
                    break;
                };
                count += 1;
                if count > limits.max_parts {
                    return Err(mlua::Error::RuntimeError(format!(
                        "multipart body has more than {} parts",
                        limits.max_parts
                    )));
                }
                let part = lua.create_userdata(crate::multipart::LuaPart::new(
                    field,
                    limits.max_field_bytes,
                    limits.max_file_bytes,
                    limits.upload_root.clone(),
                ))?;
                let outcome = cb.call_async::<()>(&part).await;

                // The parser cannot advance while a field is alive, so the
                // part is reclaimed and drained whatever the callback did
                // with it — including nothing, and including failing.
                if let Ok(part) = part.borrow::<crate::multipart::LuaPart>()
                    && let Some(mut field) = part.reclaim()
                {
                    while field.chunk().await.into_lua_err()?.is_some() {}
                }
                outcome?;
            }
            Ok(count)
        });

        // req:fresh(etag, last_modified?) — whether the client's cached
        // copy is still current. Rust compares the validators; Lua decides
        // what identifies the resource, which is application knowledge.
        methods.add_method(
            "fresh",
            |_, req, (etag, last_modified): (Option<String>, Option<i64>)| {
                Ok(is_fresh(req.req.headers(), etag.as_deref(), last_modified))
            },
        );

        methods.add_async_method_mut("text", |lua, mut req, ()| async move {
            let reader = req.req.body_mut();
            let body = reader.collect().await.into_lua_err()?;
            lua.create_string(body.to_bytes())
        });

        methods.add_async_method_mut("json", |lua, mut req, ()| async move {
            let reader = req.req.body_mut();
            let collected = reader.collect().await.into_lua_err()?;
            let buf = collected.to_bytes();
            if buf.is_empty() {
                return Err(mlua::Error::external(
                    "Unexpected end of JSON input, probably request body is empty or already consumed",
                ));
            }
            let json = serde_json::from_slice::<SerdeValue>(&buf).into_lua_err()?;
            lua.to_value(&json)
        });
    }
}

#[cfg(test)]
mod tests {
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
}
