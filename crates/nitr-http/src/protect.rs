// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Rust-side protection enforced before a request reaches Lua: rate
//! limiting and request-size limits. These are infrastructure concerns —
//! implementing them in Lua would let the thing being protected against
//! consume the resources first.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hyper::StatusCode;
use hyper::header::HeaderValue;

use crate::config::Config;
use crate::handler::{HttpResponse, plain_response};
use crate::request::LuaRequest;
use nitr_core::Result;

/// Above this many tracked client buckets, stale entries are purged on the
/// next check (a backstop against unbounded growth from IP churn).
const BUCKET_PURGE_THRESHOLD: usize = 10_000;

/// Per-server protection state, shared by all connections.
#[derive(Debug)]
pub(crate) struct Protection {
    max_body_bytes: u64,
    max_uri_bytes: usize,
    trust_request_id: bool,
    dev_mode: bool,
    /// Per-read body progress budget; `None` when disabled.
    body_read: Option<Duration>,
    /// How long a request may wait for a Lua state before it is shed.
    pool_wait: Duration,
    rate: Option<RateLimiter>,
    /// Body-parsing bounds handed to each request.
    form: crate::request::FormLimits,
    /// The compiled `[cors]` policy; `None` when CORS is not configured.
    cors: Option<crate::cors::Cors>,
    /// The compiled `[compression]` policy.
    compression: crate::compress::Compression,
}

impl Protection {
    pub(crate) fn new(cfg: &Config) -> Self {
        Self {
            max_body_bytes: cfg.limits.max_body_bytes,
            max_uri_bytes: cfg.limits.max_uri_bytes,
            trust_request_id: cfg.trust_request_id,
            dev_mode: cfg.dev_mode,
            body_read: match cfg.limits.body_read_ms {
                0 => None,
                ms => Some(Duration::from_millis(ms)),
            },
            pool_wait: Duration::from_millis(cfg.limits.pool_wait_ms),
            rate: cfg.rate_limit.enabled.then(|| RateLimiter {
                max: cfg.rate_limit.requests.max(1),
                window: Duration::from_secs(cfg.rate_limit.window.max(1)),
                trust_forwarded_for: cfg.rate_limit.trust_forwarded_for,
                buckets: Mutex::new(HashMap::new()),
            }),
            form: crate::request::FormLimits {
                max_parts: cfg.limits.max_form_parts.max(1),
                max_field_bytes: cfg.limits.max_field_bytes,
                max_file_bytes: cfg.limits.max_file_bytes,
            },
            cors: crate::cors::Cors::new(&cfg.cors),
            compression: crate::compress::Compression::new(&cfg.compression),
        }
    }

    /// The compiled CORS policy, or `None` when CORS is not configured.
    pub(crate) fn cors(&self) -> Option<&crate::cors::Cors> {
        self.cors.as_ref()
    }

    /// The compiled compression policy.
    pub(crate) fn compression(&self) -> &crate::compress::Compression {
        &self.compression
    }

    /// Body-parsing bounds handed to each request.
    pub(crate) fn form_limits(&self) -> crate::request::FormLimits {
        self.form
    }

    /// Whether error responses may carry internal detail.
    pub(crate) fn dev_mode(&self) -> bool {
        self.dev_mode
    }

    /// The checkout wait budget; zero means wait indefinitely.
    pub(crate) fn pool_wait(&self) -> Duration {
        self.pool_wait
    }

    /// How long each body read may wait for the next bytes (`[limits]
    /// body_read_ms`); `None` when the bound is disabled.
    pub(crate) fn body_read_timeout(&self) -> Option<Duration> {
        self.body_read
    }

    /// The configured request body ceiling, enforced as the body is read.
    pub(crate) fn max_body_bytes(&self) -> u64 {
        self.max_body_bytes
    }

    /// The id for a request: a trusted, well-formed inbound `X-Request-ID`
    /// when configured, otherwise a fresh UUIDv7 (time-sortable).
    pub(crate) fn request_id(&self, req: &hyper::Request<hyper::body::Incoming>) -> String {
        self.request_id_for_parts(req.headers())
    }

    /// [`request_id`](Self::request_id) over bare headers (used by the
    /// in-process test client, whose body type differs).
    pub(crate) fn request_id_for_parts(&self, headers: &hyper::HeaderMap) -> String {
        if self.trust_request_id
            && let Some(id) = headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .filter(|v| {
                    !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_graphic())
                })
        {
            return id.to_string();
        }
        uuid::Uuid::now_v7().to_string()
    }

    /// Runs the pre-Lua checks; `Some` is the rejection response.
    pub(crate) fn check(&self, req: &LuaRequest) -> Option<Result<HttpResponse>> {
        if let Some(rate) = &self.rate
            && let Err(retry_after) = rate.check(req)
        {
            tracing::debug!(peer = %req.peer_addr, "request rate limited");
            return Some(
                plain_response(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests").map(
                    |mut resp| {
                        if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                            resp.headers_mut().insert(hyper::header::RETRY_AFTER, value);
                        }
                        resp
                    },
                ),
            );
        }

        if uri_len(req) > self.max_uri_bytes {
            return Some(plain_response(StatusCode::URI_TOO_LONG, "URI Too Long"));
        }

        // Declared body size; a chunked body that lies is caught later by
        // the state's memory limit when the handler reads it.
        let declared = req
            .req
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|len| len > self.max_body_bytes) {
            return Some(plain_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload Too Large",
            ));
        }

        None
    }
}

fn uri_len(req: &LuaRequest) -> usize {
    let uri = req.req.uri();
    uri.path().len() + uri.query().map_or(0, |q| q.len() + 1)
}

/// A fixed-window request counter per client IP.
#[derive(Debug)]
struct RateLimiter {
    max: u32,
    window: Duration,
    trust_forwarded_for: bool,
    buckets: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    /// Returns `Err(retry_after_seconds)` when the client exceeded its
    /// budget for the current window.
    fn check(&self, req: &LuaRequest) -> std::result::Result<(), u64> {
        self.check_at(req, Instant::now())
    }

    /// [`check`](Self::check) at an explicit instant — the seam that lets
    /// tests drive window expiry and bucket eviction deterministically
    /// instead of sleeping against the real clock.
    fn check_at(&self, req: &LuaRequest, now: Instant) -> std::result::Result<(), u64> {
        let ip = self.client_ip(req);
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            // Poisoning is unreachable in practice (no panics while held);
            // failing open beats taking the server down.
            Err(_) => return Ok(()),
        };
        if buckets.len() > BUCKET_PURGE_THRESHOLD {
            let window = self.window;
            buckets.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let bucket = buckets.entry(ip).or_insert((now, 0));
        if now.duration_since(bucket.0) >= self.window {
            *bucket = (now, 0);
        }
        bucket.1 += 1;
        if bucket.1 > self.max {
            let elapsed = now.duration_since(bucket.0);
            let retry = self.window.saturating_sub(elapsed).as_secs().max(1);
            return Err(retry);
        }
        Ok(())
    }

    /// The IP the budget is keyed by: the first `X-Forwarded-For` entry
    /// when explicitly trusted (behind a proxy), else the peer address.
    fn client_ip(&self, req: &LuaRequest) -> IpAddr {
        if self.trust_forwarded_for
            && let Some(ip) = req
                .req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
        req.peer_addr.ip()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;

    fn limiter(max: u32, window_ms: u64, trust_forwarded_for: bool) -> RateLimiter {
        RateLimiter {
            max,
            window: Duration::from_millis(window_ms),
            trust_forwarded_for,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn request(peer: &str, forwarded_for: Option<&str>) -> LuaRequest {
        let mut builder = hyper::Request::builder().uri("/");
        if let Some(xff) = forwarded_for {
            builder = builder.header("x-forwarded-for", xff);
        }
        let req = builder
            .body(
                http_body_util::Empty::<hyper::body::Bytes>::new()
                    .map_err(|err| match err {})
                    .boxed(),
            )
            .expect("request");
        LuaRequest {
            peer_addr: format!("{peer}:1234").parse().expect("addr"),
            req,
            params: Vec::new(),
            id: "test".into(),
            limits: Default::default(),
            cached_form: None,
        }
    }

    #[test]
    fn the_budget_applies_per_client_ip() {
        let limiter = limiter(2, 60_000, false);
        let a = request("10.0.0.1", None);
        let b = request("10.0.0.2", None);
        assert!(limiter.check(&a).is_ok());
        assert!(limiter.check(&a).is_ok());
        let retry = limiter.check(&a).expect_err("third request is over");
        assert!(retry >= 1, "Retry-After must be at least a second");
        // Another client's budget is untouched.
        assert!(limiter.check(&b).is_ok());
    }

    #[test]
    fn the_window_resets_the_budget() {
        // Driven through `check_at` with synthetic instants: the old
        // real-clock version (60 ms sleep against a 30 ms window) passed
        // or failed with the scheduler's mood on a loaded runner.
        let limiter = limiter(1, 30, false);
        let req = request("10.0.0.1", None);
        let t0 = Instant::now();
        assert!(limiter.check_at(&req, t0).is_ok());
        assert!(limiter.check_at(&req, t0).is_err(), "over budget in-window");
        // One instant short of the window boundary is still the old window.
        assert!(
            limiter
                .check_at(&req, t0 + Duration::from_millis(29))
                .is_err()
        );
        assert!(
            limiter
                .check_at(&req, t0 + Duration::from_millis(30))
                .is_ok(),
            "a new window starts fresh"
        );
    }

    /// The purge backstop (guard against unbounded `HashMap` growth from
    /// spoofed source IPs): once the map exceeds `BUCKET_PURGE_THRESHOLD`,
    /// the next check drops every bucket whose window has passed.
    #[test]
    fn stale_buckets_are_purged_past_the_threshold() {
        let limiter = limiter(100, 1_000, false);
        let t0 = Instant::now();

        // One bucket per distinct client IP, all opened at t0.
        for n in 0..=BUCKET_PURGE_THRESHOLD as u32 {
            let ip = format!("10.{}.{}.{}", n >> 16 & 0xff, n >> 8 & 0xff, n & 0xff);
            assert!(limiter.check_at(&request(&ip, None), t0).is_ok());
        }
        assert!(
            limiter.buckets.lock().expect("buckets").len() > BUCKET_PURGE_THRESHOLD,
            "the map must actually be past the threshold for the purge to be tested"
        );

        // A later request finds the map oversized and evicts everything
        // stale; only itself (fresh) survives.
        let later = t0 + Duration::from_millis(1_500);
        assert!(
            limiter
                .check_at(&request("192.168.0.1", None), later)
                .is_ok()
        );
        assert_eq!(
            limiter.buckets.lock().expect("buckets").len(),
            1,
            "stale buckets must be evicted, not accumulate forever"
        );
    }

    /// The trusted-id validation edges (`len <= 64`, ASCII-graphic only,
    /// non-empty): everything outside the shape is *replaced* by a fresh
    /// UUID, never echoed — a proxy header is still attacker-influenced
    /// text headed for log pipelines.
    #[test]
    fn trusted_request_ids_validate_the_shape_edges() {
        let cfg = Config {
            trust_request_id: true,
            ..Default::default()
        };
        let protection = Protection::new(&cfg);
        let id_for = |value: &[u8]| {
            let mut headers = hyper::HeaderMap::new();
            headers.insert(
                "x-request-id",
                HeaderValue::from_bytes(value).expect("header value"),
            );
            protection.request_id_for_parts(&headers)
        };

        // In shape: passed through verbatim, including the 64-byte edge.
        assert_eq!(id_for(b"req-from-proxy-1"), "req-from-proxy-1");
        let at_cap = "a".repeat(64);
        assert_eq!(id_for(at_cap.as_bytes()), at_cap);

        // Out of shape: one past the cap, empty, whitespace, non-ASCII.
        let over_cap = "a".repeat(65).into_bytes();
        for bad in [&over_cap[..], b"", b"has space", "caf\u{e9}".as_bytes()] {
            let id = id_for(bad);
            assert_ne!(id.as_bytes(), bad, "{bad:?} must not be echoed");
            assert!(
                uuid::Uuid::parse_str(&id).is_ok(),
                "the replacement must be a generated UUID, got `{id}`"
            );
        }

        // And without trust, even a well-shaped id is replaced.
        let untrusted = Protection::new(&Config::default());
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("req-1"));
        assert_ne!(untrusted.request_id_for_parts(&headers), "req-1");
    }

    #[test]
    fn forwarded_for_is_honored_only_when_trusted() {
        // Untrusted: the header is attacker-controlled, so the peer
        // address keys the budget and the spoofed IPs share one bucket.
        let rl = limiter(1, 60_000, false);
        assert!(rl.check(&request("10.0.0.9", Some("1.1.1.1"))).is_ok());
        assert!(
            rl.check(&request("10.0.0.9", Some("2.2.2.2"))).is_err(),
            "spoofing the header must not buy a fresh budget"
        );

        // Trusted (behind a proxy): the first entry keys the budget.
        let rl = limiter(1, 60_000, true);
        assert!(
            rl.check(&request("10.0.0.9", Some("1.1.1.1, 9.9.9.9")))
                .is_ok()
        );
        assert!(rl.check(&request("10.0.0.9", Some("1.1.1.1"))).is_err());
        assert!(
            rl.check(&request("10.0.0.9", Some("2.2.2.2"))).is_ok(),
            "a different client gets its own budget"
        );
        // A garbage header falls back to the peer address.
        assert!(rl.check(&request("10.0.0.9", Some("not-an-ip"))).is_ok());
    }
}
