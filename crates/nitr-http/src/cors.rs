// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Cross-origin resource sharing, enforced in Rust.
//!
//! CORS is policy, not application logic: a preflight carries no body and
//! calls no handler, so letting one reach a Lua state would spend a pooled
//! runtime to compute a fixed answer. Keeping it here also means the policy
//! lives in one auditable place instead of being assembled from middleware.

use hyper::header::{self, HeaderValue};
use hyper::{HeaderMap, Method, Request, StatusCode};

use crate::config::CorsConfig;
use crate::handler::HttpResponse;
use nitr_core::Result;

/// The compiled `[cors]` policy. Absent when no origins are configured.
#[derive(Debug)]
pub(crate) struct Cors {
    /// `None` means "any origin" (`origins = ["*"]`).
    origins: Option<Vec<String>>,
    methods: HeaderValue,
    /// Allowed request headers, lowercased for comparison.
    allowed_headers: Vec<String>,
    /// The same list rendered once for the preflight response.
    allowed_headers_value: Option<HeaderValue>,
    expose_headers: Option<HeaderValue>,
    credentials: bool,
    max_age: Option<HeaderValue>,
}

/// Methods allowed when the configuration does not say.
const DEFAULT_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Request headers a preflight approves without them being listed. These
/// are the ones a browser may send on a "simple" request anyway, so
/// refusing them would only produce confusing failures.
const ALWAYS_ALLOWED_HEADERS: &[&str] = &["accept", "accept-language", "content-language"];

impl Cors {
    /// Compiles the configuration, or `None` when CORS is not configured.
    ///
    /// [`Config::validate`](crate::config::Config::validate) has already
    /// rejected the wildcard-plus-credentials combination, so anything that
    /// reaches here is coherent.
    pub(crate) fn new(cfg: &CorsConfig) -> Option<Self> {
        let origins = cfg.origins.as_ref()?;
        let any = origins.iter().any(|o| o == "*");
        let methods = cfg.methods.clone().unwrap_or_else(|| {
            DEFAULT_METHODS
                .iter()
                .map(|m| (*m).to_string())
                .collect::<Vec<_>>()
        });
        let allowed_headers: Vec<String> = cfg
            .headers
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();

        Some(Self {
            origins: (!any).then(|| origins.clone()),
            methods: join_header(&methods),
            allowed_headers_value: (!allowed_headers.is_empty())
                .then(|| join_header(&allowed_headers)),
            allowed_headers,
            expose_headers: cfg.expose_headers.as_ref().map(|h| join_header(h)),
            credentials: cfg.credentials,
            max_age: cfg
                .max_age
                .and_then(|age| HeaderValue::from_str(&age.to_string()).ok()),
        })
    }

    /// The `Access-Control-Allow-Origin` value for this request's `Origin`,
    /// or `None` when the origin is not allowed.
    ///
    /// A wildcard policy echoes `*` rather than the origin, so a shared
    /// cache can reuse the response across origins.
    fn allow_origin(&self, origin: &HeaderValue) -> Option<HeaderValue> {
        match &self.origins {
            None => Some(HeaderValue::from_static("*")),
            Some(allowed) => {
                let origin_str = origin.to_str().ok()?;
                allowed
                    .iter()
                    .any(|o| o == origin_str)
                    .then(|| origin.clone())
            }
        }
    }

    /// Answers a preflight (`OPTIONS` carrying
    /// `Access-Control-Request-Method`) entirely in Rust.
    ///
    /// `None` means this is not a preflight and normal dispatch continues.
    /// A preflight from a disallowed origin still gets a `204` — just
    /// without the `Access-Control-*` headers, which is what tells the
    /// browser to block the real request. Answering `403` instead would
    /// leak the policy to anyone who asks.
    pub(crate) fn preflight<B>(&self, req: &Request<B>) -> Option<Result<HttpResponse>> {
        if req.method() != Method::OPTIONS {
            return None;
        }
        let headers = req.headers();
        let origin = headers.get(header::ORIGIN)?;
        let requested = headers.get(header::ACCESS_CONTROL_REQUEST_METHOD)?;

        let mut resp = match crate::handler::empty_response(StatusCode::NO_CONTENT) {
            Ok(resp) => resp,
            Err(err) => return Some(Err(err)),
        };
        // `Vary` goes on every preflight, allowed or not: the answer depends
        // on these request headers, and a cache that misses that serves one
        // origin's verdict to another.
        vary_preflight(resp.headers_mut());

        if let Some(allow) = self.allow_origin(origin)
            && self.method_allowed(requested)
            && self.headers_allowed(headers)
        {
            let out = resp.headers_mut();
            out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
            out.insert(header::ACCESS_CONTROL_ALLOW_METHODS, self.methods.clone());
            if let Some(value) = &self.allowed_headers_value {
                out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, value.clone());
            }
            if self.credentials {
                out.insert(
                    header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                );
            }
            if let Some(age) = &self.max_age {
                out.insert(header::ACCESS_CONTROL_MAX_AGE, age.clone());
            }
        }
        Some(Ok(resp))
    }

    fn method_allowed(&self, requested: &HeaderValue) -> bool {
        let Ok(requested) = requested.to_str() else {
            return false;
        };
        self.methods
            .to_str()
            .is_ok_and(|allowed| allowed.split(", ").any(|m| m == requested))
    }

    fn headers_allowed(&self, headers: &HeaderMap) -> bool {
        let Some(requested) = headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS) else {
            return true;
        };
        let Ok(requested) = requested.to_str() else {
            return false;
        };
        requested.split(',').map(str::trim).all(|name| {
            let name = name.to_ascii_lowercase();
            ALWAYS_ALLOWED_HEADERS.contains(&name.as_str()) || self.allowed_headers.contains(&name)
        })
    }

    /// Appends the `Access-Control-*` headers to an ordinary (non-preflight)
    /// cross-origin response.
    pub(crate) fn apply(&self, req_headers: &HeaderMap, resp_headers: &mut HeaderMap) {
        let Some(origin) = req_headers.get(header::ORIGIN) else {
            return;
        };
        // The response body varies by origin even when the request is
        // refused, so any cache in front of us needs to know.
        append_vary(resp_headers, "origin");
        let Some(allow) = self.allow_origin(origin) else {
            return;
        };
        resp_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
        if self.credentials {
            resp_headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        if let Some(expose) = &self.expose_headers {
            resp_headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone());
        }
    }
}

fn join_header(values: &[String]) -> HeaderValue {
    HeaderValue::from_str(&values.join(", ")).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn vary_preflight(headers: &mut HeaderMap) {
    for name in [
        "origin",
        "access-control-request-method",
        "access-control-request-headers",
    ] {
        append_vary(headers, name);
    }
}

/// Adds one field name to `Vary` without dropping what is already there.
pub(crate) fn append_vary(headers: &mut HeaderMap, name: &'static str) {
    let already = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|f| f.trim().eq_ignore_ascii_case(name)));
    if !already {
        headers.append(header::VARY, HeaderValue::from_static(name));
    }
}

/// The `Allow` header value for a matched path, always advertising the
/// methods Nitr answers itself.
pub(crate) fn allow_header(methods: &[Method]) -> HeaderValue {
    let mut names: Vec<String> = methods.iter().map(|m| m.to_string()).collect();
    if names.iter().any(|m| m == "GET") && !names.iter().any(|m| m == "HEAD") {
        names.push("HEAD".into());
    }
    if !names.iter().any(|m| m == "OPTIONS") {
        names.push("OPTIONS".into());
    }
    names.sort();
    join_header(&names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cors(cfg: CorsConfig) -> Cors {
        Cors::new(&cfg).expect("configured")
    }

    fn request(method: Method, headers: &[(&'static str, &str)]) -> Request<()> {
        let mut req = Request::builder().method(method).uri("/");
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        req.body(()).expect("request")
    }

    #[test]
    fn a_wildcard_policy_echoes_a_star_not_the_origin() {
        let policy = cors(CorsConfig {
            origins: Some(vec!["*".into()]),
            ..Default::default()
        });
        let mut out = HeaderMap::new();
        policy.apply(
            request(Method::GET, &[("origin", "https://a.example")]).headers(),
            &mut out,
        );
        assert_eq!(out[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(out[header::VARY], "origin");
    }

    #[test]
    fn a_disallowed_origin_gets_no_allow_header() {
        let policy = cors(CorsConfig {
            origins: Some(vec!["https://ok.example".into()]),
            ..Default::default()
        });
        let mut out = HeaderMap::new();
        policy.apply(
            request(Method::GET, &[("origin", "https://evil.example")]).headers(),
            &mut out,
        );
        assert!(!out.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        // Still varies: the answer *did* depend on the origin.
        assert_eq!(out[header::VARY], "origin");
    }

    #[test]
    fn a_preflight_is_answered_without_reaching_a_handler() {
        let policy = cors(CorsConfig {
            origins: Some(vec!["https://ok.example".into()]),
            headers: Some(vec!["Content-Type".into()]),
            max_age: Some(600),
            ..Default::default()
        });
        let req = request(
            Method::OPTIONS,
            &[
                ("origin", "https://ok.example"),
                ("access-control-request-method", "POST"),
                ("access-control-request-headers", "content-type"),
            ],
        );
        let resp = policy
            .preflight(&req)
            .expect("preflight")
            .expect("response");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let h = resp.headers();
        assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://ok.example");
        assert_eq!(h[header::ACCESS_CONTROL_MAX_AGE], "600");
        assert!(
            h[header::ACCESS_CONTROL_ALLOW_METHODS]
                .to_str()
                .expect("methods")
                .contains("POST")
        );
    }

    #[test]
    fn a_preflight_for_an_unlisted_header_is_not_approved() {
        let policy = cors(CorsConfig {
            origins: Some(vec!["https://ok.example".into()]),
            headers: Some(vec!["content-type".into()]),
            ..Default::default()
        });
        let req = request(
            Method::OPTIONS,
            &[
                ("origin", "https://ok.example"),
                ("access-control-request-method", "POST"),
                ("access-control-request-headers", "x-secret"),
            ],
        );
        let resp = policy
            .preflight(&req)
            .expect("preflight")
            .expect("response");
        // 204 without the approval headers: the browser blocks the request,
        // and we have not told the caller what the policy is.
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(
            !resp
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
    }

    #[test]
    fn a_plain_options_request_is_not_a_preflight() {
        let policy = cors(CorsConfig {
            origins: Some(vec!["*".into()]),
            ..Default::default()
        });
        assert!(policy.preflight(&request(Method::OPTIONS, &[])).is_none());
    }

    #[test]
    fn allow_advertises_head_and_options() {
        let value = allow_header(&[Method::GET, Method::POST]);
        assert_eq!(value, "GET, HEAD, OPTIONS, POST");
    }
}
