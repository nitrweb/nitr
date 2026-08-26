// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `fetch` builtin: outbound HTTP requests with an options table,
//! policy-checked redirects, retries, and `await_all(...)` structured
//! concurrency.
//!
//! `fetch(method, url, opts?)` returns an *unsent* request handle;
//! `handle:send()` performs it, and `await_all(h1, h2, ...)` performs
//! several concurrently, returning their responses in argument order.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use mlua::{
    AnyUserData, ExternalResult, Function, Lua, Table, UserData, UserDataMethods, Value, Variadic,
};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::{Client as HttpClient, Method as HttpMethod, StatusCode, Url, redirect};
use tracing::Instrument as _;

use crate::config::FetchOptions;
use crate::fetch::policy::{ConnectPolicy, GuardedResolver, check_url};
use crate::fetch::response::LuaResponse;

/// Maximum redirects followed per outbound request.
const MAX_REDIRECTS: usize = 5;

/// Base delay for the first retry; each further attempt doubles it.
const RETRY_BASE_DELAY: Duration = Duration::from_millis(100);

/// Ceiling on a single backoff wait, so a long backoff cannot outlive the
/// inbound request it belongs to.
const RETRY_MAX_DELAY: Duration = Duration::from_secs(5);

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
    fn take(&self, limit: u32) -> mlua::Result<()> {
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

/// Per-call retry intent, from the Lua options table.
#[derive(Debug, Clone, Copy)]
struct Retry {
    attempts: u32,
    exponential: bool,
}

/// Everything needed to (re-)issue one outbound request.
#[derive(Clone)]
struct RequestSpec {
    method: HttpMethod,
    url: Url,
    headers: HeaderMap,
    body: Option<Bytes>,
    timeout: Option<Duration>,
    retry: Option<Retry>,
}

impl RequestSpec {
    /// Whether repeating this request is safe.
    ///
    /// Retrying a `POST` is how a customer gets charged twice, so only the
    /// methods HTTP defines as idempotent are ever repeated — regardless of
    /// what the caller asked for.
    fn is_idempotent(&self) -> bool {
        matches!(
            self.method,
            HttpMethod::GET
                | HttpMethod::HEAD
                | HttpMethod::PUT
                | HttpMethod::DELETE
                | HttpMethod::OPTIONS
        )
    }
}

/// An unsent outbound request handle.
pub(crate) struct LuaFetch {
    client: Arc<HttpClient>,
    spec: RequestSpec,
    opts: Arc<FetchOptions>,
    budget: Arc<OutboundBudget>,
}

impl UserData for LuaFetch {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_async_method("send", |_, this, ()| {
            let client = this.client.clone();
            let spec = this.spec.clone();
            let opts = this.opts.clone();
            let budget = this.budget.clone();
            async move {
                budget.take(opts.max_per_request)?;
                send_with_retries(&client, spec, &opts).await
            }
        });
    }
}

/// Statuses worth trying again: the upstream is saying "not now" rather
/// than "no". A `404` or a `400` would return the same answer forever, so
/// repeating those only wastes the budget.
fn is_retryable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504)
}

/// Performs a request, repeating it when the policy allows.
///
/// Retries count as one logical call against the per-request budget: the
/// budget exists to bound how much work one inbound request can cause, and
/// a retry is the same work being attempted again, not new work.
///
/// The last attempt's response is returned as-is even when it failed, so a
/// handler that asked for retries still gets an ordinary response object to
/// inspect rather than an error it did not ask for.
async fn send_with_retries(
    client: &HttpClient,
    spec: RequestSpec,
    opts: &FetchOptions,
) -> mlua::Result<LuaResponse> {
    let attempts = match spec.retry {
        // A retry request on a non-idempotent method is honored as "send
        // once" rather than refused: the call itself is still valid.
        Some(retry) if spec.is_idempotent() => retry.attempts.min(opts.max_retries).max(1),
        _ => 1,
    };
    let exponential = spec.retry.is_none_or(|r| r.exponential);

    let mut attempt = 0;
    loop {
        attempt += 1;
        let last = attempt >= attempts;
        let reason = match execute(client, spec.clone(), opts).await {
            Ok(resp) if last || !is_retryable(resp.status()) => return Ok(resp),
            Ok(resp) => format!("upstream answered {}", resp.status()),
            Err(err) if last => return Err(err),
            Err(err) => err.to_string(),
        };
        let delay = backoff(attempt, exponential);
        tracing::debug!(
            "fetch {} {} failed (attempt {attempt}/{attempts}), retrying in {:?}: {reason}",
            spec.method,
            spec.url,
            delay
        );
        tokio::time::sleep(delay).await;
    }
}

/// Exponential backoff with jitter.
///
/// The jitter matters more than the curve: without it, every request that
/// failed together retries together, and the upstream that just fell over
/// gets a synchronized second wave.
fn backoff(attempt: u32, exponential: bool) -> Duration {
    let base = if exponential {
        RETRY_BASE_DELAY.saturating_mul(1u32 << (attempt - 1).min(10))
    } else {
        RETRY_BASE_DELAY
    }
    .min(RETRY_MAX_DELAY);

    // Full jitter over [base/2, base]. A counter-seeded xorshift is plenty:
    // this decorrelates retries, it does not need to be unpredictable.
    static SEED: AtomicU32 = AtomicU32::new(0x9e37_79b9);
    let mut x = SEED.fetch_add(0x9e37_79b9, Ordering::Relaxed) | 1;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    let half = base / 2;
    half + half.mul_f64(f64::from(x % 1000) / 1000.0)
}

/// Performs one attempt under the fetch policy, following redirects
/// manually so every hop is re-validated ([`check_url`]).
async fn execute(
    client: &HttpClient,
    spec: RequestSpec,
    opts: &FetchOptions,
) -> mlua::Result<LuaResponse> {
    let RequestSpec {
        mut method,
        mut url,
        headers,
        mut body,
        timeout,
        ..
    } = spec;

    let mut hops = 0usize;
    loop {
        check_url(&url, opts).await?;

        let mut builder = client
            .request(method.clone(), url.clone())
            .headers(headers.clone());
        if let Some(bytes) = &body {
            builder = builder.body(bytes.clone());
        }
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        // The `fetch` span, one per network exchange (so per redirect hop
        // and per retry attempt). Host only, never the full URL — query
        // strings carry secrets; the connected IP is the address the
        // SSRF-vetted resolution actually produced, which is the
        // security-relevant fact for an audit trail. DEBUG so the
        // per-request decomposition is opt-in via the level filter.
        let span = tracing::debug_span!(
            "fetch",
            host = %url.host_str().unwrap_or_default(),
            method = %method,
            status = tracing::field::Empty,
            ip = tracing::field::Empty,
            elapsed_ms = tracing::field::Empty,
        );
        let started = std::time::Instant::now();
        let sent = builder.send().instrument(span.clone()).await;
        span.record("elapsed_ms", started.elapsed().as_millis() as u64);
        let resp = sent.into_lua_err()?;
        span.record("status", resp.status().as_u16());
        if let Some(addr) = resp.remote_addr() {
            span.record("ip", tracing::field::display(addr.ip()));
        }

        if !resp.status().is_redirection() {
            return Ok(LuaResponse::new(resp, opts.max_response_bytes));
        }
        let Some(location) = resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
        else {
            // A redirect status without a Location header is a final
            // response as far as the client is concerned.
            return Ok(LuaResponse::new(resp, opts.max_response_bytes));
        };
        hops += 1;
        if hops > MAX_REDIRECTS {
            return Err(mlua::Error::RuntimeError(format!(
                "fetch exceeded {MAX_REDIRECTS} redirects for `{url}`"
            )));
        }
        url = url.join(&location).into_lua_err()?;
        // Like browsers: 301/302/303 switch to GET and drop the body;
        // 307/308 preserve the method and body.
        if matches!(
            resp.status(),
            StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER
        ) && method != HttpMethod::GET
            && method != HttpMethod::HEAD
        {
            method = HttpMethod::GET;
            body = None;
        }
    }
}

/// Returns the HTTP client for a connect policy, building it on first use.
///
/// Keyed on the policy rather than process-wide because the DNS resolver
/// enforces part of it: two configurations that disagree about private
/// networks must not share a resolver. In practice a server has one
/// configuration and therefore one client, and so one connection pool.
fn client_for(opts: &FetchOptions) -> mlua::Result<Arc<HttpClient>> {
    static CLIENTS: OnceLock<Mutex<HashMap<ConnectPolicy, Arc<HttpClient>>>> = OnceLock::new();
    let clients = CLIENTS.get_or_init(|| Mutex::new(HashMap::new()));
    let policy = opts.connect_policy();

    let mut clients = clients
        .lock()
        .map_err(|_| mlua::Error::RuntimeError("the fetch client cache is poisoned".into()))?;
    if let Some(client) = clients.get(&policy) {
        return Ok(client.clone());
    }

    let mut builder = HttpClient::builder()
        .connect_timeout(policy.connect_timeout)
        .timeout(policy.timeout)
        .pool_max_idle_per_host(policy.pool_max_idle_per_host)
        // Redirects are followed by `execute` so the policy applies per hop.
        .redirect(redirect::Policy::none())
        // The resolution the connector uses is the one that gets filtered.
        .dns_resolver(Arc::new(GuardedResolver::new(
            policy.allow_private_networks,
        )));

    if policy.no_proxy {
        builder = builder.no_proxy();
    }
    if let Some(url) = &policy.proxy {
        builder = builder.proxy(reqwest::Proxy::all(url.as_str()).map_err(|err| {
            mlua::Error::RuntimeError(format!("invalid [fetch] proxy `{url}`: {err}"))
        })?);
    }

    let client = Arc::new(builder.build().into_lua_err()?);
    clients.insert(policy, client.clone());
    Ok(client)
}

/// The option keys that mark the third `fetch` argument as an options
/// table; any other table is treated as plain headers (the pre-options
/// call form).
const OPTION_KEYS: &[&str] = &["headers", "query", "json", "body", "timeout", "retry"];

fn parse_spec(method: String, url: String, arg: Option<Table>) -> mlua::Result<RequestSpec> {
    let method = HttpMethod::from_bytes(method.to_uppercase().as_bytes()).into_lua_err()?;
    let mut url = url.parse::<Url>().into_lua_err()?;
    let mut headers = HeaderMap::new();
    let mut body = None;
    let mut timeout = None;
    let mut retry = None;

    if let Some(table) = arg {
        let is_options = OPTION_KEYS
            .iter()
            .any(|k| table.contains_key(*k).unwrap_or(false));
        if is_options {
            if let Some(header_table) = table.get::<Option<Table>>("headers")? {
                fill_headers(&mut headers, &header_table)?;
            }
            if let Some(query) = table.get::<Option<Table>>("query")? {
                let mut pairs = url.query_pairs_mut();
                for pair in query.pairs::<String, String>() {
                    let (k, v) = pair?;
                    pairs.append_pair(&k, &v);
                }
            }
            if let Some(value) = table.get::<Option<Value>>("json")? {
                crate::utils::check_json_depth(&value)?;
                let bytes = serde_json::to_vec(&value).into_lua_err()?;
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                body = Some(Bytes::from(bytes));
            }
            if body.is_none()
                && let Some(raw) = table.get::<Option<mlua::LuaString>>("body")?
            {
                body = Some(Bytes::copy_from_slice(&raw.as_bytes()));
            }
            if let Some(secs) = table.get::<Option<f64>>("timeout")? {
                timeout = Some(Duration::from_secs_f64(secs.max(0.0)));
            }
            if let Some(table) = table.get::<Option<Table>>("retry")? {
                retry = Some(parse_retry(&table)?);
            }
        } else {
            fill_headers(&mut headers, &table)?;
        }
    }

    Ok(RequestSpec {
        method,
        url,
        headers,
        body,
        timeout,
        retry,
    })
}

/// `retry = { attempts = 3, backoff = "exponential" }`.
fn parse_retry(table: &Table) -> mlua::Result<Retry> {
    let attempts = table.get::<Option<u32>>("attempts")?.unwrap_or(3);
    let exponential = match table.get::<Option<String>>("backoff")?.as_deref() {
        None | Some("exponential") => true,
        Some("constant") => false,
        Some(other) => {
            return Err(mlua::Error::RuntimeError(format!(
                "unknown retry backoff `{other}`: expected \"exponential\" or \"constant\""
            )));
        }
    };
    Ok(Retry {
        attempts,
        exponential,
    })
}

fn fill_headers(headers: &mut HeaderMap, table: &Table) -> mlua::Result<()> {
    for pair in table.pairs::<String, String>() {
        let (k, v) = pair.into_lua_err()?;
        headers.insert(
            HeaderName::from_bytes(k.as_bytes()).into_lua_err()?,
            HeaderValue::from_bytes(v.as_bytes()).into_lua_err()?,
        );
    }
    Ok(())
}

/// The W3C `traceparent` for the current request, when propagation is on.
///
/// Pass-through, not a tracing SDK: the trace id is derived from the
/// request id the server generates for every request, so a request
/// crossing several Nitr services can be stitched together without any
/// pipeline.
fn traceparent(lua: &Lua) -> Option<HeaderValue> {
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
    lua.set_app_data(TraceContext(request_id.to_string()));
}

/// HTTP fetch function: `fetch(method, url, opts?)` → request handle.
pub(crate) fn create_fetch_fn(lua: &Lua, opts: Arc<FetchOptions>) -> mlua::Result<Function> {
    let http_client = client_for(&opts)?;
    let budget = Arc::new(OutboundBudget::default());
    lua.set_app_data(budget.clone());

    lua.create_function(
        move |lua, (method, url, arg): (String, String, Option<Table>)| {
            let mut spec = parse_spec(method, url, arg)?;
            if opts.propagate_trace_context
                && let Some(value) = traceparent(lua)
            {
                spec.headers
                    .entry(HeaderName::from_static("traceparent"))
                    .or_insert(value);
            }
            Ok(LuaFetch {
                client: http_client.clone(),
                spec,
                opts: opts.clone(),
                budget: budget.clone(),
            })
        },
    )
}

/// `await_all(h1, h2, ...)`: performs the given unsent handles concurrently
/// and returns their results in the same order. Fails as a whole if any of
/// them fails.
///
/// Accepts `fetch(...)` handles and `db:query_async(...)` handles, so a
/// handler that needs a row and an HTTP call no longer runs them in series.
/// This is deliberately *not* a general `spawn`/`await` pair: the set of
/// awaitable things is fixed and Rust-side, so a script cannot start
/// arbitrary concurrent Lua.
pub(crate) fn create_await_all_fn(lua: &Lua, opts: Arc<FetchOptions>) -> mlua::Result<Function> {
    lua.create_async_function(move |lua, handles: Variadic<AnyUserData>| {
        let opts = opts.clone();
        async move {
            let max_concurrent = opts.max_concurrent;
            if handles.len() > max_concurrent {
                return Err(mlua::Error::RuntimeError(format!(
                    "await_all called with {} handles, fetch.max_concurrent is {max_concurrent}",
                    handles.len()
                )));
            }

            // Each handle's work is copied out before awaiting, so no Lua
            // borrow lives across a suspension point.
            // Boxed: a `RequestSpec` is much larger than a pending query,
            // and every element of the job list would otherwise be padded
            // to the bigger of the two.
            enum Job {
                Fetch(Box<(Arc<HttpClient>, RequestSpec, Arc<FetchOptions>)>),
                #[cfg(feature = "db")]
                Query(crate::db::PendingQuery),
            }

            let budget = lua.app_data_ref::<Arc<OutboundBudget>>().map(|b| b.clone());
            let mut jobs = Vec::with_capacity(handles.len());
            for handle in handles.iter() {
                if let Ok(fetch) = handle.borrow::<LuaFetch>() {
                    if let Some(budget) = &budget {
                        budget.take(opts.max_per_request)?;
                    }
                    jobs.push(Job::Fetch(Box::new((
                        fetch.client.clone(),
                        fetch.spec.clone(),
                        fetch.opts.clone(),
                    ))));
                    continue;
                }
                #[cfg(feature = "db")]
                if let Ok(query) = handle.borrow::<crate::db::LuaPendingQuery>() {
                    jobs.push(Job::Query(query.take()?));
                    continue;
                }
                return Err(mlua::Error::RuntimeError(
                    "await_all expects fetch(...) or db:query_async(...) handles".into(),
                ));
            }

            let results = futures_util::future::try_join_all(jobs.into_iter().map(|job| {
                let lua = lua.clone();
                async move {
                    match job {
                        Job::Fetch(job) => {
                            let (client, spec, opts) = *job;
                            let resp = send_with_retries(&client, spec, &opts).await?;
                            lua.create_userdata(resp).map(Value::UserData)
                        }
                        #[cfg(feature = "db")]
                        Job::Query(query) => query.run(&lua).await,
                    }
                }
            }))
            .await?;
            Ok(Variadic::from_iter(results))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(method: &str) -> RequestSpec {
        RequestSpec {
            method: HttpMethod::from_bytes(method.as_bytes()).expect("method"),
            url: "https://example.com/".parse().expect("url"),
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
            retry: None,
        }
    }

    #[test]
    fn only_idempotent_methods_may_be_retried() {
        for safe in ["GET", "HEAD", "PUT", "DELETE", "OPTIONS"] {
            assert!(spec(safe).is_idempotent(), "{safe} is idempotent");
        }
        for unsafe_method in ["POST", "PATCH"] {
            assert!(
                !spec(unsafe_method).is_idempotent(),
                "{unsafe_method} must never be repeated automatically"
            );
        }
    }

    #[test]
    fn backoff_grows_and_stays_jittered_within_bounds() {
        for attempt in 1..=4u32 {
            let base = RETRY_BASE_DELAY * (1 << (attempt - 1));
            for _ in 0..20 {
                let delay = backoff(attempt, true);
                assert!(
                    delay >= base / 2 && delay <= base,
                    "attempt {attempt}: {delay:?} outside [{:?}, {:?}]",
                    base / 2,
                    base
                );
            }
        }
        // Constant backoff ignores the attempt number.
        let delay = backoff(8, false);
        assert!(delay <= RETRY_BASE_DELAY);
        // And nothing ever waits longer than the ceiling.
        assert!(backoff(30, true) <= RETRY_MAX_DELAY);
    }

    /// The security boundary is the resolver wired *into* the client, not
    /// `check_url`: even with the URL check bypassed entirely, the built
    /// client must refuse to connect to a policy-forbidden address. This
    /// fails if the `dns_resolver(GuardedResolver)` wiring in
    /// [`client_for`] is ever dropped.
    #[tokio::test]
    async fn built_client_refuses_forbidden_addresses_without_check_url() {
        // A live listener on loopback, so a connection would succeed if
        // the resolver let one through.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let client = client_for(&FetchOptions::default()).expect("client");
        let err = client
            .get(format!("http://localhost:{port}/"))
            .send()
            .await
            .expect_err("the guarded resolver must refuse loopback");

        // The policy refusal surfaces somewhere in reqwest's error chain.
        let mut chain = err.to_string();
        let mut source = std::error::Error::source(&err);
        while let Some(err) = source {
            chain.push_str(": ");
            chain.push_str(&err.to_string());
            source = err.source();
        }
        assert!(
            chain.contains("private or local"),
            "unexpected error: {chain}"
        );
    }

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
