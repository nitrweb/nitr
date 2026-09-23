// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Test doubles for `nitr test`: canned outbound responses and
//! environment overrides, installed by a test as **data** and read by the
//! standard library at the seams that honour them.
//!
//! A test file and the server's pooled states are separate Lua universes,
//! so a double cannot be a Lua function patched into `nitr.*`: it would
//! change the test's state and nothing a handler sees. Instead the runner
//! puts one [`Doubles`] into the app data of every state it builds — the
//! pooled ones through `ServerBuilder::setup`, which also runs on a
//! poison rebuild and a reload, and its own test state directly — and the
//! setters live under `nitr.test`, which only the runner registers.
//!
//! Absent app data means no double: that is the production path, and it
//! costs each seam one app-data lookup. The types here are plain data, so
//! the module compiles in every feature set even though the fetch seam
//! exists only with `fetch`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use mlua::Lua;

/// How many outbound calls a test records before the oldest are dropped:
/// a chatty handler must not grow the record without bound.
pub const MAX_RECORDED_CALLS: usize = 10_000;

/// Every double a test can install, shared by the test state and every
/// pooled state of the server under test.
#[derive(Debug, Default)]
pub struct Doubles {
    fetch: Mutex<FetchMock>,
    /// Environment overrides: `Some(value)` sets, `None` unsets.
    env: RwLock<HashMap<String, Option<String>>>,
}

impl Doubles {
    /// An empty set of doubles, ready to share.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Clears every double: rules, recorded calls, the strict flag and
    /// the environment overrides. The runner calls it before every test.
    pub fn reset(&self) {
        if let Ok(mut fetch) = self.fetch.lock() {
            *fetch = FetchMock::default();
        }
        if let Ok(mut env) = self.env.write() {
            env.clear();
        }
    }

    /// The outbound-request double.
    ///
    /// # Errors
    ///
    /// Only when a panic poisoned the lock, which nothing here can cause.
    pub fn fetch(&self) -> mlua::Result<MutexGuard<'_, FetchMock>> {
        self.fetch
            .lock()
            .map_err(|_| mlua::Error::RuntimeError("the fetch double lock is poisoned".into()))
    }

    /// Overrides one environment variable: `Some` sets it, `None` makes it
    /// read as unset. The `[env]` policy still applies on top.
    pub fn set_env(&self, name: &str, value: Option<String>) {
        if let Ok(mut env) = self.env.write() {
            env.insert(name.to_string(), value);
        }
    }

    /// Removes every environment override.
    pub fn reset_env(&self) {
        if let Ok(mut env) = self.env.write() {
            env.clear();
        }
    }

    /// The override for `name`, when one is installed: `Some(None)` is an
    /// explicit unset.
    pub(crate) fn env_override(&self, name: &str) -> Option<Option<String>> {
        self.env.read().ok()?.get(name).cloned()
    }
}

/// The doubles installed on this state, if any.
pub(crate) fn installed(lua: &Lua) -> Option<Arc<Doubles>> {
    lua.app_data_ref::<Arc<Doubles>>().map(|d| d.clone())
}

/// How a rule matches a request URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlMatch {
    /// The whole URL, as the client serializes it.
    Exact(String),
    /// A prefix, written with a trailing `*` (`https://api.example/*`).
    Prefix(String),
}

impl UrlMatch {
    fn matches(&self, url: &str) -> bool {
        match self {
            UrlMatch::Exact(expected) => url == expected,
            UrlMatch::Prefix(prefix) => url.starts_with(prefix.as_str()),
        }
    }
}

/// One canned answer for `nitr.fetch`.
#[derive(Debug, Clone)]
pub struct FetchRule {
    /// The method to match, uppercase; `None` matches any.
    pub method: Option<String>,
    /// The URL to match.
    pub url: UrlMatch,
    /// The status of the canned response.
    pub status: u16,
    /// Its headers, in order.
    pub headers: Vec<(String, String)>,
    /// Its body.
    pub body: Vec<u8>,
    /// How many requests it answers before falling through; `None` is
    /// unlimited.
    pub times: Option<u32>,
}

/// One outbound call made while the doubles were installed, whether a
/// rule answered it or not.
#[derive(Debug, Clone)]
pub struct FetchCall {
    /// The request method, uppercase.
    pub method: String,
    /// The URL as the client serialized it.
    pub url: String,
    /// The request headers, in order.
    pub headers: Vec<(String, String)>,
    /// The request body, when it had one.
    pub body: Option<Vec<u8>>,
    /// Whether a rule answered it.
    pub mocked: bool,
}

/// The canned response a matched rule produced.
#[derive(Debug, Clone)]
pub struct Canned {
    /// Response status.
    pub status: u16,
    /// Response headers, in order.
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

/// What the double says about one outbound request.
#[derive(Debug)]
pub enum FetchAnswer {
    /// A rule matched: answer with this instead of sending.
    Canned(Canned),
    /// No rule matched and the double is not strict: send it for real,
    /// down the unchanged path, policy and resolver included.
    PassThrough,
    /// No rule matched and the double is strict: refuse.
    Refused,
}

/// Canned responses, the recorded calls, and the strict flag.
#[derive(Debug, Default)]
pub struct FetchMock {
    rules: Vec<FetchRule>,
    calls: VecDeque<FetchCall>,
    strict: bool,
    dropped: u64,
}

impl FetchMock {
    /// Adds a rule; rules are tried in the order they were added.
    pub fn add(&mut self, rule: FetchRule) {
        self.rules.push(rule);
    }

    /// Whether an unmatched request is refused instead of sent.
    pub fn set_strict(&mut self, strict: bool) {
        self.strict = strict;
    }

    /// The calls recorded so far, oldest first.
    pub fn calls(&self) -> impl Iterator<Item = &FetchCall> {
        self.calls.iter()
    }

    /// How many of the oldest calls were dropped past
    /// [`MAX_RECORDED_CALLS`].
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Records one outbound request and decides its fate: the first rule
    /// that matches (method and URL) and has uses left answers it and
    /// spends one use.
    pub fn answer(
        &mut self,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> FetchAnswer {
        let rule = self.rules.iter_mut().find(|rule| {
            rule.method
                .as_deref()
                .is_none_or(|m| m.eq_ignore_ascii_case(method))
                && rule.url.matches(url)
                && rule.times.is_none_or(|left| left > 0)
        });
        let answer = match rule {
            Some(rule) => {
                if let Some(left) = &mut rule.times {
                    *left -= 1;
                }
                FetchAnswer::Canned(Canned {
                    status: rule.status,
                    headers: rule.headers.clone(),
                    body: rule.body.clone(),
                })
            }
            None if self.strict => FetchAnswer::Refused,
            None => FetchAnswer::PassThrough,
        };
        if self.calls.len() >= MAX_RECORDED_CALLS {
            self.calls.pop_front();
            self.dropped += 1;
        }
        self.calls.push_back(FetchCall {
            method: method.to_ascii_uppercase(),
            url: url.to_string(),
            headers,
            body,
            mocked: matches!(answer, FetchAnswer::Canned(_)),
        });
        answer
    }
}

/// The value `session:save` would write for `data`: the JSON payload
/// (with the expiry when `max_age` is set) signed for `name` — so a test
/// can put a session into a client's jar without a login round trip.
///
/// # Errors
///
/// The same as `session:save`: a secret under 16 bytes, reserved keys,
/// values that are not JSON, or a payload over the cookie bound.
pub fn session_cookie_value(
    data: &mlua::Table,
    name: &str,
    secret: &str,
    max_age: Option<i64>,
) -> mlua::Result<String> {
    crate::session::signed_value(data, name, secret, max_age)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(method: Option<&str>, url: UrlMatch, times: Option<u32>) -> FetchRule {
        FetchRule {
            method: method.map(str::to_string),
            url,
            status: 202,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"canned".to_vec(),
            times,
        }
    }

    fn status(answer: FetchAnswer) -> Option<u16> {
        match answer {
            FetchAnswer::Canned(c) => Some(c.status),
            _ => None,
        }
    }

    #[test]
    fn exact_and_prefix_rules_match_what_they_say() {
        let mut mock = FetchMock::default();
        mock.add(rule(
            None,
            UrlMatch::Exact("https://hooks.example/notes".into()),
            None,
        ));
        mock.add(rule(
            None,
            UrlMatch::Prefix("https://api.example/".into()),
            None,
        ));
        let mut ask = |url: &str| status(mock.answer("GET", url, Vec::new(), None));
        assert_eq!(ask("https://hooks.example/notes"), Some(202));
        assert_eq!(ask("https://hooks.example/notes/1"), None, "exact is exact");
        assert_eq!(ask("https://api.example/v1/rates"), Some(202));
        assert_eq!(
            ask("https://api.example.evil/"),
            None,
            "a prefix is a string prefix"
        );
    }

    #[test]
    fn methods_and_times_narrow_a_rule_and_the_first_match_wins() {
        let mut mock = FetchMock::default();
        mock.add(rule(
            Some("POST"),
            UrlMatch::Prefix("https://x/".into()),
            Some(1),
        ));
        let mut fallback = rule(None, UrlMatch::Prefix("https://x/".into()), None);
        fallback.status = 503;
        mock.add(fallback);
        assert_eq!(
            status(mock.answer("get", "https://x/a", Vec::new(), None)),
            Some(503)
        );
        assert_eq!(
            status(mock.answer("post", "https://x/a", Vec::new(), None)),
            Some(202)
        );
        assert_eq!(
            status(mock.answer("POST", "https://x/a", Vec::new(), None)),
            Some(503),
            "a spent rule falls through to the next"
        );
    }

    #[test]
    fn strict_refuses_what_no_rule_matches_and_every_call_is_recorded() {
        let mut mock = FetchMock::default();
        mock.add(rule(None, UrlMatch::Exact("https://x/a".into()), None));
        assert!(matches!(
            mock.answer("GET", "https://x/b", Vec::new(), None),
            FetchAnswer::PassThrough
        ));
        mock.set_strict(true);
        assert!(matches!(
            mock.answer("GET", "https://x/b", Vec::new(), None),
            FetchAnswer::Refused
        ));
        mock.answer(
            "post",
            "https://x/a",
            vec![("x-signature".into(), "sha256=1".into())],
            Some(b"{}".to_vec()),
        );
        let calls: Vec<_> = mock.calls().collect();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].method, "POST");
        assert!(calls[2].mocked);
        assert!(!calls[1].mocked);
        assert_eq!(calls[2].body.as_deref(), Some(&b"{}"[..]));
    }

    #[test]
    fn the_call_record_is_bounded() {
        let mut mock = FetchMock::default();
        for i in 0..MAX_RECORDED_CALLS + 5 {
            mock.answer("GET", &format!("https://x/{i}"), Vec::new(), None);
        }
        assert_eq!(mock.calls().count(), MAX_RECORDED_CALLS);
        assert_eq!(mock.dropped(), 5);
        assert_eq!(
            mock.calls().next().map(|c| c.url.as_str()),
            Some("https://x/5"),
            "the oldest go first"
        );
    }

    #[test]
    fn reset_clears_every_double() {
        let doubles = Doubles::new();
        doubles.set_env("APP_KEY", Some("k".into()));
        doubles
            .fetch()
            .expect("fetch")
            .add(rule(None, UrlMatch::Prefix("https://".into()), None));
        doubles.fetch().expect("fetch").set_strict(true);
        doubles.reset();
        assert_eq!(doubles.env_override("APP_KEY"), None);
        let mut fetch = doubles.fetch().expect("fetch");
        assert!(matches!(
            fetch.answer("GET", "https://x/", Vec::new(), None),
            FetchAnswer::PassThrough
        ));
    }
}
