// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Request/response cookies: parsing, the `Set-Cookie` builder, the
//! server-resolved `Secure` default, and HMAC-SHA256 signed variants.

use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, Mac as _};
use mlua::{Lua, MetaMethod, Table, UserData, UserDataMethods, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Cookies parsed from a request's `Cookie` header: values via indexing
/// (`req.cookies.session`) and signed-cookie verification via
/// `req.cookies:verify(name, secret)`.
pub struct RequestCookies(Vec<(String, String)>);

impl RequestCookies {
    /// Parses a `Cookie` request header (an empty string yields no cookies).
    pub fn parse(header: &str) -> Self {
        Self(
            cookie::Cookie::split_parse(header)
                .flatten()
                .map(|c| (c.name().to_string(), c.value().to_string()))
                .collect(),
        )
    }

    /// The parsed (name, value) pairs, in header order, for the
    /// `cookie_header` fuzz target — the parse result is otherwise only
    /// observable through Lua indexing.
    #[doc(hidden)]
    pub fn pairs(&self) -> &[(String, String)] {
        &self.0
    }

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

impl UserData for RequestCookies {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::Index, |lua, this, name: Value| {
            let Value::String(name) = name else {
                return Ok(Value::Nil);
            };
            match this.get(&name.to_string_lossy()) {
                Some(v) => Ok(Value::String(lua.create_string(v)?)),
                None => Ok(Value::Nil),
            }
        });

        // Returns the verified value of a signed cookie, or nil when the
        // cookie is missing, malformed, or its signature does not match.
        methods.add_method(
            "verify",
            |lua, this, (name, secret): (String, String)| match this
                .get(&name)
                .and_then(|raw| verify(&name, raw, &secret))
            {
                Some(v) => Ok(Value::String(lua.create_string(v)?)),
                None => Ok(Value::Nil),
            },
        );
    }
}

/// Builder for response `Set-Cookie` headers, attached as the `cookies`
/// field of helper-built response tables. The server serializes each entry
/// into its own `Set-Cookie` header.
#[derive(Default)]
pub struct ResponseCookies(Mutex<Vec<String>>);

impl ResponseCookies {
    /// The serialized `Set-Cookie` values collected so far.
    pub fn values(&self) -> Vec<String> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }

    fn push(&self, value: String) -> mlua::Result<()> {
        self.0
            .lock()
            .map_err(|_| mlua::Error::RuntimeError("the cookie list lock is poisoned".into()))?
            .push(value);
        Ok(())
    }
}

impl UserData for ResponseCookies {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method(
            "set",
            |lua, this, (name, value, opts): (String, String, Option<Table>)| {
                this.push(build_cookie(lua, &name, &value, opts.as_ref())?)
            },
        );

        // Signs the value with HMAC-SHA256 so `req.cookies:verify(name,
        // secret)` can authenticate it on later requests.
        methods.add_method(
            "set_signed",
            |lua, this, (name, value, secret, opts): (String, String, String, Option<Table>)| {
                this.push(build_cookie(
                    lua,
                    &name,
                    &sign(&name, &value, &secret),
                    opts.as_ref(),
                )?)
            },
        );
    }
}

/// Attaches a serialized `Set-Cookie` value to a handler response table:
/// through its `cookies` builder when present (helper-built responses), or
/// by creating one (hand-built plain tables), so the server's response
/// conversion picks it up either way.
pub(crate) fn attach_cookie(resp: &Table, cookie: String) -> mlua::Result<()> {
    match resp.raw_get::<Value>("cookies")? {
        Value::UserData(ud) => {
            let cookies = ud.borrow::<ResponseCookies>().map_err(|_| {
                mlua::Error::RuntimeError(
                    "the response `cookies` field is not a cookie builder".into(),
                )
            })?;
            cookies.push(cookie)
        }
        Value::Nil => {
            let cookies = ResponseCookies::default();
            cookies.push(cookie)?;
            resp.set("cookies", cookies)
        }
        other => Err(mlua::Error::RuntimeError(format!(
            "invalid `cookies` field of type `{}` in the response table",
            other.type_name()
        ))),
    }
}

/// The per-state cookie policy, stashed by `register_builtins` and read
/// by [`build_cookie`].
///
/// App data rather than a captured value because [`build_cookie`] is
/// reached from `UserData` methods, whose closures are registered once per
/// *type* and so cannot capture per-server state — the alternative would
/// be threading the flag into every `ResponseCookies` construction site.
/// Absent means not secure, matching `BuiltinsEnv`'s derived `Default`, so
/// an embedder who never sets one keeps today's behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct CookieDefaults {
    /// Whether cookies carry `Secure` when the caller's options do not say.
    pub secure: bool,
}

/// The resolved `Secure` default for this state; `false` when nothing
/// registered one.
fn secure_default(lua: &Lua) -> bool {
    lua.app_data_ref::<CookieDefaults>()
        .is_some_and(|defaults| defaults.secure)
}

/// Merges caller-supplied cookie options over a module's defaults and
/// forces `http_only` back on.
///
/// The single home of "extend, don't replace" for cookie options. CSRF
/// used to do the opposite — a caller passing `cookie_opts = { path =
/// "/admin" }` got *only* that path, silently losing `HttpOnly` and
/// `SameSite` — while sessions merged. Both now come through here, so the
/// two cannot disagree again.
///
/// `http_only` is forced because no script has business reading these
/// cookies (`nitr.csrf.token(req)` is the supported route, and a session
/// is server state). `same_site` deliberately stays overridable: a
/// legitimate cross-site form needs `None`, and forcing it would repeat
/// the same mistake in the other direction.
pub(crate) fn merge_cookie_opts(defaults: Table, caller: Option<&Table>) -> mlua::Result<Table> {
    if let Some(caller) = caller {
        for pair in caller.pairs::<Value, Value>() {
            let (key, value) = pair?;
            defaults.set(key, value)?;
        }
    }
    defaults.set("http_only", true)?;
    Ok(defaults)
}

/// Serializes one cookie, applying the recognized options: `http_only`,
/// `secure`, `path`, `domain`, `max_age` (seconds), `same_site`
/// (`"Strict"` / `"Lax"` / `"None"`).
///
/// `secure` is the one attribute with a server-resolved default (see
/// [`CookieDefaults`]): an explicit value from Lua always wins, in both
/// directions, and its absence means the `[cookies] secure` policy
/// decides. That resolution happens *outside* the options block below, so
/// it also covers `res.cookies:set(name, value)` called with no options
/// table at all.
pub(crate) fn build_cookie(
    lua: &Lua,
    name: &str,
    value: &str,
    opts: Option<&Table>,
) -> mlua::Result<String> {
    let mut builder = cookie::Cookie::build((name.to_owned(), value.to_owned()));
    let explicit_secure = match opts {
        Some(opts) => opts.get::<Option<bool>>("secure")?,
        None => None,
    };
    if explicit_secure.unwrap_or_else(|| secure_default(lua)) {
        builder = builder.secure(true);
    }
    if let Some(opts) = opts {
        if opts.get::<Option<bool>>("http_only")?.unwrap_or(false) {
            builder = builder.http_only(true);
        }
        if let Some(path) = opts.get::<Option<String>>("path")? {
            builder = builder.path(path);
        }
        if let Some(domain) = opts.get::<Option<String>>("domain")? {
            builder = builder.domain(domain);
        }
        if let Some(secs) = opts.get::<Option<i64>>("max_age")? {
            builder = builder.max_age(cookie::time::Duration::seconds(secs));
        }
        if let Some(same_site) = opts.get::<Option<String>>("same_site")? {
            builder = builder.same_site(match same_site.to_ascii_lowercase().as_str() {
                "strict" => cookie::SameSite::Strict,
                "lax" => cookie::SameSite::Lax,
                "none" => cookie::SameSite::None,
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "invalid same_site value `{other}`: expected Strict, Lax or None"
                    )));
                }
            });
        }
    }
    Ok(builder.build().to_string())
}

/// Encodes and signs a cookie value: `b64(value) . b64(hmac)`, with the
/// cookie name bound into the MAC so values cannot be swapped between
/// cookies.
pub fn sign(name: &str, value: &str, secret: &str) -> String {
    let payload = B64.encode(value);
    format!(
        "{payload}.{}",
        B64.encode(mac_bytes(name, &payload, secret))
    )
}

/// Verifies a value produced by [`sign()`]; the MAC comparison is
/// constant-time (`hmac::Mac::verify_slice`).
pub fn verify(name: &str, signed: &str, secret: &str) -> Option<String> {
    let (payload, sig) = signed.rsplit_once('.')?;
    let sig = B64.decode(sig).ok()?;
    new_mac(name, payload, secret).verify_slice(&sig).ok()?;
    String::from_utf8(B64.decode(payload).ok()?).ok()
}

fn new_mac(name: &str, payload: &str, secret: &str) -> HmacSha256 {
    let mut mac: HmacSha256 = crate::utils::new_hmac(secret.as_bytes());
    mac.update(name.as_bytes());
    mac.update(b"=");
    mac.update(payload.as_bytes());
    mac
}

fn mac_bytes(name: &str, payload: &str, secret: &str) -> Vec<u8> {
    new_mac(name, payload, secret)
        .finalize()
        .into_bytes()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_cookies_round_trip_and_reject_tampering() {
        let signed = sign("session", "user-42", "s3cret");
        assert_eq!(
            verify("session", &signed, "s3cret").as_deref(),
            Some("user-42")
        );

        // Wrong secret, wrong name (cookie swapping), tampered payload.
        assert_eq!(verify("session", &signed, "other"), None);
        assert_eq!(verify("tracking", &signed, "s3cret"), None);
        let tampered = format!("x{signed}");
        assert_eq!(verify("session", &tampered, "s3cret"), None);
        assert_eq!(verify("session", "garbage", "s3cret"), None);
    }

    /// The `Secure` default reaches every cookie Nitr serializes, and an
    /// explicit value from Lua wins in *both* directions — a caller who
    /// writes `secure = false` on a TLS server must still get a plain
    /// cookie, or the escape hatch is gone.
    #[test]
    fn the_secure_default_applies_unless_the_caller_says_otherwise() {
        for (default_secure, explicit, want_secure) in [
            // No policy registered at all: today's behaviour.
            (None, None, false),
            (Some(false), None, false),
            (Some(true), None, true),
            // An explicit value always wins.
            (Some(true), Some(false), false),
            (Some(false), Some(true), true),
        ] {
            let lua = mlua::Lua::new();
            if let Some(secure) = default_secure {
                lua.set_app_data(CookieDefaults { secure });
            }
            let opts = match explicit {
                Some(value) => {
                    let opts = lua.create_table().expect("table");
                    opts.set("secure", value).expect("set");
                    Some(opts)
                }
                None => None,
            };
            let cookie = build_cookie(&lua, "session", "abc", opts.as_ref()).expect("cookie");
            assert_eq!(
                cookie.contains("Secure"),
                want_secure,
                "default={default_secure:?} explicit={explicit:?} gave `{cookie}`"
            );
        }
    }

    /// A caller's options extend the module defaults rather than replacing
    /// them, and `http_only` cannot be un-set.
    #[test]
    fn merging_cookie_options_keeps_the_defaults_a_caller_did_not_mention() {
        let lua = mlua::Lua::new();
        let defaults = lua.create_table().expect("table");
        defaults.set("path", "/").expect("set");
        defaults.set("same_site", "Lax").expect("set");

        // A partial table: only `path` is mentioned.
        let caller = lua.create_table().expect("table");
        caller.set("path", "/admin").expect("set");
        let merged = merge_cookie_opts(defaults, Some(&caller)).expect("merge");
        assert_eq!(
            merged.get::<String>("path").expect("path"),
            "/admin",
            "the caller's value wins"
        );
        assert_eq!(
            merged.get::<String>("same_site").expect("same_site"),
            "Lax",
            "a default the caller did not mention must survive"
        );
        assert!(
            merged.get::<bool>("http_only").expect("http_only"),
            "http_only must survive"
        );

        // `http_only = false` cannot un-set it; `same_site` stays
        // overridable, because a legitimate cross-site form needs `None`.
        let defaults = lua.create_table().expect("table");
        defaults.set("same_site", "Lax").expect("set");
        let caller = lua.create_table().expect("table");
        caller.set("http_only", false).expect("set");
        caller.set("same_site", "None").expect("set");
        let merged = merge_cookie_opts(defaults, Some(&caller)).expect("merge");
        assert!(
            merged.get::<bool>("http_only").expect("http_only"),
            "http_only is forced, not merely defaulted"
        );
        assert_eq!(
            merged.get::<String>("same_site").expect("same_site"),
            "None",
            "same_site is deliberately overridable"
        );
    }

    #[test]
    fn cookies_serialize_their_options() {
        let lua = mlua::Lua::new();
        let opts: Table = lua
            .load(r#"{ http_only = true, secure = true, same_site = "Lax", max_age = 3600, path = "/" }"#)
            .eval()
            .expect("opts table");
        let cookie = build_cookie(&lua, "session", "abc", Some(&opts)).expect("cookie");
        for part in [
            "session=abc",
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
            "Max-Age=3600",
            "Path=/",
        ] {
            assert!(cookie.contains(part), "`{cookie}` should contain `{part}`");
        }
    }

    proptest::proptest! {
        /// Property: sign/verify round-trips arbitrary printable inputs,
        /// and flipping any single character of the signed value breaks
        /// it — as do the wrong secret and a swapped cookie name.
        #[test]
        fn prop_signed_cookies_round_trip_and_any_tamper_fails(
            name in "[ -~]{1,16}",
            value in "[ -~]{0,48}",
            secret in "[ -~]{1,32}",
            pos in proptest::prelude::any::<proptest::sample::Index>(),
        ) {
            let signed = sign(&name, &value, &secret);
            let verified = verify(&name, &signed, &secret);
            proptest::prop_assert_eq!(verified.as_deref(), Some(value.as_str()));

            // One changed character anywhere — payload or MAC — must fail.
            // The index is taken over the collected chars, not the byte
            // length: the two only coincide while the signed encoding
            // stays pure ASCII, and the test must not depend on that.
            let mut tampered: Vec<char> = signed.chars().collect();
            let pos = pos.index(tampered.len());
            tampered[pos] = if tampered[pos] == 'A' { 'B' } else { 'A' };
            let tampered: String = tampered.into_iter().collect();
            proptest::prop_assert_eq!(verify(&name, &tampered, &secret), None);

            proptest::prop_assert_eq!(verify(&name, &signed, "other-secret"), None);
            proptest::prop_assert_eq!(verify("other-name", &signed, &secret), None);
        }
    }
}
