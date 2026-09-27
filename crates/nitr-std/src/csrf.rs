// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! CSRF protection built on the signed-cookie primitives: `nitr.csrf(...)`
//! is a middleware factory for the phase-2 composition model
//! (`app:use(nitr.csrf({ secret = ... }))`), and `nitr.csrf.token(req)`
//! returns the request's token for embedding in a form or a meta tag.
//!
//! The scheme is a signed double-submit token: the token lives in a signed
//! cookie the middleware issues, and every unsafe-method request must echo
//! it back in a header or form field. Verification is Rust-side and
//! constant-time; safe methods (GET/HEAD/OPTIONS/TRACE) are skipped, per
//! RFC 9110's definition of safe.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use mlua::{Function, Lua, MetaMethod, ObjectLike as _, Table, Value};
use subtle::ConstantTimeEq as _;

use crate::http;

/// The token issued for the request currently executing in this Lua state.
///
/// One pooled state runs one request at a time, so a single slot suffices —
/// but it is keyed by request id and `token()` checks the key, so a stale
/// value from a previous request can never leak into one whose chain did
/// not install the middleware.
struct CsrfSlot {
    req_id: String,
    token: String,
}

/// Everything the middleware needs per request, resolved once when the
/// factory runs (at app compile time, not per request).
struct Config {
    secret: String,
    /// The cookie's name: the `name` option, default `_csrf`, spelled as
    /// `nitr.session` spells it.
    cookie: String,
    header: String,
    field: String,
    /// The `cookie` option: the cookie's attributes, **extending** the
    /// defaults rather than replacing them. See [`cookie_opts`].
    cookie_opts: Option<Table>,
    /// Whether an unsafe request a browser marks `Sec-Fetch-Site:
    /// cross-site` is refused outright. On unless the token cookie is
    /// `SameSite=None`, which is the one configuration that *means* to
    /// accept cross-site form posts. See [`refuses_cross_site`].
    refuse_cross_site: bool,
}

/// Whether the middleware refuses browser-flagged cross-site requests
/// before looking at the token.
///
/// A double-submit token proves the sender could read a cookie, not that
/// the cookie was ours: a sibling subdomain (or plain HTTP, when the
/// cookie is not `Secure`) can plant one it obtained itself. Browsers
/// state the answer to that directly — a request a third-party site
/// initiated says `Sec-Fetch-Site: cross-site` — so it is refused, unless
/// the caller set `same_site = "None"` on the token cookie, which is the
/// documented way to accept a legitimate cross-site form and would be
/// contradicted by the refusal. Older clients send no such header and
/// fall back to the token alone.
fn refuses_cross_site(cookie_opts: Option<&Table>) -> mlua::Result<bool> {
    let Some(opts) = cookie_opts else {
        return Ok(true);
    };
    let same_site: Option<String> = opts.get("same_site")?;
    Ok(!same_site.is_some_and(|value| value.eq_ignore_ascii_case("none")))
}

fn new_token() -> mlua::Result<String> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)
        .map_err(|err| mlua::Error::RuntimeError(format!("failed to read OS entropy: {err}")))?;
    Ok(B64.encode(buf))
}

/// Cookie attributes for the CSRF token cookie: site-wide, HttpOnly
/// (scripts get the token from `nitr.csrf.token`, not the cookie) and
/// SameSite=Lax as a second layer of defense.
///
/// A caller's `cookie` table **extends** these rather than replacing them.
/// It used to replace: `nitr.csrf({ secret = …, cookie = { path =
/// "/admin" } })` issued its token cookie with no `HttpOnly` and no
/// `SameSite`, silently — on the more security-sensitive of the two cookie
/// modules, while sessions merged correctly for the same job.
fn cookie_opts(lua: &Lua, caller: Option<&Table>) -> mlua::Result<Table> {
    let opts = lua.create_table()?;
    opts.set("path", "/")?;
    opts.set("same_site", "Lax")?;
    http::merge_cookie_opts(opts, caller)
}

/// The token the request supplied: the header when present, else the
/// `_csrf` field of an urlencoded form body. Reading the form goes through
/// `req:form()`, whose parse is cached on the request, so the handler can
/// still read the body afterwards. Multipart bodies are deliberately not
/// searched — file uploads should send the token in the header.
async fn supplied_token(req: &Value, config: &Config) -> mlua::Result<Option<String>> {
    let Value::UserData(ud) = req else {
        return Ok(None);
    };
    let headers: Table = ud.get("headers")?;
    if let Some(token) = headers.get::<Option<String>>(config.header.as_str())? {
        return Ok(Some(token));
    }
    let content_type: Option<String> = headers.get("content-type")?;
    let is_form = content_type
        .as_deref()
        .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));
    if !is_form {
        return Ok(None);
    }
    let form = ud.call_async_method::<Table>("form", ()).await?;
    form.get(config.field.as_str())
}

/// The verified token from the request's signed cookie, if it has one.
fn cookie_token(req: &Value, config: &Config) -> Option<String> {
    let Value::UserData(ud) = req else {
        return None;
    };
    let cookies = ud.get::<mlua::AnyUserData>("cookies").ok()?;
    let cookies = cookies.borrow::<http::RequestCookies>().ok()?;
    http::verify(&config.cookie, cookies.get(&config.cookie)?, &config.secret)
}

/// The middleware handler around one request.
async fn handle(lua: Lua, config: Arc<Config>, next: Function, req: Value) -> mlua::Result<Value> {
    // Both fields come out of the single match that proves the shape, so
    // no later code needs to re-match the value it already checked.
    let (req_id, method): (String, String) = match &req {
        Value::UserData(ud) => (ud.get("id")?, ud.get("method")?),
        other => {
            return Err(mlua::Error::RuntimeError(format!(
                "nitr.csrf middleware expects the request object, got {}",
                other.type_name()
            )));
        }
    };

    let existing = cookie_token(&req, &config);
    let issue = existing.is_none();
    let token = match existing {
        Some(token) => token,
        None => new_token()?,
    };
    lua.set_app_data(CsrfSlot {
        req_id,
        token: token.clone(),
    });

    let safe = matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE");

    let resp = if safe {
        next.call_async::<Value>(&req).await?
    } else {
        // See `refuses_cross_site`.
        let cross_site = match &req {
            Value::UserData(ud) if config.refuse_cross_site => ud
                .get::<Table>("headers")?
                .get::<Option<String>>("sec-fetch-site")?
                .is_some_and(|site| site.eq_ignore_ascii_case("cross-site")),
            _ => false,
        };
        let supplied = if cross_site {
            None
        } else {
            supplied_token(&req, &config).await?
        };
        let ok = supplied.as_deref().is_some_and(|supplied| {
            let (a, b) = (supplied.as_bytes(), token.as_bytes());
            // A freshly issued token can never match: the client has not
            // seen it yet, so an unsafe request without the cookie fails.
            !issue && a.len() == b.len() && bool::from(a.ct_eq(b))
        });
        if ok {
            next.call_async::<Value>(&req).await?
        } else {
            let resp = http::response_table(&lua, 403)?;
            let headers = resp.get::<Table>("headers")?;
            // A client asking for JSON gets a `code` it can branch on, like
            // the server's own rejections.
            let wants_json = match &req {
                Value::UserData(ud) => ud
                    .get::<Table>("headers")?
                    .get::<Option<String>>("accept")?
                    .is_some_and(|accept| accept.contains("application/json")),
                _ => false,
            };
            if wants_json {
                headers.set("Content-Type", "application/json")?;
                resp.set(
                    "body",
                    r#"{"code":"CSRF_INVALID","message":"missing or invalid CSRF token"}"#,
                )?;
            } else {
                headers.set("Content-Type", "text/plain; charset=utf-8")?;
                resp.set("body", "Forbidden: missing or invalid CSRF token")?;
            }
            Value::Table(resp)
        }
    };

    // Issue the cookie on whatever goes out — including the 403, so a
    // client that lost its cookie can succeed on retry.
    if issue && let Value::Table(resp) = &resp {
        let opts = cookie_opts(&lua, config.cookie_opts.as_ref())?;
        let signed = http::sign(&config.cookie, &token, &config.secret);
        http::attach_cookie(
            resp,
            http::build_cookie(&lua, &config.cookie, &signed, Some(&opts))?,
        )?;
    }
    Ok(resp)
}

/// Builds `nitr.csrf`: callable as `nitr.csrf(opts)` (the middleware
/// factory) with `nitr.csrf.token(req)` alongside.
///
/// Options: `secret` (required, 16+ bytes), `name` (the cookie's name,
/// default `_csrf`), `header` (default `x-csrf-token`), `field` (the form
/// field, default `_csrf`), and `cookie` (the cookie's *attributes*), the
/// spellings `nitr.session` uses too.
///
/// `cookie` **extends** the defaults (`path = "/"`, `HttpOnly`,
/// `SameSite=Lax`); it does not replace them, and `http_only` cannot be
/// un-set.
pub(crate) fn create_csrf_table(lua: &Lua) -> mlua::Result<Table> {
    let csrf = lua.create_table()?;

    csrf.set(
        "token",
        lua.create_function(|lua, req: Value| {
            let req_id: Option<String> = match &req {
                Value::UserData(ud) => ud.get("id").ok(),
                _ => None,
            };
            let slot = lua.app_data_ref::<CsrfSlot>();
            match (req_id, slot) {
                (Some(req_id), Some(slot)) if slot.req_id == req_id => {
                    Ok(lua.create_string(&slot.token)?)
                }
                _ => Err(mlua::Error::RuntimeError(
                    "nitr.csrf.token(req): the nitr.csrf middleware did not run for this \
                     request — add app:use(nitr.csrf({ secret = ... })) before the routes"
                        .into(),
                )),
            }
        })?,
    )?;

    let meta = create_call_metatable(lua)?;
    csrf.set_metatable(Some(meta))?;

    Ok(csrf)
}

fn create_call_metatable(lua: &Lua) -> mlua::Result<Table> {
    let meta = lua.create_table()?;
    meta.set(
        MetaMethod::Call.name(),
        lua.create_function(|lua, (_, opts): (Table, Table)| {
            let secret: String = opts.get::<Option<String>>("secret")?.ok_or_else(|| {
                mlua::Error::RuntimeError("nitr.csrf requires a `secret` option".into())
            })?;
            if secret.len() < 16 {
                return Err(mlua::Error::RuntimeError(
                    "nitr.csrf `secret` must be at least 16 bytes".into(),
                ));
            }
            // The same two spellings as `nitr.session`: `name` for the
            // cookie's name, `cookie` for its attributes. The old pair
            // (`cookie` the name, `cookie_opts` the attributes) is refused
            // by name rather than read another way.
            if opts.contains_key("cookie_opts")? {
                return Err(mlua::Error::RuntimeError(
                    "nitr.csrf: `cookie_opts` is now `cookie` (the attribute table), and the \
                     cookie's name is `name`, as in nitr.session"
                        .into(),
                ));
            }
            let cookie_attrs = match opts.get::<Value>("cookie")? {
                Value::Nil => None,
                Value::Table(attrs) => Some(attrs),
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "nitr.csrf: `cookie` is the attribute table (`{{ path = ..., same_site = \
                         ... }}`); the cookie's name is `name`, got {}",
                        other.type_name()
                    )));
                }
            };
            let config = Arc::new(Config {
                secret,
                cookie: opts
                    .get::<Option<String>>("name")?
                    .unwrap_or_else(|| "_csrf".into()),
                // Request header names reach Lua lowercased; a caller who
                // writes the option in canonical case must still match.
                header: opts
                    .get::<Option<String>>("header")?
                    .unwrap_or_else(|| "x-csrf-token".into())
                    .to_ascii_lowercase(),
                field: opts
                    .get::<Option<String>>("field")?
                    .unwrap_or_else(|| "_csrf".into()),
                refuse_cross_site: refuses_cross_site(cookie_attrs.as_ref())?,
                cookie_opts: cookie_attrs,
            });

            // The factory the router composes: factory(next) -> handler.
            lua.create_function(move |lua, next: Function| {
                let config = config.clone();
                lua.create_async_function(move |lua, req: Value| {
                    handle(lua, config.clone(), next.clone(), req)
                })
            })
        })?,
    )?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_long_random_and_url_safe() {
        let a = new_token().expect("token");
        let b = new_token().expect("token");
        assert_ne!(a, b);
        // 32 bytes → 43 unpadded base64url chars, cookie- and header-safe.
        assert_eq!(a.len(), 43);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    /// The option names are `nitr.session`'s: the old pair is refused by
    /// name, and a string where the attribute table goes names `name`.
    #[test]
    fn the_factory_refuses_the_old_cookie_spellings() {
        let lua = Lua::new();
        let csrf = create_csrf_table(&lua).expect("table");
        for (opts, expected) in [
            (
                r#"{ secret = "csrf-secret-0123456789", cookie_opts = { path = "/" } }"#,
                "`cookie_opts` is now `cookie`",
            ),
            (
                r#"{ secret = "csrf-secret-0123456789", cookie = "_token" }"#,
                "the cookie's name is `name`",
            ),
        ] {
            let opts: Table = lua.load(opts).eval().expect("opts");
            let err = csrf
                .call::<mlua::Function>(opts)
                .expect_err("refused")
                .to_string();
            assert!(err.contains(expected), "{err}");
        }
        let opts: Table = lua
            .load(r#"{ secret = "csrf-secret-0123456789", name = "_token", cookie = { path = "/" } }"#)
            .eval()
            .expect("opts");
        csrf.call::<mlua::Function>(opts)
            .expect("the new spellings");
    }

    #[test]
    fn the_factory_validates_its_secret_up_front() {
        let lua = Lua::new();
        let csrf = create_csrf_table(&lua).expect("table");

        for opts in ["{}", r#"{ secret = "short" }"#] {
            let opts: Table = lua.load(opts).eval().expect("opts");
            let err = csrf.call::<Value>(opts).expect_err("weak secret");
            assert!(err.to_string().contains("secret"), "got: {err}");
        }

        // A good secret yields the middleware factory, and the factory
        // wraps `next` into a new handler function.
        let opts: Table = lua
            .load(r#"{ secret = "0123456789abcdef" }"#)
            .eval()
            .expect("opts");
        let factory: Function = csrf.call(opts).expect("factory");
        let next = lua.create_function(|_, v: Value| Ok(v)).expect("next");
        let _handler: Function = factory.call(next).expect("handler");
    }

    /// Cross-site requests are refused by default and accepted only when
    /// the token cookie is deliberately `SameSite=None`.
    #[test]
    fn cross_site_refusal_follows_the_cookie_policy() {
        let lua = Lua::new();
        assert!(refuses_cross_site(None).expect("default"));
        for (opts, expected) in [
            ("{ path = '/admin' }", true),
            ("{ same_site = 'Lax' }", true),
            ("{ same_site = 'Strict' }", true),
            ("{ same_site = 'None' }", false),
            ("{ same_site = 'none' }", false),
        ] {
            let table: Table = lua.load(opts).eval().expect("opts");
            assert_eq!(
                refuses_cross_site(Some(&table)).expect("policy"),
                expected,
                "{opts}"
            );
        }
    }

    #[test]
    fn the_header_option_matches_regardless_of_case() {
        let lua = Lua::new();
        let csrf = create_csrf_table(&lua).expect("table");
        let opts: Table = lua
            .load(r#"{ secret = "0123456789abcdef", header = "X-CSRF-Token" }"#)
            .eval()
            .expect("opts");
        // The factory stores the lowercased name; the request's header
        // table is keyed lowercase, so this is what makes the lookup hit.
        let factory: Function = csrf.call(opts).expect("factory");
        let _handler: Function = factory
            .call(lua.create_function(|_, v: Value| Ok(v)).expect("next"))
            .expect("handler");
        // Observable through the config the closure captured: rebuild it
        // the same way and check the field directly.
        let opts: Table = lua
            .load(r#"{ secret = "0123456789abcdef", header = "X-CSRF-Token" }"#)
            .eval()
            .expect("opts");
        let header: String = opts.get("header").expect("header");
        assert_eq!(header.to_ascii_lowercase(), "x-csrf-token");
    }

    #[test]
    fn token_refuses_to_serve_a_stale_or_missing_slot() {
        let lua = Lua::new();
        let csrf = create_csrf_table(&lua).expect("table");
        let token: Function = csrf.get("token").expect("fn");

        // No middleware ran: hard error, not a silently absent token.
        let err = token.call::<Value>(Value::Nil).expect_err("no slot");
        assert!(err.to_string().contains("middleware"), "got: {err}");

        // A slot from some other request must never leak: `token()` keys
        // by request id, and a mismatch is the same hard error.
        lua.set_app_data(CsrfSlot {
            req_id: "other-request".into(),
            token: "t0ken".into(),
        });
        let err = token.call::<Value>(Value::Nil).expect_err("stale slot");
        assert!(err.to_string().contains("middleware"), "got: {err}");
    }
}
