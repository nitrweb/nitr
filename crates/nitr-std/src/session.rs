// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Stateless signed-cookie sessions: `nitr.session(req, { secret = ... })`
//! loads the session table, fields are plain Lua assignments, and
//! `session:save(resp)` writes the whole session back into a signed
//! cookie.
//!
//! The entire session lives in the cookie — no store to provision, no
//! eviction, no coherence problem across processes. The consequences are
//! stated plainly rather than glossed over: the session is bounded to a
//! few kilobytes, and it cannot be invalidated server-side before its
//! cookie expires (rotate the secret to invalidate everything at once).

use mlua::{Lua, ObjectLike as _, Table, Value};

use crate::http;

/// Ceiling on the serialized session, chosen so the signed, base64-encoded
/// cookie stays under the ~4 KiB browsers enforce per cookie.
const MAX_SESSION_JSON: usize = 2800;

/// Method names reserved on the session object; data under these names
/// would shadow the methods, so they are rejected rather than saved.
const RESERVED: &[&str] = &["save", "clear"];

/// The payload key carrying the session's expiry (unix seconds). Written
/// when `max_age` is set and enforced on load, so a captured cookie stops
/// working when the session it carries has aged out — `Max-Age` alone is
/// advice to the browser, and an attacker's client takes none.
const EXPIRES_KEY: &str = "_exp";

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Cookie attributes for a session cookie: HttpOnly always (a session is
/// server state, scripts in the page have no business reading it),
/// site-wide, SameSite=Lax; the caller's `cookie` options may extend but
/// not un-HttpOnly it.
fn cookie_opts(lua: &Lua, base: Option<&Table>, max_age: Option<i64>) -> mlua::Result<Table> {
    let opts = lua.create_table()?;
    opts.set("path", "/")?;
    opts.set("same_site", "Lax")?;
    // Shared with `nitr.csrf` so the two cannot drift: merge the caller's
    // table over these, then force `http_only`.
    let opts = http::merge_cookie_opts(opts, base)?;
    // After the merge deliberately: the deletion cookie's `max_age = 0` is
    // the mechanism that expires it, so a caller's `max_age` must not be
    // able to keep a cleared session alive.
    if let Some(max_age) = max_age {
        opts.set("max_age", max_age)?;
    }
    Ok(opts)
}

/// Copies the verified cookie payload (a JSON object) into `session`,
/// unless the payload carries an expiry that has passed — then the
/// session starts empty, exactly as if the cookie had not been sent.
fn load_into(lua: &Lua, session: &Table, payload: &str, now: i64) -> mlua::Result<()> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(payload)
    else {
        // A cookie that verifies but does not decode was produced by an
        // older secret sharing the name, or by tooling; start empty.
        return Ok(());
    };
    if let Some(exp) = map.get(EXPIRES_KEY) {
        // A malformed expiry is treated as expired: the only way the key
        // exists is that this code wrote it, so anything else is damage.
        if exp.as_i64().is_none_or(|exp| now >= exp) {
            return Ok(());
        }
    }
    for (key, value) in map {
        if key == EXPIRES_KEY {
            continue;
        }
        use mlua::LuaSerdeExt as _;
        session.set(key, lua.to_value(&value)?)?;
    }
    Ok(())
}

/// Serializes the session's own fields to JSON, rejecting values that
/// cannot live in a cookie and names that would shadow the methods. With
/// a `max_age`, the expiry rides inside the signed payload.
fn serialize(session: &Table, max_age: Option<i64>, now: i64) -> mlua::Result<String> {
    for reserved in RESERVED {
        if !session.raw_get::<Value>(*reserved)?.is_nil() {
            return Err(mlua::Error::RuntimeError(format!(
                "`{reserved}` is reserved on a session (it is a method name)"
            )));
        }
    }
    if !session.raw_get::<Value>(EXPIRES_KEY)?.is_nil() {
        return Err(mlua::Error::RuntimeError(format!(
            "`{EXPIRES_KEY}` is reserved on a session (it carries the expiry)"
        )));
    }
    let session = Value::Table(session.clone());
    crate::utils::check_json_bounds(&session)?;
    let mut json = serde_json::to_value(&session).map_err(|err| {
        mlua::Error::RuntimeError(format!(
            "session values must be JSON-serializable (strings, numbers, booleans, tables): {err}"
        ))
    })?;
    // An empty session stays empty (`{}` is what makes `save` delete the
    // cookie); the expiry only rides along with actual data.
    if let (Some(max_age), serde_json::Value::Object(map)) = (max_age, &mut json)
        && max_age > 0
        && !map.is_empty()
    {
        map.insert(
            EXPIRES_KEY.into(),
            serde_json::Value::from(now.saturating_add(max_age)),
        );
    }
    let json = json.to_string();
    if json.len() > MAX_SESSION_JSON {
        return Err(mlua::Error::RuntimeError(format!(
            "the session is {} bytes serialized; the whole session travels in a signed \
             cookie, which bounds it to {MAX_SESSION_JSON} bytes — store a key here and \
             the data in the database",
            json.len()
        )));
    }
    Ok(json)
}

/// Builds the `nitr.session` function.
pub(crate) fn create_session_fn(lua: &Lua) -> mlua::Result<mlua::Function> {
    lua.create_function(|lua, (req, opts): (Value, Table)| {
        let secret: String = opts.get::<Option<String>>("secret")?.ok_or_else(|| {
            mlua::Error::RuntimeError("nitr.session requires a `secret` option".into())
        })?;
        if secret.len() < 16 {
            return Err(mlua::Error::RuntimeError(
                "nitr.session `secret` must be at least 16 bytes".into(),
            ));
        }
        let name = opts
            .get::<Option<String>>("name")?
            .unwrap_or_else(|| "session".into());
        let max_age: Option<i64> = opts.get("max_age")?;
        let base_opts: Option<Table> = opts.get("cookie")?;

        let session = lua.create_table()?;
        if let Value::UserData(ud) = &req
            && let Ok(cookies) = ud.get::<mlua::AnyUserData>("cookies")
            && let Ok(cookies) = cookies.borrow::<http::RequestCookies>()
            && let Some(raw) = cookies.get(&name)
            && let Some(payload) = http::verify(&name, raw, &secret)
        {
            load_into(lua, &session, &payload, unix_now())?;
        }

        // Methods live on the metatable, so `pairs(session)` (and the
        // serializer) see only data.
        let methods = lua.create_table()?;
        {
            let (name, secret) = (name.clone(), secret.clone());
            let base_opts = base_opts.clone();
            methods.set(
                "save",
                lua.create_function(move |lua, (session, resp): (Table, Value)| {
                    let Value::Table(resp) = resp else {
                        return Err(mlua::Error::RuntimeError(format!(
                            "session:save(resp) takes the response table, got {}",
                            resp.type_name()
                        )));
                    };
                    let json = serialize(&session, max_age, unix_now())?;
                    let empty = json == "{}" || json == "[]";
                    let cookie = if empty {
                        // An empty session deletes its cookie.
                        http::build_cookie(
                            lua,
                            &name,
                            "",
                            Some(&cookie_opts(lua, base_opts.as_ref(), Some(0))?),
                        )?
                    } else {
                        http::build_cookie(
                            lua,
                            &name,
                            &http::sign(&name, &json, &secret),
                            Some(&cookie_opts(lua, base_opts.as_ref(), max_age)?),
                        )?
                    };
                    http::attach_cookie(&resp, cookie)
                })?,
            )?;
        }
        methods.set(
            "clear",
            lua.create_function(|_, session: Table| {
                let keys: Vec<Value> = session
                    .pairs::<Value, Value>()
                    .map(|pair| pair.map(|(k, _)| k))
                    .collect::<mlua::Result<_>>()?;
                for key in keys {
                    session.set(key, Value::Nil)?;
                }
                Ok(())
            })?,
        )?;

        let meta = lua.create_table()?;
        meta.set("__index", methods)?;
        session.set_metatable(Some(meta))?;
        Ok(session)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(lua: &Lua, opts: &str) -> Table {
        let session_fn = create_session_fn(lua).expect("fn");
        let opts: Table = lua.load(opts).eval().expect("opts");
        session_fn.call((Value::Nil, opts)).expect("session")
    }

    /// Session tables are script data serialized to JSON: the depth guard
    /// must fire before the byte cap can even be measured.
    #[test]
    fn save_rejects_a_session_nested_beyond_the_json_depth_bound() {
        let lua = Lua::new();
        let session = make_session(&lua, r#"{ secret = "0123456789abcdef" }"#);
        let mut cur = lua.create_table().expect("table");
        session.set("deep", cur.clone()).expect("set");
        for _ in 0..128 {
            let next = lua.create_table().expect("table");
            cur.set("x", next.clone()).expect("set");
            cur = next;
        }
        let save: mlua::Function = session.get("save").expect("method");
        let resp = lua.create_table().expect("resp");
        let err = save.call::<Value>((session, resp)).expect_err("too deep");
        assert!(
            err.to_string().contains("nested deeper than 128 levels"),
            "got: {err}"
        );
    }

    #[test]
    fn save_rejects_reserved_names_oversize_and_unserializable_values() {
        let lua = Lua::new();
        let session = make_session(&lua, r#"{ secret = "0123456789abcdef" }"#);
        let resp = lua.create_table().expect("resp");
        let save: mlua::Function = session.get("save").expect("method");

        // A data field named like a method would shadow it forever after.
        session.set("save2", "ok").expect("set");
        session.raw_set("clear", "shadowed").expect("set");
        let err = save
            .call::<()>((&session, &resp))
            .expect_err("reserved name");
        assert!(err.to_string().contains("reserved"), "got: {err}");
        session.raw_set("clear", Value::Nil).expect("unset");

        // Functions cannot travel in a cookie.
        let f = lua.create_function(|_, ()| Ok(())).expect("fn");
        session.set("cb", f).expect("set");
        let err = save.call::<()>((&session, &resp)).expect_err("function");
        assert!(err.to_string().contains("JSON-serializable"), "got: {err}");
        session.set("cb", Value::Nil).expect("unset");

        // The size ceiling reports itself instead of emitting a cookie
        // browsers will silently drop.
        session
            .set("blob", "x".repeat(MAX_SESSION_JSON))
            .expect("set");
        let err = save.call::<()>((&session, &resp)).expect_err("oversize");
        assert!(err.to_string().contains("bytes"), "got: {err}");

        // And save demands the response table, not whatever was handy.
        let err = save
            .call::<()>((&session, "not a response"))
            .expect_err("bad resp");
        assert!(err.to_string().contains("response table"), "got: {err}");
    }

    #[test]
    fn sessions_stay_http_only_and_empty_sessions_expire_the_cookie() {
        let lua = Lua::new();
        // A caller trying to un-HttpOnly the cookie loses that argument.
        let session = make_session(
            &lua,
            r#"{ secret = "0123456789abcdef", cookie = { http_only = false, secure = true } }"#,
        );
        session.set("user", "ada").expect("set");
        let resp = lua.create_table().expect("resp");
        let save: mlua::Function = session.get("save").expect("method");
        save.call::<()>((&session, &resp)).expect("save");
        let cookies: mlua::AnyUserData = resp.get("cookies").expect("builder");
        let values = cookies.borrow::<http::ResponseCookies>().expect("borrow");
        let cookie = &values.values()[0];
        assert!(cookie.contains("HttpOnly"), "got: {cookie}");
        assert!(cookie.contains("Secure"), "got: {cookie}");

        // clear() then save() writes the deletion cookie.
        let clear: mlua::Function = session.get("clear").expect("method");
        clear.call::<()>(&session).expect("clear");
        let resp = lua.create_table().expect("resp");
        save.call::<()>((&session, &resp)).expect("save");
        let cookies: mlua::AnyUserData = resp.get("cookies").expect("builder");
        let values = cookies.borrow::<http::ResponseCookies>().expect("borrow");
        let cookie = &values.values()[0];
        assert!(cookie.contains("Max-Age=0"), "got: {cookie}");
    }

    #[test]
    fn a_short_secret_is_refused() {
        let lua = Lua::new();
        let session_fn = create_session_fn(&lua).expect("fn");
        for opts in ["{}", r#"{ secret = "short" }"#] {
            let opts: Table = lua.load(opts).eval().expect("opts");
            let err = session_fn
                .call::<Table>((Value::Nil, opts))
                .expect_err("weak secret");
            assert!(err.to_string().contains("secret"), "got: {err}");
        }
    }

    #[test]
    fn corrupt_payloads_start_an_empty_session_instead_of_failing() {
        let lua = Lua::new();
        let session = lua.create_table().expect("table");
        // Verified-but-not-JSON (old secret sharing the name, tooling).
        load_into(&lua, &session, "not json at all", 0).expect("load");
        load_into(&lua, &session, "[1,2,3]", 0).expect("load");
        assert_eq!(session.len().expect("len"), 0);
    }

    /// `max_age` is enforced by the server, not only advised to the
    /// browser: the expiry travels inside the signed payload and a
    /// replayed cookie past it loads an empty session.
    #[test]
    fn sessions_expire_server_side_when_max_age_is_set() {
        let lua = Lua::new();
        let session = lua.create_table().expect("table");
        session.set("user", "ada").expect("set");
        let json = serialize(&session, Some(3600), 1_000_000).expect("serialize");
        assert!(json.contains("\"_exp\":1003600"), "got: {json}");

        // Before the expiry: loads, and the marker itself stays hidden.
        let fresh = lua.create_table().expect("table");
        load_into(&lua, &fresh, &json, 1_003_599).expect("load");
        assert_eq!(fresh.get::<String>("user").expect("user"), "ada");
        assert!(fresh.get::<Value>("_exp").expect("get").is_nil());

        // At and after the expiry: empty, as if no cookie had been sent.
        let stale = lua.create_table().expect("table");
        load_into(&lua, &stale, &json, 1_003_600).expect("load");
        assert_eq!(stale.len().expect("len"), 0);

        // Without `max_age` nothing is written and nothing expires.
        let forever = serialize(&session, None, 1_000_000).expect("serialize");
        assert!(!forever.contains("_exp"), "got: {forever}");

        // A cleared session with `max_age` is still `{}`, so `save`
        // deletes the cookie instead of issuing one that holds an expiry.
        let empty = lua.create_table().expect("table");
        assert_eq!(serialize(&empty, Some(3600), 0).expect("serialize"), "{}");

        // A script cannot set the marker itself.
        session.set("_exp", 1).expect("set");
        let err = serialize(&session, None, 0).expect_err("reserved");
        assert!(err.to_string().contains("reserved"), "got: {err}");
    }
}
