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

/// Cookie attributes for a session cookie: HttpOnly always (a session is
/// server state, scripts in the page have no business reading it),
/// site-wide, SameSite=Lax; the caller's `cookie` options may extend but
/// not un-HttpOnly it.
fn cookie_opts(lua: &Lua, base: Option<&Table>, max_age: Option<i64>) -> mlua::Result<Table> {
    let opts = lua.create_table()?;
    opts.set("path", "/")?;
    opts.set("same_site", "Lax")?;
    if let Some(base) = base {
        for pair in base.pairs::<Value, Value>() {
            let (k, v) = pair?;
            opts.set(k, v)?;
        }
    }
    opts.set("http_only", true)?;
    if let Some(max_age) = max_age {
        opts.set("max_age", max_age)?;
    }
    Ok(opts)
}

/// Copies the verified cookie payload (a JSON object) into `session`.
fn load_into(lua: &Lua, session: &Table, payload: &str) -> mlua::Result<()> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(payload)
    else {
        // A cookie that verifies but does not decode was produced by an
        // older secret sharing the name, or by tooling; start empty.
        return Ok(());
    };
    for (key, value) in map {
        use mlua::LuaSerdeExt as _;
        session.set(key, lua.to_value(&value)?)?;
    }
    Ok(())
}

/// Serializes the session's own fields to JSON, rejecting values that
/// cannot live in a cookie and names that would shadow the methods.
fn serialize(session: &Table) -> mlua::Result<String> {
    for reserved in RESERVED {
        if !session.raw_get::<Value>(*reserved)?.is_nil() {
            return Err(mlua::Error::RuntimeError(format!(
                "`{reserved}` is reserved on a session (it is a method name)"
            )));
        }
    }
    let session = Value::Table(session.clone());
    crate::utils::check_json_depth(&session)?;
    let json = serde_json::to_string(&session).map_err(|err| {
        mlua::Error::RuntimeError(format!(
            "session values must be JSON-serializable (strings, numbers, booleans, tables): {err}"
        ))
    })?;
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
            load_into(lua, &session, &payload)?;
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
                    let json = serialize(&session)?;
                    let empty = json == "{}" || json == "[]";
                    let cookie = if empty {
                        // An empty session deletes its cookie.
                        http::build_cookie(
                            &name,
                            "",
                            Some(&cookie_opts(lua, base_opts.as_ref(), Some(0))?),
                        )?
                    } else {
                        http::build_cookie(
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
        load_into(&lua, &session, "not json at all").expect("load");
        load_into(&lua, &session, "[1,2,3]").expect("load");
        assert_eq!(session.len().expect("len"), 0);
    }
}
