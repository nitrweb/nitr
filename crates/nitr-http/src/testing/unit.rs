// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Unit-testing a handler without a server: a real request userdata built
//! from a table ([`fake_request`], `t.fake_request`), and the application
//! compiled into the test state ([`load_app`], `t.app()`).
//!
//! Both are unit-test tools and say so: a fake request passes no
//! protection layer, no body guard and no route validation (`valid` is
//! whatever the test says), and `app:dispatch` runs the composed
//! middleware chain only — `on_error`, `on_invalid` and `input` are what
//! `t.request` exercises.

use http_body_util::{BodyExt as _, Full};
use hyper::Method;
use hyper::body::Bytes;
use mlua::{AnyUserData, Function, Lua, Table, UserData, UserDataMethods, Value};

use super::TestRequest;
use crate::app::{self, AppState, Lookup};
use crate::request::LuaRequest;

/// Builds a request userdata for a unit test (`t.fake_request(spec)`):
/// the same type a handler receives, so `req.*`, `req:json()`,
/// `nitr.session(req, ...)`, `nitr.csrf.token(req)` and `nitr.auth.*`
/// behave as in production.
///
/// `spec` takes `method` (default `GET`), `path` (default `/`), `params`
/// (what the router would have captured), `valid` (what route validation
/// would have produced), plus every [`TestRequest`] option — `query`,
/// `headers`, `cookies`, `auth`, one body, `remote_addr`.
///
/// # Errors
///
/// A malformed spec: two bodies, a bad method, path, header or address.
pub fn fake_request(lua: &Lua, spec: Option<Table>) -> mlua::Result<AnyUserData> {
    let (method, path) = match &spec {
        Some(spec) => (
            spec.get::<Option<String>>("method")?
                .unwrap_or_else(|| "GET".into()),
            spec.get::<Option<String>>("path")?
                .unwrap_or_else(|| "/".into()),
        ),
        None => ("GET".into(), "/".into()),
    };
    let parsed = TestRequest::from_lua(&method, &path, spec.as_ref())?;
    let method: Method = parsed
        .method
        .to_uppercase()
        .parse()
        .map_err(|_| mlua::Error::RuntimeError(format!("invalid method `{method}`")))?;
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(parsed.path.as_str());
    for (name, value) in &parsed.headers {
        builder = builder.header(name, value);
    }
    let req = builder
        .body(
            Full::new(parsed.body.unwrap_or_else(Bytes::new))
                .map_err(|never| match never {})
                .boxed(),
        )
        .map_err(|err| mlua::Error::RuntimeError(format!("invalid fake request: {err}")))?;
    let peer = parsed
        .remote_addr
        .unwrap_or_else(|| super::DEFAULT_PEER.into());
    let id = uuid::Uuid::now_v7().to_string();
    let mut req = LuaRequest::synthetic(req, peer, id.into());
    if let Some(spec) = &spec {
        if let Some(params) = spec.get::<Option<Table>>("params")? {
            let mut pairs = Vec::new();
            for pair in params.pairs::<String, String>() {
                pairs.push(pair?);
            }
            pairs.sort();
            req.params = pairs;
        }
        req.valid = spec.get::<Option<Table>>("valid")?;
    }
    lua.create_userdata(req)
}

/// Compiles the application into this state and returns the object
/// `t.app()` hands a test.
///
/// The same evaluation and compile the pool performs, into this state's
/// registry only: nothing the server serves changes. The handler script's
/// top-level code and every `app:use` factory run once more here.
///
/// # Errors
///
/// Anything that fails the application's own load.
pub fn load_app(lua: &Lua, cfg: &crate::Config) -> nitr_core::Result<AnyUserData> {
    app::register_nitr_app(lua)?;
    app::load(
        lua,
        &cfg.handler_script,
        &[],
        &crate::server::input_env(cfg),
    )?;
    Ok(lua.create_userdata(TestApp)?)
}

/// `t.app()`: reads the compiled application from the state's registry.
struct TestApp;

/// The compiled application in this state (`load_app` put it there).
fn compiled_state(lua: &Lua) -> mlua::Result<AnyUserData> {
    app::state(lua).map_err(|err| mlua::Error::RuntimeError(err.to_string()))
}

fn method_of(name: &str) -> mlua::Result<Method> {
    name.to_uppercase()
        .parse()
        .map_err(|_| mlua::Error::RuntimeError(format!("invalid method `{name}`")))
}

/// A response table like the ones the server's own answers carry.
fn plain(lua: &Lua, status: u16, allow: Option<&[Method]>, body: &str) -> mlua::Result<Table> {
    let resp = lua.create_table()?;
    resp.set("status", status)?;
    let headers = lua.create_table()?;
    if let Some(allow) = allow {
        let mut names: Vec<&str> = allow.iter().map(Method::as_str).collect();
        names.sort_unstable();
        headers.set("allow", names.join(", "))?;
    }
    resp.set("headers", headers)?;
    resp.set("body", body)?;
    Ok(resp)
}

impl UserData for TestApp {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // app:handler(method, path) — the route's own function, without
        // its middleware. `path` is the pattern as registered
        // ("/notes/:id"), or a concrete path the router matches.
        methods.add_method("handler", |lua, _, (method, path): (String, String)| {
            let wanted = method_of(&method)?;
            let state = compiled_state(lua)?;
            let state = state.borrow::<AppState>()?;
            let compiled = &state.dispatch.0;
            if let Some(chain) = compiled
                .chains
                .iter()
                .find(|c| c.method == wanted && c.path == path)
            {
                return Ok(chain.handler.clone());
            }
            if let Lookup::Route { index, .. } = compiled.lookup(&wanted, &path) {
                return Ok(compiled.chains[index].handler.clone());
            }
            let known = compiled
                .chains
                .iter()
                .map(|c| format!("{} {}", c.method, c.path))
                .collect::<Vec<_>>()
                .join(", ");
            Err(mlua::Error::RuntimeError(format!(
                "app:handler: no route {wanted} {path} (routes: {known})"
            )))
        });

        // app:dispatch(method, path, req) — the router lookup the server
        // uses (params filled into `req`) and the composed middleware
        // chain; the router's own 404/405/OPTIONS answers otherwise.
        methods.add_async_method(
            "dispatch",
            |lua, _, (method, path, req): (String, String, AnyUserData)| async move {
                let wanted = method_of(&method)?;
                let chain: Function = {
                    let state = compiled_state(&lua)?;
                    let state = state.borrow::<AppState>()?;
                    let compiled = &state.dispatch.0;
                    match compiled.lookup(&wanted, &path) {
                        Lookup::Route { index, params } => {
                            req.borrow_mut::<LuaRequest>()
                                .map_err(|_| {
                                    mlua::Error::RuntimeError(
                                        "app:dispatch takes a request (t.fake_request(...))".into(),
                                    )
                                })?
                                .params = params;
                            compiled.chains[index].fns.clone()
                        }
                        Lookup::NotFound => {
                            return Ok(Value::Table(plain(&lua, 404, None, "Not Found")?));
                        }
                        Lookup::MethodNotAllowed(allowed) => {
                            return Ok(Value::Table(plain(
                                &lua,
                                405,
                                Some(&allowed),
                                "Method Not Allowed",
                            )?));
                        }
                        Lookup::Options(allowed) => {
                            return Ok(Value::Table(plain(&lua, 204, Some(&allowed), "")?));
                        }
                    }
                };
                chain.call_async::<Value>(req).await
            },
        );

        // app:routes() — { { method, path, file, line }, ... } in
        // registration order.
        methods.add_method("routes", |lua, _, ()| {
            let state = compiled_state(lua)?;
            let state = state.borrow::<AppState>()?;
            let list = lua.create_table()?;
            for chain in &state.dispatch.0.chains {
                let route = lua.create_table()?;
                route.set("method", chain.method.as_str())?;
                route.set("path", chain.path.as_str())?;
                if let Some((file, line)) = &chain.site {
                    route.set("file", file.as_str())?;
                    route.set("line", *line)?;
                }
                list.push(route)?;
            }
            Ok(list)
        });
    }
}
