// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `nitr.app()` Lua application object: routes and middleware are
//! collected while the handler script runs, then compiled once per state
//! into a Rust-side router ([`matchit`]) plus composed handler chains.
//!
//! Route matching always happens in Rust; Lua is never invoked for a
//! request that doesn't match a registered route.
//!
//! One file per concern: this one holds the Lua object and the per-state
//! registry; [`options`] reads a route's trailing options table;
//! [`compile`] turns the collected definition into the router; [`meta`]
//! collects what the OpenAPI document is built from.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hyper::Method;
use matchit::Router;
use mlua::{AnyUserData, Function, Lua, UserData, UserDataMethods, Value, Variadic};

use nitr_core::{Error, Result};

use crate::openapi::AppMeta;
use crate::validation::{InputEnv, InputSchemas};

mod compile;
mod meta;
mod options;

use compile::compile;
use options::{caller_site, route_options};

/// Named registry slot holding each state's compiled [`AppState`].
const APP_STATE_KEY: &str = "nitr::app_state";

/// Named registry slot holding the budgeted validation function.
const VALIDATE_FN_KEY: &str = "nitr::validate_fn";

/// Route-registration methods exposed on the app object, each name paired
/// with its `Method` so the mapping is total by construction — no lookup
/// that could miss, nothing to declare unreachable.
const METHOD_NAMES: &[(&str, Method)] = &[
    ("get", Method::GET),
    ("post", Method::POST),
    ("put", Method::PUT),
    ("delete", Method::DELETE),
    ("patch", Method::PATCH),
    ("head", Method::HEAD),
    ("options", Method::OPTIONS),
];

/// Locks the app definition; the mutex exists only to satisfy `Sync` (a
/// Lua state is single-threaded), so contention/poisoning cannot occur in
/// practice.
fn lock(def: &Mutex<AppDef>) -> mlua::Result<std::sync::MutexGuard<'_, AppDef>> {
    def.lock()
        .map_err(|_| mlua::Error::RuntimeError("the app definition lock is poisoned".into()))
}

/// Where a script registered something (`source`, `line`).
pub(crate) type Site = Option<(String, u32)>;

/// A route as registered by the script: zero or more middleware followed by
/// the handler function (always the last element of `fns`).
struct RouteDef {
    method: Method,
    path: String,
    fns: Vec<Function>,
    /// A per-route error handler (`{ on_error = fn }` options), overriding
    /// the app-wide `app:on_error`.
    error_fn: Option<Function>,
    /// A per-route validation-failure handler (`{ on_invalid = fn }`),
    /// overriding the app-wide `app:on_invalid`.
    invalid_fn: Option<Function>,
    /// The `{ input = {...} }` declaration, compiled in [`compile`] where
    /// the deployment's upload settings are known.
    input: Option<mlua::Table>,
    /// The `{ doc = {...} }` table, parsed in [`compile`] once `app:doc`
    /// is known (its security scheme names are checked against it).
    doc: Option<mlua::Table>,
    /// Where the script registered this route, captured at registration
    /// so a duplicate can name both sites.
    site: Site,
}

/// What the script builds up through `app:get(...)`, `app:use(...)`, etc.
#[derive(Default)]
struct AppDef {
    middleware: Vec<Function>,
    routes: Vec<RouteDef>,
    error_fn: Option<Function>,
    invalid_fn: Option<Function>,
    statics: Vec<crate::static_files::StaticMount>,
    /// The `app:doc({...})` table and where it was called.
    api_doc: Option<(mlua::Table, Site)>,
}

/// The `nitr.app()` userdata handed to the handler script.
pub(crate) struct LuaApp(Mutex<AppDef>);

impl UserData for LuaApp {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        for (name, method) in METHOD_NAMES {
            let method = method.clone();
            methods.add_method(
                *name,
                // `middleware..., handler` optionally followed by an options
                // table: `app:get(path, handler, { on_error = fn })`.
                move |lua, this, (path, mut args): (String, Variadic<Value>)| {
                    let options = match args.last() {
                        Some(Value::Table(opts)) => {
                            let parsed = route_options(name, &path, opts)?;
                            args.pop();
                            parsed
                        }
                        _ => options::RouteOptions::default(),
                    };
                    let fns: Vec<Function> = args
                        .into_iter()
                        .map(|value| match value {
                            Value::Function(f) => Ok(f),
                            other => Err(mlua::Error::RuntimeError(format!(
                                "app:{name}(\"{path}\", ...) takes handler functions \
                                 and an optional trailing options table, got {}",
                                other.type_name()
                            ))),
                        })
                        .collect::<mlua::Result<_>>()?;
                    if fns.is_empty() {
                        return Err(mlua::Error::RuntimeError(format!(
                            "app:{name}(\"{path}\", ...) requires a handler function"
                        )));
                    }
                    if !path.starts_with('/') {
                        return Err(mlua::Error::RuntimeError(format!(
                            "route path `{path}` must start with `/`"
                        )));
                    }
                    let site = caller_site(lua);
                    lock(&this.0)?.routes.push(RouteDef {
                        method: method.clone(),
                        path,
                        fns,
                        error_fn: options.error_fn,
                        invalid_fn: options.invalid_fn,
                        input: options.input,
                        doc: options.doc,
                        site,
                    });
                    Ok(())
                },
            );
        }

        // app:on_invalid(fn): the app-wide answer to a request that failed
        // its route's `input` declaration, `function(err, req)` returning a
        // response. Without one the server answers a JSON 422.
        methods.add_method("on_invalid", |_, this, f: Function| {
            lock(&this.0)?.invalid_fn = Some(f);
            Ok(())
        });

        // app:doc(table): document-level information for the OpenAPI
        // document. Once per app: a second call names both sites.
        methods.add_method("doc", |lua, this, table: mlua::Table| {
            let site = caller_site(lua);
            let mut def = lock(&this.0)?;
            if let Some((_, first)) = &def.api_doc {
                return Err(mlua::Error::RuntimeError(format!(
                    "app:doc() called twice\n  --> {}   (first call)\n  --> {}   (called again here)",
                    options::site_label(first),
                    options::site_label(&site)
                )));
            }
            def.api_doc = Some((table, site));
            Ok(())
        });

        methods.add_method("use", |_, this, mw: Function| {
            let mut def = lock(&this.0)?;
            // Chains are composed once at load time; allowing `use` after a
            // route would silently skip that route, so make it an error.
            if !def.routes.is_empty() {
                return Err(mlua::Error::RuntimeError(
                    "app:use() must be called before registering routes".into(),
                ));
            }
            def.middleware.push(mw);
            Ok(())
        });

        methods.add_method("on_error", |_, this, f: Function| {
            lock(&this.0)?.error_fn = Some(f);
            Ok(())
        });

        // app:static(mount, dir, opts?): served entirely in Rust; opts is
        // an optional table { spa = bool, cache_control = "...",
        // dotfiles = bool }.
        methods.add_method(
            "static",
            |_, this, (mount, dir, opts): (String, String, Option<mlua::Table>)| {
                let (spa, cache_control, dotfiles) = match opts {
                    Some(opts) => (
                        opts.get::<Option<bool>>("spa")?.unwrap_or(false),
                        opts.get::<Option<String>>("cache_control")?,
                        opts.get::<Option<bool>>("dotfiles")?.unwrap_or(false),
                    ),
                    None => (false, None, false),
                };
                lock(&this.0)?.statics.push(
                    crate::static_files::StaticMount::new(mount, dir, spa, cache_control)
                        .dotfiles(dotfiles),
                );
                Ok(())
            },
        );
    }
}

/// The compiled dispatch target of a Lua state: the `nitr.app()` returned
/// by the handler script — requests are routed in Rust and only matching
/// ones reach the composed Lua chains.
pub(crate) struct Dispatch(pub(crate) Box<CompiledApp>);

/// A composed route: the middleware/handler chain plus its resolved error
/// handler (route-level `on_error` first, the app-wide one as fallback) —
/// resolved once at compile time so dispatch pays nothing.
pub(crate) struct Chain {
    pub(crate) fns: Function,
    /// The route's own handler, without its middleware: what
    /// `t.app():handler(...)` returns to a unit test.
    pub(crate) handler: Function,
    /// The route as registered (method, path pattern, file:line), for
    /// `t.app():routes()` and for finding a handler by its pattern.
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) site: Site,
    pub(crate) error_fn: Option<Function>,
    /// The route's compiled `input` declaration, plus the userdata the
    /// budgeted validation function receives it through.
    pub(crate) input: Option<(Arc<InputSchemas>, AnyUserData)>,
    /// The resolved `on_invalid` (route-level first, app-wide fallback).
    pub(crate) invalid_fn: Option<Function>,
}

/// The Rust-side router plus the per-route composed Lua chains.
pub(crate) struct CompiledApp {
    pub(crate) router: Router<HashMap<Method, usize>>,
    pub(crate) chains: Vec<Chain>,
}

/// Where the router sends a method and a path.
pub(crate) enum Lookup {
    /// A route: its index into [`CompiledApp::chains`] and the captured
    /// path parameters.
    Route {
        index: usize,
        params: Vec<(String, String)>,
    },
    /// An `OPTIONS` on a known path without an `options` route.
    Options(Vec<Method>),
    /// A known path, but no route for this method.
    MethodNotAllowed(Vec<Method>),
    /// No route pattern matches the path.
    NotFound,
}

impl CompiledApp {
    /// The one router lookup, shared by the server and `nitr test`'s
    /// `app:dispatch`: `HEAD` falls back to the `GET` route (it is `GET`
    /// without the body), while an explicit `head` route still wins.
    pub(crate) fn lookup(&self, method: &Method, path: &str) -> Lookup {
        let Ok(matched) = self.router.at(path) else {
            return Lookup::NotFound;
        };
        let route = matched.value.get(method).or_else(|| {
            (*method == Method::HEAD)
                .then(|| matched.value.get(&Method::GET))
                .flatten()
        });
        match route {
            Some(&index) => Lookup::Route {
                index,
                params: matched
                    .params
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            },
            None if *method == Method::OPTIONS => {
                Lookup::Options(matched.value.keys().cloned().collect())
            }
            None => Lookup::MethodNotAllowed(matched.value.keys().cloned().collect()),
        }
    }
}

/// The handler script path of the compiled app in this state, for
/// diagnostics that need to read the source back (Lua truncates long chunk
/// names, so the error's own `source` may not be openable).
pub(crate) fn script_path(lua: &Lua) -> Option<PathBuf> {
    state(lua)
        .ok()
        .and_then(|ud| ud.borrow::<AppState>().ok().map(|s| s.script.clone()))
}

/// Per-state dispatch state, stored in the Lua registry so it lives and
/// dies with its state without changing the runtime pool's shape.
pub(crate) struct AppState {
    pub(crate) dispatch: Dispatch,
    /// Static mounts: the script's `app:static(...)` calls first, then the
    /// server-level `[static]` configuration.
    pub(crate) statics: Arc<Vec<crate::static_files::StaticMount>>,
    /// What the OpenAPI document is built from. Collected in every build
    /// (a `doc` typo fails the same way everywhere); read only by the
    /// generator.
    #[cfg_attr(not(feature = "openapi"), allow(dead_code))]
    pub(crate) meta: Arc<AppMeta>,
    script: PathBuf,
}

impl UserData for AppState {}

/// Mounts `nitr.app()` on the shared `nitr` namespace table (`nitr.cfg` is
/// filled in by the server once the configuration snapshot is known), and
/// registers the validation function routes with `input` run through.
pub(crate) fn register_nitr_app(lua: &Lua) -> Result<()> {
    let nitr = nitr_core::nitr_table(lua)?;
    nitr.set(
        "app",
        lua.create_function(|_, ()| Ok(LuaApp(Mutex::new(AppDef::default()))))?,
    )?;
    // A Rust async function called through the runtime's budgeted
    // `call_function`, so a custom check spends the request's allowance.
    let validate = lua.create_async_function(crate::validation::run::validate)?;
    lua.set_named_registry_value(VALIDATE_FN_KEY, validate)?;
    Ok(())
}

/// The budgeted validation function registered by [`register_nitr_app`].
pub(crate) fn validate_fn(lua: &Lua) -> Result<Function> {
    lua.named_registry_value::<Function>(VALIDATE_FN_KEY)
        .map_err(|_| Error::Script("the validation function is not registered".into()))
}

/// Evaluates the handler script and stores its compiled [`AppState`] in the
/// Lua registry. Called at startup for every pooled state and again on
/// dev-mode reloads. Returns whether any route declares file uploads.
pub(crate) fn load(
    lua: &Lua,
    script: &Path,
    base_statics: &[crate::static_files::StaticMount],
    input_env: &InputEnv,
) -> Result<bool> {
    let value = nitr_core::eval_script(lua, script)?;
    let compiled = compile(lua, value, script, input_env)?;
    let has_files = compiled
        .dispatch
        .0
        .chains
        .iter()
        .any(|c| c.input.as_ref().is_some_and(|(i, _)| i.has_file_rules()));
    // The application has compiled: app-wide validation messages are
    // fixed from here, so no request can change another's wording.
    nitr_std::validation::freeze_messages(lua);
    let mut statics = compiled.statics;
    statics.extend_from_slice(base_statics);
    // Longest mount prefix first, once: the static path used to collect
    // and sort the candidates on every request. Stable, so mounts of equal
    // length keep their registration order, script mounts before `[static]`.
    statics.sort_by_key(|m| std::cmp::Reverse(m.mount.len()));
    let state = lua.create_userdata(AppState {
        dispatch: compiled.dispatch,
        statics: Arc::new(statics),
        meta: Arc::new(compiled.meta),
        script: script.to_path_buf(),
    })?;
    lua.set_named_registry_value(APP_STATE_KEY, state)?;
    Ok(has_files)
}

/// The state's [`AppState`] userdata, set by [`load()`].
pub(crate) fn state(lua: &Lua) -> Result<AnyUserData> {
    lua.named_registry_value::<AnyUserData>(APP_STATE_KEY)
        .map_err(|_| Error::Script("no HTTP handler has been loaded".into()))
}
