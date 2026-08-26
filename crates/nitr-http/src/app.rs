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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hyper::Method;
use matchit::Router;
use mlua::{AnyUserData, Function, Lua, UserData, UserDataMethods, Value, Variadic};
use std::sync::Arc;

use nitr_core::{Error, Result, Runtime};

/// Named registry slot holding each state's compiled [`AppState`].
const APP_STATE_KEY: &str = "nitr::app_state";

/// Route-registration method names exposed on the app object.
const METHOD_NAMES: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options"];

/// Locks the app definition; the mutex exists only to satisfy `Sync` (a
/// Lua state is single-threaded), so contention/poisoning cannot occur in
/// practice.
fn lock(def: &Mutex<AppDef>) -> mlua::Result<std::sync::MutexGuard<'_, AppDef>> {
    def.lock()
        .map_err(|_| mlua::Error::RuntimeError("the app definition lock is poisoned".into()))
}

fn method_of(name: &str) -> Method {
    match name {
        "get" => Method::GET,
        "post" => Method::POST,
        "put" => Method::PUT,
        "delete" => Method::DELETE,
        "patch" => Method::PATCH,
        "head" => Method::HEAD,
        "options" => Method::OPTIONS,
        other => unreachable!("unknown route method name `{other}`"),
    }
}

/// A route as registered by the script: zero or more middleware followed by
/// the handler function (always the last element of `fns`).
struct RouteDef {
    method: Method,
    path: String,
    fns: Vec<Function>,
    /// A per-route error handler (`{ on_error = fn }` options), overriding
    /// the app-wide `app:on_error`.
    error_fn: Option<Function>,
    /// Where the script registered this route (`source`, `line`), captured
    /// at registration so a duplicate can name both sites.
    site: Option<(String, u32)>,
}

/// The script frame that called into a registration method, for load-time
/// diagnostics. Costs one stack inspection at registration — never on the
/// request path.
fn caller_site(lua: &Lua) -> Option<(String, u32)> {
    lua.inspect_stack(1, |dbg| {
        let source = dbg.source().short_src?;
        Some((source.into_owned(), dbg.current_line()? as u32))
    })?
}

/// Renders a registration site for an error message.
fn site_label(site: &Option<(String, u32)>) -> String {
    match site {
        Some((source, line)) => format!("{source}:{line}"),
        None => "unknown location".into(),
    }
}

/// What the script builds up through `app:get(...)`, `app:use(...)`, etc.
#[derive(Default)]
struct AppDef {
    middleware: Vec<Function>,
    routes: Vec<RouteDef>,
    error_fn: Option<Function>,
    statics: Vec<crate::static_files::StaticMount>,
}

/// The `nitr.app()` userdata handed to the handler script.
pub(crate) struct LuaApp(Mutex<AppDef>);

impl UserData for LuaApp {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        for name in METHOD_NAMES {
            let method = method_of(name);
            methods.add_method(
                *name,
                // `middleware..., handler` optionally followed by an options
                // table: `app:get(path, handler, { on_error = fn })`.
                move |lua, this, (path, mut args): (String, Variadic<Value>)| {
                    let error_fn = match args.last() {
                        Some(Value::Table(opts)) => {
                            let error_fn = opts.get::<Option<Function>>("on_error")?;
                            args.pop();
                            error_fn
                        }
                        _ => None,
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
                        error_fn,
                        site,
                    });
                    Ok(())
                },
            );
        }

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
        // an optional table { spa = bool, cache_control = "..." }.
        methods.add_method(
            "static",
            |_, this, (mount, dir, opts): (String, String, Option<mlua::Table>)| {
                let (spa, cache_control) = match opts {
                    Some(opts) => (
                        opts.get::<Option<bool>>("spa")?.unwrap_or(false),
                        opts.get::<Option<String>>("cache_control")?,
                    ),
                    None => (false, None),
                };
                lock(&this.0)?
                    .statics
                    .push(crate::static_files::StaticMount::new(
                        mount,
                        dir,
                        spa,
                        cache_control,
                    ));
                Ok(())
            },
        );
    }
}

/// The compiled dispatch target of a Lua state: the `nitr.app()` returned
/// by the handler script — requests are routed in Rust and only matching
/// ones reach the composed Lua chains.
pub(crate) struct Dispatch(pub(crate) Box<CompiledApp>);

/// The Rust-side router plus the per-route composed Lua chains.
/// A composed route: the middleware/handler chain plus its resolved error
/// handler (route-level `on_error` first, the app-wide one as fallback) —
/// resolved once at compile time so dispatch pays nothing.
pub(crate) struct Chain {
    pub(crate) fns: Function,
    pub(crate) error_fn: Option<Function>,
}

pub(crate) struct CompiledApp {
    pub(crate) router: Router<HashMap<Method, usize>>,
    pub(crate) chains: Vec<Chain>,
}

/// Per-state dispatch state, stored in the Lua registry so it lives and
/// dies with its state without changing the runtime pool's shape.
/// The handler script path of the compiled app in this state, for
/// diagnostics that need to read the source back (Lua truncates long chunk
/// names, so the error's own `source` may not be openable).
pub(crate) fn script_path(lua: &Lua) -> Option<std::path::PathBuf> {
    state(lua)
        .ok()
        .and_then(|ud| ud.borrow::<AppState>().ok().map(|s| s.script.clone()))
}

pub(crate) struct AppState {
    pub(crate) dispatch: Dispatch,
    /// Static mounts: the script's `app:static(...)` calls first, then the
    /// server-level `[static]` configuration.
    pub(crate) statics: Arc<Vec<crate::static_files::StaticMount>>,
    script: PathBuf,
}

impl UserData for AppState {}

/// Mounts `nitr.app()` on the shared `nitr` namespace table (`nitr.cfg` is
/// filled in by the server once the configuration snapshot is known).
pub(crate) fn register_nitr_app(lua: &Lua) -> Result<()> {
    let nitr = nitr_core::nitr_table(lua)?;
    nitr.set(
        "app",
        lua.create_function(|_, ()| Ok(LuaApp(Mutex::new(AppDef::default()))))?,
    )?;
    Ok(())
}

/// Evaluates the handler script and stores its compiled [`AppState`] in the
/// Lua registry. Called at startup for every pooled state and again on
/// dev-mode reloads.
pub(crate) fn load(
    rt: &Runtime,
    script: &Path,
    base_statics: &[crate::static_files::StaticMount],
) -> Result<()> {
    let value = rt.eval_script(script)?;
    let (dispatch, mut statics) = compile(value, script)?;
    statics.extend_from_slice(base_statics);
    let state = rt.lua().create_userdata(AppState {
        dispatch,
        statics: Arc::new(statics),
        script: script.to_path_buf(),
    })?;
    rt.lua().set_named_registry_value(APP_STATE_KEY, state)?;
    Ok(())
}

/// The state's [`AppState`] userdata, set by [`load()`].
pub(crate) fn state(lua: &Lua) -> Result<AnyUserData> {
    lua.named_registry_value::<AnyUserData>(APP_STATE_KEY)
        .map_err(|_| Error::Script("no HTTP handler has been loaded".into()))
}

/// Compiles the script's return value into a [`Dispatch`]: middleware
/// factories are invoked once here (never per request), and the route set
/// is validated so conflicts fail at startup instead of at request time.
type Compiled = (Dispatch, Vec<crate::static_files::StaticMount>);

fn compile(value: Value, script: &Path) -> Result<Compiled> {
    let app_ud = match value {
        Value::UserData(ud) if ud.is::<LuaApp>() => ud,
        // Plain-function handlers (the pre-`nitr.app()` style) are gone:
        // one standard way to build an application, checked at load time.
        other => {
            return Err(Error::Script(format!(
                "the handler script {} must return a nitr.app(), got {}",
                script.display(),
                other.type_name()
            )));
        }
    };
    let app = app_ud.borrow::<LuaApp>()?;
    let def = lock(&app.0)?;
    if def.routes.is_empty() && def.statics.is_empty() {
        return Err(Error::Script(format!(
            "the app returned by {} defines no routes or static mounts",
            script.display()
        )));
    }

    let mut chains = Vec::with_capacity(def.routes.len());
    // matchit rejects a second insert of the same pattern, so methods for
    // one pattern are grouped before inserting.
    let mut patterns: Vec<(String, HashMap<Method, usize>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for route in &def.routes {
        let idx = chains.len();
        chains.push(Chain {
            fns: compose(&def.middleware, route)?,
            error_fn: route.error_fn.clone().or_else(|| def.error_fn.clone()),
        });
        let pattern = to_matchit(&route.path)?;
        let slot = match index.get(&pattern) {
            Some(&i) => &mut patterns[i].1,
            None => {
                index.insert(pattern.clone(), patterns.len());
                patterns.push((pattern, HashMap::new()));
                // Invariant: the element was pushed on the previous line.
                #[allow(clippy::expect_used)]
                &mut patterns.last_mut().expect("just pushed").1
            }
        };
        if let Some(first) = slot.insert(route.method.clone(), idx) {
            // Both registration sites: knowing only the second one means
            // hunting the file for the first.
            return Err(Error::Script(format!(
                "duplicate route `{} {}`\n  --> {}   (first registered here)\n  --> {}   (registered again here)",
                route.method,
                route.path,
                site_label(&def.routes[first].site),
                site_label(&route.site),
            )));
        }
    }

    let mut router = Router::new();
    for (pattern, methods) in patterns {
        router.insert(&pattern, methods).map_err(|err| {
            Error::Script(format!(
                "invalid or conflicting route pattern `{pattern}` in {}: {err}",
                script.display()
            ))
        })?;
    }

    Ok((
        Dispatch(Box::new(CompiledApp { router, chains })),
        def.statics.clone(),
    ))
}

/// Composes `global middleware → route middleware → handler` into a single
/// function by calling each middleware factory with its `next` link.
fn compose(global: &[Function], route: &RouteDef) -> Result<Function> {
    // Invariant: route registration refuses an empty function list, so a
    // compiled route always carries at least its handler.
    #[allow(clippy::expect_used)]
    let (handler, mws) = route
        .fns
        .split_last()
        .expect("route registration requires at least a handler");
    let mut chain = handler.clone();
    for mw in mws.iter().rev().chain(global.iter().rev()) {
        chain = mw.call::<Function>(chain).map_err(|err| {
            Error::Script(format!(
                "middleware for route `{} {}` must return a function: {err}",
                route.method, route.path
            ))
        })?;
    }
    Ok(chain)
}

/// Converts the route syntax (`/users/:id` parameters, trailing `*` or
/// `*name` catch-alls) into matchit's `{id}` / `{*name}` syntax.
fn to_matchit(path: &str) -> Result<String> {
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len() - 1;
    let mut out = Vec::with_capacity(segments.len());
    for (i, seg) in segments.iter().enumerate() {
        let seg = *seg;
        out.push(match seg {
            "*" if i == last => "{*splat}".to_string(),
            s if s.starts_with(':') && s.len() > 1 => format!("{{{}}}", &s[1..]),
            s if s.starts_with('*') && s.len() > 1 && i == last => format!("{{*{}}}", &s[1..]),
            s if s.starts_with(':') || s.starts_with('*') => {
                return Err(Error::Script(format!(
                    "invalid segment `{seg}` in route path `{path}`"
                )));
            }
            s => s.to_string(),
        });
    }
    Ok(out.join("/"))
}

#[cfg(test)]
mod tests {
    use super::to_matchit;

    #[test]
    fn route_syntax_converts_to_matchit() {
        for (given, expected) in [
            ("/", "/"),
            ("/users", "/users"),
            ("/users/:id", "/users/{id}"),
            ("/users/:id/posts/:post", "/users/{id}/posts/{post}"),
            ("/files/*", "/files/{*splat}"),
            ("/files/*rest", "/files/{*rest}"),
        ] {
            assert_eq!(to_matchit(given).expect(given), expected);
        }
    }

    #[test]
    fn invalid_route_segments_are_rejected() {
        // A bare `:`, and wildcards anywhere but the last segment.
        for bad in ["/users/:", "/a/*/b", "/a/*rest/b"] {
            assert!(to_matchit(bad).is_err(), "{bad} must fail");
        }
    }
}
