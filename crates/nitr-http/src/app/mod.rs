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
    /// The route's own `{ rate_limit = { requests, window } }`.
    rate_limit: Option<(u32, std::time::Duration)>,
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

/// The `nitr.app()` userdata handed to the handler script. The definition
/// is shared with the groups registered through it.
pub(crate) struct LuaApp(Arc<Mutex<AppDef>>);

/// `app:group(prefix)`: a registrar whose routes carry the prefix and the
/// group's middleware, layered after the app's and before the route's own.
pub(crate) struct LuaGroup {
    def: Arc<Mutex<AppDef>>,
    prefix: String,
    state: Mutex<GroupState>,
}

#[derive(Default)]
struct GroupState {
    middleware: Vec<Function>,
    /// Set once a route or a nested group took the middleware list: a
    /// later `use` would silently miss them, so it is refused.
    sealed: bool,
}

/// Registers one route: `middleware..., handler` optionally followed by an
/// options table (`app:get(path, handler, { on_error = fn })`). A group
/// supplies its prefix and its middleware, which precede the route's own.
#[allow(clippy::too_many_arguments)]
fn register_route(
    lua: &Lua,
    def: &Mutex<AppDef>,
    name: &str,
    method: &Method,
    prefix: &str,
    group_middleware: &[Function],
    path: String,
    mut args: Variadic<Value>,
) -> mlua::Result<()> {
    let options = match args.last() {
        Some(Value::Table(opts)) => {
            let parsed = route_options(name, &path, opts)?;
            args.pop();
            parsed
        }
        _ => options::RouteOptions::default(),
    };
    let route_fns = args
        .into_iter()
        .map(|value| match value {
            Value::Function(f) => Ok(f),
            other => Err(mlua::Error::RuntimeError(format!(
                "app:{name}(\"{path}\", ...) takes handler functions \
                 and an optional trailing options table, got {}",
                other.type_name()
            ))),
        })
        .collect::<mlua::Result<Vec<Function>>>()?;
    if route_fns.is_empty() {
        return Err(mlua::Error::RuntimeError(format!(
            "app:{name}(\"{path}\", ...) requires a handler function"
        )));
    }
    if !path.starts_with('/') {
        return Err(mlua::Error::RuntimeError(format!(
            "route path `{path}` must start with `/`"
        )));
    }
    let mut fns = group_middleware.to_vec();
    fns.extend(route_fns);
    let site = caller_site(lua);
    lock(def)?.routes.push(RouteDef {
        method: method.clone(),
        path: join_prefix(prefix, &path),
        fns,
        error_fn: options.error_fn,
        invalid_fn: options.invalid_fn,
        input: options.input,
        doc: options.doc,
        rate_limit: options.rate_limit,
        site,
    });
    Ok(())
}

/// A group prefix as stored: starting with `/`, without a trailing one,
/// and `/` itself as the empty prefix.
fn group_prefix(parent: &str, prefix: &str) -> mlua::Result<String> {
    if !prefix.starts_with('/') {
        return Err(mlua::Error::RuntimeError(format!(
            "group prefix `{prefix}` must start with `/`"
        )));
    }
    Ok(join_prefix(parent, prefix.trim_end_matches('/')))
}

/// `prefix` plus `path`, where `/` under a prefix is the prefix itself.
fn join_prefix(prefix: &str, path: &str) -> String {
    match path {
        "/" if !prefix.is_empty() => prefix.to_string(),
        _ => format!("{prefix}{path}"),
    }
}

/// `group(prefix, fn?)` on an app or a group: the child, after `fn` (when
/// given) has registered through it.
fn make_group(
    lua: &Lua,
    def: &Arc<Mutex<AppDef>>,
    parent_prefix: &str,
    middleware: Vec<Function>,
    (prefix, body): (String, Option<Function>),
) -> mlua::Result<AnyUserData> {
    let group = lua.create_userdata(LuaGroup {
        def: def.clone(),
        prefix: group_prefix(parent_prefix, &prefix)?,
        state: Mutex::new(GroupState {
            middleware,
            sealed: false,
        }),
    })?;
    if let Some(body) = body {
        body.call::<()>(&group)?;
    }
    Ok(group)
}

impl UserData for LuaGroup {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        for (name, method) in METHOD_NAMES {
            let method = method.clone();
            methods.add_method(
                *name,
                move |lua, this, (path, args): (String, Variadic<Value>)| {
                    let middleware = {
                        let mut state = lock_group(&this.state)?;
                        state.sealed = true;
                        state.middleware.clone()
                    };
                    register_route(
                        lua,
                        &this.def,
                        name,
                        &method,
                        &this.prefix,
                        &middleware,
                        path,
                        args,
                    )
                },
            );
        }

        methods.add_method("use", |_, this, mw: Function| {
            let mut state = lock_group(&this.state)?;
            if state.sealed {
                return Err(mlua::Error::RuntimeError(
                    "group:use() must be called before registering routes or nested groups".into(),
                ));
            }
            state.middleware.push(mw);
            Ok(())
        });

        methods.add_method("group", |lua, this, args: (String, Option<Function>)| {
            let middleware = {
                let mut state = lock_group(&this.state)?;
                state.sealed = true;
                state.middleware.clone()
            };
            make_group(lua, &this.def, &this.prefix, middleware, args)
        });
    }
}

fn lock_group(state: &Mutex<GroupState>) -> mlua::Result<std::sync::MutexGuard<'_, GroupState>> {
    state
        .lock()
        .map_err(|_| mlua::Error::RuntimeError("the group definition lock is poisoned".into()))
}

impl UserData for LuaApp {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        for (name, method) in METHOD_NAMES {
            let method = method.clone();
            methods.add_method(
                *name,
                move |lua, this, (path, args): (String, Variadic<Value>)| {
                    register_route(lua, &this.0, name, &method, "", &[], path, args)
                },
            );
        }

        // app:group(prefix, fn?): routes under a common prefix with their
        // own middleware; `fn(g)` registers through the group, which is
        // also returned.
        methods.add_method("group", |lua, this, args: (String, Option<Function>)| {
            make_group(lua, &this.0, "", Vec::new(), args)
        });

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
    /// validating link receives it through.
    pub(crate) input: Option<(Arc<InputSchemas>, AnyUserData)>,
    /// The route's own rate limit, checked before its chain runs.
    pub(crate) rate: Option<Arc<crate::protect::RateLimiter>>,
}

/// The Rust-side router plus the per-route composed Lua chains.
pub(crate) struct CompiledApp {
    pub(crate) router: Arc<Router<HashMap<Method, usize>>>,
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
    pub(crate) fn lookup(&self, method: &Method, path: &str) -> Lookup {
        lookup(&self.router, method, path)
    }
}

/// The Lua-free half of a compiled application: its router and static
/// mounts. Every state of a pool compiles the same script, so one copy,
/// kept with the pool, routes a request before any state is checked out:
/// a static file, a 404, a 405 or an `OPTIONS` answer never needs one.
pub(crate) struct Routing {
    router: Arc<Router<HashMap<Method, usize>>>,
    /// The route set the router was built from: a state whose set differs
    /// routes itself.
    fingerprint: u64,
    pub(crate) statics: Arc<Vec<crate::static_files::StaticMount>>,
    /// Each chain's own rate limit, by index, checked before checkout.
    pub(crate) limits: Vec<Option<Arc<crate::protect::RateLimiter>>>,
}

impl Routing {
    pub(crate) fn lookup(&self, method: &Method, path: &str) -> Lookup {
        lookup(&self.router, method, path)
    }
}

/// The Lua-free routing of the application compiled in this state.
pub(crate) fn routing(lua: &Lua) -> Result<Routing> {
    let ud = state(lua)?;
    let state = ud.borrow::<AppState>()?;
    let app = &state.dispatch.0;
    Ok(Routing {
        router: app.router.clone(),
        fingerprint: state.fingerprint,
        statics: state.statics.clone(),
        limits: app.chains.iter().map(|chain| chain.rate.clone()).collect(),
    })
}

/// The chain `routing` resolved to `index`, from this state, when the state
/// compiled the same route set. A state rebuilt from a script edited on
/// disk since the pool was built can differ; the caller routes it with the
/// state's own table instead.
pub(crate) fn routed_chain<R>(
    lua: &Lua,
    routing: &Routing,
    index: usize,
    take: impl FnOnce(&Chain) -> R,
) -> Result<Option<R>> {
    let ud = state(lua)?;
    let state = ud.borrow::<AppState>()?;
    if state.fingerprint != routing.fingerprint {
        return Ok(None);
    }
    Ok(state.dispatch.0.chains.get(index).map(take))
}

/// One number for a route set: every `(method, pattern)` in order.
fn route_fingerprint(chains: &[Chain]) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::hash::DefaultHasher::new();
    for chain in chains {
        chain.method.as_str().hash(&mut hasher);
        chain.path.hash(&mut hasher);
    }
    hasher.finish()
}

/// The one router lookup, shared by the server and `nitr test`'s
/// `app:dispatch`: `HEAD` falls back to the `GET` route (it is `GET`
/// without the body), while an explicit `head` route still wins.
fn lookup(router: &Router<HashMap<Method, usize>>, method: &Method, path: &str) -> Lookup {
    let Ok(matched) = router.at(path) else {
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
    /// See [`route_fingerprint`].
    fingerprint: u64,
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
        lua.create_function(|_, ()| Ok(LuaApp(Arc::new(Mutex::new(AppDef::default())))))?,
    )?;
    Ok(())
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
    // A relative directory is the script's, not the working directory's:
    // a bundle runs from anywhere, and a mount that pointed at the cwd
    // served whatever sat there. Missing is refused here, where the
    // message can name the mount, rather than answering 404 forever.
    let script_dir = script.parent().unwrap_or_else(|| Path::new("."));
    for mount in &mut statics {
        if mount.dir.is_relative() {
            mount.dir = script_dir.join(&mount.dir);
        }
    }
    if input_env.static_dirs_optional {
        // Once per process, not once per pooled state.
        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        statics.retain(|mount| {
            let exists = mount.dir.is_dir();
            if !exists && !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(
                    "app:static(\"{}\", ...): directory {} does not exist yet: the mount is \
                     skipped by this command, and `nitr run` refuses it",
                    mount.mount,
                    mount.dir.display()
                );
            }
            exists
        });
    } else if let Some(mount) = statics.iter().find(|mount| !mount.dir.is_dir()) {
        return Err(Error::Script(format!(
            "app:static(\"{}\", ...): directory {} does not exist; a relative \
             directory is resolved against the handler script's",
            mount.mount,
            mount.dir.display()
        )));
    }
    statics.extend_from_slice(base_statics);
    // Longest mount prefix first, once: the static path used to collect
    // and sort the candidates on every request. Stable, so mounts of equal
    // length keep their registration order, script mounts before `[static]`.
    statics.sort_by_key(|m| std::cmp::Reverse(m.mount.len()));
    let fingerprint = route_fingerprint(&compiled.dispatch.0.chains);
    let state = lua.create_userdata(AppState {
        dispatch: compiled.dispatch,
        statics: Arc::new(statics),
        meta: Arc::new(compiled.meta),
        fingerprint,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(script: &str) -> (Lua, tempfile_path::Guard) {
        let lua = Lua::new();
        let path = tempfile_path::write("routing", script);
        register_nitr_app(&lua).expect("nitr.app");
        let env = InputEnv {
            upload_root: None,
            reserved: Vec::new(),
            trust_forwarded_for: false,
            static_dirs_optional: false,
        };
        load(&lua, &path.0, &[], &env).expect("load");
        (lua, path)
    }

    /// Only a state that compiled the same route set is routed by the
    /// pool's shared table: a rebuilt state whose script gained a route
    /// may resolve the same request elsewhere, even when the shared index
    /// still names a chain with the same method and pattern.
    #[test]
    fn shared_routing_only_applies_to_a_state_with_the_same_route_set() {
        let (a, _ka) = loaded(
            "local app = nitr.app()
             app:get('/a/:id', function() end)
             return app",
        );
        let (b, _kb) = loaded(
            "local app = nitr.app()
             app:get('/a/:id', function() end)
             app:get('/a/special', function() end)
             return app",
        );
        let routing_a = routing(&a).expect("routing");
        let Lookup::Route { index, .. } = routing_a.lookup(&Method::GET, "/a/special") else {
            panic!("a routes /a/special to its :id route");
        };
        assert!(
            routed_chain(&a, &routing_a, index, |chain| chain.path.clone())
                .expect("same state")
                .is_some()
        );
        assert!(
            routed_chain(&b, &routing_a, index, |chain| chain.path.clone())
                .expect("other state")
                .is_none(),
            "a state with another route set routes itself"
        );
    }
}

#[cfg(test)]
mod tempfile_path {
    use std::path::PathBuf;

    pub(super) struct Guard(pub(super) PathBuf);

    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    pub(super) fn write(label: &str, content: &str) -> Guard {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("nitr-app-{label}-{}-{id}.lua", std::process::id()));
        std::fs::write(&path, content).expect("write script");
        Guard(path)
    }
}
