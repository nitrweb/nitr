// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Compilation of the collected definition into the Rust-side router:
//! middleware factories run once, route conflicts fail at startup, and
//! the document metadata is collected beside the chains.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use hyper::Method;
use matchit::Router;
use mlua::{Lua, Value};

use nitr_core::{Error, Result};

use super::options::site_label;
use super::{Chain, CompiledApp, Dispatch, LuaApp, RouteDef, lock};
use crate::openapi::AppMeta;
use crate::validation::{InputEnv, InputHolder, InputSchemas};

/// What compiling a handler script yields.
pub(super) struct Compiled {
    pub(super) dispatch: Dispatch,
    pub(super) statics: Vec<crate::static_files::StaticMount>,
    pub(super) meta: AppMeta,
}

/// The `route \`METHOD /path\` (file:line)` label diagnostics use.
pub(super) fn route_site(route: &RouteDef) -> String {
    format!(
        "route `{} {}` ({})",
        route.method,
        route.path,
        site_label(&route.site)
    )
}

/// Compiles the script's return value into a [`Dispatch`]: middleware
/// factories are invoked once here (never per request), and the route set
/// is validated so conflicts fail at startup instead of at request time.
pub(super) fn compile(
    lua: &Lua,
    value: Value,
    script: &Path,
    input_env: &InputEnv,
) -> Result<Compiled> {
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
    let mut inputs: Vec<Option<Arc<InputSchemas>>> = Vec::with_capacity(def.routes.len());
    // matchit rejects a second insert of the same pattern, so methods for
    // one pattern are grouped before inserting.
    let mut patterns: Vec<(String, HashMap<Method, usize>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for route in &def.routes {
        let idx = chains.len();
        let input = match &route.input {
            Some(table) => {
                let site = route_site(route);
                let names = crate::validation::param_names(&route.path);
                let schemas = InputSchemas::parse(lua, table, &names, input_env, &site)
                    .map_err(|err| Error::Script(err.to_string()))?;
                let schemas = Arc::new(schemas);
                let holder = lua.create_userdata(InputHolder(schemas.clone()))?;
                Some((schemas, holder))
            }
            None => None,
        };
        inputs.push(input.as_ref().map(|(schemas, _)| schemas.clone()));
        // Invariant: route registration refuses an empty function list, so
        // a compiled route always carries at least its handler.
        #[allow(clippy::expect_used)]
        let handler = route
            .fns
            .last()
            .expect("route registration requires at least a handler")
            .clone();
        chains.push(Chain {
            fns: compose(&def.middleware, route)?,
            handler,
            method: route.method.clone(),
            path: route.path.clone(),
            site: route.site.clone(),
            error_fn: route.error_fn.clone().or_else(|| def.error_fn.clone()),
            input,
            invalid_fn: route.invalid_fn.clone().or_else(|| def.invalid_fn.clone()),
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

    let meta = super::meta::collect(lua, &def, &inputs, input_env)?;

    Ok(Compiled {
        dispatch: Dispatch(Box::new(CompiledApp {
            router: Arc::new(router),
            chains,
        })),
        statics: def.statics.clone(),
        meta,
    })
}

/// Composes `global middleware → route middleware → handler` into a single
/// function by calling each middleware factory with its `next` link.
fn compose(global: &[mlua::Function], route: &RouteDef) -> Result<mlua::Function> {
    // Invariant: route registration refuses an empty function list, so a
    // compiled route always carries at least its handler.
    #[allow(clippy::expect_used)]
    let (handler, mws) = route
        .fns
        .split_last()
        .expect("route registration requires at least a handler");
    let mut chain = handler.clone();
    for mw in mws.iter().rev().chain(global.iter().rev()) {
        chain = mw.call::<mlua::Function>(chain).map_err(|err| {
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
