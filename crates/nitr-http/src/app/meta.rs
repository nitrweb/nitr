// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! What the OpenAPI document is built from, collected at compile time:
//! the `app:doc` table, every route's `doc` table beside its compiled
//! `input`, and the load-time checks that make the document consistent
//! — reserved paths, duplicate operation ids, a parameter named twice.
//! Runs in every build, so a `doc` typo fails whichever features the
//! binary carries.

use std::collections::HashMap;
use std::sync::Arc;

use mlua::Lua;

use nitr_core::{Error, Result};

use super::AppDef;
use super::compile::route_site;
use super::options::site_label;
use crate::openapi::doc::{ApiDoc, RouteDoc};
use crate::openapi::{AppMeta, RouteMeta, default_operation_id, to_openapi_path};
use crate::validation::{InputEnv, InputSchemas};

/// Collects the document metadata; `inputs` are the compiled `input`
/// declarations in route order.
pub(super) fn collect(
    lua: &Lua,
    def: &AppDef,
    inputs: &[Option<Arc<InputSchemas>>],
    env: &InputEnv,
) -> Result<AppMeta> {
    let api = match &def.api_doc {
        Some((table, site)) => Some(
            ApiDoc::parse(table, &format!("app:doc ({})", site_label(site)))
                .map_err(|err| Error::Script(err.to_string()))?,
        ),
        None => None,
    };

    let mut routes = Vec::with_capacity(def.routes.len());
    // Operation id → the route that claimed it and whether its `doc` said
    // so. Two explicit claims (or an explicit one meeting a default) are
    // an error naming both sites; two defaults are Nitr's own naming and
    // must never refuse an application that booted before this phase, so
    // the later one takes a numbered suffix.
    let mut ids: HashMap<String, (usize, bool)> = HashMap::new();
    for (i, route) in def.routes.iter().enumerate() {
        let site = route_site(route);
        for (path, key) in &env.reserved {
            if &route.path == path || route.path.starts_with(&format!("{path}/")) {
                return Err(Error::Script(format!(
                    "{site} is reserved by {key} = \"{path}\": the document is served there, \
                     before the router"
                )));
            }
        }
        let doc = match &route.doc {
            Some(table) => Some(
                RouteDoc::parse(lua, table, &site, api.as_ref())
                    .map_err(|err| Error::Script(err.to_string()))?,
            ),
            None => None,
        };
        // Validated whether or not the document is produced: two template
        // parameters cannot share one name.
        to_openapi_path(&route.path).map_err(|msg| Error::Script(format!("{site}: {msg}")))?;
        let hidden = doc.as_ref().is_some_and(|d| d.hidden);
        let explicit = doc.as_ref().and_then(|d| d.operation_id.clone());
        let mut operation_id = explicit
            .clone()
            .unwrap_or_else(|| default_operation_id(&route.method, &route.path));
        if !hidden {
            if let Some(&(first, first_explicit)) = ids.get(&operation_id) {
                if explicit.is_some() || first_explicit {
                    return Err(Error::Script(format!(
                        "operation id `{operation_id}` is claimed twice\n  --> {}   (first here)\n  --> {}   (again here)\n  \
                         set `doc = {{ operation_id = \"...\" }}` on one of them",
                        site_label(&def.routes[first].site),
                        site_label(&route.site),
                    )));
                }
                let base = operation_id.clone();
                let mut n = 2;
                while ids.contains_key(&format!("{base}_{n}")) {
                    n += 1;
                }
                operation_id = format!("{base}_{n}");
            }
            ids.insert(operation_id.clone(), (i, explicit.is_some()));
        }
        routes.push(RouteMeta {
            method: route.method.clone(),
            path: route.path.clone(),
            doc,
            input: inputs.get(i).cloned().flatten(),
            operation_id,
        });
    }
    Ok(AppMeta { api, routes })
}
