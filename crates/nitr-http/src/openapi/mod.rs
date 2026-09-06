// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The OpenAPI document and the Swagger UI page.
//!
//! The router collects what the script declared — every route, its
//! enforced `input` (phase 26) and its `doc` table — into [`AppMeta`] on
//! every build. The `doc` tables are parsed for shape in every build, so
//! a typo fails the same way whichever features the binary carries;
//! producing the document ([`spec`]), serving it ([`docs`]) and the page
//! ([`ui`]) are the feature-gated halves.

use std::sync::Arc;

use hyper::Method;

use crate::validation::InputSchemas;

pub(crate) mod doc;
#[cfg(feature = "openapi")]
pub(crate) mod docs;
#[cfg(feature = "openapi")]
pub(crate) mod output;
#[cfg(feature = "openapi")]
pub(crate) mod spec;
#[cfg(feature = "swagger")]
pub(crate) mod ui;

/// One route as the generator sees it: what the router matched, what the
/// validator enforces, what the script said about it.
#[derive(Debug, Clone)]
// Collected in every build (the load-time checks need it); read only by
// the feature-gated generator.
#[cfg_attr(not(feature = "openapi"), allow(dead_code))]
pub(crate) struct RouteMeta {
    pub(crate) method: Method,
    /// The route pattern as registered (`/users/:id`).
    pub(crate) path: String,
    pub(crate) doc: Option<doc::RouteDoc>,
    pub(crate) input: Option<Arc<InputSchemas>>,
    /// The operation id as resolved at compile time: the `doc` one, or
    /// the default made unique among the defaults.
    pub(crate) operation_id: String,
}

/// Everything the document is built from, collected at compile time.
#[derive(Debug, Clone, Default)]
// Collected in every build; read only by the feature-gated generator.
#[cfg_attr(not(feature = "openapi"), allow(dead_code))]
pub(crate) struct AppMeta {
    pub(crate) api: Option<doc::ApiDoc>,
    pub(crate) routes: Vec<RouteMeta>,
}

/// A parameter a route pattern declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathParam {
    pub(crate) name: String,
    /// A trailing `*rest`: spans segments, which OpenAPI cannot express.
    pub(crate) catch_all: bool,
}

/// Converts the route syntax to an OpenAPI path template: `/users/:id` →
/// `/users/{id}`, a trailing `*` → `/{splat}`, `*rest` → `/{rest}`. A name
/// used twice is refused: two template parameters cannot share one.
pub(crate) fn to_openapi_path(path: &str) -> Result<(String, Vec<PathParam>), String> {
    let mut params: Vec<PathParam> = Vec::new();
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len() - 1;
    let mut out = Vec::with_capacity(segments.len());
    for (i, seg) in segments.iter().enumerate() {
        let (name, catch_all) = match *seg {
            "*" if i == last => ("splat".to_string(), true),
            s if s.starts_with(':') && s.len() > 1 => (s[1..].to_string(), false),
            s if s.starts_with('*') && s.len() > 1 && i == last => (s[1..].to_string(), true),
            s => {
                out.push(s.to_string());
                continue;
            }
        };
        if params.iter().any(|p| p.name == name) {
            return Err(format!(
                "route path `{path}` names the parameter `{name}` twice"
            ));
        }
        out.push(format!("{{{name}}}"));
        params.push(PathParam { name, catch_all });
    }
    Ok((out.join("/"), params))
}

/// The operation id a route gets when its `doc` gives none:
/// `<method>_<path slug>` over the OpenAPI template (`get_api_notes_id`;
/// a catch-all keeps its name, so `/` and `/*` differ).
pub(crate) fn default_operation_id(method: &Method, path: &str) -> String {
    let template = to_openapi_path(path)
        .map(|(template, _)| template)
        .unwrap_or_else(|_| path.to_string());
    let mut slug = String::new();
    for c in template.chars() {
        match c {
            c if c.is_ascii_alphanumeric() => slug.push(c.to_ascii_lowercase()),
            _ if slug.ends_with('_') || slug.is_empty() => {}
            _ => slug.push('_'),
        }
    }
    let slug = slug.trim_end_matches('_');
    let method = method.as_str().to_ascii_lowercase();
    if slug.is_empty() {
        format!("{method}_root")
    } else {
        format!("{method}_{slug}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_patterns_convert_to_openapi_templates() {
        for (given, expected, names) in [
            ("/", "/", vec![]),
            ("/users/:id", "/users/{id}", vec![("id", false)]),
            (
                "/users/:id/posts/:post",
                "/users/{id}/posts/{post}",
                vec![("id", false), ("post", false)],
            ),
            ("/files/*", "/files/{splat}", vec![("splat", true)]),
            ("/files/*rest", "/files/{rest}", vec![("rest", true)]),
        ] {
            let (path, params) = to_openapi_path(given).expect(given);
            assert_eq!(path, expected);
            let got: Vec<(&str, bool)> = params
                .iter()
                .map(|p| (p.name.as_str(), p.catch_all))
                .collect();
            assert_eq!(got, names, "{given}");
        }
        let err = to_openapi_path("/a/:x/b/:x").expect_err("duplicate");
        assert!(err.contains("`x` twice"), "{err}");
    }

    #[test]
    fn operation_ids_are_slugs_of_method_and_path() {
        assert_eq!(
            default_operation_id(&Method::GET, "/api/notes/:id"),
            "get_api_notes_id"
        );
        assert_eq!(default_operation_id(&Method::POST, "/"), "post_root");
        assert_eq!(default_operation_id(&Method::GET, "/*"), "get_splat");
        assert_eq!(default_operation_id(&Method::GET, "/files"), "get_files");
        assert_eq!(
            default_operation_id(&Method::DELETE, "/Files/*rest"),
            "delete_files_rest"
        );
        assert_eq!(
            default_operation_id(&Method::GET, "/a--b/c.d"),
            "get_a_b_c_d"
        );
    }
}
