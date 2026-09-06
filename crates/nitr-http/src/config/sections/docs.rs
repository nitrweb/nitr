// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `[openapi]` and `[swagger]` sections: the generated API document
//! and the Swagger UI page that renders it.
//!
//! Both parse in every build. Producing the document needs the `openapi`
//! Cargo feature and the page the `swagger` one; `enabled = true` on a
//! binary without the feature is refused at startup naming it, the same
//! way `[tls]` is.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The generated OpenAPI document (`[openapi]` section).
///
/// Off by default: a route map is reconnaissance material, and publishing
/// it should be a decision. The `nitr openapi` command generates the
/// document regardless of `enabled` — the flag gates serving, not
/// generation.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpenApiConfig {
    /// Serve the document at `path`.
    pub enabled: bool,
    /// Where the document is served (`/openapi.json`).
    pub path: String,
    /// The `servers` list of the document: deployment-level, hence
    /// configuration rather than script.
    pub servers: Vec<String>,
    /// Whether routes without a `doc` table still appear, as bare
    /// operations. The default documents everything routable; a route
    /// is kept out with `doc = { hidden = true }`.
    pub include_undocumented: bool,
    /// Dev mode only: a file rewritten after each successful rebuild when
    /// the document changed, so a committed `openapi.json` stays current
    /// while `nitr dev` runs. Production never writes.
    pub output: Option<PathBuf>,
}

impl Default for OpenApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "/openapi.json".into(),
            servers: Vec::new(),
            include_undocumented: true,
            output: None,
        }
    }
}

/// The Swagger UI page (`[swagger]` section).
///
/// The page is the vendored Swagger UI bundle served from this binary:
/// no CDN, no network, and a `Content-Security-Policy` that forbids
/// inline script. Needs `[openapi] enabled` (or an explicit `spec_url`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SwaggerConfig {
    /// Serve the page at `path`.
    pub enabled: bool,
    /// Where the page is served (`/docs`); its assets live under
    /// `<path>/assets/<version>/`.
    pub path: String,
    /// The page `<title>`; defaults to the `app:doc` title.
    pub title: Option<String>,
    /// The document the page loads; defaults to `[openapi] path`. A URL
    /// with an origin needs `allow_external_spec`.
    pub spec_url: Option<String>,
    /// Allow `spec_url` on another origin, widening the page's
    /// `connect-src` to exactly that origin.
    pub allow_external_spec: bool,
    /// Swagger UI `deepLinking`.
    pub deep_linking: bool,
    /// Swagger UI `docExpansion`: `"list"`, `"full"` or `"none"`.
    pub doc_expansion: String,
    /// Swagger UI `filter`: the operation filter box.
    pub filter: bool,
    /// Swagger UI `tryItOutEnabled`: whether "Try it out" starts enabled.
    pub try_it_out: bool,
    /// Swagger UI `displayRequestDuration`.
    pub display_request_duration: bool,
    /// Swagger UI `persistAuthorization`. Off by default: it keeps entered
    /// tokens in the browser's `localStorage`.
    pub persist_authorization: bool,
    /// Swagger UI `displayOperationId`.
    pub display_operation_id: bool,
    /// Swagger UI `defaultModelsExpandDepth`.
    pub default_models_expand_depth: i64,
    /// Further Swagger UI options, passed verbatim (camelCase keys). May
    /// not repeat a typed setting above under its camelCase name, nor set
    /// `url` or `dom_id`, which the page owns.
    pub options: BTreeMap<String, toml::Value>,
}

impl Default for SwaggerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "/docs".into(),
            title: None,
            spec_url: None,
            allow_external_spec: false,
            deep_linking: true,
            doc_expansion: "list".into(),
            filter: false,
            try_it_out: false,
            display_request_duration: false,
            persist_authorization: false,
            display_operation_id: false,
            default_models_expand_depth: 1,
            options: BTreeMap::new(),
        }
    }
}

/// The typed `[swagger]` settings and the Swagger UI option each one
/// spells, so `[swagger.options]` cannot carry a second spelling.
pub(crate) const SWAGGER_TYPED_OPTIONS: &[(&str, &str)] = &[
    ("deep_linking", "deepLinking"),
    ("doc_expansion", "docExpansion"),
    ("filter", "filter"),
    ("try_it_out", "tryItOutEnabled"),
    ("display_request_duration", "displayRequestDuration"),
    ("persist_authorization", "persistAuthorization"),
    ("display_operation_id", "displayOperationId"),
    ("default_models_expand_depth", "defaultModelsExpandDepth"),
];

/// The `[swagger.options]` keys the page owns.
pub(crate) const SWAGGER_RESERVED_OPTIONS: &[&str] = &["url", "dom_id", "domNode", "spec"];

/// The accepted `doc_expansion` spellings.
pub(crate) const DOC_EXPANSIONS: &[&str] = &["list", "full", "none"];
