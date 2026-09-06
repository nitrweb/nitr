// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The built document and page, and how a request is answered from them.
//!
//! Built once per pool build from the bootstrap state and swapped with
//! the pool, so a reload can never serve a document describing the
//! previous routes. Serving is a few exact string compares and a `Bytes`
//! clone: no Lua, no filesystem, no path resolution — the asset table is
//! fixed, so `..`, percent-encoded dots and backslashes are simply names
//! nothing matches.

use std::hash::{Hash as _, Hasher as _};
use std::sync::{Arc, RwLock};

use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Bytes;
use hyper::{Method, Response, StatusCode, header};

use nitr_core::{Error, Result};

use crate::config::Config;
use crate::handler::HttpResponse;
use crate::request::LuaRequest;

/// The docs slot the server and its handler share; `None` until the
/// first build, and always `Some` afterwards.
pub(crate) type DocsSlot = Arc<RwLock<Option<Arc<OpenApiDocs>>>>;

/// One embedded file of the page.
pub(crate) struct Asset {
    /// The URL path it is served at.
    pub(crate) path: String,
    pub(crate) bytes: Bytes,
    pub(crate) content_type: &'static str,
    etag: String,
}

/// A page served at a path, with its own headers.
pub(crate) struct Page {
    pub(crate) path: String,
    pub(crate) html: Bytes,
    etag: String,
    csp: String,
}

/// The document and everything served beside it.
pub(crate) struct OpenApiDocs {
    spec: Bytes,
    spec_etag: String,
    /// Where the document answers, when `[openapi] enabled`.
    spec_path: Option<String>,
    /// The Swagger UI page, when `[swagger] enabled`.
    page: Option<Page>,
    pub(crate) assets: Vec<Asset>,
    dev_mode: bool,
    operations: u64,
    /// The document title, for a page built later (the static site).
    // Only the page reads it, and the page is the `swagger` feature.
    #[cfg_attr(not(feature = "swagger"), allow(dead_code))]
    title: String,
}

impl std::fmt::Debug for OpenApiDocs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenApiDocs")
            .field("spec_bytes", &self.spec.len())
            .field("spec_path", &self.spec_path)
            .field("operations", &self.operations)
            .finish_non_exhaustive()
    }
}

/// A strong validator derived from the bytes. `DefaultHasher` is stable
/// for one process, which is all an `ETag` needs: a rebuild that changes
/// the bytes changes the tag, and a restart may change it for free.
fn etag_of(bytes: &[u8]) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("\"{:016x}\"", hasher.finish())
}

impl OpenApiDocs {
    /// Builds the document from the state's compiled application, and the
    /// page when `[swagger]` is enabled. A document over the size bound
    /// fails the build.
    pub(crate) fn build(lua: &mlua::Lua, cfg: &Config) -> Result<Self> {
        let state = crate::app::state(lua)?;
        let state = state.borrow::<crate::app::AppState>()?;
        let spec = super::spec::build(lua, &state.meta, &cfg.openapi)
            .map_err(|msg| Error::Script(format!("openapi: {msg}")))?;
        let operations = spec["x-nitr-operations"].as_u64().unwrap_or(0);
        let mut bytes = serde_json::to_vec_pretty(&spec).map_err(|err| {
            Error::Script(format!("openapi: cannot serialize the document: {err}"))
        })?;
        bytes.push(b'\n');
        // The bound guards what is served or written; an application that
        // asked for neither must not refuse to boot over a document nobody
        // sees (`nitr openapi` still prints it, whatever its size).
        let leaves_the_process = cfg.openapi.enabled || cfg.openapi.output.is_some();
        if leaves_the_process && bytes.len() > super::spec::MAX_SPEC_BYTES {
            return Err(Error::Script(format!(
                "openapi: the document is {} bytes, over the {} byte bound; fewer routes, \
                 shorter descriptions, or `doc = {{ hidden = true }}` on internal routes",
                bytes.len(),
                super::spec::MAX_SPEC_BYTES
            )));
        }
        let title = state
            .meta
            .api
            .as_ref()
            .map(|api| api.title.clone())
            .unwrap_or_else(|| "API".into());
        drop(state);
        let spec = Bytes::from(bytes);
        let spec_etag = etag_of(&spec);
        let spec_path = cfg.openapi.enabled.then(|| cfg.openapi.path.clone());

        #[cfg(feature = "swagger")]
        let (page, assets) = if cfg.swagger.enabled {
            let spec_url = cfg
                .swagger
                .spec_url
                .clone()
                .unwrap_or_else(|| cfg.openapi.path.clone());
            let base = format!("{}/assets/{}", cfg.swagger.path, super::ui::version());
            let page_title = cfg.swagger.title.clone().unwrap_or_else(|| title.clone());
            let html = super::ui::page(&cfg.swagger, &page_title, &spec_url, &base)?;
            let html = Bytes::from(html);
            let page = Page {
                path: cfg.swagger.path.clone(),
                etag: etag_of(&html),
                html,
                csp: super::ui::csp(&cfg.swagger),
            };
            let assets = super::ui::ASSETS
                .iter()
                .map(|(name, bytes, content_type)| Asset {
                    path: format!("{base}/{name}"),
                    bytes: Bytes::from_static(bytes),
                    content_type,
                    etag: etag_of(bytes),
                })
                .collect();
            (Some(page), assets)
        } else {
            (None, Vec::new())
        };
        #[cfg(not(feature = "swagger"))]
        let (page, assets) = (None, Vec::new());

        Ok(Self {
            spec,
            spec_etag,
            spec_path,
            page,
            assets,
            dev_mode: cfg.dev_mode,
            operations,
            title,
        })
    }

    /// The page and its assets as files of a self-contained static site,
    /// with relative links so it opens from `file://`: `index.html`,
    /// `openapi.json`, `assets/<version>/<name>`. Built from the
    /// `[swagger]` settings whether or not the page is served.
    #[cfg(feature = "swagger")]
    pub(crate) fn static_site(
        &self,
        cfg: &crate::config::SwaggerConfig,
    ) -> Result<Vec<(String, Bytes)>> {
        let base = format!("assets/{}", super::ui::version());
        let title = cfg.title.clone().unwrap_or_else(|| self.title.clone());
        let html = super::ui::page(cfg, &title, "openapi.json", &base)?;
        let mut files = vec![
            ("index.html".to_string(), Bytes::from(html)),
            ("openapi.json".to_string(), self.spec.clone()),
        ];
        for (name, bytes, _) in super::ui::ASSETS {
            files.push((format!("{base}/{name}"), Bytes::from_static(bytes)));
        }
        Ok(files)
    }

    /// The document bytes (pretty JSON, trailing newline).
    pub(crate) fn spec(&self) -> &Bytes {
        &self.spec
    }

    /// The boot log line: what is served where.
    pub(crate) fn summary(&self) -> String {
        let mut line = format!("openapi: {} operation(s)", self.operations);
        match &self.spec_path {
            Some(path) => line.push_str(&format!(", spec at {path}")),
            None => line.push_str(", not served ([openapi] enabled = false)"),
        }
        if let Some(page) = &self.page {
            line.push_str(&format!(", Swagger UI at {}", page.path));
        }
        line
    }

    /// Answers a docs request, or `None` for anything else. Only `GET`
    /// and `HEAD` are docs requests: other methods fall through to the
    /// router and its `405`.
    pub(crate) fn serve(&self, req: &LuaRequest) -> Option<Result<HttpResponse>> {
        let method = req.req.method();
        if method != Method::GET && method != Method::HEAD {
            return None;
        }
        let path = req.req.uri().path();
        let headers = req.req.headers();
        if self.spec_path.as_deref() == Some(path) {
            return Some(self.answer(
                headers,
                &self.spec,
                "application/json",
                &self.spec_etag,
                self.short_cache(),
                None,
            ));
        }
        if let Some(page) = &self.page
            && page.path == path
        {
            return Some(self.answer(
                headers,
                &page.html,
                "text/html; charset=utf-8",
                &page.etag,
                self.short_cache(),
                Some(&page.csp),
            ));
        }
        let asset = self.assets.iter().find(|a| a.path == path)?;
        Some(self.answer(
            headers,
            &asset.bytes,
            asset.content_type,
            &asset.etag,
            // Versioned URL: the bytes at it never change.
            "public, max-age=31536000, immutable",
            None,
        ))
    }

    fn short_cache(&self) -> &'static str {
        if self.dev_mode {
            "no-store"
        } else {
            "max-age=60"
        }
    }

    fn answer(
        &self,
        headers: &hyper::HeaderMap,
        bytes: &Bytes,
        content_type: &'static str,
        etag: &str,
        cache: &'static str,
        csp: Option<&str>,
    ) -> Result<HttpResponse> {
        let mut builder = Response::builder()
            .header(header::CONTENT_TYPE, content_type)
            .header(header::ETAG, etag)
            .header(header::CACHE_CONTROL, cache)
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
        if let Some(csp) = csp {
            builder = builder.header(header::CONTENT_SECURITY_POLICY, csp);
        }
        if crate::request::is_fresh(headers, Some(etag), None) {
            return Ok(builder
                .status(StatusCode::NOT_MODIFIED)
                .body(Empty::<Bytes>::new().boxed())?);
        }
        Ok(builder
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(Full::new(bytes.clone()).boxed())?)
    }
}
