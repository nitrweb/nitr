// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The Swagger UI page: the vendored bundle and stylesheet, a fixed
//! initializer, and one JSON block carrying the `[swagger]` settings.
//!
//! Nothing per-deployment is interpolated as script. The page carries a
//! `Content-Security-Policy` without `'unsafe-inline'` for scripts, so
//! even a title of `</script><script>alert(1)</script>` — escaped twice
//! over anyway — could not run. Descriptions written in Lua reach the
//! browser only inside the fetched JSON document, which the bundle
//! renders as text and sanitized Markdown.

use serde_json::{Map, Value as Json, json};

use nitr_core::{Error, Result};

use crate::config::SWAGGER_TYPED_OPTIONS;
use crate::config::SwaggerConfig;

/// The vendored Swagger UI release (`assets/swagger-ui/VERSION`).
pub(crate) fn version() -> &'static str {
    include_str!("../../assets/swagger-ui/VERSION").trim()
}

/// The fixed initializer: reads the JSON block and starts the bundle.
const INIT_JS: &str = r##"(function () {
  var node = document.getElementById("nitr-swagger-config");
  var config = JSON.parse(node.textContent);
  config.dom_id = "#swagger-ui";
  config.presets = [SwaggerUIBundle.presets.apis];
  config.layout = "BaseLayout";
  window.ui = SwaggerUIBundle(config);
})();
"##;

/// Every file served under `<swagger path>/assets/<version>/`: name,
/// bytes, content type. A fixed table — the lookup is an exact match.
pub(crate) const ASSETS: &[(&str, &[u8], &str)] = &[
    (
        "swagger-ui-bundle.js",
        include_bytes!("../../assets/swagger-ui/swagger-ui-bundle.js"),
        "application/javascript; charset=utf-8",
    ),
    (
        "swagger-ui.css",
        include_bytes!("../../assets/swagger-ui/swagger-ui.css"),
        "text/css; charset=utf-8",
    ),
    (
        "init.js",
        INIT_JS.as_bytes(),
        "application/javascript; charset=utf-8",
    ),
];

/// The page's policy. The bundle needs inline styles; nothing needs
/// inline script. `connect-src` widens to the document's origin only
/// when the operator allowed an external document.
pub(crate) fn csp(cfg: &SwaggerConfig) -> String {
    let mut connect = String::from("'self'");
    if cfg.allow_external_spec
        && let Some(url) = &cfg.spec_url
        && let Some(origin) = origin_of(url)
    {
        connect.push(' ');
        connect.push_str(&origin);
    }
    format!(
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; font-src 'self' data:; connect-src {connect}; \
         frame-ancestors 'none'; base-uri 'none'"
    )
}

/// `scheme://host[:port]` of an absolute URL, for the policy.
fn origin_of(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let mut origin = format!("{}://{host}", parsed.scheme());
    if let Some(port) = parsed.port() {
        origin.push_str(&format!(":{port}"));
    }
    Some(origin)
}

/// The Swagger UI configuration object: the typed settings under their
/// camelCase names, then `[swagger.options]` verbatim, then the URL.
pub(crate) fn config_json(cfg: &SwaggerConfig, spec_url: &str) -> Result<Json> {
    let mut out = Map::new();
    for (typed, camel) in SWAGGER_TYPED_OPTIONS {
        let value = match *typed {
            "deep_linking" => json!(cfg.deep_linking),
            "doc_expansion" => json!(cfg.doc_expansion),
            "filter" => json!(cfg.filter),
            "try_it_out" => json!(cfg.try_it_out),
            "display_request_duration" => json!(cfg.display_request_duration),
            "persist_authorization" => json!(cfg.persist_authorization),
            "display_operation_id" => json!(cfg.display_operation_id),
            "default_models_expand_depth" => json!(cfg.default_models_expand_depth),
            _ => continue,
        };
        out.insert((*camel).to_string(), value);
    }
    for (key, value) in &cfg.options {
        let value = serde_json::to_value(value).map_err(|err| {
            Error::Config(format!("[swagger.options] {key} is not plain data: {err}"))
        })?;
        out.insert(key.clone(), value);
    }
    out.insert("url".into(), json!(spec_url));
    Ok(Json::Object(out))
}

/// JSON safe inside a `<script type="application/json">` block: the
/// characters that could end the element or break a line are `\u`
/// escapes, which JSON parsers read back unchanged.
fn embed_json(value: &Json) -> Result<String> {
    let text = serde_json::to_string(value).map_err(|err| {
        Error::Config(format!(
            "[swagger] cannot serialize the page settings: {err}"
        ))
    })?;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// The page: a stylesheet link, the settings block, the bundle and the
/// initializer. `base` is the versioned asset prefix.
pub(crate) fn page(cfg: &SwaggerConfig, title: &str, spec_url: &str, base: &str) -> Result<String> {
    let settings = embed_json(&config_json(cfg, spec_url)?)?;
    let title = crate::handler::escape_html(title);
    let base = crate::handler::escape_html(base);
    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{title}</title>
<link rel="stylesheet" href="{base}/swagger-ui.css">
<style>body {{ margin: 0; }}</style>
</head>
<body>
<div id="swagger-ui"></div>
<script type="application/json" id="nitr-swagger-config">{settings}</script>
<script src="{base}/swagger-ui-bundle.js"></script>
<script src="{base}/init.js"></script>
</body>
</html>
"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_interpolates_only_escaped_text_and_json() {
        let mut cfg = SwaggerConfig {
            enabled: true,
            try_it_out: true,
            ..Default::default()
        };
        cfg.options
            .insert("showExtensions".into(), toml::Value::Boolean(true));
        let html = page(
            &cfg,
            "</script><script>alert(1)</script>",
            "/openapi.json?x=</script>",
            "/docs/assets/1.0.0",
        )
        .unwrap();
        assert!(!html.contains("<script>alert"), "{html}");
        assert!(
            html.contains("&lt;/script&gt;&lt;script&gt;alert(1)"),
            "{html}"
        );
        // The settings block: one JSON object, angle brackets escaped.
        let start = html.find("nitr-swagger-config\">").unwrap() + "nitr-swagger-config\">".len();
        let end = html[start..].find("</script>").unwrap() + start;
        let block = &html[start..end];
        assert!(!block.contains('<') && !block.contains('>'), "{block}");
        let parsed: Json = serde_json::from_str(block).unwrap();
        assert_eq!(parsed["url"], "/openapi.json?x=</script>");
        assert_eq!(parsed["tryItOutEnabled"], true);
        assert_eq!(parsed["docExpansion"], "list");
        assert_eq!(parsed["showExtensions"], true);
        // No inline script: every `<script` either has a src or is JSON.
        for (i, _) in html.match_indices("<script") {
            let tag_end = html[i..].find('>').unwrap() + i;
            let tag = &html[i..=tag_end];
            assert!(
                tag.contains("src=") || tag.contains("application/json"),
                "inline script: {tag}"
            );
        }
    }

    #[test]
    fn the_policy_widens_only_for_an_allowed_external_document() {
        let mut cfg = SwaggerConfig::default();
        assert!(csp(&cfg).contains("connect-src 'self';"));
        cfg.spec_url = Some("https://specs.example.com:8443/api.json".into());
        assert!(csp(&cfg).contains("connect-src 'self';"), "not allowed yet");
        cfg.allow_external_spec = true;
        assert!(
            csp(&cfg).contains("connect-src 'self' https://specs.example.com:8443;"),
            "{}",
            csp(&cfg)
        );
        assert!(csp(&cfg).contains("script-src 'self';"));
    }
}
