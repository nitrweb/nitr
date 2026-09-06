// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Compilation of the `file`-only keys: media types checked against the
//! table, extensions normalized, the nested filename rule, image
//! dimension bounds that need image types, and the aspect ratio.

use std::sync::Arc;

use mlua::{Lua, Table, Value};

use super::getters::{get_bool, get_count, get_f64, get_size, get_strings};
use super::{bad_schema, compile_rule_value};
use crate::validate::message::fmt_num;
use crate::validate::{Aspect, FileRule, Kind, TypePattern, media};

/// How far off a declared ratio a real image may be: 1919×1080 is still
/// `16:9` to a person.
const ASPECT_TOLERANCE: f64 = 0.01;

fn compile_types(rule: &Table, path: &str) -> mlua::Result<Vec<TypePattern>> {
    let mut types = Vec::new();
    for name in get_strings(rule, "types", path)?.unwrap_or_default() {
        types.push(match name.as_str() {
            "*/*" => TypePattern::Any,
            other if other.ends_with("/*") => {
                TypePattern::Family(other.trim_end_matches("/*").to_string())
            }
            other => {
                if media::lookup(other).is_none() {
                    return Err(bad_schema(
                        path,
                        format!(
                            "unknown media type `{other}` in `types` (see nitr.validate.media_types())"
                        ),
                    ));
                }
                if media::is_active_content(other) {
                    tracing::warn!(
                        rule = %path,
                        media_type = other,
                        "the rule accepts active content: a browser runs script from such a \
                         file, so never serve it back from a static root or inline"
                    );
                }
                TypePattern::Exact(other.to_string())
            }
        });
    }
    Ok(types)
}

fn compile_aspect(rule: &Table, path: &str) -> mlua::Result<Option<Aspect>> {
    match rule.get::<Value>("aspect")? {
        Value::Nil => Ok(None),
        Value::String(s) => {
            let raw = s.to_string_lossy().to_string();
            let parsed = raw.split_once(':').and_then(|(w, h)| {
                Some((w.trim().parse::<f64>().ok()?, h.trim().parse::<f64>().ok()?))
            });
            match parsed {
                Some((w, h)) if w > 0.0 && h > 0.0 => {
                    let ratio = w / h;
                    Ok(Some(Aspect {
                        min: ratio * (1.0 - ASPECT_TOLERANCE),
                        max: ratio * (1.0 + ASPECT_TOLERANCE),
                        label: raw,
                    }))
                }
                _ => Err(bad_schema(
                    path,
                    "`aspect` must look like \"16:9\" or { min = …, max = … }",
                )),
            }
        }
        Value::Table(t) => {
            let min = get_f64(&t, "min", path)?.unwrap_or(0.0);
            let max = get_f64(&t, "max", path)?.unwrap_or(f64::INFINITY);
            if min < 0.0 || max < min {
                return Err(bad_schema(path, "`aspect` needs 0 <= min <= max"));
            }
            Ok(Some(Aspect {
                min,
                max,
                label: format!("{}:{}", fmt_num(min), fmt_num(max)),
            }))
        }
        other => Err(bad_schema(
            path,
            format!(
                "`aspect` must be a string or table, got {}",
                other.type_name()
            ),
        )),
    }
}

pub(super) fn compile_file_rule(
    lua: &Lua,
    rule: &Table,
    path: &str,
    depth: usize,
) -> mlua::Result<FileRule> {
    let types = compile_types(rule, path)?;
    let extensions: Vec<String> = get_strings(rule, "extensions", path)?
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
        .collect();
    if extensions.iter().any(String::is_empty) {
        return Err(bad_schema(path, "`extensions` entries must not be empty"));
    }
    let match_extension = get_bool(rule, "match_extension", path)?
        .unwrap_or(!types.is_empty() && !extensions.is_empty());
    let filename = match rule.get::<Value>("filename")? {
        Value::Nil => None,
        value => {
            let mut name_rule =
                compile_rule_value(lua, value, &format!("{path}.filename"), depth + 1)?;
            if name_rule.kind != Kind::String {
                return Err(bad_schema(path, "`filename` must be a `string` rule"));
            }
            name_rule.label.get_or_insert_with(|| "filename".into());
            Some(Arc::new(name_rule))
        }
    };
    let dim = |key: &str| -> mlua::Result<Option<u32>> {
        Ok(get_count(rule, key, path)?.map(|n| u32::try_from(n).unwrap_or(u32::MAX)))
    };
    let file = FileRule {
        min_bytes: get_size(rule, "min_bytes", path)?.unwrap_or(1),
        allow_executables: get_bool(rule, "allow_executables", path)?.unwrap_or(false),
        types,
        extensions,
        match_extension,
        filename,
        min_width: dim("min_width")?,
        max_width: dim("max_width")?,
        min_height: dim("min_height")?,
        max_height: dim("max_height")?,
        max_pixels: get_size(rule, "max_pixels", path)?,
        aspect: compile_aspect(rule, path)?,
        utf8: get_bool(rule, "utf8", path)?.unwrap_or(false),
    };
    if file.wants_dimensions() {
        let all_images = !file.types.is_empty()
            && file.types.iter().all(|t| match t {
                TypePattern::Family(f) => f == "image",
                TypePattern::Exact(name) => {
                    media::lookup(name).is_some_and(media::MediaType::has_dimensions)
                }
                TypePattern::Any => false,
            });
        if !all_images {
            return Err(bad_schema(
                path,
                "image dimension rules need `types` naming only image types with readable \
                 headers (png, jpeg, gif, webp, bmp, tiff or image/*)",
            ));
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(lua: &Lua, def: &str) -> mlua::Result<FileRule> {
        let rule: Table = lua.load(def).eval().unwrap();
        compile_file_rule(lua, &rule, "f", 0)
    }

    #[test]
    fn file_rules_normalize_and_refuse_contradictions() {
        let lua = Lua::new();
        let ok = compile(&lua, r#"{ types = { "image/png", "image/*" }, extensions = { ".PNG", "tar.gz" }, aspect = "16:9" }"#).unwrap();
        assert_eq!(ok.extensions, vec!["png", "tar.gz"]);
        assert!(ok.match_extension);
        assert_eq!(ok.types[0], TypePattern::Exact("image/png".into()));
        assert_eq!(ok.types[1], TypePattern::Family("image".into()));
        let aspect = ok.aspect.unwrap();
        assert!(aspect.min < 16.0 / 9.0 && aspect.max > 16.0 / 9.0);

        for (bad, needle) in [
            (r#"{ types = { "image/pngx" } }"#, "unknown media type"),
            (
                r#"{ types = { "application/pdf" }, max_width = 10 }"#,
                "image dimension rules need",
            ),
            (r#"{ aspect = "wide" }"#, "`aspect` must look like"),
            (r#"{ extensions = { "" } }"#, "must not be empty"),
            (r#"{ filename = "integer" }"#, "must be a `string` rule"),
        ] {
            let err = compile(&lua, bad).expect_err(bad).to_string();
            assert!(err.contains(needle), "{bad}: {err}");
        }
    }
}
