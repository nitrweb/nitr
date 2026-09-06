// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The `file` rule against what the spooler learned about an upload:
//! sizes, the detected type, extensions, the filename, image dimensions,
//! UTF-8. Every message is fixed text naming the rule, never the file.

use std::collections::BTreeMap;
use std::sync::Arc;

use mlua::Value;

use super::path::FieldPath;
use super::{Ctx, Params, Slot};
use crate::validate::file::FileInfo;
use crate::validate::message::Param;
use crate::validate::{Rule, SchemaDef, TypePattern, media};

fn extensions_param(list: &[String]) -> Param {
    Param::List(list.iter().map(|e| Param::Str(e.clone())).collect())
}

/// An empty owner for the nested filename check.
fn bare_schema() -> Arc<SchemaDef> {
    Arc::new(SchemaDef {
        fields: Vec::new(),
        title: None,
        strict: false,
        messages: BTreeMap::new(),
        at_least_one: Vec::new(),
        mutually_exclusive: Vec::new(),
        dependent_required: Vec::new(),
        equal_fields: Vec::new(),
        ordered: Vec::new(),
        checks: Vec::new(),
    })
}

impl Ctx<'_> {
    /// The first failing file rule, with its parameters, or `None`.
    pub(super) fn check_file(
        &mut self,
        rule: &Rule,
        info: &FileInfo,
    ) -> mlua::Result<Option<(&'static str, Params)>> {
        // Invariant: a `file` rule always carries its file part and
        // `max_bytes`.
        #[allow(clippy::expect_used)]
        let file = rule
            .file
            .as_ref()
            .expect("file rules carry their file part");
        #[allow(clippy::expect_used)]
        let max_bytes = rule.max_bytes.expect("file rules carry `max_bytes`");
        if info.size > max_bytes {
            return Ok(Some(("max_bytes", vec![("max", Param::Size(max_bytes))])));
        }
        if info.size < file.min_bytes {
            return Ok(Some((
                "min_bytes",
                vec![("min", Param::Size(file.min_bytes))],
            )));
        }
        let effective = info.effective_type();
        if info.is_executable() && !file.allow_executables {
            return Ok(Some(("executable", Vec::new())));
        }
        if !file.types.is_empty() {
            let family = effective.split('/').next().unwrap_or_default();
            let matched = file.types.iter().any(|t| match t {
                TypePattern::Any => true,
                // `image/*` means pictures, not an SVG with a script.
                TypePattern::Family(f) => f == family && !media::is_active_content(effective),
                TypePattern::Exact(name) => name == effective,
            });
            if !matched {
                return Ok(Some((
                    "types",
                    vec![("types", Param::Str(media::describe_types(&file.types)))],
                )));
            }
        }
        if !file.extensions.is_empty() {
            let name = info
                .safe_filename
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            // Longest suffix first, so `tar.gz` is tried before `gz`.
            let mut sorted: Vec<&String> = file.extensions.iter().collect();
            sorted.sort_by_key(|e| std::cmp::Reverse(e.len()));
            let matched =
                info.extension.is_some() && sorted.iter().any(|e| name.ends_with(&format!(".{e}")));
            if !matched {
                return Ok(Some((
                    "extensions",
                    vec![("extensions", extensions_param(&file.extensions))],
                )));
            }
        }
        if file.match_extension
            && let Some(ext) = info.extension.as_deref()
            && let Some(media) = media::lookup(effective)
            && !media::extension_matches(media, ext)
        {
            return Ok(Some(("match_extension", Vec::new())));
        }
        if let Some(name_rule) = &file.filename {
            match &info.safe_filename {
                None if name_rule.required => return Ok(Some(("filename", Vec::new()))),
                None => {}
                Some(name) => {
                    let value = Value::String(self.lua.create_string(name)?);
                    let mut sub = Ctx::child(self);
                    let root = FieldPath::ROOT;
                    let p = root.field("filename");
                    let slot = Slot {
                        table: self.lua.create_table()?,
                        key: Value::Integer(1),
                    };
                    let owner = bare_schema();
                    if sub
                        .check_value(name_rule, &owner, value, &p, slot)?
                        .is_none()
                    {
                        let reason = sub
                            .errors
                            .first()
                            .map(|e| e.message.clone())
                            .unwrap_or_default();
                        return Ok(Some(("filename", vec![("text", Param::Str(reason))])));
                    }
                }
            }
        }
        if file.wants_dimensions() {
            let Some((w, h)) = info.width.zip(info.height) else {
                return Ok(Some(("dimensions", Vec::new())));
            };
            let bounds: [(&'static str, Option<u32>, bool, u32); 4] = [
                ("min_width", file.min_width, true, w),
                ("max_width", file.max_width, false, w),
                ("min_height", file.min_height, true, h),
                ("max_height", file.max_height, false, h),
            ];
            for (name, bound, is_min, actual) in bounds {
                if let Some(bound) = bound
                    && ((is_min && actual < bound) || (!is_min && actual > bound))
                {
                    let key = if is_min { "min" } else { "max" };
                    return Ok(Some((name, vec![(key, Param::Num(f64::from(bound)))])));
                }
            }
            if let Some(max) = file.max_pixels
                && u64::from(w) * u64::from(h) > max
            {
                return Ok(Some(("max_pixels", vec![("max", Param::Num(max as f64))])));
            }
            if let Some(aspect) = &file.aspect {
                let ratio = f64::from(w) / f64::from(h.max(1));
                if ratio < aspect.min || ratio > aspect.max {
                    return Ok(Some((
                        "aspect",
                        vec![("aspect", Param::Str(aspect.label.clone()))],
                    )));
                }
            }
        }
        if file.utf8 && info.utf8 != Some(true) {
            return Ok(Some(("utf8", Vec::new())));
        }
        Ok(None)
    }
}
