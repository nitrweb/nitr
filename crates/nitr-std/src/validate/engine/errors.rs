// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The verdict a failed validation carries: one entry per failing path
//! with its rule code, parameters and message, in the three shapes the
//! callers need — a Lua table, a JSON body, and the Rust struct.

use mlua::{Lua, Table, Value};

use super::super::message::Param;

/// One failed rule.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorEntry {
    /// The failing path (`text`, `tags[2]`, `home.city`; `$` for the root).
    pub path: String,
    /// The nearest named field (`tags` for `tags[2]`), empty for the root.
    pub field: String,
    /// The rule code (`required`, `min_len`, `check`, …).
    pub rule: String,
    /// The rendered, sanitized message.
    pub message: String,
    /// The rule's own parameters, never the input.
    pub(crate) params: Vec<(String, Param)>,
    /// The field's `label`, when it has one.
    pub label: Option<String>,
}

impl ErrorEntry {
    /// The parameters as JSON, for the 422 body.
    pub fn params_json(&self) -> Option<serde_json::Value> {
        if self.params.is_empty() {
            return None;
        }
        Some(serde_json::Value::Object(
            self.params
                .iter()
                .map(|(k, v)| (k.clone(), v.to_json()))
                .collect(),
        ))
    }
}

/// The verdict when validation fails: the summary, and every failing
/// path with its message and rule.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError {
    /// The summary line (`validation failed` unless overridden).
    pub message: String,
    /// Sorted by path; one entry per failing path.
    pub entries: Vec<ErrorEntry>,
}

/// The request parts a path may be prefixed with.
const PARTS: [&str; 4] = ["body", "query", "params", "headers"];

impl ValidationError {
    /// A single failure not tied to a schema field: a body that is not
    /// JSON, say. `rule` is the code, `message` the text.
    pub fn single(rule: &str, message: &str) -> Self {
        Self {
            message: "validation failed".into(),
            entries: vec![ErrorEntry {
                path: "$".into(),
                field: String::new(),
                rule: rule.into(),
                message: message.into(),
                params: Vec::new(),
                label: None,
            }],
        }
    }

    /// Prefixes every path with a request part (`body`, `query`, …): the
    /// root `$` becomes the bare part name.
    pub fn prefix(&mut self, part: &str) {
        for entry in &mut self.entries {
            entry.path = if entry.path == "$" {
                part.to_string()
            } else {
                format!("{part}.{}", entry.path)
            };
        }
    }

    /// Appends another part's failures, keeping the list sorted.
    pub fn merge(&mut self, other: Self) {
        self.entries.extend(other.entries);
        self.entries.sort_by(|a, b| a.path.cmp(&b.path));
    }

    /// `{ message, fields = { path = message }, errors = { {...} } }`.
    pub fn to_lua(&self, lua: &Lua) -> mlua::Result<Table> {
        let err = lua.create_table()?;
        err.set("code", "VALIDATION_FAILED")?;
        err.set("message", self.message.as_str())?;
        let fields = lua.create_table()?;
        let errors = lua.create_table_with_capacity(self.entries.len(), 0)?;
        for (i, entry) in self.entries.iter().enumerate() {
            if fields.get::<Value>(entry.path.as_str())?.is_nil() {
                fields.set(entry.path.as_str(), entry.message.as_str())?;
            }
            let e = lua.create_table()?;
            e.set("path", entry.path.as_str())?;
            let (part, field) = split_part(&entry.path, &entry.field);
            if let Some(part) = part {
                e.set("part", part)?;
            }
            e.set("field", field)?;
            e.set("rule", entry.rule.as_str())?;
            e.set("message", entry.message.as_str())?;
            if !entry.params.is_empty() {
                let params = lua.create_table()?;
                for (k, v) in &entry.params {
                    params.set(k.as_str(), v.to_lua(lua)?)?;
                }
                e.set("params", params)?;
            }
            if let Some(label) = &entry.label {
                e.set("label", label.as_str())?;
            }
            errors.raw_set(i + 1, e)?;
        }
        err.set("fields", fields)?;
        err.set("errors", errors)?;
        Ok(err)
    }

    /// The same shape as JSON, with `code = "VALIDATION_FAILED"`.
    pub fn to_json(&self) -> serde_json::Value {
        let mut fields = serde_json::Map::new();
        let mut errors = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            fields
                .entry(entry.path.clone())
                .or_insert_with(|| serde_json::Value::String(entry.message.clone()));
            let mut e = serde_json::Map::new();
            e.insert("path".into(), entry.path.clone().into());
            let (part, field) = split_part(&entry.path, &entry.field);
            if let Some(part) = part {
                e.insert("part".into(), part.into());
            }
            e.insert("field".into(), field.into());
            e.insert("rule".into(), entry.rule.clone().into());
            e.insert("message".into(), entry.message.clone().into());
            if let Some(params) = entry.params_json() {
                e.insert("params".into(), params);
            }
            if let Some(label) = &entry.label {
                e.insert("label".into(), label.clone().into());
            }
            errors.push(serde_json::Value::Object(e));
        }
        serde_json::json!({
            "code": "VALIDATION_FAILED",
            "message": self.message,
            "fields": serde_json::Value::Object(fields),
            "errors": errors,
        })
    }
}

/// Splits `body.text` into (`body`, `text`) once the paths carry a part
/// prefix; a bare path has no part.
fn split_part<'a>(path: &'a str, field: &'a str) -> (Option<&'a str>, &'a str) {
    for part in PARTS {
        if path == part {
            return (Some(part), "");
        }
        if let Some(rest) = path.strip_prefix(part)
            && rest.starts_with('.')
        {
            return (Some(part), field);
        }
    }
    (None, field)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, field: &str, rule: &str) -> ErrorEntry {
        ErrorEntry {
            path: path.into(),
            field: field.into(),
            rule: rule.into(),
            message: format!("{rule} failed"),
            params: vec![("min".into(), Param::Num(3.0))],
            label: None,
        }
    }

    #[test]
    fn prefixing_turns_the_root_into_the_part_name() {
        let mut err = ValidationError::single("json", "must be valid JSON");
        err.prefix("body");
        assert_eq!(err.entries[0].path, "body");
        assert_eq!(split_part("body", ""), (Some("body"), ""));
        assert_eq!(split_part("body.a", "a"), (Some("body"), "a"));
        assert_eq!(split_part("bodyguard", "bodyguard"), (None, "bodyguard"));
        assert_eq!(split_part("a", "a"), (None, "a"));
    }

    #[test]
    fn merge_keeps_paths_sorted_and_json_carries_every_field() {
        let mut err = ValidationError {
            message: "validation failed".into(),
            entries: vec![entry("query.b", "b", "min")],
        };
        err.merge(ValidationError {
            message: String::new(),
            entries: vec![entry("body.a", "a", "required")],
        });
        assert_eq!(err.entries[0].path, "body.a");
        let json = err.to_json();
        assert_eq!(json["code"], "VALIDATION_FAILED");
        assert_eq!(json["fields"]["query.b"], "min failed");
        assert_eq!(json["errors"][1]["part"], "query");
        assert_eq!(json["errors"][1]["params"]["min"], 3.0);
    }
}
