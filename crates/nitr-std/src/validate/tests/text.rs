// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;

fn pairs(raw: &[(&str, &str)]) -> Vec<(String, TextValue)> {
    raw.iter()
        .map(|(k, v)| ((*k).to_string(), TextValue::Text((*v).to_string())))
        .collect()
}

fn query_schema(lua: &Lua) -> CompiledSchema {
    let fields: Table = lua
        .load(
            r#"{
                limit = "integer|min:1|max:100|default:20",
                offset = "integer|min:0|default:0",
                on = "boolean|default:false",
                q = "string|trim",
                tags = { "array|max_items:3", items = "string|format:slug" },
                age = "integer",
            }"#,
        )
        .eval()
        .unwrap();
    compile_text_schema(lua, Value::Table(fields), "query").unwrap()
}

#[tokio::test]
async fn text_input_is_coerced_by_the_schema() {
    let lua = Lua::new();
    let schema = query_schema(&lua);
    let data = schema
        .check_text(
            &lua,
            pairs(&[
                ("on", "on"),
                ("tags[]", "a"),
                ("tags[]", "b"),
                ("age", ""),
                ("q", " x "),
            ]),
            None,
        )
        .await
        .unwrap()
        .expect("valid");
    assert_eq!(data.get::<i64>("limit").unwrap(), 20);
    assert_eq!(data.get::<i64>("offset").unwrap(), 0);
    assert!(data.get::<bool>("on").unwrap());
    assert_eq!(data.get::<String>("q").unwrap(), "x");
    assert!(data.get::<Value>("age").unwrap().is_nil());
    let tags: Table = data.get("tags").unwrap();
    assert_eq!(tags.raw_len(), 2);
}

#[tokio::test]
async fn text_that_does_not_parse_fails_the_type_rule() {
    let lua = Lua::new();
    let schema = query_schema(&lua);
    let err = schema
        .check_text(
            &lua,
            pairs(&[
                ("limit", "1e3"),
                ("offset", "-1"),
                ("on", "maybe"),
                ("tags", "Bad Tag"),
            ]),
            None,
        )
        .await
        .unwrap()
        .expect_err("invalid");
    let by_path = |p: &str| {
        err.entries
            .iter()
            .find(|e| e.path == p)
            .map(|e| (e.rule.clone(), e.message.clone()))
            .unwrap_or_else(|| panic!("no error for {p}: {:?}", err.entries))
    };
    assert_eq!(
        by_path("limit"),
        ("type".into(), "must be an integer".into())
    );
    assert_eq!(
        by_path("offset"),
        ("min".into(), "must be at least 0".into())
    );
    assert_eq!(by_path("on"), ("type".into(), "must be a boolean".into()));
    assert_eq!(by_path("tags[1]").0, "format");

    // Last value wins for scalars, like `req.query`.
    let data = schema
        .check_text(&lua, pairs(&[("limit", "5"), ("limit", "6")]), None)
        .await
        .unwrap()
        .expect("valid");
    assert_eq!(data.get::<i64>("limit").unwrap(), 6);

    // Nested kinds cannot ride on text.
    let fields: Table = lua
        .load(r#"{ a = { type = "any", max_bytes = 1 } }"#)
        .eval()
        .unwrap();
    let err = compile_text_schema(&lua, Value::Table(fields), "query")
        .expect_err("nested")
        .to_string();
    assert!(err.contains("text input cannot carry"), "{err}");
}

#[tokio::test]
async fn blank_strings_are_values_and_blank_numbers_are_absent() {
    let lua = Lua::new();
    let fields: Table = lua
        .load(r#"{ name = "string|min_len:1", age = "integer", nick = "string" }"#)
        .eval()
        .unwrap();
    let schema = compile_text_schema(&lua, Value::Table(fields), "form").unwrap();
    let err = schema
        .check_text(&lua, pairs(&[("name", ""), ("age", " ")]), None)
        .await
        .unwrap()
        .expect_err("name is blank");
    assert_eq!(err.entries.len(), 1);
    assert_eq!(err.entries[0].path, "name");
    let data = schema
        .check_text(&lua, pairs(&[("nick", "")]), None)
        .await
        .unwrap()
        .expect("valid");
    assert_eq!(data.get::<String>("nick").unwrap(), "");
}

#[tokio::test]
async fn the_error_shape_prefixes_parts_and_serializes() {
    let lua = Lua::new();
    let fields: Table = lua.load(r#"{ a = "string|required" }"#).eval().unwrap();
    let schema = compile_schema(&lua, Value::Table(fields), "body").unwrap();
    let mut err = schema
        .check(&lua, Value::Table(lua.create_table().unwrap()), None)
        .await
        .unwrap()
        .expect_err("invalid");
    err.prefix("body");
    assert_eq!(err.entries[0].path, "body.a");
    let json = err.to_json();
    assert_eq!(json["code"], "VALIDATION_FAILED");
    assert_eq!(json["fields"]["body.a"], "is required");
    assert_eq!(json["errors"][0]["part"], "body");
    assert_eq!(json["errors"][0]["field"], "a");
    assert_eq!(json["errors"][0]["rule"], "required");
    let table = err.to_lua(&lua).unwrap();
    let errors: Table = table.get("errors").unwrap();
    let first: Table = errors.get(1).unwrap();
    assert_eq!(first.get::<String>("part").unwrap(), "body");

    // A compiled schema value and a plain field table compile alike; a
    // wrong value names the site.
    let ud = schema_with(&lua, r#"{ a = "string" }"#, r#"{ title = "T" }"#);
    assert_eq!(
        compile_schema(&lua, Value::UserData(ud), "body")
            .unwrap()
            .field_names(),
        vec!["a"]
    );
    let err = compile_schema(&lua, Value::Integer(1), "input.body")
        .expect_err("bad")
        .to_string();
    assert!(err.contains("input.body must be a schema"), "{err}");
}
