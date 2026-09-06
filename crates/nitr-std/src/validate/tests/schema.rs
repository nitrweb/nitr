// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;

#[tokio::test]
async fn valid_input_passes_and_is_stripped_to_declared_fields() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{
            email = { type = "string", format = "email", required = true },
            age = { type = "integer", min = 0, max = 150 },
            tags = { type = "array", items = { type = "string" }, max_items = 3 },
        }"#,
    );
    let (data, err) = check(
        &lua,
        &s,
        r#"{ email = "ada@example.com", age = 36, tags = {"math"}, role = "admin" }"#,
    )
    .await;
    assert!(err.is_nil(), "unexpected error: {err:?}");
    let data = data_table(data);
    assert_eq!(data.get::<String>("email").unwrap(), "ada@example.com");
    assert_eq!(data.get::<i64>("age").unwrap(), 36);
    // Undeclared fields never pass through.
    assert!(data.get::<Value>("role").unwrap().is_nil());
}

#[tokio::test]
async fn failures_report_every_field_with_its_path_and_rule() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{
            email = { type = "string", format = "email", required = true },
            age = { type = "integer", min = 0 },
            tags = { type = "array", items = { type = "string", max_len = 4 } },
            home = { type = "table", fields = { city = { type = "string", required = true } } },
        }"#,
    );
    let (data, err) = check(
        &lua,
        &s,
        r#"{ age = -3, tags = {"ok", "toolong"}, home = {} }"#,
    )
    .await;
    assert!(data.is_nil());
    assert_eq!(field(&err, "email"), "is required");
    assert_eq!(field(&err, "age"), "must be at least 0");
    assert_eq!(field(&err, "tags[2]"), "must be at most 4 characters");
    assert_eq!(field(&err, "home.city"), "is required");

    let Value::Table(err) = err else {
        panic!("expected error table")
    };
    assert_eq!(err.get::<String>("message").unwrap(), "validation failed");
    let errors: Table = err.get("errors").unwrap();
    // Sorted by path; rule codes and params carried.
    let first: Table = errors.get(1).unwrap();
    assert_eq!(first.get::<String>("path").unwrap(), "age");
    assert_eq!(first.get::<String>("rule").unwrap(), "min");
    assert_eq!(
        first
            .get::<Table>("params")
            .unwrap()
            .get::<i64>("min")
            .unwrap(),
        0
    );
    let second: Table = errors.get(2).unwrap();
    assert_eq!(second.get::<String>("rule").unwrap(), "required");
    assert_eq!(second.get::<String>("field").unwrap(), "email");
}

#[test]
fn schema_typos_fail_at_compile_time() {
    let lua = Lua::new();
    let validate = validate(&lua);
    let compile: mlua::Function = validate.get("schema").expect("fn");

    for (def, needle) in [
        (
            r#"{ a = { type = "string", requird = true } }"#,
            "unknown rule `requird`",
        ),
        (r#"{ a = { required = true } }"#, "missing `type`"),
        (r#"{ a = { type = "text" } }"#, "unknown type `text`"),
        (r#"{ a = { type = "array" } }"#, "requires `items`"),
        (
            r#"{ a = { type = "string", format = "phoen" } }"#,
            "unknown format `phoen`",
        ),
        (
            r#"{ a = { type = "number", min_len = 2 } }"#,
            "unknown rule `min_len`",
        ),
        (
            r#"{ a = { type = "map", values = "string" } }"#,
            "requires `max_keys`",
        ),
        (r#"{ a = { type = "any" } }"#, "requires `max_bytes`"),
        (
            r#"{ a = { type = "integer", min = 5, max = 1 } }"#,
            "`min` is greater than `max`",
        ),
        (
            r#"{ a = { type = "number", multiple_of = 0 } }"#,
            "must be positive",
        ),
        (
            r#"{ a = { type = "string", one_of = { 1, 2 } } }"#,
            "can never equal",
        ),
        (
            r#"{ a = { type = "string", after = "2020-01-01" } }"#,
            "needs `format = \"date\"",
        ),
        (
            r#"{ a = { type = "string", check = function() end } }"#,
            "needs a `description`",
        ),
        (
            r#"{ a = { type = "string", message = "{value} is bad" } }"#,
            "unknown placeholder `{value}`",
        ),
        (
            r#"{ a = { type = "string", messages = { requird = "x" } } }"#,
            "unknown rule `requird`",
        ),
        (r#"{ a = "strin|min_len:1" }"#, "unknown type `strin`"),
        (r#"{ a = "string|min_len" }"#, "needs a value"),
        (r#"{ ["a.b"] = "string" }"#, "not a valid field name"),
    ] {
        let fields: Table = lua.load(def).eval().expect("def");
        let err = compile.call::<Value>(fields).expect_err(def).to_string();
        assert!(err.contains(needle), "`{def}` -> {err}");
    }
}

#[test]
fn schema_nesting_is_bounded() {
    let lua = Lua::new();
    let validate = validate(&lua);
    let compile: mlua::Function = validate.get("schema").expect("fn");
    let mut def = String::from(r#"{ type = "string" }"#);
    for _ in 0..40 {
        def = format!(r#"{{ type = "array", items = {def} }}"#);
    }
    let fields: Table = lua.load(format!("{{ a = {def} }}")).eval().expect("def");
    let err = compile.call::<Value>(fields).expect_err("deep").to_string();
    assert!(err.contains("nested deeper than 32 levels"), "{err}");
}

#[tokio::test]
async fn arrays_of_tables_nest_and_non_table_input_is_reported() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{
            points = {
                type = "array",
                items = { type = "table", fields = {
                    x = { type = "number", required = true },
                    y = { type = "number", required = true },
                } },
            },
        }"#,
    );

    let (data, err) = check(&lua, &s, r#"{ points = { { x = 1, y = 2 }, { x = 3 } } }"#).await;
    assert!(data.is_nil());
    assert_eq!(field(&err, "points[2].y"), "is required");

    // Non-table input fails with the `$` root marker instead of a Lua
    // error.
    let (data, err) = check(&lua, &s, r#""not a table""#).await;
    assert!(data.is_nil());
    assert_eq!(field(&err, "$"), "must be an object");
}

#[tokio::test]
async fn optional_fields_are_simply_absent() {
    let lua = Lua::new();
    let s = schema(&lua, r#"{ nick = { type = "string", min_len = 2 } }"#);
    let (data, err) = check(&lua, &s, "{}").await;
    assert!(err.is_nil());
    assert!(data_table(data).get::<Value>("nick").unwrap().is_nil());
    // …but when present, the rules still apply.
    let (data, _) = check(&lua, &s, r#"{ nick = "a" }"#).await;
    assert!(data.is_nil());
}
