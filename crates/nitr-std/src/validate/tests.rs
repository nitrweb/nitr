// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use mlua::ObjectLike as _;

use super::*;

fn schema(lua: &Lua, def: &str) -> mlua::AnyUserData {
    let validate = create_validate_table(lua).expect("table");
    let fields: Table = lua.load(def).eval().expect("schema table");
    validate
        .get::<mlua::Function>("schema")
        .expect("fn")
        .call(fields)
        .expect("compile")
}

fn check(lua: &Lua, schema: &mlua::AnyUserData, input: &str) -> (Value, Value) {
    let value: Value = lua.load(input).eval().expect("input");
    let f: mlua::Function = schema.get("check").expect("method");
    f.call((schema, value)).expect("check")
}

#[test]
fn valid_input_passes_and_is_stripped_to_declared_fields() {
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
    );
    assert!(err.is_nil(), "unexpected error: {err:?}");
    let Value::Table(data) = data else {
        panic!("expected data table");
    };
    assert_eq!(data.get::<String>("email").unwrap(), "ada@example.com");
    assert_eq!(data.get::<i64>("age").unwrap(), 36);
    // Undeclared fields never pass through.
    assert!(data.get::<Value>("role").unwrap().is_nil());
}

#[test]
fn failures_report_every_field_with_its_path() {
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
    );
    assert!(data.is_nil());
    let Value::Table(err) = err else {
        panic!("expected error table");
    };
    assert_eq!(err.get::<String>("message").unwrap(), "validation failed");
    let fields: Table = err.get("fields").expect("fields");
    assert_eq!(fields.get::<String>("email").unwrap(), "is required");
    assert_eq!(fields.get::<String>("age").unwrap(), "must be >= 0");
    assert_eq!(
        fields.get::<String>("tags[2]").unwrap(),
        "must be at most 4 characters"
    );
    assert_eq!(fields.get::<String>("home.city").unwrap(), "is required");
}

#[test]
fn schema_typos_fail_at_compile_time() {
    let lua = Lua::new();
    let validate = create_validate_table(&lua).expect("table");
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
            r#"{ a = { type = "string", format = "phone" } }"#,
            "unknown format `phone`",
        ),
        (
            r#"{ a = { type = "number", min_len = 2 } }"#,
            "unknown rule `min_len`",
        ),
    ] {
        let fields: Table = lua.load(def).eval().expect("def");
        let err = compile.call::<Value>(fields).expect_err(def).to_string();
        assert!(err.contains(needle), "`{def}` -> {err}");
    }
}

#[test]
fn one_of_booleans_and_numeric_kinds() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{
                role = { type = "string", one_of = { "admin", "user" } },
                level = { type = "integer", one_of = { 1, 2, 3 } },
                score = { type = "number", min = 0 },
                active = { type = "boolean" },
            }"#,
    );

    let (data, err) = check(
        &lua,
        &s,
        r#"{ role = "admin", level = 2, score = 7.5, active = false }"#,
    );
    assert!(err.is_nil(), "unexpected error: {err:?}");
    let Value::Table(data) = data else {
        panic!("expected data table");
    };
    // A false boolean survives (the `nil`-vs-`false` classic).
    assert!(!data.get::<bool>("active").unwrap());
    assert_eq!(data.get::<f64>("score").unwrap(), 7.5);

    let (data, err) = check(
        &lua,
        &s,
        r#"{ role = "root", level = 2.5, score = "high", active = 1 }"#,
    );
    assert!(data.is_nil());
    let Value::Table(err) = err else {
        panic!("expected error table");
    };
    let fields: Table = err.get("fields").expect("fields");
    assert_eq!(
        fields.get::<String>("role").unwrap(),
        r#"must be one of: "admin", "user""#
    );
    assert_eq!(fields.get::<String>("level").unwrap(), "must be an integer");
    assert_eq!(
        fields.get::<String>("score").unwrap(),
        "must be a number, got string"
    );
    assert_eq!(
        fields.get::<String>("active").unwrap(),
        "must be a boolean, got integer"
    );
}

#[test]
fn arrays_of_tables_nest_and_non_table_input_is_reported() {
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

    let (data, err) = check(&lua, &s, r#"{ points = { { x = 1, y = 2 }, { x = 3 } } }"#);
    assert!(data.is_nil());
    let Value::Table(err) = err else {
        panic!("expected error table");
    };
    let fields: Table = err.get("fields").expect("fields");
    assert_eq!(fields.get::<String>("points[2].y").unwrap(), "is required");

    // Non-table input fails with the `$` root marker instead of a
    // Lua error.
    let (data, err) = check(&lua, &s, r#""not a table""#);
    assert!(data.is_nil());
    let Value::Table(err) = err else {
        panic!("expected error table");
    };
    let fields: Table = err.get("fields").expect("fields");
    assert_eq!(
        fields.get::<String>("$").unwrap(),
        "must be a table, got string"
    );
}

#[test]
fn optional_fields_are_simply_absent() {
    let lua = Lua::new();
    let s = schema(&lua, r#"{ nick = { type = "string", min_len = 2 } }"#);
    let (data, err) = check(&lua, &s, "{}");
    assert!(err.is_nil());
    let Value::Table(data) = data else {
        panic!("expected data table");
    };
    assert!(data.get::<Value>("nick").unwrap().is_nil());
    // …but when present, the rules still apply.
    let (data, _) = check(&lua, &s, r#"{ nick = "a" }"#);
    assert!(data.is_nil());
}

#[test]
fn formats_accept_and_reject_sensibly() {
    for (ok, value) in [
        (true, "ada@example.com"),
        (false, "ada@nodot"),
        (false, "@example.com"),
        (false, "two words@example.com"),
    ] {
        assert_eq!(Format::Email.check(value), ok, "email {value}");
    }
    assert!(Format::Uuid.check("0198c5b6-1f6a-7abc-9def-0123456789ab"));
    assert!(!Format::Uuid.check("not-a-uuid"));
    assert!(Format::Url.check("https://example.com/x"));
    assert!(!Format::Url.check("ftp://example.com"));
    assert!(!Format::Url.check("https:///nohost"));
    assert!(Format::Ip.check("192.168.1.1"));
    assert!(Format::Ip.check("::1"));
    assert!(Format::Ipv4.check("10.0.0.1") && !Format::Ipv4.check("::1"));
    assert!(Format::Ipv6.check("2001:db8::1") && !Format::Ipv6.check("10.0.0.1"));
    assert!(Format::Hostname.check("api.example.com"));
    assert!(!Format::Hostname.check("-bad.example.com"));
    assert!(Format::Date.check("2026-08-17") && !Format::Date.check("2026-13-01"));
    assert!(Format::Datetime.check("2026-08-17T10:00:00Z"));
    assert!(!Format::Datetime.check("2026-08-17"));
    assert!(Format::Hex.check("deadBEEF42") && !Format::Hex.check("xyz"));
    assert!(Format::Base64.check("aGVsbG8=") && !Format::Base64.check("!!!"));
    assert!(Format::Alphanumeric.check("abc123") && !Format::Alphanumeric.check("a b"));
    assert!(Format::Slug.check("my-post-42"));
    assert!(!Format::Slug.check("My Post") && !Format::Slug.check("-lead"));
}
