// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;

#[tokio::test]
async fn custom_checks_run_last_and_can_normalize() {
    let lua = Lua::new();
    let s = schema_with(
        &lua,
        r#"{
            email = { "string|format:email", transform = function(s) return s:lower() end },
            pw = { "string|min_len:4", description = "not common", check = function(s) return s ~= "hunter22", "is too common" end },
            n = { "integer", description = "even", check = function(n) return n % 2 == 0 end },
        }"#,
        r#"{ checks = { { description = "email is not ada", check = function(t) return t.email ~= "ada@x.io", { email = "is taken" } end } } }"#,
    );
    let (data, err) = check(&lua, &s, r#"{ email = "Bob@X.IO", pw = "abcd", n = 2 }"#).await;
    assert!(err.is_nil(), "{err:?}");
    assert_eq!(data_table(data).get::<String>("email").unwrap(), "bob@x.io");

    let (_, err) = check(&lua, &s, r#"{ email = "x@x.io", pw = "hunter22", n = 3 }"#).await;
    assert_eq!(field(&err, "pw"), "is too common");
    assert_eq!(field(&err, "n"), "is invalid");
    // Schema-level checks wait for every field.
    assert_eq!(
        fields_of(&err).get::<Option<String>>("email").unwrap(),
        None
    );

    let (_, err) = check(&lua, &s, r#"{ email = "ada@X.IO", pw = "abcd", n = 2 }"#).await;
    assert_eq!(field(&err, "email"), "is taken");

    // A value that fails the Rust rules never reaches Lua: the check
    // would raise on a non-string.
    let (_, err) = check(&lua, &s, r#"{ email = 42, pw = "abcd", n = 2 }"#).await;
    assert_eq!(field(&err, "email"), "must be a string");
}

#[tokio::test]
async fn caller_bugs_in_checks_raise_instead_of_failing_the_input() {
    let lua = Lua::new();
    let raise = |def: &str, input: &str| {
        let s = schema(&lua, def);
        let value: Value = lua.load(input).eval().unwrap();
        let f: mlua::Function = s.get("check").unwrap();
        async move {
            f.call_async::<Value>((&s, value))
                .await
                .expect_err("raises")
                .to_string()
        }
    };
    let err = raise(
        r#"{ a = { "string", transform = function() return {} end } }"#,
        r#"{ a = "v" }"#,
    )
    .await;
    assert!(
        err.contains("returned a table, but the field is a `string`"),
        "{err}"
    );
    let err = raise(
        r#"{ a = { "string", description = "x", check = function() return false, 42 end } }"#,
        r#"{ a = "v" }"#,
    )
    .await;
    assert!(err.contains("reason of type integer"), "{err}");
    let err = raise(
        r#"{ a = { "string", description = "x", check = function() return "yes" end } }"#,
        r#"{ a = "v" }"#,
    )
    .await;
    assert!(err.contains("must return true"), "{err}");
    let err = raise(
        r#"{ a = { "string", description = "x", check = function() error("boom") end } }"#,
        r#"{ a = "v" }"#,
    )
    .await;
    assert!(err.contains("boom"), "{err}");

    // A schema check naming an undeclared field is a bug too.
    let s = schema_with(
        &lua,
        r#"{ a = "string" }"#,
        r#"{ checks = { { description = "x", check = function() return false, { nope = "y" } end } } }"#,
    );
    let value: Value = lua.load(r#"{ a = "v" }"#).eval().unwrap();
    let f: mlua::Function = s.get("check").unwrap();
    let err = f
        .call_async::<Value>((&s, value))
        .await
        .expect_err("raises")
        .to_string();
    assert!(err.contains("not a field of the schema"), "{err}");
}

#[tokio::test]
async fn custom_formats_register_once_and_check_in_lua() {
    let lua = Lua::new();
    let validate = validate(&lua);
    let register: mlua::Function = validate.get("format").unwrap();
    let spec: Table = lua
        .load(r#"{ description = "a plate", check = function(s) return s:match("^%u%u%d+$") ~= nil, "must look like AB12" end, pattern = "^[A-Z]{2}[0-9]+$" }"#)
        .eval()
        .unwrap();
    register.call::<()>(("plate", spec.clone())).unwrap();
    let dup = register
        .call::<()>(("plate", spec.clone()))
        .expect_err("dup")
        .to_string();
    assert!(dup.contains("already registered"), "{dup}");
    let builtin = register
        .call::<()>(("email", spec))
        .expect_err("builtin")
        .to_string();
    assert!(builtin.contains("built-in format"), "{builtin}");

    let fields: Table = lua
        .load(r#"{ plate = "string|case:upper|format:plate" }"#)
        .eval()
        .unwrap();
    let s: mlua::AnyUserData = validate
        .get::<mlua::Function>("schema")
        .unwrap()
        .call(fields)
        .unwrap();
    let (data, err) = check(&lua, &s, r#"{ plate = "ab12" }"#).await;
    assert!(err.is_nil(), "{err:?}");
    assert_eq!(data_table(data).get::<String>("plate").unwrap(), "AB12");
    let (_, err) = check(&lua, &s, r#"{ plate = "1234" }"#).await;
    assert_eq!(field(&err, "plate"), "must look like AB12");
    let names: Vec<String> = validate
        .get::<mlua::Function>("formats")
        .unwrap()
        .call(())
        .unwrap();
    assert!(names.contains(&"plate".to_string()) && names.contains(&"email".to_string()));

    // A registered `message` template is the fallback when the check
    // returns no reason.
    let spec: Table = lua
        .load(r#"{ description = "even length", check = function(s) return #s % 2 == 0 end, message = "{label} needs an even length" }"#)
        .eval()
        .unwrap();
    register.call::<()>(("even", spec)).unwrap();
    let fields: Table = lua
        .load(r#"{ code = { "string|format:even", label = "Code" } }"#)
        .eval()
        .unwrap();
    let s: mlua::AnyUserData = validate
        .get::<mlua::Function>("schema")
        .unwrap()
        .call(fields)
        .unwrap();
    let (_, err) = check(&lua, &s, r#"{ code = "abc" }"#).await;
    assert_eq!(field(&err, "code"), "Code needs an even length");
}
