// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;

#[tokio::test]
async fn schemas_compose_and_keep_their_rules() {
    let lua = Lua::new();
    let base = schema_with(
        &lua,
        r#"{ name = "string|required|min_len:1", email = "string|format:email|required", secret = "string" }"#,
        r#"{ title = "User" }"#,
    );
    let partial: mlua::AnyUserData = base.call_method("partial", ()).unwrap();
    let (data, err) = check(&lua, &partial, "{}").await;
    assert!(err.is_nil(), "{err:?}");
    assert!(!data.is_nil());
    let (_, err) = check(&lua, &base, "{}").await;
    assert_eq!(field(&err, "name"), "is required");

    let public: mlua::AnyUserData = base.call_method("omit", vec!["secret", "name"]).unwrap();
    let names: Vec<String> = public.call_method("fields", ()).unwrap();
    assert_eq!(names, vec!["email"]);
    let (_, err) = check(&lua, &public, r#"{ email = "x" }"#).await;
    assert_eq!(field(&err, "email"), "must be an email address");

    let picked: mlua::AnyUserData = base.call_method("pick", vec!["name"]).unwrap();
    let names: Vec<String> = picked.call_method("fields", ()).unwrap();
    assert_eq!(names, vec!["name"]);

    let extra: Table = lua
        .load(r#"{ age = "integer|min:0", secret = false }"#)
        .eval()
        .unwrap();
    let extended: mlua::AnyUserData = base.call_method("extend", extra).unwrap();
    let names: Vec<String> = extended.call_method("fields", ()).unwrap();
    assert_eq!(names, vec!["age", "email", "name"]);

    let err = base
        .call_method::<Value>("pick", vec!["nope"])
        .expect_err("unknown")
        .to_string();
    assert!(err.contains("unknown field `nope`"), "{err}");

    // `with` replaces options; `strict` then reports unknowns.
    let opts: Table = lua
        .load(r#"{ strict = true, title = "Strict" }"#)
        .eval()
        .unwrap();
    let strict: mlua::AnyUserData = base.call_method("with", opts).unwrap();
    let (_, err) = check(
        &lua,
        &strict,
        r#"{ name = "a", email = "a@b.co", extra = 1 }"#,
    )
    .await;
    assert_eq!(field(&err, "extra"), "is not a known field");
}

#[tokio::test]
async fn a_derivation_cannot_drop_a_field_a_group_needs() {
    let lua = Lua::new();
    let base = schema_with(
        &lua,
        r#"{ a = "string", b = "string" }"#,
        r#"{ equal_fields = { { "a", "b" } } }"#,
    );
    let err = base
        .call_method::<Value>("omit", vec!["b"])
        .expect_err("group broken")
        .to_string();
    assert!(err.contains("unknown field `b`"), "{err}");
}

#[tokio::test]
async fn a_compiled_schema_nests_as_a_table_rule() {
    let lua = Lua::new();
    let base = schema(
        &lua,
        r#"{ name = "string|required|min_len:1", email = "string|format:email|required" }"#,
    );
    let validate = validate(&lua);
    lua.globals().set("Base", base).unwrap();
    let fields: Table = lua
        .load(r#"{ user = Base, users = { "array|max_items:2", items = Base } }"#)
        .eval()
        .unwrap();
    let outer: mlua::AnyUserData = validate
        .get::<mlua::Function>("schema")
        .unwrap()
        .call(fields)
        .unwrap();
    let (_, err) = check(
        &lua,
        &outer,
        r#"{ user = { name = "" }, users = { { name = "x", email = "bad" } } }"#,
    )
    .await;
    assert_eq!(field(&err, "user.name"), "must be at least 1 characters");
    assert_eq!(field(&err, "user.email"), "is required");
    assert_eq!(field(&err, "users[1].email"), "must be an email address");
}
