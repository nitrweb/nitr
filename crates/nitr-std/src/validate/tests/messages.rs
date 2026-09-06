// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;

#[tokio::test]
async fn messages_resolve_from_the_most_specific_level() {
    let lua = Lua::new();
    let validate = validate(&lua);
    let messages: mlua::Function = validate.get("messages").unwrap();
    let app: Table = lua
        .load(r#"{ required = "Required!", summary = "Please fix the form" }"#)
        .eval()
        .unwrap();
    messages.call::<()>(app).unwrap();

    let s = schema_with(
        &lua,
        r#"{
            a = { "string|required|min_len:3", messages = { required = "Field {label} is needed" }, label = "A" },
            b = { "string|required|min_len:3", message = "{label} wants {min}+ characters" },
            c = "string|required",
            d = "integer|required|max:5",
        }"#,
        r#"{ messages = { max = "Too big: max {max}" } }"#,
    );
    let (_, err) = check(&lua, &s, r#"{ b = "x", d = 9 }"#).await;
    assert_eq!(field(&err, "a"), "Field A is needed"); // field per rule
    assert_eq!(field(&err, "b"), "b wants 3+ characters"); // field-wide
    assert_eq!(field(&err, "c"), "Required!"); // app-wide
    assert_eq!(field(&err, "d"), "Too big: max 5"); // schema per rule
    let Value::Table(err) = err else {
        panic!("expected error table")
    };
    assert_eq!(err.get::<String>("message").unwrap(), "Please fix the form");
    let errors: Table = err.get("errors").unwrap();
    let a: Table = errors.get(1).unwrap();
    assert_eq!(a.get::<String>("label").unwrap(), "A");

    // Frozen after load: a later call raises.
    freeze_messages(&lua);
    let again: Table = lua.load(r#"{ required = "x" }"#).eval().unwrap();
    let err = messages.call::<()>(again).expect_err("frozen").to_string();
    assert!(err.contains("must be called at load"), "{err}");
}

/// Every rule code in the default table renders a sentence, and the
/// placeholders it exposes are the ones the templates may use.
#[test]
fn every_rule_code_has_a_default_and_its_placeholders() {
    use std::collections::BTreeMap;
    for rule in message::RULE_CODES {
        let mut params = BTreeMap::new();
        for name in message::rule_params(rule) {
            params.insert(*name, message::Param::Num(1.0));
        }
        let text = message::default_message(rule, "string", &params);
        assert!(
            !text.is_empty() && !text.contains("failed the"),
            "{rule}: {text}"
        );
        // A template naming exactly the rule's placeholders compiles.
        let template: String = message::rule_params(rule)
            .iter()
            .map(|p| format!("{{{p}}}"))
            .collect::<Vec<_>>()
            .join(" ");
        message::Template::compile(&template, message::rule_params(rule), rule).unwrap();
    }
    // `now` bounds read as time, not as a literal.
    let now = BTreeMap::from([("limit", message::Param::Str("now".into()))]);
    assert_eq!(
        message::default_message("after", "string", &now),
        "must be in the future"
    );
}

#[tokio::test]
async fn reasons_are_capped_and_sanitized() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{ a = { "string", description = "x", check = function() return false, string.rep("y", 1000) .. "\n\27[31m" end } }"#,
    );
    let (_, err) = check(&lua, &s, r#"{ a = "v" }"#).await;
    let msg = field(&err, "a");
    assert_eq!(msg.chars().count(), 200);
    assert!(!msg.contains('\n') && !msg.contains('\u{1b}'));
}

#[test]
fn templates_are_bounded_and_plain() {
    let lua = Lua::new();
    let validate = validate(&lua);
    let compile: mlua::Function = validate.get("schema").unwrap();
    let long = "x".repeat(600);
    let fields: Table = lua
        .load(format!(
            r#"{{ a = {{ "string|required", message = "{long}" }} }}"#
        ))
        .eval()
        .unwrap();
    let err = compile.call::<Value>(fields).expect_err("long").to_string();
    assert!(err.contains("longer than 500 characters"), "{err}");
    let fields: Table = lua
        .load(r#"{ a = { "string|required", message = "a\nb" } }"#)
        .eval()
        .unwrap();
    let err = compile
        .call::<Value>(fields)
        .expect_err("control")
        .to_string();
    assert!(err.contains("control character"), "{err}");
}
