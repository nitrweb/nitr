// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;

#[test]
fn presets_expand_to_plain_tables_that_compile() {
    let lua = Lua::new();
    let validate = validate(&lua);
    let image: mlua::Function = validate.get("image").unwrap();
    let opts: Table = lua
        .load(r#"{ max_bytes = "2mb", max_width = 4000 }"#)
        .eval()
        .unwrap();
    let rule: Table = image.call(opts).unwrap();
    assert_eq!(rule.get::<String>("type").unwrap(), "file");
    assert_eq!(rule.get::<String>("max_bytes").unwrap(), "2mb");
    assert_eq!(rule.get::<i64>("max_width").unwrap(), 4000);
    let exts: Vec<String> = rule.get("extensions").unwrap();
    assert!(exts.contains(&"jpeg".to_string()) && !exts.contains(&"svg".to_string()));

    let compile: mlua::Function = validate.get("schema").unwrap();
    for name in [
        "image",
        "document",
        "spreadsheet",
        "text_file",
        "archive",
        "audio",
        "font",
    ] {
        let preset: mlua::Function = validate.get(name).unwrap();
        let rule: Table = preset.call(()).unwrap();
        let fields = lua.create_table().unwrap();
        fields.set("f", rule).unwrap();
        let s: mlua::AnyUserData = compile
            .call(fields)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            s.borrow::<LuaSchema>().unwrap().0.has_file_rules(),
            "{name}"
        );
    }
    // text_file is UTF-8 by default.
    let text: mlua::Function = validate.get("text_file").unwrap();
    let rule: Table = text.call(()).unwrap();
    assert!(rule.get::<bool>("utf8").unwrap());

    let any: mlua::Function = validate.get("any_file").unwrap();
    let err = any.call::<Value>(()).expect_err("needs max").to_string();
    assert!(err.contains("needs `max_bytes`"), "{err}");
    let opts: Table = lua.load(r#"{ max_bytes = 10 }"#).eval().unwrap();
    let rule: Table = any.call(opts).unwrap();
    let types: Vec<String> = rule.get("types").unwrap();
    assert_eq!(types, vec!["*/*"]);
}

#[test]
fn media_types_are_listed_as_data() {
    let lua = Lua::new();
    let validate = validate(&lua);
    let list: Table = validate
        .get::<mlua::Function>("media_types")
        .unwrap()
        .call(())
        .unwrap();
    let pdf: Table = list.get("application/pdf").unwrap();
    assert_eq!(pdf.get::<String>("tier").unwrap(), "detected");
    assert_eq!(pdf.get::<String>("family").unwrap(), "document");
    let exts: Vec<String> = pdf.get("extensions").unwrap();
    assert_eq!(exts, vec!["pdf"]);
}
