// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::error_page::{error_response, escape_html};
use super::respond::to_response;
use super::*;
use mlua::Lua;

fn eval_table(lua: &Lua, src: &str) -> LuaTable {
    lua.load(src).eval().expect("eval response table")
}

async fn body_bytes(resp: HttpResponse) -> Bytes {
    resp.into_body()
        .collect()
        .await
        .expect("collect")
        .to_bytes()
}

#[tokio::test]
async fn defaults_to_200_and_empty_body() {
    let lua = Lua::new();
    let resp = to_response(eval_table(&lua, "{}")).expect("response");
    assert_eq!(resp.status(), 200);
    assert!(body_bytes(resp).await.is_empty());
}

#[tokio::test]
async fn preserves_binary_bodies() {
    let lua = Lua::new();
    let table = eval_table(
        &lua,
        r#"{ status = 201, body = string.char(0, 255, 1) .. "x" }"#,
    );
    let resp = to_response(table).expect("response");
    assert_eq!(resp.status(), 201);
    assert_eq!(&body_bytes(resp).await[..], &[0, 255, 1, b'x']);
}

#[tokio::test]
async fn supports_multi_value_and_integer_headers() {
    let lua = Lua::new();
    let table = eval_table(
        &lua,
        r#"{
            headers = {
                ["Set-Cookie"] = { "a=1", "b=2" },
                ["X-Limit"] = 42,
                ["Content-Type"] = "text/plain",
            },
        }"#,
    );
    let resp = to_response(table).expect("response");
    let cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().collect();
    assert_eq!(cookies, ["a=1", "b=2"]);
    assert_eq!(resp.headers()["x-limit"], "42");
    assert_eq!(resp.headers()["content-type"], "text/plain");
}

#[tokio::test]
async fn rejects_invalid_headers_gracefully() {
    let lua = Lua::new();
    // Each refusal must name the offending header — a failure for an
    // unrelated reason (a body error, say) would not — and the whole
    // conversion fails, so no partial header set can ever be sent.
    let bad_name = eval_table(&lua, r#"{ headers = { ["bad name"] = "x" } }"#);
    let err = to_response(bad_name).expect_err("space in a header name");
    assert!(err.to_string().contains("bad name"), "got: {err}");

    let bad_type = eval_table(&lua, r#"{ headers = { ok = function() end } }"#);
    let err = to_response(bad_type).expect_err("function as a header value");
    assert!(err.to_string().contains("header `ok`"), "got: {err}");
}

/// CRLF in a header value is response splitting; the unit-level
/// contract (mirroring the end-to-end one in `standards.rs`) is that
/// the conversion fails naming the header — the injected bytes never
/// exist in any response, because no response exists.
#[tokio::test]
async fn header_values_with_crlf_are_refused_not_split() {
    let lua = Lua::new();
    let split = eval_table(
        &lua,
        "{ headers = { [\"X-Evil\"] = \"a\\r\\nInjected: yes\" } }",
    );
    let err = to_response(split).expect_err("CRLF in a header value");
    assert!(
        err.to_string()
            .contains("invalid value for header `x-evil`"),
        "got: {err}"
    );
}

#[test]
fn escape_html_neutralizes_markup_and_quotes() {
    assert_eq!(
        escape_html(r#"<a href="x" onmouseover='y'>&z</a>"#),
        "&lt;a href=&quot;x&quot; onmouseover=&#39;y&#39;&gt;&amp;z&lt;/a&gt;"
    );
    assert_eq!(escape_html("plain text"), "plain text");
}

#[tokio::test]
async fn error_responses_hide_details_unless_dev_mode() {
    let err = Error::Script("secret traceback".into());
    let prod = error_response(&err, false).expect("prod response");
    assert_eq!(prod.status(), 500);
    assert_eq!(&body_bytes(prod).await[..], b"Internal Server Error");

    let dev = error_response(&err, true).expect("dev response");
    let body = body_bytes(dev).await;
    assert!(String::from_utf8_lossy(&body).contains("secret traceback"));
}
