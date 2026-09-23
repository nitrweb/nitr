// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;
use mlua::Lua;

fn parse(lua: &Lua, method: &str, path: &str, opts: &str) -> mlua::Result<TestRequest> {
    let opts: mlua::Table = lua.load(opts).eval()?;
    TestRequest::from_lua(method, path, Some(&opts))
}

fn header<'r>(req: &'r TestRequest, name: &str) -> Vec<&'r str> {
    req.headers
        .iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .collect()
}

#[test]
fn query_cookies_and_auth_become_the_request_they_describe() {
    let lua = Lua::new();
    let req = parse(
        &lua,
        "get",
        "/items?sort=asc",
        r#"{ query = { page = 2, tags = { "a", "b" } }, cookies = { theme = "dark", sid = "x1" },
             auth = { basic = { "ann", "secret" } }, remote_addr = "10.0.0.7",
             headers = { ["X-Api-Key"] = "k", accept = { "text/html", "*/*" } } }"#,
    )
    .expect("parse");
    assert_eq!(req.path, "/items?sort=asc&page=2&tags=a&tags=b");
    assert_eq!(header(&req, "cookie"), ["sid=x1; theme=dark"]);
    assert_eq!(header(&req, "authorization"), ["Basic YW5uOnNlY3JldA=="]);
    assert_eq!(header(&req, "x-api-key"), ["k"], "names are lowercased");
    assert_eq!(
        header(&req, "accept"),
        ["text/html", "*/*"],
        "a list repeats the header"
    );
    assert_eq!(req.remote_addr, Some("10.0.0.7:0".parse().expect("addr")));

    let bearer = parse(&lua, "GET", "/", r#"{ auth = { bearer = "t0k" } }"#).expect("bearer");
    assert_eq!(header(&bearer, "authorization"), ["Bearer t0k"]);
}

#[test]
fn a_request_has_exactly_one_body() {
    let lua = Lua::new();
    let err = parse(
        &lua,
        "POST",
        "/",
        r#"{ json = { a = 1 }, form = { b = 2 } }"#,
    )
    .expect_err("two bodies");
    assert!(
        err.to_string().contains("`json` and `form` both given"),
        "got: {err}"
    );
    let err = parse(&lua, "POST", "/", r#"{ body = "x", multipart = {} }"#).expect_err("two");
    assert!(
        err.to_string().contains("`body` and `multipart`"),
        "got: {err}"
    );
}

#[test]
fn a_content_type_the_caller_set_is_kept() {
    let lua = Lua::new();
    for opts in [
        r#"{ headers = { ["content-type"] = "application/vnd.x+json" }, json = { a = 1 } }"#,
        r#"{ headers = { ["Content-Type"] = "application/vnd.x+json" }, form = { a = 1 } }"#,
        r#"{ headers = { ["content-type"] = "application/vnd.x+json" }, multipart = { a = "1" } }"#,
    ] {
        let req = parse(&lua, "POST", "/", opts).expect(opts);
        assert_eq!(
            header(&req, "content-type"),
            ["application/vnd.x+json"],
            "{opts}"
        );
    }
    let req = parse(
        &lua,
        "POST",
        "/",
        r#"{ form = { a = 1, b = { "x", "y" } } }"#,
    )
    .expect("form");
    assert_eq!(
        header(&req, "content-type"),
        ["application/x-www-form-urlencoded"]
    );
    assert_eq!(req.body.as_deref(), Some(&b"a=1&b=x&b=y"[..]));
}

#[test]
fn malformed_options_are_refused_with_the_option_named() {
    let lua = Lua::new();
    for (opts, needle) in [
        (r#"{ remote_addr = "not-an-ip" }"#, "`remote_addr`"),
        (r#"{ timeout = 0 }"#, "`timeout`"),
        (r#"{ timeout = -1 }"#, "`timeout`"),
        (r#"{ timeout = 1/0 }"#, "`timeout`"),
        (r#"{ timeout = 0/0 }"#, "`timeout`"),
        (r#"{ auth = { token = "x" } }"#, "`auth` takes"),
        (
            r#"{ auth = { bearer = "x" }, headers = { authorization = "y" } }"#,
            "one credential",
        ),
        (r#"{ query = { a = { {} } } }"#, "`query` values"),
    ] {
        let err = parse(&lua, "GET", "/", opts).expect_err(opts);
        assert!(err.to_string().contains(needle), "{opts}: {err}");
    }
    // A deep `json` value is a bounded error, never a stack overflow.
    let err = parse(
        &lua,
        "POST",
        "/",
        "local t = {} local cur = t for _ = 1, 200 do cur.x = {} cur = cur.x end return { json = t }",
    )
    .expect_err("deep json");
    assert!(err.to_string().contains("nested deeper"), "got: {err}");
}

#[test]
fn fixtures_resolve_only_to_regular_files_under_the_root() {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("nitr-fixture-{}-{id}", std::process::id()));
    let root = base.join("tests");
    std::fs::create_dir_all(root.join("fixtures/dir")).expect("mkdir");
    std::fs::write(root.join("fixtures/notes.sql"), "SELECT 1;").expect("write");
    std::fs::write(base.join("secret.sql"), "SELECT 2;").expect("write");

    let found = fixture_path(&root, "fixtures/notes.sql").expect("inside");
    assert!(found.ends_with("notes.sql"));
    for (rel, why) in [
        ("../secret.sql", "is not a relative path"),
        ("/etc/passwd", "is not a relative path"),
        ("fixtures/missing.sql", "does not exist"),
        ("fixtures/dir", "is not a regular file"),
        ("", "is not a regular file"),
    ] {
        let err = fixture_path(&root, rel).expect_err(rel);
        assert!(err.to_string().contains(why), "{rel}: {err}");
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(base.join("secret.sql"), root.join("fixtures/link.sql"))
            .expect("symlink");
        let err = fixture_path(&root, "fixtures/link.sql").expect_err("symlink out");
        assert!(err.to_string().contains("outside"), "got: {err}");
    }
    let _ = std::fs::remove_dir_all(&base);
}
