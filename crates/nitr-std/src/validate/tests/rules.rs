// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use super::*;

#[test]
fn formats_accept_and_reject_sensibly() {
    use format::Format;
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

/// Every new format: one accept and one reject per entry.
#[test]
fn the_new_formats_accept_and_reject() {
    use format::Format;
    let cases: &[(Format, &str, &str)] = &[
        (
            Format::Ulid,
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "81ARZ3NDEKTSV4RRFFQ69G5FAV",
        ),
        (Format::Domain, "example.co.uk", "localhost"),
        (Format::Cidr, "10.0.0.0/8", "10.0.0.0/33"),
        (Format::Mac, "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee"),
        (Format::Time, "23:59:59.250", "24:00"),
        (Format::Base64Url, "aGVsbG8", "aGVs+bG8"),
        (Format::Alpha, "Ada", "Ada1"),
        (Format::Numeric, "00123", "12a"),
        (Format::AlphaDash, "ada_lovelace-1", "ada lovelace"),
        (Format::Lowercase, "ada", "Ada"),
        (Format::Uppercase, "ADA", "Ada"),
        (Format::Ascii, "plain", "café"),
        (Format::Printable, "a b c", "a\tb"),
        (Format::Semver, "1.2.3-beta.1+build.5", "01.2.3"),
        (Format::Phone, "+14155552671", "14155552671"),
        (Format::CountryCode, "GB", "gb"),
        (Format::CurrencyCode, "EUR", "EURO"),
        (Format::LanguageTag, "en-Latn-US", "english"),
        (
            Format::CreditCard,
            "4111 1111 1111 1111",
            "4111 1111 1111 1112",
        ),
        (
            Format::Iban,
            "GB82WEST12345698765432",
            "GB82WEST12345698765433",
        ),
        (Format::HexColor, "#ff8800aa", "#ff88"),
        (Format::Json, "{\"a\":[1,2]}", "{a:1}"),
        (
            Format::Jwt,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_",
            "a.b",
        ),
    ];
    for (format, ok, bad) in cases {
        assert!(format.check(ok), "{format:?} should accept {ok}");
        assert!(!format.check(bad), "{format:?} should reject {bad}");
    }
    // Every format in the table parses back to itself.
    for (name, format) in format::FORMATS {
        assert_eq!(Format::parse(name), Some(*format));
        assert_eq!(format.name(), *name);
    }
}

#[tokio::test]
async fn one_of_booleans_and_numeric_kinds() {
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
    )
    .await;
    assert!(err.is_nil(), "unexpected error: {err:?}");
    let data = data_table(data);
    // A false boolean survives (the `nil`-vs-`false` classic).
    assert!(!data.get::<bool>("active").unwrap());
    assert_eq!(data.get::<f64>("score").unwrap(), 7.5);

    let (data, err) = check(
        &lua,
        &s,
        r#"{ role = "root", level = 2.5, score = "high", active = 1 }"#,
    )
    .await;
    assert!(data.is_nil());
    assert_eq!(field(&err, "role"), r#"must be one of: "admin", "user""#);
    assert_eq!(field(&err, "level"), "must be an integer");
    assert_eq!(field(&err, "score"), "must be a number");
    assert_eq!(field(&err, "active"), "must be a boolean");
}

#[tokio::test]
async fn string_rules_transform_then_check() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{
            email = "string|trim|case:lower|format:email|max_len:254",
            code = { type = "string", starts_with = "N-", ends_with = "x", contains = "-", does_not_contain = " " },
            handle = "string|not_one_of:admin,root|len:4",
            terms = { type = "boolean", equals = true },
            due = "string|format:date|after:2030-01-01|before:2030-12-31",
        }"#,
    );
    let (data, err) = check(
        &lua,
        &s,
        r#"{ email = "  Ada@Example.COM ", code = "N-1-x", handle = "abcd", terms = true, due = "2030-06-01" }"#,
    )
    .await;
    assert!(err.is_nil(), "{err:?}");
    assert_eq!(
        data_table(data).get::<String>("email").unwrap(),
        "ada@example.com"
    );

    let (_, err) = check(
        &lua,
        &s,
        r#"{ email = "nope", code = "X-1 x", handle = "root", terms = false, due = "2031-01-01" }"#,
    )
    .await;
    assert_eq!(field(&err, "email"), "must be an email address");
    assert_eq!(field(&err, "code"), "must start with N-");
    assert_eq!(
        field(&err, "handle"),
        r#"must not be one of: "admin", "root""#
    );
    assert_eq!(field(&err, "terms"), "must be true");
    assert_eq!(field(&err, "due"), "must be before 2030-12-31");

    // `after = "now"` reads the clock once.
    let s = schema(&lua, r#"{ due = "string|format:date|after:now" }"#);
    let (_, err) = check(&lua, &s, r#"{ due = "2000-01-01" }"#).await;
    assert_eq!(field(&err, "due"), "must be in the future");
    let (_, err) = check(&lua, &s, r#"{ due = "2999-01-01" }"#).await;
    assert!(err.is_nil(), "{err:?}");
}

#[tokio::test]
async fn number_rules_cover_bounds_steps_and_decimals() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{
            price = "number|exclusive_min:0|multiple_of:0.01|decimals:2",
            qty = "integer|min:1|max:10|multiple_of:5",
            ratio = { type = "number", exclusive_max = 1 },
        }"#,
    );
    let (_, err) = check(&lua, &s, r#"{ price = 0, qty = 3, ratio = 1 }"#).await;
    assert_eq!(field(&err, "price"), "must be greater than 0");
    assert_eq!(field(&err, "qty"), "must be a multiple of 5");
    assert_eq!(field(&err, "ratio"), "must be less than 1");
    let (_, err) = check(&lua, &s, r#"{ price = 1.005 }"#).await;
    assert_eq!(field(&err, "price"), "must be a multiple of 0.01");
    let (data, err) = check(&lua, &s, r#"{ price = 19.99, qty = 10, ratio = 0.5 }"#).await;
    assert!(err.is_nil(), "{err:?}");
    assert!(!data.is_nil());
}

#[tokio::test]
async fn array_rules_cover_unique_and_contains() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{
            tags = { "array|unique|min_items:1|contains_any:a,b", items = "string|format:slug" },
            need = { type = "array", items = { type = "integer" }, contains = 7, contains_all = { 1, 2 } },
        }"#,
    );
    let (_, err) = check(&lua, &s, r#"{ tags = { "x", "x" }, need = { 1 } }"#).await;
    assert_eq!(field(&err, "tags"), "must not contain duplicates");
    assert_eq!(field(&err, "need"), "must include 7");
    let (_, err) = check(&lua, &s, r#"{ tags = { "x" }, need = { 7, 1 } }"#).await;
    assert_eq!(field(&err, "tags"), r#"must include one of: "a", "b""#);
    assert_eq!(field(&err, "need"), "must include all of: 1, 2");
    let (_, err) = check(&lua, &s, r#"{ tags = { "a" }, need = { 7, 1, 2 } }"#).await;
    assert!(err.is_nil(), "{err:?}");
}

#[tokio::test]
async fn maps_any_and_strict_mode() {
    let lua = Lua::new();
    let s = schema_with(
        &lua,
        r#"{
            settings = { "map|max_keys:2", keys = "string|format:alpha_dash", values = "string|max_len:3" },
            meta = { type = "any", max_bytes = 16 },
        }"#,
        r#"{ strict = true }"#,
    );
    let (_, err) = check(
        &lua,
        &s,
        r#"{ settings = { ["a b"] = "x", ok = "toolong" }, meta = { big = "0123456789abcdef" }, titel = 1 }"#,
    )
    .await;
    assert_eq!(
        field(&err, "settings.a b"),
        "must be letters, digits, hyphens or underscores"
    );
    assert_eq!(field(&err, "settings.ok"), "must be at most 3 characters");
    assert_eq!(field(&err, "meta"), "must be at most 16 B in size");
    assert_eq!(field(&err, "titel"), "is not a known field");
    let (data, err) = check(&lua, &s, r#"{ settings = { a = "x" }, meta = { k = 1 } }"#).await;
    assert!(err.is_nil(), "{err:?}");
    let meta: Table = data_table(data).get("meta").unwrap();
    assert_eq!(meta.get::<i64>("k").unwrap(), 1);

    // Strict listing is bounded.
    let mut many = String::from("{");
    for i in 0..40 {
        many.push_str(&format!("k{i} = 1, "));
    }
    many.push('}');
    let (_, err) = check(&lua, &s, &many).await;
    assert_eq!(field(&err, "$"), "has 8 more unknown fields");
}

#[tokio::test]
async fn cross_field_rules_are_attributed_to_the_last_field() {
    let lua = Lua::new();
    let s = schema_with(
        &lua,
        r#"{
            email = "string|format:email", phone = "string|format:phone", phone_cc = "string|format:country_code",
            password = "string|min_len:4|required", password_confirm = "string|required",
            check_in = "string|format:date|required", check_out = "string|format:date|required",
            low = "integer", high = "integer",
        }"#,
        r#"{
            at_least_one = { { "email", "phone", message = "Give us an email or a phone" } },
            mutually_exclusive = { { "email", "phone" } },
            dependent_required = { phone = { "phone_cc" } },
            equal_fields = { { "password", "password_confirm" } },
            ordered = { { "check_in", "check_out" }, { "low", "high" } },
        }"#,
    );
    let (_, err) = check(
        &lua,
        &s,
        r#"{ password = "abcd", password_confirm = "abce", check_in = "2030-03-02", check_out = "2030-03-01", low = 5, high = 5 }"#,
    )
    .await;
    assert_eq!(field(&err, "phone"), "Give us an email or a phone");
    assert_eq!(field(&err, "password_confirm"), "must equal password");
    assert_eq!(field(&err, "check_out"), "must be after check_in");
    assert_eq!(field(&err, "high"), "must be after low");
    let (_, err) = check(
        &lua,
        &s,
        r#"{ email = "a@b.co", phone = "+12345678", password = "abcd", password_confirm = "abcd", check_in = "2030-03-01", check_out = "2030-03-02" }"#,
    )
    .await;
    assert_eq!(
        field(&err, "phone"),
        r#"only one of "email", "phone" may be given"#
    );
    assert_eq!(
        fields_of(&err).get::<Option<String>>("phone_cc").unwrap(),
        None
    );
    let (_, err) = check(
        &lua,
        &s,
        r#"{ phone = "+12345678", password = "abcd", password_confirm = "abcd", check_in = "2030-03-01", check_out = "2030-03-02" }"#,
    )
    .await;
    assert_eq!(field(&err, "phone"), r#"requires "phone_cc""#);
}

/// Lengths count characters, not bytes: an emoji is one, a base letter
/// plus a combining mark is two; `trim` strips Unicode whitespace.
#[tokio::test]
async fn lengths_count_characters_and_trim_strips_unicode_space() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{
            one = { type = "string", min_len = 1, max_len = 1 },
            name = { type = "string", trim = true, min_len = 1 },
        }"#,
    );
    let (data, err) = check(
        &lua,
        &s,
        r#"{ one = "\u{1F44D}", name = "\u{A0}\u{2003}x\u{A0}" }"#,
    )
    .await;
    assert!(err.is_nil(), "unexpected error: {err:?}");
    let data = data_table(data);
    assert_eq!(data.get::<String>("name").unwrap(), "x");
    assert_eq!(data.get::<String>("one").unwrap(), "\u{1F44D}");

    let (data, err) = check(&lua, &s, r#"{ one = "e\u{301}", name = "\u{A0}\u{A0}" }"#).await;
    assert!(data.is_nil());
    assert!(field(&err, "one").contains("at most 1"), "{err:?}");
    assert!(field(&err, "name").contains("at least 1"), "{err:?}");
}

/// The literal rules compare text, so regex metacharacters mean
/// themselves.
#[tokio::test]
async fn literal_rules_take_metacharacters_literally() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{
            a = { type = "string", starts_with = "(", ends_with = "$", contains = ".*", does_not_contain = "[x]" },
            b = { type = "string", starts_with = "^\\d+", ends_with = "|", contains = "?" },
        }"#,
    );
    let (data, err) = check(&lua, &s, r#"{ a = "(hello.*world$", b = "^\\d+ what?|" }"#).await;
    assert!(err.is_nil(), "unexpected error: {err:?}");
    let data = data_table(data);
    assert_eq!(data.get::<String>("a").unwrap(), "(hello.*world$");

    for (input, field_name) in [
        (r#"{ a = "(hello world$", b = "^\\d+?|" }"#, "a"),
        (r#"{ a = "xhello.*$", b = "^\\d+?|" }"#, "a"),
        (r#"{ a = "(a.*[x]$", b = "^\\d+?|" }"#, "a"),
        (r#"{ a = "(.*$", b = "12 what?|" }"#, "b"),
        (r#"{ a = "(.*$", b = "^\\d+ what|" }"#, "b"),
    ] {
        let (data, err) = check(&lua, &s, input).await;
        assert!(data.is_nil(), "{input} passed");
        assert!(!field(&err, field_name).is_empty(), "{input}: {err:?}");
    }
}

/// A CIDR prefix is written one way: `/8`, never `/08` or `/+8`, and `/0`
/// is a prefix too.
#[test]
fn cidr_prefixes_are_canonical() {
    use format::Format;
    for ok in ["0.0.0.0/0", "10.0.0.0/8", "::/0", "2001:db8::/128"] {
        assert!(Format::Cidr.check(ok), "{ok}");
    }
    for bad in [
        "10.0.0.0/08",
        "10.0.0.0/+8",
        "10.0.0.0/8 ",
        "10.0.0.0/",
        "10.0.0.0/00",
        "::/129",
        "10.0.0.0/8/8",
    ] {
        assert!(!Format::Cidr.check(bad), "{bad}");
    }
}

/// JSON arrays and objects both arrive as Lua tables: the rule checks the
/// key shape, or `{"tags":{"admin":true}}` passes as an empty array.
#[tokio::test]
async fn arrays_and_tables_check_their_key_shape() {
    let lua = Lua::new();
    let s = schema(
        &lua,
        r#"{ tags = { "array", items = "string" }, addr = { type = "table", fields = { city = "string" } } }"#,
    );
    let (_, err) = check(&lua, &s, r#"{ tags = { admin = true } }"#).await;
    assert_eq!(field(&err, "tags"), "must be a list");
    let (_, err) = check(&lua, &s, r#"{ tags = { "a", x = 1 } }"#).await;
    assert_eq!(field(&err, "tags"), "must be a list");
    let (_, err) = check(&lua, &s, r#"{ addr = { "Paris" } }"#).await;
    assert_eq!(field(&err, "addr"), "must be an object");
    let (_, err) = check(&lua, &s, r#"{ tags = {}, addr = {} }"#).await;
    assert!(err.is_nil(), "empty is both: {err:?}");
    let (_, err) = check(&lua, &s, r#"{ tags = { "a" }, addr = { city = "Paris" } }"#).await;
    assert!(err.is_nil(), "{err:?}");
}

/// Integers above 2^53 do not survive a trip through `f64`: two distinct
/// ids must stay distinct, while `1` and `1.0` stay equal.
#[tokio::test]
async fn unique_keeps_large_integers_apart() {
    let lua = Lua::new();
    let s = schema(&lua, r#"{ ids = { "array|unique", items = "number" } }"#);
    let (_, err) = check(&lua, &s, "{ ids = { 9007199254740993, 9007199254740992 } }").await;
    assert!(err.is_nil(), "{err:?}");
    let (_, err) = check(&lua, &s, "{ ids = { 1, 1.0 } }").await;
    assert_eq!(field(&err, "ids"), "must not contain duplicates");
}
