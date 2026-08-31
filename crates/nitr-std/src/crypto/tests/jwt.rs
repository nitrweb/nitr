// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr.crypto.jwt` signing and verification.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use mlua::{Lua, Table, Value};

use crate::crypto::create_crypto_table;

#[test]
fn jwt_signs_and_verifies_with_an_allow_list() {
    let lua = Lua::new();
    let crypto = create_crypto_table(&lua).expect("crypto table");
    let jwt: Table = crypto.get("jwt").expect("jwt");
    let sign: mlua::Function = jwt.get("sign").expect("fn");
    let verify: mlua::Function = jwt.get("verify").expect("fn");
    let far_future = 4_000_000_000i64;

    let claims: Table = lua
        .load(format!("{{ sub = \"42\", exp = {far_future} }}"))
        .eval()
        .expect("claims");
    let token: String = sign.call((claims, "s3cret-key")).expect("sign");
    assert_eq!(token.split('.').count(), 3);

    let allow: Table = lua
        .load(r#"{ algorithms = { "HS256" } }"#)
        .eval()
        .expect("opts");
    let (claims, err): (Value, Option<String>) = verify
        .call((token.clone(), "s3cret-key", allow))
        .expect("verify");
    assert_eq!(err, None);
    let Value::Table(claims) = claims else {
        panic!("expected claims table");
    };
    assert_eq!(claims.get::<String>("sub").expect("sub"), "42");

    // Wrong key, tampered payload, algorithm not in the list.
    for (token, key, opts) in [
        (
            token.clone(),
            "wrong-key",
            r#"{ algorithms = { "HS256" } }"#,
        ),
        (
            format!("{token}x"),
            "s3cret-key",
            r#"{ algorithms = { "HS256" } }"#,
        ),
        (
            token.clone(),
            "s3cret-key",
            r#"{ algorithms = { "HS384" } }"#,
        ),
    ] {
        let opts: Table = lua.load(opts).eval().expect("opts");
        let (claims, err): (Value, Option<String>) =
            verify.call((token, key, opts)).expect("verify");
        assert!(claims.is_nil());
        assert!(err.is_some());
    }

    // The allow-list is mandatory, and `none` is not an algorithm.
    let empty: Table = lua.load("{}").eval().expect("opts");
    assert!(
        verify
            .call::<(Value, Value)>((token.clone(), "s3cret-key", empty))
            .is_err()
    );
    let none: Table = lua
        .load(r#"{ algorithms = { "none" } }"#)
        .eval()
        .expect("opts");
    assert!(
        verify
            .call::<(Value, Value)>((token, "s3cret-key", none))
            .is_err()
    );

    // Expired tokens are rejected by default; leeway is opt-in.
    let expired: Table = lua
        .load("{ sub = \"42\", exp = 1000000 }")
        .eval()
        .expect("claims");
    let token: String = sign.call((expired, "s3cret-key")).expect("sign");
    let allow: Table = lua
        .load(r#"{ algorithms = { "HS256" } }"#)
        .eval()
        .expect("opts");
    let (claims, err): (Value, Option<String>) =
        verify.call((token, "s3cret-key", allow)).expect("verify");
    assert!(claims.is_nil());
    assert_eq!(err.as_deref(), Some("token expired"));
}

#[test]
fn jwt_time_claims_honor_nbf_and_leeway() {
    let lua = Lua::new();
    let crypto = create_crypto_table(&lua).expect("crypto table");
    let jwt: Table = crypto.get("jwt").expect("jwt");
    let sign: mlua::Function = jwt.get("sign").expect("fn");
    let verify: mlua::Function = jwt.get("verify").expect("fn");
    let allow = |extra: &str| -> Table {
        lua.load(format!(r#"{{ algorithms = {{ "HS256" }}{extra} }}"#))
            .eval()
            .expect("opts")
    };

    // Not valid yet…
    let future_nbf: Table = lua
        .load("{ sub = \"42\", nbf = 4000000000 }")
        .eval()
        .expect("claims");
    let token: String = sign.call((future_nbf, "key")).expect("sign");
    let (claims, err): (Value, Option<String>) = verify
        .call((token.clone(), "key", allow("")))
        .expect("verify");
    assert!(claims.is_nil());
    assert_eq!(err.as_deref(), Some("token not yet valid"));

    // …unless the caller opts into enough leeway.
    let (claims, err): (Value, Option<String>) = verify
        .call((token, "key", allow(", leeway = 4000000000")))
        .expect("verify");
    assert!(err.is_none(), "got: {err:?}");
    assert!(!claims.is_nil());

    // Leeway also forgives a just-expired token.
    let expired: Table = lua
        .load("{ sub = \"42\", exp = 1000000 }")
        .eval()
        .expect("claims");
    let token: String = sign.call((expired, "key")).expect("sign");
    let (claims, err): (Value, Option<String>) = verify
        .call((token, "key", allow(", leeway = 4000000000")))
        .expect("verify");
    assert!(err.is_none(), "got: {err:?}");
    assert!(!claims.is_nil());
}

#[test]
fn jwt_survives_hostile_tokens_without_panicking() {
    let lua = Lua::new();
    let crypto = create_crypto_table(&lua).expect("crypto table");
    let jwt: Table = crypto.get("jwt").expect("jwt");
    let verify: mlua::Function = jwt.get("verify").expect("fn");
    let allow: Table = lua
        .load(r#"{ algorithms = { "HS256" } }"#)
        .eval()
        .expect("opts");

    // The classic `alg: none` downgrade: a matching header with an
    // empty signature must not verify.
    let none_token = format!(
        "{}.{}.",
        B64URL.encode(r#"{"alg":"none","typ":"JWT"}"#),
        B64URL.encode(r#"{"sub":"42"}"#)
    );

    for hostile in [
        "".to_string(),
        "a".to_string(),
        "a.b".to_string(),
        "a.b.c.d".to_string(),
        "!!!.###.$$$".to_string(),
        "e30.e30.e30".to_string(), // `{}` header: no alg at all
        none_token,
        format!("{}.x.y", B64URL.encode("[1,2]")), // non-object header
        "\u{feff}garbage\u{0000}".to_string(),
    ] {
        let (claims, err): (Value, Option<String>) = verify
            .call((hostile.clone(), "key", &allow))
            .unwrap_or_else(|e| panic!("panicked on {hostile:?}: {e}"));
        assert!(claims.is_nil(), "accepted {hostile:?}");
        assert!(err.is_some(), "no reason for {hostile:?}");
    }
}
