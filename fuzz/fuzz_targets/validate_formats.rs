// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The hand-rolled string formats a validation rule can require
//! (`nitr.validate`'s `format = "email" | "uuid" | …`), over the exact
//! text an attacker puts in a request body:
//! `nitr_std::fuzzing::{check_format, format_names}`.
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! value…
//! ```
//!
//! The whole input is the value, NUL bytes included — so a seed is exactly
//! the text it validates and every mutation the fuzzer makes lands in that
//! text. There is deliberately **no format selector**: each check is a
//! single linear pass, so the value is run past *every* name
//! `format_names()` advertises on every run, and a byte naming one of them
//! would only cost each seed and each mutant a prefix that nothing reads.
//! (It did, until this round: the selector was decoded, printed under
//! `NITR_FUZZ_DEBUG`, and never used for anything else.)
//!
//! **Panic yield here is near zero and that is the point.** Every arm is
//! `chars()`/`split()`/`len()`/`is_ascii_*` with no indexing and no
//! arithmetic, so a crash-only target would be a green light that proves
//! nothing: a validator rewritten to `true` — or to `false` — never
//! crashes, and neither does one that quietly starts accepting Unicode
//! confusables. Everything below is therefore semantic.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **The exemplars.** For every format, values that must be accepted
//!   and values that must be rejected, checked on every run. This is the
//!   heart of the target: it is the only thing here that catches
//!   `Format::check` collapsing to a constant, and each rejected exemplar
//!   is a concrete attack string (`javascript:alert(1)` for `url`,
//!   fullwidth digits for `alphanumeric`, an unpadded body for `base64`).
//! * **Every format rejects the empty string.** `hex`, `alphanumeric` and
//!   `slug` all end in `chars().all(…)`, which is *true* for an empty
//!   string, and `base64` decodes `""` to `Ok(vec![])`: the leading
//!   `!value.is_empty()` is the only thing standing between a required
//!   field and a blank one. Dropping it is a one-token edit that no other
//!   assertion here notices.
//! * **`ip` is exactly `ipv4 ∨ ipv6`.** Three parsers, one relation. A
//!   laxer `ip` — accepting a zone id, a port, or surrounding space that
//!   neither narrow form takes — is invisible on its own and loud here.
//! * **`hex` and `uuid` are case-insensitive; `slug` and `alphanumeric`
//!   are ASCII-only.** `is_alphanumeric()` for `is_ascii_alphanumeric()`
//!   is a plausible edit that admits Cyrillic `а` into a value a script
//!   then treats as a safe identifier.
//! * **Structural consequences of an acceptance.** `uuid` implies 36
//!   bytes and four hyphens, `url` implies an `http(s)://` prefix and no
//!   control characters, `email` implies its own domain half passes
//!   `hostname`, `hostname` implies no empty label and no label edged
//!   with a hyphen, `base64` implies a multiple-of-4 length inside the
//!   *standard* alphabet. Each of these is what a caller downstream
//!   assumes: the `base64` one, for instance, fails the moment the engine
//!   is swapped for a URL-safe or padding-indifferent one, which would
//!   let a value through here that the decoder on the other side rejects.
//! * **`check_format` and `format_names` agree.** Every advertised name
//!   resolves, and nothing else does — including the uppercase spelling
//!   of every advertised name, since the lookup is `==` and a rule
//!   written `format = "Email"` must fail loudly rather than silently
//!   validate nothing.
//! * **The verdict is a function of the value alone.** Cheap, and the
//!   only thing that would catch a memo table or a lazily compiled
//!   pattern keyed by the wrong thing.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nitr_fuzz::Input;
use nitr_std::fuzzing::{check_format, format_names};

/// Per format: values that **must** be accepted, then values that
/// **must** be rejected. Every entry was read off the implementation in
/// `nitr-std/src/validate/format.rs` and each rejected one names a
/// specific way the check could be loosened.
const EXEMPLARS: &[(&str, &[&str], &[&str])] = &[
    (
        "email",
        &["user@example.com", "a.b+c@sub.example.co", "x@a.b"],
        &[
            "",
            "user",
            "user@",
            "@example.com",
            // No dot in the domain: `user@localhost` is a real address on
            // a real host and still not what a signup form wants.
            "user@example",
            "user name@example.com",
            "user@exa mple.com",
            "user@-bad.example",
        ],
    ),
    (
        "uuid",
        &[
            "550e8400-e29b-41d4-a716-446655440000",
            "00000000-0000-0000-0000-000000000000",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        ],
        &[
            "",
            "550e8400e29b41d4a716446655440000",
            "550e8400-e29b-41d4-a716-44665544000",
            "550e8400-e29b-41d4-a716-4466554400000",
            "550g8400-e29b-41d4-a716-446655440000",
            "550e8400-e29b-41d4-a716-446655440000-",
        ],
    ),
    (
        "url",
        &[
            "http://example.com",
            "https://example.com/a?b=c#d",
            "http://127.0.0.1:8080/x",
        ],
        &[
            "",
            "example.com",
            "ftp://example.com",
            // The scheme allow-list is the whole point: a rule that says
            // `format = "url"` and then hands the value to a redirect must
            // never see one of these.
            "javascript:alert(1)",
            "data:text/html,<script>",
            "http://",
            "http:///etc/passwd",
            "https://exa mple.com",
            "HTTP://example.com",
        ],
    ),
    (
        "ip",
        &["127.0.0.1", "::1", "2001:db8::1", "0.0.0.0"],
        &["", "256.0.0.1", "localhost", "1.2.3", "::g", "1.2.3.4:80"],
    ),
    (
        "ipv4",
        &["192.168.1.1", "255.255.255.255", "0.0.0.0"],
        &["", "::1", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.4 "],
    ),
    (
        "ipv6",
        &["::1", "2001:db8::8a2e:370:7334", "fe80::1"],
        &["", "127.0.0.1", "gggg::1", ":::1", "2001:db8::1 "],
    ),
    (
        "hostname",
        &[
            "example.com",
            "a",
            "localhost",
            "sub.domain.example.co",
            "xn--bcher-kva.example",
            "1.2.3.4",
        ],
        &[
            "",
            "-bad.example",
            "bad-.example",
            "a..b",
            ".leading",
            "trailing.",
            "exa_mple.com",
            "exa mple.com",
        ],
    ),
    (
        "date",
        &["2020-01-01", "2016-02-29", "1970-01-01"],
        &[
            "",
            // A day that does not exist, and a month that does not: the
            // calendar check, not just the shape.
            "2020-02-30",
            "2020-13-01",
            "not-a-date",
            "2020-01-01T00:00:00Z",
            "2020/01/01",
        ],
    ),
    (
        "datetime",
        &[
            "2020-01-01T00:00:00Z",
            "2020-01-01T00:00:00+01:00",
            "2020-01-01T00:00:00.123Z",
        ],
        &[
            "",
            "2020-01-01",
            "not-a-datetime",
            // RFC 3339 requires an offset; a naive local timestamp is the
            // value that silently means a different instant per reader.
            "2020-01-01T00:00:00",
        ],
    ),
    (
        "hex",
        &["deadbeef", "DEADBEEF", "0", "0123456789abcdefABCDEF"],
        &["", "0x1f", "deadbeeg", "de ad", "-1"],
    ),
    (
        "base64",
        &["AAAA", "aGVsbG8=", "QQ=="],
        &[
            "", "!!!", "A", "AAAAA",
            // Unpadded and URL-safe bodies: both decode fine under a
            // laxer engine, and both are rejected by whatever decodes the
            // value after this check passes it.
            "aGVsbG8", "a-b_", "AAAA=", "AA=A",
        ],
    ),
    (
        "alphanumeric",
        &["abc123", "A", "0", "ABCxyz789"],
        &[
            "",
            "abc-123",
            "abc 123",
            "abc_",
            // Confusables: `is_alphanumeric()` (Unicode) accepts both, and
            // `is_ascii_alphanumeric()` — what the implementation uses —
            // accepts neither.
            "héllo",
            "\u{ff11}\u{ff12}\u{ff13}",
        ],
    ),
    (
        "slug",
        &["hello-world", "a", "a1", "my-post-2020"],
        &[
            "",
            "-lead",
            "trail-",
            "--",
            "Hello",
            "hello_world",
            "hello world",
            "héllo",
        ],
    ),
];

/// The verdict for a name `format_names()` advertises. A `None` here is
/// itself a failure: the two exported functions would disagree about
/// which formats exist.
fn verdict(name: &str, value: &str) -> bool {
    check_format(name, value).unwrap_or_else(|| {
        panic!("format_names() advertises `{name}`, which check_format does not resolve")
    })
}

fuzz_target!(|data: &[u8]| {
    // The value keeps its NUL bytes: it is the only field, and a NUL
    // inside a validated string is exactly the kind of thing that gets
    // truncated somewhere downstream.
    let value = String::from_utf8_lossy(Input::new(data).rest()).into_owned();
    let value = value.as_str();

    let names = format_names();
    assert!(!names.is_empty(), "format_names() is empty");

    if std::env::var_os("NITR_FUZZ_DEBUG").is_some() {
        let verdicts: Vec<(&str, Option<bool>)> = names
            .iter()
            .map(|name| (*name, check_format(name, value)))
            .collect();
        eprintln!("DEBUG value={value:?} verdicts={verdicts:?}");
    }

    // the exemplars, every run
    // Nothing else in this target can tell a working validator from one
    // rewritten to a constant.
    for (name, accept, reject) in EXEMPLARS {
        assert!(
            names.contains(name),
            "the exemplar table names `{name}`, which format_names() does not"
        );
        for good in *accept {
            assert!(
                verdict(name, good),
                "`{name}` rejected {good:?}, which it must accept"
            );
        }
        for bad in *reject {
            assert!(
                !verdict(name, bad),
                "`{name}` accepted {bad:?}, which it must reject"
            );
        }
    }
    // Every format is a *required* format: an empty value is never one of
    // them. Four of the thirteen are one deleted `!value.is_empty()` away
    // from accepting it.
    for name in &names {
        assert!(
            !verdict(name, ""),
            "`{name}` accepted the empty string; a required field would pass blank"
        );
    }

    // the two exported functions agree
    for name in &names {
        assert!(
            check_format(name, value).is_some(),
            "check_format does not resolve the advertised name `{name}`"
        );
        // The lookup is `==`, so a rule written with any other spelling
        // has to fail at rule-compile time rather than validate nothing.
        let shouted = name.to_ascii_uppercase();
        assert!(
            shouted.as_str() == *name || check_format(&shouted, value).is_none(),
            "check_format resolved `{shouted}`, which format_names() does not advertise"
        );
    }
    for unknown in ["", " ", "e-mail", "uuid ", "URL", "regex", "format"] {
        assert!(
            check_format(unknown, value).is_none(),
            "check_format resolved the unknown format `{unknown}`"
        );
    }

    // the fuzzer'value, through every format
    let email = verdict("email", value);
    let uuid = verdict("uuid", value);
    let url = verdict("url", value);
    let ip = verdict("ip", value);
    let ipv4 = verdict("ipv4", value);
    let ipv6 = verdict("ipv6", value);
    let hostname = verdict("hostname", value);
    let hex = verdict("hex", value);
    let base64 = verdict("base64", value);
    let alnum = verdict("alphanumeric", value);
    let slug = verdict("slug", value);

    // `IpAddr` is `Ipv4Addr` or `Ipv6Addr` and nothing else; anything
    // `ip` takes that neither narrow form takes is a laxer parser.
    assert_eq!(
        ip,
        ipv4 || ipv6,
        "`ip`={ip} but ipv4={ipv4} / ipv6={ipv6} for {value:?}"
    );

    // Case folding, both directions at once: uppercasing maps hex digits
    // to hex digits and leaves the hyphens alone, so neither verdict may
    // move.
    for name in ["hex", "uuid"] {
        assert_eq!(
            verdict(name, value),
            verdict(name, &value.to_ascii_uppercase()),
            "`{name}` is not case-insensitive: {value:?} and its uppercase form disagree"
        );
    }

    if hex {
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit()),
            "`hex` accepted {value:?}, which is not all hex digits"
        );
        // Every ASCII hex digit is an ASCII alphanumeric, so one cannot
        // hold without the other.
        assert!(
            alnum,
            "`hex` accepted {value:?} but `alphanumeric` did not; every hex digit is one"
        );
    }
    if alnum {
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric()),
            "`alphanumeric` accepted {value:?}, which holds a non-ASCII-alphanumeric \
             character — Unicode `is_alphanumeric` would, `is_ascii_alphanumeric` must not"
        );
    }
    if slug {
        assert!(
            !value.is_empty()
                && !value.starts_with('-')
                && !value.ends_with('-')
                && value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "`slug` accepted {value:?}, which is not `[a-z0-9-]` with no edge hyphen"
        );
    }
    if uuid {
        assert!(
            value.len() == 36 && value.is_ascii() && value.matches('-').count() == 4,
            "`uuid` accepted {value:?}, which is not 8-4-4-4-12"
        );
    }
    if url {
        assert!(
            value.starts_with("http://") || value.starts_with("https://"),
            "`url` accepted {value:?}, whose scheme is not http(s) — a redirect built \
             from this value would leave the origin"
        );
        assert!(
            !value.contains(|c: char| c.is_whitespace() || c.is_control()),
            "`url` accepted {value:?}, which carries whitespace or a control character"
        );
    }
    if email {
        let (local, domain) = value
            .split_once('@')
            .unwrap_or_else(|| panic!("`email` accepted {value:?}, which has no `@`"));
        assert!(
            !local.is_empty() && local.len() <= 64,
            "`email` accepted {value:?} with the local part {local:?}"
        );
        // The domain half is validated by the same hostname rules, so the
        // two must never disagree about it.
        assert!(
            domain.contains('.') && verdict("hostname", domain),
            "`email` accepted {value:?} whose domain {domain:?} is not a dotted hostname"
        );
    }
    if hostname {
        assert!(
            !value.is_empty() && value.len() <= 253,
            "`hostname` accepted {value:?} of {} bytes",
            value.len()
        );
        assert!(
            !value.starts_with('.') && !value.ends_with('.') && !value.contains(".."),
            "`hostname` accepted {value:?}, which has an empty label"
        );
        for label in value.split('.') {
            assert!(
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "`hostname` accepted {value:?} with the label {label:?}"
            );
        }
    }
    if base64 {
        // Canonical padding into the *standard* alphabet. A URL-safe or
        // padding-indifferent engine would take strings that whatever
        // decodes this value afterwards will refuse.
        assert!(
            !value.is_empty() && value.len() % 4 == 0,
            "`base64` accepted {value:?} of {} bytes, which is not canonically padded",
            value.len()
        );
        assert!(
            value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "`base64` accepted {value:?}, which leaves the standard alphabet"
        );
    }
    if ipv4 || ipv6 {
        assert!(
            value.is_ascii() && !value.contains(char::is_whitespace),
            "an IP address parser accepted {value:?}"
        );
    }

    // the verdict a function of the value
    // Cheap, and the only assertion here that would notice a memo table
    // or a lazily built matcher keyed by anything but the value.
    for name in &names {
        assert_eq!(
            check_format(name, value),
            check_format(name, value),
            "`{name}` gave two verdicts for {value:?}"
        );
    }
});
