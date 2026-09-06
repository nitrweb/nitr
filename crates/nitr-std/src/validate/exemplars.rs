// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Exemplars for every built-in format: what each must accept and what it
//! must reject. One table, two consumers — the unit test below, which
//! runs under `make test`, and the `validate-formats` fuzz target, which
//! asserts the same table on every input so a validator rewritten to a
//! constant cannot pass. Keeping the table here means a format change
//! fails in the ordinary test run, not first in the nightly fuzz job.

/// Per format: values that **must** be accepted, then values that
/// **must** be rejected. Every entry was read off the implementation in
/// [`super::format`] and each rejected one names a
/// specific way the check could be loosened.
pub const FORMAT_EXEMPLARS: &[(&str, &[&str], &[&str])] = &[
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
    // --- the phase-26 additions: one accept, one attack each -----------
    (
        "ulid",
        &["01ARZ3NDEKTSV4RRFFQ69G5FAV"],
        &[
            "",
            "81ARZ3NDEKTSV4RRFFQ69G5FAV",
            "01ARZ3NDEKTSV4RRFFQ69G5FA",
        ],
    ),
    (
        "domain",
        &["example.co.uk"],
        &["", "localhost", "example.123", "-a.example.com"],
    ),
    (
        "cidr",
        &["10.0.0.0/8", "2001:db8::/32"],
        &["", "10.0.0.0", "10.0.0.0/33", "::1/129", "10.0.0.0/08"],
    ),
    (
        "mac",
        &["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF"],
        &["", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:fg", "aabbccddeeff"],
    ),
    (
        "time",
        &["23:59", "23:59:59", "23:59:59.250"],
        &["", "24:00", "23:60", "9:00", "23:59:60"],
    ),
    (
        "base64url",
        &["aGVsbG8", "aGVsbG8="],
        &["", "aGVs+bG8", "aGVs/bG8", "!!!"],
    ),
    (
        "alpha",
        &["Ada"],
        &["", "Ada1", "Ada Lovelace", "\u{0410}da"],
    ),
    ("numeric", &["00123"], &["", "12a", "-1", "1.5", "\u{FF11}"]),
    (
        "alpha_dash",
        &["ada_lovelace-1"],
        &["", "ada lovelace", "ada.lovelace", "\u{0430}da"],
    ),
    ("lowercase", &["ada", "ada-1 x"], &["", "Ada"]),
    ("uppercase", &["ADA", "ADA-1 X"], &["", "Ada"]),
    ("ascii", &["plain text"], &["", "caf\u{e9}"]),
    (
        "printable",
        &["a b c"],
        &["", "a\tb", "a\nb", "a\u{1b}[31m"],
    ),
    (
        "semver",
        &["1.2.3", "1.2.3-beta.1+build.5"],
        &["", "1.2", "01.2.3", "1.2.3-", "1.2.3-01", "v1.2.3"],
    ),
    (
        "phone",
        &["+14155552671"],
        &[
            "",
            "14155552671",
            "+1",
            "+1 415 555 2671",
            "+1415555267112345",
        ],
    ),
    ("country_code", &["GB"], &["", "gb", "GBR", "G1"]),
    ("currency_code", &["EUR"], &["", "eur", "EURO", "EU"]),
    (
        "language_tag",
        &["en", "en-US", "zh-Hant-TW", "es-419"],
        &["", "english", "en-", "en-US-x", "EN_US"],
    ),
    (
        "credit_card",
        &["4111 1111 1111 1111", "4111-1111-1111-1111"],
        &["", "4111 1111 1111 1112", "1234", "4111111111111111a"],
    ),
    (
        "iban",
        &["GB82WEST12345698765432"],
        &[
            "",
            "GB82WEST12345698765433",
            "gb82west12345698765432",
            "GB82 WEST 1234 5698 7654 32",
        ],
    ),
    (
        "hex_color",
        &["#abc", "#AABBCC", "#ff8800aa"],
        &["", "abc", "#ff88", "#ggg", "#abcd"],
    ),
    (
        "json",
        &["{\"a\":[1,2]}", "[]", "1"],
        &["", "{a:1}", "{\"a\":}", "undefined"],
    ),
    (
        "jwt",
        &["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_", "a.b."],
        &["", "a.b", "a.b.c.d", "a b.c.d", "eyJ+.eyJ.x"],
    ),
];

#[cfg(test)]
mod tests {
    use super::FORMAT_EXEMPLARS;
    use crate::validate::format::{check_format, format_names};

    /// Every advertised format has exemplars, every exemplar names an
    /// advertised format, and each verdict is the one the table says.
    /// All mismatches are reported together.
    #[test]
    fn every_builtin_format_matches_its_exemplars() {
        let names = format_names();
        let mut problems = Vec::new();
        for name in &names {
            if !FORMAT_EXEMPLARS.iter().any(|(n, _, _)| n == name) {
                problems.push(format!("`{name}` has no exemplars"));
            }
        }
        for (name, accept, reject) in FORMAT_EXEMPLARS {
            if !names.contains(name) {
                problems.push(format!(
                    "the table names `{name}`, which format_names() does not"
                ));
                continue;
            }
            for good in *accept {
                if check_format(name, good) != Some(true) {
                    problems.push(format!("`{name}` rejected {good:?}, which it must accept"));
                }
            }
            for bad in *reject {
                if check_format(name, bad) != Some(false) {
                    problems.push(format!("`{name}` accepted {bad:?}, which it must reject"));
                }
            }
        }
        assert!(problems.is_empty(), "\n{}", problems.join("\n"));
    }
}
