// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The string formats a rule can require: one careful, dependency-free
//! Rust implementation each, plus the per-state registry of formats a
//! script defines itself (`nitr.validate.format`).

use std::collections::HashMap;
use std::sync::Arc;

use super::message::Template;

/// String formats with one careful, dependency-free Rust implementation
/// each: syntactic sanity checks, not full RFC validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Email,
    Uuid,
    Ulid,
    Url,
    Domain,
    Ip,
    Ipv4,
    Ipv6,
    Cidr,
    Mac,
    Hostname,
    Date,
    Datetime,
    Time,
    Hex,
    Base64,
    Base64Url,
    Alphanumeric,
    Alpha,
    Numeric,
    AlphaDash,
    Lowercase,
    Uppercase,
    Ascii,
    Printable,
    Slug,
    Semver,
    Phone,
    CountryCode,
    CurrencyCode,
    LanguageTag,
    CreditCard,
    Iban,
    HexColor,
    Json,
    Jwt,
}

/// Every recognized format, for the compile-time error message and the
/// `nitr.validate.formats()` listing.
pub(super) const FORMATS: &[(&str, Format)] = &[
    ("alpha", Format::Alpha),
    ("alpha_dash", Format::AlphaDash),
    ("alphanumeric", Format::Alphanumeric),
    ("ascii", Format::Ascii),
    ("base64", Format::Base64),
    ("base64url", Format::Base64Url),
    ("cidr", Format::Cidr),
    ("country_code", Format::CountryCode),
    ("credit_card", Format::CreditCard),
    ("currency_code", Format::CurrencyCode),
    ("date", Format::Date),
    ("datetime", Format::Datetime),
    ("domain", Format::Domain),
    ("email", Format::Email),
    ("hex", Format::Hex),
    ("hex_color", Format::HexColor),
    ("hostname", Format::Hostname),
    ("iban", Format::Iban),
    ("ip", Format::Ip),
    ("ipv4", Format::Ipv4),
    ("ipv6", Format::Ipv6),
    ("json", Format::Json),
    ("jwt", Format::Jwt),
    ("language_tag", Format::LanguageTag),
    ("lowercase", Format::Lowercase),
    ("mac", Format::Mac),
    ("numeric", Format::Numeric),
    ("phone", Format::Phone),
    ("printable", Format::Printable),
    ("semver", Format::Semver),
    ("slug", Format::Slug),
    ("time", Format::Time),
    ("ulid", Format::Ulid),
    ("uppercase", Format::Uppercase),
    ("url", Format::Url),
    ("uuid", Format::Uuid),
];

/// Checks `value` against the named built-in format, for the
/// `validate-formats` fuzz target: `None` when no such format exists,
/// else the verdict.
///
/// A function rather than a `pub` [`Format`] so the hand-rolled
/// validators can be fuzzed without making the enum — and a doc comment
/// per variant — part of any public surface.
#[doc(hidden)]
pub fn check_format(name: &str, value: &str) -> Option<bool> {
    Format::parse(name).map(|format| format.check(value))
}

/// Every built-in format name [`check_format`] accepts.
#[doc(hidden)]
pub fn format_names() -> Vec<&'static str> {
    FORMATS.iter().map(|(name, _)| *name).collect()
}

/// One DNS label: 1–63 chars, alphanumeric plus inner hyphens.
fn is_hostname_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

fn is_hostname(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(is_hostname_label)
}

/// Luhn checksum over a digit string.
fn luhn(digits: &str) -> bool {
    let mut sum = 0u32;
    for (i, c) in digits.chars().rev().enumerate() {
        let Some(d) = c.to_digit(10) else {
            return false;
        };
        let d = if i % 2 == 1 {
            let doubled = d * 2;
            if doubled > 9 { doubled - 9 } else { doubled }
        } else {
            d
        };
        sum += d;
    }
    sum.is_multiple_of(10)
}

/// IBAN mod-97: rotate the first four characters to the end, map letters
/// to `10..35`, and reduce iteratively so the number never overflows.
fn iban_mod97(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 5 {
        return false;
    }
    let rotated = bytes[4..].iter().chain(bytes[..4].iter());
    let mut rem: u32 = 0;
    for &b in rotated {
        let piece: u32 = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'A'..=b'Z' => u32::from(b - b'A') + 10,
            _ => return false,
        };
        rem = if piece >= 10 {
            (rem * 100 + piece) % 97
        } else {
            (rem * 10 + piece) % 97
        };
    }
    rem == 1
}

/// A semver numeric identifier: digits without a leading zero.
fn semver_numeric(part: &str) -> bool {
    !part.is_empty()
        && part.bytes().all(|b| b.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'))
}

/// A semver prerelease or build identifier chain (`alpha.1`, `build.5`).
fn semver_identifiers(part: &str, prerelease: bool) -> bool {
    !part.is_empty()
        && part.split('.').all(|id| {
            !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && (!prerelease || !id.bytes().all(|b| b.is_ascii_digit()) || semver_numeric(id))
        })
}

fn is_semver(value: &str) -> bool {
    let (core, build) = match value.split_once('+') {
        Some((core, build)) => (core, Some(build)),
        None => (value, None),
    };
    let (core, pre) = match core.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (core, None),
    };
    let mut parts = core.split('.');
    let ok = matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(a), Some(b), Some(c), None) if semver_numeric(a) && semver_numeric(b) && semver_numeric(c)
    );
    ok && pre.is_none_or(|p| semver_identifiers(p, true))
        && build.is_none_or(|b| semver_identifiers(b, false))
}

fn is_language_tag(value: &str) -> bool {
    let mut parts = value.split('-');
    let Some(lang) = parts.next() else {
        return false;
    };
    if !(2..=3).contains(&lang.len()) || !lang.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    let is_region = |p: &str| {
        (p.len() == 2 && p.bytes().all(|b| b.is_ascii_alphabetic()))
            || (p.len() == 3 && p.bytes().all(|b| b.is_ascii_digit()))
    };
    let is_script = |p: &str| p.len() == 4 && p.bytes().all(|b| b.is_ascii_alphabetic());
    match (parts.next(), parts.next(), parts.next()) {
        (None, _, _) => true,
        (Some(second), None, _) => is_script(second) || is_region(second),
        (Some(second), Some(third), None) => is_script(second) && is_region(third),
        _ => false,
    }
}

fn is_base64url(value: &str) -> bool {
    use base64::Engine as _;
    let trimmed = value.trim_end_matches('=');
    !trimmed.is_empty()
        && base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(trimmed)
            .is_ok()
}

impl Format {
    pub(super) fn parse(name: &str) -> Option<Self> {
        FORMATS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, format)| *format)
    }

    /// The configuration name of the format.
    pub(super) fn name(self) -> &'static str {
        FORMATS
            .iter()
            .find(|(_, f)| *f == self)
            .map(|(n, _)| *n)
            .unwrap_or("format")
    }

    pub(super) fn check(self, value: &str) -> bool {
        match self {
            Self::Email => {
                let Some((local, domain)) = value.split_once('@') else {
                    return false;
                };
                !local.is_empty()
                    && local.len() <= 64
                    && domain.contains('.')
                    && is_hostname(domain)
                    && !local.contains(|c: char| c.is_whitespace() || c.is_control())
            }
            Self::Uuid => {
                let groups: Vec<&str> = value.split('-').collect();
                groups.len() == 5
                    && groups
                        .iter()
                        .zip([8usize, 4, 4, 4, 12])
                        .all(|(g, len)| g.len() == len && g.chars().all(|c| c.is_ascii_hexdigit()))
            }
            Self::Ulid => {
                const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
                value.len() == 26
                    && value
                        .bytes()
                        .next()
                        .is_some_and(|b| (b'0'..=b'7').contains(&b))
                    && value
                        .bytes()
                        .all(|b| ALPHABET.contains(&b.to_ascii_uppercase()))
            }
            Self::Url => {
                let rest = value
                    .strip_prefix("http://")
                    .or_else(|| value.strip_prefix("https://"));
                matches!(rest, Some(rest) if !rest.is_empty() && !rest.starts_with('/'))
                    && !value.contains(|c: char| c.is_whitespace() || c.is_control())
            }
            Self::Domain => {
                is_hostname(value)
                    && value.matches('.').count() >= 1
                    && value
                        .rsplit('.')
                        .next()
                        .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_alphabetic()))
            }
            Self::Ip => value.parse::<std::net::IpAddr>().is_ok(),
            Self::Ipv4 => value.parse::<std::net::Ipv4Addr>().is_ok(),
            Self::Ipv6 => value.parse::<std::net::Ipv6Addr>().is_ok(),
            Self::Cidr => {
                let Some((ip, prefix_text)) = value.split_once('/') else {
                    return false;
                };
                let Ok(prefix) = prefix_text.parse::<u8>() else {
                    return false;
                };
                // The prefix is written the one canonical way: no leading
                // zero, no sign (`u8::parse` takes `+8`).
                if prefix.to_string() != prefix_text {
                    return false;
                }
                match ip.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V4(_)) => prefix <= 32,
                    Ok(std::net::IpAddr::V6(_)) => prefix <= 128,
                    Err(_) => false,
                }
            }
            Self::Mac => {
                let sep = if value.contains(':') { ':' } else { '-' };
                let groups: Vec<&str> = value.split(sep).collect();
                groups.len() == 6
                    && groups
                        .iter()
                        .all(|g| g.len() == 2 && g.chars().all(|c| c.is_ascii_hexdigit()))
            }
            Self::Hostname => is_hostname(value),
            Self::Date => chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok(),
            Self::Datetime => chrono::DateTime::parse_from_rfc3339(value).is_ok(),
            Self::Time => parse_time(value).is_some(),
            Self::Hex => !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit()),
            Self::Base64 => {
                use base64::Engine as _;
                !value.is_empty()
                    && base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .is_ok()
            }
            Self::Base64Url => is_base64url(value),
            Self::Alphanumeric => {
                !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric())
            }
            Self::Alpha => !value.is_empty() && value.chars().all(|c| c.is_ascii_alphabetic()),
            Self::Numeric => !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()),
            Self::AlphaDash => {
                !value.is_empty()
                    && value
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            }
            Self::Lowercase => !value.is_empty() && !value.chars().any(char::is_uppercase),
            Self::Uppercase => !value.is_empty() && !value.chars().any(char::is_lowercase),
            Self::Ascii => !value.is_empty() && value.is_ascii(),
            Self::Printable => !value.is_empty() && !value.chars().any(char::is_control),
            Self::Slug => {
                !value.is_empty()
                    && value
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && !value.starts_with('-')
                    && !value.ends_with('-')
            }
            Self::Semver => is_semver(value),
            Self::Phone => {
                let Some(digits) = value.strip_prefix('+') else {
                    return false;
                };
                (8..=15).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
            }
            Self::CountryCode => value.len() == 2 && value.bytes().all(|b| b.is_ascii_uppercase()),
            Self::CurrencyCode => value.len() == 3 && value.bytes().all(|b| b.is_ascii_uppercase()),
            Self::LanguageTag => is_language_tag(value),
            Self::CreditCard => {
                let digits: String = value.chars().filter(|c| *c != ' ' && *c != '-').collect();
                (12..=19).contains(&digits.len())
                    && digits.bytes().all(|b| b.is_ascii_digit())
                    && luhn(&digits)
            }
            Self::Iban => {
                (15..=34).contains(&value.len())
                    && value.bytes().take(2).all(|b| b.is_ascii_uppercase())
                    && value.bytes().skip(2).take(2).all(|b| b.is_ascii_digit())
                    && value.bytes().all(|b| b.is_ascii_alphanumeric())
                    && iban_mod97(value)
            }
            Self::HexColor => value.strip_prefix('#').is_some_and(|hex| {
                matches!(hex.len(), 3 | 6 | 8) && hex.chars().all(|c| c.is_ascii_hexdigit())
            }),
            Self::Json => serde_json::from_str::<serde_json::Value>(value).is_ok(),
            Self::Jwt => {
                // Shape only, in linear time: three base64url segments,
                // header and payload non-empty, the signature possibly
                // empty (an unsecured JWS). Verification is `nitr.jwt`'s
                // job, not a format's.
                let alphabet = |p: &str| {
                    p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                };
                let parts: Vec<&str> = value.split('.').collect();
                parts.len() == 3
                    && parts[..2].iter().all(|p| !p.is_empty() && alphabet(p))
                    && alphabet(parts[2])
            }
        }
    }

    /// The noun phrase completing "must be …".
    pub(super) fn describe(self) -> &'static str {
        match self {
            Self::Email => "an email address",
            Self::Uuid => "a UUID",
            Self::Ulid => "a ULID",
            Self::Url => "an http(s) URL",
            Self::Domain => "a domain name",
            Self::Ip => "an IP address",
            Self::Ipv4 => "an IPv4 address",
            Self::Ipv6 => "an IPv6 address",
            Self::Cidr => "an IP range in CIDR notation",
            Self::Mac => "a MAC address",
            Self::Hostname => "a hostname",
            Self::Date => "a date (YYYY-MM-DD)",
            Self::Datetime => "an RFC 3339 datetime",
            Self::Time => "a time (HH:MM or HH:MM:SS)",
            Self::Hex => "a hex string",
            Self::Base64 => "a base64 string",
            Self::Base64Url => "a URL-safe base64 string",
            Self::Alphanumeric => "letters and digits only",
            Self::Alpha => "letters only",
            Self::Numeric => "digits only",
            Self::AlphaDash => "letters, digits, hyphens or underscores",
            Self::Lowercase => "lowercase",
            Self::Uppercase => "uppercase",
            Self::Ascii => "ASCII text",
            Self::Printable => "printable text",
            Self::Slug => "a slug (lowercase letters, digits, hyphens)",
            Self::Semver => "a semantic version",
            Self::Phone => "a phone number in E.164 form (+ and digits)",
            Self::CountryCode => "a two-letter country code",
            Self::CurrencyCode => "a three-letter currency code",
            Self::LanguageTag => "a language tag (en, en-US)",
            Self::CreditCard => "a valid card number",
            Self::Iban => "a valid IBAN",
            Self::HexColor => "a hex color (#RGB, #RRGGBB or #RRGGBBAA)",
            Self::Json => "valid JSON",
            Self::Jwt => "a JWT",
        }
    }
}

/// Parses a 24-hour time in the shapes `HH:MM`, `HH:MM:SS`, `HH:MM:SS.frac`.
pub(super) fn parse_time(value: &str) -> Option<chrono::NaiveTime> {
    // `HH:MM`, `HH:MM:SS` or `HH:MM:SS.fff`: two digits each, no leap
    // second (chrono would take `9:00` and `23:59:60`).
    let two_digits = |p: &str| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit());
    let mut parts = value.split(':');
    let (Some(h), Some(m)) = (parts.next(), parts.next()) else {
        return None;
    };
    if !two_digits(h) || !two_digits(m) {
        return None;
    }
    if let Some(s) = parts.next() {
        let (whole, frac) = s.split_once('.').unwrap_or((s, "0"));
        if !two_digits(whole)
            || whole >= "60"
            || frac.is_empty()
            || !frac.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
    }
    if parts.next().is_some() {
        return None;
    }
    ["%H:%M:%S%.f", "%H:%M:%S", "%H:%M"]
        .iter()
        .find_map(|fmt| chrono::NaiveTime::parse_from_str(value, fmt).ok())
}

/// A script-defined format (`nitr.validate.format(name, {...})`).
#[derive(Debug)]
pub(crate) struct CustomFormat {
    pub(crate) name: String,
    /// Documentation only: emitted by the API description, never read
    /// by the checker.
    #[allow(dead_code)]
    pub(crate) description: String,
    pub(crate) message: Option<Template>,
    pub(crate) check: mlua::Function,
    /// Documentation only: emitted by the API description, never executed.
    #[allow(dead_code)]
    pub(crate) pattern: Option<String>,
    #[allow(dead_code)]
    pub(crate) example: Option<String>,
}

/// The per-state registry of custom formats, kept in the Lua app data.
#[derive(Debug, Default)]
pub(crate) struct FormatRegistry {
    pub(crate) formats: HashMap<String, Arc<CustomFormat>>,
}

/// A rule's format: built in, or one the script registered.
#[derive(Debug, Clone)]
pub(crate) enum FormatRule {
    Builtin(Format),
    Custom(Arc<CustomFormat>),
}

impl FormatRule {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Builtin(f) => f.name(),
            Self::Custom(c) => &c.name,
        }
    }

    /// Looks a name up: built-ins first, then the state's registry.
    pub(crate) fn resolve(lua: &mlua::Lua, name: &str) -> Option<Self> {
        if let Some(builtin) = Format::parse(name) {
            return Some(Self::Builtin(builtin));
        }
        let registry = lua.app_data_ref::<FormatRegistry>()?;
        registry.formats.get(name).cloned().map(Self::Custom)
    }
}

/// Every format name a schema in this state may use, sorted.
pub(crate) fn all_format_names(lua: &mlua::Lua) -> Vec<String> {
    let mut names: Vec<String> = format_names().into_iter().map(String::from).collect();
    if let Some(registry) = lua.app_data_ref::<FormatRegistry>() {
        names.extend(registry.formats.keys().cloned());
    }
    names.sort();
    names
}
