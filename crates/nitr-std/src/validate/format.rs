// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The string formats a rule can require: one careful, dependency-free
//! Rust implementation each.

/// String formats with one careful, dependency-free Rust implementation
/// each: syntactic sanity checks, not full RFC validation.
#[derive(Debug, Clone, Copy)]
pub(super) enum Format {
    Email,
    Uuid,
    Url,
    Ip,
    Ipv4,
    Ipv6,
    Hostname,
    Date,
    Datetime,
    Hex,
    Base64,
    Alphanumeric,
    Slug,
}

/// Every recognized format, for the compile-time error message.
pub(super) const FORMATS: &[(&str, Format)] = &[
    ("email", Format::Email),
    ("uuid", Format::Uuid),
    ("url", Format::Url),
    ("ip", Format::Ip),
    ("ipv4", Format::Ipv4),
    ("ipv6", Format::Ipv6),
    ("hostname", Format::Hostname),
    ("date", Format::Date),
    ("datetime", Format::Datetime),
    ("hex", Format::Hex),
    ("base64", Format::Base64),
    ("alphanumeric", Format::Alphanumeric),
    ("slug", Format::Slug),
];

/// One DNS label: 1–63 chars, alphanumeric plus inner hyphens.
/// Checks `value` against the named format, for the `validate_formats`
/// fuzz target: `None` when no such format exists, else the verdict.
///
/// A function rather than a `pub` [`Format`] so the hand-rolled
/// validators can be fuzzed without making the enum — and a doc comment
/// per variant — part of any public surface.
#[doc(hidden)]
pub fn check_format(name: &str, value: &str) -> Option<bool> {
    Format::parse(name).map(|format| format.check(value))
}

/// Every format name [`check_format`] accepts.
#[doc(hidden)]
pub fn format_names() -> Vec<&'static str> {
    FORMATS.iter().map(|(name, _)| *name).collect()
}

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

impl Format {
    pub(super) fn parse(name: &str) -> Option<Self> {
        FORMATS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, format)| *format)
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
            Self::Url => {
                let rest = value
                    .strip_prefix("http://")
                    .or_else(|| value.strip_prefix("https://"));
                matches!(rest, Some(rest) if !rest.is_empty() && !rest.starts_with('/'))
                    && !value.contains(|c: char| c.is_whitespace() || c.is_control())
            }
            Self::Ip => value.parse::<std::net::IpAddr>().is_ok(),
            Self::Ipv4 => value.parse::<std::net::Ipv4Addr>().is_ok(),
            Self::Ipv6 => value.parse::<std::net::Ipv6Addr>().is_ok(),
            Self::Hostname => is_hostname(value),
            Self::Date => chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok(),
            Self::Datetime => chrono::DateTime::parse_from_rfc3339(value).is_ok(),
            Self::Hex => !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit()),
            Self::Base64 => {
                use base64::Engine as _;
                !value.is_empty()
                    && base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .is_ok()
            }
            Self::Alphanumeric => {
                !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric())
            }
            Self::Slug => {
                !value.is_empty()
                    && value
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && !value.starts_with('-')
                    && !value.ends_with('-')
            }
        }
    }

    pub(super) fn describe(self) -> &'static str {
        match self {
            Self::Email => "an email address",
            Self::Uuid => "a UUID",
            Self::Url => "an http(s) URL",
            Self::Ip => "an IP address",
            Self::Ipv4 => "an IPv4 address",
            Self::Ipv6 => "an IPv6 address",
            Self::Hostname => "a hostname",
            Self::Date => "a date (YYYY-MM-DD)",
            Self::Datetime => "an RFC 3339 datetime",
            Self::Hex => "a hex string",
            Self::Base64 => "a base64 string",
            Self::Alphanumeric => "letters and digits only",
            Self::Slug => "a slug (lowercase letters, digits, hyphens)",
        }
    }
}
