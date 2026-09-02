// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Safe clocks and time formatting for Lua handlers: `nitr.time`.
//!
//! This exists so scripts never need the `os` Lua standard library for a
//! date — enabling `os` for `os.date` also grants `os.execute`, `os.remove`
//! and `os.getenv`, which costs the sandbox. Everything here is UTC (or a
//! fixed offset embedded in the input); there is deliberately no timezone
//! database.

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The first second `httpdate` cannot format (year 10000): its
/// `From<SystemTime>` panics from there on.
const MAX_HTTP_DATE_SECS: u64 = 253_402_300_800;

use chrono::format::{Item, StrftimeItems};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use mlua::{Lua, Table, Value};

/// Current unix time in whole seconds.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Converts a unix timestamp into a UTC datetime, rejecting values chrono
/// cannot represent (far outside ±262,000 years).
fn datetime(ts: i64) -> mlua::Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(ts, 0)
        .ok_or_else(|| mlua::Error::RuntimeError(format!("timestamp {ts} is out of range")))
}

/// Parses a strftime format string, rejecting unknown `%` specifiers
/// upfront — chrono's formatter panics on them only when rendered.
fn strftime_items(fmt: &str) -> mlua::Result<Vec<Item<'_>>> {
    let items: Vec<Item<'_>> = StrftimeItems::new(fmt).collect();
    if items.contains(&Item::Error) {
        return Err(mlua::Error::RuntimeError(format!(
            "invalid time format `{fmt}`"
        )));
    }
    Ok(items)
}

/// Parses `value` against a strftime format, trying the shapes in order of
/// how much they pin down: an offset-carrying datetime, a naive datetime
/// (taken as UTC), and a bare date (taken as UTC midnight).
fn parse_with(value: &str, fmt: &str) -> Option<i64> {
    if let Ok(dt) = DateTime::parse_from_str(value, fmt) {
        return Some(dt.timestamp());
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(value, fmt) {
        return Some(dt.and_utc().timestamp());
    }
    if let Ok(date) = NaiveDate::parse_from_str(value, fmt) {
        return Some(date.and_hms_opt(0, 0, 0)?.and_utc().timestamp());
    }
    None
}

/// Builds the `nitr.time` table.
pub(crate) fn create_time_table(lua: &Lua) -> mlua::Result<Table> {
    let time = lua.create_table()?;

    // Whole unix seconds: the interchange form everything else here takes.
    time.set("now", lua.create_function(|_, ()| Ok(unix_now()))?)?;

    // Seconds (with sub-second precision) on a monotonic clock, for
    // measuring durations. The wall clock is wrong for that job — it jumps
    // under NTP adjustments — and Lua offers no alternative. The origin is
    // the first call, so only differences are meaningful.
    time.set(
        "monotonic",
        lua.create_function(|_, ()| {
            static ANCHOR: OnceLock<Instant> = OnceLock::new();
            Ok(ANCHOR.get_or_init(Instant::now).elapsed().as_secs_f64())
        })?,
    )?;

    // strftime formatting in UTC — the same `%Y-%m-%d` syntax `os.date`
    // users already know. The default renders an ISO-like datetime.
    time.set(
        "format",
        lua.create_function(|_, (ts, fmt): (i64, Option<String>)| {
            let fmt = fmt.as_deref().unwrap_or("%Y-%m-%dT%H:%M:%S");
            let items = strftime_items(fmt)?;
            Ok(datetime(ts)?.format_with_items(items.iter()).to_string())
        })?,
    )?;

    // The inverse of `format`: returns unix seconds, or nil plus a reason.
    // Inputs without an offset specifier are taken as UTC.
    time.set(
        "parse",
        lua.create_function(|lua, (value, fmt): (String, String)| {
            strftime_items(&fmt)?;
            match parse_with(&value, &fmt) {
                Some(ts) => Ok((Value::Integer(ts), Value::Nil)),
                None => Ok((
                    Value::Nil,
                    Value::String(
                        lua.create_string(format!("`{value}` does not match format `{fmt}`"))?,
                    ),
                )),
            }
        })?,
    )?;

    // The HTTP date form (IMF-fixdate), e.g. "Tue, 15 Nov 1994 08:12:31
    // GMT" — for Last-Modified, Expires and cookie attributes.
    time.set(
        "http",
        lua.create_function(|_, ts: i64| {
            let ts = u64::try_from(ts).map_err(|_| {
                mlua::Error::RuntimeError(format!("HTTP dates cannot express {ts} (before 1970)"))
            })?;
            // `httpdate` panics past the year 9999; refuse the same range
            // it would, as an error a script can catch.
            if ts >= MAX_HTTP_DATE_SECS {
                return Err(mlua::Error::RuntimeError(format!(
                    "HTTP dates cannot express {ts} (past the year 9999)"
                )));
            }
            Ok(httpdate::fmt_http_date(
                UNIX_EPOCH + Duration::from_secs(ts),
            ))
        })?,
    )?;

    // Parses the three date forms HTTP allows (IMF-fixdate, RFC 850,
    // asctime) — for If-Modified-Since and friends. Returns nil on
    // anything else.
    time.set(
        "parse_http",
        lua.create_function(|_, value: String| {
            Ok(httpdate::parse_http_date(&value)
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64))
        })?,
    )?;

    // RFC 3339 / ISO 8601 in UTC, e.g. "1994-11-15T08:12:31Z".
    time.set(
        "iso8601",
        lua.create_function(|_, ts: i64| {
            Ok(datetime(ts)?.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        })?,
    )?;

    Ok(time)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call<R: mlua::FromLuaMulti>(
        _lua: &Lua,
        table: &Table,
        name: &str,
        args: impl mlua::IntoLuaMulti,
    ) -> R {
        table
            .get::<mlua::Function>(name)
            .expect("fn")
            .call(args)
            .expect(name)
    }

    #[test]
    fn formats_and_parses_round_trip_in_utc() {
        let lua = Lua::new();
        let time = create_time_table(&lua).expect("table");
        let ts = 784_887_151i64; // 1994-11-15T08:12:31Z

        let formatted: String = call(&lua, &time, "format", (ts, "%Y-%m-%d %H:%M:%S"));
        assert_eq!(formatted, "1994-11-15 08:12:31");
        let default: String = call(&lua, &time, "format", ts);
        assert_eq!(default, "1994-11-15T08:12:31");
        let iso: String = call(&lua, &time, "iso8601", ts);
        assert_eq!(iso, "1994-11-15T08:12:31Z");
        let http: String = call(&lua, &time, "http", ts);
        assert_eq!(http, "Tue, 15 Nov 1994 08:12:31 GMT");

        let (parsed, err): (Option<i64>, Option<String>) =
            call(&lua, &time, "parse", (formatted, "%Y-%m-%d %H:%M:%S"));
        assert_eq!((parsed, err), (Some(ts), None));
        let parsed: Option<i64> = call(&lua, &time, "parse_http", http);
        assert_eq!(parsed, Some(ts));

        // A bare date parses as UTC midnight.
        let (parsed, _): (Option<i64>, Option<String>) =
            call(&lua, &time, "parse", ("1994-11-15", "%Y-%m-%d"));
        assert_eq!(parsed, Some(784_857_600));
    }

    #[test]
    fn bad_inputs_fail_without_panicking() {
        let lua = Lua::new();
        let time = create_time_table(&lua).expect("table");

        // An unknown `%` specifier is an error, not a panic.
        let fmt: mlua::Function = time.get("format").expect("fn");
        assert!(fmt.call::<String>((0i64, "%Q")).is_err());

        let (parsed, err): (Option<i64>, Option<String>) =
            call(&lua, &time, "parse", ("not a date", "%Y-%m-%d"));
        assert_eq!(parsed, None);
        assert!(err.expect("reason").contains("does not match"));

        let parsed: Option<i64> = call(&lua, &time, "parse_http", "yesterday");
        assert_eq!(parsed, None);

        // Timestamps beyond chrono's representable range error cleanly.
        let format: mlua::Function = time.get("format").expect("fn");
        assert!(format.call::<String>((i64::MAX, "%Y")).is_err());
        let iso: mlua::Function = time.get("iso8601").expect("fn");
        assert!(iso.call::<String>(i64::MIN).is_err());
    }

    #[test]
    fn offsets_names_and_edge_timestamps() {
        let lua = Lua::new();
        let time = create_time_table(&lua).expect("table");

        // The epoch itself, and weekday/month names.
        let formatted: String = call(&lua, &time, "format", (0i64, "%a %d %b %Y"));
        assert_eq!(formatted, "Thu 01 Jan 1970");
        // Pre-1970 formats fine…
        let formatted: String = call(&lua, &time, "format", (-86_400i64, "%Y-%m-%d"));
        assert_eq!(formatted, "1969-12-31");
        // …but has no HTTP date form.
        let http: mlua::Function = time.get("http").expect("fn");
        assert!(http.call::<String>(-1i64).is_err());

        // An input carrying its own fixed offset lands on the right
        // instant: 10:12:31+0200 is 08:12:31Z.
        let (parsed, err): (Option<i64>, Option<String>) = call(
            &lua,
            &time,
            "parse",
            ("1994-11-15 10:12:31 +0200", "%Y-%m-%d %H:%M:%S %z"),
        );
        assert_eq!((parsed, err), (Some(784_887_151), None));

        // A custom layout round-trips.
        let (parsed, _): (Option<i64>, Option<String>) =
            call(&lua, &time, "parse", ("15/11/1994 08:12", "%d/%m/%Y %H:%M"));
        assert_eq!(parsed, Some(784_887_120));

        // `parse` with a bad format string is a hard error (caller bug),
        // unlike a non-matching value (data problem → nil, reason).
        let parse: mlua::Function = time.get("parse").expect("fn");
        assert!(
            parse
                .call::<(Option<i64>, Option<String>)>(("x", "%Q"))
                .is_err()
        );
    }

    #[test]
    fn clocks_advance() {
        let lua = Lua::new();
        let time = create_time_table(&lua).expect("table");
        let now: i64 = call(&lua, &time, "now", ());
        assert!(now > 1_700_000_000, "unix clock reads {now}");
        let a: f64 = call(&lua, &time, "monotonic", ());
        let b: f64 = call(&lua, &time, "monotonic", ());
        assert!(b >= a);
    }

    proptest::proptest! {
        /// Property: `parse(iso8601(ts))` and the strftime round trip are
        /// the identity for any timestamp between 1970 and 2100.
        #[test]
        fn prop_timestamps_round_trip(ts in 0i64..4_102_444_800) {
            let lua = Lua::new();
            let time = create_time_table(&lua).expect("table");
            let iso: String = call(&lua, &time, "iso8601", ts);
            let (parsed, err): (Option<i64>, Option<String>) =
                call(&lua, &time, "parse", (iso, "%Y-%m-%dT%H:%M:%SZ"));
            proptest::prop_assert_eq!(err, None);
            proptest::prop_assert_eq!(parsed, Some(ts));

            let formatted: String =
                call(&lua, &time, "format", (ts, "%Y-%m-%d %H:%M:%S"));
            let (parsed, _): (Option<i64>, Option<String>) =
                call(&lua, &time, "parse", (formatted, "%Y-%m-%d %H:%M:%S"));
            proptest::prop_assert_eq!(parsed, Some(ts));
        }
    }
}
