// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use rusqlite::{Connection, params_from_iter};

use crate::db::types::{SqlRow, SqlValue, read_row};

/// Runs a query expected to return exactly one row and returns it.
pub(crate) fn call(
    conn: &Connection,
    sql: &str,
    params: &[SqlValue],
    _max_rows: usize,
) -> Result<SqlRow, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(sql)?;
    let columns = stmt
        .column_names()
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    stmt.query_one(params_from_iter(params), |row| read_row(&columns, row))
}
