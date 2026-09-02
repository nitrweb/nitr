// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use rusqlite::{Connection, OptionalExtension as _, params_from_iter};

use crate::db::types::{SqlRow, SqlValue, read_row};

/// Runs a query and returns its first row, or `None` when it produced no
/// rows — the documented `query_row` contract (`nil`, not an error, for an
/// empty result), so `if row then` works as written.
pub(crate) fn call(
    conn: &Connection,
    sql: &str,
    params: &[SqlValue],
) -> Result<Option<SqlRow>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(sql)?;
    let columns = stmt
        .column_names()
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    stmt.query_row(params_from_iter(params), |row| read_row(&columns, row))
        .optional()
}
