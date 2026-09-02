// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use rusqlite::{Connection, params_from_iter};

use crate::db::types::SqlValue;

/// Executes a statement and returns the number of affected rows.
pub(crate) fn call(
    conn: &Connection,
    sql: &str,
    params: &[SqlValue],
    _max_rows: usize,
) -> Result<usize, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(sql)?;
    stmt.execute(params_from_iter(params))
}
