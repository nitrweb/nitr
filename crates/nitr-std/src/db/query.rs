// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use rusqlite::{Connection, params_from_iter};

use crate::db::types::{SqlRow, SqlValue, column_names, read_row};

/// Runs a query and returns all result rows — at most `max_rows` of
/// them. One more is an error rather than a silent truncation: a handler
/// that got fewer rows than the database holds would compute a wrong
/// answer without knowing.
pub(crate) fn call(
    conn: &Connection,
    sql: &str,
    params: &[SqlValue],
    max_rows: usize,
) -> Result<Vec<SqlRow>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(sql)?;
    let columns = column_names(&stmt);

    let mut rows = stmt.query(params_from_iter(params))?;
    let mut out = vec![];
    while let Some(row) = rows.next()? {
        if out.len() >= max_rows {
            // `SqliteFailure` with a message displays the message alone;
            // the code marks it as a size limit, which it is.
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_TOOBIG),
                Some(format!(
                    "the query returned more than {max_rows} rows ([database] max_rows); add \
                     a LIMIT or raise the setting"
                )),
            ));
        }
        out.push(read_row(&columns, row)?);
    }
    Ok(out)
}
