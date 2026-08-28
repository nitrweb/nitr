// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The input format every Nitr fuzz target shares.
//!
//! ## Why not `Arbitrary`
//!
//! The targets used to take tuples (`|input: (&str, u64)|`), which
//! libfuzzer-sys decodes with `Arbitrary`. That is convenient and wrong
//! for parsers whose corpus is *text*: `<&str as Arbitrary>::arbitrary`
//! reads its length from the **tail** of the buffer, so a hand-written
//! seed never lands in the field it was written for. Measured against
//! the seeds committed here, `bytes=0-499` reached `range::parse` as the
//! header `"by"` with a length of 4121969244163499380, and both
//! multipart seeds arrived with the content type `"multipart/"` — no
//! boundary parameter, so the parser under test was never entered at
//! all. Fourteen of sixteen seeds were dead on arrival.
//!
//! It also makes the corpus unstable: because the length comes from the
//! tail, appending one byte to a seed re-cuts *every* field.
//!
//! ## The format
//!
//! A flat, explicit layout instead — no length prefixes, so a mutation
//! in the middle of the text does not move the field boundaries:
//!
//! ```text
//! [ fixed-width numeric parameters ][ field \0 field \0 … \0 last field ]
//! ```
//!
//! Numbers come first, little-endian, and are read straight off the
//! front; the remaining bytes split on NUL into fields, and the last
//! field runs to the end of the input. A short input is not an error:
//! missing numbers read as `0` and missing fields as empty, so every
//! byte string is a valid input and libFuzzer never wastes a run on a
//! decode failure.
//!
//! Each target documents its own layout, and `fuzz/seeds/README.md`
//! shows the `printf` that writes one.

/// A cursor over one fuzz input.
pub struct Input<'a> {
    rest: &'a [u8],
}

impl<'a> Input<'a> {
    /// Wraps the raw libFuzzer buffer.
    pub fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    /// Takes `N` bytes off the front, zero-padded when the input is
    /// shorter — a truncated input stays usable instead of being
    /// discarded.
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        let n = N.min(self.rest.len());
        out[..n].copy_from_slice(&self.rest[..n]);
        self.rest = &self.rest[n..];
        out
    }

    /// A `u8` parameter.
    pub fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    /// A little-endian `u16` parameter.
    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take::<2>())
    }

    /// A little-endian `u32` parameter.
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take::<4>())
    }

    /// A little-endian `u64` parameter.
    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take::<8>())
    }

    /// One byte of the input read as a boolean (odd is true).
    pub fn flag(&mut self) -> bool {
        self.u8() % 2 == 1
    }

    /// The next NUL-separated field. The last field runs to the end of
    /// the input; past the end, fields are empty.
    pub fn field(&mut self) -> &'a [u8] {
        match self.rest.iter().position(|&b| b == 0) {
            Some(i) => {
                let (field, rest) = self.rest.split_at(i);
                self.rest = &rest[1..]; // drop the separator
                field
            }
            None => std::mem::take(&mut self.rest),
        }
    }

    /// The next field as text.
    ///
    /// Invalid UTF-8 is replaced rather than skipped: every parser this
    /// crate targets takes `&str`, so bytes that cannot be a `&str`
    /// cannot reach it in production either — dropping those inputs
    /// would throw away runs to model nothing. The replacement keeps
    /// each input useful and each field independent.
    pub fn text(&mut self) -> std::borrow::Cow<'a, str> {
        String::from_utf8_lossy(self.field())
    }

    /// Everything not yet consumed, as one field.
    pub fn rest(self) -> &'a [u8] {
        self.rest
    }

    /// Splits everything not yet consumed into all remaining
    /// NUL-separated fields.
    pub fn fields(mut self) -> Vec<&'a [u8]> {
        let mut out = Vec::new();
        while !self.rest.is_empty() {
            out.push(self.field());
        }
        out
    }

    /// [`fields`](Self::fields) as text.
    pub fn texts(self) -> Vec<String> {
        self.fields()
            .into_iter()
            .map(|f| String::from_utf8_lossy(f).into_owned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_come_off_the_front_then_fields_split_on_nul() {
        let mut input = Input::new(b"\x2a\x00\x01\x00\x00\x00\x00\x00\x00\x00hello\0world");
        assert_eq!(input.u8(), 42);
        assert_eq!(input.u16(), 1);
        assert_eq!(input.u64(), 0);
        assert_eq!(&*input.text(), "hello");
        assert_eq!(&*input.text(), "world");
    }

    #[test]
    fn a_truncated_input_is_still_usable() {
        let mut input = Input::new(b"\x07");
        assert_eq!(input.u8(), 7);
        // Everything past the end reads as zero/empty rather than failing.
        assert_eq!(input.u64(), 0);
        assert_eq!(&*input.text(), "");
        assert_eq!(input.field(), b"");
    }

    #[test]
    fn an_empty_input_decodes_to_nothing() {
        let mut input = Input::new(b"");
        assert_eq!(input.u8(), 0);
        assert_eq!(&*input.text(), "");
    }

    #[test]
    fn the_last_field_runs_to_the_end_including_nested_nuls() {
        let mut input = Input::new(b"a\0b\0c");
        assert_eq!(input.field(), b"a");
        assert_eq!(Input::new(b"a\0b\0c").fields(), vec![&b"a"[..], b"b", b"c"]);
        assert_eq!(input.rest(), b"b\0c");
    }

    #[test]
    fn invalid_utf8_is_replaced_not_dropped() {
        let mut input = Input::new(b"ok\0\xff\xfe");
        assert_eq!(&*input.text(), "ok");
        assert_eq!(&*input.text(), "\u{fffd}\u{fffd}");
    }
}
