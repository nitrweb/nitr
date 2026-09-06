// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! A field's position in the input (`order.customer.email`,
//! `lines[3].qty`), as a chain of borrowed segments rendered only when a
//! message needs it: a successful check used to allocate one `String` per
//! field and per array element purely for an error it never recorded.

/// One step of a field's position in the input.
pub(super) enum Segment<'a> {
    Field(&'a str),
    Index(usize),
    Key(&'a str),
}

/// A field's position, rendered only when a message needs it.
pub(super) struct FieldPath<'a> {
    parent: Option<&'a FieldPath<'a>>,
    segment: Option<Segment<'a>>,
}

impl<'a> FieldPath<'a> {
    pub(super) const ROOT: FieldPath<'static> = FieldPath {
        parent: None,
        segment: None,
    };

    pub(super) fn field(&'a self, name: &'a str) -> FieldPath<'a> {
        FieldPath {
            parent: Some(self),
            segment: Some(Segment::Field(name)),
        }
    }

    pub(super) fn index(&'a self, index: usize) -> FieldPath<'a> {
        FieldPath {
            parent: Some(self),
            segment: Some(Segment::Index(index)),
        }
    }

    pub(super) fn key(&'a self, key: &'a str) -> FieldPath<'a> {
        FieldPath {
            parent: Some(self),
            segment: Some(Segment::Key(key)),
        }
    }

    /// The path text; `$` for the root.
    pub(super) fn render(&self) -> String {
        let mut out = String::new();
        self.write_to(&mut out);
        if out.is_empty() { "$".into() } else { out }
    }

    fn write_to(&self, out: &mut String) {
        use std::fmt::Write as _;
        if let Some(parent) = self.parent {
            parent.write_to(out);
        }
        match self.segment {
            Some(Segment::Field(name) | Segment::Key(name)) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(name);
            }
            Some(Segment::Index(index)) => {
                let _ = write!(out, "[{index}]");
            }
            None => {}
        }
    }

    /// The nearest named field on the path.
    pub(super) fn field_name(&self) -> &'a str {
        match self.segment {
            Some(Segment::Field(name)) => name,
            _ => self.parent.map_or("", FieldPath::field_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_render_dots_indexes_and_keys() {
        let root = FieldPath::ROOT;
        assert_eq!(root.render(), "$");
        let lines = root.field("lines");
        let third = lines.index(3);
        let qty = third.field("qty");
        assert_eq!(qty.render(), "lines[3].qty");
        assert_eq!(third.field_name(), "lines");
        let settings = root.field("settings");
        assert_eq!(settings.key("a b").render(), "settings.a b");
    }
}
