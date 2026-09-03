// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The JSON bounds (depth, node budget, UTF-8 strings) enforced *during*
//! one serialization pass instead of by a separate walk in front of it.
//!
//! [`check_json_bounds`](crate::utils::check_json_bounds) visits every node
//! of a Lua value and then hands it to the serializer, which visits every
//! node again; measured (`stdlib::bounds_guard`), the guard's walk is ~44 %
//! of the pair. This module wraps the *serializer* instead: mlua's own
//! `Serialize` impl drives it exactly as it drives `serde_json`'s, and each
//! call it makes on the way down is checked before being forwarded. The
//! guarantees are the same ones, at the same points:
//!
//! - **depth**: a sequence or map deeper than [`MAX_JSON_DEPTH`] levels is
//!   refused when it is *entered*, before anything under it is visited —
//!   recursion never goes further than the bound, so the stack stays
//!   bounded (a stack overflow is an abort no boundary can catch);
//! - **nodes**: every visited value, keys included, spends one unit of
//!   [`MAX_JSON_NODES`], so a DAG that expands to 2^60 visits stops after a
//!   million of them;
//! - **UTF-8**: a Lua string that is not valid UTF-8 reaches a serializer as
//!   *bytes* (mlua's contract), and is refused rather than written out as
//!   an array of numbers.
//!
//! Nothing else is touched: every value is forwarded to the wrapped
//! serializer unchanged, so the output bytes are exactly what the plain
//! serializer produces for a value that passes the guard (the tests below
//! pin that against the walking guard, shape by shape and at the exact
//! depth boundary).

use std::cell::Cell;

use mlua::Value;
use serde::ser::{
    self, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant, Serializer,
};

use crate::utils::{MAX_JSON_DEPTH, MAX_JSON_NODES, depth_message, nodes_message, utf8_message};

/// The running bounds of one serialization.
pub(crate) struct Bounds {
    depth: Cell<usize>,
    budget: Cell<usize>,
    strict_utf8: bool,
}

impl Bounds {
    /// Fresh bounds; `strict_utf8` refuses non-UTF-8 strings (every JSON
    /// site) or lets them through as bytes (the log placeholder path).
    pub(crate) fn new(strict_utf8: bool) -> Self {
        Self {
            depth: Cell::new(0),
            budget: Cell::new(MAX_JSON_NODES),
            strict_utf8,
        }
    }

    /// Charged for every visited value, scalars and keys included — the
    /// same accounting as the walking guard.
    fn visit<E: ser::Error>(&self) -> Result<(), E> {
        let left = self.budget.get();
        if left == 0 {
            return Err(E::custom(nodes_message()));
        }
        self.budget.set(left - 1);
        Ok(())
    }

    /// Entering a sequence or map: refused past the depth bound, before
    /// any child is visited.
    fn enter<E: ser::Error>(&self) -> Result<(), E> {
        let depth = self.depth.get() + 1;
        if depth > MAX_JSON_DEPTH {
            return Err(E::custom(depth_message()));
        }
        self.depth.set(depth);
        Ok(())
    }

    fn leave(&self) {
        self.depth.set(self.depth.get().saturating_sub(1));
    }
}

/// A value serialized under `bounds`: what call sites hand to
/// `serde_json` (or any other serializer) in place of the bare value.
pub(crate) struct Guarded<'b, T: ?Sized> {
    value: &'b T,
    bounds: &'b Bounds,
}

impl<'b, T: ?Sized> Guarded<'b, T> {
    pub(crate) fn new(value: &'b T, bounds: &'b Bounds) -> Self {
        Self { value, bounds }
    }
}

impl<T: ?Sized + Serialize> Serialize for Guarded<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(Bounded {
            inner: serializer,
            bounds: self.bounds,
        })
    }
}

/// `serde_json::to_string` under the JSON bounds, strict about UTF-8.
pub(crate) fn to_json_string(value: &Value) -> serde_json::Result<String> {
    let bounds = Bounds::new(true);
    serde_json::to_string(&Guarded::new(value, &bounds))
}

/// `serde_json::to_vec` under the JSON bounds, strict about UTF-8.
pub(crate) fn to_json_vec(value: &Value) -> serde_json::Result<Vec<u8>> {
    let bounds = Bounds::new(true);
    serde_json::to_vec(&Guarded::new(value, &bounds))
}

/// The serializer adapter: checks, then forwards.
struct Bounded<'b, S> {
    inner: S,
    bounds: &'b Bounds,
}

/// A compound (sequence, map, struct...) in progress: every element goes
/// through [`Guarded`], and `end` leaves the depth level.
struct Compound<'b, C> {
    inner: C,
    bounds: &'b Bounds,
}

impl<'b, S: Serializer> Serializer for Bounded<'b, S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = Compound<'b, S::SerializeSeq>;
    type SerializeTuple = Compound<'b, S::SerializeTuple>;
    type SerializeTupleStruct = Compound<'b, S::SerializeTupleStruct>;
    type SerializeTupleVariant = Compound<'b, S::SerializeTupleVariant>;
    type SerializeMap = Compound<'b, S::SerializeMap>;
    type SerializeStruct = Compound<'b, S::SerializeStruct>;
    type SerializeStructVariant = Compound<'b, S::SerializeStructVariant>;

    fn serialize_bool(self, v: bool) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_bool(v)
    }

    fn serialize_i8(self, v: i8) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_i8(v)
    }

    fn serialize_i16(self, v: i16) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_i16(v)
    }

    fn serialize_i32(self, v: i32) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_i32(v)
    }

    fn serialize_i64(self, v: i64) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_i64(v)
    }

    fn serialize_i128(self, v: i128) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_i128(v)
    }

    fn serialize_u8(self, v: u8) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_u8(v)
    }

    fn serialize_u16(self, v: u16) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_u16(v)
    }

    fn serialize_u32(self, v: u32) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_u32(v)
    }

    fn serialize_u64(self, v: u64) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_u64(v)
    }

    fn serialize_u128(self, v: u128) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_u128(v)
    }

    fn serialize_f32(self, v: f32) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_f32(v)
    }

    fn serialize_f64(self, v: f64) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_f64(v)
    }

    fn serialize_char(self, v: char) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_char(v)
    }

    fn serialize_str(self, v: &str) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_str(v)
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        if self.bounds.strict_utf8 {
            return Err(<S::Error as ser::Error>::custom(utf8_message()));
        }
        self.inner.serialize_bytes(v)
    }

    fn serialize_none(self) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_none()
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<S::Ok, S::Error> {
        self.inner.serialize_some(&Guarded::new(value, self.bounds))
    }

    fn serialize_unit(self) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_unit()
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_unit_struct(name)
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
    ) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.serialize_unit_variant(name, index, variant)
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<S::Ok, S::Error> {
        self.inner
            .serialize_newtype_struct(name, &Guarded::new(value, self.bounds))
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<S::Ok, S::Error> {
        self.inner.serialize_newtype_variant(
            name,
            index,
            variant,
            &Guarded::new(value, self.bounds),
        )
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, S::Error> {
        self.bounds.visit()?;
        self.bounds.enter()?;
        Ok(Compound {
            inner: self.inner.serialize_seq(len)?,
            bounds: self.bounds,
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, S::Error> {
        self.bounds.visit()?;
        self.bounds.enter()?;
        Ok(Compound {
            inner: self.inner.serialize_tuple(len)?,
            bounds: self.bounds,
        })
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, S::Error> {
        self.bounds.visit()?;
        self.bounds.enter()?;
        Ok(Compound {
            inner: self.inner.serialize_tuple_struct(name, len)?,
            bounds: self.bounds,
        })
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, S::Error> {
        self.bounds.visit()?;
        self.bounds.enter()?;
        Ok(Compound {
            inner: self
                .inner
                .serialize_tuple_variant(name, index, variant, len)?,
            bounds: self.bounds,
        })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, S::Error> {
        self.bounds.visit()?;
        self.bounds.enter()?;
        Ok(Compound {
            inner: self.inner.serialize_map(len)?,
            bounds: self.bounds,
        })
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, S::Error> {
        self.bounds.visit()?;
        self.bounds.enter()?;
        Ok(Compound {
            inner: self.inner.serialize_struct(name, len)?,
            bounds: self.bounds,
        })
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, S::Error> {
        self.bounds.visit()?;
        self.bounds.enter()?;
        Ok(Compound {
            inner: self
                .inner
                .serialize_struct_variant(name, index, variant, len)?,
            bounds: self.bounds,
        })
    }

    fn collect_str<T: ?Sized + std::fmt::Display>(self, value: &T) -> Result<S::Ok, S::Error> {
        self.bounds.visit()?;
        self.inner.collect_str(value)
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

impl<C: SerializeSeq> SerializeSeq for Compound<'_, C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), C::Error> {
        self.inner
            .serialize_element(&Guarded::new(value, self.bounds))
    }

    fn end(self) -> Result<C::Ok, C::Error> {
        self.bounds.leave();
        self.inner.end()
    }
}

impl<C: SerializeTuple> SerializeTuple for Compound<'_, C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), C::Error> {
        self.inner
            .serialize_element(&Guarded::new(value, self.bounds))
    }

    fn end(self) -> Result<C::Ok, C::Error> {
        self.bounds.leave();
        self.inner.end()
    }
}

impl<C: SerializeTupleStruct> SerializeTupleStruct for Compound<'_, C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), C::Error> {
        self.inner
            .serialize_field(&Guarded::new(value, self.bounds))
    }

    fn end(self) -> Result<C::Ok, C::Error> {
        self.bounds.leave();
        self.inner.end()
    }
}

impl<C: SerializeTupleVariant> SerializeTupleVariant for Compound<'_, C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), C::Error> {
        self.inner
            .serialize_field(&Guarded::new(value, self.bounds))
    }

    fn end(self) -> Result<C::Ok, C::Error> {
        self.bounds.leave();
        self.inner.end()
    }
}

impl<C: SerializeMap> SerializeMap for Compound<'_, C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), C::Error> {
        self.inner.serialize_key(&Guarded::new(key, self.bounds))
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), C::Error> {
        self.inner
            .serialize_value(&Guarded::new(value, self.bounds))
    }

    fn serialize_entry<K: ?Sized + Serialize, V: ?Sized + Serialize>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), C::Error> {
        self.inner.serialize_entry(
            &Guarded::new(key, self.bounds),
            &Guarded::new(value, self.bounds),
        )
    }

    fn end(self) -> Result<C::Ok, C::Error> {
        self.bounds.leave();
        self.inner.end()
    }
}

impl<C: SerializeStruct> SerializeStruct for Compound<'_, C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), C::Error> {
        self.inner
            .serialize_field(key, &Guarded::new(value, self.bounds))
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), C::Error> {
        self.inner.skip_field(key)
    }

    fn end(self) -> Result<C::Ok, C::Error> {
        self.bounds.leave();
        self.inner.end()
    }
}

impl<C: SerializeStructVariant> SerializeStructVariant for Compound<'_, C> {
    type Ok = C::Ok;
    type Error = C::Error;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), C::Error> {
        self.inner
            .serialize_field(key, &Guarded::new(value, self.bounds))
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), C::Error> {
        self.inner.skip_field(key)
    }

    fn end(self) -> Result<C::Ok, C::Error> {
        self.bounds.leave();
        self.inner.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::Lua;

    fn value(lua: &Lua, src: &str) -> Value {
        lua.load(src).eval().expect("build the value")
    }

    /// The bounded pass produces exactly the bytes the plain serializer
    /// produces for every value the walking guard accepts, and refuses
    /// exactly the values it refuses.
    #[test]
    fn agrees_with_the_walking_guard_on_representative_shapes() {
        let lua = Lua::new();
        for src in [
            "nil",
            "true",
            "42",
            "1.5",
            "'text'",
            "{}",
            "{1, 2, 3}",
            "{a = 1, b = {c = {d = 'deep'}}}",
            "{ {x = 1}, {x = 2}, 'mixed', 3 }",
            "(function() local t = {} for i = 1, 200 do t[i] = { id = i, s = tostring(i) } end return t end)()",
        ] {
            let v = value(&lua, src);
            let expected = match crate::utils::check_json_bounds(&v) {
                Ok(()) => serde_json::to_string(&v).ok(),
                Err(_) => None,
            };
            assert_eq!(to_json_string(&v).ok(), expected, "{src}");
        }
    }

    #[test]
    fn the_depth_bound_holds_at_exactly_the_guards_boundary() {
        let lua = Lua::new();
        let chain = |levels: usize| {
            value(
                &lua,
                &format!(
                    "local t = {{}} local cur = t for _ = 1, {} do cur.n = {{}} cur = cur.n end return t",
                    levels - 1
                ),
            )
        };
        let ok = chain(MAX_JSON_DEPTH);
        assert!(crate::utils::check_json_bounds(&ok).is_ok());
        assert!(to_json_string(&ok).is_ok());

        let deep = chain(MAX_JSON_DEPTH + 1);
        assert!(crate::utils::check_json_bounds(&deep).is_err());
        let err = to_json_string(&deep).expect_err("one level too deep");
        assert!(err.to_string().contains("nested deeper"), "{err}");
    }

    #[test]
    fn the_node_budget_and_the_utf8_rule_are_enforced_in_the_pass() {
        let lua = Lua::new();
        // Sixty shared levels: a DAG the walk sees as 2^60 nodes.
        let dag = value(
            &lua,
            "local prev = {} for _ = 1, 60 do prev = { a = prev, b = prev } end return prev",
        );
        let err = to_json_string(&dag).expect_err("over the node budget");
        assert!(err.to_string().contains("more than"), "{err}");

        let binary = value(&lua, "return { blob = '\\255\\254' }");
        let err = to_json_string(&binary).expect_err("not UTF-8");
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");
    }

    #[test]
    fn a_cyclic_table_is_refused_without_hanging() {
        let lua = Lua::new();
        let cyclic = value(&lua, "local t = {} t.me = t return t");
        assert!(to_json_string(&cyclic).is_err());
    }
}
