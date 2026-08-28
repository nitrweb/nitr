// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr.json` in both directions: `serde_json` over attacker bytes on
//! the way in, and the Lua-value serializer plus the `MAX_JSON_DEPTH`
//! guard on the way out (`nitr_std::fuzzing::create_json_fn`).
//!
//! Input layout (see `nitr_fuzz::Input`):
//!
//! ```text
//! u16 depth | json \0 builder-program…
//! ```
//!
//! `depth` drives a table chain straight at the 128-level bound, because
//! a fuzzer will not discover 129 nested braces on its own inside a 4 KiB
//! input. `json` is the document to decode — raw bytes, so invalid UTF-8
//! reaches `serde_json::from_slice` as it would from a request body. The
//! rest is a **program for a table builder**: each byte picks a shape, so
//! the encode direction sees arrays, maps, mixed tables, non-UTF8 Lua
//! strings, NaN/Inf, and integer-, float-, boolean- and table-typed keys,
//! rather than the single-key chains that were all the previous version
//! of this target ever built.
//!
//! What is asserted, and the wrong-but-not-crashing implementation each
//! one catches:
//!
//! * **The fixpoint: `decode(encode(decode(x))) == decode(x)`.** The
//!   previous target encoded and threw the string away. A document that
//!   survives one trip through Lua must survive every further one — an
//!   encoder that loses a key, promotes an integer to a float, or drops
//!   the array/object distinction on the *second* pass fails here while
//!   still parsing cleanly. Compared structurally, not textually: the
//!   encoder walks a Lua table in hash order, which is stable inside one
//!   state but **not across states** (measured), so a textual comparison
//!   would assert something the encoder never promised. The comparison
//!   canonicalizes with sorted keys and keeps the array marker, so `[]`
//!   turning into `{}` is still caught.
//! * **Anything decoded re-encodes**, and its encoding decodes again. The
//!   second half is what pins NaN/Inf: JSON has no spelling for them, and
//!   an encoder emitting a bare `NaN` token would produce a document its
//!   own parser refuses. It does not — non-finite floats become `null`,
//!   pinned exactly in [`SHAPES`] — but the property is asserted for
//!   every value, not just the ones a table was hand-written for.
//! * **The depth bound is exact and total.** A chain of N tables encodes
//!   iff N <= 128, and beyond it the error says `nested deeper`. Past
//!   that guard lies a stack overflow, which is an abort no panic
//!   boundary can catch. The two directions do **not** meet, though the
//!   crate documents them as one bound: at exactly 128 the encoder
//!   produces a document `nitr.json.decode` refuses with `recursion
//!   limit exceeded`. That is reported as a finding and tolerated in
//!   [`check_output`] rather than asserted, so fixing it does not turn
//!   this target red.
//! * **Encoding is total in its failures.** Whatever the builder emits,
//!   `encode` either succeeds or fails with one of [`ENCODE_ERRORS`] —
//!   never a panic, and never a new unclassified message. A failure mode
//!   nobody wrote down is a failure mode nobody handles.
//! * **The shapes, exactly** ([`SHAPES`]). Every JSON-encoder edge a Lua
//!   value has, with the output it actually produces today: `null` for
//!   NaN and both infinities, `-0.0` preserved, `math.mininteger`
//!   exact, a non-UTF8 string becoming an **array of bytes**, an empty
//!   table `{}` against an array-marked one `[]`, and the three lossy
//!   cases — a mixed table dropping its map half, a sparse array dropping
//!   everything past the first hole, and an integer key colliding with
//!   the equal string key into a document with **duplicate names**. Those
//!   three are reported as findings; they are asserted here as they
//!   behave so that a change to any of them is loud instead of silent.
//! * **The grammar the decoder refuses** ([`REFUSED`]). The fixpoint only
//!   ever fires on documents that *parse*, so on its own it says nothing
//!   about what `nitr.json.decode` must turn away, and a decoder that grew
//!   trailing commas, `//` comments, single-quoted or bare names, or
//!   trailing garbage after a complete value would round-trip cleanly and
//!   be completely invisible. Each row is a document plus the substring
//!   its refusal must carry, so every laxer dialect is named rather than
//!   merely absent. The dialect matters because it is asymmetric: a
//!   handler that accepts `{"a":1,}` on the way in can never produce it on
//!   the way out, so anything that re-signs, caches by body, or forwards
//!   the document sees bytes its own encoder cannot reproduce.
//! * **The decoder's own depth bound.** 127 levels of nesting decode and
//!   128 do not, checked here rather than left to the fuzzer, which will
//!   not stack 128 brackets on its own. This is the far side of the
//!   asymmetry above: the encoder admits 128 levels of Lua tables.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mlua::{AnyUserData, Function, Lua, LuaString, ObjectLike as _, Value};
use nitr_fuzz::Input;

/// Every error class `encode` is allowed to fail with. Two come from the
/// crate (`check_json_depth`) and two from `serde_json`'s map-key
/// serializer; anything else means the failure path grew a case.
const ENCODE_ERRORS: &[&str] = &[
    "nested deeper than 128 levels",
    "key must be a string",
    "float key must be finite",
    "cannot serialize",
];

/// The guard in `nitr-std/src/utils.rs`.
const MAX_JSON_DEPTH: usize = 128;

/// What `encode` must do with one hand-built Lua value.
enum Want {
    /// The exact document. Only used where the shape has at most one key,
    /// so hash order cannot make this flaky.
    Exact(&'static str),
    /// Fragments the document must contain, in any order.
    Holds(&'static [&'static str]),
    /// A refusal whose message contains this.
    Refused(&'static str),
}

/// The Lua-value shapes a JSON encoder has to have an answer for, with
/// the answer this one gives. Compiled once per thread and asserted on
/// every run: none of them is reachable by mutating bytes, and each is a
/// place an encoder rewrite would land.
const SHAPES: &[(&str, &str, Want)] = &[
    ("nil", "return nil", Want::Exact("null")),
    // JSON cannot spell any of these three. `null` is what serde_json
    // does; a bare `NaN` token would be a document nothing can parse.
    ("NaN", "return 0/0", Want::Exact("null")),
    ("+inf", "return math.huge", Want::Exact("null")),
    ("-inf", "return -math.huge", Want::Exact("null")),
    ("a float that is integral", "return 3.0", Want::Exact("3.0")),
    ("negative zero", "return -0.0", Want::Exact("-0.0")),
    (
        "the smallest integer",
        "return math.mininteger",
        Want::Exact("-9223372036854775808"),
    ),
    // A Lua string is a byte string. Non-UTF8 bytes cannot be a JSON
    // string, and come out as an array of numbers instead — a silent
    // change of *type*, which is why it is pinned here.
    (
        "a non-UTF8 string",
        "return '\\255\\254'",
        Want::Exact("[255,254]"),
    ),
    ("an empty table", "return {}", Want::Exact("{}")),
    (
        "an empty array-marked table",
        "return setmetatable({}, ARRAY_MT)",
        Want::Exact("[]"),
    ),
    // Lossy, and asserted as it behaves: the table has a border, so it
    // serializes as a sequence and `a = 3` is gone.
    (
        "a mixed array and map",
        "return {1, 2, a = 3}",
        Want::Exact("[1,2]"),
    ),
    // Lossy: `#t` is 1, so everything past the hole is dropped.
    (
        "a sparse array",
        "return {[1] = 'a', [3] = 'c'}",
        Want::Exact("[\"a\"]"),
    ),
    // Lossy, and the worst of the three: an integer key and the equal
    // string key both stringify, so the document carries the same name
    // twice and re-decoding keeps only one.
    (
        "an integer key colliding with a string key",
        "return {[2] = 'a', ['2'] = 'b'}",
        Want::Holds(&["\"2\":\"a\"", "\"2\":\"b\""]),
    ),
    (
        "a fractional key",
        "return {[1.5] = 1}",
        Want::Exact("{\"1.5\":1}"),
    ),
    (
        "an infinite key",
        "return {[math.huge] = 1}",
        Want::Refused("float key must be finite"),
    ),
    ("a boolean key", "return {[true] = 1}", Want::Exact("{\"true\":1}")),
    (
        "a table key",
        "return {[{}] = 1}",
        Want::Refused("key must be a string"),
    ),
    (
        "a non-UTF8 key",
        "return {['\\255'] = 1}",
        Want::Refused("key must be a string"),
    ),
    (
        "a function value",
        "return {f = function() end}",
        Want::Refused("cannot serialize"),
    ),
    // A cycle is infinitely deep, so the depth guard is what stops it —
    // before any serializer recurses into it.
    (
        "a cycle",
        "local t = {} t.me = t return t",
        Want::Refused("nested deeper"),
    ),
    // A shared subtree is not a cycle and must be written out twice.
    (
        "a shared subtree",
        "local s = {1} return {a = s, b = s}",
        Want::Holds(&["\"a\":[1]", "\"b\":[1]"]),
    ),
    (
        "an empty container inside a map",
        "return {a = {1, 2}, b = {}}",
        Want::Holds(&["\"a\":[1,2]", "\"b\":{}"]),
    ),
];

/// Documents `nitr.json.decode` must refuse, each with a substring its
/// error has to carry. Every row is a concrete dialect the encoder cannot
/// produce, so accepting one would mean the two directions no longer
/// describe the same language. The messages are `serde_json`'s, read off
/// `serde_json::error::ErrorCode` and confirmed against 1.0.151.
const REFUSED: &[(&str, &str)] = &[
    // The JSON5/JavaScript relaxations, which are what a hand-rolled or
    // swapped-in parser tends to pick up first.
    (r#"{"a":1,}"#, "trailing comma"),
    ("[1,]", "trailing comma"),
    (r#"{'a':1}"#, "key must be a string"),
    ("{a:1}", "key must be a string"),
    // A complete value followed by anything at all. A decoder that stopped
    // at the first value would let a request body carry a second document
    // that only the *next* parser in the chain sees.
    (r#"{"a":1}xyz"#, "trailing characters"),
    (r#"{"a":1} // c"#, "trailing characters"),
    ("0x1f", "trailing characters"),
    // The non-finite spellings. `encode` writes `null` for all three (see
    // SHAPES), so a decoder that took these would be reading a language
    // its own encoder cannot write.
    ("NaN", "expected value"),
    ("Infinity", "expected value"),
    ("-Infinity", "invalid number"),
    // Number syntax JSON does not have, and the magnitude it cannot hold.
    ("+1", "expected value"),
    (".5", "expected value"),
    ("01", "invalid number"),
    ("1e309", "number out of range"),
    ("[1e309]", "number out of range"),
    // Strings: a lone surrogate cannot become a Rust `String`, and a raw
    // control character is not a JSON string character.
    (r#""\ud800\ud800""#, "lone leading surrogate"),
    (r#""\ud800""#, "unexpected end of hex escape"),
    (r#""\q""#, "invalid escape"),
    ("\"\u{1}\"", "control character"),
];

/// The decoder's nesting bound: `serde_json`'s default recursion limit.
/// One below it must decode and the bound itself must not — the guard that
/// keeps a hostile body off the stack, checked from both sides because a
/// fuzzer will not stack 128 brackets inside a 4 KiB input.
const MAX_DECODE_NESTING: usize = 127;

/// A canonical, order-independent rendering of a *decoded* value, so the
/// fixpoint below compares structure rather than the encoder's hash
/// order. Strings carry their length, so no separator inside one can be
/// mistaken for structure, and the array marker is kept so `[]` and `{}`
/// stay distinguishable.
const CANON: &str = r#"
local function canon(v)
  local t = type(v)
  if t == 'string' then return 's' .. #v .. ':' .. v end
  if t == 'number' then
    return (math.type(v) == 'integer' and 'i:' or 'f:') .. tostring(v)
  end
  if t ~= 'table' then return t .. ':' .. tostring(v) end
  local keys = {}
  for k in pairs(v) do keys[#keys + 1] = k end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  local parts = {}
  for i = 1, #keys do
    parts[i] = canon(keys[i]) .. '=' .. canon(rawget(v, keys[i]))
  end
  -- the only metatable a decoded value carries is the array marker
  local open = getmetatable(v) == nil and 'M{' or 'A{'
  return open .. table.concat(parts, ',') .. '}'
end
return canon
"#;

thread_local! {
    /// One Lua state for the whole process, with the `nitr.json` userdata,
    /// the canonicalizer and the [`SHAPES`] chunks built into its globals
    /// once. A fresh `Lua` per run costs more than every call this target
    /// makes, and compiling twenty-odd chunks per run would cost more
    /// still. State does carry over between runs — the caveat of any
    /// reused interpreter — which the collection at the end of each run
    /// keeps bounded.
    ///
    /// Everything is parked in the globals rather than held beside the
    /// state in Rust: an mlua handle allocates a shared refcount the first
    /// time it is cloned, and a handle living in a thread-local is never
    /// dropped, so LeakSanitizer reports that allocation at exit and the
    /// target ends non-zero. Handles fetched per run are dropped per run.
    static LUA: Lua = {
        let lua = Lua::new();
        let globals = lua.globals();
        let json = nitr_std::fuzzing::create_json_fn(&lua).expect("nitr.json");
        globals.set("json", json).expect("json global");
        let canon: Function = lua.load(CANON).eval().expect("canon");
        globals.set("canon", canon).expect("canon global");
        {
            use mlua::LuaSerdeExt as _;
            globals
                .set("ARRAY_MT", lua.array_metatable())
                .expect("ARRAY_MT global");
        }
        let shapes = lua.create_table().expect("shapes");
        for (i, (label, source, _)) in SHAPES.iter().enumerate() {
            let chunk = lua
                .load(*source)
                .set_name(*label)
                .into_function()
                .unwrap_or_else(|err| panic!("shape `{label}` does not compile: {err}"));
            shapes.set(i + 1, chunk).expect("shape");
        }
        globals.set("shapes", shapes).expect("shapes global");
        lua
    };
}

/// The handles one run works through, fetched out of the globals so they
/// are dropped when the run ends.
struct Ctx<'a> {
    lua: &'a Lua,
    json: AnyUserData,
    canon: Function,
}

impl<'a> Ctx<'a> {
    fn new(lua: &'a Lua) -> Self {
        let globals = lua.globals();
        Self {
            lua,
            json: globals.get("json").expect("json global"),
            canon: globals.get("canon").expect("canon global"),
        }
    }
}

/// Interesting `f64`s for the builder: the three JSON cannot represent,
/// the two zeroes, the extremes, and one integral float.
const FLOATS: &[f64] = &[
    f64::NAN,
    f64::INFINITY,
    f64::NEG_INFINITY,
    0.0,
    -0.0,
    1.5,
    -2.5e-8,
    f64::MAX,
    f64::MIN_POSITIVE,
    1e308,
    9_007_199_254_740_993.0,
    1.0,
];

/// How deep the builder may go. Past the bound on purpose, so a program
/// that nests all the way still lands on the guard rather than on a
/// stack overflow.
const MAX_BUILD_DEPTH: u32 = 140;

/// A cursor over the builder program. Past the end every byte reads as
/// zero, so a short input is still a valid program.
struct Program<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Program<'a> {
    fn byte(&mut self) -> u8 {
        let byte = self.data.get(self.at).copied().unwrap_or(0);
        self.at = self.at.saturating_add(1);
        byte
    }

    fn bytes(&mut self, len: usize) -> &'a [u8] {
        let start = self.at.min(self.data.len());
        let end = start.saturating_add(len).min(self.data.len());
        self.at = end;
        &self.data[start..end]
    }
}

/// Builds one Lua value from the program. Every branch is a shape a real
/// script can hand to `nitr.json.encode`.
fn build(lua: &Lua, program: &mut Program, budget: &mut u32, depth: u32) -> Value {
    if *budget == 0 || depth > MAX_BUILD_DEPTH {
        return Value::Nil;
    }
    *budget -= 1;
    let kind = program.byte() % 12;
    // Every container branch opens with a fresh table and a small entry
    // count, so the shapes stay within the node budget.
    let out = lua.create_table().expect("table");
    let count = usize::from(program.byte()) % 5;
    match kind {
        0 => Value::Nil,
        1 => Value::Boolean(program.byte() % 2 == 1),
        2 => {
            let mut bytes = [0u8; 8];
            let read = program.bytes(8);
            bytes[..read.len()].copy_from_slice(read);
            Value::Integer(i64::from_le_bytes(bytes))
        }
        3 => Value::Number(FLOATS[usize::from(program.byte()) % FLOATS.len()]),
        4 => {
            let len = usize::from(program.byte()) % 24;
            Value::String(lua.create_string(program.bytes(len)).expect("string"))
        }
        // A sequence, and the same sequence marked as an array — the
        // marker is the only thing that makes an empty one encode as `[]`.
        5 | 6 => {
            for i in 1..=count {
                let item = build(lua, program, budget, depth + 1);
                out.set(i, item).expect("array item");
            }
            if kind == 6 {
                use mlua::LuaSerdeExt as _;
                out.set_metatable(Some(lua.array_metatable()))
                    .expect("array metatable");
            }
            Value::Table(out)
        }
        // String keys, including non-UTF8 ones and the empty string.
        7 => {
            for _ in 0..count {
                let len = usize::from(program.byte()) % 8;
                let key = lua.create_string(program.bytes(len)).expect("key");
                let item = build(lua, program, budget, depth + 1);
                out.set(key, item).expect("map entry");
            }
            Value::Table(out)
        }
        // Integer keys, which is where the array/map ambiguity lives: a
        // hole, a zero key or a large one all change what comes out.
        8 => {
            for _ in 0..count {
                let key = i64::from(program.byte());
                let item = build(lua, program, budget, depth + 1);
                out.set(key, item).expect("integer key");
            }
            Value::Table(out)
        }
        // Float keys. `inf` is a legal Lua table index, and the encoder is
        // what refuses it — the case worth reaching. NaN is not: Lua
        // raises on a NaN index, and `Table::set` reaches `lua_rawset`
        // with no protected frame above it, so that raise is an `abort()`
        // rather than an `Err`. That is a footgun of mlua's and not a
        // shape `nitr.json` can be handed, so NaN is kept out of the key
        // position rather than fuzzed into a false positive.
        9 => {
            for _ in 0..count {
                let key = FLOATS[usize::from(program.byte()) % FLOATS.len()];
                let item = build(lua, program, budget, depth + 1);
                if !key.is_nan() {
                    out.set(key, item).expect("float key");
                }
            }
            Value::Table(out)
        }
        10 => {
            for _ in 0..count {
                let key = program.byte() % 2 == 1;
                let item = build(lua, program, budget, depth + 1);
                out.set(key, item).expect("boolean key");
            }
            Value::Table(out)
        }
        // A table as a key: legal in Lua, and not a JSON name.
        _ => {
            for _ in 0..count {
                let item = build(lua, program, budget, depth + 1);
                out.set(lua.create_table().expect("key table"), item)
                    .expect("table key");
            }
            Value::Table(out)
        }
    }
}

/// A chain of `depth` nested tables, root included — the shape the depth
/// guard exists for.
fn chain(lua: &Lua, depth: usize) -> Value {
    let root = lua.create_table().expect("table");
    let mut cursor = root.clone();
    for _ in 1..depth {
        let next = lua.create_table().expect("table");
        cursor.set("x", next.clone()).expect("set");
        cursor = next;
    }
    Value::Table(root)
}

fn encode(ctx: &Ctx, value: Value) -> mlua::Result<String> {
    ctx.json.call_method("encode", value)
}

fn decode(ctx: &Ctx, text: &LuaString) -> mlua::Result<Value> {
    ctx.json.call_method("decode", text)
}

fn canon(ctx: &Ctx, value: Value, what: &str) -> String {
    ctx.canon
        .call(value)
        .unwrap_or_else(|err| panic!("{what}: could not canonicalize: {err}"))
}

/// The fixpoint, entered from a value that already came out of a decode:
/// re-encoding it and decoding that again must land on the same
/// structure.
fn fixpoint(ctx: &Ctx, first: Value, what: &str) {
    let once = encode(ctx, first.clone())
        .unwrap_or_else(|err| panic!("{what}: a decoded value did not re-encode: {err}"));
    let text = ctx.lua.create_string(&once).expect("string");
    let second = decode(ctx, &text).unwrap_or_else(|err| {
        panic!("{what}: encode produced {once:?}, which its own decoder refuses: {err}")
    });
    let before = canon(ctx, first, what);
    let after = canon(ctx, second, what);
    assert_eq!(
        before, after,
        "{what}: decode(encode(decode(x))) is not decode(x); encode said {once:?}"
    );
}

/// Checks a document `encode` produced: it must parse, and then be a
/// fixpoint of the round trip.
///
/// The one tolerated failure is the recursion limit. `encode` admits 128
/// levels of Lua tables while `serde_json` admits 127 of nesting on the
/// way back, so a value at exactly the bound encodes into a document
/// `nitr.json.decode` refuses. That asymmetry is reported as a finding;
/// it is tolerated rather than asserted here so that fixing it does not
/// turn this target red.
fn check_output(ctx: &Ctx, produced: &str, what: &str) {
    let text = ctx.lua.create_string(produced).expect("string");
    match decode(ctx, &text) {
        Ok(first) => fixpoint(ctx, first, what),
        Err(err) => assert!(
            err.to_string().contains("recursion limit"),
            "{what}: encode produced {produced:?}, which its own decoder refuses: {err}"
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let depth = usize::from(input.u16() % 160) + 1;
    let document = input.field();
    let program = input.rest();

    LUA.with(|lua| {
        let ctx = Ctx::new(lua);
        let shapes: mlua::Table = lua.globals().get("shapes").expect("shapes global");

        if std::env::var_os("NITR_FUZZ_DEBUG").is_some() {
            eprintln!(
                "DEBUG depth={depth} json={:?} program={program:?}",
                String::from_utf8_lossy(document)
            );
        }

        // --- the shapes, every run ------------------------------------------
        // The only assertions here that a mutated byte string cannot reach,
        // and the only ones that pin what the encoder does with a value JSON
        // has no spelling for.
        for (i, (label, _, want)) in SHAPES.iter().enumerate() {
            let shape: Function = shapes.get(i + 1).expect("shape");
            let value: Value = shape.call(()).unwrap_or_else(|err| {
                panic!("shape `{label}` did not evaluate: {err}");
            });
            let outcome = encode(&ctx, value);
            match want {
                Want::Exact(text) => {
                    let got = outcome
                        .unwrap_or_else(|err| panic!("`{label}` did not encode: {err}"));
                    assert_eq!(got, *text, "`{label}` encoded to {got:?}, not {text:?}");
                }
                Want::Holds(fragments) => {
                    let text = outcome
                        .unwrap_or_else(|err| panic!("`{label}` did not encode: {err}"));
                    for fragment in *fragments {
                        assert!(
                            text.contains(fragment),
                            "`{label}` encoded to {text:?}, which does not contain {fragment:?}"
                        );
                    }
                }
                Want::Refused(reason) => {
                    let err = outcome
                        .err()
                        .unwrap_or_else(|| panic!("`{label}` encoded, and must not"));
                    assert!(
                        err.to_string().contains(reason),
                        "`{label}` was refused with {err}, not with {reason:?}"
                    );
                }
            }
        }
        // A document carrying the same name twice keeps only one of them:
        // the collision above is data loss, not just an odd spelling.
        let collided = lua
            .create_string(r#"{"2":"a","2":"b"}"#)
            .expect("string");
        let collided = decode(&ctx, &collided).expect("duplicate names parse");
        assert_eq!(
            canon(&ctx, collided, "duplicate names"),
            "M{s1:2=s1:b}",
            "a document with a duplicated name no longer collapses to its last value"
        );

        // --- the grammar the decoder refuses -----------------------------------
        // The other direction of SHAPES: what `decode` must turn away. The
        // fixpoint below only ever fires on documents that parse, so without
        // this a decoder that grew a laxer grammar would be silent.
        for (document, reason) in REFUSED {
            let text = lua.create_string(*document).expect("string");
            let err = match decode(&ctx, &text) {
                Ok(_) => panic!(
                    "nitr.json.decode accepted {document:?}, which is not JSON and which \
                     nitr.json.encode cannot produce"
                ),
                Err(err) => err.to_string(),
            };
            assert!(
                err.contains(reason),
                "{document:?} was refused with {err}, not with {reason:?}"
            );
        }
        // The decoder's own nesting bound, from both sides.
        let nested = |levels: usize| format!("{}1{}", "[".repeat(levels), "]".repeat(levels));
        let deepest = lua
            .create_string(nested(MAX_DECODE_NESTING))
            .expect("string");
        decode(&ctx, &deepest).unwrap_or_else(|err| {
            panic!("{MAX_DECODE_NESTING} levels of nesting must decode, and did not: {err}")
        });
        let too_deep = lua
            .create_string(nested(MAX_DECODE_NESTING + 1))
            .expect("string");
        match decode(&ctx, &too_deep) {
            Ok(_) => panic!(
                "{} levels of nesting decoded; past the recursion limit lies the stack \
                 overflow this bound exists to prevent",
                MAX_DECODE_NESTING + 1
            ),
            Err(err) => assert!(
                err.to_string().contains("recursion limit"),
                "{} levels of nesting were refused with {err}, not with the recursion limit",
                MAX_DECODE_NESTING + 1
            ),
        }

        // --- the attacker's document ------------------------------------------
        let text = lua.create_string(document).expect("string");
        if let Ok(first) = decode(&ctx, &text) {
            fixpoint(&ctx, first, "decode(input)");
        }

        // --- the depth bound ---------------------------------------------------
        match encode(&ctx, chain(lua, depth)) {
            Ok(text) => {
                assert!(
                    depth <= MAX_JSON_DEPTH,
                    "a {depth}-deep table chain encoded to {} bytes; the bound is \
                     {MAX_JSON_DEPTH}, and past it lies a stack overflow no panic \
                     boundary can catch",
                    text.len()
                );
                check_output(&ctx, &text, "the depth chain");
            }
            Err(err) => {
                assert!(
                    depth > MAX_JSON_DEPTH,
                    "a {depth}-deep table chain was refused: {err}"
                );
                assert!(
                    err.to_string()
                        .contains("nested deeper than 128 levels"),
                    "a {depth}-deep chain was refused with {err}, not with the depth error"
                );
            }
        }

        // --- the builder -------------------------------------------------------
        let mut program = Program {
            data: program,
            at: 0,
        };
        let mut budget = 400u32;
        let built = build(lua, &mut program, &mut budget, 0);
        match encode(&ctx, built) {
            Ok(text) => {
                assert!(!text.is_empty(), "encode produced an empty document");
                check_output(&ctx, &text, "the builder");
            }
            Err(err) => {
                let message = err.to_string();
                assert!(
                    ENCODE_ERRORS.iter().any(|class| message.contains(class)),
                    "encode failed with an unclassified error: {message}"
                );
            }
        }

        lua.gc_collect().expect("gc");
    });
});
