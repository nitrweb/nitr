---
name: lua-api
description: Adding or changing anything a Lua script can call or read in Nitr — `nitr.*` builtins, `req`/response fields, `nitr.test`, route options — including the contract rules, the mlua/Lua conversion traps that silently lose data, bounds on script-supplied values, and the files that must change together. Use before touching crates/nitr-std, the Lua-facing parts of crates/nitr-http, or nitr-api.toml.
---

# The Lua API (Nitr)

The Lua surface is the product. Scripts are semi-trusted, and every value a
script hands to Rust is untrusted input.

## The contract

- **Document every name, option and return shape** in
  `crates/nitr-cli/src/nitr-api.toml`. Then regenerate:
  `NITR_API_REGEN=1 cargo test -p nitr-cli --test api`. The same test
  fails when something is registered but undescribed, and when
  `resources/` has drifted.
- **Options** are a trailing table. Unknown keys are ignored; a wrong type
  raises. Request header keys are lowercase.
- **Bad data returns `nil, reason`. A caller bug raises.** Pick one per
  function, write it in the docs, and test it.
- **Keep one home per rule.** Route through the existing helper instead of
  writing a second copy:
  - `check_json_bounds`, `nitr_std::json_encode` (bounded serialization);
  - `safe_join`;
  - `new_hmac`;
  - `merge_cookie_opts`;
  - `error_lua_value`.
- **A new builtin is gated by its feature flag**, and is registered in
  `register_builtins` under that flag. It must compile, and do what its
  docs say, under both `--features all` and `--no-default-features`.

## Values from scripts are untrusted

- **Sizes and counts** arrive as `i64`. Range-check before any `as usize`
  or allocation.
- **Durations from floats** go through `Duration::try_from_secs_f64` and
  are clamped. `from_secs_f64` panics on NaN, infinity and negatives.
- **`Instant + Duration`** panics on overflow: use `checked_add`.
- **Anything that recurses over a Lua value is depth-bounded first.** Deep
  nesting overflows the stack, and a stack overflow is an abort that no
  boundary catches.
- **Strings may be arbitrary bytes.** Keep `LuaString` bytes when the
  bytes matter (URLs, cookies, crypto input). `to_string_lossy` silently
  rewrites data, so use it only for text meant for display.
- **Never hand a script a raw filesystem, process or network primitive.**
  File access resolves under a configured root through `safe_join` plus
  canonical containment.

## mlua and Lua traps (verified in mlua 0.12 and Lua 5.4 sources)

| Trap | Consequence | Do instead |
|---|---|---|
| `Table::sequence_values` stops at the table's border (`raw_len`) | a `nil` in a parameter list is silently dropped | iterate up to `n` (the `table.pack` convention) or up to the highest integer key |
| serializing a table with `raw_len() > 0` treats it as an array | `{ "a", total = 1 }` loses `total`: in JSON, a session, a cache entry, JWT claims | refuse mixed tables with an error, or enable mixed-table detection |
| `lua.to_value` turns JSON `null` into `Value::NULL`, a light userdata | the value is **truthy** in Lua, and SQL/JSON code refuses it | map `NULL` explicitly where it can arrive |
| `pairs` order depends on a per-state hash seed | two pooled states, or two restarts, iterate differently | sort keys, or take an ordered list, whenever order is observable |
| `HeaderValue::to_str` fails on non-ASCII bytes, and a map `set` keeps only the last value | a header value vanishes, and repeated headers collapse to one | convert lossily for display, and keep every value in order when repeats matter |

## Execution and state

- **Async builtins** (`create_async_function`, `add_async_method`) never
  hold a Lua borrow or a lock across `.await`. Copy plain data out first.
- **Blocking work** goes through `spawn_blocking`: SQLite, argon2,
  templates, large file reads.
- **Per-state policy** that `UserData` methods need lives in app data
  (`lua.set_app_data`). Look it up at call time, and treat "absent" as the
  production default.
- **A value stored across requests** (cache, rate buckets, pools) is
  bounded in entries and bytes, and has an eviction rule.

## Change checklist

1. Check the contract entry: added or updated in `nitr-api.toml`, and
   `resources/` regenerated.
2. Test through Lua itself, not only the Rust helper: build `mlua::Lua`,
   call `register_builtins`, and evaluate the snippet. Cover the documented
   happy path, `nil, reason`, the raise, and one hostile input (huge,
   deep, non-UTF-8, `nil` hole, mixed table).
3. Update README, the annotated `nitr.toml` and any example that shows the
   call, in the same change.
4. Run the feature matrix (`verify`).
