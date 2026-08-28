# API stability and compatibility

What Nitr promises about each of its surfaces, from strongest to weakest.
One version number covers everything (the workspace version); the `nitr.*`
Lua API does not get its own — instead this table states how each surface
is allowed to change. Pre-1.0 (`0.x`), a minor bump may break; the rules
below describe the *shape* of the promise that hardens at 1.0.

| Surface | Promise |
| --- | --- |
| **The `nitr.*` Lua API** | The strongest promise: this is what users depend on most and can least easily migrate. Breaking changes need a major version and a migration note in the changelog. The generated [API description](nitr-api.md) is the authoritative inventory — a test fails if a registered entry is undocumented, so the promised surface is always enumerable. `nitr.ext.*` is reserved for user modules and will never be occupied by a builtin. |
| **`nitr.toml`** | Unknown keys are rejected at startup, so a removed key is a loud error, never silence. A renamed key ships with the old name still accepted (and warned about) for one minor cycle before removal. |
| **The `nitr` crate (facade)** | Standard semver. This is the supported Rust entry point for applications and embedders. |
| **`nitr-core` / `nitr-std` / `nitr-http`** | Published and usable directly, but **explicitly unstable pre-1.0**: they move as fast as the phases need. Depend on the `nitr` facade unless you are writing an extension crate. The extension contract (`ServerBuilder::module`, `nitr_table`, `mount`, `ModuleFn`) is the part expected to settle first. |
| **`nitr-cli` flags and output** | Flags follow the toml policy (deprecate one minor cycle, then remove). Human-readable *output text* is not an API; `[log] format = "json"` and exit codes are. |
| **Generated type definitions** (`nitr-types.lua`) | Regenerated from the API description each release; they version with the crate and carry no independent promise. |

## Deprecation policy

Deprecations warn for **one minor version** before removal, and the warning
names the replacement (`use nitr.time.format instead of ...`). Removals and
renames will be recorded in a `CHANGELOG.md` starting with the first
release.

## Minimum supported Rust version

The MSRV is declared as `rust-version` in the workspace manifest and
checked by the CI's pinned matrix entry. **Bumping the MSRV is a minor
change, not a breaking one**, and is called out in the changelog.

## Publishing

The five crates version together and publish in dependency order:

```
nitr-core → nitr-std → nitr-http → nitr → nitr-cli
```

## What is deliberately not promised

- Internal module layout of any crate (`pub(crate)` boundaries move freely).
- The `#[doc(hidden)]` fuzzing seams (`nitr_std::fuzzing`, `nitr_http::fuzzing`)
  and the items they re-export, which are `pub` only to reach `fuzz/`.
- Benchmark names and numbers, the test framework's failure text, and the
  dev-mode 500 page's markup.
- Behavior reachable only through `Server::builder().setup()` — the
  documented low-level escape hatch is sharp by design.
