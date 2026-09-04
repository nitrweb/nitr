<!--
SPDX-License-Identifier: MIT OR Apache-2.0
This file is part of Nitr.
Copyright (C) 2024-present Jose Quintana <joseluisq.net>
-->

# Seed corpora

One directory per fuzz target. These files are **committed**; the working
corpus under `fuzz/corpus/` is generated, gitignored, and topped up from
here by `make fuzz` and by CI (`cp -n`), so a cold start — a first run, or
an evicted cache — never begins at zero coverage.

## Seeds must be written in the target's input format

This is the part that silently went wrong before, and the reason this
file exists.

Targets used to take `Arbitrary` tuples (`|input: (&str, u64)|`).
`<&str as Arbitrary>::arbitrary` reads its length from the **tail** of the
buffer, so a seed written as plain text never lands in the field it was
written for. Measured against the seeds as they were committed:

| Seed | Written as | What the target received |
| ---- | ---------- | ------------------------ |
| `range-header/simple` | `bytes=0-499` | header `"by"`, len `4121969244163499380` |
| `range-header/multi` | `bytes=0-0,5-9` | header `"bytes"`, len `12724837855080509` |
| `multipart/simple` | a full body with `boundary=XX--` | content type `"multipart/"` — no boundary parameter, so the parser was never entered |
| `accept-negotiation/zero-q` | `application/json;q=0, text/*` | `("application/js", ["n;q=0, text"])` |
| `cookie-verify/pair` | one signed cookie | `("ses", "sion=dXNlci00Mg…", "Fy", "c3R1dnd4")` |
| `json-lua/object.json` | a JSON object | the first 29 bytes, so it never parsed |

Fourteen of sixteen seeds were dead on arrival, and the two survivors were
partial. The tail-length rule also made the corpus unstable: appending one
byte to a seed re-cut *every* field.

So the targets now decode a flat, explicit format instead — see
`fuzz/src/lib.rs`:

```text
[ fixed-width little-endian numbers ][ field \0 field \0 … \0 last field ]
```

Numbers are read off the front; the rest splits on NUL, and the last field
runs to the end. Nothing is length-prefixed, so editing text in the middle
of a seed does not move any boundary. A short input is valid: missing
numbers read as `0`, missing fields as empty.

Each target's module doc states its own layout.

## Writing a seed

`printf` is enough. With no numeric prefix, a seed is just its text:

```sh
printf 'bytes=0-499' > fuzz/seeds/range-header/simple
```

With a numeric prefix, write the bytes little-endian — here a `u64`
length of 1000 (`0x3e8`) followed by the header:

```sh
printf '\xe8\x03\x00\x00\x00\x00\x00\x00bytes=0-499' > fuzz/seeds/range-header/simple
```

Multiple text fields are separated by NUL:

```sh
printf 'multipart/form-data; boundary=B\0--B\r\ncontent-disposition: form-data; name="a"\r\n\r\nv\r\n--B--\r\n' \
  > fuzz/seeds/multipart/simple
```

## Verifying a seed actually decodes

Do not assume — the whole point of this file is that assuming failed once.
Run the target over the single seed and confirm it reaches the code you
meant to reach:

```sh
cd fuzz
CARGO_BUILD_TARGET= cargo +nightly fuzz run --target x86_64-unknown-linux-gnu \
  range-header seeds/range-header/simple -- -runs=1
```

A seed that decodes to nothing costs nothing at runtime, which is exactly
why a broken one can sit unnoticed for a year. When in doubt, add a
temporary `eprintln!` of the decoded fields, confirm, and remove it.

### Never pass a seed *directory* on the command line

Note that the command above names a single **file**. That is safe:
libFuzzer runs a file argument as one input and writes nothing.

A **directory** argument is a different thing entirely — it becomes
libFuzzer's working corpus, and every interesting input it discovers is
written *into it*, named by the SHA-1 of its contents:

```sh
# SAFE: one file, executed once, nothing written.
cargo +nightly fuzz run json-lua seeds/json-lua/object -- -runs=1

# SAFE: no directory argument, so the default fuzz/corpus/<target> is used.
cargo +nightly fuzz run json-lua -- -max_total_time=60

# WRONG: this makes the curated seed directory the corpus. One 60-second
# run buried these seeds under 800 generated files.
cargo +nightly fuzz run json-lua fuzz/seeds/json-lua
```

`make fuzz` does the right thing already: it `cp -n`s the seeds into
`fuzz/corpus/<target>/` and then runs with no directory argument, so the
seeds are used without being written to.

`make fuzz-check` (which `make lint` runs, so every contributor hits it)
fails if any file under `fuzz/seeds/` has a 40-character hex name, because
nothing here is ever legitimately named that way. If it fires, the fix is
to move the listed files into `fuzz/corpus/<target>/` rather than delete
them — they are real coverage, just filed in the wrong place.

### Landing in the right field is only half of it

The fields can decode perfectly and the seed still exercise nothing,
because the *contents* do not fit together. Two that were found this way,
after the format above had already fixed the field cutting:

| Seed | Decoded correctly into | Why it still did nothing |
| ---- | ---------------------- | ------------------------ |
| `json-lua/numbers` | a JSON document of interesting numbers | it ended in `1e309`, which `serde_json` refuses as `number out of range`, so the *whole array* failed to decode and none of `i64::MAX`, `i64::MIN`, `-0.0` or `1e-400` ever reached the round trip |
| `multipart/simple`, `multipart/bytewise` | `boundary=XX--` and a body | the body's delimiters spelled `--XX`, but the dash-boundary for `XX--` is `--XX--`, so multer found no part at all and returned `incomplete multipart stream` |

So confirm the *outcome*, not just the decode: that the document parses,
that the body yields the parts it was written to yield, that the token
verifies. A seed whose only job is an error path is fine — name it for
that error (`truncated`, `numbers-out-of-range`) so the next reader knows
it is deliberate.

## Dictionaries

`fuzz/dicts/<target>.dict` holds the grammar tokens for a target
(`"bytes="`, `"boundary="`, `"q="`, …). `make fuzz` and CI pass it with
`-dict=` when present. A dictionary is what lets libFuzzer synthesize
structure it would otherwise have to discover byte by byte.
