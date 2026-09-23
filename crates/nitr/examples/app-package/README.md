# Nitr application package

The conventional layout the `nitr` CLI works with:

```
app-package/
├── nitr.toml         server + app configuration
├── app.lua           routes and middleware (returns nitr.app())
├── config.lua        runs once at startup (schema setup); result → nitr.cfg
├── lib/notes.lua     plain functions: normalize, validate, render
├── public/           static files, served by Rust
└── tests/            *.lua files for `nitr test`
```

From the repository root:

```sh
cargo run -p nitr-cli -- -c crates/nitr/examples/app-package/nitr.toml check
cargo run -p nitr-cli -- -c crates/nitr/examples/app-package/nitr.toml test
cargo run -p nitr-cli -- -c crates/nitr/examples/app-package/nitr.toml run
```

`tests/notes_test.lua` shows the three kinds of test `nitr test` runs:
unit tests of `lib/notes.lua` (no server), integration tests through the
real router with a client, the database fixtures and the doubles
(`t.clock`, `t.env`, `t.fetch`, `t.logs`), and a handler called in
isolation with a fake request. The rule of thumb: *if a function does
not take `req`, unit test it; if it does, go through `t.request`.*

In your own project you would just run `nitr check` / `nitr test` /
`nitr dev` next to `nitr.toml` (scaffold one with `nitr init`).
Send `SIGHUP` to a running server for a zero-downtime reload.
