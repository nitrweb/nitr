// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The Lua runtime itself, underneath HTTP: what a pooled state costs to
//! create, what a handler script costs to load, and what a single call into
//! Lua costs once the state is warm.
//!
//! These are the numbers that move when the sandbox setup changes (standard
//! library selection, the instruction hook, the memory limiter) and when
//! server startup or a `nitr reload` gets slower.

mod common;

use common::{tokio_runtime, write_file};
use mlua::Value;
use nitr::{Builtins, Config, Runtime, Server};

fn main() {
    divan::main();
}

/// A handler script of realistic size: a few routes, middleware, and the
/// closures that go with them.
const APP: &str = r#"
local app = nitr.app()

app:use(function(next)
    return function(req)
        local res = next(req)
        res.headers["X-App"] = "nitr"
        return res
    end
end)

app:get("/", function(req)
    return nitr.text("home")
end)

app:get("/users/:id", function(req)
    return nitr.json({ id = req.params.id })
end)

app:post("/users", function(req)
    return nitr.json({ created = true }, 201)
end)

app:get("/health/deep", function(req)
    return nitr.json({ ok = true })
end)

app:on_error(function(err, req)
    return nitr.error(500, { code = "INTERNAL" })
end)

return app
"#;

/// The state the server actually pools: the default `[lua] stdlib` set —
/// including `package`, with the `loadlib`/`cpath` scrub and the `require`
/// pinning that come with it — plus the default memory limit and execution
/// budget, derived through the same `Config::runtime_opts()` the server
/// uses. `Runtime::new()` would be cheaper to build (its default set omits
/// `package`), and a benchmark of the pooled state must not measure that.
fn server_shaped_state() -> Runtime {
    let opts = Config::default()
        .runtime_opts()
        .expect("derive the default runtime options");
    Runtime::new_with(opts).expect("create a Lua runtime")
}

/// Creating a sandboxed state: standard library selection, the memory
/// limiter, and the instruction-count hook. Paid once per pool worker, and
/// again for every state a poisoned request forces the pool to rebuild.
#[divan::bench]
fn new_state(bencher: divan::Bencher<'_, '_>) {
    bencher.bench_local(|| divan::black_box(server_shaped_state()));
}

/// Checking a state out of the pool and returning it: the per-request
/// synchronization every single dispatch pays before any Lua runs.
#[divan::bench]
fn pool_checkout(bencher: divan::Bencher<'_, '_>) {
    let rt = tokio_runtime();
    let pool = nitr::RuntimePool::new(vec![server_shaped_state()]);
    bencher.bench_local(|| {
        rt.block_on(async {
            divan::black_box(pool.get().await);
        })
    });
}

/// A self-contained script of about the size of a real `app.lua`: no
/// `nitr` namespace, because a bare runtime has none — what is measured is
/// reading the file, compiling the chunk, and building its closures. Paid
/// at startup, on a reload, and on every request in dev mode.
const CHUNK: &str = r#"
local module = {}

local function middleware(name)
    return function(next)
        return function(req)
            local res = next(req)
            res[name] = true
            return res
        end
    end
end

module.layers = {}
for i = 1, 8 do
    module.layers[i] = middleware("layer" .. i)
end

function module.render(rows)
    local out = {}
    for i = 1, #rows do
        out[i] = string.format("%d:%s", rows[i].id, rows[i].name)
    end
    return table.concat(out, ",")
end

function module.reduce(rows)
    local total = 0
    for i = 1, #rows do
        total = total + (rows[i].score or 0)
    end
    return total
end

return module
"#;

/// Compiling and running a script in a warm state.
#[divan::bench]
fn compile_script(bencher: divan::Bencher<'_, '_>) {
    let source = write_file("runtime-chunk.lua", CHUNK);
    let runtime = Runtime::new().expect("create a Lua runtime");

    bencher.bench_local(|| divan::black_box(runtime.eval_script(&source).expect("eval the chunk")));
}

/// One call into Lua through the runtime's cached coroutine, including the
/// execution-deadline bookkeeping. This is the fixed cost every request
/// pays before the handler's own work starts.
#[divan::bench]
fn call_into_lua(bencher: divan::Bencher<'_, '_>) {
    let rt = tokio_runtime();
    let script = write_file("runtime-fn.lua", "return function(n) return n + 1 end");
    let mut runtime = Runtime::new().expect("create a Lua runtime");
    let f = match runtime.eval_script(&script).expect("eval the function") {
        Value::Function(f) => f,
        other => panic!("expected a function, got {}", other.type_name()),
    };

    bencher.bench_local(|| {
        let result: i64 = rt
            .block_on(runtime.call_function(f.clone(), 41))
            .expect("call the Lua function");
        divan::black_box(result)
    });
}

/// A Lua-side loop, called the same way a handler is: the coroutine
/// round-trip amortized over real work, and the instruction hook firing
/// along the way.
#[divan::bench]
fn call_into_lua_with_work(bencher: divan::Bencher<'_, '_>) {
    let rt = tokio_runtime();
    let script = write_file(
        "runtime-loop.lua",
        "return function(n) local s = 0 for i = 1, n do s = s + i * 2 end return s end",
    );
    let mut runtime = Runtime::new().expect("create a Lua runtime");
    let f = match runtime.eval_script(&script).expect("eval the function") {
        Value::Function(f) => f,
        other => panic!("expected a function, got {}", other.type_name()),
    };

    bencher.bench_local(|| {
        let result: i64 = rt
            .block_on(runtime.call_function(f.clone(), 10_000))
            .expect("call the Lua function");
        divan::black_box(result)
    });
}

/// Full server startup: build the pool, run the handler script in every
/// state, and compile the router. This is what a deploy and a `nitr
/// reload` wait for.
#[divan::bench]
fn server_startup(bencher: divan::Bencher<'_, '_>) {
    let rt = tokio_runtime();
    let script = write_file("runtime-startup.lua", APP);

    bencher.bench_local(|| {
        let server = rt.block_on(async {
            Server::builder()
                .handler_script(&script)
                .builtins(Builtins::JSON | Builtins::HTTP)
                .workers(1)
                .build()
                .await
                .expect("build the server")
        });
        divan::black_box(server)
    });
}
