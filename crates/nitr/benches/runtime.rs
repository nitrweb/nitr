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

/// The same startup at a realistic pool size. Everything paid per state —
/// creating it, registering the builtins, reading and compiling the
/// handler script — scales with `workers`, and the single-worker bench
/// above cannot see that slope.
#[divan::bench]
fn server_startup_8_workers(bencher: divan::Bencher<'_, '_>) {
    let rt = tokio_runtime();
    let script = write_file("runtime-startup-8.lua", APP);

    bencher.bench_local(|| {
        let server = rt.block_on(async {
            Server::builder()
                .handler_script(&script)
                .builtins(Builtins::JSON | Builtins::HTTP)
                .workers(8)
                .build()
                .await
                .expect("build the server")
        });
        divan::black_box(server)
    });
}

/// The runtime's execution budget, as a Lua function returning an `i64`
/// evaluated from `source`.
fn function_in(runtime: &Runtime, name: &str, source: &str) -> mlua::Function {
    let script = write_file(name, source);
    match runtime.eval_script(&script).expect("eval the function") {
        Value::Function(f) => f,
        other => panic!("expected a function, got {}", other.type_name()),
    }
}

/// A server-shaped state with the execution budget switched on or off:
/// the only difference between the two is whether the instruction-count
/// hook is installed.
fn state_with_budget(budget: Option<std::time::Duration>) -> Runtime {
    let mut opts = Config::default()
        .runtime_opts()
        .expect("derive the default runtime options");
    opts.exec_timeout = budget;
    Runtime::new_with(opts).expect("create a Lua runtime")
}

/// The one always-on multiplier on Lua execution: the instruction-count
/// hook that enforces the CPU budget.
///
/// Lua 5.4 keeps the interpreter on its trap path for *every* instruction
/// while a count hook is set (`luaG_traceexec` returns 1 whenever the
/// counter has not reached zero — `ldebug.c`), so the hook's cost is per
/// instruction and the interval only decides how often the Rust closure
/// runs. `budget_on` vs `budget_off` is that cost; the `raw_hook_*`
/// benches show, on a bare mlua state, that the interval does not move it.
mod hook {
    use super::*;

    /// A tight arithmetic loop: pure interpreter time, no allocation, no
    /// Rust boundary — the shape where the trap is the largest share.
    const LOOP: &str =
        "return function(n) local s = 0 for i = 1, n do s = s + i * 2 end return s end";
    const ITERATIONS: i64 = 100_000;

    fn loop_bench(bencher: divan::Bencher<'_, '_>, budget: Option<std::time::Duration>) {
        let rt = tokio_runtime();
        let mut runtime = state_with_budget(budget);
        let f = function_in(&runtime, "runtime-hook-loop.lua", LOOP);

        bencher.bench_local(|| {
            let result: i64 = rt
                .block_on(runtime.call_function(f.clone(), ITERATIONS))
                .expect("call the Lua function");
            divan::black_box(result)
        });
    }

    /// The pooled state as the server runs it: budget on, hook installed.
    #[divan::bench]
    fn budget_on(bencher: divan::Bencher<'_, '_>) {
        loop_bench(bencher, Some(std::time::Duration::from_secs(30)));
    }

    /// The same state with `exec_timeout = None`: no hook, no trap. Not a
    /// configuration the server should run with; the reference point.
    #[divan::bench]
    fn budget_off(bencher: divan::Bencher<'_, '_>) {
        loop_bench(bencher, None);
    }

    /// A bare mlua state with a count hook at `interval` (0 = no hook),
    /// running the same loop directly. No Nitr code involved: this isolates
    /// the interpreter's own behaviour under `LUA_MASKCOUNT`.
    fn raw_bench(bencher: divan::Bencher<'_, '_>, interval: u32) {
        let lua = mlua::Lua::new();
        if interval > 0 {
            lua.set_global_hook(
                mlua::HookTriggers::new().every_nth_instruction(interval),
                |_, _| Ok(mlua::VmState::Continue),
            )
            .expect("install the count hook");
        }
        let f: mlua::Function = lua.load(LOOP).eval().expect("eval the loop");

        bencher.bench_local(|| {
            let result: i64 = f.call(ITERATIONS).expect("call the Lua function");
            divan::black_box(result)
        });
    }

    #[divan::bench]
    fn raw_no_hook(bencher: divan::Bencher<'_, '_>) {
        raw_bench(bencher, 0);
    }

    /// The interval Nitr uses (`HOOK_INSTRUCTION_INTERVAL`).
    #[divan::bench]
    fn raw_hook_every_4k(bencher: divan::Bencher<'_, '_>) {
        raw_bench(bencher, 4_000);
    }

    /// Ten times coarser. If this were faster than `raw_hook_every_4k`,
    /// raising the interval would buy throughput; it is not, because the
    /// trap is per instruction regardless.
    #[divan::bench]
    fn raw_hook_every_40k(bencher: divan::Bencher<'_, '_>) {
        raw_bench(bencher, 40_000);
    }

    #[divan::bench]
    fn raw_hook_every_400k(bencher: divan::Bencher<'_, '_>) {
        raw_bench(bencher, 400_000);
    }
}

/// `pcall` through the runtime's prelude wrappers, which make the CPU
/// budget error uncatchable, against the stock `pcall` on a bare state
/// carrying the same count hook. The difference is the wrapper's cost:
/// two extra Lua frames and two vararg round trips per call.
mod pcall {
    use super::*;

    const SCRIPT: &str = "return function(n) \
        local f = function() return 1 end \
        local ok = 0 \
        for i = 1, n do local o = pcall(f) if o then ok = ok + 1 end end \
        return ok end";
    const CALLS: i64 = 10_000;

    /// The server's state: `pcall` is the prelude wrapper.
    #[divan::bench]
    fn wrapped(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let mut runtime = server_shaped_state();
        let f = function_in(&runtime, "runtime-pcall.lua", SCRIPT);

        bencher.bench_local(|| {
            let result: i64 = rt
                .block_on(runtime.call_function(f.clone(), CALLS))
                .expect("call the Lua function");
            divan::black_box(result)
        });
    }

    /// Stock `pcall`, same hook interval, no wrapper.
    #[divan::bench]
    fn raw(bencher: divan::Bencher<'_, '_>) {
        let lua = mlua::Lua::new();
        lua.set_global_hook(
            mlua::HookTriggers::new().every_nth_instruction(4_000),
            |_, _| Ok(mlua::VmState::Continue),
        )
        .expect("install the count hook");
        let f: mlua::Function = lua.load(SCRIPT).eval().expect("eval the function");

        bencher.bench_local(|| {
            let result: i64 = f.call(CALLS).expect("call the Lua function");
            divan::black_box(result)
        });
    }
}

/// The checkout path the server actually takes — `get_timeout`, not
/// `get` — alone and under contention.
mod pool {
    use super::*;
    use std::time::Duration;

    /// An idle state is available: the `try_recv` fast path plus the
    /// span and clock bookkeeping around it.
    #[divan::bench]
    fn get_timeout_hit(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let pool = nitr::RuntimePool::new(vec![server_shaped_state()]);
        bencher.bench_local(|| {
            rt.block_on(async {
                divan::black_box(pool.get_timeout(Duration::from_secs(1)).await);
            })
        });
    }

    /// Eight tasks sharing two states, each checking out fifty times and
    /// yielding in between: the channel's hand-off under contention, which
    /// no single-request bench can see.
    #[divan::bench]
    fn get_timeout_contended(bencher: divan::Bencher<'_, '_>) {
        let rt = tokio_runtime();
        let pool = nitr::RuntimePool::new(vec![server_shaped_state(), server_shaped_state()]);
        bencher.bench_local(|| {
            rt.block_on(async {
                let tasks: Vec<_> = (0..8)
                    .map(|_| {
                        let pool = pool.clone();
                        tokio::spawn(async move {
                            for _ in 0..50 {
                                let guard = pool.get_timeout(Duration::from_secs(1)).await;
                                divan::black_box(&guard);
                                drop(guard);
                                tokio::task::yield_now().await;
                            }
                        })
                    })
                    .collect();
                for task in tasks {
                    task.await.expect("checkout task");
                }
            })
        });
    }
}

/// A call that suspends: the handler yields to an async builtin and is
/// resumed by mlua's trampoline. Every `nitr.db` and `nitr.fetch` handler
/// takes this path; `call_into_lua` never does.
#[divan::bench]
fn call_into_lua_yielding(bencher: divan::Bencher<'_, '_>) {
    let rt = tokio_runtime();
    let mut runtime = Runtime::new().expect("create a Lua runtime");
    let yield_once = runtime
        .lua()
        .create_async_function(|_, ()| async {
            tokio::task::yield_now().await;
            Ok(1)
        })
        .expect("create the async function");
    runtime
        .lua()
        .globals()
        .set("yield_once", yield_once)
        .expect("register the async function");
    let f = function_in(
        &runtime,
        "runtime-yield.lua",
        "return function(n) return yield_once() + n end",
    );

    bencher.bench_local(|| {
        let result: i64 = rt
            .block_on(runtime.call_function(f.clone(), 41))
            .expect("call the Lua function");
        divan::black_box(result)
    });
}

/// A full collection over a live heap of a few MiB: what the timeout arm
/// pays (`gc_collect` after resetting the coroutine) on the tokio worker
/// that hit the deadline. The heap is kept alive in a global so every
/// iteration marks the same live set instead of an empty one.
#[divan::bench]
fn gc_collect_loaded_state(bencher: divan::Bencher<'_, '_>) {
    let runtime = server_shaped_state();
    runtime
        .lua()
        .load("big = {} for i = 1, 25000 do big[i] = { i, tostring(i) } end")
        .exec()
        .expect("fill the heap");

    bencher.bench_local(|| {
        runtime.lua().gc_collect().expect("collect");
    });
}
