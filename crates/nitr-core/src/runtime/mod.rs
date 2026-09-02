// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

use mlua::{
    FromLuaMulti, Function, HookTriggers, IntoLuaMulti, Lua, LuaOptions, LuaSerdeExt as _, StdLib,
    Table, Thread, Value, Variadic, VmState, chunk::ChunkMode,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

pub(crate) mod pool;
mod script;
use script::load_error;
#[cfg(test)]
mod tests;

pub use pool::{RuntimeGuard, RuntimePool};

const MEMORY_LIMIT: usize = 8 * 1024 * 1024; // 8 MiB

/// Default wall-clock budget per handler invocation.
const EXEC_TIMEOUT: Duration = Duration::from_secs(30);

/// How often (in Lua VM instructions) the execution-deadline hook runs.
const HOOK_INSTRUCTION_INTERVAL: u32 = 4000;

/// Extra wall-clock grace given to the outer async timeout so the
/// instruction hook (with its precise error message) fires first for
/// CPU-bound overruns.
const EXEC_TIMEOUT_GRACE: Duration = Duration::from_millis(100);

/// The base-library patches every state carries, applied once at
/// construction before any script loads.
///
/// **Text-only `load`.** Lua 5.4 performs no bytecode verification, so a
/// hand-patched binary chunk (out-of-range register or constant indices)
/// is type confusion inside the VM and, from there, arbitrary memory
/// access in the process — a complete escape from the sandbox the memory
/// limit and instruction hook enforce. The stock `load` defaults its mode
/// to `"bt"`; this wrapper pins it to `"t"` whatever the caller asked for,
/// and `string.dump` goes too, since producing bytecode is the other half
/// of that primitive. The wrapper preserves the argument count: an
/// explicit `nil` environment is not the same as an absent one.
///
/// **An uncatchable budget error.** The instruction hook raises an
/// ordinary Lua error when the deadline passes, and the count restarts at
/// every fire, so `while true do pcall(function() while true do end end)
/// end` catches every trip inside the inner function and never lets the
/// outer loop accumulate enough instructions to trip on its own — one
/// request then holds a pooled state and a worker thread forever, past
/// every timeout, because nothing ever yields. `pcall`, `xpcall` and
/// `coroutine.resume` are the three doors a caught error can come back
/// through; each is wrapped so a failure caught *after* the deadline is
/// re-raised as the budget error. The wrappers are Lua functions rather
/// than Rust callbacks so a body that yields (an async builtin inside
/// `pcall`) keeps working. Startup runs with the deadline unset, so the
/// wrappers are inert until a budgeted call begins.
const PRELUDE: &str = r##"
local tripped, budget_msg = ...
local raw_load, raw_pcall, raw_xpcall = load, pcall, xpcall
local select, error = select, error

load = function(chunk, name, _, ...)
    if select("#", ...) > 0 then
        return raw_load(chunk, name, "t", (...))
    end
    return raw_load(chunk, name, "t")
end
if string then string.dump = nil end

local function guard(ok, ...)
    if not ok and tripped() then error(budget_msg, 0) end
    return ok, ...
end
pcall = function(...) return guard(raw_pcall(...)) end
xpcall = function(...) return guard(raw_xpcall(...)) end
if coroutine then
    local raw_resume = coroutine.resume
    coroutine.resume = function(...) return guard(raw_resume(...)) end
end
"##;

/// The Lua runtime that provides an interface to execute Lua scripts and manage Lua state.
/// It allows for registering Rust extension modules on the `nitr` namespace,
/// running a configuration script, and calling Lua functions under the
/// state's execution budget.
#[derive(Debug)]
pub struct Runtime {
    lua: Lua,
    cfg: Option<Table>,
    /// Cached handler coroutine, reset and reused across requests to avoid
    /// per-request thread allocation and hook installation.
    thread: Option<Thread>,
    /// Execution deadline for the instruction hook, in nanoseconds since
    /// `epoch`. Stored atomically so the hook closure (installed once for
    /// the whole state) reads the current request's deadline without
    /// locking.
    deadline: Arc<AtomicU64>,
    epoch: Instant,
    /// Set when a failure leaves this state unfit for reuse (memory limit
    /// hit, panic). The pool rebuilds a poisoned state instead of handing
    /// it to the next request.
    poisoned: bool,
    opts: RuntimeOpts,
}

/// Grants additional execution budget to a runtime while it produces a
/// streaming response: each chunk handed to the client resets the
/// instruction-hook deadline, so the budget applies per chunk-production
/// slice instead of to the total stream lifetime.
#[derive(Debug, Clone)]
pub struct DeadlineHandle {
    deadline: Arc<AtomicU64>,
    epoch: Instant,
    budget: Option<Duration>,
}

impl DeadlineHandle {
    /// Grants another full execution budget from now. A no-op when the
    /// runtime has no execution timeout configured.
    pub fn extend(&self) {
        if let Some(budget) = self.budget {
            self.deadline.store(
                (self.epoch.elapsed() + budget).as_nanos() as u64,
                Ordering::Relaxed,
            );
        }
    }
}

/// Options for configuring the Lua runtime.
#[derive(Debug)]
pub struct RuntimeOpts {
    /// Lua standard libraries to load.
    pub libs: mlua::StdLib,
    /// Lua memory limit in bytes.
    pub memory_limit: usize,
    /// Development mode: reload the HTTP handler script before each call and
    /// include error details (Lua tracebacks) in error responses.
    pub dev_mode: bool,
    /// Execution budget per handler invocation, enforced by an
    /// instruction-count hook (CPU-bound loops) and an outer async timeout
    /// (slow I/O). `None` disables both.
    pub exec_timeout: Option<Duration>,
    /// Directory `require` is confined to: `package.path` is pinned to it.
    /// `None` skips only the pinning — every `package`-bearing state has
    /// `package.loadlib` removed and `package.cpath` emptied regardless, so
    /// native modules can never load.
    pub package_dir: Option<PathBuf>,
}

impl Runtime {
    /// It creates a new Lua runtime with default options.
    ///
    /// Such as some **built-in** libraries loaded and a default memory limit.
    ///
    /// `package` is not among them, so `require` is unavailable: confinement
    /// needs a directory to pin to, and this constructor takes no arguments to
    /// name one. Embedders that want module loading call [`Runtime::new_with`]
    /// with both [`StdLib::PACKAGE`] and a
    /// [`package_dir`](RuntimeOpts::package_dir).
    pub fn new() -> Result<Self> {
        // `io` and `os` are deliberately excluded from the defaults: they
        // give scripts ambient filesystem/process access. Opt in via
        // `RuntimeOpts::libs` when needed.
        //
        // `package` is excluded for a different reason: its confinement is
        // conditional on `package_dir`, which this constructor cannot supply,
        // so enabling it here would hand out a stock `package.path`. A default
        // that is safe but less capable is the right default for a library.
        Runtime::new_with(RuntimeOpts {
            libs: StdLib::NONE
                | StdLib::MATH
                | StdLib::TABLE
                | StdLib::STRING
                | StdLib::UTF8
                | StdLib::COROUTINE,
            memory_limit: MEMORY_LIMIT,
            dev_mode: false,
            exec_timeout: Some(EXEC_TIMEOUT),
            package_dir: None,
        })
    }

    /// It creates a new Lua runtime with specified options.
    ///
    /// For example, it allows for customizing the Lua standard libraries to load
    /// like `io`, `math`, `os`, etc as well as the memory limits.
    ///
    /// Some scrubbing applies to every state, whatever the options:
    /// `collectgarbage` is always removed (the memory limit is enforced by
    /// the allocator, not the collector), and `package`-bearing states can
    /// never load native modules — see
    /// [`package_dir`](RuntimeOpts::package_dir).
    pub fn new_with(opts: RuntimeOpts) -> Result<Self> {
        let lua = Lua::new_with(opts.libs, LuaOptions::default())?;
        lua.set_memory_limit(opts.memory_limit)?;

        // The base library is always loaded, and it carries `dofile` and
        // `loadfile` — reading and executing arbitrary files is the same
        // ambient authority the excluded-by-default `io` library gates.
        // They follow the same opt-in: absent unless IO was requested.
        if !opts.libs.contains(StdLib::IO) {
            let globals = lua.globals();
            globals.set("dofile", Value::Nil)?;
            globals.set("loadfile", Value::Nil)?;
        }

        // Not a confinement escape: the memory limit is enforced by the
        // allocator, not the collector, so `collectgarbage("stop")` only
        // reaches that limit sooner and poisons the state. It goes because no
        // Nitr script has business pacing the collector, and `("count")` is a
        // heap oracle.
        lua.globals().set("collectgarbage", Value::Nil)?;

        // Forbid loading native modules in every `package`-bearing state,
        // not only the confined ones. mlua's safe constructor already stubs
        // `package.loadlib` and the C-library searchers (`searchers[3]` is
        // replaced, `[4]` removed — see mlua's `disable_c_modules`), so this
        // is defense-in-depth over that guarantee, not the load-bearing
        // layer: it is the scrub Nitr owns and tests, and the one that would
        // survive if the state were ever built another way.
        if opts.libs.contains(StdLib::PACKAGE) {
            let package: Table = lua.globals().get("package")?;
            package.set("loadlib", Value::Nil)?;
            package.set("cpath", "")?;

            // Confine `require` to the configured directory. Only the
            // pinning is conditional: without a directory there is nothing
            // to pin to.
            //
            // `package.path` is set for anything that reads it, but it is
            // not what confines: the stock file searcher would honor a
            // script's later reassignment of `package.path`, and it loads
            // whatever it finds in whatever mode — bytecode included. The
            // searcher installed here owns the directory itself, maps the
            // module name to a path without ever consulting `package.path`,
            // and compiles text only.
            if let Some(dir) = &opts.package_dir {
                let shown = dir.to_string_lossy();
                package.set("path", format!("{shown}/?.lua;{shown}/?/init.lua"))?;
                let searchers: Table = package.get("searchers")?;
                let preload: Value = searchers.get(1)?;
                let confined = lua.create_table()?;
                confined.set(1, preload)?;
                confined.set(2, confined_searcher(&lua, dir.clone())?)?;
                package.set("searchers", confined)?;
            }
        }

        let deadline = Arc::new(AtomicU64::new(u64::MAX));
        let epoch = Instant::now();

        // See `PRELUDE`. The tripped check reads the same deadline the hook
        // does, so the two cannot disagree about whether the budget is gone.
        let tripped = {
            let deadline = deadline.clone();
            lua.create_function(move |_, ()| {
                Ok(epoch.elapsed().as_nanos() as u64 > deadline.load(Ordering::Relaxed))
            })?
        };
        lua.load(PRELUDE)
            .set_name("=nitr-prelude")
            .call::<()>((tripped, crate::error::EXEC_BUDGET_MSG))?;

        // Instruction-count hook: the only mechanism that can stop a
        // CPU-bound loop (`while true do end` never reaches an await point,
        // blocking both the async timeout and the executor).
        //
        // It is installed *globally* rather than per coroutine: Lua 5.4
        // propagates a state's hook to threads created from it, so a
        // `coroutine.create` inside a handler inherits the budget instead of
        // escaping it.
        if opts.exec_timeout.is_some() {
            let deadline = deadline.clone();
            lua.set_global_hook(
                HookTriggers::new().every_nth_instruction(HOOK_INSTRUCTION_INTERVAL),
                move |_, _| {
                    if epoch.elapsed().as_nanos() as u64 > deadline.load(Ordering::Relaxed) {
                        return Err(mlua::Error::RuntimeError(
                            crate::error::EXEC_BUDGET_MSG.into(),
                        ));
                    }
                    Ok(VmState::Continue)
                },
            )?;
        }

        Ok(Self {
            lua,
            cfg: None,
            thread: None,
            deadline,
            epoch,
            poisoned: false,
            opts,
        })
    }

    /// Whether a failure has left this state unfit for reuse (a memory
    /// limit hit or a caught panic). The pool rebuilds a poisoned state
    /// rather than handing it to the next request.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Marks this state unfit for reuse. Used by the HTTP layer when a
    /// panic is caught while the state is checked out.
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Registers a Rust extension module: the closure runs now (and its
    /// result is a table by Lua module convention), mounted at
    /// `nitr.ext.<name>` — one level below the standard library, so a
    /// module can never collide with a builtin. Fails when the name is
    /// already taken, so two extensions cannot shadow each other.
    ///
    /// This is the embedding-side extension point; HTTP applications use
    /// `ServerBuilder::module()` in the `nitr-http` crate, which applies
    /// the closure to every pooled state.
    ///
    /// ## Error attribution
    ///
    /// An error a module raises should say which module failed. Wrap Rust
    /// errors with a `module <name>` context and [`ErrorInfo`] classifies
    /// them as `kind = "module"` with the module named; a module that
    /// returns an opaque string makes its failures everyone's problem:
    ///
    /// ```ignore
    /// t.set("query", lua.create_function(|_, sql: String| {
    ///     run(&sql).map_err(|err| mlua::Error::WithContext {
    ///         context: "module db".into(),
    ///         cause: std::sync::Arc::new(mlua::Error::external(err)),
    ///     })
    /// })?)?;
    /// ```
    ///
    /// [`ErrorInfo`]: crate::ErrorInfo
    pub fn register_module<F>(&self, name: &str, f: F) -> Result
    where
        F: Fn(&Lua) -> mlua::Result<Table>,
    {
        let value = f(&self.lua)?;
        crate::ns::mount(&self.lua, name, value)
    }

    /// It sets the Lua configuration script that runs once at server startup.
    ///
    /// The script is a plain Lua chunk in the same shape handler scripts
    /// use: statements at the top level ending in `return { ... }`, with
    /// the provided arguments available as its varargs (`local db = ...`).
    ///
    /// The Lua table containing the configuration fields can be accessed later
    /// using the [`cfg()`](Self::cfg) method.
    pub async fn register_cfg_fn(&mut self, cfg_src: &Path, args: impl IntoLuaMulti) -> Result {
        let data = std::fs::read(cfg_src).map_err(|err| {
            Error::Script(format!(
                "failed to read the Lua configuration file {}: {err}",
                cfg_src.display()
            ))
        })?;

        let chunk = self
            .load_chunk(data, cfg_src)
            .map_err(|err| load_error(cfg_src, err))?;
        // The chunk itself receives the arguments as its varargs, so the
        // script sees `db` via `local db = ...` at the top. A failure while
        // it runs (a misspelled `db:` method, a nil index) gets the same
        // in-context rendering as a parse error.
        let value = chunk
            .call_async::<Value>(args)
            .await
            .map_err(|err| load_error(cfg_src, err))?;
        let cfg = match value {
            Value::Table(cfg) => cfg,
            // The pre-1.0 wrapper form; point migrations at the new shape.
            Value::Function(_) => {
                return Err(Error::Script(format!(
                    "the configuration script {} returned a function; the \
                     `function(db) ... end` wrapper is no longer supported — \
                     take arguments via `local db = ...` at the top level and \
                     end the script with `return {{ ... }}`",
                    cfg_src.display()
                )));
            }
            other => {
                return Err(Error::Script(format!(
                    "the configuration script {} must return a table, got {}",
                    cfg_src.display(),
                    other.type_name()
                )));
            }
        };

        self.cfg = Some(cfg);
        Ok(())
    }

    /// The underlying Lua state, for advanced customization beyond
    /// [`register_module()`](Self::register_module).
    pub fn lua(&self) -> &Lua {
        &self.lua
    }

    /// The Lua configuration table that is returned after the script handler is invoked.
    pub fn cfg(&self) -> Option<&Table> {
        self.cfg.as_ref()
    }

    /// Serializes the configuration table into a plain-data snapshot that can
    /// be injected into other runtimes with
    /// [`set_cfg_snapshot()`](Self::set_cfg_snapshot).
    ///
    /// Returns `None` when no configuration script has been registered.
    pub fn cfg_snapshot(&self) -> Result<Option<serde_json::Value>> {
        let Some(cfg) = &self.cfg else {
            return Ok(None);
        };
        let snapshot = serde_json::to_value(cfg).map_err(|err| {
            Error::Config(format!(
                "the configuration script must return plain data \
                 (tables, strings, numbers, booleans): {err}"
            ))
        })?;
        Ok(Some(snapshot))
    }

    /// Injects a configuration snapshot produced by
    /// [`cfg_snapshot()`](Self::cfg_snapshot) as this runtime's
    /// configuration table.
    pub fn set_cfg_snapshot(&mut self, snapshot: &serde_json::Value) -> Result {
        match self.lua.to_value(snapshot)? {
            Value::Table(table) => {
                self.cfg = Some(table);
                Ok(())
            }
            _ => Err(Error::Config(
                "the configuration snapshot must be a table".into(),
            )),
        }
    }

    /// Returns the cached handler coroutine reset to the given function,
    /// creating it when necessary.
    ///
    /// The handler runs in its own coroutine; the execution-deadline hook is
    /// installed globally at construction and inherited by every thread,
    /// including coroutines the script creates itself.
    fn handler_thread(&mut self, http_fn: Function) -> Result<Thread> {
        if let Some(thread) = self.thread.take()
            && thread.reset(http_fn.clone()).is_ok()
        {
            return Ok(thread);
        }
        Ok(self.lua.create_thread(http_fn)?)
    }

    /// Calls a Lua function under the configured execution budget
    /// ([`RuntimeOpts::exec_timeout`]): an instruction-count hook stops
    /// CPU-bound overruns and an outer async timeout stops slow I/O
    /// ([`Error::Timeout`]). The function runs on this runtime's cached
    /// coroutine so the instruction-count hook applies.
    pub async fn call_function<R: FromLuaMulti>(
        &mut self,
        f: Function,
        args: impl IntoLuaMulti,
    ) -> Result<R> {
        let thread = self.handler_thread(f.clone())?;
        let result = match self.opts.exec_timeout {
            Some(timeout) => {
                self.deadline.store(
                    (self.epoch.elapsed() + timeout).as_nanos() as u64,
                    Ordering::Relaxed,
                );
                // The async timeout covers the disjoint failure mode: time
                // spent suspended in async I/O, where no Lua instructions
                // execute and the hook cannot fire.
                let timed = tokio::time::timeout(
                    timeout + EXEC_TIMEOUT_GRACE,
                    thread.clone().into_async::<R>(args)?,
                )
                .await;
                match timed {
                    Ok(result) => result,
                    Err(_) => {
                        // The coroutine is still suspended inside whatever
                        // builtin it was awaiting, and the pending Rust
                        // future — with everything it holds, an open SQLite
                        // transaction among them — lives on that coroutine's
                        // stack. Dropping the thread handle would leave both
                        // to a later collection cycle the script cannot
                        // force (`collectgarbage` is gone), so the state
                        // could serve its next request with the previous
                        // one's work still in flight. Close the stack now
                        // and collect, so the future is dropped here.
                        let _ = thread.reset(f);
                        let _ = self.lua.gc_collect();
                        self.thread = Some(thread);
                        self.clear_deadline();
                        return Err(Error::Timeout);
                    }
                }
            }
            None => thread.clone().into_async::<R>(args)?.await,
        };
        // Keep the coroutine for the next request (reset() also recovers
        // errored threads on Lua 5.4).
        self.thread = Some(thread);
        self.clear_deadline();
        self.classify(result)
    }

    /// Lifts the deadline once a budgeted call has returned. The state is
    /// idle between calls, and Lua that runs outside a call — a dev-mode
    /// reload, an embedder's own `eval` — must not inherit a deadline the
    /// last request already blew through: the hook would fire within 4000
    /// instructions and the `pcall` guard would re-raise on every caught
    /// error, so the "next" request would fail before it started.
    fn clear_deadline(&self) {
        self.deadline.store(u64::MAX, Ordering::Relaxed);
    }

    /// Calls a Lua function under the instruction-hook deadline only — no
    /// outer async timeout — for long-lived streaming calls. The caller is
    /// expected to keep granting budget via [`DeadlineHandle::extend()`] as
    /// chunks are delivered; time suspended in async I/O (e.g. waiting for a
    /// slow client) is deliberately unbounded.
    pub async fn call_function_streaming<R: FromLuaMulti>(
        &mut self,
        f: Function,
        args: impl IntoLuaMulti,
    ) -> Result<R> {
        let thread = self.handler_thread(f)?;
        if let Some(timeout) = self.opts.exec_timeout {
            self.deadline.store(
                (self.epoch.elapsed() + timeout).as_nanos() as u64,
                Ordering::Relaxed,
            );
        }
        let result = thread.clone().into_async::<R>(args)?.await;
        self.thread = Some(thread);
        self.clear_deadline();
        self.classify(result)
    }

    /// Converts a call outcome into a [`Result`], marking the state
    /// poisoned when the failure is one it cannot cleanly recover from.
    fn classify<R>(&mut self, result: mlua::Result<R>) -> Result<R> {
        match result {
            Ok(value) => Ok(value),
            Err(err) => {
                let err = Error::from(err);
                if err.poisons_state() {
                    self.poisoned = true;
                }
                Err(err)
            }
        }
    }

    /// A handle for extending this runtime's execution deadline from
    /// long-lived calls (see
    /// [`call_function_streaming()`](Self::call_function_streaming)).
    pub fn deadline_handle(&self) -> DeadlineHandle {
        DeadlineHandle {
            deadline: self.deadline.clone(),
            epoch: self.epoch,
            budget: self.opts.exec_timeout,
        }
    }

    /// Whether this runtime operates in development mode.
    pub fn dev_mode(&self) -> bool {
        self.opts.dev_mode
    }
}

/// The `require` searcher for a confined state: `a.b` resolves to
/// `<dir>/a/b.lua` or `<dir>/a/b/init.lua`, nothing else.
///
/// The module name is restricted to a dotted identifier before it touches
/// a path, so no spelling of a name can name a parent directory or an
/// absolute location; the directory is captured at construction rather
/// than read back from `package.path`, so a script cannot widen the search
/// by reassigning that string. Chunks compile as text only, for the same
/// reason `load` does (see [`PRELUDE`]).
fn confined_searcher(lua: &Lua, dir: PathBuf) -> mlua::Result<Function> {
    lua.create_function(move |lua, name: String| {
        let well_formed = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
            && name.split('.').all(|segment| !segment.is_empty());
        if !well_formed {
            let note = format!(
                "\n\tmodule name '{name}' is not a dotted identifier (letters, digits and '_' \
                 between dots)"
            );
            return Ok(Variadic::from_iter([Value::String(
                lua.create_string(note)?,
            )]));
        }
        let rel = name.replace('.', "/");
        let mut tried = String::new();
        for candidate in [
            dir.join(format!("{rel}.lua")),
            dir.join(&rel).join("init.lua"),
        ] {
            match std::fs::read(&candidate) {
                Ok(data) => {
                    let loader = lua
                        .load(data)
                        .set_name(format!("@{}", candidate.display()))
                        .set_mode(ChunkMode::Text)
                        .into_function()?;
                    let path = lua.create_string(candidate.to_string_lossy().as_bytes())?;
                    return Ok(Variadic::from_iter([
                        Value::Function(loader),
                        Value::String(path),
                    ]));
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    tried.push_str(&format!("\n\tno file '{}'", candidate.display()));
                }
                Err(err) => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "failed to read module '{name}' at {}: {err}",
                        candidate.display()
                    )));
                }
            }
        }
        Ok(Variadic::from_iter([Value::String(
            lua.create_string(tried)?,
        )]))
    })
}
