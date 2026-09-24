//! Rust extension modules: the boundary that lets someone build
//! *Nitr + their own domain functions* without forking Nitr.
//!
//! `ServerBuilder::module(name, f)` runs `f` once per pooled Lua state (and
//! again on every reload) and mounts the table it returns at `nitr.ext.<name>`,
//! right next to the builtins. A third-party extension crate is nothing
//! more than a public function shaped like [`kv_module`] below.
//!
//! Rust owns what happens inside the module — shared state, I/O, native
//! speed, no sandbox limits. Lua only composes it, still under the state's
//! memory and execution budget.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run --example extension
//!
//! curl 'http://127.0.0.1:3000/inventory/widgets'
//! curl -X PUT 'http://127.0.0.1:3000/inventory/widgets' -d '7'
//! curl 'http://127.0.0.1:3000/slugify?title=Hello%20World'
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mlua::{Lua, Table};
use nitr::{Builtins, Server};

/// A counter store shared by *every* Lua state: the states are isolated
/// from each other, but a module can hand them a common Rust-side handle.
#[derive(Clone, Default)]
struct Kv(Arc<Mutex<HashMap<String, i64>>>);

impl Kv {
    /// The map, even after a panic elsewhere poisoned the lock: every
    /// write below leaves it consistent, so the data is still good.
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, i64>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn get(&self, key: &str) -> i64 {
        *self.map().get(key).unwrap_or(&0)
    }

    /// `delta` comes from a request: an overflow is the caller's error,
    /// never a panic.
    fn add(&self, key: &str, delta: i64) -> mlua::Result<i64> {
        let mut map = self.map();
        let entry = map.entry(key.to_string()).or_insert(0);
        *entry = entry
            .checked_add(delta)
            .ok_or_else(|| mlua::Error::RuntimeError(format!("counter `{key}` would overflow")))?;
        Ok(*entry)
    }
}

/// Builds the `nitr.ext.kv` module. This is the shape an extension crate
/// (`nitr-postgres`, `nitr-redis`, …) would export.
fn kv_module(kv: Kv) -> impl Fn(&Lua) -> mlua::Result<Table> + Send + Sync + 'static {
    move |lua| {
        let table = lua.create_table()?;
        let store = kv.clone();
        table.set(
            "get",
            lua.create_function(move |_, key: String| Ok(store.get(&key)))?,
        )?;
        let store = kv.clone();
        table.set(
            "add",
            lua.create_function(move |_, (key, delta): (String, Option<i64>)| {
                store.add(&key, delta.unwrap_or(1))
            })?,
        )?;
        Ok(table)
    }
}

/// A second module, pure and stateless: string work that would be slow and
/// awkward in Lua belongs on the Rust side of the boundary.
///
/// Note the name: `nitr.text` is already a builtin response helper, so
/// mounting this as `text` would be refused at build time.
fn slug_module(lua: &Lua) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set(
        "slugify",
        lua.create_function(|_, input: String| {
            let mut slug = String::with_capacity(input.len());
            let mut pending_dash = false;
            for ch in input.chars() {
                if ch.is_alphanumeric() {
                    if pending_dash && !slug.is_empty() {
                        slug.push('-');
                    }
                    pending_dash = false;
                    slug.extend(ch.to_lowercase());
                } else {
                    pending_dash = true;
                }
            }
            Ok(slug)
        })?,
    )?;
    Ok(table)
}

#[tokio::main]
async fn main() -> nitr::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // `PORT=8080 cargo run --example extension` overrides the default port.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    Server::builder()
        .listen(([127, 0, 0, 1], port).into())
        .handler_script("crates/nitr/examples/extension/app.lua")
        .builtins(Builtins::JSON | Builtins::HTTP | Builtins::LOG)
        // Registering a module twice, or under a builtin's name, is a
        // build-time error — extensions cannot silently shadow each other.
        .module("kv", kv_module(Kv::default()))
        .module("slug", slug_module)
        .workers(4)
        .build()
        .await?
        .serve()
        .await
}
