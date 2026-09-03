// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! `nitr.cache`: a bounded, Rust-owned cache shared by every pooled state.
//!
//! This is deliberately *not* a hole in the isolation model. Values are
//! serialized on the way in and rebuilt on the way out, so no Lua value,
//! function, or userdata ever crosses between states, and one state can
//! never reach another's heap through it. Rust owns the memory and the
//! bound, so the cache cannot grow without limit. It is shared **data**,
//! not shared **state** — the same relationship Lua already has with
//! SQLite.
//!
//! Two properties applications must know, because building on the opposite
//! assumption fails quietly:
//!
//! - It lives in the process. A restart empties it, and two Nitr processes
//!   behind a load balancer have two independent caches. Do not put
//!   sessions, locks, or counters that must be exact in here.
//! - It survives a reload. A cache that empties every time the handler
//!   script changes is a cache that never warms, which is worse than not
//!   having one in development.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mlua::{ExternalResult as _, Lua, LuaSerdeExt as _, Table, UserData, UserDataMethods, Value};

/// Limits and defaults for the shared cache.
#[derive(Debug, Clone)]
pub struct CacheOptions {
    /// Maximum live entries before the least recently used is evicted.
    pub max_entries: usize,
    /// Maximum total size of stored values, in bytes.
    pub max_bytes: u64,
    /// Seconds an entry lives when `set` does not say; `0` means no expiry.
    pub default_ttl: u64,
}

impl Default for CacheOptions {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_bytes: 32 * 1024 * 1024,
            default_ttl: 300,
        }
    }
}

struct Entry {
    /// The value as JSON bytes: plain data, never a Lua handle.
    value: Vec<u8>,
    /// `None` for an entry that never expires.
    expires_at: Option<Instant>,
    /// Monotonic tick of the last read or write, for LRU eviction.
    touched: u64,
    /// Tick of the write that created the entry: the tiebreaker that
    /// keeps two entries expiring at the same instant apart in the
    /// expiry index.
    inserted: u64,
}

/// Longest key accepted, so a request-derived key cannot dominate an
/// entry's cost.
const MAX_KEY_BYTES: usize = 1024;

/// The longest TTL honored, in seconds (~10 years): anything past it is
/// indistinguishable from "never expires" and is clamped rather than let
/// near `Instant`'s arithmetic limit.
const MAX_TTL_SECS: u64 = 10 * 365 * 24 * 60 * 60;

impl Entry {
    /// What one entry costs against the byte bound: key and value both.
    fn cost(key: &str, value: &[u8]) -> u64 {
        (key.len() + value.len()) as u64
    }
}

impl Entry {
    fn is_live(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|at| at > now)
    }
}

/// The storage behind the lock.
///
/// Two ordered indexes ride beside the map so that eviction is a lookup,
/// not a scan: every `set` used to `retain` over the whole map to drop
/// expired entries and then scan it again per victim, all under the lock
/// every state shares — O(n) per write at 10 000 entries. Now a write
/// costs a few `BTreeMap` operations and a victim is the first key of an
/// index. Keys are shared (`Arc<str>`) between the map and the indexes.
#[derive(Default)]
struct Inner {
    entries: HashMap<Arc<str>, Entry>,
    /// Least recently used first; `touched` ticks are unique, so this is
    /// a total order over the live entries.
    lru: BTreeMap<u64, Arc<str>>,
    /// Soonest expiry first, over the entries that have a TTL.
    expiry: BTreeMap<(Instant, u64), Arc<str>>,
    bytes: u64,
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl Inner {
    /// Removes an entry from the map and both indexes, debiting its cost.
    fn remove(&mut self, key: &str) -> Option<Entry> {
        let (key, entry) = self.entries.remove_entry(key)?;
        self.lru.remove(&entry.touched);
        if let Some(at) = entry.expires_at {
            self.expiry.remove(&(at, entry.inserted));
        }
        // Saturating (here and at every debit): if the hand-kept counter
        // ever drifts, a wrap near `u64::MAX` would make eviction expel
        // everything forever; flooring at zero merely over-admits until
        // entries cycle out.
        self.bytes = self.bytes.saturating_sub(Entry::cost(&key, &entry.value));
        Some(entry)
    }
}

/// The shared cache. Cloning shares the same storage; the server builds one
/// and hands it to every state.
#[derive(Clone)]
pub struct Cache {
    inner: Arc<Mutex<Inner>>,
    opts: Arc<CacheOptions>,
    /// Supplies the LRU ordering. A counter rather than a timestamp: it is
    /// cheaper and cannot go backwards when the wall clock does.
    clock: Arc<AtomicU64>,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("max_entries", &self.opts.max_entries)
            .field("max_bytes", &self.opts.max_bytes)
            .finish_non_exhaustive()
    }
}

impl Cache {
    /// Creates an empty cache bounded by the given limits.
    pub fn new(opts: CacheOptions) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            opts: Arc::new(opts),
            clock: Arc::new(AtomicU64::new(0)),
        }
    }

    fn lock(&self) -> mlua::Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| mlua::Error::RuntimeError("the cache lock is poisoned".into()))
    }

    fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::Relaxed)
    }

    fn get_raw(&self, key: &str) -> mlua::Result<Option<Vec<u8>>> {
        let now = Instant::now();
        let touched = self.tick();
        let mut inner = self.lock()?;
        let inner = &mut *inner;

        match inner.entries.get_mut(key) {
            Some(entry) if entry.is_live(now) => {
                // Re-ranked in the LRU index under its new tick.
                let previous = std::mem::replace(&mut entry.touched, touched);
                let value = entry.value.clone();
                if let Some(shared) = inner.lru.remove(&previous) {
                    inner.lru.insert(touched, shared);
                }
                inner.hits += 1;
                Ok(Some(value))
            }
            // An expired entry is dropped on the way past rather than left
            // to be evicted later: it is dead weight against both bounds.
            Some(_) => {
                inner.remove(key);
                inner.misses += 1;
                Ok(None)
            }
            None => {
                inner.misses += 1;
                Ok(None)
            }
        }
    }

    fn set_raw(&self, key: String, value: Vec<u8>, ttl: Option<u64>) -> mlua::Result<()> {
        if key.len() > MAX_KEY_BYTES {
            return Err(mlua::Error::RuntimeError(format!(
                "cache key is {} bytes; keys are bounded to {MAX_KEY_BYTES} (hash a long \
                 key first)",
                key.len()
            )));
        }
        // The key is part of what the entry costs: a script keying on a
        // request-derived string would otherwise fill memory with keys
        // the byte bound never saw.
        let size = Entry::cost(&key, &value);
        if size > self.opts.max_bytes {
            return Err(mlua::Error::RuntimeError(format!(
                "cache value for `{key}` is {size} bytes, larger than the whole \
                 {} byte cache",
                self.opts.max_bytes
            )));
        }
        let ttl = ttl.unwrap_or(self.opts.default_ttl);
        // `Instant + Duration` panics on overflow; a `ttl` a script computed
        // from request data must not be able to reach that. Anything past
        // the clamp is "effectively forever" and behaves like it.
        let expires_at = (ttl > 0)
            .then(|| Instant::now().checked_add(Duration::from_secs(ttl.min(MAX_TTL_SECS))))
            .flatten();
        let touched = self.tick();
        let mut inner = self.lock()?;
        let inner = &mut *inner;

        inner.remove(&key);
        let key: Arc<str> = key.into();
        inner.bytes += size;
        inner.lru.insert(touched, key.clone());
        if let Some(at) = expires_at {
            inner.expiry.insert((at, touched), key.clone());
        }
        inner.entries.insert(
            key,
            Entry {
                value,
                expires_at,
                touched,
                inserted: touched,
            },
        );
        self.evict(inner);
        Ok(())
    }

    /// Brings the cache back inside both bounds, dropping expired entries
    /// first (soonest expired first) and then the least recently used.
    ///
    /// Only runs while a bound is exceeded: an expired entry that still
    /// fits is reaped when it is next read, or when room is needed, rather
    /// than by a sweep on every write. Dropping expired entries does not
    /// count as an eviction — they were dead already.
    fn evict(&self, inner: &mut Inner) {
        let now = Instant::now();
        while inner.entries.len() > self.opts.max_entries || inner.bytes > self.opts.max_bytes {
            let expired = inner
                .expiry
                .first_key_value()
                .filter(|((at, _), _)| *at <= now)
                .map(|(_, key)| key.clone());
            match expired {
                Some(key) => {
                    inner.remove(&key);
                }
                None => {
                    let Some(victim) = inner.lru.first_key_value().map(|(_, key)| key.clone())
                    else {
                        break;
                    };
                    inner.remove(&victim);
                    inner.evictions += 1;
                }
            }
        }
    }
}

impl UserData for Cache {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // cache:get(key) -> value | nil
        methods.add_method("get", |lua, cache, key: String| {
            match cache.get_raw(&key)? {
                Some(bytes) => {
                    let json: serde_json::Value = serde_json::from_slice(&bytes).into_lua_err()?;
                    lua.to_value(&json)
                }
                None => Ok(Value::Nil),
            }
        });

        // cache:set(key, value, opts?) — opts is { ttl = seconds }.
        // The value is serialized here, which is what keeps states isolated
        // and is also why a function or userdata cannot be cached.
        methods.add_method(
            "set",
            |_, cache, (key, value, opts): (String, Value, Option<Table>)| {
                let ttl = match &opts {
                    Some(opts) => opts.get::<Option<u64>>("ttl")?,
                    None => None,
                };
                let bytes = crate::bounded::to_json_vec(&value).map_err(|err| {
                    mlua::Error::RuntimeError(format!(
                        "cache values must be plain data (a table, string, number or \
                         boolean); `{key}` is not serializable: {err}"
                    ))
                })?;
                cache.set_raw(key, bytes, ttl)?;
                Ok(())
            },
        );

        // cache:delete(key) -> whether it was there
        methods.add_method("delete", |_, cache, key: String| {
            let mut inner = cache.lock()?;
            Ok(inner.remove(&key).is_some())
        });

        methods.add_method("clear", |_, cache, ()| {
            let mut inner = cache.lock()?;
            inner.entries.clear();
            inner.lru.clear();
            inner.expiry.clear();
            inner.bytes = 0;
            Ok(())
        });

        // cache:remember(key, opts?, fn) — get, or compute and store.
        //
        // The common shape, worth having as one call: written by hand it is
        // three lines that are easy to get subtly wrong (caching a nil,
        // forgetting the TTL).
        methods.add_async_method(
            "remember",
            |lua, cache, (key, arg, f): (String, Value, Option<mlua::Function>)| async move {
                // remember(key, fn) and remember(key, opts, fn) both work.
                let (opts, f) = match (arg, f) {
                    (Value::Function(f), None) => (None, f),
                    (Value::Table(opts), Some(f)) => (Some(opts), f),
                    _ => {
                        return Err(mlua::Error::RuntimeError(
                            "cache:remember expects (key, fn) or (key, opts, fn)".into(),
                        ));
                    }
                };
                if let Some(bytes) = cache.get_raw(&key)? {
                    let json: serde_json::Value = serde_json::from_slice(&bytes).into_lua_err()?;
                    return lua.to_value(&json);
                }
                let ttl = match &opts {
                    Some(opts) => opts.get::<Option<u64>>("ttl")?,
                    None => None,
                };
                let value: Value = f.call_async(()).await?;
                // A nil result is not cached: it would be indistinguishable
                // from a miss on the way out, so every later call would run
                // the function anyway while occupying an entry.
                if value.is_nil() {
                    return Ok(Value::Nil);
                }
                let bytes = crate::bounded::to_json_vec(&value).map_err(|err| {
                    mlua::Error::RuntimeError(format!(
                        "cache:remember value for `{key}` is not serializable: {err}"
                    ))
                })?;
                cache.set_raw(key, bytes, ttl)?;
                Ok(value)
            },
        );

        // cache:stats() — entries, bytes, hits, misses, evictions.
        methods.add_method("stats", |lua, cache, ()| {
            let inner = cache.lock()?;
            let table = lua.create_table()?;
            table.set("entries", inner.entries.len())?;
            table.set("bytes", inner.bytes)?;
            table.set("hits", inner.hits)?;
            table.set("misses", inner.misses)?;
            table.set("evictions", inner.evictions)?;
            table.set("max_entries", cache.opts.max_entries)?;
            table.set("max_bytes", cache.opts.max_bytes)?;
            Ok(table)
        });
    }
}

/// Builds the `nitr.cache` handle for one state over the shared storage.
pub(crate) fn create_cache(lua: &Lua, cache: Cache) -> mlua::Result<mlua::AnyUserData> {
    lua.create_userdata(cache)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(opts: CacheOptions) -> Cache {
        Cache::new(opts)
    }

    /// A chain of `depth` nested Lua tables (the root included).
    fn deep_table(lua: &Lua, depth: usize) -> Value {
        let root = lua.create_table().expect("table");
        let mut cur = root.clone();
        for _ in 1..depth {
            let next = lua.create_table().expect("table");
            cur.set("x", next.clone()).expect("set");
            cur = next;
        }
        Value::Table(root)
    }

    /// `cache:set` serializes script values: without the depth guard a
    /// deep chain recursed to a stack-overflow abort here too.
    #[test]
    fn set_rejects_values_nested_beyond_the_json_depth_bound() {
        let lua = Lua::new();
        let ud = lua
            .create_userdata(cache(CacheOptions::default()))
            .expect("ud");
        lua.globals().set("cache", ud).expect("global");
        lua.globals()
            .set("deep", deep_table(&lua, 129))
            .expect("global");
        let err: String = lua
            .load(
                r#"local ok, err = pcall(function() cache:set("k", deep) end)
                   assert(not ok)
                   return tostring(err)"#,
            )
            .eval()
            .expect("eval");
        assert!(err.contains("nested deeper than 128 levels"), "got: {err}");
    }

    #[test]
    fn values_round_trip_and_count_against_the_bounds() {
        let c = cache(CacheOptions::default());
        c.set_raw("a".into(), b"{\"n\":1}".to_vec(), None)
            .expect("set");
        assert_eq!(
            c.get_raw("a").expect("get").as_deref(),
            Some(&b"{\"n\":1}"[..])
        );
        assert_eq!(c.get_raw("missing").expect("get"), None);

        let inner = c.inner.lock().expect("lock");
        assert_eq!(inner.entries.len(), 1);
        // Key and value both count.
        assert_eq!(inner.bytes, Entry::cost("a", b"{\"n\":1}"));
        assert_eq!((inner.hits, inner.misses), (1, 1));
    }

    #[test]
    fn overwriting_a_key_does_not_double_count_its_bytes() {
        let c = cache(CacheOptions::default());
        c.set_raw("k".into(), vec![b'x'; 100], None).expect("set");
        c.set_raw("k".into(), vec![b'y'; 10], None)
            .expect("overwrite");
        let inner = c.inner.lock().expect("lock");
        assert_eq!(inner.entries.len(), 1);
        assert_eq!(inner.bytes, Entry::cost("k", &[b'y'; 10]));
    }

    #[test]
    fn the_least_recently_used_entry_is_evicted_first() {
        let c = cache(CacheOptions {
            max_entries: 2,
            ..Default::default()
        });
        c.set_raw("a".into(), b"1".to_vec(), None).expect("set a");
        c.set_raw("b".into(), b"2".to_vec(), None).expect("set b");
        // Touch `a`, so `b` becomes the least recently used.
        c.get_raw("a").expect("get a");
        c.set_raw("c".into(), b"3".to_vec(), None).expect("set c");

        assert!(c.get_raw("a").expect("a").is_some());
        assert!(c.get_raw("b").expect("b").is_none(), "b must be evicted");
        assert!(c.get_raw("c").expect("c").is_some());
    }

    #[test]
    fn the_byte_bound_evicts_too() {
        let c = cache(CacheOptions {
            max_bytes: 100,
            ..Default::default()
        });
        c.set_raw("a".into(), vec![b'x'; 60], None).expect("set a");
        c.set_raw("b".into(), vec![b'x'; 60], None).expect("set b");

        let inner = c.inner.lock().expect("lock");
        assert!(inner.bytes <= 100, "bytes must stay within the bound");
        assert_eq!(inner.entries.len(), 1);
        assert_eq!(inner.evictions, 1);
    }

    #[test]
    fn a_value_larger_than_the_whole_cache_is_refused() {
        let c = cache(CacheOptions {
            max_bytes: 10,
            ..Default::default()
        });
        let err = c
            .set_raw("big".into(), vec![b'x'; 11], None)
            .expect_err("must be refused");
        assert!(err.to_string().contains("larger than"), "{err}");
    }

    #[test]
    fn an_expired_entry_reads_as_a_miss_and_frees_its_bytes() {
        let c = cache(CacheOptions::default());
        // A zero TTL means "no expiry", so expiry is set directly here.
        c.set_raw("k".into(), vec![b'x'; 50], Some(1)).expect("set");
        {
            let mut inner = c.inner.lock().expect("lock");
            let entry = inner.entries.get_mut("k").expect("entry");
            entry.expires_at = Some(Instant::now() - Duration::from_secs(1));
        }
        assert!(c.get_raw("k").expect("get").is_none());
        assert_eq!(c.inner.lock().expect("lock").bytes, 0);
    }

    #[test]
    fn a_zero_ttl_never_expires() {
        let c = cache(CacheOptions {
            default_ttl: 0,
            ..Default::default()
        });
        c.set_raw("k".into(), b"v".to_vec(), None).expect("set");
        assert!(
            c.inner.lock().expect("lock").entries["k"]
                .expires_at
                .is_none()
        );
    }
}
