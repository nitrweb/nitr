// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! A fixed pool of independent Lua runtimes checked out per request.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use std::time::Duration;
use tracing::Instrument as _;

use crate::error::Result;
use crate::runtime::Runtime;

/// Builds a replacement Lua state, identical to the ones the pool was
/// created with. Used to recycle a state a request left unfit for reuse.
///
/// Construction is synchronous (the configuration script is not re-run —
/// its snapshot is injected instead), so a rebuild can happen off the
/// request path on a blocking worker.
pub type RebuildFn = dyn Fn() -> Result<Runtime> + Send + Sync;

/// A fixed pool of [`Runtime`]s over an MPMC channel.
///
/// A request checks a runtime out with [`get()`](Self::get) and uses it
/// exclusively; the returned [`RuntimeGuard`] sends it back on drop. When all
/// runtimes are busy, `get()` waits fairly (FIFO) — the channel is the
/// backpressure mechanism — and
/// [`get_timeout()`](Self::get_timeout) bounds that wait so an overloaded
/// server sheds load instead of queueing without limit.
#[derive(Clone)]
pub struct RuntimePool {
    tx: async_channel::Sender<Runtime>,
    rx: async_channel::Receiver<Runtime>,
    /// How a poisoned state is replaced. Without one, a damaged state is
    /// returned to the pool rather than shrinking capacity.
    rebuild: Option<Arc<RebuildFn>>,
}

impl std::fmt::Debug for RuntimePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimePool")
            .field("size", &self.size())
            .field("available", &self.rx.len())
            .field("recycling", &self.rebuild.is_some())
            .finish()
    }
}

impl RuntimePool {
    /// Creates a pool holding the given runtimes.
    pub fn new(runtimes: Vec<Runtime>) -> Self {
        Self::build(runtimes, None)
    }

    /// Creates a pool that recycles damaged states: when a request leaves a
    /// state poisoned (memory limit hit, panic), it is dropped and `rebuild`
    /// produces a fresh one so capacity is restored.
    pub fn with_rebuild<F>(runtimes: Vec<Runtime>, rebuild: F) -> Self
    where
        F: Fn() -> Result<Runtime> + Send + Sync + 'static,
    {
        Self::build(runtimes, Some(Arc::new(rebuild)))
    }

    fn build(runtimes: Vec<Runtime>, rebuild: Option<Arc<RebuildFn>>) -> Self {
        let (tx, rx) = async_channel::bounded(runtimes.len().max(1));
        for rt in runtimes {
            // Cannot fail: the channel capacity equals the number of runtimes.
            let _ = tx.try_send(rt);
        }
        Self { tx, rx, rebuild }
    }

    /// Number of runtimes owned by the pool.
    pub fn size(&self) -> usize {
        self.tx.capacity().unwrap_or(0)
    }

    /// Number of runtimes currently idle and available for checkout.
    pub fn available(&self) -> usize {
        self.rx.len()
    }

    /// Checks a runtime out of the pool, waiting until one is available.
    pub async fn get(&self) -> RuntimeGuard {
        // Invariant, not a fallible path: the pool owns both channel ends
        // for its whole lifetime, so recv can only fail after the pool —
        // and every guard borrowing from it — is gone.
        #[allow(clippy::expect_used)]
        let rt = self
            .rx
            .recv()
            .await
            .expect("runtime pool channel cannot be closed while the pool is alive");
        self.guard(rt)
    }

    /// Checks a runtime out, giving up after `wait`.
    ///
    /// Returns `None` when no state became available in time, so the caller
    /// can shed the request (503) instead of letting it queue behind an
    /// overloaded pool. A zero duration disables the bound and waits like
    /// [`get()`](Self::get).
    pub async fn get_timeout(&self, wait: Duration) -> Option<RuntimeGuard> {
        // The `pool_checkout` span: how long this request waited for a
        // state and whether it got one. DEBUG so the per-request
        // decomposition is opt-in via the level filter.
        let span = tracing::debug_span!(
            "pool_checkout",
            wait_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        );
        let started = std::time::Instant::now();
        let got = async {
            if wait.is_zero() {
                Some(self.get().await)
            } else if let Ok(rt) = self.rx.try_recv() {
                // The fast path (a state is already idle) skips the timer.
                Some(self.guard(rt))
            } else {
                match tokio::time::timeout(wait, self.rx.recv()).await {
                    Ok(Ok(rt)) => Some(self.guard(rt)),
                    // The channel cannot close while the pool is alive; a
                    // timeout is the only real outcome here.
                    Ok(Err(_)) | Err(_) => None,
                }
            }
        }
        .instrument(span.clone())
        .await;
        span.record("wait_ms", started.elapsed().as_millis() as u64);
        span.record("outcome", if got.is_some() { "hit" } else { "shed" });
        got
    }

    fn guard(&self, rt: Runtime) -> RuntimeGuard {
        RuntimeGuard {
            rt: Some(rt),
            tx: self.tx.clone(),
            rebuild: self.rebuild.clone(),
        }
    }
}

/// RAII guard over a checked-out [`Runtime`]; returns it to the pool on drop.
///
/// A state the request left poisoned is not returned: it is dropped and, when
/// the pool was built with [`RuntimePool::with_rebuild`], replaced by a fresh
/// one so the pool keeps its size.
pub struct RuntimeGuard {
    rt: Option<Runtime>,
    tx: async_channel::Sender<Runtime>,
    rebuild: Option<Arc<RebuildFn>>,
}

impl std::fmt::Debug for RuntimeGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeGuard")
            .field("runtime", &self.rt)
            .finish_non_exhaustive()
    }
}

impl Deref for RuntimeGuard {
    type Target = Runtime;
    fn deref(&self) -> &Self::Target {
        // Invariant: `rt` is only taken in `Drop`, after the last deref.
        #[allow(clippy::expect_used)]
        self.rt.as_ref().expect("runtime present until drop")
    }
}

impl DerefMut for RuntimeGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Invariant: `rt` is only taken in `Drop`, after the last deref.
        #[allow(clippy::expect_used)]
        self.rt.as_mut().expect("runtime present until drop")
    }
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        let Some(rt) = self.rt.take() else {
            return;
        };
        // A guard dropped mid-unwind was in use when something panicked, so
        // the state is presumed damaged even though nothing marked it: the
        // panic escaped before any code could. Conservative by design —
        // recycling a state that was in fact fine costs one rebuild.
        if !rt.is_poisoned() && !std::thread::panicking() {
            // Cannot fail: capacity equals the number of runtimes and the
            // receiver lives as long as the pool.
            let _ = self.tx.try_send(rt);
            return;
        }

        let Some(rebuild) = self.rebuild.clone() else {
            // No rebuild hook: returning a damaged state is still better
            // than permanently shrinking the pool.
            tracing::warn!("a damaged Lua state was returned to a pool without recycling");
            let _ = self.tx.try_send(rt);
            return;
        };

        // Drop the damaged state *before* building its replacement so the
        // two heaps do not coexist, then rebuild off the request path: the
        // caller has already been answered and the pool runs one slot short
        // until the replacement lands.
        drop(rt);
        let tx = self.tx.clone();
        let handle = tokio::task::spawn_blocking(move || match rebuild() {
            Ok(fresh) => {
                let _ = tx.try_send(fresh);
                tracing::info!(outcome = "rebuilt", "recycled a damaged Lua state");
            }
            // Capacity is lost until the next reload. Loud, because a pool
            // that silently shrinks looks like a mysterious slowdown.
            Err(err) => tracing::error!("failed to recycle a damaged Lua state: {err}"),
        });
        // A rebuild that *panics* never reaches either arm above; only the
        // `JoinHandle` sees it. Observe it so that failure path is exactly
        // as loud as an `Err` — the slot is just as lost.
        tokio::spawn(async move {
            if let Err(err) = handle.await {
                tracing::error!("the Lua state rebuild task panicked: {err}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Runtime, RuntimeOpts};

    fn runtime() -> Runtime {
        Runtime::new_with(RuntimeOpts {
            libs: mlua::StdLib::STRING,
            memory_limit: 8 * 1024 * 1024,
            dev_mode: false,
            exec_timeout: None,
            package_dir: None,
        })
        .expect("runtime")
    }

    #[tokio::test]
    async fn checkout_returns_the_state_on_drop() {
        let pool = RuntimePool::new(vec![runtime()]);
        assert_eq!(pool.size(), 1);
        {
            let _guard = pool.get().await;
            assert_eq!(pool.available(), 0);
        }
        assert_eq!(pool.available(), 1);
    }

    #[tokio::test]
    async fn get_timeout_sheds_when_the_pool_is_busy() {
        let pool = RuntimePool::new(vec![runtime()]);
        let held = pool.get().await;

        // Nothing is available: the wait budget expires and the caller can
        // shed instead of queueing.
        assert!(pool.get_timeout(Duration::from_millis(50)).await.is_none());

        // Once the state comes back, the same call succeeds immediately.
        drop(held);
        assert!(pool.get_timeout(Duration::from_millis(50)).await.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poisoned_states_are_rebuilt_not_reused() {
        let pool = RuntimePool::with_rebuild(vec![runtime()], || Ok(runtime()));
        {
            let mut guard = pool.get().await;
            guard.poison();
        }
        // The replacement arrives from a blocking task; wait for capacity to
        // come back rather than assuming an ordering.
        let guard = tokio::time::timeout(Duration::from_secs(5), pool.get())
            .await
            .expect("a replacement state must be built");
        assert!(!guard.is_poisoned());
    }
}
