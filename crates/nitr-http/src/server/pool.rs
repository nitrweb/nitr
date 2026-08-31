// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! Construction of the pooled Lua runtimes: the bootstrap state that runs
//! the configuration script once, snapshot injection, and the rebuild
//! closure that recycles a damaged state.

use std::sync::{Arc, RwLock};

use mlua::AnyUserData;

use crate::app;
use crate::config::Config;
use nitr_core::{Result, Runtime, RuntimePool};
use nitr_std::Builtins;

use super::{Module, SetupFn};

/// The currently-live pool (poisoning is unreachable: the lock is only
/// held to clone/replace an `Arc`).
pub(crate) fn current_pool(pool: &Arc<RwLock<Arc<RuntimePool>>>) -> Arc<RuntimePool> {
    pool.read()
        .map(|p| p.clone())
        .unwrap_or_else(|e| e.into_inner().clone())
}

/// Wraps the runtimes in a pool that can recycle a damaged state.
///
/// The rebuild closure reproduces exactly what `build_runtimes` produces for
/// a non-bootstrap state: builtins, extension modules, the configuration
/// snapshot, and the compiled handler. The configuration *script* is never
/// re-run — its snapshot is captured once, so a recycle has no side effects.
pub(super) fn new_pool(
    runtimes: Vec<Runtime>,
    cfg: &Config,
    builtins: Builtins,
    setup_fns: &Arc<Vec<SetupFn>>,
    modules: &Arc<Vec<Module>>,
    cache: Option<nitr_std::Cache>,
) -> RuntimePool {
    // A rebuilt state needs the same configuration snapshot the others got.
    let snapshot = runtimes
        .first()
        .and_then(|rt| rt.cfg_snapshot().ok().flatten());
    let cfg = cfg.clone();
    let setup_fns = setup_fns.clone();
    let modules = modules.clone();
    RuntimePool::with_rebuild(runtimes, move || {
        let base_statics = crate::static_files::base_mounts(&cfg);
        let mut rt = new_runtime(&cfg, builtins, &setup_fns, &modules, cache.as_ref())?;
        if let Some(snapshot) = &snapshot {
            rt.set_cfg_snapshot(snapshot)?;
        }
        set_nitr_cfg(&rt)?;
        app::load(&rt, &cfg.handler_script, &base_statics)?;
        Ok(rt)
    })
}

/// Builds the full set of pooled runtimes: a bootstrap state runs the
/// configuration script exactly once and its snapshot is injected into the
/// rest. Also used by reloads, so the configuration script's side effects
/// run once per (re)build.
pub(super) async fn build_runtimes(
    cfg: &Config,
    builtins: Builtins,
    setup_fns: &[SetupFn],
    modules: &[Module],
    cache: Option<&nitr_std::Cache>,
) -> Result<Vec<Runtime>> {
    let workers = cfg.workers.max(1);
    let base_statics = crate::static_files::base_mounts(cfg);
    let base_statics = base_statics.as_slice();

    // Bootstrap state: runs the configuration script exactly once.
    let mut bootstrap = new_runtime(cfg, builtins, setup_fns, modules, cache)?;
    let snapshot = match &cfg.config_script {
        Some(conf_src) => {
            // Pass the database connection to the config script when available.
            // Invariant: `nitr_name` is `None` only for combined or
            // multi-field flags; DATABASE is neither.
            #[allow(clippy::expect_used)]
            let db_name = Builtins::DATABASE
                .nitr_name()
                .expect("DATABASE is a single builtin flag");
            let db = nitr_core::nitr_table(bootstrap.lua())?.get::<Option<AnyUserData>>(db_name)?;
            bootstrap.register_cfg_fn(conf_src, db).await?;
            bootstrap.cfg_snapshot()?
        }
        None => None,
    };
    set_nitr_cfg(&bootstrap)?;
    app::load(&bootstrap, &cfg.handler_script, base_statics)?;

    // Remaining states: inject the snapshot instead of re-running the
    // configuration script, so its side effects happen exactly once.
    let mut runtimes = Vec::with_capacity(workers);
    runtimes.push(bootstrap);
    for _ in 1..workers {
        let mut rt = new_runtime(cfg, builtins, setup_fns, modules, cache)?;
        if let Some(snapshot) = &snapshot {
            rt.set_cfg_snapshot(snapshot)?;
        }
        set_nitr_cfg(&rt)?;
        app::load(&rt, &cfg.handler_script, base_statics)?;
        runtimes.push(rt);
    }
    Ok(runtimes)
}

fn new_runtime(
    cfg: &Config,
    builtins: Builtins,
    setup_fns: &[SetupFn],
    modules: &[Module],
    cache: Option<&nitr_std::Cache>,
) -> Result<Runtime> {
    let rt = Runtime::new_with(cfg.runtime_opts()?)?;
    let env = nitr_std::BuiltinsEnv {
        templates_dir: cfg.templating.dir.clone(),
        database: cfg.database.as_ref().map(|db| db.path.clone()),
        sqlite: cfg
            .database
            .as_ref()
            .map(|db| db.pragmas())
            .unwrap_or_default(),
        fetch: cfg.fetch.options(),
        env: cfg.env_options(),
        cache: cache.cloned(),
        cookie_secure: cfg.cookies.secure.resolve(cfg.tls.enabled),
    };
    nitr_std::register_builtins(rt.lua(), builtins, &env)?;
    app::register_nitr_app(rt.lua())?;
    // Extension modules mount under `nitr.ext`; two modules sharing a
    // name is caught here, at build time.
    for (name, module) in modules {
        rt.register_module(name, module.as_ref())?;
    }
    for setup in setup_fns {
        setup(rt.lua())?;
    }
    Ok(rt)
}

/// Exposes the state's configuration table to scripts as `nitr.cfg`, so
/// app-style handlers (which only receive the request) can reach it.
fn set_nitr_cfg(rt: &Runtime) -> Result {
    if let Some(cfg) = rt.cfg() {
        let nitr: mlua::Table = rt.lua().globals().get("nitr")?;
        nitr.set("cfg", cfg.clone())?;
    }
    Ok(())
}
