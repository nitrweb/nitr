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
    built: Built,
    cfg: &Config,
    builtins: Builtins,
    setup_fns: &Arc<Vec<SetupFn>>,
    modules: &Arc<Vec<Module>>,
    cache: Option<nitr_std::Cache>,
) -> RuntimePool {
    // A rebuilt state gets the snapshot every other state got: the
    // configuration script's result, before any handler touched it.
    let Built { runtimes, snapshot } = built;
    // Without it every request is routed by the state it checked out,
    // which is correct, only not before the checkout.
    let routing = runtimes.first().and_then(|rt| app::routing(rt.lua()).ok());
    let cfg = cfg.clone();
    let setup_fns = setup_fns.clone();
    let modules = modules.clone();
    let pool = RuntimePool::with_rebuild(runtimes, move || {
        let base_statics = crate::static_files::base_mounts(&cfg);
        let mut rt = new_runtime(&cfg, builtins, &setup_fns, &modules, cache.as_ref())?;
        if let Some(snapshot) = &snapshot {
            rt.set_cfg_snapshot(snapshot)?;
        }
        set_nitr_cfg(&rt)?;
        rt.budgeted(|lua| app::load(lua, &cfg.handler_script, &base_statics, &input_env(&cfg)))?;
        Ok(rt)
    });
    match routing {
        Some(routing) => pool.with_companion(routing),
        None => pool,
    }
}

/// What route `input` declarations may rely on in this deployment.
pub(crate) fn input_env(cfg: &Config) -> crate::validation::InputEnv {
    let mut reserved = Vec::new();
    if cfg.openapi.enabled {
        reserved.push((cfg.openapi.path.clone(), "[openapi] path"));
    }
    if cfg.swagger.enabled {
        reserved.push((cfg.swagger.path.clone(), "[swagger] path"));
    }
    crate::validation::InputEnv {
        upload_root: cfg.multipart.upload_dir.clone().map(Arc::new),
        reserved,
    }
}

/// Builds the OpenAPI document and page from the bootstrap state and, in
/// dev mode with `[openapi] output` set, writes the document when it
/// changed. Called on every (re)build so the served document always
/// describes the live routes.
#[cfg(feature = "openapi")]
pub(super) fn build_docs(
    cfg: &Config,
    runtimes: &[Runtime],
) -> Result<Arc<crate::openapi::docs::OpenApiDocs>> {
    let bootstrap = runtimes
        .first()
        .ok_or_else(|| nitr_core::Error::Config("the runtime pool is empty".into()))?;
    let docs = crate::openapi::docs::OpenApiDocs::build(bootstrap.lua(), cfg)?;
    tracing::info!("{}", docs.summary());
    if cfg.dev_mode
        && let Some(output) = &cfg.openapi.output
    {
        match crate::openapi::output::write_if_changed(output, docs.spec())? {
            crate::openapi::output::Written::Bytes(n) => tracing::info!(
                "openapi: wrote {} ({})",
                output.display(),
                nitr_std::validation::fmt_size(n as u64)
            ),
            crate::openapi::output::Written::Unchanged => {}
        }
    }
    Ok(Arc::new(docs))
}

/// The pooled runtimes of one (re)build, with the configuration
/// snapshot they were given.
pub(super) struct Built {
    pub(super) runtimes: Vec<Runtime>,
    /// The configuration script's result, taken before the handler script
    /// loaded: a handler may add anything to `nitr.cfg` (a function, a
    /// userdata), and that must neither fail a boot nor reach a state
    /// that did not run it.
    pub(super) snapshot: Option<serde_json::Value>,
}

/// Builds the full set of pooled runtimes: a bootstrap state runs the
/// configuration script exactly once and its snapshot is injected into the
/// rest. Also used by reloads, so the configuration script's side effects
/// run once per (re)build.
pub(super) async fn build_runtimes(
    cfg: &Config,
    builtins: Builtins,
    setup_fns: &Arc<Vec<SetupFn>>,
    modules: &Arc<Vec<Module>>,
    cache: Option<&nitr_std::Cache>,
) -> Result<Built> {
    let workers = cfg.workers.max(1);
    let base_statics = crate::static_files::base_mounts(cfg);

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
    let env = input_env(cfg);
    if bootstrap.budgeted(|lua| app::load(lua, &cfg.handler_script, &base_statics, &env))? {
        // The disk the validated uploads of one moment may occupy, so the
        // operator has seen the number before the first upload.
        tracing::info!(
            "routes declare file uploads: worst case {} on disk at once ({} workers × {} parts × {} bytes)",
            nitr_std::validation::fmt_size(
                (workers as u64)
                    .saturating_mul(cfg.limits.max_form_parts as u64)
                    .saturating_mul(cfg.limits.max_file_bytes)
            ),
            workers,
            cfg.limits.max_form_parts,
            cfg.limits.max_file_bytes,
        );
    }
    if workers == 1 {
        return Ok(Built {
            runtimes: vec![bootstrap],
            snapshot,
        });
    }

    // Remaining states: inject the snapshot instead of re-running the
    // configuration script, so its side effects happen exactly once. This
    // is synchronous CPU work — a Lua state, the builtins, the compiled
    // script, `workers - 1` times over — so it runs on the blocking pool:
    // a reload used to occupy one of the async workers for the whole
    // rebuild, the way a poisoned-state recycle never did.
    let rest = {
        let cfg = cfg.clone();
        let setup_fns = setup_fns.clone();
        let modules = modules.clone();
        let cache = cache.cloned();
        let env = env.clone();
        let snapshot = snapshot.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<Runtime>> {
            let mut runtimes = Vec::with_capacity(workers - 1);
            for _ in 1..workers {
                let mut rt = new_runtime(&cfg, builtins, &setup_fns, &modules, cache.as_ref())?;
                if let Some(snapshot) = &snapshot {
                    rt.set_cfg_snapshot(snapshot)?;
                }
                set_nitr_cfg(&rt)?;
                rt.budgeted(|lua| app::load(lua, &cfg.handler_script, &base_statics, &env))?;
                runtimes.push(rt);
            }
            Ok(runtimes)
        })
        .await
        .map_err(|err| {
            nitr_core::Error::Panic(format!("building the runtime pool failed: {err}"))
        })??
    };
    let mut runtimes = Vec::with_capacity(workers);
    runtimes.push(bootstrap);
    runtimes.extend(rest);
    Ok(Built { runtimes, snapshot })
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
