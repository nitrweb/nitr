# Deploying Nitr

Reference material for the two places Nitr actually runs: a systemd unit
and a container. Both are documentation you copy and adjust, not a release
channel.

## The operational surface

| Concern | Mechanism |
| --- | --- |
| Is the process alive? | `GET /healthz` → `200 ok`, answered in Rust, never touches a Lua state |
| Should it get traffic? | `GET /readyz` → `200 ok`, flips to `503 draining` the moment a graceful shutdown starts |
| Stop | `SIGTERM`: stop accepting → flip readiness → drain in-flight requests for `[shutdown] grace` (+ `stream_grace` for live streams) → exit. A truncated drain exits non-zero. |
| Zero-downtime reload | `SIGHUP`, or `nitr reload` (finds the process via the configured `pidfile`) |
| Machine-readable logs | `[log] format = "json"` — one object per line, request/error fields as real keys |
| Which config value won? | `nitr check --print-config` prints the effective configuration after file + env + flags |
| Single-file deploy | `nitr build --output myapp` — binary + app in one executable; the database stays external |

Health endpoints are on by default on the main listener. To keep them off
the public port, give them their own address:

```toml
[health]
bind = "127.0.0.1:9090"   # probes only; the app never answers here
```

## systemd — [systemd/nitr.service](systemd/nitr.service)

The two lines people get wrong:

- **`TimeoutStopSec` must exceed the drain deadline** (`[shutdown] grace +
  stream_grace`, default 35s). Below that, systemd SIGKILLs the process
  mid-drain — cutting exactly the requests graceful shutdown exists to
  protect.
- **`ExecReload` sends SIGHUP**, which Nitr defines as "rebuild the Lua
  runtime pool without dropping connections". It is not a restart; the
  process, its listener, and its keep-alive connections survive.

The hardening block assumes the app writes only its SQLite database
(`ReadWritePaths`); widen it deliberately, not preemptively.

## Container — [docker/Dockerfile](docker/Dockerfile)

- **Nitr must receive the SIGTERM.** `docker stop` signals PID 1 and
  nothing else. Use the exec-form `ENTRYPOINT ["/usr/local/bin/nitr"]` so
  nitr *is* PID 1 — a shell-form entrypoint puts `sh` in front, which
  swallows the signal, and the container dies by SIGKILL 10 seconds later
  having drained nothing.
- **Give `docker stop` more time than the drain**: `docker stop --time 40`
  (or `stopGracePeriodSeconds`/`terminationGracePeriodSeconds: 40` in
  Kubernetes) for the default 35s drain budget.
- **The database is a volume.** An image is immutable; SQLite is not.
- Kubernetes probes map directly:

```yaml
livenessProbe:  { httpGet: { path: /healthz, port: 3000 } }
readinessProbe: { httpGet: { path: /readyz,  port: 3000 }, periodSeconds: 2 }
```

Readiness flipping *before* requests can fail is what makes a rolling
deploy hitless: the endpoint reports `503 draining` while in-flight work
finishes, so the balancer moves traffic first.

## `nitr build` artifacts

`nitr build --output myapp` appends the application (config, Lua sources,
templates, static files, migrations) to the running binary. The result is
one executable with no dependency on the directory it was built from:

- `dev_mode` is forced off — there are no source files to watch.
- The extraction lives in the user's private cache
  (`$XDG_CACHE_HOME/nitr/apps`, else `~/.cache/nitr/apps`, mode 0700),
  content-addressed and reused across starts of the same artifact. With
  no writable cache directory (a `ProtectHome=true` unit, a HOME-less
  container user) the bundle is extracted into a fresh private temporary
  directory on every start and a warning says where.
- The **database path is untouched**: it resolves against the working
  directory as always. State stays outside the artifact, on purpose.
