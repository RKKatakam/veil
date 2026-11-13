# Veil's deployment kit

The runbook is `docs/DEPLOY.md`; to reproduce the published numbers from
the public repository alone, `docs/REPRODUCE.md`. In short:

| Path | What |
|---|---|
| `docker/Dockerfile`, `docker/build.sh` | the `veil-server` and `veil-bench` images (one build stage, two targets; pinned bases; non-root; health check; no secrets) |
| `tls/mkcert.sh` | a private CA and a server certificate for the names and addresses of a deployment |
| `versions.env` | the third-party images (PostgreSQL, YugabyteDB, HAProxy, MinIO), pinned by digest, for both the paid run and the rehearsal (MinIO: the paid run's storage droplet and the rehearsal's store) |
| `gates.sh` | the gates, written once: `pull`, `land`, `api`, `branches` (with the headline: agents on branches merging into `main`), `landing`, `scaling`, `failover`, `objects`, `openscion`, `scale`, `spaces` (5 minutes on a real Spaces bucket at 20 pushes/s, under its request limit); sourced by `do/bench.sh` and `compose/rehearsal.sh` |
| `checks/` | the failover gate's database checks (`failover*.sql`) and its verdict (`failover-verdict.py`); the `spaces` gate's verdict (`spaces-verdict.py`) |
| `scaling-table.py` | the scaling gate's table: throughput with 1, 2 and 3 servers |
| `lb/haproxy-cfg.sh` | the balancer's configuration (HAProxy, TLS passed through) in front of several servers |
| `compose/` | the local rehearsal of the multi-machine topology: three YugabyteDB nodes (or PostgreSQL), MinIO over TLS, two servers, HAProxy, one driver; `rehearsal.sh` runs every gate briefly and tears down |
| `do/` | DigitalOcean provisioning as `doctl` scripts: `estimate.sh`, `create.sh`, `configure.sh`, `bench.sh`, `logs.sh`, `destroy.sh`; dry runs unless `--approve`; `test/test.sh` tests them against a fake `doctl`. Objects: `VEIL_DO_OBJECTS=minio` (default: MinIO on a storage droplet of the run, for the speed runs; one Spaces bucket allows about 800 requests/s, the headline needs about 4,900) or `spaces` (`docs/DEPLOY.md` §2.3) |
| `results/` (ignored) | `deploy/results/NAME/<stamp>-<gate>/`: each gate's raw results with the commit, image ids, topology and command lines that made them (`docs/DEPLOY.md` §6.2) |

Nothing here talks to DigitalOcean, creates anything or publishes anything
without `--approve`, and nothing secret is committed: `deploy/do/.env`,
`deploy/do/state/` (where each run's MinIO credentials are made),
`deploy/compose/.tls/` and the results directories are ignored by git.
