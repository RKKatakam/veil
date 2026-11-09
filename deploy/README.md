# Veil's deployment kit

The runbook is `docs/DEPLOY.md`. In short:

| Path | What |
|---|---|
| `docker/Dockerfile`, `docker/build.sh` | the `veil-server` and `veil-bench` images (one build stage, two targets; pinned bases; non-root; health check; no secrets) |
| `tls/mkcert.sh` | a private CA and a server certificate for the names and addresses of a deployment |
| `compose/` | the local rehearsal: the same images with PostgreSQL 17 and MinIO (`rehearsal.sh` runs the short gates and tears down) |
| `do/` | DigitalOcean provisioning as `doctl` scripts: `estimate.sh`, `create.sh`, `configure.sh`, `bench.sh`, `logs.sh`, `destroy.sh`; dry runs unless `--approve`; `test/test.sh` tests them against a fake `doctl` |

Nothing here talks to DigitalOcean, creates anything or publishes anything
without `--approve`, and nothing secret is committed: `deploy/do/.env`,
`deploy/do/state/`, `deploy/compose/.tls/` and the results directories are
ignored by git.
