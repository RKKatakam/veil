# Deploying Veil for the DigitalOcean test

> **Status: kit ready, nothing rented** (2026-11-09). This runbook takes the
> server as built (`docs/HUB.md` §13) through one paid test on DigitalOcean,
> budget under $100, as `docs/design/server/README.md` ("Plan to the
> DigitalOcean test") asks. **Nothing is created at DigitalOcean until the
> owner approves the estimate and passes `--approve`.** Every script runs as
> a dry run without it. The kit is in `deploy/` (`deploy/README.md`).

Veil is server-centric: `vl` is always connected to the server, which
enforces every permission. This deployment is that server (`veil-server`),
its database, its object store and the load drivers, nothing else.

## 1. Prerequisites

On the operator's machine:

| Tool | Why | Check |
|---|---|---|
| Docker 24+ with Compose v2 | building the images; the rehearsal; `docker save` ships images to the droplets | `docker compose version` |
| `doctl` 1.100+ | DigitalOcean's CLI; every create and delete goes through it | `doctl version` (not needed for dry runs or the rehearsal) |
| `ssh`, `scp`, `zstd`, `openssl`, `curl` 7.75+ | configuring the droplets, the certificates, the Spaces check (`curl --aws-sigv4`) | |
| `awscli` (optional) | `destroy.sh` empties and deletes the Spaces bucket with it; without it the bucket is deleted in the control panel | `aws --version` |
| `bc`, `python3` | the estimate; the kit's tests | |

At DigitalOcean (the owner, once; nothing the scripts do):

1. an account with a payment method, and a **personal access token** with
   read and write scope (API → Tokens);
2. a **Spaces access key** pair (API → Spaces Keys);
3. the account's **droplet limit** at least 7 (the default is often 3 or 5:
   Account → request an increase);
4. the operator's **public IPv4** (`curl -4 -s https://ifconfig.me`): SSH
   and the server's port are open to it only.

Then:

```sh
cp deploy/do/.env.example deploy/do/.env && chmod 600 deploy/do/.env
$EDITOR deploy/do/.env     # token, Spaces keys, a database password, your IP, the topology
```

`deploy/do/.env` is ignored by git. The scripts also read these variables
from the environment, which wins over the file.

## 2. Topology and cost

**Default topology** (`deploy/do/.env.example`; `deploy/do/estimate.sh`
prints it priced):

| Droplet | Size | Runs | Why |
|---|---|---|---|
| `NAME-hub` | `c-16` (16 dedicated vCPUs, 32 GB) | `veil-server` in its container, port 8443; also hosts the gates that start a server of their own (§6) | the load curves saturate the server's CPU before anything else (`docs/design/scale/LOAD.md`); a dedicated-CPU size gives steady numbers |
| `NAME-db` | `c-8` (8 vCPUs, 16 GB, 200 GB NVMe) | PostgreSQL 17 in a container (`postgres:17-alpine`, `pg_stat_statements`, `max_connections=1500`), on the VPC's private address only | see "Why not managed PostgreSQL" |
| `NAME-driver1`, `-driver2` | `c-8` each | `veil-bench` in its container: 10,000 simulated agents fit in one process on 8 cores | two, so one can drive pulls while the other drives landings |
| Spaces bucket `NAME-objects-…` | 250 GiB, 1 TiB out | the server's object store (S3 API, `https://REGION.digitaloceanspaces.com`, path-style), created by the server itself at first start | |

Options:

- **`VEIL_DO_YB_NODES=3`** replaces the database droplet with a three-node
  **YugabyteDB** cluster (`yugabytedb/yugabyte:2025.2.8.1-b8`, the Apache-2.0
  core, `docs/HUB.md` §13.1), one `yugabyted` per `c-8`. Phase 4's gate
  (`docs/design/server/phase-4-agent-scale.md` §7: 1,000 landings/s into one
  `main` with 10,000 agents) is specified on a three-node YugabyteDB
  cluster. **Its landing service (S17) is not merged yet** (phase 4 §8), so
  the first test runs the phase 2, cost and OpenScion gates on PostgreSQL;
  the YugabyteDB topology is in the kit for the G4 run.
- **`VEIL_DO_WITH_CACHE=1`** adds `NAME-cache` (`s-4vcpu-8gb`) running
  `veil-server cache` (the regional cache, `docs/HUB.md` §13.18) in front of
  the hub, for `vl` clients and manual tests. The cache *gate* cannot be run
  against it (BUG-1591, §6), so it is off by default.

**Why not managed PostgreSQL.** The server's database driver is built
without TLS (BUG-1590), and DigitalOcean's managed databases accept TLS
connections only. A PostgreSQL container on a droplet in the same VPC is
also what the rehearsal and `scripts/bench-server.sh` run, so the test
measures the configuration the project has measured all along, with
superuser access for `pg_stat_statements` and the counters the cost gates
read. If BUG-1590 is fixed, a managed `db-s-4vcpu-8gb` ($0.179/h) could
replace the droplet; the gates do not need it.

**Cost** (DigitalOcean list prices as published, USD, hourly = monthly/672;
**confirm them with `deploy/do/estimate.sh --live --approve` or
`doctl compute size list` before approving**; the `--live` form only reads
prices):

| Item | $/hour | Planned 8 h | 24 h (teardown forgotten a day) |
|---|---:|---:|---:|
| hub `c-16` | 0.500 | 4.00 | 12.00 |
| db `c-8` | 0.250 | 2.00 | 6.00 |
| driver1 + driver2, `c-8` | 0.500 | 4.00 | 12.00 |
| Spaces (flat $5/month while any bucket exists) | 0.007 | 5.00 | 5.00 |
| bandwidth (pooled transfer included with the droplets) | 0 | 0 | 0 |
| **default total** | **1.257** | **15.00** | **35.00** |
| + YugabyteDB, 3 × `c-8` instead of the db droplet | +0.500 | +4.00 | +12.00 |
| + cache `s-4vcpu-8gb` | +0.071 | +0.57 | +1.70 |
| **everything on, 8 h** | 1.821 | **19.57** | 48.70 |

The planned test is about 8 hours of machines: an hour to create and
configure, five for the gates (§6), an hour for logs and teardown, one
spare. Even a day of everything left running stays under $50; a month
forgotten would be $845 or more, which is what `destroy.sh`'s check is for.

## 3. The images

```sh
deploy/docker/build.sh            # veil-server:TAG and veil-bench:TAG; TAG = this commit's id
```

One `Dockerfile` (`deploy/docker/Dockerfile`), one build stage
(`rust:1.99.1-bookworm`, the repository's toolchain; `cargo build --locked
--release`), two runtime targets on `debian:12.12-slim`:

- **`veil-server`**: the binary, `ca-certificates` (Spaces over HTTPS) and
  `curl` (the health check). Runs as `veil` (uid 10001), data in the
  `/var/lib/veil` volume, port 8443. **Health check:** HTTPS answers on the
  server's port (`/v1/epochs`; a 4xx is "up", since the route needs a
  grant). The same image runs `veil-server migrate` and `veil-server cache`
  (`VEIL_HEALTH_URL` points the check at the cache's port).
- **`veil-bench`**: `veil-bench`, `vl`, `veil-server` and `git` (the
  OpenScion gates compare with Git and start a server of their own). Runs
  as `bench` (uid 10002) in the `/work` volume.

Nothing secret is baked in: the Spaces keys and the database URL come from
the environment (`VEIL_S3_ACCESS_KEY`, `VEIL_S3_SECRET_KEY`,
`VEIL_DATABASE_URL`) and the TLS key from a mounted file. The images are
never pushed to a registry: `configure.sh` ships them over SSH (`docker save
| zstd | docker load`). The build takes about 2.5 minutes on 8 cores.

**TLS.** The server's built-in self-signed certificate names only
`localhost` and `127.0.0.1`. `deploy/tls/mkcert.sh DIR NAMES…` makes a
private CA and a certificate for the hub's public and private addresses;
`configure.sh` runs it and copies the CA to every droplet. Clients pin it:
`vl login https://HUB:8443 --ca deploy/do/state/NAME/tls/ca.pem`;
`veil-bench … --ca`. The certificate is valid 30 days.

## 4. Local rehearsal

The same images, with PostgreSQL 17 and MinIO standing in for the database
droplet and Spaces, in Docker Compose (`deploy/compose/docker-compose.yml`:
`postgres`, `minio`, `migrate`, `veil-server`, `veil-cache`, and the `bench`
profile). The rehearsal builds, brings the stack up, waits for the health
checks, smoke-tests both HTTPS ports with the rehearsal CA, runs a short
version of every gate (§6) through the bench container, prints the tables
and tears down the containers, network and volumes of this run only:

```sh
deploy/compose/rehearsal.sh NAME               # about 10 minutes; DURATION=5 s per load point
GATES="pull land" DURATION=10 deploy/compose/rehearsal.sh NAME
KEEP=1 deploy/compose/rehearsal.sh NAME        # leave it running; it prints the `down -v` command
HUB_PORT=28443 CACHE_PORT=28444 deploy/compose/rehearsal.sh NAME   # free host ports on a shared machine
```

Results: `deploy/compose/results/<stamp>/` (JSON and Markdown per gate, the
gate logs, the server's and the cache's logs). Heavy runs belong on a Boat
machine: `bash ~/.cache/veil-orch/boat/boat-verify.sh cmd NAME -- bash
deploy/compose/rehearsal.sh NAME`. On the shared development server use
unique ports and never touch the `veil-shared-*` containers; the rehearsal
names everything `veil-rehearsal-NAME`.

**Rehearsal of 2026-11-09** (Boat machines, 8 vCPU, 16 GB, Docker 28):
the results are in §9.

## 5. The DigitalOcean run, in order

Every command is a dry run without `--approve`. Run the dry run first,
read what it would do, then add `--approve`.

```sh
# 0. the kit's own tests (a fake doctl; nothing leaves the machine), and the estimate
bash deploy/do/test/test.sh
deploy/do/estimate.sh                      # built-in prices
deploy/do/estimate.sh --live --approve     # the API's prices (reads only; needs the token)

# 1. images
deploy/docker/build.sh                     # prints TAG

# 2. create: ssh key, firewall, droplets (tagged NAME), state file
deploy/do/create.sh                        # dry run: the plan and every command
deploy/do/create.sh --approve              # <- the owner's approval; the first thing that bills

# 3. configure: wait for cloud-init, certificate, ship images, database, migrations, server, smoke test
deploy/do/configure.sh --approve [TAG]

# 4. the gates (§6), one at a time; results under deploy/results/NAME/
deploy/do/bench.sh --approve pull
deploy/do/bench.sh --approve land
deploy/do/bench.sh --approve branches
deploy/do/bench.sh --approve api
deploy/do/bench.sh --approve objects
deploy/do/bench.sh --approve openscion
deploy/do/bench.sh --approve scale

# 5. logs and metrics from every droplet
deploy/do/logs.sh --approve

# 6. teardown, then the check that nothing is left
deploy/do/destroy.sh --approve
deploy/do/destroy.sh --check --approve     # repeat until it says "nothing left"
```

What `create.sh --approve` makes, all tagged `NAME` (so `destroy.sh`
deletes by tag, including anything a run that died left behind):

1. an SSH key for this run, generated into `deploy/do/state/NAME/` (mode
   0700; ignored by git) and imported;
2. a cloud firewall: inbound 22, 8443 and 8444 from the operator's address,
   everything between droplets tagged `NAME`, nothing else in; all out;
3. the droplets from `deploy/do/cloud-init/docker.yaml` (Ubuntu 24.04,
   Docker and zstd from Ubuntu, file-descriptor and port-range limits
   raised; **no secrets in user-data**, which any process on a droplet can
   read from the metadata service);
4. `deploy/do/state/NAME/state.env` (mode 0600): ids, public and private
   addresses, the bucket's name.

`configure.sh --approve` then copies secrets as root-only files
(`/etc/veil/*.env`, `/etc/veil/tls/`), starts PostgreSQL (or the YugabyteDB
nodes) on the private address, runs `veil-server migrate` once (BUG-838),
starts the server with `--restart unless-stopped`, waits for its health
check, and ends with `vl login` instructions. A `vl` on your machine then
works against it:

```sh
vl login https://HUB_IP:8443 --ca deploy/do/state/NAME/tls/ca.pem
```

## 6. The gates, and where the results go

`deploy/do/bench.sh --approve GATE` runs one gate and copies its results to
`deploy/results/NAME/<stamp>-GATE/` (`*.json`, `*.md`, `driver.log`, the
hub's `docker stats` sampled every 5 s in `hub-docker-stats.log`, and the
server's request-path counters `server-stats.json`, written on `SIGUSR1`).
`DURATION` (default 20 s per point) and `STEP_LIMIT` (default 3600 s)
bound it; extra `veil-bench` flags go after the gate name.

| Gate | Runs | What `veil-bench` does | Target (`docs/design/server/*`) |
|---|---|---|---|
| `pull` | a driver → the running server | `load --mode pull`, 1 project, 10/100/1,000 agents, `main` moving 20/s | phase 2 §8: 10,000 pulls/s with caches; 5 or fewer database statements per warm pull (cost gate) |
| `land` | a driver | `load --mode land`, 1/10/100 projects, 1 and 50 agents, `max` rate | phase 2 §8: 100/s into one `main` (p99 under 500 ms), 4,000/s across projects; 1 database commit per landing |
| `branches` | a driver | `load --mode branches`, 1/10/100 agents on branches of their own | `storage-and-cost.md` §9: 1 commit per push, at most 2 storage writes (reported) |
| `api` | a driver | `load --mode api`, commits through `POST …/changes` | `docs/HUB.md` §13.13 (S10): same counts as `land` |
| `objects` | the hub, a server and a cache the tool starts itself (BUG-1591) against the same database and a bucket of its own | `load --mode objects --via server,cache`, 10/100/1,000 fresh thin workspaces | phase 2 §8 and `docs/HUB.md` §13.18: 99 % of objects from the cache's store; the cache under 512 MiB |
| `openscion` | the hub, a server the tool starts itself | `openscion`, 1k and 10k files, 5 runs, Git beside | `docs/OVERVIEW.md` "Speed gates": 22/245, 51/544, 2.5/22, 6.1/25 ms, and beating Git on the same machine |
| `scale` | the hub, a server the tool starts itself | `run --profile 1g` (push, clone, pull, clone one directory, gc) | `docs/design/scale/BASELINE.md`: the 1 GB profile; server peak memory under 1 GB (`storage-and-cost.md` §9) |

The three same-machine gates stop nothing: the serving `veil-server`
container keeps running beside the tool's own server (another port, another
data directory, the same database and the Spaces endpoint with a bucket
suffix of its own), as `scripts/bench-server.sh` does locally. Run them
while no driver gate runs, so the hub's CPU is theirs.

**Not in the kit yet,** because the code they measure is not merged:
phase 4's `load --mode land --landing-service` at 1,000/s with 10,000
agents, `veil-bench prs` and `veil-bench bisect` (phase 4 §7), and phase
2's `veil-bench workspace` and `cache-access`. Each is one more line in
`deploy/do/bench.sh` when its tool exists.

## 7. Logs and metrics

```sh
deploy/do/logs.sh --approve       # -> deploy/results/NAME/logs-<stamp>/<droplet>/
```

Per droplet: every container's log (`containers.log`), `docker ps`,
memory, disk, uptime and the kernel log's tail (`system.txt`); on the hub
the server's counters (`server-stats.json`) and the `docker stats` samples
of every gate (`metrics/`); on the database droplet the 30 most-called
statements from `pg_stat_statements`. DigitalOcean's own graphs (CPU,
memory, disk, bandwidth per droplet) are in the control panel, since the
droplets are created with monitoring on. For anything live:
`ssh -i deploy/do/state/NAME/id_ed25519 root@IP docker logs -f veil-server`.

## 8. Teardown

```sh
deploy/do/destroy.sh --approve            # droplets by tag, firewall, ssh key, tag; empties and deletes the bucket
deploy/do/destroy.sh --check --approve    # nothing left?
```

The check counts droplets tagged `NAME`, firewalls and SSH keys named
`NAME`, block volumes, snapshots and load balancers starting with `NAME`,
reserved IPs in the account (an unassigned one bills $4/month), and asks
Spaces whether the bucket still exists (HTTP 404 means gone). It exits
non-zero while anything is left and removes the state file only when
nothing is. The bucket is emptied and deleted with `aws s3 rb --force`
when `awscli` is installed; otherwise the check names it and it is deleted
in the control panel (Spaces → bucket → Settings → Destroy). With no bucket
left the Spaces subscription ends. Look at Billing the next day: the test
appears as hourly line items.

## 9. Rehearsal results (2026-11-09)

`deploy/compose/rehearsal.sh boat` on Boat machines (8 vCPU, 16 GB, Docker
28), `integration` `ae3d57ed`, 15 s per load point, 1,000 files and one
run for OpenScion, the `tiny` scale profile. The image build took 2.5
minutes; the stack came up in 20 s; the whole run about 8 minutes.

| Gate | Outcome | Numbers (short run, a smoke test, not a measurement) |
|---|---|---|
| stack and smoke | **ok** | PostgreSQL, MinIO, migrations, server and cache healthy; HTTPS with the rehearsal CA answers on both ports |
| `pull` | **ok** | 7,800 pulls/s with 10 agents, 7,550 with 50 (p99 5 and 41 ms); 1.0 to 1.1 database statements per warm pull (gate 5) |
| `land` | **gate missed** | 26 landings/s with 1 agent (p50 19 ms), 147/s with 10 agents (p50 59 ms), no errors; **9.6 and 7.0 database commits per landing** (gate 1) |
| `branches` | **gate missed** | 53/s and 253/s; **9.4 and 2.0 commits per landing** |
| `api` | **gate missed** | 101/s and 112/s; **8.3 and 6.3 commits per landing** |
| `objects` | **ok** | through the server 1,230 reads/s (p50 7.8 ms); through the cache 1,550 reads/s (p50 6.3 ms), **100 % from the cache's store**, cache peak 32 MiB (gates 99 %, 512 MiB) |
| `openscion` (1k files, 1 run) | **ok** (beats Git on all four; targets not met, as in `docs/OVERVIEW.md`) | import 63 ms (Git 135), clone 123 ms (Git 177), commit one file 9.1 ms (Git 25.6), clone one directory 38.5 ms (Git 45.9) |
| `scale` (`tiny`) | **ok** | initial push 1.5 s, server 15 → 87 MiB; push with nothing new 22 ms |
| teardown | **ok** | nothing of the run left (containers, network, volumes) |

**The commit-count misses are not the kit's.** The same numbers came back
without the regional cache, and `scripts/bench-server.sh load` on
`integration` itself gives 9.4 (1 agent), 7.3 (10) and 1.5 (100) commits
per landing on `land`, and the like on `branches` and `api`: **BUG-1593**,
a cost regression since S4 was measured. Until it is fixed the DigitalOcean
run's landing gates will fail on cost while passing on throughput; the kit
reports both.

Found and filed by the rehearsal:

- **BUG-1590** (`docs/BUGS.md`): the server cannot use a database that
  requires TLS, which rules out managed PostgreSQL (§2).
- **BUG-1591**: `veil-bench load --via cache` cannot measure a running
  cache, so the cache gate runs on the hub in its same-machine form (§6).
- **BUG-1592**: the cache advertises HTTP/2 but serves HTTP/1 only; HTTP/2
  clients (curl, by default) get a broken stream. The health check and the
  smoke tests use `--http1.1`; `vl` and `veil-bench` are HTTP/1.1 and
  unaffected.
- **BUG-1593**: 9 to 13 database commits per landing on `integration`
  (gate 1).

## 10. Testing the kit

```sh
bash deploy/do/test/test.sh       # the provisioning scripts against a fake doctl
```

The fake (`deploy/do/test/fake-doctl`) records every call and answers made-up
ids. The tests check that dry runs call nothing and write nothing; that
`--approve` refuses without a token; that `create.sh` makes the key, the
firewall (operator-only inbound) and every droplet of the topology, tagged
and from cloud-init, and saves addresses to a private state file; that the
YugabyteDB and cache options change the topology; that `configure.sh` puts
no secret on a command line; where `bench.sh` runs each gate; and that
`destroy.sh` deletes by tag and its check fails while anything is left.
`configure.sh`, `bench.sh` and `logs.sh` over real SSH are exercised only
by the rehearsal's equivalent Docker commands and by the DigitalOcean run.

## 11. Risks and open items

- **Prices.** The built-in table is DigitalOcean's list as published;
  confirm with `estimate.sh --live --approve` before approving. Sizes may be
  unavailable in a region (`doctl compute size list` shows `Available`); the
  estimate and `create.sh` take the sizes from `.env`.
- **Droplet limit.** New accounts often may not create 4 or 7 droplets at
  once; `create.sh` then fails on the first refused droplet and leaves the
  earlier ones running: `destroy.sh --approve` removes them by tag.
- **BUG-1590**: no TLS to the database, so the database is on the VPC's
  private network only, behind the firewall; the hub and the database are
  one hop apart. Managed PostgreSQL is out until fixed.
- **BUG-1591**: the cache gate runs on the hub in the same-machine form,
  not across the network to a cache droplet.
- **Phase 4 benchmarks** are not built; the YugabyteDB topology waits for
  them (§2, §6).
- **BUG-1593**: the landing gates fail on cost (commits per landing) on
  `integration` today; fix it before the paid run, or the run measures
  throughput and latency only.
- **cloud-init timing.** `configure.sh` waits for `cloud-init status
  --wait` on every droplet (usually 1 to 3 minutes). A droplet that never
  reaches "done" is reported; `ssh root@IP cloud-init status --long` says why.
- **Secrets.** Only in `deploy/do/.env` (0600, ignored), `deploy/do/state/`
  (0700, ignored) and root-only files on the droplets; never on a command
  line (`test.sh` checks the dry run for that), never in user-data, never
  in an image. Rotate the token and the Spaces keys after the test.
- **The certificate** is valid 30 days; `vl` clients pin the run's CA.
- **Spaces** bills $5 for the month however short the test; it ends when
  the last bucket is deleted.
