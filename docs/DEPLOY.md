# Deploying Veil for the DigitalOcean test

> **Status: kit ready, nothing rented** (2026-11-12). This runbook takes the
> server as built (`docs/HUB.md` §13, phases 1 to 4) through one paid test
> on DigitalOcean, budget under $100, as `docs/design/server/README.md`
> ("Plan to the DigitalOcean test") asks. **Nothing is created at
> DigitalOcean until the owner approves the estimate and passes
> `--approve`.** Every script runs as a dry run without it. The kit is in
> `deploy/` (`deploy/README.md`). **For someone with only the public
> repository: `docs/REPRODUCE.md`**, the same run step by step, with the
> table its numbers go in.

The test's goals (owner, 2026-11-12): show that Veil **scales on a
realistic agent workload across machines** (many agents, each on a branch
of its own, landing into `main`; per-operation latency may be worse than on
one machine, which is accepted), that throughput rises with servers, and
that **other people can reproduce the published numbers**.

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
3. the account's **droplet limit** at least 9 for the full topology (three
   servers, the balancer, three YugabyteDB nodes, two drivers), 4 for the
   default (the default limit is often 3 or 5: Account → request an increase);
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

Options (all in `deploy/do/.env`; `estimate.sh` prices them, `create.sh`
makes them, `destroy.sh` removes them by tag, `deploy/do/test/test.sh`
covers them):

- **`VEIL_DO_HUBS=2` or `3`**: two or three servers (`NAME-hub`,
  `NAME-hub2`, `NAME-hub3`, each a `c-16`) on the one database and the one
  bucket, behind **one address: `NAME-lb`, an HAProxy droplet** (`c-4`,
  §2.1). Servers behind one address are one server to a client:
  `configure.sh` starts the first, then copies its signing identity, upload
  receipt key, grant key and the caches' token (`hub-identity.json`,
  `hub-receipt-key`, `hub-grant-key`, `hub-cache-token`, `docs/HUB.md`
  §13: "servers sharing the data directory accept each other's") to the
  others as root-only files through the run's private state directory, and
  starts them. One certificate names every server and the balancer.
- **`VEIL_DO_YB_NODES=3`** replaces the database droplet with a three-node
  **YugabyteDB** cluster (`yugabytedb/yugabyte:2025.2.8.1-b8`, the
  Apache-2.0 core, `docs/HUB.md` §13.1), one `yugabyted` per `c-8`, three
  copies of every tablet; server *i* connects to node *i* (§2.2). Phase 4's
  gate (`docs/design/server/phase-4-agent-scale.md` §7: 1,000 landings/s
  into one `main` with 10,000 agents) is specified on such a cluster, and
  its landing service (S17) is merged: the `landing` and `failover` gates
  run on it.
- **`VEIL_DO_WITH_CACHE=1`** adds `NAME-cache` (`s-4vcpu-8gb`) running
  `veil-server cache` (the regional cache, `docs/HUB.md` §13.18) in front of
  the servers, for `vl` clients and manual tests. The cache *gate* cannot be
  run against it (BUG-1591, §6), so it is off by default.

**The full topology** for the paid run is `VEIL_DO_HUBS=3 VEIL_DO_YB_NODES=3`:
nine droplets, $2.875 an hour, **$28.00 for the planned 8 hours** with
Spaces (below).

### 2.1 One address in front of several servers: HAProxy on a droplet

The kit's balancer is **HAProxy 3.0 in a container on a `c-4` droplet**
($0.125 an hour, $1.00 for 8 hours), not a DigitalOcean load balancer:

- **The rehearsal runs the same thing.** `deploy/lb/haproxy-cfg.sh` writes
  the one configuration both use: TCP, TLS passed through untouched (each
  server holds the run's certificate), least connections, a health check
  every second; a server that fails two checks is out of rotation and its
  connections are closed, so agents reconnect to the others. A stranger can
  try the whole flow free (§4), and the scaling and failover gates measure
  the same balancer in both places.
- **No per-node connection cap to plan around.** A DigitalOcean load
  balancer is cheaper (about $12 a month per node, under $0.02 an hour),
  but each node has a documented limit on simultaneous connections, of the
  order of the 10,000 agents one gate opens; the number of nodes would
  have to be sized against DigitalOcean's current limits, and what the
  balancer does when they are reached cannot be rehearsed.
- It is one more droplet tagged with the run's name, so `destroy.sh`
  deletes it with the rest; `destroy.sh --check` still looks for any
  DigitalOcean load balancer named after the run, which bills when
  forgotten.

The balancer has 4 dedicated cores for TCP pass-through only; its CPU is in
the gates' `docker stats` samples only if it is added to them (it is not:
watch it in DigitalOcean's graphs, the droplet is created with monitoring).

### 2.2 YugabyteDB on three 16 GB nodes

What `configure.sh` sets up, and why:

- `yugabyted start --advertise_address=<private address>`, the second and
  third with `--join=<the first's>`: three masters and three tablet
  servers, three copies of every tablet.
- `--tserver_flags=ysql_num_shards_per_tserver=1`: each hash-sharded table
  gets one tablet per node (three), led one by each node, so a hot table's
  writes are spread over the cluster. Veil's schema (migrations 1 to 36) is
  many small tables and indexes: a node holds a replica of every tablet,
  about three times the number of tables and indexes in all. The
  rehearsal's count is in §9.1 (122 per node at one tablet per table).
- **The tablet-replica limit lifted on every master**:
  `yugabyted` turns `enforce_tablet_replica_limits` on at each start,
  whatever `--master_flags` says (the same as `scripts/verify-server.sh`
  finds), and with it on, CREATE TABLE fails once a node's replicas reach a
  limit computed from its memory. `configure.sh` runs `yb-ts-cli set_flag
  --force enforce_tablet_replica_limits false` (and raises
  `tablet_replicas_per_gib_limit`) on each master **before the
  migrations**. The flag is lost when a node restarts: run that line again
  (or `configure.sh --approve` again) before any schema change.
- Memory: a `c-8` has 16 GB; `yugabyted` sizes its processes from it. With
  three servers of 64 database connections each spread over the nodes, and
  the drivers' counters, a node serves under 100 YSQL connections, well
  within its default `ysql_max_connections` (300).
- The database is the cluster's own `yugabyte`, user `yugabyte`, no
  password, no TLS: it listens on the VPC's private addresses only, and the
  firewall lets only the run's own droplets in (§11).

**Why not managed PostgreSQL.** When the kit was built, the server's
database driver had no TLS (BUG-1590, fixed since: "TLS to the database",
§3), and DigitalOcean's managed databases accept TLS connections only. The
kit keeps its PostgreSQL container on a droplet in the same VPC: it is
also what the rehearsal and `scripts/bench-server.sh` run, so the test
measures the configuration the project has measured all along, with
superuser access for `pg_stat_statements` and the counters the cost gates
read. A managed `db-s-4vcpu-8gb` ($0.179/h) could now replace the droplet
for the server itself; the kit does not set one up, the gates do not need
it, and `veil-bench`'s own reads of the database's counters are still
built without TLS.

**Cost** (DigitalOcean list prices as published, USD, hourly = monthly/672;
**confirm them with `deploy/do/estimate.sh --live --approve` or
`doctl compute size list` before approving**; the `--live` form only reads
prices):

| Item | $/hour | Planned 8 h | 24 h (teardown forgotten a day) |
|---|---:|---:|---:|
| server `c-16`, each | 0.500 | 4.00 | 12.00 |
| balancer `c-4` (with 2 or 3 servers) | 0.125 | 1.00 | 3.00 |
| db `c-8`, or each of 3 YugabyteDB `c-8` | 0.250 | 2.00 | 6.00 |
| driver1 + driver2, `c-8` | 0.500 | 4.00 | 12.00 |
| Spaces (flat $5/month while any bucket exists) | 0.007 | 5.00 | 5.00 |
| bandwidth (pooled transfer included with the droplets) | 0 | 0 | 0 |

`deploy/do/estimate.sh` prints the configured topology line by line, then
every topology the kit offers (its output, built-in prices, two drivers):

| Topology | $/hour | Planned 8 h + Spaces | A day forgotten | A month forgotten |
|---|---:|---:|---:|---:|
| one server, PostgreSQL (the default) | 1.250 | 15.00 | 35.00 | 845.00 |
| one server, YugabyteDB ×3 | 1.750 | 19.00 | 47.00 | 1,181.00 |
| two servers + balancer, YugabyteDB ×3 | 2.375 | 24.00 | 62.00 | 1,601.00 |
| **three servers + balancer, YugabyteDB ×3 (the full run)** | **2.875** | **28.00** | **74.00** | **1,937.00** |
| three servers + balancer, PostgreSQL | 2.375 | 24.00 | 62.00 | 1,601.00 |
| the full run + the cache | 2.947 | 28.58 | 75.73 | 1,985.38 |

The planned test is about 8 hours of machines: under an hour to create and
configure, about three for the gates (§6, `docs/REPRODUCE.md` §4 times
each), half an hour for logs and teardown, the rest spare. Even a day of
the full topology left running stays under $75; a month forgotten would
be nearly $2,000, which is what `destroy.sh`'s check is for.

## 3. The images

```sh
deploy/docker/build.sh            # veil-server:TAG and veil-bench:TAG; TAG = this commit's id
CARGO_BUILD_JOBS=8 deploy/docker/build.sh   # fewer compile jobs on a small or shared machine
```

One `Dockerfile` (`deploy/docker/Dockerfile`), one build stage
(`rust:1.99.1-bookworm`, the repository's toolchain; `cargo build --locked
--release`), two runtime targets on `debian:12.12-slim`:

- **`veil-server`**: the binary, `ca-certificates` (Spaces over HTTPS) and
  `curl` (the health check). Runs as `veil` (uid 10001), data in the
  `/var/lib/veil` volume, port 8443. **Health check:** HTTPS answers on the
  server's port (`/v1/epochs`; a 4xx is "up", since the route needs a
  grant). The same image runs `veil-server migrate` and `veil-server cache`
  (`VEIL_HEALTH_URL` points the check at the cache's port). **`docker
  stop` sends SIGINT** (`STOPSIGNAL`): the server handles Ctrl-C and stops
  cleanly, while as the container's PID 1 it would ignore SIGTERM and be
  killed at the stop timeout. The failover gate's `stop` relies on it.
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
private CA and one certificate for every server's and the balancer's
public and private addresses and names; `configure.sh` runs it and copies
it, with the CA, to every droplet. Clients pin the CA:
`vl login https://ADDRESS:8443 --ca deploy/do/state/NAME/tls/ca.pem`
(ADDRESS: the balancer's with several servers, else the server's);
`veil-bench … --ca`. The certificate is valid 30 days.

**TLS to the database.** `--database-url` (or `VEIL_DATABASE_URL`) says
whether the server's connections to the database are encrypted, with
PostgreSQL's own `sslmode` parameter (rustls, as the rest of the server):

| The URL ends with | The connection |
|---|---|
| nothing about `sslmode` | is not encrypted, and the server does not try TLS. For a database on the same machine or a private network (the kit's) |
| `?sslmode=require` | is encrypted; the database's certificate is not checked |
| `?sslmode=verify-ca&sslrootcert=/path/ca.pem` | is encrypted, and the certificate must be signed by the CA in that file |
| `?sslmode=verify-full&sslrootcert=/path/ca.pem` | the same, and the certificate must name the host in the URL. The form for a managed database: `sslrootcert` is the CA certificate the provider lets you download |

Without `sslrootcert`, `verify-ca` and `verify-full` accept the public
certificate authorities (Mozilla's list, built in). `PGSSLMODE` and
`PGSSLROOTCERT` in the environment do the same as the two parameters. A
database that accepts only TLS refuses a URL without `sslmode` ("no
pg_hba.conf entry … no encryption"). At present `verify-ca` also checks
the name, as `verify-full` does (BUG-1909): reach the database by a name
its certificate carries. Proven against PostgreSQL 17 with `ssl = on` and
only `hostssl` lines; not yet run against a managed service.

## 4. Local rehearsal

The paid topology on one machine, small, in Docker Compose
(`deploy/compose/docker-compose.yml`): **three YugabyteDB nodes** (`yb1`
to `yb3`; or PostgreSQL 17 with `DB=pg`), MinIO standing in for Spaces,
the migrations, **two servers** (`hub1`, `hub2`, the second given the
first's keys by `hub2-keys`, as `configure.sh` does) on the one database
and bucket, **HAProxy** (`lb`, the same configuration as the paid run's,
re-resolving the servers' names through Docker's DNS) as the one address,
and the load driver (`bench`). The same images as the paid run, the same
pinned third-party images (`deploy/versions.env`), and **the same gates**:
`deploy/gates.sh` is sourced by both `rehearsal.sh` and `bench.sh`, with
small sizes here (seconds, tens of agents). Every container has a memory
limit; with YugabyteDB they add up to 11.5 GB (three nodes of 2.25 GB with
one tablet per table, two servers of 1 GB, the driver 2 GB, MinIO 512 MB,
HAProxy 256 MB).

`rehearsal.sh` builds the images (unless `SKIP_BUILD=1`), brings the stack
up in order (the database, the tablet limit lifted on each master, MinIO,
the migrations, the first server, the keys, the second server, the
balancer), smoke-tests the balancer's HTTPS with the rehearsal CA, runs
every gate including `failover`, writes each gate's results directory as
the paid run does (§6), and tears down the containers, network and
volumes of its own Compose project (`veil-dokit-NAME`) only:

```sh
deploy/compose/rehearsal.sh NAME                       # build, every gate, tear down
SKIP_BUILD=1 TAG=<tag> GATES="failover scaling" deploy/compose/rehearsal.sh NAME
DB=pg deploy/compose/rehearsal.sh NAME                 # PostgreSQL instead of YugabyteDB
KEEP=1 deploy/compose/rehearsal.sh NAME                # leave it running; it prints the `down -v` command
LB_PORT=28443 deploy/compose/rehearsal.sh NAME         # a free host port on a shared machine
```

Results: `deploy/compose/results/<stamp>/<gate>/`, and each container's
log in `deploy/compose/results/<stamp>/`. On the shared development
machine run it as a heavy job (`bash ~/.cache/veil-orch/heavy.sh NAME 12
…`) and never touch the `veil-shared-*` containers. **The rehearsal's
numbers are for the flow only**: one machine plays nine. The rehearsal of
2026-11-12 is in §9.

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
deploy/do/bench.sh --approve api
deploy/do/bench.sh --approve branches      # the cost curve, then the headline (agents on branches merging into main)
deploy/do/bench.sh --approve landing       # 10,000 agents into one main: plain, protected, the mix; 3 and 10 min
deploy/do/bench.sh --approve scaling       # VEIL_DO_HUBS=3: the curves with 1, 2 and 3 servers
deploy/do/bench.sh --approve failover      # VEIL_DO_HUBS>=2: the lease holder stopped during landings
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
nodes, lifting the tablet limit on each, §2.2) on the private addresses,
runs `veil-server migrate` once (BUG-838), starts the first server with
`--restart unless-stopped`, waits for its health check, copies its keys to
the other servers and starts them (§2), starts the balancer, smoke-tests
the one address with the run's CA, and ends with `vl login` instructions. A `vl` on your machine then
works against it:

```sh
vl login https://HUB_IP:8443 --ca deploy/do/state/NAME/tls/ca.pem
```

## 6. The gates, and where the results go

`deploy/do/bench.sh --approve GATE` runs one gate (the commands are in
`deploy/gates.sh`, shared with the rehearsal) and copies its results to
`deploy/results/NAME/<stamp>-GATE/`. Sizes are variables of
`deploy/gates.sh` (defaults below, the paid run's), overridden from the
environment; `STEP_LIMIT` (default 3600 s) bounds each command; extra
`veil-bench` flags go after the gate name; `DRIVER=n` picks the driver of
a one-driver gate. The tool's addresses are the private ones: the agents
reach the balancer (or the only server) over the VPC.

| Gate | Runs | What `veil-bench` does | Target (`docs/design/server/*`) |
|---|---|---|---|
| `pull` | driver 1 → the one address | `load --mode pull`, 1 project, 10/100/1,000 agents, `main` moving 20/s | phase 2 §8: 10,000 pulls/s with caches; 5 or fewer database statements per warm pull |
| `land` | driver 1 | `load --mode land`, 1/10/100 projects, 1 and 50 agents, `max` rate | phase 2 §8: 100/s into one `main` (p99 under 500 ms), 4,000/s across projects; 1 database commit per landing |
| `api` | driver 1 | `load --mode api`, commits through `POST …/changes` | `docs/HUB.md` §13.13 (S10): as `land` |
| `branches` | driver 1 | `load --mode branches`, 1/10/100 agents on branches of their own (the cost curve); then **the headline**: 300, 1,000 and 3,000 agents (`HEADLINE_AGENTS`) each on its branch, landing it on `main` through the landing service after every 5th push (`--merge-every 5`), 300 s each, `max` rate | `storage-and-cost.md` §9: 1 commit per push, at most 2 storage writes; the headline has no fixed target: it is the owner's realistic workload, reported as pushes/s, merges/s and latency |
| `landing` | driver 1 | `load --mode landing --people 100`, 10,000 agents into one `main`, 1,000 landings/s offered; `plain`, `--protected` (review rules at 0 approvals), and `--protected --mix` (3 % overlapping, 2 % conflicting changes); 180 s and 600 s each | phase 4 §7 (G4): 1,000 landings/s sustained, p50 150 ms, p99 1 s; at most 1.5 commits per landing |
| `scaling` | both drivers at once → the one address | `pull` (1,000 agents), `branches` (1,000 agents) and `landing` across 100 projects (1,000 agents), 60 s each, with 1, 2 and 3 servers running (the others stopped; the balancer drops them within 2 s) | throughput rises with servers; `scaling.md` (`deploy/scaling-table.py`) sums the drivers and gives each count's ratio to one server's |
| `failover` | driver 1, and the servers | `load --mode landing`, 1,000 agents of 100 people, 300 landings/s offered, 120 s; at 45 s the server holding `main`'s landing lease is stopped (`docker stop`; `FAILOVER_HOW=kill`: SIGKILL) and started again after the checks | phase 4 §7: no ticket lost, at most 2 s of stall; and every change landed exactly once (below) |
| `objects` | the first server's machine, with a server and a cache the tool starts itself (BUG-1591) against the same database and a bucket of its own | `load --mode objects --via server,cache`, 10/100/1,000 fresh thin workspaces | phase 2 §8 and `docs/HUB.md` §13.18: 99 % of objects from the cache's store; the cache under 512 MiB |
| `openscion` | the first server's machine, a server the tool starts itself | `openscion`, 1k and 10k files, 5 runs, Git beside | `docs/OVERVIEW.md` "Speed gates", and beating Git on the same machine |
| `scale` | the first server's machine, a server the tool starts itself | `run --profile 1g` (push, clone, pull, clone one directory, gc) | `docs/design/scale/BASELINE.md`: the 1 GB profile; server peak memory under 1 GB (`storage-and-cost.md` §9) |

The three same-machine gates stop nothing: the serving container keeps
running beside the tool's own server (another port, another data
directory, the same database, a bucket of its own), as
`scripts/bench-server.sh` does locally. Run them while no driver gate runs.

**Not in the kit:** the PR speed gate (100,000 PRs in 50 classes) is a
server test, `server_hub` `prs::pr_speed`, which builds its own data in
its own database; there is no `veil-bench prs` to run against a deployed
server, so it stays a local measurement (`docs/design/scale/LOAD.md`, "The
other gates of phase 4 §7"). There is no `veil-bench bisect` yet.

### 6.1 How the lease holder is found, and what "exactly once" rests on

The landing service of a branch runs on the server that holds the
branch's lease (`landing_leases`: a holder name random per server start, a
fencing epoch that rises at every take, an expiry 2 s ahead on the
database's clock, renewed by every batch; `crates/veil-server/src/landing/service.rs`
`take_lease`). The gate asks every server for its counters twice, 3 s
apart (`SIGUSR1` → `stats.json`): the holder is the one whose
`landing_batches` rises. It reads the lease row, stops that server, and
records the moment on the database's clock (`failover-run.txt`). When the
load ends it waits until no ticket of the run is still queued and the
tip of `main` is in the derived graph, then runs `deploy/checks/failover.sql`
(`failover-check.txt`); `deploy/checks/failover-verdict.py` judges it
(`failover-verdict.md`, non-zero exit on a failed check):

- **another server took over**: the lease's holder after differs from the
  one before;
- **none lost**: no ticket of the run is left `queued` or `merging`;
  every change of every `landed` ticket has its landing record
  (`landings`); every recorded landing is on `main`'s first-parent line
  (walked from the branch's tip through `graph.parents`);
- **none twice**: no change id appears twice on that line; no landed
  snapshot is recorded for two changes; no snapshot on the line after the
  first landing lacks a ticket; and the line's length is the set-up
  snapshots plus the landed changes, exactly;
- **the pause**: the longest gap between landings (their `done_at`) after
  the stop, against the target of 2 s and the longest gap in the 30 s
  before.

The database is the authority here because the benchmark tool does not
log which change each of its landings was: it counts them. Its count over
the measured window must not exceed the database's (it is lower by the
warm-up's landings and by **answers lost with the stopped server**: the
ticket was accepted and landed, but the agent saw a broken connection).
Telling those apart change by change needs the tool to write each landed
snapshot id (the `landed` answer of `POST …/land`) and each submit that
ended in an error to a file; then "every change the tool saw land is on
`main` once" can be checked from both sides. That is a change to
`crates/veil-bench/src/load.rs` (`land_service`), not made by the kit.

### 6.2 The results directory

Beside every gate's results, `bench.sh` (and the rehearsal) writes what
made them; `docs/REPRODUCE.md` §6 says how to read each file:

| File | What |
|---|---|
| `run.txt` | gate, date, `commit=` (the checkout's full id), `image_tag=`, the agents' address, the number of servers, every size setting of `deploy/gates.sh`, extra flags |
| `topology.env` | the topology from `deploy/do/.env` without a secret (`lib.sh` `topology`: a fixed list of names, so a new secret can never leak into it) and the pinned image references |
| `images.txt` | the ids of the images built here, of the ones each server and driver has, the containers running, and the pinned third-party digests |
| `commands.txt` | every `veil-bench` command line and the machine it ran on |
| `<label>.json`, `<label>.md`, `<label>.log` | the tool's raw results, its tables, its output; `@<n>` in a label is driver *n* |
| `hub<N>-stats.json`, `hub<N>-docker-stats.log` | each server's request-path counters at the end of the gate, and its `docker stats` every 5 s |
| `scaling.md`; `failover-verdict.md`, `failover-*.txt` | the scaling table; the failover verdict and the records behind it |

## 7. Logs and metrics

```sh
deploy/do/logs.sh --approve       # -> deploy/results/NAME/logs-<stamp>/<droplet>/
```

Per droplet: every container's log (`containers.log`), `docker ps`,
memory, disk, uptime and the kernel log's tail (`system.txt`); on each
server its counters (`server-stats.json`) and the `docker stats` samples
of every gate (`metrics/`); on the database droplet the 30 most-called
statements from `pg_stat_statements`; on each YugabyteDB node the
cluster's servers and the tablets it holds (`yb.txt`). DigitalOcean's own graphs (CPU,
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

## 9. Rehearsal results

### 9.1 The rehearsal of 2026-11-12 (the multi-machine topology)

`deploy/compose/rehearsal.sh` on the development machine (32 cores, 30 GB,
Docker 28; shared with other work), `dokit2`, images `veil-server:dokit2`
and `veil-bench:dokit2`, three YugabyteDB nodes (one tablet per table,
2.25 GB each), two servers behind HAProxy, one driver, every gate at the
rehearsal's sizes (`rehearsal.sh`: seconds, tens of agents). **These
numbers are for the flow only:** one machine played nine, so they measure
nothing about Veil across machines, and the scaling ratios below say
nothing about scaling (both servers shared the machine and the database).

| Step | Outcome | What it showed |
|---|---|---|
| bring-up | **ok**, 59 s | three YugabyteDB nodes joined one at a time (two joining at once failed: one was killed mid-start, so both `rehearsal.sh` and `configure.sh` join them one by one); three copies of every tablet (`numReplicas: 3`); 122 tablets on each node after migrations 1 to 36 with one tablet per table (so about 370 per node with the paid run's three per table); both servers healthy; HTTPS through the balancer with the run's CA |
| `pull` | ok | 6,226 and 13,574 pulls/s (10 and 50 agents); 1.1 and 1.4 statements per pull |
| `land`, `api` | ok | 40 and 262 landings/s (1 and 10 agents); API 25 and 369/s |
| `branches` | ok | the cost curve 49 and 252 pushes/s; **the headline** with 10 and 30 agents merging every 5th push: 81 and 160 pushes/s, 161 merges into `main` in 10 s with 10 agents (`branch_merges`), no errors |
| `landing` | ok | 40 agents of 4 people, 50/s offered, 10 s: plain 49.5/s, protected 50.2/s, with the mix 50.1/s (p99 386 to 424 ms) |
| `scaling` | ok (flow) | `scaling.md` made from both server counts: pulls 10,099 → 11,848/s, pushes 333 → 288/s, landings across 4 projects 213 → 177/s with 1 → 2 servers |
| `failover` | **exactly once: pass; pause: miss** | stopped (`docker stop`) and, in a second run, killed: the lease moved to the other server (epoch 1 → 2); no ticket left queued; every landed change recorded and on `main`'s line once; `main` = 2 set-up snapshots + 1,622 landed changes, exactly; the tool's 1,582 (1,578) landings ≤ the database's 1,622, with 0 (2) errors. **Longest pause after the stop: 2,413 ms (stop), 2,358 ms (kill)**, against 368 to 402 ms before and a target of 2 s: BUG-1970 |
| `objects` | ok | 1,183 reads/s through the server, 2,114 through the cache |
| `openscion` | ok (1,000 files, 1 run) | import 96 ms (Git 132), clone 226 (173), commit one file 20 (35), clone one directory 59 (62) |
| `scale` (`tiny`) | ok | initial push 2.5 s, server 19 → 71 MiB; thin clone 0.28 s |
| teardown | **ok** | `nothing of veil-dokit-r1 remains (containers, volumes, networks)` |

Found by this rehearsal: the failover pause (**BUG-1970**); and three
things in the kit, fixed in it: two YugabyteDB nodes joining at once; the
server ignoring `docker stop` (SIGTERM, as PID 1) until killed, fixed by
the image's `STOPSIGNAL SIGINT`; and the failover check counting the
server's landed-from-itself records as second landings. The tool's
database-commit counter reads 0 on YugabyteDB (it counts PostgreSQL
transaction ids): commits per landing are measured on PostgreSQL only.

### 9.2 The rehearsal of 2026-11-09 (one server, PostgreSQL)

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

**The commit-count misses were not the kit's.** The same numbers came back
without the regional cache, and `scripts/bench-server.sh load` on
`integration` itself gave 9.4 (1 agent), 7.3 (10) and 1.5 (100) commits
per landing on `land`, and the like on `branches` and `api`: **BUG-1593**, a
cost regression since S4 was measured. **It is fixed** (`s24b`: 2.02
commits per landing including the deriver's). As measured locally on
2026-11-12 (`docs/design/server/README.md`, "Gate results"), the landing
service commits 1.41 to 1.45 times per landing with full batches (G4's
target, 1.5: met), while a push still costs 1.18 to 2.40 commits when
pushes come at once (G2's target, 1: missed, **BUG-1946**, open). The paid
run reports both, per gate, in `db_commits_per_op`.

Found and filed by the rehearsal:

- **BUG-1590** (`docs/BUGS.md`, fixed since): the server could not use a
  database that requires TLS, which ruled out managed PostgreSQL (§2).
- **BUG-1591**: `veil-bench load --via cache` cannot measure a running
  cache, so the cache gate runs on the hub in its same-machine form (§6).
- **BUG-1592** (fixed since): the cache advertised HTTP/2 but serves
  HTTP/1 only; HTTP/2 clients (curl, by default) got a broken stream. It
  offers only HTTP/1.1 now. The health check and the smoke tests still pass
  `--http1.1`, which an image from before the fix needs; `vl` and
  `veil-bench` are HTTP/1.1 and were unaffected.
- **BUG-1593** (fixed since): 9 to 13 database commits per landing on
  `integration` (gate 1).

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
`destroy.sh` deletes by tag and its check fails while anything is left (a
load balancer, a reserved IP, a volume or a bucket included). For **the
full topology** (three servers, the balancer, three YugabyteDB nodes) they
check that `create.sh` makes all nine droplets at their sizes; that
`estimate.sh` prices it and every other topology, a day and a month
forgotten included; that `configure.sh` joins the YugabyteDB nodes, lifts
the tablet limit on each, migrates once, starts each server on its own
node, passes the first server's keys through private files and configures
HAProxy for the servers' private addresses; that every gate's dry run
succeeds, records its settings and runs where it belongs (the drivers'
gates against the balancer's private address, `scaling` from both
drivers, `failover` stopping the lease holder and reading its checks
through stdin); and that no secret appears in any of it or in the
topology recorded beside results. `configure.sh`, `bench.sh` and `logs.sh`
over real SSH are exercised only by the rehearsal's equivalent Docker
commands (§4) and by the DigitalOcean run.

## 11. Risks and open items

- **Prices.** The built-in table is DigitalOcean's list as published;
  confirm with `estimate.sh --live --approve` before approving. Sizes may be
  unavailable in a region (`doctl compute size list` shows `Available`); the
  estimate and `create.sh` take the sizes from `.env`.
- **Droplet limit.** New accounts often may not create 4 or 9 droplets at
  once; `create.sh` then fails on the first refused droplet and leaves the
  earlier ones running: `destroy.sh --approve` removes them by tag.
- **The database is not encrypted in transit in the kit**: its URL has no
  `sslmode`, and the database is on the VPC's private network only, behind
  the firewall, one hop from the servers. The server can use TLS to a
  database (BUG-1590, fixed; §3), which the kit's PostgreSQL container and
  YugabyteDB nodes do not offer. YugabyteDB's `yugabyte` user has no
  password in the kit, for the same reason.
- **BUG-1591**: the cache gate runs on the hub in the same-machine form,
  not across the network to a cache droplet.
- **Benchmarks that do not exist**: `veil-bench prs` (the PR gate is a
  server test) and `veil-bench bisect` (§6). The tool does not log which
  change each landing was, so "exactly once" under failover rests on the
  database's records (§6.1).
- **Known misses before the run** (local, 2026-11-12,
  `docs/design/server/README.md`): G4's landing rate (BUG-1940 to
  BUG-1942: the 10-minute and protected runs fall well short of 1,000/s),
  G2's commits per push (BUG-1946) and landings across projects
  (BUG-1948). The paid run measures them across machines; it is not
  expected to pass them. BUG-1593 (commits per landing) is fixed.
- **YugabyteDB restarts.** A node that restarts turns the tablet-replica
  limit on again (§2.2); nothing in the gates creates tables, but a
  migration would fail on it.
- **The balancer** is one droplet: if it fails, the run stops. Its CPU is
  in DigitalOcean's graphs, not in the gates' samples.
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
