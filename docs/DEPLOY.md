# Deploying Veil for the DigitalOcean test

> **Status: one paid run made, scaled down; no speed result from it**
> (2026-11-14, §9.0: four-vCPU droplets, limited by its shared-CPU storage
> droplet; the kit fixed since). Kit ready 2026-11-12; objects on MinIO and
> the `spaces` gate, 2026-11-13. This runbook takes the
> server as built (`docs/HUB.md` §13, phases 1 to 4) through one paid test
> on DigitalOcean, budget under $100, as `docs/design/server/README.md`
> ("Plan to the DigitalOcean test") asks. **Nothing is created at
> DigitalOcean until the owner approves the estimate and passes
> `--approve`.** Every script runs as a dry run without it. The kit is in
> `deploy/` (`deploy/README.md`). **For someone with only the public
> repository: `docs/REPRODUCE.md`**, the same run step by step, with the
> table its numbers go in.
>
> **Google Cloud (2026-11-14):** the same kit for Google Cloud, hybrid Spot,
> is `deploy/gcp`, §12 (kit ready, nothing rented).
>
> **Objects (owner, 2026-11-13; BUG-2290):** one Spaces bucket allows about
> 800 requests a second and the many-branch headline needs about 4,900, so
> **the speed runs keep objects in MinIO on a storage droplet of the run**
> (the S3-compatible server the rehearsal uses, pinned in
> `deploy/versions.env`; `VEIL_DO_OBJECTS=minio`, the default), and **one
> short, low-rate gate, `spaces`, runs on a real Spaces bucket** to show
> Veil works there (§2.3).

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
| `doctl` 1.186.0 | DigitalOcean's CLI; every create and delete goes through it. The kit was run with 1.186.0; 2.x is untested (`docs/REPRODUCE.md`) | `doctl version` (not needed for dry runs or the rehearsal) |
| `ssh`, `scp`, `zstd`, `openssl`, `curl` 7.75+ | configuring the droplets, the certificates, the Spaces check (`curl --aws-sigv4`) | |
| `awscli` (optional) | `destroy.sh` empties and deletes the Spaces bucket with it; without it the bucket is deleted in the control panel | `aws --version` |
| `bc`, `python3` | the estimate; the kit's tests | |

At DigitalOcean (the owner, once; nothing the scripts do):

1. an account with a payment method, and a **personal access token** with
   read and write scope (API → Tokens);
2. a **Spaces access key** pair (API → Spaces Keys);
3. the account's **droplet limit** at least 10 for the full topology (three
   servers, the balancer, three YugabyteDB nodes, two drivers, the storage
   droplet), 5 for the default (the default limit is often 3 or 5: Account
   → request an increase), and **the sizes allowed**: CPU-Optimized 8- and
   16-vCPU droplets (`c-8`, `c-16`, `c2-16vcpu-32gb`) in one region that
   has Spaces. A new account may be held to 4 vCPUs a droplet (the first
   paid run's was, §9.0); `docs/REPRODUCE.md` says how to check;
4. the operator's **public IPv4** (`curl -4 -s https://ifconfig.me`): SSH
   and the server's port are open to it only.

Then:

```sh
cp deploy/do/.env.example deploy/do/.env && chmod 600 deploy/do/.env
$EDITOR deploy/do/.env     # token, Spaces keys, a database password, your IP, the topology
```

`deploy/do/.env` is ignored by git. The scripts also read these variables
from the environment, which wins over the file.

**Connect each server straight to the database.** Put no transaction-pooling
proxy (pgbouncer in transaction mode, or YugabyteDB's connection manager)
between them: the server holds session-level advisory locks (its landing
leases' crash detection, HUB §13.32 item 13; migrations; the deriver), and
under transaction pooling another client's statement can run on the
connection that holds one. The kit connects directly.

## 2. Topology and cost

**Default topology** (`deploy/do/.env.example`; `deploy/do/estimate.sh`
prints it priced):

| Droplet | Size | Runs | Why |
|---|---|---|---|
| `NAME-hub` | `c-16` (16 dedicated vCPUs, 32 GB) | `veil-server` in its container, port 8443; also hosts the gates that start a server of their own (§6) | the load curves saturate the server's CPU before anything else (`docs/design/scale/LOAD.md`); a dedicated-CPU size gives steady numbers |
| `NAME-db` | `c-8` (8 vCPUs, 16 GB, 200 GB NVMe) | PostgreSQL 17 in a container (`postgres:17-alpine`, `pg_stat_statements`, `max_connections=1500`), on the VPC's private address only | see "Why not managed PostgreSQL" |
| `NAME-driver1`, `-driver2` | `c-8` each | `veil-bench` in its container: 10,000 simulated agents fit in one process on 8 cores | two, so one can drive pulls while the other drives landings |
| `NAME-minio` | `c2-16vcpu-32gb` (16 dedicated vCPUs, 32 GB, 400 GB local SSD) | MinIO (`deploy/versions.env`), the servers' object store, on the VPC's private address only, TLS with the run's CA; bucket `NAME-objects-…`, created by the server itself at first start | §2.3: the headline's 4,900 requests a second are six times what a Spaces bucket allows |
| Spaces bucket `NAME-objects-…-spaces` | 250 GiB, 1 TiB out | the `spaces` gate's object store (S3 API, `https://REGION.digitaloceanspaces.com`, path-style), created by that gate's own server | to show Veil works on Spaces (§2.3) |

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
- **`VEIL_DO_OBJECTS=spaces`** drops the storage droplet: every server
  keeps its objects in the Spaces bucket `NAME-objects-…`, as the kit did
  before 2026-11-13. It holds only runs that stay under the bucket's
  request rate (§2.3).
- **`VEIL_DO_OBJECTS_VOLUME_GB=N`** (at least 250) keeps MinIO's data on a
  block-storage volume `NAME-minio-data` of N GB, attached to the storage
  droplet when it is created, instead of its local disk: for a
  `VEIL_DO_SIZE_OBJECTS` with less disk than the gates need. `destroy.sh`
  deletes it.
- **`VEIL_DO_WITH_CACHE=1`** adds `NAME-cache` (`s-4vcpu-8gb`) running
  `veil-server cache` (the regional cache, `docs/HUB.md` §13.18) in front of
  the servers, for `vl` clients and manual tests. The kit's cache *gate*
  does not run against it yet (§6: `veil-bench` can since BUG-1591's fix,
  `--cache-url`; `gates.sh` still starts a cache of its own), so it is off
  by default.

**The full topology** for the paid run is `VEIL_DO_HUBS=3 VEIL_DO_YB_NODES=3`
(objects on MinIO, the default): ten droplets, $3.447 an hour, **$32.58
for the planned 8 hours** with Spaces' flat fee for the `spaces` gate (below).

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
- **Veil's database `veil`, colocated by default** (`VEIL_DO_YB_LAYOUT`,
  `VEIL_GCP_YB_LAYOUT`; §12.10): `CREATE DATABASE veil WITH COLOCATION =
  true`, made once by `configure.sh`, which checks the layout of one it
  finds (`yb_is_database_colocated()`) and refuses the other. Every table
  of a colocated database is in one tablet (one leader, three copies).
  With `YB_LAYOUT=hash` the tables are hash-sharded:
  `--tserver_flags=ysql_num_shards_per_tserver=YB_TABLETS` (default 1)
  gives each table that many tablets per node, led in turn by each node.
  Veil's schema (migrations 1 to 40) is
  many small tables and indexes: a node holds a replica of every tablet,
  about three times the number of tables and indexes in all. The
  rehearsal's count is in §9.2 (124 on `yb1` at one tablet per table;
  122 per node with migrations 1 to 36, §9.3).
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
- The database is `veil` (not the cluster's default `yugabyte`), user `yugabyte`, no
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
| MinIO storage droplet `c2-16vcpu-32gb` (`VEIL_DO_OBJECTS=minio`) | 0.572 | 4.58 | 13.73 |
| a volume for MinIO instead of the local disk (optional, $0.10 a GB a month; 300 GB) | 0.045 | 0.36 | 1.07 |
| Spaces (flat $5/month while any bucket exists: the `spaces` gate's) | 0.007 | 5.00 | 5.00 |
| bandwidth (pooled transfer included with the droplets) | 0 | 0 | 0 |

`deploy/do/estimate.sh` prints the configured topology line by line, then
every topology the kit offers (its output, built-in prices, two drivers):

| Topology | $/hour | Planned 8 h + Spaces | A day forgotten | A month forgotten |
|---|---:|---:|---:|---:|
| one server, PostgreSQL, MinIO (the default) | 1.822 | 19.58 | 48.73 | 1,229.38 |
| one server, YugabyteDB ×3, MinIO | 2.322 | 23.58 | 60.73 | 1,565.38 |
| two servers + balancer, YugabyteDB ×3, MinIO | 2.947 | 28.58 | 75.73 | 1,985.38 |
| **three servers + balancer, YugabyteDB ×3, MinIO (the full run)** | **3.447** | **32.58** | **87.73** | **2,321.38** |
| the full run with objects on Spaces (`VEIL_DO_OBJECTS=spaces`, no MinIO) | 2.875 | 28.00 | 74.00 | 1,937.00 |
| three servers + balancer, PostgreSQL, MinIO | 2.947 | 28.58 | 75.73 | 1,985.38 |
| the full run + the cache | 3.519 | 33.15 | 89.46 | 2,369.77 |

The planned test is about 8 hours of machines: under an hour to create and
configure, about three for the gates (§6, `docs/REPRODUCE.md` §4 times
each), half an hour for logs and teardown, the rest spare. Even a day of
the full topology left running stays under $90; a month forgotten would
be over $2,300, which is what `destroy.sh`'s check is for.

### 2.3 Objects: MinIO on a storage droplet, and the `spaces` gate

**The decision (owner, 2026-11-13; BUG-2290).** The many-branch headline
makes about **8.6 storage reads and 11.0 storage writes a push**
(`docs/design/scale/LOAD.md`, "Storage reads in the many-branch headline",
300 agents for 10 minutes): at 250 pushes a second, about 2,150 reads and
2,750 writes, **4,900 requests a second**. One DigitalOcean Spaces bucket
allows 800 operations a second, all kinds together, and answers more with
`503 Slow Down` ([Spaces Limits](https://docs.digitalocean.com/products/spaces/details/limits/));
the server retries a `503` for at most 10 s, then the request fails. A
speed run on Spaces would measure Spaces' throttling. So:

- **the speed runs keep objects in MinIO** on a storage droplet of the run
  (`VEIL_DO_OBJECTS=minio`, the default): the S3-compatible server the
  rehearsal runs, pinned by digest in `deploy/versions.env`;
- **the `spaces` gate** runs the many-branch shape for 5 minutes on a real
  Spaces bucket, at a rate under its limit, to show Veil works there
  (correctness and flow, not speed).

**The storage droplet, `NAME-minio`** (`VEIL_DO_SIZE_OBJECTS`, default
`c2-16vcpu-32gb`: 16 dedicated vCPUs, 32 GB, 400 GB of local SSD). Sized
from the headline's rate and from the bytes the gates write:

| What | Estimate | From |
|---|---:|---|
| requests a second, headline | 2,150 reads + 2,750 writes | 8.6 + 11.0 a push × 250 pushes/s |
| bytes written a second, headline | about 11 MiB | 45.6 KiB stored a push (LOAD.md: merges copy each object about once a size class) |
| operations that store, every gate at its offered or `max` rate | at most about 4.4 million | headline 3 × 300 s × 250/s; landing 3 variants × 780 s × 1,000/s; land and api 12 runs × 20 s × 4,000/s; scaling 3 × 60 s × 4,500/s; failover 120 s × 300/s |
| bytes written over the gates | **at most about 190 GiB**, plus the `scale` gate's 1 GB profile | 4.4 million × 45.6 KiB, as if no merged-away pack were ever deleted |
| bytes kept | about 45 GiB | 10.7 KiB a push stay listed after merging (1.64 GB after 150,000 pushes, LOAD.md) |

**Its CPUs must be dedicated** (BUG-2431): on the first paid run (§9.0)
a shared-CPU `s-4vcpu-8gb` ran MinIO at its limit from the many-branch
headline on and answered hundreds of thousands of `429`s, so
`estimate.sh` and `create.sh` refuse a Basic (`s-*`) `VEIL_DO_SIZE_OBJECTS`
with `VEIL_DO_OBJECTS=minio`. So the droplet needs about 200 GiB free at most, written at tens of MiB a
second in thousands of small synced writes: **its own local SSD**
(`configure.sh` refuses to start MinIO with under 250 GB free, the
`OBJECTS_NEED_GB` of `deploy/do/lib.sh`), not a block-storage volume, which
is network storage with per-volume limits on operations a second. 16
dedicated vCPUs are the servers' size class: MinIO verifies TLS and
signatures on every request, and the landing and scaling gates may ask
more of it than the headline. Its CPU, memory and disk are sampled beside
every gate (`minio-docker-stats.log`, §6.2) and by `logs.sh`, so a run
bound by the store shows it. A size with less disk takes a volume
(`VEIL_DO_OBJECTS_VOLUME_GB=N`, at least 250): `create.sh` makes it
(`NAME-minio-data`, ext4, tagged `NAME`) and attaches it when the droplet
is created, `configure.sh` mounts it at `/mnt/minio-data`, `destroy.sh`
deletes it (by the id it saved and by name, retrying while it detaches),
and its check counts every volume named `NAME*`.

How `configure.sh` runs it:

- **Started directly, TLS from the run's CA:** the container runs the
  MinIO server binary itself (`MINIO_BIN` and `MINIO_ARGS` in
  `deploy/versions.env`, the rehearsal's too), never the image's
  start-up script, whose setup step looped on the first paid run
  (BUG-2432, §9.0); `configure.sh` checks that it answers over TLS and has
  not restarted 15 s later. The run's one certificate also names the
  storage droplet (its private address and name); MinIO serves it from
  `/certs` (`public.crt`, `private.key`). The servers trust the CA
  through `VEIL_S3_CA=/tls/ca.pem` in their `hub.env` (the server adds the
  PEM certificates of the file `VEIL_S3_CA` names to the public roots for
  its S3 client; servers the benchmark tool starts inherit it).
- **Credentials made for the run:** `deploy/do/state/NAME/minio.env` (mode
  0600: a random user and a 48-hex-digit password), copied to the droplet
  as `/etc/veil/minio.env` (root-only) and read by Docker's `--env-file`;
  the servers get them in their `hub.env`. Never on a command line, in
  user-data, in an image, in git or in a result (`deploy/do/test/test.sh`
  checks every command line, output and results file for them).
- **Reached only by the run's droplets:** MinIO listens on the droplet's
  private address only (`-p PRIVATE:9000:9000`), and the run's one cloud
  firewall lets in only droplets tagged `NAME` (and the operator, on 22,
  8443 and 8444 only).
- Its objects go with the droplet (or the volume) at teardown; there is
  nothing to empty.

With `VEIL_DO_OBJECTS=spaces` none of this exists and the servers use the
Spaces bucket, as before.

**The `spaces` gate.** `bench.sh --approve spaces` starts a server of its
own on the first server's machine (as `objects`, `openscion` and `scale`
do), with its objects in the Spaces bucket `BUCKET-spaces` (created by
that server; `destroy.sh` empties and deletes it with the others) and the
Spaces keys from `/etc/veil/spaces.env` (root-only, on the first server
only), and drives the many-branch shape at it: **100 agents, each on its
branch, merging every 5th push, 20 pushes a second, for 5 minutes**
(`SPACES_AGENTS`, `SPACES_RATE`, `SPACES_DURATION`). The rate: 8.6 + 11.0 =
19.6 requests a push, so the bucket's 800 a second is reached at 40
pushes a second; 20 (about 390 requests a second) leaves half of it for
the setup's bursts, the background merges and the deriver. The server
counts every `503 Slow Down` (and `429`) answer the store gives, each try,
and every request still failing when its 10 s of retries run out
(`stats.json`'s `s3_slow_down` and `s3_gave_up`); the tool records both
in `spaces.json`, and `deploy/checks/spaces-verdict.py` writes
`spaces-verdict.md`. It **fails** on an error an agent saw, on any request
given up, on no push or no merge into `main`, or on missing counters; the
`503` answers, the rate held and the requests a second against the 800
are recorded, not judged.

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

Nothing secret is baked in: the object store's keys and the database URL
come from the environment (`VEIL_S3_ACCESS_KEY`, `VEIL_S3_SECRET_KEY`,
`VEIL_DATABASE_URL`; `VEIL_S3_CA` names a CA for a store with a
certificate of its own, §2.3) and the TLS key from a mounted file. The images are
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
pg_hba.conf entry … no encryption"). `verify-ca` checks the CA and not
the name (BUG-1909, fixed: the workspace patches `sqlx-core` 0.8.6 for it),
so a database reached by an address its certificate does not carry is
accepted when its CA is the one given. Proven against PostgreSQL 17 with `ssl = on` and
only `hostssl` lines; not yet run against a managed service.

**Object layout (`--object-layout`, `VEIL_OBJECT_LAYOUT`).** `--object-layout packs|objects` (or `VEIL_OBJECT_LAYOUT`, default `packs`; `docs/HUB.md` §13.42, `docs/design/server/object-layout.md`) chooses whether kept objects are stored in packs or one object per key (`p/<project>/<2 hex>/<62 hex>`). Every read checks both layouts, so switching the flag and restarting needs no migration and converts nothing; `stats.json` records `object_layout`, `storage_deletes`, `storage_lists`, `objects_kept` and `uploads`. In `objects`, a push makes roughly three times as many `PUT`/`DELETE` requests to the object store as in `packs`, so a project that suddenly turns busy meets S3's or Cloud Storage's per-prefix warm-up (~3,500 writes/s before automatic prefix splitting) about three times sooner—and DigitalOcean Spaces' 800 requests/s bucket limit (§2.3) proportionately sooner too. Watch `s3_slow_down` (`503 Slow Down` / `429` retries) and `s3_gave_up` in `stats.json`.

## 4. Local rehearsal

The paid topology on one machine, small, in Docker Compose
(`deploy/compose/docker-compose.yml`): **three YugabyteDB nodes** (`yb1`
to `yb3`; or PostgreSQL 17 with `DB=pg`), MinIO (over TLS with the
rehearsal's CA, as on the paid run's storage droplet, §2.3),
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
every gate including `failover` and `spaces` (against the MinIO there, as
no Spaces bucket is at hand: its flow and its verdict, not Spaces),
writes each gate's results directory as the paid run does (§6), and
tears down the containers, network and volumes of its own Compose
project (`veil-dokit-NAME`) only:

```sh
deploy/compose/rehearsal.sh NAME                       # build, every gate, tear down
SKIP_BUILD=1 TAG=<tag> GATES="failover scaling" deploy/compose/rehearsal.sh NAME
DB=pg deploy/compose/rehearsal.sh NAME                 # PostgreSQL instead of YugabyteDB
KEEP=1 deploy/compose/rehearsal.sh NAME                # leave it running; it prints the `down -v` command
LB_PORT=28443 deploy/compose/rehearsal.sh NAME         # a free host port on a shared machine
```

Results: `deploy/compose/results/<stamp>/<gate>/`, and each container's
log in `deploy/compose/results/<stamp>/`. On a machine others use, run
it alone (it needs 11.5 GB), give it its own `NAME` and `LB_PORT`, and
leave other Compose projects alone: its teardown removes only its own
project's containers, network and volumes. **The rehearsal's
numbers are for the flow only**: one machine plays ten. The rehearsals of
2026-11-13 and 2026-11-12 are in §9.

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

# 2. create: ssh key, firewall, droplets (tagged NAME; the MinIO storage droplet included), state file
deploy/do/create.sh                        # dry run: the plan and every command
deploy/do/create.sh --approve              # <- the owner's approval; the first thing that bills

# 3. configure: wait for cloud-init, certificate, ship images, database, MinIO, migrations, server, smoke test
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
deploy/do/bench.sh --approve spaces        # 5 minutes on a real Spaces bucket at 20 pushes/s (§2.3)

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
3. with `VEIL_DO_OBJECTS_VOLUME_GB`, the storage droplet's volume
   `NAME-minio-data` (§2.3);
4. the droplets from `deploy/do/cloud-init/docker.yaml` (Ubuntu 24.04,
   Docker and zstd from Ubuntu, file-descriptor and port-range limits
   raised; **no secrets in user-data**, which any process on a droplet can
   read from the metadata service), the storage droplet `NAME-minio`
   among them;
5. `deploy/do/state/NAME/state.env` (mode 0600): ids, public and private
   addresses, the bucket's name.

`configure.sh --approve` then copies secrets as root-only files
(`/etc/veil/*.env`, `/etc/veil/tls/`), starts PostgreSQL (or the YugabyteDB
nodes, lifting the tablet limit on each, §2.2) on the private addresses,
starts MinIO on the storage droplet (TLS with the run's certificate,
credentials made for the run, §2.3), runs `veil-server migrate` once (BUG-838), starts the first server with
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
| `onerepo` | driver 1 | `load --mode branches`, **one busy repository**: 1,000 and 5,000 agents (`ONEREPO_AGENTS`) each pushing to a branch of its own in one project, as fast as answered, 120 s each (`ONEREPO_DURATION`); the database machines are sampled with the servers (`db<N>-docker-stats.log`) | 7,200 pushes a second (`ONEREPO_TARGET`), the figure of GitHub's internal test (7,200 pushes a second, 5,000 agents on one repository); `onerepo.md` (`deploy/onerepo-table.py`): pushes a second and their share of the target, statements, writes and commits per push, the servers' and the database's CPU per push (their samples inside the measured window), the driver's own cores, and the cores the target would need at those costs (§12.10) |
| `landing` | driver 1 | `load --mode landing --people 100`, 10,000 agents into one `main`, 1,000 landings/s offered; `plain`, `--protected` (review rules at 0 approvals), and `--protected --mix` (3 % overlapping, 2 % conflicting changes); 180 s and 600 s each | phase 4 §7 (G4): 1,000 landings/s sustained, p50 150 ms, p99 1 s; at most 1.5 commits per landing |
| `agents` | driver 1 | `load --mode agents`, 1,000 and 10,000 agents (`AGENTS_COUNTS`), 180 s each: coding agents at their pace, a think time between operations (120 s of agent time on average, exponential, compressed 20 times: `AGENTS_THINK`, `AGENTS_TIME_SCALE`), 3 subagents forked once a cycle on branches off the agent's, 3 pushes each, merged into its branch through the landing service (`onto` it, which deletes their branches with the merge: `docs/HUB.md` §13.41), and its branch landed on `main` every 20 pushes (about every 45 minutes of agent time) | no fixed target: reported per kind of operation (push, subagent merge, landing on `main`, pull or workspace start) as rate, uncompressed rate, p50/p99, errors and answers to come back, with commits per push and per landing |
| `scaling` | both drivers at once → the one address | `pull` (1,000 agents), `branches` (1,000 agents) and `landing` across 100 projects (1,000 agents), 60 s each, with 1, 2 and 3 servers running (the others stopped; the balancer drops them within 2 s) | throughput rises with servers; `scaling.md` (`deploy/scaling-table.py`) sums the drivers and gives each count's ratio to one server's |
| `failover` | driver 1, and the servers | `load --mode landing`, 1,000 agents of 100 people, 300 landings/s offered, 120 s; at 45 s the server holding `main`'s landing lease is stopped (`docker stop`; `FAILOVER_HOW=kill`: SIGKILL) and started again after the checks | phase 4 §7: no ticket lost, at most 2 s of stall; and every change landed exactly once (below) |
| `objects` | the first server's machine, with a server and a cache the tool starts itself (BUG-1591) against the same database and a bucket of its own | `load --mode objects --via server,cache`, 10/100/1,000 fresh thin workspaces | phase 2 §8 and `docs/HUB.md` §13.18: 99 % of objects from the cache's store; the cache under 512 MiB |
| `openscion` | the first server's machine, a server the tool starts itself | `openscion`, 1k and 10k files, 5 runs, Git beside | `docs/OVERVIEW.md` "Speed gates", and beating Git on the same machine |
| `scale` | the first server's machine, a server the tool starts itself | `run --profile 1g` (push, clone, pull, clone one directory, gc) | `docs/design/scale/BASELINE.md`: the 1 GB profile; server peak memory under 1 GB (`storage-and-cost.md` §9) |
| `spaces` | the first server's machine, a server the tool starts itself with its objects on a real Spaces bucket (`BUCKET-spaces`, the keys from `/etc/veil/spaces.env`) | `load --mode branches --merge-every 5`, 100 agents, 20 pushes/s, 300 s | §2.3: Veil works on Spaces (no error, no request given up, merges into `main`); the store's `503 Slow Down` answers recorded, not speed (BUG-2290) |

In the MinIO topology the same-machine gates' own servers keep their
objects on the MinIO too (their buckets `BUCKET-objects`, `-openscion`,
`-scale`); the `spaces` gate's on Spaces. The four same-machine gates stop nothing: the serving container keeps
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
(`failover-check.txt`) and dumps `main`'s first-parent line
(`deploy/checks/failover-line.sql`, `failover-line.txt`: each snapshot
from the tip down, its change id and the tickets that landed it);
`deploy/checks/failover-verdict.py` judges them against each other and
against what the agents were told (`failover-verdict.md`, non-zero exit on
a failed check):

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
- **what the agents were told** (`failover.landings.jsonl`, below, against
  `failover-line.txt`): every change an agent was answered `landed` is on
  `main`'s first-parent line exactly once, as the snapshot and under the
  ticket it was told, and no change was answered `landed` twice; every
  change on the line that a ticket landed and no agent was told about is
  explained by a failed submit: by its ticket, when the failure carried
  one (`still queued after the server's wait`), and otherwise by count:
  a submit that got no answer (a broken connection to the stopped server,
  a timeout, an HTTP error from the balancer) can have landed at most one
  change, so the rest may not outnumber the failed submits without a
  ticket. A missing log fails the verdict;
- **the pause**: the longest gap between landings (their `done_at`) after
  the stop, against the target of 2 s and the longest gap in the 30 s
  before. At least one landing must follow the stop: with none there is
  no pause to measure, and a lease that moved proves nothing, so the
  verdict fails.

Tickets answered `conflict` or `rejected` are counted, not judged: the
tool submits such a change again as a new ticket, so a server that
wrongly refused changes after the failover would show only in those
counts (each agent writes a file of its own, so a plain run expects no
conflicts).

The per-change log: `veil-bench load --mode landing` writes, beside its
results (`--out X.json` gives `X.landings.jsonl`), one JSON line for each
landing an agent was answered `landed` (`ticket`, `change`, the `landed`
snapshot ids, `project`, `at_ms`) and one for each submit that failed
(`failed`: the error, and the `ticket` when the server gave one), from the
start of the run, warm-up included. The tool's count over the measured
window must also not exceed the database's (it is lower by the warm-up's
landings and by the answers lost with the stopped server).

What the verdict still can't see: which change a submit without an answer
was. Those landings are accepted by count, not by name: any landed ticket
no agent heard of passes while there are no more of them than failed
submits without a ticket, whether or not they were those submits' own
(a change an agent *was* told about is judged by name either way, so a
lost or doubled one is always caught). Changes the server refused
(`conflict`, `rejected`) are counted only, as above. A change of a stack
other than its first is not matched to its ticket (the tool submits one
change per ticket). A `landed` reply the tool could not read is not in
the log; if it landed, the verdict fails (unexplained), never passes.

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
| `hub<N>-stats.json`, `hub<N>-docker-stats.log` | each server's request-path counters at the end of the gate (`s3_slow_down`, `s3_gave_up`: the object store's `503`/`429` answers and the requests given up), and its `docker stats` every 5 s |
| `minio-docker-stats.log` | the MinIO storage droplet's `docker stats` every 5 s (`VEIL_DO_OBJECTS=minio`) |
| `minio-restarts.txt` | MinIO's restart count before and after the gate (`before=N after=M`); a change fails the gate, whose results are then not valid (BUG-2432; not for `spaces`, whose server uses Spaces) |
| `scaling.md`; `failover-verdict.md`, `failover-*.txt`; `spaces-verdict.md` | the scaling table; the failover verdict and the records behind it; the `spaces` gate's verdict |

## 7. Logs and metrics

```sh
deploy/do/logs.sh --approve       # -> deploy/results/NAME/logs-<stamp>/<droplet>/
```

Per droplet: every container's log (`containers.log`), `docker ps`,
memory, disk, uptime and the kernel log's tail (`system.txt`); on each
server its counters (`server-stats.json`) and the `docker stats` samples
of every gate (`metrics/`); on the database droplet the 30 most-called
statements from `pg_stat_statements`; on each YugabyteDB node the
cluster's servers and the tablets it holds (`yb.txt`); on the storage
droplet the space MinIO's data takes (`minio-disk.txt`). DigitalOcean's own graphs (CPU,
memory, disk, bandwidth per droplet) are in the control panel, since the
droplets are created with monitoring on. For anything live:
`ssh -i deploy/do/state/NAME/id_ed25519 root@IP docker logs -f veil-server`.

## 8. Teardown

```sh
deploy/do/destroy.sh --approve            # droplets by tag, MinIO's volume if any, firewall, ssh key, tag; empties and deletes the Spaces buckets
deploy/do/destroy.sh --check --approve    # nothing left?
```

The check counts droplets tagged `NAME`, firewalls and SSH keys named
`NAME`, block volumes, snapshots and load balancers starting with `NAME`,
reserved IPs in the account (an unassigned one bills $4/month), and asks
Spaces whether each bucket still exists (HTTP 404 means gone): the
servers' (with `VEIL_DO_OBJECTS=spaces`), the same-machine gates' and the
`spaces` gate's (`BUCKET-spaces`). MinIO's objects go with its droplet,
or with its volume, which `destroy.sh` deletes by the id it saved and by
name, retrying for two minutes while it detaches from the deleted droplet. It exits
non-zero while anything is left and removes the state file only when
nothing is. The bucket is emptied and deleted with `aws s3 rb --force`
when `awscli` is installed; otherwise the check names it and it is deleted
in the control panel (Spaces → bucket → Settings → Destroy). With no bucket
left the Spaces subscription ends. Look at Billing the next day: the test
appears as hourly line items.

## 9. Results: the first paid run and the rehearsals

### 9.0 First run on DigitalOcean, 2026-11-14 (four-vCPU machines; limited by its storage droplet)

**No speed number from this run stands.** The light gates (`pull`,
`land`, `api`) passed with no error; from the many-branch headline on, the
run measured its storage droplet, and from the `landing` gate on, nothing
it measured is valid. The results are in `deploy/results/veil-test/`
(git-ignored), one folder per gate and every machine's logs; the numbers
below are read from those files.

**What ran, and why that.** The account allowed no droplet over 4 vCPUs:
`c-8`, `c-16` and `c2-16vcpu-32gb` were refused, and `c-4` was offered
only in ams3, blr1, lon1, nyc1 and sfo2. The owner chose a scaled run in
**ams3**: three servers, the HAProxy balancer, three YugabyteDB nodes and
two drivers, all **`c-4`** (4 dedicated vCPUs, 8 GB); MinIO on a
**`s-4vcpu-8gb`** (4 **shared** vCPUs, 8 GB, its own 160 GB disk),
because a `c-4`'s disk is too small and creating a 250 GiB volume for it
failed with `422 invalid size specified` (BUG-2433, cause unknown).
`VEIL_DO_OBJECTS_NEED_GB` was lowered to fit that disk, and the gates
were sized down: `LANDING_AGENTS=4000`, `HEADLINE_AGENTS=300,1000`, and
from the `landing` gate on `LANDING_DURATIONS=180`;
`VEIL_DO_DB_CONNECTIONS=32`. Images `735dc651` (public `main`); the kit
at `f8ae264e`, then `6174aaa0` (below); `doctl` 1.186.0. Billed from
18:20 to 20:05 UTC: ten droplets at $1.197 an hour at list price (nine
`c-4` at $0.125, the `s-4vcpu-8gb` at $0.072), $2.09 for the 1 h 45 min,
**about $2.2 in all**. Everything was destroyed and the check passed;
the run's Spaces key was deleted.

| Gate (start, UTC) | What the files say | Valid? |
|---|---|---|
| `pull` (18:46) | 10, 100, 1,000 clients: 746, 2,387, 292 pulls/s; p99 93 ms, 299 ms, 5.4 s; **0 errors**. The first attempt (18:42) lost its JSON to a kit bug (below) | as a flow and correctness result; the rates are four-vCPU servers' beside a restarting store, not a speed claim |
| `land` (18:48) | one project: 7.1/s (1 client), 3.1/s (50); 10 projects: 37.7 and 22.7/s; 100 projects, 100 clients: 106 and 110/s; **0 errors** | the same |
| `api` (18:53) | 15.1/s, 45.7/s, 82 and 91/s; 50 clients on one or ten projects: 2.9 and 15.2/s with p99 18 to 21 s; **0 errors** | the same |
| `branches` (18:58) | cost curve, 1, 10, 100 agents: 8.3, 33.0, 26.4 pushes/s, 0 errors. **Headline**, merging every 5th push: 300 agents **16.1 pushes/s**, p99 53 s, **883 errors** (the first: a branch landing told to come back until its deadline), 26,697 told to come back; 1,000 agents (709 finishing) **6.7/s**, p99 78 s, **3,652 errors** (the first: `tips: HTTP 500 internal`), 254,027 told to come back | **no**: bound by the store |
| `landing` (19:16; plain, protected, mix; 4,000 agents of 100 people, 1,000/s offered, 180 s) | **0 landed**: the servers' landing counters did not move; 123,091, 122,015 and 121,974 errors; the per-change logs list 2,483, 2,321 and 1,721 changes "still queued after the server's wait" | **no** |
| `failover` (19:34) | stopped while setting up: `upload: HTTP 500 internal` | **no** |
| `spaces` (19:36; its own server on the first server's machine, objects on a real Spaces bucket in ams3) | **FAIL**: 3,558 pushes, 11.9/s of 20 offered, 686 merges into `main`; **991 errors** (the first: `push: HTTP 500 internal`); 93,461 `503 Slow Down`/429 answers, 15 requests given up; **55.8 reads** and 12.0 writes a push, 804 requests a second against the bucket's 800 | the flow on Spaces is shown; the rate was too high (below) |
| `scaling` (19:43) | stopped during its two-server step when the run was stopped | **no** |

CPU (`docker stats` every 5 s; 400 % is a droplet's four vCPUs): the
servers averaged 11 to 47 % in every gate to the headline and 20 to 24 %
in `landing` (peaks 195 to 268 %), so they were mostly idle; the load
tool used 0.1 to 0.4 cores. **MinIO** averaged 42 to 94 % in `pull`,
`land` and `api`, **176 % (peak 424 %) in `branches`**, 162 % (peak
326 %) in `landing`, and 282 to 286 % in `failover` and `spaces`.

**Why.** Three things, two of them in the storage droplet:

1. **MinIO restarted every 72 seconds for the whole run** (BUG-2432): 63
   restarts from 18:37 to 19:54, the first at idle, before any gate. The
   image's start-up script runs a setup step whose client adds the local
   server as `https://localhost:9000`; the run's certificate names the
   storage droplet's addresses and name, not `localhost` (the
   rehearsal's does, which is why it never showed there). The setup gave
   up after twelve tries ("Failed to add temporary MinIO server"), the
   container exited, and Docker started it again. `configure.sh` waited
   only for `/minio/health/live`, which MinIO answers while the setup
   runs. Each restart refused connections for a moment (each server
   logged `Connection refused` 48 to 53 times); the light gates rode over
   it on the server's 10 s of retries.
2. **Four shared vCPUs were far too few for the store** (BUG-2431). From
   the headline on MinIO ran at its droplet's limit; in the `landing`
   gate it answered `429` to about 495,000 of the three servers' requests
   (their `s3_slow_down` counters), and the servers gave up on 2,550
   requests after 10 s of retries each. Its 15-minute load average was
   634 when the logs were collected (19:55). The landing gate's 4,000
   agents' entries stayed queued, and the servers kept storing for them
   after the gate (their storage counters kept rising through `failover`
   and `spaces`), so the later gates met a store still loaded.
3. **A store given up on answered `500 internal`** (BUG-2430): the 500s
   of `branches`, `failover` and `spaces` (where Spaces' own `503 Slow
   Down` outlasted the retries). Fixed: such a request is answered `503
   busy` with `retry_after_ms`, as other overload is.

The `spaces` gate also showed that its rate was set from too low a read
count: 55.8 reads a push on a fresh project, not the headline's 8.6, so 20
pushes a second made 804 requests a second, the bucket's whole limit.

**Kit bugs found and fixed during the run** (in `6174aaa0`):
`VEIL_DO_OBJECTS_NEED_GB` sets the free disk MinIO needs (it was fixed at
250 GB); MinIO's setup client got its own config folder (mounting only
the CA file made Docker create `/.mc` as root, and the setup could not
write it); `bench.sh` makes the gate's results folder on each driver
(`veil-bench` does not make its `--out` folder: the first `pull`
attempt's JSON was lost). Fixed after it: MinIO now starts directly,
without the setup step, and `configure.sh` checks that it is still up 15
s later (BUG-2432); a gate during which MinIO restarted fails, with its
restart count before and after in `minio-restarts.txt` (§6.2);
`estimate.sh` and `create.sh` refuse a shared-CPU storage droplet
(BUG-2431). The rehearsal with MinIO started directly (`dorun1` @ `8bcbf200`,
three YugabyteDB nodes, Compose project `veil-dokit-dorun1`): every gate
**ok**, MinIO never restarted and ran no setup step; `failover` moved the
lease with a longest pause of 301 ms and no change lost or landed twice;
`spaces` (against the MinIO) 49 pushes, 7 merges, no error; teardown left
nothing of the project. `doctl` 2.x has been released since; the kit was run with
1.186.0 (`docs/REPRODUCE.md` pins it).

**What the next run needs:**

- an account that may create **CPU-Optimized 8- and 16-vCPU droplets**
  (and `c2-16vcpu-32gb`) in one region that has Spaces, and at least ten
  droplets (`docs/REPRODUCE.md` §1 says how to check):
  the topology of §2, or the same shape at one size smaller throughout,
  never a shared-CPU storage droplet;
- the store's disk on the droplet itself (`c2-16vcpu-32gb`), or a volume
  once BUG-2433's `422` is understood;
- the `spaces` gate at about 10 pushes a second (`SPACES_RATE=10`), or its
  reads a push measured first;
- before reading any number: each gate's `minio-restarts.txt` unchanged,
  and `s3_gave_up` in its `hub*-stats.json` not rising.

### 9.1 The rehearsal of 2026-11-13, objects over TLS and the `spaces` gate (`dokit4`)

`bash ~/.cache/veil-orch/heavy.sh dokit4-rehearsal 12 bash
deploy/compose/rehearsal.sh dokit4` on `dokit4` @ `ccda6704` (a work
commit squashed into the branch's commit: the same code, only this
section's text added; images built by the script, tag `ccda6704`; three YugabyteDB nodes; Compose
project `veil-dokit-dokit4`), after the kit moved the speed runs' objects
to MinIO (§2.3). New in this one: MinIO serves TLS with the rehearsal's
certificate, and both servers and every server the tool started reach it
over `https` trusting the CA through `VEIL_S3_CA`, as on the paid run's
storage droplet; and the `spaces` gate ran, against that MinIO (10 agents,
5 pushes/s, 10 s).

| Gate | Result |
|---|---|
| `pull`, `land`, `api` | ok (19, 20, 19 s) |
| `branches` | ok (47 s) |
| `landing` | ok (41 s) |
| `scaling` | ok (86 s) |
| `failover` (stop) | ok: the lease moved from server 1; longest pause in landings 522 ms (target 2 s); 1,624 changes landed, each once on `main`, by the database and by the agents' answers |
| `objects`, `openscion`, `scale` | ok (17, 5, 9 s) |
| `spaces` | ok: 49 pushes at 4.9/s of 5 offered, 9 merges into `main`, no error, no request given up, 0 `503` answers; 2.8 reads and 14.3 writes a push |

Up in 63 s; teardown: "nothing of veil-dokit-dokit4 remains (containers,
volumes, networks)". For the flow only: one machine plays ten.

### 9.2 The rehearsal of 2026-11-13 (the final one before the paid run)

`deploy/compose/rehearsal.sh finalbench` on the development machine (32
cores, 30 GB, Docker 28; through `~/.cache/veil-orch/heavy.sh`, alone in
the machine's heavy-job turn), images `veil-server:dc4e3f82` and
`veil-bench:dc4e3f82` built from `integration` @ `dc4e3f82` (public
`main`), its own Compose project `veil-dokit-finalbench`, `LB_PORT=28743`:
three YugabyteDB nodes (one tablet per table, 2.25 GB each), two servers
behind HAProxy, one driver, every gate at the rehearsal's sizes; then
`GATES=failover FAILOVER_HOW=kill SKIP_BUILD=1 TAG=dc4e3f82` (the same
images; the checkout's commit, recorded in that run's `run.txt`, was
`b3bbc9dd`, records only). **These numbers are for the flow only:** one
machine played nine.

Results: `deploy/compose/results/20261113T081916Z/` (every gate, failover
by `docker stop`) and `deploy/compose/results/20261113T082838Z/` (failover
by SIGKILL); not committed.

| Step | Outcome | What it showed |
|---|---|---|
| bring-up | **ok**, 61 s (60 s for the kill run) | three YugabyteDB nodes; 124 tablets on `yb1` after migrations 1 to 39; both servers healthy; HTTPS through the balancer with the run's CA (`/v1/epochs` → 401, as expected without a grant) |
| `pull` | ok | 4,907 and 12,581 pulls/s (10 and 50 agents); 1.3 and 1.6 statements per pull |
| `land`, `api` | ok | 14.8 and 267 landings/s (1 and 10 agents); API 48 and 323/s |
| `branches` | ok | the cost curve 14 and 234 pushes/s; **the headline** with 10 and 30 agents merging every 5th push for 10 s: 83 and 147 pushes/s, 166 and 295 branch landings on `main`, no errors |
| `landing` | ok | 40 agents of 4 people, 50/s offered, 10 s: plain 48.6/s, protected 50.2/s, with the mix 50.6/s (p99 418 to 557 ms), no errors |
| `scaling` | ok (flow) | `scaling.md` from both server counts: pulls 10,258 → 11,201/s, pushes 301 → 290/s, landings across 4 projects 221 → 172/s with 1 → 2 servers |
| `failover`, stop | **pass** | server 1 held the lease and was stopped; another server took it (epoch 1 → 2); nothing left queued; `main` = 2 set-up snapshots + 1,624 landed changes, exactly; 1,624 answered `landed`, each on `main` once under its ticket; 0 landings no agent heard of, against 20 failed submits without a ticket; first landing 14 ms after the stop; **longest pause after the stop 642 ms** (376 ms in the 30 s before) |
| `failover`, kill | **pass** | server 1 held the lease and was killed; taken over at epoch 2; `main` = 2 + 1,624, exactly; 1,624 answered `landed`, each once; 0 unheard of, against 20 failed submits; first landing 318 ms after the kill; **longest pause after the kill 442 ms** (388 ms in the 30 s before) |
| `objects` | ok | 792 reads/s through the server, 1,599 through the cache (10 workspaces) |
| `openscion` | ok (1,000 files, 1 run) | import 67 ms (Git 104), clone 166 (170), commit one file 18 (21), clone one directory 40 (44) |
| `scale` (`tiny`) | ok | initial push 1.7 s, server 20 → 84 MiB; thin clone 0.33 s |
| teardown | **ok** | `nothing of veil-dokit-finalbench remains (containers, volumes, networks)`, after both runs |

**The crash takeover is rehearsed** (BUG-1970 cause (2), fixed on
`failover2`): a killed lease holder paused landings 442 ms here, where it
paused 2,711 ms on 2026-11-13 before the fix (§9.3) and 2,358 ms on
2026-11-12; a clean stop 642 ms (481 ms before). Both are within the 2 s
target; on one machine, so for the flow only. A machine that vanishes
(no closed connection) still waits for the lease's 2 s expiry. No new
problem in the kit.

### 9.3 The rehearsal of 2026-11-12 (the multi-machine topology)

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

**Failover again, 2026-11-13** (`dokit3`; images `veil-server:93f14e54`
and `veil-bench:93f14e54`, whose Rust is staging `169cd8f8`'s: BUG-1970's
fix, the per-change landing log; the same topology and sizes, `GATES=failover`,
once with `docker stop` and once with `FAILOVER_HOW=kill`). The verdict now
also holds every answer the agents got against `main`'s first-parent line
(§6.1). Again for the flow only: one machine.

| Run | Lease | Exactly once (database) | Exactly once (the agents' answers) | Longest pause after the stop (30 s before) | Verdict |
|---|---|---|---|---|---|
| stop (`20261113T012547Z`) | server 2 → server 1, epoch 1 → 2 | `main` = 2 set-up + 1,622 landed, nothing queued | 1,621 answered `landed`, each on `main` once under its ticket; 1 landing no agent heard of, against 22 failed submits without a ticket (broken connections to the stopped server) | **481 ms** (311 ms) | pass |
| kill (`20261113T012950Z`) | server 2 → server 1, epoch 1 → 2 | `main` = 2 + 1,621, nothing queued | 1,620 answered, each once; 1 unheard of, against 23 failed submits | **2,711 ms** (392 ms) | exactly once: pass; pause: **miss** |

Before BUG-1970's fix both pauses were about 2.4 s. A clean stop now
gives the lease up at once (two earlier stop runs of this round: 628 and
307 ms); a crash still waits for the lease to expire (`LEASE_MS`, 2 s)
and for the next server's retry, BUG-1970's cause (2), left open.
Cause (2) is fixed since on `failover2` (`docs/HUB.md` §13.32 item 13:
a server finds a dead holder's session lock free and takes the lease over
at once, in 57 to 623 ms in the server tests on both databases);
rehearsed since: §9.2. A machine that vanishes still waits for the lease's expiry.

Found by this round, both fixed in the kit: the agents' change ids are in
Veil's letters (`k`–`z`) and the graph's in hex, and the `landed`
snapshot ids an agent is answered are its own projection, not `main`'s
(the verdict compares hex change ids and tickets); and in the rehearsal
the second server could not write its data directory, so the gate found
no lease holder when that server held it (**BUG-2080**: the first kill
run, `20261112T231814Z`, failed so; both runs above had server 2 holding
the lease).

### 9.4 The rehearsal of 2026-11-09 (one server, PostgreSQL)

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
- **BUG-1591** (fixed since in `veil-bench`: `--cache-url`, `--cache-ca`,
  and `--cache-pid` with `--cache-dir` when the tool runs on the cache's
  machine): `veil-bench load --via cache` could not measure a running
  cache, so the cache gate runs on the hub in its same-machine form (§6);
  `gates.sh` has not been changed to use the cache droplet.
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
bash deploy/gcp/test/test.sh      # the Google Cloud kit against a fake gcloud (§12.7)
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
check that `create.sh` makes all ten droplets (the storage droplet among them) at their sizes; that
`estimate.sh` prices it and every other topology, a day and a month
forgotten included; that `configure.sh` joins the YugabyteDB nodes, lifts
the tablet limit on each, migrates once, starts each server on its own
node, passes the first server's keys through private files and configures
HAProxy for the servers' private addresses; that every gate's dry run
succeeds, records its settings and runs where it belongs (the drivers'
gates against the balancer's private address, `scaling` from both
drivers, `failover` stopping the lease holder and reading its checks
through stdin); and that no secret appears in any of it or in the
topology recorded beside results. The failover verdict is tested on
made-up results directories (§7 of the tests): a clean run passes (with
one landing explained by a failed submit's ticket and one by a failed
submit without one), and a change told landed but not on `main`, one told
landed and twice on `main`, a landing no agent was told about beyond the
failed submits, a change answered twice as two snapshots, and a run
without the per-change log each fail. For **objects** (§2.3, section 8
of the tests and the end of section 6) they check that the default
topology makes the MinIO storage droplet at its size and none with
`VEIL_DO_OBJECTS=spaces`; that the servers and the same-machine gates
point at MinIO's private address over TLS with the run's CA (and at
Spaces with `spaces`); that MinIO's credentials are made for the run in a
0600 file, travel as a file, are read with `--env-file`, and appear on no
command line, in no output and in no result; that the certificate names
the storage droplet; that the firewall opens nothing to any address but
the operator's; that a volume is made, attached, mounted, priced,
deleted by `destroy.sh` and counted by its check (which fails while it
remains); that invalid object settings are refused; that the `spaces`
gate runs on the first server with `spaces.env` at 20 pushes a second;
and that its verdict passes a clean run (recording its `503` answers)
and fails one with errors, a request given up, missing counters or no
result. Every new check was seen to fail on a mutation of the kit (the
volume not attached, the CA or MinIO's private binding dropped, MinIO's
password on the command line, the Spaces keys not used, the volume not
deleted, the rate raised). `configure.sh`, `bench.sh` and `logs.sh`
over real SSH are exercised only by the rehearsal's equivalent Docker
commands (§4) and by the DigitalOcean run.

## 11. Risks and open items

- **Prices.** The built-in table is DigitalOcean's list as published;
  confirm with `estimate.sh --live --approve` before approving. Sizes may be
  unavailable in a region (`doctl compute size list` shows `Available`); the
  estimate and `create.sh` take the sizes from `.env`.
- **Droplet limit.** New accounts often may not create 5 or 10 droplets at
  once; `create.sh` then fails on the first refused droplet and leaves the
  earlier ones running: `destroy.sh --approve` removes them by tag.
- **The database is not encrypted in transit in the kit**: its URL has no
  `sslmode`, and the database is on the VPC's private network only, behind
  the firewall, one hop from the servers. The server can use TLS to a
  database (BUG-1590, fixed; §3), which the kit's PostgreSQL container and
  YugabyteDB nodes do not offer. YugabyteDB's `yugabyte` user has no
  password in the kit, for the same reason.
- **BUG-1591** (the tool's part fixed since): the cache gate runs on the
  hub in the same-machine form, not across the network to a cache droplet.
  By hand against `NAME-cache`: `veil-bench load --mode objects --via cache
  --url https://HUB --ca ca.pem --cache-url https://CACHE --cache-ca
  cache.pem …` from a driver (the hit share and the cache's memory are then
  reported as not measured: read `local` and `upstream` from the cache's
  `stats.json`, written on `SIGUSR1`, before and after), or on the cache's
  machine with `--cache-pid` and `--cache-dir`, which measures them.
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
- **Spaces' request rate (BUG-2290): decided by the owner, 2026-11-13.**
  One Spaces bucket allows 800 operations a second, all kinds together
  (500, of which 300 writes and lists, for buckets made before
  DigitalOcean's upgrade), answers more with `503 Slow Down`, and asks for
  a support ticket above 150 a second sustained
  ([Spaces Limits](https://docs.digitalocean.com/products/spaces/details/limits/),
  [Performance Best Practices](https://docs.digitalocean.com/products/spaces/concepts/best-practices/)).
  The many-branch headline makes about 8.6 reads and 11.0 writes a push:
  at 250 pushes/s about 4,900 requests a second. **The speed runs
  therefore keep objects in MinIO on the run's storage droplet, and the
  `spaces` gate runs 5 minutes at 20 pushes a second (about 390 requests
  a second) on a real bucket** (§2.3). Its `503` answers are counted by
  the server and recorded. Two consequences: the published speed numbers
  are on a self-hosted S3-compatible store, not on Spaces (`REPRODUCE.md`
  says so beside them); and a deployment on Spaces at the headline's
  rate needs the bucket's limit raised, several buckets, or fewer
  requests a push (counting the writes by kind is the next step).
- **The storage droplet** is one MinIO on one disk: no replication, and
  if it fails the run stops (the servers' requests fail after 10 s of
  retries, answered `503 busy`, BUG-2430). It needs dedicated CPUs
  (BUG-2431); a gate during which it restarted fails (BUG-2432). Its objects live only for the run. The image is the server
  as Bitnami last packaged it (`deploy/versions.env`), pinned by digest;
  MinIO no longer publishes images on Docker Hub.
- **YugabyteDB restarts.** A node that restarts turns the tablet-replica
  limit on again (§2.2); nothing in the gates creates tables, but a
  migration would fail on it.
- **The balancer** is one droplet: if it fails, the run stops. Its CPU is
  in DigitalOcean's graphs, not in the gates' samples.
- **cloud-init timing.** `configure.sh` waits for `cloud-init status
  --wait` on every droplet (usually 1 to 3 minutes). A droplet that never
  reaches "done" is reported; `ssh root@IP cloud-init status --long` says why.
- **Secrets.** Only in `deploy/do/.env` (0600, ignored), `deploy/do/state/`
  (0700, ignored; MinIO's credentials, made for each run, are its
  `minio.env`) and root-only files on the droplets (`hub.env`,
  `spaces.env`, `minio.env`); never on a command line (`test.sh` checks
  the dry runs and the `--approve` runs with fake `ssh` for that), never
  in user-data, never in an image or a result. Rotate the token and the
  Spaces keys after the test; MinIO's die with its droplet.
- **The certificate** is valid 30 days; `vl` clients pin the run's CA.
- **Spaces** bills $5 for the month however short the test (the `spaces`
  gate makes a bucket even when the servers use MinIO); it ends when the
  last bucket is deleted.

## 12. Google Cloud (`deploy/gcp`)

> **Status: kit ready, nothing rented** (2026-11-14). The same flow and
> the same safety as the DigitalOcean kit: every script is a dry run
> without `--approve`, and nothing talks to Google Cloud, not even to read,
> without it. **For someone with only the public repository:
> `docs/REPRODUCE.md` §9**, step by step.

The Google Cloud kit makes the machines differently and runs the same
steps on them. What runs on the machines is written once and shared:
`deploy/do/configure.sh`, `bench.sh` and `logs.sh` source the kit's
`lib.sh` named by `VEIL_KIT` (`do` by default; `deploy/gcp/configure.sh`,
`bench.sh` and `logs.sh` run them with `VEIL_KIT=gcp`), the ssh, state and
address helpers are `deploy/kit.sh`, and the gates and their checks are
`deploy/gates.sh` and `deploy/checks/`. So a fix to the steps (MinIO
started directly, BUG-2432; its restarts failing a gate; the certificate
naming `localhost`) reaches both kits. What is Google's own: `lib.sh`
(settings, `run_gcloud`, the machine list, Spot or on-demand, prices),
`estimate.sh`, `preflight.sh`, `create.sh`, `destroy.sh`, the Spot watch
in `bench.sh`, and `cloud-init/docker.yaml`.

### 12.1 Topology: hybrid Spot, one zone

Owner's decision, 2026-11-14. One region and one zone
(`VEIL_GCP_ZONE`, default `us-central1-a`), one subnet of the run's own
VPC network:

| Machine | Type | Model | Boot disk | Runs |
|---|---|---|---|---|
| `NAME-hub`, `-hub2`, `-hub3` | `c2d-standard-16` (16 vCPUs, 64 GB) | **Spot** | 200 GB | `veil-server`, one each, on the one database and bucket |
| `NAME-lb` | `e2-standard-4` (4 vCPUs, 16 GB) | **Spot** | 20 GB | HAProxy 3.0, TLS passed through: the one address |
| `NAME-yb1` to `-yb3` | `c2d-standard-8` (8 vCPUs, 32 GB) | on-demand | 100 GB, and a 500 GB `pd-ssd` data disk | YugabyteDB, one node each, its data on the data disk; Veil's database colocated (§12.10) |
| `NAME-driver1`, `-driver2` | `c2d-standard-8` | **Spot** | 100 GB | `veil-bench`, the simulated agents |
| `NAME-minio` | `c2d-standard-16` + 1 × 375 GB local NVMe SSD | on-demand | 20 GB | MinIO, its data on the local SSD |

Every type is settable (`VEIL_GCP_SIZE_*`, `deploy/gcp/.env.example`), as
are the counts (`VEIL_GCP_HUBS`, `VEIL_GCP_YB_NODES=0` for PostgreSQL,
`VEIL_GCP_DRIVERS`) and the model: `VEIL_GCP_SPOT=hybrid` (the default),
`all` or `none`. The storage machine must have dedicated vCPUs and a local
SSD: E2 and the shared-core types are refused for it (BUG-2431; E2 cannot
have a local SSD at all).

**Why hybrid.** A Spot VM costs about half (C2D) or 60% (E2) of its
on-demand price, and Google may reclaim it at any time. Losing a server,
the balancer or a driver costs one gate's rerun: the VM stops, keeps its
disk, and starts again as it was (§12.5). Losing a YugabyteDB node or the
storage machine would cost the run's data (MinIO's local SSD comes back
blank), so they stay on-demand. `all` is the cheapest; a reclaimed
database or storage machine then means `configure.sh` again and the gates
before it lose their objects.

**Spot VMs stop, not delete** (`--instance-termination-action=STOP`). A
stopped VM keeps its boot disk (the images shipped to it, `/etc/veil`, the
servers' keys in `veil-data`), its internal address and its containers,
which restart themselves when it starts: `bench.sh` starts it and the gate
reruns without reconfiguring anything. Deleted, it would need a new VM,
the images shipped again and the shared keys copied again. The cost of
stopping: a stopped VM bills its disk (a 200 GB server disk is $20 a
month) until `destroy.sh`, whose check counts stopped VMs and their disks.
A started VM gets a new public address (saved to the state; the drivers
use private addresses, which stay); the certificate still names the old
public one, which matters only to `vl login` from outside the run.

**Network.** The run's own network `NAME-net` and subnet `NAME-subnet`
(`10.42.0.0/24`), so no other network's rules apply (the `default`
network opens SSH to the world). Two firewall rules for the instances
tagged `NAME`: `NAME-operator`, SSH and 8443 (8444 with the cache) from
the operator's one IPv4 address; `NAME-internal`, everything between the
run's own machines. Google's implied rules deny every other ingress.
Every VM and its disk carry the label `veil-run=NAME` and the tag `NAME`
(firewall rules, networks and subnets take no labels: they are found by
their exact names).

**Access and credentials.** The machines take one SSH key: the run's own,
generated into `deploy/gcp/state/NAME/` and written into the cloud-init
user-data as root's only key. The instances turn OS Login off and block
the project's SSH keys, so neither the project's keys nor anyone's
personal ones get in, and ssh offers only the run's key
(`IdentitiesOnly`). The VMs have no service account and no scopes: a
machine of the run cannot call Google Cloud. The operator's credentials
are either a service account's key file (`VEIL_GCP_CREDENTIALS`, its path,
mode 0600, handed to gcloud as `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE`:
the key is never read by the kit, copied, printed or on a command line)
or the operator's active `gcloud auth login`. The account needs
`roles/compute.admin` on the project (and `roles/viewer` for
`preflight.sh`'s reads of billing, services and policies). Secrets reach the machines as on DigitalOcean: root-only
files over SSH (`hub.env`, `minio.env`), never in metadata or user-data.

**No `spaces` gate.** It runs on a DigitalOcean Spaces bucket; the GCP
kit refuses it. Objects are on MinIO, as in the DigitalOcean speed runs.

### 12.2 Cost

`deploy/gcp/estimate.sh` prints it line by line. Built-in list prices for
us-central1, read on 2026-11-14 from Google's pricing pages (on-demand:
Compute Engine's VM pricing; Spot: the Spot VMs page, which changes up to
once a day; local SSD $0.08 and pd-balanced $0.10 a GiB a month; an
external IPv4 address $0.005 an hour, $0.0025 on a Spot VM), rounded up to
the millidollar. `estimate.sh --live --approve` reads the current prices
from the Cloud Billing Catalog API (read only; the access token goes to
curl on stdin). It refuses a plan of $100 or more, and any type it has no
price for. The default topology, hybrid:

| Item | USD/hour |
|---|---:|
| 3 servers, `c2d-standard-16`, Spot | 3 × 0.333 |
| balancer, `e2-standard-4`, Spot | 0.081 |
| 3 YugabyteDB nodes, `c2d-standard-8`, on-demand | 3 × 0.364 |
| 2 drivers, `c2d-standard-8`, Spot | 2 × 0.167 |
| storage, `c2d-standard-16`, on-demand | 0.727 |
| its local SSD, 375 GiB | 0.041 |
| boot disks, 1,140 GiB pd-balanced | 0.156 |
| database data disks, 3 × 500 GiB pd-ssd ($0.17 a GiB a month) | 0.349 |
| 10 external IPv4 addresses (4 standard, 6 Spot) | 0.035 |
| **total** | **3.815** |

| Model | USD/hour | 8 hours | A day forgotten | A month forgotten |
|---|---:|---:|---:|---:|
| on-demand (`VEIL_GCP_SPOT=none`) | 5.460 | 43.68 | 131.03 | 3,985.49 |
| **hybrid Spot (the default)** | **3.815** | **30.52** | **91.55** | **2,784.64** |
| all Spot | 2.820 | 22.56 | 67.67 | 2,058.29 |

Without the data disks (`VEIL_GCP_DB_DISK_GB=0`, the database on the boot
disk, as on the runs of 2026-11-14) the hybrid plan is $3.465 an hour.

Stopped VMs (reclaimed and never started, or a teardown that deleted
nothing but stopped everything) still bill their disks: $369 a month
($114 of boot disks, $255 of data disks).
Traffic between the machines is free (one zone, internal addresses); the
images go in free; the results that come out are a few megabytes.

### 12.3 Quotas

A new project's quotas are smaller than the plan. `deploy/gcp/preflight.sh
--approve` (read only) compares them with the plan and prints, for each
one short, the quota, where, and the new limit to ask for; the request is
made in the console (IAM & Admin > Quotas & System Limits, Compute Engine
API, the quota's name, Edit quotas) and is free. The default plan needs,
in the region:

| Quota | Needed | Why |
|---|---:|---|
| `C2D_CPUS` (C2D CPUs) | 104 | 40 on-demand (YugabyteDB, storage) + 64 Spot (servers, drivers); only 40 if the region grants `PREEMPTIBLE_CPUS` |
| `PREEMPTIBLE_CPUS` | 68 | only where granted: Spot VMs count there, else against the on-demand quotas |
| `CPUS` | 4 | the E2 balancer |
| `LOCAL_SSD_TOTAL_GB` | 375 | MinIO's SSD |
| `SSD_TOTAL_GB` | 2,640 | the pd-balanced boot disks (1,140) and the database machines' pd-ssd data disks (1,500) |
| `IN_USE_ADDRESSES` | 10 | one external address per VM (SSH from the operator) |
| `INSTANCES` | 10 | |
| `CPUS_ALL_REGIONS` (global) | 108 | every vCPU of the run |

A free-trial account cannot ask for more quota (and is held to a few
vCPUs): the billing account must be upgraded to a paid one first (the
trial's credit stays). `preflight.sh` also checks that the project is
active, billing is enabled, the Compute Engine API is on, every machine
type is offered in the zone, and no organisation policy enforces OS Login
(the kit's machines take only the run's own key).

### 12.4 The run, in order

```sh
bash deploy/gcp/test/test.sh                 # the kit's own tests (a fake gcloud; nothing leaves the machine)
cp deploy/gcp/.env.example deploy/gcp/.env && chmod 600 deploy/gcp/.env && $EDITOR deploy/gcp/.env
deploy/gcp/preflight.sh --approve            # reads only: project, billing, API, types, quotas
deploy/gcp/estimate.sh                       # built-in prices; --live --approve for today's
deploy/docker/build.sh                       # veil-server:TAG and veil-bench:TAG
deploy/gcp/create.sh                         # dry run: the plan and every command
deploy/gcp/create.sh --approve               # <- the owner's approval; the first thing that bills
deploy/gcp/configure.sh --approve [TAG]      # the shared steps (§5, step 3)
deploy/gcp/bench.sh --approve pull           # ... every gate of §6 but `spaces`, one at a time
deploy/gcp/logs.sh --approve
deploy/gcp/destroy.sh --approve
deploy/gcp/destroy.sh --check --approve      # repeat until it says "nothing left"
```

### 12.5 Spot reclaims

`deploy/gcp/bench.sh` watches the Spot VMs around each gate:

- **before**, any Spot VM not `RUNNING` (reclaimed between gates) is
  started and recovered, and the gate's `run.txt` says
  `spot_restarted_before=NAME`;
- **after**, a Spot VM reclaimed during the gate (a
  `compute.instances.preempted` operation in the zone that was not there
  before it, or a Spot VM not `RUNNING`) makes the result invalid: its
  `run.txt` gets `spot_reclaimed_during=NAME`, `result_valid=no` and
  `rerun=<the rerun's directory>`; the VM is started and recovered; the
  gate runs once more, its `run.txt` saying `rerun_of=`, and its result
  stands when nothing was reclaimed during it (`result_valid=yes`). A
  second reclaim fails the gate (exit 3), both results invalid, with no
  third run. Every gate's `run.txt` says `spot_reclaimed_during=` and
  `result_valid=`; only `yes` results are published. When gcloud cannot
  answer whether a Spot VM was reclaimed (an API or credentials failure
  after the gate), the result is `result_valid=no` and the gate fails
  (exit 1), never taken as "nothing reclaimed".

Recovery: `gcloud compute instances start` (retried for five minutes when
the zone has no Spot capacity), the new public addresses saved, cloud-init
and Docker awaited; then a server's container is started and its health
awaited, the balancer's or the cache's started. A reclaimed YugabyteDB
node or storage machine (`VEIL_GCP_SPOT=all` only), or a private address
that changed, means `configure.sh --approve` again, which the script runs
(`spot_reconfigured=yes`). The shared steps' own check still applies:
MinIO restarting during a gate, or its restart count unreadable, fails it
(`minio-restarts.txt`).

A restarted VM keeps its private address (the gates, the balancer, the
servers and MinIO use only those, all in the certificate) but gets a new
public one, which the certificate does not name: the gates are unaffected,
but `vl login https://PUBLIC:8443` to a restarted balancer (or single
server) fails its TLS check until `configure.sh --approve` makes a new
certificate. A reclaim during `configure.sh` fails it; then run any gate
(`bench.sh` starts the stopped VM first and saves its new address, and may
stop there), and `configure.sh --approve` again.

### 12.6 Teardown

`deploy/gcp/destroy.sh --approve` deletes every VM of the run, **running
or stopped** (a reclaimed Spot VM is stopped, not gone), zone by zone with
all its disks; any disk left; the firewall rules; the subnet; the network;
any address. It finds them by the label `veil-run=NAME` or by the exact
names the kit gives (never a bare prefix: `NAME=veil` cannot reach a run
named `veil-big`), so a run that died before saving its state is cleaned
up too. Then, and on its own with `--check --approve`, it lists VMs in any
state (saying how many are stopped), disks, firewall rules, subnets,
networks, external addresses, snapshots and images, fails while any is
left or while gcloud itself fails, and removes the state file only when
all are gone. Glance at Billing > Reports in the console the next day.

### 12.7 Testing the kit

`bash deploy/gcp/test/test.sh` (85 checks) runs every script against a
fake gcloud (`deploy/gcp/test/fake-gcloud`), a made-up project that
remembers what was created, stopped and deleted, with fake ssh, scp,
docker and curl. It checks that the dry runs of the full topology exit 0,
call nothing and write nothing; the approval gate (a project, credentials,
a private key file); that `create.sh --approve` issues exactly the
expected commands (the network, the subnet, the two firewall rules with
only the operator's address from outside, ten labelled VMs, Spot exactly
where `VEIL_GCP_SPOT` says, the local SSD on the on-demand storage
machine, no service account, only the run's public key in the metadata);
the estimate (the three models, $100 refused, unknown and E2 storage types
refused, live prices with the token on stdin only); `configure.sh` through
the shared steps (MinIO on the local SSD and started directly, `localhost`
in the certificate, no `spaces.env`; each database machine's data disk;
Veil's database colocated by default, the hash layout with its tablets,
PostgreSQL's settings sized on the machine with durability on); the
`onerepo` gate (one project, 1,000 and 5,000 agents, the database machines
sampled) and its table on made-up results; the Spot watch (a clean gate valid; a
reclaim during a gate marks it invalid, starts the VM and reruns once; a
second reclaim fails without a third run; a VM down before a gate is
started first; a reclaimed storage machine with `all` reconfigures);
teardown (stopped VMs and their disks found and deleted, the check failing
on any leftover and on a gcloud failure, a half-made run cleaned up without
state); `preflight.sh` (short quotas and what to request, enough,
`PREEMPTIBLE_CPUS`, billing off, a missing type, OS Login enforced); and
that no secret (the key file's content, the access token, MinIO's
credentials, the servers' keys, the database password) is on a command
line, in an output, in the metadata, the state or a result. With
`VEIL_GCP_REAL_GCLOUD=/path/to/gcloud`, every command shape the scripts
issued is also parsed by the real gcloud CLI, without credentials or a
network (each stops at "no active account", none at its arguments): 593.0.0
parsed all of them. Mutations of the Spot watch (no rerun, reclaims
ignored) and of the teardown's listing (running VMs only) each fail it.

### 12.8 Risks and open items (Google Cloud)

- **Spot capacity and prices.** Spot prices change up to daily, and a zone
  can be out of Spot C2D capacity: `create.sh` then fails on the refused
  VM (`destroy.sh --approve` cleans up), and a restart after a reclaim is
  retried for five minutes. Another zone (`VEIL_GCP_ZONE`), or
  `VEIL_GCP_SPOT=none`.
- **Quota requests** take minutes to two days; ask before the run day.
- **The storage machine's local SSD** is lost if the machine stops (a
  host error, an operator's stop): the run's objects go with it. It is
  on-demand, with the default host-maintenance policy (live migration).
- **Run on Google Cloud** on 2026-11-14 and 15 (§12.9). The first run
  found three kit bugs, all fixed:
  - **No price for N2D drivers:** the kit had no built-in N2D price, so it refused the drivers chosen when the C2D quota was short (598cb4bf).
  - **Long hostname:** the machine's long Google Cloud hostname crashed YugabyteDB's master (7dc2ba1a).
  - **IP forwarding off:** Google's images turn it off, so containers couldn't reach the database (aa017c63).

### 12.9 The runs on Google Cloud (2026-11-14 and 15)

**Topology:** §12.1's default.
- 3 servers (c2d-standard-16, Spot) and the balancer (e2-standard-4, Spot);
- 3 YugabyteDB nodes (c2d-standard-8, on demand);
- MinIO (c2d-standard-16, local NVMe, on demand);
- 2 drivers (n2d-standard-8, Spot, as the C2D quota was 100 vCPUs);
- us-central1-a.

**Builds:** the server image `b6de7035` in both runs. The benchmark image
was `b6de7035` in run 1 and `135245b2` in run 2 (the `agents` mode, and
`warming` waited out).

**Run 1** (21:43 to 00:44 UTC, about $10.50) ran every gate but `spaces`
(DigitalOcean only), then two database layouts switched by hand on the
same machines:
- **colocated YugabyteDB:** a database `CREATE DATABASE … WITH COLOCATION = true`, migrated, the servers' `VEIL_DATABASE_URL` pointed at it, the servers restarted;
- **PostgreSQL 17:** on the third YugabyteDB machine, its YugabyteDB stopped; `shared_buffers=8GB`, synchronous commit on.

The `branches` gate ran again on each layout, at 300 and 1,000 agents for
3 minutes.

**Run 2** (01:19 to 02:03 UTC, about $3) ran the `agents` gate on the
three layouts.

No Spot VM was reclaimed, MinIO never restarted, and `destroy.sh --check`
found nothing left after each run.

| Gate | Result |
|---|---|
| `pull` | 866 / 5,590 / 3,928 pulls a second at 10 / 100 / 1,000 agents, 0 errors |
| `land` | 13 a second (1 project, 1 agent); 8 (1 project, 50 agents: 41 collisions a landing); 102 (10 projects); **283** (100 projects); 0 errors |
| `api` | 354 to 361 requests a second, 0 errors |
| `branches` (as deployed) | pushes 17 / 98 / 118 a second at 1 / 10 / 100 agents. Headline at 300 / 1,000 / 3,000 agents: 6.7 / 8.1 / 5.7 merges on `main` a second, p99 39 / 61 / 70 s, errors 0 / 55 / 7,597 |
| `branches`, colocated | pushes 19 / 113 / 137 a second; headline 15.6 / 12.5 merges a second at 300 / 1,000, p99 9.1 / 33 s, 0 errors |
| `branches`, PostgreSQL | pushes 39 / 177 / 246 a second; headline 30.6 / 25.2 merges a second, p99 7.6 / 23 s; 123 / 301 `warming` answers counted as errors (benchmark bug, fixed in `135245b2`) |
| `landing` (10,000 agents offering 1,000 a second, one project) | 106 / 91 / 85 a second for 180 s (plain / protected / mix), 63 / 65 for 600 s (plain / protected); mix for 600 s not run; collisions 0.00 to 0.02 a landing; the rest told to come back |
| `scaling` | landings 93 / 185 / **279** a second on 1 / 2 / 3 servers (3.0×); pushes 88 / 138 / 153; pulls 300 / 528 / 514; 0 errors. Exit 1: one driver's set-up push gave up on a `busy` answer at 2 servers |
| `failover` | every check passed: 17,386 changes landed once each, none lost or twice, none answered `landed` and missing |
| `objects` | from the servers 499 / 740 / 766 reads a second (10 / 100 / 1,000 readers); through the cache 870 / 1,364 / 1,341, 99.96 to 100 % cache hits, cache peak 103 MiB; 0 errors |
| `openscion` | Veil / Git: import 110 / 251 and 720 / 2,233 ms; clone 233 / 334 and 2,064 / 1,017 ms; commit one file 15 / 7 and 18 / 15 ms; clone one directory 64 / 76 and 64 / 86 ms (1k and 10k files) |
| `scale` (1 GB) | first push 169 s, push one snapshot 0.33 s, thin clone 23 s, full clone 51 s, one folder 0.65 s, pull 0.08 s. Exit 1: the server peaked at 1,042 MiB during the full clone (gate 1 GB) |
| `agents` (run 2; think 120 s compressed 20×, 3 subagents, landing every 20 pushes) | 1,000 agents: 79 / 71 / 102 pushes a second (as deployed / colocated / PostgreSQL), p50 6.4 / 7.4 / 3.5 s, 0 errors. 3,000: 37 to 40 a second on all three, 4,700 to 5,100 errors, servers at about 10 of 16 cores. 10,000 (PostgreSQL): 40 a second, about 19,500 errors |

**What the runs found** (next steps, in order):
1. **The branch-tips answer costs more with every branch.** Every push asks for the tips first, and the server signs a grant for every branch. Database statements per operation grew from 25 to 140 to 570 as branches piled up. This is the limit at 3,000 or more agents, on every database layout.
2. **An agent can't delete a branch it merged into another branch** (403: only admins may delete a branch whose work isn't all on `main`). Subagent branches pile up.
3. **The 1 GB project's full clone peaks at 1,042 MiB on the server.** Fixed on the development machine: BUG-2456 (the allocator returns freed pages sooner and gives the small classes one-page slabs), 962 to 976 MiB there, from 1,001 to 1,026; not yet run on Google Cloud.
4. **The benchmark's set-up gives up on a `busy` answer** (the 2-server scaling run lost one driver). Fixed: BUG-2435.
5. **The colocated layout should be the kit's default for YugabyteDB:** it doubled the merge rate and removed the errors. PostgreSQL on its own machine is already a kit option (`VEIL_GCP_YB_NODES=0`); these runs switched by hand only to keep the same machines. Done: the kit's default since 2026-11-15 (§12.10).
6. **The 10-minute landing mix** is still to run across machines.

### 12.10 The database for one busy repository (2026-11-15)

The target: one repository taking thousands of pushes a second from
thousands of agents, across machines (GitHub's internal test: 7,200 pushes
a second, 5,000 agents on one repository), without weakening durability or
permissions. The settings below are both kits' (`deploy/kit.sh`,
`deploy/do/configure.sh`), with defaults picked from the Google Cloud runs
(§12.9) and the local measurements below.

| Setting | Default | Choices |
|---|---|---|
| `VEIL_GCP_YB_LAYOUT`, `VEIL_DO_YB_LAYOUT` | `colocated` | `colocated`: every table of Veil's database `veil` in one tablet; `hash`: each table hash-sharded |
| `VEIL_GCP_YB_TABLETS`, `VEIL_DO_YB_TABLETS` | 1 | `hash` only: tablets per table on each node (1 to 99) |
| `VEIL_GCP_DB_DISK_TYPE` | `pd-ssd` | `pd-ssd`, `pd-balanced`: each database machine's data disk |
| `VEIL_GCP_DB_DISK_GB` | 500 | 0 (the data on the boot disk, as on the runs of §12.9), or 10 to 4,000 |

PostgreSQL alone is `VEIL_GCP_YB_NODES=0` (`VEIL_DO_YB_NODES=0`, the
DigitalOcean default), as before.

**Why colocated is YugabyteDB's default.** Measured on Google Cloud (§12.9),
the layout as deployed then (`hash`, one tablet per table on each node):
6.7 and 8.1 merges a second at 300 and 1,000 agents, with 55 errors at
1,000; the same machines with a colocated database: 15.6 and 12.5, no
errors. PostgreSQL on one of those machines did better than both (30.6 and
25.2).

**What a push writes**, measured on this machine (one YugabyteDB node,
`yugabytedb/yugabyte:2025.2.8.1-b8`, and a PostgreSQL 17 container with the
kit's settings; release build; `veil-bench load --mode branches`, one
project, 64 agents each pushing to a branch of its own, 30 s; the
statements from `pg_stat_statements` of the run's database only):

| | YugabyteDB, `hash` | YugabyteDB, colocated | PostgreSQL |
|---|---:|---:|---:|
| pushes a second (one machine for all: relative, not a capacity) | 561 | 585 | 899 |
| statements per push | 40.1 | 39.8 | 40.1 |
| of which reads | 28.9 | 28.7 | 29.0 |
| writes per push | 9.1 | 9.1 | 9.1 |
| commits per push | 3.05 distributed transactions | 3.05 distributed transactions | 3.04 |
| rows written per push (tables and their indexes, DocDB) | 34.9 | 34.5 | – |
| tablets written over the run | 43 | 1 | – |
| WAL per push | 15.5 KB (DocDB) | 10.6 KB (DocDB) | 11.5 KB |
| server CPU per push | 7.8 ms | 7.9 ms | 7.2 ms |

A push is one transaction of seven writes (a row each into `snapshots`,
`origins`, `projections`, `landed_changes`, `audit_log` and `packs`, and
its branch's row in `branches` updated), beside two `packs` rows committed
before it (the upload's pack and the push's own, recorded before they are
written: S28), so three commits. The reads are mostly the tips
(every agent asks for them before it pushes) and the permission and pack
lookups. With `hash`, every table and index a push writes is a tablet of
its own: about 20 tablets in one push's transaction, on up to three nodes.

**The same push with more branches** (PostgreSQL with the kit's settings,
one project, 60 s, this machine of 32 threads shared with the load tool):

| Agents (branches) | Pushes a second | p50 / p99 | Server CPU per push | Server cores | Statements per push | Commits per push | WAL per push | Received per push (the tips) | Errors, "come back" answers |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---|
| 64 | 899 | 66 ms / 144 ms | 7.2 ms | 6.4 | 40.1 | 3.04 | 11.5 KB | – | 0, 0 |
| 1,000 | 333 | 3.2 s / 4.3 s | 53.8 ms | 17.9 | 46.2 | 3.19 | 13.8 KB | 746 KB | 0, 0 |
| 5,000 | 76 | 30 s / 57 s | 251 ms | 19.0 | 69.0 | 7.25 | 15.0 KB | 3.5 MB | 57, 414,401 |

The server's CPU per push grows with the number of branches: every push
asks for the tips first, and the answer names (and signs a grant for) every
branch of the project (§12.9, first finding). At 5,000 agents the server
sheds load ("come back later"), and the retried uploads add their pack
rows' commits. The database is not the limit there: it used 1.2 cores at
5,000 agents (16.2 ms of its CPU a push). With few branches it is: a second
64-agent run counting the PostgreSQL container's CPU alone measured 925
pushes a second with the database at 10.0 cores, **10.8 ms of database CPU
a push** (about 0.27 ms a statement), the server at 7.1 ms.

**What 7,200 pushes a second would need** (an estimate from the costs
above, not a measurement across machines; at 70 % of each machine's cores):

| Cost per push | Server cores | Database cores | Database load | Balancer |
|---|---:|---:|---|---|
| today, 5,000 branches (251 ms server, 16.2 ms database, 69 statements, 7.3 commits, 3.5 MB tips) | about 2,600 | about 170 | 497,000 statements and 52,000 commits a second | 25 GB/s of tips: not possible |
| today, few branches (7.1 ms, 10.8 ms, 40 statements, 3 commits, 11.6 KB WAL) | about 73: 5 servers of 16 vCPUs | about 111 | 290,000 statements and 22,000 commits a second, 84 MB/s of WAL | small |
| the tips' cost no longer growing with branches, and 15 statements and 1 commit a push | about 73 | about 42 (at 0.27 ms a statement) | 108,000 statements and 7,200 commits a second | small |

Database cores scale with statements per push, server cores with the
server's CPU per push; both are what the work on the tips and on the push
path (statements, commits) changes. One PostgreSQL machine of 48 to 64
vCPUs on a fast persistent disk covers the last row; YugabyteDB does not
help one repository past one node (above).

**Why more tablets do not spread one repository.** Every table's primary
key starts with `project_id`, and YugabyteDB hashes a key's first column:
`PRIMARY KEY (project_id, name)` is `((project_id) HASH, name ASC)`. All of
one project's rows of a table have the same hash, so they are in one tablet
whatever the number of tablets, and automatic tablet splitting cannot
separate them either. Measured on the run's rows (`yb_hash_code`, the hash
range split evenly as YugabyteDB splits it):

| Table (rows of the one project) | Tablets it is in with 3 a table | with 24 | hashed on the whole key: 3 | 24 |
|---|---:|---:|---:|---:|
| `branches` (65) | 1 | 1 | 3 | 22 |
| `snapshots` (19,396) | 1 | 1 | 3 | 24 |
| `packs` (38,924) | 1 | 1 | 3 | 24 |
| `graph` (19,396) | 1 | 1 | 3 | 24 |

So `YB_TABLETS` spreads many projects over the nodes, never one. With
`hash`, one project's writes are spread over the nodes only table by
table, and every push is a transaction across several of them; colocated,
they are all on one tablet's leader, one node, in a transaction of one
tablet. That is why colocated measured faster, and why its ceiling for one
busy repository is one node's write rate.

**Why no schema change.** Hashing `branches` and `packs` on their whole key
would spread one project's rows, but their hot reads are range scans of
one project: the tips (`WHERE project_id = $1 AND hidden_for_embargo IS
NULL`, in ten queries) and the pack listings (`WHERE project_id = $1 AND
state = $2`, in eight). Hashed on the whole key, each would read every
tablet of the table; an index on `project_id` to avoid that is itself
hashed on `project_id` (one tablet a project again, `packs_unlisted`
already is one), and an index covering the tips would be written by every
push. A push would still be a transaction across several tablets. So no
migration is proposed: for one busy repository the database is PostgreSQL,
or a colocated YugabyteDB up to one node's write rate.

**PostgreSQL's settings** (`deploy/kit.sh` `pg_settings`), for a
write-heavy server, sized on the machine at start (its memory, `m` MiB):

- `max_connections` = servers × `--db-connections` + 64 (a same-machine
  gate's own server) + 100 (the drivers' counters, migrations, psql): 356
  for the default three servers, not the 1,500 of before (every connection
  is a process);
- `shared_buffers` a quarter of the memory (8 GB on a `c2d-standard-8`, as
  on the run of §12.9), `effective_cache_size` three quarters,
  `maintenance_work_mem=1GB`;
- `wal_buffers=64MB`, `max_wal_size=16GB`, `min_wal_size=4GB`,
  `checkpoint_timeout=15min`, `checkpoint_completion_target=0.9`: few
  checkpoints, so few full-page images in the WAL (11.5 KB a push);
- `random_page_cost=1.1`, `effective_io_concurrency=200` (an SSD);
  `autovacuum_vacuum_cost_limit=2000` (`branches` rows are updated by every
  push);
- `shared_preload_libraries=pg_stat_statements` (`pg_stat_statements.max`
  10,000, `track_io_timing=on`): the benchmark's per-push counts;
- **`synchronous_commit=on`, `fsync=on`, `full_page_writes=on`**, stated:
  a push answered `ok` is on disk (owner's rule: never trade durability for
  speed). `commit_delay`, which batches commits' flushes without losing
  any, is left at its default: not measured.

The kit's tests check that no setting is `off`. The same settings started
a `postgres:17-alpine` container of the pinned digest here (the measurement
above ran on it).

**The data disk** (Google Cloud): each database machine has a persistent
disk of its own for its data (`NAME-db-data`, `NAME-ybN-data`, deleted with
its machine and labelled like it), mounted at `/mnt/db-data`, a file system
made only when it has none. `pd-ssd` (30 IOPS and 0.48 MB/s a GB, up to the
machine's own limits) rather than the `pd-balanced` boot disk of §12.9:
the WAL of 7,200 pushes a second at 11.5 KB is about 83 MB/s, flushed at
every commit. 500 GB adds $0.116 an hour a machine (§12.2). On DigitalOcean
the data stays on the droplet's own disk (local NVMe on the CPU-Optimized
sizes).

**The `onerepo` gate** (§6) measures one project at 1,000 and 5,000 agents
against the target. It runs from one driver (the agents of one project sign
in as one person, so one tool drives them all): its table shows the
driver's own cores, and a driver near its vCPUs was the limit, not Veil.
Statements on YugabyteDB are counted on the node the driver's URL names
(`pg_stat_statements` is per node): with three servers spread over three
nodes, about a third of them.

## 13. Storage and garbage collection (v1)

In Veil v1, **storage is append-only and there is no garbage collection of
history — not even offline** (owner, 2026-11-18).

* **Default layout (`objects`).** `--object-layout` (`VEIL_OBJECT_LAYOUT`,
  `Config::object_layout`) defaults to `objects`, which is the sole writable
  layout in v1. Every committed object is written under its own content-addressed
  key (`p/<project>/<2 hex>/<62 hex>`).
* **Existing packs stay readable.** Pre-existing `LISTED` packs (`veilpack3\n`)
  written by earlier servers remain readable across every read path (`get`,
  `get_many`, `get_encoded`, `get_range`, `prefetch`) with no migration. New
  data is never written into packs, and online pack merging is removed.
* **Append-only history.** Objects from deleted branches, force-pushes, or
  expired snapshots are never collected in v1, and view keys' `view_graph`,
  `view_changes`, and `view_file_history` rows are kept. Plan storage capacity
  accordingly.
* **What servers still delete.** Uploads (`POST …/objects`) still land in
  temporary staged upload containers (`packs` rows with `state = STAGED`) so
  refused pushes, unread plain-text secrets beside a landing push, or abandoned
  uploads are never kept under project keys. Committed pushes and API commits
  discard and purge their consumed staged containers; refused pushes discard
  theirs immediately; and background sweepers (`pack_gc::schedule_sweep`,
  `pack_gc::sweep_scan`) sweep only uncommitted `STAGED` upload containers past
  `DEFAULT_STAGED_GRACE_MS` (1 hour) and `DISCARDED` upload containers past
  `DEFAULT_PACK_GRACE_MS` (15 minutes). Neither ever touches `LISTED` packs or
  committed project objects.
* **Database support.** Veil v1 supports **PostgreSQL only**; YugabyteDB is
  experimental and not supported in v1.


