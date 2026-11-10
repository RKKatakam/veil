#!/bin/bash
# Verify the Veil server (crates/veil-server) against real services in
# Docker containers (shared between runs by default; see below):
#   PostgreSQL 17, YugabyteDB 2025.2 (Apache-2.0 core image) and MinIO.
#
# Steps: the migrations, once per database; the server's unit tests and
# clippy; the container test suite
# (`--features containers`) on PostgreSQL + MinIO and on YugabyteDB + MinIO,
# and its hostile-size reproductions in steps of their own;
# then the concurrency tests under load (several copies of the test binary
# at once, as the veil-review skill's lens 3 asks).
#
# Usage: scripts/verify-server.sh            (from anywhere in the repository)
# Kept out of verify-fast.sh, which must stay fast and need no Docker.
set -u
cd "$(dirname "$0")/.."
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only

# docker, or through the docker group when this login session lacks it.
D() {
  if docker info >/dev/null 2>&1; then docker "$@"; else sg docker -c "docker $(printf '%q ' "$@")"; fi
}

# By default the three services are long-lived containers shared by every
# run on this machine (`veil-shared-*`): starting YugabyteDB takes a minute
# or two, so each run only creates its own databases and buckets in them
# and drops them at the end. VEIL_VERIFY_FRESH=1 starts private containers
# for this run instead, and removes them afterwards.
PG_IMAGE=postgres:17-alpine
YB_IMAGE=yugabytedb/yugabyte:2025.2.8.1-b8
# MinIO no longer publishes images on Docker Hub; this is the MinIO server
# binary as Bitnami last packaged it.
S3_IMAGE=bitnamilegacy/minio:latest
RUN=$$
LOGS=${TMPDIR:-/tmp}/veil-server-verify-$RUN
mkdir -p "$LOGS"
if [ "${VEIL_VERIFY_FRESH:-0}" = 1 ]; then
  TAG=veil-verify-$RUN SHARED=0
else
  TAG=veil-shared SHARED=1
fi
PG=$TAG-pg YB=$TAG-yb S3=$TAG-minio
PG_DB=veil YB_DB=yugabyte

ysql() { D exec "$YB" sh -c "bin/ysqlsh -h \$(hostname -i) -c \"$1\""; }
ysql_at() { D exec "$YB" sh -c "bin/ysqlsh -h \$(hostname -i) -tAc \"$1\""; }
# Databases the tests create themselves start with this run's prefix.
export VEIL_TEST_DB_PREFIX=r${RUN}x
# Buckets each run makes in the shared MinIO, named after its pid. MinIO keeps
# one directory per object, so buckets left behind fill the disk's inodes
# (all 244 million, 2026-11-08): each run removes its own, and the next run
# removes those of runs that died first.
BUCKETS="veil-pg veil-yb veil-hpg veil-hyb veil-load-pg veil-load-yb"
remove_buckets() { # names in the shared MinIO's data directory
  [ $# -gt 0 ] && D exec "$S3" sh -c 'cd /bitnami/minio/data && for b; do case "$b" in ""|.*|*/*) continue;; esac; rm -rf -- "$b" ".minio.sys/buckets/$b"; done' sh "$@" >/dev/null 2>&1
}
cleanup() {
  if [ $SHARED = 1 ]; then
    remove_buckets $(for k in $BUCKETS; do echo "$k-$RUN"; done)
    local db q="SELECT datname FROM pg_database WHERE datname LIKE 'r${RUN}x%'"
    for db in $PG_DB $(D exec "$PG" psql -U veil -d veil -tAc "$q" 2>/dev/null); do
      D exec "$PG" psql -U veil -d veil -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" >/dev/null 2>&1
    done
    for db in $YB_DB $(ysql_at "$q" 2>/dev/null); do
      ysql "DROP DATABASE IF EXISTS $db WITH (FORCE)" >/dev/null 2>&1
    done
  else
    D rm -f "$PG" "$YB" "$S3" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

port() { D port "$1" "$2" | head -1 | sed 's/.*://'; }
running() { [ "$(D inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }

start_services() {
  # The load step runs 8 copies of the concurrency tests, each with its own
  # servers and connection pools; shared runs can overlap, so allow plenty.
  running "$PG" || { D rm -f "$PG" >/dev/null 2>&1; D run -d --name "$PG" -e POSTGRES_PASSWORD=veil -e POSTGRES_USER=veil -e POSTGRES_DB=veil -p 127.0.0.1::5432 "$PG_IMAGE" -c max_connections=1500 >/dev/null || return 1; }
  running "$S3" || { D rm -f "$S3" >/dev/null 2>&1; D run -d --name "$S3" -e MINIO_ROOT_USER=veilminio -e MINIO_ROOT_PASSWORD=veilminio-secret -p 127.0.0.1::9000 "$S3_IMAGE" >/dev/null || return 1; }
  # Memory capped, one tablet per table, no tablet-count limit: a long-lived
  # YugabyteDB otherwise grows toward most of the
  # machine's memory (8 GB seen) while agents build beside it.
  # A one-node database needs no YSQL operation lease; on a busy machine its
  # renewal comes late, and YugabyteDB then kills every connection and
  # restarts (seen on 8-vCPU Boat machines: 370 of 425 tests failed).
  running "$YB" || { D rm -f "$YB" >/dev/null 2>&1; D run -d --name "$YB" -p 127.0.0.1::5433 "$YB_IMAGE" bin/yugabyted start --background=false \
    --tserver_flags=memory_limit_hard_bytes=3221225472,ysql_num_shards_per_tserver=1,enable_ysql_operation_lease=false \
    --master_flags=memory_limit_hard_bytes=1073741824,enforce_tablet_replica_limits=false,enable_ysql_operation_lease=false >/dev/null || return 1; }
  PG_PORT=$(port "$PG" 5432) S3_PORT=$(port "$S3" 9000) YB_PORT=$(port "$YB" 5433)
  # Over TCP: a new container first runs a set-up server on its socket only.
  for i in $(seq 120); do D exec "$PG" pg_isready -h 127.0.0.1 -U veil >/dev/null 2>&1 && break; sleep 1; done
  for i in $(seq 120); do curl -sf "http://127.0.0.1:$S3_PORT/minio/health/live" >/dev/null && break; sleep 1; done
  for i in $(seq 180); do ysql "select 1" >/dev/null 2>&1 && break; sleep 2; done
}

# Databases left by runs that were killed before their cleanup ran: each
# name carries its run's pid (veil_run_PID, or rPIDx… for the tests' own).
drop_dead_runs() {
  local q="SELECT datname FROM pg_database WHERE datname LIKE 'veil_run_%' OR datname LIKE 'r%x%'" db pid
  for db in $(D exec "$PG" psql -U veil -d veil -tAc "$q" 2>/dev/null); do
    pid=$(echo "$db" | sed -E 's/^r([0-9]+)x.*/\1/; s/^veil_run_([0-9]+)$/\1/')
    [ -d "/proc/$pid" ] || D exec "$PG" psql -U veil -d veil -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" >/dev/null 2>&1
  done
  for db in $(ysql_at "$q" 2>/dev/null); do
    pid=$(echo "$db" | sed -E 's/^r([0-9]+)x.*/\1/; s/^veil_run_([0-9]+)$/\1/')
    [ -d "/proc/$pid" ] || ysql "DROP DATABASE IF EXISTS $db WITH (FORCE)" >/dev/null 2>&1
  done
  local b dead=()
  for b in $(D exec "$S3" ls /bitnami/minio/data 2>/dev/null); do
    pid=$(echo "$b" | sed -nE 's/^veil-(pg|yb|hpg|hyb|load-pg|load-yb)-([0-9]+)$/\2/p')
    [ -n "$pid" ] && [ ! -d "/proc/$pid" ] && dead+=("$b")
  done
  remove_buckets "${dead[@]}"
}

if [ $SHARED = 1 ]; then
  echo "== shared containers (VEIL_VERIFY_FRESH=1 for private ones)"
  # One run at a time starts or replaces them.
  exec 9>"${XDG_RUNTIME_DIR:-/tmp}/veil-shared-services.lock"
  flock 9
  start_services || { echo "starting containers failed"; exit 1; }
  drop_dead_runs
  flock -u 9
  PG_DB=veil_run_$RUN YB_DB=veil_run_$RUN
  D exec "$PG" psql -U veil -d veil -c "CREATE DATABASE $PG_DB" >/dev/null || { echo "creating $PG_DB failed"; exit 1; }
  ysql "CREATE DATABASE $YB_DB" >/dev/null || { echo "creating $YB_DB on YugabyteDB failed"; exit 1; }
else
  echo "== starting containers"
  start_services || { echo "starting containers failed"; exit 1; }
fi
echo "   postgres :$PG_PORT/$PG_DB  yugabyte :$YB_PORT/$YB_DB  minio :$S3_PORT"

echo "== building"
cargo build -q -p vl -p veil-server || exit 1
BIN=$(cargo test -p veil-server --features containers --test server_hub --no-run 2>&1 | grep -o 'target/debug/deps/server_hub-[0-9a-f]*' | head -1)
[ -x "$BIN" ] || { echo "no test binary"; exit 1; }
export VEIL_TEST_VL=$PWD/target/debug/vl
export VEIL_TEST_S3_ENDPOINT=http://127.0.0.1:$S3_PORT VEIL_TEST_S3_KEY=veilminio VEIL_TEST_S3_SECRET=veilminio-secret
PG_URL=postgres://veil:veil@127.0.0.1:$PG_PORT/$PG_DB
YB_URL=postgres://yugabyte@127.0.0.1:$YB_PORT/$YB_DB

# Migrate each database once, before any server starts (BUG-838): servers
# that find the schema current run no DDL, so the suites' many servers
# never change the catalog under one another.
for url in "$PG_URL" "$YB_URL"; do
  timeout 300 target/debug/veil-server migrate --database-url "$url" || { echo "migrating $url failed"; exit 1; }
done

status=0
# Every step is bounded: a hang fails the run instead of blocking it.
STEP_LIMIT=${STEP_LIMIT:-600}
step() { # name, command...
  local name=$1; shift
  if timeout --kill-after=30 "$STEP_LIMIT" "$@" > "$LOGS/$name.log" 2>&1; then echo "   ok    $name"
  else echo "   FAIL  $name (exit $?: 124 is the ${STEP_LIMIT}s limit)  ($LOGS/$name.log)"; status=1; fi
  grep -E '^test result|tests run' "$LOGS/$name.log" | tail -1 | sed 's/^/         /'
}

echo "== unit tests and lints"
step unit cargo test -p veil-server
step clippy cargo clippy -q -p veil-server --all-targets --features containers -- -D warnings

echo "== container suite"
# The hostile-size reproductions (S12's adversarial pass: millions of
# rows; S28's API commits of gigabytes, which measure the process's memory)
# run in steps of their own, one test at a time, so that their load never
# starves the suite's contention-sensitive tests (sign-up under
# SERIALIZABLE) and nothing else counts in their memory.
HOSTILE=(derived::s12_adversarial packs::hostile_)
SKIP_HOSTILE=(--skip derived::s12_adversarial --skip packs::hostile_)
step postgres env VEIL_TEST_DATABASE_URL="$PG_URL" VEIL_TEST_S3_BUCKET=veil-pg-$RUN "$BIN" "${SKIP_HOSTILE[@]}"
# YugabyteDB is shared by every run on the machine: 8 tests at a time, so
# several runs at once do not drown it in servers and pools (each test
# starts its own); results stay trustworthy under load.
STEP_LIMIT=1800 step yugabyte env VEIL_TEST_DATABASE_URL="$YB_URL" VEIL_TEST_S3_BUCKET=veil-yb-$RUN "$BIN" "${SKIP_HOSTILE[@]}" --test-threads=8
# One at a time: on a database other runs share, three at once could keep
# a statement past its timeout.
# The hostile-size sets take about half an hour and touch only S12/S13's
# derived data, so they run when this branch changes `derive/` or `query/`
# (compared with `integration`), or when VEIL_VERIFY_HOSTILE=1 (always for
# merges into `integration`). On the shared YugabyteDB they also run one at a
# time machine-wide: two runs' hostile steps at once time out statements.
hostile=${VEIL_VERIFY_HOSTILE:-auto}
if [ "$hostile" = auto ]; then
  base=$(git merge-base HEAD integration 2>/dev/null)
  if [ -n "$base" ] && git diff --name-only "$base" HEAD -- crates/veil-server/src/derive crates/veil-server/src/query crates/veil-server/src/store.rs crates/veil-server/src/sync.rs crates/veil-server/tests/server_hub/derived.rs crates/veil-server/tests/server_hub/packs.rs | grep -q .; then hostile=1; else hostile=0; fi
fi
if [ "$hostile" = 1 ]; then
  STEP_LIMIT=2400 step hostile-postgres env VEIL_TEST_DATABASE_URL="$PG_URL" VEIL_TEST_S3_BUCKET=veil-hpg-$RUN "$BIN" "${HOSTILE[@]}" --test-threads=1
  STEP_LIMIT=9000 step hostile-yugabyte flock -w 7200 "${XDG_RUNTIME_DIR:-/tmp}/veil-yb-hostile.lock" env VEIL_TEST_DATABASE_URL="$YB_URL" VEIL_TEST_S3_BUCKET=veil-hyb-$RUN "$BIN" "${HOSTILE[@]}" --test-threads=1
else
  echo "   skip  hostile sets (no derive/ or query/ changes; VEIL_VERIFY_HOSTILE=1 runs them)"
fi

echo "== concurrency under load (several copies at once)"
load() { # url, bucket, copies (each copy bounded like a step)
  local pids=() rc=0
  for i in $(seq "$3"); do
    timeout --kill-after=30 "$STEP_LIMIT" env VEIL_TEST_DATABASE_URL="$1" VEIL_TEST_S3_BUCKET="$2" "$BIN" concurrency > "$LOGS/load-$2-$i.log" 2>&1 &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  grep -h 'pushes landed' "$LOGS"/load-"$2"-*.log | head -3
  return $rc
}
load_step() { # name, url, bucket, copies: the copies are bounded, not the function
  local name=$1; shift
  if load "$@" > "$LOGS/$name.log" 2>&1; then echo "   ok    $name"; else echo "   FAIL  $name  ($LOGS/$name.log)"; status=1; fi
  cat "$LOGS/$name.log" | sed 's/^/         /'
}
load_step load-postgres "$PG_URL" veil-load-pg-$RUN 8
load_step load-yugabyte "$YB_URL" veil-load-yb-$RUN 3

echo "== result"
if [ $status = 0 ]; then echo "verify-server: all green"; else echo "verify-server: FAILED (logs in $LOGS)"; fi
exit $status
