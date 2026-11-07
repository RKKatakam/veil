#!/bin/bash
# Verify the Veil server (crates/veil-server) against real services in
# Docker containers (shared between runs by default; see below):
#   PostgreSQL 17, YugabyteDB 2025.2 (Apache-2.0 core image) and MinIO.
#
# Steps: the migrations, once per database; the server's unit tests and
# clippy; the container test suite
# (`--features containers`) on PostgreSQL + MinIO and on YugabyteDB + MinIO;
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
cleanup() {
  if [ $SHARED = 1 ]; then
    local db q="SELECT datname FROM pg_database WHERE datname LIKE 'r${RUN}x%'"
    for db in $PG_DB $(D exec "$PG" psql -U veil -d veil -tAc "$q" 2>/dev/null); do
      D exec "$PG" psql -U veil -d veil -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" >/dev/null 2>&1
    done
    for db in $YB_DB $(ysql_at "$q" 2>/dev/null); do
      ysql "DROP DATABASE IF EXISTS $db" >/dev/null 2>&1
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
  running "$YB" || { D rm -f "$YB" >/dev/null 2>&1; D run -d --name "$YB" -p 127.0.0.1::5433 "$YB_IMAGE" bin/yugabyted start --background=false >/dev/null || return 1; }
  PG_PORT=$(port "$PG" 5432) S3_PORT=$(port "$S3" 9000) YB_PORT=$(port "$YB" 5433)
  for i in $(seq 120); do D exec "$PG" pg_isready -U veil >/dev/null 2>&1 && break; sleep 1; done
  for i in $(seq 120); do curl -sf "http://127.0.0.1:$S3_PORT/minio/health/live" >/dev/null && break; sleep 1; done
  for i in $(seq 180); do ysql "select 1" >/dev/null 2>&1 && break; sleep 2; done
}

if [ $SHARED = 1 ]; then
  echo "== shared containers (VEIL_VERIFY_FRESH=1 for private ones)"
  # One run at a time starts or replaces them.
  exec 9>"${XDG_RUNTIME_DIR:-/tmp}/veil-shared-services.lock"
  flock 9
  start_services || { echo "starting containers failed"; exit 1; }
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
step postgres env VEIL_TEST_DATABASE_URL="$PG_URL" VEIL_TEST_S3_BUCKET=veil-pg-$RUN "$BIN"
step yugabyte env VEIL_TEST_DATABASE_URL="$YB_URL" VEIL_TEST_S3_BUCKET=veil-yb-$RUN "$BIN"

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
