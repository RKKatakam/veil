#!/usr/bin/env bash
# The benchmarks through the Veil server, in one command: starts PostgreSQL
# 17 and MinIO in Docker, builds the release `vl`, `veil-server` and
# `veil-bench`, runs one profile against a server it starts, prints the
# table, and removes the containers and everything generated.
#
#   scripts/bench-server.sh 1g          # the 1 GB profile: push, clone, pull, gc; 512 MiB gate
#   scripts/bench-server.sh small       # the same at 100 MB (tiny: a smoke test)
#   scripts/bench-server.sh openscion   # the four OpenScion workloads, 1k and 10k files, Git beside
#   scripts/bench-server.sh load        # the server's load curves (docs/design/scale/LOAD.md)
#   scripts/bench-server.sh landing     # the landing service: one main, 50 to 10,000 agents (S17)
#   scripts/bench-server.sh cache       # reads through a regional cache and straight from the server (S9)
#   scripts/bench-server.sh daemon      # a fresh workspace and a thin clone with no, a cold and a warm Veil daemon (S6)
#   scripts/bench-server.sh limits      # S24: quiet pulls (the middleware's cost), and quiet projects beside a flooded one
#   scripts/bench-server.sh 1g -- --runs 5   # extra veil-bench flags
#
# Environment:
#   OBJECTS=local   the server keeps objects in a local directory instead of MinIO
#   SERVER_BIN      the veil-server to measure (default: the release build here),
#                   e.g. an older build kept for a before/after comparison
#   STEP_LIMIT      seconds for the profile's run (default 3600); the build has 1800
#   OUT_DIR         where results go (default .scratch/bench-results)
#
# Everything lives under the worktree's .scratch/ (a real disk: /tmp is a
# tmpfs on the development machine), with TMPDIR there too. Every step is
# bounded by `timeout`: a hang fails the run instead of blocking it.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
PROFILE=${1:-1g}
shift || true
if [[ "${1:-}" == "--" ]]; then
    shift
fi
EXTRA=("$@")
case "$PROFILE" in
    tiny|small|1g|5g|openscion|load|landing|cache|daemon|limits) ;;
    *) echo "usage: $0 [tiny|small|1g|5g|openscion|load|landing|cache|daemon|limits] [-- veil-bench flags]" >&2; exit 2 ;;
esac

STEP_LIMIT=${STEP_LIMIT:-3600}
OUT_DIR=${OUT_DIR:-$ROOT/.scratch/bench-results}
mkdir -p "$ROOT/.scratch/tmp" "$OUT_DIR"
export TMPDIR=$ROOT/.scratch/tmp
export CARGO_INCREMENTAL=0

# docker, or through the docker group when this login session lacks it.
D() {
    if docker info >/dev/null 2>&1; then docker "$@"; else sg docker -c "docker $(printf '%q ' "$@")"; fi
}

TAG=veil-bench-$$
PG=$TAG-pg S3=$TAG-minio
WORK=$ROOT/.scratch/bench-server-$$
cleanup() {
    # The server logs go with the results (they name what failed).
    for l in "$WORK"/*/server.log "$WORK"/*/*/server.log; do
        [[ -f "$l" && -n "${OUT:-}" ]] && cp "$l" "${OUT%.json}-$(basename "$(dirname "$l")")-server.log"
    done
    D rm -f "$PG" "$S3" >/dev/null 2>&1
    # Only ever inside the worktree's .scratch/.
    [[ -n "$WORK" && "$WORK" == "$ROOT/.scratch/"* ]] && rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

port() { D port "$1" "$2" | head -1 | sed 's/.*://'; }
wait_for() { # what, seconds, command...
    local what=$1 secs=$2; shift 2
    local end=$((SECONDS + secs))
    until "$@" >/dev/null 2>&1; do
        if ((SECONDS > end)); then echo "stop: $what not ready after ${secs}s" >&2; exit 1; fi
        sleep 1
    done
}

echo "== disk"
df -h "$ROOT" | tail -1

echo "== starting PostgreSQL and MinIO ($TAG)"
D run -d --name "$PG" -e POSTGRES_PASSWORD=veil -e POSTGRES_USER=veil -e POSTGRES_DB=veil -p 127.0.0.1::5432 \
    postgres:17-alpine -c max_connections=500 -c shared_preload_libraries=pg_stat_statements >/dev/null || exit 1
D run -d --name "$S3" -e MINIO_ROOT_USER=veilminio -e MINIO_ROOT_PASSWORD=veilminio-secret -p 127.0.0.1::9000 \
    bitnamilegacy/minio:latest >/dev/null || exit 1
PG_PORT=$(port "$PG" 5432) S3_PORT=$(port "$S3" 9000)
wait_for PostgreSQL 120 D exec "$PG" pg_isready -U veil
wait_for MinIO 120 curl -sf "http://127.0.0.1:$S3_PORT/minio/health/live"
# pg_isready answers before the init scripts' restart; wait for a query.
wait_for PostgreSQL 60 D exec "$PG" psql -U veil -d veil -c "select 1"
D exec "$PG" psql -q -U veil -d veil -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements" >/dev/null || exit 1
PG_ID=$(D inspect -f '{{.Id}}' "$PG")
DB_URL=postgres://veil:veil@127.0.0.1:$PG_PORT/veil
echo "   postgres :$PG_PORT  minio :$S3_PORT"

SERVER_ARGS=(--server "${SERVER_BIN:-$ROOT/target/release/veil-server}" --database-url "$DB_URL")
if [[ "${OBJECTS:-s3}" != "local" ]]; then
    export VEIL_S3_ACCESS_KEY=veilminio VEIL_S3_SECRET_KEY=veilminio-secret
    SERVER_ARGS+=(--s3-endpoint "http://127.0.0.1:$S3_PORT" --s3-bucket veil-bench)
    echo "   objects in MinIO"
else
    echo "   objects in a local directory"
fi

echo "== building release vl, veil-server and veil-bench"
timeout --kill-after=30 1800 cargo build -q --release -p vl -p veil-server -p veil-bench || { echo "build failed or timed out" >&2; exit 1; }

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
COMMIT=$(git rev-parse --short HEAD)
OUT=$OUT_DIR/server-$PROFILE-$COMMIT-$STAMP.json
BENCH=$ROOT/target/release/veil-bench
mkdir -p "$WORK"
run() { # the profile's run, bounded
    timeout --kill-after=30 "$STEP_LIMIT" "$@"
    local rc=$?
    ((rc == 124)) && echo "stop: the run passed STEP_LIMIT=${STEP_LIMIT}s" >&2
    return $rc
}

echo "== $PROFILE through the server (commit $COMMIT)"
status=0
case "$PROFILE" in
    openscion)
        run "$BENCH" openscion --vl "$ROOT/target/release/vl" "${SERVER_ARGS[@]}" \
            --dir "$WORK/openscion" --out "$OUT" "${EXTRA[@]}" || status=$?
        if ((status == 0)); then
            echo "== the same workloads in one process, in memory (as OpenScion measures)"
            run "$BENCH" openscion-memory --out "${OUT%.json}-memory.json" || status=$?
        fi
        ;;
    daemon)
        run "$BENCH" daemon --vl "$ROOT/target/release/vl" "${SERVER_ARGS[@]}" \
            --dir "$WORK/daemon" --out "$OUT" "${EXTRA[@]}" || status=$?
        [[ -f "${OUT%.json}.md" ]] && cat "${OUT%.json}.md"
        ;;
    load)
        # Each curve with its own server (and data directory).
        L=("$BENCH" load "${SERVER_ARGS[@]}" --db-container "$PG_ID" --duration 15)
        # The cost gates (docs/design/server/storage-and-cost.md §9) fail a
        # curve: 1 database commit per landing; 5 statements per up-to-date pull.
        run "${L[@]}" --dir "$WORK/quiet" --mode pull --projects 1 --clients 10,100,1000 --background 0 --out "${OUT%.json}-quiet.json" "${EXTRA[@]}" || status=$?
        run "${L[@]}" --dir "$WORK/pull" --mode pull --projects 1 --clients 10,100,1000 --background 20 --out "${OUT%.json}-pull.json" "${EXTRA[@]}" || status=$?
        run "${L[@]}" --dir "$WORK/land" --mode land --projects 1,10,100 --clients 1 --rates max --out "${OUT%.json}-land.json" "${EXTRA[@]}" || status=$?
        run "${L[@]}" --dir "$WORK/branches" --mode branches --projects 1 --clients 1,10,100 --rates max --out "${OUT%.json}-branches.json" "${EXTRA[@]}" || status=$?
        run "${L[@]}" --dir "$WORK/hot" --mode land --projects 1 --clients 50 --rates 5,20,40,80 --out "${OUT%.json}-hot.json" "${EXTRA[@]}" || status=$?
        # Commits through the API (docs/HUB.md, S10): across projects, and
        # many agents into one main with the server rebasing.
        run "${L[@]}" --dir "$WORK/api" --mode api --projects 1,10,100 --clients 1 --rates max --out "${OUT%.json}-api.json" "${EXTRA[@]}" || status=$?
        run "${L[@]}" --dir "$WORK/api-hot" --mode api --projects 1 --clients 50 --rates 20,50,100,max --out "${OUT%.json}-api-hot.json" "${EXTRA[@]}" || status=$?
        ;;
    landing)
        # The landing service (docs/HUB.md §13.19): one project's main, open
        # loop, 50, 1,000 and 10,000 agents (LANDING_CLIENTS, LANDING_RATES).
        L=("$BENCH" load "${SERVER_ARGS[@]}" --db-container "$PG_ID" --duration "${DURATION:-15}" --mode landing --projects 1)
        run "${L[@]}" --dir "$WORK/landing" --clients "${LANDING_CLIENTS:-50,1000,10000}" --rates "${LANDING_RATES:-100,1000}" \
            --out "${OUT%.json}-landing.json" "${EXTRA[@]}" || status=$?
        ;;
    limits)
        # S24 (docs/HUB.md §13.25): up-to-date pulls, whose cost is mostly
        # the request path (the middleware's cost per request: compare with
        # SERVER_BIN set to a build without it); then 10 quiet agents on 2
        # projects beside 0, 200 and 1,000 agents flooding a third.
        L=("$BENCH" load "${SERVER_ARGS[@]}" --db-container "$PG_ID" --duration 15 --mode pull --background 0)
        run "${L[@]}" --dir "$WORK/quiet" --projects 1 --clients 10,100 --out "${OUT%.json}-quiet.json" "${EXTRA[@]}" || status=$?
        for f in 0 200 1000; do
            run "${L[@]}" --dir "$WORK/flood-$f" --projects 2 --clients 10 --flood "$f" --out "${OUT%.json}-flood-$f.json" "${EXTRA[@]}" || status=$?
        done
        ;;
    cache)
        # Fresh thin workspaces reading through a regional cache, and
        # straight from the server (docs/HUB.md §13.18): hit share, latency,
        # the cache's memory (gates: 99 % from its store, 512 MiB).
        L=("$BENCH" load "${SERVER_ARGS[@]}" --db-container "$PG_ID" --duration 15 --mode objects --via server,cache)
        run "${L[@]}" --dir "$WORK/still" --projects 1 --clients 10,100,1000 --background 0 --out "${OUT%.json}-still.json" "${EXTRA[@]}" || status=$?
        run "${L[@]}" --dir "$WORK/moving" --projects 1 --clients 10,100,1000 --background 20 --out "${OUT%.json}-moving.json" "${EXTRA[@]}" || status=$?
        ;;
    *)
        # Generation, the checkout, the server phase (push, clone, pull,
        # clone one directory) and the client's gc; the local, path, SFTP
        # and agents phases are scripts/bench-scale.sh's.
        run "$BENCH" run --profile "$PROFILE" --seed "${SEED:-1}" --dir "$WORK/scale" \
            --vl "$ROOT/target/release/vl" --src "$ROOT" --out "$OUT" "${SERVER_ARGS[@]}" \
            --skip-phase import,local,remote-path,packed,sftp,agents "${EXTRA[@]}" || status=$?
        [[ -f "${OUT%.json}.md" ]] && cat "${OUT%.json}.md"
        ;;
esac

echo "== results: $OUT_DIR/$(basename "${OUT%.json}")*"
df -h "$ROOT" | tail -1
exit $status
