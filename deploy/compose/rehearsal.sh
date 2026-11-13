#!/usr/bin/env bash
# The local rehearsal of the multi-machine test (docs/DEPLOY.md §4,
# docs/REPRODUCE.md): the paid topology in Docker Compose on one machine,
# small. Builds the images, brings up three YugabyteDB nodes (or
# PostgreSQL), MinIO (over TLS, as on the paid run's storage droplet), two servers on the one database and bucket and
# HAProxy in front of them, runs every gate of deploy/gates.sh briefly
# (seconds, tens of agents; failover included; the `spaces` gate against
# the MinIO, as no Spaces bucket is at hand) through the balancer, and
# tears down everything of this run (containers, network, volumes).
#
#   deploy/compose/rehearsal.sh [NAME]      # NAME distinguishes concurrent runs (default: the user)
#
# Environment:
#   SKIP_BUILD=1   use the images already built for TAG (deploy/docker/build.sh)
#   TAG=…          the image tag (default: this commit's, as build.sh names it)
#   DB=yb|pg       three YugabyteDB nodes (default) or one PostgreSQL 17
#   GATES="pull failover …"   a subset of deploy/gates.sh's (default: all of them)
#   KEEP=1         leave the stack running (tear down later with the printed `down -v`)
#   LB_PORT        the balancer's port on 127.0.0.1 (default 18443)
#   STEP_LIMIT     seconds allowed per benchmark command (default 1200)
#   the gates' sizes (DURATION, LANDING_AGENTS, …): small defaults below
#
# Memory: every container has a limit (docker-compose.yml); the defaults add
# up to 11.5 GB with YugabyteDB. Results: deploy/compose/results/<stamp>/,
# one directory per gate laid out as the paid run's (docs/DEPLOY.md §6),
# plus each container's log.
set -euo pipefail
cd "$(dirname "$0")"
HERE=$PWD
ROOT=$(cd ../.. && pwd)
[ $# -le 1 ] && [[ "${1:-}" != -* ]] || { echo "rehearsal: usage: rehearsal.sh [NAME]" >&2; exit 2; }
NAME=${1:-${USER:-rehearsal}}
[[ "$NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || { echo "rehearsal: invalid NAME '$NAME'" >&2; exit 2; }
DB=${DB:-yb}
case $DB in yb|pg) ;; *) echo "rehearsal: DB must be yb or pg" >&2; exit 2 ;; esac
PROJECT=veil-dokit-$NAME
STEP_LIMIT=${STEP_LIMIT:-1200}
# The gates' sizes, small (the paid run's are deploy/gates.sh's defaults).
: "${DURATION:=5}" "${WARMUP:=1}"
: "${PULL_CLIENTS:=10,50}" "${PULL_BACKGROUND:=2}" "${LAND_PROJECTS:=1,10}" "${LAND_CLIENTS:=1}"
: "${BRANCH_CLIENTS:=1,10}" "${OBJECT_CLIENTS:=10}" "${OPENSCION_FILES:=1000}" "${OPENSCION_RUNS:=1}"
: "${SCALE_PROFILE:=tiny}" "${SCALE_RUNS:=1}"
: "${LANDING_AGENTS:=40}" "${LANDING_PEOPLE:=4}" "${LANDING_RATE:=50}" "${LANDING_DURATIONS:=10}"
: "${HEADLINE_AGENTS:=10,30}" "${MERGE_EVERY:=5}" "${HEADLINE_DURATION:=10}"
: "${SCALING_SERVERS:=1 2}" "${SCALING_DURATION:=8}" "${SCALING_PULL_CLIENTS:=20}" "${SCALING_BRANCH_CLIENTS:=20}"
: "${SCALING_LANDING_PROJECTS:=4}" "${SCALING_LANDING_CLIENTS:=20}"
: "${SPACES_AGENTS:=10}" "${SPACES_RATE:=5}" "${SPACES_DURATION:=10}"
: "${FAILOVER_AGENTS:=40}" "${FAILOVER_PEOPLE:=4}" "${FAILOVER_RATE:=40}" "${FAILOVER_DURATION:=40}" "${FAILOVER_AFTER:=15}" "${FAILOVER_SETTLE:=60}"
GATES_DIR=$ROOT/deploy
. "$GATES_DIR/gates.sh"
GATES=${GATES:-$GATES_ALL}
. "$ROOT/deploy/versions.env"
mkdir -p "$ROOT/.scratch/tmp" results
export TMPDIR=$ROOT/.scratch/tmp

D() { if docker info >/dev/null 2>&1; then docker "$@"; else sg docker -c "docker $(printf '%q ' "$@")"; fi; }

# 1. Images (TAG: this commit's, or "dev" outside a git checkout).
export TAG=${TAG:-$(cd "$ROOT" && git describe --always --dirty --abbrev=8 2>/dev/null || echo dev)}
COMMIT=$(cd "$ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)
if [ "${SKIP_BUILD:-0}" != 1 ]; then
    "$ROOT/deploy/docker/build.sh" || { echo "rehearsal: the image build failed"; exit 1; }
fi

# 2. Certificates, the balancer's configuration and the secrets of this run
# (never committed; see .gitignore).
mkdir -p "$HERE/.tls"; chmod 700 "$HERE/.tls"
TLS_DIR=$HERE/.tls/$NAME
"$ROOT/deploy/tls/mkcert.sh" "$TLS_DIR" lb hub1 hub2 minio localhost 127.0.0.1 >/dev/null || exit 1
LB_CFG=$HERE/.tls/$NAME-haproxy.cfg
HAPROXY_DNS=127.0.0.11:53 "$ROOT/deploy/lb/haproxy-cfg.sh" hub1:8443 hub2:8443 > "$LB_CFG"; chmod 644 "$LB_CFG"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$HERE/results/$STAMP
mkdir -p "$OUT"; chmod 1777 results "$OUT"   # the bench runs as uid 10002
ENV_FILE=$HERE/.env.$NAME
DB_PASSWORD=$(openssl rand -hex 16)
if [ "$DB" = yb ]; then
    # Server I connects to node I; the database is the cluster's own.
    DB_URL_1=postgres://yugabyte@yb1:5433/yugabyte DB_URL_2=postgres://yugabyte@yb2:5433/yugabyte
else
    DB_URL_1=postgres://veil:$DB_PASSWORD@postgres:5432/veil DB_URL_2=$DB_URL_1
fi
umask 077
cat > "$ENV_FILE" <<ENV
TAG=$TAG
PG_IMAGE=$PG_IMAGE
YB_IMAGE=$YB_IMAGE
HAPROXY_IMAGE=$HAPROXY_IMAGE
MINIO_IMAGE=$MINIO_IMAGE
DB_PASSWORD=$DB_PASSWORD
DB_URL_1=$DB_URL_1
DB_URL_2=$DB_URL_2
S3_KEY=veilminio
S3_SECRET=$(openssl rand -hex 16)
LB_PORT=${LB_PORT:-18443}
TLS_DIR=$TLS_DIR
LB_CFG=$LB_CFG
RESULTS_DIR=$OUT
DB_CONNECTIONS=${DB_CONNECTIONS:-16}
BENCH_MEM=${BENCH_MEM:-2g}
YB_MEM=${YB_MEM:-2304m}
# Small nodes: one tablet per table (the paid run's 16 GB nodes take three:
# docs/DEPLOY.md §2), memory capped, no YSQL operation lease (a busy machine
# renews it late and YugabyteDB then drops every connection).
YB_TSERVER_FLAGS=${YB_TSERVER_FLAGS:-ysql_num_tablets=1,memory_limit_hard_bytes=1342177280,enable_ysql_operation_lease=false}
YB_MASTER_FLAGS=${YB_MASTER_FLAGS:-memory_limit_hard_bytes=402653184,enforce_tablet_replica_limits=false,enable_ysql_operation_lease=false}
ENV
umask 022
set -a; . "$ENV_FILE"; set +a
export COMPOSE_PROFILES=$DB,bench
C() { D compose -p "$PROJECT" --env-file "$ENV_FILE" "$@"; }

cleanup() {
    for s in hub1 hub2 lb migrate minio $([ "$DB" = yb ] && echo yb1 yb2 yb3 || echo postgres); do
        C logs --no-color "$s" > "$OUT/$s.log" 2>&1 || true
    done
    if [ "${KEEP:-0}" = 1 ]; then
        echo "rehearsal: stack left running; tear down with: COMPOSE_PROFILES=$COMPOSE_PROFILES docker compose -p $PROJECT --env-file $ENV_FILE down -v --remove-orphans"
        return
    fi
    echo "== tearing down $PROJECT (containers, network, volumes)"
    C down -v --remove-orphans --timeout 20 >/dev/null 2>&1 || true
    if D ps -aq --filter "label=com.docker.compose.project=$PROJECT" | grep -q . ||
       D volume ls -q --filter "label=com.docker.compose.project=$PROJECT" | grep -q . ||
       D network ls -q --filter "label=com.docker.compose.project=$PROJECT" | grep -q .; then
        echo "rehearsal: WARNING something of $PROJECT remains (docker ps -a / volume ls / network ls --filter label=com.docker.compose.project=$PROJECT)"
    else echo "   nothing of $PROJECT remains (containers, volumes, networks)"; fi
    rm -f "$ENV_FILE"
}
trap cleanup EXIT
diagnose() { C ps -a; C logs --no-color --tail 30 migrate hub1 hub2 lb 2>&1 | tail -80; }
healthy() { # service: wait until its health check passes
    local id i st=
    id=$(C ps -aq "$1"); for i in $(seq 120); do
        st=$(D inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null || echo gone); [ "$st" = healthy ] && return 0; sleep 1
    done
    echo "rehearsal: $1 is $st"; return 1
}

# 3. Up, in order: the database, the object store, the migrations, the first
# server, the second (with the first's keys), the balancer.
echo "== bringing up $PROJECT (tag $TAG, database $DB, balancer on 127.0.0.1:$LB_PORT)"
t_up=$SECONDS
if [ "$DB" = yb ]; then
    # One node at a time: two yugabyted joining at once fail (one was killed
    # mid-start, 2026-11-12). configure.sh joins them one by one as well.
    for y in 1 2 3; do
        C up -d --wait --wait-timeout 600 "yb$y" || { echo "rehearsal: yb$y did not come up"; diagnose; exit 1; }
        for i in $(seq 90); do n=$(C exec -T yb1 bin/ysqlsh -h yb1 -tAc 'select count(*) from yb_servers()' 2>/dev/null || true); [ "$n" = "$y" ] && break; sleep 2; done
    done
    echo "   YugabyteDB nodes in the cluster: $n"; [ "$n" = 3 ] || { diagnose; exit 1; }
    # yugabyted turns the tablet-replica limit on at every start whatever
    # --master_flags says: lift it on every master (docs/DEPLOY.md §2).
    for i in 1 2 3; do C exec -T "yb$i" bin/yb-ts-cli --server_address="yb$i:7100" set_flag --force enforce_tablet_replica_limits false >/dev/null || echo "   warning: could not lift the tablet limit on yb$i"; done
else
    C up -d --wait --wait-timeout 300 postgres || { echo "rehearsal: postgres did not come up"; diagnose; exit 1; }
fi
C up -d --wait --wait-timeout 120 minio || { echo "rehearsal: minio did not come up"; diagnose; exit 1; }
C run --rm --no-deps -T migrate > "$OUT/migrate-run.log" 2>&1 || { echo "rehearsal: the migrations failed"; tail -20 "$OUT/migrate-run.log"; exit 1; }
C up -d --no-deps hub1 && healthy hub1 || { echo "rehearsal: hub1 did not come up"; diagnose; exit 1; }
C run --rm --no-deps -T hub2-keys || { echo "rehearsal: copying the keys failed"; exit 1; }
C up -d --no-deps hub2 && healthy hub2 || { echo "rehearsal: hub2 did not come up"; diagnose; exit 1; }
C up -d --no-deps lb || { echo "rehearsal: the balancer did not start"; diagnose; exit 1; }
echo "   up in $((SECONDS - t_up)) s"
C ps --format '   {{.Service}}: {{.Status}}'
if [ "$DB" = yb ]; then
    echo "   tablets on yb1: $(C exec -T yb1 bin/ysqlsh -h yb1 -tAc 'select count(*) from yb_local_tablets' 2>/dev/null || echo '?')"
fi
echo "== smoke: the balancer answers HTTPS with the rehearsal certificate"
code=000
for i in $(seq 30); do
    code=$(curl -s --http1.1 -o /dev/null -w '%{http_code}' --max-time 3 --cacert "$TLS_DIR/ca.pem" --resolve "lb:$LB_PORT:127.0.0.1" "https://lb:$LB_PORT/v1/epochs" || echo 000)
    [ "$code" != 000 ] && break; sleep 1
done
echo "   https://lb:$LB_PORT/v1/epochs -> HTTP $code (a 4xx is expected: the route needs a grant)"
case "$code" in 2*|4*) ;; *) echo "rehearsal: unexpected HTTPS answer ($code)"; diagnose; exit 1;; esac

# Run a command with a deadline (a function, so `timeout` cannot wrap it):
# only the process started here is ever killed.
bounded() { # seconds, command...
    local limit=$1; shift
    "$@" & local pid=$! waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge "$limit" ]; then kill "$pid" 2>/dev/null || true; sleep 5; kill -9 "$pid" 2>/dev/null || true; wait "$pid" || true; return 124; fi
        sleep 1; waited=$((waited + 1))
    done
    wait "$pid"
}

# 4. The gates (deploy/gates.sh), each in its own results directory.
URL=https://lb:8443
SERVERS=2
DRY=0
OWN=(--server /usr/local/bin/veil-server --s3-endpoint https://minio:9000)
OWN_BUCKET=veil-rehearsal
# No Spaces bucket here: the `spaces` gate's flow, against the MinIO.
SPACES_OWN=("${OWN[@]}")
SPACES_BUCKET=veil-rehearsal-spaces
DRIVERS=1
record() { cat > "$G_OUT/$1"; }
bench() { # driver|drivers|hub, label, veil-bench arguments...
    local where=$1 label=$2 a args=(); shift 2
    # One driver container; `@D` is driver 1.
    for a in "$@"; do args+=("${a//@D/@1}"); done
    [ "$where" = drivers ] && label=$label@1
    printf 'bench %s veil-bench %s\n' "$label" "${args[*]}" >> "$G_OUT/commands.txt"
    echo "   [$label] veil-bench ${args[*]}"
    bounded "$STEP_LIMIT" C run --rm -T --no-deps bench "${args[@]}" > "$G_OUT/$label.log" 2>&1
}
hub_ctl() { # server number, stop|kill|start
    case $2 in
        stop) C stop -t 30 "hub$1" >/dev/null 2>&1 && echo "   server $1 stopped" ;;
        kill) C kill "hub$1" >/dev/null 2>&1 && echo "   server $1 killed" ;;
        start) C start "hub$1" >/dev/null 2>&1; healthy "hub$1" && echo "   server $1 healthy" ;;
    esac
}
hub_stats() { C kill -s USR1 "hub$1" >/dev/null 2>&1; sleep 1; C exec -T "hub$1" cat /var/lib/veil/stats.json 2>/dev/null || true; }
db_sql() {
    if [ "$DB" = yb ]; then C exec -T yb1 bin/ysqlsh -h yb1 -U yugabyte -d yugabyte -X -q -tA -F'|' -v ON_ERROR_STOP=1
    else C exec -T postgres psql -U veil -d veil -X -q -tA -F'|' -v ON_ERROR_STOP=1; fi
}
status=0; summary=()
for GATE in $GATES; do
    G_OUT=$OUT/$GATE; mkdir -p "$G_OUT"; chmod 1777 "$G_OUT"
    R=/work/results/$GATE
    echo "== gate: $GATE"
    { gate_meta "$COMMIT" "$TAG"; echo "rehearsal=$PROJECT"; } > "$G_OUT/run.txt"
    { echo "DB=$DB"; echo "SERVERS=2"; echo "DRIVERS=1"; echo "BALANCER=haproxy"; grep -E '^(DB_CONNECTIONS|BENCH_MEM|YB_MEM|YB_TSERVER_FLAGS|YB_MASTER_FLAGS|LB_PORT)=' "$ENV_FILE"; } > "$G_OUT/topology.env"
    {
        for img in "veil-server:$TAG" "veil-bench:$TAG"; do echo "$img $(D image inspect -f '{{.Id}}' "$img")"; done
        echo "PG_IMAGE=$PG_IMAGE"; echo "YB_IMAGE=$YB_IMAGE"; echo "HAPROXY_IMAGE=$HAPROXY_IMAGE"; echo "MINIO_IMAGE=$MINIO_IMAGE"
        C ps --format '{{.Service}} {{.Image}}'
    } > "$G_OUT/images.txt"
    t0=$SECONDS
    rc=0; run_gate "$GATE" || rc=$?
    for i in 1 2; do hub_stats "$i" > "$G_OUT/hub$i-stats.json" || true; done
    gate_report "$GATE" "$G_OUT" || rc=1
    if [ $rc = 0 ]; then r=ok; else r="FAIL (exit $rc)"; status=1; fi
    echo "   $GATE: $r in $((SECONDS - t0)) s ($G_OUT)"
    summary+=("$GATE: $r in $((SECONDS - t0)) s")
    for md in "$G_OUT"/*.md; do [ -f "$md" ] && sed 's/^/   /' "$md" || true; done
    grep -hiE 'gate missed|error|panick' "$G_OUT"/*.log 2>/dev/null | head -10 | sed 's/^/   | /' || true
done

echo "== rehearsal summary ($OUT)"
printf '   %s\n' "${summary[@]}"
exit $status
