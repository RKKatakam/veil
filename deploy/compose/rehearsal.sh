#!/usr/bin/env bash
# The local rehearsal of the DigitalOcean test (docs/DEPLOY.md, "Local
# rehearsal"): build the images, bring the Compose stack up (PostgreSQL and
# MinIO standing in for the database droplet and Spaces), run a short
# version of every gate benchmark through it, print the tables, tear
# everything down (containers, networks and volumes of this run only).
#
#   deploy/compose/rehearsal.sh [NAME]      # NAME distinguishes concurrent runs (default: the user)
#
# Environment:
#   SKIP_BUILD=1   use the images already built for TAG (deploy/docker/build.sh)
#   TAG=…          the image tag (default: this commit's, as build.sh names it)
#   KEEP=1         leave the stack running (tear down later with `… down -v`, printed at the end)
#   CACHE=0        no regional cache container (to measure the server's costs without its polling)
#   GATES="pull land …"   a subset of: pull land branches api objects openscion scale
#   DURATION=5     seconds measured per load point (the real gates use 20 or more)
#   HUB_PORT, CACHE_PORT   host ports (defaults 18443, 18444; pick free ones on a shared machine)
#
# Results: deploy/compose/results/<stamp>/ (JSON and Markdown per gate,
# server and cache logs). Everything else this script writes lives under
# deploy/compose/.tls, deploy/compose/.env.<name> and the worktree's .scratch/.
set -uo pipefail
cd "$(dirname "$0")"
HERE=$PWD
ROOT=$(cd ../.. && pwd)
NAME=${1:-${USER:-rehearsal}}
PROJECT=veil-rehearsal-$NAME
DURATION=${DURATION:-10}
GATES=${GATES:-pull land branches api objects openscion scale}
STEP_LIMIT=${STEP_LIMIT:-1200}
mkdir -p "$ROOT/.scratch/tmp" results
export TMPDIR=$ROOT/.scratch/tmp

D() { if docker info >/dev/null 2>&1; then docker "$@"; else sg docker -c "docker $(printf '%q ' "$@")"; fi; }

# 1. Images (TAG: this commit's, or "dev" outside a git checkout).
export TAG=${TAG:-$(cd "$ROOT" && git describe --always --dirty --abbrev=8 2>/dev/null || echo dev)}
if [ "${SKIP_BUILD:-0}" != 1 ]; then
    "$ROOT/deploy/docker/build.sh" || { echo "rehearsal: the image build failed"; exit 1; }
fi

# 2. Certificates and secrets for this run (never committed; see .gitignore).
TLS_DIR=$HERE/.tls/$NAME
"$ROOT/deploy/tls/mkcert.sh" "$TLS_DIR" veil-server veil-cache localhost 127.0.0.1 || exit 1
ENV_FILE=$HERE/.env.$NAME
umask 077
cat > "$ENV_FILE" <<ENV
TAG=$TAG
DB_PASSWORD=$(openssl rand -hex 16)
S3_KEY=veilminio
S3_SECRET=$(openssl rand -hex 16)
HUB_PORT=${HUB_PORT:-18443}
CACHE_PORT=${CACHE_PORT:-18444}
TLS_DIR=$TLS_DIR
ENV
umask 022
set -a; . "$ENV_FILE"; set +a
C() { D compose -p "$PROJECT" --env-file "$ENV_FILE" "$@"; }

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$HERE/results/$STAMP
mkdir -p "$OUT"; chmod 1777 results "$OUT"   # the bench runs as uid 10002
cleanup() {
    C logs --no-color veil-server > "$OUT/veil-server.log" 2>&1 || true
    C logs --no-color veil-cache > "$OUT/veil-cache.log" 2>&1 || true
    if [ "${KEEP:-0}" = 1 ]; then
        echo "rehearsal: stack left running; tear down with: docker compose -p $PROJECT --env-file $ENV_FILE down -v --remove-orphans"
        return
    else
        echo "== tearing down $PROJECT (containers, network, volumes)"
        C down -v --remove-orphans --timeout 20 >/dev/null 2>&1
        D volume ls -q --filter "label=com.docker.compose.project=$PROJECT" | grep -q . && echo "rehearsal: WARNING volumes remain" || echo "   nothing of $PROJECT remains"
    fi
    rm -f "$ENV_FILE"
}
trap cleanup EXIT

# 3. Up, then wait for health (the server's health check: HTTPS answers).
echo "== bringing up $PROJECT (tag $TAG, hub on 127.0.0.1:$HUB_PORT)"
diagnose() { # everything a failed start can say
    C ps -a; C logs --no-color --tail 40 migrate veil-server veil-cache
    for svc in veil-server veil-cache; do
        id=$(C ps -aq "$svc" 2>/dev/null | head -1); [ -n "$id" ] && D inspect -f "   $svc health: {{.State.Status}} {{if .State.Health}}{{.State.Health.Status}} {{range .State.Health.Log}}| exit {{.ExitCode}}: {{.Output}}{{end}}{{end}}" "$id"
    done
}
if ! C up -d --wait --wait-timeout 300 postgres minio migrate veil-server; then
    echo "rehearsal: the stack did not come up"; diagnose; exit 1
fi
if [ "${CACHE:-1}" = 1 ]; then C up -d veil-cache || { echo "rehearsal: the cache did not start"; diagnose; exit 1; }; fi
C ps
echo "== smoke: the server and the cache answer HTTPS with the rehearsal certificate"
for p in $HUB_PORT $([ "${CACHE:-1}" = 1 ] && echo "$CACHE_PORT"); do
    code=000
    for i in $(seq 30); do
        code=$(curl -s --http1.1 -o /dev/null -w '%{http_code}' --max-time 3 --cacert "$TLS_DIR/ca.pem" --resolve "veil-server:$p:127.0.0.1" "https://veil-server:$p/v1/epochs")
        [ "$code" != 000 ] && break; sleep 1
    done
    echo "   :$p /v1/epochs -> HTTP $code (a 4xx is expected: the route needs a grant)"
    case "$code" in 000) echo "rehearsal: no HTTPS answer on :$p"; diagnose; exit 1;; esac
done
diagnose | grep "health:"

# Run a command with a deadline (a function, so `timeout` cannot wrap it):
# only the process started here is ever killed.
bounded() { # seconds, command...
    local limit=$1; shift
    "$@" & local pid=$! waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge "$limit" ]; then kill "$pid" 2>/dev/null; sleep 5; kill -9 "$pid" 2>/dev/null; wait "$pid"; return 124; fi
        sleep 1; waited=$((waited + 1))
    done
    wait "$pid"
}

# 4. The gates, short. Each is bounded; a missed gate is reported, not fatal.
DB_URL=postgres://veil:$DB_PASSWORD@postgres:5432/veil
LOAD=(load --url https://veil-server:8443 --ca /tls/ca.pem --database-url "$DB_URL" --duration "$DURATION" --warmup 1)
OWN=(--server /usr/local/bin/veil-server --database-url "$DB_URL" --s3-endpoint http://minio:9000)
status=0; summary=()
gate() { # name, veil-bench arguments...
    local name=$1; shift
    echo "== gate: $name"
    local t0=$SECONDS
    if bounded "$STEP_LIMIT" C run --rm -T --no-deps bench "$@" > "$OUT/$name.log" 2>&1; then r=ok; else
        r="FAIL (exit $?; 124 is the ${STEP_LIMIT}s limit)"; status=1
        { echo "--- after the failure:"; C ps; C logs --no-color --tail 20 veil-server; } >> "$OUT/$name.log" 2>&1
    fi
    echo "   $r in $((SECONDS - t0))s  ($OUT/$name.log)"
    summary+=("$name: $r")
    for md in "$OUT/$name"*.md; do [ -f "$md" ] && sed 's/^/   /' "$md"; done
    grep -iE 'gate|missed|error|after the failure|veil-server-1' "$OUT/$name.log" | head -20 | sed 's/^/   | /'
}
R=/work/results/$STAMP
for g in $GATES; do
    case $g in
        pull)      gate pull      "${LOAD[@]}" --mode pull --projects 1 --clients 10,50 --background 2 --dir /work/pull --out "$R/pull.json" ;;
        land)      gate land      "${LOAD[@]}" --mode land --projects 1,10 --clients 1 --rates max --dir /work/land --out "$R/land.json" ;;
        branches)  gate branches  "${LOAD[@]}" --mode branches --projects 1 --clients 1,10 --rates max --dir /work/branches --out "$R/branches.json" ;;
        api)       gate api       "${LOAD[@]}" --mode api --projects 1,10 --clients 1 --rates max --dir /work/api --out "$R/api.json" ;;
        # The regional-cache gate needs a server the tool starts itself (BUG-1591).
        objects)   gate objects   load "${OWN[@]}" --s3-bucket veil-rehearsal-objects --mode objects --via server,cache --projects 1 --clients 10 --duration "$DURATION" --warmup 1 --dir /work/objects --out "$R/objects.json" ;;
        openscion) gate openscion openscion --vl /usr/local/bin/vl "${OWN[@]}" --s3-bucket veil-rehearsal-openscion --files 1000 --runs 1 --dir /work/openscion --out "$R/openscion.json" ;;
        scale)     gate scale     run --profile tiny --runs 1 --vl /usr/local/bin/vl "${OWN[@]}" --s3-bucket veil-rehearsal-scale --dir /work/scale --out "$R/scale-tiny.json" --skip-phase import,local,remote-path,packed,sftp,agents ;;
        *) echo "rehearsal: unknown gate $g"; status=1 ;;
    esac
done

echo "== rehearsal summary ($OUT)"
printf '   %s\n' "${summary[@]}"
exit $status
