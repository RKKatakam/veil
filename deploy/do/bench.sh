#!/usr/bin/env bash
# Run one gate benchmark against the deployment and fetch its results
# (docs/DEPLOY.md, "Run the gates"). Results land in
# deploy/results/NAME/<stamp>-<gate>/ (JSON, Markdown, the driver's log, the
# hub's docker stats samples and the server's counters).
#
#   bench.sh [--approve] GATE [veil-bench flags...]
#
# GATE and where it runs:
#   pull | land | branches | api     a driver (round-robin), against the running server
#   objects                           the hub, with a server and a regional cache the
#                                     tool starts itself (BUG-1591), against the same database and bucket
#   openscion | scale                 the hub, with a server the tool starts itself (as scripts/bench-server.sh)
#   DRIVER=n picks the driver; DURATION (default 20) seconds per point; STEP_LIMIT (default 3600).
set -euo pipefail
. "$(dirname "$0")/lib.sh"
GATE=${1:?gate: pull|land|branches|api|objects|openscion|scale}; shift
[ $APPROVED = 1 ] && require_created
# TAG: the one configure.sh saved in the state file, else this commit's.
TAG=${TAG:-$(cd "$DO_ROOT" && git describe --always --dirty --abbrev=8 2>/dev/null || echo dev)}
[ -n "$BUCKET" ] || BUCKET="$NAME-objects-DRY"
DURATION=${DURATION:-20}; STEP_LIMIT=${STEP_LIMIT:-3600}
HUB=$(ip_of "$NAME-hub"); HUB=${HUB:-HUB_IP}; HUB_PRIV=$(priv_of "$NAME-hub"); HUB_PRIV=${HUB_PRIV:-HUB_PRIVATE_IP}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$DO_ROOT/deploy/results/$NAME/$STAMP-$GATE
[ $APPROVED = 1 ] && mkdir -p "$OUT"
R=/work/results/$STAMP-$GATE

# VEIL_DATABASE_URL, VEIL_S3_ACCESS_KEY and VEIL_S3_SECRET_KEY come from
# /etc/veil/hub.env (--env-file), never the command line.
LOAD=(load --url "https://$HUB_PRIV:8443" --ca /tls/ca.pem --duration "$DURATION" --warmup 3)
OWN=(--server /usr/local/bin/veil-server --s3-endpoint "$SPACES_ENDPOINT")
case $GATE in
    pull)      WHERE=driver; ARGS=("${LOAD[@]}" --mode pull --projects 1 --clients 10,100,1000 --background 20 --dir /work/pull --out "$R/pull.json") ;;
    land)      WHERE=driver; ARGS=("${LOAD[@]}" --mode land --projects 1,10,100 --clients 1,50 --rates max --dir /work/land --out "$R/land.json") ;;
    branches)  WHERE=driver; ARGS=("${LOAD[@]}" --mode branches --projects 1 --clients 1,10,100 --rates max --dir /work/branches --out "$R/branches.json") ;;
    api)       WHERE=driver; ARGS=("${LOAD[@]}" --mode api --projects 1,10,100 --clients 1,50 --rates max --dir /work/api --out "$R/api.json") ;;
    objects)   WHERE=hub; ARGS=(load "${OWN[@]}" --s3-bucket "$BUCKET-objects" --mode objects --via server,cache --projects 1 --clients 10,100,1000 --background 20 --duration "$DURATION" --dir /work/objects --out "$R/objects.json") ;;
    openscion) WHERE=hub; ARGS=(openscion --vl /usr/local/bin/vl "${OWN[@]}" --s3-bucket "$BUCKET-openscion" --files 1000,10000 --runs 5 --dir /work/openscion --out "$R/openscion.json") ;;
    scale)     WHERE=hub; ARGS=(run --profile 1g --vl /usr/local/bin/vl "${OWN[@]}" --s3-bucket "$BUCKET-scale" --dir /work/scale --out "$R/scale-1g.json" --skip-phase import,local,remote-path,packed,sftp,agents) ;;
    *) echo "bench: unknown gate $GATE" >&2; exit 2 ;;
esac
ARGS+=("$@")
if [ $WHERE = driver ]; then
    n=${DRIVER:-$(( ($(date +%s) % DRIVERS) + 1 ))}
    HOST=$(ip_of "$NAME-driver$n"); HOST=${HOST:-DRIVER${n}_IP}
else HOST=$HUB; fi

# Metrics on the hub while the gate runs: docker stats every 5 s, the
# server's request-path counters (SIGUSR1 -> stats.json) at the end.
remote "$HUB" "rm -f /srv/metrics/$STAMP-$GATE.stats; nohup sh -c 'while true; do echo \"\$(date -u +%FT%TZ) \$(docker stats --no-stream --format \"{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}} net={{.NetIO}} blk={{.BlockIO}}\" | tr \"\\n\" \";\")\"; sleep 5; done' > /srv/metrics/$STAMP-$GATE.stats 2>/dev/null & echo \$! > /srv/metrics/$STAMP-$GATE.pid"

echo "== $GATE on $WHERE ($HOST), $DURATION s per point, limit ${STEP_LIMIT}s"
echo "   veil-bench ${ARGS[*]}"
rc=0
BENCH_CMD="mkdir -p /srv/bench/results; chown -R 10002:10002 /srv/bench; timeout --kill-after=60 $STEP_LIMIT docker run --rm --network host --env-file /etc/veil/hub.env -v /srv/bench:/work -v /etc/veil/tls:/tls:ro --ulimit nofile=1048576:1048576 veil-bench:$TAG $(printf '%q ' "${ARGS[@]}")"
STATS_CMD="kill \$(cat /srv/metrics/$STAMP-$GATE.pid) 2>/dev/null; docker kill -s USR1 veil-server >/dev/null 2>&1; sleep 1; docker exec veil-server cat /var/lib/veil/stats.json"
if [ $APPROVED = 1 ]; then
    remote "$HOST" "$BENCH_CMD" 2>&1 | tee "$OUT/driver.log" || rc=$?
    remote "$HUB" "$STATS_CMD" > "$OUT/server-stats.json" 2>/dev/null || true
else
    remote "$HOST" "$BENCH_CMD"
    remote "$HUB" "$STATS_CMD"
fi
copy_from "$HOST" "/srv/bench/results/$STAMP-$GATE/." "$OUT/"
copy_from "$HUB" "/srv/metrics/$STAMP-$GATE.stats" "$OUT/hub-docker-stats.log"
if [ $APPROVED = 1 ]; then
    echo "== results in $OUT (exit $rc; a non-zero exit means a missed gate or an error: see driver.log)"
    for md in "$OUT"/*.md; do [ -f "$md" ] && cat "$md" || true; done
fi
exit $rc
