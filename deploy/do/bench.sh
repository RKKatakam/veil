#!/usr/bin/env bash
# Run one gate against the deployment and fetch its results (docs/DEPLOY.md
# §6; the gates themselves are in deploy/gates.sh, shared with the
# rehearsal). Results land in deploy/results/NAME/<stamp>-<gate>/:
#   run.txt        the commit, the image tag, the gate's settings, the address
#   topology.env   deploy/do/.env's topology, without a single secret
#   images.txt     the image ids on every machine, the pinned third-party digests
#   commands.txt   every veil-bench command line, and on which machine
#   *.json, *.md   the tool's raw results and its tables; LABEL.log its output
#   hub<N>-stats.json, hub<N>-docker-stats.log   each server's counters and samples
#   minio-docker-stats.log   the MinIO storage droplet's samples (VEIL_DO_OBJECTS=minio)
#   scaling.md, failover-verdict.md, failover-*.txt     the gates' own tables and checks
#
#   bench.sh [--approve] GATE [veil-bench flags...]
#
# GATE (deploy/gates.sh): pull land branches api landing scaling failover   (drivers,
#   against the one address)   objects openscion scale   (the first server's machine,
#   with a server the tool starts itself)   spaces   (the same, its server on a
#   Spaces bucket, BUCKET-spaces, with /etc/veil/spaces.env's keys, at a rate
#   under the bucket's limit). Sizes come from the environment
#   (DURATION=20, LANDING_AGENTS=10000, ...: docs/REPRODUCE.md); DRIVER=n picks
#   the driver of a one-driver gate; STEP_LIMIT (default 3600 s) bounds each command.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
GATES_DIR=$DO_ROOT/deploy
. "$GATES_DIR/gates.sh"
GATE=${1:?gate: one of $GATES_ALL}; shift
case " $GATES_ALL " in *" $GATE "*) ;; *) echo "bench: unknown gate '$GATE' (one of: $GATES_ALL)" >&2; exit 2 ;; esac
[ "$GATE" != failover ] || [ "$HUBS" -ge 2 ] || { echo "bench: failover needs VEIL_DO_HUBS=2 or 3 (one server cannot fail over)" >&2; exit 2; }
[ $APPROVED = 1 ] && require_created
# TAG: the one configure.sh saved in the state file, else this commit's.
TAG=${TAG:-$(cd "$DO_ROOT" && git describe --always --dirty --abbrev=8 2>/dev/null || echo dev)}
COMMIT=$(cd "$DO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)
[ -n "$BUCKET" ] || BUCKET="$NAME-objects-DRY"
STEP_LIMIT=${STEP_LIMIT:-3600}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$DO_ROOT/deploy/results/$NAME/$STAMP-$GATE
[ $APPROVED = 1 ] && mkdir -p "$OUT"
DRY=$((1 - APPROVED))
R=/work/results/$STAMP-$GATE
URL=https://$(front_host private):8443
SERVERS=$HUBS
OWN=(--server /usr/local/bin/veil-server --s3-endpoint "$(objects_endpoint)")
OWN_BUCKET=$BUCKET
SPACES_OWN=(--server /usr/local/bin/veil-server --s3-endpoint "$SPACES_ENDPOINT")
SPACES_BUCKET=$BUCKET-spaces
addr() { local v; v=$(ip_of "$1"); echo "${v:-${1}_IP}"; }            # public (a placeholder in a dry run)
paddr() { local v; v=$(priv_of "$1"); echo "${v:-${1}_PRIVATE_IP}"; }  # private
HUB1=$(addr "$NAME-hub")

# VEIL_DATABASE_URL, VEIL_S3_ACCESS_KEY, VEIL_S3_SECRET_KEY and VEIL_S3_CA
# come from /etc/veil/hub.env (the `spaces` gate: /etc/veil/spaces.env)
# through --env-file, never the command line.
BENCH_ENV=/etc/veil/hub.env
bench_cmd() { # veil-bench arguments...
    echo "mkdir -p /srv/bench/results; chown -R 10002:10002 /srv/bench; timeout --kill-after=60 $STEP_LIMIT docker run --rm --network host --env-file $BENCH_ENV -v /srv/bench:/work -v /etc/veil/tls:/tls:ro --ulimit nofile=1048576:1048576 veil-bench:$TAG $(printf '%q ' "$@")"
}
record() { # FILE: stdin kept in this gate's results directory
    if [ $APPROVED = 1 ]; then cat > "$OUT/$1"; else cat >/dev/null; echo "would record $1" >&2; fi
}
bench_on() { # host, label, veil-bench arguments...
    local host=$1 label=$2; shift 2
    printf '%s %s veil-bench %s\n' "$host" "$label" "$*" | record_append
    echo "   [$label on $host] veil-bench $*"
    if [ $APPROVED = 1 ]; then remote "$host" "$(bench_cmd "$@")" > "$OUT/$label.log" 2>&1
    else remote "$host" "$(bench_cmd "$@")"; fi
}
record_append() { if [ $APPROVED = 1 ]; then cat >> "$OUT/commands.txt"; else cat >/dev/null; fi; }
bench() { # driver|drivers|hub|spaces, label, veil-bench arguments...
    local where=$1 label=$2; shift 2
    local n a args pids=() rc=0
    case $where in
        hub) bench_on "$HUB1" "$label" "$@" ;;
        spaces) BENCH_ENV=/etc/veil/spaces.env bench_on "$HUB1" "$label" "$@" ;;
        driver)
            n=${DRIVER:-1}
            bench_on "$(addr "$NAME-driver$n")" "$label" "$@" ;;
        drivers)
            for n in $(seq "$DRIVERS"); do
                args=(); for a in "$@"; do args+=("${a//@D/@$n}"); done
                bench_on "$(addr "$NAME-driver$n")" "$label@$n" "${args[@]}" & pids+=($!)
            done
            for n in "${pids[@]}"; do wait "$n" || rc=1; done
            return $rc ;;
        *) echo "bench: unknown place '$where'" >&2; return 2 ;;
    esac
}
hub_ctl() { # server number, stop|kill|start
    local h; h=$(addr "$(hub_name "$1")")
    case $2 in
        # The image stops on SIGINT (deploy/docker/Dockerfile, STOPSIGNAL).
        stop) remote "$h" "docker stop -t 30 veil-server >/dev/null && echo '   server $1 stopped'" ;;
        # No restart policy while it is down: Docker would bring it back at once.
        kill) remote "$h" "docker update --restart no veil-server >/dev/null && docker kill veil-server >/dev/null && echo '   server $1 killed'" ;;
        start) remote "$h" "docker update --restart unless-stopped veil-server >/dev/null; docker start veil-server >/dev/null; for i in \$(seq 60); do [ \"\$(docker inspect -f '{{.State.Health.Status}}' veil-server)\" = healthy ] && break; sleep 1; done; echo \"   server $1: \$(docker inspect -f '{{.State.Health.Status}}' veil-server)\"" ;;
    esac
}
hub_stats() { # server number
    remote "$(addr "$(hub_name "$1")")" 'docker kill -s USR1 veil-server >/dev/null 2>&1; sleep 1; docker exec veil-server cat /var/lib/veil/stats.json' 2>/dev/null || true
}
db_sql() { # SQL on stdin -> rows, | between columns
    if [ $APPROVED = 0 ]; then cat >/dev/null; fi
    if [ "$YB_NODES" -gt 0 ]; then
        remote_stdin "$(addr "$NAME-yb1")" "docker exec -i yb bin/ysqlsh -h $(paddr "$NAME-yb1") -U yugabyte -d yugabyte -X -q -tA -F'|' -v ON_ERROR_STOP=1"
    else
        remote_stdin "$(addr "$NAME-db")" "docker exec -i pg psql -U veil -d veil -X -q -tA -F'|' -v ON_ERROR_STOP=1"
    fi
}

# What runs where, and the record of it.
HUB_IPS=(); for i in $(seq "$HUBS"); do HUB_IPS+=("$(addr "$(hub_name "$i")")"); done
DRIVER_IPS=(); for i in $(seq "$DRIVERS"); do DRIVER_IPS+=("$(addr "$NAME-driver$i")"); done
{ gate_meta "$COMMIT" "$TAG"; echo "args=$*"; } | record run.txt
topology | record topology.env
{
    echo "# built here (deploy/docker/build.sh), shipped by configure.sh: the ids are the images' config digests,"
    echo "# revision= the commit each was built from (run.txt's commit= is this checkout's now)"
    for img in veil-server veil-bench; do
        echo "local $img:$TAG $(docker image inspect -f '{{.Id}} revision={{index .Config.Labels "org.opencontainers.image.revision"}}' "$img:$TAG" 2>/dev/null || echo missing)"
    done
    echo "# pinned third-party images (deploy/versions.env)"
    echo "PG_IMAGE=$PG_IMAGE"; echo "YB_IMAGE=$YB_IMAGE"; echo "HAPROXY_IMAGE=$HAPROXY_IMAGE"; echo "MINIO_IMAGE=$MINIO_IMAGE"
} | record images.txt
for h in "${HUB_IPS[@]}" "${DRIVER_IPS[@]}"; do
    if [ $APPROVED = 1 ]; then
        remote "$h" "for i in veil-server:$TAG veil-bench:$TAG; do docker image inspect -f \"$h \$i {{.Id}} revision={{index .Config.Labels \\\"org.opencontainers.image.revision\\\"}}\" \$i 2>/dev/null; done; docker ps --format '$h running {{.Names}} {{.Image}}'" >> "$OUT/images.txt" 2>/dev/null || true
    else remote "$h" "docker image inspect veil-server:$TAG veil-bench:$TAG; docker ps"; fi
done

# Metrics on every server (and the MinIO droplet) while the gate runs:
# docker stats every 5 s.
SAMPLED=("${HUB_IPS[@]}"); [ "$OBJECTS" = minio ] && SAMPLED+=("$(addr "$NAME-minio")")
for h in "${SAMPLED[@]}"; do
    remote "$h" "mkdir -p /srv/metrics; rm -f /srv/metrics/$STAMP-$GATE.stats; nohup sh -c 'while true; do echo \"\$(date -u +%FT%TZ) \$(docker stats --no-stream --format \"{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}} net={{.NetIO}} blk={{.BlockIO}}\" | tr \"\\n\" \";\")\"; sleep 5; done' > /srv/metrics/$STAMP-$GATE.stats 2>/dev/null & echo \$! > /srv/metrics/$STAMP-$GATE.pid"
done

echo "== $GATE against $URL ($HUBS server(s), $DRIVERS driver(s)), limit ${STEP_LIMIT}s per command"
rc=0
run_gate "$GATE" "$@" || rc=$?

for i in $(seq "${#SAMPLED[@]}"); do
    h=${SAMPLED[$((i - 1))]}; label=hub$i; [ "$i" -gt "$HUBS" ] && label=minio
    if [ $APPROVED = 1 ]; then
        [ "$label" = minio ] || hub_stats "$i" > "$OUT/hub$i-stats.json" || true
        remote "$h" "kill \$(cat /srv/metrics/$STAMP-$GATE.pid) 2>/dev/null" || true
    else [ "$label" = minio ] || hub_stats "$i"; remote "$h" "kill \$(cat /srv/metrics/$STAMP-$GATE.pid)"; fi
    copy_from "$h" "/srv/metrics/$STAMP-$GATE.stats" "$OUT/$label-docker-stats.log" || true
done
case $GATE in objects|openscion|scale|spaces) SRC=("$HUB1") ;; *) SRC=("${DRIVER_IPS[@]}") ;; esac
for h in "${SRC[@]}"; do
    if [ $APPROVED = 1 ]; then
        remote "$h" "test -d /srv/bench/results/$STAMP-$GATE" 2>/dev/null && copy_from "$h" "/srv/bench/results/$STAMP-$GATE/." "$OUT/" || true
    else copy_from "$h" "/srv/bench/results/$STAMP-$GATE/." "$OUT/"; fi
done
if [ $APPROVED = 1 ]; then
    for md in "$OUT"/*.md; do [ -f "$md" ] && cat "$md" || true; done
    gate_report "$GATE" "$OUT" || rc=1
    echo "== results in $OUT (exit $rc; non-zero: a missed gate or an error, see the *.log files)"
fi
exit $rc
