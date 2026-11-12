# The gates of the multi-machine test, written once (docs/DEPLOY.md, "The
# gates"; docs/REPRODUCE.md). Sourced by deploy/do/bench.sh (the paid run)
# and deploy/compose/rehearsal.sh (the free rehearsal): the same commands,
# the same checks, sizes apart.
#
# The script that sources this file sets
#   URL      the one address the agents use (the balancer's, or the server's)
#   R        the results directory as the benchmark's container sees it
#   OWN      (array) how the tool starts a server of its own: --server … --s3-endpoint …
#   OWN_BUCKET   the prefix of the buckets of those servers
#   SERVERS  how many servers run behind URL
#   DRY      1 in a dry run: every step is printed, nothing is waited for
# and defines
#   bench WHERE LABEL ARGS…   run `veil-bench ARGS…` on a driver or on the first
#                             server (WHERE: driver | hub), its output to LABEL.log,
#                             its command line recorded; its exit status returned
#   hub_ctl N stop|kill|start    stop server N gracefully, kill it, or start it and wait until it answers
#   hub_stats N               server N's counters (its stats.json) on stdout
#   db_sql                    run the SQL on stdin in the deployment's database; rows on stdout, columns split by |
#   record FILE               keep stdin as FILE in this gate's results directory
#
# Sizes: the defaults are the paid run's. The rehearsal sets small ones.
: "${DURATION:=20}" "${WARMUP:=3}"
: "${PULL_CLIENTS:=10,100,1000}" "${PULL_BACKGROUND:=20}"
: "${LAND_PROJECTS:=1,10,100}" "${LAND_CLIENTS:=1,50}"
: "${BRANCH_CLIENTS:=1,10,100}"
: "${OBJECT_CLIENTS:=10,100,1000}"
: "${OPENSCION_FILES:=1000,10000}" "${OPENSCION_RUNS:=5}" "${SCALE_PROFILE:=1g}"
# landing: 10,000 agents of 100 people into one `main`, 1,000 landings a second offered.
: "${LANDING_AGENTS:=10000}" "${LANDING_PEOPLE:=100}" "${LANDING_RATE:=1000}"
: "${LANDING_DURATIONS:=180 600}" "${LANDING_VARIANTS:=plain protected mix}"
# branches, the headline: agents on branches of their own, merging into `main` every Nth push.
: "${HEADLINE_AGENTS:=300,1000,3000}" "${MERGE_EVERY:=5}" "${HEADLINE_DURATION:=120}"
# scaling: the same three curves with 1, 2 and 3 servers running.
: "${SCALING_SERVERS:=1 2 3}" "${SCALING_DURATION:=60}"
: "${SCALING_PULL_CLIENTS:=1000}" "${SCALING_BRANCH_CLIENTS:=1000}"
: "${SCALING_LANDING_PROJECTS:=100}" "${SCALING_LANDING_CLIENTS:=1000}"
# failover: a landing run during which the server that holds `main`'s lease goes away.
: "${FAILOVER_AGENTS:=1000}" "${FAILOVER_PEOPLE:=100}" "${FAILOVER_RATE:=300}"
: "${FAILOVER_DURATION:=120}" "${FAILOVER_AFTER:=45}" "${FAILOVER_HOW:=kill}" "${FAILOVER_SETTLE:=120}"

GATES_ALL="pull land branches api landing scaling failover objects openscion scale"

# The landing queue keeps a finished ticket for an hour: the failover
# check reads it, so it runs at once.
db_one() { db_sql | head -1; }
db_now_us() { echo "select (extract(epoch from clock_timestamp()) * 1000000)::bigint" | db_one; }
stat_of() { python3 -c 'import json,sys
try: print(int(json.load(sys.stdin).get(sys.argv[1], 0)))
except Exception: print(0)' "$1"; }
pause() { [ "$DRY" = 1 ] || sleep "$1"; }

# run_gate GATE [extra veil-bench flags…]: 0 when every run of the gate
# passed, 1 when one failed or missed a gate of the tool's.
run_gate() {
    local gate=$1 rc=0; shift
    local load=(load --url "$URL" --ca /tls/ca.pem --warmup "$WARMUP")
    case $gate in
        pull)
            bench driver pull "${load[@]}" --duration "$DURATION" --mode pull --projects 1 --clients "$PULL_CLIENTS" --background "$PULL_BACKGROUND" --dir /work/pull --out "$R/pull.json" "$@" || rc=1 ;;
        land)
            bench driver land "${load[@]}" --duration "$DURATION" --mode land --projects "$LAND_PROJECTS" --clients "$LAND_CLIENTS" --rates max --dir /work/land --out "$R/land.json" "$@" || rc=1 ;;
        api)
            bench driver api "${load[@]}" --duration "$DURATION" --mode api --projects "$LAND_PROJECTS" --clients "$LAND_CLIENTS" --rates max --dir /work/api --out "$R/api.json" "$@" || rc=1 ;;
        branches)
            # The cost curve as it was (a push to a branch of one's own), then the
            # headline: many agents, each on its branch, merging into `main`.
            bench driver branches "${load[@]}" --duration "$DURATION" --mode branches --projects 1 --clients "$BRANCH_CLIENTS" --rates max --dir /work/branches --out "$R/branches.json" "$@" || rc=1
            bench driver branches-merge "${load[@]}" --duration "$HEADLINE_DURATION" --mode branches --projects 1 --clients "$HEADLINE_AGENTS" --rates max --merge-every "$MERGE_EVERY" --dir /work/branches-merge --out "$R/branches-merge.json" "$@" || rc=1 ;;
        landing)
            local d v flags
            for d in $LANDING_DURATIONS; do
                for v in $LANDING_VARIANTS; do
                    case $v in
                        plain) flags=() ;;
                        protected) flags=(--protected) ;;
                        mix) flags=(--protected --mix) ;;
                        *) echo "gates: unknown landing variant '$v' (plain, protected, mix)" >&2; return 2 ;;
                    esac
                    bench driver "landing-$v-${d}s" "${load[@]}" --duration "$d" --mode landing --projects 1 --clients "$LANDING_AGENTS" --people "$LANDING_PEOPLE" --rates "$LANDING_RATE" "${flags[@]+"${flags[@]}"}" --dir /work/landing --out "$R/landing-$v-${d}s.json" "$@" || rc=1
                done
            done ;;
        scaling) gate_scaling "$@" || rc=1 ;;
        failover) gate_failover "$@" || rc=1 ;;
        # The three gates below start a server of their own beside the
        # deployment's, on the first server's machine (BUG-1591 for the cache).
        objects)
            bench hub objects load "${OWN[@]}" --s3-bucket "$OWN_BUCKET-objects" --mode objects --via server,cache --projects 1 --clients "$OBJECT_CLIENTS" --background "$PULL_BACKGROUND" --duration "$DURATION" --warmup "$WARMUP" --dir /work/objects --out "$R/objects.json" "$@" || rc=1 ;;
        openscion)
            bench hub openscion openscion --vl /usr/local/bin/vl "${OWN[@]}" --s3-bucket "$OWN_BUCKET-openscion" --files "$OPENSCION_FILES" --runs "$OPENSCION_RUNS" --dir /work/openscion --out "$R/openscion.json" "$@" || rc=1 ;;
        scale)
            bench hub scale run --profile "$SCALE_PROFILE" --vl /usr/local/bin/vl "${OWN[@]}" --s3-bucket "$OWN_BUCKET-scale" --dir /work/scale --out "$R/scale-$SCALE_PROFILE.json" --skip-phase import,local,remote-path,packed,sftp,agents "$@" || rc=1 ;;
        *) echo "gates: unknown gate '$gate' (one of: $GATES_ALL)" >&2; return 2 ;;
    esac
    return $rc
}

# scaling: does throughput rise with servers? The pull, the push to a
# branch of one's own and the landing across projects, each with 1, 2 and
# 3 servers running behind the one address. A server out of the count is
# stopped (the balancer's health check takes it out of rotation), and all
# are started again at the end. deploy/scaling-table.py makes the table.
gate_scaling() {
    local n i rc=0 load=(load --url "$URL" --ca /tls/ca.pem --warmup "$WARMUP" --duration "$SCALING_DURATION")
    for n in $SCALING_SERVERS; do
        [ "$n" -le "$SERVERS" ] || { echo "   scaling: skipping $n servers (the deployment has $SERVERS)"; continue; }
        echo "   scaling: $n of $SERVERS servers running"
        for i in $(seq "$SERVERS"); do if [ "$i" -le "$n" ]; then hub_ctl "$i" start; else hub_ctl "$i" stop; fi; done
        pause 5   # two failed health checks, a second apart, take a stopped server out
        bench driver "scaling-${n}servers-pull" "${load[@]}" --mode pull --projects 1 --clients "$SCALING_PULL_CLIENTS" --background "$PULL_BACKGROUND" --dir /work/scaling --out "$R/scaling-${n}servers-pull.json" "$@" || rc=1
        bench driver "scaling-${n}servers-branches" "${load[@]}" --mode branches --projects 1 --clients "$SCALING_BRANCH_CLIENTS" --rates max --dir /work/scaling --out "$R/scaling-${n}servers-branches.json" "$@" || rc=1
        bench driver "scaling-${n}servers-landing" "${load[@]}" --mode landing --projects "$SCALING_LANDING_PROJECTS" --clients "$SCALING_LANDING_CLIENTS" --people "$LANDING_PEOPLE" --rates max --dir /work/scaling --out "$R/scaling-${n}servers-landing.json" "$@" || rc=1
    done
    for i in $(seq "$SERVERS"); do hub_ctl "$i" start; done
    return $rc
}

# failover: agents land into one `main` at a steady rate; part-way the
# server that holds `main`'s landing lease is killed (FAILOVER_HOW=stop: a
# graceful stop). Shown from the database and the tool's results: another
# server took the lease, how long no landing committed, and every change
# landed exactly once (deploy/checks/failover.sql has the queries and
# what each proves).
gate_failover() {
    local i rc=0 pid t0 holder=0 best=0 a b before after
    [ "$SERVERS" -ge 2 ] || { echo "gates: failover needs at least two servers behind one address (VEIL_DO_HUBS=2 or 3)" >&2; return 2; }
    t0=$(db_now_us)
    bench driver failover load --url "$URL" --ca /tls/ca.pem --warmup "$WARMUP" --duration "$FAILOVER_DURATION" --mode landing --projects 1 --clients "$FAILOVER_AGENTS" --people "$FAILOVER_PEOPLE" --rates "$FAILOVER_RATE" --dir /work/failover --out "$R/failover.json" "$@" &
    pid=$!
    pause "$FAILOVER_AFTER"
    # The holder is the one server whose landing batches are counting up.
    declare -A first
    for i in $(seq "$SERVERS"); do first[$i]=$(hub_stats "$i" | stat_of landing_batches); done
    pause 3
    for i in $(seq "$SERVERS"); do
        a=${first[$i]:-0}; b=$(hub_stats "$i" | stat_of landing_batches)
        echo "   server $i: landing batches $a -> $b in 3 s"
        if [ $((b - a)) -gt "$best" ]; then best=$((b - a)); holder=$i; fi
    done
    if [ "$DRY" = 1 ]; then holder=1
    elif [ "$holder" = 0 ]; then
        echo "   failover: no server ran a landing batch in 3 s: nothing to fail over (is the load running? see failover.log)" >&2
        wait "$pid" || true; return 1
    fi
    before=$(sed "s/:T0/${t0:-0}/g" "$GATES_DIR/checks/failover-lease.sql" | db_one)
    echo "   failover: server $holder holds the lease ($before); $FAILOVER_HOW it"
    { echo "t0_us=$t0"; echo "holder_server=$holder"; echo "how=$FAILOVER_HOW"; echo "lease_before=$before"; echo "stopped_at_us=$(db_now_us)"; } | record failover-run.txt
    hub_ctl "$holder" "$FAILOVER_HOW"
    wait "$pid" || rc=1
    # Tickets the dead server had accepted are still in the queue: the
    # server that took the lease lands them. Wait until none is left.
    for i in $(seq $((FAILOVER_SETTLE / 2))); do
        a=$(sed "s/:T0/${t0:-0}/g" "$GATES_DIR/checks/failover-unfinished.sql" | db_one)
        [ "${a:-0}" = 0 ] && break; pause 2; [ "$DRY" = 1 ] && break
    done
    after=$(sed "s/:T0/${t0:-0}/g" "$GATES_DIR/checks/failover-lease.sql" | db_one)
    sed "s/:T0/${t0:-0}/g" "$GATES_DIR/checks/failover.sql" | db_sql | record failover-check.txt
    { echo "lease_after=$after"; echo "unfinished_after_settling=${a:-}"; } | record failover-after.txt
    hub_ctl "$holder" start
    return $rc
}

# What every result directory records beside the tool's JSON (docs/DEPLOY.md,
# "Results"): `meta_header COMMIT TAG` prints the head of run.txt; the caller
# adds its topology and image ids.
meta_header() {
    echo "gate=$GATE"
    echo "date_utc=$(date -u +%FT%TZ)"
    echo "commit=$1"
    echo "image_tag=$2"
    echo "url=$URL"
    echo "servers=$SERVERS"
    local v
    for v in DURATION WARMUP PULL_CLIENTS PULL_BACKGROUND LAND_PROJECTS LAND_CLIENTS BRANCH_CLIENTS OBJECT_CLIENTS OPENSCION_FILES OPENSCION_RUNS SCALE_PROFILE \
        LANDING_AGENTS LANDING_PEOPLE LANDING_RATE LANDING_DURATIONS LANDING_VARIANTS HEADLINE_AGENTS MERGE_EVERY HEADLINE_DURATION \
        SCALING_SERVERS SCALING_DURATION SCALING_PULL_CLIENTS SCALING_BRANCH_CLIENTS SCALING_LANDING_PROJECTS SCALING_LANDING_CLIENTS \
        FAILOVER_AGENTS FAILOVER_PEOPLE FAILOVER_RATE FAILOVER_DURATION FAILOVER_AFTER FAILOVER_HOW; do
        echo "$v=${!v}"
    done
}
# After the results are on the operator's machine: the tables made from them.
gate_report() { # GATE, results directory
    case $1 in
        scaling) python3 "$GATES_DIR/scaling-table.py" "$2" > "$2/scaling.md" && cat "$2/scaling.md" ;;
        failover) python3 "$GATES_DIR/checks/failover-verdict.py" "$2" | tee "$2/failover.md"; return "${PIPESTATUS[0]}" ;;
    esac
}
