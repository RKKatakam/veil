# The gates of the multi-machine test, written once (docs/DEPLOY.md §6;
# docs/REPRODUCE.md). Sourced by deploy/do/bench.sh (the paid run) and
# deploy/compose/rehearsal.sh (the free rehearsal): the same commands and
# the same checks; only the sizes differ.
#
# The script that sources this file sets
#   URL          the one address the agents use (the balancer's, or the only server's)
#   R            this gate's results directory as the benchmark's container sees it
#   OWN          (array) how the tool starts a server of its own: --server … --s3-endpoint …
#   OWN_BUCKET   the prefix of those servers' buckets
#   SPACES_OWN   (array) the same for the `spaces` gate's server: its object store is
#                a DigitalOcean Spaces endpoint (the rehearsal: its MinIO)
#   SPACES_BUCKET  that server's bucket
#   SERVERS      how many servers run behind URL
#   DRY          1 in a dry run: every step is printed, nothing is waited for
# and defines
#   bench WHERE LABEL ARGS…   run `veil-bench ARGS…`, its output to LABEL.log and its
#                             command line to commands.txt; returns its exit status.
#                             WHERE: driver (one driver), drivers (every driver at
#                             once; `@D` in ARGS becomes the driver's number), hub
#                             (the first server's machine), spaces (the same, with
#                             the Spaces keys)
#   hub_ctl N stop|kill|start   stop server N (SIGINT, graceful), kill it (SIGKILL),
#                               or start it and wait until it is healthy
#   hub_stats N               server N's counters (its stats.json) on stdout
#   db_sql                    run the SQL on stdin in the deployment's database;
#                             rows on stdout, columns split by |
#   record FILE               keep stdin as FILE in this gate's results directory
GATES_DIR=${GATES_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}

# Sizes: the defaults are the paid run's (docs/REPRODUCE.md lists them).
# The rehearsal sets small ones.
: "${DURATION:=20}" "${WARMUP:=3}"
: "${PULL_CLIENTS:=10,100,1000}" "${PULL_BACKGROUND:=20}"
: "${LAND_PROJECTS:=1,10,100}" "${LAND_CLIENTS:=1,50}"
: "${BRANCH_CLIENTS:=1,10,100}"
: "${OBJECT_CLIENTS:=10,100,1000}"
: "${OPENSCION_FILES:=1000,10000}" "${OPENSCION_RUNS:=5}" "${SCALE_PROFILE:=1g}" "${SCALE_RUNS:=3}"
# landing: 10,000 agents of 100 people into one `main`, 1,000 landings a second offered.
: "${LANDING_AGENTS:=10000}" "${LANDING_PEOPLE:=100}" "${LANDING_RATE:=1000}"
: "${LANDING_DURATIONS:=180 600}" "${LANDING_VARIANTS:=plain protected mix}"
# branches, the headline: agents each on a branch of their own, landing it
# on `main` (through the landing service) after every MERGE_EVERY-th push.
: "${HEADLINE_AGENTS:=300,1000,3000}" "${MERGE_EVERY:=5}" "${HEADLINE_RATE:=max}" "${HEADLINE_DURATION:=300}"
# agents: coding agents at their pace (veil-bench load --mode agents): a
# think time between operations (AGENTS_THINK seconds of agent time on
# average, compressed AGENTS_TIME_SCALE times: the report states both and
# each rate uncompressed), AGENTS_SUBAGENTS subagents forked once a cycle and
# merged into the agent's branch, and its branch landed on `main` every
# AGENTS_LAND_EVERY pushes (about every 45 minutes of agent time). One run per
# agent count, AGENTS_DURATION seconds each: about 10 minutes for the two.
: "${AGENTS_COUNTS:=1000 10000}" "${AGENTS_DURATION:=180}" "${AGENTS_THINK:=120}" "${AGENTS_TIME_SCALE:=20}"
: "${AGENTS_SUBAGENTS:=3}" "${AGENTS_LAND_EVERY:=20}"
# onerepo: one busy repository. ONEREPO_AGENTS agents (one run per count,
# ONEREPO_DURATION seconds each), each pushing to a branch of its own in
# one project as fast as it is answered, from one driver (the agents of one
# project sign in as one person, so one tool drives them all). Reported by
# deploy/onerepo-table.py against ONEREPO_TARGET pushes a second, the figure
# of GitHub's internal test (7,200 pushes a second, 5,000 agents on one
# repository): pushes a second, database statements and commits per push,
# the servers' and the database's CPU per push (their docker stats samples
# inside the measured window) and what the target would need at those costs.
: "${ONEREPO_AGENTS:=1000 5000}" "${ONEREPO_DURATION:=120}" "${ONEREPO_TARGET:=7200}"
# scaling: the same three curves with 1, 2 and 3 servers running, driven
# from every driver at once (the numbers are summed).
: "${SCALING_SERVERS:=1 2 3}" "${SCALING_DURATION:=60}"
: "${SCALING_PULL_CLIENTS:=1000}" "${SCALING_BRANCH_CLIENTS:=1000}"
: "${SCALING_LANDING_PROJECTS:=100}" "${SCALING_LANDING_CLIENTS:=1000}"
# failover: a landing run during which the server that holds `main`'s lease goes away.
: "${FAILOVER_AGENTS:=1000}" "${FAILOVER_PEOPLE:=100}" "${FAILOVER_RATE:=300}"
: "${FAILOVER_DURATION:=120}" "${FAILOVER_AFTER:=45}" "${FAILOVER_HOW:=stop}" "${FAILOVER_SETTLE:=120}"

# spaces: the many-branch shape on a real Spaces bucket, for correctness
# and flow, not speed (owner, 2026-11-13; BUG-2290). A push makes about
# 8.6 storage reads and 11.0 writes (docs/design/scale/LOAD.md), 19.6
# requests; one bucket allows 800 a second, so 40 pushes/s is the limit
# itself: 20/s (about 390 requests a second) leaves half of it for the
# setup's bursts, the merges and the deriver. 100 agents, 5 minutes.
: "${SPACES_AGENTS:=100}" "${SPACES_RATE:=20}" "${SPACES_DURATION:=300}"

# yb-scale: multi-project horizontal scaling across YugabyteDB nodes (3 vs 6).
# Drives 60-100 projects across branches, landing, pull, api and land from
# every driver at once. Reported by deploy/yb-scale-table.py (single run, or
# 3-vs-6 >= 1.6x pass/fail verdict when YB_COMPARE_DIR is set).
: "${YB_SCALE_PROJECTS:=60}" "${YB_SCALE_DURATION:=60}" "${YB_SCALE_PEOPLE:=60}"
: "${YB_SCALE_BRANCH_CLIENTS:=300}" "${YB_SCALE_LANDING_CLIENTS:=300}"
: "${YB_SCALE_PULL_CLIENTS:=300}" "${YB_SCALE_PULL_BACKGROUND:=0}"
: "${YB_SCALE_API_CLIENTS:=120}" "${YB_SCALE_LAND_CLIENTS:=120}"
# yb-onerepo: single-repository many-branch scaling across YugabyteDB nodes
# (3 vs 6, from one driver so all agents share one project). Runs pure branch
# pushes (the >= 1.6x 3->6 pass curve) and a separate --merge-every curve whose
# serialized merges onto `main` are reported separately (informational).
: "${YB_ONEREPO_DURATION:=60}" "${YB_ONEREPO_CLIENTS:=300}"
: "${YB_ONEREPO_MERGE_CLIENTS:=300}" "${YB_ONEREPO_MERGE_EVERY:=5}"

GATES_ALL="pull land branches onerepo api landing agents scaling yb-scale yb-onerepo failover objects openscion scale spaces"
# The settings recorded beside every result (run.txt).
GATE_SETTINGS="DURATION WARMUP PULL_CLIENTS PULL_BACKGROUND LAND_PROJECTS LAND_CLIENTS BRANCH_CLIENTS OBJECT_CLIENTS
 OPENSCION_FILES OPENSCION_RUNS SCALE_PROFILE SCALE_RUNS LANDING_AGENTS LANDING_PEOPLE LANDING_RATE LANDING_DURATIONS
 LANDING_VARIANTS HEADLINE_AGENTS MERGE_EVERY HEADLINE_RATE HEADLINE_DURATION SCALING_SERVERS SCALING_DURATION
 SCALING_PULL_CLIENTS SCALING_BRANCH_CLIENTS SCALING_LANDING_PROJECTS SCALING_LANDING_CLIENTS FAILOVER_AGENTS
 FAILOVER_PEOPLE FAILOVER_RATE FAILOVER_DURATION FAILOVER_AFTER FAILOVER_HOW FAILOVER_SETTLE SPACES_AGENTS SPACES_RATE
 SPACES_DURATION AGENTS_COUNTS AGENTS_DURATION AGENTS_THINK AGENTS_TIME_SCALE AGENTS_SUBAGENTS AGENTS_LAND_EVERY
 ONEREPO_AGENTS ONEREPO_DURATION ONEREPO_TARGET YB_SCALE_PROJECTS YB_SCALE_DURATION YB_SCALE_PEOPLE
 YB_SCALE_BRANCH_CLIENTS YB_SCALE_LANDING_CLIENTS YB_SCALE_PULL_CLIENTS YB_SCALE_PULL_BACKGROUND
 YB_SCALE_API_CLIENTS YB_SCALE_LAND_CLIENTS YB_ONEREPO_DURATION YB_ONEREPO_CLIENTS
 YB_ONEREPO_MERGE_CLIENTS YB_ONEREPO_MERGE_EVERY"

db_one() { db_sql | head -1; }
db_now_us() { echo "select (extract(epoch from clock_timestamp()) * 1000000)::bigint" | db_one; }
stat_of() { python3 -c 'import json,sys
try: print(int(json.load(sys.stdin).get(sys.argv[1], 0)))
except Exception: print(0)' "$1"; }
pause() { [ "$DRY" = 1 ] || sleep "$1"; }
# A check's SQL with the run's database-clock times put in.
check_sql() { # file, t0_us, stop_us
    sed -e "s/:T0/${2:-0}/g" -e "s/:STOP/${3:-0}/g" "$GATES_DIR/checks/$1"
}

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
        onerepo)
            local n
            for n in $ONEREPO_AGENTS; do
                bench driver "onerepo-$n" "${load[@]}" --duration "$ONEREPO_DURATION" --mode branches --projects 1 --clients "$n" --rates max --dir /work/onerepo --out "$R/onerepo-$n.json" "$@" || rc=1
            done ;;
        api)
            bench driver api "${load[@]}" --duration "$DURATION" --mode api --projects "$LAND_PROJECTS" --clients "$LAND_CLIENTS" --rates max --dir /work/api --out "$R/api.json" "$@" || rc=1 ;;
        branches)
            # The cost curve as it was (pushes to a branch of one's own), then
            # the headline: many agents, each on its branch, landing it on `main`.
            bench driver branches "${load[@]}" --duration "$DURATION" --mode branches --projects 1 --clients "$BRANCH_CLIENTS" --rates max --dir /work/branches --out "$R/branches.json" "$@" || rc=1
            bench driver branches-merge "${load[@]}" --duration "$HEADLINE_DURATION" --mode branches --projects 1 --clients "$HEADLINE_AGENTS" --rates "$HEADLINE_RATE" --merge-every "$MERGE_EVERY" --dir /work/branches-merge --out "$R/branches-merge.json" "$@" || rc=1 ;;
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
        agents)
            local n
            for n in $AGENTS_COUNTS; do
                bench driver "agents-$n" "${load[@]}" --duration "$AGENTS_DURATION" --mode agents --projects 1 --clients "$n" --think "$AGENTS_THINK" --time-scale "$AGENTS_TIME_SCALE" --subagents "$AGENTS_SUBAGENTS" --merge-every "$AGENTS_LAND_EVERY" --dir /work/agents --out "$R/agents-$n.json" "$@" || rc=1
            done ;;
        scaling) gate_scaling "$@" || rc=1 ;;
        yb-scale)
            bench drivers yb-scale-branches "${load[@]}" --duration "$YB_SCALE_DURATION" --mode branches --projects "$YB_SCALE_PROJECTS" --clients "$YB_SCALE_BRANCH_CLIENTS" --rates max --dir /work/yb-scale@D --out "$R/yb-scale-branches@D.json" "$@" || rc=1
            bench drivers yb-scale-landing "${load[@]}" --duration "$YB_SCALE_DURATION" --mode landing --projects "$YB_SCALE_PROJECTS" --clients "$YB_SCALE_LANDING_CLIENTS" --people "$YB_SCALE_PEOPLE" --rates max --dir /work/yb-scale@D --out "$R/yb-scale-landing@D.json" "$@" || rc=1
            bench drivers yb-scale-pull "${load[@]}" --duration "$YB_SCALE_DURATION" --mode pull --projects "$YB_SCALE_PROJECTS" --clients "$YB_SCALE_PULL_CLIENTS" --background "$YB_SCALE_PULL_BACKGROUND" --dir /work/yb-scale@D --out "$R/yb-scale-pull@D.json" "$@" || rc=1
            bench drivers yb-scale-api "${load[@]}" --duration "$YB_SCALE_DURATION" --mode api --projects "$YB_SCALE_PROJECTS" --clients "$YB_SCALE_API_CLIENTS" --rates max --dir /work/yb-scale@D --out "$R/yb-scale-api@D.json" "$@" || rc=1
            bench drivers yb-scale-land "${load[@]}" --duration "$YB_SCALE_DURATION" --mode land --projects "$YB_SCALE_PROJECTS" --clients "$YB_SCALE_LAND_CLIENTS" --rates max --dir /work/yb-scale@D --out "$R/yb-scale-land@D.json" "$@" || rc=1 ;;
        yb-onerepo)
            bench driver yb-onerepo-branches "${load[@]}" --duration "$YB_ONEREPO_DURATION" --mode branches --projects 1 --clients "$YB_ONEREPO_CLIENTS" --rates max --dir /work/yb-onerepo --out "$R/yb-onerepo-branches.json" "$@" || rc=1
            bench driver yb-onerepo-merge "${load[@]}" --duration "$YB_ONEREPO_DURATION" --mode branches --projects 1 --clients "$YB_ONEREPO_MERGE_CLIENTS" --rates max --merge-every "$YB_ONEREPO_MERGE_EVERY" --dir /work/yb-onerepo-merge --out "$R/yb-onerepo-merge.json" "$@" || rc=1 ;;
        failover) gate_failover "$@" || rc=$? ;;
        # The three gates below start a server of their own beside the
        # deployment's, on the first server's machine (BUG-1591 for the cache).
        objects)
            bench hub objects load "${OWN[@]}" --s3-bucket "$OWN_BUCKET-objects" --mode objects --via server,cache --projects 1 --clients "$OBJECT_CLIENTS" --background "$PULL_BACKGROUND" --duration "$DURATION" --warmup "$WARMUP" --dir /work/objects --out "$R/objects.json" "$@" || rc=1 ;;
        openscion)
            bench hub openscion openscion --vl /usr/local/bin/vl "${OWN[@]}" --s3-bucket "$OWN_BUCKET-openscion" --files "$OPENSCION_FILES" --runs "$OPENSCION_RUNS" --dir /work/openscion --out "$R/openscion.json" "$@" || rc=1 ;;
        scale)
            bench hub scale run --profile "$SCALE_PROFILE" --runs "$SCALE_RUNS" --vl /usr/local/bin/vl "${OWN[@]}" --s3-bucket "$OWN_BUCKET-scale" --dir /work/scale --out "$R/scale-$SCALE_PROFILE.json" --skip-phase import,local,remote-path,packed,sftp,agents "$@" || rc=1 ;;
        # Its own server on the first server's machine, objects on Spaces;
        # the tool records the store's `503 Slow Down` answers (s3_slow_down)
        # and requests given up (s3_gave_up) from that server's counters.
        spaces)
            bench spaces spaces load "${SPACES_OWN[@]}" --s3-bucket "$SPACES_BUCKET" --mode branches --projects 1 --clients "$SPACES_AGENTS" --rates "$SPACES_RATE" --merge-every "$MERGE_EVERY" --duration "$SPACES_DURATION" --warmup "$WARMUP" --dir /work/spaces --out "$R/spaces.json" "$@" || rc=1 ;;
        *) echo "gates: unknown gate '$gate' (one of: $GATES_ALL)" >&2; return 2 ;;
    esac
    return $rc
}

# scaling: does throughput rise with servers? The pull, the push to a
# branch of one's own and landings across projects (the landing service),
# each with 1, 2 and 3 servers running behind the one address, driven from
# every driver at once. A server out of the count is stopped (the
# balancer's health check takes it out of rotation within 2 s); all are
# started again at the end. deploy/scaling-table.py makes the table.
gate_scaling() {
    local n i rc=0 load=(load --url "$URL" --ca /tls/ca.pem --warmup "$WARMUP" --duration "$SCALING_DURATION")
    for n in $SCALING_SERVERS; do
        [ "$n" -le "$SERVERS" ] || { echo "   scaling: skipping $n servers (the deployment has $SERVERS)"; continue; }
        echo "   scaling: $n of $SERVERS servers running"
        for i in $(seq "$SERVERS"); do if [ "$i" -le "$n" ]; then hub_ctl "$i" start; else hub_ctl "$i" stop; fi; done
        pause 5
        bench drivers "scaling-${n}servers-pull" "${load[@]}" --mode pull --projects 1 --clients "$SCALING_PULL_CLIENTS" --background "$PULL_BACKGROUND" --dir /work/scaling@D --out "$R/scaling-${n}servers-pull@D.json" "$@" || rc=1
        bench drivers "scaling-${n}servers-branches" "${load[@]}" --mode branches --projects 1 --clients "$SCALING_BRANCH_CLIENTS" --rates max --dir /work/scaling@D --out "$R/scaling-${n}servers-branches@D.json" "$@" || rc=1
        bench drivers "scaling-${n}servers-landing" "${load[@]}" --mode landing --projects "$SCALING_LANDING_PROJECTS" --clients "$SCALING_LANDING_CLIENTS" --people "$LANDING_PEOPLE" --rates max --dir /work/scaling@D --out "$R/scaling-${n}servers-landing@D.json" "$@" || rc=1
    done
    for i in $(seq "$SERVERS"); do hub_ctl "$i" start; done
    return $rc
}

# failover: agents land into one fresh `main` at a steady rate; part-way the
# server that holds `main`'s landing lease is stopped (FAILOVER_HOW=kill:
# SIGKILL). Shown from the database and the tool's results: another server
# took the lease, how long no landing committed, and every change landed
# exactly once (deploy/checks/failover.sql says what each row proves;
# deploy/checks/failover-verdict.py judges them, and holds every answer the
# agents got, failover.landings.jsonl, against `main`'s line, failover-line.txt).
gate_failover() {
    local i rc=0 pid t0 stop holder=0 best=0 a b st before after left=
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
        a=${first[$i]:-0}; st=$(hub_stats "$i"); b=$(stat_of landing_batches <<<"$st")
        if [ -z "$st" ] && [ "$DRY" != 1 ]; then
            echo "   server $i: gave no counters (its stats.json is missing or empty: can it write its data directory? see its log)" >&2
        fi
        echo "   server $i: landing batches $a -> $b in about 3 s"
        if [ $((b - a)) -gt "$best" ]; then best=$((b - a)); holder=$i; fi
    done
    if [ "$DRY" = 1 ]; then holder=1
    elif [ "$holder" = 0 ]; then
        echo "   failover: no server ran a landing batch in 3 s: nothing to fail over (is the load running? see failover.log)" >&2
        wait "$pid" || true; return 1
    fi
    before=$(check_sql failover-lease.sql "$t0" | db_one)
    stop=$(db_now_us)
    echo "   failover: server $holder holds the lease ($before); $FAILOVER_HOW it"
    hub_ctl "$holder" "$FAILOVER_HOW"
    { echo "t0_us=$t0"; echo "holder_server=$holder"; echo "how=$FAILOVER_HOW"; echo "lease_before=$before"; echo "stop_us=$stop"; echo "stopped_by_us=$(db_now_us)"; } | record failover-run.txt
    wait "$pid" || rc=1
    # Tickets the stopped server had accepted are still in the queue: the
    # server that took the lease lands them. Wait until none is left.
    for i in $(seq $((FAILOVER_SETTLE / 2))); do
        left=$(check_sql failover-unfinished.sql "$t0" | db_one)
        [ "${left:-0}" = 0 ] && break; [ "$DRY" = 1 ] && break; pause 2
    done
    # The checks walk `main`'s history in the derived graph: wait until the
    # tip is derived.
    for i in $(seq 60); do
        a=$(check_sql failover-derived.sql "$t0" | db_one)
        [ "${a:-}" = t ] && break; [ "$DRY" = 1 ] && break; pause 2
    done
    after=$(check_sql failover-lease.sql "$t0" | db_one)
    check_sql failover.sql "$t0" "$stop" | db_sql | record failover-check.txt
    # `main`'s first-parent line, for the verdict to hold against the tool's
    # per-change log (failover.landings.jsonl, beside failover.json).
    check_sql failover-line.sql "$t0" | db_sql | record failover-line.txt
    { echo "lease_after=$after"; echo "unfinished_after_settling=${left:-}"; echo "tip_derived=${a:-}"; } | record failover-after.txt
    hub_ctl "$holder" start
    return $rc
}

# The head of run.txt, beside every result: `gate_meta COMMIT TAG`. The
# caller adds the topology and the image ids.
gate_meta() {
    echo "gate=$GATE"
    echo "date_utc=$(date -u +%FT%TZ)"
    echo "commit=$1"
    echo "image_tag=$2"
    echo "url=$URL"
    echo "servers=$SERVERS"
    local v
    for v in $GATE_SETTINGS; do echo "$v=${!v}"; done
}
# After the results are on the operator's machine: the tables made from them.
gate_report() { # GATE, results directory
    case $1 in
        scaling) python3 "$GATES_DIR/scaling-table.py" "$2" > "$2/scaling.md" && cat "$2/scaling.md" ;;
        onerepo) python3 "$GATES_DIR/onerepo-table.py" --target "$ONEREPO_TARGET" --servers "$SERVERS" --server-vcpus "${SERVER_VCPUS:-0}" "$2" > "$2/onerepo.md" && cat "$2/onerepo.md" ;;
        yb-scale|yb-onerepo)
            local cmp=()
            [ -n "${YB_COMPARE_DIR:-}" ] && cmp=(--compare "$YB_COMPARE_DIR")
            python3 "$GATES_DIR/yb-scale-table.py" --gate "$1" "${cmp[@]+"${cmp[@]}"}" "$2" | tee "$2/$1.md"
            return "${PIPESTATUS[0]}" ;;
        failover) python3 "$GATES_DIR/checks/failover-verdict.py" "$2" | tee "$2/failover-verdict.md"; return "${PIPESTATUS[0]}" ;;
        spaces) python3 "$GATES_DIR/checks/spaces-verdict.py" "$2" | tee "$2/spaces-verdict.md"; return "${PIPESTATUS[0]}" ;;
    esac
}
