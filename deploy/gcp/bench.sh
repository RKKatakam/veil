#!/usr/bin/env bash
# Run one gate on Google Cloud and fetch its results (docs/DEPLOY.md §12.5):
# deploy/do/bench.sh's steps (the gates of deploy/gates.sh, the records
# beside each result), run with this kit's lib.sh (VEIL_KIT=gcp), with a
# watch on the Spot VMs around them:
#   before the gate  any Spot VM that is not RUNNING (reclaimed between
#                    gates) is started again, recovered, and noted;
#   after the gate   a Spot VM reclaimed during it, seen as a new
#                    compute.instances.preempted operation or a Spot VM not
#                    RUNNING, makes the gate's result invalid: its run.txt
#                    says so (result_valid=no, which VM), the VM is started
#                    and recovered, and the gate runs once more (its run.txt:
#                    rerun_of=); a second reclaim fails the gate, unrerun.
# Recovery: a server, the balancer, a driver or the cache comes back as it
# stopped (a Spot VM stops, keeping its disk: images, configuration and
# containers, which restart themselves); its containers are started and the
# server's health awaited. A database or storage machine (Spot only with
# VEIL_GCP_SPOT=all), or any private address that changed, means
# configure.sh --approve again (MinIO's local SSD comes back empty).
#
#   bench.sh [--approve] GATE [veil-bench flags...]     (gates: deploy/gates.sh, not `spaces`)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
. "$DO_ROOT/deploy/gates.sh"
GATE=${1:?gate: one of $GATES_ALL}; shift
case " $GATES_ALL " in *" $GATE "*) ;; *) echo "bench: unknown gate '$GATE' (one of: $GATES_ALL)" >&2; exit 2 ;; esac
[ "$GATE" != spaces ] || { echo "bench: the spaces gate runs on a DigitalOcean Spaces bucket; the gcp kit has none" >&2; exit 2; }
[ $APPROVED = 1 ] && require_created
SHARED=$GCP_HERE/../do/bench.sh
RESULTS=$DO_ROOT/deploy/results/$NAME
TAG=${TAG:-$(cd "$DO_ROOT" && git describe --always --dirty --abbrev=8 2>/dev/null || echo dev)}
SPOTS=(); declare -A ROLE
while read -r role name size; do ROLE[$name]=$role; is_spot "$role" && SPOTS+=("$name"); done < <(droplets)
APPROVE=(); [ $APPROVED = 1 ] && APPROVE=(--approve)

# The run's preemption operations in the zone (id name), and the Spot VMs not running.
# Each fails when gcloud does (pipefail): an unanswered question is never
# read as "nothing was reclaimed".
preempted_ops() {
    local id target rest
    run_gcloud compute operations list --zones="$ZONE" --filter="operationType=compute.instances.preempted" \
        --format='value(id,targetLink.basename(),insertTime)' | while read -r id target rest; do
        if [ -n "${ROLE[$target]:-}" ]; then echo "$id $target"; fi
    done
}
spots_down() {
    local name status
    run_gcloud compute instances list --filter="labels.$LABEL=$NAME" --format='csv[no-heading](name,status)' |
        while IFS=, read -r name status; do
            if [[ " ${SPOTS[*]} " == *" $name "* ]] && [ "$status" != RUNNING ]; then echo "$name"; fi
        done
}
note() { # results directory, line: kept in its run.txt
    if [ $APPROVED = 1 ]; then echo "$2" >> "$1/run.txt"; else echo "would add to run.txt: $2" >&2; fi
}
NOTES=()   # what happened before the gate, for its run.txt
recover() { # names...: start each again, refresh the addresses, bring its services back
    local n i st full=0 name pub priv old
    for n in "$@"; do
        echo "   spot: starting $n again (it was reclaimed)"
        for i in 1 2 3 4 5 6; do
            run_gcloud compute instances start "$n" --zone="$ZONE" && break
            [ $APPROVED = 1 ] || break
            [ "$i" = 6 ] && { echo "bench: could not start $n again (no Spot capacity?); try later, or VEIL_GCP_SPOT=none" >&2; return 1; }
            sleep 60
        done
        case ${ROLE[$n]} in yb|db|minio) full=1 ;; esac
    done
    if [ $APPROVED = 1 ]; then
        while IFS=, read -r name pub priv st; do
            [ -n "${ROLE[$name]:-}" ] || continue
            old=$(priv_of "$name")
            [ -n "$old" ] && [ "$old" != "$priv" ] && full=1
            [ -n "$pub" ] && save_state "IP_${name//-/_}" "$pub"; [ -n "$priv" ] && save_state "PRIV_${name//-/_}" "$priv"
        done < <(run_gcloud compute instances list --filter="labels.$LABEL=$NAME" \
            --format='csv[no-heading](name,networkInterfaces[0].accessConfigs[0].natIP,networkInterfaces[0].networkIP,status)')
    else echo "would save the restarted machines' new public addresses to $STATE_FILE" >&2; fi
    for n in "$@"; do
        for i in $(seq 36); do remote "$(ip_of "$n")" 'cloud-init status --wait >/dev/null 2>&1; docker info >/dev/null' 2>/dev/null && break; [ $APPROVED = 1 ] || break; sleep 5; done
    done
    if [ $full = 1 ]; then
        echo "   spot: a database or storage machine, or a private address, changed: configure.sh again"
        NOTES+=("spot_reconfigured=yes")
        VEIL_KIT=gcp bash "$GCP_HERE/../do/configure.sh" "${APPROVE[@]+"${APPROVE[@]}"}" "$TAG" || return 1
        return 0
    fi
    for n in "$@"; do
        case ${ROLE[$n]} in
            hub) remote "$(ip_of "$n")" "if docker inspect yb-proxy >/dev/null 2>&1; then docker start yb-proxy >/dev/null; fi; docker update --restart unless-stopped veil-server >/dev/null; docker start veil-server >/dev/null; for i in \$(seq 60); do [ \"\$(docker inspect -f '{{.State.Health.Status}}' veil-server)\" = healthy ] && break; sleep 1; done; [ \"\$(docker inspect -f '{{.State.Health.Status}}' veil-server)\" = healthy ]" || return 1 ;;
            lb) remote "$(ip_of "$n")" "docker start veil-lb >/dev/null" || return 1 ;;
            cache) remote "$(ip_of "$n")" "docker start veil-cache >/dev/null" || return 1 ;;
        esac
    done
}
run_once() { # stamp, veil-bench flags...: the shared steps, results in $RESULTS/stamp-GATE
    local rc=0 s=$1; shift
    VEIL_KIT=gcp BENCH_STAMP=$s bash "$SHARED" "${APPROVE[@]+"${APPROVE[@]}"}" "$GATE" "$@" || rc=$?
    return $rc
}
stamp() { date -u +%Y%m%dT%H%M%SZ; }

echo "== spot: ${#SPOTS[@]} Spot VM(s) (${SPOTS[*]:-none}); checking them before $GATE"
down=$(spots_down)
if [ -n "$down" ]; then
    # shellcheck disable=SC2086
    recover $down || exit 1
    NOTES+=("spot_restarted_before=$(echo $down)")
fi
seen=$(preempted_ops | awk '{print $1}')
[ $APPROVED = 1 ] || echo "would note in run.txt which Spot VMs were reclaimed during the gate (result_valid=yes|no), and rerun it once if any was" >&2

rc=0; attempt=1; prev=""; S=$(stamp)
while :; do
    rc=0; run_once "$S" "$@" || rc=$?
    OUT=$RESULTS/$S-$GATE
    # No directory: the shared steps refused before the gate and said why
    # (e.g. the servers' object layout unknown or not the one set).
    [ $APPROVED = 0 ] || [ -d "$OUT" ] || { echo "bench: $GATE did not run: no results directory ($OUT)" >&2; [ $rc != 0 ] || rc=1; exit $rc; }
    for l in "${NOTES[@]+"${NOTES[@]}"}"; do note "$OUT" "$l"; done; NOTES=()
    [ -z "$prev" ] || note "$OUT" "rerun_of=$prev"
    # Reclaimed during the gate: a preemption operation not seen before it, or a Spot VM down now.
    if ! now=$(preempted_ops) || ! down=$(spots_down); then
        note "$OUT" "result_valid=no (Google Cloud did not answer whether a Spot VM was reclaimed during the gate)"
        echo "bench: could not ask Google Cloud whether a Spot VM was reclaimed during $GATE: its result is not valid" >&2
        exit 1
    fi
    hit=$( { awk -v seen=" $(echo $seen) " 'index(seen, " " $1 " ") == 0 {print $2}' <<<"$now"; echo "$down"; } | awk 'NF && !s[$0]++' | tr '\n' ' ')
    seen=$(awk '{print $1}' <<<"$now")
    if [ -z "${hit// /}" ]; then
        note "$OUT" "spot_reclaimed_during=none"; note "$OUT" "result_valid=yes"
        [ $APPROVED = 1 ] && echo "== spot: no Spot VM was reclaimed during $GATE; the result stands (exit $rc)"
        exit $rc
    fi
    note "$OUT" "spot_reclaimed_during=${hit% }"
    note "$OUT" "result_valid=no (a Spot VM was reclaimed during the gate; its numbers are not used)"
    if [ $attempt = 2 ]; then
        echo "bench: Spot VM(s) ${hit% } reclaimed during the rerun too: $GATE is not run a third time (try later, or VEIL_GCP_SPOT=none)" >&2
        exit 3
    fi
    next=$(stamp)-rerun
    note "$OUT" "rerun=$next-$GATE"
    echo "== spot: ${hit% } reclaimed during $GATE: its result is invalid; recovering, then running $GATE once more"
    # shellcheck disable=SC2086
    recover $hit || exit 1
    prev=$S-$GATE; S=$next; attempt=2
done
