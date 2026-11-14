#!/usr/bin/env bash
# Destroy everything the test created at Google Cloud (docs/DEPLOY.md
# §12.7), then check that nothing of it is left.
#   destroy.sh            dry run: what would be deleted
#   destroy.sh --approve  delete, in order: every VM of the run, running or
#                         stopped (a reclaimed Spot VM is stopped, not gone),
#                         with all its disks; any disk left; the firewall
#                         rules; the subnet; the network; any address
#   destroy.sh --check    only the "nothing left" check (--approve to really query)
# Found by the label veil-run=NAME or by the exact names the kit gives,
# never by remembered ids, so what a run that died before saving its state
# made is removed too; never by a bare prefix, so NAME=veil cannot reach a
# run named veil-big. MinIO's objects go with its local SSD.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
CHECK_ONLY=0
for a in "$@"; do
    case "$a" in
        --check) CHECK_ONLY=1 ;;
        *) echo "destroy: unknown argument '$a' (usage: destroy.sh [--check] [--approve|--dry-run])" >&2; exit 2 ;;
    esac
done
FW_FILTER="network~'/networks/$NAME-net\$' OR name~'^$NAME-(operator|internal)\$'"
list() { # what -> lines (`name zone|region` where it has one)
    case $1 in
        instances) run_gcloud compute instances list --filter="$OWN_FILTER" --format='value(name,zone.basename(),status)' ;;
        disks) run_gcloud compute disks list --filter="$OWN_FILTER" --format='value(name,zone.basename())' ;;
        firewall) run_gcloud compute firewall-rules list --filter="$FW_FILTER" --format='value(name)' ;;
        subnets) run_gcloud compute networks subnets list --filter="name=$NAME-subnet" --format='value(name,region.basename())' ;;
        networks) run_gcloud compute networks list --filter="name=$NAME-net" --format='value(name)' ;;
        addresses) run_gcloud compute addresses list --filter="$OWN_FILTER" --format='value(name,region.basename())' ;;
        snapshots) run_gcloud compute snapshots list --filter="$OWN_FILTER" --format='value(name)' ;;
        images) run_gcloud compute images list --no-standard-images --filter="$OWN_FILTER" --format='value(name)' ;;
    esac
}

if [ $CHECK_ONLY = 0 ]; then
    echo "== destroying everything of '$NAME' in project ${PROJECT:-PROJECT}"
    if [ $APPROVED = 1 ]; then
        # VMs, zone by zone; their boot disks and local SSD go with them.
        out=$(list instances)
        for z in $(awk 'NF >= 2 {print $2}' <<<"$out" | sort -u); do
            mapfile -t names < <(awk -v z="$z" '$2 == z {print $1}' <<<"$out")
            run_gcloud compute instances delete "${names[@]}" --zone="$z" --delete-disks=all --quiet || true
        done
        out=$(list disks)
        for z in $(awk 'NF >= 2 {print $2}' <<<"$out" | sort -u); do
            mapfile -t names < <(awk -v z="$z" '$2 == z {print $1}' <<<"$out")
            run_gcloud compute disks delete "${names[@]}" --zone="$z" --quiet || true
        done
        mapfile -t names < <(list firewall | awk 'NF {print $1}')
        [ "${#names[@]}" = 0 ] || run_gcloud compute firewall-rules delete "${names[@]}" --quiet || true
        while read -r n r; do [ -n "${n:-}" ] && { run_gcloud compute networks subnets delete "$n" --region="$r" --quiet || true; }; done < <(list subnets)
        while read -r n; do [ -n "${n:-}" ] && { run_gcloud compute networks delete "$n" --quiet || true; }; done < <(list networks)
        while read -r n r; do
            [ -n "${n:-}" ] || continue
            if [ -n "${r:-}" ]; then run_gcloud compute addresses delete "$n" --region="$r" --quiet || true
            else run_gcloud compute addresses delete "$n" --global --quiet || true; fi
        done < <(list addresses)
    else
        for w in instances disks firewall subnets networks addresses; do list "$w"; done
        echo "would delete every VM listed, running or stopped, zone by zone, with --delete-disks=all; then every disk, firewall rule, subnet, network and address listed" >&2
    fi
fi

echo "== check: nothing left running or billing for '$NAME'"
left=0
count() { # label, what: count the listed lines (a failed query fails the check through set -e)
    local out n stopped
    out=$(list "$2"); n=$(printf '%s\n' "$out" | grep -c . || true)
    if [ "$2" = instances ]; then
        stopped=$(printf '%s\n' "$out" | awk 'NF >= 3 && $3 != "RUNNING"' | grep -c . || true)
        echo "   $1: $n (of which stopped, e.g. reclaimed Spot VMs, still billing their disks: $stopped)"
    else echo "   $1: $n"; fi
    [ "$n" = 0 ] || left=1
}
count "VMs (any state)" instances
count "disks" disks
count "firewall rules" firewall
count "subnets" subnets
count "networks" networks
count "external addresses" addresses
count "snapshots" snapshots
count "images" images
if [ $APPROVED = 1 ]; then
    if [ $left = 0 ]; then echo "destroy: nothing left. Also glance at Billing > Reports in the console tomorrow."; rm -f "$STATE_FILE"
    else echo "destroy: SOMETHING IS LEFT (above); fix it, then re-run $0 --check --approve" >&2; exit 1; fi
else echo "(dry run: the counts above are of the printed commands, not the project)"; fi
