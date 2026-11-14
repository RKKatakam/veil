#!/usr/bin/env bash
# Before create.sh: is the project ready for the plan? (docs/DEPLOY.md
# §12.1). Reads only; changes nothing. Checks:
#   1. the project exists and is active;
#   2. billing is enabled on it;
#   3. the Compute Engine API is enabled (and says whether the Cloud
#      Billing API is, for estimate.sh --live);
#   4. every machine type of the plan exists in the zone;
#   5. the quotas in the region (CPUS, C2D_CPUS, PREEMPTIBLE_CPUS,
#      LOCAL_SSD_TOTAL_GB, SSD_TOTAL_GB, IN_USE_ADDRESSES, INSTANCES) and
#      CPUS_ALL_REGIONS, against what the plan needs, and prints exactly
#      what to request, and where, for each one short.
# Without --approve it prints the plan's needs and the read-only commands.
#   preflight.sh [--approve]
set -euo pipefail
. "$(dirname "$0")/lib.sh"
[ $# -eq 0 ] || { echo "preflight: unknown argument '$1' (usage: preflight.sh [--approve|--dry-run])" >&2; exit 2; }
fail=0
say() { echo "   $*"; }

# The plan's needs.
quota_of() { # machine type -> its vCPU quota metric
    case ${1%%-*} in e2|n1|f1|g1) echo CPUS ;; *) echo "$(tr a-z A-Z <<<"${1%%-*}")_CPUS" ;; esac
}
declare -A NEED
disk=0; n=0; types=()
while read -r role name size; do
    v=${size##*-}; m=$(quota_of "$size")
    if is_spot "$role"; then k=spot_cpus_$m; else k=od_cpus_$m; fi
    NEED[$k]=$(( ${NEED[$k]:-0} + v ))
    disk=$((disk + $(boot_gb "$role"))); n=$((n + 1))
    [[ " ${types[*]-} " == *" $size "* ]] || types+=("$size")
    if [ "$role" = minio ]; then
        if is_spot minio; then NEED[spot_lssd_gb]=$LOCAL_SSD_GB; else NEED[od_lssd_gb]=$LOCAL_SSD_GB; fi
    fi
done < <(droplets)
NEED[ssd_gb]=$disk; NEED[addresses]=$n; NEED[instances]=$n
echo "== the plan: $n machines in $ZONE (VEIL_GCP_SPOT=$SPOT)"
for k in $(printf '%s\n' "${!NEED[@]}" | sort); do say "$k = ${NEED[$k]}"; done

echo "== 1. the project"
st=$(run_gcloud projects describe "${PROJECT:-PROJECT}" --format='value(lifecycleState)')
if [ $APPROVED = 1 ]; then [ "$st" = ACTIVE ] && say "project $PROJECT: ACTIVE" || { say "project $PROJECT: '$st' (expected ACTIVE)"; fail=1; }; fi
echo "== 2. billing"
st=$(run_gcloud billing projects describe "${PROJECT:-PROJECT}" --format='value(billingEnabled)')
if [ $APPROVED = 1 ]; then
    case "$st" in True|true) say "billing: enabled" ;; *) say "billing: NOT enabled: Console > Billing > link a billing account (a paid one: docs/REPRODUCE.md)"; fail=1 ;; esac
fi
echo "== 3. APIs"
apis=$(run_gcloud services list --enabled --format='value(config.name)')
if [ $APPROVED = 1 ]; then
    grep -qx compute.googleapis.com <<<"$apis" && say "compute.googleapis.com: enabled" ||
        { say "compute.googleapis.com: NOT enabled: gcloud services enable compute.googleapis.com --project=$PROJECT"; fail=1; }
    grep -qx cloudbilling.googleapis.com <<<"$apis" && say "cloudbilling.googleapis.com: enabled (estimate.sh --live can read prices)" ||
        say "cloudbilling.googleapis.com: not enabled (only estimate.sh --live needs it: gcloud services enable cloudbilling.googleapis.com --project=$PROJECT)"
fi
echo "== 4. machine types in $ZONE"
for t in "${types[@]}"; do
    got=$(run_gcloud compute machine-types list --zones="$ZONE" --filter="name=$t" --format='value(name)')
    if [ $APPROVED = 1 ]; then [ "$got" = "$t" ] && say "$t: offered" || { say "$t: NOT offered in $ZONE (another zone: VEIL_GCP_ZONE, or another type)"; fail=1; }; fi
done
echo "== 5. quotas in $REGION and global"
if [ $APPROVED = 1 ]; then
    tmp=$(mktemp -d); trap 'rm -rf -- "$tmp"' EXIT
    run_gcloud compute regions describe "$REGION" --format=json > "$tmp/region.json"
    run_gcloud compute project-info describe --format=json > "$tmp/project.json"
    args=(); for k in "${!NEED[@]}"; do args+=("$k=${NEED[$k]}"); done
    python3 "$GCP_HERE/quota-check.py" "$REGION" "$tmp/region.json" "$tmp/project.json" "${args[@]}" || fail=1
else
    run_gcloud compute regions describe "$REGION" --format=json
    run_gcloud compute project-info describe --format=json
    echo "(dry run: --approve reads the project's quotas and compares them with the needs above)"
fi
if [ $APPROVED = 1 ]; then
    [ $fail = 0 ] && echo "preflight: ready. Next: deploy/gcp/estimate.sh, then deploy/gcp/create.sh --approve" || { echo "preflight: NOT ready (above)" >&2; exit 1; }
fi
