#!/usr/bin/env bash
# The cost of the planned Google Cloud test, line by line (docs/DEPLOY.md
# §12.2), from the topology in deploy/gcp/.env: each machine (Spot or
# on-demand as VEIL_GCP_SPOT says), the boot disks, the storage machine's
# local SSD and the external addresses; the hourly rate and the total for
# VEIL_GCP_HOURS (and the database machines' data disks); what a teardown forgotten for a day and for a month would
# cost; what stopped (reclaimed) Spot VMs cost a month, their disks alone;
# and the same for all three models (on-demand, hybrid, all Spot).
# Refuses a plan of $100 or more, and any machine type it has no price for.
#
#   estimate.sh                  built-in list prices (us-central1, 2026-11-14)
#   estimate.sh --live --approve the current prices from the Cloud Billing
#                                Catalog API (reads only; the access token
#                                goes to curl on stdin, never a command line)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
LIVE=0
for a in "$@"; do
    case "$a" in
        --live) LIVE=1 ;;
        *) echo "estimate: unknown argument '$a' (usage: estimate.sh [--live [--approve]])" >&2; exit 2 ;;
    esac
done
[ $APPROVED = 1 ] && [ $LIVE = 0 ] && { echo "estimate: --approve is only used with --live (built-in prices need no approval)" >&2; exit 2; }
refuse_shared_objects estimate

declare -A OD SP
lssd_od=$LSSD_GB_MONTH; lssd_sp=$LSSD_GB_MONTH; pd=$PD_GB_MONTH; pdssd=$PDSSD_GB_MONTH; ip_od=$IP_HOUR; ip_sp=$IP_SPOT_HOUR
TYPES=$(droplets | awk '{print $3}' | sort -u)
for t in $TYPES; do OD[$t]=$(price_of "$t" ondemand); SP[$t]=$(price_of "$t" spot); done
SKUS_URL=https://cloudbilling.googleapis.com/v1/services/6F81-5844-456A/skus   # Compute Engine's SKUs
if [ $LIVE = 1 ]; then
    if [ $APPROVED = 1 ]; then
        token=$(run_gcloud auth print-access-token)
        [ -n "$token" ] || { echo "estimate: no access token from gcloud" >&2; exit 1; }
        pages=""; next=""
        for _ in $(seq 20); do
            page=$(printf 'header = "Authorization: Bearer %s"\n' "$token" |
                curl -sS -f -K - --max-time 60 "$SKUS_URL?currencyCode=USD&pageSize=5000${next:+&pageToken=$next}") ||
                { echo "estimate: the Cloud Billing Catalog API did not answer (is cloudbilling.googleapis.com enabled?)" >&2; exit 1; }
            pages+=$(printf '%s' "$page" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))')$'\n'
            next=$(printf '%s' "$page" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("nextPageToken",""))')
            [ -n "$next" ] || break
            [[ "$next" =~ ^[A-Za-z0-9_=-]+$ ]] || { echo "estimate: unexpected page token" >&2; exit 1; }
        done
        unset token
        # Live prices replace the built-in ones; one not found is unknown.
        for t in $TYPES; do OD[$t]=""; SP[$t]=""; done
        while read -r what a b c; do
            case $what in
                type) OD[$a]=$b; SP[$a]=$c ;;
                lssd_gb_month) lssd_od=$a; lssd_sp=$b ;;
                pd_gb_month) pd=$a ;;
                pdssd_gb_month) pdssd=$a ;;
                ip_hour) ip_od=$a; ip_sp=$b ;;
            esac
        done < <(printf '%s' "$pages" | python3 "$GCP_HERE/prices.py" "$REGION" $TYPES)
    else
        run_gcloud auth print-access-token
        echo "would fetch $SKUS_URL?currencyCode=USD (with the token on curl's stdin) and price $(echo $TYPES) in $REGION" >&2
    fi
fi

unknown=0
data_gb_price() { # USD per GiB a month of the database machines' data disks
    if [ "$DB_DISK_TYPE" = pd-ssd ]; then echo "$pdssd"; else echo "$pd"; fi
}
price() { # type, role, model -> USD/hour or empty
    if is_spot "$2" "$3"; then echo "${SP[$1]:-}"; else echo "${OD[$1]:-}"; fi
}
model_hourly() { # model -> USD/hour of the whole topology, or "unknown"
    local m=$1 role name size p t=0
    while read -r role name size; do
        p=$(price "$size" "$role" "$m"); [ -n "$p" ] || { echo unknown; return; }
        t=$(echo "$t + $p + $(boot_gb "$role") * $pd / $MONTH_HOURS + $(data_gb "$role") * $(data_gb_price) / $MONTH_HOURS" | bc -l)
        if is_spot "$role" "$m"; then t=$(echo "$t + $ip_sp" | bc -l); else t=$(echo "$t + $ip_od" | bc -l); fi
        if [ "$role" = minio ]; then
            if is_spot minio "$m"; then p=$lssd_sp; else p=$lssd_od; fi
            t=$(echo "$t + $LOCAL_SSD_GB * $p / $MONTH_HOURS" | bc -l)
        fi
    done < <(droplets)
    echo "$t"
}
disks_monthly() { # every boot disk, a month: what stopped VMs still bill
    local role name size t=0
    while read -r role name size; do t=$(echo "$t + $(boot_gb "$role") * $pd + $(data_gb "$role") * $(data_gb_price)" | bc -l); done < <(droplets)
    echo "$t"
}

printf '%-26s %-16s %-9s %10s %12s\n' "item" "type" "model" "USD/hour" "USD/${HOURS}h"
total=0
line() { # label, type, model, hourly
    if [ -z "$4" ]; then
        printf '%-26s %-16s %-9s %10s %12s\n' "$1" "$2" "$3" unknown unknown
        echo "   (no price for $2: run with --live --approve, or set a type the kit knows)" >&2; unknown=1; return
    fi
    printf '%-26s %-16s %-9s %10.3f %12.2f\n' "$1" "$2" "$3" "$4" "$(echo "$4 * $HOURS" | bc -l)"
    total=$(echo "$total + $4" | bc -l)
}
disk_gb=0; data_total=0; ips_od=0; ips_sp=0
while read -r role name size; do
    if is_spot "$role"; then m=spot; ips_sp=$((ips_sp + 1)); else m=on-demand; ips_od=$((ips_od + 1)); fi
    line "$name ($role)" "$size" "$m" "$(price "$size" "$role" "$SPOT")"
    disk_gb=$((disk_gb + $(boot_gb "$role"))); data_total=$((data_total + $(data_gb "$role")))
done < <(droplets)
if is_spot minio; then p=$lssd_sp; m=spot; else p=$lssd_od; m=on-demand; fi
line "local SSD (MinIO's data)" "${LOCAL_SSD_GB} GiB NVMe" "$m" "$(echo "$LOCAL_SSD_GB * $p / $MONTH_HOURS" | bc -l)"
line "boot disks (pd-balanced)" "${disk_gb} GiB" "-" "$(echo "$disk_gb * $pd / $MONTH_HOURS" | bc -l)"
[ "$data_total" -gt 0 ] && line "database data ($DB_DISK_TYPE)" "${data_total} GiB" "-" "$(echo "$data_total * $(data_gb_price) / $MONTH_HOURS" | bc -l)"
line "external IPv4 addresses" "$ips_od std + $ips_sp spot" "-" "$(echo "$ips_od * $ip_od + $ips_sp * $ip_sp" | bc -l)"
printf '%-26s %-16s %-9s %10s %12s\n' "traffic" "in one zone" "-" 0 0
echo
if [ $unknown = 1 ]; then echo "estimate: cannot bound the total cost with unknown prices" >&2; exit 1; fi
planned=$(echo "$total * $HOURS" | bc -l)
printf 'hourly rate:                 $%.3f  (VEIL_GCP_SPOT=%s)\n' "$total" "$SPOT"
printf 'planned %s hours:            $%.2f\n' "$HOURS" "$planned"
printf '24 hours left running:       $%.2f\n' "$(echo "$total * 24" | bc -l)"
printf 'a whole month forgotten:     $%.2f  <- why destroy.sh and its check matter\n' "$(echo "$total * $MONTH_HOURS" | bc -l)"
printf 'stopped VMs, a month:        $%.2f  (reclaimed Spot VMs stop: their disks still bill until destroy.sh)\n' "$(disks_monthly)"
echo
echo "every model (this topology; Spot prices change up to once a day):"
printf '   %-44s %9s %9s %11s %13s\n' "model" "USD/hour" "${HOURS} h" "a day left" "a month left"
for t in "none on-demand (VEIL_GCP_SPOT=none)" "hybrid hybrid Spot (hybrid, the default)" "all all Spot (all; database and storage too)"; do
    read -r m label <<<"$t"
    r=$(model_hourly "$m")
    [ "$r" != unknown ] || { printf '   %-44s %9s\n' "$label" unknown; continue; }
    printf '   %-44s %9.3f %9.2f %11.2f %13.2f\n' "$label" "$r" "$(echo "$r * $HOURS" | bc -l)" "$(echo "$r * 24" | bc -l)" "$(echo "$r * $MONTH_HOURS" | bc -l)"
done
echo
echo "every topology (VEIL_GCP_SPOT=$SPOT, $HUBS server(s), $DRIVERS driver(s), sizes as above):"
printf '   %-44s %9s %9s %11s %13s\n' "topology" "USD/hour" "${HOURS} h" "a day left" "a month left"
for t in "0 PostgreSQL (VEIL_GCP_YB_NODES=0)" "3 YugabyteDB x3 (VEIL_GCP_YB_NODES=3)" "6 YugabyteDB x6 (VEIL_GCP_YB_NODES=6)"; do
    read -r y label <<<"$t"
    r=$(YB_NODES=$y model_hourly "$SPOT")
    [ "$r" != unknown ] || { printf '   %-44s %9s\n' "$label" unknown; continue; }
    printf '   %-44s %9.3f %9.2f %11.2f %13.2f\n' "$label" "$r" "$(echo "$r * $HOURS" | bc -l)" "$(echo "$r * 24" | bc -l)" "$(echo "$r * $MONTH_HOURS" | bc -l)"
done
if [ $LIVE = 0 ] || [ $APPROVED = 0 ]; then echo "(built-in list prices for us-central1, 2026-11-14; confirm with: $0 --live --approve)"; fi
if [ "$(echo "$planned >= $BUDGET_MAX" | bc -l)" = 1 ]; then
    echo "estimate: planned cost (\$$(printf '%.2f' "$planned")) reaches or exceeds the \$$BUDGET_MAX budget" >&2
    exit 1
fi
