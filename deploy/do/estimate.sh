#!/usr/bin/env bash
# The cost of the planned test, line by line (docs/DEPLOY.md, "Topology and
# cost"), from the topology in deploy/do/.env. Prints the hourly rate and
# the total for VEIL_DO_HOURS, plus a 24-hour worst case (what it costs if
# teardown is forgotten for a day). Never talks to DigitalOcean unless
# `--live --approve`, which replaces the built-in prices with the API's.
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
declare -A live
if [ $LIVE = 1 ]; then
    if [ $APPROVED = 1 ]; then
        size_out=$(run_do compute size list --format Slug,PriceHourly --no-header)
        while read -r slug price; do [ -n "${slug:-}" ] && live[$slug]=$price; done <<<"$size_out"
    else
        run_do compute size list --format Slug,PriceHourly --no-header
    fi
fi
printf '%-28s %-16s %10s %12s\n' "item" "size" "USD/hour" "USD/${HOURS}h"
total=0
unknown=0
line() { # label, size, hourly
    local h=$3
    [ -z "$h" ] && { printf '%-28s %-16s %10s %12s\n' "$1" "$2" "unknown" "unknown"; echo "   (no built-in price for $2: run with --live --approve, or look it up)" >&2; unknown=1; return; }
    printf '%-28s %-16s %10.3f %12.2f\n' "$1" "$2" "$h" "$(echo "$h * $HOURS" | bc -l)"
    total=$(echo "$total + $h" | bc -l)
}
while read -r role name size; do
    p=${live[$size]:-$(price_of "$size")}
    line "$name ($role)" "$size" "$p"
done < <(droplets)
sp=$(echo "$SPACES_MONTHLY / 672" | bc -l)
printf '%-28s %-16s %10.3f %12.2f  (billed as a flat %s/month while a bucket exists)\n' "Spaces bucket" "250 GiB" "$sp" "$SPACES_MONTHLY" "\$$SPACES_MONTHLY"
printf '%-28s %-16s %10s %12s\n' "bandwidth" "pooled, included" "0" "0"
echo
if [ $unknown = 1 ]; then
    echo "estimate: cannot bound total cost with unknown droplet size price(s)" >&2
    exit 1
fi
planned=$(echo "$total * $HOURS + $SPACES_MONTHLY" | bc -l)
day=$(echo "$total * 24 + $SPACES_MONTHLY" | bc -l)
printf 'hourly rate (droplets):      $%.3f\n' "$total"
printf 'planned %s hours + Spaces:    $%.2f\n' "$HOURS" "$planned"
printf '24 hours left running:       $%.2f\n' "$day"
printf 'a whole month forgotten:     $%.2f  <- why destroy.sh and its check matter\n' "$(echo "$total * 672 + $SPACES_MONTHLY" | bc -l)"
if [ $LIVE = 0 ] || [ $APPROVED = 0 ]; then echo "(built-in list prices; confirm with: $0 --live --approve, or doctl compute size list)"; fi
if [ "$(echo "$planned >= $BUDGET_MAX" | bc -l)" = 1 ]; then
    echo "estimate: planned cost (\$$(printf '%.2f' "$planned")) reaches or exceeds the \$$BUDGET_MAX budget" >&2
    exit 1
fi
