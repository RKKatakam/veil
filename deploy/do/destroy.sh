#!/usr/bin/env bash
# Destroy everything the test created (docs/DEPLOY.md, "Teardown"), then
# check that nothing tagged NAME is left and that the Spaces bucket is gone.
#   destroy.sh            dry run: what would be deleted
#   destroy.sh --approve  delete: droplets, the storage droplet's volume,
#                         firewall, SSH key, tag; empty and delete the Spaces
#                         buckets (needs the Spaces keys). MinIO's objects go
#                         with its droplet (or its volume).
#   destroy.sh --check    only the "nothing left" check (--approve to really query)
# Deleting by tag, not by remembered id, so droplets created by a run that
# died before saving its state are removed too.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
CHECK_ONLY=0
for a in "$@"; do
    case "$a" in
        --check) CHECK_ONLY=1 ;;
        *) echo "destroy: unknown argument '$a' (usage: destroy.sh [--check] [--approve|--dry-run])" >&2; exit 2 ;;
    esac
done

spaces() { # METHOD, path, extra curl args...: a signed request to Spaces
    local method=$1 path=$2; shift 2
    # The keys reach curl through its config on stdin, never the command line.
    printf 'user = "%s:%s"\n' "${VEIL_DO_SPACES_KEY:?}" "${VEIL_DO_SPACES_SECRET:?}" |
        curl -sS -K - --max-time 15 -X "$method" --aws-sigv4 "aws:amz:$REGION:s3" "$SPACES_ENDPOINT$path" "$@"
}
spaces_code() { # METHOD, path -> HTTP status code (or 000 on network error)
    spaces "$1" "$2" -o /dev/null -w '%{http_code}' || echo 000
}
# Every Spaces bucket this deployment can make: the server's own ($BUCKET,
# with VEIL_DO_OBJECTS=spaces), the three same-machine benchmark buckets
# ($BUCKET-{objects,openscion,scale}) and the `spaces` gate's ($BUCKET-spaces),
# plus any bucket in the region starting with $NAME- found by listing '/'.
spaces_buckets() {
    local b list=()
    if [ -n "$BUCKET" ]; then
        list+=("$BUCKET" "$BUCKET-objects" "$BUCKET-openscion" "$BUCKET-scale" "$BUCKET-spaces")
    fi
    if [ $APPROVED = 1 ] && [ -n "${VEIL_DO_SPACES_KEY:-}" ] && [ -n "${VEIL_DO_SPACES_SECRET:-}" ]; then
        local xml
        xml=$(spaces GET "/" 2>/dev/null || true)
        while IFS= read -r b; do
            [[ "$b" == "$NAME-"* ]] && list+=("$b")
        done < <(printf '%s\n' "$xml" | grep -oE '<Name>[^<]+</Name>' | sed -e 's/<Name>//' -e 's/<\/Name>//' || true)
    fi
    printf '%s\n' "${list[@]+"${list[@]}"}" | awk 'NF && !seen[$0]++'
}

if [ $CHECK_ONLY = 0 ]; then
    echo "== destroying everything tagged '$NAME' in the account"
    run_do compute droplet delete --tag-name "$NAME" --force || true
    # The storage droplet's volume (VEIL_DO_OBJECTS_VOLUME_GB): by the id
    # create.sh saved and by its exact name (a run that died before saving
    # it). It detaches when its droplet is deleted, which takes a moment.
    if [ $APPROVED = 1 ]; then
        vol_out=$(run_do compute volume list --format ID,Name --no-header)
        for id in $( { [ -n "${VOL_ID:-}" ] && echo "$VOL_ID"; awk -v n="$VOLUME_NAME" '$2==n{print $1}' <<<"$vol_out"; } | awk 'NF && !seen[$0]++'); do
            gone=0
            for i in $(seq 24); do
                if run_do compute volume delete "$id" --force; then gone=1; break; fi
                sleep 5
            done
            [ $gone = 1 ] || echo "destroy: could not delete the volume $id (still attached?); the check below counts it" >&2
        done
    else
        if [ -n "${VOL_ID:-}" ]; then run_do compute volume delete "$VOL_ID" --force || true; fi
        run_do compute volume list --format ID,Name --no-header
        echo "would delete every volume named $VOLUME_NAME (retrying while it detaches)" >&2
    fi
    if [ -n "${FW_ID:-}" ]; then run_do compute firewall delete "$FW_ID" --force || true; fi
    if [ $APPROVED = 1 ]; then
        fw_out=$(run_do compute firewall list --format ID,Name --no-header)
        for id in $(awk -v n="$NAME" '$2==n{print $1}' <<<"$fw_out"); do run_do compute firewall delete "$id" --force || true; done
    elif [ -z "${FW_ID:-}" ]; then
        run_do compute firewall list --format ID,Name --no-header
    fi
    if [ -n "${KEY_ID:-}" ]; then run_do compute ssh-key delete "$KEY_ID" --force || true; fi
    if [ $APPROVED = 1 ]; then
        key_out=$(run_do compute ssh-key list --format ID,Name --no-header)
        for id in $(awk -v n="$NAME" '$2==n{print $1}' <<<"$key_out"); do run_do compute ssh-key delete "$id" --force || true; done
    elif [ -z "${KEY_ID:-}" ]; then
        run_do compute ssh-key list --format ID,Name --no-header
    fi
    run_do compute tag delete "$NAME" --force || true
    # The Spaces buckets: empty and delete each one (the server's own and
    # bench.sh's -objects, -openscion, -scale). With no bucket left the
    # $5/month Spaces subscription ends.
    mapfile -t buckets < <(spaces_buckets)
    if [ "${#buckets[@]}" -gt 0 ]; then
        if [ $APPROVED = 1 ]; then
            for b in "${buckets[@]}"; do
                st=$(spaces_code HEAD "/$b/")
                [ "$st" = 404 ] && continue
                if command -v aws >/dev/null; then
                    AWS_ACCESS_KEY_ID=$VEIL_DO_SPACES_KEY AWS_SECRET_ACCESS_KEY=$VEIL_DO_SPACES_SECRET AWS_DEFAULT_REGION=$REGION \
                        aws --endpoint-url "$SPACES_ENDPOINT" s3 rb "s3://$b" --force || echo "destroy: emptying $b with aws failed; empty and delete it in the control panel (Spaces > $b > Settings > Destroy)" >&2
                else
                    spaces_code DELETE "/$b/" >/dev/null || true
                    echo "destroy: no 'aws' CLI: if $b was not empty, delete it in the control panel (Spaces > $b > Settings > Destroy), or install awscli and re-run" >&2
                fi
            done
        else
            for b in "${buckets[@]}"; do echo "would empty and delete the Spaces bucket $b (aws s3 rb --force)" >&2; done
        fi
    elif [ $APPROVED = 0 ]; then
        echo "would empty and delete Spaces buckets ${NAME}-objects-* (aws s3 rb --force)" >&2
    fi
fi

echo "== check: nothing left running or billing for '$NAME'"
left=0
count_lines() { # grep args..., text in $LAST
    local text=${!#}
    [ -z "$text" ] && { echo 0; return; }
    printf '%s\n' "$text" | grep -c "${@:1:$#-1}" || true
}
out=$(run_do compute droplet list --tag-name "$NAME" --format ID --no-header); n=$(count_lines . "$out")
echo "   droplets tagged $NAME: $n"; [ "$n" = 0 ] || left=1
out=$(run_do compute firewall list --format Name --no-header); n=$(count_lines -x "$NAME" "$out")
echo "   firewalls named $NAME: $n"; [ "$n" = 0 ] || left=1
out=$(run_do compute ssh-key list --format Name --no-header); n=$(count_lines -x "$NAME" "$out")
echo "   ssh keys named $NAME: $n"; [ "$n" = 0 ] || left=1
out=$(run_do compute volume list --format Name --no-header); n=$(count_lines "^$NAME" "$out")
echo "   block volumes named $NAME*: $n"; [ "$n" = 0 ] || left=1
out=$(run_do compute snapshot list --format Name --no-header); n=$(count_lines "^$NAME" "$out")
echo "   snapshots named $NAME*: $n"; [ "$n" = 0 ] || left=1
out=$(run_do compute reserved-ip list --format IP --no-header); n=$(count_lines . "$out")
echo "   reserved IPs in the account (any bills \$4/month when unassigned): $n"; [ "$n" = 0 ] || left=1
out=$(run_do compute load-balancer list --format Name --no-header); n=$(count_lines "^$NAME" "$out")
echo "   load balancers named $NAME*: $n"; [ "$n" = 0 ] || left=1
mapfile -t buckets < <(spaces_buckets)
if [ "${#buckets[@]}" -eq 0 ]; then
    if [ $APPROVED = 1 ]; then
        lcode=$(spaces_code GET "/")
        echo "   Spaces buckets named $NAME*: 0 (list HTTP $lcode)"
        case "$lcode" in 200) ;; *) left=1 ;; esac
    else
        echo "   Spaces buckets named $NAME*: dry"
    fi
else
    for b in "${buckets[@]}"; do
        if [ $APPROVED = 1 ]; then bs=$(spaces_code HEAD "/$b/"); else echo "would HEAD $SPACES_ENDPOINT/$b/" >&2; bs=dry; fi
        echo "   Spaces bucket $b: HTTP $bs (404 = gone)"
        case "$bs" in dry|404) ;; *) left=1 ;; esac
    done
fi
if [ $APPROVED = 1 ]; then
    if [ $left = 0 ]; then echo "destroy: nothing left. Also glance at Billing in the control panel tomorrow."; rm -f "$STATE_FILE"
    else echo "destroy: SOMETHING IS LEFT (above); fix it, then re-run $0 --check --approve" >&2; exit 1; fi
else echo "(dry run: the counts above are of the printed commands, not the account)"; fi
