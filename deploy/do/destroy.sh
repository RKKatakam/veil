#!/usr/bin/env bash
# Destroy everything the test created (docs/DEPLOY.md, "Teardown"), then
# check that nothing tagged NAME is left and that the Spaces bucket is gone.
#   destroy.sh            dry run: what would be deleted
#   destroy.sh --approve  delete: droplets, firewall, SSH key, tag; empty and
#                         delete the Spaces bucket (needs the Spaces keys)
#   destroy.sh --check    only the "nothing left" check (--approve to really query)
# Deleting by tag, not by remembered id, so droplets created by a run that
# died before saving its state are removed too.
. "$(dirname "$0")/lib.sh"
CHECK_ONLY=0; for a in "$@"; do [ "$a" = --check ] && CHECK_ONLY=1; done

spaces() { # METHOD, path, extra curl args...: a signed request to Spaces
    local method=$1 path=$2; shift 2
    # The keys reach curl through its config on stdin, never the command line.
    printf 'user = "%s:%s"\n' "${VEIL_DO_SPACES_KEY:?}" "${VEIL_DO_SPACES_SECRET:?}" |
        curl -sS -K - -o /dev/null -w '%{http_code}' -X "$method" --aws-sigv4 "aws:amz:$REGION:s3" "$SPACES_ENDPOINT$path" "$@"
}
bucket_status() { # 200 exists, 404 gone, 403 not ours or no keys
    [ -n "$BUCKET" ] || { echo none; return; }
    if [ $APPROVED = 1 ]; then spaces HEAD "/$BUCKET/"; else echo "would HEAD $SPACES_ENDPOINT/$BUCKET/" >&2; echo dry; fi
}

if [ $CHECK_ONLY = 0 ]; then
    echo "== destroying everything tagged '$NAME' in the account"
    run_do compute droplet delete --tag-name "$NAME" --force
    if [ -n "${FW_ID:-}" ]; then run_do compute firewall delete "$FW_ID" --force; else
        for id in $(run_do compute firewall list --format ID,Name --no-header | awk -v n="$NAME" '$2==n{print $1}'); do run_do compute firewall delete "$id" --force; done
    fi
    if [ -n "${KEY_ID:-}" ]; then run_do compute ssh-key delete "$KEY_ID" --force; else
        for id in $(run_do compute ssh-key list --format ID,Name --no-header | awk -v n="$NAME" '$2==n{print $1}'); do run_do compute ssh-key delete "$id" --force; done
    fi
    run_do compute tag delete "$NAME" --force || true
    # The Spaces bucket: empty it (the server stores at most a few hundred
    # thousand small objects in a test), then delete it. With no bucket left
    # the $5/month Spaces subscription ends.
    if [ -n "$BUCKET" ]; then
        if [ $APPROVED = 1 ]; then
            if command -v aws >/dev/null; then
                AWS_ACCESS_KEY_ID=$VEIL_DO_SPACES_KEY AWS_SECRET_ACCESS_KEY=$VEIL_DO_SPACES_SECRET AWS_DEFAULT_REGION=$REGION \
                    aws --endpoint-url "$SPACES_ENDPOINT" s3 rb "s3://$BUCKET" --force || echo "destroy: emptying $BUCKET with aws failed; empty and delete it in the control panel (Spaces > $BUCKET > Settings > Destroy)" >&2
            else
                echo "destroy: no 'aws' CLI: delete the bucket in the control panel (Spaces > $BUCKET > Settings > Destroy), or install awscli and re-run" >&2
            fi
        else echo "would empty and delete the Spaces bucket $BUCKET (aws s3 rb --force)" >&2; fi
    fi
fi

echo "== check: nothing left running or billing for '$NAME'"
left=0
n=$(run_do compute droplet list --tag-name "$NAME" --format ID --no-header | grep -c . || true)
echo "   droplets tagged $NAME: $n"; [ "$n" = 0 ] || left=1
n=$(run_do compute firewall list --format Name --no-header | grep -cx "$NAME" || true)
echo "   firewalls named $NAME: $n"; [ "$n" = 0 ] || left=1
n=$(run_do compute ssh-key list --format Name --no-header | grep -cx "$NAME" || true)
echo "   ssh keys named $NAME: $n"; [ "$n" = 0 ] || left=1
n=$(run_do compute volume list --format Name --no-header | grep -c "^$NAME" || true)
echo "   block volumes named $NAME*: $n"; [ "$n" = 0 ] || left=1
n=$(run_do compute snapshot list --format Name --no-header | grep -c "^$NAME" || true)
echo "   snapshots named $NAME*: $n"; [ "$n" = 0 ] || left=1
n=$(run_do compute reserved-ip list --format IP --no-header | grep -c . || true)
echo "   reserved IPs in the account (any bills \$4/month when unassigned): $n"; [ "$n" = 0 ] || left=1
n=$(run_do compute load-balancer list --format Name --no-header | grep -c "^$NAME" || true)
echo "   load balancers named $NAME*: $n"; [ "$n" = 0 ] || left=1
bs=$(bucket_status)
echo "   Spaces bucket $BUCKET: HTTP $bs (404 = gone)"
case "$bs" in none|dry|404) ;; *) left=1 ;; esac
if [ $APPROVED = 1 ]; then
    if [ $left = 0 ]; then echo "destroy: nothing left. Also glance at Billing in the control panel tomorrow."; rm -f "$STATE_FILE"
    else echo "destroy: SOMETHING IS LEFT (above); fix it, then re-run $0 --check --approve" >&2; exit 1; fi
else echo "(dry run: the counts above are of the printed commands, not the account)"; fi
