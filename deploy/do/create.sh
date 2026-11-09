#!/usr/bin/env bash
# Create the test's resources at DigitalOcean (docs/DEPLOY.md, "Create").
# Without --approve it is a dry run that prints every command it would
# run. With --approve it creates, in this order, all tagged NAME:
#   1. an SSH key for this run (generated into deploy/do/state/NAME/);
#   2. a cloud firewall: SSH and the server's port from the operator's
#      address; everything between the test's own droplets; nothing else in;
#   3. the droplets (hub, database or YugabyteDB nodes, drivers, optional
#      cache), from cloud-init/docker.yaml, waiting until they run;
#   4. the state file with their addresses (the Spaces bucket is created by
#      the server itself at first start, under the name saved here).
# Then run configure.sh. Re-running create.sh on an existing state refuses.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
[ $# -eq 0 ] || { echo "create: unknown argument '$1' (usage: create.sh [--approve|--dry-run])" >&2; exit 2; }
: "${VEIL_DO_OPERATOR_IP:?set VEIL_DO_OPERATOR_IP in $ENV_FILE (your public IPv4)}"
[[ "$VEIL_DO_OPERATOR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ "$VEIL_DO_OPERATOR_IP" != "0.0.0.0" ] || {
    echo "create: invalid VEIL_DO_OPERATOR_IP '$VEIL_DO_OPERATOR_IP' (must be your single public IPv4 address)" >&2; exit 2
}
if [ $APPROVED = 1 ]; then
    if [ -s "$STATE_FILE" ] || [ -n "${KEY_ID:-}${FW_ID:-}${DROPLET_IDS:-}" ]; then
        echo "create: state for '$NAME' exists ($STATE_FILE); destroy.sh first" >&2; exit 1
    fi
fi

echo "== plan: $NAME in $REGION"
droplets | while read -r role name size; do printf '   %-10s %-22s %s\n' "$role" "$name" "$size"; done
BUCKET=${BUCKET:-$NAME-objects-$(openssl rand -hex 3)}
echo "   Spaces bucket $BUCKET at $SPACES_ENDPOINT (created by the server at first start)"
est=$("$DO_HERE/estimate.sh" 2>/dev/null) || { "$DO_HERE/estimate.sh" >/dev/null; exit 1; }
printf '%s\n' "$est" | tail -4 | sed 's/^/   /'
[ $APPROVED = 1 ] || echo "== dry run: the commands that --approve would run follow"

if [ $APPROVED = 1 ]; then
    ensure_state_dir
    save_state BUCKET "$BUCKET"
fi

# 1. SSH key for this run.
if [ ! -f "$STATE/id_ed25519" ]; then
    if [ $APPROVED = 1 ]; then ssh-keygen -q -t ed25519 -N '' -C "$NAME" -f "$STATE/id_ed25519"; chmod 600 "$STATE/id_ed25519"; else echo "would generate $STATE/id_ed25519" >&2; fi
fi
KEY_ID=$(run_do compute ssh-key import "$NAME" --public-key-file "$STATE/id_ed25519.pub" --format ID --no-header)
if [ $APPROVED = 1 ]; then save_state KEY_ID "$KEY_ID"; fi

# 2. Firewall: operator in on 22 and 8443/8444; the test's droplets reach
# each other on every port (database, YugabyteDB, the server); all out.
TAGS="tag:$NAME"
INBOUND="protocol:tcp,ports:22,address:$VEIL_DO_OPERATOR_IP/32 protocol:tcp,ports:8443,address:$VEIL_DO_OPERATOR_IP/32 protocol:tcp,ports:8444,address:$VEIL_DO_OPERATOR_IP/32 protocol:tcp,ports:all,$TAGS protocol:udp,ports:all,$TAGS protocol:icmp,$TAGS"
OUTBOUND="protocol:tcp,ports:all,address:0.0.0.0/0,address:::/0 protocol:udp,ports:all,address:0.0.0.0/0,address:::/0 protocol:icmp,address:0.0.0.0/0,address:::/0"
run_do compute tag create "$NAME" >/dev/null || true
FW_ID=$(run_do compute firewall create --name "$NAME" --tag-names "$NAME" --inbound-rules "$INBOUND" --outbound-rules "$OUTBOUND" --format ID --no-header)
if [ $APPROVED = 1 ]; then save_state FW_ID "$FW_ID"; fi

# 3. Droplets, all at once, then wait for each.
IDS=()
while read -r role name size; do
    id=$(run_do compute droplet create "$name" --region "$REGION" --size "$size" --image "$IMAGE" \
        --ssh-keys "${KEY_ID:-KEY_ID}" --tag-names "$NAME" --user-data-file "$DO_HERE/cloud-init/docker.yaml" \
        --enable-monitoring --format ID --no-header)
    IDS+=("$id")
    if [ $APPROVED = 1 ]; then save_state DROPLET_IDS "${IDS[*]}"; fi
done < <(droplets)
if [ $APPROVED = 1 ]; then
    echo "== waiting for the droplets to run"
    for id in "${IDS[@]}"; do
        for i in $(seq 60); do
            st=$(run_do compute droplet get "$id" --format Status --no-header 2>/dev/null || echo unknown)
            [ "$st" = active ] && break; sleep 5
        done
        [ "$st" = active ] || { echo "create: droplet $id is '$st' after 5 minutes; destroy.sh --approve and try again" >&2; exit 1; }
    done
    # 4. Addresses.
    while read -r id name pub priv; do
        save_state "IP_${name//-/_}" "$pub"; save_state "PRIV_${name//-/_}" "$priv"
        printf '   %-22s public %-16s private %s\n' "$name" "$pub" "$priv"
    done < <(run_do compute droplet list --tag-name "$NAME" --format ID,Name,PublicIPv4,PrivateIPv4 --no-header)
    echo "== created. Next: deploy/do/configure.sh --approve   (state: $STATE_FILE)"
else
    echo "would wait for ${#IDS[@]} droplets, save their addresses to $STATE_FILE, and save BUCKET=$BUCKET" >&2
fi
