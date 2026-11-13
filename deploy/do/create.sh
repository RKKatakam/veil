#!/usr/bin/env bash
# Create the test's resources at DigitalOcean (docs/DEPLOY.md, "Create").
# Without --approve it is a dry run that prints every command it would
# run. With --approve it creates, in this order, all tagged NAME:
#   1. an SSH key for this run (generated into deploy/do/state/NAME/);
#   2. a cloud firewall: SSH and the server's port from the operator's
#      address; everything between the test's own droplets; nothing else in;
#   3. with VEIL_DO_OBJECTS_VOLUME_GB, the storage droplet's block volume
#      (NAME-minio-data, tagged NAME, ext4);
#   4. the droplets (hub, database or YugabyteDB nodes, drivers, the MinIO
#      storage droplet with VEIL_DO_OBJECTS=minio, optional cache), from
#      cloud-init/docker.yaml, waiting until they run;
#   5. the state file with their addresses (the bucket is created by the
#      server itself at first start, under the name saved here: on MinIO, or
#      on Spaces with VEIL_DO_OBJECTS=spaces; the `spaces` gate's Spaces
#      bucket, BUCKET-spaces, by its own server).
# Then run configure.sh. Re-running create.sh on an existing state refuses.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
[ $# -eq 0 ] || { echo "create: unknown argument '$1' (usage: create.sh [--approve|--dry-run])" >&2; exit 2; }
: "${VEIL_DO_OPERATOR_IP:?set VEIL_DO_OPERATOR_IP in $ENV_FILE (your public IPv4)}"
[[ "$VEIL_DO_OPERATOR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ "$VEIL_DO_OPERATOR_IP" != "0.0.0.0" ] || {
    echo "create: invalid VEIL_DO_OPERATOR_IP '$VEIL_DO_OPERATOR_IP' (must be your single public IPv4 address)" >&2; exit 2
}
if [ $APPROVED = 1 ]; then
    if [ -s "$STATE_FILE" ] || [ -n "${KEY_ID:-}${FW_ID:-}${DROPLET_IDS:-}${VOL_ID:-}" ]; then
        echo "create: state for '$NAME' exists ($STATE_FILE); destroy.sh first" >&2; exit 1
    fi
fi

echo "== plan: $NAME in $REGION"
droplets | while read -r role name size; do printf '   %-10s %-22s %s\n' "$role" "$name" "$size"; done
BUCKET=${BUCKET:-$NAME-objects-$(openssl rand -hex 3)}
if [ "$OBJECTS" = minio ]; then
    echo "   objects: MinIO on $NAME-minio ($SIZE_OBJECTS$([ "$OBJECTS_VOLUME_GB" -gt 0 ] && echo ", volume $VOLUME_NAME of $OBJECTS_VOLUME_GB GB")), bucket $BUCKET (created by the server at first start)"
    echo "   Spaces bucket $BUCKET-spaces at $SPACES_ENDPOINT for the spaces gate (created by its server)"
else
    echo "   Spaces bucket $BUCKET at $SPACES_ENDPOINT (created by the server at first start), and $BUCKET-spaces for the spaces gate"
fi
est=$("$DO_HERE/estimate.sh" 2>/dev/null) || { "$DO_HERE/estimate.sh" >/dev/null; exit 1; }
printf '%s\n' "$est" | grep -E '^(hourly rate|planned|24 hours|a whole month)' | sed 's/^/   /'
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

# 3. The storage droplet's volume, attached when the droplet is created
# (destroy.sh deletes it by name; its check counts volumes named NAME*).
VOL_ARGS=()
if [ "$OBJECTS_VOLUME_GB" -gt 0 ]; then
    VOL_ID=$(run_do compute volume create "$VOLUME_NAME" --region "$REGION" --size "${OBJECTS_VOLUME_GB}GiB" --fs-type ext4 \
        --tag "$NAME" --desc "$NAME: MinIO's data" --format ID --no-header)
    if [ $APPROVED = 1 ]; then save_state VOL_ID "$VOL_ID"; fi
    VOL_ARGS=(--volumes "${VOL_ID:-VOL_ID}")
fi

# 4. Droplets, all at once, then wait for each.
IDS=()
while read -r role name size; do
    extra=(); [ "$role" = minio ] && extra=("${VOL_ARGS[@]+"${VOL_ARGS[@]}"}")
    id=$(run_do compute droplet create "$name" --region "$REGION" --size "$size" --image "$IMAGE" \
        --ssh-keys "${KEY_ID:-KEY_ID}" --tag-names "$NAME" --user-data-file "$DO_HERE/cloud-init/docker.yaml" \
        --enable-monitoring "${extra[@]+"${extra[@]}"}" --format ID --no-header)
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
    # 5. Addresses.
    while read -r id name pub priv; do
        save_state "IP_${name//-/_}" "$pub"; save_state "PRIV_${name//-/_}" "$priv"
        printf '   %-22s public %-16s private %s\n' "$name" "$pub" "$priv"
    done < <(run_do compute droplet list --tag-name "$NAME" --format ID,Name,PublicIPv4,PrivateIPv4 --no-header)
    echo "== created. Next: deploy/do/configure.sh --approve   (state: $STATE_FILE)"
else
    echo "would wait for ${#IDS[@]} droplets, save their addresses to $STATE_FILE, and save BUCKET=$BUCKET" >&2
fi
