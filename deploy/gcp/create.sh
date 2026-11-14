#!/usr/bin/env bash
# Create the test's resources at Google Cloud (docs/DEPLOY.md §12.3).
# Without --approve it is a dry run that prints every command it would run.
# With --approve it creates, in the project VEIL_GCP_PROJECT, in one zone:
#   1. an SSH key for this run (generated into deploy/gcp/state/NAME/);
#   2. a VPC network NAME-net with one subnet NAME-subnet (SUBNET_RANGE):
#      the run's own, so no other network's firewall rules apply;
#   3. two firewall rules on it, for the instances tagged NAME: NAME-operator
#      (SSH and the balancer's port, from the operator's address only) and
#      NAME-internal (everything between the run's machines); nothing else
#      comes in (Google's implied rule denies all other ingress);
#   4. the machines (servers, balancer, YugabyteDB nodes or PostgreSQL,
#      drivers, the MinIO storage machine with one local NVMe SSD, the
#      optional cache), Spot or on-demand as VEIL_GCP_SPOT says, each with
#      the label veil-run=NAME and the tag NAME, from cloud-init/docker.yaml
#      with the run's public key, no service account, OS Login off and the
#      project's SSH keys blocked; their boot disks get the label too;
#   5. the state file with their addresses (the bucket is made by the server
#      on MinIO at first start, under the name saved here).
# Spot VMs stop when reclaimed (--instance-termination-action=STOP): a
# stopped VM keeps its disk, its images and its configuration, and
# bench.sh starts it again and reruns the gate it interrupted (§12.5); it
# bills only its disk while stopped, and destroy.sh --check counts it.
# Then run configure.sh. Re-running create.sh on an existing state refuses.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
[ $# -eq 0 ] || { echo "create: unknown argument '$1' (usage: create.sh [--approve|--dry-run])" >&2; exit 2; }
: "${VEIL_GCP_OPERATOR_IP:?set VEIL_GCP_OPERATOR_IP in $ENV_FILE (your public IPv4)}"
[[ "$VEIL_GCP_OPERATOR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ "$VEIL_GCP_OPERATOR_IP" != "0.0.0.0" ] || {
    echo "create: invalid VEIL_GCP_OPERATOR_IP '$VEIL_GCP_OPERATOR_IP' (must be your single public IPv4 address)" >&2; exit 2
}
refuse_shared_objects create
if [ $APPROVED = 1 ] && { [ -s "$STATE_FILE" ] || [ -n "${INSTANCES:-}" ]; }; then
    echo "create: state for '$NAME' exists ($STATE_FILE); destroy.sh first" >&2; exit 1
fi

echo "== plan: $NAME in $ZONE (project ${PROJECT:-PROJECT}), VEIL_GCP_SPOT=$SPOT"
while read -r role name size; do
    if is_spot "$role"; then m=spot; else m=on-demand; fi
    extra=""; [ "$role" = minio ] && extra=", 1 x ${LOCAL_SSD_GB} GB local NVMe SSD for MinIO's data"
    printf '   %-8s %-20s %-16s %-9s boot %s GB%s\n' "$role" "$name" "$size" "$m" "$(boot_gb "$role")" "$extra"
done < <(droplets)
BUCKET=${BUCKET:-$NAME-objects-$(openssl rand -hex 3)}
echo "   objects: MinIO on $NAME-minio, bucket $BUCKET (made by the server at first start)"
est=$("$GCP_HERE/estimate.sh" 2>/dev/null) || { "$GCP_HERE/estimate.sh" >/dev/null; exit 1; }
printf '%s\n' "$est" | grep -E '^(hourly rate|planned|24 hours|a whole month|stopped VMs)' | sed 's/^/   /'
[ $APPROVED = 1 ] || echo "== dry run: the commands that --approve would run follow"
if [ $APPROVED = 1 ]; then ensure_state_dir; save_state BUCKET "$BUCKET"; fi

# 1. The run's SSH key.
if [ ! -f "$STATE/id_ed25519" ]; then
    if [ $APPROVED = 1 ]; then ssh-keygen -q -t ed25519 -N '' -C "$NAME" -f "$STATE/id_ed25519"; chmod 600 "$STATE/id_ed25519"
    else echo "would generate $STATE/id_ed25519" >&2; fi
fi

# 2. The run's network and subnet.
run_gcloud compute networks create "$NAME-net" --subnet-mode=custom --description="Veil test $NAME"
if [ $APPROVED = 1 ]; then save_state NETWORK "$NAME-net"; fi
run_gcloud compute networks subnets create "$NAME-subnet" --network="$NAME-net" --region="$REGION" --range="$SUBNET_RANGE"

# 3. Firewall: the operator in on 22 and 8443 (8444 with the cache); the
# run's machines reach each other on every port; Google's implied rules
# deny every other ingress and allow egress (packages, the images' pulls).
PORTS=tcp:22,tcp:8443; [ "$WITH_CACHE" = 1 ] && PORTS+=,tcp:8444
run_gcloud compute firewall-rules create "$NAME-operator" --network="$NAME-net" --direction=INGRESS --action=ALLOW \
    --rules="$PORTS" --source-ranges="$VEIL_GCP_OPERATOR_IP/32" --target-tags="$NAME"
run_gcloud compute firewall-rules create "$NAME-internal" --network="$NAME-net" --direction=INGRESS --action=ALLOW \
    --rules=tcp,udp,icmp --source-tags="$NAME" --target-tags="$NAME"

# 4. The machines' user-data: cloud-init with the run's public key (only).
USER_DATA=$STATE/user-data.yaml
if [ $APPROVED = 1 ]; then
    pub=$(cat "$STATE/id_ed25519.pub")
    [[ "$pub" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+\ [a-z0-9-]+$ ]] || { echo "create: unexpected public key in $STATE/id_ed25519.pub" >&2; exit 1; }
    sed "s|@@RUN_SSH_PUBLIC_KEY@@|$pub|" "$GCP_HERE/cloud-init/docker.yaml" > "$USER_DATA"; chmod 600 "$USER_DATA"
else echo "would write $USER_DATA (cloud-init/docker.yaml with the run's public key)" >&2; fi
MADE=()
while read -r role name size; do
    extra=()
    if is_spot "$role"; then
        extra+=(--provisioning-model=SPOT --instance-termination-action=STOP --maintenance-policy=TERMINATE --no-restart-on-failure)
    fi
    [ "$role" = minio ] && extra+=(--local-ssd=interface=NVME)
    run_gcloud compute instances create "$name" --zone="$ZONE" --machine-type="$size" --subnet="$NAME-subnet" \
        --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" --boot-disk-size="$(boot_gb "$role")GB" --boot-disk-type=pd-balanced \
        --labels="$LABEL=$NAME,veil-role=$role" --tags="$NAME" \
        --metadata=enable-oslogin=FALSE,block-project-ssh-keys=TRUE --metadata-from-file=user-data="$USER_DATA" \
        --no-service-account --no-scopes "${extra[@]}" --format='value(name)' >/dev/null
    MADE+=("$name")
    if [ $APPROVED = 1 ]; then save_state INSTANCES "${MADE[*]}"; fi
    run_gcloud compute disks add-labels "$name" --zone="$ZONE" --labels="$LABEL=$NAME"
done < <(droplets)

# 5. Addresses (instances create returns once each VM runs).
if [ $APPROVED = 1 ]; then
    n=0
    while IFS=, read -r name pub priv status; do
        [[ " ${MADE[*]} " == *" $name "* ]] || continue
        [ "$status" = RUNNING ] && [ -n "$pub" ] && [ -n "$priv" ] || { echo "create: $name is '$status' without both addresses; destroy.sh --approve and try again" >&2; exit 1; }
        save_state "IP_${name//-/_}" "$pub"; save_state "PRIV_${name//-/_}" "$priv"; n=$((n + 1))
        printf '   %-22s public %-16s private %s\n' "$name" "$pub" "$priv"
    done < <(run_gcloud compute instances list --filter="labels.$LABEL=$NAME" \
        --format='csv[no-heading](name,networkInterfaces[0].accessConfigs[0].natIP,networkInterfaces[0].networkIP,status)')
    [ "$n" = "${#MADE[@]}" ] || { echo "create: found $n of ${#MADE[@]} machines' addresses; destroy.sh --approve and try again" >&2; exit 1; }
    echo "== created. Next: deploy/gcp/configure.sh --approve   (state: $STATE_FILE)"
else
    echo "would save the ${#MADE[@]} machines' addresses to $STATE_FILE, and BUCKET=$BUCKET" >&2
fi
