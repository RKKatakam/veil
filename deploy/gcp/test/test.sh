#!/usr/bin/env bash
# Tests of the Google Cloud kit without Google Cloud (docs/DEPLOY.md §12.8):
# a fake `gcloud` (test/fake-gcloud: a made-up project that remembers what
# was created, stopped and deleted), and fake ssh, scp, docker and curl on
# PATH record what the scripts would do. Checks:
#   1. without --approve nothing calls gcloud, ssh, scp or curl and nothing
#      is written; every script's dry run of the full topology exits 0;
#      flag typos are refused;
#   2. the approval gate: --approve refuses without a project, without
#      credentials, with a readable key file; the key file reaches gcloud as
#      a path in the environment only;
#   3. create.sh --approve issues exactly the expected commands: the run's
#      network, subnet and two firewall rules (the operator's address only
#      from outside), ten labelled VMs, Spot exactly where VEIL_GCP_SPOT
#      says, the local SSD on the on-demand storage machine, no service
#      account, the project's SSH keys blocked, the run's public key the only
#      thing in the metadata; state private; a second create refuses;
#   4. estimate.sh: the three models, unknown types and E2 storage refused,
#      $100 refused, --live prices from the Billing Catalog with the token on
#      curl's stdin only;
#   5. configure.sh --approve through the shared steps: every machine
#      reached, MinIO's data on the local SSD, MinIO started directly, the
#      certificate naming localhost, no spaces.env;
#   6. bench.sh --approve and Spot reclaims: a clean gate is valid; a VM
#      reclaimed during a gate marks it invalid, is started again and the gate
#      rerun once (valid); reclaimed twice fails without a third run; a VM
#      down before the gate is started first; with VEIL_GCP_SPOT=all a
#      reclaimed storage machine means configure.sh again;
#   7. destroy.sh: --check finds running and stopped VMs and their disks,
#      a leftover disk, firewall rule, network or address, and fails when
#      gcloud fails; destroy --approve deletes them all, then --check passes;
#   8. preflight.sh: quotas short (what to request, where), enough, Spot on
#      PREEMPTIBLE_CPUS, billing off;
#   9. no secret (the key file's content, the access token, MinIO's
#      credentials, the servers' keys) in any command line, output, metadata,
#      result or log;
#  10. with VEIL_GCP_REAL_GCLOUD=/path/to/gcloud, every command shape the
#      scripts issued parses in the real gcloud CLI (no credentials, no
#      project: each stops at "no active account", never at its arguments).
# Everything runs under a temporary directory inside the worktree's .scratch/.
set -euo pipefail
export LC_ALL=C
HERE=$(cd "$(dirname "$0")" && pwd); GCP=$(cd "$HERE/.." && pwd); ROOT=$(cd "$GCP/../.." && pwd)
T=$ROOT/.scratch/gcp-test-$$; mkdir -p "$T"
trap '[ "${KEEP_TEST_DIR:-0}" = 1 ] || { [[ -n "${T:-}" && -n "${ROOT:-}" && "$T" == "$ROOT/.scratch/gcp-test-"* ]] && rm -rf -- "$T"; }' EXIT
export FAKE_GCLOUD_DIR=$T/project; mkdir -p "$FAKE_GCLOUD_DIR"
export FAKE_GCLOUD_LOG=$T/gcloud.log FAKE_SSH_LOG=$T/ssh.log FAKE_CURL_LOG=$T/curl.log FAKE_GCLOUD_ARGV=$T/argv.log
: > "$FAKE_GCLOUD_LOG"; : > "$FAKE_SSH_LOG"; : > "$FAKE_CURL_LOG"
mkdir -p "$T/bin"; cp "$HERE/fake-gcloud" "$T/bin/gcloud"
# Also every call's argv, quoted, for the real CLI's syntax check (10).
sed -i 's|^echo "gcloud \$\*" >> "${FAKE_GCLOUD_LOG:?}"|&\nprintf "%q " "$@" >> "$FAKE_GCLOUD_ARGV"; echo >> "$FAKE_GCLOUD_ARGV"|' "$T/bin/gcloud"
cat > "$T/bin/curl" <<'CURL'
#!/usr/bin/env bash
echo "curl $*" >> "${FAKE_CURL_LOG:?}"
if [[ " $* " == *" -K - "* ]]; then
    cfg=$(cat); [[ "$cfg" == *'header = "Authorization: Bearer '* ]] || { echo "fake-curl: no token header on stdin" >&2; exit 1; }
    if [[ "$*" == *pageToken=* ]]; then cat "${FAKE_SKUS2:?}"; else cat "${FAKE_SKUS:?}"; fi
    exit 0
fi
[[ "$*" == *"%{http_code}"* ]] && printf 404
exit 0
CURL
# ssh as the real one: without -n it reads all of stdin. A gate's benchmark
# command can trigger a Spot reclaim: the first name in $FAKE_GCLOUD_DIR/preempt
# is stopped (TERMINATED) and a compute.instances.preempted operation recorded.
cat > "$T/bin/ssh" <<'SSH'
#!/usr/bin/env bash
echo "ssh $*" >> "${FAKE_SSH_LOG:?}"
[[ " $* " == *" -n "* ]] || cat > /dev/null
D=$FAKE_GCLOUD_DIR
if [[ "$*" == *"timeout --kill-after"* ]] && [ -s "$D/preempt" ]; then
    name=$(head -1 "$D/preempt"); sed -i 1d "$D/preempt"
    awk -v n="$name" '$1 == n {$3 = "TERMINATED"} {print}' "$D/instances" > "$D/i.tmp"; mv "$D/i.tmp" "$D/instances"
    echo "op-$(( $(wc -l < "$D/ops") + 1 )) $name 2026-11-14T10:00:00.000-08:00" >> "$D/ops"
fi
# $D/break-lists: gcloud's listings fail from the gate on (fake-gcloud).
if [[ "$*" == *"timeout --kill-after"* ]] && [ -f "$D/break-lists" ]; then touch "$D/lists-broken"; fi
case "$*" in
    *"cat /var/lib/veil/hub-"*) echo "fake-server-key-material" ;;
    *"cat /var/lib/veil/stats.json"*) echo '{"landing_batches": 0}' ;;
    *"{{.RestartCount}}' minio"*) echo 0 ;;
esac
exit 0
SSH
printf '#!/usr/bin/env bash\necho "scp $*" >> "${FAKE_SSH_LOG:?}"\n' > "$T/bin/scp"
cat > "$T/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
case "$1" in save) echo "fake image $2" ;; image) echo "sha256:fake revision=fake" ;; esac
exit 0
DOCKER
printf '#!/usr/bin/env bash\ncat\n' > "$T/bin/zstd"
chmod +x "$T"/bin/*
export PATH=$T/bin:$PATH
# The kit under test, with its state and results under $T.
mkdir -p "$T/kit"; cp -r "$GCP" "$T/kit/gcp"; mkdir -p "$T/kit/do"; cp "$GCP/../do/"*.sh "$T/kit/do/"
rm -rf "$T/kit/gcp/state" "$T/kit/gcp/.env"
sed -i "s|^DO_ROOT=.*|DO_ROOT=$ROOT|; s|^STATE=\$GCP_HERE/state/\$NAME|STATE=$T/state/\$NAME|" "$T/kit/gcp/lib.sh"
sed -i "s|OUT=\$DO_ROOT/deploy/results/|OUT=$T/results/|" "$T/kit/do/bench.sh" "$T/kit/do/logs.sh"
sed -i "s|^RESULTS=\$DO_ROOT/deploy/results/\$NAME|RESULTS=$T/results/\$NAME|" "$T/kit/gcp/bench.sh"
K=$T/kit/gcp
export VEIL_GCP_ENV=$T/env
cat > "$VEIL_GCP_ENV" <<ENV
VEIL_GCP_PROJECT=veil-kit-test-1
VEIL_GCP_NAME=veil-kit
VEIL_GCP_OPERATOR_IP=203.0.113.200
VEIL_GCP_DB_PASSWORD=secret-db-pass
ENV
chmod 600 "$VEIL_GCP_ENV"
SA_SECRET=SECRET-SA-KEY-CONTENT-7f3a
printf '{"type": "service_account", "private_key": "%s"}\n' "$SA_SECRET" > "$T/sa.json"; chmod 600 "$T/sa.json"
fail=0; n_ok=0
check() { if eval "$2"; then echo "   ok    $1"; n_ok=$((n_ok + 1)); else echo "   FAIL  $1"; fail=1; fi; }
reset_project() { rm -rf "$FAKE_GCLOUD_DIR"; mkdir -p "$FAKE_GCLOUD_DIR"; : > "$FAKE_GCLOUD_LOG"; }
GATES=$(. "$ROOT/deploy/gates.sh" >/dev/null 2>&1; echo "$GATES_ALL")

echo "== 1. dry runs, .env permissions, flag typos"
chmod 644 "$VEIL_GCP_ENV"
out=$("$K/estimate.sh" 2>&1 || true); check "a world-readable .env is refused" '[[ "$out" == *"refusing a group- or world-readable file"* ]]'
chmod 600 "$VEIL_GCP_ENV"
dry_rc=""
for s in preflight estimate create configure logs destroy; do "$K/$s.sh" >/dev/null 2>&1 || dry_rc+=" $s"; done
"$K/estimate.sh" --live >/dev/null 2>&1 || dry_rc+=" estimate--live"
"$K/destroy.sh" --check >/dev/null 2>&1 || dry_rc+=" destroy--check"
for g in $GATES; do [ "$g" = spaces ] && continue; "$K/bench.sh" "$g" >/dev/null 2>&1 || dry_rc+=" bench-$g"; done
check "every script's dry run of the full topology exits 0 (failed:${dry_rc:- none})" '[ -z "$dry_rc" ]'
out=$("$K/create.sh" 2>&1)
check "create.sh's dry run prints the plan, the estimate and the commands" '[[ "$out" == *"veil-kit-minio       c2d-standard-16  on-demand boot 20 GB, 1 x 375 GB local NVMe SSD"* && "$out" == *"planned 8 hours:"* && "$out" == *"would run: gcloud compute instances create veil-kit-hub --zone=us-central1-a"* ]]'
check "no gcloud, ssh, scp or curl call without --approve" '[ ! -s "$FAKE_GCLOUD_LOG" ] && [ ! -s "$FAKE_SSH_LOG" ] && [ ! -s "$FAKE_CURL_LOG" ]'
check "dry runs touch nothing on disk (no state, no results)" '[ ! -e "$T/state" ] && [ ! -e "$T/results" ]'
check "flag typos and stray arguments are refused" '
    ! "$K/create.sh" --aprove >/dev/null 2>&1 && ! "$K/destroy.sh" --chcek >/dev/null 2>&1 &&
    ! "$K/configure.sh" --aprove >/dev/null 2>&1 && ! "$K/estimate.sh" --lve >/dev/null 2>&1 &&
    ! "$K/logs.sh" --aprove >/dev/null 2>&1 && ! "$K/bench.sh" --aprove pull >/dev/null 2>&1 &&
    ! "$K/preflight.sh" --aprove >/dev/null 2>&1 && ! "$K/bench.sh" nosuchgate >/dev/null 2>&1'
check "invalid settings are refused: a name, a zone of another region, a Spot model, a size" '
    ! VEIL_GCP_NAME=Veil_Big "$K/estimate.sh" >/dev/null 2>&1 && ! VEIL_GCP_ZONE=europe-west1-b "$K/estimate.sh" >/dev/null 2>&1 &&
    ! VEIL_GCP_SPOT=some "$K/estimate.sh" >/dev/null 2>&1 && ! VEIL_GCP_SIZE_HUB="c2d standard" "$K/estimate.sh" >/dev/null 2>&1'
out=$("$K/bench.sh" spaces 2>&1 || true)
check "the spaces gate (DigitalOcean Spaces) is refused" '[[ "$out" == *"the gcp kit has none"* ]]'
check "still no gcloud call" '[ ! -s "$FAKE_GCLOUD_LOG" ]'

echo "== 2. the approval gate and credentials"
out=$(VEIL_GCP_PROJECT= "$K/create.sh" --approve 2>&1 || true); check "--approve without a project refuses" '[[ "$out" == *"needs VEIL_GCP_PROJECT"* ]]'
out=$(FAKE_GCLOUD_ACCOUNT= "$K/create.sh" --approve 2>&1 || true)
check "--approve without a key file or an active gcloud account refuses, having only asked gcloud who is logged in" '[[ "$out" == *"needs VEIL_GCP_CREDENTIALS"* ]] && [ "$(grep -vc "^gcloud auth list" "$FAKE_GCLOUD_LOG")" = 0 ] && [ ! -e "$T/state" ]'
chmod 644 "$T/sa.json"
out=$(VEIL_GCP_CREDENTIALS=$T/sa.json "$K/create.sh" --approve 2>&1 || true)
check "a group- or world-readable key file is refused" '[[ "$out" == *"refusing a group- or world-readable file"* ]] && [ ! -e "$T/state" ]'
chmod 600 "$T/sa.json"
echo "VEIL_GCP_CREDENTIALS=$T/sa.json" >> "$VEIL_GCP_ENV"
check "--approve on estimate.sh without --live, or on configure/bench/logs before create.sh, refuses" '
    ! "$K/estimate.sh" --approve >/dev/null 2>&1 && ! "$K/configure.sh" --approve >/dev/null 2>&1 &&
    ! "$K/bench.sh" --approve pull >/dev/null 2>&1 && ! "$K/logs.sh" --approve >/dev/null 2>&1'
out=$(VEIL_GCP_OPERATOR_IP=0.0.0.0/0 "$K/create.sh" --approve 2>&1 || true)
check "create.sh refuses a wildcard or CIDR operator address" '[[ "$out" == *"invalid VEIL_GCP_OPERATOR_IP"* ]]'
out=$(VEIL_GCP_SIZE_OBJECTS=e2-standard-16 "$K/create.sh" --approve 2>&1 || true)
check "create.sh refuses an E2 or shared-core storage machine (no dedicated vCPUs, no local SSD; BUG-2431)" '[[ "$out" == *"cannot be the storage machine"* ]]'
refused=0; for t in t2d-standard-16 c3d-standard-16; do
    o=$(VEIL_GCP_SIZE_OBJECTS=$t "$K/estimate.sh" 2>&1) && continue; [[ "$o" == *"cannot be the storage machine"* ]] && refused=$((refused + 1)); done
check "a storage type that cannot take an attached local SSD (T2D, C3D) is refused before anything is made" '[ $refused = 2 ]'
check "no resource command so far" '! grep -qE "^gcloud compute (networks|firewall-rules|instances|disks)" "$FAKE_GCLOUD_LOG"'

echo "== 3. create.sh --approve: the full topology, hybrid Spot"
reset_project
out_c=$("$K/create.sh" --approve 2>&1); rc=$?
S=$T/state/veil-kit
check "create.sh --approve succeeds" '[ $rc = 0 ] && [[ "$out_c" == *"== created."* ]]'
seq_got=$(awk '{print $2, $3, $4}' "$FAKE_GCLOUD_LOG" | tr '\n' ';')
seq_want="compute networks create;compute networks subnets;compute firewall-rules create;compute firewall-rules create;$(for i in $(seq 10); do printf 'compute instances create;compute disks add-labels;'; done)compute instances list;"
check "it issues exactly: network, subnet, two firewall rules, ten VMs each with its disk labelled, one address listing" '[ "$seq_got" = "$seq_want" ]'
check "every call names the project and gets credentials from the key file's path in the environment, prompts off" '[ "$(grep -vc -- "--project=veil-kit-test-1$" "$FAKE_GCLOUD_LOG")" = 0 ] && [ "$(sort -u "$FAKE_GCLOUD_DIR/env.log")" = "cred=$T/sa.json prompts=1" ]'
check "the network is the run's own: a custom subnet in the region" 'grep -q "^gcloud compute networks create veil-kit-net --subnet-mode=custom" "$FAKE_GCLOUD_LOG" && grep -q "^gcloud compute networks subnets create veil-kit-subnet --network=veil-kit-net --region=us-central1 --range=10.42.0.0/24" "$FAKE_GCLOUD_LOG"'
check "from outside only the operator's address, on 22 and 8443; inside, the run's tagged machines" '
    grep -q "^gcloud compute firewall-rules create veil-kit-operator --network=veil-kit-net --direction=INGRESS --action=ALLOW --rules=tcp:22,tcp:8443 --source-ranges=203.0.113.200/32 --target-tags=veil-kit " "$FAKE_GCLOUD_LOG" &&
    grep -q "^gcloud compute firewall-rules create veil-kit-internal --network=veil-kit-net --direction=INGRESS --action=ALLOW --rules=tcp,udp,icmp --source-tags=veil-kit --target-tags=veil-kit " "$FAKE_GCLOUD_LOG" &&
    [ "$(grep -o -- "--source-ranges=[^ ]*" "$FAKE_GCLOUD_LOG" | sort -u)" = "--source-ranges=203.0.113.200/32" ]'
creates=$(grep "^gcloud compute instances create" "$FAKE_GCLOUD_LOG")
check "ten VMs, each labelled veil-run=veil-kit, tagged veil-kit, in the one zone and subnet, no service account" '[ "$(grep -c . <<<"$creates")" = 10 ] && [ "$(grep -c -- "--zone=us-central1-a --machine-type=[^ ]* --subnet=veil-kit-subnet .*--labels=veil-run=veil-kit,veil-role=[a-z]* --tags=veil-kit .*--no-service-account --no-scopes" <<<"$creates")" = 10 ]'
check "Spot exactly for the 3 servers, the balancer and the 2 drivers (stop when reclaimed)" '[ "$(grep -c -- "--provisioning-model=SPOT --instance-termination-action=STOP" <<<"$creates")" = 6 ] && [ "$(grep -- "--provisioning-model=SPOT" <<<"$creates" | awk "{print \$5}" | tr "\n" " ")" = "veil-kit-hub veil-kit-hub2 veil-kit-hub3 veil-kit-lb veil-kit-driver1 veil-kit-driver2 " ]'
check "sizes: c2d-standard-16 servers and storage, e2-standard-4 balancer, c2d-standard-8 YugabyteDB and drivers" 'grep -q "create veil-kit-hub3 --zone=us-central1-a --machine-type=c2d-standard-16" <<<"$creates" && grep -q "create veil-kit-lb --zone=us-central1-a --machine-type=e2-standard-4" <<<"$creates" && grep -q "create veil-kit-yb2 --zone=us-central1-a --machine-type=c2d-standard-8" <<<"$creates" && grep -q "create veil-kit-driver2 --zone=us-central1-a --machine-type=c2d-standard-8" <<<"$creates"'
check "the storage machine is on-demand with one local NVMe SSD; nothing else has one" '[ "$(grep -c -- "--local-ssd=interface=NVME" <<<"$creates")" = 1 ] && grep "create veil-kit-minio " <<<"$creates" | grep -q -- "--local-ssd=interface=NVME" && ! grep "create veil-kit-minio " <<<"$creates" | grep -q SPOT && ! grep "create veil-kit-yb" <<<"$creates" | grep -q SPOT'
check "the metadata: OS Login off, the project's SSH keys blocked, user-data from the run's state; nothing else" '[ "$(grep -o -- "--metadata[^ ]*" <<<"$creates" | sort -u | tr "\n" " ")" = "--metadata-from-file=user-data=$S/user-data.yaml --metadata=enable-oslogin=FALSE,block-project-ssh-keys=TRUE " ]'
pub=$(cat "$S/id_ed25519.pub")
check "user-data is the cloud-init with the run's public key as root's only key, and no private key" 'grep -qxF "      $pub" "$S/user-data.yaml" && [ "$(grep -c "ssh-ed25519" "$S/user-data.yaml")" = 1 ] && ! grep -q "PRIVATE KEY\|@@" "$S/user-data.yaml" && grep -q "^disable_root: false" "$S/user-data.yaml" && grep -q "PermitRootLogin prohibit-password" "$S/user-data.yaml"'
. "$S/state.env"
check "state holds the ten addresses and the bucket; the key, user-data and state are private" '[ "$IP_veil_kit_hub" = 203.0.113.1 ] && [ "$PRIV_veil_kit_minio" = 10.42.0.10 ] && [[ "$BUCKET" == veil-kit-objects-* ]] && [ "$(stat -c %a "$S")" = 700 ] && [ "$(stat -c %a "$S/state.env")" = 600 ] && [ "$(stat -c %a "$S/id_ed25519")" = 600 ] && [ "$(stat -c %a "$S/user-data.yaml")" = 600 ]'
out=$("$K/create.sh" --approve 2>&1 || true); check "a second create.sh refuses while state exists" '[[ "$out" == *"destroy.sh first"* ]]'
out=$(VEIL_GCP_SPOT=none VEIL_GCP_NAME=veil-kit-od "$K/create.sh" 2>&1)
check "VEIL_GCP_SPOT=none: no Spot VM; =all: all ten" '! grep -q -- "--provisioning-model=SPOT" <<<"$out" && [ "$(VEIL_GCP_SPOT=all VEIL_GCP_NAME=veil-kit-all "$K/create.sh" 2>&1 | grep -c -- "--provisioning-model=SPOT")" = 10 ]'

echo "== 4. estimate.sh"
out=$("$K/estimate.sh" 2>/dev/null)
check "the hybrid plan: \$3.465 an hour, \$27.72 for 8 hours; the three models priced" '[[ "$out" == *"hourly rate:                 \$3.465"* && "$out" == *"planned 8 hours:            \$27.72"* && "$out" == *"on-demand (VEIL_GCP_SPOT=none)"*"5.110     40.88"* && "$out" == *"all Spot (all; database and storage too)"*"2.470     19.76"* ]]'
check "it prices the local SSD, the boot disks, the addresses, a forgotten month and stopped VMs" '[[ "$out" == *"local SSD (MinIO'"'"'s data)   375 GiB NVMe     on-demand      0.041"* && "$out" == *"boot disks (pd-balanced)   1140 GiB"* && "$out" == *"4 std + 6 spot"* && "$out" == *"a whole month forgotten:     \$2529.64"* && "$out" == *"stopped VMs, a month:        \$114.00"* ]]'
check "a plan of \$100 or more is refused (29 hours), 28 hours is not; an unknown type is refused" '! VEIL_GCP_HOURS=29 "$K/estimate.sh" >/dev/null 2>&1 && ! VEIL_GCP_HOURS=29 "$K/create.sh" >/dev/null 2>&1 && VEIL_GCP_HOURS=28 "$K/estimate.sh" >/dev/null 2>&1 && ! VEIL_GCP_SIZE_HUB=n2-standard-16 "$K/estimate.sh" >/dev/null 2>&1 && ! VEIL_GCP_SIZE_OBJECTS=e2-standard-8 "$K/estimate.sh" >/dev/null 2>&1'
sku() { printf '{"description":"%s","serviceRegions":["us-central1"],"pricingInfo":[{"pricingExpression":{"tieredRates":[{"unitPrice":{"units":"0","nanos":%s}}]}}]}' "$1" "$2"; }
{ printf '{"skus":['; sku "C2D AMD Instance Core running in Americas" 30000000; printf ,; sku "C2D AMD Instance Ram running in Americas" 4000000; printf ,
  sku "Spot Preemptible C2D AMD Instance Core running in Americas" 10000000; printf ,; sku "Spot Preemptible C2D AMD Instance Ram running in Americas" 1000000; printf ,
  sku "E2 Instance Core running in Americas" 20000000; printf '],"nextPageToken":"page2"}\n'; } > "$T/skus1.json"
{ printf '{"skus":['; sku "E2 Instance Ram running in Americas" 3000000; printf ,; sku "Spot Preemptible E2 Instance Core running in Americas" 10000000; printf ,
  sku "Spot Preemptible E2 Instance Ram running in Americas" 1000000; printf ,; sku "SSD backed Local Storage" 80000000; printf ,
  sku "Balanced PD Capacity" 100000000; printf ,; sku "External IP Charge on a Standard VM" 5000000; printf ,; sku "External IP Charge on a Spot Preemptible VM" 2500000; printf ']}\n'; } > "$T/skus2.json"
: > "$FAKE_GCLOUD_LOG"
out=$(FAKE_SKUS=$T/skus1.json FAKE_SKUS2=$T/skus2.json "$K/estimate.sh" --live --approve 2>&1); rc=$?
check "--live --approve prices from the Billing Catalog's two pages (\$3.024 an hour with the made-up SKUs)" '[ $rc = 0 ] && [[ "$out" == *"hourly rate:                 \$3.024"* && "$out" == *"planned 8 hours:            \$24.19"* ]] && [ "$(grep -c "cloudbilling.googleapis.com/v1/services/6F81-5844-456A/skus" "$FAKE_CURL_LOG")" = 2 ]'
check "the access token went to curl on stdin only: in no command line and no output" '! grep -q "fake-access-token" "$FAKE_CURL_LOG" "$FAKE_GCLOUD_LOG" && [[ "$out" != *"fake-access-token"* ]] && [ "$(grep -c "^gcloud auth print-access-token" "$FAKE_GCLOUD_LOG")" = 1 ]'
out=$(FAKE_SKUS=$T/skus2.json FAKE_SKUS2=$T/skus2.json "$K/estimate.sh" --live --approve 2>&1 || true)
check "a live price that is missing (no C2D SKUs) is unknown, and the estimate refuses" '[[ "$out" == *"unknown"* && "$out" == *"cannot bound the total cost"* ]]'

echo "== 5. configure.sh --approve through the shared steps"
: > "$FAKE_SSH_LOG"
g_before=$(wc -l < "$FAKE_GCLOUD_LOG")
out_cfg=$("$K/configure.sh" --approve gcpkit-test 2>&1 </dev/null); rc=$?
check "configure.sh --approve succeeds" '[ $rc = 0 ] && [[ "$out_cfg" == *"== configured."* && "$out_cfg" == *"deploy/gcp/bench.sh --approve"* ]]'
check "it waits for cloud-init on all ten machines, as root with the run's key only" '[ "$(grep -c "cloud-init status --wait" "$FAKE_SSH_LOG")" = 10 ] && [ "$(grep "^ssh" "$FAKE_SSH_LOG" | grep -vc -- "-i $S/id_ed25519 .*-o IdentitiesOnly=yes")" = 0 ]'
check "MinIO's data on the storage machine's local NVMe SSD (a file system made only when it has none)" 'grep "root@203.0.113.10" "$FAKE_SSH_LOG" | grep -q "dev=/dev/disk/by-id/google-local-nvme-ssd-0;.*blkid \$dev >/dev/null 2>&1 || mkfs.ext4 .*mount -o discard,defaults,noatime \$dev /mnt/minio-data"'
check "MinIO is started directly (the server binary, never the image's setup script), its data on the SSD" 'grep -q "docker run -d --name minio .*-v /mnt/minio-data:/bitnami/minio/data .*--entrypoint /opt/bitnami/minio/bin/minio .* server --certs-dir /certs" "$FAKE_SSH_LOG"'
check "the certificate names the storage machine, and localhost (BUG-2432)" 'openssl x509 -in "$S/tls/server.pem" -noout -text | grep -q "DNS:veil-kit-minio" && openssl x509 -in "$S/tls/server.pem" -noout -text | grep -q "DNS:localhost" && openssl x509 -in "$S/tls/server.pem" -noout -text | grep -q "IP Address:10.42.0.10"'
check "three YugabyteDB nodes, three servers, the balancer; no spaces.env (no Spaces here)" '[ "$(grep -c "bin/yugabyted start" "$FAKE_SSH_LOG")" = 3 ] && [ "$(grep -c "docker run -d --name veil-server" "$FAKE_SSH_LOG")" = 3 ] && grep -q "docker run -d --name veil-lb" "$FAKE_SSH_LOG" && ! grep -q spaces.env "$FAKE_SSH_LOG" && [ ! -e "$S/spaces.env" ]'
check "configure.sh called no gcloud" '[ "$(wc -l < "$FAKE_GCLOUD_LOG")" = "$g_before" ]'
MIN_P=$(sed -n 's/^MINIO_ROOT_PASSWORD=//p' "$S/minio.env"); MIN_U=$(sed -n 's/^MINIO_ROOT_USER=//p' "$S/minio.env")

echo "== 6. bench.sh --approve and Spot reclaims"
res() { ls -d "$T"/results/veil-kit/*-"$1" 2>/dev/null | sort; }
rc=0; out=$("$K/bench.sh" --approve pull 2>&1 </dev/null) || rc=$?
r1=$(res pull)
check "a clean gate: one results directory, run.txt says no Spot VM was reclaimed and the result is valid" '[ $rc = 0 ] && [ "$(grep -c . <<<"$r1")" = 1 ] && grep -qx "spot_reclaimed_during=none" "$r1/run.txt" && grep -qx "result_valid=yes" "$r1/run.txt" && [ -s "$r1/topology.env" ] && grep -qx "SPOT=hybrid" "$r1/topology.env"'
check "it looked for preemptions in the zone and at the Spot VMs, before and after" '[ "$(grep -c "^gcloud compute operations list --zones=us-central1-a --filter=operationType=compute.instances.preempted" "$FAKE_GCLOUD_LOG")" = 2 ]'
rm -rf "$T/results"; : > "$FAKE_GCLOUD_LOG"
echo veil-kit-driver1 > "$FAKE_GCLOUD_DIR/preempt"
rc=0; out=$("$K/bench.sh" --approve pull 2>&1 </dev/null) || rc=$?
mapfile -t rr < <(res pull)
check "a reclaim during the gate: two results directories, the gate rerun once and valid" '[ $rc = 0 ] && [ "${#rr[@]}" = 2 ] && [[ "${rr[1]}" == *-rerun-pull ]]'
check "the first run.txt: reclaimed driver1, result invalid, which directory reran it" 'grep -qx "spot_reclaimed_during=veil-kit-driver1" "${rr[0]}/run.txt" && grep -q "^result_valid=no" "${rr[0]}/run.txt" && grep -qx "rerun=$(basename "${rr[1]}")" "${rr[0]}/run.txt"'
check "the rerun's run.txt: rerun_of the first, nothing reclaimed, valid" 'grep -qx "rerun_of=$(basename "${rr[0]}")" "${rr[1]}/run.txt" && grep -qx "spot_reclaimed_during=none" "${rr[1]}/run.txt" && grep -qx "result_valid=yes" "${rr[1]}/run.txt"'
. "$S/state.env"
check "driver1 was started again, its new public address saved, and the rerun reached it there" 'grep -q "^gcloud compute instances start veil-kit-driver1 --zone=us-central1-a" "$FAKE_GCLOUD_LOG" && [ "$IP_veil_kit_driver1" = 198.51.100.1 ] && grep -q "root@198.51.100.1 .*timeout --kill-after" "$FAKE_SSH_LOG" && [ "$(grep -c "instances start" "$FAKE_GCLOUD_LOG")" = 1 ]'
rm -rf "$T/results"; : > "$FAKE_GCLOUD_LOG"
printf '%s\n' veil-kit-driver1 veil-kit-driver1 > "$FAKE_GCLOUD_DIR/preempt"
rc=0; out=$("$K/bench.sh" --approve pull 2>&1 </dev/null) || rc=$?
mapfile -t rr < <(res pull)
check "reclaimed during the rerun too: exit 3, both results invalid, no third run" '[ $rc = 3 ] && [ "${#rr[@]}" = 2 ] && grep -q "^result_valid=no" "${rr[0]}/run.txt" && grep -q "^result_valid=no" "${rr[1]}/run.txt" && [[ "$out" == *"not run a third time"* ]]'
rm -rf "$T/results"; : > "$FAKE_GCLOUD_LOG"
awk '$1 == "veil-kit-driver1" {$3 = "RUNNING"} {print}' "$FAKE_GCLOUD_DIR/instances" > "$T/i"; mv "$T/i" "$FAKE_GCLOUD_DIR/instances"
touch "$FAKE_GCLOUD_DIR/break-lists"
rc=0; out=$("$K/bench.sh" --approve pull 2>&1 </dev/null) || rc=$?
rm -f "$FAKE_GCLOUD_DIR/break-lists" "$FAKE_GCLOUD_DIR/lists-broken"
r1=$(res pull)
check "gcloud failing to say whether a Spot VM was reclaimed during the gate: exit 1 and the result is not valid" '[ $rc = 1 ] && [ "$(grep -c . <<<"$r1")" = 1 ] && grep -q "^result_valid=no (Google Cloud did not answer" "$r1/run.txt" && ! grep -q "^result_valid=yes" "$r1/run.txt" && [[ "$out" == *"its result is not valid"* ]]'
rm -rf "$T/results"; : > "$FAKE_GCLOUD_LOG"
awk '$1 == "veil-kit-driver1" {$3 = "RUNNING"} $1 == "veil-kit-hub2" {$3 = "TERMINATED"} {print}' "$FAKE_GCLOUD_DIR/instances" > "$T/i"; mv "$T/i" "$FAKE_GCLOUD_DIR/instances"
: > "$FAKE_SSH_LOG"
rc=0; out=$("$K/bench.sh" --approve land 2>&1 </dev/null) || rc=$?
r1=$(res land)
check "a server stopped between gates is started first and its server brought back healthy; the gate is valid and says so" '[ $rc = 0 ] && [ "$(grep -c . <<<"$r1")" = 1 ] && grep -qx "spot_restarted_before=veil-kit-hub2" "$r1/run.txt" && grep -qx "result_valid=yes" "$r1/run.txt" && grep -q "^gcloud compute instances start veil-kit-hub2" "$FAKE_GCLOUD_LOG" && grep -q "docker start veil-server" "$FAKE_SSH_LOG"'
check "the restart did not reconfigure anything (a server keeps its disk)" '[ "$(grep -c "cloud-init status --wait" "$FAKE_SSH_LOG")" = 1 ] && ! grep -q "docker run -d --name veil-server" "$FAKE_SSH_LOG"'
rm -rf "$T/results"; : > "$FAKE_GCLOUD_LOG"; : > "$FAKE_SSH_LOG"
echo veil-kit-minio > "$FAKE_GCLOUD_DIR/preempt"
rc=0; out=$(VEIL_GCP_SPOT=all "$K/bench.sh" --approve pull 2>&1 </dev/null) || rc=$?
mapfile -t rr < <(res pull)
check "VEIL_GCP_SPOT=all, the storage machine reclaimed: configure.sh again (MinIO's SSD is blank), then the rerun" '[ $rc = 0 ] && [ "${#rr[@]}" = 2 ] && grep -qx "spot_reclaimed_during=veil-kit-minio" "${rr[0]}/run.txt" && grep -qx "spot_reconfigured=yes" "${rr[1]}/run.txt" && grep -q "docker run -d --name minio" "$FAKE_SSH_LOG" && grep -qx "result_valid=yes" "${rr[1]}/run.txt"'
rm -rf "$T/results"

echo "== 7. destroy.sh and its check"
awk '$1 == "veil-kit-driver2" {$3 = "TERMINATED"} {print}' "$FAKE_GCLOUD_DIR/instances" > "$T/i"; mv "$T/i" "$FAKE_GCLOUD_DIR/instances"
: > "$FAKE_GCLOUD_LOG"
out=$("$K/destroy.sh" --check --approve 2>&1 || true)
check "the check counts every VM, a stopped Spot VM among them, their disks, the firewall rules, subnet and network" '[[ "$out" == *"VMs (any state): 10 (of which stopped, e.g. reclaimed Spot VMs, still billing their disks: 1)"* && "$out" == *"disks: 10"* && "$out" == *"firewall rules: 2"* && "$out" == *"subnets: 1"* && "$out" == *"networks: 1"* && "$out" == *"SOMETHING IS LEFT"* ]]'
check "the check only reads" '! grep -qE "^gcloud compute [a-z -]+ (delete|create|start|stop)" "$FAKE_GCLOUD_LOG"'
check "it looks by the label or the kit's exact names (never a bare prefix), whatever the VMs' state" 'grep -q "^gcloud compute instances list --filter=labels.veil-run=veil-kit OR name~'"'"'^veil-kit-(hub\[23\]?|lb|db|yb\[0-9\]|driver\[0-9\]|minio|cache)\$'"'"' --format=value(name,zone.basename(),status) " "$FAKE_GCLOUD_LOG" && ! grep -q "name~'"'"'^veil-kit-'"'"'" "$FAKE_GCLOUD_LOG"'
check "the check fails when gcloud itself fails" '! FAKE_GCLOUD_FAIL=1 "$K/destroy.sh" --check --approve >/dev/null 2>&1'
cp "$FAKE_GCLOUD_DIR/instances" "$T/instances.bak"
: > "$FAKE_GCLOUD_LOG"
out=$("$K/destroy.sh" --approve 2>&1); rc=$?
dels=$(grep -E "^gcloud compute .* delete" "$FAKE_GCLOUD_LOG")
check "destroy deletes the ten VMs (the stopped one too) with all their disks, then the rules, subnet and network, in that order" '[ $rc = 0 ] && grep -q "^gcloud compute instances delete veil-kit-hub veil-kit-hub2 veil-kit-hub3 veil-kit-lb veil-kit-yb1 veil-kit-yb2 veil-kit-yb3 veil-kit-driver1 veil-kit-driver2 veil-kit-minio --zone=us-central1-a --delete-disks=all --quiet" <<<"$dels" && [ "$(awk "{print \$3}" <<<"$dels" | tr "\n" " ")" = "instances firewall-rules networks networks " ] && grep -q "firewall-rules delete veil-kit-operator veil-kit-internal" <<<"$dels" && grep -q "networks subnets delete veil-kit-subnet --region=us-central1" <<<"$dels" && grep -q "networks delete veil-kit-net --quiet" <<<"$dels"'
check "after it the check passed and removed the state file" '[[ "$out" == *"destroy: nothing left."* ]] && [ ! -f "$S/state.env" ]'
echo "veil-kit-minio us-central1-a" > "$FAKE_GCLOUD_DIR/disks"
out=$("$K/destroy.sh" --check --approve 2>&1 || true)
check "the check fails while a disk is left (a VM deleted without its disks)" '[[ "$out" == *"disks: 1"* && "$out" == *"SOMETHING IS LEFT"* ]]'
"$K/destroy.sh" --approve >/dev/null 2>&1; : > "$FAKE_GCLOUD_DIR/disks"
echo "veil-kit-operator" > "$FAKE_GCLOUD_DIR/fw"
out=$("$K/destroy.sh" --check --approve 2>&1 || true); : > "$FAKE_GCLOUD_DIR/fw"
check "the check fails while a firewall rule is left" '[[ "$out" == *"firewall rules: 1"* && "$out" == *"SOMETHING IS LEFT"* ]]'
out=$(FAKE_ADDRESSES=veil-kit-lb "$K/destroy.sh" --check --approve 2>&1 || true)
check "the check fails while an external address is left" '[[ "$out" == *"external addresses: 1"* && "$out" == *"SOMETHING IS LEFT"* ]]'
out=$("$K/destroy.sh" --check --approve 2>&1); rc=$?
check "with nothing left the check exits 0" '[ $rc = 0 ] && [[ "$out" == *"VMs (any state): 0"* && "$out" == *"destroy: nothing left."* ]]'
# A run that died part-way: 4 of 10 VMs; destroy finds them by label without state.
reset_project; rm -rf "$S"
rc=0; FAKE_MAX_INSTANCES=4 "$K/create.sh" --approve >/dev/null 2>&1 || rc=$?
check "a create that fails at the fifth VM leaves state that blocks configure and a second create" '[ $rc != 0 ] && grep -q "^INSTANCES=veil-kit-hub\\\\ veil-kit-hub2\\\\ veil-kit-hub3\\\\ veil-kit-lb$" "$S/state.env" && ! "$K/configure.sh" --approve >/dev/null 2>&1 && ! "$K/create.sh" --approve >/dev/null 2>&1'
rm -f "$S/state.env"
out=$("$K/destroy.sh" --approve 2>&1); rc=$?
check "destroy without state removes the four VMs, the rules, subnet and network" '[ $rc = 0 ] && [[ "$out" == *"VMs (any state): 0"* && "$out" == *"destroy: nothing left."* ]] && [ ! -s "$FAKE_GCLOUD_DIR/instances" ] && [ ! -s "$FAKE_GCLOUD_DIR/nets" ]'

echo "== 8. preflight.sh"
q() { # metric=limit... -> quota JSON
    local kv out='{"quotas":['
    for kv in "$@"; do out+="{\"metric\":\"${kv%%=*}\",\"limit\":${kv#*=},\"usage\":0},"; done
    echo "${out%,}]}"
}
q CPUS=24 C2D_CPUS=24 PREEMPTIBLE_CPUS=0 LOCAL_SSD_TOTAL_GB=6000 SSD_TOTAL_GB=500 IN_USE_ADDRESSES=8 INSTANCES=24 > "$T/region-short.json"
q CPUS_ALL_REGIONS=32 > "$T/project-short.json"
q CPUS=24 C2D_CPUS=128 PREEMPTIBLE_CPUS=0 LOCAL_SSD_TOTAL_GB=6000 SSD_TOTAL_GB=2048 IN_USE_ADDRESSES=16 INSTANCES=24 > "$T/region-ok.json"
q CPUS_ALL_REGIONS=128 > "$T/project-ok.json"
q CPUS=24 C2D_CPUS=48 PREEMPTIBLE_CPUS=96 LOCAL_SSD_TOTAL_GB=6000 SSD_TOTAL_GB=2048 IN_USE_ADDRESSES=16 INSTANCES=24 > "$T/region-pre.json"
: > "$FAKE_GCLOUD_LOG"
rc=0; out=$(FAKE_REGION_JSON=$T/region-short.json FAKE_PROJECT_JSON=$T/project-short.json "$K/preflight.sh" --approve 2>&1) || rc=$?
check "short quotas: exit 1, and exactly what to request, where" '[ $rc = 1 ] && [[ "$out" == *"- C2D CPUs (C2D_CPUS), region us-central1: new limit >= 104"* && "$out" == *"- Persistent Disk SSD (GB) (SSD_TOTAL_GB), region us-central1: new limit >= 1140"* && "$out" == *"- In-use regional external IPv4 addresses (IN_USE_ADDRESSES), region us-central1: new limit >= 10"* && "$out" == *"- CPUs (all regions) (CPUS_ALL_REGIONS), global: new limit >= 108"* && "$out" == *"IAM & Admin > Quotas & System Limits"* ]] && [[ "$out" != *"(LOCAL_SSD_TOTAL_GB)"* && "$out" != *"(INSTANCES)"* ]]'
check "preflight only reads" '! grep -qE "^gcloud [a-z -]+ (create|delete|start|stop|enable|update|link)" "$FAKE_GCLOUD_LOG"'
rc=0; out=$(FAKE_REGION_JSON=$T/region-ok.json FAKE_PROJECT_JSON=$T/project-ok.json "$K/preflight.sh" --approve 2>&1) || rc=$?
check "enough quota, billing on, the API on, the types offered: ready" '[ $rc = 0 ] && [[ "$out" == *"preflight: ready."* && "$out" == *"C2D_CPUS                   us-central1      128       0     128     104  ok"* ]]'
rc=0; out=$(FAKE_REGION_JSON=$T/region-pre.json FAKE_PROJECT_JSON=$T/project-ok.json "$K/preflight.sh" --approve 2>&1) || rc=$?
check "with PREEMPTIBLE_CPUS granted, the 68 Spot vCPUs count there and C2D_CPUS needs only the 40 on-demand" '[ $rc = 0 ] && [[ "$out" == *"PREEMPTIBLE_CPUS           us-central1       96       0      96      68  ok"* && "$out" == *"C2D_CPUS                   us-central1       48       0      48      40  ok"* ]]'
rc=0; out=$(FAKE_BILLING=False FAKE_NO_TYPE=c2d-standard-8 FAKE_REGION_JSON=$T/region-ok.json FAKE_PROJECT_JSON=$T/project-ok.json "$K/preflight.sh" --approve 2>&1) || rc=$?
check "billing off or a type the zone lacks: not ready" '[ $rc = 1 ] && [[ "$out" == *"billing: NOT enabled"* && "$out" == *"c2d-standard-8: NOT offered in us-central1-a"* ]]'
rc=0; out=$(FAKE_OSLOGIN_ENFORCED=True FAKE_REGION_JSON=$T/region-ok.json FAKE_PROJECT_JSON=$T/project-ok.json "$K/preflight.sh" --approve 2>&1) || rc=$?
check "an organisation policy enforcing OS Login: not ready" '[ $rc = 1 ] && [[ "$out" == *"enforces OS Login"* ]]'

echo "== 9. secrets"
everything=$(cat "$FAKE_GCLOUD_LOG" "$FAKE_SSH_LOG" "$FAKE_CURL_LOG" "$FAKE_GCLOUD_DIR/env.log" 2>/dev/null; echo "$out_c $out_cfg"; cat "$T"/state/*/user-data.yaml "$T"/state/*/state.env 2>/dev/null; find "$T/results" -type f -exec cat {} + 2>/dev/null || true)
check "the key file's content, the access token, the database password and the servers' keys appear in no command line, output, user-data, state or result" '[[ "$everything" != *"$SA_SECRET"* && "$everything" != *"fake-access-token"* && "$everything" != *"secret-db-pass"* && "$everything" != *"fake-server-key-material"* ]]'
check "MinIO's credentials (made for the run) appear on no command line or output" '[ -n "$MIN_P" ] && [[ "$everything" != *"$MIN_P"* && "$everything" != *"$MIN_U"* ]]'
check "the key file reached gcloud only as a path, the topology beside results has no project id or secret" '! grep -q "$SA_SECRET" "$FAKE_GCLOUD_DIR/env.log" && grep -q "cred=$T/sa.json" "$FAKE_GCLOUD_DIR/env.log" && ! (cd "$T/kit/gcp" && VEIL_KIT=gcp bash -c ". ./lib.sh; topology" 2>/dev/null | grep -q "veil-kit-test-1\|secret")'

echo "== 10. the real gcloud CLI parses every command shape"
if [ -n "${VEIL_GCP_REAL_GCLOUD:-}" ]; then
    REAL_CFG=$T/real-gcloud-config; mkdir -p "$REAL_CFG"
    bad=""; tried=0
    while IFS= read -r line; do
        eval "set -- $line"
        a=(); for x in "$@"; do [[ "$x" == --metadata-from-file=user-data=* ]] && x=--metadata-from-file=user-data=/etc/hostname; a+=("$x"); done
        # No credentials, no network: an unusable proxy, no metadata server, no update check.
        o=$(env -u CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE CLOUDSDK_CONFIG="$REAL_CFG" CLOUDSDK_CORE_CHECK_GCE_METADATA=false \
            CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=true CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=true CLOUDSDK_CORE_DISABLE_PROMPTS=1 \
            HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 \
            "$VEIL_GCP_REAL_GCLOUD" "${a[@]}" 2>&1) && continue
        tried=$((tried + 1))
        [[ "$o" == *"do not currently have an active account"* ]] || bad+=$'\n'"      $* -> $(head -1 <<<"$o")"
    done < <(awk '{k=$1" "$2" "$3; for (i=4;i<=NF;i++) if ($i ~ /^--/) { split($i, p, "="); k=k" "p[1] } } !seen[k]++' "$FAKE_GCLOUD_ARGV")
    check "every command shape ($tried) stops at the missing account, none at its arguments${bad}" '[ -z "$bad" ] && [ "$tried" -gt 10 ]'
else
    echo "   skip  (set VEIL_GCP_REAL_GCLOUD to a gcloud binary to check the commands' syntax)"
fi

[ $fail = 0 ] && echo "deploy/gcp/test: all green ($n_ok checks)" || { echo "deploy/gcp/test: FAILED"; exit 1; }
