#!/usr/bin/env bash
# Tests of the provisioning scripts without DigitalOcean (docs/DEPLOY.md,
# "Testing the kit"): fake `doctl`, `aws` and `curl` on PATH record what the
# scripts would run. Checks:
#   1. without --approve nothing calls doctl/aws/curl, and nothing is written;
#      flag typos and --approve given to the wrong script are refused;
#   2. a world-readable .env is refused; secrets never appear on command lines;
#      create.sh --approve refuses without a token, creates the key, firewall
#      and tagged droplets from cloud-init, and saves private state;
#   3. the YugabyteDB and cache options change the topology; estimate.sh bounds
#      cost (including Spaces' $5 flat fee and 24h) and refuses unknown sizes
#      or plans reaching the $100 budget;
#   4. partial create records state, blocks a second create/configure, and
#      destroy.sh --approve removes everything by tag and all 4 Spaces buckets,
#      while --check fails if anything (or doctl itself) fails.
# Everything runs under a temporary state directory inside the worktree's .scratch/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); DO=$(cd "$HERE/.." && pwd); ROOT=$(cd "$DO/../.." && pwd)
T=$ROOT/.scratch/do-test-$$; mkdir -p "$T"
trap '[ "${KEEP_TEST_DIR:-0}" = 1 ] || { [[ -n "${T:-}" && -n "${ROOT:-}" && "$T" == "$ROOT/.scratch/do-test-"* ]] && rm -rf -- "$T"; }' EXIT
export FAKE_DOCTL_LOG=$T/doctl.log; : > "$FAKE_DOCTL_LOG"
export FAKE_AWS_LOG=$T/aws.log; : > "$FAKE_AWS_LOG"
export FAKE_CURL_LOG=$T/curl.log; : > "$FAKE_CURL_LOG"
cp "$HERE/fake-doctl" "$T/doctl"; chmod +x "$T/doctl"
cat > "$T/aws" <<'AWS'
#!/usr/bin/env bash
set -euo pipefail
echo "aws $*" >> "${FAKE_AWS_LOG:?}"
AWS
chmod +x "$T/aws"
cat > "$T/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
echo "curl $*" >> "${FAKE_CURL_LOG:?}"
stdin_cfg=$(cat || true)
[[ "$stdin_cfg" == *"user ="* ]] || { echo "fake-curl: missing user on stdin" >&2; exit 1; }
if [[ "$*" == *"-X GET"* ]]; then
    if [ "${FAKE_SPACES_STATE:-exists}" = exists ]; then
        printf '<ListAllMyBucketsResult><Buckets><Bucket><Name>%s</Name></Bucket></Buckets></ListAllMyBucketsResult>' "${FAKE_BUCKET_NAME:-veil-kit-test-objects-123}"
    else
        printf '<ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>'
    fi
    [[ "$*" == *"%{http_code}"* ]] && printf '200'
elif [ "${FAKE_SPACES_STATE:-exists}" = exists ]; then
    printf '200'
else
    printf '404'
fi
CURL
chmod +x "$T/curl"
export PATH=$T:$PATH
export VEIL_DO_ENV=$T/env
cat > "$VEIL_DO_ENV" <<ENV
VEIL_DO_NAME=veil-kit-test
VEIL_DO_OPERATOR_IP=203.0.113.200
VEIL_DO_SPACES_KEY=secret-spaces-key
VEIL_DO_SPACES_SECRET=secret-spaces-val
VEIL_DO_DB_PASSWORD=secret-db-pass
ENV
export FAKE_NAME=veil-kit-test
export FAKE_DROPLETS="veil-kit-test-hub veil-kit-test-db veil-kit-test-driver1 veil-kit-test-driver2"
# State and results go under the test directory, never deploy/do/state or deploy/results.
mkdir -p "$T/do"; cp "$DO"/*.sh "$T/do/"; cp -r "$DO/cloud-init" "$T/do/"
sed -i "s|^STATE=\$DO_HERE/state/\$NAME|STATE=$T/state/\$NAME|" "$T/do/lib.sh"
sed -i "s|^DO_ROOT=.*|DO_ROOT=$ROOT|" "$T/do/lib.sh"
sed -i "s|OUT=\$DO_ROOT/deploy/results/|OUT=$T/results/|" "$T/do/bench.sh" "$T/do/logs.sh"
fail=0
check() { if eval "$2"; then echo "   ok    $1"; else echo "   FAIL  $1"; fail=1; fi; }

echo "== 1. .env permissions, dry runs, flag typos, and --approve on the wrong script"
chmod 644 "$VEIL_DO_ENV"
out=$("$T/do/estimate.sh" 2>&1 || true); check "world-readable .env is refused" '[[ "$out" == *"refusing a group- or world-readable .env"* ]]'
chmod 600 "$VEIL_DO_ENV"
out=$("$T/do/create.sh" 2>&1); check "create.sh dry run prints the plan" '[[ "$out" == *"would run: doctl compute droplet create veil-kit-test-hub"* ]]'
"$T/do/estimate.sh" >/dev/null 2>&1; "$T/do/estimate.sh" --live >/dev/null 2>&1
"$T/do/destroy.sh" >/dev/null 2>&1; "$T/do/configure.sh" >/dev/null 2>&1
"$T/do/bench.sh" pull >/dev/null 2>&1; "$T/do/logs.sh" >/dev/null 2>&1
check "no doctl, aws or curl call without --approve" '[ ! -s "$FAKE_DOCTL_LOG" ] && [ ! -s "$FAKE_AWS_LOG" ] && [ ! -s "$FAKE_CURL_LOG" ]'
check "dry runs touch nothing on disk (no state dir, no results dir)" '[ ! -e "$T/state" ] && [ ! -e "$T/results" ]'
check "flag typos are refused across every script" '
    ! "$T/do/create.sh" --aprove >/dev/null 2>&1 &&
    ! "$T/do/destroy.sh" --chcek >/dev/null 2>&1 &&
    ! "$T/do/configure.sh" --aprove >/dev/null 2>&1 &&
    ! "$T/do/estimate.sh" --lve >/dev/null 2>&1 &&
    ! "$T/do/logs.sh" --aprove >/dev/null 2>&1 &&
    ! "$T/do/bench.sh" --aprove pull >/dev/null 2>&1 &&
    ! "$ROOT/deploy/docker/build.sh" --approve >/dev/null 2>&1 &&
    ! "$ROOT/deploy/tls/mkcert.sh" --approve >/dev/null 2>&1 &&
    ! "$ROOT/deploy/compose/rehearsal.sh" --approve >/dev/null 2>&1
'
check "still no doctl call after flag typos" '[ ! -s "$FAKE_DOCTL_LOG" ]'

echo "== 2. the approval gate, secrets, and create.sh"
out=$("$T/do/create.sh" --approve 2>&1 || true); check "--approve without a token refuses" '[[ "$out" == *"VEIL_DO_TOKEN"* ]]'
check "still no doctl call" '[ ! -s "$FAKE_DOCTL_LOG" ]'
echo "VEIL_DO_TOKEN=dop_v1_fake_secret_token" >> "$VEIL_DO_ENV"
check "--approve on estimate.sh without --live or on configure/bench/logs before create.sh refuses" '
    ! "$T/do/estimate.sh" --approve >/dev/null 2>&1 &&
    ! "$T/do/configure.sh" --approve >/dev/null 2>&1 &&
    ! "$T/do/bench.sh" --approve pull >/dev/null 2>&1 &&
    ! "$T/do/logs.sh" --approve >/dev/null 2>&1 &&
    ! "$T/do/destroy.sh" --chcek --approve >/dev/null 2>&1
'
check "wrong-script --approve made no doctl call" '[ ! -s "$FAKE_DOCTL_LOG" ]'
out=$(VEIL_DO_OPERATOR_IP=0.0.0.0/0 "$T/do/create.sh" --approve 2>&1 || true)
check "create.sh refuses a wildcard or CIDR operator IP" '[[ "$out" == *"invalid VEIL_DO_OPERATOR_IP"* ]] && [ ! -s "$FAKE_DOCTL_LOG" ]'

out=$("$T/do/create.sh" --approve 2>&1); rc=$?
check "create.sh --approve succeeds" '[ $rc = 0 ]'
check "imports an ssh key generated for the run (mode 600)" 'grep -q "compute ssh-key import veil-kit-test --public-key-file" "$FAKE_DOCTL_LOG" && [ "$(stat -c %a "$T/state/veil-kit-test/id_ed25519")" = 600 ]'
check "firewall opens 22 and 8443 to the operator only" 'grep -q "firewall create --name veil-kit-test --tag-names veil-kit-test --inbound-rules protocol:tcp,ports:22,address:203.0.113.200/32 protocol:tcp,ports:8443,address:203.0.113.200/32" "$FAKE_DOCTL_LOG"'
check "creates 4 droplets, all tagged, from cloud-init" '[ "$(grep -c "compute droplet create" "$FAKE_DOCTL_LOG")" = 4 ] && [ "$(grep "compute droplet create" "$FAKE_DOCTL_LOG" | grep -c -- "--tag-names veil-kit-test .*--user-data-file .*docker.yaml")" = 4 ]'
check "sizes as configured" 'grep -q "create veil-kit-test-hub --region nyc3 --size c-16" "$FAKE_DOCTL_LOG" && grep -q "create veil-kit-test-driver2 --region nyc3 --size c-8" "$FAKE_DOCTL_LOG"'
. "$T/state/veil-kit-test/state.env"
check "state holds the addresses and bucket" '[ "$IP_veil_kit_test_hub" = 203.0.113.1 ] && [ "$PRIV_veil_kit_test_db" = 10.10.0.2 ] && [[ "$BUCKET" == veil-kit-test-objects-* ]] && [ "$FW_ID" = fw-0001 ]'
check "state file and directory are private" '[ "$(stat -c %a "$T/state/veil-kit-test/state.env")" = 600 ] && [ "$(stat -c %a "$T/state/veil-kit-test")" = 700 ]'
out=$("$T/do/create.sh" --approve 2>&1 || true); check "a second create.sh refuses while state exists" '[[ "$out" == *"destroy.sh first"* ]]'
out_cfg=$(VEIL_DO_WITH_CACHE=1 "$T/do/configure.sh" 2>&1)
check "configure.sh dry run names the server command with Spaces and the private DB address" '[[ "$out_cfg" == *"--s3-endpoint https://nyc3.digitaloceanspaces.com --s3-bucket $BUCKET"* && "$out_cfg" == *"10.10.0.2:5432:5432"* ]]'
out_pull=$("$T/do/bench.sh" pull 2>&1)
check "bench.sh pull runs on a driver against the hub's private address" '[[ "$out_pull" == *"would run on 203.0.113.3"* || "$out_pull" == *"would run on 203.0.113.4"* ]] && [[ "$out_pull" == *"--url https://10.10.0.1:8443 --ca /tls/ca.pem"* ]]'
out_os=$("$T/do/bench.sh" openscion 2>&1)
check "bench.sh openscion runs on the hub with its own server" '[[ "$out_os" == *"would run on 203.0.113.1"* && "$out_os" == *"--server /usr/local/bin/veil-server"* ]]'
all_out="$out $out_cfg $out_pull $out_os $(cat "$FAKE_DOCTL_LOG")"
check "no secret ever appears on a command line or in output" '[[ "$all_out" != *"dop_v1_fake_secret_token"* && "$all_out" != *"secret-spaces-key"* && "$all_out" != *"secret-spaces-val"* && "$all_out" != *"secret-db-pass"* ]]'

echo "== 3. topology options and cost bounds"
out=$(VEIL_DO_YB_NODES=3 VEIL_DO_WITH_CACHE=1 VEIL_DO_NAME=veil-kit-yb "$T/do/create.sh" 2>&1)
check "YB_NODES=3 replaces the db droplet with three nodes, WITH_CACHE adds a cache" '[ "$(grep -c "would run: doctl compute droplet create veil-kit-yb-yb" <<<"$out")" = 3 ] && [[ "$out" != *"create veil-kit-yb-db "* ]] && [[ "$out" == *"create veil-kit-yb-cache --region nyc3 --size s-4vcpu-8gb"* ]]'
out=$(VEIL_DO_YB_NODES=3 "$T/do/estimate.sh" 2>/dev/null); check "estimate prices the YugabyteDB topology and Spaces flat fee" '[[ "$out" == *"veil-kit-test-yb3 (yb)"* && "$out" == *"hourly rate (droplets):      \$1.750"* && "$out" == *"planned 8 hours + Spaces:    \$19.00"* && "$out" == *"24 hours left running:       \$47.00"* ]]'
check "estimate and create refuse an unknown droplet size, hours <= 0, or a plan >= \$100" '
    ! VEIL_DO_SIZE_HUB=c-999 "$T/do/estimate.sh" >/dev/null 2>&1 &&
    ! VEIL_DO_SIZE_HUB=c-999 "$T/do/create.sh" >/dev/null 2>&1 &&
    ! VEIL_DO_HOURS=0 "$T/do/estimate.sh" >/dev/null 2>&1 &&
    ! VEIL_DO_HOURS=0 "$T/do/create.sh" >/dev/null 2>&1 &&
    ! VEIL_DO_HOURS=76 "$T/do/estimate.sh" >/dev/null 2>&1 &&
    ! VEIL_DO_HOURS=76 "$T/do/create.sh" >/dev/null 2>&1 &&
    ! VEIL_DO_HOURS=80 "$T/do/estimate.sh" >/dev/null 2>&1 &&
    ! VEIL_DO_HOURS=80 "$T/do/create.sh" >/dev/null 2>&1
'

echo "== 4. destroy.sh and partial create recovery"
export FAKE_DOCTL_STATE_FILE=$T/fake-state; export FAKE_DOCTL_STATE=created; export FAKE_SPACES_STATE=exists
export FAKE_BUCKET_NAME=$BUCKET
out=$("$T/do/destroy.sh" --check --approve 2>&1 || true)
check "the check detects droplets, firewall, ssh key and all 4 Spaces buckets" '[[ "$out" == *"droplets tagged veil-kit-test: 4"* && "$out" == *"firewalls named veil-kit-test: 1"* && "$out" == *"ssh keys named veil-kit-test: 1"* && "$out" == *"Spaces bucket $BUCKET-scale: HTTP 200"* && "$out" == *"SOMETHING IS LEFT"* ]]'
: > "$FAKE_DOCTL_LOG"; : > "$FAKE_AWS_LOG"; : > "$FAKE_CURL_LOG"
out=$(FAKE_DOCTL_STATE=created FAKE_SPACES_STATE=exists "$T/do/destroy.sh" --approve 2>&1 || true)
check "destroy deletes droplets by tag, the firewall, the key and the tag" 'grep -q "compute droplet delete --tag-name veil-kit-test --force" "$FAKE_DOCTL_LOG" && grep -q "compute firewall delete fw-0001 --force" "$FAKE_DOCTL_LOG" && grep -q "compute ssh-key delete 4242 --force" "$FAKE_DOCTL_LOG" && grep -q "compute tag delete veil-kit-test --force" "$FAKE_DOCTL_LOG"'
check "destroy empties and deletes all 4 Spaces buckets without secrets on argv" '
    grep -q "s3://$BUCKET --force" "$FAKE_AWS_LOG" &&
    grep -q "s3://$BUCKET-objects --force" "$FAKE_AWS_LOG" &&
    grep -q "s3://$BUCKET-openscion --force" "$FAKE_AWS_LOG" &&
    grep -q "s3://$BUCKET-scale --force" "$FAKE_AWS_LOG" &&
    ! grep -qE "secret-spaces-(key|val)" "$FAKE_AWS_LOG" "$FAKE_CURL_LOG"
'
out=$(FAKE_DOCTL_STATE=destroyed FAKE_SPACES_STATE=exists "$T/do/destroy.sh" --check --approve 2>&1 || true)
check "the check still fails while a Spaces bucket remains" '[[ "$out" == *"SOMETHING IS LEFT"* ]] && [ -f "$T/state/veil-kit-test/state.env" ]'
out=$(FAKE_DOCTL_STATE=destroyed FAKE_SPACES_STATE=gone FAKE_VOLUMES="veil-kit-test-vol" "$T/do/destroy.sh" --check --approve 2>&1 || true)
check "the check fails when a volume remains" '[[ "$out" == *"block volumes named veil-kit-test*: 1"* && "$out" == *"SOMETHING IS LEFT"* ]]'
out=$(FAKE_DOCTL_STATE=destroyed FAKE_SPACES_STATE=gone FAKE_RESERVED_IPS="203.0.113.99" "$T/do/destroy.sh" --check --approve 2>&1 || true)
check "the check fails when an unassigned reserved IP exists" '[[ "$out" == *"reserved IPs in the account"*": 1"* && "$out" == *"SOMETHING IS LEFT"* ]]'
check "the check fails if doctl itself fails" '! FAKE_DOCTL_FAIL=1 "$T/do/destroy.sh" --check --approve >/dev/null 2>&1'
out=$(FAKE_DOCTL_STATE=destroyed FAKE_SPACES_STATE=gone "$T/do/destroy.sh" --check --approve 2>&1); rc=$?
check "after everything is gone the check exits 0 and removes state.env" '[ $rc = 0 ] && [[ "$out" == *"destroy: nothing left."* ]] && [ ! -f "$T/state/veil-kit-test/state.env" ]'
# Partial create: fails after 2 droplets; state still blocks a second create/configure, and destroy cleans up.
: > "$FAKE_DOCTL_LOG"
check "partial create saved BUCKET, KEY_ID, FW_ID and the 2 created droplets" '
    ! FAKE_DOCTL_MAX_DROPLETS=2 "$T/do/create.sh" --approve >/dev/null 2>&1 &&
    grep -q "^BUCKET=" "$T/state/veil-kit-test/state.env" &&
    grep -q "^KEY_ID=4242" "$T/state/veil-kit-test/state.env" &&
    grep -q "^FW_ID=fw-0001" "$T/state/veil-kit-test/state.env" &&
    grep -q "^DROPLET_IDS=1001\\\\ 1002$" "$T/state/veil-kit-test/state.env" &&
    ! "$T/do/create.sh" --approve >/dev/null 2>&1 &&
    ! "$T/do/configure.sh" --approve >/dev/null 2>&1
'
FAKE_DOCTL_STATE=destroyed FAKE_SPACES_STATE=gone "$T/do/destroy.sh" --approve >/dev/null 2>&1
check "destroy after partial create cleans up and removes state.env" '[ ! -f "$T/state/veil-kit-test/state.env" ]'

[ $fail = 0 ] && echo "deploy/do/test: all green" || { echo "deploy/do/test: FAILED"; exit 1; }
