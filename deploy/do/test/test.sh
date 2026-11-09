#!/usr/bin/env bash
# Tests of the provisioning scripts without DigitalOcean (docs/DEPLOY.md,
# "Testing the kit"): a fake `doctl` on PATH records what the scripts would
# run. Checks:
#   1. without --approve nothing calls doctl, and nothing is created (dry run);
#   2. create.sh --approve refuses without a token; with one, it creates the
#      key, the firewall and every droplet of the topology, tagged, and
#      saves the addresses;
#   3. the YugabyteDB and cache options change the topology as documented;
#   4. destroy.sh --approve deletes by tag, then its check reports nothing left,
#      and the check fails while something is left.
# Everything runs under a temporary state directory inside the worktree's .scratch/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); DO=$(cd "$HERE/.." && pwd); ROOT=$(cd "$DO/../.." && pwd)
T=$ROOT/.scratch/do-test-$$; mkdir -p "$T"; trap '[ "${KEEP_TEST_DIR:-0}" = 1 ] || rm -rf "$T"' EXIT
export FAKE_DOCTL_LOG=$T/doctl.log; : > "$FAKE_DOCTL_LOG"
export PATH=$HERE:$PATH   # fake-doctl is found as `doctl`
cp "$HERE/fake-doctl" "$T/doctl"; chmod +x "$T/doctl"; export PATH=$T:$PATH
export VEIL_DO_ENV=$T/env
cat > "$VEIL_DO_ENV" <<ENV
VEIL_DO_NAME=veil-kit-test
VEIL_DO_OPERATOR_IP=203.0.113.200
VEIL_DO_SPACES_KEY=k
VEIL_DO_SPACES_SECRET=s
VEIL_DO_DB_PASSWORD=p
ENV
export FAKE_NAME=veil-kit-test
export FAKE_DROPLETS="veil-kit-test-hub veil-kit-test-db veil-kit-test-driver1 veil-kit-test-driver2"
# State goes under the test directory, not deploy/do/state.
mkdir -p "$T/do"; cp "$DO"/*.sh "$T/do/"; cp -r "$DO/cloud-init" "$T/do/"
sed -i "s|^STATE=\$DO_HERE/state/\$NAME|STATE=$T/state/\$NAME|" "$T/do/lib.sh"
sed -i "s|^DO_ROOT=.*|DO_ROOT=$ROOT|" "$T/do/lib.sh"
fail=0
check() { if eval "$2"; then echo "   ok    $1"; else echo "   FAIL  $1"; fail=1; fi; }

echo "== 1. dry runs never call doctl"
out=$("$T/do/create.sh" 2>&1); check "create.sh dry run prints the plan" '[[ "$out" == *"would run: doctl compute droplet create veil-kit-test-hub"* ]]'
"$T/do/estimate.sh" >/dev/null 2>&1; "$T/do/destroy.sh" >/dev/null 2>&1; "$T/do/configure.sh" >/dev/null 2>&1 || true
"$T/do/bench.sh" pull >/dev/null 2>&1 || true; "$T/do/logs.sh" >/dev/null 2>&1 || true
check "no doctl call without --approve" '[ ! -s "$FAKE_DOCTL_LOG" ]'
check "no state written by dry runs" '[ ! -f "$T/state/veil-kit-test/state.env" ]'

echo "== 2. the approval gate and create.sh"
out=$("$T/do/create.sh" --approve 2>&1 || true); check "--approve without a token refuses" '[[ "$out" == *"VEIL_DO_TOKEN"* ]]'
check "still no doctl call" '[ ! -s "$FAKE_DOCTL_LOG" ]'
echo "VEIL_DO_TOKEN=dop_v1_fake" >> "$VEIL_DO_ENV"
out=$("$T/do/create.sh" --approve 2>&1); rc=$?
check "create.sh --approve succeeds" '[ $rc = 0 ]'
check "imports an ssh key generated for the run" 'grep -q "compute ssh-key import veil-kit-test --public-key-file" "$FAKE_DOCTL_LOG" && [ -f "$T/state/veil-kit-test/id_ed25519" ]'
check "firewall opens 22 and 8443 to the operator only" 'grep -q "firewall create --name veil-kit-test --tag-names veil-kit-test --inbound-rules protocol:tcp,ports:22,address:203.0.113.200/32 protocol:tcp,ports:8443,address:203.0.113.200/32" "$FAKE_DOCTL_LOG"'
check "creates 4 droplets, all tagged, from cloud-init" '[ "$(grep -c "compute droplet create" "$FAKE_DOCTL_LOG")" = 4 ] && [ "$(grep "compute droplet create" "$FAKE_DOCTL_LOG" | grep -c -- "--tag-names veil-kit-test .*--user-data-file .*docker.yaml")" = 4 ]'
check "sizes as configured" 'grep -q "create veil-kit-test-hub --region nyc3 --size c-16" "$FAKE_DOCTL_LOG" && grep -q "create veil-kit-test-driver2 --region nyc3 --size c-8" "$FAKE_DOCTL_LOG"'
. "$T/state/veil-kit-test/state.env"
check "state holds the addresses and bucket" '[ "$IP_veil_kit_test_hub" = 203.0.113.1 ] && [ "$PRIV_veil_kit_test_db" = 10.10.0.2 ] && [[ "$BUCKET" == veil-kit-test-objects-* ]] && [ "$FW_ID" = fw-0001 ]'
check "state file is private" '[ "$(stat -c %a "$T/state/veil-kit-test/state.env")" = 600 ]'
out=$("$T/do/create.sh" --approve 2>&1 || true); check "a second create.sh refuses while state exists" '[[ "$out" == *"destroy.sh first"* ]]'
out=$("$T/do/configure.sh" 2>&1 || true)
check "configure.sh dry run names the server command with Spaces and the private DB address" '[[ "$out" == *"--s3-endpoint https://nyc3.digitaloceanspaces.com --s3-bucket $BUCKET"* && "$out" == *"10.10.0.2:5432:5432"* ]]'
check "configure.sh never puts a secret on a command line" '[[ "$out" != *"VEIL_DO_SPACES_SECRET=s"* && "$out" != *"POSTGRES_PASSWORD=p"* && "$out" != *"veil:p@"* ]]'
out=$("$T/do/bench.sh" pull 2>&1 || true)
check "bench.sh pull runs on a driver against the hub's private address" '[[ "$out" == *"would run on 203.0.113.3"* || "$out" == *"would run on 203.0.113.4"* ]] && [[ "$out" == *"--url https://10.10.0.1:8443 --ca /tls/ca.pem"* ]]'
out=$("$T/do/bench.sh" openscion 2>&1 || true)
check "bench.sh openscion runs on the hub with its own server" '[[ "$out" == *"would run on 203.0.113.1"* && "$out" == *"--server /usr/local/bin/veil-server"* ]]'

echo "== 3. topology options"
out=$(VEIL_DO_YB_NODES=3 VEIL_DO_WITH_CACHE=1 VEIL_DO_NAME=veil-kit-yb "$T/do/create.sh" 2>&1)
echo "$out" > "$T/yb.out"; check "YB_NODES=3 replaces the db droplet with three nodes, WITH_CACHE adds a cache" '[ "$(grep -c "would run: doctl compute droplet create veil-kit-yb-yb" <<<"$out")" = 3 ] && [[ "$out" != *"create veil-kit-yb-db "* ]] && [[ "$out" == *"create veil-kit-yb-cache --region nyc3 --size s-4vcpu-8gb"* ]]'
out=$(VEIL_DO_YB_NODES=3 "$T/do/estimate.sh" 2>/dev/null); check "estimate prices the YugabyteDB topology" '[[ "$out" == *"veil-kit-test-yb3 (yb)"* && "$out" == *"hourly rate (droplets):      \$1.750"* ]]'

echo "== 4. destroy.sh"
export FAKE_DOCTL_STATE_FILE=$T/fake-state; export FAKE_DOCTL_STATE=created
out=$("$T/do/destroy.sh" --check --approve 2>&1 || true); check "the check fails while droplets exist" '[[ "$out" == *"SOMETHING IS LEFT"* ]]'
: > "$FAKE_DOCTL_LOG"
out=$(FAKE_DOCTL_STATE=created "$T/do/destroy.sh" --approve 2>&1 || true)
check "destroy deletes droplets by tag, the firewall, the key and the tag" 'grep -q "compute droplet delete --tag-name veil-kit-test --force" "$FAKE_DOCTL_LOG" && grep -q "compute firewall delete fw-0001 --force" "$FAKE_DOCTL_LOG" && grep -q "compute ssh-key delete 4242 --force" "$FAKE_DOCTL_LOG" && grep -q "compute tag delete veil-kit-test --force" "$FAKE_DOCTL_LOG"'
check "destroy tried to empty and delete the Spaces bucket" '[[ "$out" == *"$BUCKET"* ]]'
out=$(FAKE_DOCTL_STATE=destroyed "$T/do/destroy.sh" --check --approve 2>&1 || true)
check "after deletion the check reports nothing left (bucket aside, unreachable here)" '[[ "$out" == *"droplets tagged veil-kit-test: 0"* && "$out" == *"firewalls named veil-kit-test: 0"* && "$out" == *"ssh keys named veil-kit-test: 0"* ]]'

[ $fail = 0 ] && echo "deploy/do/test: all green" || { echo "deploy/do/test: FAILED"; exit 1; }
