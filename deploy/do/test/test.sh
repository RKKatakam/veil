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
#      while --check fails if anything (or doctl itself) fails, a load
#      balancer or a reserved IP included;
#   5. the full topology (three servers behind the balancer, three YugabyteDB
#      nodes): create.sh makes every droplet, configure.sh shares the first
#      server's keys through files and writes the balancer's configuration,
#      bench.sh runs every gate of deploy/gates.sh where it belongs, and no
#      secret appears in any of it;
#   6. configure.sh and bench.sh --approve on that topology, with fake ssh, scp
#      and docker: every droplet is reached (ssh inside a `while read` loop
#      must not eat the list), the first server's keys travel as private
#      files, and no secret is on an ssh or scp command line, in the output
#      or in the results;
#   7. the failover verdict on made-up results: a clean run passes, a change
#      told landed and lost, one doubled on `main`, one landed and never
#      told beyond the failed submits, one told under another ticket, and a
#      run without the per-change log each fail.
# Everything runs under a temporary state directory inside the worktree's .scratch/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); DO=$(cd "$HERE/.." && pwd); ROOT=$(cd "$DO/../.." && pwd)
T=$ROOT/.scratch/do-test-$$; mkdir -p "$T"
trap '[ "${KEEP_TEST_DIR:-0}" = 1 ] || { [[ -n "${T:-}" && -n "${ROOT:-}" && "$T" == "$ROOT/.scratch/do-test-"* ]] && rm -rf -- "$T"; }' EXIT
export FAKE_DOCTL_LOG=$T/doctl.log; : > "$FAKE_DOCTL_LOG"
export FAKE_AWS_LOG=$T/aws.log; : > "$FAKE_AWS_LOG"
export FAKE_CURL_LOG=$T/curl.log; : > "$FAKE_CURL_LOG"
export FAKE_SSH_LOG=$T/ssh.log; : > "$FAKE_SSH_LOG"
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
if [[ " $* " == *" -K - "* ]]; then
    stdin_cfg=$(cat || true)
    [[ "$stdin_cfg" == *"user ="* ]] || { echo "fake-curl: missing user on stdin" >&2; exit 1; }
fi
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
# ssh as the real one: without -n it reads all of stdin (and forwards it).
cat > "$T/ssh" <<'SSH'
#!/usr/bin/env bash
echo "ssh $*" >> "${FAKE_SSH_LOG:?}"
[[ " $* " == *" -n "* ]] || cat > /dev/null
case "$*" in
    *"cat /var/lib/veil/hub-"*) echo "fake-server-key-material" ;;
    *"cat /var/lib/veil/stats.json"*) echo '{"landing_batches": 0}' ;;
esac
exit 0
SSH
cat > "$T/scp" <<'SCP'
#!/usr/bin/env bash
echo "scp $*" >> "${FAKE_SSH_LOG:?}"
SCP
cat > "$T/docker" <<'DOCKER'
#!/usr/bin/env bash
case "$1" in
    save) echo "fake image $2" ;;
    image) echo "sha256:fake revision=fake" ;;
esac
exit 0
DOCKER
printf '#!/usr/bin/env bash\ncat\n' > "$T/zstd"
chmod +x "$T/ssh" "$T/scp" "$T/docker" "$T/zstd"
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
for g in pull land branches api landing scaling objects openscion scale; do "$T/do/bench.sh" "$g" >/dev/null 2>&1; done
VEIL_DO_HUBS=3 VEIL_DO_YB_NODES=3 "$T/do/bench.sh" failover >/dev/null 2>&1; VEIL_DO_HUBS=3 VEIL_DO_YB_NODES=3 "$T/do/configure.sh" >/dev/null 2>&1
"$T/do/logs.sh" >/dev/null 2>&1
check "no doctl, aws, curl, ssh or scp call without --approve" '[ ! -s "$FAKE_DOCTL_LOG" ] && [ ! -s "$FAKE_AWS_LOG" ] && [ ! -s "$FAKE_CURL_LOG" ] && [ ! -s "$FAKE_SSH_LOG" ]'
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
check "bench.sh pull runs on a driver against the hub's private address" '[[ "$out_pull" == *"would run on 203.0.113.3: mkdir -p /srv/bench"* ]] && [[ "$out_pull" == *"--url https://10.10.0.1:8443 --ca /tls/ca.pem"* ]]'
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

out=$(FAKE_DOCTL_STATE=destroyed FAKE_SPACES_STATE=gone FAKE_LBS="veil-kit-test-lb" "$T/do/destroy.sh" --check --approve 2>&1 || true)
check "the check fails when a load balancer named after the run remains" '[[ "$out" == *"load balancers named veil-kit-test*: 1"* && "$out" == *"SOMETHING IS LEFT"* ]]'

echo "== 5. the full topology: three servers behind the balancer, three YugabyteDB nodes"
: > "$FAKE_DOCTL_LOG"
FULL="VEIL_DO_NAME=veil-kit-full VEIL_DO_HUBS=3 VEIL_DO_YB_NODES=3"
export FAKE_NAME=veil-kit-full FAKE_DOCTL_STATE=created
export FAKE_DROPLETS="veil-kit-full-hub veil-kit-full-hub2 veil-kit-full-hub3 veil-kit-full-lb veil-kit-full-yb1 veil-kit-full-yb2 veil-kit-full-yb3 veil-kit-full-driver1 veil-kit-full-driver2"
out_est=$(env $FULL "$T/do/estimate.sh" 2>/dev/null)
check "estimate prices the full topology, a forgotten day and month, and every topology" '[[ "$out_est" == *"veil-kit-full-hub3 (hub)"* && "$out_est" == *"veil-kit-full-lb (lb)"*"c-4"* && "$out_est" == *"hourly rate (droplets):      \$2.875"* && "$out_est" == *"planned 8 hours + Spaces:    \$28.00"* && "$out_est" == *"24 hours left running:       \$74.00"* && "$out_est" == *"a whole month forgotten:     \$1937.00"* && "$out_est" == *"three servers + balancer, YugabyteDB x3 (the full run)"*"2.875"*"28.00"*"74.00"*"1937.00"* && "$out_est" == *"one server, PostgreSQL (the default)"*"1.250"*"15.00"*"35.00"*"845.00"* ]]'
out_c=$(env $FULL "$T/do/create.sh" --approve 2>&1); rc=$?
check "create.sh makes 9 droplets: 3 servers, the balancer, 3 YugabyteDB nodes, 2 drivers" '[ $rc = 0 ] && [ "$(grep -c "compute droplet create" "$FAKE_DOCTL_LOG")" = 9 ] && grep -q "create veil-kit-full-hub3 --region nyc3 --size c-16" "$FAKE_DOCTL_LOG" && grep -q "create veil-kit-full-lb --region nyc3 --size c-4" "$FAKE_DOCTL_LOG" && grep -q "create veil-kit-full-yb3 --region nyc3 --size c-8" "$FAKE_DOCTL_LOG" && ! grep -q "create veil-kit-full-db " "$FAKE_DOCTL_LOG"'
out_cfg=$(env $FULL "$T/do/configure.sh" 2>&1)
check "configure.sh starts three YugabyteDB nodes joined to the first, and lifts the tablet limit on each" '[ "$(grep -c "bin/yugabyted start" <<<"$out_cfg")" = 3 ] && [ "$(grep -c -- "--join=10.10.0.5" <<<"$out_cfg")" = 2 ] && [ "$(grep -c "set_flag --force enforce_tablet_replica_limits false" <<<"$out_cfg")" = 3 ]'
check "configure.sh runs the migrations once, then three servers, each on its own YugabyteDB node" '[ "$(grep -c "veil-server:[^ ]* migrate" <<<"$out_cfg")" = 1 ] && [ "$(grep -c "docker run -d --name veil-server" <<<"$out_cfg")" = 3 ] && [[ "$out_cfg" == *"the database URL of server 3) to 203.0.113.3"* ]]'
check "configure.sh copies the first server's keys through private files, never a command line" '[[ "$out_cfg" == *"would fetch the first server'"'"'s identity and keys"* && "$out_cfg" == *"would copy $T/state/veil-kit-full/hubkeys/hub-grant-key to 203.0.113.3:/etc/veil/hubkeys/hub-grant-key"* ]]'
check "configure.sh writes the balancer's configuration for the three servers' private addresses and starts HAProxy" '[[ "$out_cfg" == *"haproxy-cfg.sh 10.10.0.1:8443 10.10.0.2:8443 10.10.0.3:8443"* && "$out_cfg" == *"would run on 203.0.113.4: chmod 644 /etc/veil/haproxy.cfg; docker rm -f veil-lb"*"haproxy:3.0-alpine@sha256:"* && "$out_cfg" == *"would curl https://203.0.113.4:8443/v1/epochs"* ]]'
check "the certificate names every server and the balancer" '[[ "$out_cfg" == *"would run mkcert for 203.0.113.1 10.10.0.1 veil-kit-full-hub 203.0.113.2 10.10.0.2 veil-kit-full-hub2 203.0.113.3 10.10.0.3 veil-kit-full-hub3 203.0.113.4 10.10.0.4 veil-kit-full-lb"* ]]'
all_bench=""
for g in $(. "$ROOT/deploy/gates.sh" >/dev/null 2>&1; echo "$GATES_ALL"); do
    o=$(env $FULL "$T/do/bench.sh" "$g" 2>&1); r=$?
    [ $r = 0 ] || echo "   (bench.sh $g dry run exited $r)"
    all_bench="$all_bench $o"
    printf -v "bench_$g" '%s' "$o"
done
check "every gate's dry run succeeds and records run.txt, topology.env, images.txt" '[ "$(grep -c "would record run.txt" <<<"$all_bench")" = 10 ] && [ "$(grep -c "would record topology.env" <<<"$all_bench")" = 10 ]'
check "the drivers' gates run on a driver against the balancer's private address" '[[ "$bench_landing" == *"would run on 203.0.113.8: mkdir -p /srv/bench"*"--url https://10.10.0.4:8443"*"--mode landing --projects 1 --clients 10000 --people 100 --rates 1000"* ]] && [ "$(grep -c "\[landing-" <<<"$bench_landing")" = 6 ] && [[ "$bench_landing" == *"landing-mix-600s"*"--protected --mix"* ]]'
check "branches runs the cost curve and the headline (300, 1,000 and 3,000 agents merging every 5th push)" '[[ "$bench_branches" == *"[branches on"* && "$bench_branches" == *"--clients 300,1000,3000 --rates max --merge-every 5"* ]]'
check "scaling stops servers 2 and 3, then 3, then starts all, and drives from both drivers" '[[ "$bench_scaling" == *"scaling: 1 of 3 servers running"*"would run on 203.0.113.2: docker stop"*"would run on 203.0.113.3: docker stop"*"scaling: 2 of 3"*"scaling: 3 of 3"* ]] && [[ "$bench_scaling" == *"[scaling-3servers-landing@2 on 203.0.113.9]"*"--out /work/results/"*"scaling-3servers-landing@2.json"* ]]'
check "failover stops the lease holder, then reads the checks and main's line from YugabyteDB through stdin" '[[ "$bench_failover" == *"failover: server 1 holds the lease"*"would run on 203.0.113.1: docker stop -t 30 veil-server"* && "$bench_failover" == *"would run on 203.0.113.5: docker exec -i yb bin/ysqlsh -h 10.10.0.5"* && "$bench_failover" == *"would record failover-check.txt"* && "$bench_failover" == *"would record failover-line.txt"* ]]'
check "objects, openscion and scale run on the first server with a server of their own" '[[ "$bench_objects" == *"[objects on 203.0.113.1]"*"--server /usr/local/bin/veil-server"* && "$bench_openscion" == *"[openscion on 203.0.113.1]"* && "$bench_scale" == *"[scale on 203.0.113.1]"*"--profile 1g"* ]]'
check "failover refuses with one server, and an unknown gate is refused" '! VEIL_DO_NAME=veil-kit-full "$T/do/bench.sh" failover >/dev/null 2>&1 && ! env $FULL "$T/do/bench.sh" nosuchgate >/dev/null 2>&1'
check "the bench dry runs called nothing" '[ "$(grep -vc "compute droplet create\|ssh-key import\|firewall create\|tag create\|droplet get\|droplet list" "$FAKE_DOCTL_LOG")" = 0 ]'
all_out="$out_est $out_c $out_cfg $all_bench $(cat "$FAKE_DOCTL_LOG")"
check "no secret appears anywhere in the full topology's runs" '[[ "$all_out" != *"dop_v1_fake_secret_token"* && "$all_out" != *"secret-spaces-key"* && "$all_out" != *"secret-spaces-val"* && "$all_out" != *"secret-db-pass"* ]]'
topo=$(env $FULL bash -c '. "$1/do/lib.sh" 2>/dev/null; topology' _ "$T")
check "the topology recorded beside results is the settings, without a secret" '[[ "$topo" == *"HUBS=3"* && "$topo" == *"YB_NODES=3"* && "$topo" == *"HAPROXY_IMAGE=haproxy:3.0-alpine@sha256:"* && "$topo" != *"secret"* && "$topo" != *"dop_v1"* ]]'

echo "== 6. configure.sh and bench.sh --approve on the full topology (fake ssh, scp and docker)"
: > "$FAKE_SSH_LOG"
check "the dry runs above reached no droplet" '[ ! -s "$FAKE_SSH_LOG" ]'
out_ac=$(env $FULL "$T/do/configure.sh" --approve dokit-test 2>&1 </dev/null); rc=$?
check "configure.sh --approve succeeds" '[ $rc = 0 ] && [[ "$out_ac" == *"== configured."* ]]'
check "it waits for cloud-init on all 9 droplets and gives each the certificate (ssh in a loop eats no droplet)" '[ "$(grep -c "cloud-init status --wait" "$FAKE_SSH_LOG")" = 9 ] && [ "$(grep -c "/etc/veil/tls/ca.pem$" "$FAKE_SSH_LOG")" = 9 ] && [ "$(grep -c "chmod 755 /etc/veil/tls" "$FAKE_SSH_LOG")" = 9 ]'
check "every server and driver gets its hub.env as a file, and servers 2 and 3 the first one's keys" '[ "$(grep -c "/etc/veil/hub.env$" "$FAKE_SSH_LOG")" = 5 ] && [ "$(grep -c "203.0.113.2:/etc/veil/hubkeys/hub-" "$FAKE_SSH_LOG")" = 4 ] && [ "$(grep -c "203.0.113.3:/etc/veil/hubkeys/hub-" "$FAKE_SSH_LOG")" = 4 ]'
S5=$T/state/veil-kit-full
check "the fetched keys and env files stay private on this machine (in the run's 0700 state directory)" '[ "$(stat -c %a "$S5")" = 700 ] && [ "$(stat -c %a "$S5/hubkeys")" = 700 ] && [ "$(stat -c %a "$S5/hubkeys/hub-grant-key")" = 600 ] && [ "$(stat -c %a "$S5/hub3.env")" = 600 ]'
out_ab=$(env $FULL "$T/do/bench.sh" --approve pull 2>&1 </dev/null); rc=$?
res=$(ls -d "$T"/results/veil-kit-full/*-pull 2>/dev/null | head -1)
check "bench.sh --approve pull succeeds and records run.txt, topology.env, images.txt and commands.txt" '[ $rc = 0 ] && [ -n "$res" ] && [ -s "$res/run.txt" ] && [ -s "$res/topology.env" ] && [ -s "$res/images.txt" ] && [ -s "$res/commands.txt" ] && grep -q "^commit=" "$res/run.txt" && grep -q "revision=" "$res/images.txt"'
leaks=$(cat "$FAKE_SSH_LOG" "$FAKE_DOCTL_LOG" "$FAKE_CURL_LOG"; echo "$out_ac $out_ab"; cat "$res"/* 2>/dev/null)
check "no secret on an ssh or scp command line, in the output or in the results" '[[ "$leaks" != *"dop_v1_fake_secret_token"* && "$leaks" != *"secret-spaces-key"* && "$leaks" != *"secret-spaces-val"* && "$leaks" != *"secret-db-pass"* && "$leaks" != *"fake-server-key-material"* ]]'

echo "== 7. the failover verdict on made-up results (deploy/checks/failover-verdict.py)"
# A run of 6 tickets: 5 answered `landed`; t6's submit lost its connection
# (no ticket in the log) and t7's was still queued when the tool gave up,
# both landed anyway. Each case below changes one thing of the clean run.
fake_failover() { # DIR CASE: clean | lost | doubled | untold | moved
    mkdir -p "$1"
    printf 't0_us=1\nholder_server=1\nhow=stop\nlease_before=1-aa epoch 1\nstop_us=2\n' > "$1/failover-run.txt"
    printf 'lease_after=2-bb epoch 2\nunfinished_after_settling=0\ntip_derived=t\n' > "$1/failover-after.txt"
    printf '%s\n' projects\|1 tickets\|7 tickets_landed\|7 tickets_conflict\|0 tickets_rejected\|0 unfinished\|0 landed_changes\|7 \
        landed_without_record\|0 recorded_not_on_main\|0 landed_twice\|0 main_snapshots\|9 main_not_derived\|0 change_twice_on_main\|0 \
        setup_snapshots\|2 main_without_ticket\|0 landings_before_stop\|3 landings_after_stop\|4 first_landing_after_stop_ms\|100 \
        longest_gap_after_stop_ms\|900 longest_gap_before_stop_ms\|300 > "$1/failover-check.txt"
    echo '{"runs":[{"ops":4,"errors":2}]}' > "$1/failover.json"
    # Change ids: hex on main's line (as the graph keeps them), the API's
    # letters in the log (z = 0, y = 1, ...: "zy" is 01).
    local i n=0 rl=zyxwvutsrq
    : > "$1/failover-line.txt"; : > "$1/failover.landings.jsonl"
    for i in 7 6 5 4 3 2 1; do
        echo "$n|s$i|0$i|t$i" >> "$1/failover-line.txt"; n=$((n + 1))
        [ "$2" = doubled ] && [ $i = 3 ] && { echo "$n|s3b|03|t3b" >> "$1/failover-line.txt"; n=$((n + 1)); }
    done
    printf '%s\n' "$n|setup1|cs1|" "$((n + 1))|setup0|cs0|" >> "$1/failover-line.txt"
    for i in 1 2 3 4 5; do
        [ "$2" = untold ] && [ $i = 5 ] && continue
        echo "{\"ticket\":\"t$i\",\"change\":\"z${rl:$i:1}\",\"landed\":[\"s$i\"],\"project\":\"p\",\"at_ms\":$i}" >> "$1/failover.landings.jsonl"
    done
    [ "$2" = lost ] && echo '{"ticket":"t8","change":"zr","landed":["s8"],"project":"p","at_ms":8}' >> "$1/failover.landings.jsonl"
    [ "$2" = moved ] && echo '{"ticket":"t9","change":"zx","landed":["s9"],"project":"p","at_ms":9}' >> "$1/failover.landings.jsonl"
    echo '{"failed":"land: connection reset","project":"p","at_ms":6}' >> "$1/failover.landings.jsonl"
    echo '{"failed":"still queued after the server'"'"'s wait","ticket":"t7","project":"p","at_ms":7}' >> "$1/failover.landings.jsonl"
}
V=$ROOT/deploy/checks/failover-verdict.py
declare -A vout vrc
for c in clean lost doubled untold moved; do
    fake_failover "$T/failover-$c" "$c"
    vrc[$c]=0; vout[$c]=$(python3 "$V" "$T/failover-$c" 2>&1) || vrc[$c]=$?
done
check "a clean run passes: 5 told, t7 explained by its ticket, t6 by the one failed submit without a ticket" '[ "${vrc[clean]}" = 0 ] && [[ "${vout[clean]}" == *"failover: every check passed"* ]] && [[ "${vout[clean]}" == *"| 2: 1 / 1 ≤ 1 | pass |"* ]] && [[ "${vout[clean]}" == *"| told landed, not on \`main\` | 0 | pass |"* ]]'
check "a change told landed and missing from main fails as lost" '[ "${vrc[lost]}" = 1 ] && [[ "${vout[lost]}" == *"| told landed, not on \`main\` | 1 | **FAIL** |"*"\`08\`"* ]]'
check "a change told landed and twice on main fails as doubled" '[ "${vrc[doubled]}" = 1 ] && [[ "${vout[doubled]}" == *"| told landed, on \`main\` more than once | 1 | **FAIL** |"*"\`03\`"* ]]'
check "a landing no agent was told about, beyond the failed submits, fails" '[ "${vrc[untold]}" = 1 ] && [[ "${vout[untold]}" == *"| 3: 1 / 2 ≤ 1 | **FAIL** |"* ]]'
check "a change answered twice, once under another ticket, fails" '[ "${vrc[moved]}" = 1 ] && [[ "${vout[moved]}" == *"| changes answered \`landed\` twice | 1 | **FAIL** |"* ]] && [[ "${vout[moved]}" == *"| told landed under another ticket | 1 | **FAIL** |"* ]]'
rm "$T/failover-clean/failover.landings.jsonl"
rc=0; out=$(python3 "$V" "$T/failover-clean" 2>&1) || rc=$?
check "a run without the per-change log fails" '[ $rc = 1 ] && [[ "$out" == *"| missing | **FAIL** |"* ]]'

[ $fail = 0 ] && echo "deploy/do/test: all green" || { echo "deploy/do/test: FAILED"; exit 1; }
