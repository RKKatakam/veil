# Shared by every script in deploy/gcp (docs/DEPLOY.md §12). Source it; it:
#   - loads deploy/gcp/.env (or $VEIL_GCP_ENV) and sets the defaults;
#   - runs in DRY-RUN mode unless `--approve` is given: `run_gcloud` then
#     only prints the gcloud command it would run, and `remote` the ssh one;
#   - keeps this run's state (names, addresses, the run's SSH key and
#     certificates) in deploy/gcp/state/<name>/, which git ignores.
# `gcloud` is called through run_gcloud only, never directly. The steps on
# the machines (configure, the gates, logs) are deploy/do's, shared: this
# file defines what they need (deploy/kit.sh says what).
#
# Credentials: VEIL_GCP_CREDENTIALS, the path of a service account's key
# file (mode 0600), handed to gcloud as CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE
# (an environment variable naming the file: the key is never read here,
# copied, printed or on a command line); or, without it, the operator's
# active `gcloud auth login` account.
set -euo pipefail
GCP_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# The repository root. (The shared steps in deploy/do call it DO_ROOT.)
DO_ROOT=$(cd "$GCP_HERE/../.." && pwd)
ENV_FILE=${VEIL_GCP_ENV:-$GCP_HERE/.env}
private_file() { # path: refuse a file group or others can read
    local mode
    mode=$(stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1")
    case "$mode" in ?00) ;; *) echo "gcp: $1 has mode $mode; refusing a group- or world-readable file (run: chmod 600 $1)" >&2; exit 2 ;; esac
}
# Variables already in the environment win over the file.
if [ -f "$ENV_FILE" ]; then
    private_file "$ENV_FILE"
    saved=$(env | grep '^VEIL_GCP_' || true)
    set -a; . "$ENV_FILE"; set +a
    while IFS= read -r kv; do [ -n "$kv" ] && export "$kv"; done <<<"$saved"
fi

KIT=gcp; ENV_PREFIX=VEIL_GCP_; SPACES_GATE=0; DB_PASSWORD=${VEIL_GCP_DB_PASSWORD:-}
NAME=${VEIL_GCP_NAME:-veil-test}
PROJECT=${VEIL_GCP_PROJECT:-}
REGION=${VEIL_GCP_REGION:-us-central1}
ZONE=${VEIL_GCP_ZONE:-$REGION-a}
# Which machines are Spot VMs (owner, 2026-11-14: hybrid). hybrid: the
# servers, the balancer, the drivers and the cache, whose loss costs one
# gate's rerun (bench.sh); the database and the storage machine stay
# on-demand, as their loss would cost the run's data. all: every machine
# (cheapest; a reclaimed database or storage machine means configure.sh
# again, and MinIO's local SSD comes back empty). none: all on-demand.
SPOT=${VEIL_GCP_SPOT:-hybrid}
SIZE_HUB=${VEIL_GCP_SIZE_HUB:-c2d-standard-16}
SIZE_LB=${VEIL_GCP_SIZE_LB:-e2-standard-4}
SIZE_DRIVER=${VEIL_GCP_SIZE_DRIVER:-c2d-standard-8}
SIZE_DB=${VEIL_GCP_SIZE_DB:-c2d-standard-8}
SIZE_OBJECTS=${VEIL_GCP_SIZE_OBJECTS:-c2d-standard-16}
SIZE_CACHE=${VEIL_GCP_SIZE_CACHE:-e2-standard-4}
HUBS=${VEIL_GCP_HUBS:-3}
YB_NODES=${VEIL_GCP_YB_NODES:-3}
DRIVERS=${VEIL_GCP_DRIVERS:-2}
WITH_CACHE=${VEIL_GCP_WITH_CACHE:-0}
DB_CONNECTIONS=${VEIL_GCP_DB_CONNECTIONS:-64}
HOURS=${VEIL_GCP_HOURS:-8}
# Boot disks (pd-balanced, GB): the servers' and drivers' hold the images,
# the benchmarks' working trees and the same-machine gates' data.
DISK_HUB=${VEIL_GCP_DISK_HUB:-200}
DISK_DRIVER=${VEIL_GCP_DISK_DRIVER:-100}
DISK_DB=${VEIL_GCP_DISK_DB:-100}
DISK_SMALL=20   # the balancer and the storage machine (MinIO's data is on its local SSD)
DISK_CACHE=50
# Objects: always MinIO on the storage machine (there is no Spaces here, so
# no `spaces` gate), its data on one 375 GB local NVMe SSD (configure.sh
# makes the file system; the data is lost if the machine stops).
OBJECTS=minio; OBJECTS_VOLUME_GB=0; OBJECTS_LOCAL_SSD=1; LOCAL_SSD_GB=375
OBJECTS_NEED_GB=${VEIL_GCP_OBJECTS_NEED_GB:-250}
SUBNET_RANGE=${VEIL_GCP_SUBNET_RANGE:-10.42.0.0/24}
IMAGE_FAMILY=ubuntu-2404-lts-amd64; IMAGE_PROJECT=ubuntu-os-cloud
CREDENTIALS=${VEIL_GCP_CREDENTIALS:-}
LABEL=veil-run   # every VM and disk carries the label veil-run=NAME, and the network tag NAME

bad() { echo "gcp: $*" >&2; exit 2; }
# Names: resource names are lowercase, start with a letter, at most 63
# characters; NAME-operator is the longest the kit makes.
[[ "$NAME" =~ ^[a-z]([-a-z0-9]{0,28}[a-z0-9])?$ ]] || bad "invalid VEIL_GCP_NAME '$NAME' (lowercase letters, digits and hyphens, a letter first, at most 30)"
[ -z "$PROJECT" ] || [[ "$PROJECT" =~ ^[a-z][-a-z0-9]{4,28}[a-z0-9]$ ]] || bad "invalid VEIL_GCP_PROJECT '$PROJECT' (a project id)"
[[ "$REGION" =~ ^[a-z]+-[a-z]+[0-9]+$ ]] || bad "invalid VEIL_GCP_REGION '$REGION'"
[[ "$ZONE" =~ ^${REGION}-[a-z]$ ]] || bad "invalid VEIL_GCP_ZONE '$ZONE' (a zone of $REGION: all machines in one zone)"
[[ "$SPOT" =~ ^(all|hybrid|none)$ ]] || bad "invalid VEIL_GCP_SPOT '$SPOT' (all, hybrid or none)"
for v in SIZE_HUB SIZE_LB SIZE_DRIVER SIZE_DB SIZE_OBJECTS SIZE_CACHE; do
    [[ "${!v}" =~ ^[a-z][a-z0-9]*-[a-z]+-[0-9]+$ ]] || bad "invalid VEIL_GCP_$v '${!v}' (a predefined machine type, as c2d-standard-16)"
done
[[ "$HUBS" =~ ^[123]$ ]] || bad "invalid VEIL_GCP_HUBS '$HUBS' (1, 2 or 3 servers)"
[[ "$YB_NODES" =~ ^[03]$ ]] || bad "invalid VEIL_GCP_YB_NODES '$YB_NODES' (0: PostgreSQL; 3: a three-node YugabyteDB cluster)"
[[ "$DRIVERS" =~ ^[1-9]$ ]] || bad "invalid VEIL_GCP_DRIVERS '$DRIVERS' (1 to 9)"
[[ "$WITH_CACHE" =~ ^[01]$ ]] || bad "invalid VEIL_GCP_WITH_CACHE '$WITH_CACHE' (0 or 1)"
[[ "$DB_CONNECTIONS" =~ ^[1-9][0-9]*$ ]] || bad "invalid VEIL_GCP_DB_CONNECTIONS '$DB_CONNECTIONS'"
[[ "$OBJECTS_NEED_GB" =~ ^[1-9][0-9]*$ ]] && [ "$OBJECTS_NEED_GB" -le "$LOCAL_SSD_GB" ] || bad "invalid VEIL_GCP_OBJECTS_NEED_GB '$OBJECTS_NEED_GB' (1 to the local SSD's $LOCAL_SSD_GB)"
for v in DISK_HUB DISK_DRIVER DISK_DB; do
    [[ "${!v}" =~ ^[1-9][0-9]*$ ]] && [ "${!v}" -ge 20 ] && [ "${!v}" -le 2000 ] || bad "invalid VEIL_GCP_$v '${!v}' (20 to 2000 GB)"
done
[[ "$SUBNET_RANGE" =~ ^10\.[0-9]+\.[0-9]+\.0/2[0-4]$ ]] || bad "invalid VEIL_GCP_SUBNET_RANGE '$SUBNET_RANGE' (a 10.x.y.0/20 to /24 range)"
[[ "$HOURS" =~ ^[0-9]+(\.[0-9]+)?$ ]] && [ "$(echo "$HOURS > 0" | bc -l)" = 1 ] || bad "invalid VEIL_GCP_HOURS '$HOURS' (must be > 0)"
# The storage machine needs dedicated CPUs (BUG-2431: MinIO on a shared-CPU
# machine collapsed on the first paid run) and a local SSD attached with
# --local-ssd, which only these families' predefined types take (E2 and the
# shared-core types have neither; T2D has no local SSD; C3D and newer take
# one only as their -lssd types). estimate.sh and create.sh refuse the rest.
refuse_shared_objects() { # script name
    case "$SIZE_OBJECTS" in
        c2d-*|c2-*|n2d-*|n2-*|n1-*) ;;
        *)  echo "$1: VEIL_GCP_SIZE_OBJECTS=$SIZE_OBJECTS cannot be the storage machine: it needs dedicated vCPUs and an attached local NVMe SSD (C2D, C2, N2D, N2 or N1; docs/DEPLOY.md §12, BUG-2431)" >&2
            exit 2 ;;
    esac
}
. "$DO_ROOT/deploy/versions.env"
STATE=$GCP_HERE/state/$NAME
STATE_FILE=$STATE/state.env
[ -f "$STATE_FILE" ] && . "$STATE_FILE"
BUCKET=${BUCKET:-}

# The approval gate. Nothing is created, changed, deleted or even read at
# Google Cloud without `--approve` on the command line.
APPROVED=0
ARGS=()
for a in "$@"; do
    case "$a" in
        --approve) APPROVED=1 ;;
        --dry-run) ;;
        *) ARGS+=("$a") ;;
    esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"
export CLOUDSDK_CORE_DISABLE_PROMPTS=1
if [ $APPROVED = 1 ]; then
    [ -n "$PROJECT" ] || { echo "gcp: --approve needs VEIL_GCP_PROJECT in $ENV_FILE" >&2; exit 2; }
    command -v gcloud >/dev/null || { echo "gcloud is not installed (docs/REPRODUCE.md, Google Cloud)" >&2; exit 2; }
    if [ -n "$CREDENTIALS" ]; then
        [ -f "$CREDENTIALS" ] || { echo "gcp: VEIL_GCP_CREDENTIALS names no file" >&2; exit 2; }
        private_file "$CREDENTIALS"
        export CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=$CREDENTIALS
    else
        acct=$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null || true)
        [ -n "$acct" ] || { echo "gcp: --approve needs VEIL_GCP_CREDENTIALS (a service account's key file) or an active 'gcloud auth login'" >&2; exit 2; }
        unset acct
    fi
    echo "## LIVE: --approve given; this run talks to Google Cloud project $PROJECT (creating, changing or deleting what bills)." >&2
else
    echo "## DRY RUN (no --approve): printing what would happen; nothing talks to Google Cloud." >&2
fi

run_gcloud() { # gcloud arguments...   (the project is added)
    if [ $APPROVED = 1 ]; then gcloud "$@" --project="$PROJECT"; else echo "would run: gcloud $* --project=${PROJECT:-PROJECT}" >&2; fi
}
. "$DO_ROOT/deploy/kit.sh"

# The machines of this topology: role, name, machine type (the shared steps
# call them droplets). The first server is NAME-hub; the others NAME-hub2, NAME-hub3.
droplets() {
    local i
    for i in $(seq "$HUBS"); do echo "hub $(hub_name "$i") $SIZE_HUB"; done
    [ "$HUBS" -gt 1 ] && echo "lb $NAME-lb $SIZE_LB"
    if [ "$YB_NODES" -gt 0 ]; then
        for i in $(seq "$YB_NODES"); do echo "yb $NAME-yb$i $SIZE_DB"; done
    else echo "db $NAME-db $SIZE_DB"; fi
    for i in $(seq "$DRIVERS"); do echo "driver $NAME-driver$i $SIZE_DRIVER"; done
    echo "minio $NAME-minio $SIZE_OBJECTS"
    [ "$WITH_CACHE" = 1 ] && echo "cache $NAME-cache $SIZE_CACHE"
    return 0
}
is_spot() { # role [model]: is this role's machine a Spot VM?
    case ${2:-$SPOT} in
        all) return 0 ;;
        none) return 1 ;;
        hybrid) case $1 in hub|lb|driver|cache) return 0 ;; *) return 1 ;; esac ;;
    esac
}
boot_gb() { # role
    case $1 in hub) echo "$DISK_HUB" ;; driver) echo "$DISK_DRIVER" ;; yb|db) echo "$DISK_DB" ;; cache) echo "$DISK_CACHE" ;; *) echo "$DISK_SMALL" ;; esac
}
# Exactly the names the kit gives (never a prefix: NAME=veil must not reach veil-big's machines).
OWN_RE="^$NAME-(hub[23]?|lb|db|yb[0-9]|driver[0-9]|minio|cache)\$"
OWN_FILTER="labels.$LABEL=$NAME OR name~'$OWN_RE'"
# The remote command that gives MinIO its data directory on the storage
# machine's local NVMe SSD (configure.sh, VEIL_KIT=gcp): a file system is
# made only on a device that has none (it is blank after every stop).
local_ssd_mount() { # mount point
    echo "dev=/dev/disk/by-id/google-local-nvme-ssd-0; for i in \$(seq 60); do [ -e \$dev ] && break; sleep 2; done; [ -e \$dev ] || { echo 'configure: no local SSD on the storage machine' >&2; exit 1; }; mkdir -p $1 && { mountpoint -q $1 || { blkid \$dev >/dev/null 2>&1 || mkfs.ext4 -q -F -E lazy_itable_init=1,discard \$dev; mount -o discard,defaults,noatime \$dev $1; }; }"
}
# The topology beside every result: the settings without a secret (a fixed
# list of names, so a new secret can never leak into it; the project id is
# left out too).
topology() {
    local v
    for v in NAME REGION ZONE SPOT SIZE_HUB HUBS SIZE_LB SIZE_DB YB_NODES SIZE_DRIVER DRIVERS SIZE_OBJECTS LOCAL_SSD_GB WITH_CACHE SIZE_CACHE \
             DB_CONNECTIONS OBJECTS DISK_HUB DISK_DRIVER DISK_DB HOURS IMAGE_FAMILY PG_IMAGE YB_IMAGE HAPROXY_IMAGE MINIO_IMAGE; do
        printf '%s=%s\n' "$v" "${!v}"
    done
}

# List prices in us-central1 (USD an hour), rounded up to the millidollar so
# the estimate is never below them, read on 2026-11-14 from Google's pricing
# pages: on-demand from Compute Engine's VM pricing, Spot from the Spot VMs
# page (Spot prices change up to once a day: `estimate.sh --live --approve`
# reads the current ones from the Cloud Billing Catalog API). Other regions
# cost more or less: use --live there.
price_of() { # machine type, spot|ondemand
    case "$1/$2" in
        c2d-standard-4/ondemand) echo 0.182 ;;  c2d-standard-4/spot) echo 0.084 ;;
        c2d-standard-8/ondemand) echo 0.364 ;;  c2d-standard-8/spot) echo 0.167 ;;
        c2d-standard-16/ondemand) echo 0.727 ;; c2d-standard-16/spot) echo 0.333 ;;
        c2d-standard-32/ondemand) echo 1.453 ;; c2d-standard-32/spot) echo 0.666 ;;
        e2-standard-2/ondemand) echo 0.068 ;;   e2-standard-2/spot) echo 0.041 ;;
        e2-standard-4/ondemand) echo 0.135 ;;   e2-standard-4/spot) echo 0.081 ;;
        e2-standard-8/ondemand) echo 0.269 ;;   e2-standard-8/spot) echo 0.161 ;;
        *) echo "" ;;
    esac
}
LSSD_GB_MONTH=0.08    # local SSD, USD per GiB a month (the on-demand price, also used for Spot: an upper bound)
PD_GB_MONTH=0.10      # pd-balanced boot disks, USD per GiB a month (billed while a VM is stopped too)
IP_HOUR=0.005         # an external IPv4 address on a standard VM, USD an hour
IP_SPOT_HOUR=0.0025   # on a Spot VM
MONTH_HOURS=730       # Google bills by the second; a month is 730 hours
BUDGET_MAX=100.00     # owner's rule: the budget is under $100
