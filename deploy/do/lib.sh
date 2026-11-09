# Shared by every script in deploy/do (docs/DEPLOY.md). Source it; it:
#   - loads deploy/do/.env (or $VEIL_DO_ENV) and sets the defaults;
#   - runs in DRY-RUN mode unless `--approve` is given: `run_do` then only
#     prints the doctl command it would run, and `remote` the ssh command;
#   - keeps this run's state (ids, addresses, generated keys and
#     certificates) in deploy/do/state/<name>/, which git ignores.
# `doctl` is called through run_do only, never directly.
set -euo pipefail
DO_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DO_ROOT=$(cd "$DO_HERE/../.." && pwd)
ENV_FILE=${VEIL_DO_ENV:-$DO_HERE/.env}
# Variables already in the environment win over the file (VEIL_DO_NAME=x deploy/do/create.sh).
if [ -f "$ENV_FILE" ]; then
    saved=$(env | grep '^VEIL_DO_' || true)
    set -a; . "$ENV_FILE"; set +a
    while IFS= read -r kv; do [ -n "$kv" ] && export "$kv"; done <<<"$saved"
fi

NAME=${VEIL_DO_NAME:-veil-test}
REGION=${VEIL_DO_REGION:-nyc3}
SIZE_HUB=${VEIL_DO_SIZE_HUB:-c-16}
SIZE_DB=${VEIL_DO_SIZE_DB:-c-8}
SIZE_DRIVER=${VEIL_DO_SIZE_DRIVER:-c-8}
DRIVERS=${VEIL_DO_DRIVERS:-2}
YB_NODES=${VEIL_DO_YB_NODES:-0}
WITH_CACHE=${VEIL_DO_WITH_CACHE:-0}
SIZE_CACHE=${VEIL_DO_SIZE_CACHE:-s-4vcpu-8gb}
HOURS=${VEIL_DO_HOURS:-8}
IMAGE=ubuntu-24-04-x64
STATE=$DO_HERE/state/$NAME
mkdir -p "$STATE"; chmod 700 "$(dirname "$STATE")" "$STATE"
STATE_FILE=$STATE/state.env
[ -f "$STATE_FILE" ] && . "$STATE_FILE"
BUCKET=${VEIL_DO_BUCKET:-${BUCKET:-}}
SPACES_ENDPOINT=https://$REGION.digitaloceanspaces.com

# The approval gate. Nothing is created, changed or deleted at
# DigitalOcean without `--approve` on the command line.
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
if [ $APPROVED = 1 ]; then
    : "${VEIL_DO_TOKEN:?--approve needs VEIL_DO_TOKEN in $ENV_FILE}"
    export DIGITALOCEAN_ACCESS_TOKEN=$VEIL_DO_TOKEN
    command -v doctl >/dev/null || { echo "doctl is not installed (docs/DEPLOY.md, Prerequisites)" >&2; exit 2; }
    echo "## LIVE: --approve given; this run creates, changes or deletes resources that bill the account." >&2
else
    echo "## DRY RUN (no --approve): printing what would happen; nothing talks to DigitalOcean." >&2
fi

run_do() { # doctl arguments...
    if [ $APPROVED = 1 ]; then doctl "$@"; else echo "would run: doctl $*" >&2; fi
}
# Secrets never appear on a command line: they go through files or stdin.
remote() { # host, command...   (ssh as root with this run's key)
    local host=$1; shift
    if [ $APPROVED = 1 ]; then
        ssh -i "$STATE/id_ed25519" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$STATE/known_hosts" \
            -o ConnectTimeout=15 -o BatchMode=yes "root@$host" "$@"
    else echo "would run on $host: $*" >&2; fi
}
copy_to() { # local, host, remote path
    if [ $APPROVED = 1 ]; then
        scp -q -i "$STATE/id_ed25519" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$STATE/known_hosts" "$1" "root@$2:$3"
    else echo "would copy $1 to $2:$3" >&2; fi
}
copy_from() { # host, remote path, local
    if [ $APPROVED = 1 ]; then
        scp -q -r -i "$STATE/id_ed25519" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$STATE/known_hosts" "root@$1:$2" "$3"
    else echo "would copy $1:$2 to $3" >&2; fi
}
save_state() { # KEY VALUE: remembered across scripts
    touch "$STATE_FILE"; chmod 600 "$STATE_FILE"
    grep -v "^$1=" "$STATE_FILE" > "$STATE_FILE.tmp" || true
    printf '%s=%q\n' "$1" "$2" >> "$STATE_FILE.tmp"; mv "$STATE_FILE.tmp" "$STATE_FILE"; chmod 600 "$STATE_FILE"
    eval "$1=\$2"
}
# The droplets of this topology: role, name, size.
droplets() {
    echo "hub $NAME-hub $SIZE_HUB"
    if [ "$YB_NODES" -gt 0 ]; then
        for i in $(seq "$YB_NODES"); do echo "yb $NAME-yb$i $SIZE_DB"; done
    else echo "db $NAME-db $SIZE_DB"; fi
    for i in $(seq "$DRIVERS"); do echo "driver $NAME-driver$i $SIZE_DRIVER"; done
    [ "$WITH_CACHE" = 1 ] && echo "cache $NAME-cache $SIZE_CACHE"
    return 0
}
# Addresses saved by create.sh: IP_<name with - as _> and PRIV_<…>.
ip_of() { local v=IP_${1//-/_}; echo "${!v:-}"; }
priv_of() { local v=PRIV_${1//-/_}; echo "${!v:-}"; }
# The database URL the server and the benchmarks use (private network).
database_url() {
    if [ "$YB_NODES" -gt 0 ]; then echo "postgres://yugabyte@$(priv_of "$NAME-yb1"):5433/yugabyte"
    else echo "postgres://veil:${VEIL_DO_DB_PASSWORD:-}@$(priv_of "$NAME-db"):5432/veil"; fi
}
# Hourly list prices (USD) of the sizes the kit uses, DigitalOcean's
# published monthly price divided by 672 hours. **Check them against
# `doctl compute size list` (PriceHourly) before approving**: estimate.sh
# --live does that for you once a token is present.
price_of() {
    case "$1" in
        c-4) echo 0.125 ;; c-8) echo 0.250 ;; c-16) echo 0.500 ;; c-32) echo 1.000 ;;
        c2-8vcpu-16gb) echo 0.286 ;; c2-16vcpu-32gb) echo 0.571 ;;
        g-8vcpu-32gb) echo 0.375 ;; g-16vcpu-64gb) echo 0.750 ;;
        s-1vcpu-2gb) echo 0.018 ;; s-2vcpu-4gb) echo 0.036 ;; s-4vcpu-8gb) echo 0.071 ;; s-8vcpu-16gb) echo 0.143 ;;
        *) echo "" ;;
    esac
}
SPACES_MONTHLY=5.00   # the Spaces subscription: $5 a month flat (250 GiB, 1 TiB out) while any bucket exists
