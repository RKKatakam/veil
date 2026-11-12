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
    mode=$(stat -c %a "$ENV_FILE" 2>/dev/null || stat -f %Lp "$ENV_FILE")
    case "$mode" in
        ?00) ;;
        *) echo "do: $ENV_FILE has mode $mode; refusing a group- or world-readable .env (run: chmod 600 $ENV_FILE)" >&2; exit 2 ;;
    esac
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
# Servers (1 to 3), all on the one database and the one bucket. With more
# than one, a balancer droplet (HAProxy passing TLS through) is the one
# address the agents use.
HUBS=${VEIL_DO_HUBS:-1}
SIZE_LB=${VEIL_DO_SIZE_LB:-c-4}
DB_CONNECTIONS=${VEIL_DO_DB_CONNECTIONS:-64}
HOURS=${VEIL_DO_HOURS:-8}
[[ "$NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*$ ]] || { echo "do: invalid VEIL_DO_NAME '$NAME' (use letters, digits and hyphens)" >&2; exit 2; }
[[ "$REGION" =~ ^[a-z0-9-]+$ ]] || { echo "do: invalid VEIL_DO_REGION '$REGION'" >&2; exit 2; }
[[ "$DRIVERS" =~ ^[1-9][0-9]*$ ]] || { echo "do: invalid VEIL_DO_DRIVERS '$DRIVERS'" >&2; exit 2; }
[[ "$YB_NODES" =~ ^[03]$ ]] || { echo "do: invalid VEIL_DO_YB_NODES '$YB_NODES' (0: PostgreSQL; 3: a three-node YugabyteDB cluster)" >&2; exit 2; }
[[ "$HUBS" =~ ^[123]$ ]] || { echo "do: invalid VEIL_DO_HUBS '$HUBS' (1, 2 or 3 servers)" >&2; exit 2; }
[[ "$DB_CONNECTIONS" =~ ^[1-9][0-9]*$ ]] || { echo "do: invalid VEIL_DO_DB_CONNECTIONS '$DB_CONNECTIONS'" >&2; exit 2; }
[[ "$WITH_CACHE" =~ ^[01]$ ]] || { echo "do: invalid VEIL_DO_WITH_CACHE '$WITH_CACHE' (0 or 1)" >&2; exit 2; }
[[ "$HOURS" =~ ^[0-9]+(\.[0-9]+)?$ ]] && [ "$(echo "$HOURS > 0" | bc -l)" = 1 ] || { echo "do: invalid VEIL_DO_HOURS '$HOURS' (must be > 0)" >&2; exit 2; }
IMAGE=ubuntu-24-04-x64
# Third-party images, pinned (deploy/versions.env: the rehearsal runs the same).
. "$DO_ROOT/deploy/versions.env"
STATE=$DO_HERE/state/$NAME
STATE_FILE=$STATE/state.env
[ -f "$STATE_FILE" ] && . "$STATE_FILE"
BUCKET=${VEIL_DO_BUCKET:-${BUCKET:-}}
SPACES_ENDPOINT=${VEIL_DO_SPACES_ENDPOINT:-https://$REGION.digitaloceanspaces.com}

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
ensure_state_dir() {
    mkdir -p "$STATE"; chmod 700 "$(dirname "$STATE")" "$STATE"
}
save_state() { # KEY VALUE: remembered across scripts
    ensure_state_dir
    touch "$STATE_FILE"; chmod 600 "$STATE_FILE"
    grep -v "^$1=" "$STATE_FILE" > "$STATE_FILE.tmp" || true
    printf '%s=%q\n' "$1" "$2" >> "$STATE_FILE.tmp"; mv "$STATE_FILE.tmp" "$STATE_FILE"; chmod 600 "$STATE_FILE"
    printf -v "$1" '%s' "$2"
}
require_created() { # require a finished create.sh before configure/bench/logs --approve
    [ -f "$STATE_FILE" ] && [ -f "$STATE/id_ed25519" ] && [ -n "${BUCKET:-}" ] || {
        echo "do: no complete state for '$NAME' ($STATE_FILE); run deploy/do/create.sh --approve first" >&2; exit 2
    }
    local role name size
    while read -r role name size; do
        [ -n "$(ip_of "$name")" ] && [ -n "$(priv_of "$name")" ] || {
            echo "do: missing address for '$name' in $STATE_FILE; create.sh did not finish (run destroy.sh --approve first)" >&2; exit 2
        }
    done < <(droplets)
}
# The droplets of this topology: role, name, size. The first server keeps
# the name NAME-hub; the others are NAME-hub2 and NAME-hub3.
hub_name() { if [ "$1" = 1 ]; then echo "$NAME-hub"; else echo "$NAME-hub$1"; fi; }
droplets() {
    local i
    for i in $(seq "$HUBS"); do echo "hub $(hub_name "$i") $SIZE_HUB"; done
    [ "$HUBS" -gt 1 ] && echo "lb $NAME-lb $SIZE_LB"
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
# The database URL the servers and the benchmarks use (private network).
# With YugabyteDB, server I connects to node I (any node serves the whole
# database), so the servers' connections are spread over the cluster.
database_url() { # [server number, default 1]
    local i=${1:-1} n
    if [ "$YB_NODES" -gt 0 ]; then
        n=$(( (i - 1) % YB_NODES + 1 )); n=$(priv_of "$NAME-yb$n")
        echo "postgres://yugabyte@${n:-YB${i}_PRIVATE_IP}:5433/yugabyte"
    else echo "postgres://veil:${VEIL_DO_DB_PASSWORD:-}@$(priv_of "$NAME-db"):5432/veil"; fi
}
# The one address agents and `vl` use: the balancer's with several
# servers, else the server's. `front_host public|private`.
front_host() {
    local n=$NAME-hub v; [ "$HUBS" -gt 1 ] && n=$NAME-lb
    if [ "$1" = public ]; then v=$(ip_of "$n"); echo "${v:-${n}_IP}"; else v=$(priv_of "$n"); echo "${v:-${n}_PRIVATE_IP}"; fi
}
# The topology as recorded beside every result: the settings without the
# secrets (a fixed list of names, so a new secret can never leak into it).
topology() {
    local v
    for v in NAME REGION SIZE_HUB HUBS SIZE_LB SIZE_DB YB_NODES SIZE_DRIVER DRIVERS WITH_CACHE SIZE_CACHE DB_CONNECTIONS HOURS IMAGE PG_IMAGE YB_IMAGE HAPROXY_IMAGE; do
        printf '%s=%s\n' "$v" "${!v}"
    done
}
# Hourly list prices (USD) of the sizes the kit uses, DigitalOcean's
# published monthly price divided by 672 hours, rounded up to the
# millidollar so the estimate is never below the list price. **Check them
# against `doctl compute size list` (PriceHourly) before approving**:
# estimate.sh --live does that for you once a token is present.
price_of() {
    case "$1" in
        c-4) echo 0.125 ;; c-8) echo 0.250 ;; c-16) echo 0.500 ;; c-32) echo 1.000 ;;
        c2-8vcpu-16gb) echo 0.286 ;; c2-16vcpu-32gb) echo 0.572 ;;
        g-8vcpu-32gb) echo 0.375 ;; g-16vcpu-64gb) echo 0.750 ;;
        c-2) echo 0.063 ;;
        s-1vcpu-2gb) echo 0.018 ;; s-2vcpu-4gb) echo 0.036 ;; s-4vcpu-8gb) echo 0.072 ;; s-8vcpu-16gb) echo 0.143 ;;
        *) echo "" ;;
    esac
}
SPACES_MONTHLY=5.00   # the Spaces subscription: $5 a month flat (250 GiB, 1 TiB out) while any bucket exists
BUDGET_MAX=100.00     # owner's rule: the budget is under $100
