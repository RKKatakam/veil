# The helpers both deployment kits share (deploy/do, deploy/gcp; docs/DEPLOY.md).
# Sourced by each kit's lib.sh after it has set NAME, STATE, STATE_FILE,
# APPROVED, KIT (do or gcp), HUBS, YB_NODES, OBJECTS, DB_PASSWORD and
# `droplets` (the run's machines: role, name, size). The steps that run on
# the machines (deploy/do/configure.sh, bench.sh, logs.sh) are shared the
# same way: deploy/gcp runs them with VEIL_KIT=gcp, and they source its lib.
# Only the run's own key reaches a machine: ssh and scp offer no other
# (IdentitiesOnly), so an operator's personal keys never take part.
# Secrets never appear on a command line: they go through files or stdin.
# `remote` never reads stdin (ssh -n): inside `while read …; done < <(droplets)`
# ssh would forward the rest of the list to the droplet, and the loop would
# stop after its first droplet. `remote_stdin` is for a command fed on stdin.
remote() { # host, command...   (ssh as root with this run's key)
    _ssh -n "$@"
}
remote_stdin() { # host, command...   (stdin goes to the command)
    _ssh "" "$@"
}
_ssh() { # -n or "", host, command...
    local n=$1 host=$2; shift 2
    if [ $APPROVED = 1 ]; then
        ssh ${n:+"$n"} -i "$STATE/id_ed25519" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$STATE/known_hosts" \
            -o ConnectTimeout=15 -o BatchMode=yes -o IdentitiesOnly=yes "root@$host" "$@"
    else echo "would run on $host: $*" >&2; fi
}
copy_to() { # local, host, remote path
    if [ $APPROVED = 1 ]; then
        scp -q -i "$STATE/id_ed25519" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$STATE/known_hosts" "$1" "root@$2:$3"
    else echo "would copy $1 to $2:$3" >&2; fi
}
copy_from() { # host, remote path, local
    if [ $APPROVED = 1 ]; then
        scp -q -r -i "$STATE/id_ed25519" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$STATE/known_hosts" "root@$1:$2" "$3"
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
        echo "$KIT: no complete state for '$NAME' ($STATE_FILE); run deploy/$KIT/create.sh --approve first" >&2; exit 2
    }
    local role name size
    while read -r role name size; do
        [ -n "$(ip_of "$name")" ] && [ -n "$(priv_of "$name")" ] || {
            echo "$KIT: missing address for '$name' in $STATE_FILE; create.sh did not finish (run destroy.sh --approve first)" >&2; exit 2
        }
    done < <(droplets)
}
hub_name() { if [ "$1" = 1 ]; then echo "$NAME-hub"; else echo "$NAME-hub$1"; fi; }
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
    else echo "postgres://veil:${DB_PASSWORD:-}@$(priv_of "$NAME-db"):5432/veil"; fi
}
# The object store the servers use: MinIO on the storage droplet's private
# address (TLS with the run's certificate), or the Spaces endpoint.
objects_endpoint() {
    if [ "$OBJECTS" = minio ]; then
        local v; v=$(priv_of "$NAME-minio"); echo "https://${v:-$NAME-minio_PRIVATE_IP}:9000"
    else echo "$SPACES_ENDPOINT"; fi
}
# The one address agents and `vl` use: the balancer's with several
# servers, else the server's. `front_host public|private`.
front_host() {
    local n=$NAME-hub v; [ "$HUBS" -gt 1 ] && n=$NAME-lb
    if [ "$1" = public ]; then v=$(ip_of "$n"); echo "${v:-${n}_IP}"; else v=$(priv_of "$n"); echo "${v:-${n}_PRIVATE_IP}"; fi
}
