# The helpers both deployment kits share (deploy/do, deploy/gcp; docs/DEPLOY.md).
# Sourced by each kit's lib.sh after it has set NAME, STATE, STATE_FILE,
# APPROVED, KIT (do or gcp), ENV_PREFIX, HUBS, YB_NODES, YB_LAYOUT, YB_TABLETS,
# DB_CONNECTIONS, DB_DISK_GB, OBJECTS, DB_PASSWORD and
# `droplets` (the run's machines: role, name, size). The steps that run on
# the machines (deploy/do/configure.sh, bench.sh, logs.sh) are shared the
# same way: deploy/gcp runs them with VEIL_KIT=gcp, and they source its lib.
# The database's settings, shared by both kits (docs/DEPLOY.md §12.10).
[[ "$YB_LAYOUT" =~ ^(colocated|hash)$ ]] || { echo "$KIT: invalid ${ENV_PREFIX}YB_LAYOUT '$YB_LAYOUT' (colocated or hash)" >&2; exit 2; }
[[ "$YB_TABLETS" =~ ^[1-9][0-9]?$ ]] || { echo "$KIT: invalid ${ENV_PREFIX}YB_TABLETS '$YB_TABLETS' (1 to 99 tablets per table on each node)" >&2; exit 2; }
[ "$YB_LAYOUT" = hash ] || [ "$YB_TABLETS" = 1 ] || { echo "$KIT: ${ENV_PREFIX}YB_TABLETS is for ${ENV_PREFIX}YB_LAYOUT=hash (a colocated database is one tablet)" >&2; exit 2; }
# Veil's database: `veil` on PostgreSQL and on YugabyteDB (made by
# configure.sh in the chosen layout; never the default `yugabyte` one).
DB_NAME=veil
# PostgreSQL's connection limit: every server's pool (--db-connections),
# one more server's (a same-machine gate's own, 64), and the drivers'
# counters, migrations and psql.
pg_max_connections() { echo $((HUBS * DB_CONNECTIONS + 64 + 100)); }
# PostgreSQL's settings for a write-heavy server, as `-c` flags. Sized on
# the machine (MB is the shell variable `m`, its memory in MiB, set by the
# remote command before them). Durability is never traded: synchronous
# commit, fsync and full-page writes stay on (owner's rule).
pg_settings() {
    printf '%s ' -c "max_connections=$(pg_max_connections)" \
        -c 'shared_buffers=$((m / 4))MB' -c 'effective_cache_size=$((m * 3 / 4))MB' -c maintenance_work_mem=1GB \
        -c wal_buffers=64MB -c max_wal_size=16GB -c min_wal_size=4GB -c checkpoint_timeout=15min -c checkpoint_completion_target=0.9 \
        -c random_page_cost=1.1 -c effective_io_concurrency=200 -c autovacuum_vacuum_cost_limit=2000 \
        -c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.max=10000 -c track_io_timing=on \
        -c synchronous_commit=on -c fsync=on -c full_page_writes=on
}
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
        echo "postgres://yugabyte@${n:-YB${i}_PRIVATE_IP}:5433/$DB_NAME"
    else echo "postgres://veil:${DB_PASSWORD:-}@$(priv_of "$NAME-db"):5432/$DB_NAME"; fi
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
# A machine type's vCPUs: c2d-standard-16 and c-16 -> 16, c2-16vcpu-32gb -> 16; 0 when unknown.
vcpus_of() {
    local n
    case $1 in *[0-9]vcpu*) n=$(sed -E 's/.*-([0-9]+)vcpu.*/\1/' <<<"$1") ;; *) n=${1##*-} ;; esac
    [[ "$n" =~ ^[0-9]+$ ]] && echo "$n" || echo 0
}
