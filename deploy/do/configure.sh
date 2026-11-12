#!/usr/bin/env bash
# Configure the droplets create.sh made (docs/DEPLOY.md, "Configure"):
#   1. wait for cloud-init (Docker installed) on every droplet;
#   2. make this run's certificate for every server's and the balancer's
#      addresses (deploy/tls/mkcert.sh) and copy it, with the CA, to every droplet;
#   3. ship the images built here (deploy/docker/build.sh) over SSH with
#      `docker save | zstd | docker load`: no registry, nothing published;
#   4. start the database (PostgreSQL 17 in a container, or the three
#      YugabyteDB nodes), run the migrations once;
#   5. start the first server, copy its identity and keys to the other
#      servers, start them, then the balancer (and the cache);
#   6. smoke-test the address agents use from here with the CA.
# Secrets reach a droplet only as root-only files under /etc/veil.
#   configure.sh [--approve] [TAG]     TAG: the image tag (default: this commit's)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
[ $# -le 1 ] && [[ "${1:-}" != -* ]] || { echo "configure: unknown argument '${1:-}' (usage: configure.sh [--approve|--dry-run] [TAG])" >&2; exit 2; }
TAG=${1:-$(cd "$DO_ROOT" && git describe --always --dirty --abbrev=8)}
: "${VEIL_DO_SPACES_KEY:?set VEIL_DO_SPACES_KEY in $ENV_FILE}"; : "${VEIL_DO_SPACES_SECRET:?set VEIL_DO_SPACES_SECRET in $ENV_FILE}"
[ "$YB_NODES" -gt 0 ] || : "${VEIL_DO_DB_PASSWORD:?set VEIL_DO_DB_PASSWORD in $ENV_FILE}"
[ $APPROVED = 1 ] && require_created
[ -n "$BUCKET" ] || BUCKET="$NAME-objects-DRY"
FRONT=$(front_host public); FRONT_PRIV=$(front_host private)
addr() { local v; v=$(ip_of "$1"); echo "${v:-${1}_IP}"; }            # a droplet's public address (a placeholder in a dry run)
paddr() { local v; v=$(priv_of "$1"); echo "${v:-${1}_PRIVATE_IP}"; }  # its private address
D() { if docker info >/dev/null 2>&1; then docker "$@"; else sg docker -c "docker $(printf '%q ' "$@")"; fi; }

echo "== 1. waiting for cloud-init on every droplet"
while read -r role name size; do
    ip=$(ip_of "$name"); ip=${ip:-${name}_IP}
    remote "$ip" 'cloud-init status --wait >/dev/null; docker info >/dev/null && echo "   '"$name"': docker ready"'
done < <(droplets)

echo "== 2. one certificate for every server, the balancer and the cache"
CERT_NAMES=()
while read -r role name size; do
    case $role in hub|lb|cache) CERT_NAMES+=("$(addr "$name")" "$(paddr "$name")" "$name") ;; esac
done < <(droplets)
[ $APPROVED = 1 ] && "$DO_ROOT/deploy/tls/mkcert.sh" "$STATE/tls" "${CERT_NAMES[@]}" || echo "would run mkcert for ${CERT_NAMES[*]}" >&2
while read -r role name size; do
    ip=$(ip_of "$name"); ip=${ip:-${name}_IP}
    for f in ca.pem server.pem server-key.pem; do copy_to "$STATE/tls/$f" "$ip" "/etc/veil/tls/$f"; done
    remote "$ip" 'chmod 755 /etc/veil/tls; chmod 644 /etc/veil/tls/*.pem'
done < <(droplets)

echo "== 3. shipping images veil-server:$TAG and veil-bench:$TAG"
ship() { # image, host
    if [ $APPROVED = 1 ]; then
        D save "$1" | zstd -T0 -3 | ssh -i "$STATE/id_ed25519" -o UserKnownHostsFile="$STATE/known_hosts" -o StrictHostKeyChecking=accept-new "root@$2" 'zstd -d | docker load' >/dev/null
        echo "   $1 -> $2"
    else echo "would ship $1 to $2 (docker save | zstd | ssh docker load)" >&2; fi
}
while read -r role name size; do
    ip=$(ip_of "$name"); ip=${ip:-${name}_IP}
    case $role in hub|cache) ship "veil-server:$TAG" "$ip" ;; esac
    # The benchmark image: the drivers, and the first server (the same-machine gates).
    if [ "$role" = driver ] || [ "$name" = "$NAME-hub" ]; then ship "veil-bench:$TAG" "$ip"; fi
done < <(droplets)

echo "== 4. database"
if [ "$YB_NODES" -gt 0 ]; then
    YB1=$(addr "$NAME-yb1")
    # YugabyteDB, one yugabyted per node, the first the seed (docs/HUB.md
    # §13.1: the Apache-2.0 core image). Three nodes replicate every tablet
    # three times. One tablet per table and node: Veil's tables are many
    # and small.
    FIRST=$(paddr "$NAME-yb1")
    for i in $(seq "$YB_NODES"); do
        n=$NAME-yb$i; ip=$(addr "$n"); priv=$(paddr "$n")
        join=""; [ "$i" -gt 1 ] && join="--join=$FIRST"
        remote "$ip" "docker rm -f yb >/dev/null 2>&1; docker run -d --name yb --restart unless-stopped --network host --ulimit nofile=1048576:1048576 -v yb-data:/root/var $YB_IMAGE bin/yugabyted start --background=false --advertise_address=$priv $join --tserver_flags=ysql_num_shards_per_tserver=1"
        remote "$ip" 'for i in $(seq 120); do docker exec yb bin/ysqlsh -h '"$priv"' -tAc "select 1" >/dev/null 2>&1 && break; sleep 2; done; echo "   yb'"$i"' answers"'
    done
    remote "$YB1" 'for i in $(seq 60); do n=$(docker exec yb bin/ysqlsh -h '"$FIRST"' -tAc "select count(*) from yb_servers()" 2>/dev/null); [ "$n" = '"$YB_NODES"' ] && break; sleep 2; done; echo "   YugabyteDB nodes in the cluster: $n (expected '"$YB_NODES"')"; [ "$n" = '"$YB_NODES"' ]'
    # yugabyted turns enforce_tablet_replica_limits on at every start,
    # whatever --master_flags says. A migrated Veil database is about 500
    # tablets; a 16 GB node's default limit is above that, a smaller node's
    # is not (docs/DEPLOY.md, "YugabyteDB"). Lifted on every master, as the
    # rehearsal and scripts/verify-server.sh do; a restarted node needs it again.
    for i in $(seq "$YB_NODES"); do
        n=$NAME-yb$i
        remote "$(addr "$n")" "docker exec yb bin/yb-ts-cli --server_address=$(paddr "$n"):7100 set_flag --force enforce_tablet_replica_limits false"
    done
else
    DBIP=$(ip_of "$NAME-db"); DBIP=${DBIP:-DB_IP}; DBPRIV=$(priv_of "$NAME-db"); DBPRIV=${DBPRIV:-DB_PRIVATE_IP}
    # The password goes over as a root-only file, read by Docker's --env-file.
    if [ $APPROVED = 1 ]; then
        umask 077; printf 'POSTGRES_USER=veil\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=veil\n' "$VEIL_DO_DB_PASSWORD" > "$STATE/pg.env"; umask 022
        copy_to "$STATE/pg.env" "$DBIP" /etc/veil/pg.env
        copy_to "$DO_ROOT/deploy/compose/init.sql" "$DBIP" /etc/veil/init.sql
    else echo "would copy the PostgreSQL env file and deploy/compose/init.sql to $DBIP" >&2; fi
    remote "$DBIP" "docker rm -f pg >/dev/null 2>&1; docker run -d --name pg --restart unless-stopped -p $DBPRIV:5432:5432 --env-file /etc/veil/pg.env -v pgdata:/var/lib/postgresql/data -v /etc/veil/init.sql:/docker-entrypoint-initdb.d/10-veil.sql:ro --shm-size=1g $PG_IMAGE -c max_connections=1500 -c shared_preload_libraries=pg_stat_statements -c shared_buffers=4GB -c effective_cache_size=12GB -c synchronous_commit=on"
    remote "$DBIP" 'for i in $(seq 60); do docker exec pg pg_isready -U veil -d veil >/dev/null 2>&1 && docker exec pg psql -U veil -d veil -tAc "select 1" >/dev/null 2>&1 && break; sleep 2; done; echo "   postgres answers"'
fi

echo "== 5. the servers ($HUBS), all on the one database and the bucket $BUCKET"
HUB1=$(addr "$NAME-hub")
# Each server's /etc/veil/hub.env: the Spaces keys and its database URL
# (with YugabyteDB, server I connects to node I). The drivers get the
# first server's: their benchmarks read the database's counters, and the
# same-machine gates start a server of their own.
hub_env() { # server number, host
    if [ $APPROVED = 1 ]; then
        umask 077; printf 'VEIL_S3_ACCESS_KEY=%s\nVEIL_S3_SECRET_KEY=%s\nVEIL_DATABASE_URL=%s\n' "$VEIL_DO_SPACES_KEY" "$VEIL_DO_SPACES_SECRET" "$(database_url "$1")" > "$STATE/hub$1.env"; umask 022
        copy_to "$STATE/hub$1.env" "$2" /etc/veil/hub.env
    else echo "would copy /etc/veil/hub.env (Spaces keys, the database URL of server $1) to $2" >&2; fi
}
for i in $(seq "$HUBS"); do hub_env "$i" "$(addr "$(hub_name "$i")")"; done
while read -r role name size; do [ "$role" = driver ] && hub_env 1 "$(addr "$name")"; done < <(droplets)
remote "$HUB1" "docker run --rm --env-file /etc/veil/hub.env veil-server:$TAG migrate"
# The limits per device and per address are lifted, as veil-bench lifts
# them on a server it starts (crates/veil-bench/src/server.rs): a driver's
# 10,000 agents are a few devices on one address, and would measure the
# limits. A server for people keeps the defaults (docs/HUB.md §13.25).
SERVER_RUN="docker run -d --name veil-server --restart unless-stopped -p 8443:8443 --env-file /etc/veil/hub.env -v veil-data:/var/lib/veil -v /etc/veil/tls:/tls:ro --ulimit nofile=1048576:1048576 veil-server:$TAG --listen 0.0.0.0:8443 --data /var/lib/veil --db-connections $DB_CONNECTIONS --s3-endpoint $SPACES_ENDPOINT --s3-bucket $BUCKET --s3-region $REGION --tls-cert /tls/server.pem --tls-key /tls/server-key.pem --device-rate 1000000000/1000000000 --anonymous-rate 1000000000/1000000000 --max-connections 262144"
HEALTHY='for i in $(seq 30); do [ "$(docker inspect -f "{{.State.Health.Status}}" veil-server 2>/dev/null)" = healthy ] && break; sleep 2; done; docker inspect -f "   veil-server: {{.State.Health.Status}}" veil-server; docker logs --tail 5 veil-server'
remote "$HUB1" "docker rm -f veil-server >/dev/null 2>&1; $SERVER_RUN"
remote "$HUB1" "$HEALTHY"
if [ "$HUBS" -gt 1 ]; then
    # Servers behind one address are one server to a client: they share the
    # signing identity, the receipt key, the grant key and the caches'
    # token, which the first server made in its data directory. Copied
    # through this run's private state directory, as root-only files.
    KEYS="hub-identity.json hub-receipt-key hub-grant-key hub-cache-token"
    if [ $APPROVED = 1 ]; then
        umask 077; mkdir -p "$STATE/hubkeys"
        for k in $KEYS; do remote "$HUB1" "docker exec veil-server cat /var/lib/veil/$k" > "$STATE/hubkeys/$k"; [ -s "$STATE/hubkeys/$k" ] || { echo "configure: the first server has no $k" >&2; exit 1; }; done
        umask 022
    else echo "would fetch the first server's identity and keys ($KEYS) into $STATE/hubkeys (mode 0700)" >&2; fi
    for i in $(seq 2 "$HUBS"); do
        h=$(addr "$(hub_name "$i")")
        remote "$h" "docker rm -f veil-server >/dev/null 2>&1; rm -rf /etc/veil/hubkeys; mkdir -m 700 /etc/veil/hubkeys"
        for k in $KEYS; do copy_to "$STATE/hubkeys/$k" "$h" "/etc/veil/hubkeys/$k"; done
        remote "$h" "docker run --rm --user 0 --entrypoint sh -v veil-data:/var/lib/veil -v /etc/veil/hubkeys:/k:ro veil-server:$TAG -c 'cp /k/* /var/lib/veil/ && chown 10001:10001 /var/lib/veil/hub-* && chmod 600 /var/lib/veil/hub-*' && rm -rf /etc/veil/hubkeys"
        remote "$h" "$SERVER_RUN"
        remote "$h" "$HEALTHY"
    done
    # The balancer: HAProxy, TLS passed through (deploy/lb/haproxy-cfg.sh).
    LB=$(addr "$NAME-lb"); BACKENDS=()
    for i in $(seq "$HUBS"); do BACKENDS+=("$(paddr "$(hub_name "$i")"):8443"); done
    if [ $APPROVED = 1 ]; then "$DO_ROOT/deploy/lb/haproxy-cfg.sh" "${BACKENDS[@]}" > "$STATE/haproxy.cfg"
    else echo "would write $STATE/haproxy.cfg (deploy/lb/haproxy-cfg.sh ${BACKENDS[*]})" >&2; fi
    copy_to "$STATE/haproxy.cfg" "$LB" /etc/veil/haproxy.cfg
    remote "$LB" "chmod 644 /etc/veil/haproxy.cfg; docker rm -f veil-lb >/dev/null 2>&1; docker run -d --name veil-lb --restart unless-stopped --network host --ulimit nofile=1048576:1048576 -v /etc/veil/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro $HAPROXY_IMAGE"
fi
if [ "$WITH_CACHE" = 1 ]; then
    CACHE=$(addr "$NAME-cache")
    # The caches' token comes from the first server's data directory.
    if [ $APPROVED = 1 ]; then
        umask 077; remote "$HUB1" "docker exec veil-server cat /var/lib/veil/hub-cache-token" > "$STATE/hub-cache-token"; umask 022
    else
        remote "$HUB1" "docker exec veil-server cat /var/lib/veil/hub-cache-token"
    fi
    copy_to "$STATE/hub-cache-token" "$CACHE" /etc/veil/tls/hub-cache-token
    remote "$CACHE" "chmod 644 /etc/veil/tls/hub-cache-token; docker rm -f veil-cache >/dev/null 2>&1; docker run -d --name veil-cache --restart unless-stopped -p 8444:8444 -e VEIL_HEALTH_URL=https://127.0.0.1:8444/v1/epochs -v veil-cache:/var/lib/veil-cache -v /etc/veil/tls:/tls:ro veil-server:$TAG cache --upstream https://$FRONT_PRIV:8443 --upstream-ca /tls/ca.pem --token-file /tls/hub-cache-token --dir /var/lib/veil-cache --listen 0.0.0.0:8444 --size 20G --memory 128M --tls-cert /tls/server.pem --tls-key /tls/server-key.pem"
fi

echo "== 6. smoke test from here"
if [ $APPROVED = 1 ]; then
    code=$(curl -s --http1.1 -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$STATE/tls/ca.pem" "https://$FRONT:8443/v1/epochs" || echo 000)
    echo "   https://$FRONT:8443/v1/epochs -> HTTP $code with the run's CA (a 4xx is expected: the route needs a grant)"
    case "$code" in 2*|4*) ;; *) echo "configure: the server did not answer cleanly (HTTP $code); see deploy/do/logs.sh" >&2; exit 1 ;; esac
    save_state TAG "$TAG"
    echo "== configured. vl clients: vl login https://$FRONT:8443 --ca $STATE/tls/ca.pem ; benchmarks: deploy/do/bench.sh --approve <gate>"
else echo "would curl https://$FRONT:8443/v1/epochs with the run's CA" >&2; fi
