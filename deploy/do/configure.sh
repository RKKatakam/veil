#!/usr/bin/env bash
# Configure the droplets create.sh made (docs/DEPLOY.md, "Configure"):
#   1. wait for cloud-init (Docker installed) on every droplet;
#   2. make this run's certificate for the hub's addresses (deploy/tls/mkcert.sh)
#      and copy it, with the CA, to every droplet;
#   3. ship the images built here (deploy/docker/build.sh) over SSH with
#      `docker save | zstd | docker load`: no registry, nothing published;
#   4. start the database (PostgreSQL 17 in a container, or the YugabyteDB
#      nodes), run the migrations, start the server (and the cache);
#   5. smoke-test the server from here with the CA.
# Secrets reach a droplet only as root-only files under /etc/veil.
#   configure.sh [--approve] [TAG]     TAG: the image tag (default: this commit's)
. "$(dirname "$0")/lib.sh"
TAG=${1:-$(cd "$DO_ROOT" && git describe --always --dirty --abbrev=8)}
: "${VEIL_DO_SPACES_KEY:?set VEIL_DO_SPACES_KEY in $ENV_FILE}"; : "${VEIL_DO_SPACES_SECRET:?set VEIL_DO_SPACES_SECRET in $ENV_FILE}"
[ "$YB_NODES" -gt 0 ] || : "${VEIL_DO_DB_PASSWORD:?set VEIL_DO_DB_PASSWORD in $ENV_FILE}"
[ -n "$BUCKET" ] || BUCKET="$NAME-objects-DRY"
HUB=$(ip_of "$NAME-hub"); HUB=${HUB:-HUB_IP}; HUB_PRIV=$(priv_of "$NAME-hub"); HUB_PRIV=${HUB_PRIV:-HUB_PRIVATE_IP}
D() { if docker info >/dev/null 2>&1; then docker "$@"; else sg docker -c "docker $(printf '%q ' "$@")"; fi; }

echo "== 1. waiting for cloud-init on every droplet"
while read -r role name size; do
    remote "$(ip_of "$name")" 'cloud-init status --wait >/dev/null; docker info >/dev/null && echo "   '"$name"': docker ready"'
done < <(droplets)

echo "== 2. certificate for the hub ($HUB, $HUB_PRIV) and the cache"
CERT_NAMES=("$HUB" "$HUB_PRIV" "$NAME-hub")
[ "$WITH_CACHE" = 1 ] && CERT_NAMES+=("$(ip_of "$NAME-cache")" "$(priv_of "$NAME-cache")" "$NAME-cache")
[ $APPROVED = 1 ] && "$DO_ROOT/deploy/tls/mkcert.sh" "$STATE/tls" "${CERT_NAMES[@]}" || echo "would run mkcert for ${CERT_NAMES[*]}" >&2
while read -r role name size; do
    for f in ca.pem server.pem server-key.pem; do copy_to "$STATE/tls/$f" "$(ip_of "$name")" "/etc/veil/tls/$f"; done
    remote "$(ip_of "$name")" 'chmod 755 /etc/veil/tls; chmod 644 /etc/veil/tls/*.pem'
done < <(droplets)

echo "== 3. shipping images veil-server:$TAG and veil-bench:$TAG"
ship() { # image, host
    if [ $APPROVED = 1 ]; then
        D save "$1" | zstd -T0 -3 | ssh -i "$STATE/id_ed25519" -o UserKnownHostsFile="$STATE/known_hosts" -o StrictHostKeyChecking=accept-new "root@$2" 'zstd -d | docker load' >/dev/null
        echo "   $1 -> $2"
    else echo "would ship $1 to $2 (docker save | zstd | ssh docker load)" >&2; fi
}
while read -r role name size; do
    case $role in
        hub|cache) ship "veil-server:$TAG" "$(ip_of "$name")" ;;&
        hub|driver) ship "veil-bench:$TAG" "$(ip_of "$name")" ;;
    esac
done < <(droplets)

echo "== 4. database"
if [ "$YB_NODES" -gt 0 ]; then
    # YugabyteDB, one yugabyted per node, the first the seed (docs/HUB.md §13.1:
    # the Apache-2.0 core image; memory limits as scripts/verify-server.sh).
    FIRST=$(priv_of "$NAME-yb1")
    for i in $(seq "$YB_NODES"); do
        n=$NAME-yb$i; ip=$(ip_of "$n"); priv=$(priv_of "$n")
        join=""; [ "$i" -gt 1 ] && join="--join=$FIRST"
        remote "$ip" "docker rm -f yb >/dev/null 2>&1; docker run -d --name yb --restart unless-stopped --network host -v yb-data:/root/var yugabytedb/yugabyte:2025.2.8.1-b8 bin/yugabyted start --background=false --advertise_address=$priv $join --tserver_flags=ysql_num_shards_per_tserver=1 --master_flags=enforce_tablet_replica_limits=false"
        [ "$i" = 1 ] && remote "$ip" 'for i in $(seq 90); do docker exec yb bin/ysqlsh -h '"$priv"' -c "select 1" >/dev/null 2>&1 && break; sleep 2; done; echo "   yb1 answers"'
    done
else
    DBIP=$(ip_of "$NAME-db"); DBPRIV=$(priv_of "$NAME-db")
    # The password goes over as a root-only file, read by Docker's --env-file.
    if [ $APPROVED = 1 ]; then
        umask 077; printf 'POSTGRES_USER=veil\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=veil\n' "$VEIL_DO_DB_PASSWORD" > "$STATE/pg.env"; umask 022
        copy_to "$STATE/pg.env" "$DBIP" /etc/veil/pg.env
        copy_to "$DO_ROOT/deploy/compose/init.sql" "$DBIP" /etc/veil/init.sql
    else echo "would copy the PostgreSQL env file and deploy/compose/init.sql to $DBIP" >&2; fi
    remote "$DBIP" "docker rm -f pg >/dev/null 2>&1; docker run -d --name pg --restart unless-stopped -p ${DBPRIV:-DB_PRIVATE_IP}:5432:5432 --env-file /etc/veil/pg.env -v pgdata:/var/lib/postgresql/data -v /etc/veil/init.sql:/docker-entrypoint-initdb.d/10-veil.sql:ro --shm-size=1g postgres:17-alpine -c max_connections=1500 -c shared_preload_libraries=pg_stat_statements -c shared_buffers=4GB -c effective_cache_size=12GB -c synchronous_commit=on"
    remote "$DBIP" 'for i in $(seq 60); do docker exec pg pg_isready -U veil -d veil >/dev/null 2>&1 && docker exec pg psql -U veil -d veil -tAc "select 1" >/dev/null 2>&1 && break; sleep 2; done; echo "   postgres answers"'
fi
DB_URL=$(database_url)

echo "== 5. the server on the hub"
if [ $APPROVED = 1 ]; then
    umask 077; printf 'VEIL_S3_ACCESS_KEY=%s\nVEIL_S3_SECRET_KEY=%s\nVEIL_DATABASE_URL=%s\n' "$VEIL_DO_SPACES_KEY" "$VEIL_DO_SPACES_SECRET" "$DB_URL" > "$STATE/hub.env"; umask 022
    copy_to "$STATE/hub.env" "$HUB" /etc/veil/hub.env
    # The drivers' benchmarks need the database URL (statement counts) and
    # the Spaces keys for the cases that start a server of their own.
    while read -r role name size; do [ "$role" = driver ] && copy_to "$STATE/hub.env" "$(ip_of "$name")" /etc/veil/hub.env; done < <(droplets)
else echo "would copy /etc/veil/hub.env (Spaces keys, database URL) to the hub and the drivers" >&2; fi
remote "$HUB" "docker run --rm --env-file /etc/veil/hub.env veil-server:$TAG migrate"
remote "$HUB" "docker rm -f veil-server >/dev/null 2>&1; docker run -d --name veil-server --restart unless-stopped -p 8443:8443 --env-file /etc/veil/hub.env -v veil-data:/var/lib/veil -v /etc/veil/tls:/tls:ro --ulimit nofile=1048576:1048576 veil-server:$TAG --listen 0.0.0.0:8443 --data /var/lib/veil --db-connections 64 --s3-endpoint $SPACES_ENDPOINT --s3-bucket $BUCKET --s3-region $REGION --tls-cert /tls/server.pem --tls-key /tls/server-key.pem"
remote "$HUB" 'for i in $(seq 30); do [ "$(docker inspect -f "{{.State.Health.Status}}" veil-server 2>/dev/null)" = healthy ] && break; sleep 2; done; docker inspect -f "   veil-server: {{.State.Health.Status}}" veil-server; docker logs --tail 5 veil-server'
if [ "$WITH_CACHE" = 1 ]; then
    CACHE=$(ip_of "$NAME-cache")
    # The caches' token comes from the hub's data directory.
    remote "$HUB" "docker run --rm -v veil-data:/d alpine:3.20 cat /d/hub-cache-token" > "$STATE/hub-cache-token" || true
    copy_to "$STATE/hub-cache-token" "$CACHE" /etc/veil/hub-cache-token
    remote "$CACHE" "docker rm -f veil-cache >/dev/null 2>&1; docker run -d --name veil-cache --restart unless-stopped -p 8444:8444 -e VEIL_HEALTH_URL=https://127.0.0.1:8444/v1/epochs -v veil-cache:/var/lib/veil-cache -v /etc/veil:/etc/veil:ro veil-server:$TAG cache --upstream https://$HUB_PRIV:8443 --upstream-ca /etc/veil/tls/ca.pem --token-file /etc/veil/hub-cache-token --dir /var/lib/veil-cache --listen 0.0.0.0:8444 --size 20G --memory 128M --tls-cert /etc/veil/tls/server.pem --tls-key /etc/veil/tls/server-key.pem"
fi

echo "== 6. smoke test from here"
if [ $APPROVED = 1 ]; then
    code=$(curl -s --http1.1 -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$STATE/tls/ca.pem" "https://$HUB:8443/v1/epochs")
    echo "   https://$HUB:8443/v1/epochs -> HTTP $code with the run's CA (a 4xx is expected: the route needs a grant)"
    [ "$code" != 000 ] || { echo "configure: the server does not answer; see deploy/do/logs.sh" >&2; exit 1; }
    save_state TAG "$TAG"
    echo "== configured. vl clients: vl login https://$HUB:8443 --ca $STATE/tls/ca.pem ; benchmarks: deploy/do/bench.sh --approve <gate>"
else echo "would curl https://$HUB:8443/v1/epochs with the run's CA" >&2; fi
