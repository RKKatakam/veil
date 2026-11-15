#!/usr/bin/env bash
# Configure the droplets create.sh made (docs/DEPLOY.md, "Configure"):
#   1. wait for cloud-init (Docker installed) on every droplet;
#   2. make this run's certificate for every server's and the balancer's
#      addresses (deploy/tls/mkcert.sh) and copy it, with the CA, to every droplet;
#   3. ship the images built here (deploy/docker/build.sh) over SSH with
#      `docker save | zstd | docker load`: no registry, nothing published;
#   4. start the database (PostgreSQL 17 in a container, or the three
#      YugabyteDB nodes), and with VEIL_DO_OBJECTS=minio MinIO on the storage
#      droplet (TLS with the run's certificate, credentials made for this
#      run), then run the migrations once;
#   5. start the first server, copy its identity and keys to the other
#      servers, start them, then the balancer (and the cache);
#   6. smoke-test the address agents use from here with the CA.
# Secrets reach a droplet only as root-only files under /etc/veil: hub.env
# (the object store's keys, the database URL), spaces.env on the first
# server (the Spaces keys of the `spaces` gate), minio.env on the storage
# droplet (MinIO's credentials, generated here into the run's private state
# directory, never on a command line). On Google Cloud (VEIL_KIT=gcp) there
# is no Spaces bucket: no spaces.env, and MinIO keeps its data on the
# storage machine's local NVMe SSD (deploy/gcp/lib.sh `local_ssd_mount`).
#   configure.sh [--approve] [TAG]     TAG: the image tag (default: this commit's)
set -euo pipefail
# The steps on the machines are shared with deploy/gcp, which runs this
# script with VEIL_KIT=gcp: then its lib.sh is the one sourced.
case ${VEIL_KIT:-do} in do|gcp) ;; *) echo "invalid VEIL_KIT '${VEIL_KIT:-}' (do or gcp)" >&2; exit 2 ;; esac
. "$(dirname "$0")/../${VEIL_KIT:-do}/lib.sh"
[ $# -le 1 ] && [[ "${1:-}" != -* ]] || { echo "configure: unknown argument '${1:-}' (usage: configure.sh [--approve|--dry-run] [TAG])" >&2; exit 2; }
TAG=${1:-$(cd "$DO_ROOT" && git describe --always --dirty --abbrev=8)}
if [ "$SPACES_GATE" = 1 ]; then : "${VEIL_DO_SPACES_KEY:?set VEIL_DO_SPACES_KEY in $ENV_FILE}"; : "${VEIL_DO_SPACES_SECRET:?set VEIL_DO_SPACES_SECRET in $ENV_FILE}"; fi
[ "$YB_NODES" -gt 0 ] || [ -n "$DB_PASSWORD" ] || { echo "configure: set ${ENV_PREFIX}DB_PASSWORD in $ENV_FILE" >&2; exit 2; }
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
    case $role in hub|lb|cache|minio) CERT_NAMES+=("$(addr "$name")" "$(paddr "$name")" "$name") ;; esac
done < <(droplets)
# And `localhost`: anything on a machine that reaches its own service over
# TLS by that name (MinIO's setup did, BUG-2432) finds it in the certificate.
CERT_NAMES+=(localhost 127.0.0.1)
if [ $APPROVED = 1 ]; then "$DO_ROOT/deploy/tls/mkcert.sh" "$STATE/tls" "${CERT_NAMES[@]}"; else echo "would run mkcert for ${CERT_NAMES[*]}" >&2; fi
while read -r role name size; do
    ip=$(ip_of "$name"); ip=${ip:-${name}_IP}
    for f in ca.pem server.pem server-key.pem; do copy_to "$STATE/tls/$f" "$ip" "/etc/veil/tls/$f"; done
    remote "$ip" 'chmod 755 /etc/veil/tls; chmod 644 /etc/veil/tls/*.pem'
done < <(droplets)

echo "== 3. shipping images veil-server:$TAG and veil-bench:$TAG"
ship() { # image, host
    if [ $APPROVED = 1 ]; then
        D save "$1" | zstd -T0 -3 | ssh -i "$STATE/id_ed25519" -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile="$STATE/known_hosts" -o HostKeyAlias="$(host_alias "$2")" -o StrictHostKeyChecking=accept-new "root@$2" 'zstd -d | docker load' >/dev/null
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
# Each database machine's data: on its own persistent data disk when the
# kit gives it one (Google Cloud, DB_DISK_GB; docs/DEPLOY.md §12.10),
# else in a Docker volume on the machine's disk.
if [ "${DB_DISK_GB:-0}" -gt 0 ]; then PG_DATA=/mnt/db-data/pg; YB_DATA=/mnt/db-data/yb; else PG_DATA=pgdata; YB_DATA=yb-data; fi
db_disk() { # host: mount the data disk and make the data directory
    [ "${DB_DISK_GB:-0}" -gt 0 ] || return 0
    remote "$1" "$(db_disk_mount /mnt/db-data) && mkdir -p /mnt/db-data/pg /mnt/db-data/yb && echo \"   data disk: \$(df -h --output=size,avail /mnt/db-data | tail -1)\""
}
if [ "$YB_NODES" -gt 0 ]; then
    YB1=$(addr "$NAME-yb1")
    # YugabyteDB, one yugabyted per node, the first the seed (docs/HUB.md
    # §13.1: the Apache-2.0 core image). With three nodes yugabyted keeps
    # three copies of every tablet. Veil's database `veil` is made below in
    # YB_LAYOUT: colocated (every table in one tablet, the default), or
    # hash-sharded with YB_TABLETS tablets per table on each node
    # (`ysql_num_shards_per_tserver`; 1: a table has three, one led by each
    # node; docs/DEPLOY.md §12.10).
    FIRST=$(paddr "$NAME-yb1")
    for i in $(seq "$YB_NODES"); do
        n=$NAME-yb$i; ip=$(addr "$n"); priv=$(paddr "$n")
        join=""; [ "$i" -gt 1 ] && join="--join=$FIRST"
        # YugabyteDB's master refuses a long local hostname ("Unable to
        # determine local hostname: File name too long"): Google Cloud names a
        # machine NAME.ZONE.c.PROJECT.internal. The machine's short name, kept
        # in /etc/hosts, works on every cloud.
        remote "$ip" "hostnamectl set-hostname $n && { grep -q ' $n\$' /etc/hosts || echo '$priv $n' >> /etc/hosts; }"
        db_disk "$ip"
        remote "$ip" "docker rm -f yb >/dev/null 2>&1; docker run -d --name yb --restart unless-stopped --network host --ulimit nofile=1048576:1048576 -v $YB_DATA:/root/var $YB_IMAGE bin/yugabyted start --background=false --advertise_address=$priv $join --tserver_flags=yb_enable_read_committed_isolation=true,ysql_num_shards_per_tserver=$YB_TABLETS --master_flags=enforce_tablet_replica_limits=false"
        remote "$ip" 'for i in $(seq 120); do docker exec yb bin/ysqlsh -h '"$priv"' -tAc "select 1" >/dev/null 2>&1 && { echo "   yb'"$i"' answers"; exit 0; }; sleep 2; done; echo "configure: yb'"$i"' did not answer in 4 minutes (docker logs yb on it)" >&2; exit 1'
    done
    remote "$YB1" 'for i in $(seq 60); do n=$(docker exec yb bin/ysqlsh -h '"$FIRST"' -tAc "select count(*) from yb_servers()" 2>/dev/null); [ "$n" = '"$YB_NODES"' ] && break; sleep 2; done; echo "   YugabyteDB nodes in the cluster: $n (expected '"$YB_NODES"')"; [ "$n" = '"$YB_NODES"' ]'
    # yugabyted turns enforce_tablet_replica_limits on at every start,
    # whatever --master_flags says, and the limit counts every replica a
    # node holds: with three tablets per table, a migrated Veil database is
    # about three times its table count on every node (docs/DEPLOY.md §2).
    # Lifted on every master, as the rehearsal and scripts/verify-server.sh
    # do; a node that restarts needs it again (configure.sh --approve again,
    # or this one command on it), before any table is created.
    for i in $(seq "$YB_NODES"); do
        n=$NAME-yb$i
        remote "$(addr "$n")" "docker exec yb bin/yb-ts-cli --server_address=$(paddr "$n"):7100 set_flag --force enforce_tablet_replica_limits false && docker exec yb bin/yb-ts-cli --server_address=$(paddr "$n"):7100 set_flag --force tablet_replicas_per_gib_limit 100000"
    done
    # Veil's database in the chosen layout, made once: a configure.sh run
    # again finds it, and refuses one made in the other layout (a database's
    # colocation is fixed when it is made).
    if [ "$YB_LAYOUT" = colocated ]; then MAKE="CREATE DATABASE $DB_NAME WITH COLOCATION = true"; WANT=t; else MAKE="CREATE DATABASE $DB_NAME"; WANT=f; fi
    YSQL="docker exec yb bin/ysqlsh -h $FIRST -X -tA"
    remote "$YB1" "$YSQL -c \"select 1 from pg_database where datname = '$DB_NAME'\" | grep -qx 1 || $YSQL -c '$MAKE' >/dev/null; c=\$($YSQL -d $DB_NAME -c 'select yb_is_database_colocated()'); echo \"   database $DB_NAME: colocated=\$c (layout $YB_LAYOUT)\"; [ \"\$c\" = $WANT ] || { echo 'configure: database $DB_NAME exists in another layout than ${ENV_PREFIX}YB_LAYOUT=$YB_LAYOUT (destroy.sh, then create.sh)' >&2; exit 1; }"
else
    DBIP=$(ip_of "$NAME-db"); DBIP=${DBIP:-DB_IP}; DBPRIV=$(priv_of "$NAME-db"); DBPRIV=${DBPRIV:-DB_PRIVATE_IP}
    # The password goes over as a root-only file, read by Docker's --env-file.
    if [ $APPROVED = 1 ]; then
        umask 077; printf 'POSTGRES_USER=veil\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=veil\n' "$DB_PASSWORD" > "$STATE/pg.env"; umask 022
        copy_to "$STATE/pg.env" "$DBIP" /etc/veil/pg.env
        copy_to "$DO_ROOT/deploy/compose/init.sql" "$DBIP" /etc/veil/init.sql
    else echo "would copy the PostgreSQL env file and deploy/compose/init.sql to $DBIP" >&2; fi
    db_disk "$DBIP"
    # Settings for a write-heavy server, sized on the machine (`m`, its
    # memory in MiB): deploy/kit.sh pg_settings, docs/DEPLOY.md §12.10.
    remote "$DBIP" "m=\$(awk '/MemTotal/ {print int(\$2 / 1024)}' /proc/meminfo); docker rm -f pg >/dev/null 2>&1; docker run -d --name pg --restart unless-stopped -p $DBPRIV:5432:5432 --env-file /etc/veil/pg.env -v $PG_DATA:/var/lib/postgresql/data -v /etc/veil/init.sql:/docker-entrypoint-initdb.d/10-veil.sql:ro --shm-size=1g $PG_IMAGE $(pg_settings)"
    remote "$DBIP" 'for i in $(seq 60); do docker exec pg pg_isready -U veil -d veil >/dev/null 2>&1 && docker exec pg psql -U veil -d veil -tAc "select 1" >/dev/null 2>&1 && break; sleep 2; done; echo "   postgres answers"'
fi

S3_REGION=$REGION
if [ "$OBJECTS" = minio ]; then
    echo "== 4b. MinIO on $NAME-minio (TLS with the run's certificate; reached only from the run's droplets)"
    S3_REGION=us-east-1   # MinIO's own region
    MIP=$(addr "$NAME-minio"); MPRIV=$(paddr "$NAME-minio")
    # Credentials made for this run: a root-only file here and there, read
    # by Docker's --env-file; the servers get them in their hub.env.
    if [ $APPROVED = 1 ]; then
        if [ ! -s "$STATE/minio.env" ]; then
            umask 077; printf 'MINIO_ROOT_USER=veil%s\nMINIO_ROOT_PASSWORD=%s\n' "$(openssl rand -hex 8)" "$(openssl rand -hex 24)" > "$STATE/minio.env"; umask 022
        fi
    else echo "would generate MinIO's credentials into $STATE/minio.env (mode 0600)" >&2; fi
    copy_to "$STATE/minio.env" "$MIP" /etc/veil/minio.env
    if [ "$OBJECTS_VOLUME_GB" -gt 0 ]; then
        MDATA=/mnt/minio-data
        remote "$MIP" "dev=/dev/disk/by-id/scsi-0DO_Volume_$VOLUME_NAME; for i in \$(seq 60); do [ -e \$dev ] && break; sleep 2; done; mkdir -p $MDATA && { mountpoint -q $MDATA || mount -o discard,defaults,noatime \$dev $MDATA; }"
    elif [ "${OBJECTS_LOCAL_SSD:-0}" = 1 ]; then
        MDATA=/mnt/minio-data; remote "$MIP" "$(local_ssd_mount "$MDATA")"
    else MDATA=/srv/minio; fi
    remote "$MIP" "chmod 600 /etc/veil/minio.env && mkdir -p $MDATA && chown 1001:1001 $MDATA && a=\$(df --output=avail -BG $MDATA | tail -1 | tr -dc 0-9) && echo \"   MinIO's data in $MDATA: \${a} GB free (needs $OBJECTS_NEED_GB)\" && [ \"\$a\" -ge $OBJECTS_NEED_GB ] || { echo 'configure: too little disk for MinIO: a larger VEIL_DO_SIZE_OBJECTS, or VEIL_DO_OBJECTS_VOLUME_GB' >&2; exit 1; }"
    # MinIO is started directly, not through the image's start-up script
    # (BUG-2432): that script first runs a setup step whose client (mc)
    # adds the local server over TLS as `localhost`, which the run's
    # certificate does not name; a failed setup exits the container, so on
    # the first paid run Docker restarted MinIO every 72 s for the whole run.
    # Started directly it serves TLS from /certs with the run's credentials
    # (--env-file), and nothing runs before it on a restart. The bucket is
    # made by the server at first start. deploy/compose/docker-compose.yml
    # starts it the same way.
    remote "$MIP" "docker rm -f minio >/dev/null 2>&1; docker run -d --name minio --restart unless-stopped -p $MPRIV:9000:9000 --env-file /etc/veil/minio.env -v $MDATA:/bitnami/minio/data -v /etc/veil/tls/server.pem:/certs/public.crt:ro -v /etc/veil/tls/server-key.pem:/certs/private.key:ro --ulimit nofile=1048576:1048576 --entrypoint $MINIO_BIN $MINIO_IMAGE $MINIO_ARGS"
    # It answers over TLS, and is still the same process 15 s later.
    remote "$MIP" 'for i in $(seq 90); do curl -sf --cacert /etc/veil/tls/ca.pem https://'"$MPRIV"':9000/minio/health/live >/dev/null && break; sleep 2; done; curl -sf --cacert /etc/veil/tls/ca.pem https://'"$MPRIV"':9000/minio/health/live >/dev/null && echo "   minio answers over TLS" || { echo "configure: MinIO did not come up; docker logs minio on '"$MIP"'" >&2; exit 1; }; sleep 15; r=$(docker inspect -f "{{.RestartCount}} {{.State.Running}}" minio); [ "$r" = "0 true" ] || { echo "configure: MinIO is restarting (restarts, running: $r); docker logs minio on '"$MIP"'" >&2; exit 1; }'
fi

echo "== 5. the servers ($HUBS), all on the one database and the bucket $BUCKET ($OBJECTS: $(objects_endpoint))"
HUB1=$(addr "$NAME-hub")
# Each server's /etc/veil/hub.env: the object store's keys (MinIO's, with
# the run's CA, or Spaces') and its database URL (with YugabyteDB, server I
# connects to node I). The drivers get the first server's: their
# benchmarks read the database's counters, and the same-machine gates
# start a server of their own.
hub_env() { # server number, host
    if [ $APPROVED = 1 ]; then
        umask 077
        if [ "$OBJECTS" = minio ]; then
            ( . "$STATE/minio.env"; printf 'VEIL_S3_ACCESS_KEY=%s\nVEIL_S3_SECRET_KEY=%s\nVEIL_S3_CA=/tls/ca.pem\nVEIL_DATABASE_URL=%s\n' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" "$(database_url "$1")" ) > "$STATE/hub$1.env"
        else
            printf 'VEIL_S3_ACCESS_KEY=%s\nVEIL_S3_SECRET_KEY=%s\nVEIL_DATABASE_URL=%s\n' "$VEIL_DO_SPACES_KEY" "$VEIL_DO_SPACES_SECRET" "$(database_url "$1")" > "$STATE/hub$1.env"
        fi
        umask 022
        copy_to "$STATE/hub$1.env" "$2" /etc/veil/hub.env
    else echo "would copy /etc/veil/hub.env ($OBJECTS keys, the database URL of server $1) to $2" >&2; fi
}
for i in $(seq "$HUBS"); do hub_env "$i" "$(addr "$(hub_name "$i")")"; done
while read -r role name size; do [ "$role" = driver ] && hub_env 1 "$(addr "$name")"; done < <(droplets)
# The `spaces` gate's own server (on the first server's machine) uses Spaces.
if [ "$SPACES_GATE" = 0 ]; then :
elif [ $APPROVED = 1 ]; then
    umask 077; printf 'VEIL_S3_ACCESS_KEY=%s\nVEIL_S3_SECRET_KEY=%s\nVEIL_DATABASE_URL=%s\n' "$VEIL_DO_SPACES_KEY" "$VEIL_DO_SPACES_SECRET" "$(database_url 1)" > "$STATE/spaces.env"; umask 022
    copy_to "$STATE/spaces.env" "$HUB1" /etc/veil/spaces.env
else echo "would copy /etc/veil/spaces.env (Spaces keys, the database URL of server 1) to $HUB1" >&2; fi
remote "$HUB1" "docker run --rm --env-file /etc/veil/hub.env veil-server:$TAG migrate"
# The limits per device and per address are lifted, as veil-bench lifts
# them on a server it starts (crates/veil-bench/src/server.rs): a driver's
# 10,000 agents are a few devices on one address, and would measure the
# limits. A server for people keeps the defaults (docs/HUB.md §13.25).
SERVER_RUN="docker run -d --name veil-server --restart unless-stopped -p 8443:8443 --env-file /etc/veil/hub.env -v veil-data:/var/lib/veil -v /etc/veil/tls:/tls:ro --ulimit nofile=1048576:1048576 veil-server:$TAG --listen 0.0.0.0:8443 --data /var/lib/veil --db-connections $DB_CONNECTIONS --s3-endpoint $(objects_endpoint) --s3-bucket $BUCKET --s3-region $S3_REGION --tls-cert /tls/server.pem --tls-key /tls/server-key.pem --device-rate 1000000000/1000000000 --anonymous-rate 1000000000/1000000000 --max-connections 262144"
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
    case "$code" in 2*|4*) ;; *) echo "configure: the server did not answer cleanly (HTTP $code); see deploy/$KIT/logs.sh" >&2; exit 1 ;; esac
    save_state TAG "$TAG"
    echo "== configured. vl clients: vl login https://$FRONT:8443 --ca $STATE/tls/ca.pem ; benchmarks: deploy/$KIT/bench.sh --approve <gate>"
else echo "would curl https://$FRONT:8443/v1/epochs with the run's CA" >&2; fi
