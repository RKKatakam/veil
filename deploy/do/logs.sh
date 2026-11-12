#!/usr/bin/env bash
# Collect logs and metrics from every droplet into deploy/results/NAME/logs-<stamp>/
# (docs/DEPLOY.md, "Logs and metrics"): container logs (server, cache,
# database), the server's counters, the docker-stats samples bench.sh
# recorded, memory and disk, and the kernel's log tail.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
[ $# -eq 0 ] || { echo "logs: unknown argument '$1' (usage: logs.sh [--approve|--dry-run])" >&2; exit 2; }
[ $APPROVED = 1 ] && require_created
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$DO_ROOT/deploy/results/$NAME/logs-$STAMP
[ $APPROVED = 1 ] && mkdir -p "$OUT"
while read -r role name size; do
    ip=$(ip_of "$name"); ip=${ip:-${name}_IP}; d=$OUT/$name
    if [ $APPROVED = 1 ]; then
        mkdir -p "$d"
        remote "$ip" 'for c in $(docker ps -aq); do n=$(docker inspect -f "{{.Name}}" $c | tr -d /); echo "### $n"; docker logs --tail 5000 $c 2>&1; done' > "$d/containers.log" 2>&1 || true
        remote "$ip" 'docker ps -a --no-trunc; echo; free -m; echo; df -h /; echo; uptime; echo; dmesg -T 2>/dev/null | tail -50' > "$d/system.txt" 2>&1 || true
        case $role in
            hub) remote "$ip" 'docker kill -s USR1 veil-server >/dev/null 2>&1; sleep 1; docker exec veil-server cat /var/lib/veil/stats.json' > "$d/server-stats.json" 2>/dev/null || true
                 copy_from "$ip" /srv/metrics "$d/" || true ;;
            db)  remote "$ip" 'docker exec pg psql -U veil -d veil -c "select calls, mean_exec_time, left(query,80) q from pg_stat_statements order by calls desc limit 30"' > "$d/pg-stat-statements.txt" 2>&1 || true ;;
            yb)  remote "$ip" "docker exec yb bin/ysqlsh -h $(priv_of "$name") -c 'select * from yb_servers()' -c 'select count(*) as tablets_here from yb_local_tablets'" > "$d/yb.txt" 2>&1 || true ;;
        esac
    else
        remote "$ip" 'for c in $(docker ps -aq); do n=$(docker inspect -f "{{.Name}}" $c | tr -d /); echo "### $n"; docker logs --tail 5000 $c 2>&1; done'
        remote "$ip" 'docker ps -a --no-trunc; echo; free -m; echo; df -h /; echo; uptime; echo; dmesg -T 2>/dev/null | tail -50'
        case $role in
            hub) remote "$ip" 'docker kill -s USR1 veil-server >/dev/null 2>&1; sleep 1; docker exec veil-server cat /var/lib/veil/stats.json'
                 copy_from "$ip" /srv/metrics "$d/" ;;
            db)  remote "$ip" 'docker exec pg psql -U veil -d veil -c "select calls, mean_exec_time, left(query,80) q from pg_stat_statements order by calls desc limit 30"' ;;
            yb)  remote "$ip" "docker exec yb bin/ysqlsh -h PRIVATE_IP -c 'select * from yb_servers()' -c 'select count(*) as tablets_here from yb_local_tablets'" ;;
        esac
    fi
done < <(droplets)
[ $APPROVED = 1 ] && echo "== logs in $OUT" || true
