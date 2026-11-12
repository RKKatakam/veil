#!/usr/bin/env bash
# Print the balancer's HAProxy configuration for the servers given
# (docs/DEPLOY.md, "Several servers"). One address in front of every Veil
# server: TCP, TLS passed through untouched (each server holds the run's
# certificate, which names the balancer too), least connections, a TCP
# health check every second. A server that stops answering is out of
# rotation after two failed checks, and its connections are closed, so
# agents reconnect to the servers that are left.
#
#   deploy/lb/haproxy-cfg.sh HOST:PORT...  > haproxy.cfg
#   HAPROXY_DNS=127.0.0.11:53 deploy/lb/haproxy-cfg.sh hub1:8443 hub2:8443
#       (the rehearsal: names re-resolved through Docker's DNS, since a
#       restarted container may come back on another address)
#
# The DigitalOcean run and the Compose rehearsal use this one file.
set -euo pipefail
[ $# -gt 0 ] && [[ "$1" != -* ]] || { echo "haproxy-cfg: usage: haproxy-cfg.sh HOST:PORT..." >&2; exit 2; }
DNS=${HAPROXY_DNS:-}
[ -z "$DNS" ] || [[ "$DNS" =~ ^[0-9.]+:[0-9]+$ ]] || { echo "haproxy-cfg: invalid HAPROXY_DNS '$DNS' (IP:PORT)" >&2; exit 2; }
cat <<CFG
global
    maxconn 400000
    log stdout format raw local0 notice
defaults
    mode tcp
    log global
    timeout connect 5s
    timeout client 15m
    timeout server 15m
    timeout check 2s
CFG
[ -z "$DNS" ] || cat <<CFG
resolvers dns
    nameserver dns $DNS
    hold valid 1s
    hold obsolete 1s
CFG
cat <<CFG
frontend veil
    bind :8443
    maxconn 400000
    default_backend hubs
backend hubs
    balance leastconn
    default-server check inter 1s fall 2 rise 2 on-marked-down shutdown-sessions maxconn 200000${DNS:+ resolvers dns init-addr last,libc,none}
CFG
i=0
for s in "$@"; do
    [[ "$s" =~ ^[A-Za-z0-9_.-]+:[0-9]+$ ]] || { echo "haproxy-cfg: invalid server '$s' (HOST:PORT)" >&2; exit 2; }
    i=$((i + 1)); echo "    server hub$i $s"
done
