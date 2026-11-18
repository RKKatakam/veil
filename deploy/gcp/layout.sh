#!/usr/bin/env bash
# Switch the run's servers to an object layout between gates, on the same
# machines (docs/DEPLOY.md §12.11; the layouts: docs/HUB.md §13.42). Each
# server in turn is stopped (SIGINT, its clean stop), its container
# replaced by one started with --object-layout LAYOUT and nothing else
# changed (the same image, data volume, database and bucket, so its
# identity and keys stay), its health awaited, and the layout it then
# reports checked. Then the one address is asked from the first driver,
# and the layout saved in the run's state: bench.sh records it beside every
# result and passes it to the tool, and configure.sh, run again (a Spot
# recovery), starts the servers in it.
# Nothing is converted, moved or deleted: every server reads both layouts,
# and each gate makes projects of its own, so a gate reads only what its
# own layout wrote. A switch that fails part-way leaves servers in two
# layouts, which is allowed (they share the database and the store), and
# bench.sh then refuses to run a gate: run this again.
#   layout.sh [--approve] packs|objects
set -euo pipefail
. "$(dirname "$0")/lib.sh"
[ $# = 1 ] && [[ "$1" =~ ^(packs|objects)$ ]] || { echo "layout: usage: layout.sh [--approve|--dry-run] packs|objects" >&2; exit 2; }
WAS=$OBJECT_LAYOUT; OBJECT_LAYOUT=$1
[ $APPROVED = 1 ] && require_created
# The image configure.sh started the servers from (saved in the state).
[ $APPROVED = 0 ] || [ -n "${TAG:-}" ] || { echo "layout: the servers are not configured yet (no TAG in $STATE_FILE); run deploy/gcp/configure.sh --approve first" >&2; exit 2; }
TAG=${TAG:-$(cd "$DO_ROOT" && git describe --always --dirty --abbrev=8 2>/dev/null || echo dev)}
[ -n "$BUCKET" ] || BUCKET="$NAME-objects-DRY"
addr() { local v; v=$(ip_of "$1"); echo "${v:-${1}_IP}"; }   # a machine's public address (a placeholder in a dry run)
SERVER_RUN=$(server_run "$TAG")
HEALTHY='for i in $(seq 60); do [ "$(docker inspect -f "{{.State.Health.Status}}" veil-server 2>/dev/null)" = healthy ] && break; sleep 1; done; [ "$(docker inspect -f "{{.State.Health.Status}}" veil-server)" = healthy ]'

echo "== object layout: $WAS -> $OBJECT_LAYOUT on $HUBS server(s), one at a time"
for i in $(seq "$HUBS"); do
    h=$(addr "$(hub_name "$i")")
    remote "$h" "docker stop -t 30 veil-server >/dev/null 2>&1; docker rm -f veil-server >/dev/null 2>&1; $SERVER_RUN >/dev/null && $HEALTHY" ||
        { echo "layout: server $i did not come back healthy in $OBJECT_LAYOUT (docker logs veil-server on $h); run layout.sh again" >&2; exit 1; }
    if [ $APPROVED = 1 ]; then
        l=$(server_layout "$h")
        [ "$l" = "$OBJECT_LAYOUT" ] || { echo "layout: server $i is healthy but reports object layout '${l:-none}', not '$OBJECT_LAYOUT'" >&2; exit 1; }
        echo "   server $i: healthy, object layout $l"
    else echo "would check that server $i reports object layout $OBJECT_LAYOUT (its stats.json)" >&2; fi
done
# The one address the agents use answers again (the balancer puts a server
# back within 2 s of its health check passing): asked from the first
# driver, over the private network, with the run's CA. A 4xx is expected:
# the route needs a grant.
FRONT=$(front_host private)
remote "$(addr "$NAME-driver1")" "for i in \$(seq 30); do c=\$(curl -s --http1.1 -o /dev/null -w '%{http_code}' --max-time 5 --cacert /etc/veil/tls/ca.pem https://$FRONT:8443/v1/epochs); case \$c in 2*|4*) echo \"   https://$FRONT:8443 answers (HTTP \$c)\"; exit 0 ;; esac; sleep 1; done; exit 1" ||
    { echo "layout: https://$FRONT:8443 does not answer from $NAME-driver1 after the switch" >&2; exit 1; }
if [ $APPROVED = 1 ]; then
    save_state OBJECT_LAYOUT "$OBJECT_LAYOUT"
    echo "== every server runs object layout $OBJECT_LAYOUT (saved in $STATE_FILE); gates: deploy/gcp/bench.sh --approve <gate>"
else echo "would save OBJECT_LAYOUT=$OBJECT_LAYOUT in $STATE_FILE" >&2; fi
