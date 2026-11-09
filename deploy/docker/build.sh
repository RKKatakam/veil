#!/usr/bin/env bash
# Build Veil's two container images from this checkout (docs/DEPLOY.md):
#   veil-server:TAG   the Hub (also `veil-server cache` and `migrate`)
#   veil-bench:TAG    the load driver (veil-bench, vl, veil-server, git)
# TAG defaults to the short commit id (`-dirty` when the tree has changes).
# Nothing is pushed anywhere; the images stay in the local Docker daemon.
#
#   deploy/docker/build.sh            # both images
#   deploy/docker/build.sh server     # one of them
#   TAG=mytag deploy/docker/build.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
TAG=${TAG:-$(git describe --always --dirty --abbrev=8 2>/dev/null || echo dev)}
COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
D() { if docker info >/dev/null 2>&1; then docker "$@"; else sg docker -c "docker $(printf '%q ' "$@")"; fi; }
export DOCKER_BUILDKIT=1
for target in ${*:-server bench}; do
    case "$target" in
        server|bench) ;;
        *) echo "build.sh: unknown target '$target' (usage: build.sh [server] [bench])" >&2; exit 2 ;;
    esac
    echo "== building veil-$target:$TAG"
    D build -f deploy/docker/Dockerfile --target "$target" \
        --build-arg "VEIL_COMMIT=$COMMIT" -t "veil-$target:$TAG" .
done
D images --format '{{.Repository}}:{{.Tag}}  {{.Size}}' | grep -E "^veil-(server|bench):$TAG " || true
echo "TAG=$TAG"
