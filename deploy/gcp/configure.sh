#!/usr/bin/env bash
# Configure the machines create.sh made (docs/DEPLOY.md §12.4): the same
# steps on the machines as the DigitalOcean kit's, written once in
# deploy/do/configure.sh (cloud-init, the run's certificate, the images
# over SSH, YugabyteDB or PostgreSQL, MinIO on the storage machine's local
# SSD, the migrations, the servers, the balancer, the smoke test), run here
# with this kit's lib.sh (VEIL_KIT=gcp).
#   configure.sh [--approve] [TAG]
set -euo pipefail
VEIL_KIT=gcp exec bash "$(cd "$(dirname "$0")" && pwd)/../do/configure.sh" "$@"
