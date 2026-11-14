#!/usr/bin/env bash
# Collect logs and metrics from every machine into deploy/results/NAME/logs-<stamp>/
# (docs/DEPLOY.md §12.6): deploy/do/logs.sh's steps, run with this kit's
# lib.sh (VEIL_KIT=gcp).
#   logs.sh [--approve]
set -euo pipefail
VEIL_KIT=gcp exec bash "$(cd "$(dirname "$0")" && pwd)/../do/logs.sh" "$@"
