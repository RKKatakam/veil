#!/usr/bin/env bash
# The scale benchmark (docs/design/scale/9-scale-benchmark.md): builds the
# release `vl` and `veil-bench`, generates a repository, times every case,
# runs the N-agents profile, writes RESULTS.json and RESULTS.md, and
# deletes what it generated.
#
#   scripts/bench-scale.sh                 # the 1 GB profile
#   scripts/bench-scale.sh 5g              # ~5 GB: only when nothing else builds
#   scripts/bench-scale.sh small --cloaked # 85 % of the files cloaked
#   scripts/bench-scale.sh 1g -- --agents 4,16   # extra veil-bench flags
#
# Environment:
#   MIN_FREE_GB   stop when free disk would drop below this (default 8)
#   SEED          generator seed (default 1)
#   BENCH_DIR     where repositories are generated (default .scratch/bench)
#   OUT_DIR       where results go (default .scratch/bench-results)
#   FORCE=1       run 5g even though other cargo builds are running
#
# Everything lives under the worktree's .scratch/ (ext4, not a tmpfs /tmp),
# with TMPDIR there too. Disk needed: about 6 GB (1g), 16 GB (5g) above
# MIN_FREE_GB at peak; `veil-bench` checks before every phase and stops.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
PROFILE=${1:-1g}
shift || true
CLOAKED=()
if [[ "${1:-}" == "--cloaked" ]]; then
    CLOAKED=(--cloaked)
    shift
fi
if [[ "${1:-}" == "--" ]]; then
    shift
fi
EXTRA=("$@")

MIN_FREE_GB=${MIN_FREE_GB:-8}
SEED=${SEED:-1}
BENCH_DIR=${BENCH_DIR:-$ROOT/.scratch/bench}
OUT_DIR=${OUT_DIR:-$ROOT/.scratch/bench-results}
mkdir -p "$ROOT/.scratch/tmp" "$BENCH_DIR" "$OUT_DIR"
export TMPDIR=$ROOT/.scratch/tmp
export CARGO_INCREMENTAL=0

free_gb() { df -BG --output=avail "$1" | tail -1 | tr -dc '0-9'; }

echo "== disk before the build"
df -h /
if (( $(free_gb "$ROOT") < MIN_FREE_GB + 4 )); then
    echo "stop: under $((MIN_FREE_GB + 4)) GB free before building" >&2
    exit 1
fi

if [[ "$PROFILE" == "5g" && "${FORCE:-}" != "1" ]]; then
    if pgrep -x cargo >/dev/null || pgrep -x rustc >/dev/null; then
        echo "stop: 5g runs only when nothing else builds (cargo/rustc is running; FORCE=1 overrides)" >&2
        exit 1
    fi
fi

echo "== building release vl and veil-bench"
cargo build --release -p vl -p veil-bench

echo "== disk before the run"
df -h /
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAME="${PROFILE}${CLOAKED:+-cloaked}-seed${SEED}-${STAMP}"
OUT="$OUT_DIR/$NAME.json"

AGENTS=(--agents 4,16,64)
PACK=()
if [[ "$PROFILE" == "5g" ]]; then
    AGENTS=(--agents 4,16)
    # Its loose store would pass 15 GB before the first `vl gc`.
    PACK=(--pack-every 5000)
fi

"$ROOT/target/release/veil-bench" run \
    --profile "$PROFILE" "${CLOAKED[@]}" --seed "$SEED" \
    --dir "$BENCH_DIR" --vl "$ROOT/target/release/vl" \
    --out "$OUT" --min-free-gb "$MIN_FREE_GB" --src "$ROOT" \
    "${AGENTS[@]}" "${PACK[@]}" "${EXTRA[@]}"

echo "== disk after the run"
df -h /
echo "results: $OUT"
echo "         ${OUT%.json}.md"
