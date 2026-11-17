#!/usr/bin/env bash
# Explicitly install (or remove) Veil's `commit-msg` verification gate hook.
# Never invoked automatically by builds or checks.
set -euo pipefail

usage() {
    cat <<'EOF'
usage: scripts/hooks/install.sh [--force] [--uninstall]

Installs `scripts/hooks/commit-msg` into this repository's git hooks directory
(resolved via `git rev-parse --git-path hooks`, default mode: observe).

Options:
  --force       Overwrite an existing `commit-msg` hook
  --uninstall   Remove the installed `commit-msg` hook if it came from Veil
EOF
}

FORCE=0
UNINSTALL=0
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "install.sh: unknown option '$arg'" >&2; usage >&2; exit 2 ;;
    esac
done

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "install.sh: not inside a git repository" >&2
    exit 2
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_HOOK="${SRC_DIR}/commit-msg"
HOOKS_DIR="$(git rev-parse --git-path hooks)"
DST_HOOK="${HOOKS_DIR}/commit-msg"

if [[ "$UNINSTALL" -eq 1 ]]; then
    if [[ -f "$DST_HOOK" ]]; then
        if grep -q 'VERIFY_GATE' "$DST_HOOK" 2>/dev/null || [[ "$FORCE" -eq 1 ]]; then
            rm -f "$DST_HOOK"
            echo "removed $DST_HOOK"
            exit 0
        else
            echo "install.sh: $DST_HOOK is not Veil's verify-gate hook (pass --force to remove)" >&2
            exit 1
        fi
    fi
    echo "nothing to remove ($DST_HOOK not present)"
    exit 0
fi

[[ -f "$SRC_HOOK" ]] || { echo "install.sh: missing $SRC_HOOK" >&2; exit 1; }
mkdir -p "$HOOKS_DIR"

if [[ -e "$DST_HOOK" && "$FORCE" -eq 0 ]]; then
    if cmp -s "$SRC_HOOK" "$DST_HOOK"; then
        chmod +x "$DST_HOOK"
        echo "already up to date: $DST_HOOK"
        exit 0
    fi
    echo "install.sh: $DST_HOOK already exists (pass --force to overwrite)" >&2
    exit 1
fi

cp "$SRC_HOOK" "$DST_HOOK"
chmod +x "$DST_HOOK"
echo "installed $DST_HOOK (default mode: VERIFY_GATE=observe)"
