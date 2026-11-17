#!/usr/bin/env bash
# List commits in <range> (default: integration...HEAD) whose `Verified-by:`
# trailer is missing, `none` (including `none (reason: ...)` or all-skipped),
# or carries a failed/malformed check status.
#
# Output:
#   <short-sha> — <missing|none|failed> — <subject> [(reason: ...)]
set -uo pipefail

usage() {
    cat <<'EOF'
usage: scripts/unverified.sh [--check] [<range>]
       scripts/unverified.sh --self-test

Lists commits in <range> (default: integration...HEAD) whose `Verified-by:`
stamp is missing, `none`, or failed.

Options:
  --check       Exit 1 if any unverified commit is found (default: exit 0)
  --merges-only Inspect only merge commits (`git log --merges`)
  --self-test   Run embedded self-tests in a temporary repository
EOF
}

# Classify a single commit message body on stdin.
# Prints empty string if verified (at least one suite `=pass` or `=hostile` and
# zero `=fail`); otherwise prints `<missing|none|failed>\t<detail>`.
classify_message() {
    awk '
    function trim(s) {
        sub(/^[[:space:]]+/, "", s)
        sub(/[[:space:]]+$/, "", s)
        return s
    }
    /^[[:space:]]*[Vv]erified-by:[[:space:]]*/ {
        line = $0
        sub(/^[[:space:]]*[Vv]erified-by:[[:space:]]*/, "", line)
        stamp = trim(line)
        found = 1
    }
    END {
        if (!found || stamp == "") {
            print "missing\t"
            exit
        }
        if (stamp == "none") {
            print "none\t"
            exit
        }
        if (stamp ~ /^none[[:space:]]+\(reason:[[:space:]]*.+\)$/) {
            detail = stamp
            sub(/^none[[:space:]]+/, "", detail)
            print "none\t" detail
            exit
        }
        if (stamp ~ /^none([^a-zA-Z0-9_-]|$)/) {
            print "none\t" stamp
            exit
        }
        n = split(stamp, toks, /[[:space:]]+/)
        passed = 0
        failed = 0
        malformed = 0
        for (i = 1; i <= n; i++) {
            t = toks[i]
            if (t == "") continue
            eq = index(t, "=")
            if (eq <= 1) {
                malformed = 1
                continue
            }
            val = substr(t, eq + 1)
            if (val == "pass" || val == "hostile") passed++
            else if (val == "fail") failed++
            else if (val == "skipped") { }
            else if (val == "none") { }
            else malformed = 1
        }
        if (failed > 0 || malformed > 0) {
            print "failed\t(" stamp ")"
        } else if (passed == 0) {
            print "none\t"
        }
    }
    '
}

run_self_test() {
    local tmp
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/unverified-selftest.XXXXXX")
    trap 'rm -rf "$tmp"' RETURN

    local script_abs pass=0 fail=0
    script_abs="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

    echo "== unverified.sh self-test =="
    local repo="$tmp/repo"
    git init -q "$repo"
    git -C "$repo" config user.email "test@veil.local"
    git -C "$repo" config user.name "Test"

    git -C "$repo" commit -q --allow-empty -m "base commit"
    git -C "$repo" branch integration

    git -C "$repo" commit -q --allow-empty -m $'verified commit\n\nVerified-by: verify-fast=pass verify-server=skipped gate-1g=skipped load=skipped'
    git -C "$repo" commit -q --allow-empty -m "unstamped commit"
    git -C "$repo" commit -q --allow-empty -m $'explicit none commit\n\nVerified-by: none (reason: docs only)'
    git -C "$repo" commit -q --allow-empty -m $'failed check commit\n\nVerified-by: verify-fast=fail verify-server=skipped gate-1g=skipped load=skipped'

    local out rc_default rc_check
    out=$(cd "$repo" && bash "$script_abs" integration...HEAD)
    rc_default=$?
    (cd "$repo" && bash "$script_abs" --check integration...HEAD >/dev/null)
    rc_check=$?

    local count
    count=$(printf '%s\n' "$out" | sed '/^$/d' | wc -l | tr -d ' ')
    if [[ "$rc_default" -eq 0 && "$rc_check" -eq 1 && "$count" -eq 3 ]] &&
       printf '%s\n' "$out" | grep -q ' — missing — unstamped commit' &&
       printf '%s\n' "$out" | grep -q ' — none — explicit none commit (reason: docs only)' &&
       printf '%s\n' "$out" | grep -q ' — failed — failed check commit' &&
       ! printf '%s\n' "$out" | grep -q 'verified commit'; then
        printf '  ok    identifies missing, none, and failed commits while skipping verified ones\n'
        pass=$((pass + 1))
    else
        printf '  FAIL  unexpected output (rc=%d check_rc=%d count=%s):\n%s\n' "$rc_default" "$rc_check" "$count" "$out" >&2
        fail=$((fail + 1))
    fi

    echo "unverified.sh self-test: $pass passed, $fail failed"
    [[ "$fail" -eq 0 ]]
}

CHECK_EXIT=0
MERGES_ONLY=0
RANGE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --self-test)
            run_self_test
            exit $?
            ;;
        --check)
            CHECK_EXIT=1
            shift
            ;;
        --merges-only)
            MERGES_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            [[ $# -gt 0 ]] && RANGE="$1"
            break
            ;;
        -*)
            echo "unverified: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [[ -n "$RANGE" ]]; then
                echo "unverified: unexpected extra argument '$1'" >&2
                exit 2
            fi
            RANGE="$1"
            shift
            ;;
    esac
done

RANGE="${RANGE:-integration...HEAD}"
if [[ "$RANGE" =~ ^(.+)\.\.\.(.+)$ ]]; then
    LOG_RANGE="${BASH_REMATCH[1]}..${BASH_REMATCH[2]}"
else
    LOG_RANGE="$RANGE"
fi

LOG_ARGS=(--reverse --format='%H%x09%h%x09%s')
[[ "$MERGES_ONLY" -eq 1 ]] && LOG_ARGS=(--merges "${LOG_ARGS[@]}")

if ! COMMITS=$(git log "${LOG_ARGS[@]}" "$LOG_RANGE"); then
    echo "unverified: git log failed for range '$RANGE'" >&2
    exit 2
fi

FOUND=0
while IFS=$'\t' read -r full_sha short_sha subj; do
    [[ -z "$full_sha" ]] && continue
    VERDICT=$(git log -1 --format=%B "$full_sha" | classify_message)
    if [[ -n "$VERDICT" ]]; then
        KIND="${VERDICT%%$'\t'*}"
        DETAIL="${VERDICT#*$'\t'}"
        if [[ -n "$DETAIL" ]]; then
            printf '%s — %s — %s %s\n' "$short_sha" "$KIND" "$subj" "$DETAIL"
        else
            printf '%s — %s — %s\n' "$short_sha" "$KIND" "$subj"
        fi
        FOUND=$((FOUND + 1))
    fi
done <<<"$COMMITS"

if [[ "$CHECK_EXIT" -eq 1 && "$FOUND" -gt 0 ]]; then
    exit 1
fi
exit 0
