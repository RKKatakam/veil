#!/usr/bin/env bash
# Format and write `Verified-by:` git trailers from Veil check results.
#
# Stamp grammar:
#   Verified-by: verify-fast=<pass|fail|skipped> verify-server=<pass|fail|skipped|hostile> gate-1g=<pass|fail|skipped> load=<pass|fail|skipped> [extra=<status> ...]
#   Verified-by: none
#   Verified-by: none (reason: <why>)
#
# When nothing ran (all suites `skipped` or `--none`), the stamp always uses
# `none` so `scripts/unverified.sh` can query commits that were not verified.
#
# Feeds directly from existing check outputs without modifying ~/.cache/veil-orch/verify-fast.sh:
#   scripts/verify-stamp.sh --fast-tag <tag>                 # reads /tmp/veil-*-<tag>.log
#   scripts/verify-stamp.sh --fast-log <stdout.log>          # reads verify-fast.sh stdout
#   scripts/verify-stamp.sh --server-log <server.log>        # reads scripts/verify-server.sh stdout
#   scripts/verify-stamp.sh --gate-1g-log <bench-1g.log>     # reads scripts/bench-server.sh 1g output/md/json
#   scripts/verify-stamp.sh --load-log <bench-load.log>      # reads scripts/bench-server.sh load output/json
#   scripts/verify-stamp.sh verify-fast=pass gate-1g=pass    # explicit key=value overrides
#   scripts/verify-stamp.sh --none --reason "docs and scripts only"
#
# Output targets:
#   (default)              print the `Verified-by: ...` trailer line to stdout
#   -f, --msg-file <file>  insert or replace `Verified-by:` in a commit message file
#   --amend                insert or replace `Verified-by:` on HEAD's commit message
set -uo pipefail

usage() {
    cat <<'EOF'
usage: scripts/verify-stamp.sh [options] [suite=status ...]
       scripts/verify-stamp.sh --self-test

Build a `Verified-by:` trailer from Veil check outputs or explicit statuses.

Check inputs:
  --fast-tag <tag>         Parse /tmp/veil-{test,clippy,doc,wasm,ign}-<tag>.log
                           written by `bash ~/.cache/veil-orch/verify-fast.sh <tag>`
  --fast-log <file|->      Parse captured stdout of `verify-fast.sh`
  --server-log <file|->    Parse captured stdout of `scripts/verify-server.sh`
  --gate-1g-log <file>     Parse output, `.md` or `.json` from `scripts/bench-server.sh 1g`
  --load-log <file>        Parse output or `.json` from `scripts/bench-server.sh load`
  --none [<reason>]        Record that no checks ran (`Verified-by: none`)
  --reason <reason>        Attach `(reason: <reason>)` when stamp is `none`
  <suite>=<status>         Set suite directly:
                             verify-fast=pass|fail|skipped
                             verify-server=pass|fail|skipped|hostile
                             gate-1g=pass|fail|skipped
                             load=pass|fail|skipped
                             <extra>=pass|fail|skipped

Destinations:
  (default)                Print `Verified-by: ...` trailer line to stdout
  -f, --msg-file <file>    Write/replace trailer in commit message file <file>
  --amend                  Amend HEAD's commit message (tree unchanged) with trailer
EOF
}

parse_fast_tag() {
    local tag="$1"
    local prefix="${VEIL_FAST_LOG_PREFIX:-/tmp/veil}"
    local s log last
    for s in test clippy doc wasm ign; do
        log="${prefix}-${s}-${tag}.log"
        [[ -f "$log" ]] || { echo "fail"; return; }
    done
    [[ "$(tail -n 1 "${prefix}-test-${tag}.log")" == "test exit 0" ]] || { echo "fail"; return; }
    [[ "$(tail -n 1 "${prefix}-clippy-${tag}.log")" == "clippy exit 0" ]] || { echo "fail"; return; }
    [[ "$(tail -n 1 "${prefix}-doc-${tag}.log")" == "doc exit 0" ]] || { echo "fail"; return; }
    [[ "$(tail -n 1 "${prefix}-wasm-${tag}.log")" == "check-wasm exit 0" ]] || { echo "fail"; return; }
    # Ignored BUG reproductions are expected to fail at runtime (exit 101),
    # never to fail compilation.
    if grep -Eq '^error(\[|: could not compile)' "${prefix}-ign-${tag}.log"; then
        echo "fail"
        return
    fi
    last=$(tail -n 1 "${prefix}-ign-${tag}.log")
    [[ "$last" =~ ^ignored\ exit\ [0-9]+$ ]] || { echo "fail"; return; }
    echo "pass"
}

parse_fast_log() {
    local content="$1"
    [[ -z "$content" ]] && { echo "fail"; return; }
    if printf '%s\n' "$content" | grep -qx 'test exit 0' &&
       printf '%s\n' "$content" | grep -qx 'clippy exit 0' &&
       printf '%s\n' "$content" | grep -qx 'doc exit 0' &&
       printf '%s\n' "$content" | grep -qx 'check-wasm exit 0' &&
       ! printf '%s\n' "$content" | grep -Eq '^error(\[|:)'; then
        echo "pass"
    else
        echo "fail"
    fi
}

parse_server_log() {
    local content="$1"
    [[ -z "$content" ]] && { echo "fail"; return; }
    if printf '%s\n' "$content" | grep -qx 'verify-server: all green' &&
       ! printf '%s\n' "$content" | grep -Eq '^[[:space:]]*FAIL[[:space:]]'; then
        if printf '%s\n' "$content" | grep -Eq '^[[:space:]]*ok[[:space:]]+hostile-postgres$' &&
           printf '%s\n' "$content" | grep -Eq '^[[:space:]]*ok[[:space:]]+hostile-yugabyte$'; then
            echo "hostile"
        else
            echo "pass"
        fi
    else
        echo "fail"
    fi
}

parse_bench_1g() {
    local file="$1"
    [[ -f "$file" ]] || { echo "fail"; return; }
    local content
    content=$(cat "$file")
    [[ -z "$content" ]] && { echo "fail"; return; }
    if printf '%s\n' "$content" | grep -Eq '(^stop:|build failed|"gates_missed":[[:space:]]*\[[^][:space:]])'; then
        echo "fail"
        return
    fi
    # In markdown/stdout tables, `⛔` marks a case over the 512 MiB client gate or
    # 1 GB server gate (unless excused as `known: BUG-NNN`).
    if printf '%s\n' "$content" | grep '⛔' | grep -qv 'known: BUG-'; then
        echo "fail"
        return
    fi
    echo "pass"
}

parse_bench_load() {
    local file="$1"
    [[ -f "$file" ]] || { echo "fail"; return; }
    local content
    content=$(cat "$file")
    [[ -z "$content" ]] && { echo "fail"; return; }
    if printf '%s\n' "$content" | grep -Eq '(^stop:|build failed|missed gate|"gates_missed":[[:space:]]*\[[^][:space:]])'; then
        echo "fail"
    else
        echo "pass"
    fi
}

write_trailer_to_text() {
    local trailer_val="$1"
    # Place Verified-by before Co-Authored-By if present, replacing any prior Verified-by.
    awk -v val="$trailer_val" '
    {
        lines[NR] = $0
    }
    END {
        # Strip existing Verified-by lines
        out_n = 0
        coauth_idx = 0
        for (i = 1; i <= NR; i++) {
            if (lines[i] ~ /^[Vv]erified-by:[[:space:]]*/) continue
            out_n++
            out[out_n] = lines[i]
            if (coauth_idx == 0 && lines[i] ~ /^[Cc]o-[Aa]uthored-[Bb]y:[[:space:]]*/) {
                coauth_idx = out_n
            }
        }
        # Trim trailing blank lines when no Co-Authored-By
        if (coauth_idx > 0) {
            for (i = 1; i <= out_n; i++) {
                if (i == coauth_idx) {
                    printf "Verified-by: %s\n", val
                }
                print out[i]
            }
        } else {
            while (out_n > 0 && out[out_n] ~ /^[[:space:]]*$/) out_n--
            if (out_n == 0) {
                printf "Verified-by: %s\n", val
            } else {
                # Check whether the last non-empty block is already a trailer block
                last_line = out[out_n]
                for (i = 1; i <= out_n; i++) print out[i]
                if (last_line !~ /^[A-Za-z0-9-]+:[[:space:]]+/) {
                    print ""
                }
                printf "Verified-by: %s\n", val
            }
        }
    }
    '
}

run_self_test() {
    local tmp
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/verify-stamp-selftest.XXXXXX")
    trap 'rm -rf "$tmp"' RETURN

    local script_abs pass=0 fail=0
    script_abs="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

    assert_eq_str() {
        local label="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then
            printf '  ok    %-34s -> %s\n' "$label" "$got"
            pass=$((pass + 1))
        else
            printf '  FAIL  %-34s got=%q want=%q\n' "$label" "$got" "$want" >&2
            fail=$((fail + 1))
        fi
    }

    echo "== verify-stamp self-test =="

    # 1. Nothing run -> Verified-by: none
    assert_eq_str "empty args -> none" \
        "$(bash "$script_abs")" \
        "Verified-by: none"

    assert_eq_str "all skipped -> none" \
        "$(bash "$script_abs" verify-fast=skipped verify-server=skipped)" \
        "Verified-by: none"

    assert_eq_str "--none with reason" \
        "$(bash "$script_abs" --none --reason "scripts and docs only")" \
        "Verified-by: none (reason: scripts and docs only)"

    # 2. verify-fast tag parser (passing vs clippy fail like BUG-2610)
    printf 'ok\ntest exit 0\n' >"$tmp/veil-test-ok1.log"
    printf 'ok\nclippy exit 0\n' >"$tmp/veil-clippy-ok1.log"
    printf 'ok\ndoc exit 0\n' >"$tmp/veil-doc-ok1.log"
    printf 'ok\ncheck-wasm exit 0\n' >"$tmp/veil-wasm-ok1.log"
    printf 'test bug_1 ... FAILED\nignored exit 101\n' >"$tmp/veil-ign-ok1.log"
    assert_eq_str "--fast-tag passing" \
        "$(VEIL_FAST_LOG_PREFIX="$tmp/veil" bash "$script_abs" --fast-tag ok1)" \
        "Verified-by: verify-fast=pass verify-server=skipped gate-1g=skipped load=skipped"

    cp "$tmp/veil-test-ok1.log" "$tmp/veil-test-bad1.log"
    printf 'error: clippy failed\nclippy exit 101\n' >"$tmp/veil-clippy-bad1.log"
    cp "$tmp/veil-doc-ok1.log" "$tmp/veil-doc-bad1.log"
    cp "$tmp/veil-wasm-ok1.log" "$tmp/veil-wasm-bad1.log"
    cp "$tmp/veil-ign-ok1.log" "$tmp/veil-ign-bad1.log"
    assert_eq_str "--fast-tag clippy failure" \
        "$(VEIL_FAST_LOG_PREFIX="$tmp/veil" bash "$script_abs" --fast-tag bad1)" \
        "Verified-by: verify-fast=fail verify-server=skipped gate-1g=skipped load=skipped"

    # 3. verify-server stdout parser (pass vs hostile vs fail)
    cat >"$tmp/srv-pass.log" <<'EOF'
   ok    unit
   ok    clippy
   ok    postgres
   ok    yugabyte
   skip  hostile sets (no derive/ or query/ changes; VEIL_VERIFY_HOSTILE=1 runs them)
   ok    load-postgres
   ok    load-yugabyte
verify-server: all green
EOF
    assert_eq_str "--server-log pass" \
        "$(bash "$script_abs" --server-log "$tmp/srv-pass.log")" \
        "Verified-by: verify-fast=skipped verify-server=pass gate-1g=skipped load=skipped"

    cat >"$tmp/srv-hostile.log" <<'EOF'
   ok    unit
   ok    clippy
   ok    postgres
   ok    yugabyte
   ok    hostile-postgres
   ok    hostile-yugabyte
   ok    load-postgres
   ok    load-yugabyte
verify-server: all green
EOF
    assert_eq_str "--server-log hostile + fast=pass" \
        "$(VEIL_FAST_LOG_PREFIX="$tmp/veil" bash "$script_abs" --fast-tag ok1 --server-log "$tmp/srv-hostile.log" gate-1g=pass)" \
        "Verified-by: verify-fast=pass verify-server=hostile gate-1g=pass load=skipped"

    cat >"$tmp/srv-fail.log" <<'EOF'
   ok    unit
   FAIL  yugabyte (exit 101)
verify-server: FAILED (logs in /tmp/x)
EOF
    assert_eq_str "--server-log fail" \
        "$(bash "$script_abs" --server-log "$tmp/srv-fail.log")" \
        "Verified-by: verify-fast=skipped verify-server=fail gate-1g=skipped load=skipped"

    # 4. --msg-file writes before Co-Authored-By and replaces older Verified-by
    cat >"$tmp/COMMIT_EDITMSG" <<'EOF'
Merge t3/demo: summary

Verified-by: none
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
    bash "$script_abs" -f "$tmp/COMMIT_EDITMSG" verify-fast=pass
    local want_msg
    want_msg=$'Merge t3/demo: summary\n\nVerified-by: verify-fast=pass verify-server=skipped gate-1g=skipped load=skipped\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
    assert_eq_str "--msg-file replace before Co-Authored-By" \
        "$(cat "$tmp/COMMIT_EDITMSG")" \
        "$want_msg"

    echo "verify-stamp self-test: $pass passed, $fail failed"
    [[ "$fail" -eq 0 ]]
}

FAST="skipped"
SERVER="skipped"
GATE_1G="skipped"
LOAD="skipped"
EXTRAS=()
FORCE_NONE=0
REASON=""
MSG_FILE=""
AMEND=0

validate_status() {
    local key="$1" val="$2"
    case "$key" in
        verify-server)
            case "$val" in pass|fail|skipped|hostile) return 0 ;; esac
            ;;
        *)
            case "$val" in pass|fail|skipped) return 0 ;; esac
            ;;
    esac
    echo "verify-stamp: invalid status '$val' for '$key'" >&2
    return 1
}

read_file_or_stdin() {
    if [[ "$1" == "-" ]]; then
        cat
    elif [[ -f "$1" ]]; then
        cat "$1"
    else
        echo "verify-stamp: file not found: $1" >&2
        return 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --self-test)
            run_self_test
            exit $?
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --fast-tag)
            [[ $# -ge 2 ]] || { echo "verify-stamp: --fast-tag requires <tag>" >&2; exit 2; }
            FAST=$(parse_fast_tag "$2")
            shift 2
            ;;
        --fast-log)
            [[ $# -ge 2 ]] || { echo "verify-stamp: --fast-log requires <file|->" >&2; exit 2; }
            CONTENT=$(read_file_or_stdin "$2") || exit 2
            FAST=$(parse_fast_log "$CONTENT")
            shift 2
            ;;
        --server-log)
            [[ $# -ge 2 ]] || { echo "verify-stamp: --server-log requires <file|->" >&2; exit 2; }
            CONTENT=$(read_file_or_stdin "$2") || exit 2
            SERVER=$(parse_server_log "$CONTENT")
            shift 2
            ;;
        --gate-1g-log|--gate-1g-json)
            [[ $# -ge 2 ]] || { echo "verify-stamp: $1 requires <file>" >&2; exit 2; }
            GATE_1G=$(parse_bench_1g "$2")
            shift 2
            ;;
        --load-log|--load-json)
            [[ $# -ge 2 ]] || { echo "verify-stamp: $1 requires <file>" >&2; exit 2; }
            LOAD=$(parse_bench_load "$2")
            shift 2
            ;;
        --none)
            FORCE_NONE=1
            shift
            if [[ $# -gt 0 && "$1" != -* && "$1" != *=* ]]; then
                REASON="$1"
                shift
            fi
            ;;
        --reason)
            [[ $# -ge 2 ]] || { echo "verify-stamp: --reason requires <text>" >&2; exit 2; }
            REASON="$2"
            shift 2
            ;;
        -f|--msg-file)
            [[ $# -ge 2 ]] || { echo "verify-stamp: $1 requires <file>" >&2; exit 2; }
            MSG_FILE="$2"
            shift 2
            ;;
        --amend)
            AMEND=1
            shift
            ;;
        *=*)
            KEY="${1%%=*}"
            VAL="${1#*=}"
            if [[ ! "$KEY" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
                echo "verify-stamp: invalid suite name '$KEY'" >&2
                exit 2
            fi
            validate_status "$KEY" "$VAL" || exit 2
            case "$KEY" in
                verify-fast) FAST="$VAL" ;;
                verify-server) SERVER="$VAL" ;;
                gate-1g) GATE_1G="$VAL" ;;
                load) LOAD="$VAL" ;;
                *) EXTRAS+=("${KEY}=${VAL}") ;;
            esac
            shift
            ;;
        *)
            echo "verify-stamp: unrecognized argument '$1'" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -n "$MSG_FILE" && "$AMEND" -eq 1 ]]; then
    echo "verify-stamp: --msg-file and --amend are mutually exclusive" >&2
    exit 2
fi

# Clean single-line reason if provided
if [[ -n "$REASON" ]]; then
    REASON=$(printf '%s' "$REASON" | tr '\r\n)' '   ' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
fi

ANY_RAN=0
for v in "$FAST" "$SERVER" "$GATE_1G" "$LOAD"; do
    [[ "$v" != "skipped" ]] && ANY_RAN=1
done
for kv in "${EXTRAS[@]}"; do
    [[ "${kv#*=}" != "skipped" ]] && ANY_RAN=1
done

if [[ "$FORCE_NONE" -eq 1 || "$ANY_RAN" -eq 0 ]]; then
    if [[ -n "$REASON" ]]; then
        TRAILER_VAL="none (reason: $REASON)"
    else
        TRAILER_VAL="none"
    fi
else
    TRAILER_VAL="verify-fast=${FAST} verify-server=${SERVER} gate-1g=${GATE_1G} load=${LOAD}"
    for kv in "${EXTRAS[@]}"; do
        TRAILER_VAL+=" ${kv}"
    done
fi

if [[ -n "$MSG_FILE" ]]; then
    [[ -f "$MSG_FILE" ]] || { echo "verify-stamp: message file not found: $MSG_FILE" >&2; exit 2; }
    UPDATED=$(write_trailer_to_text "$TRAILER_VAL" <"$MSG_FILE")
    printf '%s\n' "$UPDATED" >"$MSG_FILE"
elif [[ "$AMEND" -eq 1 ]]; then
    CUR_MSG=$(git log -1 --format=%B HEAD) || exit 1
    UPDATED=$(printf '%s\n' "$CUR_MSG" | write_trailer_to_text "$TRAILER_VAL")
    printf '%s\n' "$UPDATED" | git commit --only --amend -F - >/dev/null
    printf 'Verified-by: %s\n' "$TRAILER_VAL"
else
    printf 'Verified-by: %s\n' "$TRAILER_VAL"
fi
