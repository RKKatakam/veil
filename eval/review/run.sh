#!/usr/bin/env bash
# Recreate the repository at review time for one eval case, emit the veil-review
# prompt for base..head, optionally score a findings file, and clean up the
# temporary .scratch/ worktree on exit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CASES_FILE="${CASES_FILE:-$SCRIPT_DIR/cases.jsonl}"
SKILL_FILE="${SKILL_FILE:-$REPO_ROOT/.claude/skills/veil-review/SKILL.md}"

usage() {
    cat <<'EOF'
Usage:
  eval/review/run.sh [--case] <case-id> [options]
  eval/review/run.sh --list [--split tuning|test|all]

Options:
  --case <id>          Case id from eval/review/cases.jsonl
  --findings <path>    Score an existing findings file (JSON, JSONL, or Markdown)
  --prompt-out <path>  Write the generated review prompt to <path> instead of stdout
  --cmd <shell-cmd>    Optional reviewer command to run inside the recreated worktree
                       (receives prompt via stdin; stdout written to --findings)
  --manual-csv <path>  Forward ambiguous partial matches to CSV when scoring
  --tolerance <lines>  Line tolerance forwarded to score.py (default: 50)
  --quiet-prompt       Suppress printing the full prompt when scoring --findings
  --list               List cases in cases.jsonl and exit
  --split <name>       Filter --list by split (tuning | test | all; default: all)
  -h, --help           Show this help message
EOF
}

CASE_ID=""
FINDINGS_FILE=""
PROMPT_OUT=""
REVIEWER_CMD=""
MANUAL_CSV=""
TOLERANCE="50"
QUIET_PROMPT=0
LIST_MODE=0
LIST_SPLIT="all"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --case)
            CASE_ID="${2:?missing value for --case}"
            shift 2
            ;;
        --findings)
            FINDINGS_FILE="${2:?missing value for --findings}"
            shift 2
            ;;
        --prompt-out)
            PROMPT_OUT="${2:?missing value for --prompt-out}"
            shift 2
            ;;
        --cmd)
            REVIEWER_CMD="${2:?missing value for --cmd}"
            shift 2
            ;;
        --manual-csv)
            MANUAL_CSV="${2:?missing value for --manual-csv}"
            shift 2
            ;;
        --tolerance)
            TOLERANCE="${2:?missing value for --tolerance}"
            shift 2
            ;;
        --quiet-prompt)
            QUIET_PROMPT=1
            shift
            ;;
        --list)
            LIST_MODE=1
            shift
            ;;
        --split)
            LIST_SPLIT="${2:?missing value for --split}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "error: unknown flag '$1'" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [[ -z "$CASE_ID" ]]; then
                CASE_ID="$1"
                shift
            else
                echo "error: unexpected positional argument '$1'" >&2
                usage >&2
                exit 2
            fi
            ;;
    esac
done

if [[ ! -f "$CASES_FILE" ]]; then
    echo "error: cases file not found at $CASES_FILE" >&2
    exit 2
fi

if [[ "$LIST_MODE" -eq 1 ]]; then
    python3 - "$CASES_FILE" "$LIST_SPLIT" <<'PY'
import json, pathlib, sys
cases_path = pathlib.Path(sys.argv[1])
split_filter = sys.argv[2]
print(f"{'ID':16s} {'SPLIT':7s} {'KIND':13s} {'AREA':8s} {'SIZE':7s} {'LINES':>6s}  {'RANGE'}")
for ln in cases_path.read_text(encoding="utf-8").splitlines():
    if not ln.strip():
        continue
    c = json.loads(ln)
    if split_filter != "all" and c["split"] != split_filter:
        continue
    rng = f"{c['base'][:8]}..{c['head'][:8]}"
    print(f"{c['id']:16s} {c['split']:7s} {c['kind']:13s} {c['area']:8s} {c['size']:7s} {c['diff_lines']:6d}  {rng}")
PY
    exit 0
fi

if [[ -z "$CASE_ID" ]]; then
    echo "error: missing <case-id>" >&2
    usage >&2
    exit 2
fi

if [[ ! -f "$SKILL_FILE" ]]; then
    echo "error: veil-review skill file not found at $SKILL_FILE" >&2
    exit 2
fi

# Extract ONLY base and head (never expose answer_key, kind, or target lines to the reviewer).
read -r BASE_SHA HEAD_SHA < <(
    python3 - "$CASES_FILE" "$CASE_ID" <<'PY'
import json, pathlib, sys
cases_path = pathlib.Path(sys.argv[1])
want = sys.argv[2]
for ln in cases_path.read_text(encoding="utf-8").splitlines():
    if not ln.strip():
        continue
    c = json.loads(ln)
    if c["id"] == want:
        print(c["base"], c["head"])
        sys.exit(0)
sys.exit(1)
PY
) || {
    echo "error: case '$CASE_ID' not found in $CASES_FILE" >&2
    exit 2
}

mkdir -p "$REPO_ROOT/.scratch"
SAFE_ID="${CASE_ID//[^A-Za-z0-9_.-]/_}"
WT_DIR="$REPO_ROOT/.scratch/review-eval-${SAFE_ID}-$$"

cleanup() {
    if [[ -d "$WT_DIR" ]]; then
        git -C "$REPO_ROOT" worktree remove --force "$WT_DIR" >/dev/null 2>&1 || rm -rf "$WT_DIR"
        git -C "$REPO_ROOT" worktree prune >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

git -C "$REPO_ROOT" worktree add --quiet --detach "$WT_DIR" "$HEAD_SHA"

COMMIT_LOG="$(git -C "$WT_DIR" log --oneline "${BASE_SHA}..${HEAD_SHA}")"
DIFF_STAT="$(git -C "$WT_DIR" diff --stat "${BASE_SHA}..${HEAD_SHA}")"

build_prompt() {
    cat <<EOF
# Veil Code Review Evaluation Task

Review the commit range \`${BASE_SHA:0:8}..${HEAD_SHA:0:8}\` in the recreated checkout at:
  Worktree: \`${WT_DIR}\`
  Base SHA: \`${BASE_SHA}\`
  Head SHA: \`${HEAD_SHA}\`

Inspect the diff and surrounding code at \`HEAD\` inside \`${WT_DIR}\` (for example with \`git diff ${BASE_SHA}..${HEAD_SHA}\`). Do NOT inspect commits newer than \`${HEAD_SHA}\`, branch refs, or \`docs/BUGS.md\` entries outside this checkout.

## Commits in range (\`${BASE_SHA:0:8}..${HEAD_SHA:0:8}\`)
\`\`\`text
${COMMIT_LOG}
\`\`\`

## Diffstat
\`\`\`text
${DIFF_STAT}
\`\`\`

## Output format
Report blocking findings using either:
1. The standard \`veil-review\` report format (\`1. [critical|important|medium] <class> — crates/.../file.rs:123 — <one sentence>\`), or \`"No issues found."\` if clean; OR
2. JSON Lines (one JSON object per finding):
   \`{"severity": "important", "file": "crates/.../file.rs", "line": 123, "description": "...", "stage": "final"}\`
   (To measure recall by review stage, emit findings tagged with \`"stage": "raw"\`, \`"stage": "verified"\`, and \`"stage": "final"\`.)

---

EOF
    cat "$SKILL_FILE"
}

if [[ -n "$PROMPT_OUT" ]]; then
    mkdir -p "$(dirname "$PROMPT_OUT")"
    build_prompt > "$PROMPT_OUT"
elif [[ "$QUIET_PROMPT" -eq 0 && -z "$REVIEWER_CMD" ]]; then
    build_prompt
fi

if [[ -n "$REVIEWER_CMD" ]]; then
    if [[ -z "$FINDINGS_FILE" ]]; then
        echo "error: --cmd requires --findings <output-path>" >&2
        exit 2
    fi
    mkdir -p "$(dirname "$FINDINGS_FILE")"
    build_prompt | (cd "$WT_DIR" && bash -c "$REVIEWER_CMD") > "$FINDINGS_FILE"
fi

if [[ -n "$FINDINGS_FILE" ]]; then
    SCORE_ARGS=(--cases "$CASES_FILE" --case "$CASE_ID" --findings "$FINDINGS_FILE" --line-tolerance "$TOLERANCE")
    if [[ -n "$MANUAL_CSV" ]]; then
        SCORE_ARGS+=(--manual-csv "$MANUAL_CSV")
    fi
    python3 "$SCRIPT_DIR/score.py" "${SCORE_ARGS[@]}"
fi
