#!/usr/bin/env bash
# Print the slowest tests and per-module totals from one or more nextest JUnit XML files.
#
# Usage:
#   scripts/test-timings.sh [-n TOP] [--no-modules] <junit.xml> [junit2.xml ...]
#
# Producing a JUnit file with cargo-nextest:
#   cargo metadata --format-version=1 > .scratch/metadata.json
#   cargo nextest run --cargo-metadata .scratch/metadata.json \
#     --config 'profile.default.junit.path = "junit.xml"' --workspace --all-targets
#   scripts/test-timings.sh target/nextest/default/junit.xml
set -euo pipefail

TOP=50
SHOW_MODULES=1
FILES=()

usage() {
  sed -n '2,11s/^# \{0,1\}//p' "$0"
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -n|--top)
      [ $# -ge 2 ] || { echo "error: $1 requires a number" >&2; exit 2; }
      TOP="$2"
      shift 2
      ;;
    --no-modules)
      SHOW_MODULES=0
      shift
      ;;
    --)
      shift
      FILES+=("$@")
      break
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      FILES+=("$1")
      shift
      ;;
  esac
done

if [ "${#FILES[@]}" -eq 0 ]; then
  usage >&2
  exit 2
fi

for f in "${FILES[@]}"; do
  [ -r "$f" ] || { echo "error: cannot read JUnit file: $f" >&2; exit 1; }
done

exec python3 - "$TOP" "$SHOW_MODULES" "${FILES[@]}" <<'PY'
import math
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

top_n = int(sys.argv[1])
show_modules = sys.argv[2] == "1"
paths = sys.argv[3:]

cases = []
suite_wall = 0.0
failed = 0
skipped = 0

for path in paths:
    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag == "testsuites" and root.attrib.get("time"):
        try:
            suite_wall += float(root.attrib["time"])
        except ValueError:
            pass
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    for suite in suites:
        suite_name = suite.attrib.get("name", "")
        for tc in suite.findall("testcase"):
            name = tc.attrib.get("name", "<unnamed>")
            cls = tc.attrib.get("classname") or suite_name or "<unknown>"
            try:
                dur = float(tc.attrib.get("time", "0") or 0.0)
            except ValueError:
                dur = 0.0
            if tc.find("skipped") is not None:
                skipped += 1
                continue
            is_fail = tc.find("failure") is not None or tc.find("error") is not None
            if is_fail:
                failed += 1
            mod = name.split("::", 1)[0] if "::" in name else "<root>"
            cases.append((dur, cls, mod, name, is_fail))

cases.sort(key=lambda x: x[0], reverse=True)
n = len(cases)
total_s = sum(c[0] for c in cases)

def pct(sorted_desc, p):
    if not sorted_desc:
        return 0.0
    asc = sorted_desc[::-1]
    idx = min(len(asc) - 1, max(0, math.ceil((p / 100.0) * len(asc)) - 1))
    return asc[idx][0]

wall_str = f", wall={suite_wall:.2f}s" if suite_wall > 0 else ""
print(
    f"Tests run: {n} (failed={failed}, skipped={skipped}), "
    f"sum={total_s:.2f}s{wall_str}, "
    f"p50={pct(cases, 50):.3f}s, p90={pct(cases, 90):.3f}s, "
    f"p99={pct(cases, 99):.3f}s, max={(cases[0][0] if cases else 0.0):.3f}s"
)

limit = min(top_n, n)
print(f"\n=== Top {limit} Slowest Tests ===")
print(f"{'Rank':>4}  {'Time (s)':>9}  {'Status':<6}  {'Suite / Test'}")
for i, (dur, cls, _mod, name, is_fail) in enumerate(cases[:limit], 1):
    st = "FAIL" if is_fail else "ok"
    print(f"{i:>4}  {dur:>9.3f}  {st:<6}  {cls} {name}")

if show_modules and cases:
    by_mod = defaultdict(lambda: [0, 0.0, 0.0])
    for dur, cls, mod, _name, _fail in cases:
        key = f"{cls}::{mod}" if mod != "<root>" else cls
        rec = by_mod[key]
        rec[0] += 1
        rec[1] += dur
        if dur > rec[2]:
            rec[2] = dur
    ranked = sorted(by_mod.items(), key=lambda kv: kv[1][1], reverse=True)
    mod_limit = min(35, len(ranked))
    print(f"\n=== Top {mod_limit} Modules by Cumulative Test Time (of {len(ranked)}) ===")
    print(f"{'Rank':>4}  {'Total (s)':>10}  {'Share':>6}  {'Count':>5}  {'Max (s)':>8}  {'Module'}")
    for i, (mkey, (cnt, s_dur, m_max)) in enumerate(ranked[:mod_limit], 1):
        share = (100.0 * s_dur / total_s) if total_s > 0 else 0.0
        print(f"{i:>4}  {s_dur:>10.2f}  {share:>5.1f}%  {cnt:>5}  {m_max:>8.3f}  {mkey}")
PY
