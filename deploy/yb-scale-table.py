#!/usr/bin/env python3
"""Tables and 3-vs-6 pass verdicts for YugabyteDB horizontal scaling gates
(`yb-scale` and `yb-onerepo` in deploy/gates.sh).

Single-run summary (called by deploy/gates.sh `gate_report` via
deploy/gcp/bench.sh and deploy/do/bench.sh):

    python3 deploy/yb-scale-table.py [--gate yb-scale|yb-onerepo] RESULTS_DIR

3-node vs 6-node comparison and pass/fail verdict (called automatically when
YB_COMPARE_DIR is set during bench.sh, or standalone after both runs):

    python3 deploy/yb-scale-table.py [--gate yb-scale|yb-onerepo] \\
        [--min-ratio 1.6] --compare RESULTS_3NODE RESULTS_6NODE

Pass criteria (docs/design/server/yugabyte-scaling.md §5 + owner decisions):
  - `yb-scale` (multi-project, 60-100 projects):
      branches, landing, pull, api, land must each scale >= 1.6x (3 -> 6 nodes)
      with 0 errors.
  - `yb-onerepo` (single-repo many-branch):
      branches (no merges) must scale >= 1.6x (3 -> 6 nodes) with 0 errors.
      merge (`--merge-every`, serialized merges on `main`) is reported in a
      separate informational table and does not fail the 3 -> 6 ratio check.
"""
import argparse
import datetime
import json
import math
import pathlib
import re
import sys
from collections import defaultdict

MULTI_CURVES = [
    ("branches", "pushes/s"),
    ("landing", "landings/s"),
    ("pull", "pulls/s"),
    ("api", "commits/s"),
    ("land", "landings/s"),
]

ONEREPO_REQUIRED = [
    ("branches", "pushes/s"),
]

ONEREPO_SEPARATE = [
    ("merge", "pushes/s"),
]


def parse_kv(path):
    out = {}
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def samples(path, containers):
    """[(unix seconds, cores)] of named containers, summed per sample."""
    out = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        ts, _, rest = line.partition(" ")
        try:
            t = (
                datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=datetime.timezone.utc)
                .timestamp()
            )
        except ValueError:
            continue
        cores, seen = 0.0, False
        for item in rest.split(";"):
            m = re.match(r"\s*(\S+) cpu=([0-9.]+)%", item)
            if m and m.group(1) in containers:
                cores += float(m.group(2)) / 100.0
                seen = True
        if seen:
            out.append((t, cores))
    return out


def node_cpu_shares(db_logs, start, end):
    """Mean CPU cores per DB node in [start, end], returning (total_cores, [pct, ...]) or (None, [])."""
    if not db_logs:
        return None, []
    per_node = []
    for s in db_logs:
        if end > start:
            vals = [c for t, c in s if start <= t <= end]
        else:
            vals = [c for _, c in s]
        per_node.append(sum(vals) / len(vals) if vals else None)
    if not any(v is not None for v in per_node):
        return None, []
    vals = [v or 0.0 for v in per_node]
    total = sum(vals)
    if total <= 0.0:
        return 0.0, [0.0 for _ in vals]
    return total, [100.0 * v / total for v in vals]


def fmt_num(v, digits=1):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "–"
    return f"{v:,.{digits}f}"


def fmt_shares(shares):
    if not shares:
        return "–"
    return "/".join(f"{s:.0f}%" for s in shares)


def detect_gate(d):
    if any(d.glob("yb-onerepo-*.json")):
        return "yb-onerepo"
    if any(d.glob("yb-scale-*.json")):
        return "yb-scale"
    meta = parse_kv(d / "run.txt")
    if meta.get("gate") in ("yb-scale", "yb-onerepo"):
        return meta["gate"]
    return "yb-scale"


def load_run(d, gate):
    prefix = "yb-onerepo" if gate == "yb-onerepo" else "yb-scale"
    pattern = re.compile(rf"^{re.escape(prefix)}-([a-z0-9_]+)(?:@(\d+))?\.json$")
    db_logs = [samples(p, {"yb", "pg"}) for p in sorted(d.glob("db*-docker-stats.log"))]
    agg = defaultdict(
        lambda: {
            "ops_per_s": 0.0,
            "ops": 0.0,
            "branch_merges": 0.0,
            "merges_per_s": 0.0,
            "p50": [],
            "p99": [],
            "errors": 0,
            "drivers": 0,
            "clients": 0,
            "projects": 0,
            "starts": [],
            "ends": [],
        }
    )
    for f in sorted(d.glob(f"{prefix}-*.json")):
        m = pattern.fullmatch(f.name)
        if not m:
            continue
        curve = m.group(1)
        try:
            runs = json.loads(f.read_text())["runs"]
        except (OSError, ValueError, KeyError):
            continue
        a = agg[curve]
        a["drivers"] += 1
        for r in runs:
            ops_s = float(r.get("ops_per_s") or 0.0)
            ops = float(r.get("ops") or 0.0)
            merges = float(r.get("branch_merges") or 0.0)
            a["ops_per_s"] += ops_s
            a["ops"] += ops
            a["branch_merges"] += merges
            ws = (r.get("window_start_unix_ms") or 0) / 1000.0
            we = (r.get("window_end_unix_ms") or 0) / 1000.0
            dur = we - ws if we > ws else (ops / ops_s if ops > 0 and ops_s > 0 else 0.0)
            if dur > 0 and merges > 0:
                a["merges_per_s"] += merges / dur
            if ws > 0:
                a["starts"].append(ws)
            if we > 0:
                a["ends"].append(we)
            a["clients"] += int(r.get("clients") or 0)
            a["projects"] += int(r.get("projects") or 0)
            a["errors"] += int(r.get("errors") or 0)
            for k in ("p50", "p99"):
                v = r.get(f"{k}_ms")
                if isinstance(v, (int, float)):
                    a[k].append(float(v))
    for a in agg.values():
        start = min(a["starts"]) if a["starts"] else 0.0
        end = max(a["ends"]) if a["ends"] else 0.0
        a["db_cores"], a["node_shares"] = node_cpu_shares(db_logs, start, end)
    topo = parse_kv(d / "topology.env")
    meta = parse_kv(d / "run.txt")
    return agg, topo, meta


def label_of(topo, fallback):
    yb = topo.get("YB_NODES")
    layout = topo.get("YB_LAYOUT")
    if yb and yb != "0":
        return f"{yb} YB nodes ({layout or 'hash'})"
    if yb == "0":
        return "PostgreSQL"
    return fallback


def print_single_table(title, curves, agg, show_merges=False):
    print(f"### {title}\n")
    if show_merges:
        print("| Curve | Throughput | Merges/s (total) | p50 / p99 ms | Projects | Agents | Drivers | Errors | DB cores | DB node CPU share |")
        print("|---|---:|---:|---|---:|---:|---:|---:|---:|---|")
    else:
        print("| Curve | Throughput | p50 / p99 ms | Projects | Agents | Drivers | Errors | DB cores | DB node CPU share |")
        print("|---|---:|---|---:|---:|---:|---:|---:|---|")
    any_row = False
    for curve, unit in curves:
        a = agg.get(curve)
        if not a or not a["drivers"]:
            continue
        any_row = True
        p50 = max(a["p50"]) if a["p50"] else float("nan")
        p99 = max(a["p99"]) if a["p99"] else float("nan")
        if show_merges:
            print(
                f"| {curve} | {fmt_num(a['ops_per_s'])} {unit} | {fmt_num(a['merges_per_s'])} ({int(a['branch_merges']):,}) "
                f"| {fmt_num(p50)} / {fmt_num(p99)} | {a['projects']:,} | {a['clients']:,} | {a['drivers']} "
                f"| {a['errors']:,} | {fmt_num(a['db_cores'])} | {fmt_shares(a['node_shares'])} |"
            )
        else:
            print(
                f"| {curve} | {fmt_num(a['ops_per_s'])} {unit} | {fmt_num(p50)} / {fmt_num(p99)} "
                f"| {a['projects']:,} | {a['clients']:,} | {a['drivers']} | {a['errors']:,} "
                f"| {fmt_num(a['db_cores'])} | {fmt_shares(a['node_shares'])} |"
            )
    if not any_row:
        cols = "| – | no results |" + " |" * (8 if show_merges else 7)
        print(cols)
    print()


def print_compare_table(title, curves, agg_a, agg_b, lab_a, lab_b, min_ratio, check_ratio, show_merges=False):
    failures = []
    print(f"### {title}\n")
    if show_merges:
        print(f"| Curve | {lab_a} | {lab_b} | Ratio | Merges/s ({lab_a} -> {lab_b}) | p50/p99 ms ({lab_b}) | Errors ({lab_a} / {lab_b}) | Status |")
        print("|---|---:|---:|---:|---|---|---:|---|")
    else:
        print(f"| Curve | {lab_a} | {lab_b} | Ratio | p50/p99 ms ({lab_a}) | p50/p99 ms ({lab_b}) | Errors ({lab_a} / {lab_b}) | DB node share ({lab_b}) | Status |")
        print("|---|---:|---:|---:|---|---|---:|---|---|")
    for curve, unit in curves:
        a = agg_a.get(curve)
        b = agg_b.get(curve)
        if not a or not a["drivers"] or not b or not b["drivers"]:
            status = "MISSING" if check_ratio else "–"
            if check_ratio:
                failures.append(f"{curve}: missing results in baseline or candidate")
            if show_merges:
                print(f"| {curve} | – | – | – | – | – | – | {status} |")
            else:
                print(f"| {curve} | – | – | – | – | – | – | – | {status} |")
            continue
        ops_a = a["ops_per_s"]
        ops_b = b["ops_per_s"]
        ratio = ops_b / ops_a if ops_a > 0 else float("nan")
        p50_a = max(a["p50"]) if a["p50"] else float("nan")
        p99_a = max(a["p99"]) if a["p99"] else float("nan")
        p50_b = max(b["p50"]) if b["p50"] else float("nan")
        p99_b = max(b["p99"]) if b["p99"] else float("nan")
        errs = a["errors"] + b["errors"]
        if check_ratio:
            ok = (not math.isnan(ratio)) and ratio >= min_ratio and errs == 0
            status = "PASS" if ok else "FAIL"
            if math.isnan(ratio) or ratio < min_ratio:
                failures.append(f"{curve}: ratio {ratio:.2f}x < {min_ratio:.2f}x")
            if errs > 0:
                failures.append(f"{curve}: {a['errors']} baseline / {b['errors']} candidate errors")
        else:
            status = "INFO (serialized on main)" if errs == 0 else f"INFO ({errs} errors)"
        if show_merges:
            print(
                f"| {curve} | {fmt_num(ops_a)} {unit} | {fmt_num(ops_b)} {unit} | {ratio:.2f}× "
                f"| {fmt_num(a['merges_per_s'])} -> {fmt_num(b['merges_per_s'])} "
                f"| {fmt_num(p50_b)} / {fmt_num(p99_b)} | {a['errors']} / {b['errors']} | {status} |"
            )
        else:
            print(
                f"| {curve} | {fmt_num(ops_a)} {unit} | {fmt_num(ops_b)} {unit} | {ratio:.2f}× "
                f"| {fmt_num(p50_a)} / {fmt_num(p99_a)} | {fmt_num(p50_b)} / {fmt_num(p99_b)} "
                f"| {a['errors']} / {b['errors']} | {fmt_shares(b['node_shares'])} | {status} |"
            )
    print()
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gate", choices=["yb-scale", "yb-onerepo"], default=None)
    ap.add_argument("--compare", metavar="BASELINE_DIR", default=None, help="baseline results directory (e.g. 3-node run) to compare against RESULTS_DIR (e.g. 6-node run)")
    ap.add_argument("--min-ratio", type=float, default=1.6, help="minimum 3->6 throughput multiplier required to pass (default: 1.6)")
    ap.add_argument("results", help="results directory (candidate run when --compare is set)")
    args = ap.parse_args()

    cand_dir = pathlib.Path(args.results)
    gate = args.gate or detect_gate(cand_dir)

    if args.compare:
        base_dir = pathlib.Path(args.compare)
        agg_a, topo_a, _ = load_run(base_dir, gate)
        agg_b, topo_b, _ = load_run(cand_dir, gate)
        lab_a = label_of(topo_a, base_dir.name)
        lab_b = label_of(topo_b, cand_dir.name)
        failures = []
        if gate == "yb-scale":
            failures += print_compare_table(
                f"YugabyteDB multi-project scaling ({lab_a} vs {lab_b}, target >= {args.min_ratio:.2f}×)",
                MULTI_CURVES,
                agg_a,
                agg_b,
                lab_a,
                lab_b,
                args.min_ratio,
                check_ratio=True,
            )
        else:
            failures += print_compare_table(
                f"YugabyteDB single-repo many-branch scaling ({lab_a} vs {lab_b}, target >= {args.min_ratio:.2f}×)",
                ONEREPO_REQUIRED,
                agg_a,
                agg_b,
                lab_a,
                lab_b,
                args.min_ratio,
                check_ratio=True,
            )
            print_compare_table(
                "Single-repo merges onto `main` (reported separately; serialized on one branch tip)",
                ONEREPO_SEPARATE,
                agg_a,
                agg_b,
                lab_a,
                lab_b,
                args.min_ratio,
                check_ratio=False,
                show_merges=True,
            )
        if failures:
            print("**Verdict: FAIL**")
            for msg in failures:
                print(f"- {msg}")
            return 1
        print(f"**Verdict: PASS** (all required curves >= {args.min_ratio:.2f}× with 0 errors)")
        return 0

    agg, topo, _ = load_run(cand_dir, gate)
    lab = label_of(topo, cand_dir.name)
    if gate == "yb-scale":
        print_single_table(f"YugabyteDB multi-project scaling ({lab})", MULTI_CURVES, agg)
        print("Compare 3-node and 6-node runs with `python3 deploy/yb-scale-table.py --gate yb-scale --compare DIR_3NODE DIR_6NODE` (or set `YB_COMPARE_DIR=DIR_3NODE` during `bench.sh`).")
    else:
        print_single_table(f"YugabyteDB single-repo many-branch ({lab})", ONEREPO_REQUIRED, agg)
        print_single_table(f"Single-repo merges onto `main` ({lab}, reported separately)", ONEREPO_SEPARATE, agg, show_merges=True)
        print("Compare 3-node and 6-node runs with `python3 deploy/yb-scale-table.py --gate yb-onerepo --compare DIR_3NODE DIR_6NODE` (or set `YB_COMPARE_DIR=DIR_3NODE` during `bench.sh`).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
