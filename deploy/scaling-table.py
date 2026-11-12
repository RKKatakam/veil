#!/usr/bin/env python3
"""The scaling gate's table (deploy/gates.sh `gate_scaling`): for each
curve (pull, push to a branch of one's own, landings across projects) the
throughput with 1, 2 and 3 servers, summed over the drivers, and its ratio
to one server's. Reads scaling-<N>servers-<curve>@<driver>.json in
RESULTS_DIR; prints Markdown.

    python3 deploy/scaling-table.py RESULTS_DIR
"""
import json
import pathlib
import re
import sys
from collections import defaultdict

CURVES = [("pull", "pulls/s"), ("branches", "pushes/s"), ("landing", "landings/s")]


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    d = pathlib.Path(sys.argv[1])
    agg = defaultdict(lambda: {"ops_per_s": 0.0, "p50": [], "p99": [], "errors": 0, "drivers": 0, "clients": 0})
    for f in sorted(d.glob("scaling-*servers-*.json")):
        m = re.match(r"scaling-(\d+)servers-(\w+)(?:@(\d+))?\.json$", f.name)
        if not m:
            continue
        n, curve = int(m.group(1)), m.group(2)
        try:
            runs = json.loads(f.read_text())["runs"]
        except (OSError, ValueError, KeyError):
            continue
        a = agg[(n, curve)]
        a["drivers"] += 1
        for r in runs:
            a["ops_per_s"] += r.get("ops_per_s") or 0.0
            a["clients"] += r.get("clients") or 0
            a["errors"] += r.get("errors") or 0
            for k in ("p50", "p99"):
                v = r.get(f"{k}_ms")
                if isinstance(v, (int, float)):
                    a[k].append(v)
    servers = sorted({n for n, _ in agg})
    if not servers:
        print("scaling: no scaling-*.json in", d, file=sys.stderr)
        return 1
    print("| Curve | " + " | ".join(f"{n} server{'s' if n > 1 else ''}" for n in servers) + " |")
    print("|---|" + "---:|" * len(servers))
    for curve, unit in CURVES:
        base = agg.get((servers[0], curve), {}).get("ops_per_s")
        cells = []
        for n in servers:
            a = agg.get((n, curve))
            if not a or not a["drivers"]:
                cells.append("–")
                continue
            ratio = f" ({a['ops_per_s'] / base:.2f}×)" if base and n != servers[0] else ""
            p50 = max(a["p50"]) if a["p50"] else float("nan")
            p99 = max(a["p99"]) if a["p99"] else float("nan")
            cells.append(f"{a['ops_per_s']:,.0f} {unit}{ratio}; p50 {p50:.1f} ms, p99 {p99:.1f} ms; {a['clients']} agents, {a['drivers']} driver(s), {a['errors']} errors")
        print(f"| {curve} | " + " | ".join(cells) + " |")
    print()
    print("Throughput is summed over the drivers; p50 and p99 are the worst driver's. A ratio is to the first column.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
