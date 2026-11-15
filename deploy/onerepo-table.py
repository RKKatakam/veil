#!/usr/bin/env python3
"""The onerepo gate's table (deploy/gates.sh `onerepo`): one busy
repository, its agents each pushing to a branch of their own, against a
target of pushes a second (7,200: GitHub's internal test, 7,200 pushes a
second and 5,000 agents on one repository).

Reads, in RESULTS_DIR, onerepo-<agents>.json (the tool's results: pushes a
second, latency, errors, the database's statements and commits per push,
the measured window's edges) and the docker stats samples bench.sh takes
every 5 s on the servers (hub<N>-docker-stats.log, container veil-server)
and on the database machines (db<N>-docker-stats.log, containers pg or
yb); the samples inside a run's window give the servers' and the
database's cores, and with the pushes a second their CPU per push. Prints
Markdown: what was measured, then what the target would need at those
costs (cores at 70 % busy, statements and commits a second).

    python3 deploy/onerepo-table.py [--target N] [--servers N] [--server-vcpus N] RESULTS_DIR
"""
import argparse
import datetime
import json
import math
import pathlib
import re
import sys

BUSY = 0.7   # the share of a machine's cores a sizing plans to use


def samples(path, containers):
    """[(unix seconds, cores)] of the named containers, summed per sample."""
    out = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        ts, _, rest = line.partition(" ")
        try:
            t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
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


def window_cores(per_machine, start, end):
    """The machines' cores summed, each its mean over the samples in [start, end]; None without samples."""
    total, any_seen = 0.0, False
    for s in per_machine:
        inside = [c for t, c in s if start <= t <= end]
        if inside:
            total += sum(inside) / len(inside)
            any_seen = True
    return total if any_seen else None


def f(v, digits=1):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "–"
    return f"{v:,.{digits}f}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", type=float, default=7200.0)
    ap.add_argument("--servers", type=int, default=0, help="servers behind the one address (for the table's note)")
    ap.add_argument("--server-vcpus", type=int, default=0, help="vCPUs of one server's machine (0: unknown)")
    ap.add_argument("results")
    a = ap.parse_args()
    d = pathlib.Path(a.results)
    hubs = [samples(p, {"veil-server"}) for p in sorted(d.glob("hub*-docker-stats.log"))]
    dbs = [samples(p, {"pg", "yb"}) for p in sorted(d.glob("db*-docker-stats.log"))]
    rows = []
    for p in d.glob("onerepo-*.json"):
        m = re.fullmatch(r"onerepo-(\d+)\.json", p.name)
        if not m:
            continue
        try:
            runs = json.loads(p.read_text())["runs"]
        except (OSError, ValueError, KeyError):
            continue
        for r in runs:
            rows.append(r)
    rows.sort(key=lambda r: r.get("clients") or 0)
    target = a.target
    print(f"### One busy repository: pushes to branches of one project, against {target:,.0f} pushes a second\n")
    print(f"The target is the figure of GitHub's internal test ({target:,.0f} pushes a second, 5,000 agents on one repository).")
    print("Each agent pushes to a branch of its own, as fast as it is answered (one push: the tips, the upload, the push).\n")
    print("| Agents | Pushes/s | Of the target | p50 / p99 ms | Errors | Told to come back | Statements/push | Writes/push | Commits/push | Server cores | Server CPU ms/push | DB cores | DB CPU ms/push | Driver cores |")
    print("|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    needs = []
    for r in rows:
        ops = r.get("ops_per_s") or 0.0
        start, end = (r.get("window_start_unix_ms") or 0) / 1000.0, (r.get("window_end_unix_ms") or 0) / 1000.0
        sc = window_cores(hubs, start, end) if end > start else None
        dc = window_cores(dbs, start, end) if end > start else None
        s_ms = sc * 1000.0 / ops if sc is not None and ops > 0 else None
        if s_ms is None and r.get("server_cpu_ms_per_op") is not None:
            # No samples (a run of the tool's own server, here): its own measure of that server.
            s_ms = r["server_cpu_ms_per_op"]
            sc = s_ms * ops / 1000.0
        d_ms = dc * 1000.0 / ops if dc is not None and ops > 0 else None
        commits = r.get("db_commits_per_op")
        if commits is None:
            commits = r.get("db_commit_statements_per_op")
        print(
            f"| {r.get('clients', 0):,} | {f(ops)} | {f(100.0 * ops / target, 1)} % | {f(r.get('p50_ms'), 0)} / {f(r.get('p99_ms'), 0)} "
            f"| {r.get('errors', 0):,} | {r.get('busy', 0):,} | {f(r.get('db_per_op'))} | {f(r.get('db_writes_per_op'))} | {f(commits, 2)} "
            f"| {f(sc)} | {f(s_ms, 2)} | {f(dc)} | {f(d_ms, 2)} | {f(r.get('load_tool_cores'))} |"
        )
        needs.append((r.get("clients", 0), s_ms, d_ms, r.get("db_per_op"), commits))
    if not rows:
        print("| – | no results | | | | | | | | | | | | |")
    print()
    print("Statements and writes per push count every statement the database ran in the window (pg_stat_statements; on YugabyteDB only")
    print("the node the driver's URL names). Commits per push: transactions that wrote and committed (PostgreSQL), else `COMMIT`s.")
    print("Server and DB cores: each machine's mean over its docker stats samples inside the run's window, summed over the machines")
    print("(without samples, the server's from the tool, when it started the server itself).")
    print("Driver cores: the load tool's own; near the driver's vCPUs, the driver was the limit, not the server.\n")
    print(f"**At these costs, {target:,.0f} pushes a second would need:**\n")
    for agents, s_ms, d_ms, stmts, commits in needs:
        parts = []
        if s_ms is not None:
            cores = target * s_ms / 1000.0
            part = f"{cores:,.0f} server cores"
            if a.server_vcpus > 0:
                part += f" ({math.ceil(cores / (a.server_vcpus * BUSY))} servers of {a.server_vcpus} vCPUs at {BUSY:.0%} busy)"
            parts.append(part)
        if d_ms is not None:
            parts.append(f"{target * d_ms / 1000.0:,.0f} database cores (at {BUSY:.0%} busy: {math.ceil(target * d_ms / 1000.0 / BUSY)})")
        if stmts is not None:
            parts.append(f"{target * stmts:,.0f} statements a second")
        if commits is not None:
            parts.append(f"{target * commits:,.0f} commits a second")
        print(f"- measured at {agents:,} agents: " + ("; ".join(parts) if parts else "no costs measured") + ".")
    if a.servers:
        print(f"\n({a.servers} server(s) ran behind the one address.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
