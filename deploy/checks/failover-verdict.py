#!/usr/bin/env python3
"""The failover gate's verdict (deploy/gates.sh `gate_failover`), from a
results directory: failover-run.txt and failover-after.txt (what the gate
did), failover-check.txt (deploy/checks/failover.sql) and failover.json
(the benchmark's own numbers). Prints a Markdown table (the gates keep
it as failover-verdict.md); exits 1 when a
check fails, 0 when every one passes.

    python3 deploy/checks/failover-verdict.py RESULTS_DIR

"Exactly once" rests on the database: the landing queue (every ticket the
servers accepted), the landing records (each landed change and the
snapshot it became) and `main`'s first-parent line in the derived graph.
The benchmark counts its landings but does not log which change each was,
so a landing whose answer was lost with the stopped server (the agent saw
an error; the ticket landed anyway) is told apart from none: the tool's
count may be lower than the database's, never higher.
"""
import json
import pathlib
import sys

PAUSE_TARGET_MS = 2000  # phase-4-agent-scale.md §7: at most 2 s of stall


def kv(path):
    out = {}
    if path.exists():
        for line in path.read_text().splitlines():
            for sep in ("|", "="):
                if sep in line:
                    k, v = line.split(sep, 1)
                    out[k.strip()] = v.strip()
                    break
    return out


def num(d, k):
    try:
        return int(float(d.get(k, "")))
    except ValueError:
        return None


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    d = pathlib.Path(sys.argv[1])
    run, after, chk = kv(d / "failover-run.txt"), kv(d / "failover-after.txt"), kv(d / "failover-check.txt")
    tool = {}
    try:
        runs = json.loads((d / "failover.json").read_text())["runs"]
        tool = runs[0] if runs else {}
    except (OSError, ValueError, KeyError):
        pass
    rows, ok = [], True

    def row(name, value, passed, why):
        nonlocal ok
        mark = "n/a" if passed is None else ("pass" if passed else "**FAIL**")
        if passed is False:
            ok = False
        rows.append(f"| {name} | {value} | {mark} | {why} |")

    if not chk:
        print("failover: no failover-check.txt in", d, file=sys.stderr)
        return 1
    holder = run.get("holder_server", "?")
    before, after_l = run.get("lease_before", ""), after.get("lease_after", "")
    hb = before.split(" epoch ")[0] if before else ""
    ha = after_l.split(" epoch ")[0] if after_l else ""
    row("lease holder before / after", f"`{before or '–'}` / `{after_l or '–'}`", bool(hb) and bool(ha) and hb != ha,
        f"server {holder} held it and was stopped ({run.get('how', '?')}); another server must hold it after")
    row("tip of `main` derived", after.get("tip_derived", "?"), after.get("tip_derived") == "t",
        "the history checks below walk the derived graph")
    for k, why in [
        ("unfinished", "tickets still queued or merging after settling: lost in the queue"),
        ("landed_without_record", "landed tickets whose change has no landing record"),
        ("recorded_not_on_main", "recorded landings that are not on `main`'s first-parent line: lost"),
        ("change_twice_on_main", "extra copies of a change id on `main`'s line: landed twice"),
        ("landed_twice", "one landed snapshot recorded as made from two changes"),
        ("main_without_ticket", "snapshots on `main`, after its first landing, that no ticket landed"),
        ("main_not_derived", "snapshots on `main`'s line, above its root, missing from the graph"),
    ]:
        v = num(chk, k)
        row(k, "–" if v is None else v, v == 0, why)
    landed = num(chk, "tickets_landed")
    changes = num(chk, "landed_changes")
    main_n, setup = num(chk, "main_snapshots"), num(chk, "setup_snapshots")
    row("tickets landed / their changes", f"{landed} / {changes}", None, "accepted tickets that landed, and the changes they carried")
    if None not in (main_n, setup, changes):
        row("snapshots on `main` = set-up + changes landed", f"{main_n} = {setup} + {main_n - setup}", main_n - setup == changes,
            "every landed change once on `main`, nothing else")
    row("tickets conflict / rejected", f"{chk.get('tickets_conflict', '–')} / {chk.get('tickets_rejected', '–')}", None,
        "answered, not landed (an agent then submits again, as a new ticket)")
    t_ops, t_err = tool.get("ops"), tool.get("errors")
    if t_ops is not None and landed is not None:
        row("the tool's landings (measured window) ≤ the database's", f"{int(t_ops)} ≤ {landed}", int(t_ops) <= landed,
            f"the difference is the warm-up's landings and answers lost with the stopped server; the tool saw {t_err} errors")
    first = num(chk, "first_landing_after_stop_ms")
    gap = num(chk, "longest_gap_after_stop_ms")
    normal = num(chk, "longest_gap_before_stop_ms")
    after_n = num(chk, "landings_after_stop")
    # Failing over means landing again: with no landing after the stop
    # there is no pause to measure, and the lease moving proves nothing.
    row("landings before / after the stop", f"{chk.get('landings_before_stop', '–')} / {chk.get('landings_after_stop', '–')}",
        after_n is not None and after_n > 0, "another server must land after the stop")
    row("first landing after the stop", "–" if first is None else f"{first} ms", None, "from the stop command on the database's clock")
    row("longest pause in landings after the stop", "–" if gap is None else f"{gap} ms", gap is not None and gap <= PAUSE_TARGET_MS,
        f"target at most {PAUSE_TARGET_MS} ms (phase 4 §7); the longest in the 30 s before: {normal} ms")
    print("| Check | Value | | What it shows |")
    print("|---|---|---|---|")
    print("\n".join(rows))
    print()
    print("failover:", "every check passed" if ok else "A CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
