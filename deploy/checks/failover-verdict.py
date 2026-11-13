#!/usr/bin/env python3
"""The failover gate's verdict (deploy/gates.sh `gate_failover`), from a
results directory: failover-run.txt and failover-after.txt (what the gate
did), failover-check.txt (deploy/checks/failover.sql) and failover.json
(the benchmark's own numbers). Prints a Markdown table (the gates keep
it as failover-verdict.md); exits 1 when a
check fails, 0 when every one passes.

    python3 deploy/checks/failover-verdict.py RESULTS_DIR

"Exactly once" is judged from both sides. The database: the landing
queue (every ticket the servers accepted), the landing records (each
landed change and the snapshot it became) and `main`'s first-parent line
in the derived graph (failover-line.txt, deploy/checks/failover-line.sql).
The agents: the benchmark's per-change log (failover.landings.jsonl), one
line for each `landed` answer (ticket, change, the landed snapshots) and
one for each submit that failed (the error, and the ticket when the server
gave one). Every change an agent was told landed must be on `main`'s line
exactly once, under the ticket it was told (the `landed` snapshot ids are
the caller's projection, not `main`'s ids, so they are not compared); every
change on the line that a ticket landed and no agent was told about must
be explained by a failed submit: by its ticket when the failure carried
one, otherwise by counting (one submit that got no answer, a broken
connection or a timeout, can have landed at most one change, so such
changes may not outnumber the failed submits without a ticket).
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


# A change id as the API writes it (veil-core `ChangeId`: 32 letters k-z,
# z = 0 ... k = f) and as the derived graph stores it (hex): both to hex.
REVERSE_HEX = str.maketrans("zyxwvutsrqponmlk", "0123456789abcdef")


def change_hex(c):
    c = str(c).strip().lower()
    return c.translate(REVERSE_HEX) if c and all("k" <= ch <= "z" for ch in c) else c


def answers(d):
    """The agents' side: {change: [ticket]}, the
    tickets of failed submits, and the number of failed submits without
    one; None when the log is missing."""
    path = d / "failover.landings.jsonl"
    if not path.exists():
        return None
    told, failed_tickets, failed_blind, bad = {}, set(), 0, 0
    for line in path.read_text().splitlines():
        try:
            v = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if "failed" in v:
            if v.get("ticket"):
                failed_tickets.add(str(v["ticket"]))
            else:
                failed_blind += 1
        elif v.get("change"):
            # `landed` holds snapshot ids as the caller sees them (its
            # projection), not the ids on `main`: the ticket is compared.
            told.setdefault(change_hex(v["change"]), []).append(str(v.get("ticket") or ""))
        else:
            bad += 1
    return told, failed_tickets, failed_blind, bad


def main_line(d):
    """The database's side: `main`'s first-parent line, [(snapshot,
    change, [tickets])], tip first; None when the dump is missing."""
    path = d / "failover-line.txt"
    if not path.exists():
        return None
    out = []
    for line in path.read_text().splitlines():
        f = line.split("|")
        if len(f) == 4 and f[0].isdigit():
            out.append((f[1], change_hex(f[2]), [t for t in f[3].split(",") if t]))
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
    # The agents' answers against `main`'s line, change by change.
    ans, line = answers(d), main_line(d)
    row("the per-change log and `main`'s line", "present" if ans is not None and line else "missing",
        ans is not None and bool(line), "failover.landings.jsonl (the tool) and failover-line.txt (the database)")
    if ans is not None and line:
        told, failed_tickets, failed_blind, bad = ans
        on_main = {}
        for snap, change, tickets in line:
            on_main.setdefault(change, []).append((snap, tickets))
        n_told = sum(len(v) for v in told.values())
        row("answers `landed` / failed submits (with a ticket, without)",
            f"{n_told} / {len(failed_tickets) + failed_blind} ({len(failed_tickets)}, {failed_blind})", None,
            "from the start of the run, warm-up included")
        row("unreadable lines in the log", bad, bad == 0, "every line is an answer or a failure")
        twice_told = sum(len(v) - 1 for v in told.values())
        row("changes answered `landed` twice", twice_told, twice_told == 0, "one answer per submit, one submit per change")
        missing = [c for c in told if c not in on_main]
        row("told landed, not on `main`", len(missing), not missing,
            "a change an agent was told had landed and is not on `main`'s first-parent line: lost" +
            (f" (e.g. `{missing[0]}`)" if missing else ""))
        doubled = [c for c in told if len(on_main.get(c, [])) > 1]
        row("told landed, on `main` more than once", len(doubled), not doubled,
            "landed twice" + (f" (e.g. `{doubled[0]}`)" if doubled else ""))
        elsewhere = [c for c, v in told.items() if len(on_main.get(c, [])) == 1 and not all(t and t in on_main[c][0][1] for t in v)]
        row("told landed under another ticket", len(elsewhere), not elsewhere,
            "the ticket the agent was answered is the one that landed the change on `main`" + (f" (e.g. `{elsewhere[0]}`)" if elsewhere else ""))
        untold = [(c, tickets) for _, c, tickets in line if tickets and c not in told]
        by_ticket = sum(1 for _, tickets in untold if failed_tickets & set(tickets))
        blind = len(untold) - by_ticket
        row("landed, no agent told: explained by a failed submit's ticket / left ≤ failed submits without a ticket",
            f"{len(untold)}: {by_ticket} / {blind} ≤ {failed_blind}", blind <= failed_blind,
            "a submit that got no answer (a broken connection, a timeout) may have landed one change; nothing else lands untold")
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
