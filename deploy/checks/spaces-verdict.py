#!/usr/bin/env python3
"""The `spaces` gate's verdict (deploy/gates.sh), from a results directory's
spaces.json: the many-branch shape at a rate under one Spaces bucket's
request limit, on a server of the tool's own whose objects are on Spaces.
It shows that Veil works on Spaces (correctness and flow), not its speed
(docs/DEPLOY.md §2.3, BUG-2290). Prints a Markdown table (the gates keep it
as spaces-verdict.md); exits 1 when a check fails, 0 when every one passes.

    python3 deploy/checks/spaces-verdict.py RESULTS_DIR

Fails: no result; no push or no merge into `main`; any error an agent saw;
any storage request the server gave up on after its retries (`s3_gave_up`);
counters missing (a server without them cannot show the store's answers).
Recorded, not judged: the store's `503 Slow Down` (and 429) answers, every
try (`s3_slow_down`), the rate held against the rate offered, and the
storage requests a second against the bucket's 800.
"""
import json
import pathlib
import sys

BUCKET_LIMIT = 800  # requests a second, one Spaces bucket (DigitalOcean, "Spaces Limits")


def main(d: pathlib.Path) -> int:
    rows, ok = [], True

    def check(what, value, passed, note=""):
        nonlocal ok
        ok &= passed
        rows.append(f"| {what} | {value} | {'pass' if passed else '**FAIL**'} | {note} |")

    def show(what, value, note=""):
        rows.append(f"| {what} | {value} | recorded | {note} |")

    try:
        runs = json.loads((d / "spaces.json").read_text())["runs"]
        r = runs[0]
    except (OSError, ValueError, KeyError, IndexError, TypeError) as e:
        print("| check | value | verdict | |\n|---|---|---|---|")
        print(f"| spaces.json | missing or unreadable ({type(e).__name__}) | **FAIL** | |")
        print("\nspaces: a check FAILED")
        return 1
    num = lambda k: r.get(k) if isinstance(r.get(k), (int, float)) else None
    ops, rate, errors = num("ops") or 0, num("ops_per_s") or 0.0, num("errors")
    offered = r.get("rate")
    check("pushes", int(ops), ops > 0)
    check("merges into `main`", r.get("branch_merges"), (num("branch_merges") or 0) > 0)
    check("errors the agents saw", errors, errors == 0, r.get("first_error") or "")
    gave_up, slow = num("s3_gave_up"), num("s3_slow_down")
    check("storage requests given up after the retries", "not counted" if gave_up is None else int(gave_up), gave_up == 0)
    check("`503 Slow Down` and 429 answers counted", "not counted" if slow is None else "yes", slow is not None)
    show("`503 Slow Down` and 429 answers (every try)", "-" if slow is None else int(slow), "the server tried each again (for at most 10 s)")
    show("pushes a second", f"{rate:.1f}", f"offered {offered}/s")
    reads, writes = num("storage_reads_per_op"), num("storage_writes_per_op")
    if reads is not None and writes is not None:
        show("storage requests a push", f"{reads:.1f} reads + {writes:.1f} writes", "")
        show("storage requests a second", f"{(reads + writes) * rate:.0f}", f"one bucket allows {BUCKET_LIMIT}")
    show("p50 / p99 (ms)", f"{num('p50_ms') or 0:.0f} / {num('p99_ms') or 0:.0f}", "")
    print("| check | value | verdict | |\n|---|---|---|---|")
    print("\n".join(rows))
    print("\nspaces: every check passed" if ok else "\nspaces: a check FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: spaces-verdict.py RESULTS_DIR", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(pathlib.Path(sys.argv[1])))
