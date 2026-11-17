#!/usr/bin/env python3
"""Score Veil code-review findings against eval/review/cases.jsonl.

Uses the Python 3 standard library only.

A bug case (`escape` or `review-catch`) counts as FOUND when at least one
blocking finding:
  1. Names a target file listed in `case["files"]`,
  2. Cites a line (or line span) within `--line-tolerance` of `case["lines"]`,
  3. Matches the one-sentence `answer_key` under a conservative stem +
     technical-anchor overlap check.

Partial matches (e.g., right file + line with low text overlap, right file with
distant/missing line, or strong text overlap on a neighbour file) are NOT
credited automatically; they are written to `--manual-csv` for human grading.

Control cases (`kind == "control"`) have no bug; every blocking finding emitted
on a control case counts as a false positive.

If findings carry stage tags (`raw`, `verified`, `final`), recall on bug cases
and false positives on controls are also reported per stage.
"""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
import re
import sys
from collections import defaultdict
from typing import Any

STAGES = ("raw", "verified", "final")
STAGE_ALIASES = {
    "raw": "raw",
    "candidate": "raw",
    "candidates": "raw",
    "pre-verification": "raw",
    "pre_verification": "raw",
    "verified": "verified",
    "post-verification": "verified",
    "post_verification": "verified",
    "final": "final",
    "reported": "final",
    "review": "final",
}

NON_BLOCKING_SEVERITIES = {
    "nit",
    "nits",
    "pre-existing",
    "pre_existing",
    "preexisting",
    "out-of-scope",
    "out_of_scope",
    "trusted",
    "info",
    "note",
}

STOPWORDS = {
    "the", "and", "for", "that", "with", "from", "into", "onto", "upon",
    "when", "whenever", "while", "where", "which", "whose", "whom", "what",
    "without", "instead", "after", "before", "during", "under", "above",
    "below", "between", "through", "across", "inside", "outside", "around",
    "every", "each", "other", "another", "same", "both", "only", "also",
    "still", "even", "such", "than", "then", "this", "these", "those",
    "their", "there", "they", "them", "its", "his", "her", "our", "your",
    "have", "has", "had", "been", "being", "were", "was", "are", "does",
    "did", "done", "can", "could", "would", "should", "may", "might", "must",
    "will", "shall", "make", "makes", "made", "making", "take", "takes",
    "taken", "taking", "give", "gives", "given", "keep", "keeps", "kept",
    "call", "calls", "called", "calling", "check", "checks", "checked",
    "checking", "test", "tests", "tested", "testing", "cause", "causes",
    "caused", "causing", "leave", "leaves", "left", "leaving", "allow",
    "allows", "allowed", "allowing", "let", "lets", "letting", "use",
    "uses", "used", "using", "read", "reads", "reading", "write", "writes",
    "written", "writing", "return", "returns", "returned", "returning",
    "pass", "passes", "passed", "passing", "run", "runs", "running",
    "set", "sets", "setting", "get", "gets", "getting", "put", "puts",
    "value", "values", "file", "files", "line", "lines", "code", "path",
    "paths", "function", "functions", "method", "methods", "crate", "crates",
    "src", "mod", "pub", "impl", "let", "some", "none", "true", "false",
    "err", "result", "veil", "server", "client", "command", "commands",
    "change", "changes", "bug", "issue", "error", "errors", "fix", "fixed",
    "way", "one", "two", "first", "second", "new", "old", "any", "all",
    "not", "never", "always", "already", "once", "again", "back", "out",
    "off", "per", "via", "whether", "because", "though", "although", "despite",
    "regardless", "rather", "either", "neither",
}

BACKTICK_RE = re.compile(r"`([^`]+)`")
WORD_RE = re.compile(r"[A-Za-z0-9_]+")
FILE_LINE_RE = re.compile(
    r"`?((?:crates|docs|scripts|\.claude)/[A-Za-z0-9_./-]+|[A-Za-z0-9_./-]+\.(?:rs|sh|py|md|sql|toml))"
    r"(?::(\d+)(?:[-–](\d+))?)?`?"
)
STAGE_TAG_RE = re.compile(r"\[stage\s*:\s*([A-Za-z_-]+)\]", re.IGNORECASE)
STAGE_HEADING_RE = re.compile(
    r"^\s*#{1,4}\s*(raw|candidates?|pre[-_ ]verification|verified|post[-_ ]verification|final)\b",
    re.IGNORECASE,
)
MD_FINDING_RE = re.compile(
    r"^\s*(?:\d+\.|[-*])\s*"
    r"(?:\[(?P<sev>critical|important|medium|high|low|nit|pre-existing|out of scope[^\]]*)\]\s*)?"
    r"(?P<rest>.+)$",
    re.IGNORECASE,
)


def stem_token(tok: str) -> str:
    w = tok.lower()
    if len(w) <= 3 or w.isdigit():
        return w
    if w.endswith("ings") and len(w) > 6:
        return w[:-4]
    if w.endswith("ing") and len(w) > 5:
        w = w[:-3]
        if len(w) >= 4 and w[-1] == w[-2]:
            w = w[:-1]
        return w
    if w.endswith("ied") and len(w) > 5:
        return w[:-3] + "y"
    if w.endswith("ies") and len(w) > 5:
        return w[:-3] + "y"
    if w.endswith("ed") and len(w) > 4:
        w = w[:-2]
        if len(w) >= 4 and w[-1] == w[-2]:
            w = w[:-1]
        return w
    if w.endswith("tion") and len(w) > 6:
        return w[:-3]
    if w.endswith("es") and len(w) > 4 and not w.endswith(("ses", "xes", "zes")):
        return w[:-2]
    if w.endswith("s") and len(w) > 3 and not w.endswith("ss"):
        return w[:-1]
    return w


def extract_stems(text: str) -> set[str]:
    out: set[str] = set()
    for raw in WORD_RE.findall(text):
        parts = [raw] + ([p for p in raw.split("_") if p] if "_" in raw else [])
        for p in parts:
            low = p.lower()
            if low in STOPWORDS:
                continue
            if len(low) < 3 and not (low.isdigit() and len(low) >= 2):
                continue
            s = stem_token(low)
            if s and s not in STOPWORDS and (len(s) >= 3 or s.isdigit()):
                out.add(s)
    return out


def extract_anchor_stems(answer_key: str) -> set[str]:
    anchors: set[str] = set()
    for span in BACKTICK_RE.findall(answer_key):
        anchors |= extract_stems(span)
    for raw in WORD_RE.findall(answer_key):
        if "_" in raw or (any(c.isupper() for c in raw[1:]) and any(c.islower() for c in raw)):
            anchors |= extract_stems(raw)
        elif raw in {"429", "503", "401", "200"}:
            anchors.add(raw)
    return anchors


def normalize_stage(raw: str | None) -> str | None:
    if not raw:
        return None
    key = raw.strip().lower().replace(" ", "-")
    return STAGE_ALIASES.get(key)


def normalize_path(path: str | None) -> str:
    if not path:
        return ""
    p = path.strip().strip("`'\"").lstrip("./")
    for prefix in ("a/", "b/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    if ":" in p:
        p = p.split(":", 1)[0]
    return p


def parse_markdown_findings(text: str, default_case_id: str | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    current_stage: str | None = None
    current: dict[str, Any] | None = None

    def flush() -> None:
        nonlocal current
        if current is not None:
            findings.append(current)
            current = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        m_head = STAGE_HEADING_RE.match(stripped)
        if m_head:
            flush()
            current_stage = normalize_stage(m_head.group(1))
            continue

        if re.match(r"^(Nits|Pre-existing|Out of scope|Recommendation|Summary|Tier|Proofs checked)\b", stripped, re.I):
            flush()
            if stripped.lower().startswith(("nits", "pre-existing", "out of scope")):
                current_stage_nonblocking = True  # noqa: F841 - stop capturing previous finding
            continue

        if stripped.lower() == "no issues found.":
            flush()
            continue

        m_item = MD_FINDING_RE.match(line)
        if m_item:
            sev = (m_item.group("sev") or "").strip().lower()
            rest = m_item.group("rest").strip()
            stage_inline = None
            m_st = STAGE_TAG_RE.search(rest)
            if m_st:
                stage_inline = normalize_stage(m_st.group(1))
                rest = STAGE_TAG_RE.sub("", rest).strip()

            file_match = FILE_LINE_RE.search(rest)
            # In plain markdown, require either a severity tag or a file[:line] reference
            # so ordinary bullet lists in prose are not mistaken for findings.
            if not sev and not file_match:
                if current is not None:
                    current["description"] += " " + stripped
                continue

            flush()
            fpath = normalize_path(file_match.group(1)) if file_match else ""
            l_start = int(file_match.group(2)) if (file_match and file_match.group(2)) else None
            l_end = int(file_match.group(3)) if (file_match and file_match.group(3)) else l_start

            current = {
                "case_id": default_case_id,
                "severity": sev or "unspecified",
                "file": fpath,
                "line": l_start,
                "end_line": l_end,
                "description": rest,
                "stage": stage_inline or current_stage,
            }
        elif current is not None and (line.startswith("  ") or line.startswith("\t")):
            current["description"] += " " + stripped

    flush()
    return findings


def normalize_finding_obj(obj: dict[str, Any], default_case_id: str | None) -> list[dict[str, Any]]:
    """Normalize one JSON finding dict into 1+ internal finding records (expanding `stages` if present)."""
    if obj.get("no_findings") is True:
        return []

    cid = obj.get("case_id") or obj.get("case") or obj.get("id") or default_case_id
    sev = str(obj.get("severity") or "unspecified").strip().lower()

    raw_file = str(obj.get("file") or obj.get("path") or "").strip()
    line_start = obj.get("line") if obj.get("line") is not None else obj.get("start_line")
    line_end = obj.get("end_line")

    if ":" in raw_file and line_start is None:
        m = re.match(r"^([^:]+):(\d+)(?:[-–](\d+))?$", raw_file.strip("`"))
        if m:
            raw_file = m.group(1)
            line_start = int(m.group(2))
            line_end = int(m.group(3)) if m.group(3) else line_start

    if isinstance(line_start, list) and len(line_start) >= 1:
        line_end = int(line_start[1]) if len(line_start) >= 2 else int(line_start[0])
        line_start = int(line_start[0])
    elif line_start is not None:
        line_start = int(line_start)
        line_end = int(line_end) if line_end is not None else line_start

    desc_parts = [
        str(obj.get(k) or "").strip()
        for k in ("class", "title", "description", "summary", "message", "scenario")
    ]
    desc = " ".join(p for p in desc_parts if p)

    if not raw_file and desc:
        m_fl = FILE_LINE_RE.search(desc)
        if m_fl:
            raw_file = m_fl.group(1)
            if line_start is None and m_fl.group(2):
                line_start = int(m_fl.group(2))
                line_end = int(m_fl.group(3)) if m_fl.group(3) else line_start

    stages_raw = obj.get("stages")
    if isinstance(stages_raw, list) and stages_raw:
        stages = [normalize_stage(str(s)) for s in stages_raw]
    else:
        stages = [normalize_stage(obj.get("stage"))]

    out = []
    for st in stages:
        out.append(
            {
                "case_id": cid,
                "severity": sev,
                "file": normalize_path(raw_file),
                "line": line_start,
                "end_line": line_end,
                "description": desc,
                "stage": st,
            }
        )
    return out


def load_findings_file(path: pathlib.Path, default_case_id: str | None) -> tuple[list[dict[str, Any]], set[str]]:
    """Return `(findings, seen_case_ids)` from a JSON, JSONL, or Markdown/text file."""
    content = path.read_text(encoding="utf-8").strip()
    seen_cases: set[str] = {default_case_id} if default_case_id else set()
    if not content:
        return [], seen_cases

    # 1. Try whole-file JSON (list or dict).
    if content[0] in "[{":
        try:
            parsed = json.loads(content)
            items: list[dict[str, Any]] = []
            if isinstance(parsed, list):
                for entry in parsed:
                    if isinstance(entry, dict) and "findings" in entry and isinstance(entry["findings"], list):
                        ecid = entry.get("case_id") or entry.get("id") or default_case_id
                        if ecid:
                            seen_cases.add(ecid)
                        for sub in entry["findings"]:
                            items.extend(normalize_finding_obj(sub, ecid))
                    elif isinstance(entry, dict):
                        if entry.get("case_id") or entry.get("id"):
                            seen_cases.add(entry.get("case_id") or entry.get("id"))
                        items.extend(normalize_finding_obj(entry, default_case_id))
                return items, seen_cases
            if isinstance(parsed, dict):
                ecid = parsed.get("case_id") or parsed.get("id") or default_case_id
                if ecid:
                    seen_cases.add(ecid)
                if "findings" in parsed and isinstance(parsed["findings"], list):
                    for sub in parsed["findings"]:
                        items.extend(normalize_finding_obj(sub, ecid))
                    return items, seen_cases
                return normalize_finding_obj(parsed, ecid), seen_cases
        except json.JSONDecodeError:
            pass

        # 2. Try JSONL (one JSON object per non-empty line).
        jsonl_items: list[dict[str, Any]] = []
        ok_jsonl = True
        for ln in content.splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            try:
                entry = json.loads(s)
            except json.JSONDecodeError:
                ok_jsonl = False
                break
            if isinstance(entry, dict) and "findings" in entry and isinstance(entry["findings"], list):
                ecid = entry.get("case_id") or entry.get("id") or default_case_id
                if ecid:
                    seen_cases.add(ecid)
                for sub in entry["findings"]:
                    jsonl_items.extend(normalize_finding_obj(sub, ecid))
            elif isinstance(entry, dict):
                ecid = entry.get("case_id") or entry.get("id") or default_case_id
                if ecid:
                    seen_cases.add(ecid)
                jsonl_items.extend(normalize_finding_obj(entry, default_case_id))
        if ok_jsonl:
            return jsonl_items, seen_cases

    # 3. Parse as Markdown / veil-review text report.
    return parse_markdown_findings(content, default_case_id), seen_cases


def load_all_findings(
    target: pathlib.Path, cases_by_id: dict[str, dict[str, Any]], single_case_id: str | None
) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_cases: set[str] = set()

    if target.is_dir():
        for cid in cases_by_id:
            if single_case_id and cid != single_case_id:
                continue
            for ext in (".jsonl", ".json", ".md", ".txt"):
                candidate = target / f"{cid}{ext}"
                if candidate.is_file():
                    f_list, seen = load_findings_file(candidate, cid)
                    by_case[cid].extend(f_list)
                    seen_cases |= seen
                    seen_cases.add(cid)
                    break
        return by_case, seen_cases

    f_list, seen = load_findings_file(target, single_case_id)
    seen_cases |= seen
    for f in f_list:
        cid = f.get("case_id") or single_case_id
        if cid:
            by_case[cid].append(f)
            seen_cases.add(cid)
    return by_case, seen_cases


def is_blocking(finding: dict[str, Any]) -> bool:
    sev = (finding.get("severity") or "unspecified").strip().lower()
    if any(sev.startswith(nb) for nb in NON_BLOCKING_SEVERITIES):
        return False
    return True


def target_spans_for_file(case: dict[str, Any], target_file: str) -> list[tuple[int, int]]:
    lines_spec = case.get("lines")
    if isinstance(lines_spec, dict):
        raw = lines_spec.get(target_file)
    elif isinstance(lines_spec, list):
        raw = lines_spec
    else:
        raw = None

    if not raw:
        return []
    if isinstance(raw, list) and len(raw) == 2 and all(isinstance(x, int) for x in raw):
        return [(raw[0], raw[1])]
    if isinstance(raw, list):
        return [(int(sp[0]), int(sp[1])) for sp in raw if isinstance(sp, list) and len(sp) == 2]
    return []


def match_file(finding_file: str, case_files: list[str]) -> str | None:
    if not finding_file:
        return None
    for cf in case_files:
        if finding_file == cf:
            return cf
    if "/" in finding_file:
        matches = [cf for cf in case_files if cf.endswith("/" + finding_file)]
        if len(matches) == 1:
            return matches[0]
    else:
        matches = [cf for cf in case_files if pathlib.PurePosixPath(cf).name == finding_file]
        if len(matches) == 1:
            return matches[0]
    return None


def evaluate_finding_on_bug_case(
    finding: dict[str, Any], case: dict[str, Any], line_tolerance: int
) -> dict[str, Any]:
    """Classify one blocking finding against a bug case as `found`, `ambiguous`, or `unmatched`."""
    answer_key = case.get("answer_key") or ""
    key_stems = extract_stems(answer_key)
    anchor_stems = extract_anchor_stems(answer_key)
    finding_stems = extract_stems(finding.get("description") or "")

    matched_stems = sorted(key_stems & finding_stems)
    matched_anchors = sorted(anchor_stems & finding_stems)
    stem_recall = len(matched_stems) / max(1, len(key_stems))

    matched_target_file = match_file(finding.get("file") or "", case.get("files") or [])
    file_ok = matched_target_file is not None

    line_ok = False
    f_lo = finding.get("line")
    f_hi = finding.get("end_line") if finding.get("end_line") is not None else f_lo
    if file_ok and f_lo is not None and f_hi is not None:
        spans = target_spans_for_file(case, matched_target_file)
        for s_lo, s_hi in spans:
            if f_hi >= (s_lo - line_tolerance) and f_lo <= (s_hi + line_tolerance):
                line_ok = True
                break

    min_stems_needed = min(3, max(1, len(key_stems)))
    anchor_ok = (len(anchor_stems) < 2) or (len(matched_anchors) >= 1)
    desc_ok = (len(matched_stems) >= min_stems_needed) and (stem_recall >= 0.28) and anchor_ok

    if file_ok and line_ok and desc_ok:
        verdict = "found"
        reason = "file, line within tolerance, and conservative key overlap matched"
    elif file_ok and line_ok and len(matched_stems) >= 1:
        verdict = "ambiguous"
        reason = f"right file and line, partial key overlap ({len(matched_stems)}/{len(key_stems)} stems)"
    elif file_ok and not line_ok and (len(matched_stems) >= 2 or stem_recall >= 0.20):
        verdict = "ambiguous"
        reason = (
            "right file with description overlap, but missing or out-of-tolerance line "
            f"(got {f_lo}, spans {target_spans_for_file(case, matched_target_file)})"
        )
    elif (not file_ok) and len(matched_stems) >= 4 and stem_recall >= 0.35:
        verdict = "ambiguous"
        reason = f"strong description overlap ({stem_recall:.2f}) on non-target file '{finding.get('file')}'"
    else:
        verdict = "unmatched"
        reason = "did not match target file/line/answer_key"

    return {
        "verdict": verdict,
        "reason": reason,
        "file_ok": file_ok,
        "line_ok": line_ok,
        "desc_ok": desc_ok,
        "stem_recall": round(stem_recall, 3),
        "matched_stems": matched_stems,
        "matched_anchors": matched_anchors,
    }


def score_subset(
    cases: list[dict[str, Any]],
    findings_by_case: dict[str, list[dict[str, Any]]],
    line_tolerance: int,
    stage_filter: str | None = None,
) -> dict[str, Any]:
    bug_cases = [c for c in cases if c["kind"] != "control"]
    ctrl_cases = [c for c in cases if c["kind"] == "control"]

    found_ids: list[str] = []
    ambiguous_rows: list[dict[str, Any]] = []
    per_case: dict[str, dict[str, Any]] = {}

    for c in bug_cases:
        cid = c["id"]
        raw_list = findings_by_case.get(cid, [])
        has_staged = any(f.get("stage") is not None for f in raw_list)
        active = [
            f for f in raw_list
            if is_blocking(f)
            and (
                (stage_filter is None and (not has_staged or f.get("stage") in (None, "final")))
                or (stage_filter is not None and f.get("stage") == stage_filter)
            )
        ]
        evals = [(f, evaluate_finding_on_bug_case(f, c, line_tolerance)) for f in active]
        case_found = any(ev["verdict"] == "found" for _, ev in evals)
        if case_found:
            found_ids.append(cid)
        else:
            for f, ev in evals:
                if ev["verdict"] == "ambiguous":
                    ambiguous_rows.append(
                        {
                            "case_id": cid,
                            "kind": c["kind"],
                            "split": c["split"],
                            "area": c["area"],
                            "stage": stage_filter or (f.get("stage") or "final"),
                            "target_files": ";".join(c.get("files") or []),
                            "target_lines": json.dumps(c.get("lines") or {}),
                            "finding_file": f.get("file") or "",
                            "finding_line": f.get("line") if f.get("line") is not None else "",
                            "finding_severity": f.get("severity") or "",
                            "stem_recall": ev["stem_recall"],
                            "matched_stems": " ".join(ev["matched_stems"]),
                            "reason": ev["reason"],
                            "answer_key": c.get("answer_key") or "",
                            "finding_description": f.get("description") or "",
                            "human_match": "",
                        }
                    )
        per_case[cid] = {
            "kind": c["kind"],
            "area": c["area"],
            "severity": c["severity"],
            "blocking_findings": len(active),
            "status": "FOUND" if case_found else (
                "AMBIGUOUS" if any(ev["verdict"] == "ambiguous" for _, ev in evals) else "MISSED"
            ),
            "details": [
                {
                    "file": f.get("file"),
                    "line": f.get("line"),
                    "severity": f.get("severity"),
                    "stage": f.get("stage"),
                    **ev,
                }
                for f, ev in evals
            ],
        }

    ctrl_fp_findings = 0
    ctrl_flagged_cases = 0
    for c in ctrl_cases:
        cid = c["id"]
        raw_list = findings_by_case.get(cid, [])
        has_staged = any(f.get("stage") is not None for f in raw_list)
        active = [
            f for f in raw_list
            if is_blocking(f)
            and (
                (stage_filter is None and (not has_staged or f.get("stage") in (None, "final")))
                or (stage_filter is not None and f.get("stage") == stage_filter)
            )
        ]
        fp = len(active)
        ctrl_fp_findings += fp
        if fp > 0:
            ctrl_flagged_cases += 1
        per_case[cid] = {
            "kind": "control",
            "area": c["area"],
            "severity": "none",
            "blocking_findings": fp,
            "status": "CLEAN" if fp == 0 else f"OVER-FLAGGED ({fp})",
            "details": [
                {
                    "file": f.get("file"),
                    "line": f.get("line"),
                    "severity": f.get("severity"),
                    "stage": f.get("stage"),
                    "description": f.get("description"),
                }
                for f in active
            ],
        }

    by_kind: dict[str, tuple[int, int]] = {}
    for k in ("escape", "review-catch"):
        sub = [c for c in bug_cases if c["kind"] == k]
        if sub:
            by_kind[k] = (sum(1 for c in sub if c["id"] in found_ids), len(sub))

    by_area: dict[str, tuple[int, int]] = {}
    for area in sorted({c["area"] for c in bug_cases}):
        sub = [c for c in bug_cases if c["area"] == area]
        by_area[area] = (sum(1 for c in sub if c["id"] in found_ids), len(sub))

    return {
        "bug_found": len(found_ids),
        "bug_total": len(bug_cases),
        "recall": (len(found_ids) / len(bug_cases)) if bug_cases else None,
        "by_kind": by_kind,
        "by_area": by_area,
        "ctrl_total": len(ctrl_cases),
        "ctrl_flagged": ctrl_flagged_cases,
        "ctrl_fp_findings": ctrl_fp_findings,
        "ambiguous_rows": ambiguous_rows,
        "per_case": per_case,
    }


def fmt_rate(num: int, den: int) -> str:
    if den == 0:
        return "n/a (0/0)"
    return f"{num}/{den} ({100.0 * num / den:.1f}%)"


def print_summary(label: str, res: dict[str, Any], verbose: bool) -> None:
    print(f"=== {label} ===")
    if res["bug_total"] > 0:
        print(f"Bug recall:           {fmt_rate(res['bug_found'], res['bug_total'])}")
        for k, (n, d) in res["by_kind"].items():
            print(f"  {k:18s}  {fmt_rate(n, d)}")
        area_parts = [f"{a}: {n}/{d}" for a, (n, d) in res["by_area"].items()]
        if area_parts:
            print(f"  by area:            {', '.join(area_parts)}")
    if res["ctrl_total"] > 0:
        print(
            f"Controls over-flagged: {fmt_rate(res['ctrl_flagged'], res['ctrl_total'])} cases, "
            f"{res['ctrl_fp_findings']} false-positive blocking finding(s)"
        )
    print(f"Ambiguous candidates: {len(res['ambiguous_rows'])}")
    if verbose:
        for cid, info in res["per_case"].items():
            print(f"  - {cid:15s} [{info['kind']:12s} | {info['area']:7s}] -> {info['status']} "
                  f"({info['blocking_findings']} blocking finding(s))")


def main() -> int:
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    default_cases = repo_root / "eval" / "review" / "cases.jsonl"

    ap = argparse.ArgumentParser(description="Score Veil reviewer findings against cases.jsonl.")
    ap.add_argument("--cases", type=pathlib.Path, default=default_cases, help="Path to cases.jsonl")
    ap.add_argument("--findings", type=pathlib.Path, required=True, help="Findings file (JSON/JSONL/MD) or directory")
    ap.add_argument("--case", dest="case_id", help="Score a single case id")
    ap.add_argument(
        "--split",
        choices=("tuning", "test", "all"),
        default="all",
        help="Subset of cases.jsonl to score when --case is not set (default: all)",
    )
    ap.add_argument(
        "--only-present",
        action="store_true",
        help="Score only cases mentioned/present in --findings rather than the entire split",
    )
    ap.add_argument(
        "--line-tolerance",
        type=int,
        default=50,
        help="Allowed line distance outside a case's [start, end] span (default: 50)",
    )
    ap.add_argument(
        "--manual-csv",
        type=pathlib.Path,
        help="Write ambiguous partial-match findings to this CSV path for human grading",
    )
    ap.add_argument("--json-out", type=pathlib.Path, help="Optional path to write full JSON score report")
    ap.add_argument("--verbose", "-v", action="store_true", help="Print per-case status lines")
    args = ap.parse_args()

    cases_all: list[dict[str, Any]] = []
    for ln in args.cases.read_text(encoding="utf-8").splitlines():
        s = ln.strip()
        if s:
            cases_all.append(json.loads(s))
    cases_by_id = {c["id"]: c for c in cases_all}

    if args.case_id:
        if args.case_id not in cases_by_id:
            print(f"error: unknown case id '{args.case_id}'", file=sys.stderr)
            return 2
        selected = [cases_by_id[args.case_id]]
    else:
        selected = [c for c in cases_all if args.split == "all" or c["split"] == args.split]

    findings_by_case, seen_cases = load_all_findings(args.findings, cases_by_id, args.case_id)
    if args.only_present and not args.case_id:
        selected = [c for c in selected if c["id"] in seen_cases]

    if not selected:
        print("error: no cases selected to score", file=sys.stderr)
        return 2

    overall = score_subset(selected, findings_by_case, args.line_tolerance, stage_filter=None)
    scope_name = f"case {args.case_id}" if args.case_id else f"split={args.split} ({len(selected)} cases)"
    print_summary(f"Overall ({scope_name})", overall, verbose=args.verbose or bool(args.case_id))

    present_stages = [
        st for st in STAGES
        if any(f.get("stage") == st for cid in (c["id"] for c in selected) for f in findings_by_case.get(cid, []))
    ]
    stage_reports: dict[str, Any] = {}
    ambiguous_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}

    def record_ambiguous(rows: list[dict[str, Any]]) -> None:
        for row in rows:
            k = (row["case_id"], row["finding_file"], row["finding_line"], row["finding_description"])
            if k not in ambiguous_by_key:
                ambiguous_by_key[k] = dict(row)
            else:
                existing_stages = ambiguous_by_key[k]["stage"].split(",")
                if row["stage"] not in existing_stages:
                    existing_stages.append(row["stage"])
                    ambiguous_by_key[k]["stage"] = ",".join(existing_stages)

    for st in present_stages:
        print()
        st_res = score_subset(selected, findings_by_case, args.line_tolerance, stage_filter=st)
        stage_reports[st] = st_res
        print_summary(f"Stage: {st}", st_res, verbose=args.verbose)
        record_ambiguous(st_res["ambiguous_rows"])

    record_ambiguous(overall["ambiguous_rows"])
    all_ambiguous = list(ambiguous_by_key.values())

    if args.manual_csv is not None:
        args.manual_csv.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "case_id", "kind", "split", "area", "stage", "target_files", "target_lines",
            "finding_file", "finding_line", "finding_severity", "stem_recall",
            "matched_stems", "reason", "answer_key", "finding_description", "human_match",
        ]
        with args.manual_csv.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_ambiguous)
        print(f"\nWrote {len(all_ambiguous)} ambiguous candidate(s) to {args.manual_csv}")

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "scope": scope_name,
            "line_tolerance": args.line_tolerance,
            "overall": overall,
            "stages": stage_reports,
        }
        args.json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
