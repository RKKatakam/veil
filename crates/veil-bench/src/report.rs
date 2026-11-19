//! Render a results JSON file as Markdown.

use serde_json::Value;

fn f(v: &Value, d: usize) -> String {
    match v.as_f64() {
        Some(x) => format!("{x:.d$}"),
        None => "–".into(),
    }
}

/// The server's memory gate (`docs/design/server/storage-and-cost.md` §9):
/// on the 1 GB profile and smaller, no case may take the server's peak RSS
/// to 1 GB (1,024 MiB) or more.
pub const SERVER_GATE_MIB: f64 = 1024.0;

/// Cases over the server gate because of a known, filed bug: still marked
/// ⛔ with "known: BUG-NNN", but they do not fail the run. Remove an entry
/// when its bug is fixed.
/// (BUG-1000's two clone cases were here until S28 fixed it.)
pub const SERVER_GATE_KNOWN: &[(&str, &str)] = &[];

/// The bug that excuses `case` over the server gate, if any.
fn known_over_gate(case: &str) -> Option<&'static str> {
    SERVER_GATE_KNOWN.iter().find(|(c, _)| *c == case).map(|(_, bug)| *bug)
}

/// Whether a case's server peak misses the gate (never on the 5 GB
/// profile, which the gate does not cover).
fn server_over(r: &Value, c: &Value) -> Option<f64> {
    let m = c["server_maxrss_mib"].as_f64()?;
    (r["manifest"]["profile"].as_str() != Some("5g") && m >= SERVER_GATE_MIB).then_some(m)
}

/// The cases whose server peak RSS misses the gate, as "case: N MiB", split
/// into those that fail the run and those a known bug excuses.
pub fn server_over_gate(r: &Value) -> (Vec<String>, Vec<String>) {
    let (mut failing, mut known) = (Vec::new(), Vec::new());
    for c in r["cases"].as_array().into_iter().flatten() {
        let Some(m) = server_over(r, c) else { continue };
        let name = c["name"].as_str().unwrap_or("?");
        match known_over_gate(name) {
            Some(bug) => known.push(format!("{name}: {m:.0} MiB (known: {bug})")),
            None => failing.push(format!("{name}: {m:.0} MiB")),
        }
    }
    (failing, known)
}

pub fn markdown(r: &Value) -> String {
    let mut o = String::new();
    let m = &r["machine"];
    let man = &r["manifest"];
    let layout_note = r["object_layout"]
        .as_str()
        .map(|l| format!("object layout `{l}`, "))
        .unwrap_or_default();
    o.push_str(&format!(
        "Profile `{}` (seed {}), {layout_note}vl {} ({}), {} CPUs ({}), {} RAM, {} on `{}`, {} cache, {}.\n\n",
        man["profile"].as_str().unwrap_or("?"),
        man["seed"],
        m["commit"].as_str().unwrap_or("?"),
        m["vl_version"].as_str().unwrap_or("?"),
        m["cpus"],
        m["cpu_model"].as_str().unwrap_or("?").trim(),
        m["mem_total"].as_str().unwrap_or("?"),
        m["kernel"].as_str().unwrap_or("?"),
        r["fs"].as_str().unwrap_or("?"),
        m["cache"].as_str().unwrap_or("warm"),
        m["date"].as_str().unwrap_or("?"),
    ));
    o.push_str(&format!(
        "Repository: {} snapshots ({} on `main`, {} merges, {} renames, {} deletions), working tree {:.2} GB in {} files; store {:.2} GB loose ({} files), {:.2} GB after gc. Generated in {:.0} s.\n\n",
        man["snapshots_total"],
        man["snapshots_main"],
        man["merges"],
        man["renames"],
        man["deletes"],
        man["tree_disk_bytes"].as_f64().unwrap_or(0.0) / 1e9,
        man["tree_files"],
        man["store_disk_bytes_loose"].as_f64().unwrap_or(0.0) / 1e9,
        man["store_files_loose"],
        man["store_disk_bytes_packed"].as_f64().unwrap_or(0.0) / 1e9,
        man["generate_seconds"].as_f64().unwrap_or(0.0),
    ));
    o.push_str(&format!(
        "Peak RSS is the child's `ru_maxrss`; it cannot read below the harness's own peak ({} MiB): values at that floor mean \"at most this\". ⛔ marks a case over the 512 MiB gate (the client's) or the 1 GB gate (the server's, `storage-and-cost.md` §9; not on the 5 GB profile; \"known: BUG-NNN\" marks a case a filed bug excuses, which does not fail the run). The server's RSS is its `VmRSS` before the case's first run and its `VmHWM` during the case's runs (reset before each run; it cannot restart below the RSS the server keeps).\n\n",
        f(&r["rss_floor_mib"], 0)
    ));
    o.push_str("| case | group | median | spread | runs | peak RSS | layout | server RSS before → peak | snapshots read | local lock held | remote lock held | ok |\n");
    o.push_str("|---|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---|\n");
    for c in r["cases"].as_array().into_iter().flatten() {
        if c.is_null() {
            continue;
        }
        let t = &c["trace"];
        let spread = c["spread"].as_f64().unwrap_or(0.0);
        let snaps = if t.is_null() {
            "".to_string()
        } else if t["store_packed"].as_bool() == Some(true) {
            "n/a (packed)".to_string()
        } else {
            format!("{} ({:.1} %)", t["snapshots_read"], t["snapshots_read_pct"].as_f64().unwrap_or(0.0))
        };
        let lock = |k: &str| {
            if t.is_null() {
                String::new()
            } else {
                let h = t[k]["hold_ms"].as_f64().unwrap_or(0.0);
                if t[k]["acquisitions"].as_u64().unwrap_or(0) == 0 {
                    "–".into()
                } else {
                    format!("{h:.0} ms")
                }
            }
        };
        let case_layout = if c["group"] == "server" || c["server_maxrss_mib"].is_number() {
            r["object_layout"].as_str().unwrap_or("–")
        } else {
            ""
        };
        o.push_str(&format!(
            "| {} | {} | {} s | {}{} | {} | {} MiB{} | {} | {}{} | {} | {} | {} | {} |\n",
            c["name"].as_str().unwrap_or(""),
            c["group"].as_str().unwrap_or(""),
            f(&c["median_secs"], 3),
            format_args!("{:.0} %", spread * 100.0),
            if spread > 0.15 { " ⚠" } else { "" },
            c["runs"].as_array().map(|a| a.len()).unwrap_or(0),
            f(&c["maxrss_mib"], 0),
            if c["maxrss_mib"].as_f64().is_some_and(|m| m > 512.0) { " ⛔" } else { "" },
            case_layout,
            c["server_maxrss_mib"].as_f64().map(|m| format!("{} → {m:.0} MiB", f(&c["server_rss_before_mib"], 0))).unwrap_or_default(),
            match (server_over(r, c), known_over_gate(c["name"].as_str().unwrap_or(""))) {
                (None, _) => String::new(),
                (Some(_), None) => " ⛔".into(),
                (Some(_), Some(bug)) => format!(" ⛔ (known: {bug})"),
            },
            snaps,
            lock("local_lock"),
            lock("remote_lock"),
            if c["ok"].as_bool() == Some(true) { "yes".to_string() } else { format!("**no** ({})", c["error"].as_str().unwrap_or("")) },
        ));
    }
    if let Some(a) = r["agents"].as_array().filter(|a| !a.is_empty()) {
        o.push_str("\n### N agents\n\n");
        o.push_str("| N | traced | iterations | wall | landings/min | failures | retries | exec p50 / p95 | tag p50 / p95 | push p50 / p95 | iteration p50 / p95 | peak RSS |\n");
        o.push_str("|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
        for v in a {
            let l = &v["latency"];
            let pp = |k: &str| format!("{} / {} s", f(&l[k]["p50"], 2), f(&l[k]["p95"], 2));
            o.push_str(&format!(
                "| {} | {} | {} | {} s | {} | {} | {} | {} | {} | {} | {} | {} MiB |\n",
                v["agents"],
                if v["traced"].as_bool() == Some(true) { "yes" } else { "no" },
                v["iterations"],
                f(&v["wall_secs"], 1),
                f(&v["landings_per_min"], 1),
                v["failures"],
                v["retries"],
                pp("exec"),
                pp("tag_set"),
                pp("push"),
                pp("iteration"),
                f(&v["maxrss_mib"], 0),
            ));
        }
        let traced: Vec<&Value> = a.iter().filter(|v| v["traced"].as_bool() == Some(true)).collect();
        if !traced.is_empty() {
            o.push_str("\nLock time in the traced runs (sums over all commands of that kind; strace inflates absolute times):\n\n");
            o.push_str("| N | command | local wait | local hold | local max hold | remote wait | remote hold | remote max hold |\n|---:|---|---:|---:|---:|---:|---:|---:|\n");
            for v in traced {
                for c in ["exec", "tag_set", "push"] {
                    let x = &v["locks"][c];
                    o.push_str(&format!(
                        "| {} | {} | {} ms | {} ms | {} ms | {} ms | {} ms | {} ms |\n",
                        v["agents"],
                        c,
                        f(&x["local_wait_ms"], 0),
                        f(&x["local_hold_ms"], 0),
                        f(&x["local_max_hold_ms"], 0),
                        f(&x["remote_wait_ms"], 0),
                        f(&x["remote_hold_ms"], 0),
                        f(&x["remote_max_hold_ms"], 0),
                    ));
                }
            }
        }
        for v in a {
            if let Some(e) = v["errors"].as_array().filter(|e| !e.is_empty()) {
                o.push_str(&format!("\nErrors at N = {}: {}\n", v["agents"], e.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; ")));
            }
        }
    }
    if let Some(n) = r["notes"].as_array().filter(|n| !n.is_empty()) {
        o.push_str("\nNotes:\n\n");
        for x in n {
            o.push_str(&format!("- {}\n", x.as_str().unwrap_or("")));
        }
    }
    o
}

/// Render any `veil-bench` result JSON as Markdown.
pub fn any_markdown(r: &Value) -> anyhow::Result<String> {
    match r["profile"].as_str() {
        Some("load") => crate::load::markdown(r),
        Some("openscion") => crate::openscion::markdown(r),
        Some("daemon") => crate::daemon::markdown(r),
        _ => Ok(markdown(r)),
    }
}

/// The server `object_layout` of a result JSON (`Some("packs")` for older
/// server results recorded before `--object-layout`, `None` for local-only
/// runs). Errors if a single result file mixes layouts across its runs.
pub fn effective_layout(v: &Value) -> anyhow::Result<Option<&str>> {
    let mut seen: Option<&str> = v["object_layout"].as_str();
    for r in v["runs"].as_array().into_iter().flatten() {
        if let Some(l) = r["object_layout"].as_str() {
            if let Some(prev) = seen {
                if prev != l {
                    anyhow::bail!("result mixes object layouts (`{prev}` and `{l}`)");
                }
            }
            seen = Some(l);
        }
    }
    if seen.is_some() {
        return Ok(seen);
    }
    let has_server = matches!(v["profile"].as_str(), Some("load" | "openscion" | "daemon"))
        || v["cases"]
            .as_array()
            .is_some_and(|cs| cs.iter().any(|c| c["group"] == "server" || c["server_maxrss_mib"].is_number()));
    Ok(has_server.then_some("packs"))
}

/// Compare `after` against `before` for regressions (`object-layout.md` §8.2,
/// §8.3), refusing when the two results come from different `object_layout`s.
pub fn compare(before: &Value, after: &Value) -> anyhow::Result<(String, Vec<String>)> {
    let (lb, la) = (effective_layout(before)?, effective_layout(after)?);
    if lb != la {
        anyhow::bail!(
            "refusing to compare results of different object layouts (`{}` vs `{}`) as a regression",
            lb.unwrap_or("none"),
            la.unwrap_or("none")
        );
    }
    if before["profile"] != after["profile"] {
        anyhow::bail!("refusing to compare different benchmark profiles ({} vs {})", before["profile"], after["profile"]);
    }
    let mut out = String::new();
    if let Some(l) = la {
        out.push_str(&format!("Object layout: `{l}`.\n\n"));
    }
    let mut regressions = Vec::new();
    if after["profile"].as_str() == Some("load") {
        out.push_str(
            "| Mode | Layout | Projects | Clients | Rate | Before (/s) | After (/s) | Before p99 (ms) | After p99 (ms) | Own writes/op (before → after) | Deletes/op (before → after) | Listings/op (before → after) | Gates missed (before → after) |\n\
             |---|---|---:|---:|---|---:|---:|---:|---:|---|---|---|---|\n",
        );
        let b_runs = before["runs"].as_array().ok_or_else(|| anyhow::anyhow!("before: no runs"))?;
        let a_runs = after["runs"].as_array().ok_or_else(|| anyhow::anyhow!("after: no runs"))?;
        let key_of = |r: &Value| {
            format!(
                "{}:{}:{}:{}:{}",
                r["mode"].as_str().unwrap_or(""),
                r["via"].as_str().unwrap_or(""),
                r["projects"],
                r["clients"],
                r["rate"]
            )
        };
        for ar in a_runs {
            let k = key_of(ar);
            let Some(br) = b_runs.iter().find(|r| key_of(r) == k) else { continue };
            let layout = la.unwrap_or("–");
            let bm = br["gates_missed"].as_array().map_or(0, Vec::len);
            let am = ar["gates_missed"].as_array().map_or(0, Vec::len);
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} → {} | {} → {} | {} → {} | {} → {} |\n",
                ar["mode"].as_str().unwrap_or(""),
                layout,
                ar["projects"],
                ar["clients"],
                ar["rate"].as_str().map(str::to_string).unwrap_or_else(|| f(&ar["rate"], 2)),
                f(&br["ops_per_s"], 1),
                f(&ar["ops_per_s"], 1),
                f(&br["p99_ms"], 1),
                f(&ar["p99_ms"], 1),
                f(&br["storage_push_writes_per_op"], 1),
                f(&ar["storage_push_writes_per_op"], 1),
                f(&br["storage_deletes_per_op"], 1),
                f(&ar["storage_deletes_per_op"], 1),
                f(&br["storage_lists_per_op"], 2),
                f(&ar["storage_lists_per_op"], 2),
                bm,
                am,
            ));
            for m in ar["gates_missed"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                let had = br["gates_missed"].as_array().is_some_and(|xs| xs.iter().any(|x| x.as_str() == Some(m)));
                if !had {
                    regressions.push(format!("{k}: newly missed gate: {m}"));
                }
            }
            let (be, ae) = (br["errors"].as_u64().unwrap_or(0), ar["errors"].as_u64().unwrap_or(0));
            if ae > be {
                regressions.push(format!("{k}: errors rose from {be} to {ae}"));
            }
            if let (Some(bo), Some(ao)) = (br["ops_per_s"].as_f64(), ar["ops_per_s"].as_f64()) {
                if bo > 0.0 && ao < bo * 0.95 {
                    regressions.push(format!("{k}: throughput dropped from {bo:.1}/s to {ao:.1}/s (> 5 %)"));
                }
            }
            if let (Some(bp), Some(ap)) = (br["p99_ms"].as_f64(), ar["p99_ms"].as_f64()) {
                if bp >= 1.0 && ap > bp * 1.10 {
                    regressions.push(format!("{k}: p99 rose from {bp:.1} ms to {ap:.1} ms (> 10 %)"));
                }
            }
        }
    } else {
        out.push_str("| Case | Layout | Before | After |\n|---|---|---:|---:|\n");
        let b_cases = before["cases"].as_array().ok_or_else(|| anyhow::anyhow!("before: no cases"))?;
        let a_cases = after["cases"].as_array().ok_or_else(|| anyhow::anyhow!("after: no cases"))?;
        let name_of = |c: &Value| {
            format!(
                "{}:{}:{}",
                c["name"].as_str().or_else(|| c["case"].as_str()).unwrap_or(""),
                c["mode"].as_str().unwrap_or(""),
                c["files"]
            )
        };
        let metric = |c: &Value| {
            c["median_secs"]
                .as_f64()
                .map(|s| (s * 1000.0, format!("{s:.3} s")))
                .or_else(|| c["veil_ms"].as_f64().map(|m| (m, format!("{m:.1} ms"))))
                .or_else(|| c["ms"].as_f64().map(|m| (m, format!("{m:.1} ms"))))
        };
        for ac in a_cases.iter().filter(|c| !c.is_null()) {
            let k = name_of(ac);
            let Some(bc) = b_cases.iter().filter(|c| !c.is_null()).find(|c| name_of(c) == k) else { continue };
            let (bm, bt) = metric(bc).unwrap_or((f64::NAN, "–".into()));
            let (am, at) = metric(ac).unwrap_or((f64::NAN, "–".into()));
            let label = ac["name"].as_str().or_else(|| ac["case"].as_str()).unwrap_or("");
            out.push_str(&format!("| {} | {} | {} | {} |\n", label, la.unwrap_or("–"), bt, at));
            if bm >= 1.0 && am > bm * 1.10 {
                regressions.push(format!("{label}: latency rose from {bt} to {at} (> 10 %)"));
            }
            if bc["ok"].as_bool() == Some(true) && ac["ok"].as_bool() == Some(false) {
                regressions.push(format!("{label}: case failed in after"));
            }
        }
        let (b_over, _) = server_over_gate(before);
        let (a_over, _) = server_over_gate(after);
        for g in a_over {
            if !b_over.contains(&g) {
                regressions.push(format!("server memory gate newly missed: {g}"));
            }
        }
    }
    Ok((out, regressions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_server_memory_gate_names_the_cases_over_1_gb() {
        let r = |profile: &str| {
            json!({
                "manifest": {"profile": profile},
                "cases": [
                    {"name": "push, initial (all tags)", "server_maxrss_mib": 1100.4},
                    {"name": "clone, full", "server_maxrss_mib": 1579.0},
                    {"name": "pull, nothing new", "server_maxrss_mib": 900.0},
                    {"name": "status in clone, clean", "server_maxrss_mib": null},
                    null,
                ],
            })
        };
        let (failing, known) = server_over_gate(&r("1g"));
        assert_eq!(failing, vec!["push, initial (all tags): 1100 MiB".to_string(), "clone, full: 1579 MiB".to_string()]);
        assert!(known.is_empty(), "BUG-1000 is fixed: no case is excused");
        assert_eq!(server_over_gate(&r("5g")), (vec![], vec![]));
        let md = markdown(&r("1g"));
        assert!(md.contains("→ 1100 MiB ⛔ |"), "{md}");
        assert!(md.contains("→ 1579 MiB ⛔ |"), "{md}");
        assert!(!md.contains("900 MiB ⛔"), "{md}");
        assert!(!markdown(&r("5g")).contains("MiB ⛔"));
    }

    #[test]
    fn compare_refuses_different_object_layouts_and_judges_same_layout() {
        let scale = json!({
            "manifest": {"profile": "1g"},
            "object_layout": "objects",
            "cases": [{"name": "push, initial (all tags)", "group": "server", "server_maxrss_mib": 500.0, "ok": true}],
        });
        let scale_md = markdown(&scale);
        assert!(scale_md.contains("object layout `objects`"), "{scale_md}");
        assert!(scale_md.contains("| objects | – → 500 MiB |"), "{scale_md}");

        let load_res = |layout: Option<&str>, ops: f64, p99: f64| {
            let mut v = json!({
                "profile": "load",
                "runs": [{
                    "mode": "branches",
                    "projects": 1,
                    "clients": 10,
                    "rate": "max",
                    "ops_per_s": ops,
                    "p99_ms": p99,
                    "storage_push_writes_per_op": 2.0,
                    "storage_deletes_per_op": 0.0,
                    "storage_lists_per_op": 0.0,
                    "errors": 0,
                    "gates_missed": [],
                }]
            });
            if let Some(l) = layout {
                v["object_layout"] = json!(l);
                v["runs"][0]["object_layout"] = json!(l);
            }
            v
        };
        // Different layouts (`packs` vs `objects`) cannot be compared as a regression.
        let err = compare(&load_res(Some("packs"), 200.0, 10.0), &load_res(Some("objects"), 50.0, 40.0)).unwrap_err();
        assert!(err.to_string().contains("different object layouts (`packs` vs `objects`)"), "{err}");

        // An older server result with no `object_layout` field is `packs`, so comparing against `objects` is refused too.
        let err_legacy = compare(&load_res(None, 200.0, 10.0), &load_res(Some("objects"), 50.0, 40.0)).unwrap_err();
        assert!(err_legacy.to_string().contains("different object layouts (`packs` vs `objects`)"), "{err_legacy}");

        // Same layout (`objects` vs `objects`): rendered and judged cleanly.
        let (md, reg) = compare(&load_res(Some("objects"), 100.0, 20.0), &load_res(Some("objects"), 98.0, 21.0)).unwrap();
        assert!(md.starts_with("Object layout: `objects`.\n\n"), "{md}");
        assert!(reg.is_empty(), "{reg:?}");

        let (_, reg_slow) = compare(&load_res(Some("objects"), 100.0, 20.0), &load_res(Some("objects"), 80.0, 30.0)).unwrap();
        assert_eq!(reg_slow.len(), 2, "{reg_slow:?}");
    }
}
