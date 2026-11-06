//! Render a results JSON file as Markdown.

use serde_json::Value;

fn f(v: &Value, d: usize) -> String {
    match v.as_f64() {
        Some(x) => format!("{x:.d$}"),
        None => "–".into(),
    }
}

pub fn markdown(r: &Value) -> String {
    let mut o = String::new();
    let m = &r["machine"];
    let man = &r["manifest"];
    o.push_str(&format!(
        "Profile `{}` (seed {}), vl {} ({}), {} CPUs ({}), {} RAM, {} on `{}`, {} cache, {}.\n\n",
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
        "Peak RSS is the child's `ru_maxrss`; it cannot read below the harness's own peak ({} MiB): values at that floor mean \"at most this\". ⛔ marks a case over the 512 MiB gate. The server's RSS is its `VmRSS` before the case's first run and its `VmHWM` during the case's runs (reset before each run; it cannot restart below the RSS the server keeps).\n\n",
        f(&r["rss_floor_mib"], 0)
    ));
    o.push_str("| case | group | median | spread | runs | peak RSS | server RSS before → peak | snapshots read | local lock held | remote lock held | ok |\n");
    o.push_str("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|\n");
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
        o.push_str(&format!(
            "| {} | {} | {} s | {}{} | {} | {} MiB{} | {} | {} | {} | {} | {} |\n",
            c["name"].as_str().unwrap_or(""),
            c["group"].as_str().unwrap_or(""),
            f(&c["median_secs"], 3),
            format_args!("{:.0} %", spread * 100.0),
            if spread > 0.15 { " ⚠" } else { "" },
            c["runs"].as_array().map(|a| a.len()).unwrap_or(0),
            f(&c["maxrss_mib"], 0),
            if c["maxrss_mib"].as_f64().is_some_and(|m| m > 512.0) { " ⛔" } else { "" },
            c["server_maxrss_mib"].as_f64().map(|m| format!("{} → {m:.0} MiB", f(&c["server_rss_before_mib"], 0))).unwrap_or_default(),
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
