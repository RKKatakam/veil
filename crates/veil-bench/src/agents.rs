//! The N-agents profile: N concurrent loops of
//!
//! 1. `vl ws exec --ephemeral -r agent-I --only <subtree> -m "…" -- <edit>`
//!    (a sparse one-shot sandbox; the edit appends to 1–10 files, and the
//!    result is recorded as a new change on top of `agent-I`);
//! 2. `vl tag set agent-I -r <new change>`,
//!
//! all in one repository. Reported: landings (recorded and tagged changes)
//! per minute, p50/p95 latency per command, and failures, and from a
//! shorter traced repetition, the time spent waiting on and holding
//! `.veil/lock`. Landings through the Veil server are measured by
//! `veil-bench load` (`docs/design/scale/LOAD.md`).

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::{
    proc::{check_stop, VlEnv},
    run::Bench,
    trace::{self, TraceSummary},
};

#[derive(Default)]
struct Samples {
    exec: Vec<f64>,
    tag: Vec<f64>,
    iteration: Vec<f64>,
    rss_kib: u64,
    landings: u64,
    failures: u64,
    errors: Vec<String>,
    traces: [TraceSummary; 2],
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i.min(v.len() - 1)]
}

fn lat(v: &mut [f64]) -> Value {
    json!({"p50": pct(v, 0.5), "p95": pct(v, 0.95), "max": pct(v, 1.0), "n": v.len()})
}

/// Pick `n` disjoint depth-2 subtrees with text files, and up to 10 files
/// in each to edit.
fn subtrees(repo: &Path, n: usize) -> Vec<(String, Vec<String>)> {
    let mut cands: Vec<(String, Vec<String>)> = Vec::new();
    let Ok(top) = std::fs::read_dir(repo) else { return vec![] };
    let mut tops: Vec<PathBuf> = top.flatten().map(|e| e.path()).filter(|p| p.is_dir() && !p.ends_with(".veil")).collect();
    tops.sort();
    for t in tops {
        let Ok(rd) = std::fs::read_dir(&t) else { continue };
        let mut subs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
        subs.sort();
        for s in subs {
            let rel = s.strip_prefix(repo).unwrap().display().to_string();
            let mut files = Vec::new();
            let mut stack = vec![s.clone()];
            let mut total = 0usize;
            while let Some(d) = stack.pop() {
                let Ok(rd) = std::fs::read_dir(&d) else { continue };
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else {
                        total += 1;
                        let name = p.display().to_string();
                        if files.len() < 10 && [".rs", ".py", ".ts"].iter().any(|x| name.ends_with(x)) {
                            files.push(p.strip_prefix(repo).unwrap().display().to_string());
                        }
                    }
                }
            }
            if !files.is_empty() && total <= 3000 {
                cands.push((rel, files));
            }
        }
    }
    if cands.is_empty() {
        return vec![];
    }
    (0..n).map(|i| cands[i % cands.len()].clone()).collect()
}

fn recorded_id(stderr: &str) -> Option<String> {
    stderr.lines().find_map(|l| l.strip_prefix("Recorded ").and_then(|r| r.split_whitespace().nth(1)).map(str::to_string))
}

/// What an agent thread needs (`Bench` itself is not `Sync`).
struct Shared<'a> {
    env: &'a VlEnv,
    repo: &'a Path,
    snapshots: &'a HashSet<String>,
}

fn agent_loop(b: &Shared<'_>, i: usize, sub: &(String, Vec<String>), iters: usize, traced: bool, out: &Mutex<Samples>) {
    let env = b.env;
    let repo = b.repo;
    let tag = format!("agent-{i}");
    for k in 0..iters {
        if check_stop().is_err() {
            return;
        }
        let t_iter = Instant::now();
        let msg = format!("agent {i} step {k}");
        let script = format!("for f; do echo '// agent {i} step {k}' >> \"$f\"; done");
        let mut args: Vec<&str> = vec!["ws", "exec", "--ephemeral", "-r", &tag, "--only", &sub.0, "-m", &msg, "--", "sh", "-c", &script, "sh"];
        let n_files = 1 + (i * 7 + k * 3) % sub.1.len();
        for f in sub.1.iter().take(n_files) {
            args.push(f);
        }
        let exec = match env.run(repo, &args, traced) {
            Ok(o) => o,
            Err(e) => {
                out.lock().unwrap().errors.push(format!("exec: {e}"));
                continue;
            }
        };
        let mut s = out.lock().unwrap();
        s.exec.push(exec.secs);
        s.rss_kib = s.rss_kib.max(exec.maxrss_kib);
        if let Some(t) = &exec.trace {
            s.traces[0].merge(&trace::summarise_files(t, b.snapshots, repo));
        }
        let Some(id) = recorded_id(&exec.stderr).filter(|_| exec.ok()) else {
            s.failures += 1;
            s.errors.push(format!("exec ({}): {}", exec.code, exec.stderr.lines().last().unwrap_or("")));
            continue;
        };
        drop(s);
        let tag_o = env.run(repo, &["tag", "set", &tag, "-r", &id], traced);
        let mut s = out.lock().unwrap();
        match tag_o {
            Ok(o) => {
                s.tag.push(o.secs);
                s.rss_kib = s.rss_kib.max(o.maxrss_kib);
                if let Some(t) = &o.trace {
                    s.traces[1].merge(&trace::summarise_files(t, b.snapshots, repo));
                }
                if !o.ok() {
                    s.failures += 1;
                    s.errors.push(format!("tag ({}): {}", o.code, o.stderr.lines().last().unwrap_or("")));
                    continue;
                }
            }
            Err(e) => {
                s.errors.push(format!("tag: {e}"));
                continue;
            }
        }
        s.landings += 1;
        s.iteration.push(t_iter.elapsed().as_secs_f64());
    }
}

fn lock_json(t: &TraceSummary) -> Value {
    let l = t.lock("local");
    json!({
        "local_wait_ms": l.wait_ms, "local_hold_ms": l.hold_ms, "local_max_hold_ms": l.max_hold_ms, "local_acquisitions": l.acquisitions, "local_failed_attempts": l.failed_attempts,
        "snapshots_read": t.snapshots_distinct,
    })
}

fn one(b: &Bench, n: usize, iters: usize, traced: bool, subs: &[(String, Vec<String>)]) -> Value {
    let shared = Shared {
        env: &b.env,
        repo: &b.repo,
        snapshots: &b.snapshots,
    };
    let shared = &shared;
    let out = Arc::new(Mutex::new(Samples::default()));
    let t = Instant::now();
    std::thread::scope(|sc| {
        for (i, sub) in subs.iter().enumerate().take(n) {
            let out = out.clone();
            sc.spawn(move || agent_loop(shared, i, sub, iters, traced, &out));
        }
    });
    let wall = t.elapsed().as_secs_f64();
    let mut s = Arc::try_unwrap(out).ok().unwrap().into_inner().unwrap();
    let mut errors = s.errors.clone();
    errors.sort();
    errors.dedup();
    errors.truncate(10);
    let mut v = json!({
        "agents": n,
        "iterations": iters,
        "traced": traced,
        "wall_secs": wall,
        "landings": s.landings,
        "landings_per_min": s.landings as f64 / wall * 60.0,
        "failures": s.failures,
        "errors": errors,
        "latency": {"exec": lat(&mut s.exec), "tag_set": lat(&mut s.tag), "iteration": lat(&mut s.iteration)},
        "maxrss_mib": s.rss_kib as f64 / 1024.0,
    });
    if traced {
        v["locks"] = json!({"exec": lock_json(&s.traces[0]), "tag_set": lock_json(&s.traces[1])});
    }
    v
}

/// Run the profile for each N (capped at twice the CPUs).
pub fn run(b: &mut Bench, ns: &[usize], iters: usize, trace_iters: usize) -> Result<Vec<Value>> {
    let repo = b.repo.clone();
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let cap = cpus * 2;
    let max_n = ns.iter().copied().max().unwrap_or(1).min(cap);
    let subs = subtrees(&repo, max_n);
    if subs.is_empty() {
        return Err(anyhow!("no subtrees for agents"));
    }
    for i in 0..max_n {
        b.env.ok(&repo, &["tag", "set", &format!("agent-{i}"), "-r", "main", "--allow-backwards"])?;
    }
    let mut results = Vec::new();
    for &n0 in ns {
        let n = n0.min(cap);
        if n < n0 {
            b.note(format!("agents: N = {n0} capped at {n} (2 × {cpus} CPUs)"));
        }
        b.preflight(&format!("agents N={n}"), 1_000_000_000)?;
        b.say(&format!("agents: N = {n}, {iters} iterations each"));
        let mut v = one(b, n, iters, false, &subs);
        v["requested"] = json!(n0);
        b.say(&format!(
            "  {} landings in {:.1} s ({:.1}/min), {} failures; exec p50 {:.2} s p95 {:.2} s; tag p50 {:.2} s p95 {:.2} s",
            v["landings"], v["wall_secs"].as_f64().unwrap_or(0.0), v["landings_per_min"].as_f64().unwrap_or(0.0), v["failures"],
            v["latency"]["exec"]["p50"].as_f64().unwrap_or(0.0), v["latency"]["exec"]["p95"].as_f64().unwrap_or(0.0),
            v["latency"]["tag_set"]["p50"].as_f64().unwrap_or(0.0), v["latency"]["tag_set"]["p95"].as_f64().unwrap_or(0.0),
        ));
        results.push(v);
        check_stop()?;
        if trace_iters > 0 {
            b.say(&format!("agents: N = {n} traced, {trace_iters} iterations each"));
            let mut v = one(b, n, trace_iters, true, &subs);
            v["requested"] = json!(n0);
            for c in ["exec", "tag_set"] {
                b.say(&format!(
                    "  {c}: local lock wait {:.0} ms hold {:.0} ms",
                    v["locks"][c]["local_wait_ms"].as_f64().unwrap_or(0.0),
                    v["locks"][c]["local_hold_ms"].as_f64().unwrap_or(0.0),
                ));
            }
            results.push(v);
            check_stop()?;
        }
    }
    Ok(results)
}
