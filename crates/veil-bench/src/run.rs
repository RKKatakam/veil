//! The single-process cases: every measured command is a release `vl`
//! process; times are the median of `runs` repetitions; peak RSS is the
//! largest `ru_maxrss` seen. Selected cases are run once more under strace
//! (before `gc`, while objects are loose) to count snapshot decodes and lock
//! waits and holds (see `trace.rs`).

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

use crate::{
    proc::{self, check_stop, du, free_bytes, remove_tree, Outcome, VlEnv},
    trace::{self, TraceSummary},
};

pub struct Options {
    pub runs: usize,
    /// Repeat a case only while a run takes less than this.
    pub long_secs: f64,
    /// Kill a single command after this long.
    pub timeout: Duration,
    /// Stop when free disk would drop below this many bytes.
    pub min_free: u64,
    pub rtts: Vec<u64>,
    pub sftp_server: Option<PathBuf>,
    pub skip: Vec<String>,
}

pub struct Bench {
    /// The bench directory (everything the run creates is below it).
    pub dir: PathBuf,
    pub repo: PathBuf,
    pub env: VlEnv,
    pub snapshots: HashSet<String>,
    pub manifest: Value,
    pub cases: Vec<Value>,
    pub notes: Vec<String>,
    pub opts: Options,
    pub edit_seq: usize,
    pub log: Box<dyn FnMut(&str)>,
    /// The server under test, when there is one: its peak RSS is recorded
    /// with every case (each run's window starts after `prep`).
    pub server_pid: Option<u32>,
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

pub fn trace_json(t: &TraceSummary, total_snapshots: usize) -> Value {
    let l = t.lock("local");
    let r = t.lock("remote");
    json!({
        "snapshots_read": t.snapshots_distinct,
        "snapshot_opens": t.snapshot_opens,
        "snapshots_read_pct": if total_snapshots > 0 { 100.0 * t.snapshots_distinct as f64 / total_snapshots as f64 } else { 0.0 },
        "other_objects_read": t.other_object_opens,
        "local_lock": {"acquisitions": l.acquisitions, "failed_attempts": l.failed_attempts, "wait_ms": l.wait_ms, "hold_ms": l.hold_ms, "max_hold_ms": l.max_hold_ms},
        "remote_lock": {"acquisitions": r.acquisitions, "failed_attempts": r.failed_attempts, "wait_ms": r.wait_ms, "hold_ms": r.hold_ms, "max_hold_ms": r.max_hold_ms},
    })
}

/// One case: how to prepare each run, and whether to trace it.
pub struct Case<'a> {
    pub name: &'a str,
    pub group: &'a str,
    pub cwd: PathBuf,
    pub args: Vec<String>,
    pub runs: Option<usize>,
    pub trace: bool,
    pub env: Vec<(String, String)>,
}

impl<'a> Case<'a> {
    pub fn new(name: &'a str, group: &'a str, cwd: &Path, args: &[&str]) -> Case<'a> {
        Case {
            name,
            group,
            cwd: cwd.to_path_buf(),
            args: args.iter().map(|s| s.to_string()).collect(),
            runs: None,
            trace: false,
            env: Vec::new(),
        }
    }
    pub fn runs(mut self, n: usize) -> Self {
        self.runs = Some(n);
        self
    }
    pub fn traced(mut self) -> Self {
        self.trace = true;
        self
    }
    pub fn env(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }
}

impl Bench {
    pub fn say(&mut self, s: &str) {
        (self.log)(s)
    }

    pub fn skipped(&self, name: &str) -> bool {
        self.opts.skip.iter().any(|s| name.starts_with(s.as_str()))
    }

    /// Stop unless `need` bytes fit above the free-space floor.
    pub fn preflight(&mut self, phase: &str, need: u64) -> Result<()> {
        check_stop()?;
        let free = free_bytes(&self.dir)?;
        self.say(&format!(
            "[disk] {phase}: {:.1} GB free, needs {:.1} GB above the {:.1} GB floor",
            free as f64 / 1e9,
            need as f64 / 1e9,
            self.opts.min_free as f64 / 1e9
        ));
        enough_disk(phase, free, need, self.opts.min_free)
    }

    fn total_snapshots(&self) -> usize {
        self.snapshots.len()
    }

    /// Run a case `runs` times (`prep` before each), plus one traced run.
    pub fn case(&mut self, c: Case<'_>, mut prep: impl FnMut(&mut Bench, usize) -> Result<()>) -> Result<Value> {
        if self.skipped(c.name) {
            return Ok(Value::Null);
        }
        check_stop()?;
        let runs = c.runs.unwrap_or(self.opts.runs);
        let args: Vec<&str> = c.args.iter().map(String::as_str).collect();
        let env: Vec<(&str, &str)> = c.env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let mut secs = Vec::new();
        let mut user = Vec::new();
        let mut sys = Vec::new();
        let mut rss = 0u64;
        let mut server_rss: Option<u64> = None;
        let mut server_before: Option<u64> = None;
        let mut last = Outcome::default();
        for i in 0..runs {
            prep(self, i)?;
            if let Some(k) = self.server_pid.and_then(crate::server::reset_peak) {
                server_before.get_or_insert(k);
            }
            let o = self.env.run_full(&c.cwd, &args, false, &env, Some(self.opts.timeout))?;
            if let Some(k) = self.server_pid.and_then(crate::server::peak_kib) {
                server_rss = Some(server_rss.unwrap_or(0).max(k));
            }
            if !o.ok() {
                self.say(&format!("  {} FAILED ({}): {}", c.name, o.code, o.stderr.lines().last().unwrap_or("")));
            }
            secs.push(o.secs);
            user.push(o.user_secs);
            sys.push(o.sys_secs);
            rss = rss.max(o.maxrss_kib);
            let long = o.secs > self.opts.long_secs;
            last = o;
            if !last.ok() || long {
                break;
            }
            check_stop()?;
        }
        let mut traced = Value::Null;
        if c.trace && last.ok() {
            prep(self, runs)?;
            let o = self.env.run_full(&c.cwd, &args, true, &env, Some(self.opts.timeout * 3))?;
            if let Some(t) = &o.trace {
                let s = trace::summarise_files(t, &self.snapshots, &c.cwd);
                traced = trace_json(&s, self.total_snapshots());
                traced["traced_secs"] = json!(o.secs);
                // Packed objects are read without an open each: the counts
                // only mean something while the snapshots are loose.
                traced["store_packed"] = json!(snapshots_packed(&c.cwd, &self.snapshots));
            }
        }
        let runs_secs = secs.clone();
        let med = median(&mut secs);
        let spread = if med > 0.0 && runs_secs.len() > 1 {
            (runs_secs.iter().cloned().fold(f64::MIN, f64::max) - runs_secs.iter().cloned().fold(f64::MAX, f64::min)) / med
        } else {
            0.0
        };
        let v = json!({
            "name": c.name,
            "group": c.group,
            "args": c.args,
            "ok": last.ok(),
            "code": last.code,
            "error": if last.ok() { Value::Null } else { json!(last.stderr.lines().rev().take(5).collect::<Vec<_>>().join(" | ")) },
            "runs": runs_secs,
            "median_secs": med,
            "spread": spread,
            "user_secs": median(&mut user),
            "sys_secs": median(&mut sys),
            "maxrss_mib": rss as f64 / 1024.0,
            "server_maxrss_mib": server_rss.map(|k| k as f64 / 1024.0),
            "server_rss_before_mib": server_before.map(|k| k as f64 / 1024.0),
            "stdout_bytes": last.stdout_bytes,
            "trace": traced,
        });
        let tr = if traced.is_null() {
            String::new()
        } else {
            format!(
                ", {} snapshots read, local lock held {:.0} ms",
                traced["snapshots_read"], traced["local_lock"]["hold_ms"].as_f64().unwrap_or(0.0)
            )
        };
        let srv = server_rss
            .map(|k| format!(", server {:.0} → {:.0} MiB", server_before.unwrap_or(0) as f64 / 1024.0, k as f64 / 1024.0))
            .unwrap_or_default();
        self.say(&format!("  {:<34} {:>9.3} s  {:>7.1} MiB{srv}{}", c.name, med, rss as f64 / 1024.0, tr));
        self.cases.push(v.clone());
        Ok(v)
    }

    /// Text files of the working copy to edit (from the manifest's sample).
    fn edit_targets(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(a) = self.manifest["sample_paths"].as_array() {
            for p in a.iter().filter_map(|v| v.as_str()) {
                if [".rs", ".py", ".ts", ".json", ".yaml"].iter().any(|e| p.ends_with(e)) {
                    let full = self.repo.join(p);
                    if full.is_file() {
                        out.push(full);
                    }
                }
            }
        }
        out
    }

    /// Append a line to `n` files of the working copy.
    pub fn dirty(&mut self, n: usize) -> Result<()> {
        use std::io::Write;
        self.edit_seq += 1;
        let targets = self.edit_targets();
        if targets.is_empty() {
            return Err(anyhow!("no files to edit"));
        }
        for i in 0..n {
            let p = &targets[(self.edit_seq * 7 + i) % targets.len()];
            let mut f = std::fs::OpenOptions::new().append(true).open(p)?;
            writeln!(f, "// bench edit {} {}", self.edit_seq, i)?;
        }
        Ok(())
    }

    fn vl_ok(&self, cwd: &Path, args: &[&str]) -> Result<Outcome> {
        self.env.ok(cwd, args)
    }

    pub fn note(&mut self, s: impl Into<String>) {
        let s = s.into();
        self.say(&format!("  note: {s}"));
        self.notes.push(s);
    }
}

/// The pre-flight rule (threat 1): a phase starts only if `need` bytes fit
/// above the floor.
pub fn enough_disk(phase: &str, free: u64, need: u64, floor: u64) -> Result<()> {
    if free < floor.saturating_add(need) {
        return Err(anyhow!(
            "stopping before {phase}: {:.1} GB free, and it needs {:.1} GB above the {:.1} GB floor",
            free as f64 / 1e9,
            need as f64 / 1e9,
            floor as f64 / 1e9
        ));
    }
    Ok(())
}

/// Snapshot reads are counted by the opens of loose snapshot objects:
/// the counts mean something only while every snapshot is loose
/// (transactions write snapshots loose, also when the rest of their new
/// objects is a pack; `gc` packs them).
fn snapshots_packed(repo: &Path, snapshots: &HashSet<String>) -> bool {
    let objects = repo.join(".veil/objects");
    snapshots.iter().any(|h| h.len() > 2 && !objects.join(&h[..2]).join(&h[2..]).exists())
}

fn traced_if(c: Case<'_>, trace: bool) -> Case<'_> {
    if trace {
        c.traced()
    } else {
        c
    }
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

/// After `gen`: check out `main`, merge the fix line under embargo, write
/// isolated files. Returns the measured tree size.
pub fn setup(b: &mut Bench) -> Result<()> {
    let repo = b.repo.clone();
    b.say("setup: checkout, embargo, isolated files");
    b.preflight("checkout", 2_000_000_000)?;
    b.case(Case::new("checkout main (full tree)", "setup", &repo, &["new", "main", "-m", "bench work"]).runs(1), |_, _| Ok(()))?;
    // A `--plain` repository (for the server) has no fix line to embargo
    // and no `isolate` rule.
    if let Some(fix) = b.manifest["fix_tip"].as_str().map(str::to_string) {
        b.case(
            Case::new("merge --embargo (fix line of 50)", "setup", &repo, &["merge", &fix, "--into", "release", "--embargo", "--until", "+30d", "-m", "Security fix (embargoed)"]).runs(1),
            |_, _| Ok(()),
        )?;
        // The merge may move the working copy; go back to main.
        b.case(Case::new("switch release → main", "setup", &repo, &["new", "main", "-m", "bench work"]).runs(1), |_, _| Ok(()))?;
        for i in 0..5 {
            let dir = repo.join(format!("config/env{i}"));
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join(".env"), format!("API_TOKEN=bench-isolated-{i}\n"))?;
        }
    }
    let (wbytes, wfiles) = du(&repo);
    let (sbytes, sfiles) = du(&repo.join(".veil"));
    b.manifest["tree_disk_bytes"] = json!(wbytes - sbytes);
    b.manifest["tree_files"] = json!(wfiles - sfiles);
    b.manifest["store_disk_bytes_loose"] = json!(sbytes);
    b.manifest["store_files_loose"] = json!(sfiles);
    b.say(&format!(
        "  working tree {:.2} GB in {} files; .veil {:.2} GB in {} files",
        (wbytes - sbytes) as f64 / 1e9,
        wfiles - sfiles,
        sbytes as f64 / 1e9,
        sfiles
    ));
    Ok(())
}

/// `vl init` of the final tree (a hard-linked copy: no extra disk for the
/// files themselves).
pub fn import(b: &mut Bench) -> Result<()> {
    if b.skipped("init") {
        return Ok(());
    }
    let store = b.manifest["store_disk_bytes_loose"].as_u64().unwrap_or(0);
    b.preflight("init (import)", store.max(1_000_000_000))?;
    let dst = b.dir.join("import");
    remove_tree(&dst, &b.dir)?;
    std::fs::create_dir_all(&dst)?;
    // Hard-link every file except .veil and isolated files.
    let st = Command::new("sh")
        .arg("-c")
        .arg("cd \"$1\" && find . -path ./.veil -prune -o -type f ! -name .env -print0 | cpio -0pdlm --quiet \"$2\"")
        .arg("sh")
        .arg(&b.repo)
        .arg(&dst)
        .status()?;
    if !st.success() {
        return Err(anyhow!("hard-linking the tree failed"));
    }
    let _ = std::fs::remove_file(dst.join(".veilpolicy"));
    std::fs::copy(b.repo.join(".veilpolicy"), dst.join(".veilpolicy"))?;
    b.case(Case::new("init (import of the final tree)", "local", &dst, &["init"]).runs(1), |_, _| Ok(()))?;
    b.case(Case::new("status, clean (fresh import)", "local", &dst, &["status"]).runs(1), |_, _| Ok(()))?;
    let (ib, _) = du(&dst.join(".veil"));
    b.note(format!("import store: {:.2} GB on disk", ib as f64 / 1e9));
    remove_tree(&dst, &b.dir)?;
    Ok(())
}

/// Local cases on the current store (`label`: loose or packed).
pub fn local(b: &mut Bench, label: &str, trace: bool) -> Result<()> {
    let repo = b.repo.clone();
    let g = format!("local, {label}");
    let g = g.as_str();
    let m = b.manifest.clone();
    let hot = m["blame_path"].as_str().unwrap_or("").to_string();
    let needle = m["needle"].as_str().unwrap_or("").to_string();
    let oldest_tag = m["oldest_tag"].as_str().unwrap_or("main").to_string();
    let t = |c| traced_if(c, trace);
    b.preflight(&format!("local cases ({label})"), 500_000_000)?;
    b.case(t(Case::new("status, clean", g, &repo, &["status"])), |_, _| Ok(()))?;
    b.case(t(Case::new("status, 1 modified file", g, &repo, &["status"])), |b, _| b.dirty(1))?;
    b.case(t(Case::new("status, 100 modified files", g, &repo, &["status"])), |b, _| b.dirty(100))?;
    b.case(t(Case::new("commit, 100 modified files", g, &repo, &["commit", "-m", "bench commit"])), |b, _| b.dirty(100))?;
    b.case(t(Case::new("log -n 20", g, &repo, &["log", "-n", "20"])), |_, _| Ok(()))?;
    b.case(t(Case::new("log -n 20 -- <hot file>", g, &repo, &["log", "-n", "20", &hot])), |_, _| Ok(()))?;
    b.case(t(Case::new("log (all history)", g, &repo, &["log"])), |_, _| Ok(()))?;
    b.case(t(Case::new("log -S <needle> (all history)", g, &repo, &["log", "-S", &needle])).runs(1), |_, _| Ok(()))?;
    b.case(t(Case::new("blame <hot file, oldest>", g, &repo, &["blame", &hot])), |_, _| Ok(()))?;
    b.case(t(Case::new("blame -r <oldest tag> <hot file>", g, &repo, &["blame", "-r", &oldest_tag, &hot])), |_, _| Ok(()))?;
    b.case(t(Case::new("tag set", g, &repo, &["tag", "set", "bench-tag", "-r", "@-", "--allow-backwards"])), |_, _| Ok(()))?;
    b.case(t(Case::new("ws exec --only (sparse sandbox)", g, &repo, &["ws", "exec", "--ephemeral", "-r", "main", "--only", "docs", "-m", "bench exec", "--", "true"])), |_, _| Ok(()))?;
    Ok(())
}

/// Push, clone and pull through a path remote or SFTP.
pub fn remote(b: &mut Bench, kind: &str, rtt_ms: u64, trace: bool) -> Result<()> {
    let repo = b.repo.clone();
    let name = if rtt_ms > 0 { format!("{kind}-{rtt_ms}ms") } else { kind.to_string() };
    let remote_dir = b.dir.join(format!("remote-{name}"));
    let clone_parent = b.dir.join(format!("clone-{name}"));
    remove_tree(&remote_dir, &b.dir)?;
    remove_tree(&clone_parent, &b.dir)?;
    let url = match kind {
        "path" => s(&remote_dir),
        _ => format!("bench@example.invalid:{}", remote_dir.display()),
    };
    let group = format!("remote: {name}");
    let g = group.as_str();
    let rtt = rtt_ms.to_string();
    let store = b.manifest["store_disk_bytes_loose"].as_u64().unwrap_or(2_000_000_000);
    let tree = b.manifest["tree_disk_bytes"].as_u64().unwrap_or(1_000_000_000);
    b.preflight(&format!("push to {name}"), store)?;
    let _ = b.env.run(&repo, &["remote", "rm", "bench"], false);
    b.vl_ok(&repo, &["remote", "add", "bench", &url])?;
    let t = |c| traced_if(c, trace);
    let r = b.case(Case::new("push, initial (all tags)", g, &repo, &["push", "bench"]).runs(1).env("VEIL_BENCH_RTT_MS", &rtt), |_, _| Ok(()))?;
    if r.get("ok") != Some(&json!(true)) {
        let _ = b.env.run(&repo, &["remote", "rm", "bench"], false);
        remove_tree(&remote_dir, &b.dir)?;
        return Ok(());
    }
    let (rb, rf) = du(&remote_dir);
    b.note(format!("{name} remote after the initial push: {:.2} GB in {} files", rb as f64 / 1e9, rf));
    b.case(t(Case::new("push, nothing new", g, &repo, &["push", "bench"]).env("VEIL_BENCH_RTT_MS", &rtt)), |_, _| Ok(()))?;
    b.case(t(Case::new("push, 1 new snapshot", g, &repo, &["push", "bench"]).env("VEIL_BENCH_RTT_MS", &rtt)), |b, _| {
        b.dirty(1)?;
        b.vl_ok(&b.repo.clone(), &["commit", "-m", "one more"])?;
        Ok(())
    })?;
    b.preflight(&format!("clone from {name}"), rb + tree)?;
    std::fs::create_dir_all(&clone_parent)?;
    let clone = clone_parent.join("c");
    b.case(Case::new("clone, full", g, &clone_parent, &["clone", &url, "c"]).runs(1).env("VEIL_BENCH_RTT_MS", &rtt), |_, _| Ok(()))?;
    if clone.join(".veil").exists() {
        let (cb, _) = du(&clone);
        b.note(format!("{name} clone: {:.2} GB on disk", cb as f64 / 1e9));
        b.case(t(Case::new("pull, 1 new snapshot", g, &clone, &["pull"]).env("VEIL_BENCH_RTT_MS", &rtt)), |b, _| {
            b.dirty(1)?;
            let repo = b.repo.clone();
            b.vl_ok(&repo, &["commit", "-m", "for pull"])?;
            b.env.ok(&repo, &["push", "bench"]).map(|_| ())
        })?;
        b.case(Case::new("pull, nothing new", g, &clone, &["pull"]).env("VEIL_BENCH_RTT_MS", &rtt), |_, _| Ok(()))?;
        b.case(Case::new("status in clone, clean", g, &clone, &["status"]), |_, _| Ok(()))?;
    }
    remove_tree(&clone_parent, &b.dir)?;
    let _ = b.env.run(&repo, &["remote", "rm", "bench"], false);
    remove_tree(&remote_dir, &b.dir)?;
    Ok(())
}

/// Push, clone and pull through the Veil server (`server`: started by the
/// caller; the repository's identity signs in as the project's admin, so
/// it may push the history it signed). Every case records the client's
/// and the server's peak RSS.
pub fn server(b: &mut Bench, server: &crate::server::Server) -> Result<()> {
    let repo = b.repo.clone();
    let project = format!("{}-{}", b.manifest["profile"].as_str().unwrap_or("bench"), std::process::id());
    let url = server.url(&project);
    let g = "server";
    let clone_parent = b.dir.join("clone-server");
    remove_tree(&clone_parent, &b.dir)?;
    let store = b.manifest["store_disk_bytes_loose"].as_u64().unwrap_or(2_000_000_000);
    let tree = b.manifest["tree_disk_bytes"].as_u64().unwrap_or(1_000_000_000);
    b.preflight("push to the server", store)?;
    let me = format!("bench-{}", std::process::id());
    b.vl_ok(&repo, &["login", &format!("veil://{}", server.authority), "--name", &me, "--ca", &s(&server.cert)])?;
    let _ = b.env.run(&repo, &["remote", "rm", "hub"], false);
    b.vl_ok(&repo, &["remote", "add", "hub", &url])?;
    b.server_pid = Some(server.pid());
    // A pushed change moves `main` (the server takes tags as branches).
    let commit_on_main = |b: &mut Bench, msg: &str| -> Result<()> {
        b.dirty(1)?;
        let repo = b.repo.clone();
        b.vl_ok(&repo, &["commit", "-m", msg])?;
        b.vl_ok(&repo, &["tag", "set", "main", "-r", "@-"]).map(|_| ())
    };
    let r = (|| -> Result<()> {
        let r = b.case(Case::new("push, initial (all tags)", g, &repo, &["push", "hub"]).runs(1), |_, _| Ok(()))?;
        if r.get("ok") != Some(&json!(true)) {
            push_in_steps(b, g)?;
            b.case(Case::new("push, all tags after the steps", g, &repo, &["push", "hub"]).runs(1), |_, _| Ok(()))?;
        }
        b.case(Case::new("push, nothing new", g, &repo, &["push", "hub"]), |_, _| Ok(()))?;
        b.case(Case::new("push, 1 new snapshot", g, &repo, &["push", "hub"]), |b, _| commit_on_main(b, "one more"))?;
        b.preflight("clone from the server", 2 * tree)?;
        std::fs::create_dir_all(&clone_parent)?;
        let clone = clone_parent.join("c");
        b.case(Case::new("clone, full", g, &clone_parent, &["clone", &url, "c"]).runs(1), |_, _| Ok(()))?;
        if clone.join(".veil").exists() {
            let (cb, _) = du(&clone);
            b.note(format!("server clone: {:.2} GB on disk", cb as f64 / 1e9));
            b.case(Case::new("pull, 1 new snapshot", g, &clone, &["pull"]), |b, _| {
                commit_on_main(b, "for pull")?;
                b.env.ok(&b.repo, &["push", "hub"]).map(|_| ())
            })?;
            b.case(Case::new("pull, nothing new", g, &clone, &["pull"]), |_, _| Ok(()))?;
            b.case(Case::new("status in clone, clean", g, &clone, &["status"]), |_, _| Ok(()))?;
            remove_tree(&clone, &b.dir)?;
        }
        // A fresh agent workspace: one top-level directory (about a tenth
        // of the tree), fetched on demand.
        b.case(Case::new("clone, one directory (--only docs)", g, &clone_parent, &["clone", &url, "o", "--only", "docs"]).runs(1), |_, _| Ok(()))?;
        Ok(())
    })();
    b.server_pid = None;
    remove_tree(&clone_parent, &b.dir)?;
    r
}

/// The server's copy of the history when the initial push fails
/// (BUG-857): `main` pushed along its first-parent line in fast-forward
/// steps (up to 512 snapshots each, fewer after a refused step), then put
/// back. Recorded as one case: the steps' total time and their largest
/// client and server peak RSS.
fn push_in_steps(b: &mut Bench, g: &str) -> Result<()> {
    let repo = b.repo.clone();
    let line: Vec<String> = std::fs::read_to_string(b.dir.join("mainline.txt"))?.lines().map(str::to_string).collect();
    let main = b.manifest["main"].as_str().unwrap_or_default().to_string();
    b.note("the initial push was refused: pushing `main` in fast-forward steps instead (BUG-857)");
    let (mut done, mut step, mut pushes, mut refused) = (0usize, 512usize, 0usize, 0usize);
    let (mut secs, mut rss, mut srss, mut sbefore) = (0.0f64, 0u64, None::<u64>, None::<u64>);
    let mut failure = None;
    while done < line.len() {
        check_stop()?;
        let to = (done + step).min(line.len());
        b.vl_ok(&repo, &["tag", "set", "main", "-r", &line[to - 1], "--allow-backwards"])?;
        if let Some(k) = b.server_pid.and_then(crate::server::reset_peak) {
            sbefore.get_or_insert(k);
        }
        let o = b.env.run_full(&repo, &["push", "hub", "-t", "main"], false, &[], Some(b.opts.timeout))?;
        pushes += 1;
        secs += o.secs;
        rss = rss.max(o.maxrss_kib);
        if let Some(k) = b.server_pid.and_then(crate::server::peak_kib) {
            srss = Some(srss.unwrap_or(0).max(k));
        }
        if o.ok() {
            done = to;
            step = (step * 2).min(512);
        } else if step > 1 {
            refused += 1;
            step = (step / 4).max(1);
        } else {
            failure = Some(o.stderr.lines().last().unwrap_or("").to_string());
            break;
        }
    }
    b.vl_ok(&repo, &["tag", "set", "main", "-r", &main, "--allow-backwards"])?;
    let name = "push, initial in steps along main (BUG-857)";
    b.say(&format!("  {name:<34} {secs:>9.3} s  {:>7.1} MiB, {pushes} pushes, {refused} refused", rss as f64 / 1024.0));
    b.cases.push(json!({
        "name": name, "group": g, "ok": failure.is_none(), "error": failure,
        "runs": [secs], "median_secs": secs, "spread": 0.0,
        "maxrss_mib": rss as f64 / 1024.0, "server_maxrss_mib": srss.map(|k| k as f64 / 1024.0),
        "server_rss_before_mib": sbefore.map(|k| k as f64 / 1024.0),
        "pushes": pushes, "refused": refused, "trace": null,
    }));
    match failure {
        Some(e) => Err(anyhow!("pushing in steps failed: {e}")),
        None => Ok(()),
    }
}

pub fn gc(b: &mut Bench) -> Result<()> {
    let repo = b.repo.clone();
    let store = b.manifest["store_disk_bytes_loose"].as_u64().unwrap_or(2_000_000_000);
    b.preflight("gc", store)?;
    b.case(Case::new("gc, first (packs the loose store)", "local", &repo, &["gc"]).runs(1), |_, _| Ok(()))?;
    let (sb, sf) = du(&repo.join(".veil"));
    b.manifest["store_disk_bytes_packed"] = json!(sb);
    b.manifest["store_files_packed"] = json!(sf);
    b.note(format!(".veil after gc: {:.2} GB in {} files", sb as f64 / 1e9, sf));
    b.case(Case::new("gc, again (nothing new)", "local", &repo, &["gc"]).runs(1), |_, _| Ok(()))?;
    Ok(())
}

/// Incremental maintenance (scale stream G2), after the packed-store cases:
/// one small commit, then `gc` packs the new objects and never rewrites
/// the big pack; then `gc --auto`.
pub fn gc_incremental(b: &mut Bench) -> Result<()> {
    let repo = b.repo.clone();
    let packs = |r: &Path| -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(r.join(".veil/objects/pack"))
            .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".pack")).collect())
            .unwrap_or_default();
        v.sort();
        v
    };
    let before = packs(&repo);
    std::fs::write(repo.join("bench-g2.txt"), b"one small change\n")?;
    let _ = b.env.run(&repo, &["commit", "-m", "one small change"], false)?;
    b.case(Case::new("gc, after one commit (incremental)", "local", &repo, &["gc"]).runs(1), |_, _| Ok(()))?;
    let after = packs(&repo);
    let kept = before.iter().filter(|p| after.contains(p)).count();
    b.note(format!("gc after one commit: {kept} of {} packs kept as they were, {} packs now", before.len(), after.len()));
    b.manifest["gc_incremental_packs_kept"] = json!(kept);
    b.manifest["gc_incremental_packs_before"] = json!(before.len());
    b.case(Case::new("gc --auto (background maintenance)", "local", &repo, &["gc", "--auto"]).runs(1), |_, _| Ok(()))?;
    Ok(())
}

/// Write the stand-in `ssh`: it ignores its arguments and runs a local
/// `sftp-server` (under strace when `VEIL_BENCH_STRACE` is set, behind the
/// RTT shim when `VEIL_BENCH_RTT_MS` is set).
pub fn write_fake_ssh(dir: &Path, server: &Path, me: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("fake-ssh");
    let script = format!(
        "#!/bin/sh\n# veil-bench stand-in for ssh: speaks SFTP on stdio with a local sftp-server.\n\
         S='{server}'\n\
         if [ -n \"$VEIL_BENCH_STRACE\" ]; then\n  set -- strace -f -qq -ttt -y -e trace={sys} -e signal=none -o \"$VEIL_BENCH_STRACE.sftp.$$\" \"$S\"\nelse\n  set -- \"$S\"\nfi\n\
         if [ -n \"$VEIL_BENCH_RTT_MS\" ] && [ \"$VEIL_BENCH_RTT_MS\" != 0 ]; then\n  exec '{me}' sftp-shim --rtt-ms \"$VEIL_BENCH_RTT_MS\" -- \"$@\"\nfi\n\
         exec \"$@\"\n",
        server = server.display(),
        me = me.display(),
        sys = proc::STRACE_SYSCALLS,
    );
    std::fs::write(&p, script)?;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))?;
    Ok(p)
}

pub fn sftp_server() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("VEIL_TEST_SFTP_SERVER") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/lib/openssh/sftp-server",
        "/usr/libexec/openssh/sftp-server",
        "/usr/libexec/sftp-server",
        "/usr/lib/ssh/sftp-server",
        "/usr/local/libexec/sftp-server",
        "/opt/homebrew/libexec/sftp-server",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

/// Machine and build facts every result records (threat 2).
pub fn machine_facts(vl: &Path, src: Option<&Path>) -> Value {
    let sh = |c: &str| {
        Command::new("sh").arg("-c").arg(c).output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
    };
    let commit = src
        .map(|d| sh(&format!("git -C '{}' rev-parse --short HEAD 2>/dev/null", d.display())))
        .unwrap_or_default();
    json!({
        "vl": s(vl),
        "vl_version": sh(&format!("'{}' --version | head -1", vl.display())),
        "commit": commit,
        "kernel": sh("uname -sr"),
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "cpu_model": sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2"),
        "mem_total": sh("grep MemTotal /proc/meminfo | awk '{print $2 \" kB\"}'"),
        "mem_available": sh("grep MemAvailable /proc/meminfo | awk '{print $2 \" kB\"}'"),
        "load": sh("cut -d' ' -f1-3 /proc/loadavg"),
        "date": sh("date -u +%Y-%m-%dT%H:%M:%SZ"),
        "cache": "warm",
    })
}

pub fn fs_type(p: &Path) -> String {
    Command::new("findmnt")
        .args(["-no", "FSTYPE", "-T"])
        .arg(p)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn elapsed(t: Instant) -> String {
    format!("{:.0} s", t.elapsed().as_secs_f64())
}

pub fn read_snapshots(dir: &Path) -> Result<HashSet<String>> {
    let text = std::fs::read_to_string(dir.join("snapshots.txt")).context("snapshots.txt")?;
    Ok(text.lines().map(str::to_string).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phase_stops_below_the_floor() {
        let gb = 1_000_000_000u64;
        assert!(enough_disk("x", 20 * gb, 6 * gb, 8 * gb).is_ok());
        let e = enough_disk("push", 13 * gb, 6 * gb, 8 * gb).unwrap_err().to_string();
        assert!(e.contains("stopping before push"), "{e}");
        assert!(enough_disk("x", 0, u64::MAX, 8 * gb).is_err());
    }

    #[test]
    fn removal_stays_inside_the_bench_directory() {
        let tmp = std::env::temp_dir().join(format!("veil-bench-test-{}", std::process::id()));
        let inside = tmp.join("a");
        std::fs::create_dir_all(&inside).unwrap();
        assert!(remove_tree(&tmp, &tmp).is_err(), "never the bench directory itself");
        assert!(remove_tree(Path::new("/etc"), &tmp).is_err());
        assert!(remove_tree(&tmp.join("../outside"), &tmp).is_err(), "no `..` escapes");
        remove_tree(&inside, &tmp).unwrap();
        assert!(!inside.exists());
        std::fs::remove_dir(&tmp).unwrap();
    }
}
