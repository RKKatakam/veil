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
    proc::{check_stop, du, free_bytes, remove_tree, Outcome, VlEnv},
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
        let mut last = Outcome::default();
        for i in 0..runs {
            prep(self, i)?;
            let o = self.env.run_full(&c.cwd, &args, false, &env, Some(self.opts.timeout))?;
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
        self.say(&format!("  {:<34} {:>9.3} s  {:>7.1} MiB{}", c.name, med, rss as f64 / 1024.0, tr));
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
    let fix = b.manifest["fix_tip"].as_str().unwrap_or_default().to_string();
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
