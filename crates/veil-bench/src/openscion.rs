//! The OpenScion workloads, Veil's speed gates (`docs/OVERVIEW.md`, "Speed
//! gates"): repositories of 4 KiB files (1,000 and 10,000), and four
//! operations, each the median of `runs` separate processes, with Git on the
//! same machine as the reference.
//!
//! | case | Veil | Git |
//! |---|---|---|
//! | import a directory (first snapshot) | `vl init` | `git init && git add -A && git commit` |
//! | clone everything | `vl clone veil://…` (the server, PostgreSQL) | `git clone --no-local file://…` |
//! | commit one changed file | `vl commit -m` | `git commit -qam` |
//! | clone one directory | `vl clone veil://… --only DIR` | `git clone --filter=blob:none --sparse` + `sparse-checkout set DIR` |
//!
//! Files sit in directories of 100 (`d000/f000.txt` …), so "one directory"
//! is 100 files at both sizes. Both clones always go through the server:
//! a release `veil-server` started here (`server.rs`), on `127.0.0.1` over
//! TLS, with the PostgreSQL the caller names and objects in S3 (MinIO) or a
//! local directory. The clones sign in as the project's admin.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

use anyhow::{anyhow, bail, Result};
use serde_json::json;

pub struct Args {
    pub vl: PathBuf,
    pub server: crate::server::ServerArgs,
    pub dir: PathBuf,
    pub sizes: Vec<usize>,
    pub runs: usize,
}

/// The targets (ms) by size: import, clone everything, commit one file,
/// clone one directory.
fn targets(files: usize) -> [f64; 4] {
    match files {
        1_000 => [22.0, 51.0, 2.5, 6.1],
        10_000 => [245.0, 544.0, 22.0, 25.0],
        _ => [f64::NAN; 4],
    }
}

fn time(cmd: &mut Command) -> Result<f64> {
    let t = Instant::now();
    let out = cmd.stdout(Stdio::null()).stderr(Stdio::piped()).output()?;
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    if !out.status.success() {
        bail!("{cmd:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(ms)
}

fn run(cmd: &mut Command) -> Result<()> {
    time(cmd).map(|_| ())
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// The files of a repository of `files` 4 KiB files in directories of
/// 100: `(d000/f000.txt, content)`.
fn files_of(files: usize, seed: u64) -> Vec<(String, String)> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..files)
        .map(|i| {
            let mut body = String::with_capacity(4096);
            while body.len() < 4096 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                body.push_str(&format!("{:016x} ", x));
            }
            body.truncate(4095);
            body.push('\n');
            (format!("d{:03}/f{:03}.txt", i / 100, i % 100), body)
        })
        .collect()
}

/// A repository of `files` 4 KiB files in directories of 100.
pub(crate) fn generate(dir: &Path, files: usize, seed: u64) -> Result<()> {
    for (path, body) in files_of(files, seed) {
        let p = dir.join(path);
        std::fs::create_dir_all(p.parent().expect("in a directory"))?;
        std::fs::write(p, body)?;
    }
    Ok(())
}

pub fn run_all(a: &Args) -> Result<serde_json::Value> {
    std::fs::create_dir_all(&a.dir)?;
    let home = a.dir.join("home");
    let vl = |cwd: &Path| {
        let mut c = Command::new(&a.vl);
        c.current_dir(cwd).env("VEIL_HOME", &home).env("NO_COLOR", "1");
        c
    };
    let git = |cwd: &Path| {
        let mut c = Command::new("git");
        c.current_dir(cwd)
            .env("GIT_AUTHOR_NAME", "bench")
            .env("GIT_AUTHOR_EMAIL", "bench@example.com")
            .env("GIT_COMMITTER_NAME", "bench")
            .env("GIT_COMMITTER_EMAIL", "bench@example.com")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &a.dir);
        c
    };
    let server = crate::server::Server::start(&a.server, &a.dir.join("server"), 32)?;
    let hub = format!("veil://{}", server.authority);
    let tag = server.pid();
    run(vl(&a.dir).args(["login", &hub, "--name", &format!("bench{tag}"), "--ca"]).arg(&server.cert))?;
    let (mut cases, mut bytes) = (Vec::new(), Vec::new());
    for &files in &a.sizes {
        let name = format!("os{files}-{tag}");
        let src = a.dir.join(format!("src-{files}"));
        generate(&src, files, files as u64)?;
        let mut veil = [vec![], vec![], vec![], vec![]];
        let mut gits = [vec![], vec![], vec![], vec![]];
        // Import: a fresh copy each run.
        for r in 0..a.runs {
            let d = a.dir.join(format!("imp-{files}-{r}"));
            copy_dir(&src, &d)?;
            veil[0].push(time(vl(&d).arg("init"))?);
            let g = a.dir.join(format!("gimp-{files}-{r}"));
            copy_dir(&src, &g)?;
            let t = Instant::now();
            run(git(&g).args(["init", "-q"]))?;
            run(git(&g).args(["add", "-A"]))?;
            run(git(&g).args(["commit", "-qm", "import"]))?;
            gits[0].push(t.elapsed().as_secs_f64() * 1000.0);
        }
        // The project on the server, and the Git origin.
        let proj = a.dir.join(format!("imp-{files}-0"));
        run(vl(&proj).args(["remote", "add", "origin", &format!("{hub}/{name}")]))?;
        run(vl(&proj).args(["commit", "-m", "import"]))?;
        run(vl(&proj).args(["tag", "set", "main", "-r", "@-"]))?;
        // The server's bytes read and written by the push and by the first
        // clone of everything (bytes received and stored; bytes sent).
        let io = || crate::server::io_bytes(tag).unwrap_or_default();
        let before = io();
        run(vl(&proj).args(["push"]))?;
        let after = io();
        let mut push_io = json!({ "push_server_read_bytes": after.0.saturating_sub(before.0), "push_server_written_bytes": after.1.saturating_sub(before.1) });
        let gorigin = a.dir.join(format!("gimp-{files}-0"));
        run(git(&gorigin).args(["config", "uploadpack.allowFilter", "true"]))?;
        // Commit one changed file.
        for r in 0..a.runs {
            std::fs::write(proj.join("d001/f001.txt"), format!("change {r}\n"))?;
            veil[2].push(time(vl(&proj).args(["commit", "-m", &format!("one file {r}")]))?);
            std::fs::write(gorigin.join("d001/f001.txt"), format!("change {r}\n"))?;
            gits[2].push(time(git(&gorigin).args(["commit", "-qam", &format!("one file {r}")]))?);
        }
        // Clone everything, and one directory.
        for r in 0..a.runs {
            let d = a.dir.join(format!("clone-{files}-{r}"));
            let before = io();
            veil[1].push(time(vl(&a.dir).args(["clone", &format!("{hub}/{name}")]).arg(&d))?);
            if r == 0 {
                let after = io();
                push_io["clone_server_read_bytes"] = json!(after.0.saturating_sub(before.0));
                push_io["clone_server_written_bytes"] = json!(after.1.saturating_sub(before.1));
            }
            let d = a.dir.join(format!("only-{files}-{r}"));
            veil[3].push(time(vl(&a.dir).args(["clone", &format!("{hub}/{name}")]).arg(&d).args(["--only", "d005"]))?);
            let g = a.dir.join(format!("gclone-{files}-{r}"));
            gits[1].push(time(git(&a.dir).args(["clone", "-q", "--no-local", &format!("file://{}", gorigin.display())]).arg(&g))?);
            let g = a.dir.join(format!("gonly-{files}-{r}"));
            let t = Instant::now();
            run(git(&a.dir)
                .args(["clone", "-q", "--filter=blob:none", "--sparse", "--no-local", &format!("file://{}", gorigin.display())])
                .arg(&g))?;
            run(git(&g).args(["sparse-checkout", "set", "d005"]))?;
            gits[3].push(t.elapsed().as_secs_f64() * 1000.0);
            let files_out = count_files(&a.dir.join(format!("only-{files}-{r}")))?;
            if files_out != 100 {
                bail!("vl clone --only wrote {files_out} files, not 100");
            }
        }
        eprintln!("{files} files, server bytes: {push_io}");
        push_io["files"] = json!(files);
        bytes.push(push_io);
        let t = targets(files);
        for (i, case) in ["import a directory", "clone everything (server)", "commit one changed file", "clone one directory (server)"]
            .iter()
            .enumerate()
        {
            let v = median(veil[i].clone());
            let g = median(gits[i].clone());
            cases.push(json!({
                "files": files, "case": case, "veil_ms": v, "git_ms": g, "target_ms": t[i],
                "meets_target": v <= t[i], "beats_git": v <= g, "runs": a.runs,
            }));
        }
    }
    Ok(json!({ "profile": "openscion", "objects": if a.server.s3_endpoint.is_some() { "s3" } else { "directory" }, "cases": cases, "bytes": bytes }))
}

/// The workloads measured as OpenScion measures its own numbers
/// (`benchmarks/README.md` of tinyhumansai/openscion): in one process, in
/// memory (a `MemoryBackend`), so no process start, no disk and no fsync,
/// for a like-for-like comparison of the design with its targets. The
/// engine work is the same as `vl`'s (secret scanning, sealing, the stat
/// cache, the op log); packing and compression are not skipped either.
///
/// | case | in process |
/// |---|---|
/// | import a directory | `Repo::init`, then the first snapshot |
/// | commit one changed file | one file written, the snapshot, the commit |
/// | clone everything | `init_for_clone`, a pull of every object, the checkout |
///
/// "Clone one directory" fetches on demand from the server; it has no
/// in-memory equivalent here.
pub fn run_in_memory(sizes: &[usize], runs: usize) -> Result<serde_json::Value> {
    use std::sync::Arc;
    use veil_core::{remote, statcache::StatCache, Identity, MemoryBackend, Repo, StorageBackend, VPath};
    let id = Identity::generate("bench");
    let ms = |t: Instant| t.elapsed().as_secs_f64() * 1000.0;
    let mut cases = Vec::new();
    for &files in sizes {
        let tree = files_of(files, files as u64);
        let fill = |fs: &MemoryBackend| -> Result<()> {
            for (path, body) in &tree {
                fs.write(&VPath::new(path)?, body.as_bytes())?;
            }
            Ok(())
        };
        let (mut import, mut commit, mut clone) = (vec![], vec![], vec![]);
        let mut kept = None;
        for _ in 0..runs {
            let fs = Arc::new(MemoryBackend::new());
            fill(&fs)?;
            let mut cache = StatCache::new();
            let t = Instant::now();
            let mut repo = Repo::init(fs.clone(), Some(id.clone()), "bench")?;
            repo.snapshot_workspace_cached("default", &*fs, Some(&mut cache))?;
            import.push(ms(t));
            kept.get_or_insert((fs, repo, cache));
        }
        let (fs, mut repo, mut cache) = kept.ok_or_else(|| anyhow!("no runs"))?;
        let (c, _) = repo.commit_working_copy("default", "import")?;
        repo.set_tag("main", c, false)?;
        for r in 0..runs {
            let t = Instant::now();
            fs.write(&VPath::new("d001/f001.txt")?, format!("change {r}\n").as_bytes())?;
            repo.snapshot_workspace_cached("default", &*fs, Some(&mut cache))?;
            repo.commit_working_copy("default", &format!("one file {r}"))?;
            commit.push(ms(t));
        }
        let main = repo.view().tags["main"].target;
        let source: Arc<dyn StorageBackend> = fs.clone();
        for _ in 0..runs {
            let to = Arc::new(MemoryBackend::new());
            let t = Instant::now();
            let mut c = Repo::init_for_clone(to.clone(), Some(id.clone()), "bench")?;
            remote::pull(&mut c, "origin", source.clone())?;
            let target = c.snapshot(&main)?.tree;
            veil_core::checkout::checkout(c.store(), &*to, None, &target)?;
            clone.push(ms(t));
            if !to.exists(&VPath::new("d001/f002.txt")?)? {
                bail!("the in-memory clone wrote no files");
            }
        }
        let t = targets(files);
        for (case, v, target) in [
            ("import a directory", import, t[0]),
            ("clone everything", clone, t[1]),
            ("commit one changed file", commit, t[2]),
        ] {
            let v = median(v);
            cases.push(json!({ "files": files, "case": case, "veil_memory_ms": v, "target_ms": target, "meets_target": v <= target, "runs": runs }));
        }
    }
    Ok(json!({ "profile": "openscion-memory", "cases": cases }))
}

/// [`run_in_memory`]'s results as a Markdown table.
pub fn markdown_in_memory(v: &serde_json::Value) -> Result<String> {
    let mut out = String::from("| Files | Workload | Veil in memory, in process (ms) | Target (ms) | Meets target |\n|---:|---|---:|---:|---|\n");
    for c in v["cases"].as_array().ok_or_else(|| anyhow!("no cases"))? {
        out.push_str(&format!(
            "| {} | {} | {:.2} | {} | {} |\n",
            c["files"],
            c["case"].as_str().unwrap_or(""),
            c["veil_memory_ms"].as_f64().unwrap_or(f64::NAN),
            c["target_ms"],
            if c["meets_target"] == json!(true) { "yes" } else { "no" },
        ));
    }
    Ok(out)
}

fn count_files(dir: &Path) -> Result<usize> {
    let mut n = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)? {
            let e = e?;
            if e.file_name() == ".veil" || e.file_name() == ".veilpolicy" {
                continue;
            }
            if e.file_type()?.is_dir() {
                stack.push(e.path());
            } else {
                n += 1;
            }
        }
    }
    Ok(n)
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let t = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &t)?;
        } else {
            std::fs::copy(e.path(), &t)?;
        }
    }
    Ok(())
}

/// The results as a Markdown table.
pub fn markdown(v: &serde_json::Value) -> Result<String> {
    let mut out = String::from(
        "| Files | Workload | Veil (ms) | Git (ms) | Target (ms) | Meets target | Beats Git |\n|---:|---|---:|---:|---:|---|---|\n",
    );
    for c in v["cases"].as_array().ok_or_else(|| anyhow!("no cases"))? {
        out.push_str(&format!(
            "| {} | {} | {:.1} | {:.1} | {} | {} | {} |\n",
            c["files"],
            c["case"].as_str().unwrap_or(""),
            c["veil_ms"].as_f64().unwrap_or(f64::NAN),
            c["git_ms"].as_f64().unwrap_or(f64::NAN),
            c["target_ms"],
            if c["meets_target"] == json!(true) { "yes" } else { "no" },
            if c["beats_git"] == json!(true) { "yes" } else { "no" },
        ));
    }
    let mib = |b: &serde_json::Value| b.as_f64().unwrap_or(f64::NAN) / 1048576.0;
    out.push_str("\n| Files | Server read by the push (MiB) | Server wrote by the push | Server wrote by a clone |\n|---:|---:|---:|---:|\n");
    for b in v["bytes"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "| {} | {:.2} | {:.2} | {:.2} |\n",
            b["files"],
            mib(&b["push_server_read_bytes"]),
            mib(&b["push_server_written_bytes"]),
            mib(&b["clone_server_written_bytes"]),
        ));
    }
    Ok(out)
}
