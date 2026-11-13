//! No `vl ws exec` failure deletes the command's unrecorded output.
//!
//! A matrix over the failure points of a persistent sandbox run (`vl`
//! terminated, hung up on, killed; the repository lock busy when recording;
//! an unreadable policy; a rebuild after a restart or after a sync that
//! never finished) × full and sparse sandboxes × with and without injected
//! secrets. In every case the command's output is either recorded or still
//! on disk (in the sandbox, or in a directory a rebuild kept), never gone;
//! and once the failure is over, the next run or `--record-only` records
//! it, without ever recording an injected secret.

use crate::adversarial_support;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use adversarial_support::*;
use veil_core::{lock::RepoLock, DiskBackend};

const SECRET: &str = "failure-matrix-Secret-Value-7731";

fn sandbox(proj: &Path) -> PathBuf {
    proj.join(".veil/local/sandboxes/agent")
}

fn project(env: &Env) -> PathBuf {
    let proj = env.project("alice", "proj", &[("a.txt", "a\n"), ("src/lib.rs", "pub fn f() {}\n"), ("docs/d.md", "d\n")]);
    write(&proj, ".netrc", &format!("API_TOKEN={SECRET}\n"));
    env.ok("alice", &proj, &["commit", "-m", "env"]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
    proj
}

fn cat(env: &Env, proj: &Path, path: &str) -> Option<String> {
    let o = env.vl("alice", proj, &["cat", "-r", "agent@", path]);
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Every copy of `path` on disk under the sandbox: in `files/`, or in a
/// directory a rebuild kept whole.
fn on_disk(proj: &Path, path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(sandbox(proj)) else { return out };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n == "files" || n.starts_with("unrecorded-") || n.starts_with("files.rebuild-") {
            if let Ok(c) = std::fs::read_to_string(e.path().join(path)) {
                out.push(c);
            }
        }
    }
    out
}

/// The invariant: the output is recorded, or still on disk.
/// The exit status a run that finished must have: 3 while the sandbox
/// holds the quarantined `creds.txt` and the run covers it (`full`: not
/// `--only src`), as `vl commit` (BUG-2171); 0 otherwise.
fn expected(proj: &Path, full: bool) -> Option<i32> {
    Some(if full && sandbox(proj).join("files/creds.txt").exists() { 3 } else { 0 })
}

fn survives(env: &Env, proj: &Path, path: &str, content: &str) -> bool {
    cat(env, proj, path).as_deref() == Some(content) || on_disk(proj, path).iter().any(|c| c == content)
}

/// No file the workspace records holds the injected secret.
fn secret_never_recorded(env: &Env, proj: &Path, tag: &str) {
    let files = env.stdout("alice", proj, &["files", "-r", "agent@"]);
    for path in files.lines().filter_map(|l| l.split_whitespace().rfind(|t| *t != "*")) {
        let c = cat(env, proj, path).unwrap_or_default();
        assert!(!c.contains(SECRET), "{tag}: the injected secret was recorded in {path}");
    }
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    /// SIGTERM to `vl` while the command runs.
    Term,
    /// SIGHUP to `vl` (a closed terminal).
    Hup,
    /// `kill -9` of `vl` (the confinement stops the command with it).
    Kill,
    /// `kill -9`, then the machine "restarts" before the next run.
    KillThenReboot,
    /// Another process holds the repository lock past the recording's wait.
    BusyLock,
    /// The command leaves `.veilpolicy` unreadable.
    UnreadablePolicy,
    /// The command deletes `.veilpolicy`.
    DeletedPolicy,
    /// A later run dies in its sync (the `running` marker is left), with
    /// quarantined work and hand edits in the sandbox: rebuilt.
    InterruptedSync,
}

struct Case {
    failure: Failure,
    sparse: bool,
    injected: bool,
}

fn run_case(c: &Case) {
    let env = Env::new();
    let proj = project(&env);
    let tag = format!("{:?}-{}-{}", c.failure, c.sparse, c.injected);
    // The command's output lands inside the set either way.
    let out_path = "src/out.txt";
    let content = format!("an hour of agent work ({tag})\n");
    let mut args: Vec<String> = vec!["ws".into(), "exec".into(), "agent".into()];
    if c.sparse {
        args.extend(["--only".into(), "src".into()]);
    }
    if c.injected {
        args.push("--with-isolated".into());
    }
    // In the sandbox: the confined command sees nothing else. The test
    // removes it as soon as it sees it.
    let started = sandbox(&proj).join("files/.started");
    let extra = match c.failure {
        Failure::UnreadablePolicy => "chmod 000 .veilpolicy;",
        Failure::DeletedPolicy => "rm .veilpolicy;",
        _ => "",
    };
    let script = format!(
        "printf '%s' '{content}' > {out_path}; {extra} {copy} touch .started; sleep 2",
        copy = if c.injected { "cp .netrc src/leak.txt; mkdir -p target; cp .netrc target/app.env;" } else { "" },
    );
    args.extend(["--".into(), "sh".into(), "-c".into(), script]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();

    // A first, ordinary run so that the sandbox exists.
    env.ok("alice", &proj, &["ws", "exec", "agent", "--", "true"]);

    match c.failure {
        Failure::Term | Failure::Hup | Failure::Kill | Failure::KillThenReboot => {
            let mut child = env.spawn("alice", &proj, &argv);
            assert!(wait_for(Duration::from_secs(30), || started.exists()), "{tag}: never started");
            let _ = std::fs::remove_file(&started);
            let sig = match c.failure {
                Failure::Term => libc::SIGTERM,
                Failure::Hup => libc::SIGHUP,
                _ => libc::SIGKILL,
            };
            // SAFETY: signals our own child.
            unsafe {
                libc::kill(child.id() as i32, sig);
            }
            let o = child.wait().unwrap();
            // Let the command finish (and the reaper act) on its own.
            std::thread::sleep(Duration::from_secs(3));
            assert!(survives(&env, &proj, out_path, &content), "{tag}: the output is gone after the signal ({o:?})");
            if matches!(c.failure, Failure::Term | Failure::Hup) {
                // Forwarded to the command; `vl` recorded what it left.
                assert_eq!(cat(&env, &proj, out_path).as_deref(), Some(content.as_str()), "{tag}: not recorded");
            }
            if let Failure::KillThenReboot = c.failure {
                let mpath = sandbox(&proj).join("manifest.json");
                let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&mpath).unwrap()).unwrap();
                assert!(m.get("pending").is_some(), "{tag}: the killed run is not marked unrecorded: {m}");
                m["boot"] = "an-earlier-boot".into();
                std::fs::write(&mpath, serde_json::to_vec(&m).unwrap()).unwrap();
            }
        }
        Failure::BusyLock => {
            let mut child = env.spawn("alice", &proj, &argv);
            assert!(wait_for(Duration::from_secs(30), || started.exists()), "{tag}: never started");
            let _ = std::fs::remove_file(&started);
            let backend: Arc<dyn veil_core::StorageBackend> = Arc::new(DiskBackend::new(&proj));
            let lock = RepoLock::acquire(backend).expect("lock");
            let o = child.wait().unwrap();
            // Format 6: recording takes no repository lock (BUG-551 is
            // gone): a held lock (`vl gc`, a key-ring change) delays nothing.
            assert!(o.success(), "{tag}: recording waited for the repository lock ({o:?})");
            assert_eq!(cat(&env, &proj, out_path).as_deref(), Some(content.as_str()), "{tag}: not recorded");
            drop(lock);
        }
        Failure::UnreadablePolicy | Failure::DeletedPolicy => {
            let o = env.vl("alice", &proj, &argv);
            assert!(o.status.success(), "{tag}: {}", text(&o));
            assert_eq!(cat(&env, &proj, out_path).as_deref(), Some(content.as_str()), "{tag}: {}", text(&o));
            assert!(
                env.stdout("alice", &proj, &["files", "-r", "agent@"]).contains(".veilpolicy"),
                "{tag}: the policy was recorded as deleted"
            );
            // Make the sandbox usable again for the checks below.
            let _ = std::fs::set_permissions(
                sandbox(&proj).join("files/.veilpolicy"),
                std::os::unix::fs::PermissionsExt::from_mode(0o644),
            );
        }
        Failure::InterruptedSync => {
            // Quarantined work, a hand edit outside the set, and the
            // command's output inside it, all unrecorded…
            env.quarantined(
                "alice",
                &proj,
                &[
                    "ws",
                    "exec",
                    "agent",
                    "--",
                    "sh",
                    "-c",
                    "echo 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' > creds.txt",
                ],
            );
            let o = env.vl("alice", &proj, &argv);
            assert_eq!(o.status.code(), expected(&proj, !c.sparse), "{tag}: {}", text(&o));
            if c.sparse {
                write(&sandbox(&proj).join("files"), "docs/hand.md", "edited by hand\n");
            }
            // …then a run dies in its sync.
            let mpath = sandbox(&proj).join("manifest.json");
            let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&mpath).unwrap()).unwrap();
            m["running"] = "deadbeef".into();
            std::fs::write(&mpath, serde_json::to_vec(&m).unwrap()).unwrap();
            let o = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
            assert_eq!(o.status.code(), expected(&proj, true), "{tag}: {}", text(&o));
            assert!(text(&o).contains("Rebuilding"), "{tag}: {}", text(&o));
            assert!(survives(&env, &proj, "creds.txt", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"), "{tag}: quarantined work lost");
            if c.sparse {
                assert!(survives(&env, &proj, "docs/hand.md", "edited by hand\n"), "{tag}: the hand edit outside the set was lost");
            }
        }
    }

    // The failure is over: the next run (or --record-only) records it, or
    // it is kept aside whole.
    let o = env.vl("alice", &proj, &["ws", "exec", "agent", "--record-only"]);
    assert!(o.status.success(), "{tag}: --record-only: {}", text(&o));
    let o = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "true"]);
    assert_eq!(o.status.code(), expected(&proj, true), "{tag}: next run: {}", text(&o));
    match c.failure {
        // A run that cannot be recorded after a restart (its files may be
        // torn) is kept whole, not recorded.
        Failure::KillThenReboot => assert!(
            on_disk(&proj, out_path).contains(&content),
            "{tag}: the output was not kept aside: {}",
            text(&o)
        ),
        _ => assert_eq!(cat(&env, &proj, out_path).as_deref(), Some(content.as_str()), "{tag}: not recorded: {}", text(&o)),
    }
    if c.injected {
        secret_never_recorded(&env, &proj, &tag);
        let left = tree_with(&sandbox(&proj).join("files"), SECRET);
        assert!(left.is_empty(), "{tag}: copies of the injected secret left in the sandbox: {left:?}");
    }
}

/// Files under `dir` (recursively, symlinks not followed) containing `needle`.
fn tree_with(dir: &Path, needle: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => stack.push(p),
                Ok(m) if m.is_file() && std::fs::read(&p).is_ok_and(|d| d.windows(needle.len()).any(|w| w == needle.as_bytes())) => {
                    out.push(p)
                }
                _ => {}
            }
        }
    }
    out
}

#[test]
fn no_failure_deletes_the_commands_output() {
    let failures = [
        Failure::Term,
        Failure::Hup,
        Failure::Kill,
        Failure::KillThenReboot,
        Failure::BusyLock,
        Failure::UnreadablePolicy,
        Failure::DeletedPolicy,
        Failure::InterruptedSync,
    ];
    let mut cases = Vec::new();
    for failure in failures {
        for sparse in [false, true] {
            for injected in [false, true] {
                cases.push(Case { failure, sparse, injected });
            }
        }
    }
    // Independent repositories: run them side by side (the lock timeout
    // alone takes 15 s).
    let handles: Vec<_> = cases
        .into_iter()
        .map(|c| std::thread::spawn(move || run_case(&c)))
        .collect();
    let mut failed = Vec::new();
    for h in handles {
        if let Err(e) = h.join() {
            failed.push(
                e.downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default(),
            );
        }
    }
    assert!(failed.is_empty(), "{} case(s) failed:\n{}", failed.len(), failed.join("\n\n"));
}
