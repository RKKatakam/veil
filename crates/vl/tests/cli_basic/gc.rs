//! `vl gc` end to end on a real directory.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

fn vl(home: &Path, cwd: &Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_vl"))
        .args(args)
        .current_dir(cwd)
        .env("VEIL_HOME", home)
        .env("VEIL_USER", "alice")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "vl {args:?} failed:\n{text}");
    text
}

fn loose_objects(proj: &Path) -> usize {
    let objects = proj.join(".veil/objects");
    std::fs::read_dir(&objects)
        .unwrap()
        .flatten()
        .filter(|d| d.file_name().len() == 2)
        .map(|d| std::fs::read_dir(d.path()).unwrap().count())
        .sum()
}

fn ops(proj: &Path) -> usize {
    std::fs::read_dir(proj.join(".veil/ops")).unwrap().count()
}

#[test]
fn gc_packs_prunes_and_keeps_the_repository_usable() {
    let tmp = tempfile::tempdir().unwrap();
    let home: PathBuf = tmp.path().join("home");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    vl(&home, &proj, &["init"]);
    for i in 0..5 {
        let body: String = (0..200).map(|l| format!("line {l} of version {i}\n")).collect();
        std::fs::write(proj.join("notes.txt"), body).unwrap();
        vl(&home, &proj, &["commit", "-m", &format!("v{i}")]);
    }
    std::fs::write(proj.join("scratch.txt"), "temporary\n").unwrap();
    vl(&home, &proj, &["status"]);
    std::fs::remove_file(proj.join("scratch.txt")).unwrap();
    assert!(loose_objects(&proj) > 10);

    // Keep every op: pack only.
    let out = vl(&home, &proj, &["gc"]);
    assert!(out.contains("0 deleted"), "{out}");
    assert!(out.contains("delta"), "{out}");
    assert_eq!(loose_objects(&proj), 0);

    // Prune the op log and delete immediately.
    let before_ops = ops(&proj);
    let out = vl(&home, &proj, &["gc", "--keep-ops-days", "0", "--prune-now"]);
    assert!(out.contains("Operations: pruned"), "{out}");
    assert!(ops(&proj) < before_ops);
    assert!(ops(&proj) >= 2, "the current op and its parent stay");

    // Everything still works.
    let log = vl(&home, &proj, &["log"]);
    assert!(log.contains("v4") && log.contains("v0"), "{log}");
    assert!(vl(&home, &proj, &["cat", "notes.txt", "-r", "@-"]).contains("version 4"));
    vl(&home, &proj, &["op", "log"]);
    vl(&home, &proj, &["evolog"]);
    std::fs::write(proj.join("after.txt"), "after gc\n").unwrap();
    vl(&home, &proj, &["commit", "-m", "after"]);
    vl(&home, &proj, &["undo"]);
    let st = vl(&home, &proj, &["status"]);
    assert!(st.contains("after.txt"), "{st}");

    // fsck (from the durability stream) understands packed and pruned repos.
    let out = vl(&home, &proj, &["fsck"]);
    assert!(out.contains("No corruption found"), "{out}");
}

/// Background maintenance (scale stream G2, threat 11): never with
/// `CI` set (or `VEIL_GC_AUTO=0`); otherwise one `vl gc --auto` once the
/// store needs it, detached, logging to `.veil/local/maintenance.log`, and
/// not again right after.
#[test]
fn background_maintenance_starts_only_where_allowed_and_once() {
    let tmp = tempfile::tempdir().unwrap();
    let home: PathBuf = tmp.path().join("home");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let run = |args: &[&str], ci: bool, auto: Option<&str>| {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_vl"));
        c.args(args).current_dir(&proj).env("VEIL_HOME", &home).env("VEIL_USER", "alice").env("NO_COLOR", "1").env_remove("CI").env_remove("VEIL_GC_AUTO");
        if ci {
            c.env("CI", "1");
        }
        if let Some(v) = auto {
            c.env("VEIL_GC_AUTO", v);
        }
        let out = c.output().unwrap();
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    run(&["init"], true, None);
    // More loose objects than the threshold, in commits small enough to
    // write loose objects (a transaction with many new objects writes a
    // pack instead).
    for batch in 0..40 {
        for i in 0..225 {
            std::fs::write(proj.join(format!("f{batch}-{i}.txt")), format!("file {batch} {i}\n")).unwrap();
        }
        run(&["commit", "-m", "many"], true, None);
    }
    let log = proj.join(".veil/local/maintenance.log");
    assert!(!log.exists(), "maintenance started with CI set");
    run(&["status"], false, Some("0"));
    assert!(!log.exists(), "maintenance started with VEIL_GC_AUTO=0");
    run(&["status"], false, None);
    assert!(wait_until(|| std::fs::read_to_string(&log).is_ok_and(|l| l.contains("packed"))), "no background run");
    run(&["status"], false, None);
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(text.matches("vl gc --auto").count(), 1, "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

fn wait_until(mut f: impl FnMut() -> bool) -> bool {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while std::time::Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}
