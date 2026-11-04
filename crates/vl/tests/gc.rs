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
