//! A fresh clone's set-up flushes (client speed round 5, BUG-1945): `vl
//! clone` into a directory it makes defers the flushes of `init` and its
//! transactions, and makes them all at once before the checkout's journal.
//! The guarantee kept: when `vl clone` returns, everything it wrote is
//! durable; an interruption at any point leaves no directory, or one `vl`
//! refuses or completes, never one that looks usable and is not.

use crate::support::*;

const REFUSED: &str = "is a clone that was interrupted before it fetched the project: remove it and clone again";

fn project(hub: &TestHub) -> (Person, String) {
    let admin = hub.person("admin");
    let name = unique("fresh");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    let files: Vec<(String, String)> = (0..40).map(|i| (format!("src/d{}/f{i}.txt", i % 4), format!("file {i}\n"))).collect();
    let pairs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    write_files(&dir, &pairs);
    admin.commit_main(&dir, "first");
    admin.ok(&dir, &["push"]);
    (admin, name)
}

/// A power cut where the most is deferred (everything fetched and set up,
/// nothing flushed): whatever of it survives (nothing, a few bytes of each
/// file, all of it), every command refuses the directory with the clone's
/// own refusal, and a clone made afterwards is complete (control).
#[test]
fn a_fresh_clone_cut_before_its_one_flush_is_refused_never_usable() {
    let hub = TestHub::start();
    let (admin, name) = project(&hub);
    for keep in ["0", "9", "1000000000"] {
        let d = admin.dir(&format!("cut-{keep}"));
        assert!(!d.exists());
        let out = admin
            .command(admin.home.path(), &["clone", &hub.url(&name), d.to_str().unwrap()])
            .env("VEIL_TEST_CLONE_POWER_CUT", keep)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(137), "keep {keep}: the cut was not reached: {}", String::from_utf8_lossy(&out.stderr));
        assert!(d.join(".veil/local/clone-incomplete").is_file(), "keep {keep}: the marker, durable before the deferral");
        assert!(!d.join("src").exists(), "keep {keep}: nothing is checked out before the flush");
        for args in [&["status"][..], &["log", "-n", "1"], &["pull"], &["commit", "-m", "x"]] {
            let r = admin.run(&d, args);
            assert!(!r.status.success(), "keep {keep}: {args:?} took the directory as usable");
            let err = String::from_utf8_lossy(&r.stderr);
            assert!(err.contains(REFUSED), "keep {keep}: {args:?}: {err}");
        }
    }
    let ok = admin.dir("whole");
    let out = admin.ok(admin.home.path(), &["clone", &hub.url(&name), ok.to_str().unwrap()]);
    assert!(out.contains("Cloned"), "{out}");
    assert!(!ok.join(".veil/local/clone-incomplete").exists());
    assert_eq!(std::fs::read_to_string(ok.join("src/d1/f5.txt")).unwrap(), "file 5\n");
    let st = admin.ok(&ok, &["status"]);
    assert!(st.contains("no changes"), "{st}");
}

/// The deferral is for a directory the clone makes only: into a directory
/// that was there (empty), the clone's flushes are made as before, and no
/// power cut is simulated (the hook is not reached).
#[test]
fn a_clone_into_a_directory_that_was_there_defers_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project(&hub);
    let d = admin.dir("there");
    std::fs::create_dir_all(&d).unwrap();
    let out = admin
        .command(admin.home.path(), &["clone", &hub.url(&name), d.to_str().unwrap()])
        .env("VEIL_TEST_CLONE_POWER_CUT", "0")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read_to_string(d.join("src/d2/f6.txt")).unwrap(), "file 6\n");
    assert!(!d.join(".veil/local/clone-incomplete").exists());
}
