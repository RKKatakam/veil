//! Sync through the server: clone one directory, pull what others push,
//! secrets keys granted and rotated by group changes, and signatures that
//! verify in every viewer's history.

use std::sync::Arc;

use crate::support::*;

#[test]
fn clone_one_directory_fetches_only_that_subtree() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.fin.dir("only");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap(), "--only", BILL_DIR]);
    assert!(d.join(BILL_DIR).join("acme/invoice.txt").exists());
    assert!(!d.join("src/lib.rs").exists(), "a file outside --only was written");
    let objects = everything_in(&d);
    assert!(!has_marker(&objects, PUBLIC_MARK), "an object outside --only was fetched");
    // Edit and push from the one-directory clone; the rest is kept.
    write_files(&d, &[(&format!("{BILL_DIR}/acme/invoice.txt") as &str, "from a partial clone")]);
    p.fin.commit_main(&d, "partial edit");
    p.fin.ok(&d, &["push"]);
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    assert_eq!(std::fs::read_to_string(p.dir.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    assert_eq!(std::fs::read_to_string(p.dir.join(BILL_DIR).join("acme/invoice.txt")).unwrap(), "from a partial clone");
}

/// BUG-830 for a one-directory clone: killed during its checkout, the
/// next command finishes it (only the directory, whose objects are the
/// only ones fetched) and records nothing as deleted.
#[test]
fn a_one_directory_clone_killed_during_its_checkout_is_finished() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let files: Vec<String> = (0..3000).map(|i| format!("{BILL_DIR}/bulk/d{:02}/f{i:04}.txt", i / 100)).collect();
    let pairs: Vec<(&str, &str)> = files.iter().map(|f| (f.as_str(), f.as_str())).collect();
    write_files(&p.dir, &pairs);
    p.admin.commit_main(&p.dir, "bulk");
    p.admin.ok(&p.dir, &["push"]);
    let mut interrupted = 0;
    for attempt in 0..8 {
        let d = p.fin.dir(&format!("only{attempt}"));
        let mut child = p
            .fin
            .command(p.fin.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap(), "--only", &format!("{BILL_DIR}/bulk")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let started = |d: &std::path::Path| std::fs::read_dir(d).is_ok_and(|r| r.flatten().any(|e| e.file_name() != ".veil"));
        while child.try_wait().unwrap().is_none() && !started(&d) {
            assert!(std::time::Instant::now() < deadline, "the clone neither started its checkout nor ended");
        }
        let _ = child.kill();
        if child.wait().unwrap().success() {
            continue;
        }
        interrupted += 1;
        let status = p.fin.ok(&d, &["status"]);
        assert!(!status.lines().any(|l| l.trim_start().starts_with("D ")), "attempt {attempt}: recorded as deleted:\n{status}");
        for f in &files {
            assert_eq!(std::fs::read_to_string(d.join(f)).ok().as_deref(), Some(f.as_str()), "attempt {attempt}: {f}");
        }
        assert!(!d.join("src/lib.rs").exists() && !d.join(BILL_DIR).join("acme").exists(), "a file outside --only was written");
        assert!(!has_marker(&everything_in(&d), PUBLIC_MARK), "an object outside --only was fetched");
        // Its next push keeps everything outside the directory.
        write_files(&d, &[(files[0].as_str(), "after the crash")]);
        p.fin.commit_main(&d, "edit after a crash");
        p.fin.ok(&d, &["push"]);
        p.admin.ok(&p.dir, &["pull"]);
        p.admin.ok(&p.dir, &["new", "main"]);
        assert_eq!(std::fs::read_to_string(p.dir.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
        assert_eq!(std::fs::read_to_string(p.dir.join(&files[0])).unwrap(), "after the crash");
        assert!(p.dir.join(&files[1]).exists() && p.dir.join(BILL_DIR).join(".env").exists());
        break;
    }
    assert!(interrupted > 0, "no clone was interrupted during its checkout (each finished first)");
}

/// BUG-832. A one-directory clone of a folder holding a secret: the
/// project's `.veilpolicy` (at the root) is not on disk, so the secret is
/// taken for a local-only file and its sealed version recorded as deleted.
/// Harm: the clone's next push deletes the folder's `.env` for everyone.
#[test]
#[ignore = "BUG-832: a --only clone records the folder's secrets as deleted"]
fn bug_832_a_one_directory_clone_keeps_the_folders_secrets() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.fin.dir("only");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap(), "--only", BILL_DIR]);
    assert!(std::fs::read_to_string(d.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
    let st = p.fin.ok(&d, &["status"]);
    assert!(!st.contains("D "), "{st}");
    write_files(&d, &[(&format!("{BILL_DIR}/acme/invoice.txt") as &str, "from a partial clone")]);
    p.fin.commit_main(&d, "partial edit");
    p.fin.ok(&d, &["push"]);
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    let env = std::fs::read_to_string(p.dir.join(BILL_DIR).join(".env")).unwrap_or_default();
    assert!(env.contains(ENV_MARK), "the push from the partial clone deleted the folder's secret");
}

#[test]
fn people_see_each_others_pushes_and_every_signature_verifies() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    write_files(&d, &[("src/dev.rs", "fn dev() {}")]);
    p.dev.commit_main(&d, "dev change");
    p.dev.ok(&d, &["push"]);
    let f = p.fin.dir("c");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), f.to_str().unwrap()]);
    assert!(f.join("src/dev.rs").exists());
    write_files(&f, &[(&format!("{BILL_DIR}/q.txt") as &str, "q")]);
    p.fin.commit_main(&f, "finance change");
    p.fin.ok(&f, &["push"]);
    p.dev.ok(&d, &["pull"]);
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    assert!(p.dir.join(BILL_DIR).join("q.txt").exists() && p.dir.join("src/dev.rs").exists());
    // Every snapshot each viewer holds carries a valid signature: the
    // author's, or the server's on a projection.
    for dir in [&d, &f, &p.dir] {
        let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(dir)), None, "test").unwrap();
        let mut stack = vec![repo.view().tags["main"].target];
        let mut seen = 0;
        while let Some(id) = stack.pop() {
            if id == repo.root_id() {
                continue;
            }
            let s = repo.store().snapshot(&id).unwrap();
            assert_eq!(s.signature_valid(), Some(true), "{} in {}", id.short(), dir.display());
            stack.extend(s.parents.iter().copied());
            seen += 1;
        }
        assert!(seen >= 2, "{seen} snapshots in {}", dir.display());
    }
    // The dev's own snapshot comes back to them with their own signature.
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&d)), None, "test").unwrap();
    let mine = (|| {
        let mut stack = vec![repo.view().tags["main"].target];
        while let Some(id) = stack.pop() {
            let s = repo.store().snapshot(&id).unwrap();
            if matches!(&s.description, veil_core::object::Text::Plain(t) if t.contains("dev change")) {
                return s;
            }
            stack.extend(s.parents.iter().copied());
        }
        panic!("the dev's change is missing")
    })();
    assert_eq!(mine.signature.as_ref().unwrap().key, p.dev.identity().verifying_hex());
}

#[test]
fn group_changes_grant_and_rotate_secret_keys() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // fin was added by the admin: their device holds the team key.
    let f = p.fin.dir("c");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), f.to_str().unwrap()]);
    assert!(std::fs::read_to_string(f.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
    // A manager's addition reaches the server's group, but the key needs a
    // ring admin's signature: until then the secret stays closed.
    p.admin.ok(&p.dir, &["group", "manager", "finance", &p.carol.name]);
    let c = p.carol.dir("c");
    p.carol.ok(p.carol.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    // Someone in no group yet, so no admin's device ever granted them a key.
    let newbie = hub.person("newbie");
    let out = p.carol.ok(&c, &["group", "add", "finance", &newbie.name]);
    assert!(out.contains("key-ring admin"), "{out}");
    let d = newbie.dir("c");
    newbie.ok(newbie.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    assert!(d.join(BILL_DIR).join("acme/invoice.txt").exists(), "folder access is the server's record");
    assert!(!d.join(BILL_DIR).join(".env").exists(), "no key without an admin's signature");
    assert_no_marker(&everything_in(&d), &[ENV_MARK], &newbie.name);
    // Removing fin from every group rotates the key away from them.
    let out = p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    assert!(out.contains("rotated away"), "{out}");
}
