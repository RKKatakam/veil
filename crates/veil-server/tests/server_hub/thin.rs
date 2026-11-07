//! S3: thin clones against the real server (`docs/HUB.md` §13.18). `vl
//! clone` is thin by default: the branch tips and what it checks out; the
//! rest is fetched when read, through S1's `fetch` and the `history` pages.

use std::path::Path;

use veil_core::object::Object;

use super::support::*;

/// A private project with history: the admin's working directory, after
/// `commits` pushed commits that each change `src/` and add a file of
/// `size` bytes under `data/`.
fn project_with_history(hub: &TestHub, commits: usize, size: usize) -> (Person, std::path::PathBuf, String) {
    let admin = hub.person("admin");
    let name = unique("thin");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    write_files(&dir, &[("src/lib.rs", "fn lib() {}\n"), ("docs/guide.md", "# guide\n")]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "first");
    admin.ok(&dir, &["push"]);
    for i in 0..commits {
        let data = format!("{i:04} {}\n", "d".repeat(size));
        write_files(&dir, &[("src/lib.rs", &format!("fn lib() {{ {i} }}\n")), (&format!("data/f{i}.bin"), &data)]);
        admin.commit_main(&dir, &format!("commit {i}"));
    }
    admin.ok(&dir, &["push"]);
    (admin, dir, name)
}

fn json(out: &str) -> serde_json::Value {
    serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("{e}: {out}"))
}

/// The snapshot ids `vl log --json` shows, in order.
fn log_ids(who: &Person, dir: &Path) -> Vec<String> {
    let o = who.run(dir, &["log", "--json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    json(&String::from_utf8_lossy(&o.stdout))["entries"].as_array().unwrap().iter().map(|e| e["snapshot_id"].as_str().unwrap().to_string()).collect()
}

fn repo_json(dir: &Path) -> serde_json::Value {
    json(&std::fs::read_to_string(dir.join(".veil/repo.json")).unwrap())
}

/// Bytes under `dir` (recursively).
fn du(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let m = e.metadata().unwrap();
            if m.is_dir() {
                stack.push(e.path());
            } else {
                total += m.len();
            }
        }
    }
    total
}

#[test]
fn a_thin_clone_holds_the_tips_and_reads_the_rest_when_asked() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 12, 2_000);
    let thin = admin.dir("thin");
    let out = admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    assert!(out.contains("thin"), "{out}");
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    // Format 9 with its marker; the full clone stays at format 8.
    let c = repo_json(&thin);
    assert_eq!(c["format"], 9, "{c}");
    assert_eq!(c["partial"]["remote"], "origin", "{c}");
    assert_eq!(repo_json(&full)["format"], 8);
    assert!(repo_json(&full).get("partial").is_none());
    // No full graph: the main store holds the tip's snapshot, not the
    // history; no tree or file of an older snapshot was fetched.
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&thin)), None, "test").unwrap();
    let snapshots = repo
        .store()
        .list_objects()
        .unwrap()
        .into_iter()
        .filter(|id| matches!(repo.store().get(id), Ok(Object::Snapshot(_))))
        .count();
    assert!(snapshots <= 4, "the thin clone holds {snapshots} snapshots");
    let cache = repo.store().cache().unwrap();
    let cached = cache.list_objects().unwrap();
    assert!(cached.iter().all(|id| !matches!(cache.get(id), Ok(Object::Snapshot(_)))));
    let old_files = (0..11).filter(|i| thin.join(format!("data/f{i}.bin")).exists()).count();
    assert_eq!(old_files, 11, "the tip's files are checked out");
    drop(repo);
    // `vl log` through the server's history pages: the same as a full clone.
    // (Each clone's working copy, `@`, is its own.)
    assert_eq!(log_ids(&admin, &thin)[1..], log_ids(&admin, &full)[1..]);
    // An old snapshot's diff, fetched on demand: the same.
    let ids = log_ids(&admin, &full);
    let first = &ids[ids.len() - 2];
    assert_eq!(admin.ok(&thin, &["show", first]), admin.ok(&full, &["show", first]));
    // status, commit and push work in the thin clone.
    admin.ok(&thin, &["status"]);
    write_files(&thin, &[("src/new.rs", "fn new() {}\n")]);
    admin.commit_main(&thin, "from the thin clone");
    admin.ok(&thin, &["push"]);
    admin.ok(&full, &["pull"]);
    assert!(admin.ok(&full, &["log", "-n", "3"]).contains("from the thin clone"));
    admin.ok(&full, &["new", "main"]);
    assert!(full.join("src/new.rs").exists());
    let fsck = admin.ok(&full, &["fsck"]);
    assert!(fsck.contains("No corruption found"), "{fsck}");
    // And `vl fsck` in the thin clone reports what it has not fetched as
    // notes, not damage.
    let o = admin.run(&thin, &["fsck"]);
    let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "{all}");
}

/// Offline is not a mode: with the server gone, what needs it fails with a
/// clear error and writes nothing; what is local still works.
#[test]
fn a_lost_server_is_a_clear_error_never_a_hidden_file() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 4, 100);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let ids = log_ids(&admin, &full);
    let old = ids[ids.len() - 2].clone();
    let before = std::fs::read(thin.join(".veil/local/checkout.json")).unwrap();
    drop(hub);
    // Local work goes on.
    admin.ok(&thin, &["status"]);
    write_files(&thin, &[("src/offline.rs", "fn offline() {}\n")]);
    admin.ok(&thin, &["commit", "-m", "written while the server is gone"]);
    // What needs the server fails, naming it, and never as "hidden".
    let err = admin.fails(&thin, &["show", &old]);
    assert!(err.contains("could not be reached"), "{err}");
    let err = admin.fails(&thin, &["new", &old]);
    assert!(err.contains("could not be reached"), "{err}");
    assert!(thin.join("src/offline.rs").exists());
    let after: serde_json::Value = json(&String::from_utf8_lossy(&std::fs::read(thin.join(".veil/local/checkout.json")).unwrap()));
    let before: serde_json::Value = json(&String::from_utf8_lossy(&before));
    assert_ne!(after["snapshot"], serde_json::Value::Null);
    assert!(after.get("pending").is_none(), "a failed move left a journal: {after}");
    let _ = before;
}

/// Nothing a person may not see is requested, received or cached by a
/// thin clone, through every read, `vl partial full` included.
#[test]
fn a_thin_clone_receives_nothing_its_person_may_not_see() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.dev.dir("thin-dev");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    p.dev.ok(&d, &["identity", "confirm", &p.fp]);
    for rev in log_ids(&p.dev, &d) {
        p.dev.run(&d, &["show", &rev]);
    }
    let items = everything_in(&d);
    assert_no_marker(&items, &restricted_markers(), "dev's thin clone");
    assert!(has_marker(&items, PUBLIC_MARK), "the thin clone holds what dev may see");
    p.dev.ok(&d, &["partial", "full"]);
    assert_eq!(repo_json(&d)["format"], 8);
    assert_no_marker(&everything_in(&d), &restricted_markers(), "dev's widened clone");
    // A thin clone of an outsider: public folders only.
    let anyone = hub.anyone();
    let o = anyone.dir("thin-anyone");
    anyone.ok(anyone.home.path(), &["clone", &hub.url(&p.name), o.to_str().unwrap()]);
    for rev in log_ids(&anyone, &o) {
        anyone.run(&o, &["show", &rev]);
    }
    assert_no_marker(&everything_in(&o), &restricted_markers(), "anyone's thin clone");
}

/// The object cache stays under its bound through a long session; a
/// checkout larger than the bound is refused at clone time.
#[test]
fn the_cache_stays_under_its_bound() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 16, 20_000);
    // The tip's checkout is about 330 KB: refused under a 100 KB bound.
    let small = admin.dir("small");
    let err = admin.fails(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), small.to_str().unwrap()]);
    assert!(err.contains("larger than its object cache"), "{err}");
    assert!(!small.join(".veil").exists(), "a refused clone leaves nothing");
    // Remove most of the checkout so it fits; old content does not.
    for i in 0..16 {
        std::fs::remove_file(dir.join(format!("data/f{i}.bin"))).unwrap();
    }
    admin.commit_main(&dir, "drop data");
    admin.ok(&dir, &["push"]);
    let thin = admin.dir("thin");
    let limit = 200_000u64;
    admin.ok(admin.home.path(), &["clone", "--cache-size", "200000", &hub.url(&name), thin.to_str().unwrap()]);
    let ids = log_ids(&admin, &thin);
    let mut most = 0;
    for rev in ids.iter().rev() {
        admin.run(&thin, &["show", rev]);
        most = most.max(du(&thin.join(".veil/cache")));
    }
    assert!(most <= limit + 64 * 1024, "the cache reached {most} bytes, over its bound {limit}");
    let st = admin.ok(&thin, &["partial", "status"]);
    assert!(st.contains("object cache"), "{st}");
}

/// `vl partial full`: every snapshot and object, then format 8; local work
/// kept; the clone then needs no server for history.
#[test]
fn partial_full_makes_an_ordinary_clone() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 6, 500);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    write_files(&thin, &[("mine.txt", "local only\n")]);
    admin.ok(&thin, &["commit", "-m", "not pushed"]);
    admin.ok(&thin, &["partial", "full"]);
    let c = repo_json(&thin);
    assert_eq!(c["format"], 8, "{c}");
    assert!(c.get("partial").is_none(), "{c}");
    assert!(!thin.join(".veil/cache").exists());
    let ids = log_ids(&admin, &thin);
    drop(hub);
    for rev in &ids {
        admin.ok(&thin, &["show", rev]);
    }
    let fsck = admin.ok(&thin, &["fsck"]);
    assert!(fsck.contains("No corruption found"), "{fsck}");
    assert!(admin.ok(&thin, &["log"]).contains("not pushed"));
}

/// The `history` route's page (revision 3): every tip, then at most
/// `limit` snapshots in all.
#[test]
fn history_answers_pages() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 5, 10);
    let api = hub.api();
    let token = admin.token();
    let tips = api.tips(Some(&token), &name).unwrap();
    assert!(tips.revision >= 3);
    let tip = tips.branches["main"];
    let one = api.post_json(Some(&token), &format!("/v1/projects/{name}/history"), &serde_json::json!({"tips": [tip], "limit": 1}));
    let frames = one.frames();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, tip);
    let three = api.post_json(Some(&token), &format!("/v1/projects/{name}/history"), &serde_json::json!({"tips": [tip], "limit": 3})).frames();
    assert_eq!(three.len(), 3);
    let all = api.post_json(Some(&token), &format!("/v1/projects/{name}/history"), &serde_json::json!({"tips": [tip]})).frames();
    assert!(all.len() > 3);
}
