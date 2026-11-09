//! S3: thin clones against the real server (`docs/HUB.md` §13.21). `vl
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
        p.dev.ok(&d, &["show", &rev]);
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
        anyone.ok(&o, &["show", &rev]);
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
        admin.ok(&thin, &["show", rev]);
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
    assert!(tips.revision >= 4, "history pages are revision 4 (BUG-1140)");
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

// ---- S3 cycle 1 review (`docs/BUGS.md`, "S3 cycle 1") --------------------

/// `vl partial full` leaves a format-8 clone holding every object its
/// history reaches (after it, nothing is fetched and a missing object reads
/// as hidden), even when the working copy's snapshots rebuilt a tree the
/// server has (the widening pull does not walk a tree the main store holds)
/// and no local snapshot reaches it any more. (S3 cycle 1 review: held.)
#[test]
fn partial_full_keeps_what_a_rebuilt_tree_reaches() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 3, 100);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let tip = log_ids(&admin, &thin)[1].clone();
    // Edit a file and put it back: the working copy's snapshot builds the
    // tip's own `data/` tree and root tree again, into the main store,
    // while `data/f2.bin` (untouched) stays in the cache only.
    let f0 = std::fs::read(thin.join("data/f0.bin")).unwrap();
    admin.ok(&thin, &["status"]);
    std::fs::write(thin.join("data/f0.bin"), b"edited\n").unwrap();
    admin.ok(&thin, &["status"]);
    std::fs::write(thin.join("data/f0.bin"), &f0).unwrap();
    admin.ok(&thin, &["status"]);
    // Then `data/` goes, pushed: no local snapshot reaches it any more.
    std::fs::remove_dir_all(thin.join("data")).unwrap();
    admin.commit_main(&thin, "drop data");
    admin.ok(&thin, &["push"]);
    admin.ok(&thin, &["partial", "full"]);
    assert_eq!(repo_json(&thin)["format"], 8);
    drop(hub);
    let o = admin.run(&thin, &["fsck"]);
    let fsck = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    // The old tip's files, as the server has them.
    let shown = admin.run(&thin, &["cat", "-r", &tip, "data/f2.bin"]);
    assert!(
        shown.status.success() && o.status.success() && fsck.contains("No corruption found"),
        "after `vl partial full`: cat {}{}\nfsck:\n{fsck}",
        String::from_utf8_lossy(&shown.stdout),
        String::from_utf8_lossy(&shown.stderr)
    );
}

/// A thin clone answers `vl show` of a snapshot whose parent it does not
/// hold yet as a full clone does (the diff against that parent), not with
/// an error or a diff against nothing.
#[test]
fn s3r_show_of_a_snapshot_whose_parent_is_beyond_the_boundary() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 4, 100);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let ids = log_ids(&admin, &full);
    let middle = ids[3].clone();
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let o = admin.run(&thin, &["show", &middle]);
    let got = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "vl show in the thin clone failed:\n{got}");
    assert_eq!(got, admin.ok(&full, &["show", &middle]));
}

/// `vl blame` in a thin clone attributes each line as in a full clone: the
/// history it walks is paged in from the server, never cut at the boundary.
#[test]
fn s3r_blame_in_a_thin_clone_is_the_full_clones() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    let name = unique("thin");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    let mut text = String::new();
    for i in 0..4 {
        text.push_str(&format!("line {i}\n"));
        write_files(&dir, &[("notes.txt", &text)]);
        admin.commit_main(&dir, &format!("line {i}"));
    }
    admin.ok(&dir, &["push"]);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let want = admin.ok(&full, &["blame", "notes.txt", "-r", "main", "--json"]);
    let got = admin.ok(&thin, &["blame", "notes.txt", "-r", "main", "--json"]);
    assert_eq!(got, want);
}

/// A merge whose second parent the thin clone does not hold: `vl show`
/// diffs it against both parents, as a full clone does, instead of taking
/// that parent for a withheld one that contributes nothing.
#[test]
fn s3r_show_of_a_merge_whose_other_parent_is_beyond_the_boundary() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    let name = unique("thin");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    write_files(&dir, &[("a.txt", "a\n")]);
    admin.commit_main(&dir, "base");
    let base = log_ids(&admin, &dir)[1].clone();
    write_files(&dir, &[("main.txt", "main side\n")]);
    admin.commit_main(&dir, "main side");
    admin.ok(&dir, &["new", &base]);
    write_files(&dir, &[("side.txt", "other side\n")]);
    admin.ok(&dir, &["commit", "-m", "other side"]);
    admin.ok(&dir, &["tag", "set", "side", "-r", "@-"]);
    admin.ok(&dir, &["merge", "side", "--into", "main", "-m", "merge side"]);
    let merge = log_ids(&admin, &dir).into_iter().find(|id| admin.ok(&dir, &["show", id]).contains("merge side")).expect("the merge");
    admin.ok(&dir, &["tag", "set", "main", "-r", &merge, "--force"]);
    admin.ok(&dir, &["tag", "delete", "side"]);
    admin.ok(&dir, &["push"]);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let want = admin.ok(&full, &["show", "main", "--json"]);
    // The thin clone holds the merge's first parent (a full id is asked of
    // the server), not the other one.
    let first = json(&want)["parents"][0]["snapshot_id"].as_str().unwrap().to_string();
    admin.ok(&thin, &["cat", "-r", &first, "a.txt"]);
    let o = admin.run(&thin, &["show", "main", "--json"]);
    let got = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "{got}");
    assert_eq!(json(&got)["diff"], json(&want)["diff"]);
}

/// Threat 11 after the clone: checking out a branch whose files pass the
/// cache's bound fails before the move writes anything (as the clone's
/// refusal does), or keeps the cache under its bound; never a cache filled
/// past it (here 204 KiB of a 100 KiB bound: the fetch-ahead charges each
/// object before its batch is on disk, and the eviction it triggers counts
/// only what is on disk).
#[test]
fn s3r_a_checkout_past_the_cache_bound_fails_before_writing() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 0, 0);
    // Branch `big`: 400 KB of files; `main` stays small.
    admin.ok(&dir, &["new", "main"]);
    // Content that does not compress: 20 files of 20 KB.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for i in 0..20 {
        let mut text = String::new();
        while text.len() < 20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            text.push_str(&format!("{x:016x}"));
        }
        write_files(&dir, &[(&format!("big/f{i:02}.bin"), &text)]);
    }
    admin.ok(&dir, &["commit", "-m", "big"]);
    admin.ok(&dir, &["tag", "set", "big", "-r", "@-"]);
    let first = log_ids(&admin, &dir)[2].clone();
    admin.ok(&dir, &["tag", "set", "main", "-r", &first, "--force"]);
    admin.ok(&dir, &["push"]);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), thin.to_str().unwrap()]);
    let o = admin.run(&thin, &["new", "big"]);
    let out = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(!o.status.success(), "`vl new big` past the cache bound succeeded:\n{out}");
    let st = std::fs::read_to_string(thin.join(".veil/local/checkout.json")).unwrap();
    let written = (0..20).filter(|i| thin.join(format!("big/f{i:02}.bin")).exists()).count();
    assert!(!st.contains("pending") && written == 0, "a failed checkout wrote {written} of 20 files and left {st}:\n{out}");
    admin.ok(&thin, &["status"]);
}

// ---- S3 cycle 2 review (`docs/BUGS.md`, "S3 cycle 2") --------------------

/// A project whose `main` is small and whose branch `big` adds 400 KB of
/// files that do not compress (20 of 20 KB), both pushed.
fn project_with_big_branch(hub: &TestHub) -> (Person, String) {
    let (admin, dir, name) = project_with_history(hub, 0, 0);
    admin.ok(&dir, &["new", "main"]);
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for i in 0..20 {
        let mut text = String::new();
        while text.len() < 20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            text.push_str(&format!("{x:016x}"));
        }
        write_files(&dir, &[(&format!("big/f{i:02}.bin"), &text)]);
    }
    admin.ok(&dir, &["commit", "-m", "big"]);
    admin.ok(&dir, &["tag", "set", "big", "-r", "@-"]);
    let first = log_ids(&admin, &dir)[2].clone();
    admin.ok(&dir, &["tag", "set", "main", "-r", &first, "--force"]);
    admin.ok(&dir, &["push"]);
    (admin, name)
}

/// After `cmd` ran in thin clone `thin` (bounded at 100 KiB) and tried to
/// move the working copy onto `big`'s 400 KB: it failed and recorded nothing,
/// so the next command works.
fn assert_a_failed_move_records_nothing(admin: &Person, thin: &Path, cmd: &[&str], o: std::process::Output) {
    let out = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(!o.status.success(), "`vl {}` past the cache bound succeeded:\n{out}", cmd.join(" "));
    let st = admin.run(thin, &["status"]);
    let status = format!("{}{}", String::from_utf8_lossy(&st.stdout), String::from_utf8_lossy(&st.stderr));
    // What the person would try next (shown on failure).
    let tried = |args: &[&str]| {
        let o = admin.run(thin, args);
        format!("`vl {}` ({}): {}{}", args.join(" "), o.status, String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
    };
    let next = if st.status.success() { String::new() } else { format!("{}\n{}", tried(&["undo"]), tried(&["partial", "limit", "1G"])) };
    assert!(
        st.status.success(),
        "`vl {}` failed to fetch, yet recorded its move: every later command retries it and fails.\n`vl {}`:\n{out}\n`vl status`:\n{status}\n{next}",
        cmd.join(" "),
        cmd.join(" ")
    );
}

/// A thin clone (default bound) that has had `big` checked out and gone
/// back to `main`, then had its bound lowered to 100 KiB: `big`'s files
/// are evicted, and an operation in the log has the working copy on `big`.
/// Returns the clone and the id of that operation.
fn clone_that_visited_big(admin: &Person, hub: &TestHub, name: &str) -> (std::path::PathBuf, String) {
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(name), thin.to_str().unwrap()]);
    admin.ok(&thin, &["new", "big"]);
    let ops = json(&admin.ok(&thin, &["op", "log", "--json"]));
    let on_big = ops["operations"][0]["op_id"].as_str().unwrap().to_string();
    admin.ok(&thin, &["new", "main"]);
    admin.ok(&thin, &["partial", "limit", "100K"]);
    // A command in a fresh process, which trims under the new bound.
    admin.ok(&thin, &["partial", "limit", "100K"]);
    assert!(du(&thin.join(".veil/cache")) <= 100 * 1024 + 64 * 1024, "big's files were evicted");
    (thin, on_big)
}

/// BUG-1146 (BUG-1145's second half, the class): `vl rebase` of the
/// working copy onto a branch past the cache's bound records the rebase,
/// then fails to fetch; every later command retries the move and fails.
#[test]
fn s3r2_a_rebase_past_the_cache_bound_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), thin.to_str().unwrap()]);
    let cmd = ["rebase", "-s", "@", "-d", "big"];
    let o = admin.run(&thin, &cmd);
    assert_a_failed_move_records_nothing(&admin, &thin, &cmd, o);
}

/// BUG-1146: `vl merge` into the working copy, the same route.
#[test]
fn s3r2_a_merge_past_the_cache_bound_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), thin.to_str().unwrap()]);
    let cmd = ["merge", "big"];
    let o = admin.run(&thin, &cmd);
    assert_a_failed_move_records_nothing(&admin, &thin, &cmd, o);
}

/// BUG-1146: `vl undo` back onto a working copy whose files were evicted.
#[test]
fn s3r2_an_undo_past_the_cache_bound_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let (thin, _) = clone_that_visited_big(&admin, &hub, &name);
    let cmd = ["undo"];
    let o = admin.run(&thin, &cmd);
    assert_a_failed_move_records_nothing(&admin, &thin, &cmd, o);
}

/// BUG-1146: `vl op restore` of an operation whose working copy was evicted.
#[test]
fn s3r2_an_op_restore_past_the_cache_bound_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let (thin, on_big) = clone_that_visited_big(&admin, &hub, &name);
    let cmd = ["op", "restore", on_big.as_str()];
    let o = admin.run(&thin, &cmd);
    assert_a_failed_move_records_nothing(&admin, &thin, &cmd, o);
}

/// `vl ws switch` to a workspace on `big`: the move is not recorded first.
/// (A control: `ws switch` holds.)
#[test]
fn s3r2_a_workspace_switch_past_the_cache_bound_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), thin.to_str().unwrap()]);
    admin.ok(&thin, &["ws", "new", "other", "-r", "big"]);
    let cmd = ["ws", "switch", "other"];
    let o = admin.run(&thin, &cmd);
    assert_a_failed_move_records_nothing(&admin, &thin, &cmd, o);
}

/// BUG-1146: `vl new A B` (a merge): the fetch-ahead of `vl new` runs for
/// one parent only.
#[test]
fn s3r2_a_new_merge_past_the_cache_bound_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), thin.to_str().unwrap()]);
    let cmd = ["new", "main", "big"];
    let o = admin.run(&thin, &cmd);
    assert_a_failed_move_records_nothing(&admin, &thin, &cmd, o);
}

/// `vl restore --from big` (the working copy takes `big`'s files): a
/// control, it holds.
#[test]
fn s3r2_a_restore_past_the_cache_bound_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), thin.to_str().unwrap()]);
    let cmd = ["restore", "--from", "big"];
    let o = admin.run(&thin, &cmd);
    assert_a_failed_move_records_nothing(&admin, &thin, &cmd, o);
}

/// BUG-1146: `vl cherry-pick big` onto the working copy's parent.
#[test]
fn s3r2_a_cherry_pick_past_the_cache_bound_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), thin.to_str().unwrap()]);
    let cmd = ["cherry-pick", "big"];
    let o = admin.run(&thin, &cmd);
    assert_a_failed_move_records_nothing(&admin, &thin, &cmd, o);
}

/// BUG-1260: a thin clone of a project with a tag whose name could be an
/// id (`lts`, `trunk`, `work`: only the letters k–z, as change ids are
/// written; or four hex digits or more, as `2025`) fetches the project's
/// whole history. The pull's tag check (`apply_remote_tags`, BUG-105:
/// would the new tag hide an id?) walks every visible snapshot
/// (`RevisionNames::shadows`, `topo_children_first`), and since cycle 1
/// every snapshot read pages history in at the boundary
/// (`Repo::snapshot_opt`). The clone then holds every snapshot, as a full
/// clone: here, `vl log` works with the server gone, where a clone of the
/// same project without that tag needs the server.
#[test]
fn s3r2_a_tag_named_like_an_id_does_not_fetch_the_whole_history() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 6, 10);
    let plain = admin.dir("plain");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), plain.to_str().unwrap()]);
    admin.ok(&dir, &["tag", "set", "lts", "-r", "main"]);
    admin.ok(&dir, &["push"]);
    let tagged = admin.dir("tagged");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), tagged.to_str().unwrap()]);
    drop(hub);
    let o = admin.run(&plain, &["log"]);
    assert!(!o.status.success(), "a thin clone holds its tips only, and needs the server for history");
    let o = admin.run(&tagged, &["log"]);
    assert!(
        !o.status.success(),
        "the clone of the project tagged `lts` holds the whole history (`vl log` with the server gone):\n{}",
        String::from_utf8_lossy(&o.stdout)
    );
}

/// BUG-1146, the class: every kind of operation that moves the project
/// directory's working copy, run past the cache's bound in a fresh thin
/// clone. Each either moves within the bound, or fails having recorded
/// nothing; then `vl status` and `vl partial limit 1G` run, and the same
/// command succeeds under the larger bound. (`Transaction::commit` fetches
/// ahead any move of the attached working copy before publishing, keyed on
/// what the operation does, so a new command is covered without a change.)
#[test]
fn every_working_copy_move_past_the_cache_bound_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let moves: &[&[&str]] = &[
        &["new", "big"],
        &["edit", "big"],
        &["new", "main", "big"],
        &["rebase", "-s", "@", "-d", "big"],
        &["merge", "big"],
        &["cherry-pick", "big"],
        &["restore", "--from", "big"],
    ];
    for (i, cmd) in moves.iter().enumerate() {
        let thin = admin.dir(&format!("every-{i}"));
        admin.ok(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), thin.to_str().unwrap()]);
        let o = admin.run(&thin, cmd);
        let failed = !o.status.success();
        assert_a_failed_move_records_nothing(&admin, &thin, cmd, o);
        if failed {
            admin.ok(&thin, &["partial", "limit", "1G"]);
            admin.ok(&thin, &["status"]);
            admin.ok(&thin, cmd);
            admin.ok(&thin, &["status"]);
        }
    }
    // Undo and op restore, back onto a working copy whose files were evicted.
    let (thin, on_big) = clone_that_visited_big(&admin, &hub, &name);
    for cmd in [vec!["undo"], vec!["op", "restore", on_big.as_str()]] {
        let o = admin.run(&thin, &cmd);
        assert_a_failed_move_records_nothing(&admin, &thin, &cmd, o);
    }
    admin.ok(&thin, &["partial", "limit", "1G"]);
    admin.ok(&thin, &["op", "restore", &on_big]);
    admin.ok(&thin, &["status"]);
    assert!(thin.join("big/f00.bin").exists(), "under the larger bound the move happens");
}

// ---- S3 cycle 3 review (`docs/BUGS.md`, "S3 cycle 3") --------------------

/// The change id (as written, letters k–z) of the snapshot described
/// `description` in `dir`'s `vl log`.
fn change_of(who: &Person, dir: &Path, description: &str) -> String {
    log_field(who, dir, description, "change_id")
}

/// The snapshot id of the snapshot described `description` in `dir`'s `vl log`.
fn snapshot_of(who: &Person, dir: &Path, description: &str) -> String {
    log_field(who, dir, description, "snapshot_id")
}

fn log_field(who: &Person, dir: &Path, description: &str, field: &str) -> String {
    let o = who.run(dir, &["log", "--json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let log = json(&String::from_utf8_lossy(&o.stdout));
    let e = log["entries"].as_array().unwrap().iter().find(|e| e["description"].as_str().is_some_and(|d| d.trim() == description));
    e.unwrap_or_else(|| panic!("no snapshot described {description:?}: {log}"))[field].as_str().unwrap().to_string()
}

/// BUG-1261 (guarantee 1 of the S3 cycle 3 brief; BUG-105's class): a tag
/// pushed under the name of an old change's id (12 characters of it: a
/// chance match with any other id is one in 16¹²) is refused as a local
/// tag by a full clone's pull ("the name is also a change or snapshot id
/// of this repository"), so `vl show <that id>` shows the change. A thin
/// clone's pull checks the name against the snapshots it holds only
/// (`RevisionNames::shadows` through `topo_children_first`, held-only
/// since the BUG-1260 fix), creates the tag, and from then on the id names
/// the tag's target, as tags resolve first (`revset::resolve_base`): the
/// same revision expression names a different change than in a full
/// clone, even after the old change was fetched. Whoever can push a tag
/// redirects `vl edit <change>` of everyone with a thin clone.
#[test]
fn s3r3_a_pulled_tag_never_hides_the_id_of_a_change_the_thin_clone_does_not_hold() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 6, 10);
    let first: String = change_of(&admin, &dir, "first").chars().take(12).collect();
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    // The tag, on the tip ("commit 5"), named after the first change's id.
    admin.ok(&dir, &["tag", "set", &first, "-r", "main"]);
    admin.ok(&dir, &["push"]);
    let full_pull = admin.ok(&full, &["pull"]);
    let thin_pull = admin.ok(&thin, &["pull"]);
    let fresh = admin.dir("fresh");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), fresh.to_str().unwrap()]);
    let shown = admin.ok(&full, &["show", &first]);
    assert!(shown.contains("first") && !shown.contains("commit 5"), "the full clone shows the change:\n{full_pull}\n{shown}");
    for (what, clone, pulled) in [("a pull", &thin, thin_pull.as_str()), ("a clone", &fresh, "")] {
        // Also once the history the change is in has been fetched.
        for when in ["at once", "after `vl log`"] {
            let o = admin.run(clone, &["show", &first]);
            let out = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
            assert!(
                o.status.success() && out.contains("first") && !out.contains("commit 5"),
                "a thin clone after {what} ({when}): `vl show {first}` names another change than a full clone:\n{pulled}\n{out}"
            );
            admin.ok(clone, &["log"]);
        }
    }
}

/// Files under `dir`, recursively, removed (a cache's contents).
fn remove_files_under(dir: &Path) {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
    }
}

/// Guarantee 2 of the S3 cycle 3 brief (BUG-1146's fallback, which the
/// builder did not test): a project directory behind `@` that cannot be
/// brought up to it. The state is built as an interrupted command leaves
/// it: `vl new big` published its operation (its fetch-ahead held `big`'s
/// files), and the process was killed before the directory moved; then
/// the cache lost those files (emptied here, as an eviction would) and is
/// bounded at 100 KiB, so they cannot come back. The person has an edit
/// in the directory. `vl status`, `vl undo`, `vl op restore` and `vl
/// partial limit` each run, and the edit survives.
#[test]
fn s3r3_a_directory_behind_at_that_cannot_catch_up_still_runs_status_undo_op_restore_and_partial_limit() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    admin.ok(&thin, &["new", "big"]);
    let on_big = veil_core::ObjectId::from_hex(&log_ids(&admin, &thin)[0]).unwrap();
    admin.ok(&thin, &["new", "main"]);
    let before = json(&admin.ok(&thin, &["op", "log", "--json"]))["operations"][0]["op_id"].as_str().unwrap().to_string();
    {
        let mut repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&thin)), None, "test").unwrap();
        let mut tx = repo.transaction("new big (killed before the directory moved)").unwrap();
        tx.view.workspaces.get_mut("default").unwrap().wc = on_big;
        tx.commit().unwrap();
    }
    remove_files_under(&thin.join(".veil/cache"));
    let config = std::fs::read_to_string(thin.join(".veil/repo.json")).unwrap();
    let mut c = json(&config);
    c["partial"]["cache_limit"] = serde_json::json!(100 * 1024);
    std::fs::write(thin.join(".veil/repo.json"), serde_json::to_string_pretty(&c).unwrap()).unwrap();
    write_files(&thin, &[("src/lib.rs", "fn edited_while_behind() {}\n")]);
    assert!(!thin.join("big/f00.bin").exists());
    let cases: &[(&str, &[&str])] = &[
        ("status", &["status"]),
        ("undo", &["undo"]),
        ("op-restore", &["op", "restore", &before]),
        ("partial-limit", &["partial", "limit", "1G"]),
    ];
    for (tag, cmd) in cases {
        let copy = admin.dir(&format!("behind-{tag}"));
        let st = std::process::Command::new("cp").arg("-a").arg(&thin).arg(&copy).status().unwrap();
        assert!(st.success());
        let o = admin.run(&copy, cmd);
        let out = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success(), "`vl {}` with the directory behind `@`:\n{out}", cmd.join(" "));
        // The fallback ran: the directory could not be brought up to `@`.
        assert!(out.contains("the working copy stays as it is"), "`vl {}` did not meet a directory behind `@`:\n{out}", cmd.join(" "));
        let o = admin.run(&copy, &["status"]);
        let after = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success(), "`vl status` after `vl {}`:\n{out}\n{after}", cmd.join(" "));
        // The edit is in the directory.
        let on_disk = std::fs::read_to_string(copy.join("src/lib.rs")).unwrap_or_default().contains("edited_while_behind");
        assert!(on_disk, "`vl {}` lost the edit made while the directory was behind `@`:\n{out}\n{after}", cmd.join(" "));
    }
}


/// `vl bisect` by hand in `dir`, from `bad` to `good`, with "bad" meaning
/// `data/f3.bin` is there: its last answer.
fn bisect_by_hand(who: &Person, dir: &Path, bad: &str, good: &str) -> String {
    let out = who.ok(dir, &["bisect", "start", "--bad", bad, "--good", good]);
    if out.contains("The first bad snapshot is") {
        who.ok(dir, &["bisect", "reset"]);
        return out;
    }
    for _ in 0..20 {
        let verdict = if dir.join("data/f3.bin").exists() { "bad" } else { "good" };
        let out = who.ok(dir, &["bisect", verdict]);
        if out.contains("The first bad snapshot is") {
            who.ok(dir, &["bisect", "reset"]);
            return out;
        }
    }
    panic!("bisect did not converge in {}", dir.display());
}

/// BUG-1262 (guarantee 3 of the S3 cycle 3 brief; introduced by the BUG-1260
/// fix): `vl bisect` reads its candidates with the whole-graph walks that
/// now read only what is held (`bisect::candidates`: `Repo::ancestors`,
/// `topo_children_first`), outside `Repo::exact`. In a thin clone, which
/// holds the tips, the candidates stop at the boundary, and bisect names
/// as the first bad snapshot one that a full clone (and the history) say
/// is not: here `data/f3.bin` arrives in "commit 3", and the thin clone's
/// bisect finds a later commit.
#[test]
fn s3r3_bisect_in_a_thin_clone_finds_what_a_full_clone_finds() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 12, 10);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let first = snapshot_of(&admin, &full, "first");
    let culprit: String = snapshot_of(&admin, &full, "commit 3").chars().take(8).collect();
    let found = bisect_by_hand(&admin, &full, "main", &first);
    assert!(found.contains(&culprit), "the full clone finds commit 3 ({culprit}):\n{found}");
    let found = bisect_by_hand(&admin, &thin, "main", &first);
    assert!(found.contains(&culprit), "the thin clone's bisect does not find commit 3 ({culprit}):\n{found}");
}

/// BUG-1263 (guarantee 2 of the S3 cycle 3 brief; BUG-1146's class): `vl ws
/// switch` past the cache's bound. The switch is an operation that leaves
/// the view as it is (the attachment is device-local), so
/// `Transaction::commit`'s fetch-ahead, keyed on a change of the view,
/// skips it; the end-of-command move then cannot fetch and leaves the
/// directory as it is. The command exits 0, prints "Project directory
/// attached to workspace other", and records the switch, while the
/// directory stays attached to `default`. The warning advises `vl undo`,
/// which (in `default`) undoes an unrelated, earlier operation: here the
/// creation of `other`. (The cycle 2 control
/// `s3r2_a_workspace_switch_past_the_cache_bound_records_nothing` passes
/// because the command now succeeds.)
#[test]
fn s3r3_a_workspace_switch_past_the_cache_bound_switches_or_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), thin.to_str().unwrap()]);
    admin.ok(&thin, &["ws", "new", "other", "-r", "big"]);
    let o = admin.run(&thin, &["ws", "switch", "other"]);
    let out = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(!o.status.success(), "`vl ws switch other` past the cache bound succeeded:\n{out}");
    let attached = json(&std::fs::read_to_string(thin.join(".veil/local/checkout.json")).unwrap())["workspace"].as_str().unwrap().to_string();
    assert_eq!(attached, "default", "`vl ws switch other` failed, yet moved attachment:\n{out}");
    let head = admin.ok(&thin, &["op", "log", "-n", "1"]);
    assert!(!head.contains("switch the project directory"), "a failed switch was recorded:\n{out}\n{head}");
    assert!(out.contains("partial limit"), "a failed switch says how to make room:\n{out}");
}


/// A project, and a fork of it (another project on the same server) with
/// one more commit, "on the fork", adding 150 KB that do not compress at
/// `x/x.txt`. Returns the admin, the project's name and the fork's.
fn project_and_fork(hub: &TestHub) -> (Person, String, String) {
    let (admin, dir, name) = project_with_history(hub, 1, 10);
    let fork = unique("fork");
    admin.ok(&dir, &["remote", "add", "fork", &hub.url(&fork)]);
    admin.ok(&dir, &["new", "main"]);
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut text = String::from("only on the fork, readable by admin\n");
    while text.len() < 150_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        text.push_str(&format!("{x:016x}"));
    }
    write_files(&dir, &[("x/x.txt", &text)]);
    admin.commit_main(&dir, "on the fork");
    admin.ok(&dir, &["push", "fork"]);
    (admin, name, fork)
}

/// BUG-1265 (guarantees 7 and 2 of the S3 cycle 3 brief; introduced by the
/// server-tips refresh of cycle 2): "on the server" is judged from *every*
/// remote's tips in the view (`Repo::pin_working_copies` hands
/// `remote_tags.values()` to `set_local_heads`; `server_tips_now` uses
/// them), where the connection's own tips were the thin clone's remote's
/// only (`thin::attach` filters `origin/`). A thin clone that also pulls
/// from a second remote (a fork on the same server) takes the fork's
/// snapshots for its server's. The fork's content, checked out once and
/// evicted, is then asked of the clone's server, which has no such
/// snapshot, and its "nothing there" reads as a redaction: `vl show
/// fork/main` fails with "object … is not present in this store", and
/// `vl new fork/main` passes its fetch-ahead (a refusal is left for the
/// reader), records the move, journals it and fails half way: from then
/// on every command, `vl status`, `vl op log`, `vl undo`, fails ("'/' is
/// not fetched, and the server has no copy of it"), until the checkout
/// record is edited by hand.
#[test]
fn s3r3_a_second_remotes_snapshot_is_never_the_servers_and_never_wedges_the_clone() {
    let hub = TestHub::start();
    let (admin, name, fork) = project_and_fork(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    admin.ok(&thin, &["remote", "add", "fork", &hub.url(&fork)]);
    admin.ok(&thin, &["pull", "fork"]);
    admin.ok(&thin, &["new", "fork/main"]);
    assert!(thin.join("x/x.txt").exists());
    // Back on the project's own tip; the fork's file is evicted.
    admin.ok(&thin, &["new", "origin/main"]);
    admin.ok(&thin, &["partial", "limit", "100K"]);
    admin.ok(&thin, &["partial", "limit", "100K"]);
    let o = admin.run(&thin, &["show", "fork/main"]);
    let show = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let o = admin.run(&thin, &["new", "fork/main"]);
    let new = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let o = admin.run(&thin, &["status"]);
    let status = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "the clone is wedged after `vl new fork/main`:\n{new}\n`vl status`:\n{status}");
    assert!(!show.contains("is not present in this store"), "the fork's file, which the server never had, reads as withheld:\n{show}");
}

/// Guarantee 3 of the S3 cycle 3 brief (BUG-1260's class): a revision name
/// that names nothing (a typo) and looks like an id prefix does not make a
/// thin clone fetch the whole history to say so.
#[test]
fn s3r3_a_revision_that_names_nothing_does_not_fetch_the_whole_history() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 6, 10);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    for typo in ["cafe0123", "kmnpqrst"] {
        let o = admin.run(&thin, &["show", typo]);
        assert!(!o.status.success(), "{typo} names nothing");
    }
    drop(hub);
    let o = admin.run(&thin, &["log"]);
    assert!(
        !o.status.success(),
        "a revision that names nothing fetched the whole history (`vl log` with the server gone):\n{}",
        String::from_utf8_lossy(&o.stdout)
    );
}

/// BUG-1266 (guarantee 1 of the S3 cycle 3 brief; introduced by S3 before
/// cycle 2, not reported): the change id of a change beyond a thin clone's
/// boundary names nothing. `revset::resolve_base` matches a change id
/// prefix against the history index (`entries_matching`), which reads what
/// is held only and records no boundary hit, so `Repo::exact` (in
/// `Ctx::rev`) has nothing to page in: `vl show <change>` of an old change,
/// as a teammate's message or a full clone's `vl log` gives it, fails with
/// "revision … not found" until a command that pages history in (`vl log`)
/// has run. A full snapshot id is asked of the server (`Ctx::rev`); a
/// change id or a short snapshot id is not. Same root as BUG-1261: an id
/// lookup answered from held history only.
#[test]
fn s3r3_an_old_change_id_names_the_same_change_as_in_a_full_clone() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 6, 10);
    let first: String = change_of(&admin, &dir, "first").chars().take(12).collect();
    let first_snapshot: String = snapshot_of(&admin, &dir, "first").chars().take(12).collect();
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    for rev in [&first, &first_snapshot] {
        let o = admin.run(&thin, &["show", rev]);
        let out = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success() && out.contains("first"), "`vl show {rev}` (the first change) in a thin clone:\n{out}");
    }
}


/// The S3 cycle 3 redesign's guarantee: on the same history a thin clone
/// answers as a full clone, command by command (names, ranges, history,
/// diffs, blame), whatever it held before. Each command runs first in the
/// full clone, then in a fresh thin one; JSON compared without each
/// clone's own working copy.
#[test]
fn a_thin_clone_answers_as_a_full_clone() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 8, 10);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let first_change: String = change_of(&admin, &dir, "first").chars().take(10).collect();
    let first = snapshot_of(&admin, &dir, "first");
    let third: String = snapshot_of(&admin, &dir, "commit 2").chars().take(10).collect();
    let cmds: Vec<Vec<String>> = vec![
        vec!["log".into(), "--json".into()],
        vec!["log".into(), "--json".into(), "-r".into(), "::main-".into()],
        vec!["log".into(), "--json".into(), "-r".into(), format!("{first}..main")],
        vec!["show".into(), "--json".into(), first_change.clone()],
        vec!["show".into(), "--json".into(), third.clone()],
        vec!["show".into(), "--json".into(), "main--".into()],
        vec!["diff".into(), "--json".into(), "--from".into(), first.clone(), "--to".into(), "main".into()],
        vec!["blame".into(), "src/lib.rs".into(), "-r".into(), "main".into(), "--json".into()],
        vec!["cat".into(), "-r".into(), third.clone(), "src/lib.rs".into()],
    ];
    // Without the working copy's own snapshot, which differs per clone.
    let normal = |out: &str| -> serde_json::Value {
        match serde_json::from_str::<serde_json::Value>(out.trim()) {
            Ok(mut v) => {
                if let Some(e) = v.get_mut("entries").and_then(|e| e.as_array_mut()) {
                    e.retain(|x| x["current"] != serde_json::json!(true));
                }
                v
            }
            Err(_) => serde_json::Value::String(out.to_string()),
        }
    };
    for (i, cmd) in cmds.iter().enumerate() {
        let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
        let want = admin.ok(&full, &args);
        let thin = admin.dir(&format!("same-{i}"));
        admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
        let got = admin.ok(&thin, &args);
        assert_eq!(normal(&got), normal(&want), "`vl {}` in a thin clone answers otherwise than in a full one", args.join(" "));
    }
}

// ---- S3 redesign review (cycle 1 of the revised design): `s3rd_…` ---------------

/// One command's answer as compared between clones: whether it succeeded,
/// and its output (JSON without each clone's own working copy, else the
/// text of stdout and stderr).
fn answer(who: &Person, dir: &Path, args: &[&str]) -> (bool, String) {
    let o = who.run(dir, args);
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    let err = String::from_utf8_lossy(&o.stderr).to_string();
    let text = match serde_json::from_str::<serde_json::Value>(out.trim()) {
        Ok(mut v) => {
            if let Some(e) = v.get_mut("entries").and_then(|e| e.as_array_mut()) {
                e.retain(|x| x["current"] != serde_json::json!(true));
            }
            v.to_string()
        }
        Err(_) => format!("{out}{err}"),
    };
    (o.status.success(), text)
}

/// Each of `cmds` in the full clone `full`, then in a fresh thin clone of
/// `name`: the same answer. Returns every one that differs.
fn first_difference(who: &Person, hub: &TestHub, name: &str, full: &Path, cmds: &[Vec<String>], tag: &str) -> Option<String> {
    let mut out = Vec::new();
    for (i, cmd) in cmds.iter().enumerate() {
        let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
        let want = answer(who, full, &args);
        let thin = who.dir(&format!("{tag}-{i}"));
        who.ok(who.home.path(), &["clone", &hub.url(name), thin.to_str().unwrap()]);
        let got = answer(who, &thin, &args);
        if got != want {
            let cut = |t: &str| t.chars().take(600).collect::<String>();
            out.push(format!("`vl {}`:\nfull clone ({}):\n{}\nthin clone ({}):\n{}", args.join(" "), want.0, cut(&want.1), got.0, cut(&got.1)));
        }
    }
    (!out.is_empty()).then(|| out.join("\n\n"))
}

/// Guarantee 1 (the redesign's): revision forms beyond the nine of
/// `a_thin_clone_answers_as_a_full_clone`: `@-`, `..x`, `x..`, `x` with
/// `-` steps past the boundary, an ambiguous and a unique change id
/// prefix of history the thin clone does not hold, a tag named like an id,
/// and `vl evolog` of an old change. Each command runs in the full clone,
/// then in a fresh thin one.
#[test]
fn s3rd_a_thin_clone_answers_as_a_full_clone_for_more_revision_forms() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 24, 10);
    // A tag named like a snapshot id prefix of the history, pushed.
    let third = snapshot_of(&admin, &dir, "commit 2");
    admin.ok(&dir, &["tag", "set", "rel-1", "-r", "main---"]);
    admin.ok(&dir, &["push"]);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    // The change ids of the pushed history (not of any clone's own working
    // copy, which a prefix must not match: ids are random).
    let log = json(&admin.ok(&full, &["log", "--json"]));
    let changes: Vec<String> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["current"] != serde_json::json!(true))
        .map(|e| e["change_id"].as_str().unwrap().to_string())
        .collect();
    // An ambiguous prefix: the longest one two pushed changes share.
    let mut ambiguous = String::new();
    for (i, a) in changes.iter().enumerate() {
        for b in &changes[i + 1..] {
            let n = a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count();
            if n > ambiguous.len() {
                ambiguous = a[..n].to_string();
            }
        }
    }
    assert!(!ambiguous.is_empty());
    // The shortest unique prefix of the oldest change, at least 5 letters
    // (a clone's own working copy matches it once in about a million). A
    // working copy matching the ambiguous prefix keeps it ambiguous.
    let oldest = changes.last().unwrap().clone();
    let unique_len = (1..=32).find(|&n| changes.iter().filter(|c| c.starts_with(&oldest[..n])).count() == 1).unwrap().max(5);
    let unique_prefix = oldest[..unique_len].to_string();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    let cmds = vec![
        s(&["show", "--json", "@-"]),
        s(&["log", "--json", "-r", "..main----"]),
        s(&["log", "--json", "-r", &format!("{}..", &third[..12])]),
        s(&["show", "--json", "main------------"]),
        s(&["show", "--json", "rel-1"]),
        s(&["show", "--json", &ambiguous]),
        s(&["show", "--json", &unique_prefix]),
        s(&["evolog", "-r", &unique_prefix]),
        s(&["log", "--json", "-r", &format!("::{unique_prefix}")]),
    ];
    if let Some(d) = first_difference(&admin, &hub, &name, &full, &cmds, "more") {
        panic!("a thin clone answers otherwise than a full clone: {d}");
    }
}

/// Guarantee 1 after history was rewritten on the server: the admin
/// rewrites the first change (`vl describe`, which rewrites everything
/// above it) and force-pushes. A full clone made afterwards holds the new
/// versions only, so `vl show <change>` of an old change shows its new
/// version; and the old versions' snapshot ids name nothing it can show.
/// `q/resolve` answers from the real graph (`graph`, every snapshot ever
/// derived, old versions included: `query::resolve_prefix`), so a thin
/// clone is told about the old versions as well.
#[test]
fn s3rd_a_thin_clone_names_what_a_full_clone_names_after_a_rewrite() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 6, 10);
    let first: String = change_of(&admin, &dir, "first").chars().take(12).collect();
    let old_first: String = snapshot_of(&admin, &dir, "first").chars().take(12).collect();
    let old_tip: String = snapshot_of(&admin, &dir, "commit 5").chars().take(12).collect();
    admin.ok(&dir, &["describe", "-r", &first, "-m", "first, renamed"]);
    admin.ok(&dir, &["push", "--force"]);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    let cmds = vec![
        s(&["show", "--json", &first]),
        s(&["show", "--json", &old_first]),
        s(&["show", "--json", &old_tip]),
        s(&["evolog", "-r", &first]),
        s(&["log", "--json"]),
    ];
    if let Some(d) = first_difference(&admin, &hub, &name, &full, &cmds, "rw") {
        panic!("after a rewrite, a thin clone answers otherwise than a full clone: {d}");
    }
}

/// The shape of `dir`'s history as `vl log --json` shows it: each entry's
/// change id (`@` for the working copy's, `new` for any other not in
/// `known`: both are made at random per clone), description, emptiness,
/// conflicts, tags and parents' change ids.
fn history_shape(who: &Person, dir: &Path, known: &[String]) -> Vec<String> {
    let log = json(&who.ok(dir, &["log", "--json"]));
    let entries = log["entries"].as_array().unwrap();
    let current: Vec<String> = entries.iter().filter(|e| e["current"] == serde_json::json!(true)).map(|e| e["change_id"].as_str().unwrap().to_string()).collect();
    let name = |c: &str| match () {
        _ if current.iter().any(|x| x == c) => "@".to_string(),
        _ if c != "-" && !known.iter().any(|k| k == c) => "new".to_string(),
        _ => c.to_string(),
    };
    let shapes: Vec<(String, String)> = entries
        .iter()
        .map(|e| {
            let parents: Vec<String> = e["parents"].as_array().unwrap().iter().map(|p| name(p["change_id"].as_str().unwrap_or("-"))).collect();
            let shape = format!(
                "{} {:?} empty={} conflicts={} tags={} parents={parents:?}",
                name(e["change_id"].as_str().unwrap_or("-")),
                e["description"].as_str().unwrap_or(""),
                e["empty"],
                e["conflicts"],
                e["tags"]
            );
            (e["timestamp"].to_string(), shape)
        })
        .collect();
    // Snapshots of one timestamp (`vl split`'s first half keeps the
    // original's) are ordered by id, which a random change id makes: in
    // any order within such a run.
    shapes
        .chunk_by(|a, b| a.0 == b.0)
        .flat_map(|run| {
            let mut run: Vec<String> = run.iter().map(|(_, s)| s.clone()).collect();
            run.sort();
            run
        })
        .collect()
}

/// Guarantee 1 for commands that rewrite or move onto history a thin
/// clone does not hold (the old changes of a long history): each runs in
/// a fresh full clone and a fresh thin one; afterwards both have the same
/// history (by change id and description, `@` aside) and the same files.
#[test]
fn s3rd_rewrites_of_unheld_history_match_a_full_clone() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 8, 10);
    let c = |d: &str| -> String { change_of(&admin, &dir, d).chars().take(12).collect() };
    let (first, c1, c2, c3, c4) = (c("first"), c("commit 1"), c("commit 2"), c("commit 3"), c("commit 4"));
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    let ops: Vec<Vec<String>> = vec![
        s(&["describe", "-r", &c1, "-m", "commit 1, renamed"]),
        s(&["abandon", &c2]),
        s(&["squash", "-r", &c3]),
        s(&["rebase", "-s", &c4, "-d", &first]),
        s(&["split", "-r", &c1, "-m", "the data of commit 1", "data"]),
        s(&["new", &first]),
        s(&["edit", &c1]),
        s(&["duplicate", &c1, "-d", "main"]),
        s(&["cherry-pick", &c1]),
        s(&["restore", "--from", &first]),
        s(&["rebase", "-s", "@", "-d", &c2]),
        s(&["new", &c1, "main"]),
    ];
    let known: Vec<String> = json(&admin.ok(&dir, &["log", "--json"]))["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["current"] != serde_json::json!(true))
        .filter_map(|e| e["change_id"].as_str().map(str::to_string))
        .collect();
    // `vl status` without the line naming the clone's own working copy.
    let status = |d: &Path| -> (bool, String) {
        let (ok, t) = answer(&admin, d, &["status"]);
        // Short ids out too: a copied change's are made at random.
        let id = |w: &str| { let w = w.trim_end_matches(')'); w.len() == 8 && (w.bytes().all(|b| (b'k'..=b'z').contains(&b)) || w.bytes().all(|b| b.is_ascii_hexdigit())) };
        let lines = t.lines().filter(|l| !l.starts_with("Working copy :"));
        (ok, lines.map(|l| l.split(' ').filter(|w| !id(w)).collect::<Vec<_>>().join(" ")).collect::<Vec<_>>().join("\n"))
    };
    let mut diffs = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        let args: Vec<&str> = op.iter().map(String::as_str).collect();
        let full = admin.dir(&format!("rwf-{i}"));
        admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
        let thin = admin.dir(&format!("rwt-{i}"));
        admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
        let want = answer(&admin, &full, &args);
        let got = answer(&admin, &thin, &args);
        if want.0 != got.0 {
            diffs.push(format!("`vl {}`: full {} ({}), thin {} ({})", args.join(" "), want.0, want.1.trim(), got.0, got.1.trim()));
            continue;
        }
        let (hf, ht) = (history_shape(&admin, &full, &known), history_shape(&admin, &thin, &known));
        if hf != ht {
            diffs.push(format!("`vl {}`: history\nfull: {hf:#?}\nthin: {ht:#?}", args.join(" ")));
        }
        let (ff, ft) = (answer(&admin, &full, &["files"]), answer(&admin, &thin, &["files"]));
        let (sf, st) = (status(&full), status(&thin));
        if ff != ft || sf != st {
            diffs.push(format!("`vl {}`: files or status\nfull: {ff:?} {sf:?}\nthin: {ft:?} {st:?}", args.join(" ")));
        }
    }
    assert!(diffs.is_empty(), "rewrites in a thin clone end otherwise than in a full clone:\n{}", diffs.join("\n\n"));
}

/// Guarantee 4 for `vl redo` and `vl undo` of a workspace switch whose
/// target's files were evicted meanwhile: `other` is moved onto `big`
/// (the directory stays on `default`), the directory switches to `other`
/// and back, everything is undone (so `big`'s files are pinned by nothing
/// and evicted under a 100 KiB bound), then redone. Redoing the switch
/// must either fetch within the bound or fail and record nothing; `vl
/// status` runs after each step.
#[test]
fn s3rd_redo_of_a_switch_past_the_cache_bound_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    admin.ok(&thin, &["ws", "new", "other", "-r", "main"]);
    admin.ok(&thin, &["rebase", "-s", "other@", "-d", "big"]);
    admin.ok(&thin, &["ws", "switch", "other"]);
    assert!(thin.join("big/f00.bin").exists());
    admin.ok(&thin, &["ws", "switch", "default"]);
    for _ in 0..3 {
        admin.ok(&thin, &["undo"]);
    }
    admin.ok(&thin, &["partial", "limit", "100K"]);
    admin.ok(&thin, &["partial", "limit", "100K"]);
    let cache = du(&thin.join(".veil/cache"));
    assert!(cache <= 100 * 1024 + 64 * 1024, "big's files were evicted: {cache} bytes in the cache");
    admin.ok(&thin, &["redo"]);
    let mut seen = Vec::new();
    for cmd in [&["redo"][..], &["redo"][..]] {
        let o = admin.run(&thin, cmd);
        seen.push(format!("`vl {}`: {}{}", cmd.join(" "), String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)));
        assert_a_failed_move_records_nothing(&admin, &thin, cmd, o);
        // Attached to `other` means holding its files.
        let attached = json(&std::fs::read_to_string(thin.join(".veil/local/checkout.json")).unwrap())["workspace"].as_str().unwrap().to_string();
        assert_eq!(attached == "other", thin.join("big/f00.bin").exists(), "attached to {attached}:\n{}", seen.join("\n"));
    }
    let undo = admin.ok(&thin, &["undo"]);
    seen.push(format!("`vl undo`: {undo}"));
    let cache = du(&thin.join(".veil/cache"));
    assert!(cache <= 100 * 1024 + 64 * 1024, "`vl undo` left {cache} bytes in a cache bounded at 100 KiB:\n{undo}");
    admin.ok(&thin, &["status"]);
    let attached = json(&std::fs::read_to_string(thin.join(".veil/local/checkout.json")).unwrap())["workspace"].as_str().unwrap().to_string();
    assert_eq!(attached == "other", thin.join("big/f00.bin").exists(), "attached to {attached}:\n{}", seen.join("\n"));
    eprintln!("{}", seen.join("\n"));
}

/// The cache's bound (threat 11) bounds what a thin clone keeps of the
/// server's files: they are fetched into `.veil/cache/`, which is
/// evicted; `.veil/objects/` holds snapshots and local work. A `vl ws
/// switch` away from a workspace whose files were fetched (here `big`'s
/// 400 KB, unchanged) writes every one of them into the main store, which
/// is never evicted; `vl gc` keeps them (the op log reaches them), even
/// after the workspace is removed. `vl new big` and `vl new main` in the
/// same clone copy nothing.
#[test]
fn s3rd_a_workspace_switch_does_not_copy_fetched_files_into_the_main_store() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    admin.ok(&thin, &["ws", "new", "other", "-r", "main"]);
    admin.ok(&thin, &["rebase", "-s", "other@", "-d", "big"]);
    admin.ok(&thin, &["ws", "switch", "other"]);
    let before = du(&thin.join(".veil/objects"));
    admin.ok(&thin, &["ws", "switch", "default"]);
    admin.ok(&thin, &["ws", "rm", "other"]);
    admin.ok(&thin, &["gc"]);
    let after = du(&thin.join(".veil/objects"));
    assert!(after < before + 100_000, "switching away from a workspace of fetched, unchanged files put {} bytes into the main store", after - before);
}

/// Guarantees 5 and 6: a thin clone that pulls in full from a second
/// remote (a fork on the same server), commits locally, pulls its own
/// server's new commit, rebases its local commit onto it, visits the fork
/// and is evicted down to 100 KiB: after each step `vl gc` completes (it
/// never says part of the history could not be read) and `vl fsck` finds
/// nothing corrupt; afterwards everything named is still readable, and
/// the fork's snapshots are never asked of the clone's server.
#[test]
fn s3rd_gc_completes_across_a_second_remote_pulls_commits_rebases_and_evictions() {
    let hub = TestHub::start();
    let (admin, name, fork) = project_and_fork(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let pusher = admin.dir("pusher");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), pusher.to_str().unwrap()]);
    let mut log = Vec::new();
    let check = |step: &str, log: &mut Vec<String>| {
        let gc = admin.ok(&thin, &["gc"]);
        let fsck = admin.run(&thin, &["fsck"]);
        let fsck_out = format!("{}{}", String::from_utf8_lossy(&fsck.stdout), String::from_utf8_lossy(&fsck.stderr));
        log.push(format!("after {step}:\n{gc}\nfsck: {fsck_out}"));
        assert!(!gc.contains("could not be read"), "{}", log.join("\n"));
        assert!(fsck.status.success() && fsck_out.contains("No corruption found"), "{}", log.join("\n"));
    };
    admin.ok(&thin, &["remote", "add", "fork", &hub.url(&fork)]);
    admin.ok(&thin, &["pull", "fork"]);
    check("a full pull of the fork", &mut log);
    write_files(&thin, &[("local/mine.txt", "local work 4d1e\n")]);
    admin.ok(&thin, &["commit", "-m", "local work"]);
    check("a local commit", &mut log);
    write_files(&pusher, &[("src/lib.rs", "fn lib() { 99 }\n")]);
    admin.commit_main(&pusher, "pushed later");
    admin.ok(&pusher, &["push"]);
    admin.ok(&thin, &["pull"]);
    check("a pull of the clone's own server", &mut log);
    admin.ok(&thin, &["rebase", "-s", "@-", "-d", "origin/main"]);
    check("a rebase onto the new tip", &mut log);
    admin.ok(&thin, &["new", "fork/main"]);
    admin.ok(&thin, &["new", "origin/main"]);
    admin.ok(&thin, &["partial", "limit", "100K"]);
    admin.ok(&thin, &["partial", "limit", "100K"]);
    check("an eviction", &mut log);
    admin.ok(&thin, &["remote", "rm", "fork"]);
    check("removing the fork", &mut log);
    for (rev, path) in [("origin/main", "src/lib.rs"), ("origin/main-", "src/lib.rs")] {
        let o = admin.run(&thin, &["cat", "-r", rev, path]);
        assert!(o.status.success(), "{rev}: {}\n{}", String::from_utf8_lossy(&o.stderr), log.join("\n"));
    }
    let local = admin.ok(&thin, &["log", "--json"]);
    let mine = json(&local)["entries"].as_array().unwrap().iter().find(|e| e["description"].as_str().is_some_and(|d| d.trim() == "local work")).unwrap()["snapshot_id"].as_str().unwrap().to_string();
    assert!(admin.ok(&thin, &["cat", "-r", &mine, "local/mine.txt"]).contains("local work 4d1e"));
}

/// Guarantees 4 and 5 for the remote a thin clone fetches from (BUG-1292):
/// `vl remote rm origin` would leave the clone's `partial` marker naming a
/// remote that is gone, so the clone would have no server and an evicted
/// file under local work could no longer be read. The removal is refused,
/// with the remedy, and changes nothing: the remote is still there and the
/// clone still reads through it. After `vl partial full` (the remedy) the
/// removal succeeds and everything stays readable without a server.
#[test]
fn s3rd_removing_a_thin_clones_remote_leaves_it_readable_or_is_refused() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 6, 20_000);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    // Local work on the tip: the tip's own root tree is pinned by nothing.
    write_files(&thin, &[("local/mine.txt", "local work 4d1e\n")]);
    admin.ok(&thin, &["commit", "-m", "local work"]);
    let err = admin.fails(&thin, &["remote", "rm", "origin"]);
    assert!(
        err.contains(
            "this thin clone fetches what it does not hold from remote 'origin'; make it a full clone first (`vl partial full`), then remove the remote"
        ),
        "{err}"
    );
    assert_eq!(repo_json(&thin)["partial"]["remote"], "origin");
    assert!(admin.ok(&thin, &["remote", "list"]).contains("origin"));
    // Still read through it, after an eviction.
    admin.ok(&thin, &["partial", "limit", "10K"]);
    let o = admin.run(&thin, &["cat", "-r", "origin/main", "data/f5.bin"]);
    assert!(o.status.success(), "a file of the checked-out tip is unreadable: {}", String::from_utf8_lossy(&o.stderr));
    // The remedy: a full clone, whose remote can go.
    admin.ok(&thin, &["partial", "full"]);
    admin.ok(&thin, &["remote", "rm", "origin"]);
    assert!(repo_json(&thin).get("partial").is_none_or(|p| p.is_null()), "{}", repo_json(&thin));
    let o = admin.run(&thin, &["cat", "-r", "@-", "data/f5.bin"]);
    assert!(o.status.success(), "a file of the local work is unreadable without a server: {}", String::from_utf8_lossy(&o.stderr));
    admin.ok(&thin, &["fsck"]);
}

/// Guarantee 1 (and 3) for `vl serve --local`'s read methods, which
/// answer "with exactly the document its command prints with `--json`"
/// (`docs/reference/json-rpc.md`): in a thin clone, the `log` method lists
/// what `vl log --json` lists. `serve.rs` calls `api::log`, whose walk
/// with no ids is `Held::visible_iter` (`api::log_entries_with`): the
/// snapshots the clone holds, outside any `Exact`.
#[test]
fn s3rd_serve_log_in_a_thin_clone_is_vl_log() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 6, 10);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let mut server = admin.command(&thin, &["serve", "--local"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
    let sock = thin.join(".veil/local/sock");
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let o = admin.run(&thin, &["serve", "--call", "log", "{\"limit\": 50}"]);
    let _ = server.kill();
    let _ = server.wait();
    let served = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(o.status.success(), "{served}{}", String::from_utf8_lossy(&o.stderr));
    let count = |v: &serde_json::Value| v["entries"].as_array().map_or(0, |e| e.len());
    let cli = json(&admin.ok(&thin, &["log", "--json", "-n", "50"]));
    assert_eq!(count(&json(&served)), count(&cli), "the served log lists otherwise than `vl log --json`:\nserved: {served}");
}

/// Guarantee 1 for `vl status` and `vl log` after a pull: a full and a
/// thin clone at the same state pull the same pushed commit; both then
/// show the same history and the same status.
#[test]
fn s3rd_status_and_log_after_a_pull_match_a_full_clone() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 6, 10);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    write_files(&dir, &[("src/lib.rs", "fn lib() { 77 }\n"), ("data/new.bin", "new\n")]);
    admin.commit_main(&dir, "pushed after the clones");
    admin.ok(&dir, &["push"]);
    let known: Vec<String> = json(&admin.ok(&dir, &["log", "--json"]))["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["current"] != serde_json::json!(true))
        .filter_map(|e| e["change_id"].as_str().map(str::to_string))
        .collect();
    for c in [&full, &thin] {
        admin.ok(c, &["pull"]);
        admin.ok(c, &["new", "main"]);
    }
    assert_eq!(history_shape(&admin, &thin, &known), history_shape(&admin, &full, &known));
    let status = |d: &Path| admin.ok(d, &["status"]).lines().filter(|l| !l.starts_with("Working copy :")).collect::<Vec<_>>().join("\n");
    assert_eq!(status(&thin), status(&full));
    assert_eq!(admin.ok(&thin, &["files"]), admin.ok(&full, &["files"]));
}

// ---- S3 redesign review, cycle 2: `s3rd2_…` -------------------------------------

/// BUG-1316 (guarantee 2 of cycle 2: a thin clone answers as a full clone;
/// BUG-866's class). A member pushes a snapshot dated `i64::MAX` (the push
/// accepts any timestamp), then ordinary commits on top. The server's
/// generations clamp a timestamp to `MAX_STAMP` (`i64::MAX / 4`,
/// `derive/graph.rs`, `query/graph.rs:105`); the client's history index
/// does not (`graph_index.rs`, `above.max(s.timestamp.max(0))`). A thin
/// clone takes its boundary's generations from the server (`q/generations`,
/// the BUG-1291 fix) and computes the rest itself, so once it pages in the
/// history below the tip, a parent's generation is above its child's:
/// `vl describe` of the commit on the far-future one finds no descendant
/// above it (`Exact::down_to` stops below the rewritten generation) and
/// leaves `after 1`, `after 2`, `main` and `@` on the old version, where a
/// full clone rebases them.
#[test]
fn s3rd2_a_far_future_timestamp_does_not_split_a_thin_clones_history() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let tip = c.tip;
    c.file("src/far-future-7d20.txt", "x");
    let (_, r) = c.push_edited("main", Some(tip), |s| s.timestamp = i64::MAX);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", r.json());
    for i in 0..3 {
        let mut c = Craft::new(&api, &p.dev, &p.name, "main");
        c.file(&format!("src/after-{i}-7d20.txt"), "y");
        let r = c.push("main", &format!("after {i}"));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["results"][0]["ok"], true, "{}", r.json());
    }
    let full = p.admin.dir("full");
    p.admin.ok(p.admin.home.path(), &["clone", "--full", &hub.url(&p.name), full.to_str().unwrap()]);
    let after0: String = change_of(&p.admin, &full, "after 0").chars().take(12).collect();
    let known: Vec<String> = json(&p.admin.ok(&full, &["log", "--json"]))["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["current"] != serde_json::json!(true))
        .filter_map(|e| e["change_id"].as_str().map(str::to_string))
        .collect();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    let reads = vec![s(&["log", "--json", "-r", &format!("{after0}..main")]), s(&["log", "--json", "-r", "::main"])];
    let mut diffs: Vec<String> = first_difference(&p.admin, &hub, &p.name, &full, &reads, "ff").into_iter().collect();
    // A rewrite of the commit on the far-future one, in a fresh full clone
    // and a fresh thin one.
    let op = ["describe", "-r", after0.as_str(), "-m", "after 0, renamed"];
    let (f, t) = (p.admin.dir("ff-full"), p.admin.dir("ff-thin"));
    p.admin.ok(p.admin.home.path(), &["clone", "--full", &hub.url(&p.name), f.to_str().unwrap()]);
    p.admin.ok(p.admin.home.path(), &["clone", &hub.url(&p.name), t.to_str().unwrap()]);
    p.admin.ok(&f, &op);
    p.admin.ok(&t, &op);
    let (hf, ht) = (history_shape(&p.admin, &f, &known), history_shape(&p.admin, &t, &known));
    if hf != ht {
        diffs.push(format!("`vl {}`: history\nfull: {hf:#?}\nthin: {ht:#?}", op.join(" ")));
    }
    assert!(diffs.is_empty(), "past a far-future timestamp a thin clone answers otherwise than a full clone:\n{}", diffs.join("\n\n"));
}

/// Guarantee 5 of cycle 2 (BUG-1292's fix): removing the remote a thin
/// clone fetches from is refused, naming the way out, and changes nothing;
/// the way out (`vl partial full`, then `vl remote rm`) works. (The cycle 1
/// reproduction, `s3rd_removing_a_thin_clones_remote_leaves_it_readable_or_is_refused`,
/// returns early when the removal is refused, so it asserts nothing now.)
#[test]
fn s3rd2_removing_a_thin_clones_own_remote_is_refused_with_the_way_out() {
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 4, 10);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let err = admin.fails(&thin, &["remote", "rm", "origin"]);
    assert!(err.contains("this thin clone fetches what it does not hold from remote 'origin'"), "{err}");
    assert!(err.contains("vl partial full"), "the refusal names no way out: {err}");
    assert_eq!(repo_json(&thin)["partial"]["remote"], "origin");
    assert!(admin.ok(&thin, &["remote", "list"]).contains("origin"));
    admin.ok(&thin, &["partial", "full"]);
    admin.ok(&thin, &["remote", "rm", "origin"]);
    assert!(repo_json(&thin).get("partial").is_none());
    let o = admin.run(&thin, &["log", "--json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

/// BUG-1318 (guarantee 5 of cycle 2; BUG-1292's fix, its second half): a
/// pull from another remote is a full pull: every tree and file its
/// snapshots reach goes into the main store, even for snapshots the thin
/// clone already holds (here `big`, a tip the clone fetched, whose 400 KB
/// of files it never read). The fix walks held snapshots of such a pull
/// (`hub::pull_with`, `held && !main_only`), but the pull asks only for
/// the tips the store lacks (`want_tips`: `widen || !store.has(t)`): with
/// every tip held, as here and in BUG-1292's own reproduction (the same
/// URL added under another name), it asks for nothing and copies nothing.
#[test]
fn s3rd2_a_pull_from_another_remote_puts_what_its_snapshots_reach_in_the_main_store() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let before = du(&thin.join(".veil/objects"));
    admin.ok(&thin, &["remote", "add", "up", &hub.url(&name)]);
    admin.ok(&thin, &["pull", "up"]);
    let after = du(&thin.join(".veil/objects"));
    // The 400 KB are random hex text, which the main store's packs
    // compress to about half.
    assert!(after >= before + 180_000, "a full pull from another remote put only {} bytes into the main store", after.saturating_sub(before));
    // Exactly: every snapshot `up`'s tips reach, and every tree and file
    // of each, is in the main store (not the cache).
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&thin)), None, "test").unwrap();
    let store = repo.store();
    let mut stack: Vec<veil_core::ObjectId> = repo.view().remote_tags.iter().filter(|(k, _)| k.starts_with("up/")).map(|(_, v)| *v).collect();
    assert!(stack.len() >= 2, "{:?}", repo.view().remote_tags);
    let (mut seen, mut objects) = (std::collections::HashSet::new(), Vec::new());
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        objects.push(id);
        match store.get(&id).unwrap() {
            Object::Snapshot(s) => stack.extend(s.parents.iter().copied().chain([s.tree])),
            Object::Tree(t) => stack.extend(t.entries.iter().map(|e| e.id)),
            _ => {}
        }
    }
    let lacking: Vec<String> = objects.iter().filter(|id| !store.has_main(id)).map(|id| id.short()).collect();
    assert!(lacking.is_empty(), "{} of {} objects `up` reaches are not in the main store: {lacking:?}", lacking.len(), objects.len());
    drop(repo);
    // The clone's own server's history is untouched: still thin, origin's
    // tips as they were.
    assert_eq!(repo_json(&thin)["partial"]["remote"], "origin");
    let o = admin.run(&thin, &["cat", "-r", "origin/big", "big/f07.bin"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

/// Guarantee 4 of cycle 2 (BUG-1293's fix): the unchanged-file shortcut of
/// a rescan (a directory a `vl ws switch` leaves without a stat cache)
/// never reuses a file whose mode changed. A fetched file made executable
/// after a switch round trip is recorded as changed, and executable.
#[test]
fn s3rd2_a_rescanned_fetched_file_whose_mode_changed_is_recorded() {
    use std::os::unix::fs::PermissionsExt;
    let hub = TestHub::start();
    let (admin, _dir, name) = project_with_history(&hub, 3, 10);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    admin.ok(&thin, &["ws", "new", "other", "-r", "main"]);
    admin.ok(&thin, &["ws", "switch", "other"]);
    admin.ok(&thin, &["ws", "switch", "default"]);
    let f = thin.join("data/f1.bin");
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    let st = admin.ok(&thin, &["status"]);
    assert!(st.contains("data/f1.bin"), "a mode change is not seen after a rescan: {st}");
    admin.ok(&thin, &["commit", "-m", "make f1 executable"]);
    let d = admin.ok(&thin, &["diff", "--json", "--from", "@--", "--to", "@-"]);
    assert!(d.contains("data/f1.bin"), "the commit does not record the mode change: {d}");
}

/// BUG-1319 (guarantee 2 of cycle 2: a thin clone answers as a full clone
/// made at the same time; introduced by the BUG-1268 fix to `history`).
/// A thin clone and a full clone are made; then the admin rewrites the
/// first change (`vl describe`, which rewrites everything above it) and
/// force-pushes. Neither clone has pulled: both still stand on the old
/// versions. The full clone holds them and shows their history; the thin
/// clone pages history in from them, and `sync::history` now starts a page
/// only from snapshots the branches reach (an old version is left out, as
/// an unknown one is), so the page is empty: `vl log` ends at the old tip,
/// and `vl show main--` says the revision is not found.
#[test]
fn s3rd2_a_thin_clone_reads_its_own_history_after_a_rewrite_elsewhere() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 6, 10);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let first: String = change_of(&admin, &dir, "first").chars().take(12).collect();
    admin.ok(&dir, &["describe", "-r", &first, "-m", "first, renamed"]);
    admin.ok(&dir, &["push", "--force"]);
    let mut diffs = Vec::new();
    for args in [vec!["log", "--json"], vec!["show", "--json", "main--"], vec!["show", "--json", "main-----"]] {
        let (want, got) = (answer(&admin, &full, &args), answer(&admin, &thin, &args));
        assert!(want.0, "`vl {}` fails in the full clone: {}", args.join(" "), want.1);
        if got != want {
            diffs.push(format!("`vl {}`:\nfull: {}\nthin ({}): {}", args.join(" "), want.1.chars().take(600).collect::<String>(), got.0, got.1.chars().take(600).collect::<String>()));
        }
    }
    assert!(diffs.is_empty(), "after a rewrite elsewhere, a thin clone reads its own history otherwise than a full clone:\n{}", diffs.join("\n\n"));
}

/// BUG-1316's class: one arithmetic for generations. A thin clone's history
/// index mixes the server's generations (its boundary's, `q/generations`)
/// with its own, so the two must be equal for every snapshot. On random
/// histories (several roots, equal timestamps, timestamps below 0 and far
/// in the future, `i64::MAX` among them), the client's history index, the
/// server's real graph rows and its viewer graph rows give every snapshot
/// the same generation, strictly above each of its parents'.
mod one_generation_arithmetic {
    use std::{collections::HashMap, sync::Arc};

    use proptest::prelude::*;
    use veil_core::{object::Text, ChangeId, MemoryBackend, ObjectId, Repo, Snapshot, StorageBackend};
    use veil_server::{derive::graph::GraphRow, query::graph::VRow};

    #[derive(Clone, Debug)]
    struct Dag {
        /// Node `i`'s parents (earlier nodes); empty: a root.
        parents: Vec<Vec<usize>>,
        times: Vec<i64>,
    }

    fn dag() -> impl Strategy<Value = Dag> {
        (2usize..24).prop_flat_map(|n| {
            let parents = (0..n)
                .map(|i| match i {
                    0 => Just(Vec::new()).boxed(),
                    // About one in eight a root of its own.
                    _ => prop_oneof![1 => Just(Vec::new()), 7 => proptest::collection::vec(0..i, 1..4)].boxed(),
                })
                .collect::<Vec<_>>();
            let stamp = prop_oneof![
                4 => 0i64..4,
                2 => 0i64..1_000,
                1 => Just(i64::MAX),
                1 => (i64::MAX / 4 - 3)..=(i64::MAX / 4 + 3),
                1 => Just(i64::MIN),
                1 => -5i64..0,
            ];
            (parents, proptest::collection::vec(stamp, n))
        })
        .prop_map(|(parents, times)| Dag { parents, times })
    }

    fn snap(parents: Vec<ObjectId>, i: usize, timestamp: i64, tree: ObjectId) -> Snapshot {
        let mut change = [0u8; 16];
        change[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        Snapshot {
            parents,
            change_id: ChangeId(change),
            tree,
            description: Text::default(),
            author: "t".into(),
            timestamp,
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(64),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        #[test]
        fn client_and_server_generations_agree(d in dag()) {
            let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
            let repo = Repo::init(backend, None, "t").unwrap();
            let tree = repo.store().empty_tree().unwrap();
            let mut ids = Vec::new();
            let mut real: HashMap<ObjectId, Arc<GraphRow>> = HashMap::new();
            let mut view: HashMap<ObjectId, Arc<VRow>> = HashMap::new();
            for (i, ps) in d.parents.iter().enumerate() {
                let mut parents: Vec<ObjectId> = Vec::new();
                for p in ps {
                    if !parents.contains(&ids[*p]) {
                        parents.push(ids[*p]);
                    }
                }
                let s = snap(parents.clone(), i, d.times[i], tree);
                let id = repo.store().put_snapshot(&s).unwrap();
                let rp: Vec<(ObjectId, Arc<GraphRow>)> = parents.iter().map(|p| (*p, real[p].clone())).collect();
                let vp: Vec<(ObjectId, Arc<VRow>)> = parents.iter().map(|p| (*p, view[p].clone())).collect();
                real.insert(id, Arc::new(GraphRow::compute(&s, &rp)));
                view.insert(id, Arc::new(VRow::compute(&s, &vp, id)));
                ids.push(id);
            }
            for (i, id) in ids.iter().enumerate() {
                let client = repo.held().index().generation(&repo, id).unwrap().expect("held");
                prop_assert_eq!(client, real[id].generation as u64, "node {}: client against the real graph", i);
                prop_assert_eq!(client, view[id].generation as u64, "node {}: client against the viewer graph", i);
                for p in &d.parents[i] {
                    let pg = repo.held().index().generation(&repo, &ids[*p]).unwrap().unwrap();
                    prop_assert!(client > pg, "node {}: {} not above its parent's {}", i, client, pg);
                }
            }
        }
    }
}

/// BUG-1319's second case: a thin clone and a full clone made before a
/// rewrite elsewhere both pull it. Their old versions are off the branches
/// now, reached only from what each clone held before (its operation log,
/// which a full clone's gc keeps). Both show the same: the evolution log
/// of the rewritten change through its old version, the old versions by
/// full and by short id, and the history.
#[test]
fn s3rd2_a_thin_clone_made_before_a_rewrite_pulls_it_as_a_full_clone() {
    let hub = TestHub::start();
    let (admin, dir, name) = project_with_history(&hub, 6, 10);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let first: String = change_of(&admin, &dir, "first").chars().take(12).collect();
    let old_first = snapshot_of(&admin, &dir, "first");
    let old_three = snapshot_of(&admin, &dir, "commit 3");
    admin.ok(&dir, &["describe", "-r", &first, "-m", "first, renamed"]);
    admin.ok(&dir, &["push", "--force"]);
    for d in [&full, &thin] {
        admin.ok(d, &["pull"]);
    }
    let mut diffs = Vec::new();
    for args in [
        vec!["evolog", "-r", &first],
        vec!["show", "--json", &old_first],
        vec!["show", "--json", &old_first[..12]],
        vec!["show", "--json", &old_three[..12]],
        vec!["log", "--json"],
    ] {
        let (want, got) = (answer(&admin, &full, &args), answer(&admin, &thin, &args));
        assert!(want.0, "`vl {}` fails in the full clone: {}", args.join(" "), want.1);
        if got != want {
            diffs.push(format!("`vl {}`:\nfull ({}): {}\nthin ({}): {}", args.join(" "), want.0, want.1.chars().take(600).collect::<String>(), got.0, got.1.chars().take(600).collect::<String>()));
        }
    }
    assert!(diffs.is_empty(), "a thin clone made before a rewrite shows otherwise than a full clone after pulling it:\n{}", diffs.join("\n\n"));
}

/// BUG-1384 (S3 redesign, cycle 3; properties 2 and 4: a thin clone
/// answers as a full clone; the viewer graph is a cache, refilled when it
/// is cleared). A thin clone and a full clone made before a rewrite
/// elsewhere both pull it; their old tip stays a head (its tag diverged).
/// Then the server is upgraded: migration 21 clears the viewer graph
/// (`TRUNCATE view_graph`), and the server starts again. A thin clone
/// names what its server does not show it from its own refs (`from`,
/// BUG-1319), sending only those `q/generations` knows
/// (`Repo::server_roots`); `q/generations` answers from rows already in the
/// viewer graph, and refills only what the branches reach. The old tip is
/// no longer filled, so it reads as the clone's own unpushed work, and the
/// old versions below it, which the clone does not hold, are named by no
/// root: "revision … not found", where the full clone shows them (and the
/// thin clone did before the cache was cleared).
#[test]
fn s3rd3_a_thin_clone_names_its_old_versions_after_the_viewer_graph_is_cleared() {
    // A database of its own: the clear below would empty every concurrent
    // test's viewer graph, whose hubs keep its rows in memory and would
    // never fill them again.
    let admin_url = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
    let db_name = format!("{}{}", std::env::var("VEIL_TEST_DB_PREFIX").unwrap_or_default(), unique("veil_cleared_"));
    let sql = |url: &str, q: String| {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let db = veil_server::db::connect(url, 1).await.unwrap();
            sqlx::raw_sql(&q).execute(&db).await.unwrap();
            db.close().await;
        });
    };
    sql(&admin_url, format!("CREATE DATABASE {db_name}"));
    let url = format!("{}/{db_name}", admin_url.rsplit_once('/').unwrap().0);
    let hub = TestHub::start_on(&url, std::time::Duration::from_secs(3600));
    let (admin, dir, name) = project_with_history(&hub, 6, 10);
    let full = admin.dir("full");
    admin.ok(admin.home.path(), &["clone", "--full", &hub.url(&name), full.to_str().unwrap()]);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let first: String = change_of(&admin, &dir, "first").chars().take(12).collect();
    let old_three = snapshot_of(&admin, &dir, "commit 3");
    admin.ok(&dir, &["describe", "-r", &first, "-m", "first, renamed"]);
    admin.ok(&dir, &["push", "--force"]);
    for d in [&full, &thin] {
        admin.ok(d, &["pull"]);
    }
    let hub = hub.restart(|url| {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let db = veil_server::db::connect(url, 1).await.unwrap();
            // What migration 21 does (and the new table, which it creates empty).
            sqlx::raw_sql("TRUNCATE view_graph; TRUNCATE view_changes").execute(&db).await.unwrap();
            db.close().await;
        });
    });
    let mut diffs = Vec::new();
    for args in [vec!["show", "--json", &old_three[..12]], vec!["show", "--json", &old_three]] {
        let want = answer(&admin, &full, &args);
        assert!(want.0 && want.1.contains(&old_three), "the full clone shows the old version (`vl {}`): {}", args.join(" "), want.1);
        let got = answer(&admin, &thin, &args);
        if got != want {
            diffs.push(format!("`vl {}`: thin ({}): {}", args.join(" "), got.0, got.1.chars().take(400).collect::<String>()));
        }
    }
    drop(hub);
    sql(&admin_url, format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)"));
    assert!(diffs.is_empty(), "after the viewer graph is cleared, a thin clone names its old versions otherwise than a full clone:\n{}", diffs.join("\n"));
}
