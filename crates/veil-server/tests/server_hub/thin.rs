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
    let st = std::fs::read_to_string(thin.join(".veil/local/checkout.json")).unwrap();
    let written = (0..20).filter(|i| thin.join(format!("big/f{i:02}.bin")).exists()).count();
    if o.status.success() {
        let cache = du(&thin.join(".veil/cache"));
        assert!(written == 20 && cache <= 100 * 1024 + 64 * 1024, "the checkout left {cache} bytes in a cache bounded at 100 KiB:\n{out}");
    } else {
        assert!(!st.contains("pending") && written == 0, "a failed checkout wrote {written} of 20 files and left {st}:\n{out}");
    }
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
/// move the working copy onto `big`'s 400 KB: either it moved, within the
/// bound, or it failed and recorded nothing, so the next command works.
fn assert_a_failed_move_records_nothing(admin: &Person, thin: &Path, cmd: &[&str], o: std::process::Output) {
    let out = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    if o.status.success() {
        let cache = du(&thin.join(".veil/cache"));
        assert!(cache <= 100 * 1024 + 64 * 1024, "`vl {}` left {cache} bytes in a cache bounded at 100 KiB:\n{out}", cmd.join(" "));
        return;
    }
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
    let o = admin.run(&thin, &["op", "log", "--json"]);
    let ops = json(&String::from_utf8_lossy(&o.stdout));
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
#[ignore = "BUG-1261: a pulled tag named like an unheld change's id hides that change in a thin clone"]
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
                out.contains("first") && !out.contains("commit 5"),
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
    let o = admin.run(&thin, &["op", "log", "--json"]);
    let before = json(&String::from_utf8_lossy(&o.stdout))["operations"][0]["op_id"].as_str().unwrap().to_string();
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
        // The edit is in the directory, or saved in a change.
        let on_disk = std::fs::read_to_string(copy.join("src/lib.rs")).unwrap_or_default().contains("edited_while_behind");
        let o = admin.run(&copy, &["log", "-p"]);
        let logged = String::from_utf8_lossy(&o.stdout).contains("edited_while_behind");
        assert!(on_disk || logged, "`vl {}` lost the edit made while the directory was behind `@`:\n{out}\n{after}", cmd.join(" "));
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
#[ignore = "BUG-1262: vl bisect in a thin clone searches only the held snapshots"]
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
#[ignore = "BUG-1263: vl ws switch past the cache bound records the switch, says it switched, and does not"]
fn s3r3_a_workspace_switch_past_the_cache_bound_switches_or_records_nothing() {
    let hub = TestHub::start();
    let (admin, name) = project_with_big_branch(&hub);
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", "--cache-size", "100K", &hub.url(&name), thin.to_str().unwrap()]);
    admin.ok(&thin, &["ws", "new", "other", "-r", "big"]);
    let o = admin.run(&thin, &["ws", "switch", "other"]);
    let out = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let attached = json(&std::fs::read_to_string(thin.join(".veil/local/checkout.json")).unwrap())["workspace"].as_str().unwrap().to_string();
    let o2 = admin.run(&thin, &["op", "log", "-n", "1"]);
    let head = String::from_utf8_lossy(&o2.stdout).to_string();
    if o.status.success() {
        assert!(
            attached == "other" && thin.join("big/f00.bin").exists(),
            "`vl ws switch other` succeeded, yet the directory is attached to '{attached}':\n{out}\n{head}"
        );
    } else {
        assert!(!head.contains("switch the project directory"), "a failed switch was recorded:\n{out}\n{head}");
    }
    // What the warning advises undoes the switch, nothing else.
    let undo = admin.ok(&thin, &["undo"]);
    assert!(!undo.contains("create workspace"), "`vl undo` undid an unrelated operation:\n{out}\n{undo}");
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
#[ignore = "BUG-1265: a second remote's snapshots count as the thin clone's server's; a move onto one wedges the clone"]
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
#[ignore = "BUG-1266: a thin clone does not find the change id of a change beyond its boundary"]
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

