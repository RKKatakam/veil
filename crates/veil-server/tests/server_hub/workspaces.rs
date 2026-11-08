//! S8: workspaces that fetch on first read, against the real server
//! (`docs/design/server/phase-2-thin-clients.md` §4.6, §4.8). A thin clone
//! holds `main`'s content; the `feature` branch's trees and files are on
//! the server only, so a workspace on `feature` reads them on demand:
//!
//! * a mounted workspace shows exactly its person's projection, the same as
//!   a full clone's checkout, through `vl ws mount`, `vl ws exec --mount`
//!   and the fallback without FUSE; nothing hidden is fetched;
//! * listing and `stat` fetch no file's content; reading a file fetches its
//!   folder's small files with it;
//! * a server that cannot be reached is an I/O error in the mount, never a
//!   missing or empty file; without FUSE the run fails before it starts;
//! * recording a mount fetches nothing and records exactly the edits;
//! * the sandbox's `vl` shows only what its person may see;
//! * a sparse sandbox (`--only`) fetches only its paths.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Output,
};

use veil_core::object::Object;

use super::support::*;

/// Folders of `wide/` on `feature`, each with small files and one big one.
const FOLDERS: usize = 6;
const SMALL: usize = 20;
const BIG: usize = 300 << 10;
const FEATURE_MARK: &str = "MARKER-FEATURE-PUBLIC-5d1c0e77";
const FEATURE_BILL: &str = "MARKER-FEATURE-BILLING-c3a7e210";
/// `EIO`, `EACCES` and `ENOENT` on Linux.
const EIO: i32 = 5;
const EACCES: i32 = 13;
const ENOENT: i32 = 2;

/// The standard project, plus a `feature` branch the thin clones of it
/// have not fetched: `wide/fN/` folders, and a billing file.
fn project_with_feature(hub: &TestHub) -> Project {
    let p = setup_project(hub);
    let mut files: Vec<(String, String)> = Vec::new();
    for f in 0..FOLDERS {
        for i in 0..SMALL {
            files.push((format!("src/wide/f{f}/s{i}.txt"), format!("{FEATURE_MARK} {f} {i}\n")));
        }
        files.push((format!("src/wide/f{f}/big.bin"), "b".repeat(BIG)));
    }
    files.push((format!("{BILL_DIR}/acme/q2.txt"), FEATURE_BILL.into()));
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    write_files(&p.dir, &refs);
    // `main` stays where it is: only `feature` has this work.
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "feature work"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    p
}

/// A thin clone of `who`, with workspace `agent` on `feature`.
fn thin_with_agent(p: &Project, hub: &TestHub, who: &Person, name: &str) -> PathBuf {
    let d = who.dir(name);
    who.ok(who.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    if who.name != p.admin.name {
        who.ok(&d, &["identity", "confirm", &p.fp]);
    }
    who.ok(&d, &["ws", "new", "agent", "-r", "feature"]);
    d
}

/// The files of `feature` as `who`'s full clone checks them out.
fn reference(p: &Project, hub: &TestHub, who: &Person) -> BTreeMap<String, Vec<u8>> {
    let d = who.dir("reference");
    who.ok(who.home.path(), &["clone", "--full", &hub.url(&p.name), d.to_str().unwrap()]);
    if who.name != p.admin.name {
        who.ok(&d, &["identity", "confirm", &p.fp]);
    }
    who.ok(&d, &["new", "feature"]);
    walk(&d)
}

/// Every file under `dir` (but `.veil`), with its content.
fn walk(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("{}: {e}", d.display())).flatten() {
            let p = e.path();
            let rel = p.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
            if rel == ".veil" || rel.starts_with(".veil/") {
                continue;
            }
            if e.file_type().unwrap().is_dir() {
                stack.push(p);
            } else {
                out.insert(rel, std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())));
            }
        }
    }
    out
}

/// A mount of `ws`, unmounted (recording it) when dropped.
struct Mounted<'a> {
    who: &'a Person,
    clone: PathBuf,
    ws: String,
    dir: PathBuf,
}

impl<'a> Mounted<'a> {
    fn new(who: &'a Person, clone: &Path, ws: &str) -> Mounted<'a> {
        let dir = who.dir(&format!("mnt-{}", unique("m")));
        who.ok(clone, &["ws", "mount", ws, dir.to_str().unwrap()]);
        Mounted { who, clone: clone.to_path_buf(), ws: ws.to_string(), dir }
    }

    fn unmount(self) -> String {
        let out = self.who.ok(&self.clone, &["ws", "unmount", &self.ws]);
        std::mem::forget(self);
        out
    }
}

impl Drop for Mounted<'_> {
    fn drop(&mut self) {
        let _ = self.who.run(&self.clone, &["ws", "unmount", &self.ws]);
        let _ = std::process::Command::new("fusermount3").args(["-u", "-z"]).arg(&self.dir).output();
    }
}

/// `(trees, files)` in a thin clone's cache: files are blobs and sealed
/// secrets.
fn cached(clone: &Path) -> (usize, usize, Vec<veil_core::ObjectId>) {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    let cache = repo.store().cache().expect("a thin clone").clone();
    let (mut trees, mut files, mut ids) = (0, 0, Vec::new());
    for id in cache.list_objects().unwrap() {
        match cache.get(&id) {
            Ok(Object::Tree(_)) => trees += 1,
            Ok(Object::Blob(_)) | Ok(Object::Sealed(_)) => {
                files += 1;
                ids.push(id);
            }
            _ => {}
        }
    }
    (trees, files, ids)
}

/// The id of `path` in `feature`, as `who`'s clone holds it: `None` when
/// the clone has not even fetched the folders on its way.
fn try_id_of(clone: &Path, path: &str) -> Option<veil_core::ObjectId> {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    repo.store().never_fetch();
    let tip = repo.view().remote_tags.iter().find(|(k, _)| k.contains("feature")).map(|(_, v)| *v).expect("feature");
    let tree = repo.snapshot(&tip).unwrap().tree;
    veil_core::tree::lookup(repo.store(), &tree, &veil_core::VPath::new(path).unwrap()).ok().flatten().map(|e| e.id)
}

/// [`try_id_of`], which must be known.
fn id_of(who: &Person, clone: &Path, path: &str) -> veil_core::ObjectId {
    let _ = who;
    try_id_of(clone, path).unwrap_or_else(|| panic!("{path}: its folders are not fetched"))
}

/// Has `clone` fetched the file at `path` of `feature`?
fn fetched(clone: &Path, path: &str) -> bool {
    let ids = cached(clone).2;
    try_id_of(clone, path).is_some_and(|id| ids.contains(&id))
}

fn all(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

#[test]
fn a_mounted_workspace_shows_exactly_its_persons_projection() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    for who in [&p.dev, &p.admin] {
        let want = reference(&p, &hub, who);
        assert!(want.keys().any(|k| k.starts_with("src/wide/f0/")), "the reference has the feature's files");
        let thin = thin_with_agent(&p, &hub, who, "thin");
        // `vl ws mount`.
        let m = Mounted::new(who, &thin, "agent");
        let got = walk(&m.dir);
        assert_eq!(got.keys().collect::<Vec<_>>(), want.keys().collect::<Vec<_>>(), "{}: the mount's files", who.name);
        assert!(got == want, "{}: the mount's contents differ from a full clone's", who.name);
        if who.name == p.dev.name {
            let items: Vec<(String, Vec<u8>)> = got.iter().map(|(k, v)| (k.clone(), v.clone())).chain(got.keys().map(|k| (format!("name {k}"), k.as_bytes().to_vec()))).collect();
            assert_no_marker(&items, &[&restricted_markers()[..], &[FEATURE_BILL]].concat(), "dev's mount");
            assert_no_marker(&everything_in(&thin), &[FEATURE_BILL, BILL_MARK], "dev's thin clone after reading the mount");
        } else {
            assert!(got.values().any(|v| v == FEATURE_BILL.as_bytes()), "the admin sees billing");
        }
        m.unmount();
        // `vl ws exec --mount`, and the fallback without FUSE: the command
        // sees the same files.
        for no_fuse in [false, true] {
            let mut c = who.command(&thin, &["ws", "exec", "agent", "--mount", "--", "sh", "-c", "find . -type f ! -path './.veil/*' | LC_ALL=C sort | while read f; do echo \"== $f\"; cat \"$f\" | head -c 80; echo; done"]);
            if no_fuse {
                c.env("VEIL_TEST_NO_FUSE", "1");
            }
            let o = c.output().unwrap();
            assert!(o.status.success(), "{}: {}", who.name, all(&o));
            let out = String::from_utf8_lossy(&o.stdout).into_owned();
            let listed: Vec<&str> = out.lines().filter_map(|l| l.strip_prefix("== ./")).collect();
            assert_eq!(listed, want.keys().map(String::as_str).collect::<Vec<_>>(), "{} no_fuse={no_fuse}", who.name);
            if who.name == p.dev.name {
                for m in [&restricted_markers()[..], &[FEATURE_BILL]].concat() {
                    assert!(!out.contains(m), "dev's sandbox shows {m}");
                }
            }
        }
    }
}

#[test]
fn listing_fetches_no_file_and_reading_one_fetches_its_folder() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let thin = thin_with_agent(&p, &hub, &p.dev, "thin");
    let want = reference(&p, &hub, &p.dev);
    let m = Mounted::new(&p.dev, &thin, "agent");
    let (_, files0, _) = cached(&thin);
    // `ls -lR`, `find`, `stat` of everything: sizes right, no file fetched.
    let o = std::process::Command::new("ls").arg("-lR").arg(&m.dir).output().unwrap();
    assert!(o.status.success(), "{}", all(&o));
    let o = std::process::Command::new("find").arg(&m.dir).args(["-type", "f", "-printf", "%P %s\n"]).output().unwrap();
    assert!(o.status.success(), "{}", all(&o));
    let sizes: BTreeMap<String, u64> = String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| l.rsplit_once(' ').map(|(p, s)| (p.to_string(), s.parse().unwrap())))
        .collect();
    let want_sizes: BTreeMap<String, u64> = want.iter().map(|(k, v)| (k.clone(), v.len() as u64)).collect();
    assert_eq!(sizes, want_sizes, "stat's sizes");
    let (_, files1, _) = cached(&thin);
    assert_eq!(files1, files0, "listing the mount fetched file contents");
    // Reading one small file of a folder fetches the folder's small files
    // in the same request, and nothing of other folders or big files.
    let s0 = std::fs::read(m.dir.join("src/wide/f2/s3.txt")).unwrap();
    assert_eq!(s0, format!("{FEATURE_MARK} 2 3\n").as_bytes());
    let (_, _, ids) = cached(&thin);
    for i in 0..SMALL {
        assert!(ids.contains(&id_of(&p.dev, &thin, &format!("src/wide/f2/s{i}.txt"))), "s{i}.txt of the folder read was not fetched with it");
    }
    assert!(!ids.contains(&id_of(&p.dev, &thin, "src/wide/f2/big.bin")), "a big file was fetched with its folder");
    for f in [0, 1, 3] {
        assert!(!fetched(&thin, &format!("src/wide/f{f}/s0.txt")), "folder f{f} was fetched");
    }
    // The big file reads when it is read.
    assert_eq!(std::fs::read(m.dir.join("src/wide/f2/big.bin")).unwrap().len(), BIG);
    m.unmount();
}

#[test]
fn an_unreachable_server_is_an_error_in_the_mount_never_a_missing_file() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let thin = thin_with_agent(&p, &hub, &p.admin, "thin");
    let m = Mounted::new(&p.admin, &thin, "agent");
    let read = std::fs::read(m.dir.join("src/wide/f0/s0.txt")).unwrap();
    assert!(String::from_utf8_lossy(&read).contains(FEATURE_MARK));
    // Listed, not read: f1's files are known by name only.
    let names: Vec<_> = std::fs::read_dir(m.dir.join("src/wide/f1")).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(names.len(), SMALL + 1);
    drop(hub);
    // What was fetched still reads; what was not is an I/O error, never
    // "no such file" and never empty.
    assert_eq!(std::fs::read(m.dir.join("src/wide/f0/s0.txt")).unwrap(), read);
    let e = std::fs::read(m.dir.join("src/wide/f1/s0.txt")).expect_err("an unfetched file read without its server");
    assert_eq!(e.raw_os_error(), Some(EIO), "{e}");
    // A folder whose tree was never fetched: listing it is an error, and so
    // is looking it up.
    let deep = m.dir.join(format!("{BILL_DIR}/acme"));
    let e = std::fs::read_dir(&deep).expect_err("an unfetched folder listed without its server");
    assert_eq!(e.raw_os_error(), Some(EIO), "{e}");
    let e = std::fs::metadata(deep.join("q2.txt")).expect_err("a file of an unfetched folder looked up without its server");
    assert_eq!(e.raw_os_error(), Some(EIO), "{e}");
    // Through a mounted run: the command meets the error.
    let o = p.admin.run(&thin, &["ws", "exec", "agent", "--mount", "--", "sh", "-c", "cat src/wide/f1/s1.txt; echo rc=$?"]);
    let out = all(&o);
    assert!(out.contains("Input/output error") && out.contains("rc=1"), "{out}");
    // Without FUSE the sandbox is checked out before the command runs: it
    // fails before running anything, naming the server.
    let mut c = p.admin.command(&thin, &["ws", "exec", "other", "--mount", "--", "sh", "-c", "echo ran > ran.txt"]);
    p.admin.ok(&thin, &["ws", "new", "other", "-r", "feature"]);
    c.env("VEIL_TEST_NO_FUSE", "1");
    let o = c.output().unwrap();
    let out = all(&o);
    assert!(!o.status.success() && out.contains("could not be reached"), "{out}");
    assert!(!out.contains("ran"));
    m.unmount();
}

#[test]
fn recording_a_mount_fetches_nothing_and_holds_exactly_its_edits() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let thin = thin_with_agent(&p, &hub, &p.admin, "thin");
    let m = Mounted::new(&p.admin, &thin, "agent");
    // What the edits below read (a rename and an overwrite copy the old
    // file up first), and the folders they touch, are fetched first; a
    // command records the mount, which writes what was fetched to the cache.
    for f in ["src/wide/f0/s7.txt", "src/wide/f3/s1.txt"] {
        std::fs::read(m.dir.join(f)).unwrap();
    }
    for d in ["src/wide/f4", "src/wide/f5"] {
        std::fs::read_dir(m.dir.join(d)).unwrap().for_each(drop);
    }
    p.admin.ok(&thin, &["status"]);
    let before = cached(&thin);
    std::fs::write(m.dir.join("src/wide/f3/s1.txt"), "edited\n").unwrap();
    std::fs::remove_file(m.dir.join("src/wide/f4/s2.txt")).unwrap();
    std::fs::create_dir_all(m.dir.join("src/wide/f5/new")).unwrap();
    std::fs::write(m.dir.join("src/wide/f5/new/n.txt"), "new\n").unwrap();
    std::fs::rename(m.dir.join("src/wide/f0/s7.txt"), m.dir.join("src/wide/f0/renamed.txt")).unwrap();
    m.unmount();
    let after = cached(&thin);
    assert_eq!((after.0, after.1), (before.0, before.1), "the edits or their recording fetched objects");
    let o = p.admin.ok(&thin, &["show", "agent@", "--stat", "--json"]);
    let v: serde_json::Value = serde_json::from_str(o.lines().find(|l| l.starts_with('{')).unwrap()).unwrap();
    let mut changed: Vec<String> = v["diff"]["files"].as_array().unwrap().iter().map(|c| format!("{} {}", c["status"].as_str().unwrap(), c["path"].as_str().unwrap())).collect();
    changed.sort();
    assert_eq!(
        changed,
        ["added src/wide/f5/new/n.txt", "deleted src/wide/f4/s2.txt", "modified src/wide/f3/s1.txt", "renamed src/wide/f0/renamed.txt"].map(String::from).to_vec()
    );
}

#[test]
fn the_sandboxs_vl_shows_only_what_its_person_may_see() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let thin = thin_with_agent(&p, &hub, &p.dev, "thin");
    let script = format!(
        "vl status; vl log -n 10; vl show feature; vl diff --from main --to feature; vl blame {BILL_DIR}/acme/q2.txt; vl blame src/lib.rs; \
         vl access {BILL_DIR}/ devs; echo end"
    );
    let o = p.dev.run(&thin, &["ws", "exec", "agent", "--mount", "--", "sh", "-c", &script]);
    let out = all(&o);
    assert!(o.status.success() && out.contains("end"), "{out}");
    assert!(out.contains(FEATURE_MARK) || out.contains("src/wide"), "the sandbox's vl answers: {out}");
    // (The script names the billing folder itself, and `vl` echoes it:
    // only what is inside counts.)
    for m in [&restricted_markers()[..], &[FEATURE_BILL]].concat().into_iter().filter(|m| *m != BILL_DIR) {
        assert!(!out.contains(m), "dev's sandbox vl showed {m}: {out}");
    }
    assert!(!out.contains("q2.txt  ") && !out.contains(&format!("{BILL_DIR}/acme/invoice")), "{out}");
    assert!(out.contains("not available inside a sandbox"), "{out}");
}

#[test]
fn a_sparse_sandbox_fetches_only_its_paths() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let thin = thin_with_agent(&p, &hub, &p.admin, "thin");
    let o = p.admin.run(&thin, &["ws", "exec", "agent", "--only", "src/wide/f1", "--", "sh", "-c", "cat src/wide/f1/s4.txt; ls src/wide"]);
    let out = all(&o);
    assert!(o.status.success() && out.contains(&format!("{FEATURE_MARK} 1 4")), "{out}");
    assert!(fetched(&thin, "src/wide/f1/s4.txt"));
    for f in [0, 2, 3] {
        assert!(!fetched(&thin, &format!("src/wide/f{f}/s0.txt")), "folder f{f}, outside --only, was fetched");
    }
}

/// BUG-1360: after an upgrade that changes the secret scanner's rules, the
/// next recording of a workspace re-reads every file of it; in a thin clone
/// that fetches the whole workspace (here: a mount's first recording after
/// the rules changed). A new workspace is not re-scanned any more (`vl ws
/// new` marks it scanned).
#[test]
#[ignore = "BUG-1360: a re-scan after a scanner-rules upgrade fetches a thin clone's whole workspace"]
fn bug_1360_a_rules_rescan_fetches_the_whole_thin_workspace() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let thin = thin_with_agent(&p, &hub, &p.admin, "thin");
    // As if this device last scanned the workspace with older rules.
    std::fs::write(thin.join(".veil/local/scanned/agent.version"), "0").unwrap();
    let m = Mounted::new(&p.admin, &thin, "agent");
    std::fs::write(m.dir.join("src/wide/new.txt"), "new\n").unwrap();
    let before = cached(&thin).1;
    m.unmount();
    let after = cached(&thin).1;
    assert!(after - before < SMALL, "the recording fetched {} files of the workspace", after - before);
}

/// §4.8's numbers: a fresh workspace on a branch this thin clone never
/// fetched, mounted, to the first `ls` and `cat` ("ready"), cold (nothing of
/// the branch fetched) and warm (mounted again); and reading 1,000 files of
/// 10 folders cold. `S8_BENCH_FILES` (default `2000,50000`): the branch's
/// files, 100 a folder. Run through `bench-quiet.sh`, with a release `vl`.
#[test]
#[ignore = "benchmark: S8_BENCH_FILES, run by hand through bench-quiet.sh"]
fn s8_bench_ready_to_read() {
    use std::time::Instant;
    let sizes: Vec<usize> = std::env::var("S8_BENCH_FILES")
        .unwrap_or_else(|_| "2000,50000".into())
        .split(',')
        .map(|s| s.trim().parse().unwrap())
        .collect();
    let hub = TestHub::start();
    let ms = |t: Instant| format!("{:.0} ms", t.elapsed().as_secs_f64() * 1000.0);
    for n in sizes {
        let admin = hub.person("admin");
        let name = unique("bench");
        let dir = admin.dir("proj");
        std::fs::create_dir_all(&dir).unwrap();
        admin.ok(&dir, &["init"]);
        write_files(&dir, &[("README.md", "bench\n")]);
        admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
        admin.commit_main(&dir, "first");
        admin.ok(&dir, &["push"]);
        for i in 0..n {
            let p = dir.join(format!("wide/d{:04}/f{:02}.txt", i / 100, i % 100));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, format!("file {i} {}\n", "x".repeat(200))).unwrap();
        }
        let t = Instant::now();
        admin.ok(&dir, &["commit", "--no-advance", "-m", "wide"]);
        admin.ok(&dir, &["tag", "set", "feature", "-r", "@-"]);
        admin.ok(&dir, &["push"]);
        eprintln!("[{n} files] import and push: {}", ms(t));
        let thin = admin.dir("thin");
        let t = Instant::now();
        admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
        eprintln!("[{n} files] thin clone (main only): {}", ms(t));
        // Cold: nothing of `feature` is in the clone.
        let t0 = Instant::now();
        admin.ok(&thin, &["ws", "new", "agent", "-r", "feature"]);
        let t_new = ms(t0);
        let t1 = Instant::now();
        let m = Mounted::new(&admin, &thin, "agent");
        let t_mount = ms(t1);
        let t2 = Instant::now();
        let top = std::fs::read_dir(m.dir.join("wide")).unwrap().count();
        let t_ls = ms(t2);
        let t3 = Instant::now();
        let first = std::fs::read(m.dir.join("wide/d0000/f00.txt")).unwrap();
        let t_cat = ms(t3);
        assert!(first.starts_with(b"file 0 ") && top == n.div_ceil(100));
        eprintln!("[{n} files] cold: ws new {t_new}, mount {t_mount}, ls wide/ ({top} folders) {t_ls}, first cat {t_cat}; ready {}", ms(t0));
        // 1,000 files of 10 folders, cold.
        let t4 = Instant::now();
        let mut bytes = 0;
        for d in 1..=10.min(n / 100 - 1) {
            for f in 0..100 {
                bytes += std::fs::read(m.dir.join(format!("wide/d{d:04}/f{f:02}.txt"))).unwrap().len();
            }
        }
        eprintln!("[{n} files] read {} files of 10 folders cold: {} ({bytes} bytes)", 10.min(n / 100 - 1) * 100, ms(t4));
        m.unmount();
        // Warm: the same workspace mounted again.
        let t5 = Instant::now();
        let m = Mounted::new(&admin, &thin, "agent");
        let _ = std::fs::read_dir(m.dir.join("wide")).unwrap().count();
        let again = std::fs::read(m.dir.join("wide/d0000/f00.txt")).unwrap();
        assert_eq!(again, first);
        eprintln!("[{n} files] warm: mount, ls, cat: ready {}", ms(t5));
        m.unmount();
        // A whole run: `vl ws exec --mount` reading one file, cold and warm.
        admin.ok(&thin, &["ws", "new", "agent2", "-r", "feature"]);
        for which in ["cold", "warm"] {
            let f = if which == "cold" { "wide/d0011/f00.txt" } else { "wide/d0000/f00.txt" };
            let t6 = Instant::now();
            let o = admin.ok(&thin, &["ws", "exec", "agent2", "--mount", "--", "cat", f]);
            assert!(o.contains("file "), "{o}");
            eprintln!("[{n} files] ws exec --mount -- cat ({which}): {}", ms(t6));
        }
        let t7 = Instant::now();
        let o = admin.ok(&thin, &["ws", "exec", "agent2", "--", "true"]);
        let _ = o;
        eprintln!("[{n} files] ws exec (checked out, the fallback): first run {}", ms(t7));
    }
}

/// The server's own refusal (access removed after the folder was listed)
/// hides the file: its content never arrives, the read is refused as not
/// this person's, never an I/O error, and listings leave it out from then
/// on.
#[test]
fn a_server_refusal_hides_the_file() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    let acme = m.dir.join(format!("{BILL_DIR}/acme"));
    let names: Vec<String> = std::fs::read_dir(&acme).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"q2.txt".to_string()), "{names:?}");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let r = std::fs::read(acme.join("q2.txt"));
    let e = r.expect_err("a refused file read");
    assert_eq!(e.raw_os_error(), Some(EACCES), "a refusal is 'not yours', never an unreachable server's EIO: {e}");
    // (The kernel keeps a lookup for a second.)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let gone = loop {
        match std::fs::metadata(acme.join("q2.txt")) {
            Err(e) if e.raw_os_error() == Some(ENOENT) => break true,
            _ if std::time::Instant::now() > deadline => break false,
            _ => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    };
    assert!(gone, "a refused file is still looked up");
    let names: Vec<String> = std::fs::read_dir(&acme).map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    assert!(!names.contains(&"q2.txt".to_string()), "a refused file is still listed: {names:?}");
    assert_no_marker(&everything_in(&thin), &[FEATURE_BILL], "fin's clone after the refusal");
    m.unmount();
}

// ---- S8 cycle 2 review (`docs/BUGS.md`, "S8 cycle 2") --------------------

/// BUG-1367: a refusal hides the refused *object* (its id), not the file
/// at its place: a file elsewhere with the same content (an empty file, a
/// licence, a copied config) that the person may read is absent from the
/// mount for 10 s, though the server serves it there.
#[test]
fn bug_1367_a_refusal_hides_only_the_refused_file_not_its_content_elsewhere() {
    const SAME: &str = "SAME-CONTENT-IN-TWO-FOLDERS-b7e24f19\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    write_files(&p.dir, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "same content twice"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    let (shared, acme) = (m.dir.join("src/shared"), m.dir.join(format!("{BILL_DIR}/acme")));
    let names: Vec<String> = std::fs::read_dir(&acme).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"same.txt".to_string()), "{names:?}");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let e = std::fs::read(acme.join("same.txt")).expect_err("the billing copy is refused");
    assert_eq!(e.raw_os_error(), Some(EACCES), "{e}");
    // fin still reads src/ (public): the server serves the same content there.
    let got = std::fs::read(shared.join("same.txt"));
    assert_eq!(
        got.as_deref().map_err(|e| e.to_string()),
        Ok(SAME.as_bytes()),
        "a file fin may read is hidden because a file elsewhere with its content was refused"
    );
    m.unmount();
}

/// BUG-1367, the whole class: a copied folder (the same tree at two paths)
/// refused at one path lists and reads at the other.
#[test]
fn a_refused_folder_hides_only_itself_not_its_copy_elsewhere() {
    const SAME: &str = "SAME-FOLDER-CONTENT-41c9e2\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    write_files(&p.dir, &[("src/copy/dup/a.txt", SAME), (&format!("{BILL_DIR}/acme/dup/a.txt"), SAME)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "the same folder twice"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    // The billing copy's folder is met first (listed), not its content.
    let names: Vec<String> = std::fs::read_dir(m.dir.join(format!("{BILL_DIR}/acme"))).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"dup".to_string()), "{names:?}");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let e = std::fs::read_dir(m.dir.join(format!("{BILL_DIR}/acme/dup"))).map(|rd| rd.count()).err();
    assert!(e.is_some_and(|e| e.raw_os_error() != Some(EIO)), "the billing copy is refused, never an I/O error");
    let listed: Vec<String> = std::fs::read_dir(m.dir.join("src/copy/dup")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(listed, ["a.txt"], "the public copy of the folder lists");
    assert_eq!(std::fs::read(m.dir.join("src/copy/dup/a.txt")).unwrap(), SAME.as_bytes());
    m.unmount();
}

// ---- S8 cycle 3 review (`docs/BUGS.md`, "S8 cycle 3") --------------------

/// BUG-1460: BUG-1367's class through the fallback without FUSE. The same
/// content at two paths, its folder at the refused one held from an
/// earlier mount: the fallback's sync (`prefetch_sync`, S3's
/// `prefetch_diff`) and the checkout behind it ask for the object at the
/// first place this process met it (the refused folder sorts first), so
/// the readable copy is left out of the sandbox as "not yours".
#[test]
fn bug_1460_the_fallback_without_fuse_leaves_out_a_readable_copy_of_refused_content() {
    const SAME: &str = "SAME-CONTENT-FALLBACK-1460-9d2e7c51\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    write_files(&p.dir, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "same content twice"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    // An earlier mount listed the billing folder: its tree is held, not
    // its files.
    let m = Mounted::new(&p.fin, &thin, "agent");
    let names: Vec<String> = std::fs::read_dir(m.dir.join(format!("{BILL_DIR}/acme"))).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"same.txt".to_string()), "{names:?}");
    m.unmount();
    assert!(!fetched(&thin, "src/shared/same.txt"), "the content is not fetched yet");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    // fin still reads src/ (public): the server serves the content there,
    // as the mount shows (`bug_1367_…`).
    let mut c = p.fin.command(&thin, &["ws", "exec", "agent", "--mount", "--", "cat", "src/shared/same.txt"]);
    c.env("VEIL_TEST_NO_FUSE", "1");
    let o = c.output().unwrap();
    assert!(o.status.success(), "the fallback left out a file fin may read: {}", all(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains(SAME.trim()), "{}", all(&o));
}

/// BUG-1460 in a thin clone's own checkout (the root cause is S3's: every
/// fetch asked at the first place the content was met): the project
/// directory moved to a revision holding a readable copy of content
/// refused elsewhere checks the readable copy out.
#[test]
fn a_thin_checkout_writes_a_readable_copy_of_content_refused_elsewhere() {
    const SAME: &str = "SAME-CONTENT-CHECKOUT-1460-4b7a90e3\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    write_files(&p.dir, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "same content twice"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    // The billing folder's tree is met first (a mount listed it).
    let m = Mounted::new(&p.fin, &thin, "agent");
    let names: Vec<String> = std::fs::read_dir(m.dir.join(format!("{BILL_DIR}/acme"))).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"same.txt".to_string()), "{names:?}");
    m.unmount();
    assert!(!fetched(&thin, "src/shared/same.txt"), "the content is not fetched yet");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&thin, &["new", "feature"]);
    let got = std::fs::read_to_string(thin.join("src/shared/same.txt"));
    assert_eq!(got.as_deref().map_err(|e| e.to_string()), Ok(SAME), "the checkout left out a file fin may read: {out}");
}

/// Guarantee 1 of the S8 cycle 3 review, in the mount: with the same
/// content at a refused and a readable path, reads of both on several
/// threads at once keep each answer to its path (the readable one always
/// reads, the refused one never does); the refused file cannot be moved
/// into a readable folder, and nothing of it lands there; the readable copy
/// moves between folders and reads at its new place.
#[test]
fn concurrent_reads_and_moves_keep_a_refusal_to_its_path() {
    const SAME: &str = "SAME-CONTENT-MOVES-s8r3-0b6f4e2a\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    write_files(&p.dir, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "same content twice"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    let (shared, acme) = (m.dir.join("src/shared"), m.dir.join(format!("{BILL_DIR}/acme")));
    let names: Vec<String> = std::fs::read_dir(&acme).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"same.txt".to_string()), "{names:?}");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let (good, bad) = std::thread::scope(|s| {
        let readers: Vec<_> = (0..6)
            .map(|i| {
                let (shared, acme) = (&shared, &acme);
                s.spawn(move || {
                    let (mut good, mut bad) = (0, Vec::new());
                    for _ in 0..15 {
                        match i % 2 {
                            0 => match std::fs::read(shared.join("same.txt")) {
                                Ok(d) if d == SAME.as_bytes() => good += 1,
                                r => bad.push(format!("src/shared/same.txt: {:?}", r.map(|d| d.len()))),
                            },
                            // Refused, or (BUG-1464, rule a) once the readable
                            // copy's bytes are held, exactly those bytes.
                            _ => match std::fs::read(acme.join("same.txt")) {
                                Err(e) if matches!(e.raw_os_error(), Some(EACCES) | Some(ENOENT)) => good += 1,
                                Ok(d) if d == SAME.as_bytes() => good += 1,
                                r => bad.push(format!("the refused copy: {:?}", r.map(|d| d.len()).map_err(|e| e.to_string()))),
                            },
                        }
                    }
                    (good, bad)
                })
            })
            .collect();
        readers.into_iter().map(|r| r.join().unwrap()).fold((0, Vec::new()), |(g, mut b), (g2, b2)| {
            b.extend(b2);
            (g + g2, b)
        })
    });
    assert!(bad.is_empty(), "{bad:?}");
    assert_eq!(good, 90);
    // The refused copy never moves into a readable place.
    std::fs::create_dir_all(m.dir.join("src/inbox")).unwrap();
    let mv = std::fs::rename(acme.join("same.txt"), m.dir.join("src/inbox/taken.txt"));
    assert!(mv.is_err(), "the refused file was moved");
    assert!(!m.dir.join("src/inbox/taken.txt").exists(), "a copy of the refused file landed in a readable folder");
    // The readable copy moves, and reads where it went.
    std::fs::rename(shared.join("same.txt"), m.dir.join("src/inbox/moved.txt")).unwrap();
    assert_eq!(std::fs::read(m.dir.join("src/inbox/moved.txt")).unwrap(), SAME.as_bytes());
    assert!(!shared.join("same.txt").exists());
    m.unmount();
    let rec = p.fin.ok(&thin, &["ws", "cat", "agent", "src/inbox/moved.txt"]);
    assert!(rec.contains(SAME.trim()), "{rec}");
}

// ---- S8 cycle 3 fixes, re-check (`docs/BUGS.md`, "S8 cycle 3 fixes re-check") --

/// BUG-1462: BUG-1460's class one level up. A copied folder (the same tree
/// at a refused and a readable path): the file below it has one place, in
/// that tree, and `climb` takes the tree's first place (the refused one),
/// so a reader by id asks only there and the thin checkout leaves out the
/// readable copy.
#[test]
fn bug_1462_a_thin_checkout_hides_a_readable_copy_of_a_folder_refused_elsewhere() {
    const SAME: &str = "SAME-FOLDER-CHECKOUT-1462-7c03e9b1\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    write_files(&p.dir, &[("src/copy/dup/a.txt", SAME), (&format!("{BILL_DIR}/acme/dup/a.txt"), SAME)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "the same folder twice"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    // The billing folder is held from an earlier mount (it sorts first).
    let m = Mounted::new(&p.fin, &thin, "agent");
    let names: Vec<String> = std::fs::read_dir(m.dir.join(format!("{BILL_DIR}/acme"))).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"dup".to_string()), "{names:?}");
    m.unmount();
    assert!(!fetched(&thin, "src/copy/dup/a.txt"), "the content is not fetched yet");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&thin, &["new", "feature"]);
    let got = std::fs::read_to_string(thin.join("src/copy/dup/a.txt"));
    assert_eq!(got.as_deref().map_err(|e| e.to_string()), Ok(SAME), "the checkout left out a file fin may read: {out}");
}

/// BUG-1463: the locator's bound. The same content at 9 refused places met
/// first (an empty `__init__.py` in 9 packages of a refused folder) fills
/// its first place and its 8 others; the readable copy met after them is
/// not kept, so a reader by id never asks there and the thin checkout
/// leaves it out.
#[test]
fn bug_1463_a_readable_copy_past_the_locators_bound_is_left_out() {
    const SAME: &str = "SAME-CONTENT-BOUND-1463-e41a6d08\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let mut files: Vec<(String, &str)> = (0..9).map(|i| (format!("{BILL_DIR}/acme/same-{i}.txt"), SAME)).collect();
    files.push(("src/shared/same.txt".into(), SAME));
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), *b)).collect();
    write_files(&p.dir, &refs);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "the same content at ten places"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    let names: Vec<String> = std::fs::read_dir(m.dir.join(format!("{BILL_DIR}/acme"))).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"same-8.txt".to_string()), "{names:?}");
    m.unmount();
    assert!(!fetched(&thin, "src/shared/same.txt"), "the content is not fetched yet");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&thin, &["new", "feature"]);
    let got = std::fs::read_to_string(thin.join("src/shared/same.txt"));
    assert_eq!(got.as_deref().map_err(|e| e.to_string()), Ok(SAME), "the checkout left out a file fin may read: {out}");
}

/// Guarantees 1 and 2 of the re-check, in the mount, past the bound: the
/// same content at 9 refused places and a readable one, the refused ones
/// met first; the readable copy reads, no refused copy does.
#[test]
fn the_mount_reads_a_readable_copy_past_the_locators_bound_and_no_refused_one() {
    const SAME: &str = "SAME-CONTENT-MOUNT-BOUND-s8x-5f2c90d1\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let mut files: Vec<(String, &str)> = (0..9).map(|i| (format!("{BILL_DIR}/acme/same-{i}.txt"), SAME)).collect();
    files.push(("src/shared/same.txt".into(), SAME));
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), *b)).collect();
    write_files(&p.dir, &refs);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "the same content at ten places"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    let acme = m.dir.join(format!("{BILL_DIR}/acme"));
    let names: Vec<String> = std::fs::read_dir(&acme).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"same-8.txt".to_string()), "{names:?}");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    for i in 0..9 {
        let r = std::fs::read(acme.join(format!("same-{i}.txt")));
        assert!(r.as_ref().is_err_and(|e| matches!(e.raw_os_error(), Some(EACCES) | Some(ENOENT))), "same-{i}.txt: {:?}", r.map(|d| d.len()));
    }
    assert_eq!(std::fs::read(m.dir.join("src/shared/same.txt")).unwrap(), SAME.as_bytes());
    // Once held (BUG-1464, rule a), a refused path naming those bytes
    // reads them, or stays hidden while its refusal is fresh: never
    // anything else.
    for i in 0..9 {
        let r = std::fs::read(acme.join(format!("same-{i}.txt")));
        let ok = match &r {
            Ok(d) => d == SAME.as_bytes(),
            Err(e) => matches!(e.raw_os_error(), Some(EACCES) | Some(ENOENT)),
        };
        assert!(ok, "after the readable read, same-{i}.txt: {:?}", r.map(|d| d.len()));
    }
    m.unmount();
}

/// BUG-1464, decided (option a, as S3 serves a file held from before access
/// was removed): content already on this machine reads at every path that
/// names it, a refused one included. Removal of access stops new fetches;
/// the person already holds those bytes. So a refused path holding the same
/// bytes as a readable copy reads exactly those bytes once they are held,
/// in the same mount and in a new one, and never anything else.
#[test]
fn bug_1464_held_content_reads_at_every_path_naming_it() {
    const SAME: &str = "SAME-CONTENT-READABLE-FIRST-s8x-a83d17c4\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    write_files(&p.dir, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "same content twice"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    let names: Vec<String> = std::fs::read_dir(m.dir.join(format!("{BILL_DIR}/acme"))).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"same.txt".to_string()), "{names:?}");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    // The readable copy first: it reads, and its content is now held.
    assert_eq!(std::fs::read(m.dir.join("src/shared/same.txt")).unwrap(), SAME.as_bytes());
    assert!(fetched(&thin, "src/shared/same.txt"), "the readable read fetched it");
    // The refused path names the same held bytes: they read, and only they.
    assert_eq!(std::fs::read(m.dir.join(format!("{BILL_DIR}/acme/same.txt"))).unwrap(), SAME.as_bytes(), "in the same mount");
    m.unmount();
    let m = Mounted::new(&p.fin, &thin, "agent");
    assert_eq!(std::fs::read(m.dir.join(format!("{BILL_DIR}/acme/same.txt"))).unwrap(), SAME.as_bytes(), "in a new mount");
    // What was never held stays refused: the billing folder's own file.
    let e = std::fs::read(m.dir.join(format!("{BILL_DIR}/acme/q2.txt"))).expect_err("a refused file never held");
    assert!(matches!(e.raw_os_error(), Some(EACCES) | Some(ENOENT)), "{e}");
    m.unmount();
}

/// Guarantee 5 of the re-check: a stale thin checkout (its billing folder
/// held from before access was removed) that reads content refused at one
/// path where it is readable writes only what fin may read: the readable
/// copy's bytes, and nothing of the refused folder's own content.
#[test]
fn a_stale_checkout_writes_nothing_its_person_may_not_read() {
    const SAME: &str = "SAME-CONTENT-STALE-s8x-3e9b0c72\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    write_files(&p.dir, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "same content twice"]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    let names: Vec<String> = std::fs::read_dir(m.dir.join(format!("{BILL_DIR}/acme"))).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(names.contains(&"same.txt".to_string()), "{names:?}");
    m.unmount();
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&thin, &["new", "feature"]);
    assert_eq!(std::fs::read_to_string(thin.join("src/shared/same.txt")).map_err(|e| e.to_string()).as_deref(), Ok(SAME), "{out}");
    // Nothing of the refused folder's own content.
    let files = walk(&thin);
    assert!(files.values().all(|d| !String::from_utf8_lossy(d).contains(FEATURE_BILL)), "{:?}", files.keys().collect::<Vec<_>>());
    assert!(!files.contains_key(&format!("{BILL_DIR}/acme/q2.txt")), "{:?}", files.keys().collect::<Vec<_>>());
    // What the refused path holds, if anything, is the readable copy's bytes.
    let at = files.get(&format!("{BILL_DIR}/acme/same.txt"));
    eprintln!("s8x: the refused path in the working copy: {:?}", at.map(|d| String::from_utf8_lossy(d).into_owned()));
    assert!(at.is_none_or(|d| d == SAME.as_bytes()), "{at:?}");
    let st = p.fin.ok(&thin, &["status"]);
    eprintln!("s8x: status: {st}");
}

// ---- S8 cycle 3 re-check fixes, re-check (`docs/BUGS.md`, "S8 cycle 3 re-check fixes, re-check") --

/// Requests the server has authenticated so far (each looks its session up
/// once): what a command cost, as the difference before and after it.
fn requests(hub: &TestHub) -> u64 {
    use std::sync::atomic::Ordering::Relaxed;
    let h = hub.hub();
    h.caches.stats.session_hits.load(Relaxed) + h.caches.stats.session_misses.load(Relaxed)
}

/// `feature` moved on by one commit holding `files`, and `removed` gone.
fn feature_with(p: &Project, files: &[(&str, &str)], removed: &[&str], msg: &str) {
    write_files(&p.dir, files);
    for r in removed {
        std::fs::remove_file(p.dir.join(r)).unwrap();
    }
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", msg]);
    p.admin.ok(&p.dir, &["tag", "set", "feature", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
}

fn list(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())).flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()
}

/// Does a file in `clone`'s cache hold `marker`?
fn cache_has(clone: &Path, marker: &str) -> bool {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    let cache = repo.store().cache().expect("a thin clone").clone();
    cache.list_objects().unwrap().into_iter().any(|id| matches!(cache.get(&id), Ok(Object::Blob(b)) if String::from_utf8_lossy(&b).contains(marker)))
}

fn refused_read(r: &std::io::Result<Vec<u8>>) -> bool {
    r.as_ref().is_err_and(|e| matches!(e.raw_os_error(), Some(EACCES) | Some(ENOENT)))
}

/// Guarantees 1 and 2 with the readable copy met first (it sorts before
/// the refused one: `src/a-open/` before `src/sec-…/`), in the mount, a
/// thin checkout and the fallback without FUSE: the readable copy reads
/// and is written; the refused folder's own file, never held, is never
/// read, written or fetched; the refused copy, once its bytes are held,
/// holds exactly them or nothing.
#[test]
fn the_same_bytes_with_the_readable_copy_met_first_keep_each_answer_to_its_path() {
    const SAME: &str = "SAME-CONTENT-READABLE-SORTS-FIRST-s8y-61d0c4a7\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let nested = format!("src/{NESTED_DIR}");
    const OWN: &str = "MARKER-NESTED-FEATURE-ONLY-s8y-93b1e0d4";
    feature_with(&p, &[("src/a-open/same.txt", SAME), (&format!("{nested}/same.txt"), SAME), (&format!("{nested}/own.txt"), OWN)], &[], "same content twice, readable first");
    let (thin, thin2, thin3) =
        (thin_with_agent(&p, &hub, &p.sec, "thin"), thin_with_agent(&p, &hub, &p.sec, "thin2"), thin_with_agent(&p, &hub, &p.sec, "thin3"));
    // Each clone's mount listed the security folder: its tree is held.
    let m = Mounted::new(&p.sec, &thin, "agent");
    let names = list(&m.dir.join(&nested));
    assert!(names.contains(&"same.txt".to_string()) && names.contains(&"own.txt".to_string()), "{names:?}");
    for t in [&thin2, &thin3] {
        let m2 = Mounted::new(&p.sec, t, "agent");
        assert!(list(&m2.dir.join(&nested)).contains(&"same.txt".to_string()));
        m2.unmount();
    }
    p.admin.ok(&p.dir, &["group", "remove", "security", &p.sec.name]);
    // The mount: the refused copy read first, while nothing is held.
    let r = std::fs::read(m.dir.join(format!("{nested}/same.txt")));
    assert!(refused_read(&r), "the refused copy read before anything was held: {:?}", r.map(|d| d.len()));
    assert_eq!(std::fs::read(m.dir.join("src/a-open/same.txt")).unwrap(), SAME.as_bytes());
    let r = std::fs::read(m.dir.join(format!("{nested}/own.txt")));
    assert!(refused_read(&r), "the refused folder's own file: {:?}", r.map(|d| d.len()));
    m.unmount();
    // A thin checkout.
    let out = p.sec.ok(&thin2, &["new", "feature"]);
    let files = walk(&thin2);
    assert_eq!(files.get("src/a-open/same.txt").map(|d| d.as_slice()), Some(SAME.as_bytes()), "{out}");
    assert!(!files.contains_key(&format!("{nested}/own.txt")), "{out}");
    let at = files.get(&format!("{nested}/same.txt"));
    assert!(at.is_none_or(|d| d == SAME.as_bytes()), "{at:?}");
    // The fallback without FUSE.
    let mut c = p.sec.command(&thin3, &["ws", "exec", "agent", "--mount", "--", "sh", "-c", &format!("cat src/a-open/same.txt; cat {nested}/own.txt; echo end")]);
    c.env("VEIL_TEST_NO_FUSE", "1");
    let o = c.output().unwrap();
    let out = all(&o);
    assert!(o.status.success() && out.contains("end"), "{out}");
    assert!(out.contains(SAME.trim()), "the fallback left out a file sec may read: {out}");
    assert!(!out.contains(OWN), "{out}");
    for t in [&thin, &thin2, &thin3] {
        assert!(!cache_has(t, OWN), "sec's clone fetched the refused folder's own file");
    }
}

/// Guarantee 2 through the fallback without FUSE, with and without
/// `--only` (`prefetch_diff_below`, `prefetch_at`), for BUG-1462's shape (a
/// copied folder whose refused copy is met first) and BUG-1463's (the same
/// content at 9 refused places met first): every readable copy is in the
/// sandbox, and nothing of the refused folder's own content.
#[test]
fn the_fallback_writes_readable_copies_of_a_refused_folder_and_past_nine_places() {
    const SAME: &str = "SAME-CONTENT-FALLBACK-s8y-2b9e71c0\n";
    const DUP: &str = "SAME-FOLDER-FALLBACK-s8y-c47a0e15\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let mut files: Vec<(String, &str)> = (0..9).map(|i| (format!("{BILL_DIR}/acme/same-{i}.txt"), SAME)).collect();
    files.push(("src/shared/same.txt".into(), SAME));
    files.push(("src/copy/dup/a.txt".into(), DUP));
    files.push((format!("{BILL_DIR}/acme/dup/a.txt"), DUP));
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), *b)).collect();
    feature_with(&p, &refs, &[], "copies at ten places, and a copied folder");
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    let names = list(&m.dir.join(format!("{BILL_DIR}/acme")));
    assert!(names.contains(&"same-8.txt".to_string()) && names.contains(&"dup".to_string()), "{names:?}");
    m.unmount();
    assert!(!fetched(&thin, "src/shared/same.txt") && !fetched(&thin, "src/copy/dup/a.txt"), "nothing is fetched yet");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let runs: [&[&str]; 4] = [&["--mount"], &["--only", "src"], &["--only", "src/copy"], &["--only", "src/shared/same.txt"]];
    for args in runs {
        let mut argv = vec!["ws", "exec", "agent"];
        argv.extend_from_slice(args);
        let script = "cat src/shared/same.txt 2>&1; cat src/copy/dup/a.txt 2>&1; echo end";
        argv.extend_from_slice(&["--", "sh", "-c", script]);
        let mut c = p.fin.command(&thin, &argv);
        c.env("VEIL_TEST_NO_FUSE", "1");
        let o = c.output().unwrap();
        let out = all(&o);
        assert!(o.status.success() && out.contains("end"), "{args:?}: {out}");
        if args.contains(&"src/copy") {
            assert!(out.contains(DUP.trim()), "{args:?}: the copied folder's readable copy is left out: {out}");
        } else if args.contains(&"src/shared/same.txt") {
            assert!(out.contains(SAME.trim()), "{args:?}: the readable copy is left out: {out}");
        } else {
            assert!(out.contains(SAME.trim()) && out.contains(DUP.trim()), "{args:?}: a readable copy is left out: {out}");
        }
        assert!(!out.contains(FEATURE_BILL) && !out.contains(BILL_MARK), "{args:?}: {out}");
    }
    assert!(!cache_has(&thin, FEATURE_BILL), "fin's clone fetched the refused folder's own file");
}

/// Guarantees 1 and 2 across renames, in a thin checkout: content moved
/// out of a refused folder into a readable one is written there; content
/// moved from a readable folder into a refused one is the held bytes or
/// nothing there; a new file of the refused folder, never held, is never
/// written or fetched.
#[test]
fn renames_into_and_out_of_a_refused_folder_keep_each_answer_to_its_path() {
    const OUT: &str = "RENAMED-OUT-OF-BILLING-s8y-90a3f6d2\n";
    const IN: &str = "RENAMED-INTO-BILLING-s8y-5e17b2c8\n";
    const NEW: &str = "MARKER-NEW-BILLING-s8y-d02c8e4b";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let bill = format!("{BILL_DIR}/acme");
    feature_with(&p, &[(&format!("{bill}/out.txt"), OUT), ("src/out/in.txt", IN)], &[], "before the renames");
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    // fin's checkout of `feature` now, with access: then a mount of the
    // workspace lists the billing folder (held).
    p.fin.ok(&thin, &["new", "feature"]);
    let m = Mounted::new(&p.fin, &thin, "agent");
    assert!(list(&m.dir.join(&bill)).contains(&"out.txt".to_string()));
    m.unmount();
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    feature_with(
        &p,
        &[("src/moved/out.txt", OUT), (&format!("{bill}/in.txt"), IN), (&format!("{bill}/new.txt"), NEW)],
        &[&format!("{bill}/out.txt"), "src/out/in.txt"],
        "the renames",
    );
    p.fin.ok(&thin, &["pull"]);
    let out = p.fin.ok(&thin, &["new", "origin/feature"]);
    let files = walk(&thin);
    assert_eq!(files.get("src/moved/out.txt").map(|d| d.as_slice()), Some(OUT.as_bytes()), "moved out of billing: {out}");
    assert!(!files.contains_key("src/out/in.txt"), "{out}");
    let at = files.get(&format!("{bill}/in.txt"));
    assert!(at.is_none_or(|d| d == IN.as_bytes()), "moved into billing: {at:?}");
    assert!(!files.contains_key(&format!("{bill}/new.txt")), "{out}");
    assert!(!cache_has(&thin, NEW), "fin's clone fetched a refused file");
}

/// Guarantee 3 with access removed between two reads, in the mount: what
/// was read (and its folder's small files, fetched with it) while fin had
/// access is held and reads after the removal; a file of another refused
/// folder, never held, stays refused and is never fetched.
#[test]
fn access_removed_between_two_reads_leaves_only_what_was_held() {
    const LATER: &str = "MARKER-BILLING-SAME-FOLDER-s8y-7c2e0a91";
    const OTHER: &str = "MARKER-BILLING-OTHER-FOLDER-s8y-1fb6d3e4";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    feature_with(&p, &[(&format!("{BILL_DIR}/acme/later.txt"), LATER), (&format!("{BILL_DIR}/other/x.txt"), OTHER)], &[], "more billing");
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    assert_eq!(std::fs::read(m.dir.join(format!("{BILL_DIR}/acme/q2.txt"))).unwrap(), FEATURE_BILL.as_bytes());
    assert!(list(&m.dir.join(format!("{BILL_DIR}/other"))).contains(&"x.txt".to_string()));
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    assert_eq!(std::fs::read(m.dir.join(format!("{BILL_DIR}/acme/q2.txt"))).unwrap(), FEATURE_BILL.as_bytes(), "held");
    assert_eq!(std::fs::read(m.dir.join(format!("{BILL_DIR}/acme/later.txt"))).unwrap(), LATER.as_bytes(), "held with its folder");
    let r = std::fs::read(m.dir.join(format!("{BILL_DIR}/other/x.txt")));
    assert!(refused_read(&r), "never held: {:?}", r.map(|d| d.len()));
    m.unmount();
    assert!(!cache_has(&thin, OTHER), "fin's clone fetched a refused file never held");
}

/// Guarantee 4: copies cost nothing more. A thin checkout of a tree with
/// the same file in 20 folders and the same folder at 20 paths asks the
/// server about as often as one without them (a request a level, not one
/// a copy); a mount lists those folders with a request a distinct folder,
/// and reading every copy costs one request.
#[test]
fn copies_cost_one_request_a_folder_in_a_checkout_and_a_mount() {
    const SAME: &str = "SAME-CONTENT-COST-s8y-48e1a7b3\n";
    const DUP: &str = "SAME-FOLDER-COST-s8y-0d93c5f6\n";
    const COPIES: usize = 20;
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let plain = thin_with_agent(&p, &hub, &p.dev, "plain");
    let before = requests(&hub);
    p.dev.ok(&plain, &["new", "feature"]);
    let without = requests(&hub) - before;
    let mut files: Vec<(String, &str)> = Vec::new();
    for i in 0..COPIES {
        files.push((format!("src/copies/c{i:02}/same.txt"), SAME));
        files.push((format!("src/copies/c{i:02}/dup/a.txt"), DUP));
        files.push((format!("src/copies/c{i:02}/dup/b.txt"), DUP));
    }
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), *b)).collect();
    feature_with(&p, &refs, &[], "copies");
    let thin = thin_with_agent(&p, &hub, &p.dev, "thin");
    let before = requests(&hub);
    p.dev.ok(&thin, &["new", "feature"]);
    let with = requests(&hub) - before;
    eprintln!("s8y: checkout requests without copies {without}, with {COPIES} copies {with}");
    let files = walk(&thin);
    for i in 0..COPIES {
        assert_eq!(files.get(&format!("src/copies/c{i:02}/same.txt")).map(|d| d.as_slice()), Some(SAME.as_bytes()));
        assert_eq!(files.get(&format!("src/copies/c{i:02}/dup/b.txt")).map(|d| d.as_slice()), Some(DUP.as_bytes()));
    }
    // Two more levels (`c…/`, `dup/`): a request for each level's folders
    // and one for its files, at most.
    assert!(with <= without + 6, "a checkout of {COPIES} copies cost {with} requests, one without them {without}");
    // The mount.
    let thin2 = thin_with_agent(&p, &hub, &p.dev, "thin2");
    let m = Mounted::new(&p.dev, &thin2, "agent");
    let before = requests(&hub);
    for i in 0..COPIES {
        let names = list(&m.dir.join(format!("src/copies/c{i:02}/dup")));
        assert_eq!(names.len(), 2, "{names:?}");
    }
    let listing = requests(&hub) - before;
    let before = requests(&hub);
    for i in 0..COPIES {
        assert_eq!(std::fs::read(m.dir.join(format!("src/copies/c{i:02}/same.txt"))).unwrap(), SAME.as_bytes());
        assert_eq!(std::fs::read(m.dir.join(format!("src/copies/c{i:02}/dup/a.txt"))).unwrap(), DUP.as_bytes());
    }
    let reading = requests(&hub) - before;
    m.unmount();
    eprintln!("s8y: mount listing {listing} requests, reading every copy {reading}");
    // src/, copies/, 20 c…/ and one dup/ (the same tree at 20 paths).
    assert!(listing <= COPIES as u64 + 3 + 4, "listing {COPIES} folders and a copied one cost {listing} requests");
    assert!(reading <= 4, "reading {} copies of two files cost {reading} requests", 2 * COPIES);
}

/// BUG-1506: guarantee 2 for readers by id that walk a tree (`vl grep`,
/// `vl diff`): with the same content at a refused path met first and a
/// readable one, the readable copy is searched and shown. Passes at
/// `38006165` (`locate_all` asked at every place met); the re-check fixes
/// keep one place an object, the first met, so these readers ask only at
/// the refused path.
#[test]
#[ignore = "BUG-1506: vl grep and vl diff leave out a readable file whose content is refused at a path met first"]
fn bug_1506_readers_by_id_hide_a_readable_copy_of_content_refused_elsewhere() {
    const SAME: &str = "SAME-CONTENT-GREP-1506-a4f2c9e1\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    feature_with(&p, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)], &[], "same content twice");
    let (thin, thin2) = (thin_with_agent(&p, &hub, &p.fin, "thin"), thin_with_agent(&p, &hub, &p.fin, "thin2"));
    // The billing folder is held from an earlier mount (it sorts first).
    for t in [&thin, &thin2] {
        let m = Mounted::new(&p.fin, t, "agent");
        assert!(list(&m.dir.join(format!("{BILL_DIR}/acme"))).contains(&"same.txt".to_string()));
        m.unmount();
        assert!(!fetched(t, "src/shared/same.txt"), "the content is not fetched yet");
    }
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    // Each in a clone of its own: whichever reads the content first makes
    // it held for the others.
    let o = p.fin.run(&thin, &["grep", "-l", "-r", "feature", "SAME-CONTENT-GREP-1506"]);
    let grep = all(&o);
    let d = p.fin.run(&thin2, &["diff", "--from", "main", "--to", "feature"]);
    let diff = all(&d);
    eprintln!("s8y: grep: {grep}\ndiff: {}", diff.lines().filter(|l| l.contains("same") || l.contains("SAME") || l.contains("redact") || l.contains("warning")).collect::<Vec<_>>().join("\n"));
    assert!(d.status.success(), "{diff}");
    assert!(grep.contains("src/shared/same.txt"), "`vl grep` left out a file fin may read: {grep}");
    let shown = diff.split("diff --veil").find(|h| h.contains("b/src/shared/same.txt")).unwrap_or_default();
    assert!(shown.contains(SAME.trim()), "`vl diff` left out the content of a file fin may read: {shown}");
}

/// BUG-1507: `HUB.md` §13.28 says "a refusal hides that path for 10 s, or
/// until something makes its bytes held", and the held rule that held
/// bytes read at every path naming them. A refused path whose bytes another
/// path's read then makes held stays hidden for the rest of the 10 s
/// (`visible_leaf` asks `refused(path)` before `has`).
#[test]
#[ignore = "BUG-1507: a refused path stays hidden for 10 s after its bytes are held, though HUB.md says until they are held"]
fn bug_1507_a_refused_path_stays_hidden_after_its_bytes_are_held() {
    const SAME: &str = "SAME-CONTENT-REFUSED-THEN-HELD-1507-6e0b3d58\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    feature_with(&p, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)], &[], "same content twice");
    let thin = thin_with_agent(&p, &hub, &p.fin, "thin");
    let m = Mounted::new(&p.fin, &thin, "agent");
    let acme = m.dir.join(format!("{BILL_DIR}/acme"));
    assert!(list(&acme).contains(&"same.txt".to_string()));
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let e = std::fs::read(acme.join("same.txt")).expect_err("refused while nothing is held");
    assert_eq!(e.raw_os_error(), Some(EACCES), "{e}");
    assert_eq!(std::fs::read(m.dir.join("src/shared/same.txt")).unwrap(), SAME.as_bytes());
    assert!(fetched(&thin, "src/shared/same.txt"), "held now");
    // (The kernel keeps a lookup for a second.)
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let r = std::fs::read(acme.join("same.txt"));
    m.unmount();
    assert_eq!(r.as_deref().map_err(|e| e.to_string()), Ok(SAME.as_bytes()), "held bytes, hidden at a path naming them for the rest of the 10 s");
}
