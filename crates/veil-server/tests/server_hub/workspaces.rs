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
/// reads; the refused one is refused, or reads exactly the readable copy's
/// bytes once they are held, BUG-1464); once held, the refused path's file
/// moves with exactly those bytes (BUG-1507); the readable copy moves
/// between folders and reads at its new place.
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
    // The readable copy's bytes are held now (its reads above), so the
    // refused path names held bytes: they read there and move from there
    // (BUG-1464, BUG-1507: held bytes read at every path naming them), and
    // what lands is exactly those bytes, never anything else.
    std::fs::create_dir_all(m.dir.join("src/inbox")).unwrap();
    std::fs::rename(acme.join("same.txt"), m.dir.join("src/inbox/taken.txt")).expect("held bytes move from the refused path");
    assert_eq!(std::fs::read(m.dir.join("src/inbox/taken.txt")).unwrap(), SAME.as_bytes());
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

/// BUG-1506's sweep: every other reader that walks a tree or looks a path
/// up and then reads by id (`vl cat`, `vl ls`, `vl show`, `vl blame`, `vl
/// log -S`) reads the readable copy of content whose first place met is
/// refused. Each in a thin clone of its own (whichever reads first makes
/// the content held for the rest of its clone).
#[test]
fn every_reader_by_path_reads_a_readable_copy_of_content_refused_elsewhere() {
    const SAME: &str = "SAME-CONTENT-READERS-1506-7c3e19d0\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    feature_with(&p, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)], &[], "same content twice");
    let names = ["cat", "ls", "show", "blame", "log"];
    let clones: Vec<PathBuf> = names.iter().map(|n| thin_with_agent(&p, &hub, &p.fin, &format!("thin-{n}"))).collect();
    for t in &clones {
        let m = Mounted::new(&p.fin, t, "agent");
        assert!(list(&m.dir.join(format!("{BILL_DIR}/acme"))).contains(&"same.txt".to_string()));
        m.unmount();
        assert!(!fetched(t, "src/shared/same.txt"), "the content is not fetched yet");
    }
    // `vl show` reads the parent's snapshot and tree too: held here (what
    // a clone never fetched of the old view is BUG-1509).
    p.fin.ok(&clones[2], &["ls", "-r", "feature-", BILL_DIR]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let cat = p.fin.ok(&clones[0], &["cat", "-r", "feature", "src/shared/same.txt"]);
    assert_eq!(cat, SAME, "vl cat");
    let ls = p.fin.ok(&clones[1], &["ls", "-r", "feature", "src/shared"]);
    let line = ls.lines().find(|l| l.contains("src/shared/same.txt")).unwrap_or_default();
    assert!(line.contains("public") && !line.contains("redacted"), "vl ls: {ls}");
    let show = p.fin.ok(&clones[2], &["show", "feature"]);
    let hunk = show.split("diff --veil").find(|h| h.contains("b/src/shared/same.txt")).unwrap_or_default();
    assert!(hunk.contains(SAME.trim()), "vl show: {show}");
    let blame = p.fin.ok(&clones[3], &["blame", "-r", "feature", "src/shared/same.txt"]);
    assert!(blame.contains(SAME.trim()), "vl blame: {blame}");
    let log = p.fin.ok(&clones[4], &["log", "-r", "feature", "-S", SAME.trim()]);
    assert!(log.contains("same content twice"), "vl log -S: {log}");
}

/// BUG-1508, decided: a tree the server refuses is never an error and
/// never silently dropped. A reader shows a refused folder as hidden, by the
/// path its parent already named, and nothing inside it. Here: `feature`
/// changes a folder fin loses access to; fin's thin clone holds the trees
/// above it (it read a file of `feature` before), not the folder's own.
#[test]
fn bug_1508_readers_show_a_refused_folder_as_hidden_and_succeed() {
    const SAME: &str = "SAME-CONTENT-SHOW-1508-2d9a6f41\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    feature_with(&p, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)], &[], "same content twice");
    let thin = plain_thin(&p, &hub, "thin");
    for r in ["feature", "feature-"] {
        p.fin.ok(&thin, &["cat", "-r", r, "src/lib.rs"]);
    }
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let hidden_line = format!("redacted {BILL_DIR}/");
    for args in [vec!["show", "feature"], vec!["diff", "--from", "feature-", "--to", "feature"]] {
        let out = p.fin.ok(&thin, &args);
        let hunk = out.split("diff --veil").find(|h| h.contains("b/src/shared/same.txt")).unwrap_or_default();
        assert!(hunk.contains(SAME.trim()), "vl {args:?}: {out}");
        assert!(out.contains(&hidden_line), "vl {args:?} names the refused folder: {out}");
        assert!(!out.contains(&format!("{BILL_DIR}/acme")), "vl {args:?} shows nothing inside the refused folder: {out}");
    }
    let json = p.fin.ok(&thin, &["show", "feature", "--json"]);
    let v: serde_json::Value = serde_json::from_str(json.lines().next().unwrap()).unwrap();
    assert_eq!(v["diff"]["hidden"], serde_json::json!([format!("{BILL_DIR}/")]), "{json}");
    let files: Vec<&str> = v["diff"]["files"].as_array().unwrap().iter().map(|f| f["path"].as_str().unwrap()).collect();
    assert!(files.contains(&"src/shared/same.txt") && !files.iter().any(|f| f.starts_with(BILL_DIR)), "{files:?}");
    let ls = p.fin.ok(&thin, &["ls", "-r", "feature"]);
    assert!(ls.lines().any(|l| l.contains("redacted") && l.contains(&format!("{BILL_DIR}/"))), "vl ls: {ls}");
    assert!(!ls.contains(&format!("{BILL_DIR}/acme")), "vl ls: {ls}");
    let log = p.fin.ok(&thin, &["log", "-r", "feature-..feature", "src"]);
    assert!(log.contains("same content twice"), "vl log: {log}");
    p.fin.ok(&thin, &["blame", "-r", "feature", "src/shared/same.txt"]);
    let cat = p.fin.fails(&thin, &["cat", "-r", "feature", &format!("{BILL_DIR}/acme/same.txt")]);
    assert!(cat.contains("no longer have access") && !cat.contains("not present"), "vl cat: {cat}");
}

/// BUG-1509: the same, in a thin clone that never fetched what it shows.
/// Removing fin from `finance` changes fin's projection of history: every
/// snapshot and every tree above the folder gets a new id in fin's view, and
/// the clone's ids are the old view's. One it holds reads (and a refused
/// folder below it is hidden, BUG-1508); one it never fetched (here
/// `feature`'s parent, needed for `vl show feature`) is no longer served,
/// and the command fails with "not present", where a clone made after the
/// removal shows the readable files (`vl pull` brings the new view).
#[test]
fn bug_1509_a_stale_view_fails_on_what_it_never_fetched() {
    const SAME: &str = "SAME-CONTENT-ROOT-1509-5b1e7c02\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    feature_with(&p, &[("src/shared/same.txt", SAME), (&format!("{BILL_DIR}/acme/same.txt"), SAME)], &[], "same content twice");
    let thin = plain_thin(&p, &hub, "thin");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let show = p.fin.ok(&thin, &["show", "feature"]);
    let hunk = show.split("diff --veil").find(|h| h.contains("b/src/shared/same.txt")).unwrap_or_default();
    assert!(hunk.contains(SAME.trim()), "vl show: {show}");
    // Decided: the clone moved to the current view by itself, once, in one
    // line; nothing of the folder fin lost is shown.
    assert_eq!(show.matches(MOVED).count(), 1, "{show}");
    assert!(!show.contains(&format!("{BILL_DIR}/acme")), "{show}");
}

/// The line `vl` prints when it moves a clone to its person's current view.
const MOVED: &str = "your access changed; moved ";

/// A thin clone of fin's with no workspace.
fn plain_thin(p: &Project, hub: &TestHub, name: &str) -> PathBuf {
    let d = p.fin.dir(name);
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    p.fin.ok(&d, &["identity", "confirm", &p.fp]);
    d
}

/// A thin clone of fin's with change `mine` on `main` (a file in `src/`,
/// and with `billing`, one in the billing folder too), `@` on top of it,
/// and `feature`'s root held; then fin loses access to the billing folder,
/// which `feature` changed.
fn fin_change_across_a_refused_folder(p: &Project, hub: &TestHub, name: &str, billing: bool) -> PathBuf {
    let d = plain_thin(p, hub, name);
    let mut files = vec![("src/mine.txt".to_string(), "fin's change\n".to_string())];
    if billing {
        files.push((format!("{BILL_DIR}/acme/mine.txt"), "fin's billing change\n".into()));
    }
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    write_files(&d, &refs);
    p.fin.ok(&d, &["commit", "-m", "fin's change"]);
    p.fin.ok(&d, &["tag", "set", "mine", "-r", "@-"]);
    p.fin.ok(&d, &["cat", "-r", "feature", "src/lib.rs"]);
    d
}

/// The store of `clone`, opened as a test reads it.
fn open_store(clone: &Path) -> std::sync::Arc<veil_core::store::ObjectStore> {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    repo.store().clone()
}

/// The tree of what `rev` names in `clone` (a tag, or a tag and `-`).
fn tree_of(clone: &Path, rev: &str) -> veil_core::ObjectId {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    let (tag, up) = rev.strip_suffix('-').map_or((rev, false), |t| (t, true));
    let mut s = repo.snapshot(&repo.view().tags[tag].target).unwrap();
    if up {
        s = repo.snapshot(&s.parents[0]).unwrap();
    }
    s.tree
}

/// The entry at `path` in the tree of what `rev` names in `clone`.
fn entry_in(clone: &Path, rev: &str, path: &str) -> veil_core::TreeEntry {
    let tree = tree_of(clone, rev);
    veil_core::tree::lookup(&open_store(clone), &tree, &veil_core::VPath::new(path).unwrap()).unwrap().unwrap()
}

/// What a refused command must leave as it was: the op log's head, the
/// history and every file of the working copy.
fn state(p: &Project, clone: &Path) -> (String, String, BTreeMap<String, Vec<u8>>) {
    let mut files = walk(clone);
    files.retain(|k, _| !k.starts_with(".veil"));
    (p.fin.ok(clone, &["op", "log", "-n", "1", "--json"]), p.fin.ok(clone, &["log", "-n", "50", "--json"]), files)
}

/// BUG-1508, writers: a refused folder only one side changed is carried by
/// its id without reading it, through a merge and a rebase (exact id
/// compared), and through the checkout and the snapshots after them.
#[test]
fn bug_1508_a_merge_and_a_rebase_keep_a_refused_folder_one_side_changed_by_id() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    let (m, r) = (fin_change_across_a_refused_folder(&p, &hub, "merge", false), fin_change_across_a_refused_folder(&p, &hub, "rebase", false));
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let theirs = entry_in(&m, "feature", BILL_DIR);
    assert_ne!(theirs.id, entry_in(&m, "main", BILL_DIR).id, "feature changed the billing folder");
    let out = p.fin.ok(&m, &["merge", "feature", "--into", "mine", "-m", "merge across"]);
    assert!(out.contains("Merged"), "{out}");
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "the checkout leaves the folder out: {out}");
    assert_eq!(entry_in(&m, "mine", BILL_DIR), theirs, "the merge keeps feature's billing folder by id");
    let out = p.fin.ok(&r, &["rebase", "-s", "mine", "-d", "feature"]);
    assert!(out.contains("Rebased"), "{out}");
    assert_eq!(entry_in(&r, "mine", BILL_DIR), theirs, "the rebase keeps feature's billing folder by id");
    // The working copy carries it as recorded, through every snapshot.
    for d in [&m, &r] {
        let st = p.fin.ok(d, &["status"]);
        assert!(st.contains(BILL_DIR), "vl status names the folder kept as recorded: {st}");
        std::fs::write(d.join("src/after.txt"), "after\n").unwrap();
        p.fin.ok(d, &["commit", "-m", "after"]);
        let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(d)), None, "test").unwrap();
        let wc = repo.view().workspace("default").unwrap().wc;
        let tree = repo.snapshot(&repo.snapshot(&wc).unwrap().parents[0]).unwrap().tree;
        let e = veil_core::tree::lookup(repo.store(), &tree, &veil_core::VPath::new(BILL_DIR).unwrap()).unwrap().unwrap();
        assert_eq!(e, theirs, "a later commit keeps the folder by id");
    }
}

/// BUG-1508, writers: a refused folder both sides changed is refused, by a
/// message naming it and saying why, and nothing changes.
#[test]
fn bug_1508_a_merge_and_a_rebase_refuse_a_refused_folder_both_sides_changed() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    let d = fin_change_across_a_refused_folder(&p, &hub, "both", true);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let before = state(&p, &d);
    for args in [vec!["merge", "feature", "--into", "mine", "-m", "merge across"], vec!["rebase", "-s", "mine", "-d", "feature"]] {
        let out = p.fin.fails(&d, &args);
        assert!(out.contains(&format!("{BILL_DIR}/ is a folder you no longer have access to")) && out.contains("nothing was changed"), "vl {args:?}: {out}");
        assert!(!out.contains("not present"), "vl {args:?}: {out}");
        assert_eq!(state(&p, &d), before, "vl {args:?} changed the repository");
    }
}

/// BUG-1507: `HUB.md` §13.28 says "a refusal hides that path for 10 s, or
/// until something makes its bytes held", and the held rule that held
/// bytes read at every path naming them. A refused path whose bytes another
/// path's read then makes held stays hidden for the rest of the 10 s
/// (`visible_leaf` asks `refused(path)` before `has`).
#[test]
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

// ---- Review of `s8h` (BUG-1508's fix): guarantees ----

const Q3: &str = "MARKER-Q3-BILLING-8f2c41aa\n";

/// fin's thin clone with `@` on `feature` (the billing folder written while
/// fin could read it), then `feature` changes the billing folder again, fin
/// holds the trees above it, and loses access: the next checkout leaves the
/// folder out.
fn left_out_by_a_checkout(p: &Project, hub: &TestHub, name: &str) -> PathBuf {
    let d = plain_thin(p, hub, name);
    p.fin.ok(&d, &["new", "feature"]);
    assert!(d.join(format!("{BILL_DIR}/acme/q2.txt")).is_file(), "fin read the billing folder first");
    feature_with(p, &[(&format!("{BILL_DIR}/acme/q3.txt"), Q3), ("src/more.txt", "more\n")], &[], "more billing");
    p.fin.ok(&d, &["pull"]);
    p.fin.ok(&d, &["cat", "-r", "feature", "src/lib.rs"]);
    d
}

/// The entry at `path` in the tree of `@` (snapshotted by the command just
/// run) and of its parent.
fn wc_entries(clone: &Path, path: &str) -> (Option<veil_core::TreeEntry>, Option<veil_core::TreeEntry>) {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    let wc = repo.snapshot(&repo.view().workspace("default").unwrap().wc).unwrap();
    let parent = repo.snapshot(&wc.parents[0]).unwrap();
    let at = |t: &veil_core::ObjectId| veil_core::tree::lookup(repo.store(), t, &veil_core::VPath::new(path).unwrap()).unwrap();
    (at(&wc.tree), at(&parent.tree))
}

/// The files of `files` below `dir/`.
fn below(files: &BTreeMap<String, Vec<u8>>, dir: &str) -> BTreeMap<String, Vec<u8>> {
    files.iter().filter(|(k, _)| k.starts_with(&format!("{dir}/"))).map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// Change `mine` (two files in `src/`) and its child `kid` on `main` in a
/// thin clone of fin's, `@` on top, no tag moved; `feature`'s root held.
fn fin_chain(p: &Project, hub: &TestHub, name: &str) -> PathBuf {
    let d = plain_thin(p, hub, name);
    write_files(&d, &[("src/mine.txt", "fin's change\n"), ("src/mine2.txt", "fin's second file\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "fin's change"]);
    p.fin.ok(&d, &["tag", "set", "mine", "-r", "@-"]);
    write_files(&d, &[("src/kid.txt", "kid\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "kid"]);
    p.fin.ok(&d, &["tag", "set", "kid", "-r", "@-"]);
    p.fin.ok(&d, &["cat", "-r", "feature", "src/lib.rs"]);
    d
}

/// Guarantee 1: no writer loses or changes a refused folder only one side
/// changed. A rebase with a descendant, a split and a squash by path, a
/// whole squash and a commit after the checkout left the folder out each
/// keep `feature`'s billing folder by its exact id (pushing them is
/// BUG-1509's).
#[test]
fn s8h_review_writers_keep_a_refused_folder_by_id() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    let d = fin_chain(&p, &hub, "chain");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let theirs = entry_in(&d, "feature", BILL_DIR);
    assert_ne!(theirs.id, entry_in(&d, "main", BILL_DIR).id, "feature changed the billing folder");
    let keeps = |what: &str, tags: &[&str]| {
        for t in tags {
            assert_eq!(entry_in(&d, t, BILL_DIR), theirs, "{what}: {t} keeps feature's billing folder by id");
        }
    };
    let out = p.fin.ok(&d, &["rebase", "-s", "mine", "-d", "feature"]);
    assert!(out.contains("Rebased"), "{out}");
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "the checkout leaves the folder out: {out}");
    keeps("rebase, with a descendant", &["mine", "kid"]);
    let out = p.fin.ok(&d, &["split", "-r", "mine", "src/mine.txt", "-m", "first"]);
    assert!(out.contains("first") || out.contains("Split"), "{out}");
    p.fin.ok(&d, &["tag", "set", "first", "-r", "mine-"]);
    assert_eq!(p.fin.ok(&d, &["cat", "-r", "first", "src/mine.txt"]), "fin's change\n");
    keeps("split by path", &["first", "mine", "kid"]);
    let out = p.fin.ok(&d, &["squash", "-r", "mine", "src/mine2.txt"]);
    assert!(out.contains("Squashed") || out.contains("Moved"), "{out}");
    assert_eq!(p.fin.ok(&d, &["cat", "-r", "first", "src/mine2.txt"]), "fin's second file\n");
    keeps("squash by path", &["first", "kid"]);
    let out = p.fin.ok(&d, &["squash", "-r", "kid"]);
    assert!(out.contains("Squashed"), "{out}");
    keeps("whole squash", &["first"]);
    write_files(&d, &[("src/after.txt", "after\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "after"]);
    p.fin.ok(&d, &["tag", "set", "after", "-r", "@-"]);
    keeps("commit after the checkout left the folder out", &["after"]);
    // Readers of `after` see the folder hidden, and read the rest.
    let ls = p.fin.ok(&d, &["ls", "-r", "after"]);
    assert!(ls.contains(&format!("{BILL_DIR}/")) && ls.contains("src/kid.txt"), "{ls}");
}

/// Guarantees 2 and 4: the checkout that leaves a folder out removes only
/// what it wrote there; the person's files (a personal key, which stays on
/// the device, and an editor's scratch file) are kept byte for byte, an
/// edit recorded before it is kept in history, and nothing of the refused
/// version is written. When access comes back the folder is written whole
/// again: exactly `feature`'s files, with nothing recorded deleted.
#[test]
fn s8h_review_a_left_out_folder_keeps_the_persons_files_and_comes_back_whole() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    let d = left_out_by_a_checkout(&p, &hub, "wc");
    let pem = format!("{BILL_DIR}/acme/deploy.pem");
    let scratch = format!("{BILL_DIR}/acme/invoice.txt~");
    write_files(&d, &[(&pem, "MINE-PEM-41d0\n"), (&scratch, "MINE-SCRATCH-9a7e\n"), (&format!("{BILL_DIR}/acme/invoice.txt"), "MINE-EDIT-5c2b\n")]);
    p.fin.ok(&d, &["tag", "set", "edits", "-r", "@"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["new", "feature"]);
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "{out}");
    let files = walk(&d);
    let mine = |f: &BTreeMap<String, Vec<u8>>| (f.get(&pem).cloned(), f.get(&scratch).cloned());
    assert_eq!(mine(&files), (Some(b"MINE-PEM-41d0\n".to_vec()), Some(b"MINE-SCRATCH-9a7e\n".to_vec())), "the person's files are kept");
    for gone in ["acme/invoice.txt", "acme/q2.txt", "acme/q3.txt"] {
        assert!(!files.contains_key(&format!("{BILL_DIR}/{gone}")), "{gone}: {:?}", below(&files, BILL_DIR).keys().collect::<Vec<_>>());
    }
    assert!(files.values().all(|v| !String::from_utf8_lossy(v).contains(Q3.trim())), "nothing of the refused version");
    assert_eq!(p.fin.ok(&d, &["cat", "-r", "edits", &format!("{BILL_DIR}/acme/invoice.txt")]), "MINE-EDIT-5c2b\n", "the edit is kept in history");
    let st = p.fin.ok(&d, &["status"]);
    assert!(st.contains(BILL_DIR) && st.contains("no longer have access"), "vl status says the folder is left out: {st}");
    let want = entry_in(&d, "feature", BILL_DIR);
    assert_eq!(wc_entries(&d, BILL_DIR), (Some(want.clone()), Some(want.clone())), "@ carries the folder by id");
    // Access comes back.
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.fin.name]);
    let st = p.fin.ok(&d, &["status"]);
    assert!(st.contains("no changes"), "nothing recorded deleted or added: {st}");
    assert_eq!(wc_entries(&d, BILL_DIR).0, Some(want), "@ still holds feature's folder");
    let mut expected = below(&reference(&p, &hub, &p.fin), BILL_DIR);
    expected.insert(pem.clone(), b"MINE-PEM-41d0\n".to_vec());
    expected.insert(scratch.clone(), b"MINE-SCRATCH-9a7e\n".to_vec());
    assert_eq!(below(&walk(&d), BILL_DIR), expected, "the folder written whole again, nothing duplicated or lost");
}

/// Guarantee 3: readers show a refused folder by its path only: nothing
/// below it (names, sizes, ids, content) in text, JSON or errors, and a
/// path below it reads the same whether or not it exists.
#[test]
fn s8h_review_readers_reveal_nothing_inside_a_refused_folder() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    let d = left_out_by_a_checkout(&p, &hub, "wc");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    p.fin.ok(&d, &["new", "feature"]);
    let q3_id = entry_in(&p.dir, "feature", &format!("{BILL_DIR}/acme/q3.txt")).id.to_string();
    let inside = [format!("{BILL_DIR}/acme"), "q3.txt".into(), "q2.txt".into(), Q3.trim().into(), FEATURE_BILL.into(), q3_id[..16].to_string()];
    let readers: Vec<Vec<&str>> = vec![
        vec!["show", "feature"],
        vec!["show", "feature", "--json"],
        vec!["show", "feature", "--stat"],
        vec!["diff", "--from", "feature-", "--to", "feature", "--json"],
        vec!["ls", "-r", "feature", "--json"],
        vec!["files", "-r", "feature"],
        vec!["grep", "-r", "feature", "--json", "MARKER"],
        vec!["log", "-r", "feature-..feature", "--json"],
        vec!["log", "-r", "feature-..feature", "-S", "MARKER", "--pickaxe-all"],
        vec!["status", "--json"],
    ];
    for args in &readers {
        let out = p.fin.ok(&d, args);
        for n in &inside {
            assert!(!out.contains(n.as_str()), "vl {args:?} shows {n}: {out}");
        }
    }
    let ls: serde_json::Value = serde_json::from_str(p.fin.ok(&d, &["ls", "-r", "feature", "--json"]).lines().next().unwrap()).unwrap();
    let e = ls["entries"].as_array().unwrap().iter().find(|e| e["path"].as_str().is_some_and(|x| x.starts_with(BILL_DIR))).expect("the folder is listed");
    assert_eq!((e["dir"].clone(), e["size"].clone(), e["visibility"].clone()), (serde_json::json!(true), serde_json::Value::Null, serde_json::Value::Null), "{e}");
    let g: serde_json::Value = serde_json::from_str(p.fin.ok(&d, &["grep", "-r", "feature", "--json", "MARKER"]).lines().next().unwrap()).unwrap();
    assert_eq!(g["skipped"]["hidden_folders"], 1, "{g}");
    // A path below it: the same answer whether it exists or not.
    for cmd in ["cat", "blame"] {
        let there = p.fin.fails(&d, &[cmd, "-r", "feature", &format!("{BILL_DIR}/acme/q3.txt")]);
        let absent = p.fin.fails(&d, &[cmd, "-r", "feature", &format!("{BILL_DIR}/acme/q9.txt")]);
        assert!(there.contains("no longer have access"), "{there}");
        assert_eq!(there.replace("q3.txt", "q9.txt"), absent, "vl {cmd}: an existence oracle");
    }
}

/// BUG-1528: a file the person creates in a folder the checkout left out is
/// neither recorded nor reported: `vl status` says "no changes", and `vl
/// commit` records the folder by id without it.
#[test]
fn bug_1528_a_file_made_in_a_left_out_folder_is_not_recorded_silently() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    let d = left_out_by_a_checkout(&p, &hub, "wc");
    write_files(&d, &[(&format!("{BILL_DIR}/acme/deploy.pem"), "MINE-PEM\n")]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["new", "feature"]);
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "{out}");
    write_files(&d, &[(&format!("{BILL_DIR}/acme/after.txt"), "MINE-AFTER\n")]);
    let st = p.fin.ok(&d, &["status"]);
    assert!(st.contains(&format!("{BILL_DIR}/acme/after.txt")), "vl status says what became of the new file: {st}");
    // Decided: under a heading of its own; `vl commit` records the rest and
    // says once what it left; the files are never touched.
    let heading = st.find("no longer have access to (not recorded").expect("the heading");
    assert!(st[heading..].contains(&format!("{BILL_DIR}/acme/after.txt")) && st[heading..].contains(&format!("{BILL_DIR}/acme/deploy.pem")), "{st}");
    write_files(&d, &[("src/also.txt", "recorded\n")]);
    let c = p.fin.ok(&d, &["commit", "-m", "the rest"]);
    assert!(c.contains("Committed") && c.contains("not recorded") && c.contains(&format!("{BILL_DIR}/acme/after.txt")), "{c}");
    let (_, parent) = wc_entries(&d, "src/also.txt");
    assert!(parent.is_some(), "the rest is recorded");
    let (_, bill) = wc_entries(&d, BILL_DIR);
    assert_eq!(bill, Some(entry_in(&d, "feature", BILL_DIR)), "the folder kept by id");
    assert_eq!(std::fs::read_to_string(d.join(format!("{BILL_DIR}/acme/after.txt"))).unwrap(), "MINE-AFTER\n");
    assert_eq!(std::fs::read_to_string(d.join(format!("{BILL_DIR}/acme/deploy.pem"))).unwrap(), "MINE-PEM\n");
    let again = p.fin.ok(&d, &["log", "-n", "1"]);
    assert!(!again.contains("not recorded"), "said once, by commit: {again}");
}

/// BUG-1529: `vl restore`, `vl split` and `vl squash` by path refuse when a
/// refused folder differs between the trees they compare, even though the
/// paths asked for are elsewhere and the folder can be kept by id.
#[test]
fn bug_1529_restore_split_squash_refuse_a_refused_folder_not_asked_for() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    let d = left_out_by_a_checkout(&p, &hub, "wc");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    p.fin.ok(&d, &["new", "feature"]);
    let theirs = entry_in(&d, "feature", BILL_DIR);
    let base = entry_in(&d, "feature-", BILL_DIR);
    assert_ne!(theirs, base, "feature's last change changed the billing folder");
    // Each from the same start (`vl undo` after it): the split moves
    // `src/more.txt` out of `feature`, which the squash then names.
    for args in [vec!["restore", "--from", "feature-", "src/lib.rs"], vec!["split", "-r", "feature", "src/more.txt", "-m", "first"], vec!["squash", "-r", "feature", "src/more.txt"]] {
        let o = p.fin.run(&d, &args);
        let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success(), "vl {args:?}: {all}");
        assert_eq!(entry_in(&d, "feature", BILL_DIR), theirs, "vl {args:?}: the folder kept by id in the change");
        if args[0] == "split" {
            assert_eq!(entry_in(&d, "feature-", BILL_DIR), base, "the split's first change has the base's folder");
            assert!(veil_core::tree::lookup(&open_store(&d), &tree_of(&d, "feature-"), &veil_core::VPath::new("src/more.txt").unwrap()).unwrap().is_some(), "and the path asked for");
        }
        if args[0] != "restore" {
            p.fin.ok(&d, &["undo"]);
        }
    }
    assert_eq!(entry_in(&d, "feature", BILL_DIR), theirs, "the folder kept by id");
    // Decided (the narrower rule): only a path asked for in the folder
    // needs its content, and is refused by name; nothing changes.
    let inside = format!("{BILL_DIR}/acme/q3.txt");
    for args in [vec!["restore", "--from", "feature-", inside.as_str()], vec!["split", "-r", "feature", inside.as_str(), "-m", "first"]] {
        let before = p.fin.ok(&d, &["op", "log", "-n", "1", "--json"]);
        let out = p.fin.fails(&d, &args);
        assert!(out.contains(&format!("{BILL_DIR}/ is a folder you no longer have access to")) && out.contains("nothing was changed"), "vl {args:?}: {out}");
        assert_eq!(p.fin.ok(&d, &["op", "log", "-n", "1", "--json"]), before, "vl {args:?} changed nothing");
    }
}

/// BUG-1530: in a thin clone whose working copy carries a refused folder
/// by id (here: the checkout left it out), `vl pull` (which the refusal's
/// own message recommends) wedges the working copy: afterwards every
/// command fails with "the Veil server could not be reached: '…' is not
/// fetched, and the server has no copy of it where this clone met it; run
/// `vl pull`", `vl pull` included in the advice, so there is no way out.
#[test]
fn bug_1530_a_pull_wedges_a_working_copy_carrying_a_refused_folder() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    let d = left_out_by_a_checkout(&p, &hub, "wc");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["new", "feature"]);
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "{out}");
    p.fin.ok(&d, &["pull"]);
    let st = p.fin.ok(&d, &["status"]);
    assert!(st.contains(BILL_DIR) && st.contains("no longer have access"), "{st}");
    p.fin.ok(&d, &["log", "-n", "3"]);
    p.fin.ok(&d, &["show", "@-"]);
}

/// BUG-1509 (another route, found by the review of `s8h`): work that
/// carries a refused folder by id cannot reach anyone.
/// fin rebases a change of `src/` onto `feature` (the billing folder, which
/// fin lost access to, kept by id) and pushes it: the server refuses
/// ("you do not have access to 'bill-…'"), though the change leaves that
/// folder exactly as its parent has it. Expected: the push lands, and the
/// admin's checkout of it holds every billing file of `feature`, byte for
/// byte.
#[test]
fn bug_1509_a_change_carrying_a_refused_folder_by_id_cannot_be_pushed() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    let d = fin_chain(&p, &hub, "chain");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["rebase", "-s", "mine", "-d", "feature"]);
    assert!(out.contains("Rebased"), "{out}");
    // Decided: the rebase met the folder fin lost, and the clone moved to
    // fin's current view, where the folder is not named at all: `kid`
    // leaves it as `feature` has it there (the server grafts it back).
    assert_eq!(out.matches(MOVED).count(), 1, "{out}");
    assert_eq!(entry_at(&d, "kid", BILL_DIR), None, "kid is in the current view");
    assert_eq!(entry_at(&d, "feature", BILL_DIR), None, "feature too");
    let out = p.fin.ok(&d, &["push", "-t", "kid"]);
    assert!(out.contains("pushed"), "{out}");
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "feature"]);
    let want = below(&walk(&p.dir), BILL_DIR);
    p.admin.ok(&p.dir, &["new", "kid"]);
    let got = walk(&p.dir);
    assert_eq!(below(&got, BILL_DIR), want, "every file of the billing folder, byte for byte");
    assert_eq!(got.get("src/kid.txt").map(Vec::as_slice), Some(b"kid\n".as_slice()));
}

/// BUG-1531, decided: when access comes back, a file kept on disk from the
/// version a folder was left from is compared with that version: equal, it
/// is the checkout's own copy, written over (below); different, it is the
/// person's edit: kept as it is, and a conflict in `vl status`.
#[test]
fn bug_1531_an_edit_kept_through_a_left_out_folder_is_a_conflict_when_access_comes_back() {
    const MINE: &str = "KEY=MARKER-FINS-OWN-EDIT-3c9a\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    let d = plain_thin(&p, &hub, "wc");
    p.fin.ok(&d, &["new", "feature"]);
    feature_with(&p, &[(&format!("{BILL_DIR}/.env"), "KEY=MARKER-NEW-ENV-a14d\n")], &[], "rotate billing");
    p.fin.ok(&d, &["pull"]);
    p.fin.ok(&d, &["cat", "-r", "feature", "src/lib.rs"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["new", "feature"]);
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "{out}");
    let env = d.join(format!("{BILL_DIR}/.env"));
    assert!(env.is_file(), "the checkout kept the secret it could not tell as its own");
    std::fs::write(&env, MINE).unwrap();
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.fin.name]);
    let st = p.fin.ok(&d, &["status"]);
    assert_eq!(std::fs::read_to_string(&env).unwrap(), MINE, "the person's edit is never touched: {st}");
    let c = st.find("Unresolved conflicts:").expect("a conflict");
    assert!(st[c..].contains(&format!("{BILL_DIR}/.env")) && st[c..].contains("the recorded version is newer"), "{st}");
    let json = p.fin.ok(&d, &["status", "--json"]);
    let v: serde_json::Value = serde_json::from_str(json.lines().next().unwrap()).unwrap();
    assert!(v["conflicts"].as_array().unwrap().iter().any(|c| c["path"] == format!("{BILL_DIR}/.env") && c["kept_edit"] == true), "{json}");
}

/// BUG-1531: a secret the checkout kept on disk when it left its folder
/// out (it could not tell it as its own) stays stale when access comes
/// back: the folder's other files are filled in, the new `.env` is not, and
/// the working copy holds the old secret while history holds the new one
/// ("kept as recorded … its edit is not recorded").
#[test]
fn bug_1531_a_secret_left_on_disk_stays_stale_when_access_comes_back() {
    const NEW_ENV: &str = "KEY=MARKER-NEW-ENV-71c0d2e9\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested below).
    p.fin.stay_in_stale_views();
    let d = plain_thin(&p, &hub, "wc");
    p.fin.ok(&d, &["new", "feature"]);
    feature_with(&p, &[(&format!("{BILL_DIR}/.env"), NEW_ENV), (&format!("{BILL_DIR}/acme/invoice.txt"), "MARKER-NEW-INVOICE-0b8e\n")], &[], "rotate billing");
    p.fin.ok(&d, &["pull"]);
    p.fin.ok(&d, &["cat", "-r", "feature", "src/lib.rs"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["new", "feature"]);
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "{out}");
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.fin.name]);
    let st = p.fin.ok(&d, &["status"]);
    assert_eq!(std::fs::read_to_string(d.join(format!("{BILL_DIR}/acme/invoice.txt"))).unwrap(), "MARKER-NEW-INVOICE-0b8e\n", "{st}");
    assert_eq!(std::fs::read_to_string(d.join(format!("{BILL_DIR}/.env"))).unwrap(), NEW_ENV, "the folder written whole again: {st}");
}

// ---- BUG-1509: a clone moves to its person's current view (`s8j`) -----------

/// The entry at `path` in the tree of what `rev` names in `clone`, if any.
fn entry_at(clone: &Path, rev: &str, path: &str) -> Option<veil_core::TreeEntry> {
    let tree = tree_of(clone, rev);
    veil_core::tree::lookup(&open_store(clone), &tree, &veil_core::VPath::new(path).unwrap()).unwrap()
}

/// What a clone's view refers to: tags, workspaces, heads and remote tags.
type ViewState = (BTreeMap<String, veil_core::ObjectId>, BTreeMap<String, veil_core::ObjectId>, Vec<veil_core::ObjectId>, BTreeMap<String, veil_core::ObjectId>);

fn view_state(clone: &Path) -> ViewState {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    let v = repo.view();
    (
        v.tags.iter().map(|(n, t)| (n.clone(), t.target)).collect(),
        v.workspaces.iter().map(|(n, w)| (n.clone(), w.wc)).collect(),
        v.heads.iter().copied().collect(),
        v.remote_tags.clone(),
    )
}

/// The parents of what `rev` names in `clone`.
fn parents_of(clone: &Path, rev: &str) -> Vec<veil_core::ObjectId> {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    repo.snapshot(&repo.view().tags[rev].target).unwrap().parents.clone()
}

/// Guarantee: the whole move is one operation, and `vl undo` returns the
/// clone exactly to before it (every tag, workspace, head and remote tag,
/// and every file of the working copy).
#[test]
fn bug_1509_undo_returns_a_moved_clone_exactly_to_before() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let d = fin_chain(&p, &hub, "chain");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let (before, files) = (view_state(&d), walk(&d));
    let ops_before = p.fin.ok(&d, &["--no-snapshot", "op", "log", "-n", "100"]).lines().count();
    let out = p.fin.ok(&d, &["show", "feature"]);
    assert_eq!(out.matches(MOVED).count(), 1, "{out}");
    let moved = view_state(&d);
    assert_ne!(moved.0["mine"], before.0["mine"], "mine moved");
    assert_ne!(moved.0["kid"], before.0["kid"], "kid moved");
    let ops = p.fin.ok(&d, &["--no-snapshot", "op", "log", "-n", "100"]).lines().count();
    assert!(ops > ops_before, "the move is an operation");
    let out = p.fin.ok(&d, &["undo"]);
    assert!(!out.contains(MOVED), "undo does not move again: {out}");
    assert_eq!(view_state(&d), before, "undo returns every reference");
    assert_eq!(walk(&d), files, "and every file");
}

/// Guarantee: a change that edited inside a folder its person can no
/// longer see is refused by name and stays exactly where it is (with what
/// is built on it); other changes move.
#[test]
fn bug_1509_a_change_inside_a_lost_folder_is_refused_and_kept() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let d = plain_thin(&p, &hub, "wc");
    write_files(&d, &[("src/fine.txt", "a fine change\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "a fine change"]);
    p.fin.ok(&d, &["tag", "set", "fine", "-r", "@-"]);
    p.fin.ok(&d, &["new", "main"]);
    write_files(&d, &[(&format!("{BILL_DIR}/acme/fin.txt"), "fin's billing edit\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "billing edit"]);
    p.fin.ok(&d, &["tag", "set", "billing", "-r", "@-"]);
    write_files(&d, &[("src/above.txt", "built on it\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "built on the billing edit"]);
    p.fin.ok(&d, &["tag", "set", "above", "-r", "@-"]);
    p.fin.ok(&d, &["new", "main"]);
    p.fin.ok(&d, &["cat", "-r", "feature", "src/lib.rs"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let before = view_state(&d);
    let out = p.fin.ok(&d, &["pull"]);
    assert_eq!(out.matches(MOVED).count(), 1, "{out}");
    assert!(out.contains("kept where it is") && out.contains("billing edit") && out.contains(&format!("{BILL_DIR}/")), "refused by name: {out}");
    let after = view_state(&d);
    assert_eq!(after.0["billing"], before.0["billing"], "the change inside the lost folder is never rewritten");
    assert_eq!(after.0["above"], before.0["above"], "nor what is built on it");
    assert!(entry_at(&d, "billing", &format!("{BILL_DIR}/acme/fin.txt")).is_some(), "never dropped");
    assert_ne!(after.0["fine"], before.0["fine"], "the other change moved");
    assert_eq!(entry_at(&d, "fine", BILL_DIR), None, "into the current view");
    assert_eq!(entry_at(&d, "fine", "src/fine.txt").map(|e| e.size), Some("a fine change\n".len() as u64));
}

/// Guarantee: tags, workspaces and the checkout record follow the move; the
/// person's own file in the lost folder is never touched, never recorded,
/// and said so; a commit afterwards is in the current view.
#[test]
fn bug_1509_tags_workspaces_and_the_checkout_record_follow() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let d = plain_thin(&p, &hub, "wc");
    p.fin.ok(&d, &["new", "feature"]);
    write_files(&d, &[("src/work.txt", "work\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "work"]);
    p.fin.ok(&d, &["tag", "set", "work", "-r", "@-"]);
    p.fin.ok(&d, &["ws", "new", "agent", "-r", "work"]);
    write_files(&d, &[(&format!("{BILL_DIR}/acme/mine.pem"), "MINE-PEM\n")]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let before = view_state(&d);
    let out = p.fin.ok(&d, &["pull"]);
    assert_eq!(out.matches(MOVED).count(), 1, "{out}");
    let after = view_state(&d);
    assert_ne!(after.0["work"], before.0["work"], "the tag follows");
    assert_eq!(parents_of(&d, "work"), vec![after.0["feature"]], "onto feature in the current view");
    assert_ne!(after.0["feature"], before.0["feature"]);
    for ws in ["default", "agent"] {
        assert_ne!(after.1[ws], before.1[ws], "workspace {ws} follows");
        let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&d)), None, "test").unwrap();
        let tree = repo.snapshot(&after.1[ws]).unwrap().tree;
        assert_eq!(veil_core::tree::lookup(repo.store(), &tree, &veil_core::VPath::new(BILL_DIR).unwrap()).unwrap(), None, "{ws} is in the current view");
    }
    let st = p.fin.ok(&d, &["status"]);
    assert!(st.contains(&format!("{BILL_DIR}/acme/mine.pem")) && st.contains("not recorded"), "the checkout record follows: {st}");
    assert_eq!(std::fs::read_to_string(d.join(format!("{BILL_DIR}/acme/mine.pem"))).unwrap(), "MINE-PEM\n");
    write_files(&d, &[("src/after.txt", "after\n")]);
    let c = p.fin.ok(&d, &["commit", "-m", "after the move"]);
    assert!(c.contains("Committed") && !c.contains(MOVED), "{c}");
    let (wc, parent) = wc_entries(&d, BILL_DIR);
    assert_eq!((wc, parent), (None, None), "nothing of the lost folder recorded");
}

/// Guarantee: nothing below a folder the person lost appears anywhere after
/// the move: not in the commands' output (text or JSON), the op log, the
/// history, or the working copy.
#[test]
fn bug_1509_nothing_below_a_hidden_folder_appears_anywhere() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let d = fin_chain(&p, &hub, "chain");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let held = walk(&d);
    let mut seen = p.fin.ok(&d, &["show", "feature", "--json"]);
    assert_eq!(seen.matches(MOVED).count(), 1, "{seen}");
    for args in [
        vec!["log", "-n", "50", "--json"],
        vec!["op", "log", "-n", "20", "--json"],
        vec!["show", "kid", "--json"],
        vec!["show", "feature"],
        vec!["ls", "-r", "feature", "--json"],
        vec!["diff", "--from", "main", "--to", "kid", "--json"],
    ] {
        seen.push_str(&p.fin.ok(&d, &args));
    }
    for below in ["acme", "invoice.txt", "q2.txt", BILL_MARK, FEATURE_BILL, ENV_MARK] {
        assert!(!seen.contains(below), "{below} appeared: {seen}");
    }
    // `vl status` names what the person still holds on disk there (never
    // recorded, BUG-1528), and nothing they never held.
    let st = p.fin.ok(&d, &["status", "--json"]);
    for never in ["q2.txt", FEATURE_BILL] {
        assert!(!st.contains(never), "{never} appeared: {st}");
    }
    // Nothing is written there: what is left is what the person held
    // before, byte for byte (a copy the checkout could not tell as its own).
    for (path, bytes) in walk(&d) {
        if path.starts_with(&format!("{BILL_DIR}/")) {
            assert_eq!(held.get(&path), Some(&bytes), "{path} written in the working copy");
        }
    }
}

/// Guarantee: when access comes back after a move, the clone moves to the
/// view that names the folder again and writes it whole: a file the
/// working copy kept there from before is the checkout's own copy where it
/// holds exactly that version (written over with the new one), and the
/// person's edit where it does not (kept as it is, and a conflict in `vl
/// status`), as BUG-1531 decided for a folder left out.
#[test]
fn bug_1509_access_back_after_a_move_writes_the_folder_whole_and_keeps_edits() {
    const NEW_ENV: &str = "KEY=MARKER-NEW-ENV-5e72b0c1\n";
    const MINE: &str = "KEY=MARKER-FINS-OWN-EDIT-9d04\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let (kept, edited) = (plain_thin(&p, &hub, "kept"), plain_thin(&p, &hub, "edited"));
    for d in [&kept, &edited] {
        p.fin.ok(d, &["new", "feature"]);
    }
    feature_with(&p, &[(&format!("{BILL_DIR}/.env"), NEW_ENV), (&format!("{BILL_DIR}/acme/invoice.txt"), "MARKER-NEW-INVOICE-77aa\n")], &[], "rotate billing");
    for d in [&kept, &edited] {
        p.fin.ok(d, &["pull"]);
        p.fin.ok(d, &["cat", "-r", "feature", "src/lib.rs"]);
    }
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    for d in [&kept, &edited] {
        let out = p.fin.ok(d, &["new", "feature"]);
        assert_eq!(out.matches(MOVED).count(), 1, "{out}");
    }
    let env = |d: &Path| d.join(format!("{BILL_DIR}/.env"));
    std::fs::write(env(&edited), MINE).unwrap();
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.fin.name]);
    for d in [&kept, &edited] {
        let out = p.fin.ok(d, &["pull"]);
        assert_eq!(out.matches(MOVED).count(), 1, "access back is a view change too: {out}");
        assert_eq!(std::fs::read_to_string(d.join(format!("{BILL_DIR}/acme/invoice.txt"))).unwrap(), "MARKER-NEW-INVOICE-77aa\n", "the folder written whole");
    }
    assert_eq!(std::fs::read_to_string(env(&kept)).unwrap(), NEW_ENV, "the checkout's own copy written over");
    assert_eq!(std::fs::read_to_string(env(&edited)).unwrap(), MINE, "the person's edit never touched");
    let st = p.fin.ok(&edited, &["status"]);
    let c = st.find("Unresolved conflicts:").expect("a conflict");
    assert!(st[c..].contains(&format!("{BILL_DIR}/.env")) && st[c..].contains("the recorded version is newer"), "{st}");
}


/// BUG-1562: a **full** clone made before its person's access changed is
/// not moved to their current view: it holds every object of the view it
/// was made in, so nothing it reads is refused, and its pull and push do
/// not ask (the move reads through a thin clone's server reads). A change
/// on top of the old view is refused by the push.
#[test]
#[ignore = "BUG-1562: a full clone is not moved to its person's current view; its push is refused"]
fn bug_1562_a_full_clone_is_not_moved_and_its_push_is_refused() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    let full = p.fin.dir("full");
    p.fin.ok(p.fin.home.path(), &["clone", "--full", &hub.url(&p.name), full.to_str().unwrap()]);
    p.fin.ok(&full, &["identity", "confirm", &p.fp]);
    write_files(&full, &[("src/full.txt", "full\n")]);
    p.fin.ok(&full, &["commit", "--no-advance", "-m", "full change"]);
    p.fin.ok(&full, &["tag", "set", "fullc", "-r", "@-"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&full, &["pull"]);
    assert_eq!(out.matches(MOVED).count(), 1, "{out}");
    let out = p.fin.ok(&full, &["push", "-t", "fullc"]);
    assert!(out.contains("pushed"), "{out}");
}

/// BUG-1563: a change the move kept in the old view (it edits a folder its
/// person lost) is rewritten by an explicit `vl rebase` onto the current
/// view, with a conflict at that folder, which no push accepts. Expected:
/// refused by name, as the move refuses it, and left where it is.
#[test]
#[ignore = "BUG-1563: a rebase of a change kept in the old view rewrites it with a conflict at the lost folder"]
fn bug_1563_a_rebase_of_a_kept_change_is_refused_by_name() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let k = plain_thin(&p, &hub, "kept");
    write_files(&k, &[(&format!("{BILL_DIR}/acme/fin.txt"), "fin's billing edit\n")]);
    p.fin.ok(&k, &["commit", "--no-advance", "-m", "billing edit"]);
    p.fin.ok(&k, &["tag", "set", "billing", "-r", "@-"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&k, &["pull"]);
    assert!(out.contains("kept where it is") && out.contains("billing edit"), "{out}");
    let before = view_state(&k);
    let out = p.fin.fails(&k, &["rebase", "-s", "billing", "-d", "main"]);
    assert!(out.contains("no longer have access") && out.contains("billing edit"), "{out}");
    assert_eq!(view_state(&k), before, "nothing changed");
}

// ---- Review of `s8i` (BUG-1528–1531's fixes): guarantee tests -----------

/// The tree of `@` in `clone`.
fn wc_tree(clone: &Path) -> veil_core::ObjectId {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    repo.snapshot(&repo.view().workspace("default").unwrap().wc).unwrap().tree
}

/// The entries of directory `dir` ("" for the root) of `tree` in `clone`,
/// by name.
fn dir_entries(clone: &Path, tree: &veil_core::ObjectId, dir: &str) -> BTreeMap<String, veil_core::TreeEntry> {
    let store = open_store(clone);
    let id = match dir {
        "" => *tree,
        d => veil_core::tree::lookup(&store, tree, &veil_core::VPath::new(d).unwrap()).unwrap().unwrap().id,
    };
    store.tree(&id).unwrap().entries.iter().map(|e| (e.name.clone(), e.clone())).collect()
}

/// `vl status --json` of `who` in `clone`, parsed (the command succeeded).
fn status_json(who: &Person, clone: &Path) -> serde_json::Value {
    let json = who.ok(clone, &["status", "--json"]);
    serde_json::from_str(json.lines().next().unwrap()).unwrap()
}

/// The files on disk below `dir` of `clone`, by path, with their bytes.
fn disk_below(clone: &Path, dir: &str) -> BTreeMap<String, Vec<u8>> {
    below(&walk(clone), dir)
}

/// Guarantee 3 (review of `s8i`): split, squash and restore never move,
/// empty or drop a refused folder, compared by exact tree ids and entries:
/// a split's second change keeps the change's exact tree and its first the
/// base's folder; a squash into the parent (of every path that can be
/// chosen) keeps the source's exact tree and gives the parent the base's
/// folder; a squash into a descendant keeps the folder in the source and
/// the descendant's exact tree; a restore of other paths keeps `@`'s
/// folder; a restore of every path is refused and changes nothing.
#[test]
fn s8ir_review_split_squash_restore_keep_a_refused_folder_exactly() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested on its own).
    p.fin.stay_in_stale_views();
    let d = left_out_by_a_checkout(&p, &hub, "wc");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["new", "feature"]);
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "{out}");
    let (t, b) = (tree_of(&d, "feature"), tree_of(&d, "feature-"));
    let (t_root, b_root) = (dir_entries(&d, &t, ""), dir_entries(&d, &b, ""));
    assert_ne!(t_root[BILL_DIR], b_root[BILL_DIR], "feature's last change changed the billing folder");
    let more = dir_entries(&d, &t, "src")["more.txt"].clone();
    // What the first half (or the parent) must be: the base with
    // `src/more.txt`, nothing else.
    let check_first = |what: &str| {
        let f = tree_of(&d, "feature-");
        let root = dir_entries(&d, &f, "");
        assert_eq!(root[BILL_DIR], b_root[BILL_DIR], "{what}: the base's folder, by id");
        for (name, e) in &b_root {
            if name != "src" {
                assert_eq!(root.get(name), Some(e), "{what}: {name}");
            }
        }
        assert_eq!(root.len(), b_root.len(), "{what}: {root:?}");
        let mut want = dir_entries(&d, &b, "src");
        want.insert("more.txt".into(), more.clone());
        assert_eq!(dir_entries(&d, &f, "src"), want, "{what}: the base's src/ with src/more.txt");
    };
    // The split's second change keeps the exact tree.
    p.fin.ok(&d, &["split", "-r", "feature", "src/more.txt", "-m", "first"]);
    assert_eq!(tree_of(&d, "feature"), t, "the split's second change: the change's exact tree");
    check_first("the split's first change");
    p.fin.ok(&d, &["undo"]);
    assert_eq!((tree_of(&d, "feature"), tree_of(&d, "feature-")), (t, b));
    // A squash of every path that can be chosen into the parent: the source
    // is not emptied (it still changes the folder) and keeps its tree.
    let out = p.fin.ok(&d, &["squash", "-r", "feature", "src/more.txt"]);
    assert!(!out.contains("abandon"), "the source still changes the folder: {out}");
    assert_eq!(tree_of(&d, "feature"), t, "the squash's source: its exact tree");
    check_first("the squash's parent");
    p.fin.ok(&d, &["undo"]);
    assert_eq!((tree_of(&d, "feature"), tree_of(&d, "feature-")), (t, b));
    // Into a descendant (`@`, an empty change on `feature`): the folder
    // stays in the source, `@` keeps its exact tree.
    let wc = wc_tree(&d);
    assert_eq!(wc, t);
    p.fin.ok(&d, &["squash", "-r", "feature", "--into", "@", "src/more.txt"]);
    assert_eq!(wc_tree(&d), t, "the descendant keeps its exact tree");
    let src_root = dir_entries(&d, &tree_of(&d, "feature"), "");
    assert_eq!(src_root[BILL_DIR], t_root[BILL_DIR], "the source keeps the folder it changed, by id");
    assert!(!dir_entries(&d, &tree_of(&d, "feature"), "src").contains_key("more.txt"), "the chosen path left the source");
    p.fin.ok(&d, &["undo"]);
    assert_eq!((tree_of(&d, "feature"), tree_of(&d, "feature-"), wc_tree(&d)), (t, b, t));
    // A whole squash into the parent (nothing named): the parent gets the
    // change's exact tree, the folder by id.
    let parent = p.fin.ok(&d, &["log", "-r", "feature-", "--json"]);
    let out = p.fin.ok(&d, &["squash", "-r", "feature"]);
    assert!(out.to_lowercase().contains("squash"), "{out}");
    assert_eq!(wc_tree(&d), t, "@ keeps its exact tree");
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&d)), None, "test").unwrap();
    let wc = repo.snapshot(&repo.view().workspace("default").unwrap().wc).unwrap();
    assert_eq!(repo.snapshot(&wc.parents[0]).unwrap().tree, t, "the parent has the change's exact tree: {parent}");
    drop(repo);
    p.fin.ok(&d, &["undo"]);
    assert_eq!((tree_of(&d, "feature"), tree_of(&d, "feature-"), wc_tree(&d)), (t, b, t));
    // A restore of another path keeps `@`'s folder (it differs from the
    // source's).
    p.fin.ok(&d, &["restore", "--from", "feature-", "src/more.txt"]);
    let after = wc_tree(&d);
    assert_eq!(dir_entries(&d, &after, "")[BILL_DIR], t_root[BILL_DIR], "the restore keeps @'s folder, by id");
    let mut want = dir_entries(&d, &t, "src");
    want.remove("more.txt");
    assert_eq!(dir_entries(&d, &after, "src"), want, "only the path asked for was restored");
    // A restore of every path needs the folder: refused, nothing changed.
    let before = (p.fin.ok(&d, &["op", "log", "-n", "1", "--json"]), wc_tree(&d));
    let out = p.fin.fails(&d, &["restore", "--from", "feature-"]);
    assert!(out.contains(&format!("{BILL_DIR}/ is a folder you no longer have access to")) && out.contains("nothing was changed"), "{out}");
    assert_eq!((p.fin.ok(&d, &["op", "log", "-n", "1", "--json"]), wc_tree(&d)), before, "the refused restore changed nothing");
}

/// Guarantees 2 and 4 (review of `s8i`): nothing the person made is lost
/// or overwritten, before or after access returns, and `vl status` and `vl
/// commit` name only what the working copy holds below the refused folder.
/// fin holds the billing folder (two `.env` secrets), keeps a personal key
/// there (local-only, in no tree: as an ignored file would be; fin's clone
/// cannot read the root `.veilpolicy`, so no ignore rule reaches it), loses access (the checkout leaves the folder
/// out), then makes a file, edits one kept secret, deletes the other, moves
/// to `main` and back, and commits elsewhere; access comes back.
#[test]
fn s8ir_review_nothing_the_person_made_is_lost_across_a_left_out_folder() {
    const ACME_ENV_OLD: &str = "KEY=MARKER-ACME-ENV-OLD-5e1b07c2\n";
    const ACME_ENV_NEW: &str = "KEY=MARKER-ACME-ENV-NEW-91d4a6f0\n";
    const ENV_NEW: &str = "KEY=MARKER-BILL-ENV-NEW-2b7c9e13\n";
    const MY_EDIT: &str = "KEY=MARKER-FINS-EDIT-WHILE-GONE-7aa3\n";
    const MY_NEW: &str = "MARKER-FINS-NEW-FILE-WHILE-GONE-c40e\n";
    const MY_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested on its own).
    p.fin.stay_in_stale_views();
    feature_with(&p, &[(&format!("{BILL_DIR}/acme/.env"), ACME_ENV_OLD)], &[], "a second secret");
    let d = plain_thin(&p, &hub, "wc");
    p.fin.ok(&d, &["new", "feature"]);
    assert_eq!(std::fs::read_to_string(d.join(format!("{BILL_DIR}/acme/.env"))).unwrap(), ACME_ENV_OLD);
    // `feature` moves on while fin holds the old version.
    feature_with(&p, &[(&format!("{BILL_DIR}/.env"), ENV_NEW), (&format!("{BILL_DIR}/acme/.env"), ACME_ENV_NEW), (&format!("{BILL_DIR}/acme/q2.txt"), "MARKER-Q2-NEW-6d02\n")], &[], "rotate billing");
    p.fin.ok(&d, &["pull"]);
    p.fin.ok(&d, &["cat", "-r", "feature", "src/lib.rs"]);
    let key = format!("{BILL_DIR}/acme/id_ed25519");
    write_files(&d, &[(&key, MY_KEY)]);
    let st = p.fin.ok(&d, &["status"]);
    assert!(st.contains(&key) && st.contains("isolated"), "the personal key is local-only: {st}");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["new", "feature"]);
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "{out}");
    let (env, acme_env, mine) = (format!("{BILL_DIR}/.env"), format!("{BILL_DIR}/acme/.env"), format!("{BILL_DIR}/acme/mine.txt"));
    assert!(d.join(&env).is_file() && d.join(&acme_env).is_file(), "the checkout kept the secrets it could not tell as its own: {:?}", disk_below(&d, BILL_DIR).keys());
    // While access is gone: fin edits one kept secret, deletes the other,
    // moves to `main` and back (`main`'s billing folder is held here, fin
    // read it before: a checkout of it writes it around fin's files,
    // BUG-1464), then makes a file.
    write_files(&d, &[(&env, MY_EDIT)]);
    std::fs::remove_file(d.join(&acme_env)).unwrap();
    p.fin.ok(&d, &["new", "main"]);
    let on_main = disk_below(&d, BILL_DIR);
    for (k, v) in [(&env, MY_EDIT), (&key, MY_KEY)] {
        assert_eq!(on_main.get(k).map(Vec::as_slice), Some(v.as_bytes()), "a checkout of main while the folder is refused touched {k}");
    }
    p.fin.ok(&d, &["new", "feature"]);
    write_files(&d, &[(&mine, MY_NEW)]);
    let held = disk_below(&d, BILL_DIR);
    let mut want: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (k, v) in [(&env, MY_EDIT), (&mine, MY_NEW), (&key, MY_KEY)] {
        want.insert(k.clone(), v.as_bytes().to_vec());
    }
    assert_eq!(held, want, "below the folder: only what fin holds");
    let st = status_json(&p.fin, &d);
    let named: std::collections::BTreeSet<String> = st["not_recorded"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    for k in [&env, &mine] {
        assert!(named.contains(k), "{k} is named: {st}");
    }
    for k in &named {
        assert!(held.contains_key(k), "status names only what the working copy holds there, not {k}: {st}");
    }
    write_files(&d, &[("src/also.txt", "recorded\n")]);
    let c = p.fin.ok(&d, &["commit", "-m", "the rest"]);
    assert!(c.contains("Committed"), "{c}");
    for k in held.keys() {
        if c.contains(k.as_str()) {
            continue;
        }
        assert!(k == &key, "commit names {k}: {c}");
    }
    assert_eq!(disk_below(&d, BILL_DIR), want, "the commit touched fin's files");
    // Access comes back.
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.fin.name]);
    let st = status_json(&p.fin, &d);
    let now = disk_below(&d, BILL_DIR);
    for (k, v) in [(&env, MY_EDIT), (&mine, MY_NEW), (&key, MY_KEY)] {
        assert_eq!(now.get(k).map(Vec::as_slice), Some(v.as_bytes()), "{k}: fin's file, byte for byte: {st}");
    }
    assert_eq!(now.get(&acme_env).map(Vec::as_slice), Some(ACME_ENV_NEW.as_bytes()), "the folder written whole again: {st}");
    assert!(st["conflicts"].as_array().unwrap().iter().any(|c| c["path"] == env.as_str() && c["kept_edit"] == true), "{st}");
    assert!(!st["conflicts"].as_array().unwrap().iter().any(|c| c["path"] != env.as_str()), "only the edit is a conflict: {st}");
    // fin commits: the new file is recorded and stays in history after fin
    // moves on; the secret's edit stays on disk (a working copy without the
    // project's `.veilpolicy` keeps a shared secret's edit local, BUG-832),
    // and so does the personal key.
    let c = p.fin.ok(&d, &["commit", "-m", "keep my work"]);
    assert!(c.contains("Committed"), "{c}");
    p.fin.ok(&d, &["tag", "set", "kept", "-r", "@-"]);
    assert!(p.fin.ok(&d, &["cat", "-r", "kept", &mine]).starts_with(MY_NEW), "fin's new file is recorded");
    p.fin.ok(&d, &["new", "feature"]);
    assert!(p.fin.ok(&d, &["cat", "-r", "kept", &mine]).starts_with(MY_NEW), "fin's new file stays in history");
    assert_eq!(std::fs::read(d.join(&env)).unwrap(), MY_EDIT.as_bytes(), "fin's edit of the secret, never written over");
    assert_eq!(std::fs::read(d.join(&key)).unwrap(), MY_KEY.as_bytes());
}

/// BUG-1531's conflict (review of `s8i`): a file fin made while access was
/// gone, at a path the version written back has (and the version left
/// had not), is kept when the
/// folder is written back, and is a conflict (`kept_edit`). Once fin has
/// recorded it (the file is fin's version, committed), the conflict is
/// resolved: `vl status` no longer lists it. Actual: it is listed for good
/// ("the recorded version is newer: `vl restore …` takes it"), after `vl
/// commit`, `vl restore` of the path and `vl new`.
#[test]
fn bug_1558_a_kept_edit_once_recorded_is_still_a_conflict() {
    const MINE: &str = "MARKER-FINS-OWN-Q4-WHILE-GONE-d1e2\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested on its own).
    p.fin.stay_in_stale_views();
    let d = left_out_by_a_checkout(&p, &hub, "wc");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["new", "feature"]);
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "{out}");
    // `q3.txt` is in the version written back (`feature`), not in the
    // version the folder was left from (fin never held it).
    let q4 = format!("{BILL_DIR}/acme/q3.txt");
    write_files(&d, &[(&q4, MINE)]);
    p.fin.ok(&d, &["status"]);
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.fin.name]);
    let st = status_json(&p.fin, &d);
    assert_eq!(std::fs::read_to_string(d.join(&q4)).unwrap(), MINE, "fin's file kept: {st}");
    assert!(st["conflicts"].as_array().unwrap().iter().any(|c| c["path"] == q4.as_str() && c["kept_edit"] == true), "{st}");
    let c = p.fin.ok(&d, &["commit", "-m", "my q4"]);
    assert!(c.contains("Committed"), "{c}");
    p.fin.ok(&d, &["tag", "set", "mine-q4", "-r", "@-"]);
    assert!(p.fin.ok(&d, &["cat", "-r", "mine-q4", &q4]).starts_with(MINE), "fin's version is recorded");
    let st = status_json(&p.fin, &d);
    assert!(!st["conflicts"].as_array().unwrap().iter().any(|c| c["path"] == q4.as_str()), "recorded, and still a conflict: {st}");
    // And `vl restore PATH`, the conflict's own advice, is no way out
    // either: it restores nothing (`@-` holds fin's version).
    let r = p.fin.ok(&d, &["restore", &q4]);
    assert!(r.contains("Restored"), "{r}");
    let st = status_json(&p.fin, &d);
    assert!(!st["conflicts"].as_array().unwrap().iter().any(|c| c["path"] == q4.as_str()), "{st}");
}

/// Guarantee 1 (review of `s8i`): asking the server whether it knows a
/// snapshot (`server_knows`) costs no request per commit of a local stack.
/// Two thin clones of fin's, with 2 and 30 local commits on `feature`, are
/// rebased onto `feature` moved on by one file: the checkout fetches that
/// file under `@`, a local commit. Expected: about the same number of
/// requests for both.
#[test]
fn s8ir_review_a_local_stack_costs_no_request_a_commit() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let mut clones = Vec::new();
    for n in [2usize, 30] {
        let d = plain_thin(&p, &hub, &format!("stack{n}"));
        p.fin.ok(&d, &["new", "feature"]);
        for i in 0..n {
            write_files(&d, &[(&format!("src/stack/c{i:02}.txt"), &format!("commit {i}\n"))]);
            p.fin.ok(&d, &["commit", "-m", &format!("stack {i}")]);
            if i == 0 {
                p.fin.ok(&d, &["tag", "set", "stack-base", "-r", "@-"]);
            }
        }
        clones.push((n, d));
    }
    feature_with(&p, &[("src/late.txt", "MARKER-LATE-FILE-0c55e1\n")], &[], "late");
    let mut cost = Vec::new();
    for (n, d) in &clones {
        p.fin.ok(d, &["pull"]);
        let before = requests(&hub);
        let out = p.fin.ok(d, &["rebase", "-s", "stack-base", "-d", "origin/feature"]);
        assert!(out.contains("Rebased"), "{out}");
        cost.push(requests(&hub) - before);
        assert_eq!(std::fs::read_to_string(d.join("src/late.txt")).unwrap(), "MARKER-LATE-FILE-0c55e1\n");
        assert_eq!(std::fs::read_to_string(d.join(format!("src/stack/c{:02}.txt", n - 1))).unwrap(), format!("commit {}\n", n - 1));
    }
    eprintln!("s8ir: rebase of a 2-commit stack cost {} requests, of a 30-commit stack {}", cost[0], cost[1]);
    assert!(cost[1] <= cost[0] + 8, "a 30-commit stack cost {} requests, a 2-commit one {}", cost[1], cost[0]);
}

/// BUG-1528's class (review of `s8i`): a symbolic link the person makes in
/// a folder the checkout left out is not recorded either, and must be
/// named as the files there are. Actual: `not_recorded` lists only the
/// files (`vfs::walk_files` never lists a link), and `vl commit` says nothing.
#[test]
fn bug_1559_a_link_made_in_a_left_out_folder_is_not_named() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    // What each command does in the view that changed (BUG-1508): the
    // clone stays in it (BUG-1509's move is tested on its own).
    p.fin.stay_in_stale_views();
    let d = left_out_by_a_checkout(&p, &hub, "wc");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["new", "feature"]);
    assert!(out.contains(&format!("redacted {BILL_DIR}/")), "{out}");
    let link = format!("{BILL_DIR}/acme/latest");
    std::fs::create_dir_all(d.join(format!("{BILL_DIR}/acme"))).unwrap();
    std::os::unix::fs::symlink("q2.txt", d.join(&link)).unwrap();
    let st = status_json(&p.fin, &d);
    let named: Vec<&str> = st["not_recorded"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
    assert!(named.contains(&link.as_str()), "the link fin made is named as not recorded: {st}");
    let c = p.fin.ok(&d, &["commit", "-m", "the rest"]);
    assert!(c.contains("Committed") && c.contains(&link), "{c}");
}


/// Guarantee 1 (review of `s8i`), a read under a local commit: fin's
/// stack of local commits on `main`, rebased onto `feature` with `@`
/// elsewhere, names `feature`'s files, which this clone never fetched;
/// `vl cat` reads one at the stack's tip. The server has no such snapshot;
/// the clone asks at its nearest ancestor on the server. Expected: about the
/// same number of requests whether the tip is 2 or 30 local commits above
/// it.
#[test]
fn s8ir_review_a_read_under_a_local_stack_costs_no_request_a_commit() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let file = "src/wide/f1/s0.txt";
    let mut cost = Vec::new();
    for n in [2usize, 30] {
        let d = plain_thin(&p, &hub, &format!("stack{n}"));
        for i in 0..n {
            write_files(&d, &[(&format!("src/stack/c{i:02}.txt"), &format!("commit {i}\n"))]);
            p.fin.ok(&d, &["commit", "-m", &format!("stack {i}")]);
            if i == 0 {
                p.fin.ok(&d, &["tag", "set", "stack-base", "-r", "@-"]);
            }
        }
        p.fin.ok(&d, &["tag", "set", "stack-tip", "-r", "@-"]);
        p.fin.ok(&d, &["new", "stack-base-"]);
        let out = p.fin.ok(&d, &["rebase", "-s", "stack-base", "-d", "feature"]);
        assert!(out.contains("Rebased"), "{out}");
        assert!(!d.join(file).exists(), "@ is not on the stack");
        let before = requests(&hub);
        let out = p.fin.run(&d, &["cat", "-r", "stack-tip", file]);
        cost.push(requests(&hub) - before);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).starts_with(FEATURE_MARK), "{}", String::from_utf8_lossy(&out.stdout));
    }
    eprintln!("s8ir: a read at the tip of 2 local commits cost {} requests, of 30 {}", cost[0], cost[1]);
    assert!(cost[1] <= cost[0] + 8, "at the tip of 30 local commits {} requests, of 2 {}", cost[1], cost[0]);
}

/// BUG-1558, decided: while a kept edit is a conflict, `vl restore PATH`
/// (its own advice) takes the recorded version, and the conflict is gone.
#[test]
fn bug_1558_restore_takes_the_recorded_version_of_a_kept_edit() {
    const MINE: &str = "MARKER-FINS-OWN-Q4-RESTORED-77b1\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.fin.stay_in_stale_views();
    let d = left_out_by_a_checkout(&p, &hub, "wc");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    p.fin.ok(&d, &["new", "feature"]);
    let q3 = format!("{BILL_DIR}/acme/q3.txt");
    write_files(&d, &[(&q3, MINE)]);
    p.fin.ok(&d, &["status"]);
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.fin.name]);
    let st = status_json(&p.fin, &d);
    assert!(st["conflicts"].as_array().unwrap().iter().any(|c| c["path"] == q3.as_str() && c["kept_edit"] == true), "{st}");
    let r = p.fin.ok(&d, &["restore", &q3]);
    assert!(r.contains("Restored"), "{r}");
    assert_eq!(std::fs::read_to_string(d.join(&q3)).unwrap(), Q3, "the recorded version");
    let st = status_json(&p.fin, &d);
    assert!(!st["conflicts"].as_array().unwrap().iter().any(|c| c["path"] == q3.as_str()), "{st}");
}

// ---- Review of `s8j` (BUG-1509's move to the current view): guarantees -------

/// The tags of `clone`, by name.
fn tags_of(clone: &Path) -> BTreeMap<String, veil_core::ObjectId> {
    view_state(clone).0
}

/// The parents of snapshot `id` in `clone`.
fn parents_by_id(clone: &Path, id: &veil_core::ObjectId) -> Vec<veil_core::ObjectId> {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    repo.snapshot(id).unwrap().parents.clone()
}

/// Guarantee 1 (review of `s8j`): `vl undo` returns a moved clone exactly
/// to before with a dirty working copy: an uncommitted edit (recorded by
/// the command before the move), ignored files in `src/` and below the lost
/// folder, and the folder's secret `.env`, every file byte for byte.
#[test]
fn s8jr_undo_after_a_move_returns_a_dirty_working_copy_byte_for_byte() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let d = fin_chain(&p, &hub, "chain");
    p.fin.ok(&d, &["ignore", "*.log"]);
    let scratch = format!("{BILL_DIR}/acme/scratch.log");
    write_files(&d, &[("src/build.log", "IGNORED-SRC-LOG\n"), (&scratch, "IGNORED-BILL-LOG\n"), ("src/lib.rs", "fin's uncommitted edit\n")]);
    let env = d.join(format!("{BILL_DIR}/.env"));
    assert!(std::fs::read_to_string(&env).unwrap().contains(ENV_MARK), "fin held the folder's secret");
    // The edit recorded in `@` while fin could read everything.
    p.fin.ok(&d, &["status"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let (before, files) = (view_state(&d), walk(&d));
    let out = p.fin.ok(&d, &["show", "feature"]);
    assert_eq!(out.matches(MOVED).count(), 1, "{out}");
    assert_ne!(view_state(&d), before, "the clone moved");
    assert_eq!(std::fs::read_to_string(d.join("src/lib.rs")).unwrap(), "fin's uncommitted edit\n", "the edit moved with `@`");
    assert_eq!(std::fs::read_to_string(d.join(&scratch)).unwrap(), "IGNORED-BILL-LOG\n", "an ignored file below the lost folder is never touched");
    let out = p.fin.ok(&d, &["undo"]);
    assert!(!out.contains(MOVED), "{out}");
    assert_eq!(view_state(&d), before, "every reference as before");
    assert_eq!(walk(&d), files, "every file as before, byte for byte");
}

/// Guarantee 1 (review of `s8j`): an edit inside the lost folder that is
/// only in the working copy (recorded in `@` before the access changed)
/// keeps `@` where it is, with the stack it stands on, never rewritten;
/// the edit stays on disk, and the next command does not report a move
/// again.
#[test]
fn s8jr_a_working_copy_edit_in_the_lost_folder_keeps_at_and_its_stack() {
    const EDIT: &str = "MARKER-FINS-UNCOMMITTED-BILLING-5a90\n";
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    let d = fin_chain(&p, &hub, "chain");
    let invoice = format!("{BILL_DIR}/acme/invoice.txt");
    write_files(&d, &[(&invoice, EDIT)]);
    p.fin.ok(&d, &["status"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let before = view_state(&d);
    let out = p.fin.ok(&d, &["show", "feature"]);
    assert_eq!(out.matches(MOVED).count(), 1, "{out}");
    assert!(out.contains("kept where it is") && out.contains(&format!("{BILL_DIR}/")), "{out}");
    let after = view_state(&d);
    assert_eq!(after.1["default"], before.1["default"], "`@` is never rewritten");
    assert_eq!((after.0["mine"], after.0["kid"]), (before.0["mine"], before.0["kid"]), "nor the stack it stands on");
    assert_eq!(std::fs::read_to_string(d.join(&invoice)).unwrap(), EDIT, "the edit stays on disk");
    let out = p.fin.ok(&d, &["log", "-n", "5"]);
    assert!(!out.contains(MOVED), "reported once: {out}");
    assert_eq!(view_state(&d).1["default"], before.1["default"]);
}

/// Guarantee 3 (review of `s8j`): without an access change nothing moves:
/// a person who never had the billing folder pushes work the server grafts
/// it into, pulls, rebases and pushes again, and reads; a person who has
/// it does the same. No command prints the move's line or rewrites a
/// change by itself.
#[test]
fn s8jr_no_access_change_never_moves_the_clone() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    for (who, name) in [(&p.dev, "dev"), (&p.fin, "fin")] {
        let d = who.dir(&format!("nomove-{name}"));
        who.ok(who.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
        who.ok(&d, &["identity", "confirm", &p.fp]);
        let mut seen = String::new();
        write_files(&d, &[(&format!("src/{name}.txt"), "work\n")]);
        seen.push_str(&who.ok(&d, &["commit", "--no-advance", "-m", "work"]));
        seen.push_str(&who.ok(&d, &["tag", "set", &format!("w-{name}"), "-r", "@-"]));
        let out = who.ok(&d, &["push", "-t", &format!("w-{name}")]);
        assert!(out.contains("pushed"), "{out}");
        seen.push_str(&out);
        feature_with(&p, &[(&format!("{BILL_DIR}/acme/later-{name}.txt"), "later\n"), (&format!("src/later-{name}.txt"), "later\n")], &[], "later");
        let tag_before = tags_of(&d)[&format!("w-{name}")];
        for args in [
            vec!["pull"],
            vec!["log", "-n", "20"],
            vec!["show", "feature"],
            vec!["show", &format!("w-{name}")],
            vec!["rebase", "-s", &format!("w-{name}"), "-d", "feature"],
            vec!["tag", "set", &format!("r-{name}"), "-r", &format!("w-{name}")],
            vec!["push", "-t", &format!("r-{name}")],
            vec!["pull"],
            vec!["new", "feature"],
            vec!["diff", "--from", "main", "--to", "feature", "--stat"],
            vec!["status"],
        ] {
            let out = who.ok(&d, &args);
            seen.push_str(&out);
        }
        assert!(!seen.contains(MOVED), "{name}: {seen}");
        assert_ne!(tags_of(&d)[&format!("w-{name}")], tag_before, "{name}: the rebase ran");
        assert_eq!(parents_of(&d, &format!("w-{name}")), vec![tags_of(&d)["feature"]], "{name}");
    }
}

/// Guarantee 4 (review of `s8j`): the move rebases all local work, each
/// change onto its parents' projections: a stack, a merge with a server
/// branch, a change in another workspace on another base, a divergent
/// change (two versions, both visible), and a tag on an old version; the
/// ids are the ones a clone made after the change has. A push afterwards
/// is accepted, and the admin's checkout of each pushed change holds every
/// file of the billing folder, byte for byte.
#[test]
fn s8jr_the_move_rebases_stacks_merges_workspaces_and_divergent_changes() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    let d = plain_thin(&p, &hub, "all");
    write_files(&d, &[("src/a.txt", "a\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "a"]);
    p.fin.ok(&d, &["tag", "set", "a", "-r", "@-"]);
    write_files(&d, &[("src/b.txt", "b\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "b"]);
    p.fin.ok(&d, &["tag", "set", "b", "-r", "@-"]);
    p.fin.ok(&d, &["new", "b", "feature"]);
    write_files(&d, &[("src/m.txt", "m\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "merge"]);
    p.fin.ok(&d, &["tag", "set", "m", "-r", "@-"]);
    // A divergent change on main: two versions of `x`, both visible.
    p.fin.ok(&d, &["new", "main"]);
    write_files(&d, &[("src/x.txt", "x\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "x one"]);
    p.fin.ok(&d, &["tag", "set", "x", "-r", "@-"]);
    let x_old = tags_of(&d)["x"];
    p.fin.ok(&d, &["describe", "-r", "x", "-m", "x two"]);
    p.fin.ok(&d, &["ws", "new", "oldx", "-r", &x_old.hex()]);
    // Another workspace, on `feature`.
    p.fin.ok(&d, &["ws", "new", "agent", "-r", "feature"]);
    p.fin.ok(&d, &["ws", "switch", "agent"]);
    write_files(&d, &[("src/w.txt", "w\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "w"]);
    p.fin.ok(&d, &["tag", "set", "w", "-r", "@-"]);
    p.fin.ok(&d, &["ws", "switch", "default"]);
    p.fin.ok(&d, &["tag", "set", "old", "-r", "main-"]);
    p.fin.ok(&d, &["cat", "-r", "feature", "src/lib.rs"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let before = view_state(&d);
    let out = p.fin.ok(&d, &["pull"]);
    assert_eq!(out.matches(MOVED).count(), 1, "{out}");
    assert!(!out.contains("kept where it is"), "{out}");
    // The current view's ids, as a clone made now has them.
    let fresh = plain_thin(&p, &hub, "fresh");
    p.fin.ok(&fresh, &["tag", "set", "old", "-r", "main-"]);
    let (now, want) = (view_state(&d), tags_of(&fresh));
    let t = &now.0;
    assert_eq!((t["main"], t["feature"]), (want["main"], want["feature"]), "server tags: their projections");
    assert_ne!(t["old"], before.0["old"], "a tag on an old version follows");
    assert_eq!(entry_at(&d, "old", BILL_DIR), None, "into the current view");
    assert_eq!(parents_of(&d, "a"), vec![t["main"]], "the stack's base");
    assert_eq!(parents_of(&d, "b"), vec![t["a"]], "the stack");
    assert_eq!(parents_of(&d, "m"), vec![t["b"], t["feature"]], "the merge");
    assert_eq!(parents_of(&d, "w"), vec![t["feature"]], "the other workspace's change");
    assert_eq!(parents_of(&d, "x"), vec![t["main"]], "x, the newer version");
    let old_ws = now.1["oldx"];
    let x_was = parents_by_id(&d, &old_ws);
    assert_eq!(x_was.len(), 1);
    assert_ne!(x_was[0], x_old, "the older version of x moved too");
    assert_ne!(x_was[0], t["x"], "and stays its own version (divergent)");
    assert_eq!(parents_by_id(&d, &x_was[0]), vec![t["main"]]);
    for (tag, file) in [("a", "src/a.txt"), ("b", "src/b.txt"), ("m", "src/m.txt"), ("m", "src/b.txt"), ("w", "src/w.txt"), ("x", "src/x.txt")] {
        assert!(entry_at(&d, tag, file).is_some(), "{tag} keeps {file}");
        assert_eq!(entry_at(&d, tag, BILL_DIR), None, "{tag} is in the current view");
    }
    // (`m` is not pushed: the server refuses a merge by someone who cannot
    // see a folder its parents differ in, whatever the clone's view.)
    for tag in ["b", "w"] {
        let out = p.fin.ok(&d, &["push", "-t", tag]);
        assert!(out.contains("pushed"), "{tag}: {out}");
    }
    p.admin.ok(&p.dir, &["pull"]);
    for (tag, like) in [("w", "feature"), ("b", "main")] {
        p.admin.ok(&p.dir, &["new", like]);
        let want = below(&walk(&p.dir), BILL_DIR);
        assert!(!want.is_empty());
        // By its remote tag (BUG-1572): `w` is made of the letters of change
        // ids, so the pull creates no local tag `w` when a change of the
        // admin's starts with it (BUG-105), and `w` then names that change.
        p.admin.ok(&p.dir, &["new", &format!("origin/{tag}")]);
        assert_eq!(below(&walk(&p.dir), BILL_DIR), want, "{tag}: every billing file, byte for byte");
    }
}

/// BUG-1565 (review of `s8j`): every `vl push` from a thin clone asks the
/// server for the current projection of each server snapshot a tag or
/// workspace names (`hub_cmd::move_before_push`: one history request per
/// snapshot, `ObjectStore::current_projection`), with no access change: a
/// push costs a request per tag. Two thin clones, with 2 and 40 tags on
/// distinct server snapshots, push one change each. Expected: about the
/// same number of requests.
#[test]
fn s8jr_a_push_costs_no_request_a_tag() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    for i in 0..40 {
        write_files(&p.dir, &[(&format!("src/n/{i:02}.txt"), &format!("n {i}\n"))]);
        p.admin.commit_main(&p.dir, &format!("n {i}"));
    }
    p.admin.ok(&p.dir, &["push"]);
    let mut cost = Vec::new();
    for n in [2usize, 40] {
        let d = plain_thin(&p, &hub, &format!("tags{n}"));
        p.fin.ok(&d, &["tag", "set", "t0", "-r", "main"]);
        for i in 1..n {
            p.fin.ok(&d, &["tag", "set", &format!("t{i}"), "-r", &format!("t{}-", i - 1)]);
        }
        write_files(&d, &[(&format!("src/push{n}.txt"), "push\n")]);
        let tag = format!("pushed{n}");
        p.fin.ok(&d, &["commit", "--no-advance", "-m", "pushed"]);
        p.fin.ok(&d, &["tag", "set", &tag, "-r", "@-"]);
        let before = requests(&hub);
        let out = p.fin.ok(&d, &["push", "-t", &tag]);
        assert!(out.contains("pushed"), "{out}");
        cost.push(requests(&hub) - before);
    }
    eprintln!("s8jr: a push with 2 tags cost {} requests, with 40 tags {}", cost[0], cost[1]);
    assert!(cost[1] <= cost[0] + 8, "with 40 tags {} requests, with 2 {}", cost[1], cost[0]);
}

// ---- Review of `s8k` (BUG-1564, BUG-1565, the retry limit) -------------------

/// The change id of `clone`'s working-copy change, as `vl log` shows it.
fn wc_change(clone: &Path) -> String {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
    repo.snapshot(&repo.view().workspaces["default"].wc).unwrap().change_id.display()
}

/// BUG-1572 (review of `s8k`), the cause, made deterministic: the push of
/// a moved clone is grafted right; the test read it back wrong. A pull
/// creates no local tag whose name is also a change-id prefix of the
/// repository (BUG-105): `w` is made of change-id letters, so when one of
/// the admin's changes starts with `w`, `vl new w` names that change (here
/// the admin's working copy on `main`, with `main`'s billing folder), or is
/// ambiguous. The server's branch `w`, read as `origin/w`, holds every
/// billing file of `feature`.
#[test]
fn bug_1572_a_pulled_tag_named_like_a_change_id_is_read_through_its_remote_tag() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    let d = plain_thin(&p, &hub, "kz");
    p.fin.ok(&d, &["new", "feature"]);
    write_files(&d, &[("src/w.txt", "w\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "w"]);
    p.fin.ok(&d, &["tag", "set", "w", "-r", "@-"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["push", "-t", "w"]);
    assert!(out.contains("pushed"), "{out}");
    assert_eq!(out.matches(MOVED).count(), 1, "the push moved the clone first: {out}");
    // The admin's working copy: a change on `main` whose id starts with `w`
    // (one in 16 does).
    for _ in 0..400 {
        if wc_change(&p.dir).starts_with('w') {
            break;
        }
        p.admin.ok(&p.dir, &["new", "main"]);
    }
    assert!(wc_change(&p.dir).starts_with('w'));
    let pulled = p.admin.ok(&p.dir, &["pull"]);
    assert!(pulled.contains("no local tag created for remote tag 'w'"), "{pulled}");
    let pushed = view_state(&p.dir).3["origin/w"];
    {
        let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
        let w = veil_core::revset::resolve(&repo, "w", "default");
        assert!(w.as_ref().ok() != Some(&pushed), "`w` names another change than the push (or is ambiguous): {w:?}");
    }
    p.admin.ok(&p.dir, &["new", "feature"]);
    let want = below(&walk(&p.dir), BILL_DIR);
    assert!(want.contains_key(&format!("{BILL_DIR}/acme/q2.txt")), "{:?}", want.keys());
    p.admin.ok(&p.dir, &["new", "origin/w"]);
    let got = walk(&p.dir);
    assert_eq!(below(&got, BILL_DIR), want, "the push as grafted: every billing file of `feature`, byte for byte");
    assert_eq!(got.get("src/w.txt").map(Vec::as_slice), Some(b"w\n".as_slice()));
}

/// Guarantees 2 and 3 (review of `s8k`): a push whose work stands on the
/// view its person had before is what moves the clone (the first command
/// after the access change, nothing moved it before), once; the push lands
/// on the current view's `feature`, and the server grafts every billing
/// file back. The pre-push hook (a command of the person's, outside the
/// repository) runs exactly once.
#[test]
fn s8kr_a_push_moves_first_and_runs_its_hook_once() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    let d = plain_thin(&p, &hub, "hooked");
    let counter = p.fin.home.path().join("pre-push-runs");
    let hook = d.join(".veil/hooks/pre-push");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, format!("#!/bin/sh\ncat > /dev/null\necho ran >> '{}'\n", counter.display())).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p.fin.ok(&d, &["new", "feature"]);
    write_files(&d, &[("src/pushme.txt", "pushme\n")]);
    p.fin.ok(&d, &["commit", "--no-advance", "-m", "pushme"]);
    p.fin.ok(&d, &["tag", "set", "pushme", "-r", "@-"]);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let out = p.fin.ok(&d, &["push", "-t", "pushme"]);
    assert!(out.contains("pushed"), "{out}");
    assert_eq!(out.matches(MOVED).count(), 1, "{out}");
    assert_eq!(std::fs::read_to_string(&counter).unwrap(), "ran\n", "the pre-push hook ran once");
    let fresh = plain_thin(&p, &hub, "fresh");
    assert_eq!(parents_of(&d, "pushme"), vec![tags_of(&fresh)["feature"]], "on the current view's `feature`");
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "feature"]);
    let want = below(&walk(&p.dir), BILL_DIR);
    p.admin.ok(&p.dir, &["new", "origin/pushme"]);
    let got = walk(&p.dir);
    assert_eq!(below(&got, BILL_DIR), want, "every billing file of `feature`, byte for byte");
    assert_eq!(got.get("src/pushme.txt").map(Vec::as_slice), Some(b"pushme\n".as_slice()));
}

/// Guarantee 2 (review of `s8k`): the check before a push costs about the
/// same with 2 tags and workspaces as with 40, also for `vl push` without
/// `-t` (every tag the remote does not have) after someone else pushed
/// since the clone's last pull. No access change. The check's own cost is
/// the push's requests less those of the same push with the check off
/// (`VEIL_TEST_NO_VIEW_MOVE=1`, in a twin clone).
#[test]
fn s8kr_a_push_after_the_server_moved_costs_no_request_a_tag() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    for i in 0..40 {
        write_files(&p.dir, &[(&format!("src/n/{i:02}.txt"), &format!("n {i}\n"))]);
        p.admin.commit_main(&p.dir, &format!("n {i}"));
    }
    p.admin.ok(&p.dir, &["push"]);
    let mut cost = Vec::new();
    for n in [2usize, 40] {
        let clones: Vec<(PathBuf, String)> = ["c", "o"].iter().map(|k| (plain_thin(&p, &hub, &format!("moved{k}{n}")), format!("{k}{n}t"))).collect();
        for (d, pre) in &clones {
            p.fin.ok(d, &["tag", "set", &format!("{pre}0"), "-r", "main"]);
            p.fin.ok(d, &["ws", "new", &format!("{pre}ws0"), "-r", "main"]);
            for i in 1..n {
                p.fin.ok(d, &["tag", "set", &format!("{pre}{i}"), "-r", &format!("{pre}{}-", i - 1)]);
                p.fin.ok(d, &["ws", "new", &format!("{pre}ws{i}"), "-r", &format!("{pre}{i}")]);
            }
        }
        // Someone else pushes after these clones' last pull.
        write_files(&p.dir, &[(&format!("src/later{n}.txt"), "later\n")]);
        p.admin.commit_main(&p.dir, &format!("later {n}"));
        p.admin.ok(&p.dir, &["push"]);
        let mut each = Vec::new();
        for (i, (d, _)) in clones.iter().enumerate() {
            let before = requests(&hub);
            let mut c = p.fin.command(d, &["push"]);
            if i == 1 {
                c.env("VEIL_TEST_NO_VIEW_MOVE", "1");
            }
            let o = c.output().unwrap();
            let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
            assert!(o.status.success() && all.contains("pushed"), "{all}");
            assert!(!all.contains(MOVED), "{all}");
            each.push(requests(&hub) - before);
        }
        eprintln!("s8kr: `vl push` of {n} tags after the server moved: {} requests, {} without the check", each[0], each[1]);
        cost.push(each[0].saturating_sub(each[1]));
    }
    assert!(cost[1] <= cost[0] + 8, "the check cost {} requests with 40 tags, {} with 2", cost[1], cost[0]);
}

/// Guarantee 3 (review of `s8k`): `vl ws exec` never runs its command
/// twice across a move. fin's workspace `agent` stands on `feature` in the
/// view fin had; fin loses the billing folder; the command (appending a
/// line to a file of the sandbox's) writes inside the folder fin lost, and
/// its run is recorded. The command runs once and the clone moves once,
/// whether the move comes after the run (today: its recording fails on
/// the history fin no longer reads, BUG-1573, and the command is not run
/// again) or before it.
#[test]
fn s8kr_ws_exec_never_runs_its_command_twice_across_a_move() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    let d = thin_with_agent(&p, &hub, &p.fin, "exec");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let script = format!("echo ran >> ran.txt; mkdir -p {BILL_DIR}/acme && echo mine > {BILL_DIR}/acme/exec.txt");
    let o = p.fin.run(&d, &["ws", "exec", "agent", "--", "sh", "-c", &script]);
    let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let ran = std::fs::read_to_string(d.join(".veil/local/sandboxes/agent/files/ran.txt")).unwrap_or_else(|e| panic!("the command ran: {e}\n{all}"));
    assert_eq!(ran, "ran\n", "the command ran once: {all}");
    assert_eq!(all.matches(MOVED).count(), 1, "the clone moved, once: {all}");
}

/// BUG-1573 (review of `s8k`): a workspace whose change stands on a server
/// snapshot this thin clone never fetched (`vl ws new agent -r feature`,
/// never run yet), after its person loses a folder. The server refuses the
/// old root, so the first `vl ws exec agent` runs the command in an empty
/// sandbox, then fails to record it; the move that follows keeps the
/// workspace's change (empty: it edits nothing) "where it is" because it
/// cannot tell what its old parent held (`lost_paths` gives `None`), so
/// every later `vl ws exec agent` does the same.
#[test]
#[ignore = "BUG-1573: a workspace on a snapshot the thin clone never fetched runs its command in an empty sandbox after an access change, for ever"]
fn bug_1573_a_workspace_never_synced_runs_on_the_current_view_after_an_access_change() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    let d = thin_with_agent(&p, &hub, &p.fin, "never");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let want = format!("{FEATURE_MARK} 0 0");
    for run in 0..2 {
        let o = p.fin.run(&d, &["ws", "exec", "agent", "--", "sh", "-c", "cat src/wide/f0/s0.txt; echo out > out.txt"]);
        let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success() && all.contains(&want), "run {run}: the command runs on feature's files, and is recorded: {all}");
        assert_eq!(all.matches(MOVED).count(), if run == 0 { 1 } else { 0 }, "run {run}: {all}");
        assert!(!all.contains("kept where it is"), "run {run}: an empty change edits nothing: {all}");
        assert!(!all.contains(FEATURE_BILL) && !all.contains(BILL_MARK), "run {run}: {all}");
    }
}

/// BUG-1574 (review of `s8k`): a sandbox synced to a tree whose root the
/// server refuses (here: a workspace never synced, in a view that changed,
/// with the move off so the record is the sync's alone) records the root
/// as hidden and refused (`""`), which the record's reader rejects
/// (`Materialised`'s `TryFrom`: no root). The manifest is then
/// "unreadable": the run's error says to run `--record-only`, which answers
/// that the sandbox holds no unrecorded run though the output is there,
/// and the next run sets the files aside as of an unreadable manifest.
#[test]
#[ignore = "BUG-1574: a sandbox whose root tree the server refuses writes a materialisation record it cannot read back (`--record-only` says there is nothing to record)"]
fn bug_1574_a_sandbox_whose_root_the_server_refuses_keeps_a_readable_record() {
    let hub = TestHub::start();
    let p = project_with_feature(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    let d = thin_with_agent(&p, &hub, &p.fin, "rootless");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    p.fin.stay_in_stale_views();
    let o = p.fin.run(&d, &["ws", "exec", "agent", "--", "sh", "-c", "echo ran >> ran.txt"]);
    let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let sb = d.join(".veil/local/sandboxes/agent");
    assert!(sb.join("files/ran.txt").exists(), "the command ran: {all}");
    let manifest = std::fs::read_to_string(sb.join("manifest.json")).unwrap();
    let r = p.fin.run(&d, &["ws", "exec", "agent", "--record-only"]);
    let rall = format!("{}{}", String::from_utf8_lossy(&r.stdout), String::from_utf8_lossy(&r.stderr));
    assert!(!rall.contains("holds no unrecorded run"), "the run's output is in the sandbox ({all}); its record reads back ({manifest}): {rall}");
    let again = p.fin.run(&d, &["ws", "exec", "agent", "--", "true"]);
    let aall = format!("{}{}", String::from_utf8_lossy(&again.stdout), String::from_utf8_lossy(&again.stderr));
    assert!(!aall.contains("its manifest is unreadable"), "{manifest}\n{aall}");
}
