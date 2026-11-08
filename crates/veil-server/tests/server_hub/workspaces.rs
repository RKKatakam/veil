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
