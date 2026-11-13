//! The review of `clifast` (guarantees 1 and 2): a build the file watcher
//! narrows, on a stat cache as loaded (its records still encoded, only the
//! directories the build inspects decoded: BUG-1944), records exactly what
//! a full scan with no cache records, after any sequence of changes, and
//! whatever happened to the cache file in between.
//!
//! Three copies of one working copy get the same changes:
//! * `Scan`: no cache, no plan (the reference);
//! * `Loaded`: the cache read from its file for each build, as every `vl`
//!   command does, and the plan a watcher gives (the directories in which a
//!   file changed, and those in which a directory came or went);
//! * `Decoded`: the same, with every record decoded before the build (what
//!   the code before the branch did).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use veil_core::{
    builder::WatchPlan,
    statcache::{cache_path, StatCache},
    workspace::SnapshotOptions,
    DiskBackend, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Scan,
    Loaded,
    Decoded,
}

struct Copy {
    mode: Mode,
    fs: Arc<dyn StorageBackend>,
    repo: Repo,
    /// The directories the last build asks the next one to look at again.
    recheck: Vec<VPath>,
    /// A cache file of an earlier build, to put back later (a stale cache).
    kept: Option<Vec<u8>>,
    _dir: Option<tempfile::TempDir>,
}

impl Copy {
    fn new(mode: Mode, disk: bool) -> Copy {
        let (fs, dir): (Arc<dyn StorageBackend>, _) = match disk {
            true => {
                let d = tempfile::tempdir().unwrap();
                (Arc::new(DiskBackend::new(d.path())), Some(d))
            }
            false => (Arc::new(MemoryBackend::new()), None),
        };
        let repo = Repo::init(fs.clone(), None, "t").unwrap();
        Copy { mode, fs, repo, recheck: Vec::new(), kept: None, _dir: dir }
    }

    /// Record the working copy; the tree recorded, and whether it changed.
    fn record(&mut self, plan: Option<(&BTreeSet<String>, &BTreeSet<String>)>) -> (ObjectId, bool) {
        let wc = self.repo.workspace_wc("default").unwrap();
        let out = match self.mode {
            Mode::Scan => self
                .repo
                .snapshot_workspace_with("default", &*self.fs, SnapshotOptions { expected_wc: Some(wc), ..Default::default() })
                .unwrap(),
            _ => {
                let path = cache_path("default");
                let mut cache = StatCache::load(&*self.fs, &path);
                if self.mode == Mode::Decoded {
                    let _ = cache.len();
                }
                let plan = plan.map(|(dirs, subtrees)| {
                    WatchPlan::new(dirs.iter().map(|d| vp(d)), subtrees.iter().map(|d| vp(d)), self.recheck.iter().cloned())
                });
                let out = self
                    .repo
                    .snapshot_workspace_with(
                        "default",
                        &*self.fs,
                        SnapshotOptions { cache: Some(&mut cache), expected_wc: Some(wc), watch: plan.as_ref(), ..Default::default() },
                    )
                    .unwrap();
                cache.save(&*self.fs, &path).unwrap();
                out
            }
        };
        assert!(!out.superseded);
        self.recheck = out.report.recheck_dirs();
        (self.repo.snapshot(&out.snapshot).unwrap().tree, out.changed)
    }
}

fn vp(s: &str) -> VPath {
    match s.is_empty() {
        true => VPath::root(),
        false => VPath::new(s).unwrap(),
    }
}

fn parent(path: &str) -> String {
    path.rfind('/').map_or(String::new(), |i| path[..i].to_string())
}

/// Every directory above `path`, outermost first.
fn above(path: &str) -> Vec<String> {
    path.match_indices('/').map(|(i, _)| path[..i].to_string()).collect()
}

/// The working copy the three copies share: its files, and what a watcher
/// would have reported since the last build.
#[derive(Default)]
struct Model {
    files: BTreeMap<String, (Vec<u8>, bool)>,
    dirty_dirs: BTreeSet<String>,
    dirty_subtrees: BTreeSet<String>,
}

impl Model {
    fn dirs(&self) -> BTreeSet<String> {
        self.files.keys().flat_map(|f| above(f)).collect()
    }

    fn is_dir(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        self.files.keys().any(|f| f.starts_with(&prefix))
    }

    /// A file event in the directory of `path`.
    fn file_event(&mut self, path: &str) {
        self.dirty_dirs.insert(parent(path));
    }

    /// A directory came or went at `dir`.
    fn dir_event(&mut self, dir: &str) {
        self.dirty_subtrees.insert(parent(dir));
    }

    /// The directories above `path` that hold nothing any more are removed.
    fn prune(&mut self, copies: &[Copy], path: &str) {
        let dirs = self.dirs();
        for d in above(path) {
            if !dirs.contains(&d) {
                for c in copies {
                    c.fs.remove_dir_all(&vp(&d)).unwrap();
                }
                self.dir_event(&d);
            }
        }
    }

    fn remove_file(&mut self, copies: &[Copy], path: &str) {
        for c in copies {
            c.fs.remove_file(&vp(path)).unwrap();
        }
        self.files.remove(path);
        self.file_event(path);
    }

    fn remove_dir(&mut self, copies: &[Copy], dir: &str) {
        for c in copies {
            c.fs.remove_dir_all(&vp(dir)).unwrap();
        }
        let prefix = format!("{dir}/");
        self.files.retain(|f, _| !f.starts_with(&prefix));
        self.dir_event(dir);
        self.prune(copies, dir);
    }

    /// Write `path`, replacing a file that stands where one of its
    /// directories must be, or the directory that stands at `path`.
    fn write(&mut self, copies: &[Copy], path: &str, data: &[u8]) {
        for d in above(path) {
            if self.files.contains_key(&d) {
                self.remove_file(copies, &d);
            }
        }
        if self.is_dir(path) {
            self.remove_dir(copies, path);
        }
        let dirs = self.dirs();
        for d in above(path) {
            if !dirs.contains(&d) {
                self.dir_event(&d);
            }
        }
        for c in copies {
            c.fs.write(&vp(path), data).unwrap();
        }
        let executable = self.files.get(path).is_some_and(|f| f.1);
        self.files.insert(path.to_string(), (data.to_vec(), executable));
        self.file_event(path);
    }

    fn set_executable(&mut self, copies: &[Copy], path: &str, executable: bool) {
        for c in copies {
            c.fs.set_executable(&vp(path), executable).unwrap();
        }
        self.files.get_mut(path).unwrap().1 = executable;
        self.file_event(path);
    }
}

/// Directories and names whose paths share prefixes (`a/b`, `a/b2`, `a/b.x`;
/// `a` and `a.d`; a file `a/b` where a directory `a/b` can stand), with
/// spaces and non-ASCII letters.
const DIRS: &[&str] = &["", "a", "a/b", "a/b2", "a/b.x", "a/b/c", "a/b/c/d", "a.d", "ab", "z é", "z é/ü b", "a/b-"];
const NAMES: &[&str] = &["f", "f2", "f.txt", "a", "b", "b2", "c", "é ü", "x y", "ab"];

fn walk(disk: bool, seed: u64, steps: usize) {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut next = |n: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % n as u64) as usize
    };
    let mut copies = vec![Copy::new(Mode::Scan, disk), Copy::new(Mode::Loaded, disk), Copy::new(Mode::Decoded, disk)];
    let mut model = Model::default();
    let (mut hits, mut plans) = (0, 0);
    for step in 0..steps {
        for _ in 0..1 + next(3) {
            let existing: Vec<String> = model.files.keys().cloned().collect();
            let what = if existing.len() < 3 { 0 } else { next(10) };
            match what {
                0..=3 => {
                    let dir = DIRS[next(DIRS.len())];
                    let name = NAMES[next(NAMES.len())];
                    let path = if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") };
                    model.write(&copies, &path, format!("{seed} {step} {}\n", next(1000)).as_bytes());
                }
                4 | 5 => {
                    // An edit that keeps the size.
                    let path = &existing[next(existing.len())];
                    let mut data = model.files[path].0.clone();
                    let at = next(data.len() - 1);
                    data[at] = b'A' + ((data[at] as usize + 1 + next(20)) % 26) as u8;
                    model.write(&copies, path, &data);
                }
                6 => {
                    let path = existing[next(existing.len())].clone();
                    model.remove_file(&copies, &path);
                    if !disk || next(2) == 0 {
                        model.prune(&copies, &path);
                    }
                }
                7 => {
                    let dirs: Vec<String> = model.dirs().into_iter().collect();
                    if !dirs.is_empty() {
                        model.remove_dir(&copies, &dirs[next(dirs.len())]);
                    }
                }
                8 => {
                    let path = existing[next(existing.len())].clone();
                    let executable = !model.files[&path].1;
                    model.set_executable(&copies, &path, executable);
                }
                _ => {
                    // A file moved (written under its new name, removed under the old).
                    let from = existing[next(existing.len())].clone();
                    let dir = DIRS[next(DIRS.len())];
                    let to = if dir.is_empty() { format!("m{}", next(3)) } else { format!("{dir}/m{}", next(3)) };
                    if model.files.contains_key(&from) && from != to && !to.starts_with(&format!("{from}/")) {
                        let (data, _) = model.files[&from].clone();
                        model.write(&copies, &to, &data);
                        if model.files.contains_key(&from) {
                            model.remove_file(&copies, &from);
                            model.prune(&copies, &from);
                        }
                    }
                }
            }
        }
        // What happens to the cache file between two commands.
        let fault = next(12);
        for c in copies.iter_mut().filter(|c| c.mode != Mode::Scan) {
            let path = cache_path("default");
            let now = c.fs.read(&path).ok();
            match (fault, now) {
                (0, Some(_)) => c.fs.remove_file(&path).unwrap(),
                (1, Some(raw)) => c.fs.write(&path, &raw[..raw.len() / 2]).unwrap(),
                (2, Some(mut raw)) => {
                    let at = raw.len() / 2;
                    raw[at] ^= 0x40;
                    c.fs.write(&path, &raw).unwrap();
                }
                (3, Some(raw)) => c.kept = Some(raw),
                (4, Some(_)) => {
                    if let Some(old) = &c.kept {
                        c.fs.write(&path, old).unwrap();
                    }
                }
                _ => {}
            }
        }
        // On a disk a record made within 100 ms of the file's last change
        // vouches for nothing: some builds wait, so that later ones find
        // records they can use.
        if disk && next(3) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(130));
        }
        // The watcher's answer, or none (it was stopped, or overflowed).
        let watched = step > 0 && next(6) > 0;
        plans += usize::from(watched);
        let plan = watched.then_some((&model.dirty_dirs, &model.dirty_subtrees));
        let reference = copies[0].record(None);
        hits += usize::from(!reference.1);
        for c in copies.iter_mut().skip(1) {
            let got = c.record(plan);
            assert_eq!(
                got, reference,
                "{} seed {seed}, step {step}, {:?}: a build with the plan (dirs {:?}, subtrees {:?}; watched: {watched}; cache fault {fault}) recorded another tree than a full scan with no cache; files: {:?}",
                if disk { "disk" } else { "memory" },
                c.mode,
                model.dirty_dirs,
                model.dirty_subtrees,
                model.files.keys().collect::<Vec<_>>()
            );
        }
        model.dirty_dirs.clear();
        model.dirty_subtrees.clear();
        // Often nothing changes at all before the next build.
        if next(4) == 0 {
            let reference = copies[0].record(None);
            assert!(!reference.1, "seed {seed}, step {step}: nothing changed");
            for c in copies.iter_mut().skip(1) {
                assert_eq!(c.record(Some((&model.dirty_dirs, &model.dirty_subtrees))), reference, "seed {seed}, step {step}, {:?}: nothing changed", c.mode);
            }
        }
    }
    assert!(plans > steps / 2, "{plans} builds with a plan");
    let _ = hits;
}

/// Stamps that are exact (a generation counter): every record vouches for
/// its file from the next build on.
#[test]
fn a_watched_build_on_a_loaded_cache_records_what_a_full_scan_does_memory() {
    for seed in 1..=40 {
        walk(false, seed, 60);
    }
}

/// A real directory: stamps of the file system, and the racy window.
#[test]
fn a_watched_build_on_a_loaded_cache_records_what_a_full_scan_does_disk() {
    for seed in 1..=6 {
        walk(true, seed, 40);
    }
}

/// BUG-1944: when the watcher vouches that nothing changed, a lock-free
/// repository looks at the watched build before any transaction; a plan
/// that does not apply there (here the policy file changed, which drops
/// it) is built in the transaction as before, and records exactly what a
/// full scan records, on every later build too.
#[test]
fn a_clean_plan_that_does_not_apply_records_what_a_full_scan_does() {
    for disk in [false, true] {
        let mut copies = vec![Copy::new(Mode::Scan, disk), Copy::new(Mode::Loaded, disk)];
        assert!(copies[1].repo.lock_free());
        let none = BTreeSet::new();
        for c in &copies {
            c.fs.write(&vp("a/x.txt"), b"x\n").unwrap();
            c.fs.write(&vp("b/y.txt"), b"y\n").unwrap();
        }
        let first: Vec<_> = copies.iter_mut().map(|c| c.record(None)).collect();
        assert!(first[0].1 && first[0] == first[1]);
        for (step, policy) in [b"b/ ignore\n".as_slice(), b"".as_slice(), b"a/x.txt ignore\n".as_slice()].into_iter().enumerate() {
            for c in &copies {
                c.fs.write(&vp(".veilpolicy"), policy).unwrap();
            }
            let reference = copies[0].record(None);
            let got = copies[1].record(Some((&none, &none)));
            assert_eq!(got, reference, "disk {disk}, step {step}: a clean plan with the policy changed");
            assert!(reference.1, "step {step}: the policy edit is recorded");
            // Nothing changed since: the plan applies, nothing is recorded.
            let reference = copies[0].record(None);
            let got = copies[1].record(Some((&none, &none)));
            assert_eq!(got, reference, "disk {disk}, step {step}: nothing changed");
            assert!(!got.1);
        }
    }
}
