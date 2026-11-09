//! Thin clones (milestone S3, `docs/HUB.md` §13.21): fetch on demand
//! through a promisor, the cache area and its bound, the history boundary,
//! and the partial-clone threat review (`docs/design/scale/6-partial-clone.md`).
//!
//! The server is a full repository behind a fake promisor that answers as
//! the Veil server does: an object only at a place (snapshot and path) where
//! it is, "no such object there" otherwise, and errors when "down".

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use veil_core::{
    gc::{gc, GcOptions},
    object::{EntryKind, Object},
    promisor::{Located, Promisor},
    repo::{PartialConfig, PARTIAL_FORMAT},
    store::ObjectStore,
    tree::lookup,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath, VeilError,
};

use crate::adversarial_support::{commit_files, p, read_at};

/// The server's side: a full repository, and what it was asked.
struct Server {
    store: Arc<ObjectStore>,
    tips: Vec<ObjectId>,
    down: AtomicBool,
    tamper: AtomicBool,
    refuse: Mutex<HashSet<ObjectId>>,
    asked: Mutex<Vec<Located>>,
    pages: Mutex<usize>,
}

impl Server {
    /// Is `w.id` at `w.path` in snapshot `w.snapshot` of the server?
    fn there(&self, w: &Located) -> bool {
        let Ok(Object::Snapshot(s)) = self.store.get(&w.snapshot) else { return false };
        if w.path.is_empty() {
            return s.tree == w.id;
        }
        match lookup(&self.store, &s.tree, &VPath::new(&w.path).unwrap()) {
            Ok(Some(e)) if e.id == w.id => true,
            Ok(Some(e)) if e.kind == EntryKind::Conflict => {
                self.store.conflict(&e.id).is_ok_and(|c| c.referenced_ids().contains(&w.id))
            }
            _ => false,
        }
    }
}

impl Promisor for Server {
    fn fetch(&self, wants: &[Located]) -> veil_core::Result<Vec<Option<Vec<u8>>>> {
        if self.down.load(Ordering::SeqCst) {
            return Err(VeilError::Unavailable("test server: connection refused".into()));
        }
        self.asked.lock().unwrap().extend(wants.iter().cloned());
        Ok(wants
            .iter()
            .map(|w| {
                if !self.there(w) || self.refuse.lock().unwrap().contains(&w.id) {
                    return None;
                }
                let mut raw = self.store.get_raw(&w.id).ok()?;
                if self.tamper.load(Ordering::SeqCst) {
                    let last = raw.len() - 1;
                    raw[last] ^= 1;
                }
                Some(raw)
            })
            .collect())
    }

    fn history(&self, tips: &[ObjectId], limit: usize) -> veil_core::Result<Vec<(ObjectId, Vec<u8>)>> {
        if self.down.load(Ordering::SeqCst) {
            return Err(VeilError::Unavailable("test server: connection refused".into()));
        }
        *self.pages.lock().unwrap() += 1;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut queue: std::collections::VecDeque<ObjectId> = tips.iter().copied().collect();
        while let Some(id) = queue.pop_front() {
            if out.len() >= limit.max(tips.len()) || !seen.insert(id) {
                continue;
            }
            let Ok(raw) = self.store.get_raw(&id) else { continue };
            let Ok(Object::Snapshot(s)) = Object::decode(&raw) else { continue };
            queue.extend(s.parents.iter().copied());
            out.push((id, raw));
        }
        Ok(out)
    }

    fn server_tips(&self) -> Vec<ObjectId> {
        self.tips.clone()
    }

    /// As the server's viewer graph computes them: `veil_core`'s one
    /// arithmetic (BUG-1316).
    fn generations(&self, snapshots: &[ObjectId]) -> veil_core::Result<Option<Vec<Option<u64>>>> {
        if self.down.load(Ordering::SeqCst) {
            return Err(VeilError::Unavailable("test server: connection refused".into()));
        }
        fn generation(store: &ObjectStore, id: &ObjectId, memo: &mut std::collections::HashMap<ObjectId, u64>) -> Option<u64> {
            if let Some(g) = memo.get(id) {
                return Some(*g);
            }
            let Ok(Object::Snapshot(s)) = store.get(id) else { return None };
            let mut parents = Vec::new();
            for p in &s.parents {
                parents.push(generation(store, p, memo)?);
            }
            let g = veil_core::graph_index::generation(s.timestamp, parents);
            memo.insert(*id, g);
            Some(g)
        }
        let mut memo = std::collections::HashMap::new();
        Ok(Some(snapshots.iter().map(|id| generation(&self.store, id, &mut memo)).collect()))
    }
}

/// The project as the server holds it: three commits, then the tip.
struct Project {
    server: Arc<Server>,
    commits: Vec<ObjectId>,
    tip: ObjectId,
    id: Identity,
}

fn project() -> Project {
    let id = Identity::generate("alice");
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    let mut commits = Vec::new();
    commits.push(commit_files(&mut repo, &*fs, &[("src/a.txt", "a one\n"), ("src/b.txt", "b one\n"), ("doc/r.md", "readme\n")], "one"));
    commits.push(commit_files(&mut repo, &*fs, &[("src/a.txt", "a two\n"), ("lib/x.rs", "fn x() {}\n")], "two"));
    for i in 0..8 {
        commits.push(commit_files(&mut repo, &*fs, &[(&format!("gen/f{i}.txt"), &format!("generated {i} {}\n", "x".repeat(400)))], "gen"));
    }
    let tip = *commits.last().unwrap();
    let server = Arc::new(Server {
        store: repo.store().clone(),
        tips: vec![tip],
        down: AtomicBool::new(false),
        tamper: AtomicBool::new(false),
        refuse: Mutex::new(HashSet::new()),
        asked: Mutex::new(Vec::new()),
        pages: Mutex::new(0),
    });
    Project { server, commits, tip, id }
}

/// A thin clone of `pr` holding the tip snapshot only, connected to its
/// server.
fn thin(pr: &Project, limit: u64) -> (Repo, Arc<MemoryBackend>) {
    let fs = Arc::new(MemoryBackend::new());
    let repo = thin_unconnected(pr, &fs, limit);
    repo.store().set_promisor(pr.server.clone());
    (repo, fs)
}

fn thin_unconnected(pr: &Project, fs: &Arc<MemoryBackend>, limit: u64) -> Repo {
    let mut repo = Repo::init(fs.clone(), Some(pr.id.clone()), "alice").unwrap();
    repo.update_config(|c| {
        c.format = PARTIAL_FORMAT;
        c.min_vl = Some(veil_core::repo::min_vl_for_format(PARTIAL_FORMAT).into());
        c.partial = Some(PartialConfig { remote: "origin".into(), cache_limit: limit });
        Ok(())
    })
    .unwrap();
    let raw = pr.server.store.get_raw(&pr.tip).unwrap();
    repo.store().put_raw(&pr.tip, &raw).unwrap();
    // As a clone records it: the server's tip.
    let mut tx = repo.transaction("clone").unwrap();
    tx.view.remote_tags.insert("origin/main".into(), pr.tip);
    tx.commit().unwrap();
    repo
}

/// Check `tip` out into `fs` as a new change of the default workspace.
fn checkout(repo: &mut Repo, fs: &MemoryBackend, tip: ObjectId) {
    let wc = repo.new_change("default", vec![tip], "").unwrap();
    repo.check_out_new(fs, "default", wc, None).unwrap();
}

fn entry(repo: &Repo, rev: &ObjectId, path: &str) -> veil_core::TreeEntry {
    let tree = repo.snapshot(rev).unwrap().tree;
    lookup(repo.store(), &tree, &p(path)).unwrap().unwrap()
}

#[test]
fn a_read_fetches_from_the_server_at_the_path_where_it_was_met() {
    let pr = project();
    let (repo, _fs) = thin(&pr, 1 << 30);
    assert_eq!(read_at(&repo, &pr.tip, "src/a.txt"), b"a two\n");
    let e = entry(&repo, &pr.tip, "src/a.txt");
    let store = repo.store();
    assert!(store.has(&e.id) && !store.has_main(&e.id), "fetched objects go to the cache area only");
    assert!(store.cache().unwrap().has(&e.id));
    let asked = pr.server.asked.lock().unwrap().clone();
    assert!(asked.iter().any(|w| w.id == e.id && w.path == "src/a.txt" && w.snapshot == pr.tip), "{asked:?}");
    // Only what the read needed: the root, `src/` and the file.
    assert_eq!(asked.len(), 3, "{asked:?}");
}

/// Threat 1 and 12: an unreachable server is never a redaction.
#[test]
fn an_unreachable_server_is_unavailable_never_hidden() {
    let pr = project();
    let (repo, _fs) = thin(&pr, 1 << 30);
    pr.server.down.store(true, Ordering::SeqCst);
    let tree = repo.snapshot(&pr.tip).unwrap().tree;
    let err = repo.store().tree(&tree).unwrap_err();
    assert!(matches!(err, VeilError::Unavailable(_)), "{err:?}");
    assert!(!err.is_unreadable());
    // A checkout fails before writing anything.
    let wc = MemoryBackend::new();
    let err = repo.check_out_new(&wc, "default", pr.tip, None).unwrap_err();
    assert!(matches!(err, VeilError::Unavailable(_)), "{err:?}");
    assert!(!wc.exists(&p("src/a.txt")).unwrap());
    // The message names no object id.
    assert!(!err.to_string().contains(&tree.hex()[..12]), "{err}");
}

/// Without a connection to the server (a command that did not attach
/// one), a read of what was never fetched is `Unavailable` too.
#[test]
fn a_command_without_a_connection_fails_instead_of_hiding() {
    let pr = project();
    let fs = Arc::new(MemoryBackend::new());
    let repo = thin_unconnected(&pr, &fs, 1 << 30);
    let tree = repo.snapshot(&pr.tip).unwrap().tree;
    let err = repo.store().tree(&tree).unwrap_err();
    assert!(matches!(err, VeilError::Unavailable(_)), "{err:?}");
}

/// The server's own refusal ("nothing there you may see") is a redaction.
#[test]
fn the_servers_refusal_is_missing() {
    let pr = project();
    let (repo, _fs) = thin(&pr, 1 << 30);
    let tree = repo.snapshot(&pr.tip).unwrap().tree;
    let src = repo.store().tree(&tree).unwrap().get("src").unwrap().id;
    let b = pr.server.store.tree(&src).unwrap().get("b.txt").unwrap().id;
    pr.server.refuse.lock().unwrap().insert(b);
    let e = entry(&repo, &pr.tip, "src/b.txt");
    let err = repo.store().read_entry(&e).unwrap_err();
    assert!(matches!(err, VeilError::Missing(_)), "{err:?}");
}

/// Every object fetched is checked against its BLAKE3 id before use.
#[test]
fn a_tampered_object_is_refused_and_never_cached() {
    let pr = project();
    let (repo, _fs) = thin(&pr, 1 << 30);
    let tree = repo.snapshot(&pr.tip).unwrap().tree;
    pr.server.tamper.store(true, Ordering::SeqCst);
    let err = repo.store().tree(&tree).unwrap_err();
    assert!(matches!(err, VeilError::Corrupt(..)), "{err:?}");
    assert!(!repo.store().has(&tree));
}

/// Threat 6: what this repository makes goes to the main store, even when
/// the cache already holds the same object; eviction to nothing loses none
/// of it.
#[test]
fn local_work_is_never_in_the_cache_and_survives_eviction() {
    let pr = project();
    let (mut repo, fs) = thin(&pr, 1 << 30);
    checkout(&mut repo, &fs, pr.tip);
    // Same content as a fetched file (src/b.txt), and a new one.
    let mine = commit_files(&mut repo, &*fs, &[("src/b2.txt", "b one\n"), ("new.txt", "mine\n")], "local work");
    let b2 = entry(&repo, &mine, "src/b2.txt");
    assert!(repo.store().has_main(&b2.id), "a local write is kept in the main store even if cached");
    repo.store().set_cache_limit(0);
    repo.store().set_anchor_snapshots(Vec::new());
    repo.store().trim_cache().unwrap();
    pr.server.down.store(true, Ordering::SeqCst);
    assert_eq!(read_at(&repo, &mine, "new.txt"), b"mine\n");
    assert_eq!(read_at(&repo, &mine, "src/b2.txt"), b"b one\n");
}

/// The cache stays under its bound; what the working copies pin is never
/// evicted, and a read after eviction fetches again.
#[test]
fn eviction_keeps_the_bound_and_the_pins() {
    let pr = project();
    let (repo, _fs) = thin(&pr, 1 << 30);
    // Pin the tip (as a workspace's working copy would).
    repo.store().set_anchor_snapshots(vec![pr.tip]);
    for i in 0..8 {
        read_at(&repo, &pr.tip, &format!("gen/f{i}.txt"));
    }
    // Older content, unpinned: three snapshots back.
    repo.deepen(&[pr.tip], 100).unwrap();
    let old = pr.commits[1];
    assert_eq!(read_at(&repo, &old, "src/a.txt"), b"a two\n");
    assert_eq!(read_at(&repo, &pr.commits[0], "src/a.txt"), b"a one\n");
    let a_one = entry(&repo, &pr.commits[0], "src/a.txt").id;
    let usage = repo.store().cache_usage().unwrap().unwrap();
    let pinned = usage.pinned;
    assert!(pinned > 0 && usage.bytes > pinned, "{usage:?}");
    // A bound just above what is pinned: everything unpinned goes.
    let limit = (pinned + 10) * 10 / 8;
    repo.store().set_cache_limit(limit);
    let t = repo.store().trim_cache().unwrap();
    assert!(!t.full && t.after <= limit, "{t:?}");
    let gen0 = entry(&repo, &pr.tip, "gen/f0.txt").id;
    assert!(repo.store().cache().unwrap().has(&gen0), "a pinned object was evicted");
    assert!(!repo.store().cache().unwrap().has(&a_one), "an unpinned old object stayed");
    // Read again: fetched again.
    let before = pr.server.asked.lock().unwrap().len();
    assert_eq!(read_at(&repo, &pr.commits[0], "src/a.txt"), b"a one\n");
    assert!(pr.server.asked.lock().unwrap().len() > before);
}

/// Threat 11: a cache whose bound is below what is pinned stops fetching
/// with a clear error, never an eviction loop or a hidden file.
#[test]
fn a_full_cache_fails_cleanly() {
    let pr = project();
    let (repo, _fs) = thin(&pr, 16);
    repo.store().set_anchor_snapshots(vec![pr.tip]);
    let tree = repo.snapshot(&pr.tip).unwrap().tree;
    let err = repo.store().tree(&tree).unwrap_err();
    assert!(matches!(err, VeilError::Repo(_)) && err.to_string().contains("full"), "{err:?}");
    assert!(!err.is_unreadable());
}

/// No full graph: the clone holds the tip only. An ancestry question that
/// reaches beyond it is answered from the server's history pages; without
/// a connection it fails instead of answering `false`.
#[test]
fn ancestry_beyond_the_boundary_asks_the_server() {
    let pr = project();
    let (repo, _fs) = thin(&pr, 1 << 30);
    assert!(repo.held().snapshot(&pr.commits[0]).unwrap().is_none(), "the clone holds no history");
    assert!(repo.is_ancestor(&pr.commits[0], &pr.tip).unwrap());
    assert!(*pr.server.pages.lock().unwrap() >= 1);
    assert!(repo.held().snapshot(&pr.commits[0]).unwrap().is_some());

    let fs = Arc::new(MemoryBackend::new());
    let unconnected = thin_unconnected(&pr, &fs, 1 << 30);
    let err = unconnected.is_ancestor(&pr.commits[0], &pr.tip).unwrap_err();
    assert!(matches!(err, VeilError::Unavailable(_)), "{err:?}");
    pr.server.down.store(true, Ordering::SeqCst);
    let (other, _fs) = thin(&pr, 1 << 30);
    let err = other.merge_bases(&[pr.commits[0]], &[pr.tip]).unwrap_err();
    assert!(matches!(err, VeilError::Unavailable(_)), "{err:?}");
}

/// Threat 5: gc in a thin clone never fetches, completes, and keeps local
/// work.
#[test]
fn gc_in_a_thin_clone_never_fetches_and_keeps_local_work() {
    let pr = project();
    let (mut repo, fs) = thin(&pr, 1 << 30);
    checkout(&mut repo, &fs, pr.tip);
    let mine = commit_files(&mut repo, &*fs, &[("new.txt", "mine\n")], "local work");
    pr.server.down.store(true, Ordering::SeqCst);
    let asked = pr.server.asked.lock().unwrap().len();
    let report = gc(&mut repo, &GcOptions { grace: Duration::ZERO, ..GcOptions::default() }).unwrap();
    assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
    let report = gc(&mut repo, &GcOptions { grace: Duration::ZERO, ..GcOptions::default() }).unwrap();
    assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
    assert_eq!(pr.server.asked.lock().unwrap().len(), asked, "gc fetched");
    assert_eq!(read_at(&repo, &mine, "new.txt"), b"mine\n");
}

/// An object met under a local commit only (its tree evicted, the commit
/// not on the server) is asked for at the same path under the server's
/// tips.
#[test]
fn an_object_met_under_a_local_commit_is_found_under_the_servers_tips() {
    let pr = project();
    let (mut repo, fs) = thin(&pr, 1 << 30);
    checkout(&mut repo, &fs, pr.tip);
    let mine = commit_files(&mut repo, &*fs, &[("new.txt", "mine\n")], "local work");
    repo.store().set_anchor_snapshots(Vec::new());
    repo.store().set_cache_limit(0);
    std::mem::drop(fs);
    // A fresh process: nothing decoded yet, the cache emptied.
    let backend: Arc<dyn StorageBackend> = repo.backend().clone();
    // No checkout record pins anything.
    let _ = backend.remove_file(&p(".veil/local/checkout.json"));
    repo.store().trim_cache().unwrap();
    let again = Repo::open(backend, Some(pr.id.clone()), "alice").unwrap();
    again.store().set_promisor(pr.server.clone());
    assert_eq!(read_at(&again, &mine, "doc/r.md"), b"readme\n");
}

/// Threat 14: the marker and format 9 go together.
#[test]
fn the_partial_marker_needs_format_9_and_back() {
    let fs = Arc::new(MemoryBackend::new());
    let id = Identity::generate("alice");
    let repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    drop(repo);
    let path = p(".veil/repo.json");
    let mut c: serde_json::Value = serde_json::from_slice(&fs.read(&path).unwrap()).unwrap();
    c["partial"] = serde_json::json!({"remote": "origin", "cache_limit": 1024});
    fs.write(&path, &serde_json::to_vec(&c).unwrap()).unwrap();
    let err = Repo::open(fs.clone(), Some(id.clone()), "alice").err().unwrap();
    assert!(matches!(err, VeilError::Corrupt(..)), "{err:?}");
    c["format"] = serde_json::json!(PARTIAL_FORMAT);
    c.as_object_mut().unwrap().remove("partial");
    fs.write(&path, &serde_json::to_vec(&c).unwrap()).unwrap();
    let err = Repo::open(fs.clone(), Some(id.clone()), "alice").err().unwrap();
    assert!(matches!(err, VeilError::Corrupt(..)), "{err:?}");
    c["partial"] = serde_json::json!({"remote": "origin", "cache_limit": 1024, "extra": 1});
    fs.write(&path, &serde_json::to_vec(&c).unwrap()).unwrap();
    assert!(Repo::open(fs.clone(), Some(id.clone()), "alice").is_err(), "unknown fields in the marker are refused");
    // A format newer than this build reads is refused before anything else.
    c["format"] = serde_json::json!(PARTIAL_FORMAT + 1);
    c["partial"] = serde_json::json!({"remote": "origin", "cache_limit": 1024});
    fs.write(&path, &serde_json::to_vec(&c).unwrap()).unwrap();
    let err = Repo::open(fs, Some(id), "alice").err().unwrap();
    assert!(matches!(err, VeilError::Unsupported(_)), "{err:?}");
}

/// Occurrences per file of what `count` counts in `veil-core/src`, sorted.
fn count_in_src(count: impl Fn(&str) -> usize) -> Vec<(String, usize)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let n = count(&std::fs::read_to_string(&path).unwrap());
            if n > 0 {
                found.push((path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/"), n));
            }
        }
    }
    found.sort();
    found
}

fn table(rows: &[(&str, usize, &str)]) -> Vec<(String, usize)> {
    let mut t: Vec<(String, usize)> = rows.iter().map(|(f, n, _)| (f.to_string(), *n)).collect();
    t.sort();
    t
}

/// Threat 1's audit: every place the engine reads `Missing` (or any
/// unreadable object) as "hidden". `VeilError::Unavailable` is a variant
/// of its own, never `is_unreadable()`, so each of these sites passes it
/// on as an error. A new site changes a count here and must be reviewed
/// for what it does with a thin clone's objects (this table is the review).
#[test]
fn every_site_that_reads_missing_as_hidden_is_audited() {
    const AUDITED: &[(&str, usize, &str)] = &[
        ("blame.rs", 4, "a hidden version ends the line's history; Unavailable propagates"),
        ("builder.rs", 9, "carry_unreadable keeps a hidden entry as recorded; Unavailable fails the snapshot"),
        ("checkout.rs", 7, "a hidden file is left out and recorded; Unavailable fails before the first write"),
        ("conflict.rs", 2, "a hidden term is shown as hidden"),
        ("embargo.rs", 2, "a withheld fix"),
        ("error.rs", 1, "the definition of is_unreadable"),
        ("fsck.rs", 1, "a thin clone's gap is classified (classify_gap): the server's a note, lost work damage"),
        ("gc.rs", 4, "a thin clone's mark skips only a gap of the server's history (classify_gap)"),
        ("hub/project.rs", 2, "the server's own projection"),
        ("maintenance.rs", 2, "fetching off"),
        ("promisor.rs", 9, "the read path itself; a checkout's prefetch leaves a refused object for its reader, who finds it hidden; read_at (S8): a mount's read at one path, Missing only from the server's refusal there"),
        ("remote.rs", 9, "transfers between local repositories (test fixtures); the server checks closure itself"),
        ("repo.rs", 2, "snapshot_held: a snapshot beyond the boundary; snapshot reads fetch history pages there"),
        ("sandbox.rs", 3, "a hidden file is not given to the sandbox"),
        ("search.rs", 1, "a hidden file is not searched"),
        ("selection.rs", 2, "a hidden file is not selectable"),
        ("store.rs", 4, "the read path: Missing only after every local area"),
        ("transaction.rs", 2, "tolerated: an entry kept by id; the fetch-ahead of a move from a snapshot no longer held"),
        ("tree.rs", 1, "refused_tree (BUG-1508): a tree the server refuses while fetching; readers list it hidden, writers carry it by id or refuse naming it (no_access); with fetching off it stays an error"),
        ("wc_policy.rs", 1, "an unreadable policy"),
    ];
    let found = count_in_src(|t| t.matches("is_unreadable()").count() + t.matches("VeilError::Missing(").count());
    assert_eq!(found, table(AUDITED), "a site that reads Missing changed: review it for thin clones and update the table");
}

/// BUG-1142's class: every place that *makes* a `Missing`. In a thin clone
/// `Missing` must mean the server's own "nothing there you may see", a
/// snapshot beyond the boundary, or (gc, fsck, maintenance only) "not held,
/// fetching off", which they classify. A new producer fails this table.
#[test]
fn every_producer_of_missing_is_audited() {
    const PRODUCERS: &[(&str, usize, &str)] = &[
        ("hub/project.rs", 2, "the server's projection: an object its store lacks"),
        ("promisor.rs", 5, "fetching off (gc, fsck, maintenance: classified); a snapshot beyond the boundary; the server's refusal under a snapshot on the server; read_at (S8, BUG-1460): fetching off, and the server's refusal at the one place asked"),
        ("repo.rs", 1, "Repo::snapshot: the server has no such snapshot in this person's history (after a page was asked)"),
        ("store.rs", 1, "the main store's read: then the cache, then the server (read_partial)"),
    ];
    let found = count_in_src(|t| t.matches("VeilError::Missing(").count() - t.matches("VeilError::Missing(_)").count());
    assert_eq!(found, table(PRODUCERS), "a producer of Missing changed: in a thin clone, Missing must come from the server's own answer");
}



// ---- S3 cycle 1 review (`docs/BUGS.md`, "S3 cycle 1") --------------------

/// A local commit on top of the server's old tip `T`, after a teammate's
/// commit `Q` moved the server's tip on (pulled, checked out): the local
/// commit's unchanged directory, evicted from the cache, is on the server
/// under `T` at the same path. The read asks the local commit, then the
/// server's tips (`Q`, where that path holds something else), never the
/// local commit's own ancestors on the server, and fails with a message
/// whose advice (`vl pull`) cannot help.
#[test]
fn s3r_a_local_commits_unchanged_directory_is_found_after_the_server_moved_on() {
    let id = Identity::generate("alice");
    let sfs = Arc::new(MemoryBackend::new());
    let mut srepo = Repo::init(sfs.clone(), Some(id.clone()), "alice").unwrap();
    let t = commit_files(&mut srepo, &*sfs, &[("src/a.txt", "a one\n"), ("doc/r.md", "readme\n")], "t");
    let q = commit_files(&mut srepo, &*sfs, &[("src/a.txt", "a by a teammate\n")], "q");
    let server = Arc::new(Server {
        store: srepo.store().clone(),
        tips: vec![q],
        down: AtomicBool::new(false),
        tamper: AtomicBool::new(false),
        refuse: Mutex::new(HashSet::new()),
        asked: Mutex::new(Vec::new()),
        pages: Mutex::new(0),
    });
    let pr = Project { server: server.clone(), commits: vec![t, q], tip: t, id: id.clone() };
    let (mut repo, fs) = thin(&pr, 1 << 30);
    checkout(&mut repo, &fs, t);
    let mine = commit_files(&mut repo, &*fs, &[("doc/r.md", "my readme\n")], "local work");
    // The pull of `Q`, and a checkout of it: the local commit is no longer
    // what the working copy pins.
    repo.store().put_raw(&q, &server.store.get_raw(&q).unwrap()).unwrap();
    checkout(&mut repo, &fs, q);
    repo.store().set_cache_limit(0);
    repo.store().trim_cache().unwrap();
    // A fresh process.
    let backend: Arc<dyn StorageBackend> = repo.backend().clone();
    drop(repo);
    let again = Repo::open(backend, Some(id), "alice").unwrap();
    again.store().set_promisor(server.clone());
    let e = entry(&again, &mine, "src/a.txt");
    let got = again.store().read_entry(&e);
    assert!(got.is_ok(), "{:?}", got.err());
}


/// Threat 1 past the locator's bound: an object whose place this process
/// did not record (`LOCATOR_CAP` reached: objects met later are not
/// recorded) is read as `Missing`, so a checkout leaves it out as hidden
/// although the server would serve it. `promisor.rs` says such reads fail
/// with `Unavailable`. Reading a tree this process never met stands in for
/// one met past the bound (8,000,000 locations; a scratch run with the
/// bound at 6 to 12 checked out 0 to 6 of 12 files and recorded the rest
/// as hidden).
#[test]
fn s3r_an_object_without_a_recorded_place_is_never_hidden() {
    let pr = project();
    let (repo, _fs) = thin(&pr, 1 << 30);
    let root = Object::decode(&pr.server.store.get_raw(&pr.tip).unwrap()).unwrap();
    let Object::Snapshot(s) = root else { panic!("a snapshot") };
    let err = repo.store().tree(&s.tree).unwrap_err();
    assert!(!err.is_unreadable(), "a tree the server would serve reads as hidden: {err:?}");
}

/// `vl fsck` in a thin clone takes every object it lacks for one on the
/// server, a note. An object of the clone's own unpushed commit is on no
/// server: its loss is damage that fsck must report.
#[test]
fn s3r_fsck_in_a_thin_clone_reports_lost_local_work() {
    let pr = project();
    let (mut repo, fs) = thin(&pr, 1 << 30);
    checkout(&mut repo, &fs, pr.tip);
    let mine = commit_files(&mut repo, &*fs, &[("mine.txt", "only here, never pushed\n")], "local work");
    let e = entry(&repo, &mine, "mine.txt");
    assert!(repo.store().has_main(&e.id));
    let backend: Arc<dyn StorageBackend> = repo.backend().clone();
    let hex = e.id.hex();
    backend.remove_file(&p(&format!(".veil/objects/{}/{}", &hex[..2], &hex[2..]))).unwrap();
    assert!(!repo.store().has_main(&e.id), "the local file's only copy is gone");
    drop(repo);
    let report = veil_core::fsck::fsck(backend, Some(pr.id.clone())).unwrap();
    let corrupt: Vec<_> = report.findings.iter().filter(|f| f.severity == veil_core::fsck::Severity::Corrupt).collect();
    assert!(!corrupt.is_empty(), "fsck found nothing wrong: {:?}", report.findings);
}

/// After the merge of S3 onto `integration`, protocol revision 3 announces
/// two things: S5's read grants and object routes, and S3's history pages.
/// Each revision names one release of the server's routes: a client that
/// sees 3 cannot tell whether `history` pages.
#[test]
fn s3r_each_protocol_revision_announces_one_thing() {
    let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/hub/wire.rs")).unwrap();
    let at = src.find("pub const REVISION: u32 = ").expect("REVISION");
    let doc: String = src[..at]
        .lines()
        .rev()
        .take_while(|l| l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|l| l.trim_start().trim_start_matches("///").trim())
        .collect::<Vec<_>>()
        .join(" ");
    let doc = doc.split_once(": ").map(|(_, d)| d.to_string()).unwrap_or(doc);
    let mut named: Vec<u32> = doc
        .split("; ")
        .filter_map(|seg| seg.split(|c: char| !c.is_ascii_digit()).next().and_then(|n| n.parse().ok()))
        .collect();
    named.sort();
    let mut once = named.clone();
    once.dedup();
    assert_eq!(named, once, "a revision is described twice: {doc}");
    assert_eq!(once.last().copied(), Some(veil_core::hub::wire::REVISION), "{doc}");
}

// ---- S3 cycle 2 review (`docs/BUGS.md`, "S3 cycle 2") --------------------

/// BUG-1147: the locator skips a file that a pack of the *cache* area holds
/// when its tree is decoded; the cache is evicted, so once that pack goes
/// (a trim in the same process) the file has no place, and every read of it
/// in this process is `Unavailable` ("run the command again"), however
/// often its tree is read again: the decoded tree stays in the store's
/// tree cache and is never decoded (noted) again. A long-lived process
/// (`vl mount`, the S6 daemon) never recovers.
#[test]
fn s3r2_a_file_whose_cache_pack_was_evicted_is_read_again_in_the_same_process() {
    // A directory of 20 files: the fetch-ahead writes them as one pack
    // (from 16 objects; fewer are written loose).
    let id = Identity::generate("alice");
    let sfs = Arc::new(MemoryBackend::new());
    let mut srepo = Repo::init(sfs.clone(), Some(id.clone()), "alice").unwrap();
    let files: Vec<(String, String)> = (0..20).map(|i| (format!("src/f{i:02}.txt"), format!("file {i}\n"))).collect();
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let tip = commit_files(&mut srepo, &*sfs, &refs, "twenty");
    let server = Arc::new(Server {
        store: srepo.store().clone(),
        tips: vec![tip],
        down: AtomicBool::new(false),
        tamper: AtomicBool::new(false),
        refuse: Mutex::new(HashSet::new()),
        asked: Mutex::new(Vec::new()),
        pages: Mutex::new(0),
    });
    let pr = Project { server, commits: vec![tip], tip, id };
    let (mut repo, fs) = thin(&pr, 1 << 30);
    // The checkout fetches the tip's files ahead, into a cache pack.
    checkout(&mut repo, &fs, pr.tip);
    let backend: Arc<dyn StorageBackend> = repo.backend().clone();
    drop(repo);
    // A fresh process (`vl mount`, a daemon): it decodes the tip's trees
    // while the pack holds their files.
    let again = Repo::open(backend.clone(), Some(pr.id.clone()), "alice").unwrap();
    again.store().set_promisor(pr.server.clone());
    let e = entry(&again, &pr.tip, "src/f07.txt");
    assert_eq!(again.store().read_entry(&e).unwrap(), b"file 7\n");
    // The working copy moves elsewhere (nothing pins the tip), and the
    // cache is trimmed: the pack goes.
    let _ = backend.remove_file(&p(".veil/local/checkout.json"));
    again.store().set_anchor_snapshots(Vec::new());
    again.store().set_cache_limit(0);
    again.store().trim_cache().unwrap();
    again.store().set_cache_limit(1 << 30);
    assert!(!again.store().cache().unwrap().has(&e.id), "the pack was evicted");
    // Read the file again, as the same process: its tree read afresh first.
    let e = entry(&again, &pr.tip, "src/f07.txt");
    let got = again.store().read_entry(&e);
    assert!(got.is_ok(), "the server would serve it, yet this process cannot place it: {:?}", got.err());
}

/// BUG-1148: gc in a thin clone after an ordinary eviction. A local commit
/// `L` on the server's tip keeps the tip's unchanged directories by id
/// (`src/`, `gen/`, …); once the working copy moves on (a pull, a checkout
/// of the new tip) and the cache is trimmed, those directories and the
/// tip's own trees are evicted. gc's mark meets the directories missing
/// under `L`; `classify_gap` needs the tip's evicted root tree to tell, so
/// every one is `Unknown`, the mark is incomplete, and gc deletes nothing,
/// in every run while `L` is in the view: in steady state a thin clone's gc
/// never completes. Each of those objects is the server's: the tip, on the
/// server, names `L`'s directory by the same id (`L`'s own tree, held, says
/// so).
#[test]
fn s3r2_gc_in_a_thin_clone_completes_after_an_eviction() {
    let id = Identity::generate("alice");
    let sfs = Arc::new(MemoryBackend::new());
    let mut srepo = Repo::init(sfs.clone(), Some(id.clone()), "alice").unwrap();
    let t = commit_files(&mut srepo, &*sfs, &[("src/a.txt", "a one\n"), ("doc/r.md", "readme\n")], "t");
    let q = commit_files(&mut srepo, &*sfs, &[("src/a.txt", "a by a teammate\n")], "q");
    let server = Arc::new(Server {
        store: srepo.store().clone(),
        tips: vec![q],
        down: AtomicBool::new(false),
        tamper: AtomicBool::new(false),
        refuse: Mutex::new(HashSet::new()),
        asked: Mutex::new(Vec::new()),
        pages: Mutex::new(0),
    });
    let pr = Project { server: server.clone(), commits: vec![t, q], tip: t, id: id.clone() };
    let (mut repo, fs) = thin(&pr, 1 << 30);
    checkout(&mut repo, &fs, t);
    let _mine = commit_files(&mut repo, &*fs, &[("new.txt", "mine, unpushed\n")], "local work");
    // The pull of `Q` (recorded as the remote's tip), and a checkout of it.
    repo.store().put_raw(&q, &server.store.get_raw(&q).unwrap()).unwrap();
    let mut tx = repo.transaction("pull").unwrap();
    tx.view.remote_tags.insert("origin/main".into(), q);
    tx.commit().unwrap();
    checkout(&mut repo, &fs, q);
    repo.store().set_anchor_snapshots(vec![q]);
    repo.store().set_cache_limit(0);
    repo.store().trim_cache().unwrap();
    repo.store().set_cache_limit(1 << 30);
    let report = gc(&mut repo, &GcOptions { grace: Duration::ZERO, ..GcOptions::default() }).unwrap();
    assert!(report.incomplete.is_empty(), "gc deleted nothing: {:?}", report.incomplete);
}

/// (S3 cycle 2, the reviewer's note for S6.) A long-lived process pulls:
/// the server's tip moves to `Q`, and an object under `Q` that the server
/// refuses for this person is its redaction, `Missing`, even though the
/// connection was attached before the pull and still names the old tip.
/// The tips come from the view, refreshed on every change of it.
#[test]
fn a_pull_in_a_long_lived_process_refreshes_what_is_on_the_server() {
    let id = Identity::generate("alice");
    let sfs = Arc::new(MemoryBackend::new());
    let mut srepo = Repo::init(sfs.clone(), Some(id.clone()), "alice").unwrap();
    let t = commit_files(&mut srepo, &*sfs, &[("src/a.txt", "a\n")], "t");
    let q = commit_files(&mut srepo, &*sfs, &[("hidden/h.txt", "not for alice\n")], "q");
    let h = entry(&srepo, &q, "hidden/h.txt").id;
    // The connection, attached before the pull, knows the old tip only.
    let server = Arc::new(Server {
        store: srepo.store().clone(),
        tips: vec![t],
        down: AtomicBool::new(false),
        tamper: AtomicBool::new(false),
        refuse: Mutex::new(HashSet::from([h])),
        asked: Mutex::new(Vec::new()),
        pages: Mutex::new(0),
    });
    let pr = Project { server: server.clone(), commits: vec![t, q], tip: t, id };
    let (repo, _fs) = thin(&pr, 1 << 30);
    // A read under the old tip: the server walk runs (and is remembered).
    assert_eq!(read_at(&repo, &t, "src/a.txt"), b"a\n");
    let _ = entry(&repo, &t, "src/a.txt");
    // The pull: `Q` arrives, and `origin/main` moves to it.
    repo.store().put_raw(&q, &server.store.get_raw(&q).unwrap()).unwrap();
    let mut repo = repo;
    let mut tx = repo.transaction("pull").unwrap();
    tx.view.remote_tags.insert("origin/main".into(), q);
    tx.commit().unwrap();
    let e = entry(&repo, &q, "hidden/h.txt");
    let err = repo.store().read_entry(&e).unwrap_err();
    assert!(matches!(err, VeilError::Missing(_)), "the server's refusal under its new tip reads as {err:?}");
}

// ---- S3 cycle 3 review (`docs/BUGS.md`, "S3 cycle 3") --------------------

/// Guarantee 4 of the S3 cycle 3 brief: gc in a thin clone across a pull, a
/// local commit, a rebase of it onto the server's new tip, and an
/// eviction. The BUG-1148 fix pins the trees of the server-side bases of
/// the *view's* heads; the rebased commit's base is the new tip `Q`. Its
/// old version `L` (on the old tip `T`) is still a root of gc, through the
/// op log (kept whole by default), and so is every working-copy snapshot
/// the log remembers on `T`; `T`'s trees are not pinned, are evicted, and
/// `classify_gap` cannot tell `L`'s unchanged directories (`src/`, `doc/`,
/// by `T`'s ids) from lost work: gc is incomplete and deletes nothing, on
/// every run while the op log holds `L`.
#[test]
fn s3r3_gc_in_a_thin_clone_completes_after_a_rebase_onto_the_new_tip() {
    let id = Identity::generate("alice");
    let sfs = Arc::new(MemoryBackend::new());
    let mut srepo = Repo::init(sfs.clone(), Some(id.clone()), "alice").unwrap();
    let t = commit_files(&mut srepo, &*sfs, &[("src/a.txt", "a one\n"), ("doc/r.md", "readme\n")], "t");
    let q = commit_files(&mut srepo, &*sfs, &[("src/a.txt", "a by a teammate\n")], "q");
    let server = Arc::new(Server {
        store: srepo.store().clone(),
        tips: vec![q],
        down: AtomicBool::new(false),
        tamper: AtomicBool::new(false),
        refuse: Mutex::new(HashSet::new()),
        asked: Mutex::new(Vec::new()),
        pages: Mutex::new(0),
    });
    let pr = Project { server: server.clone(), commits: vec![t, q], tip: t, id: id.clone() };
    let (mut repo, fs) = thin(&pr, 1 << 30);
    checkout(&mut repo, &fs, t);
    let mine = commit_files(&mut repo, &*fs, &[("new.txt", "mine, unpushed\n")], "local work");
    // The pull of `Q`, then the local commit rebased onto it (the working
    // copy, its child, moves with it).
    repo.store().put_raw(&q, &server.store.get_raw(&q).unwrap()).unwrap();
    let mut tx = repo.transaction("pull").unwrap();
    tx.view.remote_tags.insert("origin/main".into(), q);
    tx.commit().unwrap();
    let rebased = repo.rebase(mine, vec![q]).unwrap();
    assert_ne!(rebased, mine);
    // The directory follows (`vl rebase` moves it to the rebased working
    // copy; here a fresh change on the rebased commit).
    checkout(&mut repo, &fs, rebased);
    // An eviction, as the next fetch past the bound makes one (the pins are
    // the repository's own, from its view).
    repo.store().set_cache_limit(0);
    repo.store().trim_cache().unwrap();
    repo.store().set_cache_limit(1 << 30);
    let report = gc(&mut repo, &GcOptions { grace: Duration::ZERO, ..GcOptions::default() }).unwrap();
    assert!(report.incomplete.is_empty(), "gc deleted nothing: {:?}", report.incomplete);
    // And it deleted nothing of the local work.
    server.down.store(true, Ordering::SeqCst);
    assert_eq!(read_at(&repo, &rebased, "new.txt"), b"mine, unpushed\n");
}

/// The server of `inner`, serving history pages of at most `cap` snapshots
/// (a server may send fewer than asked): a walk of the whole graph then
/// takes a page per `cap` snapshots, which a project's 2,000-snapshot page
/// would hide in a small test.
struct Capped(Arc<Server>, usize);

impl Promisor for Capped {
    fn fetch(&self, wants: &[Located]) -> veil_core::Result<Vec<Option<Vec<u8>>>> {
        self.0.fetch(wants)
    }

    fn history(&self, tips: &[ObjectId], limit: usize) -> veil_core::Result<Vec<(ObjectId, Vec<u8>)>> {
        self.0.history(tips, limit.min(self.1))
    }

    fn server_tips(&self) -> Vec<ObjectId> {
        self.0.server_tips()
    }

    fn generations(&self, snapshots: &[ObjectId]) -> veil_core::Result<Option<Vec<Option<u64>>>> {
        self.0.generations(snapshots)
    }
}

/// A server project of `n` linear commits, and a thin clone of its tip
/// whose server pages history 2 snapshots at a time.
fn long_project(n: usize) -> (Project, Repo, Arc<MemoryBackend>) {
    let id = Identity::generate("alice");
    let sfs = Arc::new(MemoryBackend::new());
    let mut srepo = Repo::init(sfs.clone(), Some(id.clone()), "alice").unwrap();
    let mut commits = Vec::new();
    for i in 0..n {
        commits.push(commit_files(&mut srepo, &*sfs, &[("src/a.txt", &format!("a {i}\n"))], &format!("c{i}")));
    }
    let tip = *commits.last().unwrap();
    let server = Arc::new(Server {
        store: srepo.store().clone(),
        tips: vec![tip],
        down: AtomicBool::new(false),
        tamper: AtomicBool::new(false),
        refuse: Mutex::new(HashSet::new()),
        asked: Mutex::new(Vec::new()),
        pages: Mutex::new(0),
    });
    let pr = Project { server: server.clone(), commits, tip, id };
    let (repo, fs) = thin(&pr, 1 << 30);
    repo.store().set_promisor(Arc::new(Capped(server, 2)));
    (pr, repo, fs)
}

/// BUG-1267 (guarantee 3 of the S3 cycle 3 brief; BUG-1260's class, not in
/// its fix or its audit; the fetching read is S3 cycle 1's): the short id
/// of a hidden snapshot (an earlier version of a change, as `vl evolog`
/// and `vl op log` show it) makes a thin clone page in the project's whole
/// history. `revset::recorded_snapshots_with_prefix` walks every
/// operation's view through parents and predecessors with
/// `Repo::snapshot`, which pages history in at the boundary, and descends
/// the server tip's ancestry to the root before it reaches the working
/// copy's predecessors (always for an abandoned change, whose versions
/// only older operations name). The audit tables count `snapshot_opt(` only:
/// `Repo::snapshot(`'s callers are in none of them. Here: 40 commits, a
/// page of 2 snapshots, and resolving the earlier version reads 20 pages
/// (every snapshot), where its answer is held already.
#[test]
fn s3r3_a_hidden_snapshots_short_id_does_not_page_in_the_whole_history() {
    let (pr, mut repo, fs) = long_project(40);
    checkout(&mut repo, &fs, pr.tip);
    fs.write(&p("mine.txt"), b"mine\n").unwrap();
    let earlier = crate::adversarial_support::snap(&mut repo, &*fs);
    fs.write(&p("mine.txt"), b"mine, edited\n").unwrap();
    let now = crate::adversarial_support::snap(&mut repo, &*fs);
    assert_ne!(earlier, now);
    // The change abandoned (`vl abandon`): its versions are in older
    // operations' views only, so the walk, newest operation first, meets
    // the tip's ancestry before them whatever the ids' order.
    repo.abandon(now).unwrap();
    let prefix = &earlier.hex()[..12];
    *pr.server.pages.lock().unwrap() = 0;
    // As `vl` resolves a name (`Ctx::rev`): since the S3 cycle 3 redesign,
    // held history and the server's id lookup, never history pages.
    let got = veil_core::revset::resolve(&repo, prefix, "default").unwrap();
    assert_eq!(got, earlier);
    let pages = *pr.server.pages.lock().unwrap();
    assert!(pages <= 2, "resolving a held, hidden snapshot by its short id read {pages} history pages (the project has 40 snapshots, 2 a page)");
}

/// Guarantee 3 of the S3 cycle 3 brief, the walks the BUG-1260 fix made
/// held-only: none pages history in, however long the history.
#[test]
fn s3r3_the_whole_graph_walks_page_in_nothing() {
    let (pr, repo, _fs) = long_project(40);
    *pr.server.pages.lock().unwrap() = 0;
    repo.held().visible().unwrap();
    repo.held().ancestors(&pr.tip).unwrap();
    repo.held().merge_bases_naive(&[pr.tip], &[pr.commits[3]]).unwrap();
    assert_eq!(*pr.server.pages.lock().unwrap(), 0);
}

/// Guarantee 3 of the redesign (S3 redesign review): every `Exact` walk is
/// bounded by its own range. In a thin clone of 40 commits whose server
/// pages history 2 snapshots at a time, a range of the last 6 snapshots
/// (bisect's candidates, `x..y`, `Exact::range`), ancestry and merge
/// bases between near snapshots read a handful of pages, never the 20 of
/// the whole history; and each answer is the full clone's. Each walk runs
/// in a fresh clone.
#[test]
fn s3rd_exact_walks_page_in_only_their_range() {
    type Walk = Box<dyn Fn(&Repo, &Project)>;
    let walks: Vec<(&str, Walk)> = vec![
        ("bisect candidates", Box::new(|r, pr| assert_eq!(veil_core::bisect::candidates(r, &pr.tip, &[pr.commits[34]]).unwrap().len(), 5))),
        ("x..y", Box::new(|r, pr| assert_eq!(veil_core::revset::resolve_set(r, &format!("{}-----..{}", pr.tip.hex(), pr.tip.hex()), "default").unwrap().len(), 5))),
        ("Exact::range", Box::new(|r, pr| assert_eq!(r.exact().range(&[pr.tip], &[pr.commits[34]]).unwrap().len(), 5))),
        ("is_ancestor(near, tip)", Box::new(|r, pr| assert!(r.is_ancestor(&pr.commits[34], &pr.tip).unwrap()))),
        ("is_ancestor(tip, near)", Box::new(|r, pr| assert!(!r.is_ancestor(&pr.tip, &pr.commits[34]).unwrap()))),
        ("merge_bases", Box::new(|r, pr| assert_eq!(r.merge_bases(&[pr.tip], &[pr.commits[35]]).unwrap(), vec![pr.commits[35]]))),
        ("common_ancestor", Box::new(|r, pr| assert_eq!(r.common_ancestor(&pr.tip, &pr.commits[36]).unwrap(), pr.commits[36]))),
    ];
    let mut costs = Vec::new();
    for (what, walk) in &walks {
        let (pr, repo, _fs) = long_project(40);
        *pr.server.pages.lock().unwrap() = 0;
        walk(&repo, &pr);
        costs.push((what.to_string(), *pr.server.pages.lock().unwrap()));
    }
    let over: Vec<_> = costs.iter().filter(|(_, n)| *n > 6).collect();
    assert!(over.is_empty(), "walks of a 6-snapshot range read more pages than it needs (20 pages is the whole history): {costs:?}");
}

// ---- S3 redesign review, cycle 2: `s3rd2_…` -------------------------------------

/// Guarantee 3 of cycle 2 (nothing outside `repo.rs` reads history without
/// choosing `Held` or `Exact`). The one public read that still compiles
/// outside the engine, `ObjectStore::get` (or `get_raw` and
/// `Object::decode`), asks for an object without saying it is a snapshot:
/// for a snapshot beyond a thin clone's boundary it fails (`Unavailable`),
/// never answers held history as the person's (a `Missing`, a redaction),
/// while `Exact` gives the snapshot.
#[test]
fn s3rd2_no_read_of_history_outside_held_or_exact() {
    let pr = project();
    let (repo, _fs) = thin(&pr, 1 << 30);
    let old = pr.commits[0];
    let read = repo.store().get(&old);
    let exact = repo.exact().snapshot(&old).unwrap();
    assert!(exact.is_some(), "the person's history has the snapshot");
    match read {
        Ok(Object::Snapshot(s)) => assert_eq!(Some(s), exact.as_deref().cloned()),
        Err(VeilError::Unavailable(_)) => {}
        r => panic!("a snapshot of the person's history, read outside Held and Exact: {:?}", r.map(|o| o.kind_name())),
    }
}

// ---- S8 cycle 2 review (`docs/BUGS.md`, "S8 cycle 2") --------------------

/// BUG-1366: `names_held` (S8 cycle 1 fixes) turns fetching off for the
/// whole store (`without_fetching`, a counter every thread reads), not for
/// its own thread, while it looks a refused object up in a held tree. A
/// read on any other thread in that window gets `Missing` ("not yours")
/// for a file the server serves: the "fetching off" producer of `Missing`,
/// outside gc, fsck and maintenance, which alone may meet it. Here one
/// thread reads a refused file under a local change (as a mount does after
/// access is removed) while another reads 600 readable files under the
/// server's tip, as a checkout's staging threads or `vl grep` do: every one
/// of them must read.
#[test]
fn s8r2_a_refusal_met_on_one_thread_never_hides_another_threads_read() {
    let id = Identity::generate("alice");
    let sfs = Arc::new(MemoryBackend::new());
    let mut srv = Repo::init(sfs.clone(), Some(id.clone()), "alice").unwrap();
    let mut files: Vec<(String, String)> = (0..600).map(|i| (format!("many/f{i}.txt"), format!("readable {i}\n"))).collect();
    files.push(("closed/s.txt".into(), "REFUSED-CONTENT-1366\n".into()));
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let tip = commit_files(&mut srv, &*sfs, &refs, "one");
    let server = Arc::new(Server {
        store: srv.store().clone(),
        tips: vec![tip],
        down: AtomicBool::new(false),
        tamper: AtomicBool::new(false),
        refuse: Mutex::new(HashSet::new()),
        asked: Mutex::new(Vec::new()),
        pages: Mutex::new(0),
    });
    let pr = Project { server: server.clone(), commits: vec![tip], tip, id: id.clone() };
    let (mut repo, fs) = thin(&pr, 1 << 30);
    checkout(&mut repo, &fs, tip);
    // The local change adds a file beside the one access will be removed from.
    let mine = commit_files(&mut repo, &*fs, &[("closed/mine.txt", "mine\n")], "local work");
    repo.store().set_anchor_snapshots(Vec::new());
    repo.store().set_cache_limit(0);
    std::mem::drop(fs);
    let backend: Arc<dyn StorageBackend> = repo.backend().clone();
    let _ = backend.remove_file(&p(".veil/local/checkout.json"));
    repo.store().trim_cache().unwrap();
    let again = Repo::open(backend, Some(id), "alice").unwrap();
    again.store().set_promisor(server.clone());
    again.store().set_cache_limit(1 << 30);
    // Access to closed/ is removed on the server.
    let closed = lookup(&server.store, &srv.snapshot(&tip).unwrap().tree, &p("closed/s.txt")).unwrap().unwrap();
    server.refuse.lock().unwrap().insert(closed.id);
    // Met under the local change first (its place is there), then the
    // tip's trees are held too (a listing read them); no file is.
    let refused = entry(&again, &mine, "closed/s.txt");
    let _ = entry(&again, &tip, "closed/s.txt");
    let many: Vec<veil_core::TreeEntry> = (0..600).map(|i| entry(&again, &tip, &format!("many/f{i}.txt"))).collect();
    assert_eq!(refused.id, closed.id);
    let err = again.store().read_entry(&refused).unwrap_err();
    assert!(matches!(err, VeilError::Missing(_)), "the refusal under the local change is the server's: {err:?}");
    let store = again.store().clone();
    let done = AtomicBool::new(false);
    let hidden: Vec<usize> = std::thread::scope(|s| {
        let a = s.spawn(|| {
            let mut n = 0u64;
            while !done.load(Ordering::SeqCst) {
                let e = store.read_entry(&refused).unwrap_err();
                assert!(matches!(e, VeilError::Missing(_)), "{e:?}");
                n += 1;
            }
            n
        });
        let reader = s.spawn(|| {
            let mut hidden = Vec::new();
            for (i, e) in many.iter().enumerate() {
                match store.read_entry(e) {
                    Ok(data) => assert_eq!(data, format!("readable {i}\n").into_bytes()),
                    Err(VeilError::Missing(_)) => hidden.push(i),
                    Err(other) => panic!("many/f{i}.txt: {other:?}"),
                }
            }
            done.store(true, Ordering::SeqCst);
            hidden
        });
        let h = reader.join().unwrap();
        assert!(a.join().unwrap() > 0, "the refusal was read meanwhile");
        h
    });
    assert!(hidden.is_empty(), "{} of 600 files the server serves read as Missing (hidden) while another thread met a refusal: {:?}", hidden.len(), &hidden[..hidden.len().min(10)]);
}

// ---- Review of `s8j` (BUG-1509's move to the current view) ----

/// Copy snapshot `s`, its ancestors and every object their trees name from
/// `from` to `to` (a second view's history on the same test server).
fn copy_closure(from: &ObjectStore, to: &ObjectStore, s: ObjectId) {
    let mut stack = vec![s];
    let mut seen = HashSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        to.put_raw(&id, &from.get_raw(&id).unwrap()).unwrap();
        match from.get(&id).unwrap() {
            Object::Snapshot(snap) => {
                stack.extend(snap.parents.iter().copied());
                stack.push(snap.tree);
            }
            Object::Tree(t) => stack.extend(t.entries.iter().map(|e| e.id)),
            _ => {}
        }
    }
}

/// A server whose person's view changed: `history` answers each snapshot of
/// the older view with its projection in the current one (as the Veil
/// server does, `sync::history`), and fails once, as a transient error,
/// for the snapshots in `flaky`.
struct Projecting {
    inner: Arc<Server>,
    map: std::collections::HashMap<ObjectId, ObjectId>,
    flaky: Mutex<HashSet<ObjectId>>,
    tips: Vec<ObjectId>,
}

impl Promisor for Projecting {
    fn fetch(&self, wants: &[Located]) -> veil_core::Result<Vec<Option<Vec<u8>>>> {
        self.inner.fetch(wants)
    }

    fn history(&self, tips: &[ObjectId], limit: usize) -> veil_core::Result<Vec<(ObjectId, Vec<u8>)>> {
        if let [t] = tips {
            if self.flaky.lock().unwrap().remove(t) {
                return Err(VeilError::Unavailable("test server: 502 bad gateway".into()));
            }
        }
        let tips: Vec<ObjectId> = tips.iter().map(|t| *self.map.get(t).unwrap_or(t)).collect();
        self.inner.history(&tips, limit)
    }

    fn server_tips(&self) -> Vec<ObjectId> {
        self.tips.clone()
    }

    fn generations(&self, snapshots: &[ObjectId]) -> veil_core::Result<Option<Vec<Option<u64>>>> {
        self.inner.generations(snapshots)
    }
}

/// BUG-1564 (review of `s8j`): a transient error from the server while the
/// clone moves to its person's current view is taken for "this snapshot is
/// only this clone's" (`ObjectStore::is_servers` is `false` on any failed
/// request), so the move rewrites the server's own change as if it were
/// local work: `main` is left on a local copy of the admin's commit,
/// divergent from the server's, instead of its projection. Expected: a
/// failed request fails the move, which changes nothing (the command, or
/// the next one, moves).
#[test]
#[ignore = "BUG-1564: a transient error during the move to the current view rewrites a server change as local work"]
fn s8jr_a_transient_error_during_the_move_never_rewrites_a_server_change() {
    // The older view: `c1` (src/ and bill/), then `c2` (src/ only).
    let id = Identity::generate("alice");
    let sfs = Arc::new(MemoryBackend::new());
    let mut srepo = Repo::init(sfs.clone(), Some(id.clone()), "alice").unwrap();
    let c1 = commit_files(&mut srepo, &*sfs, &[("src/a.txt", "a one\n"), ("bill/x.txt", "billing\n")], "one");
    let c2 = commit_files(&mut srepo, &*sfs, &[("src/a.txt", "a two\n")], "two");
    // `main` was rewritten on the server since: the remote tag names `c2b`,
    // and no remote tag reaches `c2`, which the person's work stands on.
    checkout(&mut srepo, &sfs, c1);
    let c2b = commit_files(&mut srepo, &*sfs, &[("src/a.txt", "a two, again\n")], "two again");
    // The current view, without bill/: the same commits projected.
    let pfs = Arc::new(MemoryBackend::new());
    let mut prepo = Repo::init(pfs.clone(), Some(id.clone()), "alice").unwrap();
    let n1 = commit_files(&mut prepo, &*pfs, &[("src/a.txt", "a one\n")], "one");
    let n2 = commit_files(&mut prepo, &*pfs, &[("src/a.txt", "a two\n")], "two");
    copy_closure(prepo.store(), srepo.store(), n2);
    let server = Arc::new(Server {
        store: srepo.store().clone(),
        tips: vec![c2b],
        down: AtomicBool::new(false),
        tamper: AtomicBool::new(false),
        refuse: Mutex::new(HashSet::new()),
        asked: Mutex::new(Vec::new()),
        pages: Mutex::new(0),
    });
    let pr = Project { server: server.clone(), commits: vec![c1, c2, c2b], tip: c2b, id };
    let (mut repo, fs) = thin(&pr, 1 << 30);
    // History as a clone pages it in: the snapshots below its tips.
    for s in [c1, c2] {
        repo.store().put_raw(&s, &pr.server.store.get_raw(&s).unwrap()).unwrap();
    }
    checkout(&mut repo, &fs, c2);
    let mine = commit_files(&mut repo, &*fs, &[("src/mine.txt", "mine\n")], "mine");
    repo.set_tag("main", c2, true).unwrap();
    repo.set_tag("mine", mine, true).unwrap();
    // The person's access changed; the next command (a new process) moves
    // the clone, and one history request fails on the way.
    drop(repo);
    let mut repo = Repo::open(fs.clone(), Some(pr.id.clone()), "alice").unwrap();
    repo.store().set_promisor(Arc::new(Projecting {
        inner: server.clone(),
        map: [(c1, n1), (c2, n2)].into_iter().collect(),
        flaky: Mutex::new(HashSet::from([c2])),
        tips: vec![c2b],
    }));
    let before = repo.view().tags.clone();
    let mut tx = repo.transaction("pull").unwrap();
    // Actual: `Ok` with 3 changes moved, `c2` among them; at commit `main`
    // names a snapshot of the clone's own, `c2` rewritten onto `n1` and
    // signed by the clone (its predecessor `c2`), not `n2`.
    let r = tx.move_to_view();
    let err = r.expect_err("a failed request must fail the move");
    assert!(matches!(err, VeilError::Unavailable(_)), "{err:?}");
    drop(tx);
    assert_eq!(repo.view().tags, before, "nothing changed");
}
