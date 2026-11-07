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
    assert!(repo.snapshot_held(&pr.commits[0]).unwrap().is_none(), "the clone holds no history");
    assert!(repo.is_ancestor(&pr.commits[0], &pr.tip).unwrap());
    assert!(*pr.server.pages.lock().unwrap() >= 1);
    assert!(repo.snapshot_held(&pr.commits[0]).unwrap().is_some());

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
        ("promisor.rs", 7, "the read path itself; a checkout's prefetch leaves a refused object for its reader, who finds it hidden"),
        ("remote.rs", 9, "transfers between local repositories (test fixtures); the server checks closure itself"),
        ("repo.rs", 2, "snapshot_held: a snapshot beyond the boundary; snapshot reads fetch history pages there"),
        ("sandbox.rs", 3, "a hidden file is not given to the sandbox"),
        ("search.rs", 1, "a hidden file is not searched"),
        ("selection.rs", 2, "a hidden file is not selectable"),
        ("store.rs", 4, "the read path: Missing only after every local area"),
        ("transaction.rs", 1, "tolerated: an entry kept by id"),
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
        ("promisor.rs", 3, "fetching off (gc, fsck, maintenance: classified); a snapshot beyond the boundary; the server's refusal under a snapshot on the server"),
        ("repo.rs", 1, "Repo::snapshot: the server has no such snapshot in this person's history (after a page was asked)"),
        ("store.rs", 1, "the main store's read: then the cache, then the server (read_partial)"),
    ];
    let found = count_in_src(|t| t.matches("VeilError::Missing(").count() - t.matches("VeilError::Missing(_)").count());
    assert_eq!(found, table(PRODUCERS), "a producer of Missing changed: in a thin clone, Missing must come from the server's own answer");
}

/// BUG-1141's class: snapshot reads that do not fetch history beyond a
/// thin clone's boundary. `Repo::snapshot` and `snapshot_opt` fetch it;
/// these read only what is held, on purpose.
#[test]
fn every_snapshot_read_that_does_not_fetch_is_audited() {
    const HELD_ONLY: &[(&str, usize, &str)] = &[
        ("gc.rs", 1, "gc never fetches; its mark classifies a gap"),
        ("graph_index.rs", 2, "a generation needs every ancestor: the index walks what is held, and Repo::exact pages history in"),
        ("maintenance.rs", 1, "maintenance never fetches"),
        ("remote.rs", 3, "transfers between local repositories (test fixtures)"),
        ("repo.rs", 4, "snapshot_held itself, and snapshot_opt's first read"),
    ];
    let found = count_in_src(|t| t.matches("store.snapshot(").count() + t.matches("store().snapshot(").count() + t.matches("snapshot_held(").count());
    assert_eq!(found, table(HELD_ONLY), "a snapshot read that skips the boundary's history changed: review it for thin clones");
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
#[ignore = "BUG-1147: a file in an evicted cache pack has no place for the rest of the process"]
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
#[ignore = "BUG-1148: gc in a thin clone never completes once the tip's trees are evicted"]
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
