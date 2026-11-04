//! Storage efficiency: packfiles, garbage collection, op-log pruning, caches.
//! Everything runs on `MemoryBackend` unless a test says otherwise.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use veil_core::{
    cache::LruCache,
    commands::EmbargoSpec,
    embargo::apply_embargo,
    gc::{gc, GcOptions},
    now_millis,
    object::{Object, Snapshot, Text, Tree, TreeEntry, Visibility},
    pack::{Pack, PackBuilder},
    remote,
    store::CacheLimits,
    tree::lookup,
    ChangeId, EntryKind, Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath, VeilError,
};

const WS: &str = "default";
const DAY: i64 = 86_400_000;

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

fn new_repo() -> (Repo, Arc<MemoryBackend>, Identity) {
    let fs = Arc::new(MemoryBackend::new());
    let id = Identity::generate("alice");
    let repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    (repo, fs, id)
}

fn snap(repo: &mut Repo, fs: &MemoryBackend) -> ObjectId {
    repo.snapshot_workspace(WS, fs).unwrap().snapshot
}

fn now_gc() -> GcOptions {
    GcOptions {
        grace: Duration::ZERO,
        ..GcOptions::default()
    }
}

fn read_file(repo: &Repo, rev: &ObjectId, path: &str) -> Option<Vec<u8>> {
    let tree = repo.snapshot(rev).unwrap().tree;
    let e = lookup(repo.store(), &tree, &p(path)).unwrap()?;
    Some(repo.store().read_entry(&e).unwrap())
}

fn all_raw(repo: &Repo) -> HashMap<ObjectId, Vec<u8>> {
    let store = repo.store();
    store
        .list_objects()
        .unwrap()
        .into_iter()
        .map(|id| (id, store.get_raw(&id).unwrap()))
        .collect()
}

/// Every object reachable from the view of every operation still in the op
/// log is present and intact (an fsck of the retained history).
fn assert_history_intact(repo: &Repo) {
    let store = repo.store();
    let mut seen = HashSet::new();
    let mut snaps: Vec<ObjectId> = Vec::new();
    for (_, op) in repo.op_log(usize::MAX).unwrap() {
        snaps.extend(op.view.refs());
    }
    let mut trees = Vec::new();
    while let Some(id) = snaps.pop() {
        if !seen.insert(id) {
            continue;
        }
        let s = store
            .snapshot(&id)
            .unwrap_or_else(|e| panic!("snapshot {}: {e}", id.short()));
        snaps.extend(s.parents.iter().copied());
        trees.push(s.tree);
    }
    while let Some(id) = trees.pop() {
        if !seen.insert(id) {
            continue;
        }
        let t = store.tree(&id).unwrap_or_else(|e| panic!("tree {}: {e}", id.short()));
        for e in &t.entries {
            match e.kind {
                EntryKind::Dir => trees.push(e.id),
                EntryKind::File => {
                    for id in std::iter::once(e.id).chain(e.fallback) {
                        let raw = store
                            .get_raw(&id)
                            .unwrap_or_else(|err| panic!("{} {}: {err}", e.name, id.short()));
                        assert_eq!(ObjectId::hash(&raw), id);
                    }
                }
                EntryKind::Conflict => {
                    let c = store.conflict(&e.id).unwrap_or_else(|err| panic!("{} conflict: {err}", e.name));
                    for id in c.referenced_ids() {
                        let raw = store.get_raw(&id).unwrap_or_else(|err| panic!("{} {}: {err}", e.name, id.short()));
                        assert_eq!(ObjectId::hash(&raw), id);
                    }
                }
            }
        }
    }
}

fn history(repo: &mut Repo, fs: &MemoryBackend, files: usize, snapshots: usize) {
    for s in 0..snapshots {
        for f in 0..files {
            if f % 3 == s % 3 || s == 0 {
                let body: String = (0..40).map(|l| format!("file {f} line {l} rev {}\n", s / 3)).collect();
                fs.write(&p(&format!("src/m{}/f{f}.txt", f % 4)), body.as_bytes())
                    .unwrap();
            }
        }
        snap(repo, fs);
        if s % 2 == 1 {
            repo.commit_working_copy(WS, &format!("change {s}")).unwrap();
        }
    }
}

// ---- packs ----------------------------------------------------------------

#[test]
fn pack_round_trip_every_object_kind() {
    let (mut repo, fs, _) = new_repo();
    history(&mut repo, &fs, 12, 6);
    // A cloaked file gives sealed blobs, an embargo gives sealed + fallback.
    fs.write(&p(".veilpolicy"), b"secret/ cloak team\n").unwrap();
    fs.write(&p("secret/plan.md"), b"the plan\n").unwrap();
    let wc = snap(&mut repo, &fs);
    let before = all_raw(&repo);
    assert!(before.values().any(|r| Object::sealed_scope(r).is_some()));

    let r = gc(&mut repo, &now_gc()).unwrap();
    assert_eq!(r.deleted, 0, "nothing is garbage while every op is retained");
    assert!(r.pack_stats.deltas > 0, "successive versions are delta-compressed");
    assert!(r.pack_stats.stored > 0, "sealed objects are stored uncompressed");
    let stats = repo.store().stats().unwrap();
    assert_eq!((stats.loose_objects, stats.packs), (0, 1));

    // A fresh process sees exactly the same canonical bytes.
    let reopened = Repo::open(fs.clone(), None, "alice").unwrap();
    for (id, raw) in &before {
        assert_eq!(&reopened.store().get_raw(id).unwrap(), raw, "{}", id.short());
        assert!(reopened.store().has(id));
    }
    assert_eq!(read_file(&repo, &wc, "secret/plan.md").unwrap(), b"the plan\n");
    assert!(repo.store().verify_packs().unwrap().is_empty());
    assert_history_intact(&repo);
}

#[test]
fn pack_builder_stores_incompressible_and_sealed_objects_raw() {
    let fs = MemoryBackend::new();
    let dir = p("objects/pack");
    let noise: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let blob = Object::Blob(noise).encode();
    let id = ObjectId::hash(&blob);
    let mut pb = PackBuilder::new(3).unwrap();
    pb.add(id, &blob, None).unwrap();
    assert!(pb.add(ObjectId([1; 32]), &blob, None).is_err(), "ids are verified");
    let (name, stats) = pb.finish(&fs, &dir).unwrap().unwrap();
    assert_eq!(stats.stored + stats.compressed, 1);
    let pack = Pack::open(&fs, &dir, &name).unwrap();
    assert_eq!(pack.get(&fs, &id, &LruCache::new(1 << 20)).unwrap().unwrap(), blob);
    assert!(PackBuilder::new(3).unwrap().finish(&fs, &dir).unwrap().is_none());
}

#[test]
fn mixed_loose_and_packed_store() {
    let (mut repo, fs, _) = new_repo();
    history(&mut repo, &fs, 8, 4);
    gc(&mut repo, &now_gc()).unwrap();
    let packed_wc = repo.workspace_wc(WS).unwrap();

    // New work lands as loose objects next to the pack.
    fs.write(&p("src/new.txt"), b"fresh\n").unwrap();
    let wc = snap(&mut repo, &fs);
    let stats = repo.store().stats().unwrap();
    assert!(stats.loose_objects > 0 && stats.packs == 1);
    assert_eq!(read_file(&repo, &wc, "src/new.txt").unwrap(), b"fresh\n");
    assert!(
        read_file(&repo, &wc, "src/m0/f0.txt").is_some(),
        "packed content still reads"
    );
    assert!(repo.store().has(&packed_wc));

    // An object both loose and packed reads fine and is listed once.
    let raw = repo.store().get_raw(&packed_wc).unwrap();
    fs.write(
        &p(&format!(
            ".veil/objects/{}/{}",
            &packed_wc.hex()[..2],
            &packed_wc.hex()[2..]
        )),
        &raw,
    )
    .unwrap();
    let ids = repo.store().list_objects().unwrap();
    assert_eq!(ids.iter().filter(|i| **i == packed_wc).count(), 1);

    // The next gc folds everything back into a single pack.
    let before = all_raw(&repo);
    let r = gc(&mut repo, &now_gc()).unwrap();
    assert_eq!(r.packs_before, 1);
    let stats = repo.store().stats().unwrap();
    assert_eq!((stats.loose_objects, stats.packs), (0, 1));
    let pack_files = fs.list_dir(&p(".veil/objects/pack")).unwrap();
    assert_eq!(pack_files.len(), 2, "old pack removed: {pack_files:?}");
    for (id, raw) in &before {
        assert_eq!(&repo.store().get_raw(id).unwrap(), raw);
    }
}

#[test]
fn other_process_survives_a_repack() {
    let (mut repo, fs, id) = new_repo();
    history(&mut repo, &fs, 6, 4);
    gc(&mut repo, &now_gc()).unwrap();
    // Another process has the first pack loaded…
    let other = Repo::open(fs.clone(), Some(id), "alice").unwrap();
    let wc = other.workspace_wc(WS).unwrap();
    assert!(read_file(&other, &wc, "src/m1/f1.txt").is_some());
    // …while gc replaces it.
    fs.write(&p("src/later.txt"), b"later\n").unwrap();
    snap(&mut repo, &fs);
    gc(&mut repo, &now_gc()).unwrap();
    other.store().snapshot(&repo.workspace_wc(WS).unwrap()).unwrap();
    assert!(
        read_file(&other, &wc, "src/m2/f2.txt").is_some(),
        "re-scans packs after they vanish"
    );
}

#[test]
fn corrupt_packs_are_detected() {
    let (mut repo, fs, _) = new_repo();
    history(&mut repo, &fs, 10, 4);
    let ids: Vec<ObjectId> = repo.store().list_objects().unwrap();
    gc(&mut repo, &now_gc()).unwrap();
    let pack = repo.store().packs().unwrap()[0].clone();
    let pack_path = pack.path().clone();
    let idx_path = pack.index_path().clone();
    let good_pack = fs.read(&pack_path).unwrap();
    let good_idx = fs.read(&idx_path).unwrap();

    // 1. A flipped bit inside object data: the read fails as Corrupt and
    //    verification names the pack. It never returns wrong bytes.
    let mut bad = good_pack.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x40;
    fs.write(&pack_path, &bad).unwrap();
    let r = Repo::open(fs.clone(), None, "alice");
    let reopened = match r {
        Ok(r) => r,
        Err(e) => {
            assert!(matches!(e, VeilError::Corrupt(..)), "{e}");
            fs.write(&pack_path, &good_pack).unwrap();
            Repo::open(fs.clone(), None, "alice").unwrap()
        }
    };
    fs.write(&pack_path, &bad).unwrap();
    let mut corrupt = 0;
    for id in &ids {
        match reopened.store().get_raw(id) {
            Ok(raw) => assert_eq!(ObjectId::hash(&raw), *id),
            Err(VeilError::Corrupt(..)) => corrupt += 1,
            Err(e) => panic!("unexpected error {e}"),
        }
    }
    assert!(corrupt > 0, "the damaged object was reported");
    assert!(!reopened.store().verify_packs().unwrap().is_empty());

    // 2. A damaged index: the pack is reported broken, misses become
    //    Corrupt instead of Missing, and gc refuses to run.
    fs.write(&pack_path, &good_pack).unwrap();
    let mut bad_idx = good_idx.clone();
    bad_idx[100] ^= 1;
    fs.write(&idx_path, &bad_idx).unwrap();
    let store = repo.store().clone();
    store.invalidate().unwrap();
    assert_eq!(store.broken_packs().unwrap().len(), 1);
    assert!(matches!(store.get_raw(&ids[0]), Err(VeilError::Corrupt(..))));
    assert!(matches!(gc(&mut repo, &now_gc()), Err(VeilError::Corrupt(..))));

    // 3. A truncated pack.
    fs.write(&idx_path, &good_idx).unwrap();
    fs.write(&pack_path, &good_pack[..good_pack.len() - 10]).unwrap();
    store.invalidate().unwrap();
    assert_eq!(store.broken_packs().unwrap().len(), 1);

    // Restored, everything is fine again.
    fs.write(&pack_path, &good_pack).unwrap();
    store.invalidate().unwrap();
    assert!(store.verify_packs().unwrap().is_empty());
    assert_history_intact(&repo);
}

// ---- gc ------------------------------------------------------------------

#[test]
fn gc_deletes_only_what_no_retained_view_reaches() {
    let (mut repo, fs, _) = new_repo();
    fs.write(&p("keep.txt"), b"keep\n").unwrap();
    snap(&mut repo, &fs);
    fs.write(&p("junk.bin"), b"temporary junk\n").unwrap();
    snap(&mut repo, &fs);
    let junk = Object::blob_id(b"temporary junk\n");
    fs.remove_file(&p("junk.bin")).unwrap();
    snap(&mut repo, &fs);
    repo.commit_working_copy(WS, "keep").unwrap();
    // An object nobody references at all.
    let stray = repo.store().put(&Object::Blob(b"stray".to_vec())).unwrap();

    // With the whole op log retained, the junk is still reachable.
    let r = gc(&mut repo, &now_gc()).unwrap();
    assert!(repo.store().has(&junk));
    assert!(!repo.store().has(&stray));
    assert_eq!(r.deleted, 1);

    // Prune the op log: junk was only in a rewritten working copy.
    let later = GcOptions {
        keep_ops: Some(Duration::from_secs(86_400)),
        now: Some(now_millis() + 2 * DAY),
        ..now_gc()
    };
    let r = gc(&mut repo, &later).unwrap();
    assert!(r.ops_pruned > 0);
    assert!(!repo.store().has(&junk), "junk collected once its ops were pruned");
    let wc = repo.workspace_wc(WS).unwrap();
    let parent = repo.snapshot(&wc).unwrap().parents[0];
    assert_eq!(read_file(&repo, &parent, "keep.txt").unwrap(), b"keep\n");
    assert_history_intact(&repo);
}

#[test]
fn gc_after_undo_keeps_the_undone_state() {
    let (mut repo, fs, _) = new_repo();
    fs.write(&p("a.txt"), b"v1\n").unwrap();
    snap(&mut repo, &fs);
    fs.write(&p("a.txt"), b"v2\n").unwrap();
    let v2 = snap(&mut repo, &fs);
    repo.undo().unwrap();
    assert_ne!(repo.workspace_wc(WS).unwrap(), v2);

    // Even with the most aggressive settings, the state undo stepped away
    // from stays (it is the view of the current op's parent), so the undo
    // can itself be undone.
    let aggressive = GcOptions {
        keep_ops: Some(Duration::ZERO),
        now: Some(now_millis() + 10 * DAY),
        ..now_gc()
    };
    gc(&mut repo, &aggressive).unwrap();
    assert_eq!(read_file(&repo, &v2, "a.txt").unwrap(), b"v2\n");
    assert_history_intact(&repo);
    repo.undo().unwrap();
    assert_eq!(repo.workspace_wc(WS).unwrap(), v2, "undo of the undo");
    assert_eq!(read_file(&repo, &v2, "a.txt").unwrap(), b"v2\n");

    // With the default (keep every op), all undo targets survive.
    for i in 0..5 {
        fs.write(&p("a.txt"), format!("v{}\n", i + 3).as_bytes()).unwrap();
        snap(&mut repo, &fs);
    }
    for _ in 0..4 {
        repo.undo().unwrap();
    }
    gc(&mut repo, &now_gc()).unwrap();
    assert_history_intact(&repo);
    let ops = repo.op_log(usize::MAX).unwrap();
    for (op, _) in &ops {
        repo.restore_operation(*op).unwrap();
        assert_history_intact(&repo);
    }
}

#[test]
fn gc_keeps_embargo_fallbacks_that_are_the_only_reference() {
    let (mut repo, _fs, _) = new_repo();
    let store = repo.store().clone();
    // Pre-merge content that is referenced by nothing but a fallback.
    let old = store
        .store_file(b"fn check() -> bool { true }\n", &Visibility::Public)
        .unwrap();
    let file = |id| TreeEntry {
        name: "auth.rs".into(),
        kind: EntryKind::File,
        id,
        size: 0,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
    };
    let mut base = Tree::default();
    base.insert(file(old));
    let base_tree = store.put_tree(&base).unwrap();
    let new = store
        .store_file(b"fn check() -> bool { verify() }\n", &Visibility::Public)
        .unwrap();
    let mut merged = Tree::default();
    merged.insert(file(new));
    let merged_tree = store.put_tree(&merged).unwrap();
    let embargo = repo.keys().create_embargo("team", None).unwrap();
    let sealed_tree = apply_embargo(&store, &merged_tree, &base_tree, &embargo).unwrap();

    let root = repo.root_id();
    let mut tx = repo.transaction("embargoed").unwrap();
    let s = tx
        .write_snapshot(&Snapshot {
            parents: vec![root],
            change_id: ChangeId::random(),
            tree: sealed_tree,
            description: Text::Plain("embargoed fix".into()),
            author: "alice".into(),
            timestamp: now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            cloak: None,
            embargo: Some(embargo.clone()),
            signature: None,
        })
        .unwrap();
    tx.view
        .tags
        .insert("main".into(), veil_core::oplog::Tag { target: s, cloak: None });
    tx.commit().unwrap();

    let r = gc(&mut repo, &now_gc()).unwrap();
    assert!(r.deleted >= 2, "the merged tree and plain new blob were garbage");
    assert!(!store.has(&merged_tree) && !store.has(&new));
    // The embargoed tree is sealed whole (BUG-018); its fallback is the
    // pre-merge tree, which therefore stays reachable along with its blob.
    assert!(store.has(&base_tree), "fallback tree kept");
    assert!(store.has(&old), "fallback-only blob kept");
    let e = lookup(&store, &sealed_tree, &p("auth.rs")).unwrap().unwrap();
    assert_eq!(e.fallback, Some(old));
    assert_eq!(store.read_entry(&e).unwrap(), b"fn check() -> bool { verify() }\n");

    // A public mirror only has the fallback; its gc keeps it too.
    let mirror_fs = Arc::new(MemoryBackend::new());
    remote::push(&mut repo, mirror_fs.clone(), true, &[], false).unwrap();
    let mut mirror = Repo::open(mirror_fs.clone(), Some(Identity::generate("pub")), "pub").unwrap();
    assert!(!mirror.store().has(&e.id), "embargoed content withheld");
    let r = gc(&mut mirror, &now_gc()).unwrap();
    assert!(r.incomplete.is_empty(), "{:?}", r.incomplete);
    let mirror = Repo::open(mirror_fs, Some(Identity::generate("pub")), "pub").unwrap();
    assert_eq!(mirror.store().read_entry(&e).unwrap(), b"fn check() -> bool { true }\n");
}

#[test]
fn gc_after_real_embargoed_merge_and_release() {
    let (mut repo, fs, _) = new_repo();
    fs.write(&p("auth.rs"), b"fn check() -> bool { true }\n").unwrap();
    snap(&mut repo, &fs);
    let (main, _) = repo.commit_working_copy(WS, "v1").unwrap();
    repo.set_tag("main", main, None, false).unwrap();
    let fix_ws = repo.ephemeral_workspace(main).unwrap();
    fix_ws.write("auth.rs", "fn check() -> bool { verify() }\n").unwrap();
    let (fix, _) = repo.commit_ephemeral(&fix_ws, "fix").unwrap();
    let res = repo
        .merge(
            WS,
            main,
            vec![fix],
            "merge",
            Some(EmbargoSpec {
                scope: "team".into(),
                until: None,
            }),
        )
        .unwrap();
    gc(
        &mut repo,
        &GcOptions {
            keep_ops: Some(Duration::ZERO),
            now: Some(now_millis() + DAY),
            ..now_gc()
        },
    )
    .unwrap();
    assert_history_intact(&repo);
    repo.release_embargo(res.embargo.as_deref().unwrap()).unwrap();
    gc(&mut repo, &now_gc()).unwrap();
    assert!(String::from_utf8(read_file(&repo, &res.snapshot, "auth.rs").unwrap())
        .unwrap()
        .contains("verify"));
    assert_history_intact(&repo);
}

#[test]
fn op_log_pruning_keeps_the_current_op_and_its_parents() {
    let (mut repo, fs, _) = new_repo();
    for i in 0..6 {
        fs.write(&p("f.txt"), format!("{i}\n").as_bytes()).unwrap();
        snap(&mut repo, &fs);
    }
    let total = repo.op_log(usize::MAX).unwrap().len();
    assert_eq!(total, 7);

    // Within the window nothing is pruned.
    let r = gc(
        &mut repo,
        &GcOptions {
            keep_ops: Some(Duration::from_secs(3600)),
            ..now_gc()
        },
    )
    .unwrap();
    assert_eq!(r.ops_pruned, 0);

    // Two days later with a one-day window: only the head and its parent stay.
    let head = repo.op_id();
    let r = gc(
        &mut repo,
        &GcOptions {
            keep_ops: Some(Duration::from_secs(86_400)),
            now: Some(now_millis() + 2 * DAY),
            ..now_gc()
        },
    )
    .unwrap();
    assert_eq!((r.ops_before, r.ops_pruned), (7, 5));
    let log = repo.op_log(usize::MAX).unwrap();
    assert_eq!(log.len(), 2, "the log ends where it was pruned");
    assert_eq!(log[0].0, head);
    assert_eq!(repo.ops().resolve_prefix(&head.hex()[..8]).unwrap(), head);
    assert!(repo.ops().resolve_prefix(&log[1].0.hex()[..10]).is_ok());

    // The repository keeps working: reopen, snapshot, undo.
    let mut repo = Repo::open(fs.clone(), None, "alice").unwrap();
    fs.write(&p("f.txt"), b"after\n").unwrap();
    snap(&mut repo, &fs);
    repo.undo().unwrap();
    assert_history_intact(&repo);
}

#[test]
fn grace_period_and_keep_markers() {
    let (mut repo, fs, id) = new_repo();
    let t0 = now_millis();
    let stray = repo.store().put(&Object::Blob(b"maybe needed".to_vec())).unwrap();
    let other_stray = repo.store().put(&Object::Blob(b"really unused".to_vec())).unwrap();
    let opts = |now| GcOptions {
        grace: Duration::from_secs(3600),
        now: Some(now),
        ..GcOptions::default()
    };

    // `has` would count as a use of the object (and rescue it), so look
    // without touching.
    let present = |repo: &Repo, id: &ObjectId| repo.store().list_objects().unwrap().contains(id);

    // First sighting: unreachable objects are only marked pending.
    let r = gc(&mut repo, &opts(t0)).unwrap();
    assert_eq!((r.deleted, r.pending), (0, 2));
    assert!(present(&repo, &stray));

    // Still inside the grace period.
    let r = gc(&mut repo, &opts(t0 + 30 * 60_000)).unwrap();
    assert_eq!((r.deleted, r.pending), (0, 2));

    // Another process starts using one of them (e.g. re-adds the content).
    let other = Repo::open(fs.clone(), Some(id), "alice").unwrap();
    other.store().put(&Object::Blob(b"maybe needed".to_vec())).unwrap();
    assert!(fs
        .exists(&p(&format!(".veil/objects/gc/keep/{}", stray.hex())))
        .unwrap());

    // After the grace period only the untouched one goes.
    let r = gc(&mut repo, &opts(t0 + 2 * 3_600_000)).unwrap();
    assert_eq!(r.deleted, 1);
    assert!(present(&repo, &stray), "kept: another process freshened it");
    assert!(!present(&repo, &other_stray));
    assert!(fs
        .list_dir(&p(".veil/objects/gc/keep"))
        .map(|d| d.is_empty())
        .unwrap_or(true));

    // The rescue restarts its grace period.
    let r = gc(&mut repo, &opts(t0 + 3 * 3_600_000)).unwrap();
    assert_eq!((r.deleted, r.pending), (0, 1));
    let r = gc(&mut repo, &opts(t0 + 5 * 3_600_000)).unwrap();
    assert_eq!(r.deleted, 1);
    assert!(!present(&repo, &stray));
}

#[test]
fn gc_with_a_concurrent_writer() {
    let (repo, fs, id) = new_repo();
    drop(repo);
    let writer_fs = fs.clone();
    let writer_id = id.clone();
    let writer = std::thread::spawn(move || {
        let mut repo = Repo::open(writer_fs.clone(), Some(writer_id), "alice").unwrap();
        for i in 0..40 {
            writer_fs
                .write(&p(&format!("d{}/f{i}.txt", i % 5)), format!("content {i}\n").as_bytes())
                .unwrap();
            loop {
                match repo.snapshot_workspace(WS, &*writer_fs) {
                    Ok(_) => break,
                    Err(VeilError::Locked(_)) => continue,
                    Err(e) => panic!("{e}"),
                }
            }
            if i % 7 == 0 {
                repo.commit_working_copy(WS, &format!("c{i}")).unwrap();
            }
        }
        repo.op_id()
    });
    let mut gcr = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    for _ in 0..15 {
        // Default grace: objects of in-flight snapshots are never deleted,
        // while ops are pruned aggressively.
        gc(
            &mut gcr,
            &GcOptions {
                keep_ops: Some(Duration::ZERO),
                ..GcOptions::default()
            },
        )
        .unwrap();
    }
    writer.join().unwrap();
    let mut repo = Repo::open(fs.clone(), Some(id), "alice").unwrap();
    gc(&mut repo, &GcOptions::default()).unwrap();
    assert_history_intact(&repo);
    let wc = repo.workspace_wc(WS).unwrap();
    for i in 0..40 {
        assert_eq!(
            read_file(&repo, &wc, &format!("d{}/f{i}.txt", i % 5)).unwrap(),
            format!("content {i}\n").as_bytes()
        );
    }
}

// ---- caches ----------------------------------------------------------------

#[test]
fn tree_and_snapshot_caches_are_bounded() {
    let (mut repo, fs, _) = new_repo();
    history(&mut repo, &fs, 30, 12);
    let store = repo.store().clone();
    store.set_cache_limits(CacheLimits {
        tree_entries: 50,
        snapshots: 5,
        delta_base_bytes: 4096,
    });
    gc(&mut repo, &now_gc()).unwrap();
    for (_, op) in repo.op_log(usize::MAX).unwrap() {
        for s in op.view.refs() {
            for id in repo.ancestors(&s).unwrap() {
                let t = repo.snapshot(&id).unwrap().tree;
                lookup(&store, &t, &p("src/m3/f7.txt")).unwrap();
            }
        }
    }
    let stats = store.stats().unwrap();
    assert!(stats.trees.weight <= 50 && stats.trees.entries > 0, "{:?}", stats.trees);
    assert!(stats.snapshots.entries <= 5);
    assert!(stats.delta_bases.weight <= 4096);
    assert_history_intact(&repo);
}
