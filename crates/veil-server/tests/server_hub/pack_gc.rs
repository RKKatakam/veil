//! Milestone S29: merging packs, and pack garbage collection
//! (`docs/HUB.md` §13.37; `docs/design/server/storage-and-cost.md` §8).
//!
//! Guarantees tested here:
//! 1. **Merging never loses or changes an object.** Every object reachable
//!    before a merge reads back byte-identical after it, through `get`,
//!    `get_many`, range (`get_range`) and staged reads (`get_staged`). Readers
//!    racing a merge never see one missing, across two servers (`TestHub::beside`)
//!    and a crash mid-merge (resumed or rolled back).
//! 2. **GC deletes only what nothing references:** no branch, tag, PR, embargo
//!    line (S22), landing queue entry (S17, S18), attempt (S11), CI result
//!    (S19), projection memo, or pending upload (S28 staging) refers to it. It
//!    never deletes inside the retention window, and never an object a racing
//!    push is about to reference. Also cleans up unreferenced search segments
//!    (S15).
//! 3. **Embargoed objects:** GC never deletes a hidden embargo line's objects
//!    before release.
//! 4. **Bounded:** merge and GC work per run, memory and storage requests are
//!    bounded, and they yield to landings and pushes (S24's limits,
//!    `limits::DERIVE_PAUSE`).
//! 5. **Cost:** storage objects and bytes before and after merging a history of
//!    10,000 small pushes, and the storage requests a merge makes.

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use serde_json::{json, Value};
use veil_core::{
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEntry, Visibility},
    tag_object::Atag,
    ChangeId, ObjectId,
};
use veil_server::{
    pack::{self, LISTED},
    pack_gc::{self, CrashPoint, Options},
};

use crate::support::*;

fn project_id(hub: &TestHub, name: &str) -> i64 {
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&hub.hub().db))
        .unwrap()
}

/// `(staged, listed, discarded)` pack rows of the project.
fn pack_counts(hub: &TestHub, project: i64) -> (i64, i64, i64) {
    hub.rt
        .block_on(
            sqlx::query_as::<_, (i64, i64, i64)>(
                "SELECT count(*) FILTER (WHERE state = 0), count(*) FILTER (WHERE state = 1), count(*) FILTER (WHERE state = 2) FROM packs WHERE project_id = $1",
            )
            .bind(project)
            .fetch_one(&hub.hub().db),
        )
        .unwrap()
}

/// All storage keys in `p/<project>/` and their total byte size.
fn storage_objects_and_bytes(hub: &TestHub, project: i64) -> (Vec<String>, u64) {
    let store = hub.hub().objects.blob_store().clone();
    let prefix = format!("p/{project}/");
    hub.rt.block_on(async move {
        let mut keys = store.list(&prefix).await.unwrap();
        keys.sort();
        let mut total = 0u64;
        let mut set = tokio::task::JoinSet::new();
        for k in &keys {
            let store = store.clone();
            let k = k.clone();
            set.spawn(async move { store.len(&k).await.unwrap().unwrap_or(0) });
            if set.len() >= 64 {
                total += set.join_next().await.unwrap().unwrap();
            }
        }
        while let Some(r) = set.join_next().await {
            total += r.unwrap();
        }
        (keys, total)
    })
}

fn make_blob(text: &str) -> (ObjectId, Bytes) {
    let raw = Bytes::from(Object::Blob(text.as_bytes().to_vec()).encode());
    (ObjectId::hash(&raw), raw)
}

/// Collect every object `(id, raw_bytes)` currently in any listed pack or loose
/// in `project`.
fn collect_all_stored_objects(hub: &TestHub, project: i64) -> Vec<(ObjectId, Bytes)> {
    let h = hub.hub();
    let store = h.objects.blob_store().clone();
    let bound = h.objects.index_bound();
    let listed: Vec<String> = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND state = $2 ORDER BY created_at, name")
                .bind(project)
                .bind(LISTED)
                .fetch_all(&h.db),
        )
        .unwrap();
    let mut ids = HashSet::new();
    for name in listed {
        let k = pack::key(project, &name);
        if let Some(held) = hub.rt.block_on(pack::read_index(&*store, &k, bound)).unwrap() {
            for (id, _) in held.index.iter() {
                ids.insert(*id);
            }
        }
    }
    let prefix = format!("p/{project}/");
    for k in hub.rt.block_on(store.list(&prefix)).unwrap() {
        if let Some(rest) = k.strip_prefix(&prefix) {
            if !rest.starts_with("pack/") {
                let parts: Vec<&str> = rest.split('/').collect();
                if parts.len() == 2 && parts[0].len() == 2 && parts[1].len() == 62 {
                    if let Ok(id) = ObjectId::from_hex(&format!("{}{}", parts[0], parts[1])) {
                        ids.insert(id);
                    }
                }
            }
        }
    }
    let mut sorted: Vec<ObjectId> = ids.into_iter().collect();
    sorted.sort();
    sorted
        .into_iter()
        .map(|id| {
            let raw = hub
                .rt
                .block_on(h.objects.get(project, &id))
                .unwrap()
                .unwrap_or_else(|| panic!("expected stored object {id} to be readable"));
            (id, raw)
        })
        .collect()
}

/// Format a millisecond epoch timestamp as an ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
fn iso_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Guarantee 1: Merging never loses or changes an object.
/// Every object reachable before a merge reads back byte-identical after it,
/// through `get`, `get_many`, range (`get_range`) and staged reads
/// (`get_staged`). Readers racing a merge never see one missing, across two
/// servers (`TestHub::beside`) and a crash mid-merge (resumed or rolled back).
#[test]
fn guarantee_1_merging_never_loses_or_changes_an_object_across_servers_and_crashes() {
    let hub = TestHub::start();
    let other = TestHub::beside(&hub);
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);

    // Push 12 small changes across admin and dev so the project has > 12 small
    // listed packs with both plain and zstd-compressed blobs, trees, snapshots,
    // origins, and projections.
    for i in 0..8 {
        let plain = format!("PLAIN-MERGE-G1-{i}-{}", "x".repeat(48));
        let compressible = format!("COMPRESS-MERGE-G1-{i}-{}", "abcd1234".repeat(400));
        write_files(
            &p.dir,
            &[
                (&format!("src/plain_{i}.rs"), &plain),
                (&format!("src/comp_{i}.rs"), &compressible),
            ],
        );
        p.admin.commit_main(&p.dir, &format!("admin push {i}"));
        p.admin.ok(&p.dir, &["push"]);
    }
    let dev_dir = p.dev.dir("dev-g1");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), dev_dir.to_str().unwrap()]);
    for i in 0..4 {
        let body = format!("DEV-MERGE-G1-{i}-{}", "z".repeat(120));
        write_files(&dev_dir, &[(&format!("src/dev_{i}.rs"), &body)]);
        p.dev.commit_main(&dev_dir, &format!("dev push {i}"));
        p.dev.ok(&dev_dir, &["push"]);
    }

    // Also stage an active upload pack (`STAGED`) to verify staged reads
    // (`get_staged`) are untouched by pack merging.
    let (staged_id, staged_raw) = make_blob("STAGED-UPLOAD-WHILE-MERGING-991a");
    let staged_enc = veil_server::store::encode(staged_raw.clone());
    let staged_pack = hub
        .rt
        .block_on(hub.hub().objects.stage(pid, 1, vec![(staged_id, staged_enc.clone())]))
        .unwrap();
    let staged_slot = hub
        .rt
        .block_on(hub.hub().objects.staged_slots(pid, &staged_pack, &[staged_id]))
        .unwrap()
        .unwrap()
        .slots[0]
        .1;

    // Record every reachable object and its exact bytes before any merge.
    let before_objects = collect_all_stored_objects(&hub, pid);
    assert!(before_objects.len() >= 30, "expected >= 30 objects, got {}", before_objects.len());
    let (_, listed_before, _) = pack_counts(&hub, pid);
    assert!(listed_before >= 12, "expected >= 12 listed packs before merge, got {listed_before}");

    // Warm `other` server's pack lookup map so it holds the old pack names!
    for (id, expected) in &before_objects {
        let got = other.rt.block_on(other.hub().objects.get(pid, id)).unwrap().unwrap();
        assert_eq!(&got, expected);
    }

    // --- Crash 1: Crash after writing the new STAGED merged pack, before the
    // switch transaction commits. ---
    let crash1_opts = Options {
        min_packs_to_merge: 2,
        run_gc: false,
        pack_grace_ms: 0,
        crash: Some(CrashPoint::AfterWriteBeforeSwitch),
        ..Options::default()
    };
    let r_crash1 = hub.rt.block_on(pack_gc::run_project(&hub.hub(), pid, &crash1_opts)).unwrap();
    assert_eq!(r_crash1.packs_merged, 0, "switch did not commit on CrashPoint::AfterWriteBeforeSwitch");
    // Old packs are still listed; all objects read identically on both servers.
    let (staged_c1, listed_c1, _) = pack_counts(&hub, pid);
    assert_eq!(listed_c1, listed_before, "old packs remain listed after pre-switch crash");
    assert!(staged_c1 >= 2, "uncommitted job pack + active upload pack are staged");
    for (id, expected) in &before_objects {
        assert_eq!(&other.rt.block_on(other.hub().objects.get(pid, id)).unwrap().unwrap(), expected);
    }

    // --- Crash 2: Crash right after the switch transaction commits (new pack is
    // LISTED, old packs are DISCARDED in DB, before `forget_packs` or storage
    // delete runs). ---
    let crash2_opts = Options {
        min_packs_to_merge: 2,
        max_packs_per_run: 6,
        run_gc: false,
        pack_grace_ms: 0,
        crash: Some(CrashPoint::AfterSwitchBeforeDelete),
        ..Options::default()
    };
    let r_crash2 = hub.rt.block_on(pack_gc::run_project(&hub.hub(), pid, &crash2_opts)).unwrap();
    assert_eq!(r_crash2.staged_packs_swept, 1, "resumed run swept the uncommitted job pack from Crash 1");
    assert_eq!(r_crash2.packs_merged, 6, "merged first 6 packs before post-switch crash");
    assert_eq!(r_crash2.discarded_packs_swept, 0, "stopped before sweeping discarded packs");

    // Verify every object is still byte-identical on both servers mid-crash.
    for (id, expected) in &before_objects {
        assert_eq!(&hub.rt.block_on(hub.hub().objects.get(pid, id)).unwrap().unwrap(), expected);
        assert_eq!(&other.rt.block_on(other.hub().objects.get(pid, id)).unwrap().unwrap(), expected);
    }

    // --- Concurrent readers across two servers racing the remaining merge and
    // immediate storage deletion of replaced packs (`pack_grace_ms: 0`)! ---
    let stop = Arc::new(AtomicBool::new(false));
    let reads_done = Arc::new(AtomicUsize::new(0));
    let mut reader_threads = Vec::new();
    for s_idx in 0..4usize {
        let stop = stop.clone();
        let reads_done = reads_done.clone();
        let expected_objs = before_objects.clone();
        let h = if s_idx % 2 == 0 { hub.hub() } else { other.hub() };
        let rt_handle = if s_idx % 2 == 0 {
            hub.rt.handle().clone()
        } else {
            other.rt.handle().clone()
        };
        reader_threads.push(std::thread::spawn(move || {
            let mut round = s_idx;
            while !stop.load(Relaxed) {
                round = round.wrapping_add(1);
                // Build a fresh uncached `Objects` view on the same store & DB
                // every other iteration so readers exercise actual storage
                // reads and pack refreshes (not only the in-memory LRU cache).
                let uncached = veil_server::store::Objects::with_db(
                    h.objects.blob_store().clone(),
                    1 << 10,
                    Some(h.db.clone()),
                );
                let target_objs = if round % 2 == 0 { &*h.objects } else { &uncached };
                let (id, raw) = &expected_objs[round % expected_objs.len()];
                let got = rt_handle
                    .block_on(target_objs.get(pid, id))
                    .expect("racing get must not error")
                    .expect("racing get must never see a missing object");
                assert_eq!(&got, raw, "racing get byte mismatch for {id}");
                let (slice, total_len) = rt_handle
                    .block_on(target_objs.get_range(pid, id, 3, 19))
                    .expect("racing get_range must not error")
                    .expect("racing get_range must never see a missing object");
                assert_eq!(total_len, raw.len() as u64);
                let expected_end = 19.min(raw.len().saturating_sub(1));
                if 3 < raw.len() {
                    assert_eq!(&slice[..], &raw[3..=expected_end]);
                }
                reads_done.fetch_add(1, Relaxed);
            }
        }));
    }

    // Wait until reader threads are actively reading, then finish the merge and
    // sweep all discarded packs with `pack_grace_ms: 0`.
    while reads_done.load(Relaxed) < 16 {
        std::thread::sleep(Duration::from_millis(5));
    }
    let finish_opts = Options {
        min_packs_to_merge: 2,
        run_gc: false,
        pack_grace_ms: 0,
        ..Options::default()
    };
    let r_finish = hub.rt.block_on(pack_gc::run_project(&hub.hub(), pid, &finish_opts)).unwrap();
    assert!(r_finish.packs_merged >= 2);
    assert!(r_finish.discarded_packs_swept >= 6);

    // Let readers keep reading after old packs have been deleted from storage!
    let mark = reads_done.load(Relaxed);
    while reads_done.load(Relaxed) < mark + 32 {
        std::thread::sleep(Duration::from_millis(5));
    }
    stop.store(true, Relaxed);
    for t in reader_threads {
        t.join().expect("reader thread panicked during merge");
    }

    let (_, listed_after, discarded_after) = pack_counts(&hub, pid);
    assert_eq!(listed_after, 1, "all small packs compacted into 1 listed pack");
    assert_eq!(discarded_after, 0, "all discarded packs swept after grace");

    // Verify every object reads back byte-identical through `get`, `get_many`,
    // `get_range` (on both cached and fresh uncached `Objects` across both
    // servers), and `get_staged` for the staged upload.
    for target_hub in [&hub, &other] {
        let fresh = veil_server::store::Objects::with_db(
            target_hub.hub().objects.blob_store().clone(),
            64 << 10,
            Some(target_hub.hub().db.clone()),
        );
        let all_ids: Vec<ObjectId> = before_objects.iter().map(|(id, _)| *id).collect();
        let batch_got = target_hub.rt.block_on(fresh.get_many(pid, &all_ids)).unwrap();
        assert_eq!(batch_got.len(), before_objects.len());
        for ((id, expected), got_opt) in before_objects.iter().zip(batch_got) {
            let got = got_opt.unwrap_or_else(|| panic!("missing {id} in get_many"));
            assert_eq!(&got, expected, "get_many mismatch for {id}");

            let single = target_hub.rt.block_on(fresh.get(pid, id)).unwrap().unwrap();
            assert_eq!(&single, expected, "get mismatch for {id}");

            let mid = expected.len() / 2;
            let (rng, len) = target_hub
                .rt
                .block_on(fresh.get_range(pid, id, mid as u64, u64::MAX))
                .unwrap()
                .unwrap();
            assert_eq!(len, expected.len() as u64);
            assert_eq!(&rng[..], &expected[mid..], "get_range mismatch for {id}");
        }

        // Verify the staged upload is still intact and readable through `get_staged`.
        let (st_enc, st_raw) = target_hub
            .rt
            .block_on(target_hub.hub().objects.get_staged(pid, &staged_pack, staged_slot, &staged_id))
            .unwrap()
            .expect("staged upload must remain readable");
        assert_eq!(st_enc, staged_enc);
        assert_eq!(st_raw, staged_raw);
    }
}

/// Guarantee 2:
/// - GC deletes only what nothing references: no branch, tag, PR, embargo line
///   (S22), landing queue entry (S17, S18), attempt (S11), CI result (S19),
///   projection memo, or pending upload (S28 staging) refers to it.
/// - It never deletes inside the retention window, and never an object a racing
///   push is about to reference.
/// - It cleans up unreferenced search segments (S15) and unreferenced objects
///   once the retention window passes.
#[test]
fn guarantee_2_gc_deletes_only_unreferenced_objects_respects_retention_window_and_racing_push() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);

    // 1. Branch reference (`main`), origin (`origins`), and projection memos (`projections` for dev/fin).
    write_files(&p.dir, &[("src/branch_kept.rs", "BRANCH-KEPT-OBJECT-1001")]);
    p.admin.commit_main(&p.dir, "branch kept");
    p.admin.ok(&p.dir, &["push"]);
    let (branch_blob_id, branch_blob_raw) = make_blob("BRANCH-KEPT-OBJECT-1001");

    let api = hub.api();
    let mut c_dev = Craft::new(&api, &p.dev, &p.name, "main");
    c_dev.file("src/dev_origin.rs", "DEV-ORIGIN-OBJECT-1002");
    let (_, r_dev) = c_dev.push_edited("dev-line", None, |_| {});
    assert_eq!(r_dev.status, 200);

    // Derive and index search for `main`, producing initial S15 search segments,
    // and memoising projections for `dev` and `fin`.
    hub.rt.block_on(veil_server::derive::catch_up_project(&hub.hub(), pid)).unwrap();
    hub.rt.block_on(veil_server::search::index::catch_up_project(&hub.hub(), pid)).unwrap();

    // Find a projected snapshot ID from `projections` and an origin snapshot + tree from `origins`.
    let proj_hex: String = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT projected_id FROM projections WHERE project_id = $1 AND projected_id != real_id LIMIT 1")
                .bind(pid)
                .fetch_one(&hub.hub().db),
        )
        .unwrap();
    let proj_snap_id = ObjectId::from_hex(&proj_hex).unwrap();
    let proj_snap_raw = hub.rt.block_on(hub.hub().objects.get(pid, &proj_snap_id)).unwrap().unwrap();

    let orig_hex: String = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT origin_id FROM origins WHERE project_id = $1 LIMIT 1")
                .bind(pid)
                .fetch_one(&hub.hub().db),
        )
        .unwrap();
    let orig_snap_id = ObjectId::from_hex(&orig_hex).unwrap();
    let orig_snap_raw = hub.rt.block_on(hub.hub().objects.get(pid, &orig_snap_id)).unwrap().unwrap();
    let Object::Snapshot(orig_snap) = Object::decode(&orig_snap_raw).unwrap() else { panic!() };
    let orig_tree_id = orig_snap.tree;
    assert!(
        hub.rt.block_on(hub.hub().objects.exists(pid, &orig_tree_id)).unwrap(),
        "origin projected tree is stored before GC"
    );

    // 2. S15 search segment compaction: push 6 more commits and compact the
    // search index so old search segment objects become superseded (unreferenced)!
    let segs_before: Vec<String> = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT segments FROM search_shards WHERE project_id = $1").bind(pid).fetch_all(&hub.hub().db))
        .unwrap();
    let mut initial_seg_ids = Vec::new();
    for s_json in segs_before {
        let arr: Vec<Value> = serde_json::from_str(&s_json).unwrap();
        for item in arr {
            if let Some(hex) = item["id"].as_str() {
                initial_seg_ids.push(ObjectId::from_hex(hex).unwrap());
            }
        }
    }
    assert!(!initial_seg_ids.is_empty(), "expected initial S15 search segments");

    for k in 0..5 {
        write_files(&p.dir, &[(&format!("src/search_extra_{k}.rs"), &format!("SEARCH_TERM_EXTRA_{k}"))]);
        p.admin.commit_main(&p.dir, &format!("search extra {k}"));
        p.admin.ok(&p.dir, &["push"]);
        hub.rt.block_on(veil_server::derive::catch_up_project(&hub.hub(), pid)).unwrap();
        hub.rt.block_on(veil_server::search::index::catch_up_project(&hub.hub(), pid)).unwrap();
    }
    // Force a full rebuild of the search index so the old segment IDs are replaced.
    hub.rt
        .block_on(sqlx::query("DELETE FROM search_heads WHERE project_id = $1").bind(pid).execute(&hub.hub().db))
        .unwrap();
    hub.rt
        .block_on(sqlx::query("DELETE FROM search_shards WHERE project_id = $1").bind(pid).execute(&hub.hub().db))
        .unwrap();
    hub.rt.block_on(veil_server::search::index::catch_up_project(&hub.hub(), pid)).unwrap();

    let segs_after: Vec<String> = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT segments FROM search_shards WHERE project_id = $1").bind(pid).fetch_all(&hub.hub().db))
        .unwrap();
    let mut live_seg_ids = HashSet::new();
    for s_json in segs_after {
        let arr: Vec<Value> = serde_json::from_str(&s_json).unwrap();
        for item in arr {
            if let Some(hex) = item["id"].as_str() {
                live_seg_ids.insert(ObjectId::from_hex(hex).unwrap());
            }
        }
    }
    let dead_seg_id = *initial_seg_ids
        .iter()
        .find(|id| !live_seg_ids.contains(id))
        .expect("superseded S15 search segment");
    let live_seg_id = *live_seg_ids.iter().next().expect("live S15 search segment");
    assert!(hub.rt.block_on(hub.hub().objects.exists(pid, &dead_seg_id)).unwrap(), "superseded segment is still in store before GC");

    // 3. S11 recorded attempt (`Snapshot.attempts`) on a live commit.
    let api = hub.api();
    let (attempt_blob_id, attempt_blob_raw) = make_blob("ATTEMPT-DEAD-END-BLOB-S11-2002");
    let mut attempt_tree = Tree::default();
    attempt_tree.insert(TreeEntry {
        name: "attempt.txt".into(),
        kind: EntryKind::File,
        id: attempt_blob_id,
        size: "ATTEMPT-DEAD-END-BLOB-S11-2002".len() as u64,
        executable: false,
        visibility: Visibility::Public,
    });
    let attempt_tree_raw = Bytes::from(Object::Tree(attempt_tree).encode());
    let attempt_tree_id = ObjectId::hash(&attempt_tree_raw);
    let main_tip = api.tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"];
    let attempt_change_id = ChangeId::random();
    let mut attempt_snap = Snapshot {
        parents: vec![main_tip],
        change_id: attempt_change_id,
        tree: attempt_tree_id,
        description: Text::Plain("dead-end attempt".into()),
        author: p.admin.name.clone(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        agent: None,
        abandoned: Some("tried and failed".into()),
        attempts: vec![],
        signature: None,
    };
    attempt_snap.sign(&p.admin.identity());
    let attempt_snap_raw = Bytes::from(Object::Snapshot(attempt_snap).encode());
    let attempt_snap_id = ObjectId::hash(&attempt_snap_raw);

    let mut c_att = Craft::new(&api, &p.admin, &p.name, "main");
    c_att.objects.push((attempt_blob_id, attempt_blob_raw.to_vec()));
    c_att.objects.push((attempt_tree_id, attempt_tree_raw.to_vec()));
    c_att.objects.push((attempt_snap_id, attempt_snap_raw.to_vec()));
    c_att.file("src/with_attempt.rs", "MAIN-COMMIT-WITH-ATTEMPT-2002");
    let (_, r_att) = c_att.push_edited("main", Some(main_tip), |s| {
        s.change_id = attempt_change_id;
        s.attempts = vec![attempt_snap_id];
    });
    assert_eq!(r_att.status, 200, "{}", String::from_utf8_lossy(&r_att.body));

    // 4. Hidden embargo line (S22, Guarantee 3): push an embargoed change onto
    // `embargo/<id>` with a deadline 1 hour in the future.
    let sec_dir = p.sec.dir("embargo-gc");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    const EMBARGO_BLOB_TEXT: &str = "EMBARGO-PROTECTED-FROM-GC-3003";
    write_files(&sec_dir, &[("src/embargo_gc.rs", EMBARGO_BLOB_TEXT)]);
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "embargoed fix"]);
    let until = iso_utc(veil_core::now_millis() + 3_600_000);
    p.sec.ok(
        &sec_dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", "embargoed merge"],
    );
    p.sec.ok(&sec_dir, &["push"]);
    let (embargo_blob_id, embargo_blob_raw) = make_blob(EMBARGO_BLOB_TEXT);
    assert!(hub.rt.block_on(hub.hub().objects.exists(pid, &embargo_blob_id)).unwrap(), "embargoed blob is stored");

    // 5. Annotated Tag (`Atag`), PR revision (`pr_revisions`), Landing queue
    // entry (`landing_queue`), CI check (`checks`), and Pending Upload (`STAGED`).
    let (tag_blob_id, tag_blob_raw) = make_blob("TAGGED-OBJECT-4004");
    let mut atag = Atag::annotated("v1.0-gc", tag_blob_id, Text::Plain("tag v1.0".into()), &p.admin.name, veil_core::now_millis());
    atag.sign(&p.admin.identity());
    let atag_raw = Bytes::from(Object::Atag(atag).encode());
    let atag_id = ObjectId::hash(&atag_raw);

    let (pr_blob_id, pr_blob_raw) = make_blob("PR-REFERENCED-OBJECT-5005");
    let (queue_blob_id, queue_blob_raw) = make_blob("LANDING-QUEUE-OBJECT-6006");
    let (ci_blob_id, ci_blob_raw) = make_blob("CI-CHECK-OBJECT-7007");
    let (unreferenced_packed_id, unreferenced_packed_raw) = make_blob("UNREFERENCED-PACKED-OBJECT-8008");
    let (unreferenced_loose_id, unreferenced_loose_raw) = make_blob("UNREFERENCED-LOOSE-OBJECT-9009");

    // Store these in a listed pack and loose in the project's store.
    let h = hub.hub();
    hub.rt
        .block_on(async {
            let (pack_name, held) = h
                .objects
                .put_pack(
                    pid,
                    1,
                    vec![
                        (tag_blob_id, veil_server::store::encode(tag_blob_raw.clone())),
                        (atag_id, veil_server::store::encode(atag_raw.clone())),
                        (pr_blob_id, veil_server::store::encode(pr_blob_raw.clone())),
                        (queue_blob_id, veil_server::store::encode(queue_blob_raw.clone())),
                        (ci_blob_id, veil_server::store::encode(ci_blob_raw.clone())),
                        (unreferenced_packed_id, veil_server::store::encode(unreferenced_packed_raw.clone())),
                    ],
                )
                .await
                .unwrap();
            sqlx::query("UPDATE packs SET state = $3 WHERE project_id = $1 AND name = $2")
                .bind(pid)
                .bind(&*pack_name)
                .bind(LISTED)
                .execute(&h.db)
                .await
                .unwrap();
            h.objects.listed_here(pid, vec![(pack_name, held.index.clone())]);
            h.objects.put(pid, &unreferenced_loose_id, unreferenced_loose_raw.clone()).await.unwrap();

            // Record references in `tags`, `pr_revisions`, `landing_queue`, and `checks`:
            sqlx::query("CREATE TABLE IF NOT EXISTS tags (project_id BIGINT NOT NULL, name TEXT NOT NULL, target TEXT NOT NULL, PRIMARY KEY (project_id, name))")
                .execute(&h.db)
                .await
                .unwrap();
            sqlx::query("INSERT INTO tags (project_id, name, target) VALUES ($1, 'v1.0-gc', $2)")
                .bind(pid)
                .bind(atag_id.hex())
                .execute(&h.db)
                .await
                .unwrap();

            // S21's table (migration 17): a PR revision's head is a root.
            sqlx::query(
                "INSERT INTO pr_revisions (project_id, pr, n, base, head, changes, patch, files, risk, reasons, rules_key, files_count, pushed_by, at) \
                 VALUES ($1, 'pr-gc-test', 1, $2, $2, '[]', '', '[]', 'normal', '[]', '', 0, 1, 0)",
            )
            .bind(pid)
            .bind(pr_blob_id.hex())
            .execute(&h.db)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, stack, lineage, person_epoch, project_epoch, state, created_at) \
                 VALUES ($1, 'main', $2, 1, $3, 'k', $4, 0, 0, 0, 'queued', $5)",
            )
            .bind(pid)
            .bind(format!("t-gc-{pid}-1"))
            .bind(&p.admin.name)
            .bind(json!([[queue_blob_id.hex(), main_tip.hex()]]).to_string())
            .bind(veil_core::now_millis())
            .execute(&h.db)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO checks (project_id, snapshot, name, state, summary, runner_id, runner_name, updated_at) \
                 VALUES ($1, $2, 'build', 'pass', 'ok', 1, $3, $4)",
            )
            .bind(pid)
            .bind(ci_blob_id.hex())
            .bind(&p.admin.name)
            .bind(veil_core::now_millis())
            .execute(&h.db)
            .await
            .unwrap();
        });

    // Pending staged upload (S28):
    let (staged_blob_id, staged_blob_raw) = make_blob("PENDING-STAGED-UPLOAD-OBJECT-1111");
    let staged_pack = hub
        .rt
        .block_on(h.objects.stage(pid, 1, vec![(staged_blob_id, veil_server::store::encode(staged_blob_raw.clone()))]))
        .unwrap();

    // --- Run 1: GC inside the retention window (`retention_window_ms = 60_000`, `now_offset_ms = 0`). ---
    // Nothing unreferenced may be deleted yet!
    let opts_in_window = Options {
        min_packs_to_merge: 2,
        run_gc: true,
        retention_window_ms: 60_000,
        pack_grace_ms: 0,
        now_offset_ms: 0,
        ..Options::default()
    };
    let r1 = hub.rt.block_on(pack_gc::run_project(&h, pid, &opts_in_window)).unwrap();
    assert_eq!(r1.packed_objects_deleted, 0, "GC must never delete inside the retention window");
    assert_eq!(r1.loose_objects_deleted, 0, "GC must never delete loose objects inside the retention window");
    for id in [unreferenced_packed_id, unreferenced_loose_id, dead_seg_id] {
        assert!(
            hub.rt.block_on(h.objects.exists(pid, &id)).unwrap(),
            "unreferenced object {id} must be kept inside the retention window"
        );
    }

    // --- Run 2: Advance past the retention window (`now_offset_ms = 120_000`). ---
    // Unreferenced objects (`unreferenced_packed_id`, `unreferenced_loose_id`, `dead_seg_id`)
    // MUST be deleted, while EVERY referenced object (branch, tag, PR, embargo line,
    // landing queue, attempt, CI check, projection memo, live search segment,
    // and pending staged upload) MUST remain intact!
    let opts_after_window = Options {
        min_packs_to_merge: 2,
        run_gc: true,
        retention_window_ms: 60_000,
        pack_grace_ms: 0,
        now_offset_ms: 120_000,
        ..Options::default()
    };
    let r2 = hub.rt.block_on(pack_gc::run_project(&h, pid, &opts_after_window)).unwrap();
    assert!(r2.packed_objects_deleted >= 1, "expected unreferenced packed object to be deleted: {r2:?}");
    assert!(r2.loose_objects_deleted >= 2, "expected unreferenced loose object and dead search segment to be deleted: {r2:?}");

    // Verify unreferenced objects and superseded S15 search segment are gone from storage:
    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    for gone in [unreferenced_packed_id, unreferenced_loose_id, dead_seg_id] {
        assert!(
            !hub.rt.block_on(fresh.exists(pid, &gone)).unwrap(),
            "unreferenced object {gone} should have been deleted by GC"
        );
    }

    // Verify every referenced object is still present and byte-identical:
    for (name, id, expected_opt) in [
        ("branch blob", branch_blob_id, Some(branch_blob_raw)),
        ("projection memo snapshot", proj_snap_id, Some(proj_snap_raw)),
        ("origin projected snapshot", orig_snap_id, Some(orig_snap_raw)),
        ("origin projected tree", orig_tree_id, None),
        ("live S15 search segment", live_seg_id, None),
        ("S11 attempt snapshot", attempt_snap_id, Some(attempt_snap_raw)),
        ("S11 attempt tree", attempt_tree_id, Some(attempt_tree_raw)),
        ("S11 attempt blob", attempt_blob_id, Some(attempt_blob_raw)),
        ("S22 hidden embargo blob", embargo_blob_id, Some(embargo_blob_raw)),
        ("Atag object", atag_id, Some(atag_raw)),
        ("tag target blob", tag_blob_id, Some(tag_blob_raw)),
        ("PR revision head", pr_blob_id, Some(pr_blob_raw)),
        ("landing queue entry", queue_blob_id, Some(queue_blob_raw)),
        ("S19 CI check snapshot", ci_blob_id, Some(ci_blob_raw)),
    ] {
        assert!(
            hub.rt.block_on(fresh.exists(pid, &id)).unwrap(),
            "{name} ({id}) must NOT be deleted by GC"
        );
        if let Some(expected) = expected_opt {
            let got = hub.rt.block_on(fresh.get(pid, &id)).unwrap().unwrap();
            assert_eq!(got, expected, "{name} bytes changed after GC");
        }
    }

    // Verify pending staged upload is still usable and readable:
    assert!(
        hub.rt.block_on(h.objects.staged_index(pid, &staged_pack)).unwrap().is_some(),
        "pending staged upload must not be deleted inside staged_grace_ms"
    );

    // --- Racing push safety: an object a racing push is about to reference is
    // never deleted by GC! ---
    // Simulate a push that stages/lands while GC's mark phase saw an object as
    // unreferenced:
    let (racing_blob_id, racing_blob_raw) = make_blob("RACING-PUSH-BLOB-ABOUT-TO-REFERENCE-9999");
    hub.rt
        .block_on(h.objects.put(pid, &racing_blob_id, racing_blob_raw.clone()))
        .unwrap();
    // Mark `racing_blob_id` as unreferenced in `unreferenced_objects` with an expired timestamp:
    hub.rt
        .block_on(
            sqlx::query("INSERT INTO unreferenced_objects (project_id, object_id, since_ms) VALUES ($1, $2, 0)")
                .bind(pid)
                .bind(racing_blob_id.hex())
                .execute(&h.db),
        )
        .unwrap();
    // Before GC runs, the racing push stages `racing_blob_id` (or references it
    // on a branch):
    let mut c_race = Craft::new(&api, &p.admin, &p.name, "main");
    c_race.objects.push((racing_blob_id, racing_blob_raw.to_vec()));
    c_race.refer("src/raced.rs", racing_blob_id, racing_blob_raw.len() as u64 - 10);
    let up = api.upload(&p.admin.token(), &p.name, &c_race.objects);
    assert_eq!(up.status, 200);
    // Now `racing_blob_id` is in an active STAGED pack for the push that is about to land!
    // Run GC with expired retention window:
    let _ = hub.rt.block_on(pack_gc::run_project(&h, pid, &opts_after_window)).unwrap();
    assert!(
        hub.rt.block_on(fresh.exists(pid, &racing_blob_id)).unwrap(),
        "GC must never delete an object a racing push staged and is about to reference"
    );
}

/// Guarantee 3: Embargoed objects: GC never deletes a hidden embargo line's
/// objects before release, even across pack compaction and expired retention
/// windows, and the embargoed line releases cleanly onto `main` afterwards.
#[test]
fn guarantee_3_embargoed_objects_never_deleted_before_release() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);

    let sec_dir = p.sec.dir("embargo-g3");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    const SECRET_PATCH_A: &str = "EMBARGO-G3-SECRET-PATCH-A-9001";
    const SECRET_PATCH_B: &str = "EMBARGO-G3-SECRET-PATCH-B-9002";
    write_files(&sec_dir, &[("src/vuln_a.rs", SECRET_PATCH_A)]);
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "embargo fix part A"]);
    write_files(&sec_dir, &[("src/vuln_b.rs", SECRET_PATCH_B)]);
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "embargo fix part B"]);
    let until = iso_utc(veil_core::now_millis() + 3_600_000);
    p.sec.ok(
        &sec_dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", "embargoed fix"],
    );
    p.sec.ok(&sec_dir, &["push"]);

    let (blob_a_id, blob_a_raw) = make_blob(SECRET_PATCH_A);
    let (blob_b_id, blob_b_raw) = make_blob(SECRET_PATCH_B);

    // Also add an unreferenced packed object and loose object so GC actively
    // rewrites packs and deletes unreferenced objects across two GC passes:
    let (unref_id, unref_raw) = make_blob("UNREFERENCED-BESIDE-EMBARGO-9999");
    hub.rt.block_on(async {
        let (pname, held) = h
            .objects
            .put_pack(pid, 1, vec![(unref_id, veil_server::store::encode(unref_raw))])
            .await
            .unwrap();
        sqlx::query("UPDATE packs SET state = $3 WHERE project_id = $1 AND name = $2")
            .bind(pid)
            .bind(&*pname)
            .bind(LISTED)
            .execute(&h.db)
            .await
            .unwrap();
        h.objects.listed_here(pid, vec![(pname, held.index.clone())]);
    });

    // Pass 1: mark unreferenced objects at T0 and compact all small packs into 1 pack.
    let opts1 = Options {
        min_packs_to_merge: 2,
        run_gc: true,
        retention_window_ms: 60_000,
        pack_grace_ms: 0,
        now_offset_ms: 0,
        ..Options::default()
    };
    let r1 = hub.rt.block_on(pack_gc::run_project(&h, pid, &opts1)).unwrap();
    assert!(r1.packs_merged >= 2);
    assert_eq!(r1.packed_objects_deleted, 0);

    // Pass 2: advance past the retention window (`now_offset_ms = 180_000`) while
    // the embargo is still active (deadline is +3,600,000 ms).
    let opts2 = Options {
        min_packs_to_merge: 2,
        run_gc: true,
        retention_window_ms: 60_000,
        pack_grace_ms: 0,
        now_offset_ms: 180_000,
        ..Options::default()
    };
    let r2 = hub.rt.block_on(pack_gc::run_project(&h, pid, &opts2)).unwrap();
    assert!(r2.packed_objects_deleted >= 1, "unreferenced object deleted: {r2:?}");

    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    assert!(!hub.rt.block_on(fresh.exists(pid, &unref_id)).unwrap(), "unreferenced object removed");
    for (id, raw) in [(&blob_a_id, &blob_a_raw), (&blob_b_id, &blob_b_raw)] {
        let got = hub
            .rt
            .block_on(fresh.get(pid, id))
            .unwrap()
            .expect("embargoed object must never be deleted before release");
        assert_eq!(&got, raw);
    }

    // Verify all embargo snapshots and trees recorded in `embargo_snapshots`
    // and `branches WHERE hidden_for_embargo IS NOT NULL` are intact in storage:
    let emb_snaps: Vec<String> = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT snapshot FROM embargo_snapshots WHERE project_id = $1").bind(pid).fetch_all(&h.db))
        .unwrap();
    assert!(!emb_snaps.is_empty());
    for hex in emb_snaps {
        let sid = ObjectId::from_hex(&hex).unwrap();
        let raw = hub.rt.block_on(fresh.get(pid, &sid)).unwrap().expect("embargo snapshot intact");
        let Object::Snapshot(s) = Object::decode(&raw).unwrap() else { panic!() };
        assert!(hub.rt.block_on(fresh.exists(pid, &s.tree)).unwrap(), "embargo tree intact");
    }
}

/// Guarantee 4: Bounded: merge and GC work per run, memory and storage requests
/// are bounded, and they yield to landings and pushes (S24's limits,
/// `limits::DERIVE_PAUSE`).
#[test]
fn guarantee_4_merge_and_gc_are_bounded_and_yield_to_landings_and_pushes() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();

    // Create 20 small listed packs directly.
    for i in 0..20 {
        let (id, raw) = make_blob(&format!("BOUNDED-MERGE-OBJ-{i}-{}", "b".repeat(128)));
        let enc = veil_server::store::encode(raw);
        hub.rt.block_on(async {
            let (name, held) = h.objects.put_pack(pid, 1, vec![(id, enc)]).await.unwrap();
            sqlx::query("UPDATE packs SET state = $3 WHERE project_id = $1 AND name = $2")
                .bind(pid)
                .bind(&*name)
                .bind(LISTED)
                .execute(&h.db)
                .await
                .unwrap();
            h.objects.listed_here(pid, vec![(name, held.index.clone())]);
        });
    }

    let (_, listed_0, _) = pack_counts(&hub, pid);
    assert!(listed_0 >= 21);

    // 1. Bounded work per run: with `max_packs_per_run = 8`, one run merges
    // exactly 8 packs into 1 new pack, leaving the remaining packs for subsequent
    // runs, and makes bounded storage reads/writes.
    let reads_before = h.objects.reads.load(Relaxed);
    let writes_before = h.objects.writes.load(Relaxed);
    let index_avail_before = h.objects.index_bound().available();

    let bounded_opts = Options {
        min_packs_to_merge: 2,
        max_packs_per_run: 8,
        run_gc: false,
        pack_grace_ms: 0,
        ..Options::default()
    };
    let rep = hub.rt.block_on(pack_gc::run_project(&h, pid, &bounded_opts)).unwrap();
    assert_eq!(rep.packs_merged, 8, "work per run bounded by max_packs_per_run");
    assert_eq!(rep.packs_written, 1, "8 small packs merged into 1 pack");
    let reads_used = h.objects.reads.load(Relaxed) - reads_before;
    let writes_used = h.objects.writes.load(Relaxed) - writes_before;
    assert_eq!(writes_used, 1, "1 storage write for the merged pack");
    assert!(reads_used <= 16, "at most 2 reads (index + span) per merged pack, got {reads_used}");
    assert!(
        h.objects.index_bound().available() >= index_avail_before,
        "all temporary pack::INDEXES_HELD shares returned after run"
    );

    // 2. Yielding to pushes and landings (`limits::DERIVE_PAUSE`):
    // Saturate the server gate so `h.limits.overloaded()` is true (one waiting
    // request in `h.limits.server`), then start a pack_gc run and release the
    // overload after 250ms; verify `pack_gc` waited for the overload to clear!
    let (hold_places, waiter_task) = hub.rt.block_on(async {
        use veil_server::limits::gate::Class;
        let mut places = Vec::new();
        while let Some(p) = h
            .limits
            .server_place(Class::Read, tokio::time::Instant::now() + Duration::from_millis(10))
            .await
        {
            places.push(p);
        }
        // Spawn one waiter so `h.limits.overloaded()` (`server.load().1 > 0`) becomes true!
        let hub_clone = h.clone();
        let waiter = tokio::spawn(async move {
            let _p = hub_clone
                .limits
                .server_place(Class::Write, tokio::time::Instant::now() + Duration::from_secs(10))
                .await;
        });
        while !h.limits.overloaded() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        (places, waiter)
    });
    assert!(h.limits.overloaded(), "server gate is overloaded");

    let start = Instant::now();
    let releaser = {
        let h_rel = h.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            drop(hold_places);
            let _ = h_rel;
        })
    };
    let rep2 = hub.rt.block_on(pack_gc::run_project(&h, pid, &bounded_opts)).unwrap();
    let elapsed = start.elapsed();
    releaser.join().unwrap();
    hub.rt.block_on(waiter_task).unwrap();
    assert!(
        elapsed >= Duration::from_millis(200) && elapsed < veil_server::limits::DERIVE_PAUSE,
        "pack_gc must yield while server is overloaded and resume once load clears (elapsed: {elapsed:?})"
    );
    assert_eq!(rep2.packs_merged, 8);
}

/// Guarantee 5: Cost: storage objects and bytes before and after merging a
/// history of 10,000 small pushes, and the storage requests a merge makes.
#[test]
fn guarantee_5_cost_of_merging_10000_small_pushes() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();

    // Build a history of 10,000 small pushes (each push produces 1 small listed
    // pack holding its unique object, plus some shared objects across pushes).
    const PUSHES: usize = 10_000;
    let store = h.objects.blob_store().clone();
    let mut sample_objects: Vec<(ObjectId, Bytes)> = Vec::new();
    let mut pack_names: Vec<String> = Vec::with_capacity(PUSHES);
    let mut pack_sizes: Vec<i64> = Vec::with_capacity(PUSHES);
    let mut pack_counts_vec: Vec<i64> = Vec::with_capacity(PUSHES);
    let mut pack_times: Vec<i64> = Vec::with_capacity(PUSHES);

    let base_now = veil_core::now_millis();
    hub.rt.block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for i in 0..PUSHES {
            let (id, raw) = make_blob(&format!("SMALL-PUSH-{i:05}-payload"));
            let enc = veil_server::store::encode(raw.clone());
            if i % 500 == 0 || i + 1 == PUSHES {
                sample_objects.push((id, raw));
            }
            let (bytes, idx) = pack::build(vec![(id, enc)]).unwrap();
            let name = pack::new_name();
            let sz = bytes.len() as i64;
            let cnt = idx.len() as i64;
            pack_names.push(name.clone());
            pack_sizes.push(sz);
            pack_counts_vec.push(cnt);
            pack_times.push(base_now + i as i64);

            let store = store.clone();
            let k = pack::key(pid, &name);
            set.spawn(async move {
                store.put(&k, bytes).await.unwrap();
            });
            if set.len() >= 64 {
                set.join_next().await.unwrap().unwrap();
            }
        }
        while let Some(r) = set.join_next().await {
            r.unwrap();
        }
        for chunk_start in (0..PUSHES).step_by(1000) {
            let end = (chunk_start + 1000).min(PUSHES);
            sqlx::query(
                "INSERT INTO packs (project_id, name, state, size, objects, created_at) \
                 SELECT $1, n, $2, s, o, t FROM UNNEST($3::text[], $4::bigint[], $5::bigint[], $6::bigint[]) AS x(n, s, o, t)",
            )
            .bind(pid)
            .bind(LISTED)
            .bind(&pack_names[chunk_start..end])
            .bind(&pack_sizes[chunk_start..end])
            .bind(&pack_counts_vec[chunk_start..end])
            .bind(&pack_times[chunk_start..end])
            .execute(&h.db)
            .await
            .unwrap();
        }
    });

    let (keys_before, bytes_before) = storage_objects_and_bytes(&hub, pid);
    let (_, listed_before, _) = pack_counts(&hub, pid);
    assert!(keys_before.len() >= PUSHES, "expected >= {PUSHES} storage objects before merge, got {}", keys_before.len());
    assert!(listed_before as usize >= PUSHES);

    // Compact all 10,000 small packs in bounded passes of 1,000 packs each,
    // measuring total storage reads and writes made by the merge.
    let reads_0 = h.objects.reads.load(Relaxed);
    let writes_0 = h.objects.writes.load(Relaxed);
    let written_bytes_0 = h.objects.written_bytes.load(Relaxed);

    let merge_opts = Options {
        min_packs_to_merge: 2,
        max_packs_per_run: 1_000,
        run_gc: false,
        pack_grace_ms: 0,
        ..Options::default()
    };
    loop {
        let rep = hub.rt.block_on(pack_gc::run_project(&h, pid, &merge_opts)).unwrap();
        if rep.packs_merged == 0 {
            break;
        }
    }

    let merge_reads = h.objects.reads.load(Relaxed) - reads_0;
    let merge_writes = h.objects.writes.load(Relaxed) - writes_0;
    let merge_written_bytes = h.objects.written_bytes.load(Relaxed) - written_bytes_0;
    let (keys_after, bytes_after) = storage_objects_and_bytes(&hub, pid);
    let (_, listed_after, discarded_after) = pack_counts(&hub, pid);

    eprintln!(
        "S29 cost (10,000 small pushes): storage objects {} -> {} (listed packs {} -> {}), storage bytes {} -> {}, merge requests: {} reads, {} writes ({} bytes written)",
        keys_before.len(),
        keys_after.len(),
        listed_before,
        listed_after,
        bytes_before,
        bytes_after,
        merge_reads,
        merge_writes,
        merge_written_bytes
    );

    let non_pack_keys = keys_before.len() - listed_before as usize;
    assert_eq!(listed_after, 1, "10,000 small packs merged down to 1 listed pack");
    assert_eq!(discarded_after, 0, "all discarded packs swept");
    assert_eq!(
        keys_after.len(),
        non_pack_keys + 1,
        "all {listed_before} listed packs collapsed into 1 pack object in storage"
    );
    assert!(
        bytes_after < bytes_before,
        "merged pack eliminates per-pack headers ({bytes_before} -> {bytes_after} bytes)"
    );
    assert!(merge_writes <= 15, "at most 15 pack writes across passes, got {merge_writes}");
    assert!(
        merge_reads <= (PUSHES as u64) * 2 + 50,
        "at most 2 reads per pack during merge, got {merge_reads}"
    );

    // Every sampled object reads back byte-identical from the compacted pack.
    let fresh = veil_server::store::Objects::with_db(store, 64 << 10, Some(h.db.clone()));
    for (id, expected) in &sample_objects {
        let got = hub.rt.block_on(fresh.get(pid, id)).unwrap().unwrap();
        assert_eq!(&got, expected);
    }
}

/// BUG-1780: Cross-server cache invalidation (`hub2` warm before GC, re-push on
/// `hub2` while discarded pack is still inside `pack_grace_ms`, both admin and
/// restricted viewer read whole) AND retention-window closure preservation (an
/// unreferenced snapshot still inside `retention_window_ms` keeps its older
/// shared blobs/ancestors alive until its own window expires).
#[test]
fn bug_1780_cross_server_repush_and_retained_snapshot_closure() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let hub2 = TestHub::beside(&hub);
    let api1 = hub.api();
    let api2 = hub2.api();
    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();

    // 1. Push `s1` on `b_early` with shared blob `src/shared.txt`, and warm
    // BOTH `hub` and `hub2` for both `admin` and `dev` (restricted viewer).
    let mut c1 = Craft::new(&api1, &p.admin, &p.name, "main");
    c1.file("src/shared.txt", "SHARED-BLOB-1780\n");
    c1.file(&format!("{BILL_DIR}/secret.txt"), "BILLING-1780\n");
    let mut saved_s1 = c1.objects.clone();
    let (_cs1, push1) = c1.push_edited("b_early", None, |_| {});
    assert_eq!(push1.status, 200);
    assert_eq!(push1.json()["results"][0]["ok"], json!(true));
    let s1 = ObjectId::from_hex(push1.json()["results"][0]["tip"].as_str().unwrap()).unwrap();
    let (_, s1_raw) = api1.history(&admin_tok, &p.name, &[s1]).frames().into_iter().find(|(id, _)| *id == s1).unwrap();
    saved_s1.push((s1, s1_raw));

    for a in [&api1, &api2] {
        for tok in [&admin_tok, &dev_tok] {
            let r = a.get(Some(tok), &format!("/v1/projects/{}/q/file?rev=b_early&path=src/shared.txt", p.name));
            assert_eq!(r.status, 200);
            assert!(String::from_utf8_lossy(&r.body).contains("SHARED-BLOB-1780"));
        }
    }

    // 2. Delete `b_early` at t=0 and mark `s1` + `src/shared.txt` unreferenced at t=0.
    let del1 = api1.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "b_early", "expected": s1.hex(), "new": null}], "force": true}),
    );
    assert_eq!(del1.status, 200);
    hub.rt
        .block_on(pack_gc::run_project(
            &hub.hub(),
            pid,
            &Options {
                min_packs_to_merge: 1,
                run_gc: true,
                retention_window_ms: 60_000,
                now_offset_ms: 0,
                ..Options::default()
            },
        ))
        .unwrap();

    // 3. Push `s2` on `b_late` referencing the SAME `src/shared.txt` content, then
    // delete `b_late` and run GC at t=40_000 (`b_late` unreferenced at t=40_000),
    // then run GC at t=70_000: `s1` (since=0) is expired, `s2` (since=40_000) is
    // STILL inside its 60s retention window, so `src/shared.txt` MUST NOT be
    // deleted yet while `s2` remains in `snapshots`!
    let mut c2 = Craft::new(&api1, &p.admin, &p.name, "main");
    c2.file("src/shared.txt", "SHARED-BLOB-1780\n");
    c2.file("src/only_s2.txt", "ONLY-S2-1780\n");
    let (_cs2, push_s2) = c2.push_edited("b_late", None, |_| {});
    assert_eq!(push_s2.status, 200);
    let s2 = ObjectId::from_hex(push_s2.json()["results"][0]["tip"].as_str().unwrap()).unwrap();
    let del2 = api1.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "b_late", "expected": s2.hex(), "new": null}], "force": true}),
    );
    assert_eq!(del2.status, 200);

    for off in [40_000i64, 70_000] {
        hub.rt
            .block_on(pack_gc::run_project(
                &hub.hub(),
                pid,
                &Options {
                    min_packs_to_merge: 1,
                    run_gc: true,
                    retention_window_ms: 60_000,
                    pack_grace_ms: 300_000,
                    now_offset_ms: off,
                    ..Options::default()
                },
            ))
            .unwrap();
    }
    let (shared_blob_id, _) = make_blob("SHARED-BLOB-1780\n");
    assert!(
        hub.rt.block_on(hub.hub().objects.exists(pid, &shared_blob_id)).unwrap(),
        "shared blob referenced by retained snapshot s2 must remain stored until s2 expires"
    );

    // 4. Advance past `s2`'s retention window too (t=120_000), keeping `pack_grace_ms = 300_000`
    // so discarded packs still sit in storage while `hub2` did NOT run GC itself.
    let rep_exp = hub
        .rt
        .block_on(pack_gc::run_project(
            &hub.hub(),
            pid,
            &Options {
                min_packs_to_merge: 1,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 300_000,
                now_offset_ms: 120_000,
                ..Options::default()
            },
        ))
        .unwrap();
    assert!(rep_exp.packed_objects_deleted >= 1, "expired objects dropped from packs: {rep_exp:?}");

    // 5. Re-upload `saved_s1` and push `revived_on_peer` directly against `hub2`!
    // Even if `hub2` had warm `committed` / `memo` / `resolved` / `Objects::cache` / `Packs`,
    // `hub2` observes the bumped `gc_epoch`, stores `saved_s1` again, and serves it whole
    // even after `DISCARDED` packs are swept!
    let reup = api2.upload(&admin_tok, &p.name, &saved_s1);
    assert_eq!(reup.status, 200);
    let receipts = reup.json()["receipts"].as_array().unwrap().clone();
    let rmap: serde_json::Map<String, Value> = saved_s1.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
    let push_rev = api2.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({
            "updates": [{"branch": "revived_on_peer", "expected": null, "new": s1.hex()}],
            "receipts": rmap,
        }),
    );
    assert_eq!(push_rev.status, 200);
    assert_eq!(push_rev.json()["results"][0]["ok"], json!(true), "re-push on peer server ok: {}", String::from_utf8_lossy(&push_rev.body));

    // Sweep discarded packs (`pack_grace_ms: 0`) so nothing from before GC survives on disk.
    hub.rt
        .block_on(pack_gc::run_project(
            &hub.hub(),
            pid,
            &Options {
                min_packs_to_merge: 2,
                run_gc: false,
                pack_grace_ms: 0,
                now_offset_ms: 500_000,
                ..Options::default()
            },
        ))
        .unwrap();

    let hub3 = TestHub::beside(&hub);
    for a in [&api1, &api2, &hub3.api()] {
        for tok in [&admin_tok, &dev_tok] {
            let r = a.get(Some(tok), &format!("/v1/projects/{}/q/file?rev=revived_on_peer&path=src/shared.txt", p.name));
            assert_eq!(r.status, 200, "revived_on_peer readable across all servers and views: {}", String::from_utf8_lossy(&r.body));
            assert!(String::from_utf8_lossy(&r.body).contains("SHARED-BLOB-1780"));
        }
    }
}

/// BUG-1781: Peer server (`hub2`) with BOTH `hub2.grants.stored` AND
/// `hub2.objects` (`Objects::cache`) warmed before GC on `hub` never skips
/// re-writing loose projected trees (`t_proj`) after GC deletes them, nor
/// serves a deleted `t_proj` after branch deletion.
#[test]
fn bug_1781_peer_server_grants_stored_and_object_cache_invalidated_on_gc() {
    use veil_core::hub::grant::{sign_request, Grant};

    let signed_get = |via: &Api, project: &str, grant: &str, grant_key: &str, signer: &veil_core::Identity, id: &ObjectId| {
        let ts = veil_core::now_millis();
        let g = Grant::verify(grant, grant_key).unwrap();
        let sig = format!("{ts}.{}", sign_request(signer, &g, ts, &[*id]));
        via.get_with(
            &format!("/v1/objects/{project}/{}", id.hex()),
            &[("veil-grant", grant), ("veil-chain", ""), ("veil-signature", &sig)],
        )
    };

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let hub2 = TestHub::beside(&hub);
    let api1 = hub.api();
    let api2 = hub2.api();
    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();
    let dev_id = p.dev.identity();

    // 1. Admin creates `b1` touching `src/sub/vis.txt` and hidden `BILL_DIR/h1.txt`.
    let mut c1 = Craft::new(&api1, &p.admin, &p.name, "main");
    c1.file("src/sub/vis.txt", "VISIBLE-PEER-1781\n");
    c1.file(&format!("{BILL_DIR}/h1.txt"), "HIDDEN-PEER-V1\n");
    let (_cs1, r1) = c1.push_edited("b1", None, |_| {});
    assert_eq!(r1.status, 200);
    assert_eq!(r1.json()["results"][0]["ok"], json!(true));
    let b1_tip = ObjectId::from_hex(r1.json()["results"][0]["tip"].as_str().unwrap()).unwrap();

    // 2. Warm `hub2.grants.stored` AND `hub2.objects` (`Objects::cache`) by
    // requesting `tips` and reading `t_proj` directly from `hub2`.
    let tips1 = api2.tips(Some(&dev_tok), &p.name).unwrap();
    let g1 = tips1.grants.get("b1").expect("dev grant for b1 on hub2");
    let gkey = tips1.grant_key.as_ref().unwrap();
    let t_proj = Grant::read_unverified(g1).unwrap().root;
    let read1 = signed_get(&api2, &p.name, g1, gkey, &dev_id, &t_proj);
    assert_eq!(read1.status, 200, "hub2 serves projected root before GC");

    // 3. Delete `b1` on `hub` and run GC on `hub` past retention window.
    let del = api1.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "b1", "expected": b1_tip.hex(), "new": null}], "force": true}),
    );
    assert_eq!(del.status, 200);
    for off in [0i64, 120_000, 120_001] {
        hub.rt
            .block_on(pack_gc::run_project(
                &hub.hub(),
                pid,
                &Options {
                    min_packs_to_merge: 1,
                    run_gc: true,
                    retention_window_ms: 60_000,
                    pack_grace_ms: 0,
                    now_offset_ms: off,
                    ..Options::default()
                },
            ))
            .unwrap();
    }

    // Old grant `g1` must NOT read deleted `t_proj` from `hub2`'s `Objects::cache`!
    let stale_read = signed_get(&api2, &p.name, g1, gkey, &dev_id, &t_proj);
    assert_eq!(stale_read.status, 404, "peer server must not serve GC-deleted projected root from Objects::cache");

    // 4. Push `b2` with the same visible tree and different hidden content, then
    // ask `hub2` (which had BOTH `grants.stored` and `Objects::cache` warmed!)
    // to issue the grant and re-store `t_proj`.
    let mut c2 = Craft::new(&api1, &p.admin, &p.name, "main");
    c2.file("src/sub/vis.txt", "VISIBLE-PEER-1781\n");
    c2.file(&format!("{BILL_DIR}/h2.txt"), "HIDDEN-PEER-V2\n");
    let (_cs2, r2) = c2.push_edited("b2", None, |_| {});
    assert_eq!(r2.status, 200);
    assert_eq!(r2.json()["results"][0]["ok"], json!(true));

    let tips2 = api2.tips(Some(&dev_tok), &p.name).unwrap();
    let g2 = tips2.grants.get("b2").expect("dev grant for b2 on hub2");
    assert_eq!(Grant::read_unverified(g2).unwrap().root, t_proj);

    // 5. A brand-new peer server `hub3` reads `t_proj` from shared storage (`200 OK`).
    let hub3 = TestHub::beside(&hub);
    let read3 = signed_get(&hub3.api(), &p.name, g2, gkey, &dev_id, &t_proj);
    assert_eq!(read3.status, 200, "hub2 re-wrote t_proj to shared storage so hub3 serves it");
}
