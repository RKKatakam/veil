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
    // (A reader that failed ends these waits: its panic is reported below,
    // where the readers are joined, instead of a test that never ends.)
    while reads_done.load(Relaxed) < 16 && !reader_threads.iter().any(|t| t.is_finished()) {
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
    while reads_done.load(Relaxed) < mark + 32 && !reader_threads.iter().any(|t| t.is_finished()) {
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
    // A database of its own: it creates the `tags` table (BUG-2532).
    let hub = TestHub::start_own();
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
    }

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

    // Catch up derive and force a clean search-index rebuild AFTER all branch
    // pushes (`main` will not move again before `r1`/`r2`, so background
    // `search::index::compact` cannot supersede `live_seg_id`, BUG-1820).
    hub.rt.block_on(veil_server::derive::catch_up_project(&hub.hub(), pid)).unwrap();
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
    let mut live_seg_ids = std::collections::BTreeSet::new();
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
    let r2 = gc_pass(&hub, pid, &opts_after_window);
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
    let r2 = gc_pass(&hub, pid, &opts2);
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
    // A database and an object store of its own (BUG-2457): every test of a
    // run shares one database, and this server's embargo release loop
    // (`embargo::run_loop`) releases the other tests' embargoes that are
    // due, reading their objects in this server's storage counters (63 to
    // 441 reads in the merge's window under load). The store too: a new
    // database numbers its projects from 1 again, and the run's bucket holds
    // other such tests' `p/1/` keys, which the counts below would include.
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let hub = TestHub::start_with_s3(&crate::grants::fresh_database(&rt), Duration::from_secs(3600), None);
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

/// A GC pass by hand, run again as the server's own GC loop would run it at
/// its next tick when it did not do its work: it lost a race with another
/// database's schema change on a shared YugabyteDB (40001; BUG-2212: every
/// pass of the test, not only some), another server's pass held the
/// project's lock (`skipped`), or it deleted nothing because the project's
/// references moved while it ran and it gave way (BUG-2590: the server's
/// search index still writing what the test's pushes started, under the
/// suite's load; `search_shards` is in the reference stamp, BUG-1923). The
/// stamp is read before and after each pass: a pass that deleted nothing
/// while it stood still is final, and what the test checks is unchanged.
pub(crate) fn gc_pass(hub: &TestHub, pid: i64, opts: &Options) -> pack_gc::Report {
    let h = hub.hub();
    let stamp = || hub.rt.block_on(pack_gc::project_ref_stamp(&h.db, pid)).ok();
    let mut tries = 0;
    loop {
        let before = stamp();
        match hub.rt.block_on(pack_gc::run_project(&h, pid, opts)) {
            Ok(r) => {
                let gave_way = r.packed_objects_deleted + r.loose_objects_deleted == 0 && {
                    let after = stamp();
                    before.is_none() || after != before
                };
                if !(r.skipped || gave_way) || tries >= 20 {
                    return r;
                }
            }
            Err(e) if e.is_retryable() && tries < 20 => {}
            Err(e) => panic!("GC pass at offset {}: {e:?}", opts.now_offset_ms),
        }
        tries += 1;
        std::thread::sleep(std::time::Duration::from_millis(200));
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
    gc_pass(
        &hub,
        pid,
        &Options {
            min_packs_to_merge: 1,
            run_gc: true,
            retention_window_ms: 60_000,
            now_offset_ms: 0,
            ..Options::default()
        },
    );

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
        let opts = Options {
            min_packs_to_merge: 1,
            run_gc: true,
            retention_window_ms: 60_000,
            pack_grace_ms: 300_000,
            now_offset_ms: off,
            ..Options::default()
        };
        gc_pass(&hub, pid, &opts);
    }
    let (shared_blob_id, _) = make_blob("SHARED-BLOB-1780\n");
    assert!(
        hub.rt.block_on(hub.hub().objects.exists(pid, &shared_blob_id)).unwrap(),
        "shared blob referenced by retained snapshot s2 must remain stored until s2 expires"
    );

    // 4. Advance past `s2`'s retention window too (t=120_000), keeping `pack_grace_ms = 300_000`
    // so discarded packs still sit in storage while `hub2` did NOT run GC itself.
    let rep_exp = gc_pass(
        &hub,
        pid,
        &Options {
            min_packs_to_merge: 1,
            run_gc: true,
            retention_window_ms: 60_000,
            pack_grace_ms: 300_000,
            now_offset_ms: 120_000,
            ..Options::default()
        },
    );
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

/// BUG-1782: Every `(table, column)` in the migrated PostgreSQL schema must be
/// registered in `pack_gc`, every root-bearing table must be stamped in
/// `read_ref_stamp`, and adding an unregistered table or column naming objects
/// immediately fails `pack_gc::audit_schema_columns`.
#[test]
fn bug_1782_every_schema_column_is_registered_and_root_tables_are_stamped() {
    use veil_server::pack_gc::{
        audit_schema_columns, stamped_root_tables, SchemaColumnRole, OBJECT_SCHEMA_COLUMNS,
    };

    // A database of its own (BUG-2532): its `ALTER TABLE bisects`, though
    // rolled back, answered the GC tests' statements on `bisects` in the
    // shared database `40001` on YugabyteDB.
    let hub = TestHub::start_own();
    let db = hub.hub().db.clone();

    // 1. Live migrated schema matches `pack_gc`'s column registry 1-to-1.
    let (unregistered, missing) = hub
        .rt
        .block_on(async {
            let mut conn = db.acquire().await.unwrap();
            audit_schema_columns(&mut conn).await
        })
        .unwrap();
    assert!(
        unregistered.is_empty(),
        "unregistered schema columns found — register their GC role in pack_gc::OBJECT_SCHEMA_COLUMNS or NON_OBJECT_SCHEMA_COLUMNS: {unregistered:?}"
    );
    assert!(
        missing.is_empty(),
        "stale or duplicate registered schema columns not present in information_schema.columns: {missing:?}"
    );

    // 2. Every table GC takes roots from (`GcRoot`, `GcConditionalLeafRoot`:
    // none excepted, BUG-1923), with each of its root columns, plus
    // `snapshots` and staged `packs`, is fingerprinted by `read_ref_stamp`.
    let stamped: HashSet<&str> = stamped_root_tables().into_iter().collect();
    assert!(stamped.contains("packs"), "staged packs must be in read_ref_stamp");
    assert!(stamped.contains("snapshots"), "snapshots must be in read_ref_stamp");
    let roots = OBJECT_SCHEMA_COLUMNS
        .iter()
        .filter(|(_, _, role)| matches!(role, SchemaColumnRole::GcRoot | SchemaColumnRole::GcConditionalLeafRoot))
        .count();
    assert!(roots >= 24, "the registry lists the root columns: {roots}");
    assert_eq!(
        veil_server::pack_gc::unstamped_root_columns(),
        Vec::<(&str, &str)>::new(),
        "root columns of the registry that pack_gc::STAMP_TABLES does not read"
    );
    for table in ["search_shards", "pr_review_rules"] {
        assert!(stamped.contains(table), "`{table}` must be in read_ref_stamp");
    }

    // 3. Negative meta-test: adding a new table or column naming objects without
    // registering it in `pack_gc` is immediately caught by `audit_schema_columns`.
    let (unreg_after_ddl, _) = hub
        .rt
        .block_on(async {
            let mut tx = db.begin().await.unwrap();
            sqlx::query(
                "CREATE TABLE unregistered_future_feature (project_id BIGINT NOT NULL, target_snapshot TEXT NOT NULL)",
            )
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query("ALTER TABLE bisects ADD COLUMN unregistered_extra_snapshot TEXT")
                .execute(&mut *tx)
                .await
                .unwrap();
            let res = audit_schema_columns(&mut tx).await.unwrap();
            tx.rollback().await.unwrap();
            res
        });
    assert!(
        unreg_after_ddl
            .iter()
            .any(|(t, c, _)| t == "unregistered_future_feature" && c == "target_snapshot"),
        "audit_schema_columns must fail when an unregistered table naming objects is added: {unreg_after_ddl:?}"
    );
    assert!(
        unreg_after_ddl
            .iter()
            .any(|(t, c, _)| t == "bisects" && c == "unregistered_extra_snapshot"),
        "audit_schema_columns must fail when an unregistered column is added to an existing table: {unreg_after_ddl:?}"
    );
}

/// BUG-2590: a pass past the retention window that gives way to a root
/// written during it (here, once, by the switch hook: a `change_refs` row
/// naming `main`, which moves the reference stamp; in the suite, the
/// server's search index finishing what a push started) deletes nothing,
/// and the next pass collects what fell out of the window: a give-way loses
/// one pass, never the object's expiry. `gc_pass` runs the pass again as the
/// server would; a test that ran one pass and expected the deletion failed.
#[test]
fn bug_2590_a_pass_that_gave_way_to_a_root_write_is_followed_by_one_that_collects() {
    use veil_server::pack_gc::SwitchHook;

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let main0 = hub.api().tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"];
    let admin_pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT created_by FROM projects WHERE id = $1").bind(pid).fetch_one(&h.db))
        .unwrap();

    let (dead_id, dead_raw) = make_blob("DEAD-LOOSE-2590\n");
    hub.rt.block_on(h.objects.put(pid, &dead_id, dead_raw)).unwrap();
    // Marked unreferenced now; inside the window, nothing is deleted.
    let marked = gc_pass(
        &hub,
        pid,
        &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, ..Options::default() },
    );
    assert_eq!(marked.loose_objects_deleted, 0, "inside the window: {marked:?}");

    let calls = Arc::new(AtomicUsize::new(0));
    let (db, hook_calls) = (h.db.clone(), calls.clone());
    let main_hex = main0.hex();
    let rep = gc_pass(
        &hub,
        pid,
        &Options {
            min_packs_to_merge: 99,
            run_gc: true,
            retention_window_ms: 60_000,
            pack_grace_ms: 0,
            now_offset_ms: 120_000,
            before_switch: Some(SwitchHook(Arc::new(move || {
                let (db, hook_calls, main_hex) = (db.clone(), hook_calls.clone(), main_hex.clone());
                Box::pin(async move {
                    if hook_calls.fetch_add(1, Relaxed) == 0 {
                        sqlx::query(
                            "INSERT INTO change_refs (project_id, change_id, snapshot, created_by, created_at) \
                             VALUES ($1, 'chg-2590', $2, $3, 1000)",
                        )
                        .bind(pid)
                        .bind(&main_hex)
                        .bind(admin_pid)
                        .execute(&db)
                        .await
                        .unwrap();
                    }
                })
            }))),
            ..Options::default()
        },
    );
    assert!(rep.loose_objects_deleted >= 1, "the pass after the give-way collects what fell out of the window: {rep:?}");
    assert!(calls.load(Relaxed) >= 2, "the first pass reached its switch and gave way, and another ran");
    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    assert!(!hub.rt.block_on(fresh.exists(pid, &dead_id)).unwrap(), "dead loose object deleted from storage");
    assert!(hub.rt.block_on(fresh.exists(pid, &main0)).unwrap(), "main's snapshot kept");
}

/// BUG-2602: a GC pass gave way to any root write made while it ran (the
/// reference stamp, compared whole at the switch), so on a project pushed to
/// steadily no pass ever collected (0 of 90). A pusher moves one branch back
/// and forth between two stored snapshots, one push after another (each a
/// root write GC must see: `branches`), while passes past the retention
/// window run one after another: one of them deletes the dead loose object,
/// which no push names. Each pass is counted: collected, gave way (nothing
/// deleted, the stamp moved), or nothing.
#[test]
fn bug_2602_gc_collects_while_a_project_is_pushed_to_steadily() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let api = hub.api();
    let admin_tok = p.admin.token();
    let main0 = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/busy.rs", "BUSY-2602\n");
    let (_, r) = c.push_edited("busy", None, |_| {});
    assert_eq!(r.status, 200, "push busy: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "push busy ok");
    let snap_a = ObjectId::from_hex(r.json()["results"][0]["tip"].as_str().unwrap()).unwrap();

    let (dead_id, dead_raw) = make_blob("DEAD-LOOSE-2602\n");
    hub.rt.block_on(h.objects.put(pid, &dead_id, dead_raw)).unwrap();
    let marked = gc_pass(&hub, pid, &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, ..Options::default() });
    assert_eq!(marked.loose_objects_deleted, 0, "inside the window: {marked:?}");

    let stop = Arc::new(AtomicBool::new(false));
    let pushes = Arc::new(AtomicUsize::new(0));
    let pusher = {
        let (authority, cert, tok, name) = (hub.authority(), hub.cert_pem.clone(), admin_tok.clone(), p.name.clone());
        let (stop, pushes) = (stop.clone(), pushes.clone());
        std::thread::spawn(move || {
            let api = Api::at(&authority, &cert);
            let (mut cur, mut other) = (snap_a, main0);
            while !stop.load(Relaxed) {
                let r = api.post_json(
                    Some(&tok),
                    &format!("/v1/projects/{name}/push"),
                    &json!({"updates": [{"branch": "busy", "expected": cur.hex(), "new": other.hex()}], "force": true}),
                );
                assert_eq!(r.status, 200, "steady push: {}", String::from_utf8_lossy(&r.body));
                assert_eq!(r.json()["results"][0]["ok"], json!(true), "steady push ok: {}", String::from_utf8_lossy(&r.body));
                std::mem::swap(&mut cur, &mut other);
                pushes.fetch_add(1, Relaxed);
            }
        })
    };
    while pushes.load(Relaxed) < 5 {
        std::thread::sleep(Duration::from_millis(10));
    }

    let opts = Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, now_offset_ms: 120_000, ..Options::default() };
    let (mut collected, mut gave_way, mut nothing, mut skipped) = (0, 0, 0, 0);
    let started = Instant::now();
    let pushes_at_start = pushes.load(Relaxed);
    let mut pass_ms = Vec::new();
    for _ in 0..30 {
        let before = hub.rt.block_on(pack_gc::project_ref_stamp(&h.db, pid)).unwrap();
        let t = Instant::now();
        let r = hub.rt.block_on(pack_gc::run_project(&h, pid, &opts)).unwrap();
        pass_ms.push(t.elapsed().as_millis());
        let after = hub.rt.block_on(pack_gc::project_ref_stamp(&h.db, pid)).unwrap();
        if r.skipped {
            skipped += 1;
        } else if r.loose_objects_deleted + r.packed_objects_deleted > 0 {
            collected += 1;
            break;
        } else if after != before {
            gave_way += 1;
        } else {
            nothing += 1;
        }
    }
    let secs = started.elapsed().as_secs_f64();
    let during = pushes.load(Relaxed) - pushes_at_start;
    stop.store(true, Relaxed);
    pusher.join().expect("the pusher's pushes all succeeded");
    eprintln!(
        "BUG-2602: passes collected {collected}, gave way {gave_way}, nothing {nothing}, skipped {skipped}; \
         {during} pushes in {secs:.1} s ({:.0}/s); pass times (ms) {pass_ms:?}",
        during as f64 / secs
    );
    assert!(during > 0, "pushes ran while GC passed");
    assert_eq!(collected, 1, "a pass collects the dead object while the project is pushed to (gave way {gave_way} times)");
    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    assert!(!hub.rt.block_on(fresh.exists(pid, &dead_id)).unwrap(), "dead loose object deleted from storage");
}

/// Every object `tip` reaches (its tree and files, its ancestors and
/// theirs) is stored, read by a store that shares no cache with the hub.
fn assert_closure_stored(hub: &TestHub, pid: i64, tip: ObjectId, what: &str) {
    let h = hub.hub();
    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    // The universal root and its empty tree, which no project stores.
    let empty = ObjectId::hash(&Object::Tree(Tree::default()).encode());
    let builtin = [veil_server::sync::root_snapshot_id(), empty];
    let mut queue = vec![tip];
    let mut seen = HashSet::new();
    while let Some(id) = queue.pop() {
        if builtin.contains(&id) || !seen.insert(id) {
            continue;
        }
        let raw = hub.rt.block_on(fresh.get(pid, &id)).unwrap().unwrap_or_else(|| panic!("{what}: object {id} reached from {tip} is gone"));
        match Object::decode(&raw).unwrap() {
            Object::Snapshot(s) => {
                queue.push(s.tree);
                queue.extend(s.parents);
            }
            Object::Tree(t) => queue.extend(t.entries.iter().map(|e| e.id)),
            _ => {}
        }
    }
}

/// A snapshot on `branch` with a file of its own, the branch deleted, and a
/// pass at `mark_at` that marks its objects unreferenced: past the
/// retention window (60 s) at `mark_at + 120_000`. The snapshot and the
/// file's blob.
fn expiring_snapshot(hub: &TestHub, p: &Project, pid: i64, branch: &str, mark_at: i64) -> (ObjectId, ObjectId) {
    let api = hub.api();
    let admin_tok = p.admin.token();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let content = format!("EXPIRING-2602-{branch}\n");
    let (blob, _) = make_blob(&content);
    c.file(&format!("src/{branch}.txt"), &content);
    let (snap, r) = c.push_edited(branch, None, |_| {});
    assert_eq!(r.status, 200, "push {branch}: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "push {branch} ok");
    let del = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": branch, "expected": snap.hex(), "new": null}], "force": true}),
    );
    assert_eq!(del.status, 200, "delete {branch}: {}", String::from_utf8_lossy(&del.body));
    assert_eq!(del.json()["results"][0]["ok"], json!(true), "delete {branch} ok");
    let marked = gc_pass(
        hub,
        pid,
        &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, now_offset_ms: mark_at, ..Options::default() },
    );
    assert!(!marked.skipped, "the marking pass ran: {marked:?}");
    (snap, blob)
}

/// One GC pass (no second try) past the retention window at `at`, whose
/// switch hook runs `racing` once, right before the pass's first switch
/// that drops objects: after everything the pass reads outside its
/// transaction, so only the switch itself can see what `racing` wrote.
fn pass_with_a_racing_write<F, Fut>(hub: &TestHub, pid: i64, at: i64, racing: F) -> pack_gc::Report
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    use veil_server::pack_gc::SwitchHook;
    let calls = Arc::new(AtomicUsize::new(0));
    let hook_calls = calls.clone();
    let racing = Arc::new(racing);
    let rep = hub
        .rt
        .block_on(pack_gc::run_project(
            &hub.hub(),
            pid,
            &Options {
                min_packs_to_merge: 99,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: at,
                before_switch: Some(SwitchHook(Arc::new(move || {
                    let (hook_calls, racing) = (hook_calls.clone(), racing.clone());
                    Box::pin(async move {
                        if hook_calls.fetch_add(1, Relaxed) == 0 {
                            racing().await;
                        }
                    })
                }))),
                ..Options::default()
            },
        ))
        .unwrap();
    assert!(!rep.skipped, "the pass ran: {rep:?}");
    assert!(calls.load(Relaxed) >= 1, "the pass reached a switch that drops objects, and the racing write was made");
    rep
}

/// BUG-2602: a root written as a GC pass reaches its switch keeps every
/// object it names, and the pass still collects what nothing names (before,
/// it gave way: nothing was collected). One case for every table the
/// reference stamp covers: the walk roots (`branches`, `change_refs`, the
/// landing queue's stack and its result, `landings`, `embargo_snapshots`,
/// `embargo_lines`, `checks`, `tested`, `pr_revisions`, `pr_review_rules`,
/// `bisects`, `bisect_reverts`), a `snapshots` row (BUG-1780: a row that
/// stays keeps its closure), a search segment (`search_shards`), and a
/// client upload staged in `packs`. Each case: a snapshot (or object) past
/// the retention window that the racing write names, and a dead loose
/// object that nothing names; in one pass the dead one is deleted and the
/// named ones stay, with their `snapshots` row.
#[test]
fn bug_2602_a_root_written_as_gc_switches_keeps_its_objects_and_the_pass_collects_the_rest() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let api = hub.api();
    let admin_tok = p.admin.token();
    let main0 = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"].hex();
    let admin_pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT created_by FROM projects WHERE id = $1").bind(pid).fetch_one(&h.db))
        .unwrap();
    let exists = |id: &ObjectId| {
        let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
        hub.rt.block_on(fresh.exists(pid, id)).unwrap()
    };
    let snapshot_rows = |id: &ObjectId| -> i64 {
        hub.rt
            .block_on(sqlx::query_scalar("SELECT count(*) FROM snapshots WHERE project_id = $1 AND id = $2").bind(pid).bind(id.hex()).fetch_one(&h.db))
            .unwrap()
    };

    // The walk roots: one statement each, naming the snapshot `{s}`.
    type RootWrite = Box<dyn Fn(&str) -> String>;
    let m = main0.clone();
    let roots: Vec<(&str, RootWrite)> = vec![
        ("branches", Box::new(move |s| format!("INSERT INTO branches (project_id, name, target) VALUES ({pid}, 'racing-2602', '{s}')"))),
        (
            "change_refs",
            Box::new(move |s| {
                format!("INSERT INTO change_refs (project_id, change_id, snapshot, created_by, created_at) VALUES ({pid}, 'chg-2602', '{s}', {admin_pid}, 1000)")
            }),
        ),
        ("landing_queue.stack", {
            let m = m.clone();
            Box::new(move |s| {
                format!(
                    "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, stack, lineage, person_epoch, project_epoch, state, created_at) \
                     VALUES ({pid}, 'main', 't-2602-stack', {admin_pid}, 'admin', 'k', '[[\"{s}\", \"{m}\"]]', 0, 0, 0, 'queued', 1000)"
                )
            })
        }),
        ("landing_queue.result", {
            Box::new(move |s| {
                format!(
                    "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, stack, result, lineage, person_epoch, project_epoch, state, created_at) \
                     VALUES ({pid}, 'main', 't-2602-result', {admin_pid}, 'admin', 'k', '[]', '{{\"landed\": \"{s}\"}}', 0, 0, 0, 'landed', 1000)"
                )
            })
        }),
        ("landings", {
            let m = m.clone();
            Box::new(move |s| format!("INSERT INTO landings (project_id, branch, lineage, submitted, landed, at) VALUES ({pid}, 'main', 0, '{m}', '{s}', 1000)"))
        }),
        ("embargo_snapshots", Box::new(move |s| format!("INSERT INTO embargo_snapshots (project_id, snapshot, embargo_id) VALUES ({pid}, '{s}', 'e2602snap')"))),
        (
            "embargo_lines",
            Box::new(move |s| {
                format!(
                    "INSERT INTO embargo_lines (project_id, embargo_id, group_names, target_branch, embargo_branch, until_ms, released_at, record_json, created_by, created_at) \
                     VALUES ({pid}, 'e2602line', ARRAY['g'], 'main', 'embargo/e2602line', NULL, NULL, '{{\"tip\": \"{s}\"}}', 'admin', 1000)"
                )
            }),
        ),
        (
            "checks",
            Box::new(move |s| {
                format!(
                    "INSERT INTO checks (project_id, snapshot, name, state, summary, runner_id, runner_name, updated_at) \
                     VALUES ({pid}, '{s}', 'build-2602', 'pass', 'ok', {admin_pid}, 'admin', 1000)"
                )
            }),
        ),
        ("tested", Box::new(move |s| format!("INSERT INTO tested (project_id, branch, lineage, snapshot, depth, updated_at) VALUES ({pid}, 'racing-tested-2602', 0, '{s}', 1, 1000)"))),
        ("pr_revisions", {
            let m = m.clone();
            Box::new(move |s| {
                format!(
                    "INSERT INTO pr_revisions (project_id, pr, n, base, head, changes, patch, files, risk, reasons, rules_key, files_count, pushed_by, at) \
                     VALUES ({pid}, 'pr-2602', 1, '{m}', '{s}', '[]', 'p', '[]', 'low', '[]', 'rk', 1, {admin_pid}, 2000)"
                )
            })
        }),
        (
            "pr_review_rules",
            Box::new(move |s| {
                format!(
                    "INSERT INTO pr_review_rules (project_id, checked, state) VALUES ({pid}, '{s}', 'ok') \
                     ON CONFLICT (project_id) DO UPDATE SET checked = EXCLUDED.checked"
                )
            }),
        ),
        ("bisects", {
            let m = m.clone();
            Box::new(move |s| {
                format!(
                    "INSERT INTO bisects (project_id, branch, lineage, check_name, good, bad, candidates, lo, hi, phase, probes, culprit, culprit_parent, session_paths, revert_snapshot, created_at, updated_at) \
                     VALUES ({pid}, 'main', 0, 'ci/2602', '{m}', '{s}', '[]', 0, 0, 'searching', '[]', NULL, NULL, '[]', NULL, 3000, 3000)"
                )
            })
        }),
        ("bisect_reverts", {
            let m = m.clone();
            Box::new(move |s| {
                format!(
                    "INSERT INTO bisect_reverts (project_id, branch, lineage, culprit, check_name, ticket, revert_snapshot, state, created_at) \
                     VALUES ({pid}, 'main', 0, '{m}', 'ci/2602', 'tkt-2602', '{s}', 'reverted', 3000)"
                )
            })
        }),
    ];

    let mut at = 0i64;
    for (i, (kind, write)) in roots.iter().enumerate() {
        let (dead, dead_raw) = make_blob(&format!("DEAD-LOOSE-2602-{kind}\n"));
        hub.rt.block_on(h.objects.put(pid, &dead, dead_raw)).unwrap();
        let (snap, blob) = expiring_snapshot(&hub, &p, pid, &format!("exp-{i}"), at);
        let (db, sql) = (h.db.clone(), write(&snap.hex()));
        let rep = pass_with_a_racing_write(&hub, pid, at + 120_000, move || {
            let (db, sql) = (db.clone(), sql.clone());
            async move {
                sqlx::query(&sql).execute(&db).await.unwrap();
            }
        });
        assert!(!exists(&dead), "{kind}: the pass collects what nothing names, though a root was written as it switched: {rep:?}");
        assert!(rep.loose_objects_deleted >= 1, "{kind}: {rep:?}");
        assert!(exists(&snap), "{kind}: the snapshot the racing root names is kept: {rep:?}");
        assert!(exists(&blob), "{kind}: its file is kept: {rep:?}");
        assert_eq!(snapshot_rows(&snap), 1, "{kind}: its `snapshots` row is kept");
        assert_closure_stored(&hub, pid, snap, kind);
        at += 400_000;
    }

    // A `snapshots` row (BUG-1780): `child`'s row is written as the pass
    // switches; its parent is past the window, and stays with it.
    {
        let (dead, dead_raw) = make_blob("DEAD-LOOSE-2602-snapshots\n");
        hub.rt.block_on(h.objects.put(pid, &dead, dead_raw)).unwrap();
        let (parent, parent_blob) = expiring_snapshot(&hub, &p, pid, "exp-row-parent", at);
        // The child is stored and unreferenced, with no row yet (as a push
        // that has stored it and not yet recorded it): made here and stored
        // directly, so that nothing of the server names it (a push would
        // leave the review rules' pointer on it, a root of its own).
        let mut c = Craft::new(&api, &p.admin, &p.name, "main");
        c.file("src/exp-row-child.txt", "EXPIRING-2602-child\n");
        let mut s = Snapshot {
            parents: vec![parent],
            change_id: ChangeId::random(),
            tree: c.root,
            description: Text::Plain("child".into()),
            author: "crafter".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            agent: None,
            abandoned: None,
            attempts: vec![],
            signature: None,
        };
        s.sign(&c.identity);
        let child_raw = Object::Snapshot(s).encode();
        let child = ObjectId::hash(&child_raw);
        for (id, raw) in c.objects.iter().cloned().chain([(child, child_raw)]) {
            hub.rt.block_on(h.objects.put(pid, &id, Bytes::from(raw))).unwrap();
        }
        let author = admin_pid;
        let (db, child_hex) = (h.db.clone(), child.hex());
        let rep = pass_with_a_racing_write(&hub, pid, at + 120_000, move || {
            let (db, child_hex) = (db.clone(), child_hex.clone());
            async move {
                sqlx::query("INSERT INTO snapshots (project_id, id, author) VALUES ($1, $2, $3)").bind(pid).bind(&child_hex).bind(author).execute(&db).await.unwrap();
            }
        });
        assert!(!exists(&dead), "snapshots: the pass collects what nothing names: {rep:?}");
        assert_eq!(snapshot_rows(&child), 1, "snapshots: the row written as the pass switched stays");
        assert!(exists(&parent) && exists(&parent_blob), "snapshots: the parent of a snapshot whose row stays is kept: {rep:?}");
        assert_eq!(snapshot_rows(&parent), 1, "snapshots: the parent's row is kept");
        assert_closure_stored(&hub, pid, child, "snapshots");
        at += 400_000;
    }

    // A search segment and a staged client upload: each names a loose
    // object past the window.
    for kind in ["search_shards", "packs"] {
        let (dead, dead_raw) = make_blob(&format!("DEAD-LOOSE-2602-{kind}\n"));
        hub.rt.block_on(h.objects.put(pid, &dead, dead_raw)).unwrap();
        let (named, named_raw) = make_blob(&format!("NAMED-LOOSE-2602-{kind}\n"));
        hub.rt.block_on(h.objects.put(pid, &named, named_raw.clone())).unwrap();
        let marked = gc_pass(
            &hub,
            pid,
            &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, now_offset_ms: at, ..Options::default() },
        );
        assert!(!marked.skipped, "{kind}: the marking pass ran");
        let (db, hub2) = (h.db.clone(), h.clone());
        let rep = pass_with_a_racing_write(&hub, pid, at + 120_000, move || {
            let (db, hub2, named_raw) = (db.clone(), hub2.clone(), named_raw.clone());
            async move {
                if kind == "search_shards" {
                    sqlx::query(
                        "INSERT INTO search_shards (project_id, kind, branch, line_key, segments, docs, text_docs, text_bytes, dead) \
                         VALUES ($1, 'names', '', 'k2602', $2, 0, 0, 0, 0)",
                    )
                    .bind(pid)
                    .bind(json!([named.hex()]).to_string())
                    .execute(&db)
                    .await
                    .unwrap();
                } else {
                    hub2.objects.stage(pid, admin_pid, vec![(named, veil_server::store::encode(named_raw))]).await.unwrap();
                }
            }
        });
        assert!(!exists(&dead), "{kind}: the pass collects what nothing names: {rep:?}");
        let loose = hub.rt.block_on(h.objects.blob_store().exists(&veil_server::store::object_key(pid, &named))).unwrap();
        assert!(loose, "{kind}: the object named as the pass switched is kept: {rep:?}");
        at += 400_000;
    }

    // Later passes, far past every window: the roots written keep what they name.
    for off in [at + 1_000_000, at + 2_000_000] {
        let rep = gc_pass(
            &hub,
            pid,
            &Options { min_packs_to_merge: 1, run_gc: true, retention_window_ms: 60_000, pack_grace_ms: 0, now_offset_ms: off, ..Options::default() },
        );
        assert!(!rep.skipped, "a later pass ran: {rep:?}");
    }
    let named: Vec<String> = hub
        .rt
        .block_on(
            sqlx::query_scalar(
                "SELECT target FROM branches WHERE project_id = $1 AND name = 'racing-2602' \
                 UNION ALL SELECT snapshot FROM change_refs WHERE project_id = $1 AND change_id = 'chg-2602' \
                 UNION ALL SELECT snapshot FROM checks WHERE project_id = $1 AND name = 'build-2602' \
                 UNION ALL SELECT snapshot FROM tested WHERE project_id = $1 AND branch = 'racing-tested-2602' \
                 UNION ALL SELECT head FROM pr_revisions WHERE project_id = $1 AND pr = 'pr-2602' \
                 UNION ALL SELECT snapshot FROM embargo_snapshots WHERE project_id = $1 AND embargo_id = 'e2602snap' \
                 UNION ALL SELECT landed FROM landings WHERE project_id = $1 AND landed <> submitted AND at = 1000",
            )
            .bind(pid)
            .fetch_all(&h.db),
        )
        .unwrap();
    assert_eq!(named.len(), 7, "the roots written are still there: {named:?}");
    for s in named {
        assert_closure_stored(&hub, pid, ObjectId::from_hex(&s).unwrap(), "after later passes");
    }
}

/// BUG-2602: a pass does not read again what it found absent (a project
/// names many objects it does not store: predecessors never pushed, the
/// trees of signed origins), unless a client upload made since holds it. A
/// snapshot that stays names a predecessor the server does not store; the
/// predecessor's tree and file are stored, unreferenced and past the
/// window. As the pass switches, a push stores the predecessor (an upload,
/// listed) and writes a root: the predecessor is read then, and its tree
/// and file are kept; the pass collects what nothing names.
#[test]
fn bug_2602_an_object_stored_as_gc_switches_that_others_already_named_keeps_what_it_names() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let api = hub.api();
    let admin_pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT created_by FROM projects WHERE id = $1").bind(pid).fetch_one(&h.db))
        .unwrap();
    let exists = |id: &ObjectId| {
        let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
        hub.rt.block_on(fresh.exists(pid, id)).unwrap()
    };

    // The predecessor: made here, its tree and file stored (loose,
    // unreferenced), the snapshot itself not stored.
    let mut old = Craft::new(&api, &p.admin, &p.name, "main");
    old.file("src/old-version.txt", "OLD-VERSION-2602\n");
    let (old_blob, _) = make_blob("OLD-VERSION-2602\n");
    let old_tree = old.root;
    let mut s = Snapshot {
        parents: vec![old.tip],
        change_id: ChangeId::random(),
        tree: old_tree,
        description: Text::Plain("old version".into()),
        author: "crafter".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        agent: None,
        abandoned: None,
        attempts: vec![],
        signature: None,
    };
    s.sign(&old.identity);
    let (change_id, old_raw) = (s.change_id, Bytes::from(Object::Snapshot(s).encode()));
    let old_snap = ObjectId::hash(&old_raw);
    for (id, raw) in old.objects.iter().cloned() {
        hub.rt.block_on(h.objects.put(pid, &id, Bytes::from(raw))).unwrap();
    }
    assert!(exists(&old_tree) && exists(&old_blob) && !exists(&old_snap), "the old version's tree and file are stored, the snapshot is not");

    // The snapshot that stays: the new version, naming the old one.
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/new-version.txt", "NEW-VERSION-2602\n");
    let (kept, r) = c.push_edited("kept-2602", None, |s| {
        s.change_id = change_id;
        s.predecessors = vec![old_snap];
    });
    assert_eq!(r.status, 200, "push the new version: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "push the new version ok: {}", String::from_utf8_lossy(&r.body));

    let (dead, dead_raw) = make_blob("DEAD-LOOSE-2602-upload\n");
    hub.rt.block_on(h.objects.put(pid, &dead, dead_raw)).unwrap();
    let marked = gc_pass(&hub, pid, &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, ..Options::default() });
    assert!(!marked.skipped, "the marking pass ran");

    let (db, hub2, kept_hex) = (h.db.clone(), h.clone(), kept.hex());
    let rep = pass_with_a_racing_write(&hub, pid, 120_000, move || {
        let (db, hub2, kept_hex, old_raw) = (db.clone(), hub2.clone(), kept_hex.clone(), old_raw.clone());
        async move {
            let pack = hub2.objects.stage(pid, admin_pid, vec![(old_snap, veil_server::store::encode(old_raw))]).await.unwrap();
            sqlx::query("UPDATE packs SET state = $3 WHERE project_id = $1 AND name = $2").bind(pid).bind(&*pack).bind(LISTED).execute(&db).await.unwrap();
            sqlx::query("INSERT INTO change_refs (project_id, change_id, snapshot, created_by, created_at) VALUES ($1, 'chg-2602-upload', $2, $3, 1000)")
                .bind(pid)
                .bind(&kept_hex)
                .bind(admin_pid)
                .execute(&db)
                .await
                .unwrap();
        }
    });
    assert!(!exists(&dead), "the pass collects what nothing names: {rep:?}");
    assert!(exists(&old_snap), "the predecessor the push stored is there: {rep:?}");
    assert!(exists(&old_tree) && exists(&old_blob), "the tree and file of a predecessor stored as the pass switched are kept: {rep:?}");
    assert_closure_stored(&hub, pid, old_snap, "the predecessor");
    assert_closure_stored(&hub, pid, kept, "the snapshot that stays");
}

/// BUG-2621: the switch that drops loose objects committed (the purge, the
/// GC epoch raised), then deleted the objects from the store with no lock
/// held, and raised the epoch again only once all were deleted. A writer
/// that began after the commit read the new epoch, stored or found its
/// objects, and committed before they were deleted: its guard passed, and
/// its root then named an object GC deleted. Here an API commit puts back a
/// file whose blob is stored loose, unreferenced and past the window (the
/// server stores an API commit's objects loose, under the same key), between
/// the switch's commit and the deletes. The deletes are now made in
/// transactions that hold the root writers' gate and read the roots again:
/// the commit's root is seen, and its blob is kept.
#[test]
fn bug_2621_a_commit_between_the_loose_switch_and_its_deletes_keeps_its_file() {
    use veil_server::pack_gc::SwitchHook;
    const CONTENT: &str = "BACK-AGAIN-2621-CONTENT-7a1e\n";

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let api = hub.api();
    let admin_tok = p.admin.token();
    let main0 = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];

    // The file's blob, stored loose, that nothing names: past the window at
    // the second pass.
    let (blob, blob_raw) = make_blob(CONTENT);
    hub.rt.block_on(h.objects.put(pid, &blob, blob_raw)).unwrap();
    let marked = gc_pass(&hub, pid, &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, ..Options::default() });
    assert!(!marked.skipped, "the marking pass ran");

    // After the switch's transaction, before the deletes: an API commit of
    // a file with that content.
    let (tx, rx) = std::sync::mpsc::channel::<Reply>();
    let calls = Arc::new(AtomicUsize::new(0));
    let hook = {
        let (authority, cert, name, token, calls) = (hub.authority(), hub.cert_pem.clone(), p.name.clone(), admin_tok.clone(), calls.clone());
        SwitchHook(Arc::new(move || {
            let (authority, cert, name, token, tx) = (authority.clone(), cert.clone(), name.clone(), token.clone(), tx.clone());
            let first = calls.fetch_add(1, Relaxed) == 0;
            Box::pin(async move {
                if !first {
                    return;
                }
                let (done, committed) = tokio::sync::oneshot::channel();
                std::thread::spawn(move || {
                    let api = Api::at(&authority, &cert);
                    let r = api.post_json(
                        Some(&token),
                        &format!("/v1/projects/{name}/changes"),
                        &json!({"base": main0.hex(), "edits": [{"path": "src/back-2621.txt", "put": {"text": CONTENT}}]}),
                    );
                    let _ = tx.send(r);
                    let _ = done.send(());
                });
                let _ = committed.await;
            })
        }))
    };
    let rep = hub
        .rt
        .block_on(pack_gc::run_project(
            &h,
            pid,
            &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, pack_grace_ms: 0, now_offset_ms: 120_000, before_loose_delete: Some(hook), ..Options::default() },
        ))
        .unwrap();
    assert!(!rep.skipped, "the pass ran: {rep:?}");
    assert_eq!(calls.load(Relaxed), 1, "the pass committed its loose switch and reached its deletes once: {rep:?}");
    let r = rx.recv_timeout(Duration::from_secs(60)).expect("the commit answers");
    assert_eq!(r.status, 200, "the API commit: {}", String::from_utf8_lossy(&r.body));
    let committed: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).expect("the commit's snapshot");

    // What the commit holds is stored.
    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    assert!(hub.rt.block_on(fresh.exists(pid, &blob)).unwrap(), "the committed file's blob was deleted by GC: {rep:?}");
    let r = api.get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?rev={}&path=src/back-2621.txt", p.name, committed.hex()));
    assert_eq!(r.status, 200, "the committed file: {}", String::from_utf8_lossy(&r.body).chars().take(300).collect::<String>());
    assert!(String::from_utf8_lossy(&r.body).contains(CONTENT.trim_end()), "the file's content is served");
    assert_closure_stored(&hub, pid, committed, "the change committed as GC deleted");
}

/// On `main`, a directory two levels under `src/` with a file: the commit,
/// the directory's tree as stored, and the file's blob.
fn victim_directory(hub: &TestHub, p: &Project, pid: i64, content: &str) -> (ObjectId, Tree, ObjectId) {
    let api = hub.api();
    let h = hub.hub();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/victim/deep/file.txt", content);
    let before = c.tip;
    let (main1, r) = c.push_edited("main", Some(before), |_| {});
    assert_eq!(r.status, 200, "push main: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "push main ok: {}", String::from_utf8_lossy(&r.body));
    let get = |id: &ObjectId| Object::decode(&hub.rt.block_on(h.objects.get(pid, id)).unwrap().expect("stored")).unwrap();
    let Object::Snapshot(s) = get(&main1) else { panic!("a snapshot") };
    let mut at = s.tree;
    for part in ["src", "victim", "deep"] {
        let Object::Tree(t) = get(&at) else { panic!("a tree") };
        at = t.get(part).unwrap_or_else(|| panic!("no {part}")).id;
    }
    let Object::Tree(deep) = get(&at) else { panic!("a tree") };
    (main1, deep, make_blob(content).0)
}

/// BUG-2622, the push's end: an entry's object is of the entry's kind. A
/// file or symlink entry names a file's content (a blob, or a secret's
/// sealed envelope), a directory entry a tree, a conflict entry a conflict:
/// a push of anything else is refused, as is an API commit that puts a
/// tree at a file's path. (Pack GC keeps what a file entry names as a leaf:
/// a member who may write `src/` pushed, to a branch of their own, a file
/// entry naming the tree of a directory of `main`, the push was accepted,
/// and GC deleted the directory's files.)
#[test]
fn bug_2622_a_push_or_an_api_commit_of_an_entry_whose_object_is_not_of_its_kind_is_refused() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let dev_tok = p.dev.token();
    let (_main1, deep, _blob) = victim_directory(&hub, &p, pid, "VICTIM-2622-KINDS\n");
    let branches = || api.tips(Some(&dev_tok), &p.name).unwrap().branches;

    // The member's ordinary push is accepted: what is refused below is the entry.
    let mut ok = Craft::new(&api, &p.dev, &p.name, "main");
    ok.file("src/ordinary-2622.txt", "ORDINARY-2622\n");
    let (_, r) = ok.push_edited("ordinary-2622", None, |_| {});
    assert_eq!(r.status, 200, "an ordinary push: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "an ordinary push is accepted: {}", String::from_utf8_lossy(&r.body));

    let refused = |what: &str, branch: &str, r: Reply, message: &str| {
        let body = String::from_utf8_lossy(&r.body).to_string();
        assert_eq!(r.status, 400, "{what}: refused: {body}");
        assert!(body.contains(message), "{what}: the refusal says why ({message}): {body}");
        assert!(!branches().contains_key(branch), "{what}: nothing was pushed");
    };
    // A file entry, and a symlink entry, naming a directory's tree.
    for (what, kind, branch) in [("a file entry naming a tree", EntryKind::File, "forge-file-2622"), ("a symlink entry naming a tree", EntryKind::Symlink, "forge-link-2622")] {
        let mut forge = Craft::new(&api, &p.dev, &p.name, "main");
        forge.set_kind("src/aaa-forged", Object::Tree(deep.clone()), kind, Visibility::Public);
        let (_, r) = forge.push_edited(branch, None, |_| {});
        refused(what, branch, r, "'src/aaa-forged': a file entry names something that is not a file's content");
    }
    // A directory entry naming a file's blob.
    {
        let mut forge = Craft::new(&api, &p.dev, &p.name, "main");
        let id = forge.put(Object::Blob(b"NOT-A-DIRECTORY-2622\n".to_vec()));
        forge.refer_dir("src/aaa-notadir", id);
        let (_, r) = forge.push_edited("forge-dir-2622", None, |_| {});
        refused("a directory entry naming a blob", "forge-dir-2622", r, "'src/aaa-notadir': a directory entry names something that is not a directory");
    }
    // A conflict entry naming a blob.
    {
        let mut forge = Craft::new(&api, &p.dev, &p.name, "main");
        forge.set_kind("src/aaa-conflict", Object::Blob(b"NOT-A-CONFLICT-2622\n".to_vec()), EntryKind::Conflict, Visibility::Public);
        let (_, r) = forge.push_edited("forge-conflict-2622", None, |_| {});
        refused("a conflict entry naming a blob", "forge-conflict-2622", r, "'src/aaa-conflict': a conflict entry names something else");
    }
    // An API commit that puts the tree, uploaded first, at a file's path.
    {
        let raw = Object::Tree(deep.clone()).encode_with(veil_core::object::TreeEncoding::Binary);
        let id = ObjectId::hash(&raw);
        let up = api.upload(&dev_tok, &p.name, &[(id, raw)]);
        assert_eq!(up.status, 200, "the upload: {}", String::from_utf8_lossy(&up.body));
        let base = branches()["main"];
        let receipt = up.json()["receipts"][0].as_str().expect("the upload's receipt").to_string();
        let r = api.post_json(
            Some(&dev_tok),
            &format!("/v1/projects/{}/changes", p.name),
            &json!({"base": base.hex(), "edits": [{"path": "src/aaa-forged", "put": {"object": id.hex()}}], "receipts": {id.hex(): receipt}}),
        );
        let body = String::from_utf8_lossy(&r.body).to_string();
        assert_eq!(r.status, 400, "an API commit putting a tree at a file's path: refused: {body}");
        assert!(body.contains("'src/aaa-forged': the object is not a file's content"), "the refusal says why: {body}");
    }
}

/// BUG-2622, GC's end: the walk kept what a tree's file entry names as a
/// leaf, never read, and took it for walked: a directory entry naming the
/// same object was then skipped. A commit whose file entry `src/aaa-forged`
/// names the tree of `src/victim/deep` (a directory of `main`) is stored
/// here directly, on a branch, as one accepted before the push checked an
/// entry's kind (the push of it is refused now): the walk met that entry
/// before the directory entry, never walked the directory, and a pass past
/// the retention window deleted its files from `main`. An object named as
/// a leaf and also as a directory is now read and expanded.
#[test]
fn bug_2622_a_file_entry_naming_a_tree_never_hides_the_trees_files_from_gc() {
    const CONTENT: &str = "VICTIM-2622-CONTENT-41c9\n";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let api = hub.api();
    let admin_tok = p.admin.token();
    let (main1, deep, blob) = victim_directory(&hub, &p, pid, CONTENT);

    // The forged commit, as a member with write access to `src/` made it.
    let mut forge = Craft::new(&api, &p.dev, &p.name, "main");
    forge.set_kind("src/aaa-forged", Object::Tree(deep), EntryKind::File, Visibility::Public);
    let mut s = Snapshot {
        parents: vec![forge.tip],
        change_id: ChangeId::random(),
        tree: forge.root,
        description: Text::Plain("forged".into()),
        author: "crafter".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        agent: None,
        abandoned: None,
        attempts: vec![],
        signature: None,
    };
    s.sign(&forge.identity);
    let forged_raw = Object::Snapshot(s).encode();
    let forged = ObjectId::hash(&forged_raw);
    // Its push is refused,
    let mut pushed = Craft::new(&api, &p.dev, &p.name, "main");
    pushed.objects = forge.objects.clone();
    pushed.root = forge.root;
    let (_, r) = pushed.push_edited("forge-2622", None, |_| {});
    assert_eq!(r.status, 400, "the forged push is refused: {}", String::from_utf8_lossy(&r.body));
    // so it is stored as it would have been: its objects, and its branch.
    for (id, raw) in forge.objects.iter().cloned().chain([(forged, forged_raw)]) {
        hub.rt.block_on(h.objects.put(pid, &id, Bytes::from(raw))).unwrap();
    }
    hub.rt
        .block_on(sqlx::query("INSERT INTO branches (project_id, name, target) VALUES ($1, 'forge-2622', $2)").bind(pid).bind(forged.hex()).execute(&h.db))
        .unwrap();

    // Two passes: marked, then past the window.
    for at in [0, 120_000] {
        let rep = gc_pass(&hub, pid, &Options { min_packs_to_merge: 1, run_gc: true, retention_window_ms: 60_000, pack_grace_ms: 0, now_offset_ms: at, ..Options::default() });
        assert!(!rep.skipped, "the pass at {at} ran: {rep:?}");
    }

    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    assert!(hub.rt.block_on(fresh.exists(pid, &blob)).unwrap(), "main's file under the directory was deleted by GC");
    let r = api.get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?rev=main&path=src/victim/deep/file.txt", p.name));
    assert_eq!(r.status, 200, "main's file: {}", String::from_utf8_lossy(&r.body).chars().take(300).collect::<String>());
    assert!(String::from_utf8_lossy(&r.body).contains(CONTENT.trim_end()), "main's file is served");
    assert_closure_stored(&hub, pid, main1, "main");
}

/// BUG-2602 (found by its review): a switch's transaction is run again when
/// it fails on an error that may pass (a lost race, a timeout), and its walk
/// had already put the objects it read into the pass's marks: run again, it
/// stopped at an object whose tree it had never read, and the tree and its
/// files stayed candidates and were deleted. A root naming a snapshot past
/// the window is written as the pass switches, and the walk's read of that
/// snapshot's tree fails once with such an error: the pass deletes nothing
/// (a walk that failed leaves no candidate), the snapshot is whole, and the
/// next pass collects.
#[test]
fn bug_2602_a_read_that_fails_in_the_switchs_walk_leaves_nothing_to_delete() {
    use veil_server::pack_gc::{Fault, FaultPoint, SwitchHook};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let admin_pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT created_by FROM projects WHERE id = $1").bind(pid).fetch_one(&h.db))
        .unwrap();
    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));

    let (dead, dead_raw) = make_blob("DEAD-LOOSE-2602-fault\n");
    hub.rt.block_on(h.objects.put(pid, &dead, dead_raw)).unwrap();
    let (snap, blob) = expiring_snapshot(&hub, &p, pid, "exp-fault", 0);
    let Object::Snapshot(s) = Object::decode(&hub.rt.block_on(h.objects.get(pid, &snap)).unwrap().expect("stored")).unwrap() else { panic!("a snapshot") };
    let tree = s.tree;

    let (writes, faults) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let hook = {
        let (db, writes, snap_hex) = (h.db.clone(), writes.clone(), snap.hex());
        SwitchHook(Arc::new(move || {
            let (db, writes, snap_hex) = (db.clone(), writes.clone(), snap_hex.clone());
            Box::pin(async move {
                if writes.fetch_add(1, Relaxed) == 0 {
                    sqlx::query("INSERT INTO change_refs (project_id, change_id, snapshot, created_by, created_at) VALUES ($1, 'chg-2602-fault', $2, $3, 1000)")
                        .bind(pid)
                        .bind(&snap_hex)
                        .bind(admin_pid)
                        .execute(&db)
                        .await
                        .unwrap();
                }
            })
        }))
    };
    let fault = {
        let (db, faults) = (h.db.clone(), faults.clone());
        Fault(Arc::new(move |at, id| {
            let (db, faults) = (db.clone(), faults.clone());
            Box::pin(async move {
                if at == FaultPoint::SwitchRead && id == tree && faults.fetch_add(1, Relaxed) == 0 {
                    // A lost race, as the database answers one.
                    let e = sqlx::query("DO $$ BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '40001'; END $$").execute(&db).await.expect_err("raises");
                    return Err(veil_server::error::Error::Db(e));
                }
                Ok(())
            })
        }))
    };
    let rep = hub
        .rt
        .block_on(pack_gc::run_project(
            &h,
            pid,
            &Options {
                min_packs_to_merge: 99,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: 120_000,
                before_switch: Some(hook),
                fault: Some(fault),
                ..Options::default()
            },
        ))
        .expect("the transaction ran again and the pass ended");
    assert!(!rep.skipped, "the pass ran: {rep:?}");
    assert_eq!(faults.load(Relaxed), 1, "the walk's read of the snapshot's tree failed once");
    assert_eq!(rep.loose_objects_deleted + rep.packed_objects_deleted, 0, "a walk that failed leaves nothing to delete: {rep:?}");
    assert!(hub.rt.block_on(fresh.exists(pid, &blob)).unwrap(), "the file of the snapshot the walk was reading is kept");
    assert_closure_stored(&hub, pid, snap, "after the failed walk");
    assert!(hub.rt.block_on(fresh.exists(pid, &dead)).unwrap(), "nothing is deleted by that pass");

    let next = hub
        .rt
        .block_on(pack_gc::run_project(
            &h,
            pid,
            &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, pack_grace_ms: 0, now_offset_ms: 240_000, ..Options::default() },
        ))
        .unwrap();
    assert!(!next.skipped, "the next pass ran: {next:?}");
    assert!(!hub.rt.block_on(fresh.exists(pid, &dead)).unwrap(), "the next pass collects what nothing names: {next:?}");
    assert_closure_stored(&hub, pid, snap, "after the next pass");
}

/// BUG-2623: a projection memo (`projections`) is written with no GC guard
/// (its writer stores the projected snapshot, then inserts the row), and its
/// table is not in the reference stamp. A memo whose snapshot is stored,
/// unreferenced and past the window, whose writer stored it before a pass
/// deleted it and committed the row after the pass's last purge, names a
/// snapshot that is gone; the server does not derive it again: it answers
/// the memo's viewer `missing object`. Here the memo of `main`'s tip for a
/// member's view loses its row (the projected snapshot stays stored and
/// passes the window), a pass deletes the snapshot, and the row is written
/// again after it, as that writer's insert would be: the member can no
/// longer read `main`'s history. (The race itself is not driven here: it
/// needs a writer held between its put and its insert.)
#[test]
#[ignore = "BUG-2623: a projection memo committed after a pass deleted its snapshot is answered 'missing object', never derived again"]
fn bug_2623_a_memo_whose_snapshot_gc_deleted_is_derived_again() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let api = hub.api();
    let dev_tok = p.dev.token();
    hub.rt.block_on(veil_server::derive::catch_up_project(&h, pid)).unwrap();
    // The member's view of main's tip: a projection (they do not see billing).
    let real = api.tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"];
    let projected = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    assert_ne!(real, projected, "the member sees a projection of main");
    let stored = |id: &ObjectId| hub.rt.block_on(h.objects.blob_store().exists(&veil_server::store::object_key(pid, id))).unwrap();
    assert!(stored(&projected), "the projected snapshot is stored loose");

    // Its memo rows go (as when a purge took them and the object stayed).
    let rows: Vec<(String, String, i64, bool)> = hub
        .rt
        .block_on(
            sqlx::query_as("DELETE FROM projections WHERE project_id = $1 AND projected_id = $2 RETURNING view_key, real_id, created_at, collapsed")
                .bind(pid)
                .bind(projected.hex())
                .fetch_all(&h.db),
        )
        .unwrap();
    assert!(!rows.is_empty(), "the projection had a memo");
    let marked = gc_pass(&hub, pid, &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, ..Options::default() });
    assert!(!marked.skipped, "the marking pass ran");

    // The pass deletes the snapshot; the memo's row is committed after the
    // pass's last purge (its writer stored the object before the delete).
    let rep = hub
        .rt
        .block_on(pack_gc::run_project(
            &h,
            pid,
            &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, pack_grace_ms: 0, now_offset_ms: 120_000, ..Options::default() },
        ))
        .unwrap();
    assert!(!rep.skipped, "the pass ran: {rep:?}");
    for (view_key, real_id, created_at, collapsed) in rows {
        hub.rt
            .block_on(
                sqlx::query("INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at, collapsed) VALUES ($1, $2, $3, $4, $5, $6)")
                    .bind(pid)
                    .bind(view_key)
                    .bind(real_id)
                    .bind(projected.hex())
                    .bind(created_at)
                    .bind(collapsed)
                    .execute(&h.db),
            )
            .unwrap();
    }
    let memo: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT count(*) FROM projections WHERE project_id = $1 AND projected_id = $2").bind(pid).bind(projected.hex()).fetch_one(&h.db))
        .unwrap();
    assert!(memo >= 1, "the memo written during the pass is there");
    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    assert!(!hub.rt.block_on(fresh.exists(pid, &projected)).unwrap(), "the pass deleted the projected snapshot (unreferenced, past the window): {rep:?}");
    // The member still reads main's history.
    let r = api.history(&dev_tok, &p.name, &[projected]);
    assert_eq!(r.status, 200, "the member's history of main: {}", String::from_utf8_lossy(&r.body).chars().take(300).collect::<String>());
    assert!(r.frames().iter().any(|(id, _)| *id == projected), "the member's history holds main's tip");
}

/// BUG-2621's review, settled: the loose switch purges the rows of every
/// candidate (`snapshots`, the derived ones) before its deletes, and a
/// snapshot named again after that purge keeps its objects. No writer can
/// name it then without recording it again: a snapshot is named by
/// resolving its id through `snapshots` (or a memo), which the purge took.
/// Between the purge and the deletes: a push of a branch to the snapshot
/// that uploads nothing, an API commit on it, and a push of a child of it
/// are each refused; a push that uploads it again is accepted, its row is
/// there again, and the pass keeps what it names.
#[test]
fn bug_2621_a_snapshot_purged_by_the_switch_is_named_again_only_by_uploading_it_again() {
    use veil_server::pack_gc::SwitchHook;
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let api = hub.api();
    let admin_tok = p.admin.token();
    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    let rows = |id: &ObjectId| -> i64 {
        hub.rt
            .block_on(sqlx::query_scalar("SELECT count(*) FROM snapshots WHERE project_id = $1 AND id = $2").bind(pid).bind(id.hex()).fetch_one(&h.db))
            .unwrap()
    };

    // A loose candidate (so the pass has a loose switch), and a snapshot
    // past the window with its objects, as its pusher holds them.
    let (dead, dead_raw) = make_blob("DEAD-LOOSE-2621-rows\n");
    hub.rt.block_on(h.objects.put(pid, &dead, dead_raw)).unwrap();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/purged-2621.txt", "PURGED-2621-CONTENT\n");
    let held = c.objects.clone();
    let (snap, r) = c.push_edited("purged-2621", None, |_| {});
    assert_eq!(r.status, 200, "push: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "push ok");
    let mut held: Vec<(ObjectId, Vec<u8>)> = held;
    held.push((snap, hub.rt.block_on(h.objects.get(pid, &snap)).unwrap().expect("stored").to_vec()));
    let del = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "purged-2621", "expected": snap.hex(), "new": null}], "force": true}),
    );
    assert_eq!(del.json()["results"][0]["ok"], json!(true), "delete the branch: {}", String::from_utf8_lossy(&del.body));
    let marked = gc_pass(&hub, pid, &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, ..Options::default() });
    assert!(!marked.skipped, "the marking pass ran");
    assert_eq!(rows(&snap), 1, "the snapshot is recorded before the pass");

    // After the switch's purge, before the deletes.
    type Tried = (&'static str, u16, String);
    let (tx, rx) = std::sync::mpsc::channel::<Vec<Tried>>();
    let calls = Arc::new(AtomicUsize::new(0));
    let hook = {
        let (authority, cert, name, token, identity, calls) = (hub.authority(), hub.cert_pem.clone(), p.name.clone(), admin_tok.clone(), p.admin.identity(), calls.clone());
        let (db, held) = (h.db.clone(), held.clone());
        SwitchHook(Arc::new(move || {
            let (authority, cert, name, token, identity, tx, db, held) = (authority.clone(), cert.clone(), name.clone(), token.clone(), identity.clone(), tx.clone(), db.clone(), held.clone());
            let first = calls.fetch_add(1, Relaxed) == 0;
            Box::pin(async move {
                if !first {
                    return;
                }
                let purged: i64 = sqlx::query_scalar("SELECT count(*) FROM snapshots WHERE project_id = $1 AND id = $2").bind(pid).bind(snap.hex()).fetch_one(&db).await.unwrap();
                let (done, tried) = tokio::sync::oneshot::channel();
                std::thread::spawn(move || {
                    let api = Api::at(&authority, &cert);
                    let push = format!("/v1/projects/{name}/push");
                    let said = |what: &'static str, r: Reply| (what, r.status, String::from_utf8_lossy(&r.body).to_string());
                    let mut out: Vec<Tried> = vec![("rows of the snapshot after the purge", purged as u16, String::new())];
                    // A branch to it, nothing uploaded.
                    out.push(said("a push naming it", api.post_json(Some(&token), &push, &json!({"updates": [{"branch": "again-a", "expected": null, "new": snap.hex()}]}))));
                    // An API commit on it.
                    out.push(said(
                        "an API commit on it",
                        api.post_json(Some(&token), &format!("/v1/projects/{name}/changes"), &json!({"base": snap.hex(), "edits": [{"path": "src/on-purged.txt", "put": {"text": "x\n"}}]})),
                    ));
                    // A child of it, the child alone uploaded.
                    let mut child = Craft::with(&api, token.clone(), identity, &name, "main");
                    child.file("src/child-of-purged.txt", "CHILD-2621\n");
                    let (_, r) = child.push_edited("again-c", None, |s| s.parents = vec![snap]);
                    out.push(said("a push of a child of it", r));
                    // It, uploaded again.
                    let up = api.upload(&token, &name, &held);
                    let receipts: serde_json::Map<String, Value> = match up.status {
                        200 => held.iter().zip(up.json()["receipts"].as_array().unwrap().clone()).map(|((id, _), r)| (id.hex(), r)).collect(),
                        _ => Default::default(),
                    };
                    out.push(said("its upload", up));
                    out.push(said(
                        "a push of it, uploaded again",
                        api.post_json(Some(&token), &push, &json!({"updates": [{"branch": "again-d", "expected": null, "new": snap.hex()}], "receipts": receipts})),
                    ));
                    let _ = tx.send(out);
                    let _ = done.send(());
                });
                let _ = tried.await;
            })
        }))
    };
    let rep = hub
        .rt
        .block_on(pack_gc::run_project(
            &h,
            pid,
            &Options { min_packs_to_merge: 1, run_gc: true, retention_window_ms: 60_000, pack_grace_ms: 0, now_offset_ms: 120_000, before_loose_delete: Some(hook), ..Options::default() },
        ))
        .unwrap();
    assert!(!rep.skipped, "the pass ran: {rep:?}");
    assert_eq!(calls.load(Relaxed), 1, "the pass committed its loose switch and reached its deletes once");
    let tried = rx.recv_timeout(Duration::from_secs(60)).expect("the writers answered");
    let of = |what: &str| tried.iter().find(|t| t.0 == what).unwrap_or_else(|| panic!("no {what}: {tried:?}")).clone();
    assert_eq!(of("rows of the snapshot after the purge").1, 0, "the switch purged the snapshot's row: {tried:?}");
    let branches = api.tips(Some(&admin_tok), &p.name).unwrap().branches;
    // Refused, each: nothing names the snapshot without recording it.
    let (_, status, body) = of("a push naming it");
    assert!(status == 400 || (status == 200 && body.contains("\"ok\":false")), "a push naming the purged snapshot without uploading it is refused: {status} {body}");
    assert!(!branches.contains_key("again-a"), "no branch was made: {body}");
    let (_, status, body) = of("an API commit on it");
    assert!((400..500).contains(&status), "an API commit on the purged snapshot is refused: {status} {body}");
    let (_, status, body) = of("a push of a child of it");
    assert!(status == 400 || (status == 200 && body.contains("\"ok\":false")), "a push of a child of the purged snapshot, the parent not uploaded, is refused: {status} {body}");
    assert!(!branches.contains_key("again-c"), "no branch was made: {body}");
    // Uploaded again: accepted, recorded again, and kept by the pass.
    let (_, status, body) = of("its upload");
    assert_eq!(status, 200, "the upload: {body}");
    let (_, status, body) = of("a push of it, uploaded again");
    assert_eq!(status, 200, "a push of the snapshot, uploaded again: {body}");
    assert!(body.contains("\"ok\":true"), "is accepted: {body}");
    assert_eq!(branches.get("again-d"), Some(&snap), "its branch is at the snapshot");
    assert_eq!(rows(&snap), 1, "the snapshot is recorded again");
    assert!(!hub.rt.block_on(fresh.exists(pid, &dead)).unwrap(), "the pass collected what nothing names: {rep:?}");
    assert_closure_stored(&hub, pid, snap, "the snapshot named again after the purge");
    let r = api.get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?rev=again-d&path=src/purged-2621.txt", p.name));
    assert_eq!(r.status, 200, "its file: {}", String::from_utf8_lossy(&r.body).chars().take(300).collect::<String>());
}

/// BUG-2602: what a switch reads from the store while root writers wait is
/// bounded (`SWITCH_WALK_MAX` objects). A root written as the pass switches
/// that names more than that gives the switch way, as any root write did
/// before: the pass deletes nothing and everything stays; the next pass
/// (which walks the root outside its switch) collects.
#[test]
fn bug_2602_a_switch_gives_way_past_its_bound_and_the_next_pass_collects() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let api = hub.api();
    let admin_tok = p.admin.token();
    let admin_pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT created_by FROM projects WHERE id = $1").bind(pid).fetch_one(&h.db))
        .unwrap();
    let exists = |id: &ObjectId| {
        let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
        hub.rt.block_on(fresh.exists(pid, id)).unwrap()
    };

    // A snapshot of more folders than the bound (a tree each to read).
    let folders = pack_gc::SWITCH_WALK_MAX + 40;
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    for i in 0..folders {
        c.file(&format!("wide/d{i}/f.txt"), &format!("WIDE-2602-{i}\n"));
    }
    let (wide, r) = c.push_edited("wide", None, |_| {});
    assert_eq!(r.status, 200, "push wide: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "push wide ok");
    let del = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "wide", "expected": wide.hex(), "new": null}], "force": true}),
    );
    assert_eq!(del.status, 200, "delete wide: {}", String::from_utf8_lossy(&del.body));
    assert_eq!(del.json()["results"][0]["ok"], json!(true), "delete wide ok");
    let (dead, dead_raw) = make_blob("DEAD-LOOSE-2602-bound\n");
    hub.rt.block_on(h.objects.put(pid, &dead, dead_raw)).unwrap();
    let marked = gc_pass(&hub, pid, &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, ..Options::default() });
    assert!(!marked.skipped, "the marking pass ran");

    let (db, wide_hex) = (h.db.clone(), wide.hex());
    let rep = pass_with_a_racing_write(&hub, pid, 120_000, move || {
        let (db, wide_hex) = (db.clone(), wide_hex.clone());
        async move {
            sqlx::query("INSERT INTO change_refs (project_id, change_id, snapshot, created_by, created_at) VALUES ($1, 'chg-2602-wide', $2, $3, 1000)")
                .bind(pid)
                .bind(&wide_hex)
                .bind(admin_pid)
                .execute(&db)
                .await
                .unwrap();
        }
    });
    assert_eq!(rep.loose_objects_deleted + rep.packed_objects_deleted, 0, "past its bound the switch gives way: nothing is deleted: {rep:?}");
    assert!(exists(&dead), "nothing is deleted by a pass that gave way");
    assert_closure_stored(&hub, pid, wide, "after the give-way");

    let next = hub
        .rt
        .block_on(pack_gc::run_project(
            &h,
            pid,
            &Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, pack_grace_ms: 0, now_offset_ms: 240_000, ..Options::default() },
        ))
        .unwrap();
    assert!(!next.skipped, "the next pass ran: {next:?}");
    assert!(!exists(&dead), "the next pass collects what nothing names: {next:?}");
    assert_closure_stored(&hub, pid, wide, "after the next pass");
}

/// BUG-2602, with real writers: one thread pushes commit after commit to a
/// branch (each a staged upload, new objects, a `snapshots` row and a
/// branch move, through the push's own guard) while GC passes past the
/// retention window run one after another. A pass collects the dead object,
/// and every commit pushed is whole afterwards (its tree, files and
/// ancestors), as is a snapshot past the window that the pusher builds on
/// while the passes run.
#[test]
fn bug_2602_gc_collects_under_pushes_of_new_commits_and_loses_nothing() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let api = hub.api();
    let admin_tok = p.admin.token();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/busy.rs", "BUSY-2602-0\n");
    let (first, r) = c.push_edited("busy", None, |_| {});
    assert_eq!(r.status, 200, "push busy: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "push busy ok");

    let (dead, dead_raw) = make_blob("DEAD-LOOSE-2602-commits\n");
    hub.rt.block_on(h.objects.put(pid, &dead, dead_raw)).unwrap();
    // Past the window when the passes run: the pusher's commits build on it.
    let (old, _) = expiring_snapshot(&hub, &p, pid, "old-2602", 0);

    let stop = Arc::new(AtomicBool::new(false));
    let pushed = Arc::new(std::sync::Mutex::new(vec![first]));
    let pusher = {
        let (authority, cert, name) = (hub.authority(), hub.cert_pem.clone(), p.name.clone());
        let (token, identity) = (admin_tok.clone(), p.admin.identity());
        let (stop, pushed) = (stop.clone(), pushed.clone());
        std::thread::spawn(move || {
            let api = Api::at(&authority, &cert);
            let mut tip = first;
            let mut n = 0;
            while !stop.load(Relaxed) {
                n += 1;
                let mut c = Craft::with(&api, token.clone(), identity.clone(), &name, "busy");
                c.file(&format!("src/busy-{}.rs", n % 7), &format!("BUSY-2602-{n}\n"));
                // Every fifth commit is a merge with the snapshot past the window.
                let (id, r) = c.push_edited("busy", Some(tip), |s| {
                    if n % 5 == 0 {
                        s.parents.push(old);
                    }
                });
                assert_eq!(r.status, 200, "steady push {n}: {}", String::from_utf8_lossy(&r.body));
                assert_eq!(r.json()["results"][0]["ok"], json!(true), "steady push {n} ok: {}", String::from_utf8_lossy(&r.body));
                tip = id;
                pushed.lock().unwrap().push(id);
            }
        })
    };
    while pushed.lock().unwrap().len() < 4 {
        std::thread::sleep(Duration::from_millis(10));
    }

    let opts = Options { min_packs_to_merge: 99, run_gc: true, retention_window_ms: 60_000, pack_grace_ms: 0, now_offset_ms: 120_000, ..Options::default() };
    let (mut collected, mut passes) = (0, 0);
    let at_start = pushed.lock().unwrap().len();
    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    for _ in 0..30 {
        let r = hub.rt.block_on(pack_gc::run_project(&h, pid, &opts)).unwrap();
        passes += 1;
        if !r.skipped && !hub.rt.block_on(fresh.exists(pid, &dead)).unwrap() {
            collected += 1;
            break;
        }
    }
    // More passes while the pushes go on, now with nothing to collect.
    for _ in 0..5 {
        hub.rt.block_on(pack_gc::run_project(&h, pid, &opts)).unwrap();
    }
    let during = pushed.lock().unwrap().len() - at_start;
    stop.store(true, Relaxed);
    pusher.join().expect("the pusher's pushes all succeeded");
    eprintln!("BUG-2602 (new commits): collected after {passes} passes; {during} pushes while GC passed");
    assert!(during > 0, "pushes ran while GC passed");
    assert_eq!(collected, 1, "a pass collects the dead object while commits are pushed");
    let pushed = pushed.lock().unwrap().clone();
    assert_closure_stored(&hub, pid, *pushed.last().unwrap(), "the last commit pushed");
    for id in &pushed {
        assert!(hub.rt.block_on(fresh.exists(pid, id)).unwrap(), "commit {id} pushed while GC passed is stored");
    }
    assert!(hub.rt.block_on(fresh.exists(pid, &old)).unwrap(), "the snapshot past the window that pushes built on is kept");
}

/// BUG-2602: every table the reference stamp covers is one the switch reads
/// again: the tables of the walk roots (`collect_db_roots`' union, built
/// from the registry), and `snapshots`, `packs` (staged uploads) and
/// `search_shards`, which it reads by name. A table stamped later must be
/// read by the switch too, or a row written as GC switches would be seen
/// (the stamp moves) and not kept.
#[test]
fn bug_2602_every_stamped_table_is_read_again_by_the_switch() {
    let mut read: Vec<&str> = pack_gc::OBJECT_SCHEMA_COLUMNS
        .iter()
        .filter(|(_, _, role)| *role == pack_gc::SchemaColumnRole::GcRoot)
        .map(|(table, _, _)| *table)
        .collect();
    read.extend(["snapshots", "packs", "search_shards"]);
    read.sort();
    read.dedup();
    let mut stamped = pack_gc::stamped_root_tables();
    stamped.sort();
    assert_eq!(stamped, read);
}

/// BUG-1782: Concurrent in-place `change_refs` target updates (`COUNT(*)`
/// unchanged), `pr_revisions` inserts/updates, and `bisects` / `bisect_reverts`
/// writes during a GC switch are detected by `read_ref_stamp`, aborting the
/// stale switch without deleting objects or purging DB rows, and subsequent GC
/// passes retain all `bisects`, `bisect_reverts`, `pr_revisions`, and
/// `change_refs` roots.
#[test]
fn bug_1782_concurrent_change_refs_pr_revisions_and_bisects_abort_gc_switch_and_preserve_roots() {
    use veil_server::pack_gc::{project_ref_stamp, SwitchHook};

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let admin_tok = p.admin.token();
    let h = hub.hub();

    let main0 = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];

    // Helper: create a branch snapshot with unique blob content, then delete the
    // branch and mark the snapshot's closure expired in `unreferenced_objects`
    // (simulating an expiring snapshot right as a concurrent feature references it).
    let make_expiring_branch_snap = |branch: &str, tag: &str| -> (ObjectId, ObjectId) {
        let mut c = Craft::new(&api, &p.admin, &p.name, "main");
        let content = format!("EXPIRING-1782-{tag}\n");
        let (blob_id, _) = make_blob(&content);
        c.file(&format!("src/{branch}.txt"), &content);
        let (_cs, r) = c.push_edited(branch, None, |_| {});
        assert_eq!(r.status, 200);
        let snap = ObjectId::from_hex(r.json()["results"][0]["tip"].as_str().unwrap()).unwrap();
        let del = api.post_json(
            Some(&admin_tok),
            &format!("/v1/projects/{}/push", p.name),
            &json!({"updates": [{"branch": branch, "expected": snap.hex(), "new": null}], "force": true}),
        );
        assert_eq!(del.status, 200);
        // Mark unreferenced at t=0 so the next pass at offset +120_000 sees it as expired.
        hub.rt
            .block_on(pack_gc::run_project(
                &h,
                pid,
                &Options {
                    min_packs_to_merge: 99,
                    run_gc: true,
                    retention_window_ms: 60_000,
                    now_offset_ms: 0,
                    ..Options::default()
                },
            ))
            .unwrap();
        (snap, blob_id)
    };

    // --- 1. In-place `change_refs` snapshot amend (`COUNT(*)` stays 1!) ---
    // Seed one `change_refs` row pointing at `main0` so `COUNT(*)` is already 1.
    let admin_pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT created_by FROM projects WHERE id = $1").bind(pid).fetch_one(&h.db))
        .unwrap();
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO change_refs (project_id, change_id, snapshot, created_by, created_at) \
                 VALUES ($1, 'chg-1782-amend', $2, $3, 1000)",
            )
            .bind(pid)
            .bind(main0.hex())
            .bind(admin_pid)
            .execute(&h.db),
        )
        .unwrap();

    let (snap_amend, blob_amend) = make_expiring_branch_snap("tmp-amend", "AMEND");
    let stamp_before = hub.rt.block_on(project_ref_stamp(&h.db, pid)).unwrap();
    let db_for_hook = h.db.clone();
    let snap_amend_hex = snap_amend.hex();
    let rep_amend = hub
        .rt
        .block_on(pack_gc::run_project(
            &h,
            pid,
            &Options {
                min_packs_to_merge: 1,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: 120_000,
                before_switch: Some(SwitchHook(Arc::new(move || {
                    let db = db_for_hook.clone();
                    let hex = snap_amend_hex.clone();
                    Box::pin(async move {
                        sqlx::query(
                            "UPDATE change_refs SET snapshot = $2 WHERE project_id = $1 AND change_id = 'chg-1782-amend'",
                        )
                        .bind(pid)
                        .bind(&hex)
                        .execute(&db)
                        .await
                        .unwrap();
                    })
                }))),
                ..Options::default()
            },
        ))
        .unwrap();
    let stamp_after = hub.rt.block_on(project_ref_stamp(&h.db, pid)).unwrap();
    assert_ne!(stamp_before, stamp_after, "in-place change_refs update must change RefStamp");
    assert_eq!(rep_amend.packed_objects_deleted, 0, "racing change_refs amend must abort GC pack switch");

    // --- 2. Concurrent `pr_revisions` write during GC switch ---
    let (snap_pr, blob_pr) = make_expiring_branch_snap("tmp-pr", "PR-REV");
    let db_for_pr = h.db.clone();
    let snap_pr_hex = snap_pr.hex();
    let main0_hex = main0.hex();
    let rep_pr = hub
        .rt
        .block_on(pack_gc::run_project(
            &h,
            pid,
            &Options {
                min_packs_to_merge: 1,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: 240_000,
                before_switch: Some(SwitchHook(Arc::new(move || {
                    let db = db_for_pr.clone();
                    let head_hex = snap_pr_hex.clone();
                    let base_hex = main0_hex.clone();
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO pr_revisions (project_id, pr, n, base, head, changes, patch, files, risk, reasons, rules_key, files_count, pushed_by, at) \
                             VALUES ($1, 'pr-1782', 1, $2, $3, $4, 'p', '[]', 'low', '[]', 'rk', 1, $5, 2000) \
                             ON CONFLICT DO NOTHING",
                        )
                        .bind(pid)
                        .bind(&base_hex)
                        .bind(&head_hex)
                        .bind(json!([{"change": "c1", "snapshot": head_hex, "parent": base_hex}]).to_string())
                        .bind(admin_pid)
                        .execute(&db)
                        .await
                        .unwrap();
                    })
                }))),
                ..Options::default()
            },
        ))
        .unwrap();
    assert_eq!(rep_pr.packed_objects_deleted, 0, "racing pr_revisions insert must abort GC pack switch");

    // Verify an in-place update to `pr_revisions` also changes `RefStamp`.
    let pr_stamp_1 = hub.rt.block_on(project_ref_stamp(&h.db, pid)).unwrap();
    hub.rt
        .block_on(
            sqlx::query("UPDATE pr_revisions SET changes = $2 WHERE project_id = $1 AND pr = 'pr-1782' AND n = 1")
                .bind(pid)
                .bind(json!([{"change": "c1-updated", "snapshot": snap_pr.hex(), "parent": main0.hex()}]).to_string())
                .execute(&h.db),
        )
        .unwrap();
    let pr_stamp_2 = hub.rt.block_on(project_ref_stamp(&h.db, pid)).unwrap();
    assert_ne!(pr_stamp_1, pr_stamp_2, "in-place pr_revisions update must change RefStamp");

    // --- 3. Concurrent `bisects` (`probes`, `candidates`) & `bisect_reverts` write during GC switch ---
    let (snap_probe, blob_probe) = make_expiring_branch_snap("tmp-probe", "BISECT-PROBE");
    let (snap_rev, blob_rev) = make_expiring_branch_snap("tmp-rev", "BISECT-REVERT");
    let db_for_bisect = h.db.clone();
    let probe_hex = snap_probe.hex();
    let rev_hex = snap_rev.hex();
    let main0_hex2 = main0.hex();
    let rep_bisect = hub
        .rt
        .block_on(pack_gc::run_project(
            &h,
            pid,
            &Options {
                min_packs_to_merge: 1,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: 360_000,
                before_switch: Some(SwitchHook(Arc::new(move || {
                    let db = db_for_bisect.clone();
                    let probe_h = probe_hex.clone();
                    let rev_h = rev_hex.clone();
                    let good_h = main0_hex2.clone();
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO bisects (project_id, branch, lineage, check_name, good, bad, candidates, lo, hi, phase, probes, culprit, culprit_parent, session_paths, revert_snapshot, created_at, updated_at) \
                             VALUES ($1, 'main', 0, 'ci/test', $2, $3, $4, 0, 0, 'searching', $5, NULL, NULL, '[]', NULL, 3000, 3000) \
                             ON CONFLICT DO NOTHING",
                        )
                        .bind(pid)
                        .bind(&good_h)
                        .bind(&probe_h)
                        .bind(json!([probe_h]).to_string())
                        .bind(json!([probe_h]).to_string())
                        .execute(&db)
                        .await
                        .unwrap();
                        sqlx::query(
                            "INSERT INTO bisect_reverts (project_id, branch, lineage, culprit, check_name, ticket, revert_snapshot, state, created_at) \
                             VALUES ($1, 'main', 0, $2, 'ci/test', 'tkt-r', $3, 'reverted', 3000) \
                             ON CONFLICT DO NOTHING",
                        )
                        .bind(pid)
                        .bind(&probe_h)
                        .bind(&rev_h)
                        .execute(&db)
                        .await
                        .unwrap();
                    })
                }))),
                ..Options::default()
            },
        ))
        .unwrap();
    assert_eq!(rep_bisect.packed_objects_deleted, 0, "racing bisects/bisect_reverts write must abort GC pack switch");

    // --- 4. Run full unhooked GC passes past retention window and verify ALL
    // roots (`change_refs`, `pr_revisions`, `bisects`, `bisect_reverts`) and
    // their blob closures remain stored! ---
    for off in [480_000i64, 600_000, 600_001] {
        hub.rt
            .block_on(pack_gc::run_project(
                &h,
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

    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    for (label, id) in [
        ("change_refs snap", snap_amend),
        ("change_refs blob", blob_amend),
        ("pr_revisions snap", snap_pr),
        ("pr_revisions blob", blob_pr),
        ("bisects probe snap", snap_probe),
        ("bisects probe blob", blob_probe),
        ("bisect_reverts snap", snap_rev),
        ("bisect_reverts blob", blob_rev),
    ] {
        assert!(
            hub.rt.block_on(fresh.exists(pid, &id)).unwrap(),
            "{label} ({id}) must be retained by pack_gc"
        );
    }
}

/// A store that pauses one read of a pack (an entry's bytes, or whether the
/// pack is there) until the test lets it go on: the moment between a lookup
/// in a pack's index and the read of that pack (BUG-1898).
struct PausedStore {
    inner: Arc<dyn veil_server::store::BlobStore>,
    /// Reads of a pack left before the one that pauses (negative: none).
    left: std::sync::atomic::AtomicI64,
    reached: std::sync::Mutex<std::sync::mpsc::Sender<()>>,
    go: tokio::sync::Notify,
}

impl PausedStore {
    async fn pack_read(&self, key: &str) {
        if key.contains("/pack/") && self.left.fetch_sub(1, Relaxed) == 0 {
            self.reached.lock().unwrap().send(()).unwrap();
            self.go.notified().await;
        }
    }
}

#[async_trait::async_trait]
impl veil_server::store::BlobStore for PausedStore {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Bytes>> {
        self.inner.get(key).await
    }
    async fn put(&self, key: &str, data: Bytes) -> anyhow::Result<()> {
        self.inner.put(key, data).await
    }
    async fn exists(&self, key: &str) -> anyhow::Result<bool> {
        self.pack_read(key).await;
        self.inner.exists(key).await
    }
    async fn len(&self, key: &str) -> anyhow::Result<Option<u64>> {
        self.inner.len(key).await
    }
    async fn get_range(&self, key: &str, start: u64, end: u64) -> anyhow::Result<Option<(Bytes, u64)>> {
        // An index is read from the pack's first byte; an entry never is.
        if start > 0 {
            self.pack_read(key).await;
        }
        self.inner.get_range(key, start, end).await
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        self.inner.list(prefix).await
    }
}

/// BUG-1898: a read listed the project's packs, found its object in one, and
/// by the time it read that pack a merge had switched to a new pack and
/// swept the old one (`pack_grace_ms: 0`; or a read that outlasts the grace
/// period). It forgot the pack, missed the loose object, and then took the
/// listing it had itself read moments before for a current one (it began
/// after the read did): "missing", for an object the merged pack holds.
/// Here every read path is stopped at exactly that moment (after its index
/// lookup, before its read of the pack) while the packs are merged and the
/// old ones deleted, on a server that has never listed the project: each
/// must answer the object, from the merged pack.
#[test]
fn bug_1898_every_read_that_finds_its_pack_merged_and_swept_reads_the_listing_again() {
    use veil_server::store::Objects;
    type Read = fn(&Objects, &tokio::runtime::Handle, i64, &ObjectId, &Bytes, &Bytes);
    fn range(o: &Objects, rt: &tokio::runtime::Handle, p: i64, id: &ObjectId, raw: &Bytes, _: &Bytes) {
        let (part, len) = rt.block_on(o.get_range(p, id, 3, 19)).expect("get_range must not fail").expect("get_range must never see a missing object");
        assert_eq!(len, raw.len() as u64);
        assert_eq!(&part[..], &raw[3..=19]);
    }
    // (name, reads of a pack before the one that is stopped, the read)
    let reads: [(&str, i64, Read); 8] = [
        ("get", 0, |o, rt, p, id, raw, _| {
            assert_eq!(&rt.block_on(o.get(p, id)).expect("get must not fail").expect("get must never see a missing object"), raw)
        }),
        ("get_many", 0, |o, rt, p, id, raw, _| {
            let got = rt.block_on(o.get_many(p, &[*id])).expect("get_many must not fail");
            assert_eq!(got[0].as_ref().expect("get_many must never see a missing object"), raw)
        }),
        ("get_encoded", 0, |o, rt, p, id, _, enc| {
            assert_eq!(&rt.block_on(o.get_encoded(p, id)).expect("get_encoded must not fail").expect("get_encoded must never see a missing object"), enc)
        }),
        ("get_blocking", 0, |o, rt, p, id, raw, _| {
            assert_eq!(&o.get_blocking(rt, p, id).expect("get_blocking must not fail").expect("get_blocking must never see a missing object"), raw)
        }),
        ("get_ephemeral_blocking", 0, |o, rt, p, id, raw, _| {
            assert_eq!(&o.get_ephemeral_blocking(rt, p, id).expect("get_ephemeral_blocking must not fail").expect("get_ephemeral_blocking must never see a missing object"), raw)
        }),
        // Stopped at the read of the entry's first bytes, then at the read
        // of the range itself.
        ("get_range (its head)", 0, range),
        ("get_range (its bytes)", 1, range),
        ("exists", 0, |o, rt, p, id, _, _| assert!(rt.block_on(o.exists(p, id)).expect("exists must not fail"), "exists must never see a missing object")),
    ];

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let listed = || -> Vec<String> {
        hub.rt
            .block_on(
                sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND state = $2 ORDER BY created_at, name")
                    .bind(pid)
                    .bind(LISTED)
                    .fetch_all(&h.db),
            )
            .unwrap()
    };
    let opts = Options { min_packs_to_merge: 2, run_gc: false, pack_grace_ms: 0, ..Options::default() };

    for (i, (name, before_pause, read)) in reads.into_iter().enumerate() {
        // A push: one more small listed pack beside what the last merge left.
        write_files(&p.dir, &[(&format!("src/b1898_{i}.txt"), &format!("bug-1898 {i} {}\n", unique("q")))]);
        p.admin.commit_main(&p.dir, &format!("bug 1898, push {i}"));
        p.admin.ok(&p.dir, &["push"]);
        let old = listed();
        assert!(old.len() >= 2, "{name}: {} listed packs to merge", old.len());

        // An object of the newest pack that is stored as it is (so a ranged
        // read reads the pack for those bytes), with what it must read as.
        let newest = pack::key(pid, old.last().unwrap());
        let index = hub.rt.block_on(pack::read_index(&**h.objects.blob_store(), &newest, h.objects.index_bound())).unwrap().expect("the pushed pack is stored");
        let (id, raw, enc) = index
            .index
            .iter()
            .find_map(|(id, _)| {
                let enc = hub.rt.block_on(h.objects.get_encoded(pid, id)).unwrap()?;
                let raw = hub.rt.block_on(h.objects.get(pid, id)).unwrap()?;
                (!veil_core::hub::encoding::is_compressed(&enc) && raw.len() > 20).then_some((*id, raw, enc))
            })
            .unwrap_or_else(|| panic!("{name}: the pushed pack holds an object stored as it is"));
        drop(index);

        // A server that has never listed this project reads it, and stops
        // between its lookup in the old pack's index and its read of it.
        let (reached, at_the_read) = std::sync::mpsc::channel();
        let store = Arc::new(PausedStore {
            inner: h.objects.blob_store().clone(),
            left: std::sync::atomic::AtomicI64::new(before_pause),
            reached: std::sync::Mutex::new(reached),
            go: tokio::sync::Notify::new(),
        });
        let objects = Objects::with_db(store.clone(), 1 << 10, Some(h.db.clone()));
        let rt = hub.rt.handle().clone();
        let reader = std::thread::spawn(move || read(&objects, &rt, pid, &id, &raw, &enc));
        at_the_read
            .recv_timeout(Duration::from_secs(120))
            .unwrap_or_else(|_| panic!("{name}: the read never reached the pack (did it fail? {})", reader.is_finished()));

        // Meanwhile the packs are merged, and the old ones deleted at once.
        let r = hub.rt.block_on(pack_gc::run_project(&h, pid, &opts)).unwrap();
        assert_eq!(r.packs_merged, old.len(), "{name}: every listed pack was merged");
        assert_eq!(r.discarded_packs_swept, old.len(), "{name}: every replaced pack was swept");
        assert!(!hub.rt.block_on(h.objects.blob_store().exists(&newest)).unwrap(), "{name}: the pack the reader found is gone from the store");
        assert_eq!(listed().len(), 1, "{name}: one merged pack is listed");

        store.go.notify_one();
        if let Err(e) = reader.join() {
            let why = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            panic!("{name}, racing a merge and its sweep: {why}");
        }
    }
}
