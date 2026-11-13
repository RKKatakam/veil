//! BUG-2230: a push's pack is merged in the background once a project's
//! small listed packs reach `MERGE_MIN_PACKS` (`pack_gc::maybe_schedule`,
//! called by every push that lists a pack), so the packs a lookup searches
//! stay bounded under continuous pushes; BUG-2270: a merge whose staged
//! replacement another server discarded meanwhile gives way instead of
//! replacing the old packs by nothing; BUG-2280: the packs a merge replaced,
//! and a crashed merge's staged pack, are swept with no push since.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use veil_core::{object::Object, ObjectId};
use veil_server::{
    pack::LISTED,
    pack_gc::{self, CrashPoint, Options, SwitchHook, MERGE_MIN_PACKS, SMALL_PACK_BYTES},
};

use crate::{limits::project_id_of, support::*};

fn tip_of(api: &Api, token: &str, project: &str, branch: &str) -> Option<ObjectId> {
    api.tips(Some(token), project).unwrap().branches.get(branch).copied()
}

/// Push one new file to `branch`: the new snapshot.
fn push_file(api: &Api, p: &Project, branch: &str, path: &str) -> ObjectId {
    let tok = p.admin.token();
    let had = tip_of(api, &tok, &p.name, branch);
    let mut c = Craft::new(api, &p.admin, &p.name, if had.is_some() { branch } else { "main" });
    c.file(path, &format!("{path}\n"));
    let (id, r) = c.push_edited(branch, had, |_| {});
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    id
}

/// `project`'s small listed packs and its discarded ones.
fn small_and_discarded(hub: &TestHub, project: i64) -> (i64, i64) {
    hub.rt
        .block_on(
            sqlx::query_as::<_, (i64, i64)>(
                "SELECT count(*) FILTER (WHERE state = 1 AND size <= $2), count(*) FILTER (WHERE state = 2) FROM packs WHERE project_id = $1",
            )
            .bind(project)
            .bind(SMALL_PACK_BYTES as i64)
            .fetch_one(&hub.hub().db),
        )
        .unwrap()
}

/// Every one of `ids` read through `hub`'s object store: none may be missing.
fn read_all(hub: &TestHub, project: i64, ids: &[ObjectId], when: &str) {
    let h = hub.hub();
    let got = hub.rt.block_on(h.objects.get_many(project, ids)).expect("the objects are read");
    for (id, g) in ids.iter().zip(&got) {
        assert!(g.is_some(), "{when}: object {} missing", id.hex());
    }
}

/// Three agents push 100 times each to branches of their own, while
/// readers on this server and on a second one read every snapshot pushed
/// so far, again and again, and the second server runs merges of its own
/// (once the first server merged in the background)
/// that sweep replaced packs at once (no grace period): the small listed
/// packs stay bounded throughout (each push lists one; nobody runs a merge
/// on the first server), the background merges ran, and no read ever
/// missed an object.
#[test]
fn bug_2230_background_merging_keeps_packs_bounded_and_readers_never_miss() {
    let hub = TestHub::start();
    let other = TestHub::beside(&hub);
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let pushed: Mutex<Vec<ObjectId>> = Mutex::new(Vec::new());
    let done = AtomicBool::new(false);
    let most_small = Mutex::new(0i64);
    let reads = Mutex::new(0usize);
    const AGENTS: usize = 3;
    const PUSHES: usize = 100;
    std::thread::scope(|s| {
        let pushers: Vec<_> = (0..AGENTS)
            .map(|a| {
                let (hub, p, pushed) = (&hub, &p, &pushed);
                s.spawn(move || {
                    let api = hub.api();
                    for i in 0..PUSHES {
                        let id = push_file(&api, p, &format!("agent-{a}"), &format!("src/a{a}/p{i}.txt"));
                        pushed.lock().unwrap().push(id);
                    }
                })
            })
            .collect();
        for server in [&hub, &other] {
            let (pushed, done, reads) = (&pushed, &done, &reads);
            s.spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    let ids = pushed.lock().unwrap().clone();
                    read_all(server, pid, &ids, "while pushing and merging");
                    *reads.lock().unwrap() += 1;
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
        }
        {
            let (hub, other, done) = (&hub, &other, &done);
            s.spawn(move || {
                let oh = other.hub();
                let opts = Options { min_packs_to_merge: MERGE_MIN_PACKS, pack_grace_ms: 0, ..Options::merge_only() };
                // Only once the first server merged in the background: run
                // from the start, these merges did its work before its task
                // had its turn (on YugabyteDB, no background merge at all).
                while !done.load(Ordering::SeqCst) && hub.hub().pack_gc.background_merges.load(Ordering::Relaxed) == 0 {
                    std::thread::sleep(Duration::from_millis(50));
                }
                while !done.load(Ordering::SeqCst) {
                    other.rt.block_on(pack_gc::run_project(&oh, pid, &opts)).expect("the second server's merge runs");
                    std::thread::sleep(Duration::from_millis(300));
                }
            });
        }
        {
            let (hub, done, most_small) = (&hub, &done, &most_small);
            s.spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    let (small, _) = small_and_discarded(hub, pid);
                    let mut m = most_small.lock().unwrap();
                    *m = (*m).max(small);
                    drop(m);
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
        }
        for t in pushers {
            t.join().expect("the pushes succeed");
        }
        // The last pushes' packs get counted after the check gap.
        let until = Instant::now() + Duration::from_secs(30);
        while small_and_discarded(&hub, pid).0 >= MERGE_MIN_PACKS as i64 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        done.store(true, Ordering::SeqCst);
    });
    let ids = pushed.into_inner().unwrap();
    assert_eq!(ids.len(), AGENTS * PUSHES, "every push succeeded");
    let merges = hub.hub().pack_gc.background_merges.load(Ordering::Relaxed);
    assert!(merges >= 1, "the first server merged in the background ({merges} merges)");
    let (small, discarded) = small_and_discarded(&hub, pid);
    let most = most_small.into_inner().unwrap();
    assert!(*reads.lock().unwrap() >= 4, "the readers read while the pushes went on");
    assert!(small < MERGE_MIN_PACKS as i64, "{small} small packs still listed after the pushes ({discarded} discarded)");
    assert!(
        most <= 2 * MERGE_MIN_PACKS as i64,
        "the small listed packs stayed bounded under {} pushes: at most {most}",
        AGENTS * PUSHES
    );
    read_all(&hub, pid, &ids, "after the pushes");
    read_all(&other, pid, &ids, "after the pushes, the second server");
}

/// BUG-2270: a merge's switch replaced the old packs by its staged pack
/// without checking the staged pack was still its own. Another server that
/// took the project's lock after this run's lock session ended discards a
/// staged job pack as an interrupted run's (`sweep_staged`), bytes and all;
/// the switch then turned the old packs discarded with nothing listed in
/// their place, and their objects were lost once swept. Here the discard
/// happens right before the switch: the switch gives way, the old packs
/// stay listed and every object is read; a later run merges them.
#[test]
fn bug_2270_a_merge_whose_staged_pack_was_discarded_gives_way() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let h = hub.hub();
    let mut ids = Vec::new();
    for i in 0..4 {
        let raw = Bytes::from(Object::Blob(format!("BUG-2270 object {i}").into_bytes()).encode());
        let id = ObjectId::hash(&raw);
        ids.push(id);
        let enc = veil_server::store::encode(raw);
        hub.rt.block_on(async {
            let (name, held) = h.objects.put_pack(pid, 1, vec![(id, enc)]).await.expect("the pack is stored");
            let r = sqlx::query("UPDATE packs SET state = $3 WHERE project_id = $1 AND name = $2")
                .bind(pid)
                .bind(&*name)
                .bind(LISTED)
                .execute(&h.db)
                .await
                .expect("the pack is listed");
            assert_eq!(r.rows_affected(), 1);
            h.objects.listed_here(pid, vec![(name, held.index.clone())]);
        });
    }
    read_all(&hub, pid, &ids, "before the merge");
    let listed = |hub: &TestHub| -> i64 {
        hub.rt
            .block_on(sqlx::query_scalar("SELECT count(*) FROM packs WHERE project_id = $1 AND state = $2").bind(pid).bind(LISTED).fetch_one(&hub.hub().db))
            .unwrap()
    };
    let before = listed(&hub);
    // What `sweep_staged` on a server that took the lock does: discard
    // every staged job pack.
    let hk = h.clone();
    let discarded = Arc::new(Mutex::new(0usize));
    let d = discarded.clone();
    let hook = SwitchHook(Arc::new(move || {
        let (hk, d) = (hk.clone(), d.clone());
        Box::pin(async move {
            let names: Vec<String> = sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND state = 0 AND person_id IS NULL")
                .bind(pid)
                .fetch_all(&hk.db)
                .await
                .unwrap();
            let arcs: Vec<Arc<str>> = names.iter().map(|n| Arc::from(n.as_str())).collect();
            hk.objects.discard(pid, &arcs).await.expect("the staged job pack is discarded");
            *d.lock().unwrap() += arcs.len();
        })
    }));
    let opts = Options { pack_grace_ms: 0, before_switch: Some(hook), ..Options::merge_only() };
    let rep = hub.rt.block_on(pack_gc::run_project(&h, pid, &opts)).expect("the merge runs");
    assert!(!rep.skipped, "{rep:?}");
    assert_eq!(*discarded.lock().unwrap(), 1, "the merge staged one pack, which was discarded before its switch");
    assert_eq!(rep.packs_merged, 0, "the switch gave way: {rep:?}");
    assert_eq!(listed(&hub), before, "the old packs stay listed");
    read_all(&hub, pid, &ids, "after the merge that gave way");
    let fresh = TestHub::beside(&hub);
    read_all(&fresh, pid, &ids, "after the merge that gave way, another server");
    // A later run merges them.
    let rep = hub.rt.block_on(pack_gc::run_project(&h, pid, &Options { pack_grace_ms: 0, ..Options::merge_only() })).expect("the merge runs");
    assert!(rep.packs_merged >= 4, "{rep:?}");
    read_all(&hub, pid, &ids, "after the merge");
    read_all(&fresh, pid, &ids, "after the merge, another server");
}

/// The names of `project`'s packs in `state`, and of its merges' staged
/// packs when `state` is `STAGED` (`person_id IS NULL`).
fn pack_names(hub: &TestHub, project: i64, state: i16) -> Vec<String> {
    hub.rt
        .block_on(
            sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND state = $2 AND (state <> 0 OR person_id IS NULL) ORDER BY name")
                .bind(project)
                .bind(state)
                .fetch_all(&hub.hub().db),
        )
        .unwrap()
}

/// Whether pack `name` of `project` is still in storage.
fn stored(hub: &TestHub, project: i64, name: &str) -> bool {
    let h = hub.hub();
    hub.rt.block_on(h.objects.blob_store().exists(&veil_server::pack::key(project, name))).expect("storage answers")
}

/// BUG-2280: the packs a background merge replaced are deleted once their
/// grace period has passed, with no push since: a merging pass starts a
/// sweeper (`pack_gc::schedule_sweep`) that looks again at least every
/// `SWEEP_RECHECK` and sweeps what is due. Here the grace period is made
/// to pass at once (the discarded rows aged): their rows and storage
/// objects go, and every snapshot pushed is still read, on this server and
/// a fresh one.
#[test]
fn bug_2280_packs_a_background_merge_replaced_are_deleted_after_the_grace_period() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let mut pushed = Vec::new();
    for i in 0..MERGE_MIN_PACKS + 8 {
        pushed.push(push_file(&api, &p, "quiet", &format!("src/q{i}.txt")));
    }
    let h = hub.hub();
    let until = Instant::now() + Duration::from_secs(30);
    while (h.pack_gc.background_merges.load(Ordering::Relaxed) == 0 || small_and_discarded(&hub, pid).0 >= MERGE_MIN_PACKS as i64)
        && Instant::now() < until
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(h.pack_gc.background_merges.load(Ordering::Relaxed) >= 1, "the pushes started a background merge");
    let (small, discarded) = small_and_discarded(&hub, pid);
    assert!(small < MERGE_MIN_PACKS as i64, "{small} small packs still listed");
    assert!(discarded >= pack_gc::TIER_MIN_PACKS as i64, "the merges replaced the pushes' packs: {discarded} discarded");
    let replaced = pack_names(&hub, pid, 2);
    assert!(replaced.iter().all(|n| stored(&hub, pid, n)), "the replaced packs are stored through their grace period");
    // The grace period passes (as it does a minute later).
    let aged = hub
        .rt
        .block_on(
            sqlx::query("UPDATE packs SET discarded_at = discarded_at - $2 WHERE project_id = $1 AND state = 2")
                .bind(pid)
                .bind(2 * pack_gc::DEFAULT_PACK_GRACE_MS)
                .execute(&h.db),
        )
        .expect("the discarded rows are aged");
    assert_eq!(aged.rows_affected() as i64, discarded);
    let until = Instant::now() + pack_gc::SWEEP_RECHECK + Duration::from_secs(20);
    while small_and_discarded(&hub, pid).1 > 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(500));
    }
    let (_, left) = small_and_discarded(&hub, pid);
    assert_eq!(left, 0, "{left} replaced packs still stored after their grace period, with no push since");
    assert!(h.pack_gc.sweeps.load(Ordering::Relaxed) >= 1, "the sweeper swept");
    for n in &replaced {
        assert!(!stored(&hub, pid, n), "replaced pack {n} still in storage");
    }
    read_all(&hub, pid, &pushed, "after the sweep");
    let fresh = TestHub::beside(&hub);
    read_all(&fresh, pid, &pushed, "after the sweep, another server");
}

/// BUG-2280: a merge interrupted after writing its staged pack, before its
/// switch (a server stopped), leaves the pack staged; another server's
/// look at start-up (`pack_gc::projects_to_sweep`, then `schedule_sweep`,
/// as `sweep_scan` does) finds the project and sweeps it with no push
/// since: the staged pack is discarded (its storage object deleted at
/// once), its row deleted once the grace period has passed, and the packs
/// listed are untouched (every object read on both servers).
#[test]
fn bug_2280_a_crashed_merges_staged_pack_is_swept_without_a_push() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let h = hub.hub();
    let mut ids = Vec::new();
    for i in 0..4 {
        let raw = Bytes::from(Object::Blob(format!("BUG-2280 object {i}").into_bytes()).encode());
        let id = ObjectId::hash(&raw);
        ids.push(id);
        let enc = veil_server::store::encode(raw);
        hub.rt.block_on(async {
            let (name, held) = h.objects.put_pack(pid, 1, vec![(id, enc)]).await.expect("the pack is stored");
            let r = sqlx::query("UPDATE packs SET state = $3 WHERE project_id = $1 AND name = $2")
                .bind(pid)
                .bind(&*name)
                .bind(LISTED)
                .execute(&h.db)
                .await
                .expect("the pack is listed");
            assert_eq!(r.rows_affected(), 1);
            h.objects.listed_here(pid, vec![(name, held.index.clone())]);
        });
    }
    let listed_before = pack_names(&hub, pid, LISTED);
    assert!(listed_before.len() >= 4, "{listed_before:?}");
    let crash = Options { crash: Some(CrashPoint::AfterWriteBeforeSwitch), ..Options::merge_only() };
    let rep = hub.rt.block_on(pack_gc::run_project(&h, pid, &crash)).expect("the merge runs");
    assert!(!rep.skipped, "{rep:?}");
    assert_eq!(rep.packs_merged, 0, "the merge stopped before its switch: {rep:?}");
    let staged = pack_names(&hub, pid, 0);
    assert_eq!(staged.len(), 1, "the interrupted merge left its pack staged");
    assert!(stored(&hub, pid, &staged[0]), "the staged pack was written");
    // Another server starts.
    let fresh = TestHub::beside(&hub);
    let f = fresh.hub();
    let due = fresh.rt.block_on(pack_gc::projects_to_sweep(&f)).expect("the look runs");
    assert!(due.contains(&pid), "the start-up look finds the project");
    fresh.rt.block_on(async { pack_gc::schedule_sweep(&f, pid) });
    let until = Instant::now() + pack_gc::SWEEP_RECHECK + Duration::from_secs(20);
    while (!pack_names(&hub, pid, 0).is_empty() || stored(&hub, pid, &staged[0])) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(pack_names(&hub, pid, 0).is_empty(), "the staged pack is no longer staged");
    assert!(!stored(&hub, pid, &staged[0]), "the staged pack's storage object is deleted");
    assert_eq!(pack_names(&hub, pid, 2), staged, "its row is discarded, kept for the grace period");
    // The grace period passes: the row goes.
    let aged = hub
        .rt
        .block_on(
            sqlx::query("UPDATE packs SET discarded_at = discarded_at - $2 WHERE project_id = $1 AND state = 2")
                .bind(pid)
                .bind(2 * pack_gc::DEFAULT_PACK_GRACE_MS)
                .execute(&h.db),
        )
        .expect("the discarded row is aged");
    assert_eq!(aged.rows_affected(), 1);
    let until = Instant::now() + pack_gc::SWEEP_RECHECK + Duration::from_secs(20);
    while !pack_names(&hub, pid, 2).is_empty() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(pack_names(&hub, pid, 2).is_empty(), "the discarded row is deleted after its grace period");
    assert!(f.pack_gc.sweeps.load(Ordering::Relaxed) >= 2, "the other server's sweeper swept twice");
    assert_eq!(pack_names(&hub, pid, LISTED), listed_before, "the listed packs are untouched");
    read_all(&hub, pid, &ids, "after the sweep");
    read_all(&fresh, pid, &ids, "after the sweep, another server");
    // Nothing is left to sweep: the sweeper stopped and the look finds nothing.
    let due = fresh.rt.block_on(pack_gc::projects_to_sweep(&f)).expect("the look runs");
    assert!(!due.contains(&pid), "nothing of the project is left to sweep");
}
