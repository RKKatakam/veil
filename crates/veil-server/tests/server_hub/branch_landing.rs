//! BUG-2221: many agents, each pushing to a branch of its own and landing
//! it on `main` every few pushes, slowed down over minutes. Each landing
//! asked the derived graph, for every snapshot of the branch down to where
//! it left `main`, whether it is below `main`'s tip; none is (each landed
//! as a rebased copy), and each answer walked every snapshot of `main`
//! newer than it. Now a snapshot found not below a tip is remembered so,
//! the next walk for it stops at that tip, and one walk serves a submit's
//! questions. Each test here is one guarantee of the fix.

use std::sync::atomic::Ordering;

use serde_json::json;
use veil_core::ObjectId;

use crate::{limits::project_id_of, support::*};

fn tip_of(api: &Api, token: &str, project: &str, branch: &str) -> Option<ObjectId> {
    api.tips(Some(token), project).unwrap().branches.get(branch).copied()
}

/// The derived graph holds `snapshot` (as the deriver makes it after a
/// landing), so that the landing's questions go to it.
fn derive(hub: &TestHub, pid: i64, snapshot: ObjectId) {
    let h = hub.hub();
    hub.rt.block_on(veil_server::derive::ensure(&h, pid, snapshot)).expect("the snapshot is derived");
}

/// Push one new file to `branch` (made from `main`'s tip when new); the
/// new snapshot.
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

/// Land `snapshot` (on a branch) on `main`: the answer, which must be `landed`.
fn land_on_main(api: &Api, p: &Project, snapshot: ObjectId) -> serde_json::Value {
    let r = api.post_json(Some(&p.admin.token()), &format!("/v1/projects/{}/land", p.name), &json!({"onto": "main", "snapshot": snapshot.hex()}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let v = r.json();
    assert_eq!(v["state"], "landed", "{v}");
    v
}

/// An agent pushes two files to its branch and lands it on `main`, eight
/// times; between its landings `main` gains 30 other landings. With
/// `behind`, the derived graph loses those 30 before each of the agent's
/// landings (as when the deriver is a few landings behind `main`'s tip).
/// The graph rows each of the agent's landings read.
fn landed_again_and_again(hub: &TestHub, p: &Project, behind: bool) -> Vec<u64> {
    let pid = project_id_of(hub, &p.name);
    let api = hub.api();
    let tok = p.admin.token();
    let h = hub.hub();
    let stats = || h.landing.stats.graph_reads.load(Ordering::Relaxed);
    let mut reads = Vec::new();
    let mut gained: Vec<String> = Vec::new();
    for round in 0..8 {
        let mut snap = ObjectId([0; 32]);
        for k in 0..2 {
            snap = push_file(&api, p, "agent-1", &format!("src/agent/f{round}-{k}.txt"));
        }
        let main = tip_of(&api, &tok, &p.name, "main").unwrap();
        derive(hub, pid, main);
        if behind && !gained.is_empty() {
            hub.rt.block_on(sqlx::query("DELETE FROM graph WHERE project_id = $1 AND snapshot = ANY($2)").bind(pid).bind(&gained).execute(&h.db)).unwrap();
            h.derive.clear_cache();
            let held = hub.rt.block_on(veil_server::derive::read(&h, pid, move |g| Ok(g.row(&main)?.is_some()))).unwrap();
            assert!(!held, "the graph does not hold main's tip");
        }
        let before = stats();
        let v = land_on_main(&api, p, snap);
        reads.push(stats() - before);
        // Only this round's two changes land: the earlier ones are skipped
        // as landed already.
        assert_eq!(v["landed"].as_array().map(Vec::len), Some(2), "round {round}: {v}");
        gained.clear();
        for n in 0..30 {
            let base = tip_of(&api, &tok, &p.name, "main").unwrap();
            let r = crate::limits::land_edit(&api, &tok, &p.name, base, &format!("src/main/r{round}-{n}.txt"), "x\n", true);
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            let v = r.json();
            assert_eq!(v["state"], "landed", "{v}");
            gained.push(v["landed"].as_array().unwrap().last().unwrap().as_str().unwrap().to_string());
        }
    }
    reads
}

/// BUG-2221: a branch landed on `main` again and again reads, at each
/// landing, about what `main` gained since its last one, not `main`'s
/// whole history since the branch left it. Before the fix the eighth
/// landing read every snapshot of `main` newer than each of the branch's
/// 16 snapshots (about 2,000 rows); now about the 32 `main` gained.
#[test]
fn bug_2221_a_branch_landed_again_and_again_reads_only_what_main_gained_since() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let reads = landed_again_and_again(&hub, &p, false);
    // Every landing after the first reads what main gained since the one
    // before (30 landings and the 2 copies), each twice at most (the new
    // snapshots' walk and the remembered ones'), whatever the history.
    for (round, n) in reads.iter().enumerate().skip(1) {
        assert!(*n <= 2 * 32 + 8, "landing {round} of the branch read {n} graph rows: {reads:?}");
    }
}

/// BUG-2221, with the deriver behind `main`'s tip (it is, most of the time,
/// under many landings): the part of `main` it does not hold yet is read
/// from the store down to where the graph holds it, once per submit, and
/// the graph answers below that, with the same answers (each landing
/// brings exactly its own two changes) and as little read: before, a
/// submit read up to 4,096 snapshots of `main` from the store, then asked
/// the graph from the snapshot it stopped at.
#[test]
fn bug_2221_with_the_deriver_behind_a_branch_landing_reads_only_what_main_gained_since() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let reads = landed_again_and_again(&hub, &p, true);
    for (round, n) in reads.iter().enumerate().skip(1) {
        assert!(*n <= 2 * 32 + 8, "landing {round} of the branch read {n} graph rows: {reads:?}");
    }
}

/// BUG-2221: a remembered "not below" is only ever a shortcut: whatever was
/// asked before and in whatever order, `is_below` answers as
/// `is_ancestor` does, for every pair of snapshots of a history with
/// merges, crossing lines and timestamps out of order; and a snapshot found
/// not below `main` once is below it after `main` merges it. Several
/// starting points too (below any one of them).
#[test]
fn bug_2221_is_below_answers_as_is_ancestor_whatever_was_remembered() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let tok = p.admin.token();
    let base = tip_of(&api, &tok, &p.name, "main").unwrap();
    // 36 snapshots, each on a branch of its own, with one or two parents
    // among the earlier ones (a fixed seed), timestamps jittered by up to
    // a minute either way.
    let mut seed = 0x2221_u64;
    let mut next = |n: u64| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) % n
    };
    let mut all = vec![base];
    for i in 0..36 {
        let a = all[next(all.len() as u64) as usize];
        let b = all[next(all.len() as u64) as usize];
        let parents = if i % 3 == 2 && a != b { vec![a, b] } else { vec![a] };
        let jitter = next(120_000) as i64 - 60_000;
        let c = Craft::new(&api, &p.admin, &p.name, "main");
        let (id, r) = c.push_edited(&format!("dag-{i}"), None, |s| {
            s.parents = parents;
            s.timestamp += jitter;
        });
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
        derive(&hub, pid, id);
        all.push(id);
    }
    let h = hub.hub();
    let pairs = all.clone();
    let (checked, below) = hub
        .rt
        .block_on(veil_server::derive::read(&h, pid, move |g| {
            let (mut checked, mut below) = (0, 0);
            // Twice over: the second pass finds the first's facts remembered.
            for pass in 0..2 {
                for (i, t) in pairs.iter().enumerate() {
                    let mut walks = Vec::new();
                    // Every snapshot asked against tip `t`, newest first then
                    // oldest first, sharing one submit's walks.
                    let order: Vec<&ObjectId> = if (i + pass) % 2 == 0 { pairs.iter().rev().collect() } else { pairs.iter().collect() };
                    for x in order {
                        let want = g.is_ancestor(*x, *t)?;
                        assert_eq!(g.is_below(&mut walks, *x, &[*t])?, want, "pass {pass}: is {} below {}", x.short(), t.short());
                        checked += 1;
                        below += want as usize;
                    }
                }
            }
            // Several starting points (the frontier the landing asks the
            // graph about while the deriver is behind): below any of them.
            for (i, t) in pairs.iter().enumerate() {
                let u = pairs[(i * 7 + 3) % pairs.len()];
                let mut walks = Vec::new();
                for x in pairs.iter().rev() {
                    let want = g.is_ancestor(*x, *t)? || g.is_ancestor(*x, u)?;
                    assert_eq!(g.is_below(&mut walks, *x, &[*t, u])?, want, "is {} below {} or {}", x.short(), t.short(), u.short());
                }
            }
            Ok((checked, below))
        }))
        .expect("the graph answers");
    assert_eq!(checked, 2 * all.len() * all.len());
    assert!(below > all.len() * 2 && below < checked, "{below} of {checked} below: the history has both answers");

    // A snapshot of a branch found not below main, then merged into main.
    let x = push_file(&api, &p, "side", "src/side/one.txt");
    let main = tip_of(&api, &tok, &p.name, "main").unwrap();
    derive(&hub, pid, x);
    let asked = hub.rt.block_on(veil_server::derive::read(&h, pid, move |g| g.is_below(&mut Vec::new(), x, &[main]))).unwrap();
    assert!(!asked, "the branch's snapshot is not below main yet");
    let c = Craft::new(&api, &p.admin, &p.name, "main");
    let r = c.push_merge("main", &[x]);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let merged = tip_of(&api, &tok, &p.name, "main").unwrap();
    assert_ne!(merged, main);
    derive(&hub, pid, merged);
    let now = hub.rt.block_on(veil_server::derive::read(&h, pid, move |g| g.is_below(&mut Vec::new(), x, &[merged]))).unwrap();
    assert!(now, "a snapshot merged into main is below it, though it was not below main's earlier tip");
    // And a landing of the branch on main now brings only its new change.
    let y = push_file(&api, &p, "side", "src/side/two.txt");
    derive(&hub, pid, merged);
    let v = land_on_main(&api, &p, y);
    assert_eq!(v["landed"].as_array().map(Vec::len), Some(1), "{v}");
}

/// BUG-2230: under the many-branch headline every push's pack stays listed
/// (about 78,000 after 10 minutes at 300 agents), and each object lookup
/// that misses the newest packs probes every pack's index
/// (`pack::Packs::find_in`, 28 % of the server's CPU at 560 s) while each
/// listing reads every row: S29's background merge
/// (`pack_gc::maybe_schedule`, HUB §13.37) was never called. Once a
/// project's small listed packs reach `MERGE_MIN_PACKS`, the server merges
/// them in the background, without anyone running it.
#[test]
fn bug_2230_small_packs_are_merged_in_the_background_once_they_pile_up() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let h = hub.hub();
    let counts = || {
        hub.rt
            .block_on(
                sqlx::query_as::<_, (i64, i64)>(
                    "SELECT count(*) FILTER (WHERE state = 1 AND size <= $2), count(*) FILTER (WHERE state = 2) FROM packs WHERE project_id = $1",
                )
                .bind(pid)
                .bind(veil_server::pack_gc::SMALL_PACK_BYTES as i64)
                .fetch_one(&h.db),
            )
            .unwrap()
    };
    let pushes = veil_server::pack_gc::MERGE_MIN_PACKS + 8;
    for i in 0..pushes {
        push_file(&hub.api(), &p, "agent-1", &format!("src/agent/p{i}.txt"));
    }
    let (small, discarded) = counts();
    assert!(small + discarded >= pushes as i64, "each push listed a pack: {small} small listed, {discarded} discarded");
    let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let (mut small, mut discarded) = (small, discarded);
    while (small >= veil_server::pack_gc::MERGE_MIN_PACKS as i64 || discarded == 0) && std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_millis(200));
        (small, discarded) = counts();
    }
    assert!(discarded > 0, "no pack was merged within 30 s of {pushes} pushes ({small} small packs listed)");
    assert!(small < veil_server::pack_gc::MERGE_MIN_PACKS as i64, "{small} small packs still listed after the merges");
}

/// Push `n` snapshots to `p`, each on a branch of its own, with one or two
/// parents among the earlier ones (and `main`'s tip), timestamps jittered
/// by up to a minute either way; each derived. Every snapshot, `main`'s
/// tip first.
fn random_dag(hub: &TestHub, p: &Project, seed: u64, n: usize) -> Vec<ObjectId> {
    let pid = project_id_of(hub, &p.name);
    let api = hub.api();
    let tok = p.admin.token();
    let mut seed = seed;
    let mut next = |m: u64| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) % m
    };
    let mut all = vec![tip_of(&api, &tok, &p.name, "main").unwrap()];
    for i in 0..n {
        let a = all[next(all.len() as u64) as usize];
        let b = all[next(all.len() as u64) as usize];
        // Mostly the newest few as first parent (long lines), merges often.
        let a = if next(3) > 0 { all[all.len() - 1 - next(all.len().min(4) as u64) as usize] } else { a };
        let parents = if next(5) < 2 && a != b { vec![a, b] } else { vec![a] };
        let jitter = next(120_000) as i64 - 60_000;
        let c = Craft::new(&api, &p.admin, &p.name, "main");
        let (id, r) = c.push_edited(&format!("rdag-{i}"), None, |s| {
            s.parents = parents;
            s.timestamp += jitter;
        });
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
        derive(hub, pid, id);
        all.push(id);
    }
    all
}

/// BUG-2221 (review): over random histories in two projects sharing one
/// server (and its remembered "not below" facts), random questions with
/// one to three starting points, asked in "submits" that share one list of
/// walks across different starting points (as `Ancestry::near` does for
/// the tip, the frontier and the base below the part the deriver lacks),
/// the projects' submits interleaved and tips asked in any order (a later
/// tip, then an earlier one, as after a forced push): `is_below` answers
/// exactly as `is_ancestor` of any start, every time.
#[test]
fn bug_2221_is_below_matches_is_ancestor_over_random_histories_in_two_projects() {
    let hub = TestHub::start();
    let projects: Vec<(i64, Vec<ObjectId>)> = [0x5eed1_u64, 0x5eed2]
        .iter()
        .map(|seed| {
            let p = setup_project(&hub);
            let pid = project_id_of(&hub, &p.name);
            (pid, random_dag(&hub, &p, *seed, 48))
        })
        .collect();
    let h = hub.hub();
    let mut seed = 0x2221_beef_u64;
    let mut next = move |m: u64| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) % m
    };
    let (mut checked, mut below) = (0usize, 0usize);
    for submit in 0..60 {
        let (pid, all) = projects[submit % 2].clone();
        let pick = |k: u64| all[k as usize];
        let n = all.len() as u64;
        // Up to three start lists in this submit, of one to three starts.
        let lists: Vec<Vec<ObjectId>> = (0..1 + next(3)).map(|_| (0..1 + next(3)).map(|_| pick(next(n))).collect()).collect();
        let questions: Vec<(ObjectId, Vec<ObjectId>)> =
            (0..40).map(|_| (pick(next(n)), lists[next(lists.len() as u64) as usize].clone())).collect();
        let (c, b) = hub
            .rt
            .block_on(veil_server::derive::read(&h, pid, move |g| {
                let mut walks = Vec::new();
                let (mut c, mut b) = (0usize, 0usize);
                for (x, starts) in &questions {
                    let mut want = false;
                    for s in starts {
                        want |= g.is_ancestor(*x, *s)?;
                    }
                    let got = g.is_below(&mut walks, *x, starts)?;
                    assert_eq!(got, want, "submit {submit}: is {} below {:?}", x.short(), starts.iter().map(|s| s.short()).collect::<Vec<_>>());
                    c += 1;
                    b += want as usize;
                }
                Ok((c, b))
            }))
            .expect("the graph answers");
        checked += c;
        below += b;
    }
    assert_eq!(checked, 60 * 40);
    assert!(below > checked / 10 && below < checked * 9 / 10, "{below} of {checked} below: the histories have both answers");
}
