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
