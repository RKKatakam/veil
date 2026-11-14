//! Database commits by kind (BUG-2350, `storage-and-cost.md` §9): the
//! server counts each where it is made (`Hub::commits`), and a landing run
//! that takes many branches' pushes at once writes everything derived from
//! them in its one transaction.

use veil_server::{db::Commit, sync::root_snapshot_id};

use crate::{
    derived::{policy, Files, Hist},
    support::*,
};

/// BUG-2350: under 300 agents pushing their own branches, a deriver run
/// takes about 32 snapshots at once, past the inline caps (16 snapshots,
/// 64 file-history rows): it leaves its view keys' rows and projection
/// memos to background fills, and its search index to an update of its
/// own. Each fill stored every projection memo it made in a commit of its
/// own, and the update committed twice a branch: 1.2 commits a push beside
/// the push's own. Now a run of 24 branches' new snapshots commits once,
/// each fill stores its memos together (at most four commits: its lease,
/// the memos, the rows, the lease's end), and the update commits once.
#[test]
fn bug_2350_a_run_of_many_branches_costs_a_few_commits() {
    const BRANCHES: usize = 24;
    let th = TestHub::start();
    let (text, bindings) = policy(900_001);
    let mut h = Hist::new(&th, &text, &bindings);
    let base = h.commit(&th, &[root_snapshot_id()], Files::from([("pub/a.txt".to_string(), b"a\n".to_vec())]), [1; 16], 1, None);
    h.set_branch(&th, "main", base);
    let first = th.rt.block_on(veil_server::derive::landing(&h.hub, h.id, vec!["main".to_string()])).unwrap();
    assert_eq!(first.branches, vec!["main".to_string()], "the first landing derived main");
    // Each branch one new snapshot on main's tip, each its own change.
    let mut names = Vec::new();
    let mut tips = Vec::new();
    for i in 0..BRANCHES {
        let files = Files::from([
            ("pub/a.txt".to_string(), b"a\n".to_vec()),
            (format!("pub/b{i:02}.txt"), format!("branch {i}\n").into_bytes()),
        ]);
        let mut change = [2; 16];
        change[0] = i as u8;
        let tip = h.commit(&th, &[base], files, change, 10 + i as i64, None);
        let name = format!("agent-{i:02}");
        h.set_branch(&th, &name, tip);
        names.push(name);
        tips.push(tip.hex());
    }
    let hub = h.hub.clone();
    let before = |k| hub.commits.of(k);
    let (derive0, fill0, search0, memo0) = (before(Commit::Derive), before(Commit::Fill), before(Commit::Search), before(Commit::Memo));
    let started = |id| hub.query.fills_started(id) + hub.query.file_fills_started(id);
    let fills0 = started(h.id);
    let stats = th.rt.block_on(veil_server::derive::landing(&hub, h.id, names.clone())).unwrap();
    let mut derived = stats.branches.clone();
    derived.sort();
    assert_eq!(derived, names, "the run derived every branch");
    assert!(!stats.skipped);
    let id = h.id;
    // The search index's update and the fills run in the background.
    let done = || -> (i64, i64, i64) {
        th.rt.block_on(async {
            let heads: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM search_heads WHERE project_id = $1 AND kind IN ('code', 'walk') AND snapshot = ANY($2)",
            )
            .bind(id)
            .bind(&tips)
            .fetch_one(&hub.db)
            .await
            .unwrap();
            let (memos, keys): (i64, i64) =
                sqlx::query_as("SELECT count(*), count(DISTINCT view_key) FROM projections WHERE project_id = $1 AND real_id = ANY($2)")
                    .bind(id)
                    .bind(&tips)
                    .fetch_one(&hub.db)
                    .await
                    .unwrap();
            (heads, memos, keys)
        })
    };
    let want = (2 * BRANCHES as i64, 2 * BRANCHES as i64, 2);
    let t = std::time::Instant::now();
    while done() != want && t.elapsed() < std::time::Duration::from_secs(30) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // Anything more they would start: give it time.
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert_eq!(
        done(),
        want,
        "every branch's search index (code and walk) is at its tip; every tip is memoised for both view keys (anyone on Earth, carol)"
    );
    let progress: i64 = th
        .rt
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM derive_progress WHERE project_id = $1 AND through_snapshot = ANY($2)")
                .bind(id)
                .bind(&tips)
                .fetch_one(&hub.db),
        )
        .unwrap();
    assert_eq!(progress, BRANCHES as i64, "every branch's derived tip is recorded");
    let fills = started(id) - fills0;
    let fill = hub.commits.of(Commit::Fill) - fill0;
    assert!((1..=3).contains(&fills), "{fills} fills: one a view key (anyone on Earth, carol, the admins)");
    assert!(fill <= 4 * fills, "{fill} commits for {fills} fills of {BRANCHES} tips");
    assert_eq!(
        (hub.commits.of(Commit::Derive) - derive0, hub.commits.of(Commit::Search) - search0, hub.commits.of(Commit::Memo) - memo0),
        (1, 1, 0),
        "one commit for the run, one for the search index, none a memo (derive, search, memo commits)"
    );
}

/// The kinds the load tool's gate reads (BUG-2350): a push is one `push`
/// commit, and a branch's landing through the landing service one
/// `land_submit` and one `land_batch` (alone in its batch).
#[test]
fn bug_2350_a_push_and_a_landing_are_counted_as_theirs() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let h = hub.hub();
    let count = |k| h.commits.of(k);
    let (push0, submit0, batch0) = (count(Commit::Push), count(Commit::LandSubmit), count(Commit::LandBatch));
    p.admin.ok(&p.dir, &["new", "main"]);
    write_files(&p.dir, &[("src/one.txt", "one")]);
    p.admin.ok(&p.dir, &["commit", "-m", "on a branch"]);
    p.admin.ok(&p.dir, &["tag", "set", "side", "-r", "@-"]);
    let out = p.admin.ok(&p.dir, &["push"]);
    assert!(out.contains("side"), "{out}");
    assert_eq!((count(Commit::Push) - push0, count(Commit::LandSubmit) - submit0), (1, 0), "a push is one push commit");
    // Another change, landed from this clone (not pushed first).
    p.admin.ok(&p.dir, &["new", "main"]);
    write_files(&p.dir, &[("src/two.txt", "two")]);
    p.admin.ok(&p.dir, &["commit", "-m", "to land"]);
    p.admin.ok(&p.dir, &["tag", "set", "to-land", "-r", "@-"]);
    let out = p.admin.ok(&p.dir, &["land", "to-land", "--onto", "main"]);
    assert!(out.contains("landed main"), "{out}");
    assert_eq!(
        (count(Commit::Push) - push0, count(Commit::LandSubmit) - submit0, count(Commit::LandBatch) - batch0),
        (1, 1, 1),
        "a landing is its submit's commit and its batch's"
    );
}

/// BUG-2350: a fill stores the memos its tips need together; a row stored
/// first (by another server) with another projection still wins: the fill
/// drops what it worked out and projects the tips one memo at a time,
/// each stored row taken as it is.
#[test]
fn bug_2350_a_memo_stored_first_wins_over_a_fills_batch() {
    let th = TestHub::start();
    let (text, bindings) = policy(900_002);
    let mut h = Hist::new(&th, &text, &bindings);
    let base = h.commit(&th, &[root_snapshot_id()], Files::from([("pub/a.txt".to_string(), b"a\n".to_vec())]), [1; 16], 1, None);
    h.set_branch(&th, "main", base);
    let first = th.rt.block_on(veil_server::derive::landing(&h.hub, h.id, vec!["main".to_string()])).unwrap();
    assert_eq!(first.branches, vec!["main".to_string()], "the first landing derived main");
    let mut tips = Vec::new();
    for i in 0..4u8 {
        let files = Files::from([("pub/a.txt".to_string(), b"a\n".to_vec()), (format!("pub/c{i}.txt"), vec![b'c', i])]);
        let tip = h.commit(&th, &[base], files, [3 + i; 16], 100 + i as i64, None);
        h.set_branch(&th, &format!("side-{i}"), tip);
        tips.push(tip);
    }
    let hub = h.hub.clone();
    let project = h.project(&th);
    let anyone = veil_server::perm::Viewer::default();
    let vk = project.view(&anyone).key();
    // Another server's projection of the first tip, stored first: a real
    // projected snapshot (main's), not the one worked out here.
    let other = th.rt.block_on(veil_server::sync::projected(&hub, &project, &anyone, base)).unwrap();
    th.rt
        .block_on(
            sqlx::query("INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at, collapsed) VALUES ($1, $2, $3, $4, 0, false)")
                .bind(h.id)
                .bind(&vk)
                .bind(tips[0].hex())
                .bind(other.hex())
                .execute(&hub.db),
        )
        .unwrap();
    th.rt.block_on(veil_server::query::graph::prefill(&hub, &project, &anyone, &tips)).unwrap();
    let hexes: Vec<String> = tips.iter().map(|t| t.hex()).collect();
    let stored = || -> Vec<(String, String)> {
        th.rt
            .block_on(
                sqlx::query_as("SELECT real_id, projected_id FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = ANY($3)")
                    .bind(h.id)
                    .bind(&vk)
                    .bind(&hexes)
                    .fetch_all(&hub.db),
            )
            .unwrap()
    };
    let t = std::time::Instant::now();
    while stored().len() < tips.len() && t.elapsed() < std::time::Duration::from_secs(30) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let rows: std::collections::HashMap<String, String> = stored().into_iter().collect();
    assert_eq!(rows.len(), tips.len(), "every tip is memoised: {rows:?}");
    assert_eq!(rows[&tips[0].hex()], other.hex(), "the row stored first is kept");
    for t in &tips[1..] {
        let p = th.rt.block_on(veil_server::sync::projected(&hub, &project, &anyone, *t)).unwrap();
        assert_eq!(rows[&t.hex()], p.hex(), "each other tip's memo is its projection");
    }
}
