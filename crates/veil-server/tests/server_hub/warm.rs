//! A history is read as soon as the server names it (BUG-1943, BUG-1949).
//!
//! A viewer's graph is filled in two parts (`query::graph`): its rows, which
//! cost one read of each new snapshot, and the file history of those rows,
//! which costs a diff of each. Every query but blame and the history of a
//! path reads rows and trees only, so:
//!
//! * a push of thousands of snapshots is read at once, by the first query
//!   that names its tip, and a fill reads what is new and nothing else;
//! * a tip the server named a moment ago is read while `main` moves;
//! * rows that have no file history yet answer exactly what the viewer's
//!   copy of the project answers (the same rows, from the same per-viewer
//!   projection): no hidden revision, path, embargo line or path outside a
//!   narrowed session is read through them, and blame and the history of a
//!   path wait for the file history instead of answering from half of it.

use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use veil_core::ObjectId;
use veil_server::{
    derive,
    error::Error,
    perm::Viewer,
    query::{self, BlameParams, FileParams, HistoryParams, Limits, LogParams, TreeParams},
    sync::{self, root_snapshot_id},
};

use crate::{
    derived::{again, copy_for, policy, projections, random_history, viewers, Files, Hist, Rng},
    query::{admin, all_paths, ask, forget_blames, norm, queries, run, seeds, Q},
    support::*,
};

/// Snapshots `start..start + n` of a line on top of `from`: each changes
/// `pub/a.txt`, every other one `fin/b.txt` too (so every view key's
/// projection differs from the admins').
fn line(th: &TestHub, h: &mut Hist, from: ObjectId, start: usize, n: usize, files: &mut Files) -> ObjectId {
    let mut tip = from;
    for i in start..start + n {
        files.insert("pub/a.txt".into(), format!("version {i}\n").into_bytes());
        if i % 2 == 0 {
            files.insert("fin/b.txt".into(), format!("ledger {i}\n").into_bytes());
        }
        let mut change = [0u8; 16];
        change[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        change[15] = 0xb3;
        tip = h.commit(th, &[tip], files.clone(), change, 1_700_000_000_000 + i as i64 * 1000, None);
    }
    tip
}

/// How many rows of `viewer`'s graph of `h` are marked as having their
/// file history.
fn rows_with_files(th: &TestHub, h: &Hist, viewer: &Viewer) -> i64 {
    let key = h.project(th).view(viewer).key();
    th.rt.block_on(again(|| {
        sqlx::query_scalar("SELECT count(*) FROM view_graph WHERE project_id = $1 AND view_key = $2 AND files IS TRUE")
            .bind(h.id)
            .bind(&key)
            .fetch_one(&h.hub.db)
    }))
}

/// Another server holds the lease of `viewer`'s file history of `h`: no
/// fill of it runs here until [`release`].
fn hold_file_history(th: &TestHub, h: &Hist, viewer: &Viewer) {
    let key = h.project(th).view(viewer).key();
    th.rt.block_on(again(|| {
        sqlx::query("INSERT INTO view_fills (project_id, view_key, holder, expires_at) VALUES ($1, $2, 'another-server', $3)")
            .bind(h.id)
            .bind(&key)
            .bind(veil_core::now_millis() + 3_600_000)
            .execute(&h.hub.db)
    }));
}

fn release(th: &TestHub, h: &Hist) {
    th.rt.block_on(again(|| sqlx::query("DELETE FROM view_fills WHERE project_id = $1 AND holder = 'another-server'").bind(h.id).execute(&h.hub.db)));
}

fn code<T>(r: &veil_server::error::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(Error::Api { code, .. }) => code.to_string(),
        Err(e) => panic!("internal error: {e:?}"),
    }
}

/// BUG-1943: a history of over a thousand snapshots that nothing has
/// filled or derived (a push a moment ago) is read by the **first** ask of
/// every route a clone and a reader use, within a query's ordinary
/// deadline: by an admin, and by each viewer the server named the tip to
/// (as `tips` does: their projection of it). And a fill reads what is
/// new: forty snapshots on top cost about forty reads, not the history's.
#[test]
fn bug_1943_a_long_history_is_read_at_once_and_a_fill_reads_what_is_new() {
    let th = TestHub::start();
    let carol = 770_001;
    let (policy_text, bindings) = policy(carol);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let n = 1_200usize;
    let mut files = Files::new();
    let tip = line(&th, &mut h, root_snapshot_id(), 0, n, &mut files);
    h.set_branch(&th, "main", tip);
    let hub = h.hub.clone();
    let project = h.project(&th);
    assert_eq!(hub.query.fills_started(h.id), 0, "nothing is filled yet");
    let reads = || hub.query.fill_reads.load(Ordering::Relaxed);

    // The admin who pushed it: what a thin clone asks first (the tip's
    // generation), then a log, a file and a folder at the tip.
    let adm = ask(&th, &h, &admin());
    let t = Instant::now();
    let g = th.rt.block_on(query::generations(&hub, &adm, vec![tip], Limits::default())).expect("the first ask for the tip's generation");
    let first = t.elapsed();
    assert!(g["generations"][0].as_u64().is_some_and(|g| g > 0), "{g}");
    let log = th
        .rt
        .block_on(query::log(&hub, &adm, LogParams { rev: Some("main".into()), n: Some(5), ..Default::default() }, Limits::default()))
        .expect("the first log");
    assert_eq!(log["entries"][0]["snapshot_id"], tip.hex());
    assert_eq!(log["entries"].as_array().unwrap().len(), 5);
    let (_, bytes) = th
        .rt
        .block_on(query::file(&hub, &adm, FileParams { rev: Some(tip.hex()), path: "pub/a.txt".into() }, Limits::default()))
        .expect("the first read of a file at the tip");
    assert_eq!(bytes, format!("version {}\n", n - 1).into_bytes());
    let tree = th
        .rt
        .block_on(query::tree(&hub, &adm, TreeParams { rev: Some(tip.hex()), path: Some("pub".into()), ..Default::default() }, Limits::default()))
        .expect("the first listing at the tip");
    assert!(tree.to_string().contains("a.txt"), "{tree}");
    let whole = reads();
    assert!(whole >= n as u64, "the first fill read the history: {whole} reads of {n} snapshots");
    assert_eq!(hub.query.fills_started(h.id), 1, "one fill of the admins' rows");

    // Forty more land: the next ask reads those, nothing below them.
    let more = 40usize;
    let tip2 = line(&th, &mut h, tip, n, more, &mut files);
    h.set_branch(&th, "main", tip2);
    let g2 = th.rt.block_on(query::generations(&hub, &adm, vec![tip2], Limits::default())).expect("the first ask for the new tip");
    assert!(g2["generations"][0].as_u64() > g["generations"][0].as_u64(), "{g2} after {g}");
    let new = reads() - whole;
    println!("BUG-1943: the first ask of {n} snapshots took {first:?} ({whole} reads); {more} more cost {new} reads");
    assert!(
        (more as u64..=2 * more as u64 + 2).contains(&new),
        "a fill on top of {n} filled snapshots read {new} snapshots for {more} new ones"
    );

    // People who are not admins, each told the tip as the server names it
    // to them (their projection): the first ask of each route answers.
    let all = viewers(carol);
    for (who, path) in [("anyone on Earth", "pub/a.txt"), ("finance", "fin/b.txt")] {
        let viewer = all.iter().find(|(w, _)| *w == who).unwrap().1.clone();
        let mine = th.rt.block_on(sync::projected(&hub, &project, &viewer, tip2)).unwrap();
        // (Finance reads all of this history: their id of the tip is its own.)
        assert_eq!(mine != tip2, who == "anyone on Earth", "{who}");
        let a = ask(&th, &h, &viewer);
        let t = Instant::now();
        let (_, bytes) = th
            .rt
            .block_on(query::file(&hub, &a, FileParams { rev: Some(mine.hex()), path: path.into() }, Limits::default()))
            .unwrap_or_else(|e| panic!("{who}: the first read of {path} at the tip the server named: {e:?}"));
        let took = t.elapsed();
        assert!(!bytes.is_empty());
        let g = th.rt.block_on(query::generations(&hub, &a, vec![mine], Limits::default())).unwrap_or_else(|e| panic!("{who}: generations: {e:?}"));
        assert!(g["generations"][0].as_u64().is_some_and(|g| g > 0), "{who}: {g}");
        let log = th
            .rt
            .block_on(query::log(&hub, &a, LogParams { rev: Some(mine.hex()), n: Some(3), ..Default::default() }, Limits::default()))
            .unwrap_or_else(|e| panic!("{who}: log: {e:?}"));
        assert_eq!(log["entries"][0]["snapshot_id"], mine.hex(), "{who}");
        println!("BUG-1943: {who}: the first read at the tip took {took:?}");
    }
}

/// BUG-1949: while `main` lands change after change (nothing but the
/// readers fills their graphs between the deriver's passes), a reader who
/// asks for the tip and then for a file and the log at that tip is always
/// answered: never `warming`, whoever they are.
#[test]
fn bug_1949_a_tip_just_named_is_read_while_main_moves() {
    let th = TestHub::start();
    let carol = 770_002;
    let (policy_text, bindings) = policy(carol);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut files = Files::new();
    let mut tip = line(&th, &mut h, root_snapshot_id(), 0, 30, &mut files);
    h.set_branch(&th, "main", tip);
    let hub = h.hub.clone();
    let project = h.project(&th);
    let all = viewers(carol);
    let mut readers: Vec<(&str, Viewer, &str)> = vec![("an admin", admin(), "pub/a.txt")];
    for (who, path) in [("anyone on Earth", "pub/a.txt"), ("finance", "fin/b.txt")] {
        readers.push((who, all.iter().find(|(w, _)| *w == who).unwrap().1.clone(), path));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();
    for (who, viewer, path) in readers {
        let (hub, project, stop, a, id) = (hub.clone(), project.clone(), stop.clone(), ask(&th, &h, &viewer), h.id);
        let done = Arc::new(AtomicUsize::new(0));
        let done2 = done.clone();
        let task = th.rt.spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                // The tip, as `GET …/tips` names it to this reader.
                let real: String = again(|| sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = 'main'").bind(id).fetch_one(&hub.db)).await;
                let real = ObjectId::from_hex(&real).unwrap();
                let mine = sync::projected(&hub, &project, &viewer, real).await.unwrap();
                let file = query::file(&hub, &a, FileParams { rev: Some(mine.hex()), path: path.into() }, Limits::default()).await;
                assert!(file.is_ok(), "{who}: the file at the tip just named: {:?}", file.err());
                let log = query::log(&hub, &a, LogParams { rev: Some(mine.hex()), n: Some(3), ..Default::default() }, Limits::default()).await;
                let log = log.unwrap_or_else(|e| panic!("{who}: the log at the tip just named: {e:?}"));
                assert_eq!(log["entries"][0]["snapshot_id"], mine.hex(), "{who}");
                done2.fetch_add(1, Ordering::Relaxed);
            }
        });
        tasks.push((who, task, done));
    }
    // The landings: one change at a time; the deriver passes now and then
    // (it writes the file history of what the readers' fills left it).
    for i in 0..240usize {
        tip = line(&th, &mut h, tip, 30 + i, 1, &mut files);
        h.set_branch(&th, "main", tip);
        if i % 60 == 59 {
            th.rt.block_on(derive::landing(&hub, h.id, vec!["main".into()])).expect("a deriver's pass");
        }
    }
    stop.store(true, Ordering::Relaxed);
    for (who, task, done) in tasks {
        th.rt.block_on(task).unwrap_or_else(|e| panic!("{who}: {e}"));
        let n = done.load(Ordering::Relaxed);
        println!("BUG-1949: {who} read the tip {n} times while main moved");
        assert!(n >= 5, "{who} read the moving tip only {n} times");
    }
}

/// The access rules on rows that have no file history yet: for random
/// histories and every kind of viewer, each route's answer (the work it
/// took included) is byte for byte the answer an admin gets on a copy of
/// the project built only from that viewer's projected history, as it is
/// once everything is filled (`query_projection_equivalence`). So nothing
/// hidden is read through fresh rows: a hidden revision is no revision, a
/// hidden path no path. Blame and the history of a path answer `warming`
/// until the file history is written, whatever the path (never from half
/// a history, and the same for a hidden path and a readable one); then
/// what the copy answers.
#[test]
fn rows_without_file_history_answer_exactly_as_the_viewers_copy() {
    let th = TestHub::start();
    for seed in seeds(&[311]) {
        let carol = 771_000 + seed as i64;
        let (policy_text, bindings) = policy(carol);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut rng = Rng::new(seed);
        random_history(&th, &mut h, &mut rng, 40);
        let project = h.project(&th);
        let tips: Vec<ObjectId> = h.branches.values().copied().collect();
        let mut paths: Vec<String> = all_paths(&h).into_iter().collect();
        paths.extend(["pub", "fin", "pub/sec", "", "missing-9f2c.txt", "fin/missing-77ab.txt", "pub/missing"].map(String::from));
        let mut compared = 0usize;
        let mut keys = BTreeSet::new();
        for (who, viewer) in viewers(carol) {
            let view = project.view(&viewer);
            // One graph per view key: a viewer who reads as an earlier one
            // does would find that one's file history.
            if !keys.insert(view.key()) {
                continue;
            }
            let p = projections(&th, &h, &project, &viewer);
            let copy = copy_for(&th, &h, &project, &viewer, &p);
            let mine: Vec<ObjectId> = p.values().copied().collect::<BTreeSet<_>>().into_iter().collect();
            let mut revs: Vec<String> = vec!["main".into(), "side".into(), "no-such-branch".into()];
            for _ in 0..6 {
                revs.push(mine[rng.below(mine.len())].hex());
            }
            revs.push(root_snapshot_id().hex());
            let hidden_real: Vec<ObjectId> = h.order.iter().copied().filter(|s| p[s] != *s).collect();
            if let Some(s) = hidden_real.first() {
                revs.push(s.hex());
            }
            let (mine_ask, copy_ask) = (ask(&th, &h, &viewer), ask(&th, &copy, &admin()));
            forget_blames(&th, &h);
            // The copy: everything filled. The viewer's graph: its rows
            // only (another server holds the lease of its file history).
            let copy_tips: Vec<ObjectId> = copy.branches.values().copied().collect();
            th.rt.block_on(query::graph::ensure_files(&copy.hub, &copy.project(&th), &admin(), &copy_tips, None)).unwrap();
            hold_file_history(&th, &h, &viewer);
            th.rt.block_on(query::graph::extend_rows(&h.hub, &project, &viewer, &tips)).unwrap();
            assert_eq!(rows_with_files(&th, &h, &viewer), 0, "seed {seed}, {who}: rows only");
            let hidden_paths: Vec<String> = all_paths(&h).into_iter().filter(|k| !view.read(k) && !k.is_empty()).collect();
            let mut of_files = Vec::new();
            for q in queries(&mut rng, &revs, &paths) {
                if matches!(q, Q::Blame(..) | Q::History(..)) {
                    of_files.push(q);
                    continue;
                }
                let (real, theirs) = (run(&th, &h, &mine_ask, &q), run(&th, &copy, &copy_ask, &q));
                assert_eq!(real, theirs, "seed {seed}, {who}, rows without file history: {q:?}");
                compared += real.len();
                for a in &real {
                    for k in &hidden_paths {
                        if !paths.iter().any(|r| view.read(r) && r.starts_with(k.as_str())) {
                            assert!(!a.contains(&format!("\"{k}\"")), "seed {seed}, {who}: hidden path {k} in {a}");
                        }
                    }
                    for s in &hidden_real {
                        assert!(!a.contains(&s.hex()), "seed {seed}, {who}: real id {} in {a}", s.short());
                    }
                }
            }
            assert_eq!(rows_with_files(&th, &h, &viewer), 0, "seed {seed}, {who}: those answers came from rows alone");
            // Blame and the history of a path: `warming` whatever the path
            // (readable, hidden or missing), or the copy's own refusal of
            // a revision or a request (decided before any file history).
            let quick = Limits { deadline: Duration::from_millis(40), ..Limits::default() };
            let mut warming = 0usize;
            for q in of_files.iter().take(10) {
                let mine = match q {
                    Q::Blame(p, _) => th.rt.block_on(query::blame(&h.hub, &mine_ask, p.clone(), quick)),
                    Q::History(p, _) => th.rt.block_on(query::history(&h.hub, &mine_ask, p.clone(), quick)),
                    _ => unreachable!(),
                };
                match code(&mine).as_str() {
                    "warming" => warming += 1,
                    _ => {
                        assert!(mine.is_err(), "seed {seed}, {who}: an answer from half a file history: {q:?}");
                        let theirs = match q {
                            Q::Blame(p, _) => th.rt.block_on(query::blame(&copy.hub, &copy_ask, p.clone(), Limits::default())),
                            Q::History(p, _) => th.rt.block_on(query::history(&copy.hub, &copy_ask, p.clone(), Limits::default())),
                            _ => unreachable!(),
                        };
                        assert_eq!(norm(mine), norm(theirs), "seed {seed}, {who}: {q:?}");
                    }
                }
            }
            assert!(warming > 0, "seed {seed}, {who}: no blame or file history waited for the file history");
            assert_eq!(rows_with_files(&th, &h, &viewer), 0);
            // The other server is done: the file history is written here,
            // and blame and the history of a path answer as the copy's.
            release(&th, &h);
            // (Of every branch, as the copy's is: the work a history of a
            // path takes counts the path's changes on other lines too.)
            th.rt.block_on(query::graph::ensure_files(&h.hub, &project, &viewer, &tips, None)).unwrap();
            forget_blames(&th, &h);
            forget_blames(&th, &copy);
            for q in &of_files {
                let (real, theirs) = (run(&th, &h, &mine_ask, q), run(&th, &copy, &copy_ask, q));
                assert_eq!(real, theirs, "seed {seed}, {who}: {q:?}");
                compared += real.len();
            }
            assert!(rows_with_files(&th, &h, &viewer) > 0 || mine.len() <= 1, "seed {seed}, {who}: the file history was written");
        }
        println!("seed {seed}: {} changes, {} view keys, {compared} answers compared on rows without file history", h.order.len(), keys.len());
        assert!(keys.len() >= 4, "seed {seed}: {} view keys", keys.len());
    }
}

/// On fresh rows (nothing filled before the first ask), exactly the
/// refusals there are once everything is filled: a hidden revision, a
/// branch that does not exist and an embargo line are the same "no such
/// revision" for anyone on Earth (the embargo line for admins too), by
/// name, by their own id and by the real id; a narrowed agent session
/// reads its paths and is refused every other with the same words. Then
/// everything is filled, and every answer is asked again: byte for byte
/// the same.
#[test]
fn fresh_rows_keep_embargo_lines_hidden_revisions_and_a_narrowing() {
    let th = TestHub::start();
    let carol = 770_004;
    let (policy_text, bindings) = policy(carol);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let base = Files::from([
        ("pub/a.rs".to_string(), b"fn a() {}\n".to_vec()),
        ("pub/docs/guide.md".to_string(), b"guide\n".to_vec()),
        ("fin/ledger.txt".to_string(), b"ledger\n".to_vec()),
    ]);
    let a = h.commit(&th, &[root_snapshot_id()], base.clone(), [1; 16], 1_000, None);
    let mut hid = base.clone();
    hid.insert("fin/q3-plan-5e1d.txt".into(), b"plan\n".to_vec());
    let hidden = h.commit(&th, &[a], hid.clone(), [2; 16], 2_000, None);
    let mut fixed = hid.clone();
    fixed.insert("pub/fix-embargo-77c1e0.rs".into(), b"FIX-MARKER-a91f\n".to_vec());
    let e = h.commit(&th, &[hidden], fixed.clone(), [3; 16], 3_000, Some("cve-1"));
    let mut later = fixed;
    later.insert("pub/after-fix-5d2c.rs".into(), b"later\n".to_vec());
    let c = h.commit(&th, &[e], later, [4; 16], 4_000, None);
    h.set_branch(&th, "main", hidden);
    h.set_branch(&th, "embargoed", c);
    let project = h.project(&th);
    let anyone = ask(&th, &h, &Viewer::default());
    let adm = ask(&th, &h, &admin());
    let dev = viewers(carol).into_iter().find(|(w, _)| *w == "a dev").unwrap().1;
    let narrowed = ask(
        &th,
        &h,
        &Viewer {
            only: Some(Arc::new(vec!["pub/docs".to_string()])),
            agent: true,
            ..dev.clone()
        },
    );
    let log = |rev: &str| Q::Log(LogParams { rev: Some(rev.into()), ..Default::default() }, Limits::default());
    let file = |rev: &str, path: &str| Q::File(FileParams { rev: Some(rev.into()), path: path.into() });
    let tree = |rev: &str, path: &str| Q::Tree(TreeParams { rev: Some(rev.into()), path: Some(path.into()), ..Default::default() });
    let missing = ObjectId([0x5a; 32]).hex();
    // What the server names to the dev as the tip of `main`.
    let dev_tip = th.rt.block_on(sync::projected(&h.hub, &project, &dev, hidden)).unwrap().hex();
    let mut asked: Vec<(&str, &query::Ask, Q)> = Vec::new();
    for rev in [missing.clone(), hidden.hex(), "no-such-branch".into(), "embargoed".into(), e.hex(), c.hex()] {
        asked.push(("anyone, hidden or withheld", &anyone, log(&rev)));
        asked.push(("anyone, hidden or withheld", &anyone, file(&rev, "pub/a.rs")));
    }
    for rev in [missing.clone(), "embargoed".into(), e.hex(), c.hex()] {
        asked.push(("an admin, withheld", &adm, log(&rev)));
        asked.push(("an admin, withheld", &adm, file(&rev, "pub/a.rs")));
    }
    let refused_from = asked.len();
    for rev in ["main", dev_tip.as_str()] {
        asked.push(("narrowed, inside", &narrowed, file(rev, "pub/docs/guide.md")));
        asked.push(("narrowed, inside", &narrowed, tree(rev, "pub/docs")));
    }
    let outside_from = asked.len();
    for rev in ["main", dev_tip.as_str()] {
        asked.push(("narrowed, outside", &narrowed, file(rev, "pub/a.rs")));
        asked.push(("narrowed, outside", &narrowed, file(rev, "fin/ledger.txt")));
        asked.push(("narrowed, outside", &narrowed, tree(rev, "fin")));
        asked.push(("narrowed, outside", &narrowed, Q::Blame(BlameParams { rev: Some(rev.into()), path: "pub/a.rs".into(), ..Default::default() }, Limits::default())));
        asked.push(("narrowed, outside", &narrowed, Q::History(HistoryParams { rev: Some(rev.into()), path: Some("pub/a.rs".into()), ..Default::default() }, Limits::default())));
    }
    assert_eq!(h.hub.query.fills_started(h.id), 0, "nothing is filled before the first ask");
    let fresh: Vec<String> = asked.iter().map(|(_, a, q)| run(&th, &h, a, q).remove(0)).collect();
    let no_rev = &fresh[0];
    assert!(no_rev.starts_with("error 404") && no_rev.contains("no such revision that you can see"), "{no_rev}");
    for (i, ((what, _, q), answer)) in asked.iter().zip(&fresh).enumerate() {
        if i < refused_from {
            assert_eq!(answer, no_rev, "{what}: {q:?}");
        } else if i < outside_from {
            assert!(!answer.starts_with("error") && answer.contains("guide"), "{what}: {q:?}: {answer}");
        } else {
            assert!(
                answer.starts_with("error") && answer.contains("this agent session is narrowed to other paths: ask for a path inside them"),
                "{what}: {q:?}: {answer}"
            );
        }
        for hidden in ["FIX-MARKER", "fix-embargo-77c1e0", "after-fix-5d2c", &e.hex(), &c.hex()] {
            assert!(!answer.contains(hidden), "{what}: {q:?} answers {hidden}: {answer}");
        }
    }
    // Everything filled (rows and file history, for every viewer here):
    // the same answers.
    let all_tips = [hidden];
    for v in [Viewer::default(), admin(), dev.clone()] {
        th.rt.block_on(query::graph::ensure_files(&h.hub, &project, &v, &all_tips, None)).unwrap();
    }
    let filled: Vec<String> = asked.iter().map(|(_, a, q)| run(&th, &h, a, q).remove(0)).collect();
    for (((what, _, q), before), after) in asked.iter().zip(&fresh).zip(&filled) {
        assert_eq!(before, after, "{what}: {q:?} answered otherwise on fresh rows");
    }
}

/// A query that gives up waiting for a fill says how far the fill is (the
/// viewer's own snapshots projected and written so far), so a client that
/// asks again sees the server getting on (`vl` waits on while the number
/// grows): the numbers never go back, and they grow.
#[test]
fn warming_says_how_far_the_fill_is() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(770_005);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut files = Files::new();
    let tip = line(&th, &mut h, root_snapshot_id(), 0, 400, &mut files);
    h.set_branch(&th, "main", tip);
    let a = ask(&th, &h, &Viewer::default());
    let quick = Limits { deadline: Duration::from_millis(20), ..Limits::default() };
    let mut seen: Vec<u64> = Vec::new();
    let t = Instant::now();
    loop {
        match th.rt.block_on(query::log(&h.hub, &a, LogParams::default(), quick)) {
            Ok(_) | Err(Error::Api { code: "deadline", .. }) => break,
            Err(Error::Api { code: "warming", message, .. }) => {
                let n = message
                    .strip_prefix("this history is being prepared for you (")
                    .and_then(|m| m.strip_suffix(" snapshots so far); try again in a few seconds"))
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or_else(|| panic!("a `warming` answer without the fill's progress: {message}"));
                seen.push(n);
            }
            Err(e) => panic!("{e:?}"),
        }
        assert!(t.elapsed() < Duration::from_secs(300), "the fill never finished");
    }
    println!("warming: {} answers, from {:?} to {:?}", seen.len(), seen.first(), seen.last());
    assert!(seen.len() >= 2, "a first fill of 400 projected snapshots was not waited for twice: {seen:?}");
    assert!(seen.windows(2).all(|w| w[0] <= w[1]), "the progress went back: {seen:?}");
    assert!(seen.last() > seen.first(), "the progress never grew: {seen:?}");
    assert!(th.rt.block_on(query::log(&h.hub, &a, LogParams::default(), Limits::default())).is_ok());
}
