//! Blame and file history (milestone S14; phase-3 design §3.6 and the
//! threat review, §6).
//!
//! The projection-equivalence harness (`query.rs`, row 1) compares every
//! blame and history answer, work included, with the copy's. Here: both
//! against a model computed straight from each viewer's projected files
//! (no server code), the boundary cuts (row 5), kept blames and budgets,
//! hostile inputs (row 10) and speed (§5).

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    time::{Duration, Instant},
};

use serde_json::Value;
use veil_core::{blame::map_lines, hub::access::View, ObjectId};
use veil_server::{
    error::Error,
    perm::Viewer,
    query::{self, files::BlameLimits, Ask, BlameParams, HistoryParams, Limits},
    sync::root_snapshot_id,
};

use crate::{
    derived::{copy_for, policy, projections, random_history, text, viewers, Files, Hist, Rng},
    query::{admin, ask, forget_blames, model_log, seeds, warm_up},
    support::*,
};

// ---- the model ----------------------------------------------------------------------

/// One viewer's projected history of a project, as plain data: each
/// projected snapshot's parents and the files they may read.
struct Model {
    parents: HashMap<ObjectId, Vec<ObjectId>>,
    files: HashMap<ObjectId, Files>,
}

fn model(h: &Hist, p: &HashMap<ObjectId, ObjectId>, view: &View) -> Model {
    let root = root_snapshot_id();
    let mut m = Model {
        parents: HashMap::from([(root, Vec::new())]),
        files: HashMap::from([(root, Files::new())]),
    };
    for s in &h.order {
        let ps = &h.parents[s];
        if ps.first().is_some_and(|p0| p[p0] == p[s]) {
            continue; // collapsed into its first parent
        }
        let mut parents = Vec::new();
        for q in ps {
            if !parents.contains(&p[q]) {
                parents.push(p[q]);
            }
        }
        let files: Files = h.files[s].iter().filter(|(k, _)| !k.ends_with('/') && view.read(k)).map(|(k, v)| (k.clone(), v.clone())).collect();
        m.parents.insert(p[s], parents);
        m.files.insert(p[s], files);
    }
    m
}

type Origins = Vec<(String, String, u32)>;

/// Blame of `path` at projected snapshot `x`, by recursion over snapshots
/// (not versions): a line moves to the first parent whose file holds it.
fn model_blame(m: &Model, x: ObjectId, path: &str, memo: &mut HashMap<(ObjectId, String), Origins>) -> Origins {
    if let Some(o) = memo.get(&(x, path.to_string())) {
        return o.clone();
    }
    let v = &m.files[&x][path];
    let n = veil_core::blame::line_ranges(v).len();
    let mut out: Vec<Option<(String, String, u32)>> = vec![None; n];
    for q in &m.parents[&x] {
        let Some(vq) = m.files[q].get(path) else { continue };
        let map: Vec<Option<u32>> = if vq == v { (0..n as u32).map(Some).collect() } else { map_lines(vq, v, n).0 };
        let above = model_blame(m, *q, path, memo);
        for i in 0..n {
            if out[i].is_none() {
                if let Some(j) = map[i] {
                    out[i] = Some(above[j as usize].clone());
                }
            }
        }
    }
    let o: Origins = out.into_iter().enumerate().map(|(i, o)| o.unwrap_or_else(|| (x.hex(), path.to_string(), i as u32 + 1))).collect();
    memo.insert((x, path.to_string()), o.clone());
    o
}

/// The snapshots that made each version of `path` reachable from `x` (no
/// renames): the snapshot whose file differs from its first parent's, down
/// the first parents, and from each of its parents again.
fn model_history(m: &Model, x: ObjectId, path: &str) -> BTreeSet<ObjectId> {
    let intro = |mut x: ObjectId| loop {
        let ps = &m.parents[&x];
        match ps.first() {
            None => return m.files[&x].contains_key(path).then_some(x),
            Some(p0) if m.files[&x].get(path) != m.files[p0].get(path) => return Some(x),
            Some(p0) => x = *p0,
        }
    };
    let mut out = BTreeSet::new();
    let mut stack: Vec<ObjectId> = intro(x).into_iter().collect();
    while let Some(v) = stack.pop() {
        if out.insert(v) {
            stack.extend(m.parents[&v].iter().filter_map(|q| intro(*q)));
        }
    }
    out
}

/// Every page of a blame, its lines' origins; or the error.
fn blame_all(th: &TestHub, h: &Hist, a: &Ask, rev: &str, path: &str, follow: bool, limits: Limits) -> Result<(Origins, Vec<Value>), String> {
    let mut out = Vec::new();
    let mut pages = Vec::new();
    let mut after = None;
    for _ in 0..1000 {
        let q = BlameParams { rev: Some(rev.into()), path: path.into(), follow: Some(follow), after, ..Default::default() };
        match th.rt.block_on(query::blame(&h.hub, a, q, limits)) {
            Ok(v) => {
                for l in v["lines"].as_array().unwrap() {
                    out.push((l["snapshot"].as_str().unwrap().to_string(), l["path"].as_str().unwrap().to_string(), l["origin_line"].as_u64().unwrap() as u32));
                }
                after = v["next"].as_u64().map(|n| n as usize);
                pages.push(v);
                if after.is_none() {
                    return Ok((out, pages));
                }
            }
            // Ask again, as a client does: a blame stopped at its budget or
            // its deadline goes on from what it kept (and a loaded machine
            // can pass the 2 s deadline: BUG-1172).
            Err(Error::Api { code: "partial" | "deadline" | "warming", .. }) => continue,
            Err(Error::Api { status, code, message }) => return Err(format!("{status} {code} {message}")),
            Err(e) => panic!("internal error: {e:?}"),
        }
    }
    panic!("a blame that never finished");
}

/// Every page of a file history: `(snapshot, path, status)`.
fn history_all(th: &TestHub, h: &Hist, a: &Ask, rev: &str, path: &str, follow: bool, n: usize) -> Result<Vec<(String, String, String)>, String> {
    let mut out = Vec::new();
    let mut after = None;
    for _ in 0..1000 {
        let q = HistoryParams { rev: Some(rev.into()), path: Some(path.into()), follow: Some(follow), n: Some(n), after: after.clone() };
        match th.rt.block_on(query::history(&h.hub, a, q, Limits::default())) {
            Err(Error::Api { code: "deadline" | "warming", .. }) => continue,
            Ok(v) => {
                for e in v["entries"].as_array().unwrap() {
                    out.push((e["snapshot_id"].as_str().unwrap().to_string(), e["path"].as_str().unwrap().to_string(), e["status"].as_str().unwrap().to_string()));
                }
                after = v["next"].as_str().map(str::to_string);
                if after.is_none() {
                    return Ok(out);
                }
            }
            Err(Error::Api { status, code, message }) => return Err(format!("{status} {code} {message}")),
            Err(e) => panic!("internal error: {e:?}"),
        }
    }
    panic!("a history that never ended");
}

/// Row 1 against a model that shares no code with the server: for random
/// histories and every viewer, each readable file's blame (every line's
/// change, path and line there) and file history (which changes, in which
/// order, with which status) at every branch tip and at some of the
/// viewer's own snapshots equal what the viewer's projected files say.
/// Hidden and missing paths get the same error.
#[test]
fn blame_and_history_match_the_projected_files() {
    let th = TestHub::start();
    for seed in seeds(&[301, 302, 303]) {
        let carol = 720_000 + seed as i64;
        let (policy_text, bindings) = policy(carol);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut rng = Rng::new(seed);
        random_history(&th, &mut h, &mut rng, 50);
        let project = h.project(&th);
        let all: BTreeSet<String> = h.files.values().flat_map(|f| f.keys().filter(|k| !k.ends_with('/')).cloned()).collect();
        let (mut blamed, mut listed) = (0usize, 0usize);
        for (who, viewer) in viewers(carol).into_iter().chain([("admin", admin())]) {
            let p = projections(&th, &h, &project, &viewer);
            let view = project.view(&viewer);
            let m = model(&h, &p, &view);
            let copy = copy_for(&th, &h, &project, &viewer, &p);
            let a = ask(&th, &h, &viewer);
            warm_up(&th, &h, &viewer);
            let mut revs: Vec<(String, ObjectId)> = h.branches.iter().map(|(b, t)| (b.clone(), p[t])).collect();
            let mine: Vec<ObjectId> = m.parents.keys().copied().filter(|x| *x != root_snapshot_id()).collect::<BTreeSet<_>>().into_iter().collect();
            for _ in 0..3 {
                let x = mine[rng.below(mine.len())];
                revs.push((x.hex(), x));
            }
            let missing = blame_all(&th, &h, &a, "main", "pub/no-such-file-6f1.txt", false, Limits::default()).unwrap_err();
            let missing_h = history_all(&th, &h, &a, "main", "pub/no-such-file-6f1.txt", false, 5).unwrap_err();
            for (rev, x) in &revs {
                let order: Vec<ObjectId> = model_log(&th, &copy, *x).iter().map(|s| ObjectId::from_hex(s).unwrap()).collect();
                let mut memo = HashMap::new();
                for path in &all {
                    let readable = view.read(path);
                    // Blame.
                    let got = blame_all(&th, &h, &a, rev, path, false, Limits::default());
                    match m.files[x].get(path) {
                        Some(_) if readable => {
                            let (lines, _) = got.unwrap_or_else(|e| panic!("seed {seed}, {who}: blame {path}@{rev}: {e}"));
                            assert_eq!(lines, model_blame(&m, *x, path, &mut memo), "seed {seed}, {who}: blame {path}@{rev}");
                            blamed += 1;
                        }
                        _ if !readable => assert_eq!(got.unwrap_err(), missing, "seed {seed}, {who}: hidden {path}"),
                        _ => {}
                    }
                    // File history, in small pages.
                    let got = history_all(&th, &h, &a, rev, path, false, 2);
                    let want = model_history(&m, *x, path);
                    if want.is_empty() {
                        assert_eq!(got.unwrap_err(), missing_h, "seed {seed}, {who}: history of {path}@{rev}");
                        continue;
                    }
                    let got = got.unwrap_or_else(|e| panic!("seed {seed}, {who}: history {path}@{rev}: {e}"));
                    let want: Vec<String> = order.iter().filter(|s| want.contains(s)).map(|s| s.hex()).collect();
                    assert_eq!(got.iter().map(|e| e.0.clone()).collect::<Vec<_>>(), want, "seed {seed}, {who}: history {path}@{rev}");
                    for (s, p, status) in &got {
                        assert_eq!(p, path);
                        let s = ObjectId::from_hex(s).unwrap();
                        let before = m.parents[&s].first().and_then(|p0| m.files[p0].get(path));
                        let want = match (before, m.files[&s].get(path)) {
                            (None, _) => "added",
                            (_, None) => "deleted",
                            _ => "modified",
                        };
                        assert_eq!(status, want, "seed {seed}, {who}: {path}@{}", s.short());
                    }
                    listed += got.len();
                }
            }
        }
        assert!(blamed > 100 && listed > 300, "seed {seed}: only {blamed} blames and {listed} history entries checked");
        println!("seed {seed}: {blamed} blames and {listed} history entries checked against the model");
    }
}

// ---- boundary cuts -------------------------------------------------------------------

fn lines(tag: &str, n: usize) -> Vec<u8> {
    (0..n).map(|i| format!("{tag} {i}\n")).collect::<String>().into_bytes()
}

/// Row 5: a file moved out of a folder a viewer cannot read is added for
/// them (its lines are the moving change's, and no answer names the hidden
/// path or change); one moved into it is deleted; a reader of both sides
/// follows the rename. The same for a file copied out of a hidden folder.
#[test]
fn blame_and_history_cut_at_the_boundary() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut f = Files::new();
    let mut ts = 1_700_000_000_000i64;
    let mut commit = |h: &mut Hist, f: &Files, parents: &[ObjectId], n: u8| {
        ts += 1000;
        h.commit(&th, parents, f.clone(), [n; 16], ts, None)
    };
    f.insert("fin/core.txt".into(), lines("core", 8));
    f.insert("pub/old.txt".into(), lines("old", 4));
    let c1 = commit(&mut h, &f, &[root_snapshot_id()], 1);
    let mut core = lines("core", 8);
    core.extend(b"core edit\n");
    f.insert("fin/core.txt".into(), core.clone());
    let c2 = commit(&mut h, &f, &[c1], 2);
    // Moved out of fin/ (and a line added), then edited.
    f.remove("fin/core.txt");
    core.extend(b"moved out\n");
    f.insert("pub/pay.txt".into(), core.clone());
    let c3 = commit(&mut h, &f, &[c2], 3);
    let mut pay = core.clone();
    pay.extend(b"pay edit\n");
    f.insert("pub/pay.txt".into(), pay);
    let c4 = commit(&mut h, &f, &[c3], 4);
    // Moved into fin/.
    let old = f.remove("pub/old.txt").unwrap();
    f.insert("fin/old.txt".into(), old);
    let c5 = commit(&mut h, &f, &[c4], 5);
    h.set_branch(&th, "main", c5);
    let project = h.project(&th);
    let finance = viewers(1)[3].1.clone();
    for (who, viewer, reads_fin) in [("anyone on Earth", Viewer::default(), false), ("finance", finance, true), ("admin", admin(), true)] {
        let p = projections(&th, &h, &project, &viewer);
        let a = ask(&th, &h, &viewer);
        warm_up(&th, &h, &viewer);
        let (c1, c2, c3, c4, c5) = (p[&c1].hex(), p[&c2].hex(), p[&c3].hex(), p[&c4].hex(), p[&c5].hex());
        let (blame, pages) = blame_all(&th, &h, &a, "main", "pub/pay.txt", true, Limits::default()).unwrap();
        let history = history_all(&th, &h, &a, "main", "pub/pay.txt", true, 50).unwrap();
        let moved_in = history_all(&th, &h, &a, &c5, "pub/old.txt", true, 50).unwrap();
        if reads_fin {
            // The lines from fin/core.txt keep their changes and path.
            assert_eq!(blame[0], (c1.clone(), "fin/core.txt".into(), 1), "{who}");
            assert_eq!(blame[8], (c2.clone(), "fin/core.txt".into(), 9), "{who}");
            assert_eq!(blame[9], (c3.clone(), "pub/pay.txt".into(), 10), "{who}");
            assert_eq!(blame[10], (c4.clone(), "pub/pay.txt".into(), 11), "{who}");
            let want: Vec<(String, String, String)> = vec![
                (c4.clone(), "pub/pay.txt".into(), "modified".into()),
                (c3.clone(), "pub/pay.txt".into(), "renamed".into()),
                (c2.clone(), "fin/core.txt".into(), "modified".into()),
                (c1.clone(), "fin/core.txt".into(), "added".into()),
            ];
            assert_eq!(history, want, "{who}");
            let into = history_all(&th, &h, &a, "main", "fin/old.txt", true, 50).unwrap();
            assert_eq!(into, vec![(c5.clone(), "fin/old.txt".into(), "renamed".into()), (c1.clone(), "pub/old.txt".into(), "added".into())], "{who}");
        } else {
            // Cut: every line of the moved file is the moving change's.
            assert!(blame[..10].iter().all(|l| *l == (c3.clone(), "pub/pay.txt".into(), l.2)), "{who}: {blame:?}");
            assert_eq!(blame[10], (c4.clone(), "pub/pay.txt".into(), 11));
            assert_eq!(history, vec![(c4.clone(), "pub/pay.txt".into(), "modified".into()), (c3.clone(), "pub/pay.txt".into(), "added".into())], "{who}");
            // The hidden change before the move is no revision of theirs
            // (c1 and c2 project to the same snapshot, which holds only pub/old.txt).
            assert_eq!(c1, c2);
            let text: String = pages.iter().map(|v| v.to_string()).collect::<String>() + &format!("{history:?}{moved_in:?}");
            assert!(!text.contains("fin/"), "{who}: a hidden path in {text}");
            assert!(!text.contains(&h.order[1].hex()), "{who}: a hidden change in {text}");
        }
        // Moved into fin/: a deletion for the reader of pub/ only.
        assert_eq!(moved_in[0], (c5.clone(), "pub/old.txt".into(), "deleted".into()), "{who}");
        assert_eq!(moved_in[1], (c1.clone(), "pub/old.txt".into(), "added".into()), "{who}");
    }
}

// ---- kept blames and budgets ---------------------------------------------------------

/// A long history of one file (readable) among hidden changes: blames are
/// kept every few versions and at every version asked for, a second blame
/// costs a fraction of the first, a blame stopped at its budget goes on
/// from what it kept to the same answer, and the memory bound is kept.
#[test]
fn blame_keeps_versions_and_resumes() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut rng = Rng::new(17);
    let mut f = Files::new();
    let mut body: Vec<String> = (0..120).map(|i| format!("line {i}\n")).collect();
    let mut tip = root_snapshot_id();
    for i in 0..200usize {
        let k = rng.below(body.len());
        if rng.chance(30) {
            body.insert(k, format!("inserted {i}\n"));
        } else {
            body[k] = format!("edited {i}\n");
        }
        f.insert("pub/long.txt".into(), body.concat().into_bytes());
        if i % 3 == 0 {
            f.insert(format!("fin/h{}.txt", i % 5), text(&mut rng, "h", 4));
        }
        tip = h.commit(&th, &[tip], f.clone(), [(i % 250) as u8; 16], 1_700_000_000_000 + i as i64 * 1000, None);
        if i == 120 {
            h.set_branch(&th, "old", tip);
        }
    }
    h.set_branch(&th, "main", tip);
    let project = h.project(&th);
    let viewer = Viewer::default();
    let p = projections(&th, &h, &project, &viewer);
    let m = model(&h, &p, &project.view(&viewer));
    let a = ask(&th, &h, &viewer);
    warm_up(&th, &h, &viewer);
    let want = model_blame(&m, p[&tip], "pub/long.txt", &mut HashMap::new());
    let work = |pages: &[Value]| pages.iter().map(|v| v["work"].as_u64().unwrap()).sum::<u64>();
    let (first, pages) = blame_all(&th, &h, &a, "main", "pub/long.txt", false, Limits::default()).unwrap();
    assert_eq!(first, want);
    let first_work = work(&pages);
    let kept: i64 = th.rt.block_on(async {
        sqlx::query_scalar("SELECT COUNT(*) FROM blame_memo WHERE project_id = $1").bind(h.id).fetch_one(&h.hub.db).await.unwrap()
    });
    assert!((200 / 32..=200 / 32 + 1).contains(&kept), "{kept} kept blames for 200 versions");
    let (again, pages) = blame_all(&th, &h, &a, "main", "pub/long.txt", false, Limits::default()).unwrap();
    assert_eq!(again, want);
    println!("first blame: work {first_work}; again: {}", work(&pages));
    assert!(work(&pages) * 2 < first_work, "kept: {} against {first_work}", work(&pages));
    // An older version starts from the nearest kept one below it.
    let old = p[&h.branches["old"]];
    let (o, pages) = blame_all(&th, &h, &a, "old", "pub/long.txt", false, Limits::default()).unwrap();
    assert_eq!(o, model_blame(&m, old, "pub/long.txt", &mut HashMap::new()));
    println!("an older version: work {}", work(&pages));
    assert!(work(&pages) < first_work, "from a kept version: {} against {first_work}", work(&pages));
    // From nothing, with a budget of a few diffs: stops, keeps, goes on.
    forget_blames(&th, &h);
    let tiny = Limits {
        blame: BlameLimits { work: 3_000, ..BlameLimits::default() },
        ..Limits::default()
    };
    let mut stops = 0;
    let got = loop {
        let q = BlameParams { rev: Some("main".into()), path: "pub/long.txt".into(), ..Default::default() };
        match th.rt.block_on(query::blame(&h.hub, &a, q, tiny)) {
            Ok(v) => break v,
            Err(Error::Api { code: "partial", .. }) => stops += 1,
            Err(e) => panic!("{e:?}"),
        }
        assert!(stops < 200, "no progress");
    };
    assert!(stops > 2, "the budget never stopped it ({stops})");
    let lines: Origins = got["lines"].as_array().unwrap().iter().map(|l| (l["snapshot"].as_str().unwrap().into(), l["path"].as_str().unwrap().into(), l["origin_line"].as_u64().unwrap() as u32)).collect();
    assert_eq!(lines, want);
    // Memory: a bound below one version's text and blame refuses. The walk
    // down stops at it first, keeping where it got to (BUG-1212), until
    // the versions to compute do not fit.
    forget_blames(&th, &h);
    let small = Limits {
        blame: BlameLimits { held: 2_000, ..BlameLimits::default() },
        ..Limits::default()
    };
    let mut partials = 0;
    let r = loop {
        let r = th.rt.block_on(query::blame(&h.hub, &a, BlameParams { path: "pub/long.txt".into(), ..Default::default() }, small));
        match r {
            Err(Error::Api { code: "partial", .. }) if partials < 500 => partials += 1,
            r => break r,
        }
    };
    assert!(matches!(r, Err(Error::Api { code: "too_wide", .. })), "after {partials} partial answers: {r:?}");
}

// ---- hostile inputs ------------------------------------------------------------------

/// Row 10, and row 6 for cursors: files that are not text, large files,
/// pages past the cap, bad paths and cursors, cursors naming hidden or
/// missing versions (one error), and many blames at once (bounded by the
/// process's slots, every one answered).
#[test]
fn blame_hostile_inputs_are_bounded() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut f = Files::new();
    f.insert("pub/big.txt".into(), vec![b'x'; (1 << 20) + 1]);
    f.insert("pub/nul.txt".into(), b"a\0b\n".to_vec());
    f.insert("pub/latin.txt".into(), vec![0xe9, b'\n']);
    f.insert("pub/many.txt".into(), (0..12_000).map(|i| format!("{i}\n")).collect::<String>().into_bytes());
    f.insert("pub/d/x.txt".into(), b"x\n".to_vec());
    f.insert("fin/hidden.txt".into(), b"hidden\n".to_vec());
    for i in 0..24 {
        f.insert(format!("pub/c{i}.txt"), lines(&format!("c{i}"), 50));
    }
    let mut tip = h.commit(&th, &[root_snapshot_id()], f.clone(), [1; 16], 1_700_000_000_000, None);
    for i in 0..24 {
        f.insert(format!("pub/c{i}.txt"), lines(&format!("c{i}x"), 50));
    }
    tip = h.commit(&th, &[tip], f.clone(), [2; 16], 1_700_000_001_000, None);
    h.set_branch(&th, "main", tip);
    let viewer = Viewer::default();
    let a = ask(&th, &h, &viewer);
    warm_up(&th, &h, &viewer);
    let blame = |path: &str| th.rt.block_on(query::blame(&h.hub, &a, BlameParams { path: path.into(), ..Default::default() }, Limits::default()));
    let code = |r: veil_server::error::Result<Value>| match r {
        Ok(_) => "ok".to_string(),
        Err(Error::Api { status, code, message }) => format!("{status} {code} {message}"),
        Err(e) => panic!("{e:?}"),
    };
    for p in ["pub/big.txt", "pub/nul.txt", "pub/latin.txt"] {
        assert!(code(blame(p)).contains("not a plain-text file"), "{p}");
    }
    assert!(code(blame("pub/d")).contains("a folder"));
    assert_eq!(code(blame("fin/hidden.txt")), code(blame("fin/nothing.txt")));
    for bad in ["", "/pub/x", "pub/../fin/hidden.txt", &"a/".repeat(3000)] {
        assert!(code(blame(bad)).starts_with("4"), "{bad:?}");
    }
    // A page holds at most 10,000 lines, then goes on.
    let v = th.rt.block_on(query::blame(&h.hub, &a, BlameParams { path: "pub/many.txt".into(), n: Some(1 << 40), ..Default::default() }, Limits::default())).unwrap();
    assert_eq!((v["lines"].as_array().unwrap().len(), v["next"].as_u64()), (10_000, Some(10_000)));
    let v = th.rt.block_on(query::blame(&h.hub, &a, BlameParams { path: "pub/many.txt".into(), after: Some(usize::MAX), ..Default::default() }, Limits::default())).unwrap();
    assert!(v["lines"].as_array().unwrap().is_empty() && v["next"].is_null());
    // Cursors.
    let hist = |after: &str| code(th.rt.block_on(query::history(&h.hub, &a, HistoryParams { after: Some(after.into()), ..Default::default() }, Limits::default())));
    let me = th.rt.block_on(query::resolve(&h.hub, &a, "main", Instant::now() + Duration::from_secs(60))).unwrap();
    let hex = |s: &str| hex::encode(s.as_bytes());
    assert!(hist("zz").contains("invalid cursor"));
    assert!(hist(&format!("{}.zz", me.hex())).contains("invalid cursor"));
    assert!(hist(&format!("{}.{}", me.hex(), hex("../x"))).contains("invalid cursor"));
    assert_eq!(hist(&format!("{}.{}", me.hex(), hex("fin/hidden.txt"))), hist(&format!("{}.{}", me.hex(), hex("fin/nothing.txt"))));
    assert_eq!(hist(&format!("{}.{}", ObjectId([9; 32]).hex(), hex("pub/c1.txt"))), code(Err(Error::not_found("no such revision that you can see"))));
    let long: Vec<String> = (0..1001).map(|_| format!("{}.{}", me.hex(), hex("pub/c1.txt"))).collect();
    assert!(hist(&long.join(",")).contains("cursor too long"));
    // Many blames at once: each waits for one of the process's slots.
    let hub = h.hub.clone();
    let results: Vec<String> = th.rt.block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for i in 0..24 {
            let (hub, a) = (hub.clone(), a.clone());
            set.spawn(async move {
                let q = BlameParams { path: format!("pub/c{i}.txt"), ..Default::default() };
                match query::blame(&hub, &a, q, Limits { deadline: Duration::from_secs(60), ..Limits::default() }).await {
                    Ok(v) => format!("{}", v["lines"].as_array().unwrap().len()),
                    Err(e) => format!("{e:?}"),
                }
            });
        }
        let mut out = Vec::new();
        while let Some(r) = set.join_next().await {
            out.push(r.unwrap());
        }
        out
    });
    assert!(results.iter().all(|r| r == "50"), "{results:?}");
    assert_eq!(h.hub.query.blames.available_permits(), query::files::BLAMES_AT_ONCE);
}

/// Row 11: concurrent fills of one view key write the same file history
/// as one fill does (rows a function of the projected history alone).
#[test]
fn file_history_rows_agree_across_fills() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(5);
    let mut rows_of = Vec::new();
    for racing in [1usize, 6] {
        let mut h = Hist::new(&th, &policy_text, &bindings);
        random_history(&th, &mut h, &mut Rng::new(61), 40);
        let project = h.project(&th);
        let viewer = Viewer::default();
        let tips: Vec<ObjectId> = h.branches.values().copied().collect();
        th.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for _ in 0..racing {
                let (hub, project, viewer, tips) = (h.hub.clone(), project.clone(), viewer.clone(), tips.clone());
                set.spawn(async move { query::graph::extend(&hub, &project, &viewer, &tips).await.map(|_| ()) });
            }
            while let Some(r) = set.join_next().await {
                r.unwrap().unwrap();
            }
        });
        let mut rows: Vec<(String, i64, String, String)> = th.rt.block_on(async {
            sqlx::query_as("SELECT path_key, depth, snapshot, change FROM view_file_history WHERE project_id = $1")
                .bind(h.id)
                .fetch_all(&h.hub.db)
                .await
                .unwrap()
        });
        rows.sort();
        assert!(rows.len() > 20, "{} rows", rows.len());
        rows_of.push(rows);
    }
    assert_eq!(rows_of[0], rows_of[1]);
}

// ---- speed -----------------------------------------------------------------------

fn pct(mut v: Vec<Duration>, p: usize) -> Duration {
    v.sort();
    v[(v.len() * p / 100).min(v.len() - 1)]
}

/// The design's targets (§5): blame of a 5,000-line file changed many times
/// (precomputed: 50 ms; the first time: 1 s) and `history --follow`
/// (50 ms), for an admin and for anyone on Earth (who cannot see a fifth
/// of the changes). `VEIL_BLAME_BENCH_VERSIONS` versions of the file
/// (default 100; the gate run 2,000), one hidden change between every two,
/// and a rename half way.
#[test]
fn blame_speed() {
    let versions: usize = std::env::var("VEIL_BLAME_BENCH_VERSIONS").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
    let rounds: usize = std::env::var("VEIL_BLAME_BENCH_ROUNDS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut rng = Rng::new(91);
    let mut body: Vec<String> = (0..5000).map(|i| format!("fn line_{i}() {{ let x = {}; }}\n", rng.next() % 100_000)).collect();
    let mut f = Files::new();
    for i in 0..50 {
        f.insert(format!("pub/other/o{i}.txt"), text(&mut rng, "o", 30));
    }
    let mut path = "pub/hot/old_name.rs".to_string();
    let mut tip = root_snapshot_id();
    let t0 = Instant::now();
    for i in 0..versions {
        for _ in 0..1 + rng.below(3) {
            let k = rng.below(body.len());
            body[k] = format!("fn line_{k}() {{ edited({i}); }}\n");
        }
        if i == versions / 2 {
            f.remove(&path);
            path = "pub/hot/new_name.rs".into();
        }
        f.insert(path.clone(), body.concat().into_bytes());
        let mut change = [0u8; 16];
        change[..8].copy_from_slice(&rng.next().to_le_bytes());
        tip = h.commit(&th, &[tip], f.clone(), change, 1_700_000_000_000 + i as i64 * 2000, None);
        f.insert(format!("fin/h{}.txt", i % 20), text(&mut rng, "h", 5));
        change[8] ^= 1;
        tip = h.commit(&th, &[tip], f.clone(), change, 1_700_000_000_000 + i as i64 * 2000 + 1000, None);
    }
    h.set_branch(&th, "main", tip);
    println!("blame_speed: built {} snapshots ({versions} versions of a 5,000-line file) in {:?}", h.order.len(), t0.elapsed());
    let project = h.project(&th);
    for (who, viewer) in [("admin", admin()), ("anyone on Earth", Viewer::default())] {
        let a = ask(&th, &h, &viewer);
        let t = Instant::now();
        projections(&th, &h, &project, &viewer);
        let projected = t.elapsed();
        let t = Instant::now();
        let tips: Vec<ObjectId> = h.branches.values().copied().collect();
        th.rt.block_on(query::graph::extend(&h.hub, &project, &viewer, &tips)).unwrap();
        let filled = t.elapsed();
        let rows: i64 = th.rt.block_on(async {
            sqlx::query_scalar("SELECT COUNT(*) FROM view_file_history WHERE project_id = $1").bind(h.id).fetch_one(&h.hub.db).await.unwrap()
        });
        println!("blame_speed: {who}: projected every snapshot (S1) in {projected:?}; then filled the graph and its file history in {filled:?} ({rows} file-history rows in the project)");
        let hub = h.hub.clone();
        let bq = |follow: bool| BlameParams { path: path.clone(), follow: Some(follow), ..Default::default() };
        // Where a first blame's time goes: the walk down alone (a diff
        // budget of 1 stops it at its first diff), then one diff and one
        // version's read on their own.
        let walk_only = Limits { blame: BlameLimits { work: 1, walk: u64::MAX, ..BlameLimits::default() }, deadline: Duration::from_secs(600), ..Limits::default() };
        let t = Instant::now();
        let r = th.rt.block_on(query::blame(&hub, &a, bq(true), walk_only));
        assert!(matches!(r, Err(Error::Api { code: "partial", .. })), "{r:?}");
        let walk = t.elapsed();
        forget_blames(&th, &h);
        let texts: Vec<Vec<u8>> = h.order.iter().rev().take(41).filter_map(|s| h.files[s].get(&path).cloned()).collect();
        let t = Instant::now();
        let mut diffs = 0;
        for w in texts.windows(2) {
            let n = veil_core::blame::line_ranges(&w[1]).len();
            std::hint::black_box(veil_core::blame::map_lines(&w[0], &w[1], n));
            diffs += 1;
        }
        let per_diff = t.elapsed() / diffs.max(1);
        let tip_file = th.rt.block_on(query::file(&hub, &a, query::FileParams { rev: None, path: path.clone() }, Limits::default())).unwrap();
        let t = Instant::now();
        for _ in 0..20 {
            std::hint::black_box(th.rt.block_on(query::file(&hub, &a, query::FileParams { rev: None, path: path.clone() }, Limits::default())).unwrap());
        }
        println!(
            "blame_speed: {who}: walk down over {versions} versions: {walk:?}; one diff of 5,000 lines (map_lines): {per_diff:?}; one `file` request of {} bytes (graph, projected tree, object): {:?}",
            tip_file.1.len(),
            t.elapsed() / 20
        );
        // The first time: from nothing (a blame stopped at its budget goes
        // on, and counts).
        let t = Instant::now();
        let mut tries = 0;
        let first = loop {
            tries += 1;
            match th.rt.block_on(query::blame(&hub, &a, bq(true), Limits::default())) {
                Ok(v) => break v,
                // Stopped at its budget or deadline: what it computed is
                // kept, and the next request goes on.
                Err(Error::Api { code: "partial" | "deadline", .. }) if tries < 100 => continue,
                Err(e) => panic!("{e:?}"),
            }
        };
        let first_time = t.elapsed();
        let origins: HashSet<&str> = first["lines"].as_array().unwrap().iter().map(|l| l["snapshot"].as_str().unwrap()).collect();
        println!(
            "blame_speed: {who}: first blame {first_time:?} ({tries} requests, work {}, {} lines from {} changes)",
            first["work"],
            first["lines"].as_array().unwrap().len(),
            origins.len()
        );
        let mut runs: Vec<(&str, Vec<Duration>, u64)> = Vec::new();
        for (name, f) in [
            ("blame --follow (precomputed)", 0),
            ("history --follow -n 50", 1),
            ("history --follow, every page", 2),
        ] {
            let mut times = Vec::new();
            let mut work = 0;
            for _ in 0..rounds {
                let t = Instant::now();
                let v = th.rt.block_on(async {
                    match f {
                        0 => query::blame(&hub, &a, bq(true), Limits::default()).await.unwrap(),
                        1 => query::history(&hub, &a, HistoryParams { path: Some(path.clone()), follow: Some(true), n: Some(50), ..Default::default() }, Limits::default()).await.unwrap(),
                        _ => {
                            let mut after = None;
                            let mut total = 0;
                            loop {
                                let q = HistoryParams { path: Some(path.clone()), follow: Some(true), n: Some(1000), after: after.clone(), ..Default::default() };
                                let v = query::history(&hub, &a, q, Limits::default()).await.unwrap();
                                total += v["entries"].as_array().unwrap().len();
                                after = v["next"].as_str().map(str::to_string);
                                if after.is_none() {
                                    assert_eq!(total, versions, "{v}");
                                    break v;
                                }
                            }
                        }
                    }
                });
                times.push(t.elapsed());
                work = v["work"].as_u64().unwrap();
            }
            runs.push((name, times, work));
        }
        for (name, times, work) in runs {
            println!("blame_speed: {who}: {name}: p50 {:?} p99 {:?} (work {work})", pct(times.clone(), 50), pct(times, 99));
        }
    }
}

// ---- S14 cycle 1: adversarial review ---------------------------------------------------

mod s14c1_adversarial {
    use super::*;

    /// The snapshot ids of a blame's lines, in order.
    pub(super) fn origins(v: &Value) -> Vec<String> {
        v["lines"].as_array().unwrap().iter().map(|l| l["snapshot"].as_str().unwrap().to_string()).collect()
    }

    /// BUG-1210. A viewer graph row whose snapshot has no file-history rows
    /// is trusted as if it had them. That is the state an S13 server leaves
    /// beside S14 servers after migration 0015 (a rolling restart, which
    /// `db::migrate` supports: the S13 server goes on filling, writing graph
    /// rows only). Here the S13 server's fill is reproduced by removing one
    /// snapshot's file-history rows after the fill; then an S14 server fills
    /// the next landing on top. Blame and history answer from the older
    /// version, silently and for good: the next landing's `prev` skips the
    /// snapshot, and nothing ever fills it again.
    #[test]
    fn bug_1210_graph_rows_without_file_history_give_silently_wrong_answers() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut f = Files::new();
        f.insert("pub/a.txt".into(), b"one\n".to_vec());
        let c1 = h.commit(&th, &[root_snapshot_id()], f.clone(), [1; 16], 1_700_000_000_000, None);
        f.insert("pub/a.txt".into(), b"one\ntwo\n".to_vec());
        let c2 = h.commit(&th, &[c1], f.clone(), [2; 16], 1_700_000_001_000, None);
        h.set_branch(&th, "main", c2);
        let viewer = Viewer::default();
        warm_up(&th, &h, &viewer);
        // c2's graph row as an S13 server writes it: no file history, and
        // (since the fix) no `files` mark; that server's rows were never in
        // this server's cache.
        th.rt.block_on(async {
            sqlx::query("DELETE FROM view_file_history WHERE project_id = $1 AND snapshot = $2").bind(h.id).bind(c2.hex()).execute(&h.hub.db).await.unwrap();
            sqlx::query("UPDATE view_graph SET files = NULL WHERE project_id = $1 AND snapshot = $2").bind(h.id).bind(c2.hex()).execute(&h.hub.db).await.unwrap();
        });
        h.hub.query.rows.clear();
        // The next landing, filled by an S14 server.
        f.insert("pub/a.txt".into(), b"one\ntwo\nthree\n".to_vec());
        let c3 = h.commit(&th, &[c2], f.clone(), [3; 16], 1_700_000_002_000, None);
        h.set_branch(&th, "main", c3);
        warm_up(&th, &h, &viewer);
        let p = projections(&th, &h, &h.project(&th), &viewer);
        assert_eq!((p[&c1], p[&c2], p[&c3]), (c1, c2, c3), "every change is public");
        let a = ask(&th, &h, &viewer);
        // The server may refuse (it cannot know the missing rows); it may not answer wrongly.
        let blame = th.rt.block_on(query::blame(&h.hub, &a, BlameParams { path: "pub/a.txt".into(), ..Default::default() }, Limits::default()));
        let history = history_all(&th, &h, &a, "main", "pub/a.txt", false, 50);
        println!("blame: {:?}\nhistory: {history:?}", blame.as_ref().map(origins));
        if let Ok(v) = &blame {
            assert_eq!(origins(v), [c1.hex(), c2.hex(), c3.hex()], "a silently wrong blame: line 2 is c2's");
        }
        if let Ok(hist) = &history {
            let got: Vec<String> = hist.iter().map(|e| e.0.clone()).collect();
            assert_eq!(got, [c3.hex(), c2.hex(), c1.hex()], "a silently wrong file history: c2 changed the file");
        }
        // Since the fix: answered, and right (c2 filled again).
        assert!(blame.is_ok() && history.is_ok());
    }

    /// BUG-1210's fix, for a whole graph: every graph row as an S13 server
    /// fills them (graph rows only, unmarked), then a landing; S14 fills
    /// them again with their file history, and every viewer's blame and
    /// file history equal the model's.
    #[test]
    fn s13_filled_graphs_are_filled_again_with_file_history() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(3);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut rng = Rng::new(404);
        random_history(&th, &mut h, &mut rng, 30);
        let project = h.project(&th);
        for (_, viewer) in viewers(3) {
            warm_up(&th, &h, &viewer);
        }
        warm_up(&th, &h, &admin());
        th.rt.block_on(async {
            sqlx::query("DELETE FROM view_file_history WHERE project_id = $1").bind(h.id).execute(&h.hub.db).await.unwrap();
            sqlx::query("UPDATE view_graph SET files = NULL WHERE project_id = $1").bind(h.id).execute(&h.hub.db).await.unwrap();
        });
        h.hub.query.rows.clear();
        // One more landing on main.
        let tip = h.branches["main"];
        let mut f = h.files[&tip].clone();
        f.insert("pub/after-s13.txt".into(), lines("after", 5));
        if let Some(k) = f.keys().find(|k| k.starts_with("pub/") && !k.ends_with('/')).cloned() {
            let mut c = f[&k].clone();
            c.extend(b"edited after the S13 fill\n");
            f.insert(k, c);
        }
        let c = h.commit(&th, &[tip], f, [77; 16], 1_800_000_000_000, None);
        h.set_branch(&th, "main", c);
        let all: BTreeSet<String> = h.files.values().flat_map(|f| f.keys().filter(|k| !k.ends_with('/')).cloned()).collect();
        let mut checked = 0;
        for (who, viewer) in viewers(3).into_iter().chain([("admin", admin())]) {
            let p = projections(&th, &h, &project, &viewer);
            let view = project.view(&viewer);
            let m = model(&h, &p, &view);
            let copy = copy_for(&th, &h, &project, &viewer, &p);
            let a = ask(&th, &h, &viewer);
            warm_up(&th, &h, &viewer);
            let x = p[&h.branches["main"]];
            let order: Vec<ObjectId> = model_log(&th, &copy, x).iter().map(|s| ObjectId::from_hex(s).unwrap()).collect();
            let mut memo = HashMap::new();
            for path in all.iter().filter(|p| view.read(p)) {
                if m.files[&x].contains_key(path) {
                    let (got, _) = blame_all(&th, &h, &a, "main", path, false, Limits::default()).unwrap();
                    assert_eq!(got, model_blame(&m, x, path, &mut memo), "{who}: blame {path}");
                    checked += 1;
                }
                let want = model_history(&m, x, path);
                if !want.is_empty() {
                    let got: Vec<String> = history_all(&th, &h, &a, "main", path, false, 3).unwrap().into_iter().map(|e| e.0).collect();
                    let want: Vec<String> = order.iter().filter(|s| want.contains(s)).map(|s| s.hex()).collect();
                    assert_eq!(got, want, "{who}: history {path}");
                }
            }
        }
        assert!(checked > 50, "{checked}");
    }

    /// BUG-1212. A blame keeps its progress when it stops while computing
    /// (its budget, the deadline, the memory bound), but not when it stops
    /// on its walk down to the versions it starts from: nothing is computed
    /// or kept yet, so the next request walks the same way and stops in the
    /// same place. A first blame whose walk down is longer than the deadline
    /// never answers. Here: a file renamed at each of 400 changes, blamed
    /// with `follow` (each version's walk diffs the snapshot's projected
    /// trees to pair the rename), with a deadline a quarter of what the
    /// walk down takes.
    #[test]
    fn bug_1212_a_blame_stopped_on_its_walk_down_never_makes_progress() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut f = Files::new();
        let mut body: Vec<String> = (0..40).map(|i| format!("line {i} of a file that moves at every change\n")).collect();
        for i in 0..20 {
            f.insert(format!("pub/other/o{i}.txt"), lines(&format!("o{i}"), 10));
        }
        let mut tip = root_snapshot_id();
        let mut path = String::new();
        for i in 0..400usize {
            body[i % 40] = format!("edited at change {i}\n");
            f.remove(&path);
            path = format!("pub/moving/name{}.txt", i % 2);
            f.insert(path.clone(), body.concat().into_bytes());
            let mut change = [7u8; 16];
            change[..2].copy_from_slice(&(i as u16).to_le_bytes());
            tip = h.commit(&th, &[tip], f.clone(), change, 1_700_000_000_000 + i as i64 * 1000, None);
        }
        h.set_branch(&th, "main", tip);
        let viewer = Viewer::default();
        let a = ask(&th, &h, &viewer);
        warm_up(&th, &h, &viewer);
        let q = || BlameParams { path: path.clone(), follow: Some(true), ..Default::default() };
        // How long the walk down takes: a budget of one diff stops the blame
        // right after it (warm: the second time).
        let walk = Limits { blame: BlameLimits { work: 1, ..BlameLimits::default() }, deadline: Duration::from_secs(120), ..Limits::default() };
        let mut took = Duration::ZERO;
        for _ in 0..2 {
            forget_blames(&th, &h);
            let t = Instant::now();
            let r = th.rt.block_on(query::blame(&h.hub, &a, q(), walk));
            took = t.elapsed();
            assert!(matches!(r, Err(Error::Api { code: "partial", .. })), "{r:?}");
        }
        forget_blames(&th, &h);
        let deadline = took / 4;
        println!("walk down: {took:?}; deadline {deadline:?}");
        let short = Limits { deadline, ..Limits::default() };
        let mut answers = Vec::new();
        for _ in 0..40 {
            match th.rt.block_on(query::blame(&h.hub, &a, q(), short)) {
                Ok(v) => {
                    assert_eq!(v["line_count"], 40);
                    return;
                }
                Err(Error::Api { code, .. }) => answers.push(code),
                Err(e) => panic!("{e:?}"),
            }
        }
        let kept: i64 = th.rt.block_on(async {
            sqlx::query_scalar("SELECT COUNT(*) FROM blame_memo WHERE project_id = $1").bind(h.id).fetch_one(&h.hub.db).await.unwrap()
        });
        panic!("40 requests and no blame ({kept} versions kept): {answers:?}");
    }

    /// BUG-1213 (BUG-1076's class). A history cursor names each version
    /// still to walk with its path inline (`snapshot.hex(path)`), up to
    /// `Limits::cursor` (1,000) versions, and the route takes it in its URL.
    /// A frontier of a few dozen versions of a file with a long path (a
    /// path may have 4,096 bytes, so a version up to 8,257 bytes) already
    /// passes what a request line can carry (64 KiB), and the history
    /// cannot be paged past it, for everyone who sees the file. Here: a
    /// file of a 1,500-byte path changed on 30 branches, merged together.
    #[test]
    fn bug_1213_a_history_cursor_is_longer_than_a_request_carries() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let path = format!("pub/{}f.txt", format!("{}/", "d".repeat(99)).repeat(15));
        assert!(path.len() > 1_500 && path.len() < 4096);
        let mut f = Files::new();
        f.insert(path.clone(), lines("base", 40));
        let c0 = h.commit(&th, &[root_snapshot_id()], f.clone(), [1; 16], 1_700_000_000_000, None);
        let mut branches = Vec::new();
        let mut merged: Vec<String> = (0..40).map(|i| format!("base {i}\n")).collect();
        for i in 0..30usize {
            let mut body: Vec<String> = (0..40).map(|j| format!("base {j}\n")).collect();
            body[i] = format!("branch {i}\n");
            merged[i] = format!("branch {i}\n");
            let mut g = f.clone();
            g.insert(path.clone(), body.concat().into_bytes());
            branches.push(h.commit(&th, &[c0], g, [10 + i as u8; 16], 1_700_000_001_000 + i as i64 * 1000, None));
        }
        f.insert(path.clone(), merged.concat().into_bytes());
        let m = h.commit(&th, &branches, f.clone(), [99; 16], 1_700_000_100_000, None);
        h.set_branch(&th, "main", m);
        warm_up(&th, &h, &Viewer::default());
        let api = th.api();
        let base = format!("/v1/projects/{}/q/history", h.name);
        let first = api.get(None, &format!("{base}?path={path}&n=1"));
        assert_eq!(first.status, 200, "{}", String::from_utf8_lossy(&first.body));
        let next = first.json()["next"].as_str().unwrap().to_string();
        println!("a cursor of {} bytes", next.len());
        let second = api.get(None, &format!("{base}?after={next}&n=50"));
        assert_eq!(second.status, 200, "the second page: {} {}", second.status, String::from_utf8_lossy(&second.body));
        assert_eq!(second.json()["entries"].as_array().unwrap().len(), 31);
    }
}

// ---- S14 cycle 2: review of the cycle-1 fixes ------------------------------------------

mod s14c2_adversarial {
    use super::*;
    use crate::support::unique;

    /// Kept blames and cut walks of the project.
    fn progress(th: &TestHub, h: &Hist) -> (i64, i64) {
        th.rt.block_on(async {
            let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blame_memo WHERE project_id = $1").bind(h.id).fetch_one(&h.hub.db).await.unwrap();
            let walks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blame_walks WHERE project_id = $1").bind(h.id).fetch_one(&h.hub.db).await.unwrap();
            (kept, walks)
        })
    }

    /// BUG-1215. A walk down cut by its own budget (`BlameLimits::walk`)
    /// keeps where it got to, and the next requests blame those deeper
    /// versions first; but nothing shortens the walk from the version
    /// asked for down to them. Once they are kept, that walk costs what it
    /// cost the first time (each request reads its rows, windows, kept
    /// blames and renames afresh), passes the budget at the same place
    /// (the check comes before a version is expanded, kept or not) and is
    /// cut again with the same frontier: every request answers `partial`
    /// and nothing more is kept, for good. Here: a file renamed at each of
    /// 80 changes, blamed with `follow`, with walk budgets that its walk
    /// down passes (the default, 20,000 reads, is passed the same way by a
    /// longer history), and a deadline long enough not to matter.
    #[test]
    fn bug_1215_a_blame_whose_walk_down_passes_its_budget_never_finishes() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut f = Files::new();
        let mut body: Vec<String> = (0..40).map(|i| format!("line {i} of a file that moves at every change\n")).collect();
        for i in 0..10 {
            f.insert(format!("pub/other/o{i}.txt"), lines(&format!("o{i}"), 10));
        }
        let mut tip = root_snapshot_id();
        let mut path = String::new();
        for i in 0..80usize {
            body[i % 40] = format!("edited at change {i}\n");
            f.remove(&path);
            path = format!("pub/moving/name{}.txt", i % 2);
            f.insert(path.clone(), body.concat().into_bytes());
            let mut change = [9u8; 16];
            change[..2].copy_from_slice(&(i as u16).to_le_bytes());
            tip = h.commit(&th, &[tip], f.clone(), change, 1_700_000_000_000 + i as i64 * 1000, None);
        }
        h.set_branch(&th, "main", tip);
        let viewer = Viewer::default();
        let a = ask(&th, &h, &viewer);
        warm_up(&th, &h, &viewer);
        let q = || BlameParams { path: path.clone(), follow: Some(true), ..Default::default() };
        // What the whole walk down costs: unbounded, a diff budget of one.
        forget_blames(&th, &h);
        let whole = Limits { blame: BlameLimits { work: 1, walk: u64::MAX, ..BlameLimits::default() }, deadline: Duration::from_secs(120), ..Limits::default() };
        let r = th.rt.block_on(query::blame(&h.hub, &a, q(), whole));
        assert!(matches!(r, Err(Error::Api { code: "partial", .. })), "{r:?}");
        let mut stuck = Vec::new();
        for walk in [150u64, 400, 1_000] {
            forget_blames(&th, &h);
            let limits = Limits { blame: BlameLimits { walk, ..BlameLimits::default() }, deadline: Duration::from_secs(120), ..Limits::default() };
            let mut seen = Vec::new();
            let mut answered = false;
            for _ in 0..200 {
                match th.rt.block_on(query::blame(&h.hub, &a, q(), limits)) {
                    Ok(v) => {
                        assert_eq!(v["line_count"], 40);
                        answered = true;
                        break;
                    }
                    Err(Error::Api { code: "partial", .. }) => seen.push(progress(&th, &h)),
                    Err(e) => panic!("{e:?}"),
                }
            }
            println!("bug_1215: walk budget {walk}: answered {answered} after {} partial answers; (kept blames, cut walks) after each: {seen:?}", seen.len());
            if !answered {
                stuck.push((walk, seen.last().copied()));
            }
        }
        assert!(stuck.is_empty(), "blames that never finished (walk budget, kept blames and cut walks after 200 requests): {stuck:?}");
    }

    /// Every row of a project's viewer graphs and file history, without
    /// the project id (the same history in two projects compares equal).
    fn dump(th: &TestHub, h: &Hist) -> (Vec<String>, Vec<String>) {
        th.rt.block_on(async {
            type G = (String, String, i64, i64, String, i32, String, String, Option<bool>);
            let g: Vec<G> = sqlx::query_as(
                "SELECT view_key, snapshot, generation, depth, parents, flags, skip, down_id, files FROM view_graph WHERE project_id = $1",
            )
            .bind(h.id)
            .fetch_all(&h.hub.db)
            .await
            .unwrap();
            type F = (String, String, i64, String, String);
            let f: Vec<F> = sqlx::query_as("SELECT view_key, path_key, depth, snapshot, change FROM view_file_history WHERE project_id = $1")
                .bind(h.id)
                .fetch_all(&h.hub.db)
                .await
                .unwrap();
            let mut g: Vec<String> = g.iter().map(|x| format!("{x:?}")).collect();
            let mut f: Vec<String> = f.iter().map(|x| format!("{x:?}")).collect();
            g.sort();
            f.sort();
            (g, f)
        })
    }

    /// Guarantee 1 of the cycle-1 fixes (BUG-1210): rows an S13 server
    /// left (graph rows, no mark, no file history), all of them or the
    /// newest ones, filled again by several servers at once, are exactly
    /// what one S14 fill writes: the same graph rows, all marked, and the
    /// same file history.
    #[test]
    fn s13_rows_refilled_by_servers_at_once_equal_one_fill() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut answers = Vec::new();
        // (servers refilling at once, rows left unmarked: all, or those
        // above this generation)
        for (parallel, above) in [(0usize, 0i64), (1, 0), (6, 0), (6, 25), (3, 40)] {
            let mut h = Hist::new(&th, &policy_text, &bindings);
            random_history(&th, &mut h, &mut Rng::new(37), 50);
            let project = h.project(&th);
            let tips: Vec<ObjectId> = h.branches.values().copied().collect();
            let vs: Vec<Viewer> = viewers(1).into_iter().map(|(_, v)| v).chain([admin()]).collect();
            for v in &vs {
                th.rt.block_on(query::graph::extend(&h.hub, &project, v, &tips)).unwrap();
            }
            if parallel > 0 {
                th.rt.block_on(async {
                    sqlx::query(
                        "DELETE FROM view_file_history f WHERE project_id = $1 AND EXISTS (SELECT 1 FROM view_graph g \
                         WHERE g.project_id = f.project_id AND g.view_key = f.view_key AND g.snapshot = f.snapshot AND g.generation > $2)",
                    )
                    .bind(h.id)
                    .bind(above)
                    .execute(&h.hub.db)
                    .await
                    .unwrap();
                    sqlx::query("UPDATE view_graph SET files = NULL WHERE project_id = $1 AND generation > $2").bind(h.id).bind(above).execute(&h.hub.db).await.unwrap();
                });
                h.hub.query.rows.clear();
                th.rt.block_on(async {
                    let mut set = tokio::task::JoinSet::new();
                    for i in 0..parallel {
                        for v in &vs {
                            let (hub, project, v) = (h.hub.clone(), project.clone(), v.clone());
                            let mut tips = tips.clone();
                            if i % 2 == 1 {
                                tips.reverse();
                            }
                            set.spawn(async move { query::graph::extend(&hub, &project, &v, &tips).await.unwrap() });
                        }
                    }
                    while let Some(r) = set.join_next().await {
                        r.unwrap();
                    }
                });
            }
            let d = dump(&th, &h);
            assert!(d.0.iter().all(|r| r.ends_with("Some(true))")), "({parallel}, {above}): a row left unmarked");
            answers.push(((parallel, above), d));
        }
        let (_, first) = &answers[0];
        assert!(!first.0.is_empty() && !first.1.is_empty());
        for (case, d) in &answers[1..] {
            assert_eq!(d.0, first.0, "{case:?}: graph rows");
            assert_eq!(d.1, first.1, "{case:?}: file history");
        }
    }

    /// Guarantee 5 of the cycle-1 fixes (BUG-1211). `bug_1211_…` runs
    /// migration 0015 on a database `db::migrate` already brought to 0015,
    /// where `ADD COLUMN IF NOT EXISTS` does nothing, so it measures no
    /// change to the table. Here the column is removed first (the table as
    /// S13 left it, 300,000 rows), and the migration runs while S13 servers
    /// go on writing and reading graph rows with S13's own statements: it
    /// takes a small, size-independent time, and their statements fail at
    /// most with errors they retry.
    #[test]
    fn migration_0015_adds_its_column_in_bounded_time_beside_s13_servers() {
        const ROWS: i64 = 300_000;
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(4).build().unwrap();
        let admin = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
        let name = format!("{}{}", std::env::var("VEIL_TEST_DB_PREFIX").unwrap_or_default(), unique("veil_m15c2_"));
        rt.block_on(async {
            let db = veil_server::db::connect(&admin, 1).await.unwrap();
            sqlx::raw_sql(&format!("CREATE DATABASE {name}")).execute(&db).await.unwrap();
            db.close().await;
            let url = format!("{}/{name}", admin.rsplit_once('/').unwrap().0);
            let db = veil_server::db::connect(&url, 8).await.unwrap();
            veil_server::db::migrate(&db).await.unwrap();
            sqlx::raw_sql("ALTER TABLE view_graph DROP COLUMN files").execute(&db).await.unwrap();
            for chunk in 0..ROWS / 50_000 {
                sqlx::query(
                    "INSERT INTO view_graph (project_id, view_key, snapshot, generation, depth, parents, flags, skip, down_id, real_id) \
                     SELECT g / 20000, 'k' || (g % 10), md5(g::text), g, g, '[]', 0, '[]', '', '' FROM generate_series($1::bigint, $2::bigint) g",
                )
                .bind(chunk * 50_000)
                .bind(chunk * 50_000 + 49_999)
                .execute(&db)
                .await
                .unwrap();
            }
            // S13 servers at work: their insert and their read.
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut s13 = tokio::task::JoinSet::new();
            for w in 0..4i64 {
                let (db, stop) = (db.clone(), stop.clone());
                s13.spawn(async move {
                    let (mut done, mut retried) = (0u64, 0u64);
                    let mut i = 0i64;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        i += 1;
                        let snap = format!("s13-{w}-{i}");
                        let r = sqlx::query(
                            "INSERT INTO view_graph (project_id, view_key, snapshot, generation, depth, parents, flags, skip, down_id, real_id) \
                             VALUES (999, 'k', $1, $2, $2, '[]', 0, '[]', '', '') ON CONFLICT DO NOTHING",
                        )
                        .bind(&snap)
                        .bind(i)
                        .execute(&db)
                        .await
                        .map(|_| ());
                        let r = match r {
                            Ok(()) => sqlx::query_scalar::<_, i64>("SELECT generation FROM view_graph WHERE project_id = 999 AND view_key = 'k' AND snapshot = $1")
                                .bind(&snap)
                                .fetch_optional(&db)
                                .await
                                .map(|_| ()),
                            e => e,
                        };
                        match r {
                            Ok(()) => done += 1,
                            Err(e) => {
                                let e = Error::from(e);
                                assert!(e.is_retryable(), "an S13 statement failed for good during migration 0015: {e:?}");
                                retried += 1;
                            }
                        }
                    }
                    (done, retried)
                });
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            // Migration 0015 as `migrate_locked` applies it: in a
            // transaction, again on a retryable error.
            let sql = include_str!("../../migrations/0015_file_history_and_blame.sql");
            let t = Instant::now();
            let mut attempts = 0;
            loop {
                attempts += 1;
                let mut tx = db.begin().await.unwrap();
                let r = sqlx::raw_sql(sql).execute(&mut *tx).await.map(|_| ());
                let r = match r {
                    Ok(()) => tx.commit().await,
                    Err(e) => Err(e),
                };
                match r {
                    Ok(()) => break,
                    Err(e) if attempts < 50 => {
                        let e = Error::from(e);
                        assert!(e.is_retryable(), "migration 0015 failed: {e:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => panic!("migration 0015 failed after {attempts} attempts: {e:?}"),
                }
            }
            let took = t.elapsed();
            tokio::time::sleep(Duration::from_millis(500)).await;
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let mut totals = Vec::new();
            while let Some(r) = s13.join_next().await {
                totals.push(r.unwrap());
            }
            let has: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'view_graph' AND column_name = 'files')")
                .fetch_one(&db)
                .await
                .unwrap();
            db.close().await;
            let db = veil_server::db::connect(&admin, 1).await.unwrap();
            let _ = sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).execute(&db).await;
            println!("migration 0015 over {ROWS} graph rows beside S13 servers: {took:?} in {attempts} attempt(s); S13 statements (done, retried) per server: {totals:?}");
            assert!(has);
            assert!(took < Duration::from_secs(10), "migration 0015 took {took:?} over {ROWS} rows");
            assert!(totals.iter().all(|(done, _)| *done > 0));
        });
    }

    /// Guarantee 3 of the cycle-1 fixes (BUG-1213): a history cursor the
    /// server keeps fits in a URL and answers only the viewer (view key)
    /// and project it was made for; another viewer, or the same history in
    /// another project, gets `invalid cursor`, never the page.
    #[test]
    fn kept_history_cursors_answer_only_their_viewer_and_project() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let path = format!("pub/{}f.txt", format!("{}/", "d".repeat(99)).repeat(15));
        let make = |th: &TestHub| {
            let mut h = Hist::new(th, &policy_text, &bindings);
            let mut f = Files::new();
            f.insert(path.clone(), lines("base", 12));
            let c0 = h.commit(th, &[root_snapshot_id()], f.clone(), [1; 16], 1_700_000_000_000, None);
            let mut branches = Vec::new();
            for i in 0..10usize {
                let mut g = f.clone();
                let mut body: Vec<String> = (0..12).map(|j| format!("base {j}\n")).collect();
                body[i] = format!("branch {i}\n");
                g.insert(path.clone(), body.concat().into_bytes());
                branches.push(h.commit(th, &[c0], g, [10 + i as u8; 16], 1_700_000_001_000 + i as i64 * 1000, None));
            }
            f.insert(path.clone(), lines("merged", 12));
            let m = h.commit(th, &branches, f, [99; 16], 1_700_000_100_000, None);
            h.set_branch(th, "main", m);
            h
        };
        let (h, other) = (make(&th), make(&th));
        let anyone = Viewer::default();
        for v in [&anyone, &admin()] {
            warm_up(&th, &h, v);
            warm_up(&th, &other, v);
        }
        let page = |h: &Hist, v: &Viewer, after: Option<String>| th.rt.block_on(query::history(&h.hub, &ask(&th, h, v), HistoryParams { path: Some(path.clone()), n: Some(1), after, ..Default::default() }, Limits::default()));
        let first = page(&h, &anyone, None).unwrap();
        let next = first["next"].as_str().unwrap().to_string();
        assert!(next.starts_with("frontier-") && next.len() < 100, "a kept cursor: {next}");
        assert!(page(&h, &anyone, Some(next.clone())).is_ok(), "its own viewer pages on");
        for (who, r) in [("admin", page(&h, &admin(), Some(next.clone()))), ("another project", page(&other, &anyone, Some(next.clone())))] {
            match r {
                Err(Error::Api { code, message, .. }) => assert!(code == "bad_request" && message.contains("invalid cursor"), "{who}: {code} {message}"),
                r => panic!("{who}: a kept cursor answered for someone it was not made for: {r:?}"),
            }
        }
    }

    /// BUG-1215's class, over history shapes and small budgets: every
    /// request that answers `partial` keeps a version it had not kept, or
    /// records a walk down from a version no walk started from (while the
    /// first walk is still on its way down, nothing below can be blamed
    /// yet); never neither, and no walk is recorded twice. And the blame it
    /// ends with is the one a single unbounded request gives.
    #[test]
    fn every_stopped_blame_leaves_progress() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        // (shape, walk budget, diff budget)
        for (shape, walk, work) in [("chain", 40u64, u64::MAX), ("chain", 25, 1_500), ("renames", 60, u64::MAX), ("merges", 50, u64::MAX), ("merges", 30, 2_000)] {
            let mut h = Hist::new(&th, &policy_text, &bindings);
            let mut f = Files::new();
            let mut body: Vec<String> = (0..60).map(|i| format!("line {i} of the file\n")).collect();
            for i in 0..8 {
                f.insert(format!("pub/other/o{i}.txt"), lines(&format!("o{i}"), 6));
            }
            let mut path = "pub/f/name0.txt".to_string();
            let mut tip = root_snapshot_id();
            let mut ts = 1_700_000_000_000i64;
            let mut n = 0u16;
            let mut commit = |h: &mut Hist, parents: &[ObjectId], f: &Files| {
                n += 1;
                ts += 1000;
                let mut change = [11u8; 16];
                change[..2].copy_from_slice(&n.to_le_bytes());
                h.commit(&th, parents, f.clone(), change, ts, None)
            };
            let steps = if shape == "chain" { 120 } else { 70 };
            for i in 0..steps {
                body[i % 60] = format!("edited at step {i}\n");
                if shape == "renames" {
                    f.remove(&path);
                    path = format!("pub/f/name{}.txt", i % 3);
                }
                f.insert(path.clone(), body.concat().into_bytes());
                tip = commit(&mut h, &[tip], &f);
                if shape == "merges" && i % 20 == 10 {
                    // A wide merge: 12 branches each editing their own line.
                    let base = tip;
                    let mut branches = vec![base];
                    let mut merged = body.clone();
                    for b in 0..12 {
                        let mut bb = body.clone();
                        bb[(b * 5 + 1) % 60] = format!("branch {b} at step {i}\n");
                        merged[(b * 5 + 1) % 60] = bb[(b * 5 + 1) % 60].clone();
                        let mut g = f.clone();
                        g.insert(path.clone(), bb.concat().into_bytes());
                        branches.push(commit(&mut h, &[base], &g));
                    }
                    body = merged;
                    f.insert(path.clone(), body.concat().into_bytes());
                    tip = commit(&mut h, &branches, &f);
                }
            }
            h.set_branch(&th, "main", tip);
            let viewer = Viewer::default();
            let a = ask(&th, &h, &viewer);
            warm_up(&th, &h, &viewer);
            let follow = shape == "renames";
            let q = || BlameParams { path: path.clone(), follow: Some(follow), n: Some(1000), ..Default::default() };
            let lines_of = |v: &Value| s14c1_adversarial::origins(v);
            // The blame of one unbounded request.
            forget_blames(&th, &h);
            let whole = Limits { blame: BlameLimits { walk: u64::MAX, work: u64::MAX, ..BlameLimits::default() }, deadline: Duration::from_secs(120), ..Limits::default() };
            let want = lines_of(&th.rt.block_on(query::blame(&h.hub, &a, q(), whole)).unwrap());
            forget_blames(&th, &h);
            let small = Limits { blame: BlameLimits { walk, work, ..BlameLimits::default() }, deadline: Duration::from_secs(120), ..Limits::default() };
            let mut before = progress(&th, &h);
            let mut partials = 0;
            let got = loop {
                match th.rt.block_on(query::blame(&h.hub, &a, q(), small)) {
                    Ok(v) => break v,
                    Err(Error::Api { code: "partial", .. }) => {
                        partials += 1;
                        let now = progress(&th, &h);
                        assert!(now.0 >= before.0 && now.1 >= before.1 && now != before, "{shape} (walk {walk}, work {work}): a partial answer left no progress: {before:?} -> {now:?}");
                        before = now;
                        assert!(partials < 2_000, "{shape}: no end");
                    }
                    Err(e) => panic!("{shape}: {e:?}"),
                }
            };
            assert_eq!(lines_of(&got), want, "{shape} (walk {walk}, work {work})");
            println!("every_stopped_blame_leaves_progress: {shape}, walk {walk}, work {work}: {partials} partial answers, then the whole blame; (kept, walks) {before:?}");
            assert!(partials > 0, "{shape}: the budgets never stopped it");
        }
    }

}

// ---- S14 cycle 3: review of the cycle-2 fixes (BUG-1215) ------------------------------

mod s14c3_adversarial {
    use super::*;
    use veil_server::derive::changes::path_key;

    const ROOT_TS: i64 = 1_700_000_000_000;

    /// Kept blames and recorded walks of the project.
    fn progress(th: &TestHub, h: &Hist) -> (i64, i64) {
        th.rt.block_on(async {
            let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blame_memo WHERE project_id = $1").bind(h.id).fetch_one(&h.hub.db).await.unwrap();
            let walks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blame_walks WHERE project_id = $1").bind(h.id).fetch_one(&h.hub.db).await.unwrap();
            (kept, walks)
        })
    }

    fn limits(walk: u64, work: u64, held: usize) -> Limits {
        Limits { blame: BlameLimits { walk, work, held, ..BlameLimits::default() }, deadline: Duration::from_secs(300), ..Limits::default() }
    }

    fn unbounded() -> Limits {
        limits(u64::MAX, u64::MAX, BlameLimits::default().held)
    }

    /// One blame request on `hub`.
    fn ask_once(th: &TestHub, hub: &std::sync::Arc<veil_server::Hub>, a: &Ask, q: BlameParams, l: Limits) -> Result<Value, Error> {
        th.rt.block_on(query::blame(hub, a, q, l))
    }

    /// A history the test writes, one snapshot after another.
    struct Writer {
        n: u16,
        ts: i64,
        tag: u8,
    }

    impl Writer {
        fn new(tag: u8) -> Writer {
            Writer { n: 0, ts: ROOT_TS, tag }
        }
        fn commit(&mut self, th: &TestHub, h: &mut Hist, parents: &[ObjectId], f: &Files) -> ObjectId {
            self.n += 1;
            self.ts += 1000;
            let mut change = [self.tag; 16];
            change[..2].copy_from_slice(&self.n.to_le_bytes());
            h.commit(th, parents, f.clone(), change, self.ts, None)
        }
    }

    /// A file of `path` edited at each of `n` changes (one line each, in
    /// turn), as a chain; the snapshots, oldest first.
    fn chain(th: &TestHub, h: &mut Hist, path: &str, n: usize, tag: u8) -> Vec<ObjectId> {
        let mut w = Writer::new(tag);
        let mut f = Files::new();
        for i in 0..6 {
            f.insert(format!("pub/other/o{i}.txt"), lines(&format!("o{i}"), 6));
        }
        let mut body: Vec<String> = (0..60).map(|i| format!("line {i} of the file\n")).collect();
        let mut tip = root_snapshot_id();
        let mut out = Vec::new();
        for i in 0..n {
            body[i % 60] = format!("edited at change {i}\n");
            f.insert(path.to_string(), body.concat().into_bytes());
            tip = w.commit(th, h, &[tip], &f);
            out.push(tip);
        }
        h.set_branch(th, "main", tip);
        out
    }

    /// BUG-1216. The stated invariant says no walk is made twice and that
    /// reaching recorded progress costs a read per record. But a version a
    /// request blames on its way (a frontier version walked to the end, or
    /// a cut walk's versions blamed from its record) is kept only in the
    /// request's write buffer: the request's view of the kept blames
    /// (`Blamer::kept`) learns of it only when the buffer is written, every
    /// 32 kept blames. So the next round of `resumed` finds that version
    /// unsettled again and walks it (or blames its record) again, and again,
    /// until 32 kept blames have piled up. Here: a 150-version chain, with
    /// walk budgets that cut the first walk: the request that finishes
    /// costs many times what one unbounded request from nothing costs.
    #[test]
    #[ignore = "BUG-1216: a resumed blame walks again (or blames again from its record) a version it just blamed, until 32 kept blames are written"]
    fn bug_1216_a_resumed_blame_walks_again_what_it_just_blamed() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let path = "pub/f/chain.txt";
        chain(&th, &mut h, path, 150, 21);
        let viewer = Viewer::default();
        let a = ask(&th, &h, &viewer);
        warm_up(&th, &h, &viewer);
        let q = || BlameParams { path: path.into(), n: Some(1000), ..Default::default() };
        forget_blames(&th, &h);
        let whole = ask_once(&th, &h.hub, &a, q(), unbounded()).unwrap();
        assert_eq!(whole["line_count"], 60);
        let w0 = whole["work"].as_u64().unwrap();
        let want = s14c1_adversarial::origins(&whole);
        let mut costly = Vec::new();
        let mut cut = 0;
        for div in [2u64, 3, 4, 6, 8] {
            forget_blames(&th, &h);
            let l = limits(w0 / div, u64::MAX, BlameLimits::default().held);
            let mut partials = 0;
            let done = loop {
                match ask_once(&th, &h.hub, &a, q(), l) {
                    Ok(v) => break v,
                    Err(Error::Api { code: "partial", .. }) => {
                        partials += 1;
                        assert!(partials < 500, "no end");
                    }
                    Err(e) => panic!("{e:?}"),
                }
            };
            assert_eq!(s14c1_adversarial::origins(&done), want, "walk budget {}", w0 / div);
            let wf = done["work"].as_u64().unwrap();
            println!("bug_1216: walk budget {} ({w0}/{div}): {partials} partial answers, then one of work {wf} (one unbounded request from nothing: {w0})", w0 / div);
            cut += (partials > 0) as usize;
            if wf > w0 + w0 / 2 {
                costly.push((w0 / div, partials, wf));
            }
        }
        assert!(cut > 0, "no budget cut the walk");
        assert!(costly.is_empty(), "requests that went on from recorded progress cost more than one unbounded request from nothing ({w0}): (walk budget, partial answers before, work of the answer): {costly:?}");
    }

    /// BUG-1217. The 8 MiB keep cap was dropped because "a blame is bounded
    /// by its file, at most 1 MiB". It is not: a kept blame holds each
    /// origin's snapshot id and path, so it grows with the versions its
    /// lines come from times the path's length, not with the file; and the
    /// kept blames one request computes wait in its write buffer (32 of
    /// them) outside the memory bound (`BlameLimits::held`). Here: a file
    /// of 400 one-line versions at a 3.8 KB path (a 3 KB file): one request
    /// keeps a blame of about 1.6 MB, and about 11 MB of kept blames in all,
    /// against a memory bound of 8 MiB it never passed.
    #[test]
    #[ignore = "BUG-1217: a kept blame is bounded by its origins' paths, not its file, and kept blames wait outside the memory bound"]
    fn bug_1217_a_kept_blame_is_not_bounded_by_its_file() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let path = format!("pub/{}f.txt", format!("{}/", "d".repeat(199)).repeat(19));
        assert!(path.len() > 3_800 && path.len() <= 4096, "{}", path.len());
        let mut w = Writer::new(22);
        let mut f = Files::new();
        let mut body = String::new();
        let mut tip = root_snapshot_id();
        for i in 0..400 {
            body.push_str(&format!("line {i}\n"));
            f.insert(path.clone(), body.clone().into_bytes());
            tip = w.commit(&th, &mut h, &[tip], &f);
        }
        h.set_branch(&th, "main", tip);
        let viewer = Viewer::default();
        let a = ask(&th, &h, &viewer);
        warm_up(&th, &h, &viewer);
        forget_blames(&th, &h);
        let held = 8usize << 20;
        let v = ask_once(&th, &h.hub, &a, BlameParams { path: path.clone(), n: Some(10), ..Default::default() }, limits(u64::MAX, u64::MAX, held)).unwrap();
        assert_eq!(v["line_count"], 400);
        let sizes: Vec<usize> = th.rt.block_on(async {
            let objects: Vec<String> = sqlx::query_scalar("SELECT object FROM blame_memo WHERE project_id = $1").bind(h.id).fetch_all(&h.hub.db).await.unwrap();
            let mut out = Vec::new();
            for o in objects {
                let raw = h.hub.objects.get(h.id, &ObjectId::from_hex(&o).unwrap()).await.unwrap().expect("a kept blame object");
                out.push(raw.len());
            }
            out
        });
        let file = body.len();
        let largest = sizes.iter().copied().max().unwrap_or(0);
        let total: usize = sizes.iter().sum();
        println!("bug_1217: a {file}-byte file at a {}-byte path: {} kept blames, the largest {largest} bytes, {total} bytes in all (memory bound {held})", path.len(), sizes.len());
        assert!(!sizes.is_empty(), "nothing kept");
        assert!(largest <= 1 << 20 && total <= held, "kept blames of a {file}-byte file: the largest {largest} bytes (\"bounded by its file, at most 1 MiB\"), {total} bytes held by one request before it wrote them (memory bound {held})");
    }

    /// BUG-1218. Recorded progress is bounded per viewer, file and version
    /// a walk started from, but each record now holds every version its
    /// walk expanded (up to 2,048, each with its path, entry and parents)
    /// and its whole frontier, and a walk stops only at kept blames, never
    /// at another record's versions. So anyone on Earth, blaming a file at
    /// each of its revisions once (nothing below them kept yet), makes the
    /// server keep one record per revision, each repeating the versions
    /// below it: quadratic in the file's history, and nothing purges it.
    /// Here: a chain of 160 versions, a walk budget an eighth of the whole
    /// walk (by default the cut is at 2,048 versions, so the same holds of
    /// histories past that), one request at each of the newest 120
    /// revisions: what is recorded against the viewer's file history of the
    /// file it walks.
    #[test]
    #[ignore = "BUG-1218: one viewer makes the server keep a cut-walk record per revision blamed, each repeating the versions below it"]
    fn bug_1218_cut_walk_records_grow_with_revisions_blamed_times_history() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let path = format!("pub/{}/f.txt", "r".repeat(100));
        let snaps = chain(&th, &mut h, &path, 160, 23);
        let viewer = Viewer::default();
        let a = ask(&th, &h, &viewer);
        warm_up(&th, &h, &viewer);
        let vk = h.project(&th).view(&viewer).key();
        forget_blames(&th, &h);
        let whole = ask_once(&th, &h.hub, &a, BlameParams { path: path.clone(), ..Default::default() }, unbounded()).unwrap();
        let w0 = whole["work"].as_u64().unwrap();
        forget_blames(&th, &h);
        let l = limits(w0 / 8, u64::MAX, BlameLimits::default().held);
        let mut answers = (0, 0);
        for s in snaps[40..].iter().rev() {
            match ask_once(&th, &h.hub, &a, BlameParams { rev: Some(s.hex()), path: path.clone(), ..Default::default() }, l) {
                Ok(_) => answers.0 += 1,
                Err(Error::Api { code: "partial", .. }) => answers.1 += 1,
                Err(e) => panic!("{e:?}"),
            }
        }
        assert!(answers.1 > 0, "no walk was cut");
        let (records, recorded, history): (i64, i64, i64) = th.rt.block_on(async {
            let (r, b): (i64, i64) = sqlx::query_as(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(frontier) + LENGTH(expanded)), 0)::BIGINT FROM blame_walks WHERE project_id = $1 AND view_key = $2",
            )
            .bind(h.id)
            .bind(&vk)
            .fetch_one(&h.hub.db)
            .await
            .unwrap();
            let f: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(LENGTH(snapshot) + LENGTH(change) + LENGTH(path_key) + 8), 0)::BIGINT FROM view_file_history WHERE project_id = $1 AND view_key = $2 AND path_key = $3",
            )
            .bind(h.id)
            .bind(&vk)
            .bind(path_key(&path))
            .fetch_one(&h.hub.db)
            .await
            .unwrap();
            (r, b, f)
        });
        let entries: usize = th.rt.block_on(async {
            let rows: Vec<String> = sqlx::query_scalar("SELECT expanded FROM blame_walks WHERE project_id = $1 AND view_key = $2").bind(h.id).bind(&vk).fetch_all(&h.hub.db).await.unwrap();
            rows.iter().map(|r| serde_json::from_str::<Vec<Value>>(r).unwrap().len()).sum()
        });
        println!(
            "bug_1218: {} requests ({} answered, {} partial): {records} records of {entries} versions expanded ({} bytes each), {recorded} bytes, against {history} bytes of the file's history rows ({:.1}x)",
            answers.0 + answers.1,
            answers.0,
            answers.1,
            recorded / entries.max(1) as i64,
            recorded as f64 / history as f64
        );
        assert!(recorded <= 4 * history, "{records} cut-walk records of {recorded} bytes for one viewer and one file, against {history} bytes of its history rows");
    }

    /// Every snapshot id and path a recorded walk names (`blame_walks`'
    /// `frontier` and `expanded`).
    fn named(frontier: &str, expanded: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut version = |v: &Value| {
            if !v.is_null() {
                out.push((v["id"].as_str().unwrap().to_string(), v["path"].as_str().unwrap().to_string()));
            }
        };
        for v in serde_json::from_str::<Vec<Value>>(frontier).unwrap() {
            version(&v);
        }
        for w in serde_json::from_str::<Vec<Value>>(expanded).unwrap() {
            version(&w["v"]);
            for p in w["parents"].as_array().unwrap() {
                version(p);
            }
        }
        out
    }

    /// Guarantee 2: recorded progress is per view key. Records of three
    /// viewers' blames (a file renamed out of `fin/` into `pub/` half way,
    /// with hidden changes between, blamed with `follow`) name only
    /// snapshots of the viewer's own graph and paths they read; and with
    /// every other key's records and kept blames made unreadable, each
    /// viewer (and a finance member removed from finance, whose key
    /// changed) finishes with the answer one unbounded request gives.
    #[test]
    fn s14c3_recorded_progress_is_read_only_under_its_view_key() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut w = Writer::new(24);
        let mut f = Files::new();
        f.insert("pub/other.txt".into(), lines("other", 5));
        let mut body: Vec<String> = (0..40).map(|i| format!("line {i} of a file that moves out of fin\n")).collect();
        let mut tip = root_snapshot_id();
        let mut path = "fin/doc.txt".to_string();
        for i in 0..130usize {
            body[i % 40] = format!("edited at change {i}\n");
            if i == 30 {
                f.remove(&path);
                path = "pub/doc.txt".into();
            }
            f.insert(path.clone(), body.concat().into_bytes());
            tip = w.commit(&th, &mut h, &[tip], &f);
            // A change only finance sees.
            f.insert("fin/hidden.txt".into(), format!("hidden {i}\n").into_bytes());
            tip = w.commit(&th, &mut h, &[tip], &f);
        }
        h.set_branch(&th, "main", tip);
        let finance = viewers(1).into_iter().find(|(n, _)| *n == "finance").unwrap().1;
        let removed = Viewer { groups: Default::default(), ..finance.clone() };
        let people = [("anyone on Earth", Viewer::default()), ("finance", finance), ("admin", admin()), ("removed from finance", removed)];
        let project = h.project(&th);
        let key = |v: &Viewer| project.view(v).key();
        assert_ne!(key(&people[1].1), key(&people[3].1), "an access change gives a new key");
        let q = || BlameParams { path: "pub/doc.txt".into(), follow: Some(true), n: Some(1000), ..Default::default() };
        let mut want = HashMap::new();
        for (name, v) in &people {
            warm_up(&th, &h, v);
            forget_blames(&th, &h);
            let r = ask_once(&th, &h.hub, &ask(&th, &h, v), q(), unbounded()).unwrap();
            assert_eq!(r["line_count"], 40, "{name}");
            want.insert(*name, s14c1_adversarial::origins(&r));
        }
        assert_ne!(want["anyone on Earth"], want["finance"], "the boundary shows");
        let small = limits(25, u64::MAX, BlameLimits::default().held);
        for (name, v) in &people {
            forget_blames(&th, &h);
            // Every viewer leaves recorded progress.
            for (other, ov) in &people {
                // (A viewer whose key another shares goes on from its records.)
                let r = ask_once(&th, &h.hub, &ask(&th, &h, ov), q(), small);
                assert!(matches!(r, Ok(_) | Err(Error::Api { code: "partial", .. })), "{other}: {r:?}");
            }
            let rows: Vec<(String, String, String, String, String)> = th.rt.block_on(async {
                sqlx::query_as("SELECT view_key, snapshot, path_key, frontier, expanded FROM blame_walks WHERE project_id = $1").bind(h.id).fetch_all(&h.hub.db).await.unwrap()
            });
            for (other, ov) in &people {
                let keys: Vec<&String> = rows.iter().map(|r| &r.0).collect();
                assert!(rows.iter().any(|r| r.0 == key(ov)), "{other}'s walk was recorded: {} under {keys:?}", key(ov));
            }
            for (vk, snap, _, frontier, expanded) in &rows {
                let (owner, ov) = people.iter().find(|(_, v)| key(v) == *vk).unwrap();
                let graph: HashSet<String> = th.rt.block_on(async {
                    sqlx::query_scalar("SELECT snapshot FROM view_graph WHERE project_id = $1 AND view_key = $2").bind(h.id).bind(vk).fetch_all(&h.hub.db).await.unwrap().into_iter().collect()
                });
                assert!(graph.contains(snap), "{owner}: a record starts at a snapshot of their own graph");
                for (id, p) in named(frontier, expanded) {
                    assert!(graph.contains(&id), "{owner}: a record names {id}, not in their graph");
                    let reads = p.starts_with("pub/") || (p.starts_with("fin/") && !ov.groups.is_empty()) || ov.admin;
                    assert!(reads, "{owner}: a record names {p}");
                }
            }
            // Everything kept under other keys, unreadable.
            let mine = key(v);
            th.rt.block_on(async {
                sqlx::query("UPDATE blame_walks SET frontier = 'not json', expanded = 'not json' WHERE project_id = $1 AND view_key <> $2").bind(h.id).bind(&mine).execute(&h.hub.db).await.unwrap();
                sqlx::query("UPDATE blame_memo SET object = $3 WHERE project_id = $1 AND view_key <> $2").bind(h.id).bind(&mine).bind("00".repeat(32)).execute(&h.hub.db).await.unwrap();
            });
            let a = ask(&th, &h, v);
            let mut partials = 0;
            let got = loop {
                match ask_once(&th, &h.hub, &a, q(), small) {
                    Ok(r) => break r,
                    Err(Error::Api { code: "partial", .. }) => {
                        partials += 1;
                        assert!(partials < 1_000, "{name}: no end");
                    }
                    Err(e) => panic!("{name}: {e:?}"),
                }
            };
            let expect = if *name == "removed from finance" { &want["anyone on Earth"] } else { &want[name] };
            assert_eq!(&s14c1_adversarial::origins(&got), expect, "{name}");
            println!("s14c3 per key: {name}: {partials} partial answers, then the blame one unbounded request gives");
        }
    }

    /// One shape of history for the resumption tests: the history (on
    /// `main`), the path blamed at the tip, and whether to follow renames.
    fn shape(th: &TestHub, h: &mut Hist, shape: &str) -> (String, bool) {
        let mut w = Writer::new(25);
        let mut f = Files::new();
        for i in 0..4 {
            f.insert(format!("pub/other/o{i}.txt"), lines(&format!("o{i}"), 4));
        }
        let mut body: Vec<String> = (0..48).map(|i| format!("line {i} of the file\n")).collect();
        let mut path = "pub/f/name0.txt".to_string();
        let mut tip = root_snapshot_id();
        let mut follow = false;
        match shape {
            "long chain" => {
                for i in 0..300 {
                    body[i % 48] = format!("edited at step {i}\n");
                    f.insert(path.clone(), body.concat().into_bytes());
                    tip = w.commit(th, h, &[tip], &f);
                }
            }
            "diamonds" => {
                // Each step: two changes from one base, each editing its own
                // line, and their merge.
                for i in 0..40 {
                    let base = tip;
                    let mut sides = Vec::new();
                    for s in 0..2 {
                        let mut b = body.clone();
                        b[(i * 2 + s) % 48] = format!("side {s} at step {i}\n");
                        let mut g = f.clone();
                        g.insert(path.clone(), b.concat().into_bytes());
                        sides.push(w.commit(th, h, &[base], &g));
                        body[(i * 2 + s) % 48] = b[(i * 2 + s) % 48].clone();
                    }
                    f.insert(path.clone(), body.concat().into_bytes());
                    tip = w.commit(th, h, &sides, &f);
                }
            }
            "renamed merges" => {
                // Renamed on the main line every few changes (the merges
                // too), with wide merges of branches that edit it.
                follow = true;
                for i in 0..70 {
                    body[i % 48] = format!("edited at step {i}\n");
                    if i % 4 == 0 {
                        f.remove(&path);
                        path = format!("pub/f/name{}.txt", i % 3);
                    }
                    f.insert(path.clone(), body.concat().into_bytes());
                    tip = w.commit(th, h, &[tip], &f);
                    if i % 15 == 7 {
                        let base = tip;
                        let mut branches = vec![base];
                        for b in 0..6 {
                            let mut bb = body.clone();
                            bb[(b * 7 + 3) % 48] = format!("branch {b} at step {i}\n");
                            body[(b * 7 + 3) % 48] = bb[(b * 7 + 3) % 48].clone();
                            let mut g = f.clone();
                            g.insert(path.clone(), bb.concat().into_bytes());
                            branches.push(w.commit(th, h, &[base], &g));
                        }
                        f.remove(&path);
                        path = format!("pub/f/merged{i}.txt");
                        f.insert(path.clone(), body.concat().into_bytes());
                        tip = w.commit(th, h, &branches, &f);
                    }
                }
            }
            "deleted and re-added" => {
                // Deleted twice, and re-added (with its old lines) each time.
                for i in 0..200 {
                    body[i % 48] = format!("edited at step {i}\n");
                    match i {
                        30 | 60 => {
                            f.remove(&path);
                        }
                        31..=34 | 61..=63 => {}
                        _ => {
                            f.insert(path.clone(), body.concat().into_bytes());
                        }
                    }
                    tip = w.commit(th, h, &[tip], &f);
                }
            }
            "memory" => {
                // A larger file: what blames hold is near the memory bound.
                let mut big: Vec<String> = (0..1000).map(|i| format!("a longer line {i:>6} here\n")).collect();
                for i in 0..100 {
                    big[(i * 37) % 1000] = format!("edited at step {i:>6}\n");
                    f.insert(path.clone(), big.concat().into_bytes());
                    tip = w.commit(th, h, &[tip], &f);
                }
            }
            "binary between" => {
                // Some versions hold a NUL byte (not plain text: they hold
                // no line), though their entry says a small file.
                for i in 0..120 {
                    body[i % 48] = format!("edited at step {i}\n");
                    let mut text = body.concat().into_bytes();
                    if i % 20 == 9 {
                        text.push(0);
                    }
                    f.insert(path.clone(), text);
                    tip = w.commit(th, h, &[tip], &f);
                }
            }
            _ => unreachable!(),
        }
        h.set_branch(th, "main", tip);
        (path, follow)
    }

    /// Guarantee 1: on every shape, with small walk and diff budgets and a
    /// small memory bound, every `partial` answer keeps a version or records
    /// a walk (never neither), so a blame answers within twice its versions'
    /// count of requests; and the answer is what one unbounded request
    /// gives.
    #[test]
    fn s14c3_every_shape_finishes_with_progress_at_every_partial() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let held_small = 160 << 10;
        for (name, walk, work, held) in [
            ("long chain", 30u64, u64::MAX, BlameLimits::default().held),
            ("long chain", 60, 3_000, BlameLimits::default().held),
            ("memory", 30, u64::MAX, held_small),
            ("memory", 40, 40_000, held_small),
            ("diamonds", 25, u64::MAX, BlameLimits::default().held),
            ("diamonds", 50, 2_500, BlameLimits::default().held),
            ("renamed merges", 40, u64::MAX, BlameLimits::default().held),
            ("renamed merges", 90, 2_000, BlameLimits::default().held),
            ("deleted and re-added", 30, 1_500, BlameLimits::default().held),
            ("binary between", 30, u64::MAX, BlameLimits::default().held),
            ("binary between", 45, 1_500, BlameLimits::default().held),
        ] {
            let mut h = Hist::new(&th, &policy_text, &bindings);
            let (path, follow) = shape(&th, &mut h, name);
            let viewer = Viewer::default();
            let a = ask(&th, &h, &viewer);
            warm_up(&th, &h, &viewer);
            let vk = h.project(&th).view(&viewer).key();
            let versions: i64 = th.rt.block_on(async {
                sqlx::query_scalar("SELECT COUNT(*) FROM view_file_history WHERE project_id = $1 AND view_key = $2").bind(h.id).bind(&vk).fetch_one(&h.hub.db).await.unwrap()
            });
            let q = || BlameParams { path: path.clone(), follow: Some(follow), n: Some(1000), ..Default::default() };
            forget_blames(&th, &h);
            let want = s14c1_adversarial::origins(&ask_once(&th, &h.hub, &a, q(), unbounded()).unwrap());
            forget_blames(&th, &h);
            let l = limits(walk, work, held);
            let mut before = progress(&th, &h);
            let mut partials = 0i64;
            let got = loop {
                match ask_once(&th, &h.hub, &a, q(), l) {
                    Ok(v) => break v,
                    Err(Error::Api { code: "partial", .. }) => {
                        partials += 1;
                        let now = progress(&th, &h);
                        assert!(now.0 >= before.0 && now.1 >= before.1 && now != before, "{name} (walk {walk}, work {work}, held {held}): a partial answer left no progress: {before:?} -> {now:?}");
                        before = now;
                        assert!(partials <= 2 * versions + 2, "{name}: more partial answers than twice the viewer's {versions} file-history rows");
                    }
                    Err(e) => panic!("{name} (walk {walk}, work {work}, held {held}): {e:?}"),
                }
            };
            assert_eq!(s14c1_adversarial::origins(&got), want, "{name} (walk {walk}, work {work}, held {held})");
            println!("s14c3 shapes: {name}, walk {walk}, work {work}, held {held}: {partials} partial answers ({versions} file-history rows), then the whole blame; (kept, walks) {before:?}");
            assert!(partials > 0, "{name}: the budgets never stopped it");
        }
    }

    /// Guarantee 4: six requests on two servers resuming the same blames at
    /// once, each with its own small budgets, all finish with the answer of
    /// one unbounded request; every version two records name is recorded the
    /// same (no conflicting walks); and every kept blame is the one an
    /// unbounded request from nothing keeps for that version.
    #[test]
    fn s14c3_blames_resumed_at_once_on_two_servers_keep_only_right_blames() {
        let th = TestHub::start();
        let th2 = TestHub::beside(&th);
        let (policy_text, bindings) = policy(1);
        for name in ["long chain", "diamonds", "renamed merges"] {
            let mut h = Hist::new(&th, &policy_text, &bindings);
            let (path, follow) = shape(&th, &mut h, name);
            let viewer = Viewer::default();
            let a = ask(&th, &h, &viewer);
            warm_up(&th, &h, &viewer);
            let q = || BlameParams { path: path.clone(), follow: Some(follow), n: Some(1000), ..Default::default() };
            forget_blames(&th, &h);
            let want = s14c1_adversarial::origins(&ask_once(&th, &h.hub, &a, q(), unbounded()).unwrap());
            forget_blames(&th, &h);
            let hubs = [th.hub(), th2.hub()];
            let budgets = [(20u64, u64::MAX), (35, 2_000), (50, u64::MAX), (25, 3_000), (45, 1_500), (60, u64::MAX)];
            let answers: Vec<Vec<String>> = std::thread::scope(|s| {
                let handles: Vec<_> = budgets
                    .iter()
                    .enumerate()
                    .map(|(i, (walk, work))| {
                        let (hub, a, q, which) = (hubs[i % 2].clone(), a.clone(), q, if i % 2 == 0 { &th } else { &th2 });
                        let l = limits(*walk, *work, BlameLimits::default().held);
                        s.spawn(move || {
                            for _ in 0..5_000 {
                                match which.rt.block_on(query::blame(&hub, &a, q(), l)) {
                                    Ok(v) => return s14c1_adversarial::origins(&v),
                                    Err(Error::Api { code: "partial", .. }) => continue,
                                    Err(e) => panic!("{name}: {e:?}"),
                                }
                            }
                            panic!("{name}: no end");
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            for got in &answers {
                assert_eq!(got, &want, "{name}");
            }
            // No conflicting records: a version two records expanded is the
            // same in both.
            let records: Vec<String> = th.rt.block_on(async {
                sqlx::query_scalar("SELECT expanded FROM blame_walks WHERE project_id = $1").bind(h.id).fetch_all(&h.hub.db).await.unwrap()
            });
            let mut seen: HashMap<String, Value> = HashMap::new();
            for r in &records {
                for w in serde_json::from_str::<Vec<Value>>(r).unwrap() {
                    let k = w["v"].to_string();
                    if let Some(x) = seen.get(&k) {
                        assert_eq!(x, &w, "{name}: two records disagree on a version");
                    }
                    seen.insert(k, w);
                }
            }
            // Every kept blame is the one a request from nothing keeps.
            let kept: Vec<(String, bool, String, String)> = th.rt.block_on(async {
                sqlx::query_as("SELECT path_key, follow, snapshot, object FROM blame_memo WHERE project_id = $1").bind(h.id).fetch_all(&h.hub.db).await.unwrap()
            });
            assert!(!kept.is_empty());
            let paths: HashSet<String> = h.files.values().flat_map(|f| f.keys().cloned()).collect();
            let by_key: HashMap<String, String> = paths.iter().map(|p| (path_key(p), p.clone())).collect();
            for (pk, fl, snap, object) in &kept {
                let p = &by_key[pk];
                forget_blames(&th, &h);
                let r = ask_once(&th, &h.hub, &a, BlameParams { rev: Some(snap.clone()), path: p.clone(), follow: Some(*fl), n: Some(1), ..Default::default() }, unbounded());
                assert!(r.is_ok(), "{name}: {r:?}");
                let fresh: String = th.rt.block_on(async {
                    sqlx::query_scalar("SELECT object FROM blame_memo WHERE project_id = $1 AND path_key = $2 AND follow = $3 AND snapshot = $4")
                        .bind(h.id)
                        .bind(pk)
                        .bind(fl)
                        .bind(snap)
                        .fetch_one(&h.hub.db)
                        .await
                        .unwrap()
                });
                assert_eq!(&fresh, object, "{name}: the blame kept for {p} at {snap}");
            }
            println!("s14c3 at once: {name}: 6 requests on 2 servers agree; {} records, {} kept blames, each as a request from nothing keeps it", records.len(), kept.len());
        }
    }
}
