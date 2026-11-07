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
            Err(Error::Api { code: "partial", .. }) => continue,
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
    // Memory: a bound below one version's text and blame refuses.
    forget_blames(&th, &h);
    let small = Limits {
        blame: BlameLimits { held: 2_000, ..BlameLimits::default() },
        ..Limits::default()
    };
    let r = th.rt.block_on(query::blame(&h.hub, &a, BlameParams { path: "pub/long.txt".into(), ..Default::default() }, small));
    assert!(matches!(r, Err(Error::Api { code: "too_wide", .. })), "{r:?}");
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
