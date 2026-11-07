//! The query API (milestone S13; phase-3 design §3.3 and the threat
//! review, §6).
//!
//! The central check is **projection equivalence** (row 1): for random
//! histories and viewers, every route's answer for a viewer of the real
//! project, the work it took included, is byte for byte the answer its
//! admin gets on a copy of the project built only from that viewer's
//! projected history. Since the copy holds nothing hidden, no hidden name,
//! content, change, count or amount of work can be in the viewer's answers.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    time::{Duration, Instant},
};

use serde_json::{json, Value};
use veil_core::ObjectId;
use veil_server::{
    error::Error,
    perm::Viewer,
    query::{self, Ask, DiffParams, FileParams, Limits, LogParams, ShowParams, TreeParams},
    sync::root_snapshot_id,
};

use crate::{
    derived::{again, copy_for, policy, projections, random_history, text, viewers, Files, Hist, Rng},
    support::*,
};

fn seeds(default: &[u64]) -> Vec<u64> {
    match std::env::var("VEIL_QUERY_SEED").ok().and_then(|s| s.parse::<u64>().ok()) {
        Some(s) => (s..s + default.len() as u64).collect(),
        None => default.to_vec(),
    }
}

fn ask(th: &TestHub, h: &Hist, viewer: &Viewer) -> Ask {
    Ask {
        project: h.project(th),
        viewer: viewer.clone(),
        policy_version: 1,
    }
}

/// Fill `viewer`'s graph of `h` up to its branches (as a landing does), so
/// that no query of the test meets a first fill.
fn warm_up(th: &TestHub, h: &Hist, viewer: &Viewer) {
    let tips: Vec<ObjectId> = h.branches.values().copied().collect();
    th.rt.block_on(query::graph::ensure(&h.hub, &h.project(th), viewer, &tips, None)).unwrap();
}

fn admin() -> Viewer {
    Viewer {
        admin: true,
        ..Viewer::default()
    }
}

/// An answer as compared: the JSON without the policy version (the copy has
/// its own), or the error's status, code and message.
fn norm(r: veil_server::error::Result<Value>) -> String {
    match r {
        Ok(mut v) => {
            v.as_object_mut().unwrap().remove("policy_version");
            v.to_string()
        }
        Err(Error::Api { status, code, message }) => format!("error {status} {code} {message}"),
        Err(e) => panic!("internal error: {e:?}"),
    }
}

/// One query of the harness.
#[derive(Clone, Debug)]
enum Q {
    Log(LogParams, Limits),
    Show(ShowParams),
    Tree(TreeParams),
    File(FileParams),
    Diff(DiffParams),
    Ancestry(Vec<(String, String)>),
}

/// Ask again while the answer is `warming` or `deadline`, as a client does
/// (both say "try again"), for at most 120 s: what the harness compares is
/// the answer, and under a loaded machine a first fill or a slow page can
/// pass the 2 s deadline (BUG-1172). Tests of those answers call the query
/// functions directly.
async fn settled<T, F, Fut>(mut f: F) -> veil_server::error::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = veil_server::error::Result<T>>,
{
    let end = Instant::now() + Duration::from_secs(120);
    loop {
        match f().await {
            Err(Error::Api { code: "warming" | "deadline", .. }) if Instant::now() < end => tokio::time::sleep(Duration::from_millis(100)).await,
            r => return r,
        }
    }
}

/// Run `q` as `a`; a log is followed through every page (at most 60).
fn run(th: &TestHub, h: &Hist, a: &Ask, q: &Q) -> Vec<String> {
    let hub = h.hub.clone();
    th.rt.block_on(async {
        match q {
            Q::Log(p, limits) => {
                let mut out = Vec::new();
                let mut p = p.clone();
                for _ in 0..60 {
                    let r = settled(|| query::log(&hub, a, p.clone(), *limits)).await;
                    let next = r.as_ref().ok().and_then(|v| v["next"].as_str().map(str::to_string));
                    out.push(norm(r));
                    match next {
                        Some(n) => p.after = Some(n),
                        None => break,
                    }
                }
                out
            }
            Q::Show(p) => vec![norm(settled(|| query::show(&hub, a, p.clone(), Limits::default())).await)],
            Q::Tree(p) => vec![norm(settled(|| query::tree(&hub, a, p.clone(), Limits::default())).await)],
            Q::File(p) => vec![norm(settled(|| query::file(&hub, a, p.clone(), Limits::default())).await.map(|(mut m, bytes)| {
                m["bytes"] = json!(hex::encode(bytes));
                m
            }))],
            Q::Diff(p) => vec![norm(settled(|| query::diff(&hub, a, p.clone(), Limits::default())).await)],
            Q::Ancestry(pairs) => vec![norm(settled(|| query::ancestry(&hub, a, query::AncestryRequest { pairs: pairs.clone() }, Limits::default())).await)],
        }
    })
}

/// Every path any snapshot of `h` held.
fn all_paths(h: &Hist) -> BTreeSet<String> {
    h.files.values().flat_map(|f| f.keys().map(|k| k.trim_end_matches('/').to_string())).collect()
}

/// The harness's queries for one viewer: revisions by branch and by the
/// viewer's own ids, paths readable, hidden and missing.
fn queries(rng: &mut Rng, revs: &[String], paths: &[String]) -> Vec<Q> {
    let pick = |rng: &mut Rng, v: &[String]| v[rng.below(v.len())].clone();
    let small = Limits {
        work: 12,
        ..Limits::default()
    };
    let mut out = Vec::new();
    for rev in revs {
        let n = [1, 3, 7, 50][rng.below(4)];
        out.push(Q::Log(LogParams { rev: Some(rev.clone()), n: Some(n), ..Default::default() }, Limits::default()));
        out.push(Q::Show(ShowParams { rev: Some(rev.clone()), stat: Some(rng.chance(30)), ..Default::default() }));
    }
    for _ in 0..12 {
        let rev = pick(rng, revs);
        let path = pick(rng, paths);
        let limits = if rng.chance(50) { small } else { Limits::default() };
        out.push(Q::Log(LogParams { rev: Some(rev.clone()), n: Some([2, 5, 50][rng.below(3)]), path: Some(path.clone()), ..Default::default() }, limits));
        out.push(Q::Show(ShowParams { rev: Some(rev.clone()), path: Some(path.clone()), stat: Some(false) }));
        out.push(Q::Tree(TreeParams { rev: Some(rev.clone()), path: Some(path.clone()), ..Default::default() }));
        out.push(Q::File(FileParams { rev: Some(rev.clone()), path: path.clone() }));
    }
    for dir in ["", "pub", "fin", "pub/sec", "carol-d", "pub/deep"] {
        out.push(Q::Tree(TreeParams { rev: Some(pick(rng, revs)), path: Some(dir.into()), ..Default::default() }));
    }
    for _ in 0..10 {
        let (from, to) = (pick(rng, revs), pick(rng, revs));
        let base = if rng.chance(30) { Some("from".to_string()) } else { None };
        let path = rng.chance(25).then(|| pick(rng, paths));
        out.push(Q::Diff(DiffParams { from, to: Some(to), base, path, stat: Some(rng.chance(30)) }));
    }
    let pairs: Vec<(String, String)> = (0..8).map(|_| (pick(rng, revs), pick(rng, revs))).collect();
    out.push(Q::Ancestry(pairs));
    out
}

#[test]
fn query_projection_equivalence() {
    let th = TestHub::start();
    for seed in seeds(&[101, 102, 103]) {
        let carol = 710_000 + seed as i64;
        let (policy_text, bindings) = policy(carol);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut rng = Rng::new(seed);
        random_history(&th, &mut h, &mut rng, 40);
        let project = h.project(&th);
        let mut paths: Vec<String> = all_paths(&h).into_iter().collect();
        paths.extend(["pub", "fin", "pub/sec", "", "missing-9f2c.txt", "fin/missing-77ab.txt", "pub/missing"].map(String::from));
        let mut compared = 0usize;
        for (who, viewer) in viewers(carol) {
            let p = projections(&th, &h, &project, &viewer);
            let copy = copy_for(&th, &h, &project, &viewer, &p);
            let view = project.view(&viewer);
            // Revisions: the branches, the viewer's own ids (the root's
            // too), and a real id of a snapshot whose projection differs
            // (hidden from them: "no such revision", as in the copy, which
            // has no such id).
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
            warm_up(&th, &h, &viewer);
            warm_up(&th, &copy, &admin());
            // The log's order and cursors come from the viewer's own graph:
            // page through each branch's whole log, as the viewer and on the
            // copy, and compare both with the order computed directly from
            // the copy's snapshots (generations of the projected graph, never
            // the real one's).
            for branch in ["main", "side"] {
                let pages = |hh: &Hist, a: &Ask| -> (Vec<String>, Vec<Option<String>>) {
                    let (mut ids, mut cursors, mut after) = (Vec::new(), Vec::new(), None);
                    loop {
                        let p = LogParams { rev: Some(branch.into()), n: Some(3), after: after.clone(), ..Default::default() };
                        let v = th.rt.block_on(query::log(&hh.hub, a, p, Limits::default())).unwrap();
                        ids.extend(v["entries"].as_array().unwrap().iter().map(|e| e["snapshot_id"].as_str().unwrap().to_string()));
                        after = v["next"].as_str().map(str::to_string);
                        cursors.push(after.clone());
                        if after.is_none() {
                            return (ids, cursors);
                        }
                    }
                };
                let (mine, mine_cursors) = pages(&h, &mine_ask);
                let (theirs, theirs_cursors) = pages(&copy, &copy_ask);
                assert_eq!(mine, theirs, "seed {seed}, {who}: log order of {branch}");
                assert_eq!(mine_cursors, theirs_cursors, "seed {seed}, {who}: log cursors of {branch}");
                assert_eq!(mine, model_log(&th, &copy, copy.branches[branch]), "seed {seed}, {who}: log order of {branch} against the projected graph");
            }
            let hidden_paths: Vec<String> = all_paths(&h).into_iter().filter(|k| !view.read(k) && !k.is_empty()).collect();
            for q in queries(&mut rng, &revs, &paths) {
                let (real, theirs) = (run(&th, &h, &mine_ask, &q), run(&th, &copy, &copy_ask, &q));
                assert_eq!(real, theirs, "seed {seed}, {who}: {q:?}");
                compared += real.len();
                // No hidden path, and no real id of a snapshot the viewer
                // sees differently, in any answer (rows 5, 6).
                for a in &real {
                    for k in &hidden_paths {
                        // Only a path no readable path starts with.
                        if !paths.iter().any(|r| view.read(r) && r.starts_with(k.as_str())) {
                            assert!(!a.contains(&format!("\"{k}\"")), "seed {seed}, {who}: hidden path {k} in {a}");
                        }
                    }
                    for s in &hidden_real {
                        assert!(!a.contains(&s.hex()), "seed {seed}, {who}: real id {} in {a}", s.short());
                    }
                }
            }
        }
        println!("seed {seed}: {} changes, {compared} answers compared", h.order.len());
    }
}

/// The viewer graph's walks against direct ones (row 11: a function of
/// immutable inputs, never wrong): ancestry and merge bases by brute force,
/// and the log against its order (newest first by generation, children
/// before parents),
/// on histories of long linear runs, merges every way and timestamps far
/// ahead and far behind, so that the walks pass over runs through the jump
/// table.
#[test]
fn query_graph_matches_direct_walks() {
    let th = TestHub::start();
    for seed in seeds(&[201, 202]) {
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut rng = Rng::new(seed);
        let root = root_snapshot_id();
        let mut tips: Vec<ObjectId> = vec![root];
        let mut stamps: HashMap<ObjectId, i64> = HashMap::from([(root, 0)]);
        let mut ts = 1_700_000_000_000i64;
        for i in 0..700usize {
            let b = if rng.chance(85) { 0 } else { rng.below(tips.len()) };
            if tips.len() < 4 && rng.chance(3) {
                tips.push(tips[rng.below(tips.len())]);
            }
            let mut parents = vec![tips[b]];
            if rng.chance(4) {
                let o = tips[rng.below(tips.len())];
                if !parents.contains(&o) {
                    parents.push(o);
                }
            }
            ts += 1000;
            let stamp = match rng.below(100) {
                0..=3 => 9_000_000_000_000 + i as i64,
                4..=6 => 1_000 + i as i64,
                _ => ts,
            };
            let mut files = h.files[&parents[0]].clone();
            files.insert(format!("pub/f{}.txt", rng.below(20)), format!("{i}\n").into_bytes());
            let mut change = [0u8; 16];
            change[..8].copy_from_slice(&rng.next().to_le_bytes());
            let id = h.commit(&th, &parents, files, change, stamp, None);
            stamps.insert(id, stamp);
            tips[b] = id;
        }
        for (i, t) in tips.iter().enumerate() {
            h.set_branch(&th, if i == 0 { "main" } else { ["s1", "s2", "s3"][i - 1] }, *t);
        }
        let project = h.project(&th);
        th.rt.block_on(query::graph::extend(&h.hub, &project, &admin(), &tips)).unwrap();
        // The model.
        let anc = |x: ObjectId| -> HashSet<ObjectId> {
            let mut seen = HashSet::new();
            let mut stack = vec![x];
            while let Some(y) = stack.pop() {
                if seen.insert(y) {
                    stack.extend(h.parents[&y].iter().copied());
                }
            }
            seen
        };
        let all: Vec<ObjectId> = h.order.clone();
        let mut pairs: Vec<(ObjectId, ObjectId)> = (0..80).map(|_| (all[rng.below(all.len())], all[rng.below(all.len())])).collect();
        for a in &tips {
            for b in &tips {
                pairs.push((*a, *b));
            }
        }
        let mut want = Vec::new();
        for (a, b) in &pairs {
            let (aa, ab) = (anc(*a), anc(*b));
            let common: Vec<ObjectId> = aa.intersection(&ab).copied().collect();
            let mut best: Vec<ObjectId> = common.iter().copied().filter(|c| !common.iter().any(|d| d != c && anc(*d).contains(c))).collect();
            best.sort();
            want.push((ab.contains(a), best));
        }
        let (hub, pid, pairs2) = (h.hub.clone(), h.id, pairs.clone());
        let (got, work) = th
            .rt
            .block_on(query::graph::blocking(&hub, pid, move |cx| {
                let g = query::graph::G::new(cx, "admin", None);
                let mut out = Vec::new();
                for (a, b) in &pairs2 {
                    out.push((g.is_ancestor(*a, *b)?, g.merge_bases(*a, *b)?));
                }
                Ok((out, g.work()))
            }))
            .unwrap();
        for ((pair, w), g) in pairs.iter().zip(&want).zip(&got) {
            assert_eq!(w, g, "seed {seed}: {} {}", pair.0.short(), pair.1.short());
        }
        // The log: newest first by generation (the corrected commit date,
        // timestamps clamped as the graph clamps them), ties by id.
        let reach = anc(tips[0]);
        let mut gens: HashMap<ObjectId, i64> = HashMap::from([(root, 0)]);
        for x in &h.order {
            let g = h.parents[x].iter().map(|p| gens[p] + 1).max().unwrap_or(0).max(stamps[x].clamp(0, i64::MAX / 4));
            gens.insert(*x, g);
        }
        let mut sorted: Vec<(i64, ObjectId)> = reach.iter().map(|x| (gens[x], *x)).collect();
        sorted.sort_by(|a, b| b.cmp(a));
        let order: Vec<String> = sorted.iter().map(|(_, x)| x.hex()).collect();
        // Children before parents, whatever the timestamps.
        let at: HashMap<&str, usize> = order.iter().enumerate().map(|(i, x)| (x.as_str(), i)).collect();
        for x in &reach {
            for p in &h.parents[x] {
                assert!(at[x.hex().as_str()] < at[p.hex().as_str()], "seed {seed}: a parent before its child");
            }
        }
        let a = ask(&th, &h, &admin());
        let mut logged = Vec::new();
        let mut after = None;
        loop {
            let v = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(97), after: after.clone(), ..Default::default() }, Limits::default())).unwrap();
            logged.extend(v["entries"].as_array().unwrap().iter().map(|e| e["snapshot_id"].as_str().unwrap().to_string()));
            match v["next"].as_str() {
                Some(n) => after = Some(n.to_string()),
                None => break,
            }
        }
        assert_eq!(logged, order, "seed {seed}: log order");
        println!("seed {seed}: {} snapshots, {} pairs, {work} rows read", h.order.len(), pairs.len());
    }
}

/// The log of `tip` in `copy` (a project holding one viewer's projected
/// history), computed from its snapshot objects alone: newest first by the
/// generation of that graph (timestamps clamped as the graphs clamp them,
/// raised above the parents'), ties by id.
fn model_log(th: &TestHub, copy: &Hist, tip: ObjectId) -> Vec<String> {
    let (hub, id) = (copy.hub.clone(), copy.id);
    th.rt
        .block_on(veil_server::sync::blocking(&hub, id, move |src| {
            let mut snaps: HashMap<ObjectId, (i64, Vec<ObjectId>)> = HashMap::new();
            let mut stack = vec![tip];
            while let Some(x) = stack.pop() {
                if snaps.contains_key(&x) {
                    continue;
                }
                let s = src.snapshot(&x)?;
                stack.extend(s.parents.iter().copied());
                snaps.insert(x, (s.timestamp, s.parents.clone()));
            }
            let mut gens: HashMap<ObjectId, i64> = HashMap::new();
            let mut order: Vec<ObjectId> = snaps.keys().copied().collect();
            // Parents first: by depth of the walk, repeated until settled.
            while gens.len() < snaps.len() {
                for x in &order {
                    if gens.contains_key(x) {
                        continue;
                    }
                    let (ts, ps) = &snaps[x];
                    if ps.iter().all(|p| gens.contains_key(p)) {
                        let g = ps.iter().map(|p| gens[p] + 1).max().unwrap_or(0).max((*ts).clamp(0, i64::MAX / 4));
                        gens.insert(*x, g);
                    }
                }
            }
            order.sort_by(|a, b| (gens[b], *b).cmp(&(gens[a], *a)));
            Ok(order.iter().map(|x| x.hex()).collect())
        }))
        .unwrap()
}

/// Row 4: two projects that differ only in what a viewer cannot see give
/// that viewer the same answers, and the same work, for every query.
#[test]
fn query_work_ignores_hidden_content() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut rng = Rng::new(7);
    let mut a = Hist::new(&th, &policy_text, &bindings);
    let mut b = Hist::new(&th, &policy_text, &bindings);
    let root = root_snapshot_id();
    let (mut ta, mut tb) = (root, root);
    let mut files = Files::new();
    let mut hidden = Files::new();
    for i in 0..30u8 {
        // B: more hidden content in every snapshot, and runs of hidden
        // changes between the visible ones (dated far ahead, too).
        for j in 0..(i % 4) {
            hidden.insert(format!("fin/extra-{i}-{j}.txt"), text(&mut rng, "extra", 40));
            let mut fb = files.clone();
            fb.extend(hidden.clone());
            tb = b.commit(&th, &[tb], fb, [200 + j; 16], 9_000_000_000_000 + i64::from(i), None);
        }
        // Shared: readable work; and a hidden file in both, so that every
        // visible snapshot is a projection in both.
        files.insert(format!("pub/f{}.txt", i % 7), text_lines(&mut rng, i));
        files.insert("fin/base.txt".into(), b"hidden in both\n".to_vec());
        let ts = 1_700_000_000_000 + i64::from(i) * 1000;
        ta = a.commit(&th, &[ta], files.clone(), [i; 16], ts, None);
        let mut fb = files.clone();
        fb.extend(hidden.clone());
        tb = b.commit(&th, &[tb], fb, [i; 16], ts, None);
    }
    a.set_branch(&th, "main", ta);
    b.set_branch(&th, "main", tb);
    for (who, viewer) in [("anyone on Earth", Viewer::default()), ("a dev", viewers(1)[1].1.clone())] {
        let (aa, ab) = (ask(&th, &a, &viewer), ask(&th, &b, &viewer));
        warm_up(&th, &a, &viewer);
        warm_up(&th, &b, &viewer);
        let tip = th.rt.block_on(query::resolve(&a.hub, &aa, "main", Instant::now() + Duration::from_secs(60))).unwrap();
        assert_eq!(tip, th.rt.block_on(query::resolve(&b.hub, &ab, "main", Instant::now() + Duration::from_secs(60))).unwrap());
        let revs = vec!["main".to_string(), tip.hex()];
        let paths: Vec<String> = ["pub/f1.txt", "pub", "fin", "fin/extra-3-0.txt", ""].map(String::from).to_vec();
        for q in queries(&mut rng, &revs, &paths) {
            let (x, y) = (run(&th, &a, &aa, &q), run(&th, &b, &ab, &q));
            assert_eq!(x, y, "{who}: {q:?}");
        }
    }
}

fn text_lines(rng: &mut Rng, i: u8) -> Vec<u8> {
    format!("version {i}\n{}", String::from_utf8(text(rng, "body", 5)).unwrap()).into_bytes()
}

/// Rows 6 and 8: a hidden revision or path and a missing one get the same
/// error, byte for byte; an embargo line is no revision for anyone.
#[test]
fn query_hidden_and_withheld_are_missing() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let base = Files::from([("pub/a.rs".to_string(), b"fn a() {}\n".to_vec()), ("fin/ledger.txt".to_string(), b"ledger\n".to_vec())]);
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
    let anyone = ask(&th, &h, &Viewer::default());
    let adm = ask(&th, &h, &admin());
    warm_up(&th, &h, &Viewer::default());
    warm_up(&th, &h, &admin());
    let one = |a: &Ask, q: Q| run(&th, &h, a, &q).remove(0);
    let log = |rev: &str| Q::Log(LogParams { rev: Some(rev.into()), ..Default::default() }, Limits::default());
    let missing = ObjectId([0x5a; 32]).hex();
    let no_rev = one(&anyone, log(&missing));
    assert!(no_rev.starts_with("error 404"), "{no_rev}");
    for rev in [hidden.hex(), "no-such-branch".into(), "embargoed".into(), e.hex(), c.hex()] {
        assert_eq!(one(&anyone, log(&rev)), no_rev, "{rev}");
    }
    // Withheld from admins too, until the release (S22).
    for rev in ["embargoed".to_string(), e.hex(), c.hex()] {
        assert_eq!(one(&adm, log(&rev)), no_rev, "admin, {rev}");
    }
    let main_log = one(&adm, log("main"));
    assert!(main_log.contains(&hidden.hex()) && !main_log.contains(&e.hex()), "{main_log}");
    // Paths: hidden, missing, and missing under a hidden folder.
    let file = |path: &str| Q::File(FileParams { rev: Some("main".into()), path: path.into() });
    let no_path = one(&anyone, file("pub/nothing.rs"));
    assert!(no_path.starts_with("error 404"), "{no_path}");
    for path in ["fin/ledger.txt", "fin/q3-plan-5e1d.txt", "fin/nothing.txt", "fin", "nothing/at/all"] {
        assert_eq!(one(&anyone, file(path)), no_path, "{path}");
        let tree = one(&anyone, Q::Tree(TreeParams { rev: Some("main".into()), path: Some(path.into()), ..Default::default() }));
        assert_eq!(tree, one(&anyone, Q::Tree(TreeParams { rev: Some("main".into()), path: Some("nothing/at/all".into()), ..Default::default() })), "{path}");
    }
    // The change of fin/ only is in nobody's log but finance's and admins'.
    let anyone_log = one(&anyone, log("main"));
    assert!(!anyone_log.contains("q3-plan") && !anyone_log.contains(&hidden.hex()), "{anyone_log}");
    // Nothing of the embargo line in any answer, for anyone.
    for a in [&anyone, &adm] {
        for q in [log("main"), Q::Tree(TreeParams { rev: Some("main".into()), path: Some("pub".into()), ..Default::default() })] {
            let out = one(a, q);
            assert!(!out.contains("fix-embargo") && !out.contains("FIX-MARKER") && !out.contains(&c.hex()), "{out}");
        }
    }
}

/// Row 10: hostile sizes and syntax are refused or capped, never served
/// in full.
#[test]
fn query_hostile_inputs_are_bounded() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut files = Files::new();
    for i in 0..30 {
        files.insert(format!("pub/many/f{i:02}.txt"), format!("file {i}\n").into_bytes());
    }
    files.insert("pub/big.txt".into(), vec![b'x'; (2 << 20) + 10]);
    let a = h.commit(&th, &[root_snapshot_id()], files.clone(), [1; 16], 1_000, None);
    let mut tip = a;
    for i in 0..5u8 {
        files.insert(format!("pub/many/f{i:02}.txt"), format!("edited {i}\n").into_bytes());
        tip = h.commit(&th, &[tip], files.clone(), [10 + i; 16], 2_000 + i64::from(i), None);
    }
    h.set_branch(&th, "main", tip);
    let a_ = ask(&th, &h, &Viewer::default());
    warm_up(&th, &h, &Viewer::default());
    let hub = h.hub.clone();
    th.rt.block_on(async {
        // `n` is capped.
        let v = query::log(&hub, &a_, LogParams { n: Some(1 << 40), ..Default::default() }, Limits { page: 3, ..Limits::default() }).await.unwrap();
        assert_eq!(v["entries"].as_array().unwrap().len(), 3);
        assert!(v["truncated"].as_bool().unwrap());
        // Cursors: too long, or not ids.
        let long = vec![tip.hex(); 1_001].join(",");
        for after in [long, "zz".into(), format!("{},nope", tip.hex())] {
            let r = query::log(&hub, &a_, LogParams { after: Some(after), ..Default::default() }, Limits::default()).await;
            assert!(matches!(r, Err(Error::Api { code: "bad_request", .. })), "{r:?}");
        }
        // Paths that are not paths.
        for path in ["../etc/passwd", "a//b", "/abs", "a/./b", &"d/".repeat(3000)] {
            let r = query::show(&hub, &a_, ShowParams { path: Some(path.to_string()), ..Default::default() }, Limits::default()).await;
            assert!(matches!(r, Err(Error::Api { code: "bad_request", .. })), "{path}: {r:?}");
        }
        // Revisions that are too long, or nothing.
        for rev in ["x".repeat(10_000), String::new()] {
            let r = query::show(&hub, &a_, ShowParams { rev: Some(rev), ..Default::default() }, Limits::default()).await;
            assert!(matches!(r, Err(Error::Api { code: "not_found", .. })), "{r:?}");
        }
        // Too many pairs; an unknown base.
        let pairs = vec![("main".to_string(), "main".to_string()); 101];
        assert!(query::ancestry(&hub, &a_, query::AncestryRequest { pairs }, Limits::default()).await.is_err());
        let r = query::diff(&hub, &a_, DiffParams { from: "main".into(), base: Some("octopus".into()), ..Default::default() }, Limits::default()).await;
        assert!(matches!(r, Err(Error::Api { code: "bad_request", .. })), "{r:?}");
        // A diff is cut at its file limit, and lines beyond the byte budget
        // or the size limit are left out.
        let small = Limits {
            diff: query::trees::DiffLimits { files: 10, content_bytes: 40 },
            ..Limits::default()
        };
        let v = query::diff(&hub, &a_, DiffParams { from: root_snapshot_id().hex(), base: Some("from".into()), ..Default::default() }, small).await.unwrap();
        assert_eq!(v["files"].as_array().unwrap().len(), 10);
        assert!(v["truncated"].as_bool().unwrap() && v["content_truncated"].as_bool().unwrap(), "{v}");
        let v = query::show(&hub, &a_, ShowParams { rev: Some(a.hex()), path: Some("pub/big.txt".into()), ..Default::default() }, Limits::default()).await.unwrap();
        assert_eq!(v["diff"]["files"][0]["content"]["too_large"], json!(true), "{v}");
        // A folder listing is paged.
        let v = query::tree(&hub, &a_, TreeParams { path: Some("pub/many".into()), ..Default::default() }, Limits { list: 7, ..Limits::default() }).await.unwrap();
        assert_eq!(v["entries"].as_array().unwrap().len(), 7);
        assert_eq!(v["next"], json!("f06.txt"));
        let v = query::tree(&hub, &a_, TreeParams { path: Some("pub/many".into()), after: Some("f06.txt".into()), ..Default::default() }, Limits { list: 100, ..Limits::default() }).await.unwrap();
        assert_eq!(v["entries"][0]["name"], json!("f07.txt"));
        // A deadline already past: an error, not a shorter answer.
        let r = query::log(&hub, &a_, LogParams::default(), Limits { deadline: Duration::ZERO, ..Limits::default() }).await;
        assert!(matches!(r, Err(Error::Api { code: "deadline", .. })), "{r:?}");
    });
}

/// Row 11: servers extending one viewer's graph at once write the rows a
/// single extension writes.
#[test]
fn query_concurrent_extensions_agree() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let rows = |h: &Hist| -> Vec<String> {
        th.rt.block_on(async {
            type Row = (String, String, i64, i64, String, i32, String, String);
            let r: Vec<Row> = sqlx::query_as(
                "SELECT view_key, snapshot, generation, depth, parents, flags, skip, down_id FROM view_graph WHERE project_id = $1",
            )
            .bind(h.id)
            .fetch_all(&h.hub.db)
            .await
            .unwrap();
            let mut out: Vec<String> = r.iter().map(|x| format!("{x:?}")).collect();
            out.sort();
            out
        })
    };
    let mut answers = Vec::new();
    for parallel in [1usize, 6] {
        let mut h = Hist::new(&th, &policy_text, &bindings);
        random_history(&th, &mut h, &mut Rng::new(31), 40);
        let project = h.project(&th);
        let tips: Vec<ObjectId> = h.branches.values().copied().collect();
        th.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for i in 0..parallel {
                for (_, v) in viewers(1).into_iter().chain([("admin", admin())]) {
                    let (hub, project, tips) = (h.hub.clone(), project.clone(), tips.clone());
                    let mut tips = tips;
                    if i % 2 == 1 {
                        tips.reverse();
                    }
                    set.spawn(async move { query::graph::extend(&hub, &project, &v, &tips).await.unwrap() });
                }
            }
            while set.join_next().await.is_some() {}
        });
        // The view keys are the same in both projects (the same policy).
        answers.push(rows(&h));
    }
    assert!(!answers[0].is_empty());
    assert_eq!(answers[0], answers[1]);
}

/// A landing fills every view key's graph (the admins' included) as it
/// memoises the tips' projections, so that queries find it filled.
#[test]
fn query_landing_fills_the_viewer_graphs() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    random_history(&th, &mut h, &mut Rng::new(61), 30);
    let project = h.project(&th);
    // Viewers the landing knows of: the project's people (none here) and
    // anyone on Earth, and the admins.
    th.rt.block_on(veil_server::derive::landing(&h.hub, h.id, vec!["main".into(), "side".into()])).unwrap();
    for viewer in [Viewer::default(), admin()] {
        let key = project.view(&viewer).key();
        for tip in h.branches.values() {
            let p = th.rt.block_on(veil_server::sync::projected(&h.hub, &project, &viewer, *tip)).unwrap();
            // The landing queued the fill; it runs in the background.
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                let n: i64 = th.rt.block_on(
                    sqlx::query_scalar("SELECT COUNT(*) FROM view_graph WHERE project_id = $1 AND view_key = $2 AND snapshot = $3")
                        .bind(h.id)
                        .bind(&key)
                        .bind(p.hex())
                        .fetch_one(&h.hub.db),
                )
                .unwrap();
                if n == 1 {
                    break;
                }
                assert!(Instant::now() < deadline, "{key}: the tip's row");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// A first fill of a view key (minutes on a long history) runs once, in
/// the background: many requests at once, from anyone on Earth and from
/// people who signed up with no access (the same view key: keys come from
/// the server's records, never from a request), start one fill; each gets
/// `warming` at its deadline, never pays for the fill inside it, and the
/// fill finishes after they gave up.
#[test]
fn query_first_fill_runs_once_in_the_background() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    random_history(&th, &mut h, &mut Rng::new(71), 150);
    let project = h.project(&th);
    let nobody = |i: i64| Viewer {
        person: Some(990_000 + i),
        ..Viewer::default()
    };
    for i in 0..8 {
        assert_eq!(project.view(&nobody(i)).key(), project.view(&Viewer::default()).key(), "a sign-up without access reads as anyone on Earth");
    }
    assert_eq!(th.hub().query.fills_started(h.id), 0);
    let quick = Limits {
        deadline: Duration::from_millis(5),
        ..Limits::default()
    };
    let base = ask(&th, &h, &Viewer::default());
    let codes: Vec<String> = th.rt.block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for i in 0..24 {
            let viewer = if i % 3 == 0 { Viewer::default() } else { nobody(i) };
            let (hub, a) = (h.hub.clone(), Ask { viewer, ..base.clone() });
            set.spawn(async move {
                match query::log(&hub, &a, LogParams::default(), quick).await {
                    Ok(_) => "ok".to_string(),
                    Err(Error::Api { code, .. }) => code.to_string(),
                    Err(e) => panic!("{e:?}"),
                }
            });
        }
        let mut out = Vec::new();
        while let Some(r) = set.join_next().await {
            out.push(r.unwrap());
        }
        out
    });
    assert!(codes.iter().all(|c| c == "warming" || c == "deadline" || c == "ok"), "{codes:?}");
    assert!(codes.iter().any(|c| c == "warming"), "{codes:?}");
    // The fill goes on without them, and is the only one.
    let t = Instant::now();
    let a = ask(&th, &h, &Viewer::default());
    loop {
        match th.rt.block_on(query::log(&h.hub, &a, LogParams::default(), quick)) {
            Ok(_) | Err(Error::Api { code: "deadline", .. }) => break,
            Err(Error::Api { code: "warming", .. }) => {}
            Err(e) => panic!("{e:?}"),
        }
        assert!(t.elapsed() < Duration::from_secs(300), "the fill never finished");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(th.hub().query.fills_started(h.id), 1, "one fill for one view key");
    assert!(th.rt.block_on(query::log(&h.hub, &a, LogParams::default(), Limits::default())).is_ok());
    // A landing keeps the view key warm (`memo_tips`) without a new fill
    // of the history: it joins or extends by the new snapshots only.
    assert_eq!(th.hub().query.fills_started(h.id), 1);
}

/// Row 13: a new policy is answered under its own view keys: what a viewer
/// newly may read appears, what they no longer may read goes, at once.
#[test]
fn query_follows_policy_changes() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    random_history(&th, &mut h, &mut Rng::new(41), 30);
    let set_policy = |t: &str, version: i64| {
        th.rt.block_on(async {
            again(|| sqlx::query("UPDATE projects SET policy_text = $1, policy_version = $2 WHERE id = $3").bind(t).bind(version).bind(h.id).execute(&h.hub.db)).await;
        })
    };
    let fin_files = |version: i64| -> bool {
        let a = Ask {
            policy_version: version,
            ..ask(&th, &h, &Viewer::default())
        };
        let out = run(&th, &h, &a, &Q::Log(LogParams { rev: Some("main".into()), n: Some(1000), path: Some("fin".into()), ..Default::default() }, Limits::default()));
        let tree = run(&th, &h, &a, &Q::Tree(TreeParams { rev: Some("main".into()), ..Default::default() }));
        let listed = out.iter().any(|p| p.contains("\"snapshot_id\""));
        assert_eq!(listed, tree[0].contains("\"name\":\"fin\""), "{out:?} {tree:?}");
        listed
    };
    assert!(!fin_files(1));
    set_policy(&format!("{policy_text}fin/ public finance\n"), 2);
    assert!(fin_files(2), "fin/ made public");
    set_policy(&policy_text, 3);
    assert!(!fin_files(3), "fin/ private again");
}

// ---- through the routes, with `vl` ------------------------------------------------

fn get(api: &Api, token: Option<&str>, path: &str) -> Reply {
    api.get(token, path)
}

/// Every route over HTTPS, as each person of the standard project: nobody
/// receives a marker of what they may not see, a change of billing only is
/// in nobody else's log, a secret comes back as ciphertext, and someone
/// removed from a group loses its folder at once (row 9).
#[test]
fn query_routes_serve_each_person_their_part() {
    let th = TestHub::start();
    let p = setup_project(&th);
    let api = th.api();
    let base = format!("/v1/projects/{}/q", p.name);
    let tok = |who: &Person| Some(who.token());
    let people: Vec<(&str, Option<String>, Vec<&str>)> = vec![
        ("anyone", None, restricted_markers()),
        ("dev", tok(&p.dev), restricted_markers()),
        ("fin", tok(&p.fin), vec![ROOT_FILE, ROOT_MARK, NESTED_DIR, NESTED_MARK, PERSON_DIR, PERSON_MARK, ENV_MARK]),
        ("carol", tok(&p.carol), vec![ROOT_FILE, ROOT_MARK, BILL_DIR, BILL_MARK, NESTED_DIR, NESTED_MARK, ENV_MARK, DESC_MARK]),
        ("sec", tok(&p.sec), vec![ROOT_FILE, ROOT_MARK, BILL_DIR, BILL_MARK, PERSON_DIR, PERSON_MARK, ENV_MARK, DESC_MARK]),
    ];
    let admin_log = get(&api, tok(&p.admin).as_deref(), &format!("{base}/log?n=100")).json();
    let entries = admin_log["entries"].as_array().unwrap();
    assert!(entries.len() >= 4, "{admin_log}");
    assert!(admin_log.to_string().contains(DESC_MARK));
    for (who, token, hidden) in &people {
        let t = token.as_deref();
        let log = get(&api, t, &format!("{base}/log?n=100"));
        assert_eq!(log.status, 200, "{who}: {}", String::from_utf8_lossy(&log.body));
        let lv = log.json();
        assert!(lv["policy_version"].as_i64().unwrap() >= 1);
        let mut bodies = vec![log.body.clone()];
        for e in lv["entries"].as_array().unwrap() {
            let id = e["snapshot_id"].as_str().unwrap();
            let show = get(&api, t, &format!("{base}/show?rev={id}"));
            assert_eq!(show.status, 200, "{who}");
            bodies.push(show.body);
            bodies.push(get(&api, t, &format!("{base}/tree?rev={id}")).body);
            bodies.push(get(&api, t, &format!("{base}/diff?from={}&to={id}&base=from", root_snapshot_id().hex())).body);
        }
        let tip = lv["entries"][0]["snapshot_id"].as_str().unwrap().to_string();
        for path in [format!("src/{NESTED_DIR}/key.txt"), format!("{BILL_DIR}/acme/invoice.txt"), format!("{PERSON_DIR}/notes.txt"), ROOT_FILE.to_string(), "src/lib.rs".into()] {
            let f = get(&api, t, &format!("{base}/file?rev={tip}&path={path}"));
            bodies.push(f.body);
        }
        bodies.push(get(&api, t, &format!("{base}/tree?path={BILL_DIR}")).body);
        let anc = api.post_json(t, &format!("{base}/ancestry"), &json!({ "pairs": [[tip, "main"]] }));
        assert_eq!(anc.status, 200, "{who}: {}", String::from_utf8_lossy(&anc.body));
        bodies.push(anc.body);
        let all: Vec<(String, Vec<u8>)> = bodies.into_iter().map(|b| (who.to_string(), b)).collect();
        assert_no_marker(&all, hidden, who);
        // Everyone reads the public file.
        let f = get(&api, t, &format!("{base}/file?rev={tip}&path=src/lib.rs"));
        assert!(has_marker(&[(String::new(), f.body)], PUBLIC_MARK), "{who}");
    }
    // Finance gets billing's secret as ciphertext only.
    let env = get(&api, tok(&p.fin).as_deref(), &format!("{base}/file?path={BILL_DIR}/.env"));
    assert_eq!(env.status, 200, "{}", String::from_utf8_lossy(&env.body));
    assert!(!env.body.is_empty() && !has_marker(&[(String::new(), env.body.clone())], ENV_MARK));
    // A hidden path and a missing one, a hidden revision and a missing
    // one: the same bodies, byte for byte.
    let dev = tok(&p.dev);
    let a = get(&api, dev.as_deref(), &format!("{base}/file?path={BILL_DIR}/acme/invoice.txt"));
    let b = get(&api, dev.as_deref(), &format!("{base}/file?path=nothing/here.txt"));
    assert_eq!((a.status, &a.body), (b.status, &b.body));
    let real_hidden = entries.iter().find(|e| e["description"].as_str().unwrap_or("").contains(DESC_MARK)).unwrap()["snapshot_id"].as_str().unwrap().to_string();
    let a = get(&api, dev.as_deref(), &format!("{base}/show?rev={real_hidden}"));
    let b = get(&api, dev.as_deref(), &format!("{base}/show?rev={}", ObjectId([7; 32]).hex()));
    assert_eq!((a.status, &a.body), (b.status, &b.body));
    assert_eq!(a.status, 404);
    // Row 9: the admin removes fin from finance; billing goes at once.
    let fin_tree = |t: Option<&str>| get(&api, t, &format!("{base}/tree?path={BILL_DIR}"));
    assert_eq!(fin_tree(tok(&p.fin).as_deref()).status, 200);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let after = fin_tree(tok(&p.fin).as_deref());
    let missing = get(&api, tok(&p.fin).as_deref(), &format!("{base}/tree?path=nothing/here"));
    assert_eq!((after.status, &after.body), (404, &missing.body));
    let log = get(&api, tok(&p.fin).as_deref(), &format!("{base}/log?n=100"));
    assert!(!has_marker(&[(String::new(), log.body)], DESC_MARK));
    // Row 7: the viewer graphs hold ids and numbers, nothing of any file.
    let rows: Vec<String> = th.rt.block_on(async {
        let hub = th.hub();
        let id: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&hub.db).await.unwrap();
        sqlx::query_scalar("SELECT view_key || parents || skip || down_id || real_id || snapshot FROM view_graph WHERE project_id = $1")
            .bind(id)
            .fetch_all(&hub.db)
            .await
            .unwrap()
    });
    assert!(!rows.is_empty());
    let all: Vec<(String, Vec<u8>)> = rows.into_iter().map(|r| ("view_graph".to_string(), r.into_bytes())).collect();
    let mut markers = restricted_markers();
    markers.push(PUBLIC_MARK);
    assert_no_marker(&all, &markers, "view_graph");
}

// ---- speed -----------------------------------------------------------------------

fn pct(mut v: Vec<Duration>, p: usize) -> Duration {
    v.sort();
    v[(v.len() * p / 100).min(v.len() - 1)]
}

/// The design's latency targets (§5), on a generated history of
/// `VEIL_QUERY_BENCH_SNAPSHOTS` (default 600; the gate runs 20,000) snapshots: 500 files, a
/// merge every 50, two branches whose merge base is the history's start.
/// Prints p50 and p99 per query, for an admin and for anyone on Earth
/// (who cannot see a fifth of the files).
#[test]
fn query_speed() {
    let n: usize = std::env::var("VEIL_QUERY_BENCH_SNAPSHOTS").ok().and_then(|s| s.parse().ok()).unwrap_or(600);
    let rounds: usize = std::env::var("VEIL_QUERY_BENCH_ROUNDS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut rng = Rng::new(51);
    let mut files = Files::new();
    for i in 0..500 {
        let dir = ["pub", "pub/sec", "fin", "carol-d", "pub/x"][i % 5];
        files.insert(format!("{dir}/d{}/f{i}.txt", i % 25), text(&mut rng, "f", 20));
    }
    let keys: Vec<String> = files.keys().cloned().collect();
    let hot = "pub/d0/f0.txt".to_string();
    let t0 = Instant::now();
    let mut tip = root_snapshot_id();
    let mut side = None;
    for i in 0..n {
        for _ in 0..1 + rng.below(4) {
            let k = &keys[rng.below(keys.len())];
            let mut c = files[k].clone();
            c.extend(format!("edit {i}\n").bytes());
            files.insert(k.clone(), c);
        }
        if i % 10 == 0 {
            let mut c = files[&hot].clone();
            c.extend(format!("hot {i}\n").bytes());
            files.insert(hot.clone(), c);
        }
        let mut parents = vec![tip];
        if i % 50 == 49 {
            if let Some(s) = side.take() {
                parents.push(s);
            }
        }
        let mut change = [0u8; 16];
        change[..8].copy_from_slice(&rng.next().to_le_bytes());
        tip = h.commit(&th, &parents, files.clone(), change, 1_700_000_000_000 + i as i64 * 1000, None);
        if i % 50 == 10 {
            side = Some(tip);
        }
    }
    // A branch off the start, and one off the tip that changes 100 files.
    let base = h.order[10];
    let mut fa = h.files[&base].clone();
    fa.insert("pub/branch-a.txt".into(), b"a\n".to_vec());
    let side_a = h.commit(&th, &[base], fa, [7; 16], 1, None);
    let mut fb = files.clone();
    for k in keys.iter().filter(|k| k.starts_with("pub/")).take(100) {
        let mut c = fb[k].clone();
        c.extend(b"branch b\n");
        fb.insert(k.clone(), c);
    }
    let side_b = h.commit(&th, &[tip], fb, [8; 16], 2, None);
    h.set_branch(&th, "main", tip);
    h.set_branch(&th, "a", side_a);
    h.set_branch(&th, "b", side_b);
    println!("query_speed: built {n} snapshots in {:?}", t0.elapsed());
    let project = h.project(&th);
    // It measures time; the 2 s deadline is not what it tests (BUG-1172).
    let patient = Limits {
        deadline: Duration::from_secs(120),
        ..Limits::default()
    };
    for (who, viewer) in [("admin", admin()), ("anyone on Earth", Viewer::default())] {
        let a = ask(&th, &h, &viewer);
        let t = Instant::now();
        let tips: Vec<ObjectId> = h.branches.values().copied().collect();
        th.rt.block_on(query::graph::extend(&h.hub, &project, &viewer, &tips)).unwrap();
        println!("query_speed: {who}: projected and extended the graph in {:?}", t.elapsed());
        let hub = h.hub.clone();
        let mut runs: BTreeMap<&str, Vec<Duration>> = BTreeMap::new();
        let mut works: BTreeMap<&str, u64> = BTreeMap::new();
        th.rt.block_on(async {
            let tip_p = query::resolve(&hub, &a, "main", Instant::now() + Duration::from_secs(60)).await.unwrap();
            let (pa, pb) = (
                query::resolve(&hub, &a, "a", Instant::now() + Duration::from_secs(60)).await.unwrap(),
                query::resolve(&hub, &a, "b", Instant::now() + Duration::from_secs(60)).await.unwrap(),
            );
            for round in 0..rounds + 1 {
                let mut time = |name: &'static str, v: Value, t: Instant| {
                    if round > 0 {
                        runs.entry(name).or_default().push(t.elapsed());
                    }
                    works.insert(name, v["work"].as_u64().unwrap_or(0));
                };
                let t = Instant::now();
                let v = query::log(&hub, &a, LogParams { n: Some(50), ..Default::default() }, patient).await.unwrap();
                time("log -n 50", v, t);
                let t = Instant::now();
                let v = query::log(&hub, &a, LogParams { n: Some(50), path: Some(hot.clone()), ..Default::default() }, patient).await.unwrap();
                assert_eq!(v["entries"].as_array().unwrap().len(), 50, "{v}");
                time("log -n 50 -- hot file", v, t);
                let t = Instant::now();
                let v = query::ancestry(&hub, &a, query::AncestryRequest { pairs: vec![(pa.hex(), pb.hex())] }, patient).await.unwrap();
                assert_eq!(v["results"][0]["is_ancestor"], json!(false));
                time("ancestry (merge base 20k apart)", v, t);
                let t = Instant::now();
                let v = query::ancestry(&hub, &a, query::AncestryRequest { pairs: vec![(root_snapshot_id().hex(), tip_p.hex())] }, patient).await.unwrap();
                time("is_ancestor(root, tip)", v, t);
                let t = Instant::now();
                let v = query::diff(&hub, &a, DiffParams { from: "main".into(), to: Some("b".into()), ..Default::default() }, patient).await.unwrap();
                assert!(v["files"].as_array().unwrap().len() >= 50, "{}", v["files"].as_array().unwrap().len());
                time("diff, 100 files vs merge base", v, t);
                let t = Instant::now();
                let v = query::tree(&hub, &a, TreeParams { path: Some("pub/d0".into()), ..Default::default() }, patient).await.unwrap();
                time("tree", v, t);
                let t = Instant::now();
                let v = query::file(&hub, &a, FileParams { rev: None, path: hot.clone() }, patient).await.unwrap().0;
                time("file", v, t);
            }
        });
        for (name, v) in runs {
            println!("query_speed: {who}: {name}: p50 {:?}, p99 {:?}, work {}", pct(v.clone(), 50), pct(v, 99), works[name]);
        }
    }
}

/// BUG-1070 (found while building S13; S1's sync routes): `history` and
/// `fetch` accept a real snapshot id from someone who sees that snapshot
/// differently, so a known id of a change of billing only is answered (its
/// projection: the history below it) where any other id is "no snapshot
/// you can see". The query API takes only the viewer's own ids.
#[test]
#[ignore = "BUG-1070: S1's history and fetch routes answer a real id of a snapshot hidden from the caller"]
fn bug_1070_sync_routes_accept_real_ids_of_hidden_snapshots() {
    let th = TestHub::start();
    let p = setup_project(&th);
    let api = th.api();
    let admin_log = api.get(Some(&p.admin.token()), &format!("/v1/projects/{}/q/log?n=100", p.name)).json();
    let hidden = admin_log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["description"].as_str().unwrap_or("").contains(DESC_MARK))
        .unwrap()["snapshot_id"]
        .as_str()
        .unwrap()
        .to_string();
    let dev = p.dev.token();
    let ask = |id: &str| api.post_json(Some(&dev), &format!("/v1/projects/{}/history", p.name), &json!({ "tips": [id], "stop": [] }));
    let (a, b) = (ask(&hidden), ask(&ObjectId([9; 32]).hex()));
    assert_eq!((a.status, a.body), (b.status, b.body), "a hidden snapshot's real id is answered");
}

/// Adversarial pass on S13 (`docs/BUGS.md`, "Adversarial pass: S13"):
/// reproductions of the bounds that the query API states (phase-3 design
/// §11, "Bounds", row 10) and does not keep.
mod s13_adversarial {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use veil_core::{
        object::{EntryKind, Object, Snapshot, Text, Tree, TreeEntry},
        ChangeId,
    };

    use super::*;

    fn rss() -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        let kib: u64 = s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse().unwrap();
        kib * 1024
    }

    /// `f`'s result, and how far the process's memory rose while it ran.
    fn peak_growth<T>(f: impl FnOnce() -> T) -> (T, u64) {
        let base = rss();
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let sampler = std::thread::spawn(move || {
            let mut m = 0;
            while !s2.load(Ordering::Relaxed) {
                m = m.max(rss());
                std::thread::sleep(Duration::from_millis(5));
            }
            m
        });
        let r = f();
        stop.store(true, Ordering::Relaxed);
        let peak = sampler.join().unwrap().max(rss());
        (r, peak.saturating_sub(base))
    }

    fn entry(name: &str, kind: EntryKind, id: ObjectId, size: u64) -> TreeEntry {
        TreeEntry {
            name: name.to_string(),
            kind,
            id,
            size,
            executable: false,
            visibility: Default::default(),
        }
    }

    fn tree(entries: Vec<TreeEntry>, out: &mut Vec<(ObjectId, Vec<u8>)>) -> ObjectId {
        let raw = Object::Tree(Tree { entries }).encode();
        let id = ObjectId::hash(&raw);
        out.push((id, raw));
        id
    }

    /// The tree `pub/<dir>/f0000.txt … f<n-1>.txt`, every file the one blob
    /// `blob` (`size` bytes): a few hundred bytes of upload per file.
    fn folder_of_copies(dir: &str, n: usize, blob: ObjectId, size: u64, out: &mut Vec<(ObjectId, Vec<u8>)>) -> ObjectId {
        let files: Vec<TreeEntry> = (0..n).map(|i| entry(&format!("f{i:04}.txt"), EntryKind::File, blob, size)).collect();
        let d = tree(files, out);
        let p = tree(vec![entry(dir, EntryKind::Dir, d, 0)], out);
        tree(vec![entry("pub", EntryKind::Dir, p, 0)], out)
    }

    fn commit_tree(th: &TestHub, h: &mut Hist, parents: &[ObjectId], tree: ObjectId, mut objects: Vec<(ObjectId, Vec<u8>)>, n: u8, timestamp: i64) -> ObjectId {
        let s = Snapshot {
            parents: parents.to_vec(),
            change_id: ChangeId([n; 16]),
            tree,
            description: Text::Plain(format!("change {n}")),
            author: "gen".into(),
            timestamp,
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
        };
        let raw = Object::Snapshot(s).encode();
        let id = ObjectId::hash(&raw);
        objects.push((id, raw));
        h.put(th, objects);
        th.rt.block_on(async {
            again(|| sqlx::query("INSERT INTO snapshots (project_id, id) VALUES ($1, $2) ON CONFLICT DO NOTHING").bind(h.id).bind(id.hex()).execute(&h.hub.db)).await;
        });
        h.parents.insert(id, parents.to_vec());
        h.order.push(id);
        id
    }

    /// BUG-1071: a log page's work budget (`Limits::work`, 20,000 reads) is
    /// checked only between emitted entries. One step of the topological
    /// walk explores every snapshot whose generation is above the next
    /// snapshot to settle, so a merge that takes in one snapshot dated far
    /// behind (timestamp 0: a crafted push, or a device whose clock is
    /// wrong) makes the first page of every log above it walk the whole
    /// line below, whatever the budget. On a long history every such log
    /// meets the 2 s deadline and fails for everyone.
    #[test]
    fn bug_1071_a_log_page_walks_past_its_work_budget() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let n: usize = std::env::var("VEIL_BUG1071_LINE").ok().and_then(|s| s.parse().ok()).unwrap_or(400);
        let mut files = Files::new();
        let mut tip = root_snapshot_id();
        for i in 0..n {
            files.insert("pub/line.txt".into(), format!("version {i}\n").into_bytes());
            let mut change = [0u8; 16];
            change[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            tip = h.commit(&th, &[tip], files.clone(), change, 1_700_000_000_000 + i as i64 * 1000, None);
        }
        let old = h.commit(&th, &[root_snapshot_id()], Files::from([("pub/old.txt".to_string(), b"old\n".to_vec())]), [0xee; 16], 0, None);
        let mut merged = files.clone();
        merged.insert("pub/old.txt".into(), b"old\n".to_vec());
        let top = h.commit(&th, &[tip, old], merged, [0xef; 16], 1_800_000_000_000, None);
        h.set_branch(&th, "main", top);
        let a = ask(&th, &h, &Viewer::default());
        warm_up(&th, &h, &Viewer::default());
        let limits = Limits {
            work: 100,
            ..Limits::default()
        };
        let v = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(1), ..Default::default() }, limits)).unwrap();
        let work = v["work"].as_u64().unwrap();
        println!("BUG-1071: a page of 1 entry over a line of {n}, budget {}: work {work}", limits.work);
        assert!(work <= 2 * limits.work, "a page with a budget of {} read {work} rows and objects", limits.work);
    }

    /// BUG-1072: `diff` (and `show`) run the rename and copy detection of
    /// S12 (`changes::sources`) on any pair of revisions anyone may name.
    /// It hashes every line of up to 1,000 deleted and 1,000 added plain-text
    /// files of up to 1 MiB each, and keeps every file's table of line
    /// hashes until it is done: gigabytes for one request, with no deadline
    /// check (`G::tick` is not called) and no `work` counted. A member who
    /// may write a public folder uploads one blob and two trees of copies
    /// of it (a few hundred KB); then each `diff?from=X&to=Y&base=from`
    /// from anyone on Earth costs the server that memory and CPU, and a few
    /// at once take the process (every project) down.
    #[test]
    fn bug_1072_a_diff_holds_gigabytes_past_its_deadline() {
        const CHILD: &str = "VEIL_BUG1072_CHILD";
        if std::env::var(CHILD).is_err() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "query::s13_adversarial::bug_1072_a_diff_holds_gigabytes_past_its_deadline", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines().filter(|l| l.contains("BUG-1072:")) {
                println!("{line}");
            }
            assert!(out.status.success() && stdout.contains("1 passed"), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
            return;
        }
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let n: usize = std::env::var("VEIL_BUG1072_FILES").ok().and_then(|s| s.parse().ok()).unwrap_or(400);
        let kib: usize = std::env::var("VEIL_BUG1072_KIB").ok().and_then(|s| s.parse().ok()).unwrap_or(256);
        // Distinct short lines: one table entry per line.
        let blob = |tag: char| -> (ObjectId, Vec<u8>, u64) {
            let mut s = String::new();
            let mut i = 0u64;
            while s.len() + 8 < kib << 10 {
                s.push_str(&format!("{tag}{i:06}\n"));
                i += 1;
            }
            let raw = Object::Blob(s.clone().into_bytes()).encode();
            (ObjectId::hash(&raw), raw, s.len() as u64)
        };
        let (ida, rawa, sa) = blob('a');
        let (idb, rawb, sb) = blob('b');
        let mut oa = vec![(ida, rawa)];
        let ta = folder_of_copies("a", n, ida, sa, &mut oa);
        let mut ob = vec![(idb, rawb)];
        let tb = folder_of_copies("b", n, idb, sb, &mut ob);
        let x = commit_tree(&th, &mut h, &[root_snapshot_id()], ta, oa, 1, 1_000);
        let y = commit_tree(&th, &mut h, &[x], tb, ob, 2, 2_000);
        h.set_branch(&th, "main", y);
        let a = ask(&th, &h, &Viewer::default());
        warm_up(&th, &h, &Viewer::default());
        let limits = Limits {
            deadline: Duration::from_millis(500),
            ..Limits::default()
        };
        let p = DiffParams { from: x.hex(), to: Some(y.hex()), base: Some("from".into()), stat: Some(true), path: None };
        let t = Instant::now();
        let (r, grew) = peak_growth(|| th.rt.block_on(query::diff(&h.hub, &a, p, limits)));
        let took = t.elapsed();
        let what = match &r {
            Ok(v) => format!("answered, work {}", v["work"]),
            Err(Error::Api { code, .. }) => format!("error {code}"),
            Err(e) => format!("{e:?}"),
        };
        println!("BUG-1072: diff of {n} deleted and {n} added files of {kib} KiB, as anyone on Earth: memory rose {} MiB, took {took:?} with a deadline of {:?} ({what})", grew >> 20, limits.deadline);
        // With time to finish, the diff answers: renames by content are
        // skipped for the whole change (past the bytes held), as past the
        // other caps, and the memory stays bounded.
        let p = DiffParams { from: x.hex(), to: Some(y.hex()), base: Some("from".into()), stat: Some(true), path: None };
        let slow = Limits {
            deadline: Duration::from_secs(120),
            ..Limits::default()
        };
        let (full, grew_full) = peak_growth(|| th.rt.block_on(query::diff(&h.hub, &a, p, slow)));
        let full = full.unwrap();
        println!("BUG-1072: with time to finish: {} files, renames_skipped {}, memory rose {} MiB", full["files"].as_array().unwrap().len(), full["renames_skipped"], grew_full >> 20);
        assert_eq!(full["renames_skipped"], json!(true));
        assert!(grew_full < 256 << 20, "memory rose {} MiB", grew_full >> 20);
        assert!(
            grew < 256 << 20 && took < limits.deadline + Duration::from_secs(3),
            "one diff: memory rose {} MiB, and it took {took:?} with a deadline of {:?}",
            grew >> 20,
            limits.deadline
        );
    }

    /// BUG-1073: every first fill holds a pooled database connection for its
    /// whole run (`graph::locked_fill`, for the session advisory lock), and
    /// the fill's own statements need others from the same pool. Fills run
    /// one per (project, view key), with no limit on how many at once, and a
    /// query starts one whenever the viewer's graph is cold: after S13 is
    /// deployed on existing projects (every graph is), after a policy or
    /// group change, or for a key no landing warmed. As many cold fills as
    /// the pool has connections (16 here, 32 by default) hold every
    /// connection while their statements wait for one: every request on
    /// the server, in every project, waits for the pool's 30 s timeout and
    /// fails, and so do the fills. Anyone on Earth starts them by asking
    /// for the logs of that many public projects at once.
    #[test]
    fn bug_1073_cold_fills_exhaust_the_connection_pool() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let k: usize = std::env::var("VEIL_BUG1073_PROJECTS").ok().and_then(|s| s.parse().ok()).unwrap_or(24);
        let mut hs = Vec::new();
        for i in 0..k {
            let mut h = Hist::new(&th, &policy_text, &bindings);
            random_history(&th, &mut h, &mut Rng::new(500 + i as u64), 12);
            hs.push(h);
        }
        let asks: Vec<Ask> = hs.iter().map(|h| ask(&th, h, &Viewer::default())).collect();
        let hub = th.hub();
        let limits = Limits {
            deadline: Duration::from_secs(90),
            ..Limits::default()
        };
        let t = Instant::now();
        let (codes, probe) = th.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for a in asks {
                let hub = hub.clone();
                set.spawn(async move {
                    match query::log(&hub, &a, LogParams::default(), limits).await {
                        Ok(_) => "ok".to_string(),
                        Err(Error::Api { code, .. }) => code.to_string(),
                        Err(e) => format!("{e:?}").chars().take(120).collect(),
                    }
                });
            }
            // Meanwhile, an unrelated request's statement.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let p = Instant::now();
            let one: Result<i32, sqlx::Error> = sqlx::query_scalar("SELECT 1").fetch_one(&hub.db).await;
            let probe = (one.is_ok(), p.elapsed());
            let mut out = Vec::new();
            while let Some(r) = set.join_next().await {
                out.push(r.unwrap());
            }
            (out, probe)
        });
        let took = t.elapsed();
        println!("BUG-1073: {k} cold fills at once on a pool of 16: took {took:?}; an unrelated statement meanwhile: {probe:?}; answers {codes:?}");
        assert!(
            codes.iter().all(|c| c == "ok") && probe.0 && probe.1 < Duration::from_secs(5) && took < Duration::from_secs(25),
            "{k} cold fills: took {took:?}, unrelated statement {probe:?}, answers {codes:?}"
        );
    }
    // ---- S13 cycle 2 -------------------------------------------------------------

    /// A line of `n` snapshots on `main`, each changing `pub/a.txt` and
    /// every other one `fin/b.txt` too, so that every view key's projection
    /// differs from the admins' (a fill walks and projects all of it).
    fn line(th: &TestHub, h: &mut Hist, n: usize) -> ObjectId {
        let mut files = Files::new();
        let mut tip = root_snapshot_id();
        for i in 0..n {
            files.insert("pub/a.txt".into(), format!("version {i}\n").into_bytes());
            if i % 2 == 0 {
                files.insert("fin/b.txt".into(), format!("ledger {i}\n").into_bytes());
            }
            let mut change = [0u8; 16];
            change[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            change[15] = 0xa7;
            tip = h.commit(th, &[tip], files.clone(), change, 1_700_000_000_000 + i as i64 * 1000, None);
        }
        h.set_branch(th, "main", tip);
        tip
    }

    /// Viewers of `project` with distinct view keys (the admins' last).
    fn distinct_viewers(project: &veil_server::perm::Project, carol: i64) -> Vec<Viewer> {
        let mut keys = HashSet::new();
        let mut out: Vec<Viewer> = viewers(carol).into_iter().map(|(_, v)| v).chain([admin()]).filter(|v| keys.insert(project.view(v).key())).collect();
        out.truncate(query::graph::MAX_FILLS + 1);
        assert_eq!(out.len(), query::graph::MAX_FILLS + 1, "enough distinct view keys");
        out
    }

    fn code(r: &veil_server::error::Result<Value>) -> String {
        match r {
            Ok(_) => "ok".into(),
            Err(Error::Api { code, .. }) => code.to_string(),
            Err(e) => format!("{e:?}").chars().take(160).collect(),
        }
    }

    /// BUG-1074: a query whose view key is cold starts its fill only if one
    /// of the server's `MAX_FILLS` slots frees up before the query's own
    /// deadline (`graph::start_or_join` waits for the slot *before* it
    /// registers the fill). A query that gives up leaves nothing queued, so
    /// `ensure`'s promise ("a query's deadline never bounds, nor pays for,
    /// a first fill") is broken: while four fills run (landings, which wait
    /// with no deadline, other projects' first fills, anyone on Earth's
    /// queries of cold public projects), every query of the cold key
    /// answers `warming`, and when they end the key is still cold. Under a
    /// steady supply of fills it never warms: the queries starve.
    #[test]
    fn bug_1074_a_query_that_waits_out_its_deadline_for_a_fill_slot_never_fills() {
        let th = TestHub::start();
        let carol = 760_001;
        let (policy_text, bindings) = policy(carol);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let n: usize = std::env::var("VEIL_BUG1074_LINE").ok().and_then(|s| s.parse().ok()).unwrap_or(400);
        let tip = line(&th, &mut h, n);
        let project = h.project(&th);
        let vs = distinct_viewers(&project, carol);
        let hub = th.hub();
        // Four fills, as four landings start them (no deadline).
        let t = Instant::now();
        let busy: Vec<_> = vs[..query::graph::MAX_FILLS]
            .iter()
            .map(|v| {
                let (hub, project, v) = (hub.clone(), project.clone(), v.clone());
                th.rt.spawn(async move { query::graph::ensure(&hub, &project, &v, &[tip], None).await.map(|_| ()) })
            })
            .collect();
        while hub.query.fills_started(h.id) < query::graph::MAX_FILLS as u64 {
            assert!(t.elapsed() < Duration::from_secs(30));
            std::thread::sleep(Duration::from_millis(5));
        }
        // Meanwhile a fifth viewer asks for the log, with a deadline of
        // 300 ms: `warming`, as the design says, "and the fill goes on".
        let late = ask(&th, &h, &vs[4]);
        let quick = Limits {
            deadline: Duration::from_millis(300),
            ..Limits::default()
        };
        let answer = code(&th.rt.block_on(query::log(&hub, &late, LogParams::default(), quick)));
        let all_busy = !busy.iter().any(|b| b.is_finished());
        for b in busy {
            th.rt.block_on(b).unwrap().unwrap();
        }
        let busy_took = t.elapsed();
        // Nobody asks any more: the fill the query asked for runs now, if
        // anything queued it (up to 30 s; asking would start it).
        let wait = Instant::now();
        while hub.query.fills_started(h.id) <= query::graph::MAX_FILLS as u64 && wait.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(50));
        }
        let started = hub.query.fills_started(h.id);
        println!("BUG-1074: four fills of a line of {n} took {busy_took:?}; a fifth view key's query meanwhile answered {answer}; fills started {:?} after: {started}", wait.elapsed());
        assert!(answer == "warming" && all_busy, "precondition: the four fills ended before the query met its deadline (make the line longer): {answer}");
        assert_eq!(
            started,
            query::graph::MAX_FILLS as u64 + 1,
            "the query met its deadline waiting for a fill slot and left no fill of its view key queued: still cold once every slot was free"
        );
        let a = ask(&th, &h, &vs[4]);
        let patient = Limits {
            deadline: Duration::from_secs(120),
            ..Limits::default()
        };
        assert_eq!(code(&th.rt.block_on(query::log(&hub, &a, LogParams::default(), patient))), "ok");
        assert_eq!(hub.query.fills_started(h.id), query::graph::MAX_FILLS as u64 + 1, "the queued fill was the one");
    }

    /// BUG-1075: a fill holds one of the server's `MAX_FILLS` slots while it
    /// waits for another server's lease on its view key
    /// (`graph::leased_fill` polls for up to `FILL_LOCK_WAIT`, 600 s, inside
    /// the slot `start_or_join` took). Another server filling four view keys
    /// (anyone on Earth asking it for four cold public projects' logs) or a
    /// server that stopped mid-fill (its leases stand for 120 s) makes this
    /// server's landings and queries of the same keys take all four slots
    /// and wait: no fill of any other key runs here, though none is
    /// running; every cold query on the server answers `warming`.
    #[test]
    fn bug_1075_fills_waiting_for_another_servers_lease_hold_every_slot() {
        let th = TestHub::start();
        let carol = 760_002;
        let (policy_text, bindings) = policy(carol);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let tip = line(&th, &mut h, 12);
        let project = h.project(&th);
        let vs = distinct_viewers(&project, carol);
        let hub = th.hub();
        // Another server holds the leases of four of the project's keys.
        let now = veil_core::now_millis();
        for v in &vs[..query::graph::MAX_FILLS] {
            let key = project.view(v).key();
            th.rt.block_on(again(|| {
                sqlx::query("INSERT INTO view_fills (project_id, view_key, holder, expires_at) VALUES ($1, $2, 'another-server', $3)")
                    .bind(h.id)
                    .bind(&key)
                    .bind(now + 600_000)
                    .execute(&hub.db)
            }));
        }
        // Landings here need the same keys (as `memo_tips` does).
        let t = Instant::now();
        let waiting: Vec<_> = vs[..query::graph::MAX_FILLS]
            .iter()
            .map(|v| {
                let (hub, project, v) = (hub.clone(), project.clone(), v.clone());
                th.rt.spawn(async move { query::graph::ensure(&hub, &project, &v, &[tip], None).await.map(|_| ()) })
            })
            .collect();
        while hub.query.fills_started(h.id) < query::graph::MAX_FILLS as u64 {
            assert!(t.elapsed() < Duration::from_secs(30));
            std::thread::sleep(Duration::from_millis(5));
        }
        // A key no server is filling: a short history, ten seconds.
        let a = ask(&th, &h, &vs[4]);
        let limits = Limits {
            deadline: Duration::from_secs(10),
            ..Limits::default()
        };
        let q = Instant::now();
        let r = th.rt.block_on(query::log(&hub, &a, LogParams::default(), limits));
        let took = q.elapsed();
        // The other server finishes: the waiting fills go on.
        th.rt.block_on(again(|| sqlx::query("DELETE FROM view_fills WHERE project_id = $1 AND holder = 'another-server'").bind(h.id).execute(&hub.db)));
        for w in waiting {
            th.rt.block_on(w).unwrap().unwrap();
        }
        println!("BUG-1075: four fills waiting for another server's leases; a query of a fifth, cold key of 12 snapshots answered {} after {took:?}", code(&r));
        assert_eq!(code(&r), "ok", "a cold key no server fills waited {took:?} for a slot held by fills that only wait");
    }

    /// BUG-1076: a log page's cursor is the walk's whole frontier, and the
    /// next page refuses a cursor naming more than `Limits::cursor`
    /// snapshots (1,000): so a log whose frontier is wider than that cannot
    /// be paged past, for everyone who sees it. With the walk by
    /// generation, the frontier holds every fork point whose branch was
    /// shown: `k` long-lived branches, each forked from its own main-line
    /// snapshot and merged at the top, leave all `k` fork points in it
    /// (the client's Kahn walk held only the main line's next snapshot).
    /// Here `k` = 8 with a cursor limit of 8; by default, 1,000 branches.
    #[test]
    fn bug_1076_a_log_cursor_names_more_snapshots_than_the_next_page_accepts() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let k: usize = std::env::var("VEIL_BUG1076_BRANCHES").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
        let t0 = 1_700_000_000_000i64;
        let mut files = Files::new();
        let mut main = vec![root_snapshot_id()];
        for i in 0..k + 2 {
            files.insert("pub/main.txt".into(), format!("main {i}\n").into_bytes());
            let mut change = [0u8; 16];
            change[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            change[15] = 0xb1;
            let tip = *main.last().unwrap();
            main.push(h.commit(&th, &[tip], files.clone(), change, t0 + i as i64 * 1000, None));
        }
        let mut top = *main.last().unwrap();
        let mut all = files.clone();
        for (i, fork) in main.iter().copied().enumerate().take(k + 1).skip(1) {
            let mut f = h.files[&fork].clone();
            f.insert(format!("pub/b{i}.txt"), b"branch\n".to_vec());
            let mut change = [0u8; 16];
            change[..8].copy_from_slice(&(i as u64).to_le_bytes());
            change[15] = 0xb2;
            let x = h.commit(&th, &[fork], f, change, t0 + 1_000_000 + i as i64, None);
            all.insert(format!("pub/b{i}.txt"), b"branch\n".to_vec());
            change[15] = 0xb3;
            top = h.commit(&th, &[top, x], all.clone(), change, t0 + 2_000_000 + i as i64, None);
        }
        h.set_branch(&th, "main", top);
        warm_up(&th, &h, &Viewer::default());
        let a = ask(&th, &h, &Viewer::default());
        let limits = Limits {
            cursor: k,
            ..Limits::default()
        };
        let total = h.order.len() + 1; // and the root
        let (mut seen, mut after, mut pages) = (0usize, None::<String>, Vec::new());
        loop {
            let r = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(2 * k), after: after.clone(), ..Default::default() }, limits));
            let v = match r {
                Ok(v) => v,
                Err(e) => {
                    let width = after.as_deref().map_or(0, |c| c.split(',').count());
                    println!("BUG-1076: {k} long-lived branches, cursor limit {k}: pages {pages:?}, then a cursor of {width} snapshots: {e:?}");
                    panic!("after {seen} of {total} entries, the server refused the cursor it gave ({width} snapshots, limit {k}): {e:?}");
                }
            };
            let got = v["entries"].as_array().unwrap().len();
            seen += got;
            pages.push(got);
            match v["next"].as_str() {
                Some(c) => after = Some(c.to_string()),
                None => break,
            }
            assert!(pages.len() < 100);
        }
        assert_eq!(seen, total);
    }
    /// 40 lines from the root that never meet but at the top, merged one
    /// after another: 40 are open at once while a log walks them.
    fn wide_graph(th: &TestHub) -> (Hist, usize, usize) {
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(th, &policy_text, &bindings);
        let t0 = 1_700_000_000_000i64;
        let (lines, len) = (40usize, 5usize);
        let mut tips = Vec::new();
        for l in 0..lines {
            let mut tip = root_snapshot_id();
            for i in 0..len {
                let f = Files::from([(format!("pub/l{l}.txt"), format!("{i}\n").into_bytes())]);
                let mut change = [0u8; 16];
                change[..8].copy_from_slice(&((l * 100 + i) as u64 + 1).to_le_bytes());
                change[15] = 0xd1;
                tip = h.commit(th, &[tip], f, change, t0 + (i * lines + l) as i64 * 1000, None);
            }
            tips.push(tip);
        }
        let mut top = tips[0];
        for (l, t) in tips.iter().enumerate().skip(1) {
            let mut change = [0u8; 16];
            change[..8].copy_from_slice(&(l as u64).to_le_bytes());
            change[15] = 0xd2;
            top = h.commit(th, &[top, *t], Files::from([("pub/top.txt".to_string(), format!("{l}\n").into_bytes())]), change, t0 + 10_000_000 + l as i64, None);
        }
        h.set_branch(th, "main", top);
        warm_up(th, &h, &Viewer::default());
        (h, lines, len)
    }

    /// A log over a wide graph pages to the end, through cursors the server
    /// keeps (BUG-1076), and the pages together are the log in one page:
    /// 40 lines from the root that never meet but at the top, merged one
    /// after another, so that 40 are open at once while the log walks
    /// them; with a cursor limit of 8.
    #[test]
    fn query_wide_logs_page_through_kept_cursors() {
        let th = TestHub::start();
        let (h, lines, len) = wide_graph(&th);
        let a = ask(&th, &h, &Viewer::default());
        let ids = |v: &Value| v["entries"].as_array().unwrap().iter().map(|e| e["snapshot_id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        let whole = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(1000), ..Default::default() }, Limits::default())).unwrap();
        assert!(whole["next"].is_null());
        let narrow = Limits {
            cursor: 8,
            ..Limits::default()
        };
        let (mut paged, mut after, mut kept) = (Vec::new(), None::<String>, 0);
        for _ in 0..200 {
            let v = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(7), after: after.clone(), ..Default::default() }, narrow)).unwrap();
            paged.extend(ids(&v));
            after = v["next"].as_str().map(str::to_string);
            match &after {
                Some(c) if c.starts_with("frontier-") => kept += 1,
                Some(c) => assert!(c.split(',').count() <= 8, "{c}"),
                None => break,
            }
        }
        assert!(after.is_none(), "the log did not end");
        assert_eq!(paged, ids(&whole));
        assert_eq!(paged.len(), lines * len + lines - 1 + 1);
        assert!(kept > 0, "the frontier never passed the limit");
        // A kept cursor is the viewer's: another view key does not have it.
        let v = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(lines), ..Default::default() }, narrow)).unwrap();
        let c = v["next"].as_str().unwrap().to_string();
        assert!(c.starts_with("frontier-"), "{c}");
        let other = ask(&th, &h, &admin());
        warm_up(&th, &h, &admin());
        let r = th.rt.block_on(query::log(&h.hub, &other, LogParams { after: Some(c), ..Default::default() }, narrow));
        assert!(matches!(r, Err(Error::Api { code: "bad_request", .. })), "{r:?}");
    }

    /// BUG-1079: a page that only reads its cursor's snapshots, and cannot
    /// take the next one without passing `Limits::frontier`, answered no
    /// entries and the cursor it was given, so a reader paging to the end
    /// asked forever (each page reading the whole frontier). It must end
    /// in the "too wide" error instead. 40 lines open at once, a frontier
    /// limit of 20: every page either moves the log on or is that error.
    #[test]
    fn bug_1079_a_log_page_never_hands_back_the_cursor_it_was_given() {
        let th = TestHub::start();
        let (h, _, _) = wide_graph(&th);
        let a = ask(&th, &h, &Viewer::default());
        let tight = Limits {
            cursor: 8,
            frontier: 20,
            ..Limits::default()
        };
        let mut after = None::<String>;
        for page in 0..200 {
            let r = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(7), after: after.clone(), ..Default::default() }, tight));
            let v = match r {
                Ok(v) => v,
                Err(Error::Api { code: "bad_request", .. }) if page > 0 => return,
                Err(e) => panic!("page {page}: {e:?}"),
            };
            let next = v["next"].as_str().map(str::to_string);
            assert!(next.is_none() || next != after, "page {page} answered {} entries and the cursor it was given", v["entries"].as_array().unwrap().len());
            if next.is_none() {
                return;
            }
            after = next;
        }
        panic!("200 pages and the log neither ended nor refused");
    }

    /// Kept cursors are bounded, whatever anyone asks: anyone on Earth
    /// paging a wide public log over and over, from many places, makes the
    /// server keep at most `Limits::kept_bytes` of cursors for the project
    /// after every request (oldest dropped first; one row per request, of
    /// at most `Limits::frontier` snapshots); the same frontier is kept
    /// once; rows past `Limits::kept_for` are dropped by the next write and
    /// never served.
    #[test]
    fn query_kept_cursors_stay_bounded() {
        let th = TestHub::start();
        let (h, _, _) = wide_graph(&th);
        let a = ask(&th, &h, &Viewer::default());
        let limits = Limits {
            cursor: 2,
            kept_bytes: 8 << 10,
            ..Limits::default()
        };
        let kept = || -> (i64, i64) {
            th.rt.block_on(
                sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(LENGTH(frontier)), 0)::bigint FROM log_cursors WHERE project_id = $1")
                    .bind(h.id)
                    .fetch_one(&h.hub.db),
            )
            .unwrap()
        };
        let mut rng = Rng::new(97);
        let (mut after, mut written, mut tokens) = (None::<String>, 0usize, HashSet::new());
        for _ in 0..300 {
            if rng.chance(10) {
                after = None;
            }
            let n = 1 + rng.below(6);
            let v = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(n), after: after.clone(), ..Default::default() }, limits));
            after = match v {
                Ok(v) => v["next"].as_str().map(str::to_string),
                // A cursor dropped meanwhile (the cap): start again.
                Err(Error::Api { code: "bad_request", .. }) => None,
                Err(e) => panic!("{e:?}"),
            };
            if let Some(c) = after.as_ref().filter(|c| c.starts_with("frontier-")) {
                written += 1;
                tokens.insert(c.clone());
            }
            let (rows, bytes) = kept();
            assert!(bytes as usize <= limits.kept_bytes, "{rows} rows, {bytes} bytes kept");
        }
        let (rows, bytes) = kept();
        println!("kept cursors: {written} written ({} distinct), {rows} rows and {bytes} bytes kept, cap {}", tokens.len(), limits.kept_bytes);
        assert!(tokens.len() > rows as usize, "the cap never dropped a row");
        // The same frontier is one row.
        let v = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(3), ..Default::default() }, limits)).unwrap();
        let first = v["next"].as_str().unwrap().to_string();
        let before = kept().0;
        let v = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(3), ..Default::default() }, limits)).unwrap();
        assert_eq!(v["next"].as_str().unwrap(), first);
        assert_eq!(kept().0, before, "the same frontier was kept twice");
        // Expired rows are never served, and the next write drops them.
        th.rt.block_on(again(|| sqlx::query("UPDATE log_cursors SET created_at = 0 WHERE project_id = $1").bind(h.id).execute(&h.hub.db)));
        let r = th.rt.block_on(query::log(&h.hub, &a, LogParams { after: Some(first.clone()), ..Default::default() }, limits));
        assert!(matches!(r, Err(Error::Api { code: "bad_request", .. })), "an expired cursor was served: {r:?}");
        let v = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(5), ..Default::default() }, limits)).unwrap();
        assert!(v["next"].as_str().unwrap().starts_with("frontier-"));
        let old: i64 = th.rt.block_on(sqlx::query_scalar("SELECT COUNT(*) FROM log_cursors WHERE project_id = $1 AND created_at = 0").bind(h.id).fetch_one(&h.hub.db)).unwrap();
        assert_eq!(old, 0, "expired rows were not dropped by the next write");
    }

    /// BUG-1078's bound at the source: a snapshot of more than
    /// `sync::MAX_PARENTS` (64) parents is refused at push; 64 are taken.
    #[test]
    fn query_pushes_cap_a_snapshots_parents() {
        let th = TestHub::start();
        let p = setup_project(&th);
        let api = th.api();
        let token = p.admin.token();
        let max = veil_server::sync::MAX_PARENTS;
        let mut tips = Vec::new();
        for i in 0..max {
            let mut f = Craft::new(&api, &p.admin, &p.name, "main");
            f.file(&format!("src/w{i}.txt"), "w");
            let r = f.push_to(&format!("w{i}"), None);
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            tips.push(api.tips(Some(&token), &p.name).unwrap().branches[&format!("w{i}")]);
        }
        let c = Craft::new(&api, &p.admin, &p.name, "main");
        let r = c.push_merge("main", &tips);
        assert_eq!(r.status, 400, "{} parents: {}", max + 1, String::from_utf8_lossy(&r.body));
        assert!(String::from_utf8_lossy(&r.body).contains("at most 64 parents"));
        let c = Craft::new(&api, &p.admin, &p.name, "main");
        let r = c.push_merge("main", &tips[1..]);
        assert_eq!(r.status, 200, "{max} parents: {}", String::from_utf8_lossy(&r.body));
    }

    /// BUG-1077: `SIMILAR_MAX_HELD` (16 MiB) counts the deleted files'
    /// bytes, but what is held is their tables of line hashes: an entry of
    /// 12 bytes, in a hash table, per distinct line. Lines of 4 bytes
    /// (three non-zero bytes and a newline: 16 million distinct ones) make
    /// a table several times its file, so one anonymous `diff` holds
    /// several times the stated bound; and nothing bounds how many run at
    /// once (each on its own blocking thread, up to 512).
    #[test]
    fn bug_1077_rename_detection_holds_far_more_than_its_held_bound() {
        const CHILD: &str = "VEIL_BUG1077_CHILD";
        if std::env::var(CHILD).is_err() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "query::s13_adversarial::bug_1077_rename_detection_holds_far_more_than_its_held_bound", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines().filter(|l| l.contains("BUG-1077:")) {
                println!("{line}");
            }
            assert!(out.status.success() && stdout.contains("1 passed"), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
            return;
        }
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        // Just under 1 MiB of distinct 4-byte lines (no zero byte, so text).
        let blob = |salt: u8| -> (ObjectId, Vec<u8>, u64) {
            let mut b = Vec::with_capacity(1 << 20);
            let nl = |v: u8| if v == b'\n' { 251 } else { v };
            for j in 0..((1u32 << 20) - 64) / 4 {
                let c = |k: u32| ((j / k) % 250) as u8 + 1;
                b.extend_from_slice(&[nl(c(62_500) + salt), nl(c(250)), nl(c(1)), b'\n']);
            }
            let raw = Object::Blob(b.clone()).encode();
            (ObjectId::hash(&raw), raw, b.len() as u64)
        };
        let (ida, rawa, sa) = blob(0);
        let (idb, rawb, sb) = blob(5);
        let n = 15; // 15 MiB: under the 16 MiB held
        let mut oa = vec![(ida, rawa)];
        let ta = folder_of_copies("a", n, ida, sa, &mut oa);
        let mut ob = vec![(idb, rawb)];
        let tb = folder_of_copies("b", n, idb, sb, &mut ob);
        let x = commit_tree(&th, &mut h, &[root_snapshot_id()], ta, oa, 1, 1_000);
        let y = commit_tree(&th, &mut h, &[x], tb, ob, 2, 2_000);
        h.set_branch(&th, "main", y);
        let a = ask(&th, &h, &Viewer::default());
        warm_up(&th, &h, &Viewer::default());
        let slow = Limits {
            deadline: Duration::from_secs(120),
            ..Limits::default()
        };
        let p = DiffParams { from: x.hex(), to: Some(y.hex()), base: Some("from".into()), stat: Some(true), path: None };
        let t = Instant::now();
        let (r, grew) = peak_growth(|| th.rt.block_on(query::diff(&h.hub, &a, p, slow)));
        let r = r.unwrap();
        println!(
            "BUG-1077: diff of {n} deleted and {n} added files of 1 MiB of 4-byte lines, as anyone on Earth: renames_skipped {}, took {:?}, memory rose {} MiB (bound stated: {} MiB held)",
            r["renames_skipped"],
            t.elapsed(),
            grew >> 20,
            veil_server::derive::changes::SIMILAR_MAX_HELD >> 20
        );
        assert!(grew < 2 * veil_server::derive::changes::SIMILAR_MAX_HELD, "memory rose {} MiB", grew >> 20);
    }
    /// BUG-1078: BUG-1071's fix bounds a log page by its budget "whatever
    /// the history holds" because each step reads one snapshot's parents;
    /// but nothing bounds how many parents a snapshot has (push accepts any
    /// number). One step of a merge of `k` parents reads `k` rows, and puts
    /// all `k` in the frontier, which is the next cursor (so past 1,000
    /// parents, BUG-1076's refusal too). A page of 1 entry with a budget
    /// of 100 here reads every parent.
    #[test]
    fn bug_1078_one_log_step_over_a_wide_merge_passes_the_budget() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let k: usize = std::env::var("VEIL_BUG1078_PARENTS").ok().and_then(|s| s.parse().ok()).unwrap_or(600);
        let t0 = 1_700_000_000_000i64;
        let mut parents = Vec::new();
        let mut files = Files::new();
        for i in 0..k {
            let f = Files::from([(format!("pub/p{i}.txt"), b"x\n".to_vec())]);
            files.extend(f.clone());
            let mut change = [0u8; 16];
            change[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            change[15] = 0xc4;
            parents.push(h.commit(&th, &[root_snapshot_id()], f, change, t0 + i as i64, None));
        }
        let top = h.commit(&th, &parents, files, [0xc5; 16], t0 + 1_000_000, None);
        h.set_branch(&th, "main", top);
        warm_up(&th, &h, &Viewer::default());
        let a = ask(&th, &h, &Viewer::default());
        let limits = Limits {
            work: 100,
            ..Limits::default()
        };
        let v = th.rt.block_on(query::log(&h.hub, &a, LogParams { n: Some(1), ..Default::default() }, limits)).unwrap();
        let work = v["work"].as_u64().unwrap();
        let width = v["next"].as_str().map_or(0, |c| c.split(',').count());
        println!("BUG-1078: a page of 1 entry over a merge of {k} parents, budget {}: work {work}, next cursor of {width} snapshots", limits.work);
        assert!(work <= 2 * limits.work, "a page with a budget of {} read {work} rows and objects", limits.work);
    }
}
