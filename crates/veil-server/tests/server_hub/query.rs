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

/// Run `q` as `a`; a log is followed through every page (at most 60).
fn run(th: &TestHub, h: &Hist, a: &Ask, q: &Q) -> Vec<String> {
    let hub = h.hub.clone();
    th.rt.block_on(async {
        match q {
            Q::Log(p, limits) => {
                let mut out = Vec::new();
                let mut p = p.clone();
                for _ in 0..60 {
                    let r = query::log(&hub, a, p.clone(), *limits).await;
                    let next = r.as_ref().ok().and_then(|v| v["next"].as_str().map(str::to_string));
                    out.push(norm(r));
                    match next {
                        Some(n) => p.after = Some(n),
                        None => break,
                    }
                }
                out
            }
            Q::Show(p) => vec![norm(query::show(&hub, a, p.clone(), Limits::default()).await)],
            Q::Tree(p) => vec![norm(query::tree(&hub, a, p.clone(), Limits::default()).await)],
            Q::File(p) => vec![norm(query::file(&hub, a, p.clone(), Limits::default()).await.map(|(mut m, bytes)| {
                m["bytes"] = json!(hex::encode(bytes));
                m
            }))],
            Q::Diff(p) => vec![norm(query::diff(&hub, a, p.clone(), Limits::default()).await)],
            Q::Ancestry(pairs) => vec![norm(query::ancestry(&hub, a, query::AncestryRequest { pairs: pairs.clone() }, Limits::default()).await)],
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
/// and the log against the client's order (Kahn's algorithm, newest first),
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
        th.rt.block_on(query::graph::extend(&h.hub, &project, &admin(), &tips, None)).unwrap();
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
        // The log: Kahn's algorithm, newest (timestamp, id) first.
        let reach = anc(tips[0]);
        let mut children: HashMap<ObjectId, usize> = HashMap::new();
        for x in &reach {
            for p in &h.parents[x] {
                *children.entry(*p).or_default() += 1;
            }
        }
        let mut heap: std::collections::BinaryHeap<(i64, ObjectId)> = reach.iter().filter(|x| !children.contains_key(*x)).map(|x| (stamps[x], *x)).collect();
        let mut order = Vec::new();
        while let Some((_, x)) = heap.pop() {
            order.push(x.hex());
            for p in &h.parents[&x] {
                let c = children.get_mut(p).unwrap();
                *c -= 1;
                if *c == 0 {
                    heap.push((stamps[p], *p));
                }
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
                    set.spawn(async move { query::graph::extend(&hub, &project, &v, &tips, None).await.unwrap() });
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
            let n: i64 = th.rt.block_on(
                sqlx::query_scalar("SELECT COUNT(*) FROM view_graph WHERE project_id = $1 AND view_key = $2 AND snapshot = $3")
                    .bind(h.id)
                    .bind(&key)
                    .bind(p.hex())
                    .fetch_one(&h.hub.db),
            )
            .unwrap();
            assert_eq!(n, 1, "{key}: the tip's row");
        }
    }
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
    for (who, viewer) in [("admin", admin()), ("anyone on Earth", Viewer::default())] {
        let a = ask(&th, &h, &viewer);
        let t = Instant::now();
        let tips: Vec<ObjectId> = h.branches.values().copied().collect();
        th.rt.block_on(query::graph::extend(&h.hub, &project, &viewer, &tips, None)).unwrap();
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
                let v = query::log(&hub, &a, LogParams { n: Some(50), ..Default::default() }, Limits::default()).await.unwrap();
                time("log -n 50", v, t);
                let t = Instant::now();
                let v = query::log(&hub, &a, LogParams { n: Some(50), path: Some(hot.clone()), ..Default::default() }, Limits::default()).await.unwrap();
                assert_eq!(v["entries"].as_array().unwrap().len(), 50, "{v}");
                time("log -n 50 -- hot file", v, t);
                let t = Instant::now();
                let v = query::ancestry(&hub, &a, query::AncestryRequest { pairs: vec![(pa.hex(), pb.hex())] }, Limits::default()).await.unwrap();
                assert_eq!(v["results"][0]["is_ancestor"], json!(false));
                time("ancestry (merge base 20k apart)", v, t);
                let t = Instant::now();
                let v = query::ancestry(&hub, &a, query::AncestryRequest { pairs: vec![(root_snapshot_id().hex(), tip_p.hex())] }, Limits::default()).await.unwrap();
                time("is_ancestor(root, tip)", v, t);
                let t = Instant::now();
                let v = query::diff(&hub, &a, DiffParams { from: "main".into(), to: Some("b".into()), ..Default::default() }, Limits::default()).await.unwrap();
                assert!(v["files"].as_array().unwrap().len() >= 50, "{}", v["files"].as_array().unwrap().len());
                time("diff, 100 files vs merge base", v, t);
                let t = Instant::now();
                let v = query::tree(&hub, &a, TreeParams { path: Some("pub/d0".into()), ..Default::default() }, Limits::default()).await.unwrap();
                time("tree", v, t);
                let t = Instant::now();
                let v = query::file(&hub, &a, FileParams { rev: None, path: hot.clone() }, Limits::default()).await.unwrap().0;
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
