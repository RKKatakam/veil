//! Search (milestone S15; phase-3 design §3.5 and the threat review, §6).
//!
//! The central check is **projection equivalence** (rows 1–3): for random
//! histories and viewers, every search, name search and grep a viewer
//! makes of the real project, followed through every page, equals byte for
//! byte (counts, scores, order, cursors and `work` included) what its
//! admin gets on a copy of the project built only from that viewer's
//! projected history. The copy holds nothing hidden, so nothing hidden can
//! be found, counted, ranked or paid for in an answer.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use serde_json::Value;
use veil_core::{
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEntry, Visibility},
    ChangeId, ObjectId,
};
use veil_server::{
    error::Error,
    perm::Viewer,
    query::{self, Ask},
    search::{self, index, segment, GrepParams, Limits, SearchParams},
    sync::root_snapshot_id,
};

use crate::{
    derived::{again, copy_for, policy, projections, random_history, text, viewers, Files, Hist, Rng},
    support::*,
};

fn seeds(default: &[u64]) -> Vec<u64> {
    match std::env::var("VEIL_SEARCH_SEED").ok().and_then(|s| s.parse::<u64>().ok()) {
        Some(s) => (s..s + default.len() as u64).collect(),
        None => default.to_vec(),
    }
}

fn admin() -> Viewer {
    Viewer {
        admin: true,
        ..Viewer::default()
    }
}

fn ask(th: &TestHub, h: &Hist, viewer: &Viewer) -> Ask {
    Ask {
        project: h.project(th),
        viewer: viewer.clone(),
        policy_version: 1,
    }
}

fn warm_up(th: &TestHub, h: &Hist, viewer: &Viewer) {
    let tips: Vec<ObjectId> = h.branches.values().copied().collect();
    th.rt.block_on(query::graph::ensure(&h.hub, &h.project(th), viewer, &tips, None)).unwrap();
}

/// Derive `h`, then bring its search index up to every branch.
fn index(th: &TestHub, h: &Hist) -> index::Stats {
    h.derive(th);
    th.rt.block_on(index::update(&h.hub, h.id, None)).unwrap()
}

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

#[derive(Clone, Debug)]
enum S {
    Search(SearchParams, Limits),
    Grep(GrepParams, Limits),
}

/// Run `q` as `a`, following `next` through every page (at most 40).
fn run(th: &TestHub, h: &Hist, a: &Ask, q: &S) -> Vec<String> {
    let hub = h.hub.clone();
    th.rt.block_on(async {
        let mut out = Vec::new();
        let mut q = q.clone();
        for _ in 0..40 {
            let r = match &q {
                S::Search(p, l) => search::search(&hub, a, p.clone(), *l).await,
                S::Grep(p, l) => search::grep(&hub, a, p.clone(), *l).await,
            };
            let next = r.as_ref().ok().and_then(|v| v["next"].as_str().map(str::to_string));
            out.push(norm(r));
            match (next, &mut q) {
                (Some(n), S::Search(p, _)) => p.after = Some(n),
                (Some(n), S::Grep(p, _)) => p.after = Some(n),
                (None, _) => break,
            }
        }
        out
    })
}

/// Words of every file and path any snapshot of `h` held (hidden ones
/// too: searching for them must find nothing hidden).
fn vocabulary(h: &Hist) -> Vec<String> {
    let mut out = BTreeSet::new();
    for files in h.files.values() {
        for (p, c) in files {
            out.extend(p.split('/').filter(|s| !s.is_empty()).map(str::to_string));
            for w in String::from_utf8_lossy(c).split_whitespace() {
                out.insert(w.to_string());
                out.extend(w.split('/').filter(|s| s.len() > 1).map(str::to_string));
            }
        }
    }
    out.into_iter().collect()
}

fn small() -> Limits {
    Limits {
        confirm_files: 3,
        confirm_bytes: 600,
        names: 4,
        grep_files: 2,
        grep_bytes: 500,
        grep_lines: 2,
        lines: 1,
        ..Limits::default()
    }
}

/// The harness's queries: ranked code and name searches with folders,
/// languages, page sizes and small bounds; greps at branches (the index)
/// and at the viewer's own ids (a scan).
fn queries(rng: &mut Rng, words: &[String], revs: &[String], ids: &[String]) -> Vec<S> {
    let pick = |rng: &mut Rng, v: &[String]| v[rng.below(v.len())].clone();
    let dirs = ["", "pub", "fin", "pub/sec", "carol-d", "pub/deep", "missing-dir"];
    let mut out = Vec::new();
    for i in 0..36 {
        let mut q = pick(rng, words);
        if rng.chance(35) {
            q = format!("{q} {}", pick(rng, words));
        }
        if rng.chance(10) {
            q = ["line", "edit", "e", "li", "txt"][rng.below(5)].to_string();
        }
        let p = SearchParams {
            q: Some(q),
            rev: Some(if rng.chance(80) { pick(rng, revs) } else { pick(rng, ids) }),
            kind: if i % 3 == 0 { Some("path".into()) } else { None },
            path: rng.chance(30).then(|| dirs[rng.below(dirs.len())].to_string()),
            lang: rng.chance(5).then(|| "markdown".to_string()),
            n: Some([1, 2, 5, 20][rng.below(4)]),
            after: None,
        };
        out.push(S::Search(p, if rng.chance(40) { small() } else { Limits::default() }));
    }
    let patterns = ["line [0-9]+ 7", "edit", "(?i)MOVED", "twin|shared", "f[0-9]+-", "one more", "^pub", "source edited$"];
    for _ in 0..20 {
        let pattern = if rng.chance(40) { regex::escape(&pick(rng, words)) } else { patterns[rng.below(patterns.len())].to_string() };
        let rev = if rng.chance(60) { pick(rng, revs) } else { pick(rng, ids) };
        let p = GrepParams {
            pattern,
            rev: Some(rev),
            i: Some(rng.chance(30)),
            path: rng.chance(30).then(|| dirs[rng.below(dirs.len())].to_string()),
            n: Some([1, 2, 100][rng.below(3)]),
            after: None,
        };
        out.push(S::Grep(p, if rng.chance(40) { small() } else { Limits::default() }));
    }
    out
}

/// An answer without the query or pattern it echoes.
fn without_echo(a: &str) -> String {
    match serde_json::from_str::<Value>(a) {
        Ok(mut v) => {
            v.as_object_mut().unwrap().remove("query");
            v.as_object_mut().unwrap().remove("pattern");
            v.to_string()
        }
        Err(_) => a.to_string(),
    }
}

fn all_paths(h: &Hist) -> BTreeSet<String> {
    h.files.values().flat_map(|f| f.keys().map(|k| k.trim_end_matches('/').to_string())).collect()
}

#[test]
fn search_projection_equivalence() {
    let th = TestHub::start();
    for seed in seeds(&[301, 302, 303]) {
        let carol = 730_000 + seed as i64;
        let (policy_text, bindings) = policy(carol);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut rng = Rng::new(seed);
        random_history(&th, &mut h, &mut rng, 40);
        index(&th, &h);
        let project = h.project(&th);
        let words = vocabulary(&h);
        let mut compared = 0usize;
        let mut found = 0usize;
        for (who, viewer) in viewers(carol) {
            let p = projections(&th, &h, &project, &viewer);
            let copy = copy_for(&th, &h, &project, &viewer, &p);
            index(&th, &copy);
            warm_up(&th, &h, &viewer);
            warm_up(&th, &copy, &admin());
            let view = project.view(&viewer);
            let mine: Vec<String> = p.values().map(|i| i.hex()).collect::<BTreeSet<_>>().into_iter().collect();
            let mut ids: Vec<String> = (0..4).map(|_| mine[rng.below(mine.len())].clone()).collect();
            ids.push(root_snapshot_id().hex());
            if let Some(s) = h.order.iter().find(|s| p[*s] != **s) {
                ids.push(s.hex());
            }
            let revs: Vec<String> = ["main", "side", "main", "side", "no-such-branch"].map(String::from).to_vec();
            let (mine_ask, copy_ask) = (ask(&th, &h, &viewer), ask(&th, &copy, &admin()));
            let hidden: Vec<String> = all_paths(&h).into_iter().filter(|k| !k.is_empty() && !view.read(k)).collect();
            let readable: Vec<String> = all_paths(&h).into_iter().filter(|k| view.read(k)).collect();
            for q in queries(&mut rng, &words, &revs, &ids) {
                let (real, theirs) = (run(&th, &h, &mine_ask, &q), run(&th, &copy, &copy_ask, &q));
                assert_eq!(real, theirs, "seed {seed}, {who}: {q:?}");
                compared += real.len();
                found += real.iter().filter(|a| a.contains("\"path\":")).count();
                for a in &real {
                    // What the viewer asked for is echoed; the rest is
                    // what the server found.
                    let a = &without_echo(a);
                    for k in &hidden {
                        if !readable.iter().any(|r| r.starts_with(k.as_str())) {
                            assert!(!a.contains(&format!("\"{k}\"")), "seed {seed}, {who}: hidden path {k} in {a}");
                        }
                    }
                }
            }
        }
        println!("seed {seed}: {} changes, {compared} answers compared, {found} with hits", h.order.len());
        assert!(found > 50, "the harness finds things");
    }
}

/// Row 4: two projects that differ only in hidden content (hidden files
/// full of the words searched for, and runs of hidden changes) give a
/// restricted viewer identical answers and work for every query.
#[test]
fn search_work_ignores_hidden_content() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut rng = Rng::new(9);
    let mut a = Hist::new(&th, &policy_text, &bindings);
    let mut b = Hist::new(&th, &policy_text, &bindings);
    let root = root_snapshot_id();
    let (mut ta, mut tb) = (root, root);
    let mut files = Files::new();
    let mut hidden = Files::new();
    let words = ["alpha", "beta", "gamma", "delta", "handler", "pub", "fin"];
    for i in 0..24u8 {
        for j in 0..(i % 3) {
            let flood: String = (0..200).map(|k| format!("{} {} pub/f{k}.txt\n", words[k % words.len()], words[(k + j as usize) % words.len()])).collect();
            hidden.insert(format!("fin/flood-{i}-{j}.txt"), flood.into_bytes());
            hidden.insert(format!("fin/handler-{i}-{j}.rs"), b"alpha handler\n".to_vec());
            let mut fb = files.clone();
            fb.extend(hidden.clone());
            tb = b.commit(&th, &[tb], fb, [100 + j; 16], 9_000_000_000_000 + i64::from(i), None);
        }
        let w = words[i as usize % words.len()];
        files.insert(format!("pub/f{}.txt", i % 5), format!("{w} line {i}\n{}", String::from_utf8(text(&mut rng, w, 4)).unwrap()).into_bytes());
        files.insert("fin/base.txt".into(), b"alpha hidden in both\n".to_vec());
        let ts = 1_700_000_000_000 + i64::from(i) * 1000;
        ta = a.commit(&th, &[ta], files.clone(), [i; 16], ts, None);
        let mut fb = files.clone();
        fb.extend(hidden.clone());
        tb = b.commit(&th, &[tb], fb, [i; 16], ts, None);
    }
    a.set_branch(&th, "main", ta);
    b.set_branch(&th, "main", tb);
    index(&th, &a);
    index(&th, &b);
    for (who, viewer) in [("anyone on Earth", Viewer::default()), ("a dev", viewers(1)[1].1.clone())] {
        let (aa, ab) = (ask(&th, &a, &viewer), ask(&th, &b, &viewer));
        warm_up(&th, &a, &viewer);
        warm_up(&th, &b, &viewer);
        let tip = th.rt.block_on(query::resolve(&a.hub, &aa, "main", Instant::now() + Duration::from_secs(60))).unwrap();
        let vocab: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        let mut n = 0;
        for q in queries(&mut rng, &vocab, &["main".to_string()], &[tip.hex()]) {
            let (x, y) = (run(&th, &a, &aa, &q), run(&th, &b, &ab, &q));
            assert_eq!(x, y, "{who}: {q:?}");
            n += x.iter().filter(|r| r.contains("\"path\":")).count();
        }
        assert!(n > 5, "{who}: some hits");
    }
}

// ---- secrets and embargoes ------------------------------------------------------------

/// Every segment object of `h`'s indexes, raw.
fn segments(th: &TestHub, hub: &std::sync::Arc<veil_server::Hub>, project: i64) -> Vec<(String, Vec<u8>)> {
    th.rt.block_on(async {
        let rows: Vec<String> = sqlx::query_scalar("SELECT segments FROM search_shards WHERE project_id = $1").bind(project).fetch_all(&hub.db).await.unwrap();
        let mut out = Vec::new();
        for r in rows {
            let segs: Vec<index::SegRef> = serde_json::from_str(&r).unwrap();
            for s in segs {
                let raw = hub.objects.get(project, &ObjectId::from_hex(&s.id).unwrap()).await.unwrap().expect("segment stored");
                out.push((s.id.clone(), raw.to_vec()));
            }
        }
        out
    })
}

/// Row 8: an embargo line is never indexed, walked or found: no search by
/// anyone (admins included) finds its names or strings, its branch is no
/// revision, and no segment holds them.
#[test]
fn search_withholds_embargo_lines() {
    let th = TestHub::start();
    let (text_, bindings) = policy(1);
    let mut h = Hist::new(&th, &text_, &bindings);
    let base = Files::from([("pub/a.rs".to_string(), b"fn a() {}\n".to_vec())]);
    let a = h.commit(&th, &[root_snapshot_id()], base.clone(), [1; 16], 1_000, None);
    let mut fixed = base.clone();
    fixed.insert("pub/fix-embargo-77c1e0.rs".into(), b"FIX-MARKER-a91f\n".to_vec());
    let e = h.commit(&th, &[a], fixed.clone(), [2; 16], 2_000, Some("cve-1"));
    let mut later = fixed;
    later.insert("pub/after-fix-5d2c.rs".into(), b"later\n".to_vec());
    let c = h.commit(&th, &[e], later, [3; 16], 3_000, None);
    h.set_branch(&th, "main", a);
    h.set_branch(&th, "embargoed", c);
    index(&th, &h);
    for (who, viewer) in [("admin", admin()), ("anyone", Viewer::default()), ("a dev", viewers(1)[1].1.clone())] {
        warm_up(&th, &h, &viewer);
        let x = ask(&th, &h, &viewer);
        for q in ["FIX-MARKER-a91f", "fix-embargo", "after-fix", "later"] {
            for kind in [None, Some("path".to_string())] {
                let r = run(&th, &h, &x, &S::Search(SearchParams { q: Some(q.into()), kind: kind.clone(), ..Default::default() }, Limits::default()));
                assert!(r[0].contains("\"results\":[]"), "{who}: {q}: {r:?}");
                let r = run(&th, &h, &x, &S::Search(SearchParams { q: Some(q.into()), kind, rev: Some("embargoed".into()), ..Default::default() }, Limits::default()));
                assert!(r[0].starts_with("error 404"), "{who}: {r:?}");
            }
            let r = run(&th, &h, &x, &S::Grep(GrepParams { pattern: q.into(), rev: Some("embargoed".into()), ..Default::default() }, Limits::default()));
            assert!(r[0].starts_with("error 404"), "{who}: {r:?}");
            for rev in [e.hex(), c.hex()] {
                let r = run(&th, &h, &x, &S::Grep(GrepParams { pattern: q.into(), rev: Some(rev), ..Default::default() }, Limits::default()));
                assert!(r[0].starts_with("error 404"), "{who}: {r:?}");
            }
        }
    }
    for (id, raw) in segments(&th, &h.hub, h.id) {
        let s = String::from_utf8_lossy(&raw);
        assert!(!s.contains("fix-embargo") && !s.contains("FIX-MARKER") && !s.contains("after-fix"), "segment {id}");
    }
    let heads: Vec<String> = th.rt.block_on(sqlx::query_scalar("SELECT snapshot FROM search_heads WHERE project_id = $1").bind(h.id).fetch_all(&h.hub.db)).unwrap();
    assert!(!heads.contains(&e.hex()) && !heads.contains(&c.hex()), "{heads:?}");
}

/// A tree of `files`, with the paths in `sealed` as secrets (cloaked
/// entries whose objects the server must never open).
fn sealed_tree(files: &Files, sealed: &BTreeSet<String>, prefix: &str, out: &mut Vec<(ObjectId, Vec<u8>)>) -> ObjectId {
    let mut here: BTreeMap<String, TreeEntry> = BTreeMap::new();
    let mut sub: BTreeMap<String, Files> = BTreeMap::new();
    for (p, c) in files {
        match p.split_once('/') {
            Some((d, rest)) => {
                sub.entry(d.to_string()).or_default().insert(rest.to_string(), c.clone());
            }
            None => {
                let raw = Object::Blob(c.clone()).encode();
                let id = ObjectId::hash(&raw);
                out.push((id, raw));
                let full = format!("{prefix}{p}");
                let visibility = if sealed.contains(&full) { Visibility::Cloaked { scope: "billing".into() } } else { Visibility::Public };
                here.insert(p.clone(), TreeEntry { name: p.clone(), kind: EntryKind::File, id, size: c.len() as u64, executable: false, visibility });
            }
        }
    }
    for (d, m) in sub {
        let id = sealed_tree(&m, sealed, &format!("{prefix}{d}/"), out);
        here.insert(d.clone(), TreeEntry { name: d, kind: EntryKind::Dir, id, size: 0, executable: false, visibility: Visibility::Public });
    }
    let raw = Object::Tree(Tree { entries: here.into_values().collect() }).encode();
    let id = ObjectId::hash(&raw);
    out.push((id, raw));
    id
}

/// Row 7: a secret is indexed by path only. Its object (here, plaintext
/// a broken client might upload) is never opened: no segment holds its
/// content, no search or grep finds it (admins included), and its path is
/// found by name only by those who may see its folder.
#[test]
fn search_finds_secrets_by_name_only() {
    let th = TestHub::start();
    let (text_, bindings) = policy(1);
    let mut h = Hist::new(&th, &text_, &bindings);
    let marker = "SECRET-CONTENT-3b9e41";
    let files = Files::from([
        ("pub/app.rs".to_string(), b"fn main() { load_env() }\n".to_vec()),
        ("fin/.env".to_string(), format!("KEY={marker}\n").into_bytes()),
        ("pub/.env".to_string(), format!("PUBLIC_KEY={marker}\n").into_bytes()),
    ]);
    let sealed: BTreeSet<String> = ["fin/.env", "pub/.env"].map(String::from).into();
    let mut objects = Vec::new();
    let tree = sealed_tree(&files, &sealed, "", &mut objects);
    let s = Snapshot {
        parents: vec![root_snapshot_id()],
        change_id: ChangeId([5; 16]),
        tree,
        description: Text::Plain("with secrets".into()),
        author: "gen".into(),
        timestamp: 1_000,
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        agent: None,
        abandoned: None,
        attempts: vec![],
        signature: None,
    };
    let raw = Object::Snapshot(s).encode();
    let id = ObjectId::hash(&raw);
    objects.push((id, raw));
    h.put(&th, objects);
    th.rt.block_on(async {
        again(|| sqlx::query("INSERT INTO snapshots (project_id, id) VALUES ($1, $2)").bind(h.id).bind(id.hex()).execute(&h.hub.db)).await;
    });
    h.files.insert(id, files);
    h.order.push(id);
    h.set_branch(&th, "main", id);
    index(&th, &h);
    for (_, raw) in segments(&th, &h.hub, h.id) {
        assert!(!String::from_utf8_lossy(&raw).contains(marker), "a segment holds a secret's content");
    }
    let fin = viewers(1)[3].1.clone();
    for (who, viewer, sees_fin) in [("admin", admin(), true), ("finance", fin, true), ("anyone", Viewer::default(), false)] {
        warm_up(&th, &h, &viewer);
        let x = ask(&th, &h, &viewer);
        let r = run(&th, &h, &x, &S::Search(SearchParams { q: Some(marker.into()), ..Default::default() }, Limits::default()));
        assert!(r[0].contains("\"results\":[]") && !without_echo(&r[0]).contains(marker), "{who}: {r:?}");
        for pattern in [marker, "KEY", "."] {
            let r = run(&th, &h, &x, &S::Grep(GrepParams { pattern: pattern.into(), ..Default::default() }, Limits::default()));
            assert!(!r[0].starts_with("error") && !without_echo(&r[0]).contains(marker) && !r[0].contains(".env"), "{who}: {r:?}");
            let r = run(&th, &h, &x, &S::Grep(GrepParams { pattern: pattern.into(), rev: Some(id.hex()), ..Default::default() }, Limits::default()));
            if sees_fin {
                assert!(!r[0].starts_with("error") && !without_echo(&r[0]).contains(marker) && !r[0].contains(".env"), "{who}: {r:?}");
            } else {
                assert!(r[0].starts_with("error 404"), "{who}: {r:?}");
            }
        }
        let r = run(&th, &h, &x, &S::Search(SearchParams { q: Some(".env".into()), kind: Some("path".into()), ..Default::default() }, Limits::default()));
        assert!(r[0].contains("\"path\":\"pub/.env\""), "{who}: {r:?}");
        assert_eq!(r[0].contains("\"path\":\"fin/.env\""), sees_fin, "{who}: {r:?}");
    }
}

// ---- policy changes, increments, races ------------------------------------------------

/// Every answer of a fixed set of queries, for `viewer`.
fn answers(th: &TestHub, h: &Hist, viewer: &Viewer, words: &[String], seed: u64) -> Vec<String> {
    warm_up(th, h, viewer);
    let a = Ask {
        project: h.project(th),
        ..ask(th, h, viewer)
    };
    let mut rng = Rng::new(seed);
    let tip = th.rt.block_on(query::resolve(&h.hub, &a, "main", Instant::now() + Duration::from_secs(60))).unwrap();
    queries(&mut rng, words, &["main".to_string()], &[tip.hex()]).iter().flat_map(|q| run(th, h, &a, q)).collect()
}

/// Forget `h`'s index and build it again from nothing.
fn rebuild(th: &TestHub, h: &Hist) {
    th.rt.block_on(async {
        for t in ["search_heads", "search_shards"] {
            let q = format!("DELETE FROM {t} WHERE project_id = $1");
            again(|| sqlx::query(&q).bind(h.id).execute(&h.hub.db)).await;
        }
    });
    segment::clear_cache();
    index(th, h);
}

/// Row 13: under a new policy, the index answers `indexing` until it is
/// rebuilt (never a result outside the new access); the rebuild keeps the
/// shards of unchanged lines (same segments) and gives exactly the answers
/// of an index built from nothing under the new policy.
#[test]
fn search_follows_policy_changes() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    random_history(&th, &mut h, &mut Rng::new(43), 30);
    index(&th, &h);
    let words = vocabulary(&h);
    let shard_rows = || -> BTreeMap<String, String> {
        th.rt.block_on(async {
            let rows: Vec<(String, String, String)> = sqlx::query_as("SELECT kind || branch, line_key, segments FROM search_shards WHERE project_id = $1")
                .bind(h.id)
                .fetch_all(&h.hub.db)
                .await
                .unwrap();
            rows.into_iter().map(|(a, b, c)| (format!("{a} {b}"), c)).collect()
        })
    };
    let before = shard_rows();
    let anyone = Viewer::default();
    let fin_found = |h: &Hist| -> bool {
        let a = Ask { project: h.project(&th), ..ask(&th, h, &anyone) };
        warm_up(&th, h, &anyone);
        let r = run(&th, h, &a, &S::Search(SearchParams { q: Some("fin".into()), kind: Some("path".into()), n: Some(100), ..Default::default() }, Limits::default()));
        assert!(!r[0].starts_with("error"), "{r:?}");
        r[0].contains("\"path\":\"fin/")
    };
    assert!(!fin_found(&h));
    // Who reads a line is not part of its key: making fin/ public needs
    // no rebuild, and anyone finds it at once.
    let opened = format!("{policy_text}fin/ public finance\n");
    th.rt.block_on(async {
        again(|| sqlx::query("UPDATE projects SET policy_text = $1, policy_version = 2 WHERE id = $2").bind(&opened).bind(h.id).execute(&h.hub.db)).await;
    });
    assert!(fin_found(&h), "fin/ made public");
    assert_eq!(shard_rows(), before);
    // A line below pub/ changes the paths pub/'s line (and no line)
    // decides: those shards are rebuilt.
    let moved = format!("{opened}pub/deep/ security\n");
    th.rt.block_on(async {
        again(|| sqlx::query("UPDATE projects SET policy_text = $1, policy_version = 3 WHERE id = $2").bind(&moved).bind(h.id).execute(&h.hub.db)).await;
    });
    // Before the rebuild: `indexing`, for code and names alike.
    let a = Ask { project: h.project(&th), ..ask(&th, &h, &anyone) };
    warm_up(&th, &h, &anyone);
    for kind in [None, Some("path".to_string())] {
        let r = run(&th, &h, &a, &S::Search(SearchParams { q: Some("fin".into()), kind, ..Default::default() }, Limits::default()));
        assert!(r[0].starts_with("error 503") && r[0].contains("indexing"), "{r:?}");
    }
    index(&th, &h);
    assert!(fin_found(&h), "fin/ still public");
    // Shards of lines whose paths did not change kept their segments.
    let after = shard_rows();
    assert_ne!(after, before);
    let entry = |k: EntryKind| TreeEntry { name: String::new(), kind: k, id: ObjectId([0; 32]), size: 0, executable: false, visibility: Visibility::Public };
    let lines = |t: &str| veil_server::derive::lines::Lines::new(&veil_core::hub::access::AccessPolicy::parse(t));
    let (old, new) = (lines(&policy_text), lines(&moved));
    assert_ne!(old.key_of("pub/a", &entry(EntryKind::File)), new.key_of("pub/a", &entry(EntryKind::File)));
    let kept = old.key_of("pub/sec/x", &entry(EntryKind::File)).to_string();
    assert_eq!(kept, new.key_of("pub/sec/x", &entry(EntryKind::File)));
    for (k, segs) in &before {
        if k.ends_with(&kept) {
            assert_eq!(after.get(k), Some(segs), "{k}: an unchanged line's shard was rebuilt");
        }
    }
    let incremental: Vec<Vec<String>> = viewers(1).iter().map(|(_, v)| answers(&th, &h, v, &words, 5)).collect();
    rebuild(&th, &h);
    let fresh: Vec<Vec<String>> = viewers(1).iter().map(|(_, v)| answers(&th, &h, v, &words, 5)).collect();
    assert_eq!(incremental, fresh);
}

/// Row 11: an index moved landing by landing (with merges, tombstones,
/// a rewrite of dead documents, and two servers updating it at once)
/// answers exactly like one built from nothing at the end.
#[test]
fn search_increments_equal_a_fresh_build() {
    let th = TestHub::start();
    let other = TestHub::beside(&th);
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut rng = Rng::new(61);
    let mut files = Files::new();
    let mut tip = root_snapshot_id();
    let mut side = None;
    let mut merges = 0;
    for i in 0..70usize {
        // Many edits of few files (dead documents), adds, deletes and
        // renames, across the boundary.
        for _ in 0..1 + rng.below(3) {
            let dir = ["pub", "fin", "pub/sec", "carol-d"][rng.below(4)];
            let k = format!("{dir}/f{}.txt", rng.below(12));
            match rng.below(6) {
                0 => {
                    files.remove(&k);
                }
                1 => {
                    if let Some(c) = files.remove(&k) {
                        files.insert(format!("{dir}/r{i}.txt"), c);
                    }
                }
                _ => {
                    let lines = 3 + rng.below(5);
                    files.insert(k.clone(), text(&mut rng, &k, lines));
                }
            }
        }
        let mut parents = vec![tip];
        if i % 17 == 16 {
            if let Some(s) = side.take() {
                parents.push(s);
            }
        }
        tip = h.commit(&th, &parents, files.clone(), [i as u8; 16], 1_700_000_000_000 + i as i64 * 1000, None);
        if i % 17 == 5 {
            side = Some(tip);
        }
        h.set_branch(&th, "main", tip);
        if i % 3 == 0 {
            let mut f2 = files.clone();
            f2.insert(format!("pub/side-{i}.txt"), b"side branch\n".to_vec());
            let s = h.commit(&th, &[tip], f2, [200 + (i % 50) as u8; 16], 1_700_000_000_500 + i as i64 * 1000, None);
            h.set_branch(&th, "side", s);
        }
        h.derive(&th);
        // Two servers update the index at once.
        let (h1, h2) = (h.hub.clone(), other.hub());
        let id = h.id;
        let (a, b) = std::thread::scope(|s| {
            let a = s.spawn(|| th.rt.block_on(index::update(&h1, id, None)));
            let b = s.spawn(|| other.rt.block_on(index::update(&h2, id, None)));
            (a.join().unwrap().unwrap(), b.join().unwrap().unwrap())
        });
        merges += a.merges + b.merges;
    }
    assert!(merges > 0, "segments were merged");
    let rows: Vec<(String, i64, i64)> = th.rt.block_on(sqlx::query_as("SELECT segments, docs, dead FROM search_shards WHERE project_id = $1 AND kind = 'code'").bind(h.id).fetch_all(&h.hub.db)).unwrap();
    for (segs, docs, dead) in &rows {
        let n = serde_json::from_str::<Vec<index::SegRef>>(segs).unwrap().len();
        assert!(n <= index::MAX_SEGMENTS && (*dead < 64 || dead * 2 <= *docs + 1), "{n} segments, {docs} docs, {dead} dead");
    }
    let words = vocabulary(&h);
    let who: Vec<Viewer> = [admin(), Viewer::default(), viewers(1)[3].1.clone()].to_vec();
    let incremental: Vec<Vec<String>> = who.iter().map(|v| answers(&th, &h, v, &words, 9)).collect();
    rebuild(&th, &h);
    let fresh: Vec<Vec<String>> = who.iter().map(|v| answers(&th, &h, v, &words, 9)).collect();
    assert_eq!(incremental, fresh);
}

/// Row 10: hostile queries are refused or bounded; a pathological regular
/// expression runs in linear time; a page holds a bounded number of lines;
/// the deadline fails a query rather than cutting it.
#[test]
fn search_hostile_inputs_are_bounded() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut files = Files::new();
    files.insert("pub/aaaa.txt".into(), vec![b'a'; 1 << 20]);
    files.insert("pub/lines.txt".into(), "match me\n".repeat(100_000).into_bytes());
    files.insert("pub/big.txt".into(), vec![b'x'; (1 << 20) + 1]);
    files.insert("pub/bin.txt".into(), b"match me\0binary\n".to_vec());
    for i in 0..300 {
        files.insert(format!("pub/many/f{i}.txt"), format!("common word {i}\n").into_bytes());
    }
    let tip = h.commit(&th, &[root_snapshot_id()], files, [1; 16], 1_000, None);
    h.set_branch(&th, "main", tip);
    index(&th, &h);
    let anyone = Viewer::default();
    warm_up(&th, &h, &anyone);
    let a = ask(&th, &h, &anyone);
    let go = |q: S| run(&th, &h, &a, &q);
    let g = |pattern: &str| S::Grep(GrepParams { pattern: pattern.into(), ..Default::default() }, Limits::default());
    // Refused.
    for q in [
        S::Search(SearchParams { q: Some("x ".repeat(9)), ..Default::default() }, Limits::default()),
        S::Search(SearchParams { q: Some("y".repeat(300)), ..Default::default() }, Limits::default()),
        S::Search(SearchParams { q: Some(String::new()), ..Default::default() }, Limits::default()),
        S::Search(SearchParams { q: Some("a".into()), kind: Some("everything".into()), ..Default::default() }, Limits::default()),
        S::Search(SearchParams { q: Some("a".into()), after: Some("nonsense".into()), ..Default::default() }, Limits::default()),
        S::Search(SearchParams { q: Some("a".into()), rev: Some(tip.hex()), ..Default::default() }, Limits::default()),
        S::Search(SearchParams { q: Some("a".into()), path: Some("../etc".into()), ..Default::default() }, Limits::default()),
        g(&"(".repeat(10)),
        g(&"a".repeat(5000)),
        g("(\\w{100}){100}"),
    ] {
        let r = go(q.clone());
        assert!(r[0].starts_with("error 400"), "{q:?}: {r:?}");
    }
    // Linear: (a*)*b over a mebibyte of a's.
    let t = Instant::now();
    let r = go(g("(a*)*b"));
    assert!(r[0].contains("\"files\":[]"), "{r:?}");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    // Bounded lines per file; files over 1 MiB and binary files skipped.
    let r = go(g("match me"));
    let v: Value = serde_json::from_str(&r[0]).unwrap();
    let f = &v["files"][0];
    assert_eq!(f["path"], "pub/lines.txt");
    assert_eq!(f["matches"], 100_000);
    assert_eq!(f["lines"].as_array().unwrap().len(), 1_000);
    assert_eq!(f["lines_truncated"], true);
    assert_eq!(v["files"].as_array().unwrap().len(), 1, "{}", r[0]);
    assert!(!go(g("x{10}"))[0].contains("big.txt"));
    // Candidates beyond the bound: an incomplete answer, the same each time.
    let bounded = Limits { confirm_files: 50, ..Limits::default() };
    let q = S::Search(SearchParams { q: Some("common word".into()), n: Some(100), ..Default::default() }, bounded);
    let r = go(q.clone());
    let v: Value = serde_json::from_str(&r[0]).unwrap();
    assert_eq!(v["complete"], false);
    assert_eq!(v["files"], 50);
    assert_eq!(v["work"], 50);
    assert_eq!(go(q), r);
    // A page of a grep ends at its bound, with a cursor that goes on.
    let pages = go(S::Grep(GrepParams { pattern: "common".into(), n: Some(7), ..Default::default() }, Limits::default()));
    assert_eq!(pages.len(), 40, "pages go on past 40");
    // The deadline fails the query.
    let none = Limits { deadline: Duration::ZERO, ..Limits::default() };
    let r = go(S::Search(SearchParams { q: Some("common".into()), ..Default::default() }, none));
    assert!(r[0].contains("deadline"), "{r:?}");
}

// ---- through the routes, with `vl` -------------------------------------------------

/// Every person of the standard project, over HTTPS: nobody finds,
/// counts or is shown a marker of what they may not see; a secret's
/// content is found by nobody, its name by those who see its folder; a
/// hidden match and no match give the same body; `vl search` prints
/// the same; someone removed from a group loses its folder at once.
/// `api.get`, asked again while the server answers 503 (`deadline`,
/// `indexing`, `warming`: each says "try again"), for at most 120 s, as a
/// client does (BUG-1174: under a loaded machine an answer passed the 2 s
/// deadline and the test read an error as an answer).
fn settled(api: &Api, token: Option<&str>, path: &str) -> Reply {
    let end = Instant::now() + Duration::from_secs(120);
    loop {
        let r = api.get(token, path);
        if r.status != 503 || Instant::now() >= end {
            return r;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn search_routes_serve_each_person_their_part() {
    let th = TestHub::start();
    let p = setup_project(&th);
    let api = th.api();
    let base = format!("/v1/projects/{}/q", p.name);
    let tok = |who: &Person| Some(who.token());
    // The landings index in the background: wait for it.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let r = api.get(tok(&p.admin).as_deref(), &format!("{base}/search?q={PUBLIC_MARK}"));
        if r.status == 200 && r.json()["files"] == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "never indexed: {}", String::from_utf8_lossy(&r.body));
        std::thread::sleep(Duration::from_millis(200));
    }
    let markers = [ROOT_MARK, PUBLIC_MARK, NESTED_MARK, BILL_MARK, PERSON_MARK, ENV_MARK];
    let people: Vec<(&str, Option<String>, Vec<&str>)> = vec![
        ("anyone", None, restricted_markers()),
        ("dev", tok(&p.dev), restricted_markers()),
        ("fin", tok(&p.fin), vec![ROOT_FILE, ROOT_MARK, NESTED_DIR, NESTED_MARK, PERSON_DIR, PERSON_MARK, ENV_MARK]),
        ("carol", tok(&p.carol), vec![ROOT_FILE, ROOT_MARK, BILL_DIR, BILL_MARK, NESTED_DIR, NESTED_MARK, ENV_MARK]),
        ("sec", tok(&p.sec), vec![ROOT_FILE, ROOT_MARK, BILL_DIR, BILL_MARK, PERSON_DIR, PERSON_MARK, ENV_MARK]),
        ("admin", tok(&p.admin), vec![ENV_MARK]),
    ];
    for (who, token, hidden) in &people {
        let t = token.as_deref();
        let mut bodies = Vec::new();
        for m in markers {
            let r = settled(&api, t, &format!("{base}/search?q={m}"));
            assert_eq!(r.status, 200, "{who}: {}", String::from_utf8_lossy(&r.body));
            let found = r.json()["files"].as_u64().unwrap();
            assert_eq!(found == 1, !hidden.contains(&m), "{who}: {m}: {}", String::from_utf8_lossy(&r.body));
            if hidden.contains(&m) {
                // A hidden match and no match: the same answer.
                let none = settled(&api, t, &format!("{base}/search?q=no-such-word-{}", &m[..6]));
                let strip = |b: &[u8]| {
                    let mut v: Value = serde_json::from_slice(b).unwrap();
                    v.as_object_mut().unwrap().remove("query");
                    v
                };
                assert_eq!(strip(&r.body), strip(&none.body), "{who}: {m}");
            } else {
                bodies.push(r.body);
            }
            let g = settled(&api, t, &format!("{base}/grep?pattern={m}"));
            assert_eq!(g.status, 200, "{who}");
            if hidden.contains(&m) {
                assert!(g.json()["files"].as_array().unwrap().is_empty(), "{who}: {m}");
            }
            bodies.push(g.body);
        }
        for q in ["md", "txt", "env", "acme", "notes", "lib", "key"] {
            bodies.push(settled(&api, t, &format!("{base}/search?q={q}&kind=path")).body);
            bodies.push(settled(&api, t, &format!("{base}/grep?pattern=.&path=src")).body);
        }
        let env = settled(&api, t, &format!("{base}/search?q=.env&kind=path")).json();
        let sees = env["results"].as_array().unwrap().iter().any(|r| r["path"] == format!("{BILL_DIR}/.env"));
        assert_eq!(sees, matches!(*who, "fin" | "admin"), "{who}: {env}");
        // What they asked for is echoed; the rest is what they were given.
        let all: Vec<(String, Vec<u8>)> = bodies.into_iter().map(|b| (who.to_string(), without_echo(&String::from_utf8_lossy(&b)).into_bytes())).collect();
        assert_no_marker(&all, hidden, who);
    }
    // No segment holds a secret's content.
    let hub = th.hub();
    let id: i64 = th.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&hub.db)).unwrap();
    let segs: Vec<(String, Vec<u8>)> = segments(&th, &hub, id);
    assert!(!segs.is_empty());
    assert_no_marker(&segs, &[ENV_MARK], "segments");
    // `vl search`, as dev.
    let dir = p.dev.dir("search-clone");
    p.dev.clone_trusting(&th.url(&p.name), &dir, &p.fp);
    let out = p.dev.ok(&dir, &["search", PUBLIC_MARK]);
    assert!(out.contains("src/lib.rs"), "{out}");
    let miss = p.dev.run(&dir, &["search", BILL_MARK]);
    assert_eq!(miss.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&miss.stdout).contains(BILL_MARK) && !String::from_utf8_lossy(&miss.stderr).contains(BILL_DIR));
    let json: Value = serde_json::from_str(p.dev.ok(&dir, &["search", "lib", "--path", "--json"]).trim()).unwrap();
    assert_eq!(json["schema"], "veil.search/1");
    assert!(json["results"].as_array().unwrap().iter().any(|r| r["path"] == "src/lib.rs"), "{json}");
    // Row 9: removed from finance, fin no longer finds billing.
    let fin_finds = || api.get(tok(&p.fin).as_deref(), &format!("{base}/search?q={BILL_MARK}")).json()["files"].as_u64().unwrap();
    assert_eq!(fin_finds(), 1);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    assert_eq!(fin_finds(), 0);
}

// ---- speed -----------------------------------------------------------------------

fn pct(mut v: Vec<Duration>, p: usize) -> Duration {
    v.sort();
    v[(v.len() * p / 100).min(v.len() - 1)]
}

/// Index size, build cost and query times on a generated project of
/// `VEIL_SEARCH_BENCH_FILES` files (default 1,000) of about 4 KiB of code-like
/// text in five folders (anyone on Earth reads two fifths), with
/// `VEIL_SEARCH_BENCH_SNAPSHOTS` (default 100) snapshots of history. Prints the
/// build (time, content and segment bytes), one landing's update, and p50 /
/// p99 per query for an admin and for anyone on Earth.
#[test]
fn search_speed() {
    let n: usize = std::env::var("VEIL_SEARCH_BENCH_FILES").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000);
    let snaps: usize = std::env::var("VEIL_SEARCH_BENCH_SNAPSHOTS").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
    let rounds: usize = std::env::var("VEIL_SEARCH_BENCH_ROUNDS").ok().and_then(|s| s.parse().ok()).unwrap_or(10);
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut rng = Rng::new(77);
    let idents = ["handler", "request", "response", "config", "parse", "render", "buffer", "stream", "token", "cache", "index", "query", "worker", "session", "router"];
    let body = |rng: &mut Rng, i: usize| -> Vec<u8> {
        let mut s = String::new();
        for l in 0..100 {
            let (a, b) = (idents[rng.below(idents.len())], idents[rng.below(idents.len())]);
            s.push_str(&format!("    let {a}_{l} = {b}::new(&{a}, {});  // {i}\n", rng.next() % 100_000));
        }
        s.push_str(&format!("fn unique_symbol_{i}() {{}}\n"));
        s.into_bytes()
    };
    let mut files = Files::new();
    for i in 0..n {
        let dir = ["pub", "pub/sec", "fin", "carol-d", "pub/x"][i % 5];
        files.insert(format!("{dir}/m{}/file_{i}.rs", i % 40), body(&mut rng, i));
    }
    let keys: Vec<String> = files.keys().cloned().collect();
    let t0 = Instant::now();
    let mut tip = root_snapshot_id();
    for s in 0..snaps {
        for _ in 0..1 + rng.below(4) {
            let k = &keys[rng.below(keys.len())];
            files.insert(k.clone(), body(&mut rng, s));
        }
        if s % 10 == 0 {
            files.insert(format!("pub/renamed/r{s}.rs"), b"fn renamed() {}\n".to_vec());
        }
        tip = h.commit(&th, &[tip], files.clone(), [s as u8; 16], 1_700_000_000_000 + s as i64 * 1000, None);
    }
    h.set_branch(&th, "main", tip);
    h.derive(&th);
    println!("search_speed: built {n} files, {snaps} snapshots in {:?}", t0.elapsed());
    let t = Instant::now();
    let st = th.rt.block_on(index::update(&h.hub, h.id, None)).unwrap();
    println!(
        "search_speed: first index: {:?}; {} docs, {} MiB of content, {} segments of {} KiB in all ({:.2} bytes of index per byte of content), {} snapshots walked",
        t.elapsed(),
        st.docs,
        st.content_bytes >> 20,
        st.segments,
        st.segment_bytes >> 10,
        st.segment_bytes as f64 / st.content_bytes.max(1) as f64,
        st.walked
    );
    // One landing of a few files.
    let mut ups = Vec::new();
    for s in 0..5 {
        for _ in 0..3 {
            let k = &keys[rng.below(keys.len())];
            files.insert(k.clone(), body(&mut rng, 10_000 + s));
        }
        tip = h.commit(&th, &[tip], files.clone(), [200 + s as u8; 16], 1_800_000_000_000 + s as i64, None);
        h.set_branch(&th, "main", tip);
        h.derive(&th);
        let t = Instant::now();
        th.rt.block_on(index::update(&h.hub, h.id, Some(vec!["main".into()]))).unwrap();
        ups.push(t.elapsed());
    }
    println!("search_speed: one landing of 3 files: p50 {:?}, max {:?}", pct(ups.clone(), 50), pct(ups, 100));
    for (who, viewer) in [("admin", admin()), ("anyone on Earth", Viewer::default())] {
        warm_up(&th, &h, &viewer);
        let a = ask(&th, &h, &viewer);
        let hub = h.hub.clone();
        let old = th.rt.block_on(veil_server::sync::projected(&hub, &h.project(&th), &viewer, h.order[snaps / 2])).map(|p| p.hex());
        let queries: Vec<(&str, S)> = vec![
            ("code: common word", S::Search(SearchParams { q: Some("handler".into()), ..Default::default() }, Limits::default())),
            ("code: two words", S::Search(SearchParams { q: Some("buffer stream".into()), ..Default::default() }, Limits::default())),
            ("code: rare word", S::Search(SearchParams { q: Some(format!("unique_symbol_{}", n / 2)), ..Default::default() }, Limits::default())),
            ("path search", S::Search(SearchParams { q: Some("file_1".into()), kind: Some("path".into()), ..Default::default() }, Limits::default())),
            ("grep at the tip, rare", S::Grep(GrepParams { pattern: "unique_symbol_7\\b".into(), ..Default::default() }, Limits::default())),
            ("grep at the tip, a page of 100", S::Grep(GrepParams { pattern: "cache::new".into(), ..Default::default() }, Limits::default())),
        ];
        let mut queries = queries;
        if let Ok(old) = old {
            queries.push(("grep scan at an old revision, rare", S::Grep(GrepParams { pattern: "unique_symbol_7\\b".into(), rev: Some(old), ..Default::default() }, Limits::default())));
        }
        for (name, q) in queries {
            let mut times = Vec::new();
            let mut last = Value::Null;
            for round in 0..rounds + 1 {
                let t = Instant::now();
                let v = th.rt.block_on(async {
                    match &q {
                        S::Search(p, l) => search::search(&hub, &a, p.clone(), *l).await,
                        S::Grep(p, l) => search::grep(&hub, &a, p.clone(), *l).await,
                    }
                });
                let v = v.unwrap_or_else(|e| panic!("{name}: {e:?}"));
                if round > 0 {
                    times.push(t.elapsed());
                }
                last = v;
            }
            let hits = last["results"].as_array().or(last["files"].as_array()).map(|a| a.len()).unwrap_or(0);
            println!("search_speed: {who}: {name}: p50 {:?}, p99 {:?}, work {}, {hits} hits shown", pct(times.clone(), 50), pct(times, 99), last["work"]);
        }
    }
}

// ---- S15 cycle 1 review (BUG-1230..) ------------------------------------------------

/// A grep's deadline is checked only between files, and one file's regular
/// expression search cannot be stopped: a short pattern the size limits
/// accept (a counted repetition of a class, with no literal to skip by)
/// takes seconds per mebibyte of line, so one request by anyone on Earth
/// holds a blocking thread far past its 2 s deadline, at a branch tip
/// (through the index) and at an old revision (a scan) alike.
#[test]
fn bug_1230_grep_pattern_cost_passes_the_deadline() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    // A mebibyte on one line (as a minified bundle is), no newline.
    let mut x: u64 = 12345;
    let line: Vec<u8> = (0..(1usize << 20) - 1)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b"abcdefghijklmnopqrstuvwxyz0123456789 "[(x % 37) as usize]
        })
        .collect();
    let files = Files::from([("pub/bundle.min.js".to_string(), line)]);
    let tip = h.commit(&th, &[root_snapshot_id()], files, [7; 16], 1_000, None);
    h.set_branch(&th, "main", tip);
    index(&th, &h);
    let anyone = Viewer::default();
    warm_up(&th, &h, &anyone);
    let a = ask(&th, &h, &anyone);
    let projected = projections(&th, &h, &a.project, &anyone)[&tip].hex();
    // 41 bytes; compiles under the 1 MiB limit.
    let pattern = r"(?-u)[\x00-\xff]*[a-f][\x00-\xff]{1000}[A-Z]";
    for rev in [None, Some(projected)] {
        let t = Instant::now();
        let r = th.rt.block_on(search::grep(&h.hub, &a, GrepParams { pattern: pattern.into(), rev: rev.clone(), ..Default::default() }, Limits::default()));
        let took = t.elapsed();
        assert!(!norm(r).starts_with("error 400"), "the pattern is accepted");
        assert!(took < Duration::from_secs(5), "rev {rev:?}: a grep with a 2 s deadline took {took:?}");
    }
}

/// The names index holds only the branches an update was asked for (a
/// landing's, or the one a query names): a branch that has not landed
/// since the index began (every branch of a project when the server is
/// upgraded) is never walked, so a path only its history held is not
/// found by a name search of "every path the project's history held".
/// The same root: an update that did not run (a restart, an error, which
/// is only logged) is resumed by nothing but that branch's next landing,
/// so its index stays behind its tip (S12 resumes derivation; BUG-982).
#[test]
fn bug_1231_index_follows_only_the_branches_asked_for() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let base = h.commit(&th, &[root_snapshot_id()], Files::from([("pub/common.txt".to_string(), b"hello\n".to_vec())]), [1; 16], 1_000, None);
    let feature = h.commit(
        &th,
        &[base],
        Files::from([("pub/common.txt".to_string(), b"hello\n".to_vec()), ("pub/featurexyzzy.txt".to_string(), b"new\n".to_vec())]),
        [2; 16],
        2_000,
        None,
    );
    h.set_branch(&th, "main", base);
    h.set_branch(&th, "feature", feature);
    h.derive(&th);
    let anyone = Viewer::default();
    warm_up(&th, &h, &anyone);
    let a = ask(&th, &h, &anyone);
    // What the first query of main does (`search::shards` → `index::landed`).
    th.rt.block_on(index::update(&h.hub, h.id, Some(vec!["main".to_string()]))).unwrap();
    let names = run(&th, &h, &a, &S::Search(SearchParams { q: Some("featurexyzzy".into()), kind: Some("path".into()), ..Default::default() }, Limits::default()));
    let v: Value = serde_json::from_str(&names[0]).unwrap_or_else(|_| panic!("{names:?}"));
    // main moves with no update run for it (one that failed or was cut).
    let next = h.commit(&th, &[base], Files::from([("pub/common.txt".to_string(), b"hello again\n".to_vec())]), [3; 16], 3_000, None);
    h.set_branch(&th, "main", next);
    h.derive(&th);
    warm_up(&th, &h, &anyone);
    let want = projections(&th, &h, &a.project, &anyone)[&next].hex();
    let mut covered = String::new();
    let mut first = None;
    for _ in 0..25 {
        let r = run(&th, &h, &a, &S::Search(SearchParams { q: Some("hello".into()), ..Default::default() }, Limits::default()));
        let v: Value = serde_json::from_str(&r[0]).unwrap_or_else(|_| panic!("{r:?}"));
        first.get_or_insert(v.clone());
        covered = v["snapshot_id"].as_str().unwrap_or("").to_string();
        if covered == want {
            assert_eq!(v["behind"], false, "{v}");
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(covered, want, "main's index stays behind its tip");
    assert_eq!(v["files"], 1, "a path only feature's history held: {names:?}");
    // The first answer after the move came from the old tip, and said so.
    let first = first.unwrap();
    assert_eq!((first["behind"].clone(), first["tip_id"].as_str()), (Value::Bool(true), Some(want.as_str())), "{first}");
    // A landing the viewer cannot see moves nothing they see: not behind.
    let hidden = h.commit(
        &th,
        &[next],
        Files::from([("pub/common.txt".to_string(), b"hello again\n".to_vec()), ("fin/secret-plan.txt".to_string(), b"hidden\n".to_vec())]),
        [4; 16],
        4_000,
        None,
    );
    h.set_branch(&th, "main", hidden);
    h.derive(&th);
    warm_up(&th, &h, &anyone);
    let r = run(&th, &h, &a, &S::Search(SearchParams { q: Some("hello".into()), ..Default::default() }, Limits::default()));
    let v: Value = serde_json::from_str(&r[0]).unwrap();
    assert_eq!((v["behind"].clone(), v["snapshot_id"].as_str()), (Value::Bool(false), Some(want.as_str())), "{v}");
}

/// BUG-1231: at start-up, a project whose index is behind (or was never
/// built: a project from before the index) is brought up to date.
#[test]
fn search_index_resumes_at_start() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let tip = h.commit(&th, &[root_snapshot_id()], Files::from([("pub/a.txt".to_string(), b"resumed\n".to_vec())]), [1; 16], 1_000, None);
    h.set_branch(&th, "main", tip);
    let side = h.commit(&th, &[tip], Files::from([("pub/b.txt".to_string(), b"side\n".to_vec())]), [2; 16], 2_000, None);
    h.set_branch(&th, "side", side);
    h.derive(&th);
    th.rt.block_on(index::resume(h.hub.clone(), Some(h.id)));
    let heads: BTreeSet<(String, String, String)> =
        th.rt.block_on(sqlx::query_as("SELECT kind, branch, snapshot FROM search_heads WHERE project_id = $1 AND kind <> 'names'").bind(h.id).fetch_all(&h.hub.db)).unwrap().into_iter().collect();
    let want: BTreeSet<(String, String, String)> = [("code", "main", tip), ("code", "side", side), ("walk", "main", tip), ("walk", "side", side)]
        .into_iter()
        .map(|(k, b, s)| (k.to_string(), b.to_string(), s.hex()))
        .collect();
    assert_eq!(heads, want);
}

/// The bounds and the deadline are checked only in the loop that reads
/// candidates; before it, a query loads every segment of the viewer's
/// shards and collects and sorts every live document holding the words'
/// trigrams (every matching name; a grep's every candidate after its
/// cursor, cheaper only while they come sorted). So one request's time and memory grow with the project, not with the
/// 4,000 candidates (or a grep page) it reads, and no deadline stops it.
/// Anyone on Earth can ask it of a large public project.
#[test]
fn bug_1232_candidates_are_collected_past_the_bounds() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    // 300,000 small public files (one shared blob: cheap to store and index).
    let mut files = Files::new();
    for d in 0..150 {
        for f in 0..2_000 {
            files.insert(format!("pub/d{d}/f{f}.txt"), b"common word\n".to_vec());
        }
    }
    let tip = h.commit(&th, &[root_snapshot_id()], files, [9; 16], 1_000, None);
    h.set_branch(&th, "main", tip);
    index(&th, &h);
    let anyone = Viewer::default();
    warm_up(&th, &h, &anyone);
    let a = ask(&th, &h, &anyone);
    let deadline = Duration::from_millis(300);
    let limits = Limits { deadline, ..Limits::default() };
    let queries = [
        // Words of under three bytes narrow nothing: every live document is
        // a candidate for each.
        S::Search(SearchParams { q: Some("c o m n w r d on".into()), ..Default::default() }, limits),
        S::Search(SearchParams { q: Some("txt".into()), kind: Some("path".into()), ..Default::default() }, limits),
    ];
    // Once to load the segments into the cache, then measured.
    let mut took = Vec::new();
    for q in &queries {
        let hub = h.hub.clone();
        let call = || {
            th.rt.block_on(async {
                match q {
                    S::Search(p, l) => search::search(&hub, &a, p.clone(), *l).await,
                    S::Grep(p, l) => search::grep(&hub, &a, p.clone(), *l).await,
                }
            })
        };
        let warm = norm(call());
        assert!(!warm.starts_with("error") || warm.contains("deadline"), "{warm}");
        let t = Instant::now();
        let r = norm(call());
        assert!(!r.starts_with("error") || r.contains("deadline"), "{r}");
        took.push((t.elapsed(), r.chars().take(120).collect::<String>()));
    }
    println!("bug_1232: {took:?}");
    for (t, r) in &took {
        assert!(*t < deadline + Duration::from_millis(700), "a query with a {deadline:?} deadline took {t:?}: {r}\n{took:?}");
    }
}

// ---- S15 cycle 2 review (BUG-1233..) ------------------------------------------------

/// A name search's answer is current (`behind: false`) only once its names
/// are: the branch's walked tip is read after the names shards, in its own
/// statement, so an update that commits between the two reads gives an
/// answer from the shards before it that says it covers the new tip. Each
/// round adds a name and asks for it from six searches at once while the
/// update runs; the first answer each gets that says it is current must
/// hold the name.
#[test]
fn bug_1233_a_name_search_is_current_only_with_its_names() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut files = Files::from([("pub/base.txt".to_string(), b"base\n".to_vec())]);
    let mut tip = h.commit(&th, &[root_snapshot_id()], files.clone(), [1; 16], 1_000, None);
    h.set_branch(&th, "main", tip);
    index(&th, &h);
    let anyone = Viewer::default();
    let a = ask(&th, &h, &anyone);
    let mut stale = Vec::new();
    let mut samples = 0;
    for i in 0..40u8 {
        let word = format!("racename{i:03}q");
        files.insert(format!("pub/{word}.txt"), b"x\n".to_vec());
        tip = h.commit(&th, &[tip], files.clone(), [10 + i; 16], 2_000 + i64::from(i), None);
        h.set_branch(&th, "main", tip);
        h.derive(&th);
        let want = th.rt.block_on(query::resolve(&h.hub, &a, "main", Instant::now() + Duration::from_secs(60))).unwrap().hex();
        let got: Vec<Option<String>> = th.rt.block_on(async {
            let mut tasks = Vec::new();
            for _ in 0..6 {
                let (hub, a, word, want) = (h.hub.clone(), a.clone(), word.clone(), want.clone());
                tasks.push(tokio::spawn(async move {
                    let give_up = Instant::now() + Duration::from_secs(60);
                    loop {
                        let p = SearchParams { q: Some(word.clone()), kind: Some("path".into()), ..Default::default() };
                        if let Ok(v) = search::search(&hub, &a, p, Limits::default()).await {
                            if v["behind"] == false && v["tip_id"].as_str() == Some(want.as_str()) {
                                return (v["files"] != 1).then(|| v.to_string());
                            }
                        }
                        assert!(Instant::now() < give_up, "{word}: never caught up");
                    }
                }));
            }
            let mut out = Vec::new();
            for t in tasks {
                out.push(t.await.unwrap());
            }
            out
        });
        samples += got.len();
        stale.extend(got.into_iter().flatten());
    }
    assert!(stale.is_empty(), "{} of {samples} answers said they were current without the tip's names: {:?}", stale.len(), &stale[..stale.len().min(3)]);
}

/// Guarantee 1 of cycle 2: a word's document count (saturated at
/// `DF_CAP`), the ranking built on it, and the long lines a grep skips are
/// functions of the viewer's documents alone: the same answers from a
/// project indexed landing by landing (several segments, dead documents)
/// and from one holding as well hidden files full of the same words and
/// long lines, indexed at once (one layout, another count if hidden ones
/// were counted).
#[test]
fn search_counts_and_long_lines_are_per_viewer() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut a = Hist::new(&th, &policy_text, &bindings);
    let mut b = Hist::new(&th, &policy_text, &bindings);
    let root = root_snapshot_id();
    let (mut ta, mut tb) = (root, root);
    // One line longer than the costly pattern below may search (16 KiB).
    let mut long = b"handler zeta ".to_vec();
    long.extend(std::iter::repeat_n(b'b', 20_000));
    long.extend(b"\nshort line\n");
    let mut files = Files::from([("fin/base.txt".to_string(), b"alpha hidden in both\n".to_vec())]);
    let mut hidden = Files::new();
    for i in 0..6u8 {
        for k in 0..2_000usize {
            let n = usize::from(i) * 2_000 + k;
            // `zeta` in 9,500 visible files (under the cap), 11,900 with
            // the hidden ones; `handler` in all (past it either way).
            let body = format!("handler {}{}\n", "x ".repeat(n % 7), if n < 9_500 { "zeta" } else { "" });
            files.insert(format!("pub/d{i}/f{k}.txt"), body.into_bytes());
        }
        // Edits: dead documents in the older segments of `a`.
        for k in 0..300usize {
            files.insert(format!("pub/d0/f{k}.txt"), format!("handler zeta edit {i}\n").into_bytes());
        }
        files.insert(format!("pub/long/l{i}.min.js"), long.clone());
        for k in 0..400 {
            hidden.insert(format!("fin/d{i}/h{k}.txt"), b"handler zeta\n".to_vec());
        }
        hidden.insert(format!("fin/long/h{i}.min.js"), long.clone());
        let ts = 1_700_000_000_000 + i64::from(i) * 1000;
        ta = a.commit(&th, &[ta], files.clone(), [i + 1; 16], ts, None);
        a.set_branch(&th, "main", ta);
        index(&th, &a);
        let mut fb = files.clone();
        fb.extend(hidden.clone());
        tb = b.commit(&th, &[tb], fb, [i + 1; 16], ts, None);
    }
    b.set_branch(&th, "main", tb);
    index(&th, &b);
    let segs = |h: &Hist| -> usize {
        th.rt.block_on(async {
            let rows: Vec<String> = sqlx::query_scalar("SELECT segments FROM search_shards WHERE project_id = $1 AND kind = 'code'").bind(h.id).fetch_all(&h.hub.db).await.unwrap();
            rows.iter().map(|r| serde_json::from_str::<Vec<index::SegRef>>(r).unwrap().len()).sum()
        })
    };
    println!("code segments: a {}, b {}", segs(&a), segs(&b));
    let anyone = Viewer::default();
    let (aa, ab) = (ask(&th, &a, &anyone), ask(&th, &b, &anyone));
    warm_up(&th, &a, &anyone);
    warm_up(&th, &b, &anyone);
    let tip = th.rt.block_on(query::resolve(&a.hub, &aa, "main", Instant::now() + Duration::from_secs(60))).unwrap();
    let slow = Limits { deadline: Duration::from_secs(120), ..Limits::default() };
    let costly = r"(?-u)[\x00-\xff]*[a-f][\x00-\xff]{1000}[A-Z]";
    let mut qs = Vec::new();
    for q in ["zeta", "handler", "handler zeta", "edit zeta"] {
        qs.push(S::Search(SearchParams { q: Some(q.into()), n: Some(50), ..Default::default() }, slow));
    }
    for rev in ["main".to_string(), tip.hex()] {
        qs.push(S::Grep(GrepParams { pattern: costly.into(), rev: Some(rev.clone()), n: Some(1_000), ..Default::default() }, slow));
        qs.push(S::Grep(GrepParams { pattern: "short line".into(), rev: Some(rev), ..Default::default() }, slow));
    }
    for q in &qs {
        let (x, y) = (run(&th, &a, &aa, q), run(&th, &b, &ab, q));
        assert!(!x[0].starts_with("error"), "{q:?}: {x:?}");
        assert_eq!(x, y, "{q:?}");
        assert!(!x.iter().any(|r| r.contains("fin/")), "{q:?}: {x:?}");
        if let S::Grep(p, _) = q {
            if p.pattern == costly {
                let v: Value = serde_json::from_str(&x[0]).unwrap();
                let skipped: Vec<(String, u64)> = v["files"].as_array().unwrap().iter().map(|f| (f["path"].as_str().unwrap().to_string(), f["long_lines_skipped"].as_u64().unwrap_or(0))).collect();
                let want: Vec<(String, u64)> = (0..6).map(|i| (format!("pub/long/l{i}.min.js"), 1)).collect();
                assert_eq!(skipped, want, "{q:?}");
            }
        }
    }
}

/// Guarantee 2 of cycle 2: over 300,000 public files written in three
/// landings (several segments), every route stays within its deadline:
/// a grep whose trigrams every file holds and whose expression matches
/// none (through the index and by a scan), a grep from a cursor near the
/// end, searches whose language filter rejects every candidate, and a
/// folder at the end of the tree.
#[test]
fn search_every_route_is_bounded_at_scale() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut files = Files::new();
    let mut tip = root_snapshot_id();
    for part in 0..3 {
        for d in (part * 50)..(part * 50 + 50) {
            for f in 0..2_000 {
                files.insert(format!("pub/d{d}/f{f}.txt"), b"common word\n".to_vec());
            }
        }
        tip = h.commit(&th, &[tip], files.clone(), [9 + part as u8; 16], 1_000 + part as i64, None);
        h.set_branch(&th, "main", tip);
        index(&th, &h);
    }
    let anyone = Viewer::default();
    warm_up(&th, &h, &anyone);
    let a = ask(&th, &h, &anyone);
    let id = th.rt.block_on(query::resolve(&h.hub, &a, "main", Instant::now() + Duration::from_secs(60))).unwrap().hex();
    let deadline = Duration::from_millis(300);
    let limits = Limits { deadline, ..Limits::default() };
    let grep = |pattern: &str, rev: &str, after: Option<&str>| S::Grep(GrepParams { pattern: pattern.into(), rev: Some(rev.into()), after: after.map(str::to_string), ..Default::default() }, limits);
    let queries = [
        grep(r"common\d word", "main", None),
        grep(r"common\d word", &id, None),
        grep("common", "main", Some("pub/d149/f1990.txt")),
        grep("common", &id, Some("pub/d149/f1990.txt")),
        S::Search(SearchParams { q: Some("common".into()), lang: Some("rust".into()), ..Default::default() }, limits),
        S::Search(SearchParams { q: Some("txt".into()), kind: Some("path".into()), lang: Some("rust".into()), ..Default::default() }, limits),
        S::Search(SearchParams { q: Some("common word".into()), path: Some("pub/d149".into()), ..Default::default() }, limits),
    ];
    let mut took = Vec::new();
    for q in &queries {
        let hub = h.hub.clone();
        let call = || {
            th.rt.block_on(async {
                match q {
                    S::Search(p, l) => search::search(&hub, &a, p.clone(), *l).await,
                    S::Grep(p, l) => search::grep(&hub, &a, p.clone(), *l).await,
                }
            })
        };
        let warm = norm(call());
        assert!(!warm.starts_with("error") || warm.contains("deadline"), "{warm}");
        let t = Instant::now();
        let r = norm(call());
        assert!(!r.starts_with("error") || r.contains("deadline"), "{r}");
        took.push((t.elapsed(), r.chars().take(160).collect::<String>()));
    }
    println!("every route: {took:#?}");
    for (t, r) in &took {
        assert!(*t < deadline + Duration::from_millis(700), "a query with a {deadline:?} deadline took {t:?}: {r}");
    }
}

/// Guarantee 3 of cycle 2: an update asked for one branch also brings up
/// to date a branch whose update was cut (its names walk behind its tip)
/// and, after a policy change, every branch built under the old one; the
/// answers then equal an index built from nothing.
#[test]
fn search_index_catches_up_every_branch() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let base = h.commit(&th, &[root_snapshot_id()], Files::from([("pub/deep/a.txt".to_string(), b"alpha\n".to_vec())]), [1; 16], 1_000, None);
    h.set_branch(&th, "main", base);
    let side = h.commit(
        &th,
        &[base],
        Files::from([("pub/deep/a.txt".to_string(), b"alpha\n".to_vec()), ("pub/deep/sidewalkq.txt".to_string(), b"beta\n".to_vec())]),
        [2; 16],
        2_000,
        None,
    );
    h.set_branch(&th, "side", side);
    index(&th, &h);
    let heads = || -> BTreeSet<(String, String, String, String)> {
        th.rt.block_on(sqlx::query_as("SELECT kind, branch, snapshot, lines FROM search_heads WHERE project_id = $1").bind(h.id).fetch_all(&h.hub.db)).unwrap().into_iter().collect()
    };
    // A cut update of side: its walk recorded nothing.
    th.rt.block_on(sqlx::query("DELETE FROM search_heads WHERE project_id = $1 AND kind = 'walk' AND branch = 'side'").bind(h.id).execute(&h.hub.db)).unwrap();
    th.rt.block_on(index::update(&h.hub, h.id, Some(vec!["main".to_string()]))).unwrap();
    assert!(heads().iter().any(|(k, b, s, _)| k == "walk" && b == "side" && *s == side.hex()), "{:?}", heads());
    // A line below pub/: every shard of pub/ is under new keys.
    let moved = format!("{policy_text}pub/deep/ security\n");
    th.rt.block_on(async {
        again(|| sqlx::query("UPDATE projects SET policy_text = $1, policy_version = 2 WHERE id = $2").bind(&moved).bind(h.id).execute(&h.hub.db)).await;
    });
    th.rt.block_on(index::update(&h.hub, h.id, Some(vec!["main".to_string()]))).unwrap();
    let lines: BTreeSet<String> = heads().into_iter().filter(|(k, ..)| k != "walk").map(|(.., l)| l).collect();
    assert_eq!(lines.len(), 1, "every head under one policy: {:?}", heads());
    let sec = viewers(1)[2].1.clone();
    let side_answers = |h: &Hist| -> Vec<String> {
        let a = Ask { project: h.project(&th), ..ask(&th, h, &sec) };
        warm_up(&th, h, &sec);
        ["alpha", "beta", "sidewalkq"]
            .iter()
            .flat_map(|w| {
                [None, Some("path".to_string())].into_iter().flat_map(|kind| {
                    run(&th, h, &a, &S::Search(SearchParams { q: Some(w.to_string()), rev: Some("side".into()), kind, ..Default::default() }, Limits::default()))
                })
            })
            .collect()
    };
    let caught_up = side_answers(&h);
    assert!(caught_up.iter().all(|r| !r.starts_with("error")), "{caught_up:?}");
    assert!(caught_up.iter().any(|r| r.contains("pub/deep/sidewalkq.txt")), "{caught_up:?}");
    rebuild(&th, &h);
    assert_eq!(caught_up, side_answers(&h));
}
