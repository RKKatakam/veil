//! Derived history data (milestone S12; phase-3 design §3.1–§3.4 and the
//! threat review, §6). Most histories here are written straight into the
//! store and the database, as committed history (the deriver reads nothing
//! else); `derived_on_landing` goes through `vl` and the push route.
//!
//! The central check is **projection equivalence** (§6, row 1): for each
//! viewer, the derived data of the real project, read through what that
//! viewer may see, answers exactly like the derived data of a copy of the
//! project built only from their projected history (`sync::projected`, what
//! the server gives them), read by its admin. Nothing of a hidden folder
//! (names, counts, sources of copies) may make the two differ.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use veil_core::{
    hub::{access::View, project::Projector},
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEntry},
    ChangeId, ObjectId,
};
use veil_server::{
    derive::{self, changes::Changed, view::Reader},
    perm::{Binding, Project as PermProject, Viewer},
    sync::{self, root_snapshot_id},
    Hub,
};

use crate::support::*;

/// A pinned, seedable generator (no dependency): `VEIL_DERIVE_SEED` picks
/// the first seed.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    pub fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

fn seeds(default: &[u64]) -> Vec<u64> {
    match std::env::var("VEIL_DERIVE_SEED").ok().and_then(|s| s.parse::<u64>().ok()) {
        Some(s) => vec![s],
        None => default.to_vec(),
    }
}

/// A write of the test's own, run again on a retryable error: YugabyteDB
/// reports concurrent tests' inserts conflicting as deadlocks (`40P01`).
pub async fn again<T, F, Fut>(f: F) -> T
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match f().await {
            Ok(v) => return v,
            Err(e) => {
                let e = veil_server::error::Error::from(e);
                assert!(e.is_retryable() && Instant::now() < deadline, "{e:?}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

pub type Files = BTreeMap<String, Vec<u8>>;

/// A project whose committed history the test writes itself.
pub struct Hist {
    pub hub: Arc<Hub>,
    pub id: i64,
    pub name: String,
    pub files: HashMap<ObjectId, Files>,
    pub parents: HashMap<ObjectId, Vec<ObjectId>>,
    /// Every snapshot, in the order written (parents first).
    pub order: Vec<ObjectId>,
    pub branches: BTreeMap<String, ObjectId>,
    /// Objects written already.
    pub stored: HashSet<ObjectId>,
}

/// Encode `files` as trees; every object goes to `out`. A path ending in
/// `/` is an empty folder.
fn build_tree(files: &Files, out: &mut Vec<(ObjectId, Vec<u8>)>) -> ObjectId {
    let mut here: BTreeMap<String, TreeEntry> = BTreeMap::new();
    let mut sub: BTreeMap<String, Files> = BTreeMap::new();
    for (p, c) in files {
        if p.is_empty() {
            // The folder itself (it was named `…/`).
            continue;
        }
        match p.split_once('/') {
            Some((d, rest)) => {
                sub.entry(d.to_string()).or_default().insert(rest.to_string(), c.clone());
            }
            None => {
                let raw = Object::Blob(c.clone()).encode();
                let id = ObjectId::hash(&raw);
                out.push((id, raw));
                here.insert(p.clone(), entry(p, EntryKind::File, id, c.len() as u64));
            }
        }
    }
    for (d, m) in sub {
        let id = build_tree(&m, out);
        here.insert(d.clone(), entry(&d, EntryKind::Dir, id, 0));
    }
    let raw = Object::Tree(Tree {
        entries: here.into_values().collect(),
    })
    .encode();
    let id = ObjectId::hash(&raw);
    out.push((id, raw));
    id
}

fn entry(name: &str, kind: EntryKind, id: ObjectId, size: u64) -> TreeEntry {
    TreeEntry {
        name: name.to_string(),
        kind,
        id,
        size,
        executable: false,
        visibility: Default::default(),
        fallback: None,
    }
}

impl Hist {
    /// A new project with `policy` (its accepted `.veilpolicy`) and the
    /// names' `bindings`.
    pub fn new(th: &TestHub, policy: &str, bindings: &BTreeMap<String, Binding>) -> Hist {
        let hub = th.hub();
        let name = unique("derived");
        let id = th.rt.block_on(async {
            let person: i64 = again(|| sqlx::query_scalar("INSERT INTO people (name, created_at) VALUES ($1, 0) RETURNING id")
                .bind(unique("gen"))
                .fetch_one(&hub.db)).await;
            again(|| sqlx::query_scalar(
                "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
                 VALUES ($1, $2, 0, 'main', $3, $4, 1) RETURNING id",
            )
            .bind(&name)
            .bind(person)
            .bind(policy)
            .bind(serde_json::to_string(bindings).unwrap())
            .fetch_one(&hub.db)).await
        });
        let root = root_snapshot_id();
        Hist {
            hub,
            id,
            name,
            files: HashMap::from([(root, Files::new())]),
            parents: HashMap::from([(root, Vec::new())]),
            order: Vec::new(),
            branches: BTreeMap::new(),
            stored: HashSet::new(),
        }
    }

    pub fn project(&self, th: &TestHub) -> PermProject {
        th.rt.block_on(async {
            let mut c = self.hub.db.acquire().await.unwrap();
            veil_server::perm::load_project(&mut c, &self.name).await.unwrap().unwrap()
        })
    }

    /// Write a snapshot with `parents` and `files`: its objects, then its
    /// row in `snapshots` (committed history).
    pub fn commit(&mut self, th: &TestHub, parents: &[ObjectId], files: Files, change: [u8; 16], timestamp: i64, embargo: Option<&str>) -> ObjectId {
        let mut objects = Vec::new();
        let tree = build_tree(&files, &mut objects);
        let s = Snapshot {
            parents: parents.to_vec(),
            change_id: ChangeId(change),
            tree,
            description: Text::Plain(format!("change at {timestamp}")),
            author: "gen".into(),
            timestamp,
            predecessors: vec![],
            conflicts: vec![],
            cloak: None,
            embargo: embargo.map(str::to_string),
            signature: None,
        };
        let raw = Object::Snapshot(s).encode();
        let id = ObjectId::hash(&raw);
        objects.push((id, raw));
        self.put(th, objects);
        th.rt.block_on(async {
            again(|| sqlx::query("INSERT INTO snapshots (project_id, id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(self.id)
                .bind(id.hex())
                .execute(&self.hub.db)).await;
        });
        self.files.insert(id, files);
        self.parents.insert(id, parents.to_vec());
        self.order.push(id);
        id
    }

    pub fn put(&mut self, th: &TestHub, mut objects: Vec<(ObjectId, Vec<u8>)>) {
        // Content-addressed: one write per distinct object.
        objects.retain(|o| self.stored.insert(o.0));
        let (hub, project) = (self.hub.clone(), self.id);
        th.rt.block_on(async move {
            let mut set = tokio::task::JoinSet::new();
            let mut it = objects.into_iter();
            loop {
                while set.len() < 32 {
                    let Some((id, raw)) = it.next() else { break };
                    let h = hub.clone();
                    set.spawn(async move { h.objects.put(project, &id, raw.into()).await.unwrap() });
                }
                if set.join_next().await.is_none() {
                    break;
                }
            }
        });
    }

    pub fn set_branch(&mut self, th: &TestHub, name: &str, tip: ObjectId) {
        th.rt.block_on(async {
            again(|| sqlx::query(
                "INSERT INTO branches (project_id, name, target) VALUES ($1, $2, $3) \
                 ON CONFLICT (project_id, name) DO UPDATE SET target = EXCLUDED.target",
            )
            .bind(self.id)
            .bind(name)
            .bind(tip.hex())
            .execute(&self.hub.db)).await;
        });
        self.branches.insert(name.to_string(), tip);
    }

    pub fn derive(&self, th: &TestHub) -> derive::Stats {
        th.rt.block_on(derive::catch_up(&self.hub, self.id, derive::Scope::All)).unwrap()
    }

    /// Every derived row of the project, and every changed-paths object.
    pub fn state(&self, th: &TestHub) -> Vec<String> {
        let (hub, id) = (self.hub.clone(), self.id);
        th.rt.block_on(async move {
            let mut out: Vec<String> = Vec::new();
            type Row = (String, i64, i64, String, String, i32, String, Option<String>);
            let g: Vec<Row> = sqlx::query_as(
                "SELECT snapshot, generation, depth, parents, change_id, flags, skip, changed FROM graph WHERE project_id = $1",
            )
            .bind(id)
            .fetch_all(&hub.db)
            .await
            .unwrap();
            for r in g {
                if let Some(c) = &r.7 {
                    if let Ok(oid) = ObjectId::from_hex(c) {
                        let raw = hub.objects.get(id, &oid).await.unwrap().expect("changed-paths object stored");
                        out.push(format!("object {c} {}", String::from_utf8_lossy(&raw)));
                    }
                }
                out.push(format!("graph {r:?}"));
            }
            let f: Vec<(String, i64, String)> = sqlx::query_as("SELECT path_key, depth, snapshot FROM file_history WHERE project_id = $1")
                .bind(id)
                .fetch_all(&hub.db)
                .await
                .unwrap();
            out.extend(f.iter().map(|r| format!("history {r:?}")));
            let l: Vec<(String, i64, String)> = sqlx::query_as("SELECT line_key, generation, snapshot FROM rule_history WHERE project_id = $1")
                .bind(id)
                .fetch_all(&hub.db)
                .await
                .unwrap();
            out.extend(l.iter().map(|r| format!("rule {r:?}")));
            let k: Vec<(String, bool)> = sqlx::query_as("SELECT line_key, ready FROM rule_lines WHERE project_id = $1")
                .bind(id)
                .fetch_all(&hub.db)
                .await
                .unwrap();
            out.extend(k.iter().map(|r| format!("lines {r:?}")));
            out.sort();
            out
        })
    }
}

// ---- the generator ---------------------------------------------------------------

/// Folders of the generated projects, with the access lines below.
const DIRS: &[&str] = &["pub", "pub/sec", "pub/deep", "fin", "carol-d", ""];
const GROUP_DEVS: i64 = 900_001;
const GROUP_SEC: i64 = 900_002;
const GROUP_FIN: i64 = 900_003;

/// The policy and bindings of a generated project; `carol` is a person id.
fn policy(carol: i64) -> (String, BTreeMap<String, Binding>) {
    let text = "pub/ public devs\npub/sec/ security\nfin/ finance\ncarol-d/ carol\n".to_string();
    let b = BTreeMap::from([
        ("devs".to_string(), Binding::Group(GROUP_DEVS)),
        ("security".to_string(), Binding::Group(GROUP_SEC)),
        ("finance".to_string(), Binding::Group(GROUP_FIN)),
        ("carol".to_string(), Binding::Person(carol)),
    ]);
    (text, b)
}

fn viewers(carol: i64) -> Vec<(&'static str, Viewer)> {
    let v = |person: i64, groups: &[i64]| Viewer {
        person: Some(person),
        admin: false,
        groups: groups.iter().copied().collect(),
    };
    vec![
        ("anyone on Earth", Viewer::default()),
        ("a dev", v(800_001, &[GROUP_DEVS])),
        ("security", v(800_002, &[GROUP_SEC])),
        ("finance", v(800_003, &[GROUP_FIN])),
        ("carol", v(carol, &[])),
        ("finance and security", v(800_004, &[GROUP_FIN, GROUP_SEC])),
    ]
}

fn text(rng: &mut Rng, tag: &str, n: usize) -> Vec<u8> {
    let mut out = String::new();
    for i in 0..n {
        out.push_str(&format!("{tag} line {i} {}\n", rng.next() % 1000));
    }
    out.into_bytes()
}

fn path_in(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// A random history of about `n` changes on `main` and `side`, with
/// merges both ways, renames and copies across folders (and across the
/// access boundary), edits, deletions, changes of hidden folders only,
/// empty changes, and timestamps that jump far ahead.
pub fn random_history(th: &TestHub, h: &mut Hist, rng: &mut Rng, n: usize) {
    let root = root_snapshot_id();
    let mut counter = 0usize;
    let mut fresh = |rng: &mut Rng, dir: &str| {
        counter += 1;
        path_in(dir, &format!("f{counter}-{}.txt", rng.next() % 100))
    };
    let mut tips: BTreeMap<&str, ObjectId> = BTreeMap::from([("main", root)]);
    let mut ts = 1_700_000_000_000i64;
    for i in 0..n {
        let on_side = tips.contains_key("side") && rng.chance(40);
        let branch = if on_side { "side" } else { "main" };
        let tip = tips[branch];
        let mut files = h.files[&tip].clone();
        let mut parents = vec![tip];
        let other = if on_side { "main" } else { "side" };
        let merging = tips.contains_key(other) && tips[other] != tip && rng.chance(18);
        if merging {
            let o = tips[other];
            parents.push(o);
            // "ours" merges keep the first parent's tree; others take some
            // of the other side's files.
            if !rng.chance(30) {
                for (p, c) in h.files[&o].clone() {
                    if files.get(&p) != Some(&c) && rng.chance(70) {
                        files.insert(p, c);
                    }
                }
            }
        } else if i == 3 {
            // The boundary cases, always: a file moved out of a hidden
            // folder, one moved into it, and an added file whose exact
            // sources are a hidden file (ranked first) and a readable one.
            let shared = text(rng, "shared", 8);
            for (p, c) in [
                ("fin/moved-out.txt", text(rng, "moved", 8)),
                ("pub/moved-in.txt", text(rng, "in", 8)),
                ("fin/a-twin.txt", shared.clone()),
                ("pub/b-twin.txt", shared.clone()),
            ] {
                files.insert(p.into(), c);
            }
        } else if i == 4 {
            let out = files.remove("fin/moved-out.txt").unwrap();
            files.insert("pub/moved-out.txt".into(), out);
            let into = files.remove("pub/moved-in.txt").unwrap();
            files.insert("fin/moved-in.txt".into(), into);
            let twin = files.remove("fin/a-twin.txt").unwrap();
            files.remove("pub/b-twin.txt");
            files.insert("pub/c-twin.txt".into(), twin);
        } else {
            let ops = 1 + rng.below(3);
            for _ in 0..ops {
                let paths: Vec<String> = files.keys().cloned().collect();
                let pick = |rng: &mut Rng| paths.get(rng.below(paths.len())).cloned();
                // A file, not an empty folder (whose bytes are not content).
                let pick_file = |rng: &mut Rng| pick(rng).filter(|p| !p.ends_with('/'));
                match rng.below(10) {
                    0 | 1 => {
                        if let Some(p) = pick_file(rng) {
                            let mut c = files[&p].clone();
                            c.extend(format!("edit {}\n", rng.next() % 1000).bytes());
                            files.insert(p, c);
                        }
                    }
                    2 | 3 => {
                        let d = DIRS[rng.below(DIRS.len())];
                        let p = fresh(rng, d);
                        let n = 6 + rng.below(6);
                        files.insert(p.clone(), text(rng, &p, n));
                    }
                    4 => {
                        if let Some(p) = pick(rng) {
                            files.remove(&p);
                        }
                    }
                    5 => {
                        // A rename, maybe across folders.
                        if let Some(p) = pick(rng) {
                            let c = files.remove(&p).unwrap();
                            let d = DIRS[rng.below(DIRS.len())];
                            files.insert(fresh(rng, d), c);
                        }
                    }
                    6 => {
                        // A rename with an edit (similar, not the same object).
                        if let Some(p) = pick_file(rng) {
                            let mut c = files.remove(&p).unwrap();
                            c.extend(b"one more line\n");
                            let d = DIRS[rng.below(DIRS.len())];
                            files.insert(fresh(rng, d), c);
                        }
                    }
                    7 => {
                        // A copy whose source is edited too.
                        if let Some(p) = pick_file(rng) {
                            let c = files[&p].clone();
                            let d = DIRS[rng.below(DIRS.len())];
                            files.insert(fresh(rng, d), c.clone());
                            let mut e = c;
                            e.extend(b"source edited\n");
                            files.insert(p, e);
                        }
                    }
                    8 => {
                        // An empty folder (BUG-871): a tree change with no
                        // leaf change.
                        let d = DIRS[rng.below(DIRS.len())];
                        let p = fresh(rng, d);
                        files.insert(format!("{p}/"), Vec::new());
                    }
                    _ => {
                        // A change of a hidden-to-most folder only.
                        let p = fresh(rng, "fin");
                        files.insert(p.clone(), text(rng, &p, 5));
                    }
                }
            }
            // Sometimes nothing at all changes.
            if rng.chance(5) {
                files = h.files[&tip].clone();
            }
        }
        ts += 1000 + rng.below(5000) as i64;
        let stamp = if rng.chance(8) { 9_000_000_000_000 + rng.below(1000) as i64 } else { ts };
        let mut change = [0u8; 16];
        change[..8].copy_from_slice(&rng.next().to_le_bytes());
        change[8..].copy_from_slice(&rng.next().to_le_bytes());
        let id = h.commit(th, &parents, files, change, stamp, None);
        tips.insert(branch, id);
        if i == 6 && !tips.contains_key("side") {
            tips.insert("side", id);
        }
    }
    for (b, t) in tips {
        h.set_branch(th, b, t);
    }
}

// ---- answers, as one viewer sees them -------------------------------------------

/// One path of a change, with ids mapped to the viewer's projected ones.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PathAnswer {
    path: String,
    old: Option<String>,
    new: Option<String>,
    /// (projected parent, projected last change), one per distinct parent.
    prev: Vec<(ObjectId, Option<ObjectId>)>,
    from: Vec<(String, u32)>,
    capped: bool,
}

/// Everything derived data answers for one viewer, in projected ids.
#[derive(Debug, Default, PartialEq, Eq)]
struct Answers {
    listed: BTreeSet<ObjectId>,
    changes: BTreeMap<ObjectId, Option<Vec<PathAnswer>>>,
    ancestry: BTreeMap<(ObjectId, ObjectId), bool>,
    merge_bases: BTreeMap<(ObjectId, ObjectId), Vec<ObjectId>>,
    last_change: BTreeMap<(ObjectId, String), Option<ObjectId>>,
}

/// The answers of `project`'s derived data for `view`: over `snaps` (that
/// project's ids, each in the viewer's history), `pairs` and `at_paths`,
/// with ids mapped by `map`.
#[allow(clippy::too_many_arguments)]
fn answers(
    th: &TestHub,
    hub: &Arc<Hub>,
    project: PermProject,
    viewer: Option<Viewer>,
    snaps: Vec<ObjectId>,
    pairs: Vec<(ObjectId, ObjectId)>,
    at_paths: Vec<(ObjectId, String)>,
    map: HashMap<ObjectId, ObjectId>,
) -> Answers {
    th.rt
        .block_on(derive::read(hub, project.id, move |g| {
            let lines = g.cx.lines()?;
            let view = match &viewer {
                Some(v) => project.view(v),
                None => View::admin(&project.policy),
            };
            let r = Reader::new(g, &lines, &view);
            let m = |id: &ObjectId| *map.get(id).unwrap_or(id);
            let mut a = Answers {
                listed: r.listed_all()?.iter().map(m).collect(),
                ..Answers::default()
            };
            for s in &snaps {
                let row = g.get(s)?;
                let ch = r.changes(s)?.map(|paths| {
                    let mut out: Vec<PathAnswer> = paths
                        .into_iter()
                        .map(|p| {
                            let mut prev: Vec<(ObjectId, Option<ObjectId>)> = Vec::new();
                            for (parent, pv) in row.parents.iter().zip(&p.prev) {
                                let pp = m(parent);
                                if !prev.iter().any(|(x, _)| *x == pp) {
                                    prev.push((pp, pv.as_ref().map(m)));
                                }
                            }
                            PathAnswer {
                                path: p.path,
                                old: p.old.map(|e| format!("{e:?}")),
                                new: p.new.map(|e| format!("{e:?}")),
                                prev,
                                from: p.from.into_iter().map(|f| (f.path, f.score)).collect(),
                                capped: p.capped,
                            }
                        })
                        .collect();
                    out.sort();
                    out
                });
                a.changes.insert(m(s), ch);
            }
            for (x, y) in &pairs {
                a.ancestry.insert((m(x), m(y)), g.is_ancestor(*x, *y)?);
                a.merge_bases.insert((m(x), m(y)), r.merge_bases(*x, *y)?.iter().map(m).collect());
            }
            for (at, path) in &at_paths {
                a.last_change.insert((m(at), path.clone()), derive::last_change(g.cx, path, *at)?.as_ref().map(m));
            }
            Ok(a)
        }))
        .unwrap()
}

/// `viewer`'s projection of every snapshot of `h` (the root maps to itself).
fn projections(th: &TestHub, h: &Hist, project: &PermProject, viewer: &Viewer) -> HashMap<ObjectId, ObjectId> {
    let mut p = HashMap::from([(root_snapshot_id(), root_snapshot_id())]);
    for s in &h.order {
        let q = th.rt.block_on(sync::projected(&h.hub, project, viewer, *s)).unwrap();
        p.insert(*s, q);
    }
    p
}

/// A new project holding exactly `viewer`'s projected history of `h`: the
/// projected snapshots and the projected trees under them, and the same
/// branches. Nobody is restricted in it (no access lines).
fn copy_for(th: &TestHub, h: &Hist, project: &PermProject, viewer: &Viewer, p: &HashMap<ObjectId, ObjectId>) -> Hist {
    let mut copy = Hist::new(th, "", &BTreeMap::new());
    let reals: Vec<ObjectId> = h.order.clone();
    let wanted: BTreeSet<ObjectId> = p.values().copied().filter(|q| *q != root_snapshot_id()).collect();
    let (hub, real_id, project2, viewer2) = (h.hub.clone(), h.id, project.clone(), viewer.clone());
    let objects: Vec<(ObjectId, Vec<u8>)> = th
        .rt
        .block_on(sync::blocking(&hub, real_id, move |src| {
            let view = project2.view(&viewer2);
            let mut pr = Projector::new(src, &view);
            for s in &reals {
                pr.root(src.snapshot(s)?.tree)?;
            }
            let mut out = Vec::new();
            let mut seen = HashSet::new();
            for q in &wanted {
                out.push((*q, src.raw(q)?.to_vec()));
                let mut stack = vec![src.snapshot(q)?.tree];
                while let Some(id) = stack.pop() {
                    if !seen.insert(id) {
                        continue;
                    }
                    let raw = match pr.created_raw(&id) {
                        Some(r) => r.to_vec(),
                        None => src.raw(&id)?.to_vec(),
                    };
                    if let Ok(Object::Tree(t)) = Object::decode(&raw) {
                        stack.extend(t.entries.iter().map(|e| e.id));
                    }
                    out.push((id, raw));
                }
            }
            Ok(out)
        }))
        .unwrap();
    let ids: BTreeSet<ObjectId> = objects.iter().filter_map(|(id, raw)| matches!(Object::decode(raw), Ok(Object::Snapshot(_))).then_some(*id)).collect();
    copy.put(th, objects);
    th.rt.block_on(async {
        for q in &ids {
            again(|| sqlx::query("INSERT INTO snapshots (project_id, id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(copy.id)
                .bind(q.hex())
                .execute(&copy.hub.db)).await;
        }
    });
    copy.order = ids.into_iter().collect();
    for (b, t) in h.branches.clone() {
        copy.set_branch(th, &b, p[&t]);
    }
    copy
}

/// Is `id` in `viewer`'s projected history (`sync::projected`, the S1
/// definition)?
fn in_projected_history(h: &Hist, p: &HashMap<ObjectId, ObjectId>, id: &ObjectId) -> bool {
    match h.parents[id].first() {
        None => true,
        Some(p0) => p[id] != p[p0],
    }
}

fn merges(h: &Hist) -> usize {
    h.order.iter().filter(|s| h.parents[s].len() > 1).count()
}

#[test]
fn projection_equivalence() {
    let th = TestHub::start();
    for seed in seeds(&[1, 2, 3]) {
        let carol = 700_000 + seed as i64;
        let (text, bindings) = policy(carol);
        let mut h = Hist::new(&th, &text, &bindings);
        let mut rng = Rng::new(seed);
        random_history(&th, &mut h, &mut rng, 40);
        h.derive(&th);
        let project = h.project(&th);
        let (mut hidden_somewhere, mut sourced) = (0, 0);
        let folders_only = h
            .order
            .iter()
            .filter(|s| {
                let (now, before) = (&h.files[*s], &h.files[&h.parents[*s][0]]);
                now != before && now.keys().chain(before.keys()).filter(|k| now.get(*k) != before.get(*k)).all(|k| k.ends_with('/'))
            })
            .count();
        for (who, viewer) in viewers(carol) {
            let p = projections(&th, &h, &project, &viewer);
            let copy = copy_for(&th, &h, &project, &viewer, &p);
            copy.derive(&th);
            let view = project.view(&viewer);
            // Which snapshots are in the viewer's history: derived data
            // decides it exactly as the S1 projection does.
            let visible_real: Vec<ObjectId> = th
                .rt
                .block_on(derive::read(&h.hub, h.id, {
                    let (project, viewer, order) = (project.clone(), viewer.clone(), h.order.clone());
                    move |g| {
                        let lines = g.cx.lines()?;
                        let view = project.view(&viewer);
                        let r = Reader::new(g, &lines, &view);
                        let mut out = Vec::new();
                        for s in &order {
                            if r.visible(s)? {
                                out.push(*s);
                            }
                        }
                        Ok(out)
                    }
                }))
                .unwrap();
            hidden_somewhere += h.order.len() - visible_real.len();
            for s in &h.order {
                assert_eq!(
                    visible_real.contains(s),
                    in_projected_history(&h, &p, s),
                    "seed {seed}, {who}: derived visibility of {} differs from the projection",
                    s.short()
                );
            }
            // Pairs and paths to ask about.
            let mut pairs = Vec::new();
            for _ in 0..25 {
                let a = visible_real[rng.below(visible_real.len())];
                let b = visible_real[rng.below(visible_real.len())];
                pairs.push((a, b));
            }
            let mut at_paths = Vec::new();
            for s in &visible_real {
                let readable: Vec<&String> = h.files[s].keys().filter(|k| view.read(k)).collect();
                for _ in 0..3 {
                    if let Some(k) = readable.get(rng.below(readable.len().max(1))) {
                        at_paths.push((*s, (*k).clone()));
                    }
                }
            }
            let real = answers(&th, &h.hub, project.clone(), Some(viewer.clone()), visible_real.clone(), pairs.clone(), at_paths.clone(), p.clone());
            let copy_project = copy.project(&th);
            let copy_snaps: Vec<ObjectId> = visible_real.iter().map(|s| p[s]).collect();
            let copy_pairs = pairs.iter().map(|(a, b)| (p[a], p[b])).collect();
            let copy_paths = at_paths.iter().map(|(s, k)| (p[s], k.clone())).collect();
            let theirs = answers(&th, &h.hub, copy_project, None, copy_snaps, copy_pairs, copy_paths, HashMap::new());
            sourced += real.changes.values().flatten().flatten().filter(|p| !p.from.is_empty()).count();
            assert_eq!(real.listed.len(), theirs.listed.len(), "seed {seed}, {who}: list sizes differ");
            assert_eq!(real.listed, theirs.listed, "seed {seed}, {who}: lists differ");
            for (k, v) in &real.changes {
                assert_eq!(Some(v), theirs.changes.get(k), "seed {seed}, {who}: changes of {} differ", k.short());
            }
            assert_eq!(real.changes.len(), theirs.changes.len());
            assert_eq!(real.ancestry, theirs.ancestry, "seed {seed}, {who}: ancestry differs");
            assert_eq!(real.merge_bases, theirs.merge_bases, "seed {seed}, {who}: merge bases differ");
            assert_eq!(real.last_change, theirs.last_change, "seed {seed}, {who}: file history differs");
            // No hidden path in any answer (row 5): every path named is one
            // the viewer may read.
            for paths in real.changes.values().flatten() {
                for pa in paths {
                    assert!(view.read(&pa.path), "seed {seed}, {who}: hidden path {} answered", pa.path);
                    for (f, _) in &pa.from {
                        assert!(view.read(f), "seed {seed}, {who}: hidden source {f} answered for {}", pa.path);
                    }
                }
            }
        }
        // The history exercised what the test is about.
        assert!(hidden_somewhere > 0 && merges(&h) > 0 && sourced > 0, "seed {seed}: {hidden_somewhere} {} {sourced}", merges(&h));
        println!("seed {seed}: {} changes, {} merges, {folders_only} changing empty folders only", h.order.len(), merges(&h));
        // The boundary cases happened: a readable file's exact sources were
        // a hidden one (ranked first) and a readable one.
        let c4 = h.order[4];
        let all: Changed = th
            .rt
            .block_on(derive::read(&h.hub, h.id, move |g| Ok(g.cx.changed(g.get(&c4)?.changed.as_deref().unwrap())?.unwrap())))
            .unwrap();
        let twin = all.paths.iter().find(|p| p.path == "pub/c-twin.txt").unwrap();
        let from: Vec<&str> = twin.from.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(from, ["fin/a-twin.txt", "pub/b-twin.txt"], "seed {seed}");
    }
}

/// The model's answer: the snapshot that last changed `path` along `at`'s
/// first parents.
fn model_last_change(h: &Hist, at: ObjectId, path: &str) -> Option<ObjectId> {
    let mut x = at;
    loop {
        let p0 = h.parents[&x].first().copied()?;
        if h.files[&x].get(path) != h.files[&p0].get(path) {
            return Some(x);
        }
        x = p0;
    }
}

fn model_ancestors(h: &Hist, of: ObjectId) -> HashSet<ObjectId> {
    let mut seen = HashSet::new();
    let mut stack = vec![of];
    while let Some(x) = stack.pop() {
        if seen.insert(x) {
            stack.extend(h.parents[&x].iter().copied());
        }
    }
    seen
}

/// Ancestry, merge bases, depths and file history from derived data equal
/// direct walks of the history (design §6, row 11's self-check).
#[test]
fn derived_graph_matches_direct_walks() {
    let th = TestHub::start();
    for seed in seeds(&[11, 12]) {
        let (text, bindings) = policy(1);
        let mut h = Hist::new(&th, &text, &bindings);
        let mut rng = Rng::new(seed);
        random_history(&th, &mut h, &mut rng, 120);
        let stats = h.derive(&th);
        assert_eq!(stats.snapshots, h.order.len(), "seed {seed}: every snapshot derived once");
        assert_eq!(h.derive(&th).snapshots, 0, "seed {seed}: nothing left to derive");
        let mut pairs = Vec::new();
        for _ in 0..60 {
            pairs.push((h.order[rng.below(h.order.len())], h.order[rng.below(h.order.len())]));
        }
        let anc: HashMap<ObjectId, HashSet<ObjectId>> =
            h.order.iter().chain([&root_snapshot_id()]).map(|s| (*s, model_ancestors(&h, *s))).collect();
        let order = h.order.clone();
        let parents = h.parents.clone();
        let mut wants = Vec::new();
        for s in &h.order {
            let mut paths: BTreeSet<&String> = h.files[s].keys().collect();
            for p in &h.parents[s] {
                paths.extend(h.files[p].keys());
            }
            for path in paths.into_iter().filter(|p| !p.ends_with('/')) {
                if rng.chance(30) {
                    wants.push((*s, path.clone()));
                }
            }
        }
        let expected: Vec<Option<ObjectId>> = wants.iter().map(|(s, p)| model_last_change(&h, *s, p)).collect();
        let (got, prevs_ok) = th
            .rt
            .block_on(derive::read(&h.hub, h.id, move |g| {
                for (a, b) in &pairs {
                    assert_eq!(g.is_ancestor(*a, *b)?, anc[b].contains(a), "seed {seed}: is_ancestor");
                    let common: Vec<ObjectId> = anc[a].intersection(&anc[b]).copied().collect();
                    let mut best: Vec<ObjectId> =
                        common.iter().filter(|c| !common.iter().any(|d| d != *c && anc[d].contains(c))).copied().collect();
                    best.sort();
                    assert_eq!(g.merge_bases(*a, *b)?, best, "seed {seed}: merge bases");
                }
                for s in &order {
                    // The first-parent line, and every depth on it.
                    let mut line = vec![*s];
                    while let Some(p) = parents[line.last().unwrap()].first() {
                        line.push(*p);
                    }
                    let depth = g.get(s)?.depth;
                    assert_eq!(depth as usize, line.len() - 1);
                    for (i, x) in line.iter().enumerate() {
                        assert_eq!(g.at_depth(*s, depth - i as i64)?, Some(*x));
                    }
                }
                let mut got = Vec::new();
                for (s, p) in &wants {
                    got.push(derive::last_change(g.cx, p, *s)?);
                }
                // Each stored `prev` is the last change along its parent.
                let mut prevs = Vec::new();
                for s in &order {
                    if let Some(c) = g.cx.changed(g.get(s)?.changed.as_deref().unwrap())? {
                        for pc in c.paths {
                            prevs.push((*s, pc.path, pc.prev));
                        }
                    }
                }
                Ok((got, prevs))
            }))
            .unwrap();
        assert_eq!(got, expected, "seed {seed}: file history starts");
        for (s, path, prev) in prevs_ok {
            let want: Vec<Option<ObjectId>> = h.parents[&s].iter().map(|p| model_last_change(&h, *p, &path)).collect();
            assert_eq!(prev, want, "seed {seed}: prev of {path} in {}", s.short());
        }
    }
}

/// Values are a function of immutable inputs: after a crash at any point
/// (derived rows partly written, the marking rows missing, a list being
/// built) and a restart, the next run writes exactly the same data; and
/// derivers racing on one project (one server's, several at once) agree
/// (design §6, row 11).
#[test]
fn derived_data_resumes_after_a_crash() {
    let th = TestHub::start();
    let (text, bindings) = policy(1);
    let mut h = Hist::new(&th, &text, &bindings);
    let mut rng = Rng::new(21);
    random_history(&th, &mut h, &mut rng, 60);
    h.derive(&th);
    let before = h.state(&th);
    for round in 0..4 {
        // Crash: the later snapshots lose their marking rows, and some of
        // their other rows; a list goes back to being built.
        let cut: Vec<String> = h.order[h.order.len() / (2 + round)..].iter().map(|s| s.hex()).collect();
        let db = h.hub.db.clone();
        let id = h.id;
        th.rt.block_on(async {
            again(|| sqlx::query("DELETE FROM graph WHERE project_id = $1 AND snapshot = ANY($2)").bind(id).bind(&cut).execute(&db)).await;
            again(|| sqlx::query("DELETE FROM file_history WHERE project_id = $1 AND snapshot = ANY($2) AND depth % 2 = $3")
                .bind(id)
                .bind(&cut)
                .bind(round as i64 % 2)
                .execute(&db)).await;
            again(|| sqlx::query("DELETE FROM rule_history WHERE project_id = $1 AND generation % 3 = $2")
                .bind(id)
                .bind(round as i64 % 3)
                .execute(&db)).await;
            again(|| sqlx::query("UPDATE rule_lines SET ready = FALSE WHERE project_id = $1").bind(id).execute(&db)).await;
        });
        h.hub.derive.clear_cache();
        // Several derivers at once: one works, the others wait for it.
        let hub = h.hub.clone();
        let stats: Vec<derive::Stats> = th.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for _ in 0..4 {
                let hub = hub.clone();
                set.spawn(async move { derive::catch_up(&hub, id, derive::Scope::All).await.unwrap() });
            }
            let mut out = Vec::new();
            while let Some(r) = set.join_next().await {
                out.push(r.unwrap());
            }
            out
        });
        assert_eq!(stats.iter().map(|s| s.snapshots).sum::<usize>(), cut.len(), "round {round}: each snapshot derived once: {stats:?}");
        assert_eq!(h.state(&th), before, "round {round}: resumed data differs");
    }
}

/// A new accepted policy builds the lists whose lines' paths changed, keeps
/// the others, and ends with exactly the lists a project derived under the
/// new policy from scratch has (design §6, row 13).
#[test]
fn policy_change_rebuilds_only_the_lines_that_moved() {
    let th = TestHub::start();
    let (text, bindings) = policy(1);
    // Under the new policy fin/ is public and pub/deep/ is its own line.
    let text2 = "pub/ public devs\npub/sec/ security\npub/deep/ finance\nfin/ public\ncarol-d/ carol\n";
    let mut a = Hist::new(&th, &text, &bindings);
    let mut b = Hist::new(&th, text2, &bindings);
    random_history(&th, &mut a, &mut Rng::new(31), 50);
    random_history(&th, &mut b, &mut Rng::new(31), 50);
    assert_eq!(a.order, b.order, "the same history in both projects");
    a.derive(&th);
    let anyone = Viewer::default();
    let listed = |h: &Hist| -> BTreeSet<ObjectId> {
        let project = h.project(&th);
        let v = anyone.clone();
        th.rt
            .block_on(derive::read(&h.hub, h.id, move |g| {
                let lines = g.cx.lines()?;
                let view = project.view(&v);
                Ok(Reader::new(g, &lines, &view).listed_all()?.into_iter().collect())
            }))
            .unwrap()
    };
    let fin_only: Vec<ObjectId> = a
        .order
        .iter()
        .filter(|s| {
            let p0 = a.parents[s][0];
            let changed: Vec<&String> =
                a.files[s].keys().chain(a.files[&p0].keys()).filter(|k| a.files[s].get(*k) != a.files[&p0].get(*k)).collect();
            !changed.is_empty() && changed.iter().all(|k| k.starts_with("fin/"))
        })
        .copied()
        .collect();
    assert!(!fin_only.is_empty());
    let before = listed(&a);
    assert!(fin_only.iter().all(|s| !before.contains(s)), "hidden-only changes are not on anyone's lists");
    // An admin's push accepts the new policy (here written directly).
    th.rt.block_on(async {
        again(|| sqlx::query("UPDATE projects SET policy_text = $1, policy_version = policy_version + 1 WHERE id = $2")
            .bind(text2)
            .bind(a.id)
            .execute(&a.hub.db)).await;
    });
    let stats = a.derive(&th);
    assert!(stats.rebuilt > 0 && stats.snapshots == 0, "{stats:?}");
    b.derive(&th);
    let after = listed(&a);
    assert_eq!(after, listed(&b), "the rebuilt lists answer like lists derived under the new policy");
    assert!(fin_only.iter().all(|s| after.contains(s)), "fin/ is public now");
    // The kept lists were not built again: only lines whose paths changed.
    let keys = |h: &Hist| -> BTreeSet<(String, i64, String)> {
        th.rt.block_on(async {
            sqlx::query_as::<_, (String, i64, String)>(
                "SELECT r.line_key, r.generation, r.snapshot FROM rule_history r JOIN rule_lines l \
                 ON l.project_id = r.project_id AND l.line_key = r.line_key WHERE r.project_id = $1",
            )
            .bind(h.id)
            .fetch_all(&h.hub.db)
            .await
            .unwrap()
            .into_iter()
            .collect()
        })
    };
    assert_eq!(keys(&a), keys(&b), "the same lists, row for row");
    let unchanged = veil_server::derive::lines::Lines::new(&veil_core::hub::access::AccessPolicy::parse(&text));
    let new = veil_server::derive::lines::Lines::new(&veil_core::hub::access::AccessPolicy::parse(text2));
    let kept: BTreeSet<String> = unchanged.all().into_iter().filter(|k| new.all().contains(k)).collect();
    assert!(!kept.is_empty(), "some lines kept their paths (pub/sec/, carol-d/)");
    let rebuilt_rows = keys(&a).iter().filter(|(k, _, _)| !kept.contains(k)).count();
    assert_eq!(stats.rebuilt, rebuilt_rows, "only the moved lines were built");
}

/// Secrets are never indexed in the clear (row 7), landings are derived
/// without anyone asking, and each viewer's history from derived data is
/// the S1 projection: through `vl` and the push route.
#[test]
fn derived_on_landing() {
    let th = TestHub::start();
    let p = setup_project(&th);
    let hub = th.hub();
    let (pid, tip): (i64, String) = th.rt.block_on(async {
        sqlx::query_as("SELECT p.id, b.target FROM projects p JOIN branches b ON b.project_id = p.id AND b.name = 'main' WHERE p.name = $1")
            .bind(&p.name)
            .fetch_one(&hub.db)
            .await
            .unwrap()
    });
    // Eager: derived and memoised in the background after the last push.
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let through: Option<String> = th.rt.block_on(async {
            sqlx::query_scalar("SELECT through_snapshot FROM derive_progress WHERE project_id = $1 AND branch = 'main'")
                .bind(pid)
                .fetch_optional(&hub.db)
                .await
                .unwrap()
        });
        if through.as_deref() == Some(tip.as_str()) {
            break;
        }
        assert!(Instant::now() < deadline, "the landing was not derived within 90 s");
        std::thread::sleep(Duration::from_millis(200));
    }
    let reals = real_snapshots(&p.dir);
    let project = th.rt.block_on(async {
        let mut c = hub.db.acquire().await.unwrap();
        veil_server::perm::load_project(&mut c, &p.name).await.unwrap().unwrap()
    });
    let viewer_of = |who: &Person| -> Viewer {
        th.rt.block_on(async {
            let person: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&who.name).fetch_one(&hub.db).await.unwrap();
            let groups: Vec<i64> = sqlx::query_scalar(
                "SELECT g.id FROM groups g JOIN group_members m ON m.group_id = g.id WHERE g.project_id = $1 AND m.person_id = $2",
            )
            .bind(pid)
            .bind(person)
            .fetch_all(&hub.db)
            .await
            .unwrap();
            Viewer {
                person: Some(person),
                admin: false,
                groups: groups.into_iter().collect(),
            }
        })
    };
    let mut people = vec![("anyone", Viewer::default())];
    for (n, who) in [("dev", &p.dev), ("fin", &p.fin), ("sec", &p.sec), ("carol", &p.carol)] {
        people.push((n, viewer_of(who)));
    }
    // Each person's tip projection was memoised by the deriver (phase 4
    // §4.5): poll, it runs right after the derive.
    let tip_id = ObjectId::from_hex(&tip).unwrap();
    for (n, v) in &people {
        let key = project.view(v).key();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let memo: Option<String> = th.rt.block_on(async {
                sqlx::query_scalar("SELECT projected_id FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = $3")
                    .bind(pid)
                    .bind(&key)
                    .bind(&tip)
                    .fetch_optional(&hub.db)
                    .await
                    .unwrap()
            });
            if memo.is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "{n}'s tip projection was not memoised");
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = tip_id;
    }
    // Visibility from derived data equals the projection, for everyone.
    for (n, v) in &people {
        let mut proj = HashMap::from([(root_snapshot_id(), root_snapshot_id())]);
        let mut parents = HashMap::new();
        for s in &reals {
            proj.insert(*s, th.rt.block_on(sync::projected(&hub, &project, v, *s)).unwrap());
            let snap = th.rt.block_on(sync::blocking(&hub, pid, {
                let s = *s;
                move |src| Ok(src.snapshot(&s)?)
            }))
            .unwrap();
            parents.insert(*s, snap.parents.clone());
        }
        let (project2, v2, reals2) = (project.clone(), v.clone(), reals.clone());
        let vis: Vec<bool> = th
            .rt
            .block_on(derive::read(&hub, pid, move |g| {
                let lines = g.cx.lines()?;
                let view = project2.view(&v2);
                let r = Reader::new(g, &lines, &view);
                reals2.iter().map(|s| r.visible(s)).collect()
            }))
            .unwrap();
        for (s, vis) in reals.iter().zip(vis) {
            let want = parents[s].first().is_none_or(|p0| proj[s] != proj[p0]);
            assert_eq!(vis, want, "{n}: visibility of {}", s.short());
        }
    }
    // Secrets: the path of billing's .env is indexed, sealed; its content
    // never is (the server never holds it).
    let objects: Vec<Vec<u8>> = th.rt.block_on(async {
        let ids: Vec<Option<String>> = sqlx::query_scalar("SELECT changed FROM graph WHERE project_id = $1").bind(pid).fetch_all(&hub.db).await.unwrap();
        let mut out = Vec::new();
        for id in ids.into_iter().flatten() {
            if let Ok(oid) = ObjectId::from_hex(&id) {
                out.push(hub.objects.get(pid, &oid).await.unwrap().unwrap().to_vec());
            }
        }
        out
    });
    let env = format!("{BILL_DIR}/.env");
    let mut sealed_env = false;
    for raw in &objects {
        let c = Changed::decode(raw).unwrap();
        for pc in &c.paths {
            if pc.path == env {
                sealed_env |= pc.new.as_ref().is_some_and(|e| !e.visibility.is_public());
            }
        }
    }
    assert!(sealed_env, "billing's .env is listed by path, as a sealed entry");
    let mut everything: Vec<(String, Vec<u8>)> = objects.into_iter().map(|o| ("derived object".to_string(), o)).collect();
    everything.extend(th.rt.block_on(async {
        let mut out = Vec::new();
        for (table, cols) in [
            ("graph", "snapshot || parents || change_id || skip || coalesce(changed, '')"),
            ("file_history", "path_key || snapshot"),
            ("rule_history", "line_key || snapshot"),
            ("rule_lines", "line_key"),
            ("derive_progress", "branch || through_snapshot"),
        ] {
            let rows: Vec<String> = sqlx::query_scalar(&format!("SELECT {cols} FROM {table} WHERE project_id = $1"))
                .bind(pid)
                .fetch_all(&hub.db)
                .await
                .unwrap();
            out.extend(rows.into_iter().map(|r| (format!("{table} row"), r.into_bytes())));
        }
        out
    }));
    assert_no_marker(&everything, &[ENV_MARK], "the derived data");
}

/// An embargo line is not indexed or listed until its release (row 8): its
/// snapshots get graph rows (flags), and nothing else names their paths.
#[test]
fn embargo_lines_are_withheld() {
    let th = TestHub::start();
    let (text, bindings) = policy(1);
    let mut h = Hist::new(&th, &text, &bindings);
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
    h.derive(&th);
    let (hub, id) = (h.hub.clone(), h.id);
    th.rt
        .block_on(derive::read(&hub, id, move |g| {
            assert_eq!(g.get(&a)?.flags, 0);
            assert_eq!(g.get(&e)?.flags, 3);
            assert_eq!(g.get(&c)?.flags, 2);
            for s in [e, c] {
                assert_eq!(g.get(&s)?.changed.as_deref(), Some("withheld"));
            }
            Ok(())
        }))
        .unwrap();
    let state = h.state(&th);
    let keys = [derive::changes::path_key("pub/fix-embargo-77c1e0.rs"), derive::changes::path_key("pub/after-fix-5d2c.rs")];
    for line in &state {
        assert!(!line.contains("fix-embargo") && !line.contains("FIX-MARKER") && !line.contains("after-fix"), "{line}");
        assert!(!keys.iter().any(|k| line.contains(k.as_str())), "{line}");
        if line.starts_with("rule ") || line.starts_with("history ") {
            assert!(!line.contains(&e.hex()) && !line.contains(&c.hex()), "{line}");
        }
    }
    let project = h.project(&th);
    th.rt
        .block_on(derive::read(&hub, id, move |g| {
            let lines = g.cx.lines()?;
            let anyone = Viewer::default();
            let view = project.view(&anyone);
            let r = Reader::new(g, &lines, &view);
            assert!(r.visible(&a)? && !r.visible(&e)? && !r.visible(&c)?);
            assert!(!r.listed_all()?.contains(&e));
            Ok(())
        }))
        .unwrap();
}

/// Hostile changes stay within linear work and bounded objects (row 10):
/// thousands of identical files moved at once, and a change of more paths
/// than an object lists ("many"), whose file history stays exact.
#[test]
fn hostile_changes_stay_bounded() {
    let th = TestHub::start();
    let (text, bindings) = policy(1);
    let mut h = Hist::new(&th, &text, &bindings);
    // 3,000 identical files, half in a hidden folder, all renamed at once.
    let same = b"the same\ncontent\n".to_vec();
    let mut files = Files::new();
    for i in 0..3000 {
        let dir = if i % 2 == 0 { "pub" } else { "fin" };
        files.insert(format!("{dir}/old/{i:05}.txt"), same.clone());
    }
    let a = h.commit(&th, &[root_snapshot_id()], files, [1; 16], 1, None);
    let moved: Files = (0..3000).map(|i| (format!("{}/new/{i:05}.txt", if i % 2 == 0 { "pub" } else { "fin" }), same.clone())).collect();
    let b = h.commit(&th, &[a], moved, [2; 16], 2, None);
    // More paths than one object lists: one blob, 100,001 names.
    let mut big = Files::new();
    for i in 0..=derive::changes::MAX_PATHS {
        big.insert(format!("pub/many/{i:06}"), b"x".to_vec());
    }
    big.insert("pub/kept.rs".into(), b"kept\n".to_vec());
    let mut pre = h.files[&b].clone();
    pre.insert("pub/kept.rs".into(), b"kept\n".to_vec());
    let c0 = h.commit(&th, &[b], pre, [3; 16], 3, None);
    let mut with_big = h.files[&c0].clone();
    with_big.extend(big);
    let m = h.commit(&th, &[c0], with_big.clone(), [4; 16], 4, None);
    let mut edit = with_big;
    edit.insert("pub/many/000007".into(), b"y".to_vec());
    edit.insert("pub/kept.rs".into(), b"kept, edited\n".to_vec());
    let after = h.commit(&th, &[m], edit, [5; 16], 5, None);
    h.set_branch(&th, "main", after);
    let t = Instant::now();
    h.derive(&th);
    let took = t.elapsed();
    println!("hostile: 3,000 identical renames and a change of 100,002 paths derived in {took:?}");
    assert!(took < Duration::from_secs(240), "{took:?}");
    let project = h.project(&th);
    let (hub, id) = (h.hub.clone(), h.id);
    th.rt
        .block_on(derive::read(&hub, id, move |g| {
            let rb = g.get(&b)?;
            let raw_len = g.cx.src.raw(&ObjectId::from_hex(rb.changed.as_deref().unwrap()).unwrap())?.len();
            let all = g.cx.changed(rb.changed.as_deref().unwrap())?.unwrap();
            assert!(!all.similar, "too many files to compare");
            for pc in all.paths.iter().filter(|p| p.old.is_none()) {
                assert!(pc.from.len() <= derive::changes::MAX_SOURCES && pc.capped);
            }
            assert!(raw_len < 6000 * 2000, "bounded object: {raw_len} bytes");
            // A reader of pub/ only gets sources from pub/, computed on
            // their part.
            let lines = g.cx.lines()?;
            let anyone = Viewer::default();
            let view = project.view(&anyone);
            let r = Reader::new(g, &lines, &view);
            let mine = r.changes(&b)?.unwrap();
            assert_eq!(mine.len(), 3000, "1,500 deleted and 1,500 added readable files");
            for pc in mine.iter().filter(|p| p.new.is_some()) {
                assert!(!pc.from.is_empty() && pc.from.len() <= derive::changes::MAX_SOURCES);
                assert!(pc.from.iter().all(|f| f.path.starts_with("pub/")), "{:?}", pc.from);
            }
            // "many": listed, no object; file history across it stays exact.
            assert_eq!(g.get(&m)?.changed.as_deref(), Some("many"));
            assert!(r.listed(&m)?);
            assert!(r.changes(&m)?.is_none());
            assert_eq!(derive::last_change(g.cx, "pub/many/000007", after)?, Some(after));
            assert_eq!(derive::last_change(g.cx, "pub/many/000007", m)?, Some(m));
            assert_eq!(derive::last_change(g.cx, "pub/kept.rs", m)?, Some(c0), "the many change did not touch it");
            let c = g.cx.changed(g.get(&after)?.changed.as_deref().unwrap())?.unwrap();
            let prev: HashMap<&str, &Vec<Option<ObjectId>>> = c.paths.iter().map(|p| (p.path.as_str(), &p.prev)).collect();
            assert_eq!(prev["pub/many/000007"], &vec![Some(m)]);
            assert_eq!(prev["pub/kept.rs"], &vec![Some(c0)]);
            Ok(())
        }))
        .unwrap();
}

/// On demand: `ensure` derives a snapshot and what is below it, and
/// refuses one that is not committed history.
#[test]
fn ensure_derives_on_demand() {
    let th = TestHub::start();
    let (text, bindings) = policy(1);
    let mut h = Hist::new(&th, &text, &bindings);
    random_history(&th, &mut h, &mut Rng::new(41), 20);
    let mid = h.order[9];
    let stats = th.rt.block_on(derive::ensure(&h.hub, h.id, mid)).unwrap();
    assert_eq!(stats.snapshots, model_ancestors(&h, mid).len() - 1, "the snapshot and its ancestors, nothing else");
    let unknown = ObjectId::hash(b"never committed");
    assert!(th.rt.block_on(derive::ensure(&h.hub, h.id, unknown)).is_err());
    assert_eq!(h.derive(&th).snapshots, h.order.len() - stats.snapshots);
}

/// The cost of a landing and the speed of a backfill on a large history
/// (`VEIL_DERIVE_BENCH_SNAPSHOTS`, default 2,000), printed.
#[test]
fn derived_speed() {
    let n: usize = std::env::var("VEIL_DERIVE_BENCH_SNAPSHOTS").ok().and_then(|s| s.parse().ok()).unwrap_or(2_000);
    let th = TestHub::start();
    let (policy_text, bindings) = policy(1);
    let mut h = Hist::new(&th, &policy_text, &bindings);
    let mut rng = Rng::new(51);
    // 500 files in 25 folders, each change editing 1 to 4 of them; a side
    // branch merged every 50 changes.
    let mut files = Files::new();
    for i in 0..500 {
        let dir = ["pub", "pub/sec", "fin", "carol-d", "root"][i % 5];
        files.insert(format!("{dir}/d{}/f{i}.txt", i % 25), text(&mut rng, "f", 20));
    }
    let build = Instant::now();
    let mut objects = Vec::new();
    let mut tip = root_snapshot_id();
    let mut side = None;
    let mut rows = Vec::new();
    let keys: Vec<String> = files.keys().cloned().collect();
    for i in 0..n {
        let edits = 1 + rng.below(4);
        for _ in 0..edits {
            let k = &keys[rng.below(keys.len())];
            let mut c = files[k].clone();
            c.extend(format!("edit {i}\n").bytes());
            files.insert(k.clone(), c);
        }
        let mut parents = vec![tip];
        if i % 50 == 49 {
            if let Some(s) = side.take() {
                parents.push(s);
            }
        }
        let tree = build_tree(&files, &mut objects);
        let s = Snapshot {
            parents: parents.clone(),
            change_id: ChangeId(rng.next().to_le_bytes().repeat(2).try_into().unwrap()),
            tree,
            description: Text::Plain(format!("change {i}")),
            author: "bench".into(),
            timestamp: 1_700_000_000_000 + i as i64 * 1000,
            predecessors: vec![],
            conflicts: vec![],
            cloak: None,
            embargo: None,
            signature: None,
        };
        let raw = Object::Snapshot(s).encode();
        let id = ObjectId::hash(&raw);
        objects.push((id, raw));
        rows.push(id.hex());
        if i % 50 == 10 {
            side = Some(tip);
        }
        tip = id;
        h.parents.insert(id, parents);
        h.order.push(id);
        if objects.len() > 20_000 {
            h.put(&th, std::mem::take(&mut objects));
        }
    }
    h.put(&th, objects);
    th.rt.block_on(async {
        for chunk in rows.chunks(5000) {
            again(|| sqlx::query("INSERT INTO snapshots (project_id, id) SELECT $1, * FROM UNNEST($2::text[]) ON CONFLICT DO NOTHING")
                .bind(h.id)
                .bind(chunk)
                .execute(&h.hub.db)).await;
        }
    });
    h.set_branch(&th, "main", tip);
    println!("derived_speed: built {n} snapshots in {:?}", build.elapsed());
    let t = Instant::now();
    let stats = h.derive(&th);
    let backfill = t.elapsed();
    assert_eq!(stats.snapshots, n);
    println!(
        "derived_speed: backfill {n} snapshots in {backfill:?} ({:.0} snapshots/s)",
        n as f64 / backfill.as_secs_f64()
    );
    // Landings one at a time on top: the cost of deriving each.
    let mut times = Vec::new();
    for i in 0..40 {
        let k = &keys[rng.below(keys.len())];
        let mut c = files[k].clone();
        c.extend(format!("landing {i}\n").bytes());
        files.insert(k.clone(), c);
        let id = h.commit(&th, &[tip], files.clone(), rng.next().to_le_bytes().repeat(2).try_into().unwrap(), 1_800_000_000_000 + i, None);
        h.set_branch(&th, "main", id);
        tip = id;
        let t = Instant::now();
        assert_eq!(h.derive(&th).snapshots, 1);
        times.push(t.elapsed());
    }
    times.sort();
    println!(
        "derived_speed: one landing on {n} snapshots: p50 {:?}, p90 {:?}, max {:?}",
        times[times.len() / 2],
        times[times.len() * 9 / 10],
        times[times.len() - 1]
    );
    // Ancestry and depth lookups on the large history; two branches off a
    // snapshot early in it.
    let base = h.order[10];
    let mut files_a = h.files.get(&base).cloned().unwrap_or_default();
    files_a.insert("pub/branch-a.txt".into(), b"a\n".to_vec());
    let side_a = h.commit(&th, &[base], files_a.clone(), [7; 16], 1, None);
    files_a.insert("pub/branch-b.txt".into(), b"b\n".to_vec());
    let side_b = h.commit(&th, &[tip], files_a, [8; 16], 2, None);
    h.set_branch(&th, "a", side_a);
    h.set_branch(&th, "b", side_b);
    h.derive(&th);
    let (first, last) = (h.order[0], tip);
    let (hub, id) = (h.hub.clone(), h.id);
    let total = h.order.len();
    th.rt
        .block_on(derive::read(&hub, id, move |g| {
            let t = Instant::now();
            assert!(g.is_ancestor(first, last)?);
            let t1 = t.elapsed();
            assert_eq!(g.at_depth(last, 1)?, Some(first));
            let t2 = t.elapsed();
            assert_eq!(g.merge_bases(first, last)?, vec![first]);
            let t3 = t.elapsed();
            // Two branches off the line: a merge base far down.
            let (x, y) = (side_a, side_b);
            let mb = g.merge_bases(x, y)?;
            let t4 = t.elapsed();
            assert_eq!(mb.len(), 1);
            println!(
                "derived_speed: across {total} snapshots: is_ancestor(first, tip) {t1:?}, at_depth(tip, 1) {:?}, \
                 merge_bases(first, tip) {:?}, merge_bases of two branches {:?}",
                t2 - t1,
                t3 - t2,
                t4 - t3
            );
            Ok(())
        }))
        .unwrap();
}

// ---- adversarial pass: S12 derived data (BUG-866…) -------------------------------

mod s12_adversarial {
    use std::sync::atomic::{AtomicBool, Ordering};

    use veil_core::hub::project::empty_tree_id;

    use super::*;

    /// A snapshot of tree `tree` (its objects in `objects`) written as
    /// committed history, without keeping a copy of its files.
    fn commit_tree(th: &TestHub, h: &mut Hist, parents: &[ObjectId], tree: ObjectId, mut objects: Vec<(ObjectId, Vec<u8>)>, n: u128, timestamp: i64) -> ObjectId {
        let s = Snapshot {
            parents: parents.to_vec(),
            change_id: ChangeId(n.to_le_bytes()),
            tree,
            description: Text::Plain(format!("change {n}")),
            author: "gen".into(),
            timestamp,
            predecessors: vec![],
            conflicts: vec![],
            cloak: None,
            embargo: None,
            signature: None,
        };
        let raw = Object::Snapshot(s).encode();
        let id = ObjectId::hash(&raw);
        objects.push((id, raw));
        h.put(th, objects);
        th.rt.block_on(async {
            again(|| {
                sqlx::query("INSERT INTO snapshots (project_id, id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                    .bind(h.id)
                    .bind(id.hex())
                    .execute(&h.hub.db)
            })
            .await;
        });
        h.parents.insert(id, parents.to_vec());
        h.order.push(id);
        id
    }

    fn tree_of(files: &Files) -> (ObjectId, Vec<(ObjectId, Vec<u8>)>) {
        let mut out = Vec::new();
        let id = build_tree(files, &mut out);
        (id, out)
    }

    fn devs_policy() -> (String, BTreeMap<String, Binding>) {
        ("pub/ public devs\nfin/ finance\n".to_string(), BTreeMap::from([
            ("devs".to_string(), Binding::Group(GROUP_DEVS)),
            ("finance".to_string(), Binding::Group(GROUP_FIN)),
        ]))
    }

    fn rss() -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        let kib: u64 = s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse().unwrap();
        kib * 1024
    }

    /// `f`'s result, and how far the process's memory rose above where it
    /// was when `f` started.
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

    fn project_id(th: &TestHub, name: &str) -> i64 {
        let hub = th.hub();
        th.rt.block_on(async { sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&hub.db).await.unwrap() })
    }

    /// BUG-866: a member's push with a timestamp of `i64::MAX` overflows the
    /// generation of every snapshot built on it. Debug builds panic in the
    /// deriver on every run (the project's derived history stops for good);
    /// release builds wrap, so generations no longer decrease along parent
    /// edges and ancestry and merge-base walks answer wrongly.
    #[test]
    fn bug_866_a_far_future_timestamp_breaks_the_commit_graph() {
        let th = TestHub::start();
        let p = setup_project(&th);
        let api = th.api();
        // A dev (write access to src/ only) pushes a far-future snapshot,
        // then an ordinary one on top of it.
        let mut c = Craft::new(&api, &p.dev, &p.name, "main");
        let tip = c.tip;
        c.file("src/far-future-5e1a.txt", "x");
        let (_, r) = c.push_edited("main", Some(tip), |s| s.timestamp = i64::MAX);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["results"][0]["ok"], true, "{}", r.json());
        let mut c = Craft::new(&api, &p.dev, &p.name, "main");
        c.file("src/after-it-5e1a.txt", "y");
        let r = c.push("main", "built on it");
        assert_eq!(r.json()["results"][0]["ok"], true, "{}", r.json());
        let hub = th.hub();
        let pid = project_id(&th, &p.name);
        let run = th.rt.block_on(derive::catch_up(&hub, pid, derive::Scope::All));
        assert!(run.is_ok(), "deriving the project fails on every run: {run:?}");
        // Generations strictly decrease along every parent edge.
        let rows: Vec<(String, i64, String)> = th.rt.block_on(async {
            sqlx::query_as("SELECT snapshot, generation, parents FROM graph WHERE project_id = $1").bind(pid).fetch_all(&hub.db).await.unwrap()
        });
        let gen: HashMap<String, i64> = rows.iter().map(|(s, g, _)| (s.clone(), *g)).collect();
        for (s, g, parents) in &rows {
            for p in serde_json::from_str::<Vec<ObjectId>>(parents).unwrap() {
                let pg = gen.get(&p.hex()).copied().unwrap_or(0);
                assert!(*g > pg, "snapshot {s}: generation {g} not above its parent's {pg}");
            }
        }
    }

    /// BUG-867: one batch of the deriver holds every row and object of up
    /// to 512 snapshots in memory before writing. A member alternating one
    /// folder between two trees makes each snapshot change tens of thousands
    /// of paths for an upload of a few hundred bytes, so a single push
    /// drives the server's memory to gigabytes (512 x 100,000 paths: tens of
    /// GB).
    #[test]
    fn bug_867_a_derive_batch_holds_unbounded_memory() {
        // Memory is the whole process's: measured in a process of its own,
        // so other tests running beside it count for nothing.
        const CHILD: &str = "VEIL_BUG867_CHILD";
        if std::env::var(CHILD).is_err() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "derived::s12_adversarial::bug_867_a_derive_batch_holds_unbounded_memory", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            let line = stdout.lines().find(|l| l.contains("BUG-867:")).unwrap_or_default();
            println!("{line}");
            assert!(out.status.success() && stdout.contains("1 passed"), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
            return;
        }
        let th = TestHub::start();
        let (text, bindings) = devs_policy();
        let mut h = Hist::new(&th, &text, &bindings);
        let n_files: usize = std::env::var("VEIL_BUG867_FILES").ok().and_then(|s| s.parse().ok()).unwrap_or(50_000);
        let n_snaps: usize = std::env::var("VEIL_BUG867_SNAPSHOTS").ok().and_then(|s| s.parse().ok()).unwrap_or(48);
        let small = Files::from([("pub/keep.txt".to_string(), b"keep\n".to_vec())]);
        let mut big = small.clone();
        for i in 0..n_files {
            big.insert(format!("pub/bulk/{i:06}"), b"x".to_vec());
        }
        let (ta, oa) = tree_of(&big);
        let (tb, ob) = tree_of(&small);
        let mut tip = commit_tree(&th, &mut h, &[root_snapshot_id()], tb, ob, 1, 1);
        let mut objects = Some(oa);
        for k in 0..n_snaps {
            let t = if k % 2 == 0 { ta } else { tb };
            tip = commit_tree(&th, &mut h, &[tip], t, objects.take().unwrap_or_default(), 2 + k as u128, 2 + k as i64);
        }
        h.set_branch(&th, "main", tip);
        let (stats, grew) = peak_growth(|| h.derive(&th));
        assert_eq!(stats.snapshots, n_snaps + 1);
        println!("BUG-867: {n_snaps} snapshots of {n_files} changed paths each: memory rose {} MiB while deriving", grew >> 20);
        // The caches are bounded at 512 MiB together (objects and trees);
        // the batch itself should stay well under another 512 MiB.
        assert!(grew < 1 << 30, "memory rose {} MiB deriving one batch", grew >> 20);
    }

    /// BUG-868: every snapshot that changed more than 100,000 paths (`many`)
    /// is checked, against the trees, for every path of every later change
    /// on the same line. `many` snapshots cost a member nothing to make (one
    /// folder alternating between two trees, a few hundred bytes a
    /// snapshot), so after a push of them, everyone's later landings cost a
    /// multiple of what they did.
    #[test]
    fn bug_868_many_snapshots_slow_every_later_landing() {
        let th = TestHub::start();
        let n_many: usize = std::env::var("VEIL_BUG868_MANY").ok().and_then(|s| s.parse().ok()).unwrap_or(30);
        // The same history twice: the bulk folder just above the cap (many)
        // and just below it (listed).
        let land = |bulk: usize| -> Duration {
            let (text, bindings) = devs_policy();
            let mut h = Hist::new(&th, &text, &bindings);
            let small = Files::from([("pub/keep.txt".to_string(), b"keep\n".to_vec())]);
            let mut big = small.clone();
            for i in 0..bulk {
                big.insert(format!("pub/bulk/{i:06}"), b"x".to_vec());
            }
            let (ta, oa) = tree_of(&big);
            let (tb, ob) = tree_of(&small);
            let mut tip = commit_tree(&th, &mut h, &[root_snapshot_id()], tb, ob, 1, 1);
            let mut objects = Some(oa);
            for k in 0..n_many {
                let t = if k % 2 == 0 { ta } else { tb };
                tip = commit_tree(&th, &mut h, &[tip], t, objects.take().unwrap_or_default(), 2 + k as u128, 2 + k as i64);
            }
            h.set_branch(&th, "main", tip);
            h.derive(&th);
            // One ordinary landing of 5,000 new files elsewhere.
            let mut later = if n_many % 2 == 1 { big } else { small };
            for i in 0..5_000 {
                later.insert(format!("pub/other/{i:05}.txt"), format!("{i}\n").into_bytes());
            }
            let (tl, ol) = tree_of(&later);
            let tip = commit_tree(&th, &mut h, &[tip], tl, ol, 10_000, 10_000);
            h.set_branch(&th, "main", tip);
            let t = Instant::now();
            assert_eq!(h.derive(&th).snapshots, 1);
            t.elapsed()
        };
        let listed = land(derive::changes::MAX_PATHS - 10);
        let many = land(derive::changes::MAX_PATHS + 1);
        println!("BUG-868: a landing of 5,000 paths after {n_many} large changes: {listed:?} (listed) vs {many:?} (many)");
        assert!(many < listed * 3 + Duration::from_millis(500), "{many:?} vs {listed:?}");
    }

    /// BUG-869: `Reader::visible` of a merge asks `rep` of its parents,
    /// which asks `visible` of the next merge down: one stack frame pair per
    /// merge. A member's push of a few thousand merges (100,000 are allowed
    /// in one push) makes the first `visible` or `rep` of the tip overflow
    /// the thread's stack, which aborts the whole server process. Run in a
    /// child process, which the overflow kills.
    #[test]
    fn bug_869_a_chain_of_merges_overflows_the_readers_stack() {
        const CHILD: &str = "VEIL_BUG869_CHILD";
        if std::env::var(CHILD).is_err() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "derived::s12_adversarial::bug_869_a_chain_of_merges_overflows_the_readers_stack", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "the reader's process died ({:?}): {}", out.status, err.lines().filter(|l| l.contains("overflow") || l.contains("BUG-869")).collect::<Vec<_>>().join(" | "));
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("1 passed"), "the child ran the test: {stdout}");
            return;
        }
        let th = TestHub::start();
        let (text, bindings) = devs_policy();
        let mut h = Hist::new(&th, &text, &bindings);
        let n: usize = std::env::var("VEIL_BUG869_MERGES").ok().and_then(|s| s.parse().ok()).unwrap_or(20_000);
        let (t0, o0) = tree_of(&Files::from([("pub/a.txt".to_string(), b"a\n".to_vec())]));
        let a = commit_tree(&th, &mut h, &[root_snapshot_id()], t0, o0, 1, 1);
        let (t1, o1) = tree_of(&Files::from([("pub/a.txt".to_string(), b"b\n".to_vec())]));
        let mut tip = commit_tree(&th, &mut h, &[a], t1, o1, 2, 2);
        // Each merge takes `a` in again and changes nothing.
        for k in 0..n {
            tip = commit_tree(&th, &mut h, &[tip, a], t1, Vec::new(), 3 + k as u128, 3 + k as i64);
        }
        h.set_branch(&th, "main", tip);
        h.derive(&th);
        eprintln!("BUG-869: {n} merges derived; asking visible(tip)");
        let project = h.project(&th);
        let ok = th
            .rt
            .block_on(derive::read(&h.hub, h.id, move |g| {
                let lines = g.cx.lines()?;
                let anyone = Viewer::default();
                let view = project.view(&anyone);
                let r = Reader::new(g, &lines, &view);
                r.visible(&tip)
            }))
            .unwrap();
        assert!(ok);
    }

    /// BUG-870: every run of the deriver writes one `derive_progress` row
    /// per branch, and every landing projects every branch tip for every
    /// view key (`memo_tips`), whether or not the branch moved. Any
    /// participant may create branches, with no limit (one push may create
    /// thousands, all naming one snapshot), so one landing then costs
    /// thousands of statements per view key.
    #[test]
    fn bug_870_branches_multiply_the_work_of_every_landing() {
        let th = TestHub::start();
        let n_branches: usize = std::env::var("VEIL_BUG870_BRANCHES").ok().and_then(|s| s.parse().ok()).unwrap_or(3_000);
        let land = |branches: usize| -> Duration {
            let (text, bindings) = policy(1);
            let mut h = Hist::new(&th, &text, &bindings);
            let (t0, o0) = tree_of(&Files::from([("pub/a.txt".to_string(), b"a\n".to_vec())]));
            let a = commit_tree(&th, &mut h, &[root_snapshot_id()], t0, o0, 1, 1);
            h.set_branch(&th, "main", a);
            let (hub, id) = (h.hub.clone(), h.id);
            th.rt.block_on(async {
                again(|| {
                    sqlx::query("INSERT INTO branches (project_id, name, target) SELECT $1, 'b' || n, $2 FROM generate_series(1, $3) AS n ON CONFLICT DO NOTHING")
                        .bind(id)
                        .bind(a.hex())
                        .bind(branches as i64)
                        .execute(&hub.db)
                })
                .await;
            });
            h.derive(&th);
            th.rt.block_on(derive::memo_tips(&hub, id, &["main".to_string()])).unwrap();
            // One landing on main: what derive::landed runs for it.
            let (t1, o1) = tree_of(&Files::from([("pub/a.txt".to_string(), b"b\n".to_vec())]));
            let b = commit_tree(&th, &mut h, &[a], t1, o1, 2, 2);
            h.set_branch(&th, "main", b);
            let t = Instant::now();
            assert_eq!(th.rt.block_on(derive::landing(&hub, id, vec!["main".to_string()])).unwrap().snapshots, 1);
            t.elapsed()
        };
        let one = land(0);
        let many = land(n_branches);
        println!("BUG-870: one landing with 1 branch: {one:?}; with {} branches: {many:?}", n_branches + 1);
        assert!(many < one * 5 + Duration::from_millis(500), "{many:?} vs {one:?}");
    }

    /// BUG-871: a change whose tree differs from its first parent's but
    /// changes no leaf (an empty folder added in `fin/`, which a finance
    /// member may write) is derived as `none`, and `Reader::visible` shows a
    /// one-parent `none` change to everyone. The projection hides it from
    /// whoever cannot read `fin/` (it collapses into its parent), so the
    /// reader disagrees with `sync::projected` and would show the change,
    /// its description and author to people without access.
    #[test]
    fn bug_871_a_change_of_an_empty_hidden_folder_is_visible_to_all() {
        let th = TestHub::start();
        let (text, bindings) = devs_policy();
        let mut h = Hist::new(&th, &text, &bindings);
        let files = Files::from([("pub/a.txt".to_string(), b"a\n".to_vec()), ("fin/b.txt".to_string(), b"b\n".to_vec())]);
        let (t0, mut o0) = tree_of(&files);
        let a = commit_tree(&th, &mut h, &[root_snapshot_id()], t0, std::mem::take(&mut o0), 1, 1);
        // The same files, and an empty folder fin/empty-4c1d.
        let fin_tree = {
            let mut out = Vec::new();
            let id = build_tree(&Files::from([("b.txt".to_string(), b"b\n".to_vec())]), &mut out);
            let Object::Tree(mut t) = Object::decode(&out.iter().find(|(i, _)| *i == id).unwrap().1).unwrap() else { panic!() };
            t.insert(TreeEntry::dir("empty-4c1d", empty_tree_id()));
            let raw = Object::Tree(t).encode();
            let fid = ObjectId::hash(&raw);
            out.push((fid, raw));
            (fid, out)
        };
        let pub_tree = {
            let mut out = Vec::new();
            let id = build_tree(&Files::from([("a.txt".to_string(), b"a\n".to_vec())]), &mut out);
            (id, out)
        };
        let root = Tree {
            entries: vec![TreeEntry::dir("fin", fin_tree.0), TreeEntry::dir("pub", pub_tree.0)],
        };
        let raw = Object::Tree(root).encode();
        let rid = ObjectId::hash(&raw);
        let mut objects = fin_tree.1;
        objects.extend(pub_tree.1);
        objects.push((rid, raw));
        let b = commit_tree(&th, &mut h, &[a], rid, objects, 2, 2);
        h.set_branch(&th, "main", b);
        h.derive(&th);
        let project = h.project(&th);
        let anyone = Viewer::default();
        let p = projections(&th, &h, &project, &anyone);
        let in_history = in_projected_history(&h, &p, &b);
        let visible = th
            .rt
            .block_on(derive::read(&h.hub, h.id, move |g| {
                let lines = g.cx.lines()?;
                let view = project.view(&anyone);
                Reader::new(g, &lines, &view).visible(&b)
            }))
            .unwrap();
        assert!(!in_history, "the projection hides the change of fin/ only");
        assert_eq!(visible, in_history, "the reader shows anyone on Earth a change of fin/ only");
    }
}
