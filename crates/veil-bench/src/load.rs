//! The server load test (`veil-bench load`): many simulated agents
//! pulling from and landing changes on projects of one Veil server, to
//! measure scaling curves (`docs/design/scale/LOAD.md`).
//!
//! An agent speaks the server's API as `vl` does, in process (a separate
//! `vl` per operation would measure process starts, not the server):
//!
//! * **pull:** the tips; when `main` moved, the history down to the tip it
//!   knows, then the new trees and files level by level, only what it
//!   does not hold yet (`vl pull`, `crates/vl/src/hub.rs`);
//! * **api:** one new file in its own directory, committed through the
//!   API (`POST …/changes`, `docs/HUB.md` §13.13) on the tip it last saw,
//!   with `onto main` and `"rebase"`: no pull and no upload. When `main`
//!   moved, the server applies the file to the new tip itself; a change
//!   rejected after its rebases (a *collision*) asks for the tips and
//!   tries again;
//! * **landing:** one new file in its own directory, submitted to the
//!   landing service (`POST …/land`, `docs/HUB.md` §13.19) on the snapshot
//!   it last saw (its own last landing): no pull, no upload, no race. The
//!   request answers once the change landed, in a batch with the others
//!   that arrived meanwhile; a conflict or a refusal (a *collision*) asks
//!   for the tips and submits again;
//! * **land:** a pull, then a new file in its own directory on top of that
//!   `main` (a blob and the trees above it, and a signed snapshot),
//!   uploaded, then pushed as a compare-and-swap of `main`. When `main`
//!   moved meanwhile (409, a *collision*) it pulls and tries again on the
//!   new tip, as an agent rebasing would. Changes never overlap, so every
//!   retry is a lost race on the one row, never a content conflict.
//!
//! Agents are members of group `agents`, which may read and write `w/`;
//! `.veilpolicy` is private to the admin, so every agent reads projected
//! history and every landing is completed by the server (the real path,
//! not an admin's shortcut). All agents of one run sign in as one person,
//! as agents run by one person do.
//!
//! A *run* is one point of a curve: `projects` new projects, `clients`
//! agents spread over them, for `duration` after a warm-up. In `land`
//! mode, `rate` is the target aggregate landings per second (open loop:
//! landings are scheduled at that rate and latency counts from the
//! scheduled time) or `max` (closed loop: every agent lands again as soon
//! as it is done). In `pull` mode every agent pulls in a closed loop while
//! one lander per project moves `main` at `background` landings per
//! second.
//!
//! In `branches` mode every agent lands on a branch of its own in one
//! project (`a/NNNN`, made from `main` by its first push): pushes never
//! collide, so a run measures what one push costs.
//!
//! In `objects` mode (S9, `docs/HUB.md` §13.18) every agent reads as a
//! fresh thin workspace, in a closed loop: the tips and its read grant from
//! the server, then through the object routes (`--via cache`: a regional
//! cache this tool starts in front of the server; `--via server`: the server
//! itself) the root tree, `w/`, `w/seed/` (1,000 files of 4 KiB) and 100 of
//! its files, each request signed by its device. One lander per project
//! moves `main` at `background` landings per second meanwhile. Measured
//! besides: the cache's hit share (objects it served from its store, of all
//! it served), its CPU and its peak memory. **Gates** (`--via cache`): at
//! least 99 % of objects from the cache's store, and its peak memory at
//! most 512 MiB.
//!
//! Measured per run: operations per second, latency p50/p99, collisions
//! and retries per landing, errors, and when known the server's CPU per
//! operation (`--server-pid`, or the server this tool started), the
//! database's CPU (processes named `postgres`, `yb-tserver` or
//! `yb-master` on this machine), database statements per operation
//! (`pg_stat_statements` if it is loaded, else transactions from
//! `pg_stat_database`) and this tool's own CPU.
//!
//! **Cost per operation** (`docs/design/server/storage-and-cost.md` §9):
//! database commits (transactions that wrote and committed: the ids
//! PostgreSQL assigned in the window, each checked with `txid_status`), of
//! which the deriver's background writes (S12), statements, storage writes
//! and reads (the server this tool started writes its counters on
//! `SIGUSR1`), and bytes sent and received.
//! **Gates**, which fail the run: at most 1 database commit per landing,
//! the deriver's background work aside (`land`, `branches`), and at most 5
//! statements per pull with warm caches when nothing changed (`pull` with
//! `--background 0`).

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Barrier, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Result};
use serde_json::json;
use veil_core::{
    hub::grant::{sign_request, BatchRequest, ChainWant, Grant},
    hub::wire::{put_frame, read_frames, BranchUpdate, FetchRequest, HistoryRequest, PushRequest, PushResult, Tips, Want},
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEncoding, TreeEntry, Visibility},
    ChangeId, Identity, ObjectId,
};

/// What the agents do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Pull,
    Land,
    /// Land on a branch of one's own.
    Branches,
    Api,
    /// Through the landing service.
    Landing,
    /// Read as fresh thin workspaces, through the object routes.
    Objects,
}

/// The cost gates (`storage-and-cost.md` §9).
pub const GATE_COMMITS_PER_PUSH: f64 = 1.0;
/// Database commits per landing through the landing service (phase 4 §7):
/// the submit's, and its share of its batch's.
pub const GATE_COMMITS_PER_LANDING: f64 = 1.5;
pub const GATE_STATEMENTS_PER_WARM_PULL: f64 = 5.0;
/// `objects` through a regional cache: the share of objects it serves from
/// its store, and its peak memory (it runs with the default `--memory 128M` and
/// 1,024 connections: a bound of about 480 MiB, `docs/HUB.md` §13.18).
pub const GATE_CACHE_HITS: f64 = 0.99;
pub const GATE_CACHE_MIB: f64 = 512.0;

/// Files of `w/seed/` in an `objects` run's projects, and how many of
/// them each read takes.
const SEED_FILES: usize = 1000;
const READ_FILES: usize = 100;

/// Request and response bytes of every agent (counted in windows).
static BYTES_SENT: AtomicU64 = AtomicU64::new(0);
static BYTES_RECEIVED: AtomicU64 = AtomicU64::new(0);

/// Target aggregate landings per second, or as fast as the agents go.
#[derive(Clone, Copy, Debug)]
pub enum Rate {
    Max,
    PerSecond(f64),
}

impl std::str::FromStr for Rate {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Rate, String> {
        match s {
            "max" => Ok(Rate::Max),
            _ => s.parse::<f64>().ok().filter(|r| *r > 0.0).map(Rate::PerSecond).ok_or_else(|| format!("rate {s}: a number or `max`")),
        }
    }
}

pub struct Args {
    /// A running server (`https://host:port`); `None`: start `server`.
    pub url: Option<String>,
    /// Its certificate (PEM), for a self-signed one.
    pub ca: Option<PathBuf>,
    /// The server to start here when no `url` is given (its
    /// `database_url` also serves the statement counts).
    pub server: crate::server::ServerArgs,
    pub db_connections: u32,
    /// The server's process, for its CPU (the one started here if none).
    pub server_pid: Option<u32>,
    pub dir: PathBuf,
    pub mode: Mode,
    pub projects: Vec<usize>,
    pub clients: Vec<usize>,
    pub rates: Vec<Rate>,
    pub duration: Duration,
    pub warmup: Duration,
    /// Landings per second per project while agents pull.
    pub background: f64,
    /// Count only the database processes of this container (an id prefix,
    /// as `/proc/PID/cgroup` names it).
    pub db_container: Option<String>,
    /// `objects`: read through a regional cache (`true`) or the server, one
    /// set of curves each.
    pub vias: Vec<bool>,
}

// ---- the HTTP client ------------------------------------------------------------------------

/// One connection's worth of API (each agent has its own).
struct Api {
    agent: ureq::Agent,
    base: String,
    authority: String,
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}

impl Api {
    fn new(base: &str, ca: Option<&str>) -> Result<Api> {
        let mut tls = ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::Rustls);
        if let Some(pem) = ca {
            let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(pem.as_bytes())
                .filter_map(|i| match i {
                    Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
                    _ => None,
                })
                .collect();
            tls = tls.root_certs(ureq::tls::RootCerts::Specific(Arc::new(certs)));
        }
        let agent = ureq::Agent::config_builder()
            .tls_config(tls.build())
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(120)))
            .build()
            .new_agent();
        let authority = base.trim_start_matches("https://").trim_end_matches('/').to_string();
        Ok(Api {
            agent,
            base: base.trim_end_matches('/').to_string(),
            authority,
        })
    }

    fn finish(r: std::result::Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Reply> {
        let r = r?;
        let status = r.status().as_u16();
        let body = r.into_body().with_config().limit(1 << 32).read_to_vec()?;
        BYTES_RECEIVED.fetch_add(body.len() as u64, Ordering::Relaxed);
        Ok(Reply { status, body })
    }

    fn get(&self, token: &str, path: &str) -> Result<Reply> {
        Self::finish(self.agent.get(format!("{}{path}", self.base)).header("authorization", &format!("Bearer {token}")).call())
    }

    fn post(&self, token: Option<&str>, path: &str, body: &[u8], json: bool) -> Result<Reply> {
        let mut r = self.agent.post(format!("{}{path}", self.base));
        if let Some(t) = token {
            r = r.header("authorization", &format!("Bearer {t}"));
        }
        r = r.header("content-type", if json { "application/json" } else { "application/octet-stream" });
        BYTES_SENT.fetch_add(body.len() as u64, Ordering::Relaxed);
        Self::finish(r.send(body))
    }

    fn post_json(&self, token: Option<&str>, path: &str, v: &impl serde::Serialize) -> Result<Reply> {
        self.post(token, path, &serde_json::to_vec(v)?, true)
    }

    /// Sign in as `id`, registering `name`; the session token.
    fn login(&self, id: &Identity, name: &str) -> Result<String> {
        let ch = self.post_json(None, "/v1/auth/challenge", &json!({"key": id.verifying_hex()}))?;
        ok(&ch, "challenge")?;
        let ch: serde_json::Value = serde_json::from_slice(&ch.body)?;
        let challenge = ch["challenge"].as_str().ok_or_else(|| anyhow!("no challenge"))?.to_string();
        let sig = id.sign(veil_core::crypto::domains::SIG_CONTEXT_HUB_LOGIN, &veil_core::hub::wire::login_message(&self.authority, &challenge));
        let r = self.post_json(
            None,
            "/v1/auth/login",
            &json!({"key": id.verifying_hex(), "challenge": challenge, "hub": self.authority,
                "signature": sig, "identity": id.public_id(), "name": name}),
        )?;
        ok(&r, "login")?;
        let s: serde_json::Value = serde_json::from_slice(&r.body)?;
        Ok(s["token"].as_str().ok_or_else(|| anyhow!("no token"))?.to_string())
    }
}

fn ok(r: &Reply, what: &str) -> Result<()> {
    if r.status != 200 {
        bail!("{what}: HTTP {} {}", r.status, String::from_utf8_lossy(&r.body));
    }
    Ok(())
}

// ---- an agent's clone -----------------------------------------------------------------------

fn root_snapshot_id() -> ObjectId {
    let empty = ObjectId::hash(&Object::Tree(Tree::default()).encode());
    ObjectId::hash(&Object::Snapshot(Snapshot::root(empty)).encode())
}

/// What one agent holds of one project.
#[derive(Default)]
struct Held {
    /// `main` as this agent last saw it, and its root tree.
    tip: Option<(ObjectId, ObjectId)>,
    have: HashSet<ObjectId>,
    trees: HashMap<ObjectId, Arc<Tree>>,
}

/// Counters of one run, shared by its agents. Events count while
/// `measuring` is set, when they happen (a landing that never finishes
/// still counts its collisions).
#[derive(Default)]
struct Counters {
    measuring: AtomicBool,
    ops: AtomicU64,
    collisions: AtomicU64,
    busy: AtomicU64,
    errors: AtomicU64,
    requests: AtomicU64,
    /// Landings that were up to date (pull mode: nothing to fetch).
    noop: AtomicU64,
    latencies: Mutex<Vec<f64>>,
    /// Agents that finished an operation while measuring (fairness: a hot
    /// row lets one agent win every race).
    finished_agents: Mutex<HashSet<usize>>,
    first_error: Mutex<Option<String>>,
}

impl Counters {
    fn count(&self, what: &AtomicU64, n: u64) {
        if self.measuring.load(Ordering::Relaxed) {
            what.fetch_add(n, Ordering::Relaxed);
        }
    }

    fn error(&self, e: &anyhow::Error) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        let mut f = self.first_error.lock().unwrap();
        if f.is_none() {
            *f = Some(format!("{e:#}"));
        }
    }
}

struct Agent<'a> {
    api: Api,
    token: &'a str,
    identity: &'a Identity,
    project: String,
    /// This agent's directory, `w/gNN/aNNNN`.
    dir: Vec<String>,
    /// The branch it lands on (`main`, or its own in `branches` mode), and
    /// whether that exists yet.
    branch: String,
    exists: bool,
    clone: Held,
    files: u64,
    c: &'a Counters,
    /// `objects` through a regional cache: its API.
    objects: Option<Api>,
}

impl Agent<'_> {
    fn path(&self, p: &str) -> String {
        format!("/v1/projects/{}{p}", self.project)
    }

    /// `vl pull`, as the server sees it. `true` if `main` had moved.
    fn pull(&mut self) -> Result<bool> {
        self.c.requests.fetch_add(1, Ordering::Relaxed);
        let r = self.api.get(self.token, &self.path("/tips"))?;
        ok(&r, "tips")?;
        let tips: Tips = serde_json::from_slice(&r.body)?;
        // A branch of its own starts from `main`.
        self.exists = tips.branches.contains_key(&self.branch);
        let tip = *tips.branches.get(&self.branch).or_else(|| tips.branches.get("main")).ok_or_else(|| anyhow!("no main"))?;
        if self.clone.tip.is_some_and(|(t, _)| t == tip) {
            return Ok(false);
        }
        self.c.requests.fetch_add(1, Ordering::Relaxed);
        let stop: Vec<ObjectId> = self.clone.tip.map(|(t, _)| t).into_iter().collect();
        let h = self.api.post_json(Some(self.token), &self.path("/history"), &HistoryRequest { tips: vec![tip], stop })?;
        ok(&h, "history")?;
        let mut new = Vec::new();
        let mut tip_tree = None;
        for (id, raw) in read_frames(&h.body)? {
            if ObjectId::hash(raw) != id {
                bail!("history: an object does not match its id");
            }
            let Object::Snapshot(s) = Object::decode(raw)? else { bail!("history: not a snapshot") };
            if id == tip {
                tip_tree = Some(s.tree);
            }
            self.clone.have.insert(id);
            new.push((id, s.tree));
        }
        let tip_tree = match tip_tree {
            Some(t) => t,
            None => bail!("history: the tip is missing"),
        };
        // Each new snapshot's trees from the root down, then the files: one
        // request per snapshot and level, as `vl pull` asks.
        let mut frontier: Vec<(ObjectId, String, ObjectId)> = Vec::new();
        let mut seen = HashSet::new();
        for (snap, t) in new {
            if !self.clone.have.contains(&t) && seen.insert(t) {
                frontier.push((snap, String::new(), t));
            }
        }
        // A server of revision 1 takes every snapshot's wants at once.
        let across = tips.revision >= 1;
        while !frontier.is_empty() {
            let mut by_snap: HashMap<ObjectId, Vec<(String, ObjectId, ObjectId)>> = HashMap::new();
            for (snap, path, id) in frontier.drain(..) {
                let key = match across {
                    true => *by_snap.keys().next().unwrap_or(&snap),
                    false => snap,
                };
                by_snap.entry(key).or_default().push((path, id, snap));
            }
            let mut next = Vec::new();
            for (key, wants) in by_snap {
                self.c.requests.fetch_add(1, Ordering::Relaxed);
                let objects: Vec<Want> =
                    wants.iter().map(|(path, id, snap)| Want { path: path.clone(), id: *id, snapshot: (*snap != key).then_some(*snap) }).collect();
                let r = self.api.post_json(Some(self.token), &self.path("/fetch"), &FetchRequest { snapshot: key, objects })?;
                ok(&r, "fetch")?;
                let got = read_frames(&r.body)?;
                if got.len() != wants.len() {
                    bail!("fetch: {} objects for {} asked", got.len(), wants.len());
                }
                for ((path, want, snap), (id, raw)) in wants.iter().zip(got) {
                    if id != *want || ObjectId::hash(raw) != id {
                        bail!("fetch: another object than asked");
                    }
                    if let Object::Tree(t) = Object::decode(raw)? {
                        for e in &t.entries {
                            if !self.clone.have.contains(&e.id) && seen.insert(e.id) {
                                let p = if path.is_empty() { e.name.clone() } else { format!("{path}/{}", e.name) };
                                next.push((*snap, p, e.id));
                            }
                        }
                        self.clone.trees.insert(id, Arc::new(t));
                    }
                    self.clone.have.insert(id);
                }
            }
            frontier = next;
        }
        self.clone.tip = Some((tip, tip_tree));
        Ok(true)
    }

    /// Pull, then land one new file on `main` (as `vl pull` then `vl
    /// push`); the number of collisions on the way: pushes that lost to
    /// another landing between this agent's pull and its push.
    fn land(&mut self, deadline: Instant) -> Result<u64> {
        self.pull()?;
        let mut collisions = 0;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            if Instant::now() > deadline {
                bail!("no landing within the deadline after {collisions} collisions");
            }
            let Some((tip, root)) = self.clone.tip else {
                self.pull()?;
                continue;
            };
            self.files += 1;
            let mut objects: Vec<(ObjectId, Vec<u8>)> = Vec::new();
            let mut put = |o: Object| {
                let raw = o.encode_with(TreeEncoding::Binary);
                let id = ObjectId::hash(&raw);
                objects.push((id, raw));
                id
            };
            let body = format!("agent file {} of {}\n", self.files, self.dir.join("/"));
            let size = body.len() as u64;
            let blob = put(Object::Blob(body.into_bytes()));
            let name = format!("f{:06}", self.files);
            // The trees on the way down, then back up with the new entry.
            let mut chain: Vec<Tree> = Vec::new();
            let mut cur = Some(root);
            for part in &self.dir {
                let t = match cur {
                    Some(id) => (*self.clone.trees.get(&id).ok_or_else(|| anyhow!("tree {} not held", id.short()))?.as_ref()).clone(),
                    None => Tree::default(),
                };
                cur = t.get(part).filter(|e| e.kind == EntryKind::Dir).map(|e| e.id);
                chain.push(t);
            }
            let mut leaf = match cur {
                Some(id) => (*self.clone.trees.get(&id).ok_or_else(|| anyhow!("tree {} not held", id.short()))?.as_ref()).clone(),
                None => Tree::default(),
            };
            leaf.insert(TreeEntry {
                name,
                kind: EntryKind::File,
                id: blob,
                size,
                executable: false,
                visibility: Visibility::Public,
            });
            let mut child = put(Object::Tree(leaf));
            for (t, part) in chain.into_iter().zip(&self.dir).rev() {
                let mut t = t;
                t.remove(part);
                t.insert(TreeEntry::dir(part, child));
                child = put(Object::Tree(t));
            }
            let mut s = Snapshot {
                parents: vec![tip],
                change_id: ChangeId::random(),
                tree: child,
                description: Text::Plain(format!("land {}", self.files)),
                author: "agent".into(),
                timestamp: veil_core::now_millis(),
                predecessors: vec![],
                conflicts: vec![],
                embargo: None,
                signature: None,
            };
            s.sign(self.identity);
            let snap = put(Object::Snapshot(s));
            let mut frames = Vec::new();
            for (id, raw) in &objects {
                put_frame(&mut frames, id, raw);
            }
            self.c.requests.fetch_add(2, Ordering::Relaxed);
            let up = self.api.post(Some(self.token), &self.path("/objects"), &frames, false)?;
            if up.status == 503 {
                self.c.count(&self.c.busy, 1);
                backoff(attempt);
                continue;
            }
            ok(&up, "upload")?;
            let up: serde_json::Value = serde_json::from_slice(&up.body)?;
            let receipts = up["receipts"].as_array().ok_or_else(|| anyhow!("no receipts"))?;
            let receipts = objects
                .iter()
                .zip(receipts)
                .map(|((id, _), r)| Ok((*id, r.as_str().ok_or_else(|| anyhow!("bad receipt"))?.to_string())))
                .collect::<Result<_>>()?;
            let req = PushRequest {
                updates: vec![BranchUpdate {
                    branch: self.branch.clone(),
                    expected: self.exists.then_some(tip),
                    new: Some(snap),
                }],
                force: false,
                receipts,
            };
            let r = self.api.post_json(Some(self.token), &self.path("/push"), &req)?;
            match r.status {
                200 => {
                    let res: PushResult = serde_json::from_slice(&r.body)?;
                    let b = res.results.first().ok_or_else(|| anyhow!("no result"))?;
                    if !b.ok {
                        // Lost the race inside the push (moved meanwhile).
                        collisions += 1;
                        self.c.count(&self.c.collisions, 1);
                        self.pull()?;
                        continue;
                    }
                    self.exists = true;
                    // What was made is held; the server shows the pusher
                    // its own snapshot back.
                    for (id, raw) in objects {
                        if let Ok(Object::Tree(t)) = Object::decode(&raw) {
                            self.clone.trees.insert(id, Arc::new(t));
                        }
                        self.clone.have.insert(id);
                    }
                    match b.tip {
                        Some(t) if t == snap => self.clone.tip = Some((snap, child)),
                        _ => {
                            self.clone.tip = None;
                            self.pull()?;
                        }
                    }
                    return Ok(collisions);
                }
                409 => {
                    collisions += 1;
                    self.c.count(&self.c.collisions, 1);
                    self.pull()?;
                }
                503 => {
                    self.c.count(&self.c.busy, 1);
                    backoff(attempt);
                }
                _ => ok(&r, "push").map(|_| ())?,
            }
        }
    }
}

impl Agent<'_> {
    /// `--mode objects`: what a fresh thin workspace reads (see the
    /// module's comment); the objects it read.
    fn read(&mut self) -> Result<u64> {
        self.c.requests.fetch_add(1, Ordering::Relaxed);
        let r = self.api.get(self.token, &self.path("/tips"))?;
        ok(&r, "tips")?;
        let tips: Tips = serde_json::from_slice(&r.body)?;
        let token = tips.grants.get("main").ok_or_else(|| anyhow!("no grant for main"))?;
        let grant = Grant::verify(token, tips.grant_key.as_deref().unwrap_or_default()).ok_or_else(|| anyhow!("a grant that does not verify"))?;
        let via = self.objects.as_ref().unwrap_or(&self.api);
        let path = format!("/v1/objects/{}:batch", self.project);
        // A batch, asking again for what did not arrive (a cache leaves out
        // an object it lost since its check).
        let batch = |wants: Vec<(Vec<ObjectId>, ObjectId)>| -> Result<HashMap<ObjectId, Vec<u8>>> {
            let mut got = HashMap::new();
            let mut left = wants;
            for _ in 0..3 {
                self.c.requests.fetch_add(1, Ordering::Relaxed);
                let ids: Vec<ObjectId> = left.iter().map(|w| w.1).collect();
                let ts = veil_core::now_millis();
                let req = BatchRequest {
                    grant: token.clone(),
                    ts,
                    signature: Some(sign_request(self.identity, &grant, ts, &ids)),
                    wants: left.iter().map(|(chain, id)| ChainWant { chain: chain.clone(), id: *id }).collect(),
                    skip: Vec::new(),
                };
                let r = via.post(None, &path, &serde_json::to_vec(&req)?, true)?;
                ok(&r, "objects")?;
                for (id, raw) in read_frames(&r.body)? {
                    got.insert(id, raw.to_vec());
                }
                left.retain(|w| !got.contains_key(&w.1));
                if left.is_empty() {
                    return Ok(got);
                }
            }
            bail!("objects: {} never arrived", left.len())
        };
        let tree = |raw: &[u8]| -> Result<Tree> {
            match Object::decode(raw)? {
                Object::Tree(t) => Ok(t),
                _ => bail!("objects: not a tree"),
            }
        };
        let entry = |t: &Tree, name: &str| t.entries.iter().find(|e| e.name == name).map(|e| e.id).ok_or_else(|| anyhow!("objects: no {name}"));
        let root = grant.body.root;
        let t = tree(&batch(vec![(vec![], root)])?[&root])?;
        let w = entry(&t, "w")?;
        let wt = tree(&batch(vec![(vec![root], w)])?[&w])?;
        let seed = entry(&wt, "seed")?;
        let st = tree(&batch(vec![(vec![root, w], seed)])?[&seed])?;
        let start = u16::from_le_bytes(veil_core::crypto::random_bytes::<2>()) as usize;
        let files: Vec<(Vec<ObjectId>, ObjectId)> =
            (0..READ_FILES.min(st.entries.len())).map(|i| (vec![root, w, seed], st.entries[(start + i) % st.entries.len()].id)).collect();
        let n = files.len();
        batch(files)?;
        Ok(3 + n as u64)
    }

    /// Land one new file through the API (`--mode api`); the collisions on
    /// the way: rebases the server made, and rejections after them.
    fn land_api(&mut self, deadline: Instant) -> Result<u64> {
        let mut collisions = 0;
        let mut attempt = 0u32;
        self.files += 1;
        let path = format!("{}/f{:06}", self.dir.join("/"), self.files);
        loop {
            attempt += 1;
            if Instant::now() > deadline {
                bail!("no landing within the deadline after {collisions} collisions");
            }
            let base = match self.clone.tip {
                Some((t, _)) => t,
                None => {
                    self.c.requests.fetch_add(1, Ordering::Relaxed);
                    let r = self.api.get(self.token, &self.path("/tips"))?;
                    ok(&r, "tips")?;
                    let tips: Tips = serde_json::from_slice(&r.body)?;
                    *tips.branches.get("main").ok_or_else(|| anyhow!("no main"))?
                }
            };
            self.c.requests.fetch_add(1, Ordering::Relaxed);
            let req = json!({"base": base.hex(), "description": format!("land {}", self.files),
                "edits": [{"path": path, "put": {"text": format!("agent file {} of {}\n", self.files, self.dir.join("/"))}}],
                "onto": {"branch": "main", "expected": "rebase"}});
            let r = self.api.post_json(Some(self.token), &self.path("/changes"), &req)?;
            if r.status == 503 {
                self.c.count(&self.c.busy, 1);
                backoff(attempt);
                continue;
            }
            ok(&r, "change")?;
            let v: serde_json::Value = serde_json::from_slice(&r.body)?;
            let rebased = v["branch"]["rebased"].as_u64().unwrap_or(0);
            collisions += rebased;
            self.c.count(&self.c.collisions, rebased);
            if v["branch"]["status"] == "ok" {
                let mine: ObjectId = serde_json::from_value(v["snapshot"].clone())?;
                self.clone.tip = Some((mine, mine));
                return Ok(collisions);
            }
            collisions += 1;
            self.c.count(&self.c.collisions, 1);
            self.clone.tip = None;
        }
    }
}

impl Agent<'_> {
    /// Land one new file through the landing service (`--mode landing`);
    /// the collisions on the way: conflicts and refusals, each followed by
    /// a new submit on the tip.
    fn land_service(&mut self, deadline: Instant) -> Result<u64> {
        let mut collisions = 0;
        let mut attempt = 0u32;
        self.files += 1;
        let path = format!("{}/f{:06}", self.dir.join("/"), self.files);
        loop {
            attempt += 1;
            if Instant::now() > deadline {
                bail!("no landing within the deadline after {collisions} collisions");
            }
            let base = match self.clone.tip {
                Some((t, _)) => t,
                None => {
                    self.c.requests.fetch_add(1, Ordering::Relaxed);
                    let r = self.api.get(self.token, &self.path("/tips"))?;
                    ok(&r, "tips")?;
                    let tips: Tips = serde_json::from_slice(&r.body)?;
                    *tips.branches.get("main").ok_or_else(|| anyhow!("no main"))?
                }
            };
            self.c.requests.fetch_add(1, Ordering::Relaxed);
            let req = json!({"onto": "main", "base": base.hex(), "description": format!("land {}", self.files),
                "edits": [{"path": path, "put": {"text": format!("agent file {} of {}\n", self.files, self.dir.join("/"))}}]});
            let r = self.api.post_json(Some(self.token), &self.path("/land"), &req)?;
            if r.status == 503 {
                self.c.count(&self.c.busy, 1);
                backoff(attempt);
                continue;
            }
            ok(&r, "land")?;
            let v: serde_json::Value = serde_json::from_slice(&r.body)?;
            match v["state"].as_str() {
                Some("landed") => {
                    let mine: ObjectId = serde_json::from_value(v["landed"].as_array().and_then(|l| l.last()).cloned().unwrap_or_default())?;
                    self.clone.tip = Some((mine, mine));
                    return Ok(collisions);
                }
                Some("queued") => bail!("still queued after the server's wait: {v}"),
                _ => {
                    collisions += 1;
                    self.c.count(&self.c.collisions, 1);
                    self.clone.tip = None;
                }
            }
        }
    }
}

/// Capped, jittered backoff after a busy server.
fn backoff(attempt: u32) {
    let cap = 5u64 << attempt.min(6);
    let jitter = u64::from(veil_core::crypto::random_bytes::<1>()[0]) % cap.max(1);
    std::thread::sleep(Duration::from_millis(cap / 2 + jitter));
}

// ---- measurements of the machine ------------------------------------------------------------

/// CPU seconds (user + system) of process `pid`.
fn cpu_of(pid: u32) -> Option<f64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    let f: Vec<&str> = rest.split_whitespace().collect();
    let ticks: f64 = f.get(11)?.parse::<f64>().ok()? + f.get(12)?.parse::<f64>().ok()?;
    Some(ticks / clock_ticks())
}

fn clock_ticks() -> f64 {
    // SAFETY: sysconf has no preconditions.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 {
        t as f64
    } else {
        100.0
    }
}

/// CPU seconds of every database process on this machine (of container
/// `container` only, when given).
fn db_cpu(container: Option<&str>) -> f64 {
    let Ok(d) = std::fs::read_dir("/proc") else { return 0.0 };
    d.flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()))
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .is_ok_and(|c| matches!(c.trim(), "postgres" | "yb-tserver" | "yb-master"))
                && container.is_none_or(|id| std::fs::read_to_string(format!("/proc/{pid}/cgroup")).is_ok_and(|g| g.contains(id)))
        })
        .filter_map(cpu_of)
        .sum()
}

/// Explicit transactions committed (`COMMIT`) and write statements
/// (`INSERT`, `UPDATE`, `DELETE`, in a transaction or not) the database
/// ran so far, if `pg_stat_statements` is loaded: the cost gates of
/// `docs/design/server/storage-and-cost.md` §9.
fn db_writes(rt: &tokio::runtime::Runtime, url: &str) -> Option<(f64, f64)> {
    rt.block_on(async {
        let mut c = <sqlx::PgConnection as sqlx::Connection>::connect(url).await.ok()?;
        sqlx::query_as::<_, (f64, f64)>(
            "SELECT coalesce(sum(calls) FILTER (WHERE query ILIKE 'commit%'), 0)::float8, \
             coalesce(sum(calls) FILTER (WHERE query ~* '^\\s*(insert|update|delete)'), 0)::float8 FROM pg_stat_statements",
        )
        .fetch_one(&mut c)
        .await
        .ok()
    })
}

/// Statements the database ran so far (`pg_stat_statements`), or its
/// transactions (`pg_stat_database`): `(count, what was counted)`.
fn db_statements(rt: &tokio::runtime::Runtime, url: &str) -> Option<(f64, &'static str)> {
    rt.block_on(async {
        let mut c = <sqlx::PgConnection as sqlx::Connection>::connect(url).await.ok()?;
        if let Ok(n) = sqlx::query_scalar::<_, f64>("SELECT coalesce(sum(calls), 0)::float8 FROM pg_stat_statements").fetch_one(&mut c).await {
            return Some((n, "statements"));
        }
        let n = sqlx::query_scalar::<_, f64>("SELECT coalesce(sum(xact_commit + xact_rollback), 0)::float8 FROM pg_stat_database")
            .fetch_one(&mut c)
            .await
            .ok()?;
        Some((n, "transactions"))
    })
}

/// The next transaction id PostgreSQL will assign (`None` elsewhere:
/// YugabyteDB).
fn next_xid(rt: &tokio::runtime::Runtime, url: &str) -> Option<i64> {
    rt.block_on(async {
        let mut c = <sqlx::PgConnection as sqlx::Connection>::connect(url).await.ok()?;
        sqlx::query_scalar::<_, i64>("SELECT pg_snapshot_xmax(pg_current_snapshot())::text::bigint").fetch_one(&mut c).await.ok()
    })
}

/// Transactions that wrote and committed among the ids `from..to`: each id
/// is one transaction that wrote (a read-only one gets none); a
/// compare-and-swap that lost a race took one and aborted.
fn db_commits(rt: &tokio::runtime::Runtime, url: &str, from: i64, to: i64) -> Option<f64> {
    rt.block_on(async {
        let mut c = <sqlx::PgConnection as sqlx::Connection>::connect(url).await.ok()?;
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM generate_series($1::bigint, $2::bigint - 1) x WHERE txid_status(x) = 'committed'",
        )
        .bind(from)
        .bind(to)
        .fetch_one(&mut c)
        .await
        .ok()
        .map(|n| n as f64)
    })
}

/// Executions of the deriver's own writes so far (S12, in the background
/// after a landing: `derive/mod.rs`), from `pg_stat_statements`: each is at
/// most one commit of its own.
fn deriver_writes(rt: &tokio::runtime::Runtime, url: &str) -> Option<f64> {
    rt.block_on(async {
        let mut c = <sqlx::PgConnection as sqlx::Connection>::connect(url).await.ok()?;
        sqlx::query_scalar::<_, f64>(
            "SELECT coalesce(sum(calls), 0)::float8 FROM pg_stat_statements WHERE query ~* \
             '^\\s*(INSERT INTO|UPDATE|DELETE FROM) (graph|file_history|rule_history|rule_lines|derive_progress)\\M'",
        )
        .fetch_one(&mut c)
        .await
        .ok()
    })
}

/// The counters of the server `pid` (which writes them to `file` at start
/// and on `SIGUSR1`): the answer to this signal, waited for up to 2 s.
fn server_stats(pid: u32, file: &std::path::Path) -> Option<serde_json::Value> {
    let read = || std::fs::read(file).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    // A server that never wrote the file does not answer SIGUSR1 (an older
    // build): the signal would end it.
    let before = read()?["n"].as_u64()?;
    // SAFETY: kill has no memory preconditions; the pid is our own child.
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGUSR1) } != 0 {
        return None;
    }
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(2) {
        if let Some(v) = read().filter(|v| v["n"].as_u64().is_some_and(|n| n > before)) {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    None
}

/// The gates one run missed (`storage-and-cost.md` §9).
pub fn missed_gates(r: &serde_json::Value, background: f64) -> Vec<String> {
    let mut out = Vec::new();
    let mode = r["mode"].as_str().unwrap_or("");
    // The design's gate is at its target rate, where batches fill (phase 4
    // §7); a landing alone in its batch costs two commits.
    if mode == "landing" && r["rate"].as_f64().is_none_or(|rate| rate >= 500.0) {
        let ops = r["ops"].as_f64().unwrap_or(0.0);
        if let Some(c) = r["db_push_commits_per_op"].as_f64().filter(|c| c * ops > GATE_COMMITS_PER_LANDING * ops * 1.02 + 20.0) {
            out.push(format!("landing: {c:.2} database commits per landing, the deriver's aside (gate: {GATE_COMMITS_PER_LANDING})"));
        }
    }
    if matches!(mode, "land" | "branches" | "api") {
        // A few landings straddle the window's edges, and the database's own
        // maintenance (autovacuum, analyze) takes a few transactions.
        let ops = r["ops"].as_f64().unwrap_or(0.0);
        let over = |c: f64| c * ops > GATE_COMMITS_PER_PUSH * ops * 1.02 + 20.0;
        if let Some(c) = r["db_push_commits_per_op"].as_f64().filter(|c| over(*c)) {
            out.push(format!("{mode}: {c:.2} database commits per landing, the deriver's aside (gate: {GATE_COMMITS_PER_PUSH})"));
        }
    }
    if mode == "objects" && r["via"] == "cache" {
        match r["cache_hit_share"].as_f64() {
            Some(h) if h >= GATE_CACHE_HITS => {}
            h => out.push(format!("objects: {} of objects from the cache's store (gate: {:.0} %)", h.map_or("–".into(), |h| format!("{:.2} %", h * 100.0)), GATE_CACHE_HITS * 100.0)),
        }
        match r["cache_peak_mib"].as_f64() {
            Some(m) if m <= GATE_CACHE_MIB => {}
            m => out.push(format!("objects: the cache's peak memory {} MiB (gate: {GATE_CACHE_MIB} MiB)", m.map_or("–".into(), |m| format!("{m:.0}")))),
        }
    }
    if mode == "pull" && background == 0.0 {
        if let Some(n) = r["db_per_op"].as_f64().filter(|n| *n > GATE_STATEMENTS_PER_WARM_PULL) {
            out.push(format!("pull: {n:.1} statements per up-to-date pull (gate: {GATE_STATEMENTS_PER_WARM_PULL})"));
        }
    }
    out
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

// ---- the run --------------------------------------------------------------------------------

fn unique(prefix: &str) -> String {
    format!("{prefix}{}", hex::encode(veil_core::crypto::random_bytes::<4>()))
}

/// Create a project as `admin`: group `agents` (with `agent`), the policy
/// `w/  agents`, and a first snapshot, with `seed` files of 4 KiB in
/// `w/seed/`.
fn create_project(api: &Api, admin: &Identity, admin_token: &str, agent: &str, seed: usize) -> Result<String> {
    let name = unique("load-");
    ok(&api.post_json(Some(admin_token), &format!("/v1/projects/{name}"), &json!({}))?, "create project")?;
    ok(&api.post_json(Some(admin_token), &format!("/v1/projects/{name}/groups/agents"), &json!({}))?, "create group")?;
    ok(&api.post_json(Some(admin_token), &format!("/v1/projects/{name}/groups/agents/members"), &json!({"people": [agent]}))?, "add agent")?;
    let mut objects = Vec::new();
    let mut put = |o: Object| {
        let raw = o.encode_with(TreeEncoding::Binary);
        let id = ObjectId::hash(&raw);
        objects.push((id, raw));
        id
    };
    let file = |name: &str, id: ObjectId, size: u64| TreeEntry {
        name: name.into(),
        kind: EntryKind::File,
        id,
        size,
        executable: false,
        visibility: Visibility::Public,
    };
    let policy = b"w/  agents\n".to_vec();
    let readme = b"agents land here\n".to_vec();
    let (pl, rl) = (policy.len() as u64, readme.len() as u64);
    let policy = put(Object::Blob(policy));
    let readme = put(Object::Blob(readme));
    let mut w = Tree::default();
    w.insert(file("README", readme, rl));
    if seed > 0 {
        let mut st = Tree::default();
        for i in 0..seed {
            let mut body = format!("seed file {i} of {name}\n").into_bytes();
            body.resize(4096, b'.');
            let id = put(Object::Blob(body));
            st.insert(file(&format!("f{i:05}"), id, 4096));
        }
        let st = put(Object::Tree(st));
        w.insert(TreeEntry::dir("seed", st));
    }
    let w = put(Object::Tree(w));
    let mut root = Tree::default();
    root.insert(file(".veilpolicy", policy, pl));
    root.insert(TreeEntry::dir("w", w));
    let root = put(Object::Tree(root));
    let mut s = Snapshot {
        parents: vec![root_snapshot_id()],
        change_id: ChangeId::random(),
        tree: root,
        description: Text::Plain("load test".into()),
        author: "admin".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
    };
    s.sign(admin);
    let snap = put(Object::Snapshot(s));
    let mut frames = Vec::new();
    for (id, raw) in &objects {
        put_frame(&mut frames, id, raw);
    }
    let up = api.post(Some(admin_token), &format!("/v1/projects/{name}/objects"), &frames, false)?;
    ok(&up, "upload")?;
    let up: serde_json::Value = serde_json::from_slice(&up.body)?;
    let receipts = objects
        .iter()
        .zip(up["receipts"].as_array().ok_or_else(|| anyhow!("no receipts"))?)
        .map(|((id, _), r)| (*id, r.as_str().unwrap_or_default().to_string()))
        .collect();
    let req = PushRequest {
        updates: vec![BranchUpdate {
            branch: "main".into(),
            expected: None,
            new: Some(snap),
        }],
        force: false,
        receipts,
    };
    let r = api.post_json(Some(admin_token), &format!("/v1/projects/{name}/push"), &req)?;
    ok(&r, "first push")?;
    let res: PushResult = serde_json::from_slice(&r.body)?;
    if !res.results.first().is_some_and(|b| b.ok) {
        bail!("first push refused: {}", String::from_utf8_lossy(&r.body));
    }
    Ok(name)
}

struct Ctx<'a> {
    base: &'a str,
    ca: Option<&'a str>,
    admin: &'a Identity,
    admin_token: &'a str,
    agent: &'a Identity,
    agent_name: &'a str,
    agent_token: &'a str,
    server_pid: Option<u32>,
    stats: Option<(&'a tokio::runtime::Runtime, &'a str)>,
    /// The server this tool started, and the file its `SIGUSR1` writes.
    server_stats: Option<(u32, PathBuf)>,
}

/// Scheduled landings of one project, shared by its agents.
type Schedule = Arc<Mutex<mpsc::Receiver<Instant>>>;

/// One point of a curve; `objects` mode reads through `cache` if given.
fn run_one(cx: &Ctx<'_>, a: &Args, projects: usize, clients: usize, rate: Rate, cache: Option<&crate::server::CacheProc>) -> Result<serde_json::Value> {
    let setup = Api::new(cx.base, cx.ca)?;
    let seed = if a.mode == Mode::Objects { SEED_FILES } else { 0 };
    let names: Vec<String> = (0..projects).map(|_| create_project(&setup, cx.admin, cx.admin_token, cx.agent_name, seed)).collect::<Result<_>>()?;
    let cache_ca = cache.map(|c| std::fs::read_to_string(&c.cert)).transpose()?;
    let c = Counters::default();
    let bg = Counters::default();
    let stop = AtomicBool::new(false);
    // Agents, the background landers (pull mode) and this thread.
    let landers = if matches!(a.mode, Mode::Pull | Mode::Objects) && a.background > 0.0 { projects } else { 0 };
    let ready = Barrier::new(clients + landers + 1);
    // Open loop: scheduled landings, one queue per project.
    let queues: Vec<(mpsc::Sender<Instant>, Schedule)> = (0..projects)
        .map(|_| {
            let (tx, rx) = mpsc::channel();
            (tx, Arc::new(Mutex::new(rx)))
        })
        .collect();
    let mut result = json!({});
    std::thread::scope(|s| -> Result<()> {
        for i in 0..clients {
            let p = i % projects;
            let (name, c, stop, ready, rx, cache_ca) = (&names[p], &c, &stop, &ready, queues[p].1.clone(), &cache_ca);
            std::thread::Builder::new().stack_size(256 << 10).spawn_scoped(s, move || {
                let mut agent = match Api::new(cx.base, cx.ca) {
                    Ok(api) => Agent {
                        api,
                        token: cx.agent_token,
                        identity: cx.agent,
                        project: name.clone(),
                        dir: vec!["w".into(), format!("g{:02}", (i / projects) / 32), format!("a{:04}", i / projects)],
                        branch: match a.mode {
                            Mode::Branches => format!("a/{:04}", i / projects),
                            _ => "main".into(),
                        },
                        exists: false,
                        clone: Held::default(),
                        files: 0,
                        c,
                        objects: match (cache, cache_ca) {
                            (Some(k), Some(ca)) => match Api::new(&k.https(), Some(ca)) {
                                Ok(api) => Some(api),
                                Err(e) => {
                                    c.error(&e);
                                    ready.wait();
                                    return;
                                }
                            },
                            _ => None,
                        },
                    },
                    Err(e) => {
                        c.error(&e);
                        ready.wait();
                        return;
                    }
                };
                // The first clone (or read), before the clock starts (through
                // the landing service an agent needs only the tip it lands on).
                let first = match a.mode {
                    Mode::Landing => agent.api.get(agent.token, &agent.path("/tips")).and_then(|r| {
                        ok(&r, "tips")?;
                        let tips: Tips = serde_json::from_slice(&r.body)?;
                        let tip = *tips.branches.get("main").ok_or_else(|| anyhow!("no main"))?;
                        agent.clone.tip = Some((tip, tip));
                        Ok(true)
                    }),
                    Mode::Objects => agent.read().map(|_| true),
                    _ => agent.pull(),
                };
                if let Err(e) = first {
                    c.error(&e);
                }
                ready.wait();
                while !stop.load(Ordering::Relaxed) {
                    let scheduled = match (a.mode, rate) {
                        (Mode::Land | Mode::Branches | Mode::Api | Mode::Landing, Rate::PerSecond(_)) => match rx.lock().unwrap().recv_timeout(Duration::from_millis(100)) {
                            Ok(t) => t,
                            Err(_) => continue,
                        },
                        _ => Instant::now(),
                    };
                    let r = match a.mode {
                        Mode::Pull => agent.pull().map(|moved| u64::from(!moved)),
                        Mode::Land | Mode::Branches => agent.land(scheduled + Duration::from_secs(60)),
                        Mode::Api => agent.land_api(scheduled + Duration::from_secs(60)),
                        Mode::Landing => agent.land_service(scheduled + Duration::from_secs(60)),
                        Mode::Objects => agent.read(),
                    };
                    let done = Instant::now();
                    if !c.measuring.load(Ordering::Relaxed) {
                        continue;
                    }
                    match r {
                        Ok(n) => {
                            c.ops.fetch_add(1, Ordering::Relaxed);
                            if matches!(a.mode, Mode::Pull | Mode::Objects) {
                                // Objects mode: the objects read.
                                c.noop.fetch_add(n, Ordering::Relaxed);
                            }
                            c.latencies.lock().unwrap().push((done - scheduled).as_secs_f64() * 1000.0);
                            c.finished_agents.lock().unwrap().insert(i);
                        }
                        Err(e) => {
                            c.error(&e);
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })?;
        }
        for (p, name) in names.iter().enumerate().take(landers) {
            let (bg, stop, ready) = (&bg, &stop, &ready);
            std::thread::Builder::new().stack_size(256 << 10).spawn_scoped(s, move || {
                let mut agent = match Api::new(cx.base, cx.ca) {
                    Ok(api) => Agent {
                        api,
                        token: cx.agent_token,
                        identity: cx.agent,
                        project: name.clone(),
                        dir: vec!["w".into(), "bg".into(), format!("p{p}")],
                        branch: "main".into(),
                        exists: false,
                        clone: Held::default(),
                        files: 0,
                        c: bg,
                        objects: None,
                    },
                    Err(e) => {
                        bg.error(&e);
                        ready.wait();
                        return;
                    }
                };
                let _ = agent.pull();
                ready.wait();
                let gap = Duration::from_secs_f64(1.0 / a.background);
                let mut next = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    match agent.land(next + Duration::from_secs(60)) {
                        Ok(_) => {
                            bg.ops.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => bg.error(&e),
                    }
                    next += gap;
                    if let Some(wait) = next.checked_duration_since(Instant::now()) {
                        std::thread::sleep(wait);
                    }
                }
            })?;
        }
        ready.wait();
        // Open loop: schedule landings at `rate`, round robin over the projects.
        let schedule = |until: Instant, start: Instant, mut k: u64| -> u64 {
            if let (Mode::Land | Mode::Branches | Mode::Api | Mode::Landing, Rate::PerSecond(r)) = (a.mode, rate) {
                loop {
                    let at = start + Duration::from_secs_f64(k as f64 / r);
                    if at >= until {
                        return k;
                    }
                    if let Some(wait) = at.checked_duration_since(Instant::now()) {
                        std::thread::sleep(wait);
                    }
                    let _ = queues[(k as usize) % projects].0.send(at);
                    k += 1;
                }
            } else {
                std::thread::sleep(until.saturating_duration_since(Instant::now()));
                k
            }
        };
        let start = Instant::now();
        let k = schedule(start + a.warmup, start, 0);
        // The measured window.
        let before_server = cx.server_pid.and_then(cpu_of);
        let before_db = db_cpu(a.db_container.as_deref());
        let before_self = cpu_of(std::process::id());
        let before_stmts = cx.stats.and_then(|(rt, url)| db_statements(rt, url));
        let before_xid = cx.stats.and_then(|(rt, url)| next_xid(rt, url));
        let before_deriver = cx.stats.and_then(|(rt, url)| deriver_writes(rt, url));
        let before_server_stats = cx.server_stats.as_ref().and_then(|(pid, f)| server_stats(*pid, f));
        let (sent0, received0) = (BYTES_SENT.load(Ordering::Relaxed), BYTES_RECEIVED.load(Ordering::Relaxed));
        let before_dml = cx.stats.and_then(|(rt, url)| db_writes(rt, url));
        let cache_pid = cache.map(|k| k.pid());
        let before_cache = cache.and_then(|k| server_stats(k.pid(), &k.dir.join("stats.json")));
        let before_cache_cpu = cache_pid.and_then(cpu_of);
        if let Some(pid) = cache_pid {
            crate::server::reset_peak(pid);
        }
        let req0 = c.requests.load(Ordering::Relaxed);
        c.measuring.store(true, Ordering::Relaxed);
        let t0 = Instant::now();
        schedule(t0 + a.duration, start, k);
        let elapsed = t0.elapsed().as_secs_f64();
        c.measuring.store(false, Ordering::Relaxed);
        let server_cpu = cx.server_pid.and_then(cpu_of).zip(before_server).map(|(b, a)| b - a);
        let db = db_cpu(a.db_container.as_deref()) - before_db;
        let me = cpu_of(std::process::id()).zip(before_self).map(|(b, a)| b - a);
        let stmts = cx.stats.and_then(|(rt, url)| db_statements(rt, url)).zip(before_stmts).map(|((b, what), (a, _))| (b - a, what));
        let writes = cx
            .stats
            .and_then(|(rt, url)| Some((rt, url, next_xid(rt, url)?)))
            .zip(before_xid)
            .and_then(|((rt, url, to), from)| db_commits(rt, url, from, to));
        let deriver = cx.stats.and_then(|(rt, url)| deriver_writes(rt, url)).zip(before_deriver).map(|(b, a)| b - a);
        let (sent, received) = (BYTES_SENT.load(Ordering::Relaxed) - sent0, BYTES_RECEIVED.load(Ordering::Relaxed) - received0);
        let server_stats = cx.server_stats.as_ref().and_then(|(pid, f)| server_stats(*pid, f)).zip(before_server_stats);
        let stat = |k: &str| server_stats.as_ref().and_then(|(b, a)| Some(b[k].as_f64()? - a[k].as_f64()?));
        let dml = cx.stats.and_then(|(rt, url)| db_writes(rt, url)).zip(before_dml).map(|((_, bw), (_, aw))| bw - aw);
        let requests = c.requests.load(Ordering::Relaxed) - req0;
        let cache_stats = cache.and_then(|k| self::server_stats(k.pid(), &k.dir.join("stats.json"))).zip(before_cache);
        let cstat = |k: &str| cache_stats.as_ref().and_then(|(b, a)| Some(b[k].as_f64()? - a[k].as_f64()?));
        let cache_cpu = cache_pid.and_then(cpu_of).zip(before_cache_cpu).map(|(b, a)| b - a);
        let cache_peak = cache_pid.and_then(crate::server::peak_kib);
        stop.store(true, Ordering::Relaxed);
        let ops = c.ops.load(Ordering::Relaxed) as f64;
        let mut lat = std::mem::take(&mut *c.latencies.lock().unwrap());
        lat.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let per_op = |x: f64| if ops > 0.0 { x / ops } else { f64::NAN };
        result = json!({
            "mode": match a.mode { Mode::Pull => "pull", Mode::Land => "land", Mode::Branches => "branches", Mode::Api => "api", Mode::Landing => "landing", Mode::Objects => "objects" },

            "projects": projects,
            "clients": clients,
            "rate": match rate { Rate::Max => json!("max"), Rate::PerSecond(r) => json!(r) },
            "seconds": elapsed,
            "ops": ops,
            "ops_per_s": ops / elapsed,
            "p50_ms": percentile(&lat, 0.5),
            "p99_ms": percentile(&lat, 0.99),
            "collisions_per_op": per_op(c.collisions.load(Ordering::Relaxed) as f64),
            "up_to_date_share": per_op(c.noop.load(Ordering::Relaxed) as f64),
            "busy": c.busy.load(Ordering::Relaxed),
            "agents_finishing": c.finished_agents.lock().unwrap().len(),
            "errors": c.errors.load(Ordering::Relaxed),
            "first_error": c.first_error.lock().unwrap().clone(),
            "requests_per_op": per_op(requests as f64),
            "server_cpu_ms_per_op": server_cpu.map(|x| per_op(x * 1000.0)),
            "server_cores": server_cpu.map(|x| x / elapsed),
            "db_cpu_ms_per_op": per_op(db * 1000.0),
            "db_cores": db / elapsed,
            "db_per_op": stmts.map(|(n, _)| per_op(n)),
            "db_counted": stmts.map(|(_, w)| w),
            "db_per_request": stmts.map(|(n, _)| if requests > 0 { n / requests as f64 } else { f64::NAN }),
            "db_commits_per_op": writes.map(per_op),
            "db_deriver_writes_per_op": deriver.map(per_op),
            "db_push_commits_per_op": writes.zip(deriver).map(|(w, d)| per_op((w - d).max(0.0))),
            "storage_writes_per_op": stat("storage_writes").map(per_op),
            "storage_written_bytes_per_op": stat("storage_written_bytes").map(per_op),
            "storage_reads_per_op": stat("storage_reads").map(per_op),
            "session_hit_share": stat("session_hits").zip(stat("session_misses")).map(|(h, m)| h / (h + m)),
            "permission_hit_share": stat("permission_hits").zip(stat("permission_misses")).map(|(h, m)| h / (h + m)),
            "tips_hit_share": stat("tips_hits").zip(stat("tips_misses")).map(|(h, m)| h / (h + m)),
            "bytes_sent_per_op": per_op(sent as f64),
            "bytes_received_per_op": per_op(received as f64),
            "db_writes_per_op": dml.map(per_op),
            "load_tool_cores": me.map(|x| x / elapsed),
            "background_landings": bg.ops.load(Ordering::Relaxed),
            "background_errors": bg.errors.load(Ordering::Relaxed),
        });
        // The landing service's own counters (the server this tool started).
        let ratio = |a: Option<f64>, b: Option<f64>, k: f64| a.zip(b).map(|(a, b)| if b > 0.0 { a / b / k } else { f64::NAN });
        result["landing_batches"] = json!(stat("landing_batches"));
        result["landings_per_batch"] = json!(ratio(stat("landing_landed"), stat("landing_batches"), 1.0));
        result["landing_build_ms_per_op"] = json!(ratio(stat("landing_build_us"), stat("landing_landed"), 1000.0));
        for k in ["landing_projected", "landing_attached", "landing_prefilled", "landing_dropped", "landing_memo_races", "landing_rechecked"] {
            result[k] = json!(stat(k));
        }
        result["landing_prepare_ms_per_batch"] = json!(ratio(stat("landing_prepare_us"), stat("landing_batches"), 1000.0));
        result["landing_store_ms_per_batch"] = json!(ratio(stat("landing_store_us"), stat("landing_batches"), 1000.0));
        result["landing_commit_ms_per_batch"] = json!(ratio(stat("landing_commit_us"), stat("landing_batches"), 1000.0));
        if a.mode == Mode::Objects {
            result["via"] = json!(if cache.is_some() { "cache" } else { "server" });
            result["objects_per_op"] = json!(per_op(c.noop.load(Ordering::Relaxed) as f64));
            result["cache_hit_share"] = json!(cstat("local").zip(cstat("upstream")).map(|(l, u)| l / (l + u)));
            result["cache_forwarded_per_op"] = json!(cstat("forwarded").map(per_op));
            result["cache_cpu_ms_per_op"] = json!(cache_cpu.map(|x| per_op(x * 1000.0)));
            result["cache_peak_mib"] = json!(cache_peak.map(|k| k as f64 / 1024.0));
            result["cache_stored_mib"] = json!(cache_stats.as_ref().and_then(|(b, _)| b["stored_bytes"].as_f64()).map(|b| b / (1 << 20) as f64));
        }
        Ok(())
    })?;
    // The deriver's lag (S12, BUG-911): once the agents stopped, how long
    // until every branch of these projects is derived, and how many are not
    // after five minutes.
    if let Some((rt, url)) = cx.stats {
        let t = Instant::now();
        let behind = loop {
            let n = derive_behind(rt, url, &names);
            if n != Some(0) && n.is_some() && t.elapsed() < Duration::from_secs(300) {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            break n;
        };
        result["derive_lag_s"] = json!(t.elapsed().as_secs_f64());
        result["derive_behind"] = json!(behind);
    }
    Ok(result)
}

/// Branches of `projects` whose derived history is not their tip.
fn derive_behind(rt: &tokio::runtime::Runtime, url: &str, projects: &[String]) -> Option<i64> {
    rt.block_on(async {
        let mut c = <sqlx::PgConnection as sqlx::Connection>::connect(url).await.ok()?;
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM branches b JOIN projects p ON p.id = b.project_id LEFT JOIN derive_progress d \
             ON d.project_id = b.project_id AND d.branch = b.name WHERE p.name = ANY($1) AND d.through_snapshot IS DISTINCT FROM b.target",
        )
        .bind(projects)
        .fetch_one(&mut c)
        .await
        .ok()
    })
}

pub fn run_all(a: &Args) -> Result<serde_json::Value> {
    std::fs::create_dir_all(&a.dir)?;
    let mut _server = None;
    let (base, ca, mut server_pid) = match (&a.url, &a.server.server) {
        (Some(u), _) => (u.clone(), a.ca.as_ref().map(std::fs::read_to_string).transpose()?, None),
        (None, Some(_)) => {
            let s = crate::server::Server::start(&a.server, &a.dir.join("server"), a.db_connections)?;
            let (base, ca, pid) = (s.https(), std::fs::read_to_string(&s.cert)?, s.pid());
            _server = Some(s);
            (base, Some(ca), Some(pid))
        }
        (None, None) => bail!("give --url of a running server, or --server to start one"),
    };
    if a.server_pid.is_some() {
        server_pid = a.server_pid;
    }
    let api = Api::new(&base, ca.as_deref())?;
    let admin = Identity::generate("load-admin");
    let agent = Identity::generate("load-agent");
    let agent_name = unique("agent-");
    let admin_token = api.login(&admin, &unique("admin-"))?;
    let agent_token = api.login(&agent, &agent_name)?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let cx = Ctx {
        base: &base,
        ca: ca.as_deref(),
        admin: &admin,
        admin_token: &admin_token,
        agent: &agent,
        agent_name: &agent_name,
        agent_token: &agent_token,
        server_pid,
        stats: a.server.database_url.as_deref().map(|u| (&rt, u)),
        server_stats: _server.as_ref().map(|s: &crate::server::Server| (s.pid(), a.dir.join("server").join("stats.json"))),
    };
    let rates = match a.mode {
        Mode::Pull | Mode::Objects => vec![Rate::Max],
        Mode::Land | Mode::Branches | Mode::Api | Mode::Landing => a.rates.clone(),
    };
    // `objects --via cache`: one regional cache in front of the server
    // started here, for every run.
    let vias = if a.mode == Mode::Objects { a.vias.clone() } else { vec![false] };
    let cache = match (vias.contains(&true), &_server, &a.server.server) {
        (false, _, _) => None,
        (true, Some(s), Some(bin)) => Some(crate::server::CacheProc::start(bin, s, &a.dir.join("server"), &a.dir.join("cache"))?),
        _ => bail!("--via cache needs a server started here (--server)"),
    };
    let mut runs = Vec::new();
    for &via in &vias {
    for &projects in &a.projects {
        for &clients in &a.clients {
            for &rate in &rates {
                let clients = clients.max(projects);
                eprintln!("load: {:?} projects={projects} clients={clients} rate={rate:?}{}", a.mode, if via { " via the cache" } else { "" });
                let mut r = run_one(&cx, a, projects, clients, rate, cache.as_ref().filter(|_| via))?;
                eprintln!("      {}", line(&r));
                let missed = missed_gates(&r, a.background);
                for m in &missed {
                    eprintln!("      GATE MISSED: {m}");
                }
                r["gates_missed"] = json!(missed);
                runs.push(r);
            }
        }
    }
    }
    Ok(json!({ "profile": "load", "server": base, "runs": runs }))
}

fn line(r: &serde_json::Value) -> String {
    let f = |k: &str| r[k].as_f64().map(|v| format!("{v:.2}")).unwrap_or_else(|| "–".into());
    format!(
        "{} ops/s ({} agents finishing), p50 {} ms, p99 {} ms, collisions/op {}, errors {}, server ms/op {}, db ms/op {}, db/op {}, commits/op {}, writes/op {}, derived {} s later ({} branches behind)",
        f("ops_per_s"),
        r["agents_finishing"],
        f("p50_ms"),
        f("p99_ms"),
        f("collisions_per_op"),
        r["errors"],
        f("server_cpu_ms_per_op"),
        f("db_cpu_ms_per_op"),
        f("db_per_op"),
        f("db_commits_per_op"),
        f("db_writes_per_op"),
        f("derive_lag_s"),
        r["derive_behind"]
    )
}

/// The runs as a Markdown table.
pub fn markdown(v: &serde_json::Value) -> Result<String> {
    let mut out = String::from(
        "| Mode | Projects | Clients | Agents finishing | Target rate (/s) | Done (/s) | p50 (ms) | p99 (ms) | Collisions per landing | Requests per op | Server CPU (ms/op) | Server cores | DB CPU (ms/op) | DB cores | DB statements per op | DB commits per op | DB writes per op | Load tool cores | Errors |\n\
         |---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    let f = |x: &serde_json::Value, d: usize| x.as_f64().filter(|v| v.is_finite()).map(|v| format!("{v:.d$}")).unwrap_or_else(|| "–".into());
    for r in v["runs"].as_array().ok_or_else(|| anyhow!("no runs"))? {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            r["mode"].as_str().unwrap_or(""),
            r["projects"],
            r["clients"],
            r["agents_finishing"],
            r["rate"].as_str().map(str::to_string).unwrap_or_else(|| f(&r["rate"], 2)),
            f(&r["ops_per_s"], 1),
            f(&r["p50_ms"], 1),
            f(&r["p99_ms"], 1),
            match r["mode"].as_str() {
                Some("land" | "branches" | "api" | "landing") => f(&r["collisions_per_op"], 2),
                _ => "–".into(),
            },
            f(&r["requests_per_op"], 1),
            f(&r["server_cpu_ms_per_op"], 2),
            f(&r["server_cores"], 1),
            f(&r["db_cpu_ms_per_op"], 2),
            f(&r["db_cores"], 1),
            f(&r["db_per_op"], 1),
            f(&r["db_commits_per_op"], 2),
            f(&r["db_writes_per_op"], 1),
            f(&r["load_tool_cores"], 1),
            r["errors"],
        ));
    }
    out.push_str(
        "\n| Mode | Projects | Clients | Target rate (/s) | DB commits per op (the deriver's aside) | DB statements per op | DB statements per request | Storage writes per op | Storage reads per op | KiB stored per op | KiB sent per op | KiB received per op | Session / permission / tips cache hits | Gates missed |\n\
         |---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|\n",
    );
    let pct = |x: &serde_json::Value| x.as_f64().filter(|v| v.is_finite()).map(|v| format!("{:.0} %", v * 100.0)).unwrap_or_else(|| "–".into());
    let kib = |x: &serde_json::Value| x.as_f64().filter(|v| v.is_finite()).map(|v| format!("{:.1}", v / 1024.0)).unwrap_or_else(|| "–".into());
    for r in v["runs"].as_array().ok_or_else(|| anyhow!("no runs"))? {
        let missed = r["gates_missed"].as_array().map(|m| m.len()).unwrap_or(0);
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} ({}) | {} | {} | {} | {} | {} | {} | {} | {} / {} / {} | {} |\n",
            r["mode"].as_str().unwrap_or(""),
            r["projects"],
            r["clients"],
            r["rate"].as_str().map(str::to_string).unwrap_or_else(|| f(&r["rate"], 2)),
            f(&r["db_commits_per_op"], 2),
            f(&r["db_push_commits_per_op"], 2),
            f(&r["db_per_op"], 1),
            f(&r["db_per_request"], 2),
            f(&r["storage_writes_per_op"], 1),
            f(&r["storage_reads_per_op"], 1),
            kib(&r["storage_written_bytes_per_op"]),
            kib(&r["bytes_sent_per_op"]),
            kib(&r["bytes_received_per_op"]),
            pct(&r["session_hit_share"]),
            pct(&r["permission_hit_share"]),
            pct(&r["tips_hit_share"]),
            if missed == 0 { "none".to_string() } else { format!("**{missed}**") },
        ));
    }
    let landing: Vec<&serde_json::Value> = v["runs"].as_array().map(|r| r.iter().filter(|r| r["mode"] == "landing").collect()).unwrap_or_default();
    if !landing.is_empty() {
        out.push_str(
            "\n| Landing service: clients | Target rate (/s) | Done (/s) | Batches | Landings per batch | Prepare (ms/batch) | Build CPU (ms/landing) | Store objects (ms/batch) | Transaction (ms/batch) |\n\
             |---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
        );
        for r in landing {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                r["clients"],
                r["rate"].as_str().map(str::to_string).unwrap_or_else(|| f(&r["rate"], 2)),
                f(&r["ops_per_s"], 1),
                f(&r["landing_batches"], 0),
                f(&r["landings_per_batch"], 1),
                f(&r["landing_prepare_ms_per_batch"], 1),
                f(&r["landing_build_ms_per_op"], 3),
                f(&r["landing_store_ms_per_batch"], 1),
                f(&r["landing_commit_ms_per_batch"], 1),
            ));
        }
    }
    let objects: Vec<&serde_json::Value> = v["runs"].as_array().into_iter().flatten().filter(|r| r["mode"] == "objects").collect();
    if !objects.is_empty() {
        out.push_str(
            "\n| Via | Projects | Clients | Reads (/s) | Objects per read | p50 (ms) | p99 (ms) | Server CPU (ms/read) | Cache hits | Cache requests to the server per read | Cache CPU (ms/read) | Cache peak (MiB) | Errors |\n\
             |---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
        );
        for r in objects {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                r["via"].as_str().unwrap_or(""),
                r["projects"],
                r["clients"],
                f(&r["ops_per_s"], 1),
                f(&r["objects_per_op"], 0),
                f(&r["p50_ms"], 1),
                f(&r["p99_ms"], 1),
                f(&r["server_cpu_ms_per_op"], 2),
                r["cache_hit_share"].as_f64().map(|h| format!("{:.2} %", h * 100.0)).unwrap_or_else(|| "–".into()),
                f(&r["cache_forwarded_per_op"], 2),
                f(&r["cache_cpu_ms_per_op"], 2),
                f(&r["cache_peak_mib"], 0),
                r["errors"],
            ));
        }
    }
    Ok(out)
}
