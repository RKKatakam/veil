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
//! Measured per run: operations per second, latency p50/p99, collisions
//! and retries per landing, errors, and when known the server's CPU per
//! operation (`--server-pid`, or the server this tool started), the
//! database's CPU (processes named `postgres`, `yb-tserver` or
//! `yb-master` on this machine), database statements per operation
//! (`pg_stat_statements` if it is loaded, else transactions from
//! `pg_stat_database`) and this tool's own CPU.

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
    hub::wire::{put_frame, read_frames, BranchUpdate, FetchRequest, HistoryRequest, PushRequest, PushResult, Tips, Want},
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEncoding, TreeEntry, Visibility},
    ChangeId, Identity, ObjectId,
};

/// What the agents do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Pull,
    Land,
    Api,
}

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
    clone: Held,
    files: u64,
    c: &'a Counters,
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
        let tip = *tips.branches.get("main").ok_or_else(|| anyhow!("no main"))?;
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
                    branch: "main".into(),
                    expected: Some(tip),
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
/// `w/  agents`, and a first snapshot.
fn create_project(api: &Api, admin: &Identity, admin_token: &str, agent: &str) -> Result<String> {
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
}

/// Scheduled landings of one project, shared by its agents.
type Schedule = Arc<Mutex<mpsc::Receiver<Instant>>>;

/// One point of a curve.
fn run_one(cx: &Ctx<'_>, a: &Args, projects: usize, clients: usize, rate: Rate) -> Result<serde_json::Value> {
    let setup = Api::new(cx.base, cx.ca)?;
    let names: Vec<String> = (0..projects).map(|_| create_project(&setup, cx.admin, cx.admin_token, cx.agent_name)).collect::<Result<_>>()?;
    let c = Counters::default();
    let bg = Counters::default();
    let stop = AtomicBool::new(false);
    // Agents, the background landers (pull mode) and this thread.
    let landers = if a.mode == Mode::Pull && a.background > 0.0 { projects } else { 0 };
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
            let (name, c, stop, ready, rx) = (&names[p], &c, &stop, &ready, queues[p].1.clone());
            std::thread::Builder::new().stack_size(256 << 10).spawn_scoped(s, move || {
                let mut agent = match Api::new(cx.base, cx.ca) {
                    Ok(api) => Agent {
                        api,
                        token: cx.agent_token,
                        identity: cx.agent,
                        project: name.clone(),
                        dir: vec!["w".into(), format!("g{:02}", (i / projects) / 32), format!("a{:04}", i / projects)],
                        clone: Held::default(),
                        files: 0,
                        c,
                    },
                    Err(e) => {
                        c.error(&e);
                        ready.wait();
                        return;
                    }
                };
                // The first clone, before the clock starts.
                if let Err(e) = agent.pull() {
                    c.error(&e);
                }
                ready.wait();
                while !stop.load(Ordering::Relaxed) {
                    let scheduled = match (a.mode, rate) {
                        (Mode::Land | Mode::Api, Rate::PerSecond(_)) => match rx.lock().unwrap().recv_timeout(Duration::from_millis(100)) {
                            Ok(t) => t,
                            Err(_) => continue,
                        },
                        _ => Instant::now(),
                    };
                    let r = match a.mode {
                        Mode::Pull => agent.pull().map(|moved| u64::from(!moved)),
                        Mode::Land => agent.land(scheduled + Duration::from_secs(60)),
                        Mode::Api => agent.land_api(scheduled + Duration::from_secs(60)),
                    };
                    let done = Instant::now();
                    if !c.measuring.load(Ordering::Relaxed) {
                        continue;
                    }
                    match r {
                        Ok(n) => {
                            c.ops.fetch_add(1, Ordering::Relaxed);
                            if a.mode == Mode::Pull {
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
                        clone: Held::default(),
                        files: 0,
                        c: bg,
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
            if let (Mode::Land | Mode::Api, Rate::PerSecond(r)) = (a.mode, rate) {
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
        let before_writes = cx.stats.and_then(|(rt, url)| db_writes(rt, url));
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
        let writes = cx.stats.and_then(|(rt, url)| db_writes(rt, url)).zip(before_writes).map(|((bc, bw), (ac, aw))| (bc - ac, bw - aw));
        let requests = c.requests.load(Ordering::Relaxed) - req0;
        stop.store(true, Ordering::Relaxed);
        let ops = c.ops.load(Ordering::Relaxed) as f64;
        let mut lat = std::mem::take(&mut *c.latencies.lock().unwrap());
        lat.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let per_op = |x: f64| if ops > 0.0 { x / ops } else { f64::NAN };
        result = json!({
            "mode": match a.mode { Mode::Pull => "pull", Mode::Land => "land", Mode::Api => "api" },
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
            "db_commits_per_op": writes.map(|(c, _)| per_op(c)),
            "db_writes_per_op": writes.map(|(_, w)| per_op(w)),
            "load_tool_cores": me.map(|x| x / elapsed),
            "background_landings": bg.ops.load(Ordering::Relaxed),
            "background_errors": bg.errors.load(Ordering::Relaxed),
        });
        Ok(())
    })?;
    Ok(result)
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
    };
    let rates = match a.mode {
        Mode::Pull => vec![Rate::Max],
        Mode::Land | Mode::Api => a.rates.clone(),
    };
    let mut runs = Vec::new();
    for &projects in &a.projects {
        for &clients in &a.clients {
            for &rate in &rates {
                let clients = clients.max(projects);
                eprintln!("load: {:?} projects={projects} clients={clients} rate={rate:?}", a.mode);
                let r = run_one(&cx, a, projects, clients, rate)?;
                eprintln!("      {}", line(&r));
                runs.push(r);
            }
        }
    }
    Ok(json!({ "profile": "load", "server": base, "runs": runs }))
}

fn line(r: &serde_json::Value) -> String {
    let f = |k: &str| r[k].as_f64().map(|v| format!("{v:.2}")).unwrap_or_else(|| "–".into());
    format!(
        "{} ops/s ({} agents finishing), p50 {} ms, p99 {} ms, collisions/op {}, errors {}, server ms/op {}, db ms/op {}, db/op {}, commits/op {}, writes/op {}",
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
        f("db_writes_per_op")
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
                Some("land" | "api") => f(&r["collisions_per_op"], 2),
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
    Ok(out)
}
