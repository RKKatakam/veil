//! Thin clones of server projects (milestone S3, `docs/HUB.md` §13.21):
//! the connection the engine fetches through ([`HubPromisor`]), and
//! `vl partial`.
//!
//! The engine's side (`veil_core::promisor`) decides what is fetched and
//! kept; this module only carries requests to the server and maps its
//! answers: an object or page that arrived, "no such object there that you
//! can see" (404, a real redaction: `None`), or anything else, which is
//! [`VeilError::Unavailable`] and never read as hidden.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{anyhow, bail, Result};
use veil_core::{
    hub::wire::{FetchRequest, HistoryRequest, Want},
    promisor::{human, parse_size, Located, Promisor},
    store::ObjectStore,
    Identity, ObjectId, Repo, VeilError,
};

use crate::{
    ctx::Ctx,
    hub::{Client, HubUrl},
    render::{dim, green},
};

/// The server of a thin clone, as the engine's promisor. The client is made
/// on the first request: commands that read only what is local never sign
/// in.
pub struct HubPromisor {
    url: HubUrl,
    identity: Identity,
    client: Mutex<Option<Client>>,
    tips: Vec<ObjectId>,
    /// Asked the server for grants (its tips) in this process (S6).
    asked_grants: std::sync::atomic::AtomicBool,
}

// ---- reads through the Veil daemon (S6, `docs/HUB.md` §13.29) ----------------------

/// Read grants this process received with the tips (`hub::pull`, or asked
/// for by [`HubPromisor`]), by server and project: the grant key, and each
/// grant by its projected root.
struct Grants {
    key: String,
    by_root: std::collections::HashMap<ObjectId, String>,
}

static GRANTS: Mutex<Option<std::collections::HashMap<(String, String), Grants>>> = Mutex::new(None);

/// Remember the grants of `tips` (the server's answer to this person's
/// device) for reads through the daemon.
pub fn remember_grants(url: &HubUrl, tips: &veil_core::hub::wire::Tips) {
    let Some(key) = tips.grant_key.clone() else { return };
    let mut by_root = std::collections::HashMap::new();
    for token in tips.grants.values() {
        if let Some(b) = veil_core::hub::grant::Grant::read_unverified(token) {
            by_root.insert(b.root, token.clone());
        }
    }
    let mut g = GRANTS.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(Default::default).insert((url.authority.clone(), url.project.clone()), Grants { key, by_root });
}

/// A grant remembered for projected root `root`, verified under the
/// server's grant key and valid for at least another 30 s.
pub(crate) fn grant_for(url: &HubUrl, root: &ObjectId) -> Option<(String, veil_core::hub::grant::Grant)> {
    let g = GRANTS.lock().unwrap_or_else(|e| e.into_inner());
    let set = g.as_ref()?.get(&(url.authority.clone(), url.project.clone()))?;
    let token = set.by_root.get(root)?;
    let grant = veil_core::hub::grant::Grant::verify(token, &set.key)?;
    (grant.body.expires > veil_core::now_millis() + 30_000).then(|| (token.clone(), grant))
}

/// Is the daemon on (not turned off with `vl daemon stop`)?
pub(crate) fn daemon_on() -> bool {
    cfg!(unix) && !crate::daemon::paths().off.exists()
}

/// What the daemon serves of `wants` (each: the projected root it was met
/// under, its chain from that root, its id): the objects that arrived, each
/// checked against its id. Only wants under a remembered grant are asked.
pub(crate) fn via_daemon(url: &HubUrl, identity: &Identity, wants: &[(ObjectId, Vec<ObjectId>, ObjectId)]) -> std::collections::HashMap<ObjectId, Vec<u8>> {
    let mut by_root: std::collections::BTreeMap<ObjectId, Vec<(Vec<ObjectId>, ObjectId)>> = Default::default();
    for (root, chain, id) in wants {
        by_root.entry(*root).or_default().push((chain.clone(), *id));
    }
    let mut parts = Vec::new();
    for (root, ws) in by_root {
        let Some((token, grant)) = grant_for(url, &root) else { continue };
        for part in ws.chunks(1_000) {
            parts.push((token.clone(), grant.clone(), part.to_vec()));
        }
    }
    // Up to 8 requests at once, as a fetch from the server.
    let mut got = std::collections::HashMap::new();
    for group in parts.chunks(8) {
        let answers: Vec<Vec<(ObjectId, Vec<u8>)>> = std::thread::scope(|s| {
            let hs: Vec<_> = group
                .iter()
                .map(|(token, grant, part)| s.spawn(move || crate::daemon::fetch_under(&url.authority, &url.project, identity, grant, token, part.clone())))
                .collect();
            hs.into_iter().map(|h| h.join().unwrap_or_default()).collect()
        });
        got.extend(answers.into_iter().flatten());
    }
    got
}

/// The engine's error for a server that could not be reached or answered
/// something else than an object or "not there".
fn unavailable(url: &HubUrl, what: impl std::fmt::Display) -> VeilError {
    VeilError::Unavailable(format!("{}: {what}", url.authority))
}

impl HubPromisor {
    fn client(&self) -> veil_core::Result<MutexGuard<'_, Option<Client>>> {
        let mut c = self.client.lock().unwrap_or_else(|e| e.into_inner());
        if c.is_none() {
            *c = Some(Client::new(&self.url, self.identity.clone()).map_err(|e| unavailable(&self.url, format!("{e:#}")))?);
        }
        Ok(c)
    }

    /// POST `path` with `body`; the status and answer, or `Unavailable`.
    fn post(&self, path: &str, body: Vec<u8>) -> veil_core::Result<(u16, Vec<u8>)> {
        let c = self.client()?;
        c.as_ref().expect("made above").post_status(path, body).map_err(|e| unavailable(&self.url, format!("{e:#}")))
    }

    fn refused(&self, status: u16, body: &[u8]) -> VeilError {
        let why = serde_json::from_slice::<veil_core::hub::wire::ErrorBody>(body)
            .map(|e| format!("{} ({})", e.message, e.code))
            .unwrap_or_else(|_| format!("HTTP {status}"));
        unavailable(&self.url, format!("the server answered {why}"))
    }
}

impl HubPromisor {
    /// The objects of `wants` the daemon serves (by index), under grants of
    /// the projected roots they were met at; the server's tips are asked
    /// once per process for grants this process has none of.
    fn through_daemon(&self, wants: &[Located]) -> Vec<Option<Vec<u8>>> {
        let mut out = vec![None; wants.len()];
        if !daemon_on() {
            return out;
        }
        let placed: Vec<(usize, ObjectId, Vec<ObjectId>)> = wants
            .iter()
            .enumerate()
            .filter_map(|(i, w)| w.chain.as_ref().map(|c| (i, c.first().copied().unwrap_or(w.id), c.clone())))
            .collect();
        if placed.is_empty() {
            return out;
        }
        if placed.iter().any(|(_, root, _)| grant_for(&self.url, root).is_none()) && !self.asked_grants.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let tips = self.client().ok().and_then(|c| c.as_ref().and_then(|c| c.tips().ok().flatten()));
            if let Some(t) = tips {
                remember_grants(&self.url, &t);
            }
        }
        let asked: Vec<(ObjectId, Vec<ObjectId>, ObjectId)> = placed.iter().map(|(i, root, chain)| (*root, chain.clone(), wants[*i].id)).collect();
        let mut got = via_daemon(&self.url, &self.identity, &asked);
        for (i, _, _) in placed {
            out[i] = got.get(&wants[i].id).cloned();
        }
        got.clear();
        out
    }
}

impl Promisor for HubPromisor {
    /// Through the daemon first (S6), then the server for whatever did not
    /// arrive: only the server's own answer is ever "not there".
    fn fetch(&self, wants: &[Located]) -> veil_core::Result<Vec<Option<Vec<u8>>>> {
        let mut out = self.through_daemon(wants);
        let rest: Vec<Located> = wants.iter().zip(&out).filter(|(_, o)| o.is_none()).map(|(w, _)| w.clone()).collect();
        if rest.is_empty() {
            return Ok(out);
        }
        let mut direct = self.fetch_direct(&rest)?.into_iter();
        for o in out.iter_mut().filter(|o| o.is_none()) {
            *o = direct.next().flatten();
        }
        Ok(out)
    }

    fn history(&self, tips: &[ObjectId], limit: usize) -> veil_core::Result<Vec<(ObjectId, Vec<u8>)>> {
        self.history_direct(tips, limit)
    }

    fn server_tips(&self) -> Vec<ObjectId> {
        self.tips.clone()
    }

    fn generations(&self, snapshots: &[ObjectId]) -> veil_core::Result<Option<Vec<Option<u64>>>> {
        self.generations_direct(snapshots)
    }

    fn resolve(&self, prefix: &str, from: &[ObjectId]) -> veil_core::Result<Option<veil_core::hub::wire::Resolved>> {
        self.resolve_direct(prefix, from)
    }

    fn query(&self, route: &str, params: &[(&str, String)]) -> veil_core::Result<std::result::Result<serde_json::Value, (String, String)>> {
        self.query_direct(route, params)
    }
}

impl HubPromisor {
    /// S1's `fetch` route, straight to the server.
    fn fetch_direct(&self, wants: &[Located]) -> veil_core::Result<Vec<Option<Vec<u8>>>> {
        let Some(first) = wants.first() else { return Ok(Vec::new()) };
        let req = FetchRequest {
            snapshot: first.snapshot,
            objects: wants
                .iter()
                .map(|w| Want { path: w.path.clone(), id: w.id, snapshot: (w.snapshot != first.snapshot).then_some(w.snapshot) })
                .collect(),
        };
        let (status, out) = self.post("/fetch", serde_json::to_vec(&req)?)?;
        match status {
            200 => {
                let objects = crate::hub::objects_of(&out).map_err(|e| unavailable(&self.url, format!("{e:#}")))?;
                if objects.len() != wants.len() || objects.iter().zip(wants).any(|((id, _), w)| *id != w.id) {
                    return Err(unavailable(&self.url, "the server sent other objects than asked"));
                }
                Ok(objects.into_iter().map(|(_, raw)| Some(raw)).collect())
            }
            // The server's own answer: no such object at that place that
            // this person may see. One want refused refuses the request:
            // each is asked for alone then.
            404 if wants.len() == 1 => Ok(vec![None]),
            404 => wants.iter().map(|w| Ok(self.fetch_direct(std::slice::from_ref(w))?.pop().flatten())).collect(),
            s => Err(self.refused(s, &out)),
        }
    }

    fn history_direct(&self, tips: &[ObjectId], limit: usize) -> veil_core::Result<Vec<(ObjectId, Vec<u8>)>> {
        if tips.is_empty() {
            return Ok(Vec::new());
        }
        let req = HistoryRequest { tips: tips.to_vec(), stop: Vec::new(), limit: Some(limit) };
        let body = serde_json::to_vec(&req)?;
        // Any other 503 than `warming` (which `Client::send` has waited
        // out, BUG-1913): ask again for about 10 s, as for any query.
        let mut answer = self.post("/history", body.clone())?;
        for _ in 0..20 {
            if answer.0 != 503 || crate::hub::is_warming(answer.0, &answer.1) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
            answer = self.post("/history", body.clone())?;
        }
        let (status, out) = answer;
        match status {
            200 => crate::hub::objects_of(&out).map_err(|e| unavailable(&self.url, format!("{e:#}"))),
            // A tip this person's history does not have is left out.
            404 if tips.len() == 1 => Ok(Vec::new()),
            404 => {
                let mut all = Vec::new();
                for t in tips {
                    all.extend(self.history_direct(std::slice::from_ref(t), limit)?);
                    if all.len() >= limit {
                        break;
                    }
                }
                Ok(all)
            }
            s => Err(self.refused(s, &out)),
        }
    }

    fn generations_direct(&self, snapshots: &[ObjectId]) -> veil_core::Result<Option<Vec<Option<u64>>>> {
        let body = serde_json::to_vec(&veil_core::hub::wire::GenerationsRequest { snapshots: snapshots.to_vec() })?;
        for attempt in 0..20 {
            let (status, out) = self.post("/q/generations", body.clone())?;
            match status {
                200 => {
                    let g: veil_core::hub::wire::Generations = serde_json::from_slice(&out).map_err(|e| unavailable(&self.url, e))?;
                    if g.generations.len() != snapshots.len() {
                        return Err(unavailable(&self.url, "the server answered other generations than asked"));
                    }
                    return Ok(Some(g.generations));
                }
                // A server older than revision 6.
                404 | 405 => return Ok(None),
                503 if attempt < 19 && !crate::hub::is_warming(status, &out) => std::thread::sleep(std::time::Duration::from_millis(500)),
                s => return Err(self.refused(s, &out)),
            }
        }
        Err(unavailable(&self.url, "the server kept preparing this history"))
    }

    fn resolve_direct(&self, prefix: &str, from: &[ObjectId]) -> veil_core::Result<Option<veil_core::hub::wire::Resolved>> {
        // Only letters and digits reach the URL (a prefix is hex or k–z).
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Ok(Some(Default::default()));
        }
        let mut path = format!("/q/resolve?prefix={prefix}");
        if !from.is_empty() {
            let from: Vec<String> = from.iter().take(veil_core::hub::wire::MAX_RESOLVE_FROM).map(|f| f.hex()).collect();
            path.push_str(&format!("&from={}", from.join(",")));
        }
        // A query past its deadline (503): ask again, as any client of the
        // query API does, for about 10 s. (`warming`, the viewer's graph
        // still filling, was waited out by `Client::send`: BUG-1913.)
        for attempt in 0..20 {
            let (status, out) = {
                let c = self.client()?;
                c.as_ref().expect("made").get_status(&path).map_err(|e| unavailable(&self.url, format!("{e:#}")))?
            };
            match status {
                200 => return serde_json::from_slice(&out).map(Some).map_err(|e| unavailable(&self.url, e)),
                // A server without the route (older than revision 5).
                404 | 405 => return Ok(None),
                503 if attempt < 19 && !crate::hub::is_warming(status, &out) => std::thread::sleep(std::time::Duration::from_millis(500)),
                s => return Err(self.refused(s, &out)),
            }
        }
        Err(unavailable(&self.url, "the server kept preparing this history"))
    }

    /// A query route (`/v1/projects/{p}/q/{route}`, S16, `docs/HUB.md`
    /// §13.34), retrying `deadline` and `indexing` (`503`) up to 20 times
    /// (`warming` was waited out by `Client::send`, BUG-1913).
    fn query_direct(&self, route: &str, params: &[(&str, String)]) -> veil_core::Result<std::result::Result<serde_json::Value, (String, String)>> {
        const RETRIES: usize = 19;
        for attempt in 0..=RETRIES {
            let r = {
                let c = self.client()?;
                c.as_ref().expect("made").query(route, params).map_err(|e| unavailable(&self.url, format!("{e:#}")))?
            };
            match r {
                Ok(v) => return Ok(Ok(v)),
                Err((code, msg)) if matches!(code.as_str(), "warming" | "deadline" | "indexing") => {
                    if attempt < RETRIES && code != "warming" {
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        continue;
                    }
                    return Err(unavailable(&self.url, format!("the server answered {msg} ({code})")));
                }
                Err((code, msg)) => return Ok(Err((code, msg))),
            }
        }
        Err(unavailable(&self.url, "the server kept preparing this history"))
    }
}

/// Attach the server to a thin clone opened as `repo` (nothing for any
/// other repository). Without it, what the clone has not fetched reads as
/// [`VeilError::Unavailable`].
pub fn attach(repo: &Repo, identity: &Identity) {
    let Some(p) = &repo.config().partial else { return };
    let Some(Some(Ok(url))) = repo.config().remotes.get(&p.remote).map(|r| HubUrl::parse(&r.url)) else { return };
    let prefix = format!("{}/", p.remote);
    let tips = repo.view().remote_tags.iter().filter(|(k, _)| k.starts_with(&prefix)).map(|(_, v)| *v).collect();
    // The daemon keeps what the working copies check out (S6): the trees
    // of each workspace's snapshot and of its parents (on the server).
    pin_working_copies(repo, &url);
    repo.store().set_promisor(Arc::new(HubPromisor {
        url,
        identity: identity.clone(),
        client: Mutex::new(None),
        tips,
        asked_grants: std::sync::atomic::AtomicBool::new(false),
    }));
}

/// Tell a running daemon (it is not started for this) which trees this
/// clone's working copies check out, so it never evicts them.
fn pin_working_copies(repo: &Repo, url: &HubUrl) {
    #[cfg(unix)]
    {
        if !daemon_on() || !crate::daemon::paths().socket.exists() {
            return;
        }
        let mut roots = Vec::new();
        for ws in repo.view().workspaces.values() {
            let Ok(Some(s)) = repo.held().snapshot(&ws.wc) else { continue };
            roots.push(s.tree);
            for p in &s.parents {
                if let Ok(Some(ps)) = repo.held().snapshot(p) {
                    roots.push(ps.tree);
                }
            }
        }
        roots.sort();
        roots.dedup();
        roots.truncate(64);
        let key = blake3::hash(repo.config().repo_id.as_bytes()).to_hex().to_string();
        crate::daemon::pin(&url.authority, &url.project, &key, roots);
    }
    #[cfg(not(unix))]
    let _ = (repo, url);
}

/// `vl partial`.
#[derive(clap::Subcommand, Debug)]
pub enum PartialCmd {
    /// Show what this thin clone holds: its object cache, its bound and
    /// what the working copies pin.
    Status,
    /// Set the bound of the object cache (bytes, or with K, M or G).
    Limit {
        /// The new bound, for instance `8G`.
        size: String,
    },
    /// Fetch every snapshot and object you may see, and make this an
    /// ordinary (full) clone.
    Full,
}

pub fn run(ctx: &mut Ctx, cmd: &PartialCmd) -> Result<()> {
    let Some(p) = ctx.repo.config().partial.clone() else {
        bail!("this is not a thin clone: it holds everything it can see already");
    };
    match cmd {
        PartialCmd::Status => status(ctx, &p.remote),
        PartialCmd::Limit { size } => {
            let limit = parse_size(size)?;
            if limit == 0 {
                bail!("the cache needs room for what is checked out; give a size above 0");
            }
            ctx.repo.update_config(|c| {
                if let Some(p) = c.partial.as_mut() {
                    p.cache_limit = limit;
                }
                Ok(())
            })?;
            let t = ctx.repo.store().trim_cache()?;
            println!("Object cache bound set to {} (holds {})", human(limit), human(t.after));
            Ok(())
        }
        PartialCmd::Full => full(ctx, &p.remote),
    }
}

fn status(ctx: &Ctx, remote: &str) -> Result<()> {
    let store = ctx.repo.store();
    let u = store.cache_usage()?.ok_or_else(|| anyhow!("no object cache"))?;
    let snapshots = veil_core::store::ObjectStore::stats(store)?;
    println!("Thin clone of {} ({remote})", crate::render::safe(&ctx.repo.config().remotes.get(remote).map(|r| r.url.clone()).unwrap_or_default()));
    println!(
        "  object cache  {} of {} ({} pinned by what is checked out; {} pack(s), {} loose)",
        human(u.bytes),
        human(u.limit),
        human(u.pinned),
        u.packs,
        u.loose
    );
    println!(
        "  this clone's own  {} object(s), {} (snapshots, and what you made here: never evicted)",
        snapshots.loose_objects + snapshots.packed_objects,
        human(snapshots.loose_bytes + snapshots.pack_bytes)
    );
    println!("  {}", dim("everything else is fetched from the server when read; `vl partial full` fetches it all"));
    Ok(())
}

/// `vl partial full`: every snapshot and object into the main store, then
/// the marker removed (format 8). The marker goes last: until then the
/// clone is a thin one, which reads what it lacks from the server, never
/// as hidden.
fn full(ctx: &mut Ctx, remote: &str) -> Result<()> {
    let (client, cfg) = crate::hub_cmd::client_for(ctx, remote)?;
    let r = crate::hub::pull_with(&mut ctx.repo, remote, &client, cfg.only.as_deref(), true)?;
    for w in &r.warnings {
        crate::render::warn(&crate::render::safe(w));
    }
    // What this clone made itself, and what only its own commits reach
    // (an object fetched from an older server tip): copied into the main
    // store, from the cache or the server.
    let promoted = promote_local(&ctx.repo)?;
    ctx.repo.update_config(|c| {
        c.partial = None;
        c.format = veil_core::repo::REPO_FORMAT;
        c.min_vl = Some(veil_core::repo::min_vl_for_format(c.format).to_string());
        Ok(())
    })?;
    // The history index's entries at the thin boundary took their
    // generation from the server and list no missing parents: computed
    // again, so that history arriving below a head is noticed (BUG-1960).
    ctx.repo.discard_history_index();
    // The cache is no longer read: removed (best effort; `.veil/cache/`
    // is nothing but fetched copies).
    let cache = ctx.root.join(veil_core::promisor::CACHE_DIR);
    if cache.starts_with(&ctx.root) {
        let _ = std::fs::remove_dir_all(&cache);
    }
    println!(
        "{} this is a full clone now ({} object(s) fetched, {} kept from the cache)",
        green("done:"),
        r.objects_copied,
        promoted
    );
    Ok(())
}

/// Copy into the main store every object that the history this clone now
/// holds reaches and that only the cache holds (or nobody: fetched): every
/// snapshot of the view and of every operation the op log keeps, every tree
/// and file below. A working copy's snapshot reuses fetched files it did
/// not change (BUG-1293), and the widening pull does not walk into a tree
/// the main store already has, so both are covered here. Returns how many
/// objects were copied.
fn promote_local(repo: &Repo) -> Result<usize> {
    let store: &Arc<ObjectStore> = repo.store();
    let mut roots = repo.view().refs();
    for (_, op) in repo.op_log(usize::MAX)? {
        roots.extend(op.view.refs());
    }
    roots.sort();
    roots.dedup();
    // Held: after the widening pull every snapshot is.
    let mut stack: Vec<ObjectId> = Vec::new();
    for s in repo.held().topo_children_first(roots)? {
        if let Some(snap) = repo.held().snapshot(&s)? {
            stack.push(snap.tree);
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut incoming = veil_core::remote::Incoming::new(store);
    let mut copied = 0;
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let in_main = store.has_main(&id);
        let raw = match store.get_raw(&id) {
            Ok(raw) => raw,
            Err(e) if e.is_unreadable() => continue,
            Err(e) => return Err(e.into()),
        };
        match veil_core::object::Object::decode(&raw)? {
            veil_core::object::Object::Tree(t) => stack.extend(t.entries.iter().map(|e| e.id)),
            veil_core::object::Object::Conflict(c) => stack.extend(c.referenced_ids()),
            _ => {}
        }
        if !in_main && incoming.put(id, raw, "")? {
            copied += 1;
        }
    }
    incoming.finish()?;
    Ok(copied)
}
