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

impl Promisor for HubPromisor {
    fn fetch(&self, wants: &[Located]) -> veil_core::Result<Vec<Option<Vec<u8>>>> {
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
            404 => wants.iter().map(|w| Ok(self.fetch(std::slice::from_ref(w))?.pop().flatten())).collect(),
            s => Err(self.refused(s, &out)),
        }
    }

    fn history(&self, tips: &[ObjectId], limit: usize) -> veil_core::Result<Vec<(ObjectId, Vec<u8>)>> {
        if tips.is_empty() {
            return Ok(Vec::new());
        }
        let req = HistoryRequest { tips: tips.to_vec(), stop: Vec::new(), limit: Some(limit) };
        let (status, out) = self.post("/history", serde_json::to_vec(&req)?)?;
        match status {
            200 => crate::hub::objects_of(&out).map_err(|e| unavailable(&self.url, format!("{e:#}"))),
            // A tip this person's history does not have is left out.
            404 if tips.len() == 1 => Ok(Vec::new()),
            404 => {
                let mut all = Vec::new();
                for t in tips {
                    all.extend(self.history(std::slice::from_ref(t), limit)?);
                    if all.len() >= limit {
                        break;
                    }
                }
                Ok(all)
            }
            s => Err(self.refused(s, &out)),
        }
    }

    fn server_tips(&self) -> Vec<ObjectId> {
        self.tips.clone()
    }

    fn resolve(&self, prefix: &str) -> veil_core::Result<Option<veil_core::hub::wire::Resolved>> {
        // Only letters and digits reach the URL (a prefix is hex or k–z).
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Ok(Some(Default::default()));
        }
        let path = format!("/q/resolve?prefix={prefix}");
        // The viewer's graph may still be filling ("warming"): ask again,
        // as any client of the query API does, for about 10 s.
        for attempt in 0..20 {
            let (status, out) = {
                let c = self.client()?;
                c.as_ref().expect("made").get_status(&path).map_err(|e| unavailable(&self.url, format!("{e:#}")))?
            };
            match status {
                200 => return serde_json::from_slice(&out).map(Some).map_err(|e| unavailable(&self.url, e)),
                // A server without the route (older than revision 5).
                404 | 405 => return Ok(None),
                503 if attempt < 19 => std::thread::sleep(std::time::Duration::from_millis(500)),
                s => return Err(self.refused(s, &out)),
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
    repo.store().set_promisor(Arc::new(HubPromisor { url, identity: identity.clone(), client: Mutex::new(None), tips }));
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

/// Copy into the main store every object the snapshots only this clone
/// holds (not reachable from the server's tips) reach, that is not there
/// yet. Returns how many were copied.
fn promote_local(repo: &Repo) -> Result<usize> {
    let store: &Arc<ObjectStore> = repo.store();
    let prefix = format!("{}/", repo.config().partial.as_ref().map_or("origin", |p| p.remote.as_str()));
    let server: Vec<ObjectId> = repo.view().remote_tags.iter().filter(|(k, _)| k.starts_with(&prefix)).map(|(_, v)| *v).collect();
    let local = repo.graph().range(repo, &repo.view().refs(), &server)?;
    let mut seen = std::collections::HashSet::new();
    let mut stack: Vec<ObjectId> = Vec::new();
    for s in &local {
        stack.push(repo.snapshot(s)?.tree);
    }
    let mut copied = 0;
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let raw = match store.get_raw(&id) {
            Ok(raw) => raw,
            Err(e) if e.is_unreadable() => continue,
            Err(e) => return Err(e.into()),
        };
        if !store.has_main(&id) {
            store.put_raw(&id, &raw)?;
            copied += 1;
        }
        match veil_core::object::Object::decode(&raw)? {
            veil_core::object::Object::Tree(t) => stack.extend(t.entries.iter().map(|e| e.id)),
            veil_core::object::Object::Conflict(c) => stack.extend(c.referenced_ids()),
            _ => {}
        }
    }
    Ok(copied)
}
