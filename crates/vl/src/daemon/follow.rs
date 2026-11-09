//! `vl daemon follow`: warm trees of followed projects (design §4.6,
//! "Warm start"). The daemon holds no key and no session, so it cannot ask
//! the server for tips or sign a request; this `vl` of the same Veil home
//! does, as any `vl` would: once a second it asks for the tips of every
//! project the daemon follows (one a thin clone read through it), and when
//! the default branch's projected root changes, reads its trees down to
//! [`DEPTH`] through the daemon, which keeps them. A new clone or workspace
//! then finds its first trees on the machine.
//!
//! It exits when the daemon stops answering, and holds nothing but what any
//! `vl` holds (the device key, its session).

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use anyhow::Result;
use veil_core::{
    hub::grant::Grant,
    object::{EntryKind, Object},
    ObjectId,
};

use super::{proto::Request, Paths};
use crate::hub::{Client, HubUrl};

/// Trees below the root kept warm (the root is depth 0).
pub const DEPTH: usize = 3;
/// Most trees one warm-up reads.
const MAX_TREES: usize = 4_000;
/// Most objects per request.
const PART: usize = 1_000;

pub fn run(_p: &Paths) -> Result<()> {
    let path = crate::ctx::identity_path();
    if !path.exists() {
        return Ok(());
    }
    let identity = crate::ctx::load_identity()?;
    let mut warmed: HashMap<(String, String), ObjectId> = HashMap::new();
    let mut clients: HashMap<(String, String), Client> = HashMap::new();
    loop {
        let tick = Instant::now();
        let Some(s) = super::connect() else { return Ok(()) };
        let follows: Vec<(String, String)> = super::request(s, &Request::Follows, &|_| false)
            .1
            .and_then(|h| h.body)
            .and_then(|b| serde_json::from_value(b).ok())
            .unwrap_or_default();
        for (authority, project) in follows {
            let k = (authority.clone(), project.clone());
            if !clients.contains_key(&k) {
                let Some(Ok(url)) = HubUrl::parse(&format!("veil://{authority}/{project}")) else { continue };
                let Ok(c) = Client::new(&url, identity.clone()) else { continue };
                clients.insert(k.clone(), c);
            }
            let c = &clients[&k];
            let Ok(Some(tips)) = c.tips() else { continue };
            let (Some(token), Some(key)) = (tips.grants.get(&tips.default_branch), tips.grant_key.as_ref()) else { continue };
            let Some(g) = Grant::verify(token, key) else { continue };
            if warmed.get(&k) == Some(&g.body.root) {
                continue;
            }
            warm(&authority, &project, &identity, &g, token);
            warmed.insert(k, g.body.root);
        }
        std::thread::sleep(Duration::from_secs(1).saturating_sub(tick.elapsed()));
    }
}

/// Read the trees of `grant`'s root down to [`DEPTH`] through the daemon.
fn warm(authority: &str, project: &str, identity: &veil_core::Identity, grant: &Grant, token: &str) {
    let mut level: Vec<(Vec<ObjectId>, ObjectId)> = vec![(Vec::new(), grant.body.root)];
    let mut seen = HashSet::from([grant.body.root]);
    for _ in 0..=DEPTH {
        if level.is_empty() {
            break;
        }
        let mut got: HashMap<ObjectId, Vec<u8>> = HashMap::new();
        for part in level.chunks(PART) {
            got.extend(super::fetch_under(authority, project, identity, grant, token, part.to_vec()));
        }
        let mut next = Vec::new();
        for (chain, id) in &level {
            let Some(Ok(Object::Tree(t))) = got.get(id).map(|raw| Object::decode(raw)) else { continue };
            for e in t.entries.iter().filter(|e| e.kind == EntryKind::Dir) {
                if seen.len() < MAX_TREES && seen.insert(e.id) {
                    next.push(([chain.clone(), vec![*id]].concat(), e.id));
                }
            }
        }
        level = next;
    }
}
