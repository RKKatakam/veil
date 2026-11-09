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
/// How often a followed project's tips are asked for: every second after
/// its tip moved, twice as long after each unchanged answer, at most once a
/// minute (BUG-1681: a project followed for a week costs about 60 requests
/// an hour while idle, not 3,600).
const POLL_MIN_MS: i64 = 1_000;
const POLL_MAX_MS: i64 = 60_000;

pub fn run(_p: &Paths) -> Result<()> {
    let path = crate::ctx::identity_path();
    if !path.exists() {
        return Ok(());
    }
    let identity = crate::ctx::load_identity()?;
    let mut warmed: HashMap<(String, String), ObjectId> = HashMap::new();
    let mut clients: HashMap<(String, String), Client> = HashMap::new();
    let mut backoff_until: HashMap<String, i64> = HashMap::new();
    // Each project's next poll and the interval after it.
    let mut next_poll: HashMap<(String, String), (i64, i64)> = HashMap::new();
    loop {
        let tick = Instant::now();
        let Some(s) = super::connect() else { return Ok(()) };
        let follows: Vec<(String, String)> = super::request(s, &Request::Follows, &|_| false)
            .1
            .and_then(|h| h.body)
            .and_then(|b| serde_json::from_value(b).ok())
            .unwrap_or_default();
        next_poll.retain(|k, _| follows.contains(k));
        for (authority, project) in follows {
            if backoff_until.get(&authority).is_some_and(|until| veil_core::now_millis() < *until) {
                continue;
            }
            let k = (authority.clone(), project.clone());
            let now = veil_core::now_millis();
            let (due, interval) = next_poll.get(&k).copied().unwrap_or((now, POLL_MIN_MS / 2));
            if now < due {
                continue;
            }
            // Unchanged or failed: twice as long; a moved tip resets it below.
            let longer = (interval * 2).clamp(POLL_MIN_MS, POLL_MAX_MS);
            next_poll.insert(k.clone(), (now + longer, longer));
            if !clients.contains_key(&k) {
                let Some(Ok(url)) = HubUrl::parse(&format!("veil://{authority}/{project}")) else { continue };
                let Ok(c) = Client::new(&url, identity.clone()) else { continue };
                clients.insert(k.clone(), c);
            }
            let c = &clients[&k];
            let Ok((tips, wait_ms)) = c.tips_once() else { continue };
            if wait_ms > 0 {
                backoff_until.insert(authority, veil_core::now_millis().saturating_add(wait_ms.min(300_000)));
                continue;
            }
            let Some(tips) = tips else { continue };
            let (Some(token), Some(key)) = (tips.grants.get(&tips.default_branch), tips.grant_key.as_ref()) else { continue };
            let Some(g) = Grant::verify(token, key) else { continue };
            if warmed.get(&k) == Some(&g.body.root) {
                continue;
            }
            warm(&authority, &project, &identity, &g, token);
            next_poll.insert(k.clone(), (veil_core::now_millis() + POLL_MIN_MS, POLL_MIN_MS));
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
