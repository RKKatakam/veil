//! Health metrics per project (design §4.11, `docs/HUB.md` §13.25): what
//! this server counted for the project since it started and over the last
//! minute, and how far its derived history lags. **Admins of the project
//! only** (`GET /v1/projects/{p}/health`, `vl stats`): the counts include
//! work by people and on folders others may not see. Nothing here names a
//! person, a device, a path or another project.
//!
//! Landing metrics (landings per second, time to land, batch sizes, queue
//! depth, conflicts) join [`Counts`] with the landing service (S17).

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;

use crate::{
    auth::Caller,
    error::{Error, Result},
    HubState,
};

/// What is counted per project.
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Counts {
    /// Requests that named the project.
    pub requests: u64,
    /// Refused for their device's or address's rate (`429`).
    pub rate_limited: u64,
    /// Refused `busy` (`503`): shed under load, or the database busy.
    pub busy: u64,
    /// Bodies that came too slowly (`408`).
    pub timeouts: u64,
    /// The request-path caches (`caches`): branch tips and permissions.
    pub tips_hits: u64,
    pub tips_misses: u64,
    pub permission_hits: u64,
    pub permission_misses: u64,
    /// The landing service (S17, S24 part B): changes landed, batches
    /// committed, conflicts and rejections.
    pub landings: u64,
    pub landing_batches: u64,
    pub landing_conflicts: u64,
    pub landing_rejected: u64,
}

impl Counts {
    fn add(&mut self, o: &Counts) {
        self.requests += o.requests;
        self.rate_limited += o.rate_limited;
        self.busy += o.busy;
        self.timeouts += o.timeouts;
        self.tips_hits += o.tips_hits;
        self.tips_misses += o.tips_misses;
        self.permission_hits += o.permission_hits;
        self.permission_misses += o.permission_misses;
        self.landings += o.landings;
        self.landing_batches += o.landing_batches;
        self.landing_conflicts += o.landing_conflicts;
        self.landing_rejected += o.landing_rejected;
    }
}

#[derive(Default)]
struct Window {
    total: Counts,
    /// The minute (since the server started) `this` counts, and the one
    /// before it.
    minute: u64,
    this: Counts,
    last: Counts,
}

impl Window {
    fn roll(&mut self, minute: u64) {
        if minute != self.minute {
            self.last = if minute == self.minute + 1 { self.this } else { Counts::default() };
            self.this = Counts::default();
            self.minute = minute;
        }
    }
}

const SHARDS: usize = 16;

/// The counters of every project this server served, by id.
pub struct Health {
    started: Instant,
    started_ms: i64,
    shards: Vec<Mutex<HashMap<i64, Window>>>,
}

impl Default for Health {
    fn default() -> Health {
        let started_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
        Health { started: Instant::now(), started_ms, shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect() }
    }
}

impl Health {
    fn minute(&self) -> u64 {
        self.started.elapsed().as_secs() / 60
    }

    /// Add `c` to `project`'s counts.
    pub fn record(&self, project: i64, c: &Counts) {
        let minute = self.minute();
        let mut m = self.shards[project.rem_euclid(SHARDS as i64) as usize].lock().unwrap();
        let w = m.entry(project).or_default();
        w.roll(minute);
        w.total.add(c);
        w.this.add(c);
    }

    /// Since the start, and over the last whole minute.
    pub fn read(&self, project: i64) -> (Counts, Counts) {
        let minute = self.minute();
        let mut m = self.shards[project.rem_euclid(SHARDS as i64) as usize].lock().unwrap();
        match m.get_mut(&project) {
            Some(w) => {
                w.roll(minute);
                (w.total, w.last)
            }
            None => Default::default(),
        }
    }
}

/// A request-path cache, for [`hit`].
#[derive(Clone, Copy, Debug)]
pub enum Layer {
    Tips,
    Permissions,
}

/// Shareable per-request cache hit/miss counters carried by [`super::REQUEST`].
#[derive(Default)]
pub(crate) struct LayerCounts {
    tips_hits: AtomicU64,
    tips_misses: AtomicU64,
    permission_hits: AtomicU64,
    permission_misses: AtomicU64,
}

impl LayerCounts {
    pub(crate) fn hit(&self, layer: Layer, hit: bool) {
        match (layer, hit) {
            (Layer::Tips, true) => self.tips_hits.fetch_add(1, Ordering::Relaxed),
            (Layer::Tips, false) => self.tips_misses.fetch_add(1, Ordering::Relaxed),
            (Layer::Permissions, true) => self.permission_hits.fetch_add(1, Ordering::Relaxed),
            (Layer::Permissions, false) => self.permission_misses.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub(crate) fn snapshot(&self) -> Counts {
        Counts {
            tips_hits: self.tips_hits.load(Ordering::Relaxed),
            tips_misses: self.tips_misses.load(Ordering::Relaxed),
            permission_hits: self.permission_hits.load(Ordering::Relaxed),
            permission_misses: self.permission_misses.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
}

/// Count a hit or a miss of `layer` for the request being served (nothing
/// outside a request).
pub fn hit(layer: Layer, hit: bool) {
    super::record_layer_hit(layer, hit);
}

#[derive(Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub project: String,
    /// This server's counts: each server counts what it served.
    pub server_started_ms: i64,
    pub since_start: Counts,
    pub last_minute: Counts,
    pub derive: DeriveLag,
}

#[derive(Serialize)]
pub struct DeriveLag {
    pub branches: i64,
    /// Branches whose derived history (S12) is not at their tip yet.
    pub branches_behind: i64,
}

/// `GET /v1/projects/{p}/health`: the project's metrics, for its admins
/// only. Someone who cannot see the project gets what a project that does
/// not exist gets; anyone else who is not an admin, `403`.
pub async fn route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>) -> Result<Json<Report>> {
    caller.signed_in()?;
    let (project, viewer) = crate::perm::open(&hub, &p, &caller).await?;
    // A narrowed agent session sees statistics over its own paths only
    // (BUG-1536), and these counts are the whole project's (BUG-1995).
    if !viewer.admin || viewer.only.is_some() {
        return Err(Error::forbidden("only the project's admins see its health"));
    }
    let (since_start, last_minute) = hub.limits.health.read(project.id);
    let (branches, branches_behind): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE d.through_snapshot IS DISTINCT FROM b.target) FROM branches b \
         LEFT JOIN derive_progress d ON d.project_id = b.project_id AND d.branch = b.name AND d.index_name = $2 AND d.index_version = $3 \
         WHERE b.project_id = $1 AND b.hidden_for_embargo IS NULL",
    )
    .bind(project.id)
    .bind(crate::derive::INDEX.0)
    .bind(crate::derive::INDEX.1)
    .fetch_one(&hub.db)
    .await?;
    Ok(Json(Report {
        schema: "veil.health/1",
        project: project.name,
        server_started_ms: hub.limits.health.started_ms,
        since_start,
        last_minute,
        derive: DeriveLag { branches, branches_behind },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Projects' counts are apart, and a minute's roll keeps the last one.
    #[test]
    fn counts_are_per_project() {
        let h = Health::default();
        h.record(1, &Counts { requests: 3, busy: 1, ..Default::default() });
        h.record(2, &Counts { requests: 5, ..Default::default() });
        assert_eq!(h.read(1).0, Counts { requests: 3, busy: 1, ..Default::default() });
        assert_eq!(h.read(2).0.requests, 5);
        assert_eq!(h.read(3).0, Counts::default());
        let mut w = Window::default();
        w.this.requests = 7;
        w.roll(1);
        assert_eq!((w.last.requests, w.this.requests), (7, 0));
        w.roll(3);
        assert_eq!(w.last.requests, 0, "a minute with nothing in it");
    }
}
