//! The project event stream: `GET /v1/projects/{p}/events` (milestone S18;
//! `docs/HUB.md` §13.30; `docs/design/server/phase-4-agent-scale.md` §4.3,
//! §5.4).
//!
//! Server-Sent Events (`text/event-stream`) telling a signed-in participant
//! what happened to their landing submissions (`land.requeued`, `land.landed`,
//! `land.conflict`, `land.rejected`) and when a branch moved (`main.moved`).
//!
//! **Guarantees:**
//! * Every event is re-checked and projected for the receiver's current
//!   [`View`](veil_core::hub::access::View) at delivery (`landing::seen`):
//!   a branch move that collapsed for the viewer emits nothing, and a
//!   conflict in a hidden path reports only `"conflicts with changes you
//!   can't see"`, naming no hidden path, count or content.
//! * Streams are bounded per person ([`MAX_STREAMS_PER_PERSON`]) and per
//!   connection/device ([`MAX_STREAMS_PER_CONNECTION`]).
//! * Each stream holds at most [`MAX_QUEUE_PER_STREAM`] frames and at most
//!   [`MAX_BYTES_PER_STREAM`] bytes in memory; a slow or absent reader whose
//!   queue overflows is evicted at once and its held memory freed to zero.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::Deserialize;
use tokio::sync::Notify;
use veil_core::{
    hub::land::{LandResult, LandState},
    ObjectId,
};

use crate::{
    auth::{Caller, Person},
    error::{Error, Result},
    Hub,
};

/// Most open event streams one person may hold at once on a server.
pub const MAX_STREAMS_PER_PERSON: usize = 8;
/// Most open event streams one connection/device key may hold at once.
pub const MAX_STREAMS_PER_CONNECTION: usize = 8;
/// Most unread event frames queued for one stream before it is evicted.
pub const MAX_QUEUE_PER_STREAM: usize = 64;
/// Most unread event bytes queued for one stream before it is evicted.
pub const MAX_BYTES_PER_STREAM: usize = 64 << 10;

/// Optional filters on `GET /v1/projects/{p}/events`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub ticket: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub types: Option<String>,
}

struct SubQueue {
    frames: VecDeque<Bytes>,
    bytes: usize,
    closed: bool,
}

struct Subscriber {
    id: u64,
    project_id: i64,
    project_name: String,
    person: Person,
    conn_key: (IpAddr, String),
    ticket: Option<String>,
    branch: Option<String>,
    types: Option<Vec<String>>,
    queue: Mutex<SubQueue>,
    wake: Notify,
    released: AtomicBool,
}

impl Subscriber {
    fn wants_type(&self, event_name: &str, state_name: &str) -> bool {
        match &self.types {
            None => true,
            Some(list) => list.iter().any(|t| {
                t == event_name || t == state_name || (t == "pr.*" && event_name.starts_with("pr."))
            }),
        }
    }
}

/// Active event streams on this server.
pub struct Events {
    next_id: AtomicU64,
    subscribers: Mutex<HashMap<u64, Arc<Subscriber>>>,
    per_person: Mutex<HashMap<i64, usize>>,
    per_conn: Mutex<HashMap<(IpAddr, String), usize>>,
    total_bytes: Arc<AtomicUsize>,
}

impl Default for Events {
    fn default() -> Self {
        Events {
            next_id: AtomicU64::new(1),
            subscribers: Mutex::new(HashMap::new()),
            per_person: Mutex::new(HashMap::new()),
            per_conn: Mutex::new(HashMap::new()),
            total_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Events {
    /// Total number of active event streams on this server.
    pub fn open_total(&self) -> usize {
        self.subscribers.lock().unwrap().len()
    }

    /// Number of active event streams open for `person_id`.
    pub fn open_for(&self, person_id: i64) -> usize {
        self.per_person.lock().unwrap().get(&person_id).copied().unwrap_or(0)
    }

    /// Total bytes of unread event frames currently held in memory across all
    /// open streams.
    pub fn held_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::SeqCst)
    }

    /// Remove subscriber `sub`, freeing its queued frames and decrementing its
    /// per-person and per-connection counters once.
    fn evict(&self, sub: &Arc<Subscriber>) {
        self.subscribers.lock().unwrap().remove(&sub.id);
        {
            let mut q = sub.queue.lock().unwrap();
            if q.bytes > 0 {
                self.total_bytes.fetch_sub(q.bytes, Ordering::SeqCst);
                q.bytes = 0;
            }
            q.frames.clear();
            q.frames.shrink_to_fit();
            q.closed = true;
        }
        if !sub.released.swap(true, Ordering::SeqCst) {
            {
                let mut pp = self.per_person.lock().unwrap();
                if let Some(n) = pp.get_mut(&sub.person.id) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        pp.remove(&sub.person.id);
                    }
                }
            }
            {
                let mut pc = self.per_conn.lock().unwrap();
                if let Some(n) = pc.get_mut(&sub.conn_key) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        pc.remove(&sub.conn_key);
                    }
                }
            }
        }
        sub.wake.notify_waiters();
    }

    /// Enqueue `frame` for `sub` without blocking; if `sub`'s bounded queue is
    /// full or exceeds [`MAX_BYTES_PER_STREAM`], evict `sub` immediately so a
    /// slow or absent reader never holds server memory.
    fn push_frame(&self, sub: &Arc<Subscriber>, frame: Bytes) {
        let len = frame.len();
        let overflow = {
            let mut q = sub.queue.lock().unwrap();
            if q.closed {
                return;
            }
            if q.frames.len() >= MAX_QUEUE_PER_STREAM || q.bytes + len > MAX_BYTES_PER_STREAM {
                true
            } else {
                q.bytes += len;
                self.total_bytes.fetch_add(len, Ordering::SeqCst);
                q.frames.push_back(frame);
                false
            }
        };
        if overflow {
            self.evict(sub);
        } else {
            sub.wake.notify_one();
        }
    }
}

/// Route handler for `GET /v1/projects/{p}/events`.
pub async fn route(
    axum::extract::State(hub): axum::extract::State<crate::HubState>,
    caller: Caller,
    peer: Option<axum::Extension<crate::limits::Peer>>,
    axum::extract::Path(p): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<EventsQuery>,
) -> Result<Response> {
    open(&hub, &caller, peer.map(|axum::Extension(x)| x.0), &p, q).await
}

/// Open an SSE stream for `caller` on project `project_name`.
pub async fn open(
    hub: &Arc<Hub>,
    caller: &Caller,
    peer: Option<IpAddr>,
    project_name: &str,
    query: EventsQuery,
) -> Result<Response> {
    let person = caller.signed_in()?.clone();
    let (project, viewer) = crate::perm::open(hub, project_name, caller).await?;
    if !project.participant(&viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    let ip = peer.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let conn_key = (ip, person.device_key.clone());

    let sub = {
        let mut pp = hub.events.per_person.lock().unwrap();
        let mut pc = hub.events.per_conn.lock().unwrap();
        let person_count = pp.get(&person.id).copied().unwrap_or(0);
        let conn_count = pc.get(&conn_key).copied().unwrap_or(0);
        if person_count >= MAX_STREAMS_PER_PERSON || conn_count >= MAX_STREAMS_PER_CONNECTION {
            return Err(Error::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many event streams open for this person or connection",
            ));
        }
        *pp.entry(person.id).or_default() += 1;
        *pc.entry(conn_key.clone()).or_default() += 1;
        let id = hub.events.next_id.fetch_add(1, Ordering::Relaxed);
        let types = query
            .types
            .as_ref()
            .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect::<Vec<_>>())
            .filter(|v| !v.is_empty());
        let sub = Arc::new(Subscriber {
            id,
            project_id: project.id,
            project_name: project.name.clone(),
            person: person.clone(),
            conn_key,
            ticket: query.ticket.clone(),
            branch: query.branch.clone(),
            types,
            queue: Mutex::new(SubQueue {
                frames: VecDeque::new(),
                bytes: 0,
                closed: false,
            }),
            wake: Notify::new(),
            released: AtomicBool::new(false),
        });
        hub.events.subscribers.lock().unwrap().insert(id, sub.clone());
        sub
    };

    // If a specific ticket was requested and already has an outcome, enqueue
    // it immediately so a caller subscribing after submit does not miss it.
    if let Some(t) = &query.ticket {
        if let Ok(Some((branch, r))) = crate::landing::read(hub, project.id, person.id, t).await {
            if r.state != LandState::Queued {
                if let Ok(seen) = crate::landing::seen(hub, &project, &viewer, r).await {
                    let (ev, st) = match seen.state {
                        LandState::Landed => ("land.landed", "landed"),
                        LandState::Conflict => ("land.conflict", "conflict"),
                        LandState::Rejected => ("land.rejected", "rejected"),
                        LandState::Queued => ("land.queued", "queued"),
                    };
                    if sub.wants_type(ev, st) {
                        let frame = format_ticket_sse(ev, st, &branch, &seen);
                        hub.events.push_frame(&sub, frame);
                    }
                }
            }
        }
    }

    crate::limits::leave_gates();
    let body = StreamBody {
        hub: hub.clone(),
        sub,
        initial: Some(Bytes::from_static(b": ready\n\n")),
        wait: None,
    };
    let mut resp = Response::new(Body::new(body));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    Ok(resp.into_response())
}

fn format_ticket_sse(event_name: &str, state_name: &str, branch: &str, r: &LandResult) -> Bytes {
    let mut obj = serde_json::Map::new();
    obj.insert("event".into(), serde_json::Value::String(event_name.into()));
    obj.insert("state".into(), serde_json::Value::String(state_name.into()));
    obj.insert("ticket".into(), serde_json::Value::String(r.ticket.clone()));
    obj.insert("branch".into(), serde_json::Value::String(branch.into()));
    if let Some(cid) = &r.change_id {
        obj.insert("change_id".into(), serde_json::Value::String(cid.to_string()));
    }
    if !r.landed.is_empty() {
        obj.insert(
            "landed".into(),
            serde_json::Value::Array(r.landed.iter().map(|x| serde_json::Value::String(x.hex())).collect()),
        );
    }
    if let Some(onto) = &r.onto {
        obj.insert("onto".into(), serde_json::Value::String(onto.hex()));
    }
    if let Some(base) = &r.base {
        obj.insert("base".into(), serde_json::Value::String(base.hex()));
    }
    if !r.paths.is_empty() {
        obj.insert(
            "paths".into(),
            serde_json::Value::Array(r.paths.iter().map(|p| serde_json::Value::String(p.clone())).collect()),
        );
    }
    if !r.conflicts.is_empty() {
        if let Ok(v) = serde_json::to_value(&r.conflicts) {
            obj.insert("conflicts".into(), v);
        }
    }
    if !r.landed_since.is_empty() {
        obj.insert(
            "landed_since".into(),
            serde_json::Value::Array(r.landed_since.iter().map(|x| serde_json::Value::String(x.hex())).collect()),
        );
    }
    if r.merges > 0 {
        obj.insert("merges".into(), serde_json::Value::Number(r.merges.into()));
    }
    if let Some(msg) = &r.message {
        obj.insert("message".into(), serde_json::Value::String(msg.clone()));
    }
    if !r.warnings.is_empty() {
        obj.insert(
            "warnings".into(),
            serde_json::Value::Array(r.warnings.iter().map(|w| serde_json::Value::String(w.clone())).collect()),
        );
    }
    let data = serde_json::Value::Object(obj).to_string();
    Bytes::from(format!("event: {event_name}\ndata: {data}\n\n"))
}

/// Emit a ticket lifecycle event (`land.requeued`, `land.landed`,
/// `land.conflict`, `land.rejected`) to its submitter's active streams,
/// re-checking and projecting `result` through the receiver's current view.
pub async fn emit_ticket(
    hub: &Arc<Hub>,
    project_id: i64,
    branch: &str,
    person_id: i64,
    event_name: &str,
    state_name: &str,
    result: LandResult,
) {
    let subs: Vec<Arc<Subscriber>> = {
        let map = hub.events.subscribers.lock().unwrap();
        map.values()
            .filter(|s| {
                s.project_id == project_id
                    && s.person.id == person_id
                    && s.branch.as_deref().is_none_or(|b| b == branch)
                    && s.ticket.as_deref().is_none_or(|t| t == result.ticket)
                    && s.wants_type(event_name, state_name)
            })
            .cloned()
            .collect()
    };
    if subs.is_empty() {
        return;
    }
    for sub in subs {
        if let Some(a) = &sub.person.agent {
            match crate::auth::load_agent_session(&hub.db, &a.session_hash, sub.person.id, project_id).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    hub.events.evict(&sub);
                    continue;
                }
                Err(_) => continue,
            }
        }
        // Read current access epochs from the database before opening the
        // subscriber's view so permission changes are seen at once and never
        // poison the viewer cache with epoch 0.
        let Ok(epochs) = crate::caches::read_epochs(&hub.db, sub.person.id, Some(project_id)).await else {
            continue;
        };
        let caller = Caller {
            person: Some(sub.person.clone()),
            epochs,
        };
        let Ok((project, viewer)) = crate::perm::open(hub, &sub.project_name, &caller).await else {
            hub.events.evict(&sub);
            continue;
        };
        if !project.participant(&viewer) {
            hub.events.evict(&sub);
            continue;
        }
        let Ok(seen) = crate::landing::seen(hub, &project, &viewer, result.clone()).await else {
            continue;
        };
        let frame = format_ticket_sse(event_name, state_name, branch, &seen);
        hub.events.push_frame(&sub, frame);
    }
}

/// Emit `main.moved` to active streams on `project_id` whose viewer sees the
/// branch tip change. If the batch only touched paths hidden from a viewer
/// (their projected tip did not move), nothing is emitted to that viewer.
pub async fn emit_moved(
    hub: &Arc<Hub>,
    project_id: i64,
    branch: &str,
    old_tip: Option<ObjectId>,
    new_tip: ObjectId,
    snapshots: &[ObjectId],
) {
    let subs: Vec<Arc<Subscriber>> = {
        let map = hub.events.subscribers.lock().unwrap();
        map.values()
            .filter(|s| {
                s.project_id == project_id
                    && s.ticket.is_none()
                    && s.branch.as_deref().is_none_or(|b| b == branch)
                    && s.wants_type("main.moved", "moved")
            })
            .cloned()
            .collect()
    };
    if subs.is_empty() {
        return;
    }
    for sub in subs {
        if let Some(a) = &sub.person.agent {
            match crate::auth::load_agent_session(&hub.db, &a.session_hash, sub.person.id, project_id).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    hub.events.evict(&sub);
                    continue;
                }
                Err(_) => continue,
            }
        }
        let Ok(epochs) = crate::caches::read_epochs(&hub.db, sub.person.id, Some(project_id)).await else {
            continue;
        };
        let caller = Caller {
            person: Some(sub.person.clone()),
            epochs,
        };
        let Ok((project, viewer)) = crate::perm::open(hub, &sub.project_name, &caller).await else {
            hub.events.evict(&sub);
            continue;
        };
        if !project.participant(&viewer) {
            hub.events.evict(&sub);
            continue;
        }
        let Ok(p_new) = crate::sync::projected(hub, &project, &viewer, new_tip).await else {
            continue;
        };
        let p_old = match old_tip {
            Some(o) => crate::sync::projected(hub, &project, &viewer, o).await.ok(),
            None => Some(crate::sync::root_snapshot_id()),
        };
        if p_old == Some(p_new) {
            // The move is completely hidden from this viewer: emit nothing.
            continue;
        }
        let mut visible_snaps = Vec::new();
        let mut prev = p_old;
        for s in snapshots {
            if let Ok(ps) = crate::sync::projected(hub, &project, &viewer, *s).await {
                if Some(ps) != prev && !visible_snaps.contains(&ps) {
                    visible_snaps.push(ps);
                }
                prev = Some(ps);
            }
        }
        let data = serde_json::json!({
            "event": "main.moved",
            "state": "moved",
            "branch": branch,
            "onto": p_new.hex(),
            "landed": visible_snaps.iter().map(ObjectId::hex).collect::<Vec<_>>(),
        });
        let frame = Bytes::from(format!("event: main.moved\ndata: {data}\n\n"));
        hub.events.push_frame(&sub, frame);
    }
}

/// Emit `check.requested` to active streams on `project_id` whose viewer can
/// see the requested check (`can_see_check`) and where `real_snapshot` did not
/// collapse into its parent's projection (`docs/VISIBILITY.md`, S20).
#[allow(clippy::too_many_arguments)]
pub async fn emit_check_requested(
    hub: &Arc<Hub>,
    project_id: i64,
    branch: &str,
    real_snapshot: ObjectId,
    check_name: &str,
    session_paths: &[String],
    admin_only: bool,
    reason: &str,
) {
    let subs: Vec<Arc<Subscriber>> = {
        let map = hub.events.subscribers.lock().unwrap();
        map.values()
            .filter(|s| {
                s.project_id == project_id
                    && s.ticket.is_none()
                    && s.branch.as_deref().is_none_or(|b| b == branch)
                    && s.wants_type("check.requested", "requested")
            })
            .cloned()
            .collect()
    };
    if subs.is_empty() {
        return;
    }
    for sub in subs {
        if let Some(a) = &sub.person.agent {
            match crate::auth::load_agent_session(&hub.db, &a.session_hash, sub.person.id, project_id).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    hub.events.evict(&sub);
                    continue;
                }
                Err(_) => continue,
            }
        }
        let Ok(epochs) = crate::caches::read_epochs(&hub.db, sub.person.id, Some(project_id)).await else {
            continue;
        };
        let caller = Caller {
            person: Some(sub.person.clone()),
            epochs,
        };
        let Ok((project, viewer)) = crate::perm::open(hub, &sub.project_name, &caller).await else {
            hub.events.evict(&sub);
            continue;
        };
        if !project.participant(&viewer) {
            hub.events.evict(&sub);
            continue;
        }
        if !crate::ci::can_see_check(&project, &viewer, session_paths, admin_only) {
            continue;
        }
        if crate::embargo::is_withheld_from_viewer(hub, &project, &viewer, &real_snapshot).await.unwrap_or(true) {
            continue;
        }
        let Ok(p_snap) = crate::sync::projected(hub, &project, &viewer, real_snapshot).await else {
            continue;
        };
        if (!viewer.admin || project.view(&viewer).is_narrowed())
            && real_snapshot != crate::sync::root_snapshot_id()
        {
            let parent = crate::sync::blocking(hub, project.id, move |src| {
                Ok(src.snapshot(&real_snapshot)?.parents.first().copied())
            })
            .await
            .ok()
            .flatten();
            if let Some(p0) = parent {
                if crate::sync::projected(hub, &project, &viewer, p0).await.ok() == Some(p_snap) {
                    continue;
                }
            }
        }
        let data = serde_json::json!({
            "event": "check.requested",
            "state": "requested",
            "branch": branch,
            "snapshot": p_snap.hex(),
            "check": check_name,
            "name": check_name,
            "reason": reason,
        });
        let frame = Bytes::from(format!("event: check.requested\ndata: {data}\n\n"));
        hub.events.push_frame(&sub, frame);
    }
}

/// Emit `reverted` (`event: reverted`) to active streams on `project_id` whose
/// viewer sees the culprit and revert snapshots (`docs/VISIBILITY.md`, S20).
/// The failing `check` name is included only if the viewer can see that check.
#[allow(clippy::too_many_arguments)]
pub async fn emit_reverted(
    hub: &Arc<Hub>,
    project_id: i64,
    branch: &str,
    culprit_real: ObjectId,
    culprit_change_id: &str,
    revert_real: ObjectId,
    check_name: &str,
    session_paths: &[String],
    admin_only: bool,
) {
    let subs: Vec<Arc<Subscriber>> = {
        let map = hub.events.subscribers.lock().unwrap();
        map.values()
            .filter(|s| {
                s.project_id == project_id
                    && s.ticket.is_none()
                    && s.branch.as_deref().is_none_or(|b| b == branch)
                    && s.wants_type("reverted", "reverted")
            })
            .cloned()
            .collect()
    };
    if subs.is_empty() {
        return;
    }
    for sub in subs {
        if let Some(a) = &sub.person.agent {
            match crate::auth::load_agent_session(&hub.db, &a.session_hash, sub.person.id, project_id).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    hub.events.evict(&sub);
                    continue;
                }
                Err(_) => continue,
            }
        }
        let Ok(epochs) = crate::caches::read_epochs(&hub.db, sub.person.id, Some(project_id)).await else {
            continue;
        };
        let caller = Caller {
            person: Some(sub.person.clone()),
            epochs,
        };
        let Ok((project, viewer)) = crate::perm::open(hub, &sub.project_name, &caller).await else {
            hub.events.evict(&sub);
            continue;
        };
        if !project.participant(&viewer) {
            hub.events.evict(&sub);
            continue;
        }
        if crate::embargo::is_withheld_from_viewer(hub, &project, &viewer, &culprit_real).await.unwrap_or(true)
            || crate::embargo::is_withheld_from_viewer(hub, &project, &viewer, &revert_real).await.unwrap_or(true)
        {
            continue;
        }
        let Ok(p_culprit) = crate::sync::projected(hub, &project, &viewer, culprit_real).await else {
            continue;
        };
        let Ok(p_revert) = crate::sync::projected(hub, &project, &viewer, revert_real).await else {
            continue;
        };
        if !viewer.admin || project.view(&viewer).is_narrowed() {
            let (policy_text, bindings, v) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
            let (c_parent, r_parent, touches_visible) = crate::sync::blocking(hub, project.id, move |src| {
                let cs = src.snapshot(&culprit_real)?;
                let rs = src.snapshot(&revert_real)?;
                let cp = cs.parents.first().copied();
                let rp = rs.parents.first().copied();
                let p = crate::perm::Project {
                    id: src.project,
                    name: String::new(),
                    default_branch: String::new(),
                    policy: veil_core::hub::access::AccessPolicy::parse(&policy_text),
                    policy_text,
                    bindings,
                };
                let view = p.view(&v);
                let step = match rp {
                    Some(rp0) => crate::landing::edits::edit_set(src, rs.tree, src.snapshot(&rp0)?.tree)?,
                    None => Vec::new(),
                };
                let vis = step.iter().any(|c| view.read(&c.path) && view.within_narrowing(&c.path));
                Ok((cp, rp, vis))
            })
            .await
            .unwrap_or((None, None, false));
            if !touches_visible {
                continue;
            }
            if let Some(cp0) = c_parent {
                if crate::sync::projected(hub, &project, &viewer, cp0).await.ok() == Some(p_culprit) {
                    continue;
                }
            }
            if let Some(rp0) = r_parent {
                if crate::sync::projected(hub, &project, &viewer, rp0).await.ok() == Some(p_revert) {
                    continue;
                }
            }
        }
        let mut obj = serde_json::Map::new();
        obj.insert("event".into(), serde_json::Value::String("reverted".into()));
        obj.insert("state".into(), serde_json::Value::String("reverted".into()));
        obj.insert("branch".into(), serde_json::Value::String(branch.into()));
        obj.insert("culprit".into(), serde_json::Value::String(p_culprit.hex()));
        obj.insert("change_id".into(), serde_json::Value::String(culprit_change_id.into()));
        obj.insert("culprit_change_id".into(), serde_json::Value::String(culprit_change_id.into()));
        obj.insert("revert".into(), serde_json::Value::String(p_revert.hex()));
        if crate::ci::can_see_check(&project, &viewer, session_paths, admin_only) {
            obj.insert("check".into(), serde_json::Value::String(check_name.into()));
        }
        let data = serde_json::Value::Object(obj).to_string();
        let frame = Bytes::from(format!("event: reverted\ndata: {data}\n\n"));
        hub.events.push_frame(&sub, frame);
    }
}

/// Emit a PR lifecycle event (`pr.opened`, `pr.revision`, `pr.comment`,
/// `pr.review`, `pr.closed`, `pr.landed`) only to subscribers whose fresh
/// [`crate::prs::visible`] check succeeds (enforcing visibility classes,
/// unreleased embargoes, and S11 agent narrowing).
pub async fn emit_pr(hub: &Arc<Hub>, project_id: i64, pr_id: &str, event_name: &str) {
    let state_name = event_name.strip_prefix("pr.").unwrap_or(event_name);
    let subs: Vec<Arc<Subscriber>> = {
        let map = hub.events.subscribers.lock().unwrap();
        map.values()
            .filter(|s| s.project_id == project_id && s.ticket.is_none() && s.wants_type(event_name, state_name))
            .cloned()
            .collect()
    };
    if subs.is_empty() {
        return;
    }
    for sub in subs {
        if let Some(a) = &sub.person.agent {
            match crate::auth::load_agent_session(&hub.db, &a.session_hash, sub.person.id, project_id).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    hub.events.evict(&sub);
                    continue;
                }
                Err(_) => continue,
            }
        }
        let Ok(epochs) = crate::caches::read_epochs(&hub.db, sub.person.id, Some(project_id)).await else {
            continue;
        };
        let caller = Caller {
            person: Some(sub.person.clone()),
            epochs,
        };
        let Ok(ask) = crate::query::Ask::open(hub, &sub.project_name, &caller).await else {
            hub.events.evict(&sub);
            continue;
        };
        if !ask.project.participant(&ask.viewer) {
            hub.events.evict(&sub);
            continue;
        }
        let Ok(pr) = crate::prs::visible(hub, &ask, pr_id).await else {
            continue;
        };
        if sub.branch.as_deref().is_some_and(|b| b != pr.target) {
            continue;
        }
        let mut obj = serde_json::Map::new();
        obj.insert("event".into(), serde_json::Value::String(event_name.into()));
        obj.insert("id".into(), serde_json::Value::String(pr.id));
        obj.insert("title".into(), serde_json::Value::String(pr.title));
        obj.insert("state".into(), serde_json::Value::String(pr.state));
        obj.insert("target".into(), serde_json::Value::String(pr.target));
        obj.insert("revision".into(), serde_json::json!(pr.revision));
        if !pr.embargo.is_empty() {
            obj.insert("embargo".into(), serde_json::Value::String(pr.embargo));
        }
        let data = serde_json::Value::Object(obj).to_string();
        let frame = Bytes::from(format!("event: {event_name}\ndata: {data}\n\n"));
        hub.events.push_frame(&sub, frame);
    }
}

/// Emit `embargo.released` to active streams of members of that embargo's
/// groups and project admins.
pub async fn emit_embargo_released(hub: &Arc<Hub>, project_id: i64, embargo_id: &str) {
    let subs: Vec<Arc<Subscriber>> = {
        let map = hub.events.subscribers.lock().unwrap();
        map.values()
            .filter(|s| s.project_id == project_id && s.ticket.is_none() && s.wants_type("embargo.released", "released"))
            .cloned()
            .collect()
    };
    if subs.is_empty() {
        return;
    }
    let groups: Vec<String> = sqlx::query_scalar(
        "SELECT group_names FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2",
    )
    .bind(project_id)
    .bind(embargo_id)
    .fetch_optional(&hub.db)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    for sub in subs {
        if let Some(a) = &sub.person.agent {
            match crate::auth::load_agent_session(&hub.db, &a.session_hash, sub.person.id, project_id).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    hub.events.evict(&sub);
                    continue;
                }
                Err(_) => continue,
            }
        }
        let Ok(epochs) = crate::caches::read_epochs(&hub.db, sub.person.id, Some(project_id)).await else {
            continue;
        };
        let caller = Caller {
            person: Some(sub.person.clone()),
            epochs,
        };
        let Ok((project, viewer)) = crate::perm::open(hub, &sub.project_name, &caller).await else {
            hub.events.evict(&sub);
            continue;
        };
        if !project.participant(&viewer) {
            hub.events.evict(&sub);
            continue;
        }
        if !crate::embargo::can_see_groups(hub, &project, &viewer, &groups).await.unwrap_or(false) {
            continue;
        }
        let data = serde_json::json!({
            "event": "embargo.released",
            "embargo": embargo_id,
        })
        .to_string();
        let frame = Bytes::from(format!("event: embargo.released\ndata: {data}\n\n"));
        hub.events.push_frame(&sub, frame);
    }
}

type WaitFut = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

struct StreamBody {
    hub: Arc<Hub>,
    sub: Arc<Subscriber>,
    initial: Option<Bytes>,
    wait: Option<WaitFut>,
}

impl Drop for StreamBody {
    fn drop(&mut self) {
        self.hub.events.evict(&self.sub);
    }
}

impl hyper::body::Body for StreamBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<hyper::body::Frame<Bytes>, axum::Error>>> {
        let this = self.get_mut();
        if let Some(init) = this.initial.take() {
            return Poll::Ready(Some(Ok(hyper::body::Frame::data(init))));
        }
        loop {
            {
                let mut q = this.sub.queue.lock().unwrap();
                if let Some(bytes) = q.frames.pop_front() {
                    let len = bytes.len();
                    q.bytes = q.bytes.saturating_sub(len);
                    this.hub.events.total_bytes.fetch_sub(len, Ordering::SeqCst);
                    this.wait = None;
                    return Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))));
                }
                if q.closed {
                    this.wait = None;
                    return Poll::Ready(None);
                }
            }
            if this.wait.is_none() {
                let sub = this.sub.clone();
                this.wait = Some(Box::pin(async move {
                    sub.wake.notified().await;
                }));
            }
            match this.wait.as_mut().unwrap().as_mut().poll(cx) {
                Poll::Ready(()) => {
                    this.wait = None;
                }
                Poll::Pending => {
                    // Re-check once after registering the waker so a notification
                    // between unlocking `queue` and polling `notified` is never missed.
                    let mut q = this.sub.queue.lock().unwrap();
                    if let Some(bytes) = q.frames.pop_front() {
                        let len = bytes.len();
                        q.bytes = q.bytes.saturating_sub(len);
                        this.hub.events.total_bytes.fetch_sub(len, Ordering::SeqCst);
                        this.wait = None;
                        return Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))));
                    }
                    if q.closed {
                        this.wait = None;
                        return Poll::Ready(None);
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}
