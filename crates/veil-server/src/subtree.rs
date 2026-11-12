//! `GET /v1/projects/{p}/subtree?snapshot=ID&path=DIR` (BUG-1945): the
//! trees of one snapshot from its root down to folder `DIR`, and every tree
//! below it, in one answer, so that a clone of one folder reads its trees
//! in one request instead of one per level.
//!
//! **Access is exactly `fetch`'s.** The route lists the trees by walking
//! the caller's projected tree (what the caller may see of the snapshot,
//! `Projector`), keeping only what a narrowed agent session may read (its
//! paths, and the folders on the way to them), then answers through
//! [`crate::sync::fetch`] with one want per tree: every want is checked
//! there as any fetch's is (the snapshot as the caller sees it, an embargo
//! that withholds it, each object at its path in the caller's projection,
//! the narrowing), and anything that fails refuses the whole answer as a
//! fetch does. The path comes through `Ask::file_path`. A folder the caller
//! may not see is not in the projected tree: asking for it, or for a path
//! through it, is refused as a fetch of it is, naming nothing; nothing
//! below a hidden folder is listed or read.
//!
//! The answer is `fetch`'s: frames in the order listed (the root, the
//! folders on the way to `DIR`, then the trees below it breadth first), at
//! most [`MAX_SUBTREE`] trees. A client takes each tree only where its own
//! walk from the snapshot's tree reaches it, and asks for any further level
//! as before, one request per level.

use std::{collections::VecDeque, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use veil_core::{
    hub::{access::AccessPolicy, project::Projector, wire::Want},
    object::EntryKind,
    ObjectId,
};

use crate::{
    auth::Caller,
    error::{Error, Result},
    perm::{Project, Viewer},
    query::Ask,
    sync, Hub, HubState,
};

/// Most trees one answer lists.
pub const MAX_SUBTREE: usize = 20_000;

#[derive(Deserialize)]
pub struct SubtreeParams {
    pub snapshot: String,
    pub path: Option<String>,
}

pub async fn subtree(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, headers: HeaderMap, Query(q): Query<SubtreeParams>) -> Result<Response> {
    caller.not_web()?;
    let ask = Ask::open(&hub, &p, &caller).await?;
    let path = ask.file_path(q.path.as_deref())?;
    let snapshot = ObjectId::from_hex(&q.snapshot).map_err(|_| Error::bad_request("snapshot: an object id in hex"))?;
    let wants = wants(&hub, &ask.project, &ask.viewer, snapshot, path).await?;
    let encoded = crate::api::reads_encoded(&headers);
    let stream = sync::fetch(&hub, &ask.project, &ask.viewer, snapshot, wants, encoded).await?;
    Ok(([(header::CONTENT_TYPE, crate::api::frames_type(encoded))], axum::body::Body::new(stream)).into_response())
}

/// The trees the answer names: the root, the folders down to `path`, and
/// the trees below it, as `viewer` sees snapshot `snapshot`.
async fn wants(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, snapshot: ObjectId, path: String) -> Result<Vec<Want>> {
    // Refused as `fetch` refuses it (which checks it again).
    let gone = || Error::not_found(format!("no snapshot {} that you can see", snapshot.short()));
    if crate::embargo::is_withheld_from_viewer(hub, project, viewer, &snapshot).await? {
        return Err(gone());
    }
    let Some(real) = sync::resolve(hub, project.id, &project.view(viewer).key(), &snapshot).await?.into_iter().next() else {
        return Err(gone());
    };
    if crate::embargo::is_withheld_from_viewer(hub, project, viewer, &real).await? {
        return Err(gone());
    }
    let (policy_text, bindings, viewer) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
    sync::blocking(hub, project.id, move |src| {
        let p = Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: AccessPolicy::parse(&policy_text),
            policy_text: String::new(),
            bindings,
        };
        let view = p.view(&viewer);
        // Word for word the refusal of a fetch of an object the caller
        // cannot see at its path (`check_wants`).
        let no_path = || Error::not_found("no such object at that path that you can see");
        let mut pr = Projector::new(src, &view);
        let root = pr.root(src.snapshot(&real)?.tree)?;
        let mut out = vec![Want { path: String::new(), id: root, snapshot: None }];
        let mut tree = pr.tree(&root)?.ok_or_else(no_path)?;
        let mut at = String::new();
        for part in path.split('/').filter(|s| !s.is_empty()) {
            let e = tree.get(part).filter(|e| e.kind == EntryKind::Dir).ok_or_else(no_path)?;
            at = join(&at, part);
            out.push(Want { path: at.clone(), id: e.id, snapshot: None });
            tree = pr.tree(&e.id)?.ok_or_else(no_path)?;
        }
        let mut queue = VecDeque::from([(at, tree)]);
        while let Some((dir, t)) = queue.pop_front() {
            for e in t.entries.iter().filter(|e| e.kind == EntryKind::Dir) {
                let p = join(&dir, &e.name);
                // What a narrowed agent session may read (`check_wants`).
                if !view.within_narrowing(&p) && !view.toward_narrowing(&p) {
                    continue;
                }
                if out.len() >= MAX_SUBTREE {
                    return Ok(out);
                }
                out.push(Want { path: p.clone(), id: e.id, snapshot: None });
                if let Some(child) = pr.tree(&e.id)? {
                    queue.push_back((p, child));
                }
            }
        }
        Ok(out)
    })
    .await
}

fn join(dir: &str, name: &str) -> String {
    match dir.is_empty() {
        true => name.to_string(),
        false => format!("{dir}/{name}"),
    }
}
