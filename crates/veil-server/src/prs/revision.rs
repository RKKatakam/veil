//! One revision of a PR, computed on the real history (the server reads
//! every tree; who may see the result is the class's business).
//!
//! * **The stack** is the head and its first parents down to (not
//!   including) the first one that is an ancestor of the target's tip: the
//!   base. Every change of it has exactly one parent (a merge is refused:
//!   rebase it), and no change id twice.
//! * **What it touches**: every change's own diff against its parent
//!   (files, and folders that differ with nothing differing below them),
//!   so a file a lower change adds and a higher one deletes is touched.
//! * **The patch**: a hash of every file change of every change that
//!   changes a file (change id, path, both entries). An approval counts for
//!   any revision with the same patch, so a rebase over unrelated changes
//!   keeps it, and any change to the files dismisses it.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use veil_core::{
    hub::project::{Change, Node, TreeSource},
    object::{EntryKind, Object, TreeEntry},
    ChangeId, ObjectId,
};

use super::rules::{classify, FileChange, Review, Risk};
use crate::{
    derive::{changes, Cx},
    error::{Error, Result},
    query::graph::G,
};

/// How the one refusal anyone may be told the reason of starts: the
/// revision is already part of the target (their own history shows it).
pub const NOTHING_TO_REVIEW: &str = "nothing to review";

/// The most changes one PR's stack may hold.
pub const MAX_STACK: usize = 100;
/// The most paths one PR may touch, over all its revisions.
pub const MAX_PATHS: usize = 10_000;
/// Text larger than this is never anchored to.
pub const MAX_TEXT: u64 = 1 << 20;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct StackChange {
    pub change: String,
    pub snapshot: String,
    pub parent: String,
}

impl StackChange {
    pub fn snapshot_id(&self) -> ObjectId {
        ObjectId::from_hex(&self.snapshot).expect("stored ids are hex")
    }
    pub fn parent_id(&self) -> ObjectId {
        ObjectId::from_hex(&self.parent).expect("stored ids are hex")
    }
}

#[derive(Debug)]
pub struct Computed {
    pub base: ObjectId,
    pub head: ObjectId,
    /// Bottom first.
    pub changes: Vec<StackChange>,
    pub touched: BTreeSet<String>,
    pub files: usize,
    pub patch: String,
    pub risk: Risk,
    pub reasons: Vec<String>,
}

fn refuse(m: impl Into<String>) -> Error {
    Error::bad_request(m)
}

/// The tree under `id`, if it is one the server can read.
fn tree_of(src: &dyn TreeSource, id: &ObjectId) -> Result<Option<std::sync::Arc<veil_core::object::Tree>>> {
    Ok(match src.node(id)? {
        Node::Tree(t, _) => Some(t),
        Node::Leaf => None,
    })
}

/// The entry at `path` under real tree `root`.
pub fn entry_at(src: &dyn TreeSource, root: ObjectId, path: &str) -> Result<Option<TreeEntry>> {
    let mut dir = root;
    let mut parts = path.split('/').peekable();
    while let Some(name) = parts.next() {
        let Some(t) = tree_of(src, &dir)? else { return Ok(None) };
        let Some(e) = t.entries.iter().find(|e| e.name == name) else { return Ok(None) };
        if parts.peek().is_none() {
            return Ok(Some(e.clone()));
        }
        if e.kind != EntryKind::Dir {
            return Ok(None);
        }
        dir = e.id;
    }
    Ok(None)
}

/// The text of a public file entry, if it is UTF-8 text of at most
/// [`MAX_TEXT`] bytes.
pub fn text_of(cx: &Cx, e: &TreeEntry) -> Result<Option<String>> {
    if e.kind != EntryKind::File || !e.visibility.is_public() || e.size > MAX_TEXT {
        return Ok(None);
    }
    let raw = cx.src.raw(&e.id)?;
    let Ok(Object::Blob(bytes)) = Object::decode(&raw) else { return Ok(None) };
    if bytes.len() as u64 > MAX_TEXT || bytes.contains(&0) {
        return Ok(None);
    }
    Ok(String::from_utf8(bytes).ok())
}

fn entry_bytes(h: &mut blake3::Hasher, e: Option<&TreeEntry>) {
    match e {
        None => {
            h.update(&[0]);
        }
        Some(e) => {
            h.update(&[1, e.kind as u8, e.executable as u8]);
            h.update(&e.id.0);
        }
    }
}

/// The revision of a PR whose head is real snapshot `head`, onto real
/// snapshot `onto` (the target's tip), with the default branch's `rules`.
pub fn compute(cx: &Cx, g: &G, head: ObjectId, onto: ObjectId, rules: &Review) -> Result<Computed> {
    let mut chain = Vec::new();
    let mut seen: HashSet<ChangeId> = HashSet::new();
    let mut x = head;
    while !g.is_ancestor(x, onto)? {
        let s = g.snapshot(&x)?;
        if s.parents.len() != 1 {
            return Err(refuse(format!(
                "{} is a merge (or the root): a PR is a stack of changes with one parent each; rebase it onto the target",
                s.change_id.short()
            )));
        }
        if !seen.insert(s.change_id) {
            return Err(refuse(format!("change {} is in the stack twice", s.change_id.short())));
        }
        if chain.len() == MAX_STACK {
            return Err(refuse(format!("a PR holds at most {MAX_STACK} changes")));
        }
        chain.push((x, s.parents[0], s.change_id, s.tree));
        x = s.parents[0];
    }
    if chain.is_empty() {
        return Err(refuse(format!("{NOTHING_TO_REVIEW}: that revision is already part of the target")));
    }
    chain.reverse();
    let mut touched = BTreeSet::new();
    let mut files: BTreeMap<String, FileChange> = BTreeMap::new();
    let mut patch = blake3::Hasher::new_derive_key("veil 2026 hub pr patch v1");
    let mut out = Vec::new();
    for (snap, parent, change, tree) in &chain {
        let ptree = g.snapshot(parent)?.tree;
        let (leaves, dirs) = changes::diff(&cx.src, ptree, *tree)?;
        if !leaves.is_empty() {
            patch.update(&change.0);
            patch.update(&(leaves.len() as u64).to_le_bytes());
        }
        for c in &leaves {
            g.tick()?;
            patch.update(&(c.path.len() as u64).to_le_bytes());
            patch.update(c.path.as_bytes());
            entry_bytes(&mut patch, c.old.as_ref());
            entry_bytes(&mut patch, c.new.as_ref());
            let secret = [&c.old, &c.new].iter().any(|e| e.as_ref().is_some_and(|e| !e.visibility.is_public()));
            let executable = c.new.as_ref().is_some_and(|e| e.executable);
            let f = files.entry(c.path.clone()).or_insert(FileChange { path: c.path.clone(), secret, executable });
            f.secret |= secret;
            f.executable |= executable;
            touched.insert(c.path.clone());
        }
        touched.extend(dirs.into_iter().filter(|d| !d.is_empty()));
        if touched.len() > MAX_PATHS {
            return Err(refuse(format!("a PR touches at most {MAX_PATHS} paths; land larger changes in parts")));
        }
        out.push(StackChange {
            change: change.to_string(),
            snapshot: snap.hex(),
            parent: parent.hex(),
        });
    }
    let files: Vec<FileChange> = files.into_values().collect();
    let (risk, reasons) = classify(&files, rules);
    Ok(Computed {
        base: x,
        head,
        changes: out,
        touched,
        files: files.len(),
        patch: patch.finalize().to_hex().to_string(),
        risk,
        reasons,
    })
}

/// The leaf changes one change of a stack made (for anchors).
pub fn change_files(cx: &Cx, c: &StackChange) -> Result<Vec<Change>> {
    let (now, before) = (cx.src.snapshot(&c.snapshot_id())?.tree, cx.src.snapshot(&c.parent_id())?.tree);
    Ok(changes::diff(&cx.src, before, now)?.0)
}
