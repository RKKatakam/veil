//! Projected trees for one viewer (milestone S13): the trees of their
//! projected history (`hub::project::Projector`), read by path, listed and
//! diffed. A hidden path and a missing one are the same thing here: the
//! projected tree simply does not hold it, so both get the same answer by
//! the same code path (phase-3 design §3.3, step 3).
//!
//! Reads of projected trees and blobs count as work ([`G::tick`]); the
//! projector's own reads of the directories that hold an access rule do
//! not (an admin's copy has none), and are bounded by the policy.

use std::cell::RefCell;

use serde_json::{json, Value};
use veil_core::{
    hub::{
        access::View,
        project::{empty_tree_id, Change, Node, Projector, TreeSource},
    },
    object::{EntryKind, Object, Tree, TreeEncoding, TreeEntry},
    tree::MAX_TREE_DEPTH,
    ObjectId,
};

use super::graph::{VRow, G};
use crate::{
    derive::changes,
    error::{Error, Result},
};

/// Most bytes of one version of a file that a diff shows lines of.
pub const MAX_TEXT_BYTES: u64 = 1 << 20;

/// What one answer's diff may hold.
#[derive(Clone, Copy, Debug)]
pub struct DiffLimits {
    /// Files listed.
    pub files: usize,
    /// Bytes of changed lines shown, over all files.
    pub content_bytes: usize,
}

impl Default for DiffLimits {
    fn default() -> Self {
        DiffLimits {
            files: 10_000,
            content_bytes: 8 << 20,
        }
    }
}

/// A path as the routes take it: relative to the project root, `/`
/// separated, no empty, `.` or `..` part; a trailing `/` is dropped. `""`
/// is the root.
pub fn clean_path(p: &str) -> Result<String> {
    let p = p.strip_suffix('/').unwrap_or(p);
    let invalid = || Error::bad_request("invalid path: relative to the project root, '/'-separated, without '.' or '..' parts");
    if p.is_empty() {
        return Ok(String::new());
    }
    if p.len() > 4096 || p.split('/').count() > MAX_TREE_DEPTH {
        return Err(invalid());
    }
    if p.split('/').any(|c| matches!(c, "" | "." | "..") || c.contains('\0')) {
        return Err(invalid());
    }
    Ok(p.to_string())
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// One viewer's projected trees.
pub struct Trees<'g, 'a> {
    pub g: &'g G<'a>,
    view: &'g View<'g>,
    pr: RefCell<Projector<'g>>,
}

/// Trees a long-lived [`Trees`] (a fill's) keeps created before it starts
/// afresh ([`Trees::forget`]).
const KEPT_CREATED: usize = 4096;

impl<'g, 'a> Trees<'g, 'a> {
    pub fn new(g: &'g G<'a>, view: &'g View<'g>) -> Trees<'g, 'a> {
        Trees {
            g,
            view,
            pr: RefCell::new(Projector::new(&g.cx.src, view)),
        }
    }

    /// Start afresh once the projector holds many created trees, so a
    /// fill's memory stays bounded. Only between uses: no projected id
    /// handed out before may be looked up after.
    pub fn forget(&self) {
        if self.pr.borrow().created.len() > KEPT_CREATED {
            *self.pr.borrow_mut() = Projector::new(&self.g.cx.src, self.view);
        }
    }

    /// The projected root tree of the snapshot `row` stands for.
    pub fn root_of(&self, row: &VRow) -> Result<ObjectId> {
        let s = self.g.snapshot(&row.real)?;
        Ok(self.pr.borrow_mut().root(s.tree)?)
    }

    /// The projected root trees of the snapshot `row` stands for and of
    /// its first parent (the empty tree for the root).
    pub fn roots_of(&self, row: &VRow) -> Result<(ObjectId, ObjectId)> {
        let s = self.g.snapshot(&row.real)?;
        let now = self.pr.borrow_mut().root(s.tree)?;
        let before = match s.parents.first() {
            None => empty_tree_id(),
            Some(p) => {
                let ps = self.g.snapshot(p)?;
                self.pr.borrow_mut().root(ps.tree)?
            }
        };
        Ok((now, before))
    }

    /// Does `path` (not the root) differ between projected trees `a` and
    /// `b`? Walked down both at once, stopping where they meet: a change
    /// elsewhere costs a tree or two.
    pub fn differs_at(&self, a: ObjectId, b: ObjectId, path: &str) -> Result<bool> {
        let (mut a, mut b) = (a, b);
        let parts: Vec<&str> = path.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            if a == b {
                return Ok(false);
            }
            let get = |id: &ObjectId| -> Result<Option<TreeEntry>> {
                Ok(match self.node(id)? {
                    Node::Tree(t, _) => t.get(part).cloned(),
                    Node::Leaf => None,
                })
            };
            let (ea, eb) = (get(&a)?, get(&b)?);
            if i + 1 == parts.len() || ea.is_none() || eb.is_none() {
                return Ok(ea != eb);
            }
            let (ea, eb) = (ea.unwrap(), eb.unwrap());
            if ea == eb {
                return Ok(false);
            }
            (a, b) = (ea.id, eb.id);
        }
        Ok(false)
    }

    /// The projected entry at `path` (not the root) in projected tree `root`.
    pub fn entry_at(&self, root: ObjectId, path: &str) -> Result<Option<TreeEntry>> {
        let mut cur = root;
        let parts: Vec<&str> = path.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            let Node::Tree(t, _) = self.node(&cur)? else { return Ok(None) };
            let Some(e) = t.get(part) else { return Ok(None) };
            if i + 1 == parts.len() {
                return Ok(Some(e.clone()));
            }
            cur = e.id;
        }
        Ok(None)
    }

    /// The projected tree `id`, if it is one (a sealed directory is not).
    pub fn tree(&self, id: &ObjectId) -> Result<Option<std::sync::Arc<Tree>>> {
        Ok(match self.node(id)? {
            Node::Tree(t, _) => Some(t),
            Node::Leaf => None,
        })
    }

    /// Bytes of object `id` (a blob's content, or the encoded object for
    /// anything else: a secret's ciphertext, a conflict).
    pub fn content(&self, id: &ObjectId) -> Result<(bool, Vec<u8>)> {
        self.g.tick()?;
        let raw = self.g.cx.src.raw(id)?;
        if Object::is_blob_raw(&raw) {
            if let Object::Blob(b) = Object::decode(&raw)? {
                return Ok((true, b));
            }
        }
        Ok((false, raw.to_vec()))
    }

    /// The changes from projected tree `old` to projected tree `new` at or
    /// under `under`, sorted by path.
    pub fn changes(&self, old: ObjectId, new: ObjectId, under: &str) -> Result<Vec<Change>> {
        if under.is_empty() {
            return Ok(changes::diff(self, old, new)?.0);
        }
        let (o, n) = (self.entry_at(old, under)?, self.entry_at(new, under)?);
        let subtree = |e: &Option<TreeEntry>| -> Result<Option<ObjectId>> {
            Ok(match e {
                Some(e) if e.kind == EntryKind::Dir && self.tree(&e.id)?.is_some() => Some(e.id),
                _ => None,
            })
        };
        let (ot, nt) = (subtree(&o)?, subtree(&n)?);
        let mut out = Vec::new();
        if ot.is_some() || nt.is_some() {
            let (a, b) = (ot.unwrap_or_else(empty_tree_id), nt.unwrap_or_else(empty_tree_id));
            for c in changes::diff(self, a, b)?.0 {
                out.push(Change {
                    path: join(under, &c.path),
                    ..c
                });
            }
        }
        let leaf = |e: Option<TreeEntry>, t: Option<ObjectId>| if t.is_some() { None } else { e };
        let (ol, nl) = (leaf(o, ot), leaf(n, nt));
        if ol != nl {
            out.push(Change {
                path: under.to_string(),
                old: ol,
                new: nl,
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// The diff from projected tree `old` to `new` at or under `under`, as
    /// file diffs (renames and copies from the viewer's part only, lines
    /// with `content`), and whether the files were cut at the limit and
    /// whether inexact renames were skipped.
    pub fn diff(&self, old: ObjectId, new: ObjectId, under: &str, content: bool, limits: DiffLimits) -> Result<Value> {
        let ch = self.changes(old, new, under)?;
        let (from, _capped, similar) = changes::sources_with(&self.g.cx.src, &ch, &|| self.g.tick())?;
        let (pairs, claimed) = pairs(&ch, &from);
        let mut files = Vec::new();
        let mut budget = limits.content_bytes;
        let mut truncated = false;
        let mut content_truncated = false;
        for (i, c) in ch.iter().enumerate() {
            if claimed[i] {
                continue;
            }
            if files.len() == limits.files {
                truncated = true;
                break;
            }
            let (status, from_path, score, old_entry) = match pairs[i] {
                Some((s, score, rename)) => (if rename { "renamed" } else { "copied" }, Some(ch[s].path.clone()), Some(score), ch[s].old.clone()),
                None => (
                    match (&c.old, &c.new) {
                        (None, _) => "added",
                        (_, None) => "deleted",
                        _ => "modified",
                    },
                    None,
                    None,
                    c.old.clone(),
                ),
            };
            let lines = if content {
                let v = self.lines(old_entry.as_ref(), c.new.as_ref(), &mut budget)?;
                content_truncated |= v.get("omitted").is_some();
                v
            } else {
                Value::Null
            };
            let mut f = json!({
                "path": c.path,
                "status": status,
                "old": entry_json(old_entry.as_ref()),
                "new": entry_json(c.new.as_ref()),
                "content": lines,
            });
            if let (Some(p), Some(s)) = (from_path, score) {
                f["from"] = json!(p);
                f["score"] = json!(s);
            }
            files.push(f);
        }
        let mut out = json!({ "stat": !content, "files": files, "truncated": truncated });
        if !similar {
            out["renames_skipped"] = json!(true);
        }
        if content_truncated {
            out["content_truncated"] = json!(true);
        }
        Ok(out)
    }

    /// The changed lines between two versions (`content` of a file diff).
    fn lines(&self, old: Option<&TreeEntry>, new: Option<&TreeEntry>, budget: &mut usize) -> Result<Value> {
        let sealed = |e: Option<&TreeEntry>| e.is_some_and(|e| !e.visibility.is_public());
        if sealed(old) || sealed(new) {
            // A secret: ciphertext only, never decoded.
            return Ok(json!({ "binary": true, "hidden": "sealed" }));
        }
        let mut texts = Vec::new();
        for e in [old, new] {
            match e {
                None => texts.push(String::new()),
                Some(e) if !e.kind.holds_blob() => return Ok(json!({ "binary": true })),
                Some(e) if e.size > MAX_TEXT_BYTES => return Ok(json!({ "binary": false, "too_large": true })),
                Some(e) => {
                    let (blob, bytes) = self.content(&e.id)?;
                    if !blob || bytes.contains(&0) || bytes.len() as u64 > MAX_TEXT_BYTES {
                        return Ok(json!({ "binary": true }));
                    }
                    match String::from_utf8(bytes) {
                        Ok(s) => texts.push(s),
                        Err(_) => return Ok(json!({ "binary": true })),
                    }
                }
            }
        }
        let d = veil_core::hunks::diff_text(&texts[0], &texts[1]);
        let mut hunks = Vec::new();
        let mut size = 0usize;
        for h in &d.hunks {
            let lines: Vec<String> = h.lines.iter().map(|l| format!("{}{}", l.kind.prefix(), l.text)).collect();
            size += lines.iter().map(|l| l.len()).sum::<usize>();
            hunks.push(json!({
                "old_start": h.old_start,
                "old_lines": h.old_lines,
                "new_start": h.new_start,
                "new_lines": h.new_lines,
                "lines": lines,
            }));
        }
        if size > *budget {
            *budget = 0;
            return Ok(json!({ "binary": false, "omitted": true }));
        }
        *budget -= size;
        Ok(json!({ "binary": false, "hunks": hunks }))
    }
}

/// An added file's best source: `(source index, score, rename)`.
pub type Pair = (usize, u32, bool);

/// Each added file's best source among `changes` (`from`, as
/// [`changes::sources`] ranks them): `(source index, score, rename)`, a
/// rename when the change deleted the source and no added file before it
/// (in path order) took it; and which changes a rename took (a diff lists
/// them once, as the renamed file).
pub fn pairs(changes: &[Change], from: &[Vec<changes::From>]) -> (Vec<Option<Pair>>, Vec<bool>) {
    let index: std::collections::HashMap<&str, usize> = changes.iter().enumerate().map(|(i, c)| (c.path.as_str(), i)).collect();
    let mut claimed = vec![false; changes.len()];
    let mut out: Vec<Option<Pair>> = vec![None; changes.len()];
    for (i, f) in from.iter().enumerate() {
        let Some(best) = f.first() else { continue };
        let src = *index.get(best.path.as_str()).expect("a source is a change of the same diff");
        let rename = changes[src].new.is_none() && !claimed[src];
        if rename {
            claimed[src] = true;
        }
        out[i] = Some((src, best.score, rename));
    }
    (out, claimed)
}

impl TreeSource for Trees<'_, '_> {
    fn node(&self, id: &ObjectId) -> veil_core::Result<Node> {
        self.g.tick().map_err(|e| veil_core::VeilError::Repo(format!("{e:?}")))?;
        if let Some((t, _)) = self.pr.borrow().created.get(id) {
            return Ok(Node::Tree(t.clone(), TreeEncoding::Json));
        }
        self.g.cx.src.node(id)
    }
}

/// A tree entry as the routes show it.
pub fn entry_json(e: Option<&TreeEntry>) -> Value {
    match e {
        None => Value::Null,
        Some(e) => json!({
            "kind": kind_name(e.kind),
            "id": e.id.hex(),
            "size": e.size,
            "executable": e.executable,
            "sealed": !e.visibility.is_public(),
        }),
    }
}

pub fn kind_name(k: EntryKind) -> &'static str {
    match k {
        EntryKind::File => "file",
        EntryKind::Dir => "dir",
        EntryKind::Conflict => "conflict",
        EntryKind::Symlink => "symlink",
    }
}
