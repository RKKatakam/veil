//! Changed paths, copies and renames, and file history (phase-3 design
//! §3.1): for each snapshot, every path it changed against its first
//! parent, with the old and new entries, where an added file came from,
//! and, per parent, the snapshot that last changed the path before it.
//! These are the inputs blame and `history --follow` need (S14).
//!
//! * **Leaves only.** Files, symbolic links, conflicts, and directories the
//!   server cannot look inside (sealed); folders are walked, not listed
//!   (the folders above a path are its prefixes).
//! * **Stored as one object per snapshot** (`veil-derived changed-paths 1`,
//!   then JSON), addressed by its hash in the project's object space. It is
//!   not an [`veil_core::object::Object`] encoding, so no upload can name it
//!   and `fetch` (which serves only what a viewer's tree names) never
//!   serves it. Above [`MAX_PATHS`] paths the snapshot is `many`: no
//!   object, and queries walk the trees instead.
//! * **Copies and renames** (for an added file): a source is a file the
//!   same change deleted or modified, with the same object id (score 100),
//!   or, for plain-text files under [`SIMILAR_MAX_BYTES`] that the change
//!   deleted, one with at least [`SIMILAR_MIN`] % of its lines in common.
//!   **Every** source is kept, ranked, so that each viewer is answered with
//!   the best source *they* may read: a source in a hidden folder never
//!   decides what a reader sees (design §3.6). Above the caps the object
//!   says so (`similar: false`, `capped`), and the viewer's answer is
//!   computed from the part they may read ([`sources`] on it), exactly as
//!   it would be on a project holding only that part.
//! * **Secrets are never read:** sources of sealed files are matched by
//!   object id only (an id of ciphertext); their content is never decoded,
//!   compared or stored. Nothing of any file's content is stored: only
//!   paths, entries and scores.
//! * **File history** (`prev`): per parent `p`, the snapshot that last
//!   changed the path along `p`'s first parents (the one that introduced
//!   `p`'s version of it), found through the `file_history` rows
//!   ([`super::Batch::last_changes`]).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use veil_core::{
    hub::project::{Change, Node, TreeSource},
    object::{EntryKind, Object, TreeEntry, Visibility},
    tree::MAX_TREE_DEPTH,
    ObjectId,
};

use crate::{
    error::{Error, Result},
    sync::Source,
};

/// `graph.changed` for a snapshot that changed no path.
pub const NONE: &str = "none";
/// `graph.changed` above [`MAX_PATHS`].
pub const MANY: &str = "many";
/// `graph.changed` for a snapshot on an embargo line: nothing is indexed
/// until release (design §6, row 8).
pub const WITHHELD: &str = "withheld";
/// The `file_history` key of `many` snapshots.
pub const MANY_KEY: &str = "*";

/// Most paths one changed-paths object lists.
pub const MAX_PATHS: usize = 100_000;
/// Most sources kept for one added path (the best ones): bounds the object
/// at 16 sources a path whatever a change holds.
pub const MAX_SOURCES: usize = 16;
/// Similarity: largest file compared, most added and deleted files of one
/// change, most line comparisons, and the lowest score kept.
pub const SIMILAR_MAX_BYTES: u64 = 1 << 20;
pub const SIMILAR_MAX_FILES: usize = 1_000;
pub const SIMILAR_BUDGET: u64 = 20_000_000;
pub const SIMILAR_MIN: u32 = 50;

const MAGIC: &[u8] = b"veil-derived changed-paths 1\n";

/// One snapshot's changed paths.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changed {
    /// Sorted by path.
    pub paths: Vec<PathChange>,
    /// Similarity was computed for the whole change (false above the caps).
    pub similar: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathChange {
    pub path: String,
    pub old: Option<TreeEntry>,
    pub new: Option<TreeEntry>,
    /// Per parent, in order: the snapshot that last changed this path along
    /// that parent's first parents (`None`: never).
    pub prev: Vec<Option<ObjectId>>,
    /// For an added file: where it may have come from, best first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<From>,
    /// More than [`MAX_SOURCES`] sources: `from` holds the best ones.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub capped: bool,
}

/// A source of an added file: a path the same change deleted (a rename) or
/// modified (a copy).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct From {
    pub path: String,
    /// 100 for the same object; else the share of lines in common, in %.
    pub score: u32,
}

impl Changed {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend(serde_json::to_vec(self).expect("changed paths serialise"));
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Changed> {
        let body = raw
            .strip_prefix(MAGIC)
            .ok_or_else(|| Error::Other(anyhow::anyhow!("not a changed-paths object")))?;
        serde_json::from_slice(body).map_err(|e| Error::Other(e.into()))
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// The tree `id` names, if it is one the server can read (a sealed
/// directory is a leaf).
fn tree_of(src: &dyn TreeSource, e: &TreeEntry) -> Result<Option<std::sync::Arc<veil_core::object::Tree>>> {
    if e.kind != EntryKind::Dir {
        return Ok(None);
    }
    Ok(match src.node(&e.id)? {
        Node::Tree(t, _) => Some(t),
        Node::Leaf => None,
    })
}

/// Every leaf that differs between real trees `old` and `new`, sorted by
/// path.
pub fn diff(src: &dyn TreeSource, old: ObjectId, new: ObjectId) -> Result<Vec<Change>> {
    let mut out = Vec::new();
    if old != new {
        let root = |id: &ObjectId| -> Result<Option<std::sync::Arc<veil_core::object::Tree>>> {
            Ok(match src.node(id)? {
                Node::Tree(t, _) => Some(t),
                Node::Leaf => None,
            })
        };
        walk(src, "", root(&old)?.as_deref(), root(&new)?.as_deref(), &mut out, 0)?;
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn walk(
    src: &dyn TreeSource,
    dir: &str,
    old: Option<&veil_core::object::Tree>,
    new: Option<&veil_core::object::Tree>,
    out: &mut Vec<Change>,
    depth: usize,
) -> Result<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(Error::Other(anyhow::anyhow!("tree nested deeper than {MAX_TREE_DEPTH} directories")));
    }
    let mut names: BTreeMap<&str, (Option<&TreeEntry>, Option<&TreeEntry>)> = BTreeMap::new();
    for e in old.map(|t| t.entries.as_slice()).unwrap_or_default() {
        names.entry(&e.name).or_default().0 = Some(e);
    }
    for e in new.map(|t| t.entries.as_slice()).unwrap_or_default() {
        names.entry(&e.name).or_default().1 = Some(e);
    }
    for (name, (o, n)) in names {
        if o == n {
            continue;
        }
        let path = join(dir, name);
        let ot = match o {
            Some(e) => tree_of(src, e)?,
            None => None,
        };
        let nt = match n {
            Some(e) => tree_of(src, e)?,
            None => None,
        };
        // A side that is a readable folder is walked; any other side is a leaf.
        let ol = if ot.is_some() { None } else { o.cloned() };
        let nl = if nt.is_some() { None } else { n.cloned() };
        if (ot.is_some() || nt.is_some()) && ot.as_ref().map(|t| t.as_ref()) != nt.as_ref().map(|t| t.as_ref()) {
            walk(src, &path, ot.as_deref(), nt.as_deref(), out, depth + 1)?;
        }
        if ol.is_some() || nl.is_some() {
            out.push(Change { path, old: ol, new: nl });
        }
    }
    Ok(())
}

/// A text's lines, as counts per line hash, and how many there are.
type Lines = (HashMap<[u8; 8], u32>, u64);

/// Lines of a plain-text file the server may read; `None` for anything
/// else (sealed, binary, too large, not a blob).
fn text_lines(src: &Source, e: &TreeEntry) -> Result<Option<Lines>> {
    if e.kind != EntryKind::File || e.visibility != Visibility::Public || e.size > SIMILAR_MAX_BYTES {
        return Ok(None);
    }
    let raw = src.raw(&e.id)?;
    if !Object::is_blob_raw(&raw) {
        return Ok(None);
    }
    let Object::Blob(bytes) = Object::decode(&raw)? else { return Ok(None) };
    if bytes.len() as u64 > SIMILAR_MAX_BYTES || bytes.contains(&0) {
        return Ok(None);
    }
    let mut lines: HashMap<[u8; 8], u32> = HashMap::new();
    let mut n = 0u64;
    for line in bytes.split(|b| *b == b'\n') {
        let h: [u8; 8] = blake3::hash(line).as_bytes()[..8].try_into().unwrap();
        *lines.entry(h).or_default() += 1;
        n += 1;
    }
    Ok(Some((lines, n)))
}

/// The sources of each added file in `changes` (the same order), whether
/// each list was capped, and whether similarity was computed for the whole
/// of `changes`. A function of `changes` alone: run on the part a viewer
/// may read, it gives what a project holding only that part would hold.
pub fn sources(src: &Source, changes: &[Change]) -> Result<(Vec<Vec<From>>, Vec<bool>, bool)> {
    let file_like = |e: &TreeEntry| e.kind.holds_blob();
    let adds: Vec<usize> = (0..changes.len())
        .filter(|&i| changes[i].old.is_none() && changes[i].new.as_ref().is_some_and(file_like))
        .collect();
    // Sources by object id: deleted ones, then modified ones, each in path
    // order (the order they rank in).
    let mut by_id: HashMap<ObjectId, (Vec<usize>, Vec<usize>)> = HashMap::new();
    for (i, c) in changes.iter().enumerate() {
        if let Some(o) = c.old.as_ref().filter(|o| file_like(o)) {
            let e = by_id.entry(o.id).or_default();
            if c.new.is_none() { &mut e.0 } else { &mut e.1 }.push(i);
        }
    }
    // (score, renamed, source index) per add. Only the best exact matches
    // are collected: thousands of identical files cost linear work.
    let mut found: HashMap<usize, Vec<(u32, bool, usize)>> = HashMap::new();
    for &a in &adds {
        let id = changes[a].new.as_ref().unwrap().id;
        if let Some((del, modified)) = by_id.get(&id) {
            let list = found.entry(a).or_default();
            for &s in del.iter().chain(modified).take(MAX_SOURCES + 1) {
                list.push((100, changes[s].new.is_none(), s));
            }
        }
    }
    // Similarity: added and deleted plain-text files, within the caps.
    let deleted: Vec<usize> = (0..changes.len())
        .filter(|&i| changes[i].new.is_none() && changes[i].old.as_ref().is_some_and(|o| o.kind == EntryKind::File))
        .collect();
    let added_files: Vec<usize> = adds.iter().copied().filter(|&a| changes[a].new.as_ref().unwrap().kind == EntryKind::File).collect();
    let mut similar = true;
    if !deleted.is_empty() && !added_files.is_empty() {
        if deleted.len() > SIMILAR_MAX_FILES || added_files.len() > SIMILAR_MAX_FILES {
            similar = false;
        } else {
            let mut texts: HashMap<usize, Lines> = HashMap::new();
            for &i in deleted.iter().chain(&added_files) {
                let e = changes[i].new.as_ref().or(changes[i].old.as_ref()).unwrap();
                if let Some(t) = text_lines(src, e)? {
                    texts.insert(i, t);
                }
            }
            let mut budget = SIMILAR_BUDGET;
            let mut extra: Vec<(usize, u32, usize)> = Vec::new();
            'pairs: for &a in &added_files {
                let Some((la, na)) = texts.get(&a) else { continue };
                for &d in &deleted {
                    let Some((ld, nd)) = texts.get(&d) else { continue };
                    if changes[a].new.as_ref().unwrap().id == changes[d].old.as_ref().unwrap().id {
                        continue;
                    }
                    // The score cannot reach the minimum: skip the comparison.
                    if 200 * na.min(nd) < u64::from(SIMILAR_MIN) * (na + nd) {
                        continue;
                    }
                    let (small, large) = if la.len() <= ld.len() { (la, ld) } else { (ld, la) };
                    let cost = small.len() as u64;
                    if cost > budget {
                        similar = false;
                        break 'pairs;
                    }
                    budget -= cost;
                    let common: u64 = small.iter().map(|(h, c)| u64::from((*c).min(large.get(h).copied().unwrap_or(0)))).sum();
                    let score = (200 * common / (na + nd)) as u32;
                    if score >= SIMILAR_MIN {
                        extra.push((a, score, d));
                    }
                }
            }
            if similar {
                for (a, score, d) in extra {
                    found.entry(a).or_default().push((score, true, d));
                }
            }
        }
    }
    let mut from = vec![Vec::new(); changes.len()];
    let mut capped = vec![false; changes.len()];
    for (a, mut list) in found {
        // Best first: score, then a rename before a copy, then the path.
        list.sort_by(|x, y| y.0.cmp(&x.0).then(y.1.cmp(&x.1)).then(changes[x.2].path.cmp(&changes[y.2].path)));
        if list.len() > MAX_SOURCES {
            list.truncate(MAX_SOURCES);
            capped[a] = true;
        }
        from[a] = list
            .into_iter()
            .map(|(score, _, s)| From {
                path: changes[s].path.clone(),
                score,
            })
            .collect();
    }
    Ok((from, capped, similar))
}

/// The entry at `path` in real tree `tree`.
pub fn entry_at(src: &dyn TreeSource, tree: &ObjectId, path: &str) -> Result<Option<TreeEntry>> {
    let mut cur = *tree;
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        let Node::Tree(t, _) = src.node(&cur)? else {
            return Ok(None);
        };
        let Some(e) = t.get(part) else {
            return Ok(None);
        };
        if i + 1 == parts.len() {
            return Ok(Some(e.clone()));
        }
        cur = e.id;
    }
    Ok(None)
}

/// The key of `path` in `file_history`.
pub fn path_key(path: &str) -> String {
    let h = blake3::derive_key(PATH_KEY_CONTEXT, path.as_bytes());
    hex::encode(&h[..16])
}

const PATH_KEY_CONTEXT: &str = "veil 2026 hub derive path-key v1";
