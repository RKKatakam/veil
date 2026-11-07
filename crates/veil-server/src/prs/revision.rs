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

use super::rules::{classify, FileChange, Review, Risk, RULES_FILE};
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
/// The most bytes read to tell whitespace-only changes, per revision.
const WHITESPACE_BUDGET: u64 = 16 << 20;
/// Text larger than this is never compared for whitespace (or anchored).
pub const MAX_TEXT: u64 = 1 << 20;
/// The largest `.veilrules` read.
const MAX_RULES: u64 = 64 << 10;

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

/// How far back on the default branch's first parents a broken
/// `.veilrules` looks for its last valid version.
pub const RULES_HISTORY: usize = 1_000;

/// The `.veilrules` of snapshot `id` as parsed (`None`: no such file), and
/// the file's entry id.
fn rules_of(cx: &Cx, id: &ObjectId) -> Result<Option<(ObjectId, Review)>> {
    let tree = cx.src.snapshot(id)?.tree;
    let Some(e) = entry_at(&cx.src, tree, RULES_FILE)? else { return Ok(None) };
    if e.kind != EntryKind::File || !e.visibility.is_public() || e.size > MAX_RULES {
        return Ok(Some((e.id, Review::strict("not a plain file of at most 64 KiB".into()))));
    }
    let raw = cx.src.raw(&e.id)?;
    Ok(Some((
        e.id,
        match Object::decode(&raw) {
            Ok(Object::Blob(b)) if b.len() as u64 <= MAX_RULES => Review::parse(Some(&b)),
            _ => Review::strict("not a plain file of at most 64 KiB".into()),
        },
    )))
}

/// The review rules of the default branch's tip (`None`: no branch yet).
/// A `.veilrules` that does not parse never weakens review: the last
/// version that parsed, on the tip's first parents (at most
/// [`RULES_HISTORY`] back), applies; with none (the file was new, or
/// absent before), the strict rules do.
pub fn rules_at(cx: &Cx, tip: Option<ObjectId>) -> Result<Review> {
    let Some(tip) = tip else { return Ok(Review::default()) };
    let Some((mut seen, first)) = rules_of(cx, &tip)? else { return Ok(Review::default()) };
    if !first.broken {
        return Ok(first);
    }
    let mut x = tip;
    for _ in 0..RULES_HISTORY {
        let Some(p) = cx.src.snapshot(&x)?.parents.first().copied() else { break };
        x = p;
        match rules_of(cx, &x)? {
            None => break,
            Some((id, _)) if id == seen => continue,
            Some((_, r)) if !r.broken => {
                let mut kept = r;
                kept.warnings = first.warnings.clone();
                kept.warnings.push(format!("until it is fixed, the last valid {RULES_FILE} applies (as of {})", x.short()));
                kept.broken = true;
                return Ok(kept);
            }
            Some((id, _)) => seen = id,
        }
    }
    let mut strict = first;
    strict.warnings.push("until it is fixed, every PR needs one person's approval (no earlier version of it is valid)".into());
    Ok(strict)
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

/// Does a file's meaning depend on trailing whitespace or indentation?
/// There only line endings may change for a whitespace-only change.
fn whitespace_significant(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    matches!(ext.as_str(), "py" | "pyi" | "pyw" | "yaml" | "yml" | "mk" | "make" | "haml" | "pug" | "sass" | "coffee" | "nim")
        || matches!(name, "Makefile" | "makefile" | "GNUmakefile")
}

/// Is a change whitespace-only (BUG-1251)? The same kind and executable
/// bit, both sides text with the same lines, each equal but for trailing
/// whitespace and its line ending (only the line ending, for files whose
/// meaning depends on whitespace). Moving text between lines, splitting a
/// token or changing indentation is never whitespace-only.
fn whitespace_only(cx: &Cx, c: &Change, budget: &mut u64) -> Result<bool> {
    let (Some(o), Some(n)) = (&c.old, &c.new) else { return Ok(false) };
    if o.kind != n.kind || o.executable != n.executable || o.size + n.size > *budget {
        return Ok(false);
    }
    *budget -= o.size + n.size;
    let (Some(a), Some(b)) = (text_of(cx, o)?, text_of(cx, n)?) else { return Ok(false) };
    Ok(same_but_whitespace(&c.path, &a, &b))
}

/// The texts of `whitespace_only`: the same lines, each equal but for
/// trailing whitespace (only its `\r`, where whitespace is significant).
pub fn same_but_whitespace(path: &str, a: &str, b: &str) -> bool {
    let strict = whitespace_significant(path);
    let norm = |l: &'_ str| -> String {
        if strict {
            l.strip_suffix('\r').unwrap_or(l).to_string()
        } else {
            l.trim_end().to_string()
        }
    };
    let (la, lb): (Vec<&str>, Vec<&str>) = (a.split('\n').collect(), b.split('\n').collect());
    la.len() == lb.len() && la.iter().zip(&lb).all(|(x, y)| norm(x) == norm(y))
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
    let mut budget = WHITESPACE_BUDGET;
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
            let ws = !secret && whitespace_only(cx, c, &mut budget)?;
            let executable = c.new.as_ref().is_some_and(|e| e.executable);
            let f = files.entry(c.path.clone()).or_insert(FileChange { path: c.path.clone(), secret, whitespace_only: ws, executable });
            f.secret |= secret;
            f.whitespace_only &= ws;
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

#[cfg(test)]
mod tests {
    use super::same_but_whitespace as same;

    #[test]
    fn whitespace_only_keeps_every_line_and_its_indentation() {
        assert!(same("a.rs", "fn a() {}  \nb();\n", "fn a() {}\nb();\t\n"));
        assert!(same("a.rs", "a\r\nb\r\n", "a\nb\n"));
        // BUG-1251: joined lines, split tokens, indentation.
        assert!(!same("a.rs", "// check\nverify();\n", "// check verify();\n"));
        assert!(!same("c.sh", "rm -rf /tmp/build\n", "rm -rf / tmp/build\n"));
        assert!(!same("g.py", "if x:\n    a()\n    b()\n", "if x:\n    a()\nb()\n"));
        assert!(!same("a.rs", "  a\n", "a\n"));
        // Trailing whitespace is meaning in a Makefile or YAML.
        assert!(!same("Makefile", "X = a \n", "X = a\n"));
        assert!(!same("ci/a.yml", "k: |\n  v  \n", "k: |\n  v\n"));
        assert!(same("Makefile", "X = a\r\n", "X = a\n"));
    }
}
