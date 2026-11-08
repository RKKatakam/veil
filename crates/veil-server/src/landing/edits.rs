//! Edit sets, the fast path and the landing check
//! (`docs/design/server/phase-4-agent-scale.md` §4.2), on real trees.
//!
//! * A change's **edit set** is every leaf (file, link, secret, conflict)
//!   where its snapshot's tree differs from its first parent's, with the
//!   entry on each side: the same diff the push's checks walk
//!   ([`Graft`] with nothing hidden). It is read from the objects, never
//!   stored: objects are the authority.
//! * **The fast path:** the change lands on a newer tip, without merging
//!   anything, when every path of its edit set is, in the tip, what it was
//!   in the change's base: the same entry (kind, content, mode, label), or
//!   absent in both, or under the same non-folder in both. The check is
//!   exact per path; nothing else in the tip matters.
//! * [`apply`] rewrites only the folder listings on the way to the edited
//!   paths, creating folders as needed and dropping those left empty.
//! * **The landing check:** the new tree's edit set against the tip must be
//!   the change's edit set, path for path ([`same_edits`]); a mismatch is a
//!   bug, and the change never lands.

use std::{collections::HashMap, sync::Arc};

use veil_core::{
    hub::{
        access::{AccessPolicy, View},
        project::{Change, Graft, Node, TreeSource},
    },
    object::{EntryKind, Object, Tree, TreeEncoding, TreeEntry},
    ObjectId, Result,
};

/// The edit set of a change whose tree is `new` on a parent whose tree is
/// `old` (real root trees), in tree order.
pub fn edit_set(src: &dyn TreeSource, new: ObjectId, old: ObjectId) -> Result<Vec<Change>> {
    let policy = AccessPolicy::default();
    let everything = View::admin(&policy);
    let mut g = Graft::new(src, &everything);
    g.root(new, Some(old))?;
    Ok(g.changes)
}

/// The same entry, as the push's checks compare them: kind, content, mode
/// and label (the name is the path's).
fn same(a: Option<&TreeEntry>, b: Option<&TreeEntry>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.same_content(b),
        _ => false,
    }
}

/// What a path reaches in a tree.
#[derive(Debug)]
enum At {
    Entry(TreeEntry),
    /// Nothing there (folders on the way may be missing too).
    Absent,
    /// A non-folder after this many components: the path cannot exist.
    Blocked(usize),
}

fn at(src: &dyn TreeSource, root: ObjectId, path: &str) -> Result<At> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut cur = root;
    for (i, part) in parts.iter().enumerate() {
        let Node::Tree(t, _) = src.node(&cur)? else { return Ok(At::Blocked(i)) };
        let Some(e) = t.get(part) else { return Ok(At::Absent) };
        if i + 1 == parts.len() {
            return Ok(At::Entry(e.clone()));
        }
        if e.kind != EntryKind::Dir {
            return Ok(At::Blocked(i + 1));
        }
        cur = e.id;
    }
    Ok(At::Absent)
}

/// The fast path: may the edit set `edits`, made on real tree `base`, be
/// applied to real tree `tip` as it is? `Ok(None)` if so, else the first
/// path where `tip` differs from `base` (one of the change's own paths).
pub fn fast_path(src: &dyn TreeSource, base: ObjectId, tip: ObjectId, edits: &[Change]) -> Result<Option<String>> {
    if base == tip {
        return Ok(None);
    }
    for c in edits {
        let ok = match (at(src, base, &c.path)?, at(src, tip, &c.path)?) {
            (At::Entry(a), At::Entry(b)) => same(Some(&a), Some(&b)),
            (At::Absent, At::Absent) => true,
            (At::Blocked(i), At::Blocked(j)) => i == j,
            _ => false,
        };
        if !ok {
            return Ok(Some(c.path.clone()));
        }
    }
    Ok(None)
}

/// Does real tree `tree` hold edit `c`'s outcome already: its new entry
/// at its path, or nothing there where it deletes? (What of a change landed
/// in part for another view is on the tip: `service::entry`.)
pub fn holds(src: &dyn TreeSource, tree: ObjectId, c: &Change) -> Result<bool> {
    Ok(match (at(src, tree, &c.path)?, &c.new) {
        (At::Entry(e), Some(n)) => same(Some(&e), Some(n)),
        (At::Absent | At::Blocked(_), None) => true,
        _ => false,
    })
}

/// Why [`apply`] could not place an edit (a tip the fast path did not
/// clear): the path.
#[derive(Debug)]
pub struct Blocked(pub String);

type Edit<'a> = (Vec<&'a str>, &'a Change);

/// Apply edit set `edits` to real root tree `root`: the new root, with every
/// tree made on the way in `made` (id → raw object, decoded tree,
/// encoding). Folders are made where an added path needs them, and left out
/// once empty, as trees never record empty folders.
pub fn apply(
    src: &dyn TreeSource,
    root: ObjectId,
    edits: &[Change],
    made: &mut HashMap<ObjectId, (Vec<u8>, Arc<Tree>)>,
) -> Result<std::result::Result<ObjectId, Blocked>> {
    let mut list: Vec<Edit<'_>> = edits.iter().map(|c| (c.path.split('/').collect(), c)).collect();
    list.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(match dir(src, Some(root), &list, 0, made)? {
        Ok(Some(id)) => Ok(id),
        Ok(None) => {
            let raw = Object::Tree(Tree::default()).encode();
            let id = ObjectId::hash(&raw);
            made.insert(id, (raw, Arc::new(Tree::default())));
            Ok(id)
        }
        Err(b) => Err(b),
    })
}

fn load(src: &dyn TreeSource, id: &ObjectId) -> Result<Option<(Arc<Tree>, TreeEncoding)>> {
    Ok(match src.node(id)? {
        Node::Tree(t, enc) => Some((t, enc)),
        Node::Leaf => None,
    })
}

fn dir(
    src: &dyn TreeSource,
    tree: Option<ObjectId>,
    edits: &[Edit<'_>],
    depth: usize,
    made: &mut HashMap<ObjectId, (Vec<u8>, Arc<Tree>)>,
) -> Result<std::result::Result<Option<ObjectId>, Blocked>> {
    let (mut t, enc) = match tree {
        // The empty tree is always the format-1 encoding: a tree grown from
        // it is a new one, binary as new trees are.
        Some(id) => match load(src, &id)? {
            Some((t, _)) if t.entries.is_empty() => (Tree::default(), TreeEncoding::Binary),
            Some((t, enc)) => ((*t).clone(), enc),
            None => return Ok(Err(Blocked(edits[0].1.path.clone()))),
        },
        None => (Tree::default(), TreeEncoding::Binary),
    };
    let mut i = 0;
    while i < edits.len() {
        let name = edits[i].0[depth];
        let mut j = i;
        while j < edits.len() && edits[j].0[depth] == name {
            j += 1;
        }
        let group = &edits[i..j];
        let orig = t.get(name).cloned();
        let exact = group.iter().find(|e| e.0.len() == depth + 1).map(|e| e.1.new.clone());
        let below: Vec<Edit<'_>> = group.iter().filter(|e| e.0.len() > depth + 1).cloned().collect();
        let here = if below.is_empty() {
            exact.expect("a group names this entry or something below it").map(|e| TreeEntry { name: name.to_string(), ..e })
        } else {
            // The folder the edits below apply to: the one here, unless an
            // edit replaces it with something else (it is then emptied).
            let sub = match &orig {
                Some(o) if o.kind == EntryKind::Dir => Some(o.id),
                Some(_) if matches!(exact, Some(None)) => None,
                Some(_) => return Ok(Err(Blocked(edits[i].0[..=depth].join("/")))),
                None => None,
            };
            let rewritten = match dir(src, sub, &below, depth + 1, made)? {
                Ok(r) => r,
                Err(b) => return Ok(Err(b)),
            };
            match exact {
                // A folder replaced by a file (or link): the edits below
                // must have emptied it.
                Some(Some(e)) => match rewritten {
                    None => Some(TreeEntry { name: name.to_string(), ..e }),
                    Some(_) => return Ok(Err(Blocked(e.name.clone()))),
                },
                _ => rewritten.map(|id| match &orig {
                    Some(o) if o.kind == EntryKind::Dir => TreeEntry { id, ..o.clone() },
                    _ => TreeEntry::dir(name, id),
                }),
            }
        };
        t.remove(name);
        if let Some(h) = here {
            t.insert(h);
        }
        i = j;
    }
    if t.entries.is_empty() && depth > 0 {
        return Ok(Ok(None));
    }
    let raw = Object::Tree(t.clone()).encode_with(enc);
    let id = ObjectId::hash(&raw);
    made.insert(id, (raw, Arc::new(t)));
    Ok(Ok(Some(id)))
}


/// The landing check: is `got` (a new snapshot's edit set against the tip
/// it lands on) exactly `want` (the change's edit set against its base)?
pub fn same_edits(got: &[Change], want: &[Change]) -> bool {
    got.len() == want.len()
        && got
            .iter()
            .zip(want)
            .all(|(g, w)| g.path == w.path && same(g.old.as_ref(), w.old.as_ref()) && same(g.new.as_ref(), w.new.as_ref()))
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use veil_core::{object::Visibility, VeilError};

    use super::*;

    /// Objects in memory, with what [`apply`] made added as it goes.
    #[derive(Default)]
    struct Mem(RefCell<HashMap<ObjectId, Vec<u8>>>);

    impl TreeSource for Mem {
        fn node(&self, id: &ObjectId) -> Result<Node> {
            let m = self.0.borrow();
            let raw = m.get(id).ok_or(VeilError::Missing(*id))?;
            Ok(match Object::decode(raw)? {
                Object::Tree(t) => Node::Tree(Arc::new(t), Object::tree_encoding(raw).unwrap()),
                _ => Node::Leaf,
            })
        }
    }

    impl Mem {
        fn put(&self, raw: Vec<u8>) -> ObjectId {
            let id = ObjectId::hash(&raw);
            self.0.borrow_mut().insert(id, raw);
            id
        }

        /// A tree of `(path, content)` files (content `"@"`: a link).
        fn build(&self, files: &BTreeMap<String, String>) -> ObjectId {
            fn go(m: &Mem, files: &[(String, String)]) -> Option<ObjectId> {
                let mut sub: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
                let mut t = Tree::default();
                for (p, c) in files {
                    match p.split_once('/') {
                        Some((d, rest)) => sub.entry(d.to_string()).or_default().push((rest.to_string(), c.clone())),
                        None => {
                            let id = m.put(Object::Blob(c.as_bytes().to_vec()).encode());
                            t.insert(TreeEntry {
                                name: p.clone(),
                                kind: EntryKind::File,
                                id,
                                size: c.len() as u64,
                                executable: false,
                                visibility: Visibility::Public,
                            });
                        }
                    }
                }
                for (d, fs) in sub {
                    if let Some(id) = go(m, &fs) {
                        t.insert(TreeEntry::dir(&d, id));
                    }
                }
                (!t.entries.is_empty()).then(|| m.put(Object::Tree(t).encode_with(TreeEncoding::Binary)))
            }
            let v: Vec<(String, String)> = files.iter().map(|(a, b)| (a.clone(), b.clone())).collect();
            go(self, &v).unwrap_or_else(|| self.put(Object::Tree(Tree::default()).encode()))
        }

        fn land(&self, edits: &[Change], tip: ObjectId) -> std::result::Result<ObjectId, Blocked> {
            let mut made = HashMap::new();
            let r = apply(self, tip, edits, &mut made).unwrap();
            for (id, (raw, _)) in made {
                self.0.borrow_mut().insert(id, raw);
            }
            r
        }
    }

    fn files(list: &[(&str, &str)]) -> BTreeMap<String, String> {
        list.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn the_fast_path_is_exact_per_path() {
        let m = Mem::default();
        let base = files(&[("a/x", "1"), ("a/y", "2"), ("b/z", "3"), ("c", "4")]);
        let base_t = m.build(&base);
        // The change: edit a/x, delete c, add d/new.
        let mut mine = base.clone();
        mine.insert("a/x".into(), "1'".into());
        mine.remove("c");
        mine.insert("d/new".into(), "5".into());
        let edits = edit_set(&m, m.build(&mine), base_t).unwrap();
        assert_eq!(edits.iter().map(|c| c.path.as_str()).collect::<Vec<_>>(), ["a/x", "c", "d/new"]);
        // Others landed b/z and a/y: no overlap; it lands, keeping theirs.
        let mut tip = base.clone();
        tip.insert("b/z".into(), "3'".into());
        tip.insert("a/y".into(), "2'".into());
        let tip_t = m.build(&tip);
        assert!(fast_path(&m, base_t, tip_t, &edits).unwrap().is_none());
        let landed = m.land(&edits, tip_t).unwrap();
        let mut want = tip.clone();
        want.insert("a/x".into(), "1'".into());
        want.remove("c");
        want.insert("d/new".into(), "5".into());
        assert_eq!(landed, m.build(&want));
        assert!(same_edits(&edit_set(&m, landed, tip_t).unwrap(), &edits));
        // Someone else changed a/x, deleted c, or added d/new: each overlaps.
        for (path, content) in [("a/x", Some("other")), ("c", None), ("d/new", Some("theirs"))] {
            let mut t = tip.clone();
            match content {
                Some(c) => t.insert(path.into(), c.into()),
                None => t.remove(path),
            };
            assert_eq!(fast_path(&m, base_t, m.build(&t), &edits).unwrap().as_deref(), Some(path));
        }
        // A file where the change needs a folder.
        let mut t = tip.clone();
        t.insert("d".into(), "file".into());
        assert_eq!(fast_path(&m, base_t, m.build(&t), &edits).unwrap().as_deref(), Some("d/new"));
    }

    #[test]
    fn folders_made_emptied_and_replaced() {
        let m = Mem::default();
        let base = files(&[("a/x", "1"), ("f", "2"), ("k/only", "3")]);
        let base_t = m.build(&base);
        // A file replaced by a folder, a folder by a file, a folder emptied.
        let mine = files(&[("a", "now a file"), ("f/inside", "4")]);
        let edits = edit_set(&m, m.build(&mine), base_t).unwrap();
        let tip = files(&[("a/x", "1"), ("f", "2"), ("k/only", "3"), ("z", "elsewhere")]);
        let tip_t = m.build(&tip);
        assert!(fast_path(&m, base_t, tip_t, &edits).unwrap().is_none());
        let landed = m.land(&edits, tip_t).unwrap();
        assert_eq!(landed, m.build(&files(&[("a", "now a file"), ("f/inside", "4"), ("z", "elsewhere")])));
        assert!(same_edits(&edit_set(&m, landed, tip_t).unwrap(), &edits));
        let busy = files(&[("a/x", "1"), ("a/y", "new"), ("f", "2"), ("k/only", "3")]);
        let busy_t = m.build(&busy);
        // Someone added a/y: the folder the change turns into a file is not
        // what its base had there, so it overlaps (at `a`, one of its own
        // paths), and applying it anyway would drop a/y.
        assert_eq!(fast_path(&m, base_t, busy_t, &edits).unwrap().as_deref(), Some("a"));
        assert!(m.land(&edits, busy_t).is_err());
        // Deleting everything leaves the empty tree.
        let all = edit_set(&m, m.build(&BTreeMap::new()), base_t).unwrap();
        assert_eq!(m.land(&all, base_t).unwrap(), m.build(&BTreeMap::new()));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 64, ..Default::default() })]
        /// Changes that pass the fast path, applied one after another on a
        /// moving tip, give what applying each one's edits to the tip by hand
        /// gives, and each passes the landing check (threat 4).
        #[test]
        fn batched_landings_equal_sequential_edits(
            start in proptest::collection::btree_map("[a-c]/[a-c]|[a-d]", "[xy]", 0..8),
            changes in proptest::collection::vec(proptest::collection::btree_map("[a-c]/[a-c]|[a-d]", proptest::option::of("[xyz]"), 1..4), 1..6),
        ) {
            let m = Mem::default();
            // Paths that are both a file and a folder are dropped (a tree
            // cannot hold both).
            let clean = |f: &BTreeMap<String, String>| -> BTreeMap<String, String> {
                f.iter().filter(|(p, _)| !f.keys().any(|q| q.starts_with(&format!("{p}/")))).map(|(a, b)| (a.clone(), b.clone())).collect()
            };
            let start = clean(&start);
            let base_t = m.build(&start);
            let mut tip = start.clone();
            let mut tip_t = base_t;
            for ch in changes {
                let mut mine = start.clone();
                for (p, c) in &ch {
                    match c {
                        Some(c) => { mine.insert(p.clone(), c.clone()); }
                        None => { mine.remove(p); }
                    }
                }
                let mine = clean(&mine);
                let edits = edit_set(&m, m.build(&mine), base_t).unwrap();
                if edits.is_empty() || fast_path(&m, base_t, tip_t, &edits).unwrap().is_some() {
                    continue;
                }
                let landed = match m.land(&edits, tip_t) {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                proptest::prop_assert!(same_edits(&edit_set(&m, landed, tip_t).unwrap(), &edits));
                // By hand: the tip with each edited path set as the change has it.
                for c in &edits {
                    match &c.new {
                        Some(_) => { tip.insert(c.path.clone(), mine[&c.path].clone()); }
                        None => { tip.remove(&c.path); }
                    }
                }
                proptest::prop_assert_eq!(landed, m.build(&tip));
                tip_t = landed;
            }
        }
    }
}
