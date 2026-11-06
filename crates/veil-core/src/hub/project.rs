//! Per-viewer projection of trees, and the graft that undoes it on push
//! (`docs/HUB.md` §4.6, §5.4).
//!
//! **Projection.** A viewer receives each tree with the entries they may
//! not read left out: neither the files nor their names reach them. A
//! directory they may not read but that holds something they may (the root
//! above `src/` when only `src/` is public) is kept with only that part.
//! Access lines name literal paths ([`super::access`]), so a subtree with no
//! rule below it is either wholly visible (its id is kept: no walk) or
//! wholly hidden: only the directories that hold a rule are rewritten.
//! A rewritten tree is a new, ordinary tree object in the original's
//! encoding; a directory left empty is dropped, as trees never record
//! empty directories.
//!
//! **Graft.** A viewer commits on top of their projection, so the tree they
//! push lacks what they cannot see. [`Graft`] rebuilds the full tree: what
//! they left unchanged keeps the real subtree (hidden parts included), what
//! they cannot see is taken from the real parent, and every path they
//! changed is reported ([`Change`]) for the server's write, policy and
//! secret checks. Writing to, replacing or removing anything the viewer
//! cannot see is refused here.

use std::{collections::HashMap, sync::Arc};

use super::access::View;
use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Tree, TreeEncoding, TreeEntry},
    tree::MAX_TREE_DEPTH,
};

/// What an object is, for projection.
pub enum Node {
    /// A tree, and the encoding it is stored in.
    Tree(Arc<Tree>, TreeEncoding),
    /// Anything else: a blob, a sealed object (a sealed directory is a
    /// leaf: nobody but key holders can look inside), a conflict.
    Leaf,
}

/// Where trees are read from.
pub trait TreeSource {
    /// The object `id`; [`VeilError::Missing`] if it is not there.
    fn node(&self, id: &ObjectId) -> Result<Node>;
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn too_deep() -> VeilError {
    VeilError::Corrupt("tree".into(), format!("nested deeper than {MAX_TREE_DEPTH} directories"))
}

/// The id of the empty tree (always the format-1 encoding).
pub fn empty_tree_id() -> ObjectId {
    ObjectId::hash(&Object::Tree(Tree::default()).encode())
}

/// Encode `entries` (sorted) as a tree in `enc`; the empty tree is always
/// the format-1 encoding.
fn encode_tree(entries: Vec<TreeEntry>, enc: TreeEncoding) -> (ObjectId, Arc<Tree>, Vec<u8>) {
    let tree = Tree { entries };
    let raw = Object::Tree(tree.clone()).encode_with(enc);
    (ObjectId::hash(&raw), Arc::new(tree), raw)
}

/// Computes projections for one viewer, remembering each one.
pub struct Projector<'a> {
    src: &'a dyn TreeSource,
    view: &'a View<'a>,
    memo: HashMap<(String, ObjectId), Option<ObjectId>>,
    /// Trees this projector created (rewritten directories), by id.
    pub created: HashMap<ObjectId, (Arc<Tree>, Vec<u8>)>,
}

impl<'a> Projector<'a> {
    pub fn new(src: &'a dyn TreeSource, view: &'a View<'a>) -> Projector<'a> {
        Projector {
            src,
            view,
            memo: HashMap::new(),
            created: HashMap::new(),
        }
    }

    pub fn view(&self) -> &View<'a> {
        self.view
    }

    /// The projection of root tree `tree`: never absent (the empty tree
    /// when the viewer sees nothing).
    pub fn root(&mut self, tree: ObjectId) -> Result<ObjectId> {
        match self.dir("", tree)? {
            Some(id) => Ok(id),
            None => {
                let (id, t, raw) = encode_tree(Vec::new(), TreeEncoding::Json);
                self.created.insert(id, (t, raw));
                Ok(id)
            }
        }
    }

    /// The projection of tree `tree` found at directory `dir`; `None` when
    /// the viewer sees nothing of it.
    pub fn dir(&mut self, dir: &str, tree: ObjectId) -> Result<Option<ObjectId>> {
        self.dir_at(dir, tree, 0)
    }

    fn dir_at(&mut self, dir: &str, tree: ObjectId, depth: usize) -> Result<Option<ObjectId>> {
        if depth > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        if !self.view.rule_below(dir) {
            return Ok(self.view.read(dir).then_some(tree));
        }
        let key = (dir.to_string(), tree);
        if let Some(v) = self.memo.get(&key) {
            return Ok(*v);
        }
        let (t, enc) = match self.src.node(&tree)? {
            Node::Tree(t, enc) => (t, enc),
            // A sealed directory with a rule below it: whoever lacks some
            // of it cannot be given any of it.
            Node::Leaf => return Ok(None),
        };
        let mut out = Vec::with_capacity(t.entries.len());
        let mut changed = false;
        for e in &t.entries {
            let child = join(dir, &e.name);
            let keep = if e.kind == EntryKind::Dir {
                match self.dir_at(&child, e.id, depth + 1)? {
                    Some(id) if id == e.id => Some(e.clone()),
                    Some(id) => Some(TreeEntry { id, ..e.clone() }),
                    None => None,
                }
            } else {
                self.view.read(&child).then(|| e.clone())
            };
            match keep {
                Some(k) => {
                    changed |= k.id != e.id;
                    out.push(k)
                }
                None => changed = true,
            }
        }
        let result = if out.is_empty() {
            None
        } else if !changed {
            Some(tree)
        } else {
            let (id, t, raw) = encode_tree(out, enc);
            self.created.insert(id, (t, raw));
            Some(id)
        };
        self.memo.insert(key, result);
        Ok(result)
    }

    /// The projected tree `id` (a tree this projector created, or a real
    /// tree kept as is).
    pub fn tree(&self, id: &ObjectId) -> Result<Option<Arc<Tree>>> {
        if let Some((t, _)) = self.created.get(id) {
            return Ok(Some(t.clone()));
        }
        Ok(match self.src.node(id)? {
            Node::Tree(t, _) => Some(t),
            Node::Leaf => None,
        })
    }

    /// The encoding of a tree this projector created.
    pub fn created_raw(&self, id: &ObjectId) -> Option<&[u8]> {
        self.created.get(id).map(|(_, r)| r.as_slice())
    }
}

/// One path a push changes, relative to its first parent as the pusher saw
/// it: added (`old` absent), removed (`new` absent) or modified. Only files
/// and other leaves are reported; directories are walked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    pub old: Option<TreeEntry>,
    pub new: Option<TreeEntry>,
}

/// Rebuilds full trees from trees a viewer pushed.
pub struct Graft<'a> {
    pub proj: Projector<'a>,
    src: &'a dyn TreeSource,
    /// Full trees this graft built, by id.
    pub created: HashMap<ObjectId, Vec<u8>>,
    pub changes: Vec<Change>,
}

fn refused(path: &str) -> VeilError {
    VeilError::Policy(format!("you do not have access to '{path}'"))
}

impl<'a> Graft<'a> {
    pub fn new(src: &'a dyn TreeSource, view: &'a View<'a>) -> Graft<'a> {
        Graft {
            proj: Projector::new(src, view),
            src,
            created: HashMap::new(),
            changes: Vec::new(),
        }
    }

    fn is_tree(&self, e: Option<&TreeEntry>) -> Result<Option<Arc<Tree>>> {
        match e {
            Some(e) if e.kind == EntryKind::Dir => match self.src.node(&e.id)? {
                Node::Tree(t, _) => Ok(Some(t)),
                Node::Leaf => Ok(None),
            },
            _ => Ok(None),
        }
    }

    /// The full root tree for pushed root `pushed`, on top of the real
    /// parent root `real` (`None` for a first snapshot).
    pub fn root(&mut self, pushed: ObjectId, real: Option<ObjectId>) -> Result<ObjectId> {
        match self.dir("", Some(pushed), real, 0)? {
            Some(id) => Ok(id),
            None => {
                let (id, _, raw) = encode_tree(Vec::new(), TreeEncoding::Json);
                self.created.insert(id, raw);
                Ok(id)
            }
        }
    }

    fn dir(&mut self, dir: &str, pushed: Option<ObjectId>, real: Option<ObjectId>, depth: usize) -> Result<Option<ObjectId>> {
        if depth > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        let seen = match real {
            Some(r) => self.proj.dir_at(dir, r, depth)?,
            None => None,
        };
        // The pushed root of an empty projection is the empty tree.
        let pushed = pushed.filter(|p| !(dir.is_empty() && seen.is_none() && self.is_empty_tree(p)));
        if pushed == seen {
            return Ok(real);
        }
        let view = self.proj.view;
        if !view.rule_below(dir) {
            if !view.read(dir) {
                return Err(refused(if dir.is_empty() { "/" } else { dir }));
            }
            // Wholly visible here: the pushed tree replaces the real one.
            self.diff(dir, real, pushed, depth)?;
            return Ok(pushed);
        }
        let pt = match pushed {
            Some(p) => Some(self.tree_at(dir, &p)?),
            None => None,
        };
        let rt = match real {
            Some(r) => Some(self.tree_at(dir, &r)?),
            None => None,
        };
        let enc = [pushed, real]
            .into_iter()
            .flatten()
            .find_map(|id| match self.src.node(&id) {
                Ok(Node::Tree(_, enc)) => Some(enc),
                _ => None,
            })
            .unwrap_or(TreeEncoding::Binary);
        let mut names: Vec<&str> = Vec::new();
        for t in pt.iter().chain(rt.iter()) {
            names.extend(t.entries.iter().map(|e| e.name.as_str()));
        }
        names.sort_unstable();
        names.dedup();
        let names: Vec<String> = names.into_iter().map(str::to_string).collect();
        let mut out = Vec::new();
        for name in names {
            let child = join(dir, &name);
            let pe = pt.as_ref().and_then(|t| t.get(&name)).cloned();
            let re = rt.as_ref().and_then(|t| t.get(&name)).cloned();
            let p_dir = self.is_tree(pe.as_ref())?.is_some();
            let r_dir = self.is_tree(re.as_ref())?.is_some();
            // Hidden from the pusher (a file they may not read, or a
            // directory with nothing they may read below it): theirs cannot
            // name it, and the real one is kept.
            let hidden = match r_dir {
                false if re.is_some() => !view.read(&child),
                _ => !view.read(&child) && !view.rule_below(&child),
            };
            if hidden {
                if pe.is_some() {
                    return Err(refused(&child));
                }
                out.extend(re);
                continue;
            }
            if (p_dir || pe.is_none()) && (r_dir || re.is_none()) {
                let id = self.dir(&child, pe.as_ref().map(|e| e.id), re.as_ref().map(|e| e.id), depth + 1)?;
                if let Some(id) = id {
                    let base = pe.clone().or(re.clone()).expect("one side exists");
                    out.push(TreeEntry { id, ..base });
                }
            } else if r_dir {
                // A file replaces a directory: only one the pusher sees whole.
                if view.rule_below(&child) || !view.read(&child) {
                    return Err(refused(&child));
                }
                self.diff(&child, re.as_ref().map(|e| e.id), None, depth + 1)?;
                self.leaf(&child, None, pe.clone());
                out.extend(pe);
            } else if p_dir {
                self.leaf(&child, re.clone(), None);
                self.diff(&child, None, pe.as_ref().map(|e| e.id), depth + 1)?;
                out.extend(pe);
            } else {
                self.leaf(&child, re, pe.clone());
                out.extend(pe);
            }
        }
        if out.is_empty() {
            return Ok(None);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        let (id, _, raw) = encode_tree(out, enc);
        self.created.insert(id, raw);
        Ok(Some(id))
    }

    fn is_empty_tree(&self, id: &ObjectId) -> bool {
        *id == empty_tree_id() || matches!(self.src.node(id), Ok(Node::Tree(t, _)) if t.entries.is_empty())
    }

    /// The tree `id` at `dir`: a pushed or real tree, or a projection.
    fn tree_at(&self, dir: &str, id: &ObjectId) -> Result<Arc<Tree>> {
        if *id == empty_tree_id() {
            return Ok(Arc::new(Tree::default()));
        }
        if let Some(t) = self.proj.created.get(id) {
            return Ok(t.0.clone());
        }
        match self.src.node(id)? {
            Node::Tree(t, _) => Ok(t),
            Node::Leaf => Err(VeilError::Corrupt(id.hex(), format!("'{dir}' is not a directory"))),
        }
    }

    fn leaf(&mut self, path: &str, old: Option<TreeEntry>, new: Option<TreeEntry>) {
        let same = match (&old, &new) {
            (Some(a), Some(b)) => a.kind == b.kind && a.same_content(b),
            (None, None) => true,
            _ => false,
        };
        if !same {
            self.changes.push(Change {
                path: path.to_string(),
                old,
                new,
            });
        }
    }

    /// Report every leaf that differs between trees `old` and `new` at `dir`.
    fn diff(&mut self, dir: &str, old: Option<ObjectId>, new: Option<ObjectId>, depth: usize) -> Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        if old == new {
            return Ok(());
        }
        let ot = match old {
            Some(o) => Some(self.tree_at(dir, &o)?),
            None => None,
        };
        let nt = match new {
            Some(n) => Some(self.tree_at(dir, &n)?),
            None => None,
        };
        let mut names: Vec<String> = Vec::new();
        for t in ot.iter().chain(nt.iter()) {
            names.extend(t.entries.iter().map(|e| e.name.clone()));
        }
        names.sort_unstable();
        names.dedup();
        for name in names {
            let child = join(dir, &name);
            let oe = ot.as_ref().and_then(|t| t.get(&name)).cloned();
            let ne = nt.as_ref().and_then(|t| t.get(&name)).cloned();
            if oe == ne {
                continue;
            }
            let o_dir = self.is_tree(oe.as_ref())?.is_some();
            let n_dir = self.is_tree(ne.as_ref())?.is_some();
            match (o_dir, n_dir) {
                (true, true) => self.diff(&child, oe.map(|e| e.id), ne.map(|e| e.id), depth + 1)?,
                (true, false) => {
                    self.diff(&child, oe.map(|e| e.id), None, depth + 1)?;
                    self.leaf(&child, None, ne);
                }
                (false, true) => {
                    self.leaf(&child, oe, None);
                    self.diff(&child, None, ne.map(|e| e.id), depth + 1)?;
                }
                (false, false) => self.leaf(&child, oe, ne),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::{super::access::AccessPolicy, *};
    use crate::object::Visibility;

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
        /// A tree from `(path, content)` files.
        fn build(&self, files: &[(&str, &str)]) -> ObjectId {
            fn go(m: &Mem, files: &[(String, String)]) -> ObjectId {
                let mut by: std::collections::BTreeMap<String, Vec<(String, String)>> = Default::default();
                let mut entries = Vec::new();
                for (p, c) in files {
                    match p.split_once('/') {
                        Some((d, rest)) => by.entry(d.to_string()).or_default().push((rest.to_string(), c.clone())),
                        None => {
                            let id = m.put(Object::Blob(c.as_bytes().to_vec()).encode());
                            entries.push(TreeEntry {
                                name: p.clone(),
                                kind: EntryKind::File,
                                id,
                                size: c.len() as u64,
                                executable: false,
                                visibility: Visibility::Public,
                                fallback: None,
                            });
                        }
                    }
                }
                for (d, sub) in by {
                    entries.push(TreeEntry::dir(&d, go(m, &sub)));
                }
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                m.put(Object::Tree(Tree { entries }).encode_with(TreeEncoding::Binary))
            }
            let files: Vec<(String, String)> = files.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
            go(self, &files)
        }
        fn files(&self, root: ObjectId, created: &HashMap<ObjectId, Vec<u8>>) -> Vec<String> {
            let mut out = Vec::new();
            let mut stack = vec![(String::new(), root)];
            while let Some((dir, id)) = stack.pop() {
                let raw = created.get(&id).cloned().or_else(|| self.0.borrow().get(&id).cloned()).unwrap();
                if let Object::Tree(t) = Object::decode(&raw).unwrap() {
                    for e in t.entries {
                        let p = join(&dir, &e.name);
                        if e.kind == EntryKind::Dir {
                            stack.push((p, e.id));
                        } else {
                            out.push(p);
                        }
                    }
                }
            }
            out.sort();
            out
        }
    }

    const POLICY: &str = "src/ public devs\nsrc/secret/ security\nbilling/ finance\n";
    const FILES: &[(&str, &str)] = &[
        (".veilpolicy", POLICY),
        ("README", "r"),
        ("src/a.rs", "a"),
        ("src/secret/key.txt", "MARKER-secret"),
        ("billing/acme/invoice.txt", "MARKER-billing"),
    ];

    #[test]
    fn projection_hides_names() {
        let m = Mem::default();
        let root = m.build(FILES);
        let p = AccessPolicy::parse(POLICY);
        let anon = View::anonymous(&p);
        let mut pr = Projector::new(&m, &anon);
        let r = pr.root(root).unwrap();
        let created: HashMap<_, _> = pr.created.iter().map(|(k, v)| (*k, v.1.clone())).collect();
        assert_eq!(m.files(r, &created), ["src/a.rs"]);
        for raw in created.values() {
            let s = String::from_utf8_lossy(raw);
            assert!(!s.contains("secret") && !s.contains("billing") && !s.contains("README"), "{s}");
        }
        let admin = View::admin(&p);
        assert_eq!(Projector::new(&m, &admin).root(root).unwrap(), root);
        let fin = View::new(&p, false, |_, n| n == "finance");
        let mut pr = Projector::new(&m, &fin);
        let r = pr.root(root).unwrap();
        let created: HashMap<_, _> = pr.created.iter().map(|(k, v)| (*k, v.1.clone())).collect();
        assert_eq!(m.files(r, &created), ["billing/acme/invoice.txt", "src/a.rs"]);
        // Nobody sees nothing: the empty tree.
        let none = AccessPolicy::parse("");
        let v = View::anonymous(&none);
        let mut pr = Projector::new(&m, &v);
        let r = pr.root(root).unwrap();
        assert_eq!(pr.tree(&r).unwrap().unwrap().entries.len(), 0);
    }

    fn graft_of(m: &Mem, view: &View, real: ObjectId, pushed_files: &[(&str, &str)]) -> Result<(ObjectId, Vec<Change>, HashMap<ObjectId, Vec<u8>>)> {
        let pushed = m.build(pushed_files);
        let mut g = Graft::new(m, view);
        let id = g.root(pushed, Some(real))?;
        Ok((id, g.changes, g.created))
    }

    #[test]
    fn graft_restores_hidden_and_reports_changes() {
        let m = Mem::default();
        let real = m.build(FILES);
        let p = AccessPolicy::parse(POLICY);
        let dev = View::new(&p, false, |_, n| n == "devs");
        // devs see src/a.rs only; they edit it and add a file.
        let (id, changes, created) = graft_of(&m, &dev, real, &[("src/a.rs", "a2"), ("src/b.rs", "b")]).unwrap();
        let paths: Vec<&str> = changes.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, ["src/a.rs", "src/b.rs"]);
        assert_eq!(
            m.files(id, &created),
            [".veilpolicy", "README", "billing/acme/invoice.txt", "src/a.rs", "src/b.rs", "src/secret/key.txt"]
        );
        // Unchanged: the real tree itself.
        let (id, changes, _) = graft_of(&m, &dev, real, &[("src/a.rs", "a")]).unwrap();
        assert_eq!(id, real);
        assert!(changes.is_empty());
        // Deleting everything they see keeps what they don't.
        let (id, changes, created) = graft_of(&m, &dev, real, &[]).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(m.files(id, &created), [".veilpolicy", "README", "billing/acme/invoice.txt", "src/secret/key.txt"]);
    }

    #[test]
    fn graft_refuses_hidden_paths() {
        let m = Mem::default();
        let real = m.build(FILES);
        let p = AccessPolicy::parse(POLICY);
        let dev = View::new(&p, false, |_, n| n == "devs");
        for files in [
            &[("src/a.rs", "a"), ("billing/x", "x")][..],
            &[("src/a.rs", "a"), ("src/secret/key.txt", "overwrite")][..],
            &[("src/a.rs", "a"), ("src/secret", "a file over a hidden folder")][..],
            &[("src/a.rs", "a"), (".veilpolicy", "src/ public devs\n")][..],
            &[("src/a.rs", "a"), ("NEW", "private by default")][..],
        ] {
            let err = graft_of(&m, &dev, real, files).unwrap_err();
            assert!(matches!(err, VeilError::Policy(_)), "{files:?}: {err}");
        }
    }

    mod props {
        use std::collections::BTreeMap;

        use proptest::prelude::*;

        use super::*;

        const PARTS: &[&str] = &["a", "b", "c"];

        fn path_strategy() -> impl Strategy<Value = String> {
            prop::collection::vec(0..PARTS.len(), 1..4).prop_map(|v| v.iter().map(|i| PARTS[*i]).collect::<Vec<_>>().join("/"))
        }

        /// Files whose paths never make one a directory of another.
        fn files_strategy() -> impl Strategy<Value = BTreeMap<String, String>> {
            prop::collection::btree_map(path_strategy(), "[a-z]{1,4}", 1..10).prop_map(|m| {
                let keys: Vec<String> = m.keys().cloned().collect();
                m.into_iter()
                    .filter(|(k, _)| !keys.iter().any(|o| o.len() > k.len() && o.starts_with(&format!("{k}/"))))
                    .collect()
            })
        }

        fn policy_strategy() -> impl Strategy<Value = String> {
            prop::collection::vec((path_strategy(), any::<bool>(), prop::sample::subsequence(vec!["g", "h", "me"], 0..3)), 0..5).prop_map(|rules| {
                rules
                    .into_iter()
                    .filter(|(_, public, names)| *public || !names.is_empty())
                    .map(|(p, public, names)| {
                        let mut who: Vec<&str> = names;
                        if public {
                            who.insert(0, "public");
                        }
                        format!("{p}/ {}\n", who.join(" "))
                    })
                    .collect()
            })
        }

        fn files_of(m: &Mem, root: ObjectId, created: &HashMap<ObjectId, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
            let mut out = BTreeMap::new();
            let mut stack = vec![(String::new(), root)];
            while let Some((dir, id)) = stack.pop() {
                let raw = created.get(&id).cloned().or_else(|| m.0.borrow().get(&id).cloned()).unwrap();
                if let Object::Tree(t) = Object::decode(&raw).unwrap() {
                    for e in t.entries {
                        let p = join(&dir, &e.name);
                        if e.kind == EntryKind::Dir {
                            stack.push((p, e.id));
                        } else {
                            let b = m.0.borrow().get(&e.id).cloned().unwrap();
                            out.insert(p, b);
                        }
                    }
                }
            }
            out
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// A viewer's projection holds exactly the files they may read (so
            /// no other name), and grafting it back unchanged gives the real
            /// tree; an edit of what they may write changes only that.
            #[test]
            fn projection_hides_exactly_and_graft_restores(
                files in files_strategy(),
                policy in policy_strategy(),
                groups in prop::sample::subsequence(vec!["g", "h"], 0..3),
                edit in "[a-z]{1,4}",
            ) {
                let m = Mem::default();
                let list: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
                let real = m.build(&list);
                let p = AccessPolicy::parse(&policy);
                let view = View::new(&p, false, |_, n| n == "me" || groups.contains(&n));
                let mut pr = Projector::new(&m, &view);
                let proj = pr.root(real).unwrap();
                let created: HashMap<ObjectId, Vec<u8>> = pr.created.iter().map(|(k, v)| (*k, v.1.clone())).collect();
                let seen = files_of(&m, proj, &created);
                let readable: BTreeMap<String, Vec<u8>> = files_of(&m, real, &HashMap::new())
                    .into_iter()
                    .filter(|(k, _)| view.read(k))
                    .collect();
                prop_assert_eq!(&seen, &readable);
                // Every name in a projected tree leads to something readable.
                for raw in created.values() {
                    if let Ok(Object::Tree(t)) = Object::decode(raw) {
                        for e in &t.entries {
                            prop_assert!(seen.keys().any(|k| k.split('/').any(|c| c == e.name)), "{} named", e.name);
                        }
                    }
                }
                // Unchanged: the real tree itself.
                let mut g = Graft::new(&m, &view);
                prop_assert_eq!(g.root(proj, Some(real)).unwrap(), real);
                // Edit every file they may write; the graft keeps the rest.
                let mut mine: Vec<(String, String)> = Vec::new();
                for (k, _) in &seen {
                    if view.write(k) {
                        mine.push((k.clone(), edit.clone()));
                    } else {
                        mine.push((k.clone(), String::from_utf8_lossy(&seen[k][10..]).into_owned()));
                    }
                }
                let pushed = m.build(&mine.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>());
                let mut g = Graft::new(&m, &view);
                let full = g.root(pushed, Some(real)).unwrap();
                let after = files_of(&m, full, &g.created);
                for (k, v) in files_of(&m, real, &HashMap::new()) {
                    let want = if view.read(&k) && view.write(&k) { format!("veil:blob\n{edit}").into_bytes() } else { v };
                    prop_assert_eq!(after.get(&k), Some(&want), "{}", k);
                }
                prop_assert_eq!(after.len(), files.len());
                for c in &g.changes {
                    prop_assert!(view.write(&c.path), "{} changed without write access", c.path);
                }
            }
        }
    }
}
