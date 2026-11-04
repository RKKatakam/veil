//! Tree depth in `.veil/` is attacker-controlled (a tampered local
//! repository is not depth-limited the way remote transfers are). Merge,
//! normalisation, embargo sealing, the builder and fsck are iterative and
//! must neither overflow the stack nor accept unbounded nesting. Tests run
//! on the default 2 MiB test-thread stack on purpose.

use std::{collections::BTreeSet, sync::Arc};

use veil_core::{
    embargo::{normalize_tree, wrap, NormalizeOptions, NormalizeReport},
    fsck::{fsck, Severity},
    merge::merge_trees,
    object::{EntryKind, Snapshot, Tree, TreeEntry, Visibility},
    policy::Policy,
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

fn file(store: &ObjectStore, name: &str, data: &[u8]) -> TreeEntry {
    TreeEntry {
        name: name.into(),
        kind: EntryKind::File,
        id: store.store_file(data, &Visibility::Public).unwrap(),
        size: data.len() as u64,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
    }
}

/// `d/d/…/d/f` with `depth` directories, `f` holding `leaf`.
fn chain(store: &ObjectStore, depth: usize, leaf: &[u8]) -> ObjectId {
    let mut id = store
        .put_tree(&Tree {
            entries: vec![file(store, "f", leaf)],
        })
        .unwrap();
    for _ in 1..depth {
        id = store
            .put_tree(&Tree {
                entries: vec![TreeEntry::dir("d", id)],
            })
            .unwrap();
    }
    id
}

fn repo() -> Repo {
    Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("t")), "t").unwrap()
}

#[test]
fn merge_of_deep_trees_is_bounded_and_does_not_overflow() {
    let r = repo();
    let s = r.store();
    // Legitimate depth: merged without recursion.
    let depth = MAX_TREE_DEPTH - 24;
    let (b, o, t) = (
        chain(s, depth, b"a\nb\nc\n"),
        chain(s, depth, b"A\nb\nc\n"),
        chain(s, depth, b"a\nb\nC\n"),
    );
    let m = merge_trees(s, Some(b), o, t).unwrap();
    assert!(m.conflicts.is_empty());
    let mut path = "d/".repeat(depth - 1);
    path.push('f');
    let e = veil_core::tree::lookup(s, &m.tree, &VPath::new(&path).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(s.read_entry(&e).unwrap(), b"A\nb\nC\n");
    // Hostile depth: refused.
    let depth = 4 * MAX_TREE_DEPTH;
    let (b, o, t) = (chain(s, depth, b"1"), chain(s, depth, b"2"), chain(s, depth, b"3"));
    let err = merge_trees(s, Some(b), o, t).unwrap_err();
    assert!(err.to_string().contains("nesting exceeds"), "{err}");
}

#[test]
fn normalisation_and_embargo_sealing_of_deep_trees_do_not_overflow() {
    let r = repo();
    let s = r.store();
    let policy = Policy::parse("secret/ cloak team\n");
    let none = BTreeSet::new();
    let base = chain(s, 3, b"base");
    let opts = NormalizeOptions {
        policy: &policy,
        dest_policy: &policy,
        dest_tree: base,
        cloak: Some("team"),
        declassify: &none,
        defer_declassify: false,
    };
    let ok = chain(s, MAX_TREE_DEPTH - 24, b"x");
    normalize_tree(s, &ok, &opts, &mut NormalizeReport::default()).unwrap();
    let deep = chain(s, 4 * MAX_TREE_DEPTH, b"x");
    assert!(normalize_tree(s, &deep, &opts, &mut NormalizeReport::default()).is_err());

    let id = r.keys().create_embargo("team", None).unwrap();
    wrap(s, &id, &ok, &base).unwrap();
    assert!(wrap(s, &id, &deep, &base).is_err());
}

#[test]
fn fsck_reports_hostile_nesting_without_overflowing() {
    let mut r = repo();
    let tree = chain(r.store(), 4 * MAX_TREE_DEPTH, b"x");
    let snap = Snapshot {
        parents: vec![r.root_id()],
        tree,
        ..Snapshot::root(tree)
    };
    let id = r.store().put_snapshot(&snap).unwrap();
    r.set_tag("deep", id, None, true).unwrap();
    let report = fsck(r.backend().clone(), None).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.severity == Severity::Corrupt && f.message.contains("nesting exceeds")),
        "{:#?}",
        report.findings
    );
}

#[test]
fn builder_handles_a_working_copy_deeper_than_the_limit() {
    let mut r = repo();
    let wc = Arc::new(MemoryBackend::new());
    let deep = format!("{}f.txt", "d/".repeat(MAX_TREE_DEPTH + 50));
    wc.write(&VPath::new(&deep).unwrap(), b"deep\n").unwrap();
    wc.write(&VPath::new("top.txt").unwrap(), b"top\n").unwrap();
    let out = r.snapshot_workspace("default", &*wc).unwrap();
    assert!(
        out.report
            .unreadable
            .iter()
            .any(|(_, why)| why.contains("nesting exceeds")),
        "{:?}",
        out.report.unreadable
    );
    let tree = r.snapshot(&out.snapshot).unwrap().tree;
    let files = veil_core::tree::walk_files(r.store(), &tree).unwrap();
    assert!(files.iter().any(|(p, _)| p.as_str() == "top.txt"));
    // A legitimately deep working copy is recorded completely.
    let wc = Arc::new(MemoryBackend::new());
    let ok = format!("{}f.txt", "d/".repeat(MAX_TREE_DEPTH - 24));
    wc.write(&VPath::new(&ok).unwrap(), b"ok\n").unwrap();
    let out = r.snapshot_workspace("default", &*wc).unwrap();
    assert!(out.report.unreadable.is_empty());
    let tree = r.snapshot(&out.snapshot).unwrap().tree;
    assert_eq!(veil_core::tree::walk_files(r.store(), &tree).unwrap().len(), 1);
}
