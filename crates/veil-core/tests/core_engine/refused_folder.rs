//! A thin clone whose person lost access to a folder: the server refuses
//! that folder's tree, the clone keeps it by its id, and a writer that does
//! not need its content works without it (BUG-1508, BUG-1529). The server
//! suite proves this through `vl` (`server_hub::workspaces`); these are the
//! engine's own tests of it (BUG-1897: the engine's suite passed while
//! every such merge, rebase, split and squash was refused).

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use veil_core::{
    object::Object,
    promisor::{Located, Promisor},
    repo::{PartialConfig, PARTIAL_FORMAT},
    selection::{Pick, Selection},
    store::ObjectStore,
    tree::lookup,
    MemoryBackend, ObjectId, Repo, TreeEntry,
};

use crate::adversarial_support::*;

const BILL: &str = "bill";

/// The server: a full repository that answers by id, and has nothing for
/// this person below the folders in `refuse`.
struct Server {
    store: Arc<ObjectStore>,
    tips: Vec<ObjectId>,
    refuse: HashSet<ObjectId>,
}

impl Promisor for Server {
    fn fetch(&self, wants: &[Located]) -> veil_core::Result<Vec<Option<Vec<u8>>>> {
        Ok(wants.iter().map(|w| if self.refuse.contains(&w.id) { None } else { self.store.get_raw(&w.id).ok() }).collect())
    }

    fn history(&self, tips: &[ObjectId], limit: usize) -> veil_core::Result<Vec<(ObjectId, Vec<u8>)>> {
        let (mut out, mut seen) = (Vec::new(), HashSet::new());
        let mut queue: VecDeque<ObjectId> = tips.iter().copied().collect();
        while let Some(id) = queue.pop_front() {
            if out.len() >= limit.max(tips.len()) || !seen.insert(id) {
                continue;
            }
            let Ok(raw) = self.store.get_raw(&id) else { continue };
            let Ok(Object::Snapshot(s)) = Object::decode(&raw) else { continue };
            queue.extend(s.parents.iter().copied());
            out.push((id, raw));
        }
        Ok(out)
    }

    fn server_tips(&self) -> Vec<ObjectId> {
        self.tips.clone()
    }
}

/// A thin clone of a project whose `bill/` folder the server refuses:
/// `feature` (on `base`) changed `bill/`, `src/lib.rs` and added
/// `src/more.txt`; `mine` (on `base` too) added `src/mine.txt`.
struct Clone {
    repo: Repo,
    feature: ObjectId,
    mine: ObjectId,
    /// `bill/` as `base` and as `feature` have it.
    base_bill: TreeEntry,
    feature_bill: TreeEntry,
}

fn dir_entry(repo: &Repo, rev: &ObjectId, path: &str) -> TreeEntry {
    let tree = repo.snapshot(rev).unwrap().tree;
    lookup(repo.store(), &tree, &p(path)).unwrap().unwrap_or_else(|| panic!("{path} missing"))
}

fn clone_with_a_refused_folder() -> Clone {
    clone_refusing(false)
}

/// [`clone_with_a_refused_folder`]; with `root`, the server refuses the
/// root of `feature`'s tree too (the clone never fetched it, and its
/// person's view changed since).
fn clone_refusing(root: bool) -> Clone {
    let (mut server, fs, id) = new_repo("alice");
    let base = commit_files(&mut server, &*fs, &[("bill/acme/q1.txt", "q1\n"), ("src/lib.rs", "one\n")], "base");
    let feature =
        commit_files(&mut server, &*fs, &[("bill/acme/q2.txt", "q2\n"), ("src/lib.rs", "two\n"), ("src/more.txt", "more\n")], "feature work");
    let ws = server.ephemeral_workspace(base).unwrap();
    ws.write("src/mine.txt", "mine\n").unwrap();
    let mine = server.commit_ephemeral(&ws, "mine").unwrap().0;
    let (base_bill, feature_bill) = (dir_entry(&server, &base, BILL), dir_entry(&server, &feature, BILL));
    assert_ne!(base_bill.id, feature_bill.id, "feature changed the folder");

    let cfs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(cfs, Some(id), "alice").unwrap();
    repo.update_config(|c| {
        c.format = PARTIAL_FORMAT;
        c.min_vl = Some(veil_core::repo::min_vl_for_format(PARTIAL_FORMAT).into());
        c.partial = Some(PartialConfig { remote: "origin".into(), cache_limit: 1 << 30 });
        Ok(())
    })
    .unwrap();
    for tip in [feature, mine] {
        repo.store().put_raw(&tip, &server.store().get_raw(&tip).unwrap()).unwrap();
    }
    repo.store().set_promisor(Arc::new(Server {
        store: server.store().clone(),
        tips: vec![feature, mine],
        refuse: HashSet::from([base_bill.id, feature_bill.id]).into_iter().chain(root.then(|| server.snapshot(&feature).unwrap().tree)).collect(),
    }));
    // As a clone records them: the server's branches, and their changes.
    let mut tx = repo.transaction("clone").unwrap();
    tx.view.remote_tags.insert("origin/feature".into(), feature);
    tx.view.remote_tags.insert("origin/mine".into(), mine);
    tx.add_head(feature).unwrap();
    tx.add_head(mine).unwrap();
    tx.commit().unwrap();

    // The fixture's own check: the folder is refused, to a writer by name.
    let tree = repo.snapshot(&feature).unwrap().tree;
    let err = veil_core::tree::walk_files(repo.store(), &tree).unwrap_err().to_string();
    let what = if root { "/ is a folder" } else { "bill/ is a folder" };
    assert!(err.contains(&format!("{what} you no longer have access to")), "{err}");
    Clone { repo, feature, mine, base_bill, feature_bill }
}

/// A merge and a rebase where only the other side changed the refused
/// folder take that side's folder by its id.
#[test]
fn bug_1897_a_merge_and_a_rebase_keep_a_refused_folder_one_side_changed_by_id() {
    let Clone { mut repo, feature, mine, feature_bill, .. } = clone_with_a_refused_folder();
    let start = repo.op_id();
    let merged = repo.merge(WS, mine, vec![feature], "merge across", None).unwrap();
    assert_eq!(merged.conflicts, Vec::<String>::new());
    assert_eq!(dir_entry(&repo, &merged.snapshot, BILL), feature_bill, "the merge keeps feature's folder by id");
    assert_eq!(read_at(&repo, &merged.snapshot, "src/mine.txt"), b"mine\n");
    assert_eq!(read_at(&repo, &merged.snapshot, "src/more.txt"), b"more\n");

    repo.restore_operation(start).unwrap();
    let rebased = repo.rebase(mine, vec![feature]).unwrap();
    assert_eq!(repo.snapshot(&rebased).unwrap().parents, vec![feature]);
    assert_eq!(dir_entry(&repo, &rebased, BILL), feature_bill, "the rebase keeps feature's folder by id");
    assert_eq!(read_at(&repo, &rebased, "src/mine.txt"), b"mine\n");
}

/// A split and a squash of a path outside the refused folder leave the
/// folder where the change had it, by its id, and move only that path.
#[test]
fn bug_1897_a_split_and_a_squash_of_other_paths_keep_a_refused_folder_by_id() {
    let Clone { mut repo, feature, base_bill, feature_bill, .. } = clone_with_a_refused_folder();
    let start = repo.op_id();
    let parts = repo.change_parts(&feature, false).unwrap();
    let more = Selection::from([(p("src/more.txt"), Pick { whole: true, ..Pick::default() })]);

    let split = repo.split(&parts, &more, Some("first")).unwrap();
    assert_eq!(dir_entry(&repo, &split.first, BILL), base_bill, "the split's first change has the base's folder");
    assert_eq!(read_at(&repo, &split.first, "src/more.txt"), b"more\n");
    assert_eq!(read_at(&repo, &split.first, "src/lib.rs"), b"one\n", "and only the path asked for");
    assert_eq!(dir_entry(&repo, &split.second, BILL), feature_bill, "the rest keeps feature's folder by id");
    assert_eq!(read_at(&repo, &split.second, "src/lib.rs"), b"two\n");

    repo.restore_operation(start).unwrap();
    let squashed = repo.squash_into(feature, None, Some((&parts, &more))).unwrap();
    assert!(!squashed.emptied, "the change keeps the rest");
    assert_eq!(dir_entry(&repo, &squashed.destination, BILL), base_bill, "the parent keeps its own folder");
    assert_eq!(read_at(&repo, &squashed.destination, "src/more.txt"), b"more\n");
    let rest = squashed.source.expect("the change keeps the rest");
    assert_eq!(dir_entry(&repo, &rest, BILL), feature_bill, "the change keeps feature's folder by id");
    assert_eq!(read_at(&repo, &rest, "src/lib.rs"), b"two\n");
}

/// BUG-1573, BUG-1574: a checkout of a tree whose root the server refuses
/// is the reader's refusal (what a view change makes a command fail with,
/// so the clone moves and the command runs again), never a working copy of
/// no files with the root recorded as a folder left out, which the record's
/// reader rejects. Nothing is written and the record stays as it was.
#[test]
fn bug_1574_a_checkout_of_a_refused_root_fails_and_records_no_root() {
    let Clone { repo, feature, .. } = clone_refusing(true);
    let to = repo.snapshot(&feature).unwrap().tree;
    let fs = MemoryBackend::new();
    let mut record = veil_core::checkout::Materialised::default();
    let err = repo.checkout_tree_recorded(&fs, None, &to, &mut record, None).unwrap_err();
    assert!(veil_core::tree::is_view_error(&err), "{err}");
    assert!(record.is_empty(), "{record:?}");
    let back: veil_core::checkout::Materialised = serde_json::from_str(&serde_json::to_string(&record).unwrap()).expect("the record reads back");
    assert_eq!(back, record);
    assert!(veil_core::StorageBackend::list_dir(&fs, &veil_core::VPath::root()).unwrap().is_empty(), "nothing was written");
}

/// A folder the server refuses, left out by a checkout, is carried by the
/// next build and reported as carried (what `vl status` lists as "you no
/// longer have access to this folder"), with or without files of the
/// person's own in it: only what a one-directory clone left out is carried
/// silently (BUG-1945's fix took every hidden folder for one).
#[test]
fn a_refused_folder_left_out_is_reported_as_carried() {
    let Clone { repo, feature, feature_bill, .. } = clone_with_a_refused_folder();
    let tree = repo.snapshot(&feature).unwrap().tree;
    let fs = MemoryBackend::new();
    let mut record = veil_core::checkout::Materialised::default();
    let r = veil_core::checkout::checkout_recorded(repo.store(), &fs, None, &tree, &mut record, None).expect("the checkout");
    assert!(r.redacted.contains(&p(BILL)), "{r:?}");
    assert!(record.hidden(&p(BILL)) && !record.left_out(&p(BILL)));
    let (built, report) = repo.build_from_recorded(&fs, Some(tree), None, Some(&record)).unwrap();
    assert_eq!(built, tree);
    assert_eq!(report.carried, vec![p(BILL)], "the refused folder is not reported");
    veil_core::StorageBackend::write(&fs, &p(&format!("{BILL}/mine.txt")), b"mine\n").unwrap();
    let (built, report) = repo.build_from_recorded(&fs, Some(tree), None, Some(&record)).unwrap();
    assert_eq!(built, tree);
    assert_eq!(lookup(repo.store(), &built, &p(BILL)).unwrap(), Some(feature_bill));
    assert_eq!(report.carried, vec![p(BILL)], "the refused folder is not reported");
    assert_eq!(report.not_recorded, vec![p(&format!("{BILL}/mine.txt"))]);
}
