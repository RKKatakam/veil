//! First-class conflicts (repository format 4): conflicts are tree entries
//! naming a conflict object, rendered as markers only when checkout writes
//! them, parsed back when a copy is partly edited, carried and simplified
//! by rebases, resolved by editing or `resolve_conflicts`, and never a way
//! for a sealed version to reach a reader outside its audience.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    conflict::{materialize_entry, Audience, Pick},
    object::Visibility,
    remote, EntryKind, Identity, MemoryBackend, ObjectId, Repo, StorageBackend, TreeEntry,
};

fn team() -> Visibility {
    Visibility::Cloaked { scope: "team".into() }
}

fn wc_tree(repo: &Repo) -> ObjectId {
    repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree
}

/// Check the working copy out from `from` to the workspace's tree.
fn sync(repo: &Repo, fs: &dyn StorageBackend, from: ObjectId) {
    repo.checkout_tree(fs, Some(&from), &wc_tree(repo)).unwrap();
}

fn entry(repo: &Repo, path: &str) -> TreeEntry {
    let wc = repo.workspace_wc(WS).unwrap();
    file_entry(repo, &wc, path).unwrap_or_else(|| panic!("{path} missing"))
}

fn conflicts(repo: &Repo) -> Vec<String> {
    repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().conflicts.clone()
}

/// `f.txt` = `a b c` at `base`; `ours` and `theirs` edit line 2 (`theirs`
/// sealed for `team` if `theirs_sealed`); merged with `vl merge`, the
/// working copy checked out on top of the merge.
struct World {
    repo: Repo,
    fs: Arc<MemoryBackend>,
    base: ObjectId,
    ours: ObjectId,
    theirs: ObjectId,
}

fn world(theirs_sealed: bool) -> World {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f.txt", "a\nb\nc\n"), ("other.txt", "x\n")], "base");
    let ours = commit_files(&mut repo, &*fs, &[("f.txt", "a\nOURS\nc\n")], "ours");
    let theirs = if theirs_sealed {
        // A version sealed for `team` (as a secret file's is), stored as is.
        let store = repo.store();
        let mut root = (*store.tree(&repo.snapshot(&base).unwrap().tree).unwrap()).clone();
        let mut e = root.get("f.txt").unwrap().clone();
        e.id = store.store_file(b"a\nTHEIRS\nc\n", &team()).unwrap();
        e.size = "a\nTHEIRS\nc\n".len() as u64;
        e.visibility = team();
        root.insert(e);
        raw_snapshot(&repo, vec![base], store.put_tree(&root).unwrap(), "theirs")
    } else {
        repo.create_workspace("t", vec![base]).unwrap();
        let o = repo.workspace_overlay("t").unwrap();
        o.write(&p("f.txt"), b"a\nTHEIRS\nc\n").unwrap();
        repo.snapshot_workspace("t", &o).unwrap().snapshot
    };
    World { repo, fs, base, ours, theirs }
}

impl World {
    fn merge(&mut self) -> ObjectId {
        let before = wc_tree(&self.repo);
        let m = self.repo.merge(WS, self.ours, vec![self.theirs], "merge", None).unwrap();
        assert_eq!(m.conflicts, vec!["f.txt".to_string()]);
        sync(&self.repo, &*self.fs, before);
        m.snapshot
    }

    fn disk(&self, path: &str) -> String {
        String::from_utf8(self.fs.read(&p(path)).unwrap()).unwrap()
    }

    fn snap(&mut self) -> veil_core::builder::BuildReport {
        self.repo.snapshot_workspace(WS, &*self.fs).unwrap().report
    }
}

#[test]
fn a_merge_records_a_conflict_entry_rendered_only_on_checkout() {
    let mut w = world(false);
    let m = w.merge();
    let e = file_entry(&w.repo, &m, "f.txt").unwrap();
    assert_eq!(e.kind, EntryKind::Conflict);
    assert!(e.visibility.is_public() && !e.executable && e.size == 0);
    let c = w.repo.store().conflict(&e.id).unwrap();
    assert_eq!((c.adds.len(), c.removes.len()), (2, 1));
    // No blob in the store holds the markers: they exist only on disk.
    for id in w.repo.store().list_objects().unwrap() {
        if let Ok(b) = w.repo.store().read_blob(&id) {
            assert!(!String::from_utf8_lossy(&b).contains("<<<<<<<"), "a marker file was stored");
        }
    }
    let text = w.disk("f.txt");
    assert_eq!(text, "a\n<<<<<<< ours\nOURS\n||||||| original\nb\n=======\nTHEIRS\n>>>>>>> theirs\nc\n");
    // The merge and the change on top both list it; an unchanged copy keeps it.
    assert_eq!(w.repo.snapshot(&m).unwrap().conflicts, vec!["f.txt"]);
    w.snap();
    assert_eq!(conflicts(&w.repo), vec!["f.txt"]);
    assert_eq!(entry(&w.repo, "f.txt").kind, EntryKind::Conflict);
}

#[test]
fn removing_the_markers_resolves_the_conflict() {
    let mut w = world(false);
    w.merge();
    w.fs.write(&p("f.txt"), b"a\nBOTH\nc\n").unwrap();
    w.snap();
    let e = entry(&w.repo, "f.txt");
    assert_eq!(e.kind, EntryKind::File);
    assert_eq!(read_at(&w.repo, &w.repo.workspace_wc(WS).unwrap(), "f.txt"), b"a\nBOTH\nc\n");
    assert!(conflicts(&w.repo).is_empty());
}

#[test]
fn deleting_the_file_resolves_the_conflict_as_a_deletion() {
    let mut w = world(false);
    w.merge();
    w.fs.remove_file(&p("f.txt")).unwrap();
    w.snap();
    assert!(file_entry(&w.repo, &w.repo.workspace_wc(WS).unwrap(), "f.txt").is_none());
    assert!(conflicts(&w.repo).is_empty());
}

/// jj's rule: text outside the markers belongs to every side, so a partly
/// edited copy stays a conflict whose sides carry the edit.
#[test]
fn a_partly_edited_copy_stays_a_conflict_with_its_sides_parsed_back() {
    let mut w = world(false);
    w.merge();
    let text = w.disk("f.txt").replace("a\n", "A-EDITED\n").replace("THEIRS\n", "THEIRS-2\n");
    w.fs.write(&p("f.txt"), text.as_bytes()).unwrap();
    w.snap();
    let e = entry(&w.repo, "f.txt");
    assert_eq!(e.kind, EntryKind::Conflict, "markers left: still a conflict");
    assert_eq!(conflicts(&w.repo), vec!["f.txt"]);
    let c = w.repo.store().conflict(&e.id).unwrap();
    let read = |t: &Option<veil_core::ConflictTerm>| String::from_utf8(w.repo.store().read_blob(&t.as_ref().unwrap().id).unwrap()).unwrap();
    assert_eq!(read(&c.adds[0]), "A-EDITED\nOURS\nc\n");
    assert_eq!(read(&c.adds[1]), "A-EDITED\nTHEIRS-2\nc\n");
    assert_eq!(read(&c.removes[0]), "A-EDITED\nb\nc\n");
    // Stable: snapshotting the same copy again records nothing new.
    let id = w.repo.workspace_wc(WS).unwrap();
    w.snap();
    assert_eq!(w.repo.workspace_wc(WS).unwrap(), id);
    // Keeping a side picks the edited version.
    w.repo.resolve_conflicts(WS, &[p("f.txt")], Pick::Theirs).unwrap();
    assert_eq!(read_at(&w.repo, &w.repo.workspace_wc(WS).unwrap(), "f.txt"), b"A-EDITED\nTHEIRS-2\nc\n");
}

#[test]
fn a_copy_whose_markers_no_longer_parse_is_taken_as_it_is() {
    let mut w = world(false);
    w.merge();
    let text = w.disk("f.txt").replace("=======\n", "");
    w.fs.write(&p("f.txt"), text.as_bytes()).unwrap();
    w.snap();
    let e = entry(&w.repo, "f.txt");
    assert_eq!(e.kind, EntryKind::File);
    assert_eq!(w.repo.store().read_entry(&e).unwrap(), text.as_bytes());
}

#[test]
fn rebasing_onto_a_resolution_resolves_and_otherwise_carries_the_conflict() {
    let mut w = world(false);
    // `theirs` rebased onto `ours`: the conflict is carried into the
    // rebased change instead of stopping the rebase.
    let moved = w.repo.rebase(w.theirs, vec![w.ours]).unwrap();
    let s = w.repo.snapshot(&moved).unwrap();
    let e = file_entry(&w.repo, &moved, "f.txt").unwrap();
    assert_eq!(e.kind, EntryKind::Conflict);
    assert_eq!(s.conflicts, vec!["f.txt"]);
    // Rebased back onto `base`: the conflict simplifies away, and the
    // change is `theirs` again.
    let back = w.repo.rebase(moved, vec![w.base]).unwrap();
    let e = file_entry(&w.repo, &back, "f.txt").unwrap();
    assert_eq!(e.kind, EntryKind::File);
    assert_eq!(read_at(&w.repo, &back, "f.txt"), b"a\nTHEIRS\nc\n");
    assert!(w.repo.snapshot(&back).unwrap().conflicts.is_empty());
    // Onto a change of `ours` that already made `theirs`' edit: resolved
    // by the new parent (both sides made the same change).
    let moved = w.repo.rebase(back, vec![w.ours]).unwrap();
    w.repo.create_workspace("fix", vec![w.ours]).unwrap();
    let o = w.repo.workspace_overlay("fix").unwrap();
    o.write(&p("f.txt"), b"a\nTHEIRS\nc\n").unwrap();
    let fixed = w.repo.snapshot_workspace("fix", &o).unwrap().snapshot;
    let done = w.repo.rebase(moved, vec![fixed]).unwrap();
    let e = file_entry(&w.repo, &done, "f.txt").unwrap();
    assert_eq!(e.kind, EntryKind::File, "resolved by the new parent");
    assert_eq!(read_at(&w.repo, &done, "f.txt"), b"a\nTHEIRS\nc\n");
    assert!(w.repo.snapshot(&done).unwrap().conflicts.is_empty());
    // A change on top of a conflicted merge that does not touch the file
    // takes whatever its new parent has there.
    w.merge();
    w.fs.write(&p("other.txt"), b"y\n").unwrap();
    w.snap();
    let child = w.repo.commit_working_copy(WS, "child").unwrap().0;
    let moved = w.repo.rebase(child, vec![w.theirs]).unwrap();
    assert_eq!(read_at(&w.repo, &moved, "f.txt"), b"a\nTHEIRS\nc\n");
    assert_eq!(read_at(&w.repo, &moved, "other.txt"), b"y\n");
}

#[test]
fn auto_rebase_carries_conflicts_into_descendants() {
    let mut w = world(false);
    let m = w.merge();
    w.fs.write(&p("other.txt"), b"z\n").unwrap();
    w.snap();
    let child = w.repo.commit_working_copy(WS, "child").unwrap().0;
    // Rewriting the merge's first parent rebases the merge and its child.
    w.repo.describe(w.ours, "ours, reworded").unwrap();
    let new_child = w.repo.snapshot(&w.repo.workspace_wc(WS).unwrap()).unwrap().parents[0];
    assert_ne!(new_child, child);
    let s = w.repo.snapshot(&new_child).unwrap();
    assert_eq!(s.conflicts, vec!["f.txt"]);
    assert_eq!(file_entry(&w.repo, &new_child, "f.txt").unwrap().kind, EntryKind::Conflict);
    let _ = m;
}

#[test]
fn resolve_keeps_a_version_exactly_as_recorded() {
    for (pick, want) in [(Pick::Ours, "a\nOURS\nc\n"), (Pick::Theirs, "a\nTHEIRS\nc\n"), (Pick::Base, "a\nb\nc\n")] {
        let mut w = world(true);
        w.merge();
        let c = w.repo.store().conflict(&entry(&w.repo, "f.txt").id).unwrap();
        let chosen = pick.term(&c).unwrap().unwrap();
        let before = wc_tree(&w.repo);
        let done = w.repo.resolve_conflicts(WS, &[p("f.txt")], pick).unwrap();
        assert_eq!(done, vec![p("f.txt")]);
        sync(&w.repo, &*w.fs, before);
        let e = entry(&w.repo, "f.txt");
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!((e.id, &e.visibility), (chosen.id, &chosen.visibility), "{pick:?}: the version as recorded");
        assert_eq!(w.disk("f.txt"), want);
        assert!(conflicts(&w.repo).is_empty());
        // Theirs was sealed for `team`: kept so.
        if pick == Pick::Theirs {
            assert_eq!(e.visibility, team());
        }
        // Undo brings the conflict back.
        w.repo.undo().unwrap();
        assert_eq!(entry(&w.repo, "f.txt").kind, EntryKind::Conflict);
    }
}

#[test]
fn resolve_refuses_what_is_not_a_conflict() {
    let mut w = world(false);
    w.merge();
    assert!(w.repo.resolve_conflicts(WS, &[p("other.txt")], Pick::Ours).is_err());
    assert!(w.repo.resolve_conflicts(WS, &[p("f.txt")], Pick::Side(3)).is_err());
}

/// A public side and a side sealed for `team`: the materialised file is
/// sealed for `team` (never wider than a side it shows) for members; for a
/// reader outside `team` the sealed side is a redaction line, the reader
/// cannot resolve it (edit held back, deletion carried), and once granted
/// the copy is rewritten in full.
#[test]
fn a_sealed_side_is_redacted_for_outsiders_who_cannot_resolve_it() {
    let mut w = world(true);
    let m = w.merge();
    w.repo.set_tag("main", m, true).unwrap();
    let e = file_entry(&w.repo, &m, "f.txt").unwrap();
    let mine = materialize_entry(w.repo.store(), &e, Audience::Reader).unwrap();
    assert_eq!(mine.visibility, team());
    assert!(String::from_utf8_lossy(&mine.content).contains("THEIRS"));
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut w.repo, hub.clone(), false, &[], false).unwrap();

    let bob = Identity::generate("bob");
    let (mut b, bfs) = (Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(bob.clone()), "bob").unwrap(), Arc::new(MemoryBackend::new()));
    remote::pull(&mut b, "origin", hub.clone()).unwrap();
    let root = wc_tree(&b);
    b.new_change(WS, vec![m], "").unwrap();
    sync(&b, &*bfs, root);
    let shown = String::from_utf8(bfs.read(&p("f.txt")).unwrap()).unwrap();
    assert!(shown.contains("OURS") && !shown.contains("THEIRS"), "{shown}");
    assert!(shown.contains("not shown"), "{shown}");
    // An unchanged copy is not an edit.
    let r = b.snapshot_workspace(WS, &*bfs).unwrap();
    assert!(!r.changed);
    // An edit cannot resolve it: held back, the conflict kept.
    bfs.write(&p("f.txt"), b"a\nBOB\nc\n").unwrap();
    let r = b.snapshot_workspace(WS, &*bfs).unwrap();
    assert!(r.report.cloak_failures.iter().any(|(q, _)| q.as_str() == "f.txt"), "{:?}", r.report.cloak_failures);
    assert_eq!(entry(&b, "f.txt").kind, EntryKind::Conflict);
    // Nor can a deletion.
    bfs.remove_file(&p("f.txt")).unwrap();
    b.snapshot_workspace(WS, &*bfs).unwrap();
    assert_eq!(entry(&b, "f.txt").kind, EntryKind::Conflict);
}

/// A copy written while a side was unreadable is recorded as such; after a
/// grant it is rewritten in full (`Materialised::fill_in`) and was never
/// taken for an edit.
#[test]
fn a_redacted_copy_is_filled_in_once_the_reader_is_granted() {
    let mut w = world(true);
    let m = w.merge();
    w.repo.set_tag("main", m, true).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut w.repo, hub.clone(), false, &[], false).unwrap();
    let bob = Identity::generate("bob");
    let mut b = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(bob.clone()), "bob").unwrap();
    let bfs = Arc::new(MemoryBackend::new());
    remote::pull(&mut b, "origin", hub.clone()).unwrap();
    let root = wc_tree(&b);
    b.new_change(WS, vec![m], "").unwrap();
    let mut record = veil_core::checkout::Materialised::default();
    b.checkout_tree_recorded(&*bfs, Some(&root), &wc_tree(&b), &mut record, None).unwrap();
    assert!(!String::from_utf8_lossy(&bfs.read(&p("f.txt")).unwrap()).contains("THEIRS"));
    // Alice grants Bob; he pulls the ring.
    w.repo.keys().grant("team", &bob.public_id(), "bob").unwrap();
    remote::push(&mut w.repo, hub.clone(), false, &[], false).unwrap();
    remote::pull(&mut b, "origin", hub.clone()).unwrap();
    // The stale copy is not an edit…
    let out = b
        .snapshot_workspace_with(WS, &*bfs, veil_core::workspace::SnapshotOptions { materialised: Some(&record), ..Default::default() })
        .unwrap();
    assert!(!out.changed);
    // …and is rewritten in full.
    record.fill_in(b.store(), &*bfs, &wc_tree(&b), None).unwrap();
    let shown = String::from_utf8(bfs.read(&p("f.txt")).unwrap()).unwrap();
    assert!(shown.contains("THEIRS") && shown.contains("<<<<<<<"), "{shown}");
}

/// A public remote keeps the conflict entry and its public versions, never
/// a sealed one; nothing on it holds the sealed side's plaintext, and a
/// public clone shows the side as redacted.
#[test]
fn a_public_push_withholds_sealed_sides_of_a_conflict() {
    let mut w = world(true);
    let m = w.merge();
    w.repo.set_tag("main", m, true).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    let rep = remote::push(&mut w.repo, mirror.clone(), true, &["main".into()], false).unwrap();
    assert!(rep.redacted >= 1, "{rep:?}");
    assert!(backend_contains(&*mirror, b"THEIRS").is_empty(), "the sealed side reached the public mirror");
    let anon = Repo::open(mirror.clone(), Some(Identity::generate("anon")), "anon").unwrap();
    let e = file_entry(&anon, &m, "f.txt").unwrap();
    assert_eq!(e.kind, EntryKind::Conflict);
    let c = anon.store().conflict(&e.id).unwrap();
    assert!(anon.store().has(&c.adds[0].as_ref().unwrap().id), "the public side is there");
    assert!(!anon.store().has(&c.adds[1].as_ref().unwrap().id), "the sealed side is withheld");
    let shown = materialize_entry(anon.store(), &e, Audience::Reader).unwrap();
    let text = String::from_utf8_lossy(&shown.content);
    assert!(shown.unreadable_side && text.contains("OURS") && !text.contains("THEIRS"), "{text}");
    veil_core::fsck::fsck(mirror, None).unwrap();
}

/// Two conflicts of the same file merged: one conflict of three sides,
/// rendered as whole blocks, resolved by `--side`.
#[test]
fn merging_conflicts_gives_a_many_sided_conflict() {
    let mut w = world(false);
    let m1 = w.merge();
    // A second, different conflict of f.txt from `ours`.
    w.repo.create_workspace("u", vec![w.base]).unwrap();
    let o = w.repo.workspace_overlay("u").unwrap();
    o.write(&p("f.txt"), b"a\nUUU\nc\n").unwrap();
    let u = w.repo.snapshot_workspace("u", &o).unwrap().snapshot;
    let before = wc_tree(&w.repo);
    let m2 = w.repo.merge(WS, w.ours, vec![u], "merge u", None).unwrap().snapshot;
    let both = w.repo.merge(WS, m1, vec![m2], "merge both", None).unwrap();
    sync(&w.repo, &*w.fs, before);
    let e = file_entry(&w.repo, &both.snapshot, "f.txt").unwrap();
    let c = w.repo.store().conflict(&e.id).unwrap();
    assert_eq!(c.adds.len(), 3, "{c:?}");
    let text = w.disk("f.txt");
    assert!(text.contains("side 1 of 3") && text.contains("UUU") && text.contains("THEIRS"), "{text}");
    w.snap();
    w.repo.resolve_conflicts(WS, &[p("f.txt")], Pick::Side(3)).unwrap();
    assert!(w.repo.resolve_conflicts(WS, &[p("f.txt")], Pick::Theirs).is_err(), "already resolved");
}

/// A modify/delete conflict shows the modified side (no markers, as
/// before); keeping it unchanged keeps the conflict.
#[test]
fn a_modify_delete_conflict_shows_the_modified_side() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f.txt", "v1\n")], "base");
    let ours = commit_files(&mut repo, &*fs, &[("f.txt", "v2\n")], "ours");
    repo.create_workspace("d", vec![base]).unwrap();
    let o = repo.workspace_overlay("d").unwrap();
    o.remove_file(&p("f.txt")).unwrap();
    o.write(&p("g.txt"), b"g\n").unwrap();
    let theirs = repo.snapshot_workspace("d", &o).unwrap().snapshot;
    let before = wc_tree(&repo);
    repo.merge(WS, ours, vec![theirs], "merge", None).unwrap();
    sync(&repo, &*fs, before);
    assert_eq!(fs.read(&p("f.txt")).unwrap(), b"v2\n");
    repo.snapshot_workspace(WS, &*fs).unwrap();
    assert_eq!(entry(&repo, "f.txt").kind, EntryKind::Conflict);
    let c = repo.store().conflict(&entry(&repo, "f.txt").id).unwrap();
    assert!(c.adds.iter().any(Option::is_none));
    repo.resolve_conflicts(WS, &[p("f.txt")], Pick::Theirs).unwrap();
    assert!(file_entry(&repo, &repo.workspace_wc(WS).unwrap(), "f.txt").is_none(), "theirs deleted it");
}

/// A hostile conflict object (no file on any side, labels claiming
/// `public` for sealed content) never panics, never fails a snapshot, and
/// never decides how new content is sealed.
#[test]
fn hostile_conflict_objects_never_fail_a_snapshot() {
    let mut w = world(true);
    w.merge();
    let store = w.repo.store().clone();
    let c = veil_core::Conflict { adds: vec![None, None], removes: vec![None] };
    let id = store.put_conflict(&c).unwrap();
    let mut root = (*store.tree(&wc_tree(&w.repo)).unwrap()).clone();
    root.insert(TreeEntry::conflict("empty.txt", id));
    let tree = store.put_tree(&root).unwrap();
    let wc = w.repo.workspace_wc(WS).unwrap();
    let s = raw_snapshot(&w.repo, vec![wc], tree, "hostile");
    let before = wc_tree(&w.repo);
    w.repo.edit(WS, s).unwrap();
    sync(&w.repo, &*w.fs, before);
    w.snap();
    w.fs.write(&p("empty.txt"), b"now something\n").unwrap();
    w.snap();
}
