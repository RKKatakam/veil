//! Checkout never deletes what it did not write (BUG-110, BUG-111), the
//! vault keeps the backup of an isolated file that vanished, and commands
//! whose effect lies outside the view are not "undone" by restoring an
//! older view (BUG-116).

use std::sync::Arc;

use veil_core::{
    checkout::checkout,
    vault::REMOVED_RETENTION_MS,
    DiskBackend, Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

fn mem_repo() -> Repo {
    Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("alice")), "alice").unwrap()
}

/// The tree a working copy holding `files` would record.
fn tree(repo: &Repo, files: &[(&str, &str)]) -> ObjectId {
    let fs = MemoryBackend::from_files(files.iter().map(|(p, c)| (*p, c.as_bytes()))).unwrap();
    repo.build_from(&fs, None, None).unwrap().0
}

fn wc(repo: &Repo, files: &[(&str, &str)]) -> MemoryBackend {
    let fs = MemoryBackend::new();
    checkout(repo.store(), &fs, None, &tree(repo, files)).unwrap();
    fs
}

#[test]
fn a_directory_holding_unrecorded_files_is_never_removed_to_place_a_file() {
    let repo = mem_repo();
    let fs = wc(&repo, &[(".veilpolicy", "private/ isolate\n"), ("a.txt", "a\n")]);
    fs.write(&p("private/notes.md"), b"my notes\n").unwrap();
    let from = tree(&repo, &[(".veilpolicy", "private/ isolate\n"), ("a.txt", "a\n")]);
    let to = tree(&repo, &[(".veilpolicy", "private/ isolate\n"), ("a.txt", "a\n"), ("private", "a file\n")]);
    let r = checkout(repo.store(), &fs, Some(&from), &to).unwrap();
    assert_eq!(fs.read(&p("private/notes.md")).unwrap(), b"my notes\n");
    assert_eq!(r.obstructed, vec![(p("private"), p("private"))]);
    assert_eq!(r.written, 0);
}

#[test]
fn a_tracked_directory_is_replaced_by_a_file_once_emptied_and_the_rest_is_kept() {
    let repo = mem_repo();
    let from = tree(&repo, &[("d/x.txt", "x\n")]);
    let to = tree(&repo, &[("d", "now a file\n")]);
    // Only what checkout put there: the directory goes, the file is written.
    let fs = wc(&repo, &[("d/x.txt", "x\n")]);
    let r = checkout(repo.store(), &fs, Some(&from), &to).unwrap();
    assert_eq!(fs.read(&p("d")).unwrap(), b"now a file\n");
    assert!(r.obstructed.is_empty());
    // With an untracked file next to it: the tracked file goes, the rest stays.
    let fs = wc(&repo, &[("d/x.txt", "x\n")]);
    fs.write(&p("d/mine.txt"), b"mine\n").unwrap();
    let r = checkout(repo.store(), &fs, Some(&from), &to).unwrap();
    assert_eq!(fs.read(&p("d/mine.txt")).unwrap(), b"mine\n");
    assert!(fs.metadata(&p("d/x.txt")).unwrap().is_none());
    assert_eq!(r.obstructed, vec![(p("d"), p("d"))]);
}

#[test]
fn a_file_in_the_way_of_a_directory_is_kept_and_reported() {
    let repo = mem_repo();
    let from = tree(&repo, &[("a.txt", "a\n")]);
    let to = tree(&repo, &[("a.txt", "a\n"), ("cfg/settings.json", "{}\n"), ("cfg/sub/more.json", "[]\n"), ("b.txt", "b\n")]);
    let fs = wc(&repo, &[("a.txt", "a\n")]);
    fs.write(&p("cfg"), b"untracked\n").unwrap();
    let r = checkout(repo.store(), &fs, Some(&from), &to).unwrap();
    assert_eq!(fs.read(&p("cfg")).unwrap(), b"untracked\n");
    assert_eq!(fs.read(&p("b.txt")).unwrap(), b"b\n", "the rest of the checkout went ahead");
    let mut obstructed = r.obstructed.clone();
    obstructed.sort();
    assert_eq!(
        obstructed,
        vec![(p("cfg/settings.json"), p("cfg")), (p("cfg/sub/more.json"), p("cfg"))]
    );
    // Running it again (an interrupted move resumed) changes nothing more.
    let again = checkout(repo.store(), &fs, Some(&from), &to).unwrap();
    assert_eq!(again.obstructed.len(), 2);
    assert_eq!(fs.read(&p("cfg")).unwrap(), b"untracked\n");
}

#[cfg(unix)]
#[test]
fn a_directory_left_holding_only_a_symlink_is_not_pruned() {
    let repo = mem_repo();
    let dir = tempfile::tempdir().unwrap();
    let fs = DiskBackend::new(dir.path());
    let from = tree(&repo, &[("d/x.txt", "x\n"), ("a.txt", "a\n")]);
    checkout(repo.store(), &fs, None, &from).unwrap();
    std::os::unix::fs::symlink("/somewhere/else", dir.path().join("d/link")).unwrap();
    let to = tree(&repo, &[("a.txt", "a\n")]);
    checkout(repo.store(), &fs, Some(&from), &to).unwrap();
    assert!(dir.path().join("d/link").symlink_metadata().is_ok(), "the untracked symlink was deleted");
    assert!(!dir.path().join("d/x.txt").exists());
}

#[test]
fn the_vault_keeps_the_backup_of_an_isolated_file_that_vanished() {
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    fs.write(&p(".env"), b"TOKEN=abc\n").unwrap();
    let out = repo.snapshot_workspace("default", &*fs).unwrap();
    repo.capture_local_files(&*fs, &out.report).unwrap();
    assert!(repo.vault_load().unwrap().files.contains_key(".env"));
    fs.remove_file(&p(".env")).unwrap();
    let out = repo.snapshot_workspace("default", &*fs).unwrap();
    repo.capture_local_files(&*fs, &out.report).unwrap();
    let vault = repo.vault_load().unwrap();
    assert!(!vault.files.contains_key(".env"), "a vanished file is not injected into sandboxes");
    let kept = vault.removed.get(".env").expect("the backup is kept");
    assert!(kept.removed_at > veil_core::now_millis() - REMOVED_RETENTION_MS);
    // Further snapshots keep it (the clock did not run out).
    let out = repo.snapshot_workspace("default", &*fs).unwrap();
    repo.capture_local_files(&*fs, &out.report).unwrap();
    assert!(repo.vault_load().unwrap().removed.contains_key(".env"));
    // Recovered on request, never over an existing file.
    assert!(repo.vault_recover_file(&*fs, &p(".env")).unwrap());
    assert_eq!(fs.read(&p(".env")).unwrap(), b"TOKEN=abc\n");
    assert!(repo.vault_recover_file(&*fs, &p(".env")).is_err());
    assert!(!repo.vault_recover_file(&*fs, &p("nothing.txt")).unwrap());
    // Back in the working copy: a live backup again.
    let out = repo.snapshot_workspace("default", &*fs).unwrap();
    repo.capture_local_files(&*fs, &out.report).unwrap();
    let vault = repo.vault_load().unwrap();
    assert!(vault.files.contains_key(".env") && vault.removed.is_empty());
}

#[test]
fn undo_refuses_a_command_whose_effect_is_outside_the_view() {
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    fs.write(&p("a.txt"), b"a\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (c, _) = repo.commit_working_copy("default", "one").unwrap();
    repo.set_tag("main", c, None, false).unwrap();
    let before = repo.op_id();
    repo.record_outside_view("grant scope team to bob", "revoke it with `vl scope revoke`").unwrap();
    let err = repo.undo_keeping_edits("default").unwrap_err().to_string();
    assert!(err.contains("grant scope team to bob") && err.contains("vl scope revoke"), "{err}");
    assert!(repo.view().tags.contains_key("main"), "an unrelated operation was undone");
    let since = repo.manual_undo_since(before).unwrap();
    assert_eq!(since.len(), 1);
    assert_eq!(since[0].description, "grant scope team to bob");
    // Automatic snapshots after it do not hide it.
    fs.write(&p("b.txt"), b"b\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    assert!(repo.undo_keeping_edits("default").is_err());
}

/// BUG-202: no file name can wedge a working copy. A tree from a remote
/// may hold a name this filesystem cannot (here 300 bytes, beyond every
/// common filesystem's 255-byte limit). Checkout writes everything else,
/// reports that one path, records it as left out, and the next snapshot
/// keeps it in history instead of recording it deleted.
#[test]
fn a_name_the_filesystem_refuses_is_reported_and_the_checkout_goes_on() {
    let repo = mem_repo();
    let long = "n".repeat(300);
    let store = repo.store();
    let blob = |d: &[u8]| store.put(&veil_core::object::Object::Blob(d.to_vec())).unwrap();
    let entry = |name: &str, id| veil_core::TreeEntry {
        name: name.to_string(),
        kind: veil_core::object::EntryKind::File,
        id,
        size: 1,
        executable: false,
        visibility: veil_core::object::Visibility::Public,
        fallback: None,
    };
    let mut t = veil_core::object::Tree::default();
    t.insert(entry(&long, blob(b"long\n")));
    t.insert(entry("ok.txt", blob(b"ok\n")));
    let to = store.put_tree(&t).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let fs = DiskBackend::new(dir.path());
    let mut record = veil_core::checkout::Materialised::default();
    let report = veil_core::checkout::checkout_recorded(store, &fs, None, &to, &mut record, None).expect("checkout stopped");
    assert_eq!(fs.read(&p("ok.txt")).unwrap(), b"ok\n");
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert_eq!(report.failed[0].0.as_str(), long);
    assert!(record.hidden(&p(&long)));
    // No temp file is left behind either.
    let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(left, vec![std::ffi::OsString::from("ok.txt")]);
    // The next snapshot keeps the entry it could not write.
    let (built, _) = repo.build_from_recorded(&fs, Some(to), None, None, Some(&record)).unwrap();
    assert_eq!(built, to, "the unwritable file was recorded as deleted");
}

/// BUG-202: a name of 250 bytes (legal on ext4, APFS, btrfs, XFS) is
/// written: the temp file it goes through has a short name.
#[test]
fn a_name_near_the_filesystem_limit_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let fs = DiskBackend::new(dir.path());
    let name = "é".repeat(125); // 250 bytes, cut on a character boundary
    fs.write(&p(&name), b"x\n").unwrap();
    assert_eq!(fs.read(&p(&name)).unwrap(), b"x\n");
}
