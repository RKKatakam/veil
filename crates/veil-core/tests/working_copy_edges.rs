//! Working-copy edge cases: crash debris, unreadable files, names that are
//! not UTF-8, symlinks (never followed when snapshotting, never written
//! through on checkout), injected sandbox secrets, and undo / op restore
//! with uncommitted edits.

use std::sync::Arc;

use veil_core::{
    builder::{InjectedSecrets, INJECTED_RULE},
    object::Visibility,
    tree::lookup,
    vfs::is_temp_name,
    DiskBackend, Identity, MemoryBackend, ObjectId, Repo, StorageBackend, TreeEntry, VPath,
};

const WS: &str = "default";

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

fn mem_repo() -> Repo {
    Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("alice")), "alice").unwrap()
}

fn entry(repo: &Repo, tree: &ObjectId, path: &str) -> Option<TreeEntry> {
    lookup(repo.store(), tree, &p(path)).unwrap()
}

fn wc(repo: &Repo) -> ObjectId {
    repo.workspace_wc(WS).unwrap()
}

fn wc_tree(repo: &Repo) -> ObjectId {
    repo.snapshot(&wc(repo)).unwrap().tree
}

fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| o.stdout.starts_with(b"0\n"))
        .unwrap_or(false)
}

// ---- crash debris ---------------------------------------------------------

#[test]
fn temp_names_match_only_disk_backend_leftovers() {
    assert!(is_temp_name(".main.rs.vltmp1a2b3c4d"));
    assert!(is_temp_name(".x.vltmpABCDEF01"));
    for n in ["main.rs.vltmp1a2b3c4d", ".vltmp1a2b3c4d", ".x.vltmp1a2b3c4", ".x.vltmp1a2b3c4dd", ".x.vltmp1a2b3c4g", ".x.vltmp"] {
        assert!(!is_temp_name(n), "{n}");
    }
}

#[test]
fn interrupted_write_leftovers_are_never_snapshotted() {
    let mut repo = mem_repo();
    let fs = MemoryBackend::from_files([("src/main.rs", &b"fn main() {}\n"[..]), ("src/.main.rs.vltmp0badf00d", b"fn main() { half")]).unwrap();
    let out = repo.snapshot_workspace(WS, &fs).unwrap();
    assert!(entry(&repo, &wc_tree(&repo), "src/main.rs").is_some());
    assert!(entry(&repo, &wc_tree(&repo), "src/.main.rs.vltmp0badf00d").is_none());
    assert_eq!(out.report.ignored, 1);
}

// ---- unreadable files and directories -----------------------------------

#[cfg(unix)]
fn chmod(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
#[test]
fn unreadable_files_keep_their_tracked_version_and_never_fail_the_build() {
    if is_root() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let fs = Arc::new(DiskBackend::new(tmp.path()));
    let mut repo = Repo::init(fs.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    fs.write(&p("tracked.txt"), b"v1\n").unwrap();
    fs.write(&p("dir/inner.txt"), b"inner\n").unwrap();
    repo.snapshot_workspace(WS, &*fs).unwrap();
    let before = wc_tree(&repo);

    fs.write(&p("tracked.txt"), b"v2\n").unwrap();
    fs.write(&p("new.bin"), b"x").unwrap();
    chmod(&tmp.path().join("tracked.txt"), 0o000);
    chmod(&tmp.path().join("new.bin"), 0o000);
    chmod(&tmp.path().join("dir"), 0o000);
    let out = repo.snapshot_workspace(WS, &*fs);
    chmod(&tmp.path().join("tracked.txt"), 0o644);
    chmod(&tmp.path().join("new.bin"), 0o644);
    chmod(&tmp.path().join("dir"), 0o755);
    let out = out.expect("an unreadable file must not fail the snapshot");

    let unreadable: Vec<&str> = out.report.unreadable.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(unreadable, vec!["dir", "new.bin", "tracked.txt"]);
    let now = wc_tree(&repo);
    assert_eq!(entry(&repo, &now, "tracked.txt"), entry(&repo, &before, "tracked.txt"), "previous version kept, not deleted");
    assert_eq!(entry(&repo, &now, "dir/inner.txt"), entry(&repo, &before, "dir/inner.txt"), "unreadable directory kept");
    assert!(entry(&repo, &now, "new.bin").is_none());
    assert!(out.report.local_only().is_empty(), "unreadable files are not vault candidates");

    // readable again: the edit is picked up
    repo.snapshot_workspace(WS, &*fs).unwrap();
    let e = entry(&repo, &wc_tree(&repo), "tracked.txt").unwrap();
    assert_eq!(repo.store().read_entry(&e).unwrap(), b"v2\n");
}

// ---- names that are not UTF-8 -------------------------------------------

#[cfg(unix)]
#[test]
fn non_utf8_names_are_reported_not_silently_dropped() {
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(std::ffi::OsStr::from_bytes(b"report-\xff\xfe.csv")), "data").unwrap();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    std::fs::write(tmp.path().join("sub").join(std::ffi::OsStr::from_bytes(b"\x1b[31m\xc3")), "x").unwrap();
    std::fs::write(tmp.path().join("ok.txt"), "ok").unwrap();
    let fs = DiskBackend::new(tmp.path());
    let listing = fs.list_dir_full(&VPath::root()).unwrap();
    assert_eq!(listing.unrepresentable, vec!["report-\\xff\\xfe.csv".to_string()]);
    let mut repo = mem_repo();
    let out = repo.snapshot_workspace(WS, &fs).unwrap();
    assert_eq!(
        out.report.unrepresentable,
        vec!["report-\\xff\\xfe.csv".to_string(), "sub/\\u{1b}[31m\\xc3".to_string()],
        "reported with their directory, control characters escaped"
    );
    assert!(entry(&repo, &wc_tree(&repo), "ok.txt").is_some());
}

// ---- symlinks --------------------------------------------------------------

#[cfg(unix)]
#[test]
fn disk_backend_never_reads_through_a_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret"), "outside").unwrap();
    std::os::unix::fs::symlink(outside.path().join("secret"), tmp.path().join("link")).unwrap();
    let fs = DiskBackend::new(tmp.path());
    assert_eq!(fs.metadata(&p("link")).unwrap(), None);
    assert!(fs.read(&p("link")).unwrap_err().is_not_found());
    assert_eq!(fs.read_opt(&p("link")).unwrap(), None);
    assert_eq!(fs.list_dir_full(&VPath::root()).unwrap().special, vec!["link".to_string()]);
}

/// `write` (and `write_unsynced`, `create_new`) refuse a path below a
/// symlinked directory, whoever calls them; `.veil/` is the engine's own.
#[cfg(unix)]
#[test]
fn disk_backend_never_writes_through_a_symlinked_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("real")).unwrap();
    std::os::unix::fs::symlink(outside.path(), tmp.path().join("real/vendor")).unwrap();
    let fs = DiskBackend::new(tmp.path());
    for path in ["real/vendor/x", "real/vendor/deep/x"] {
        let e = fs.write(&p(path), b"pulled").unwrap_err();
        assert!(e.to_string().contains("symbolic link"), "{e}");
        assert!(fs.write_unsynced(&p(path), b"pulled").is_err());
        assert!(fs.create_new(&p(path), b"pulled").is_err());
    }
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0, "nothing was written outside");
    fs.write(&p("real/ok/x"), b"fine").unwrap();
    assert_eq!(std::fs::read(tmp.path().join("real/ok/x")).unwrap(), b"fine");
    // The engine's own directory may be a symlink (e.g. to another disk).
    let store = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(store.path(), tmp.path().join(".veil")).unwrap();
    fs.write(&p(".veil/local/state"), b"s").unwrap();
    assert_eq!(std::fs::read(store.path().join("local/state")).unwrap(), b"s");
}

#[cfg(unix)]
#[test]
fn a_tracked_path_replaced_by_a_symlink_keeps_its_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("x"), "outside").unwrap();
    let fs = DiskBackend::new(tmp.path());
    fs.write(&p("vendor/x"), b"tracked").unwrap();
    fs.write(&p("notes.txt"), b"notes").unwrap();
    let mut repo = mem_repo();
    repo.snapshot_workspace(WS, &fs).unwrap();
    let before = wc_tree(&repo);
    std::fs::remove_dir_all(tmp.path().join("vendor")).unwrap();
    std::fs::remove_file(tmp.path().join("notes.txt")).unwrap();
    std::os::unix::fs::symlink(outside.path(), tmp.path().join("vendor")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("x"), tmp.path().join("notes.txt")).unwrap();
    let out = repo.snapshot_workspace(WS, &fs).unwrap();
    assert!(!out.changed, "neither a deletion nor content read through the links");
    assert_eq!(wc_tree(&repo), before);
    let shadowed: Vec<&str> = out.report.shadowed.iter().map(|p| p.as_str()).collect();
    assert_eq!(shadowed, vec!["notes.txt", "vendor"]);
}

#[cfg(unix)]
#[test]
fn checkout_never_writes_removes_or_replaces_through_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let shared = tempfile::tempdir().unwrap();
    let mut repo = mem_repo();
    // tree A: vendor/x, notes.txt, a.txt; tree B: vendor/y, notes.txt changed, no a.txt
    let src = MemoryBackend::from_files([("vendor/x", &b"x"[..]), ("notes.txt", b"n1"), ("keep/a.txt", b"a")]).unwrap();
    repo.snapshot_workspace(WS, &src).unwrap();
    let a = wc_tree(&repo);
    src.remove_file(&p("vendor/x")).unwrap();
    src.write(&p("vendor/y"), b"y").unwrap();
    src.write(&p("notes.txt"), b"n2").unwrap();
    src.remove_file(&p("keep/a.txt")).unwrap();
    repo.snapshot_workspace(WS, &src).unwrap();
    let b = wc_tree(&repo);

    // The user's working copy: `vendor` and `notes.txt` are links; vendor/x
    // and keep/a.txt exist *behind* links with exactly A's content.
    std::fs::write(shared.path().join("x"), "x").unwrap();
    std::fs::write(shared.path().join("notes-target"), "n1").unwrap();
    std::fs::create_dir(shared.path().join("keep")).unwrap();
    std::fs::write(shared.path().join("keep/a.txt"), "a").unwrap();
    std::os::unix::fs::symlink(shared.path(), tmp.path().join("vendor")).unwrap();
    std::os::unix::fs::symlink(shared.path().join("notes-target"), tmp.path().join("notes.txt")).unwrap();
    std::os::unix::fs::symlink(shared.path().join("keep"), tmp.path().join("keep")).unwrap();
    let fs = DiskBackend::new(tmp.path());

    let report = repo.checkout_tree(&fs, Some(&a), &b).unwrap();
    let mut blocked: Vec<&str> = report.blocked.iter().map(|p| p.as_str()).collect();
    blocked.sort();
    assert_eq!(blocked, vec!["keep/a.txt", "notes.txt", "vendor/x", "vendor/y"]);
    assert!(!shared.path().join("y").exists(), "wrote through the vendor link");
    assert!(shared.path().join("x").exists(), "removed through the vendor link");
    assert!(shared.path().join("keep/a.txt").exists(), "removed through the keep link");
    assert_eq!(std::fs::read_to_string(shared.path().join("notes-target")).unwrap(), "n1");
    assert!(std::fs::symlink_metadata(tmp.path().join("notes.txt")).unwrap().file_type().is_symlink(), "link replaced");
    assert!(std::fs::symlink_metadata(tmp.path().join("keep")).unwrap().file_type().is_symlink(), "link pruned");
}

// ---- injected sandbox secrets ----------------------------------------------

#[test]
fn injected_secrets_pick_secret_like_values_only() {
    let env = b"API_TOKEN=super-secret-isolated-value\nexport DB_URL=\"postgres://u:p4ss@db/x\"\nHOST=localhost\nPORT=3000\nMODE=production\n";
    let inj = InjectedSecrets::from_files([(".env", &env[..])]);
    let hit = |s: &str| inj.find(s.as_bytes()).is_some();
    assert!(hit("token: super-secret-isolated-value"));
    assert!(hit("url = postgres://u:p4ss@db/x"));
    assert!(hit(std::str::from_utf8(env).unwrap()), "a verbatim copy");
    assert!(hit("API_TOKEN=super-secret-isolated-value"));
    for benign in ["localhost", "connect to localhost:3000", "MODE=production", "fn main() {}"] {
        assert!(!hit(benign), "false positive on {benign:?}");
    }
    let f = inj.find(b"line one\nx super-secret-isolated-value").unwrap();
    assert_eq!((f.rule, f.line), (INJECTED_RULE, 2));
    assert!(!f.excerpt.contains("super-secret"), "the excerpt must not print the secret: {}", f.excerpt);
    assert!(InjectedSecrets::from_files([(".env", &b"A=1\n"[..])]).is_empty());

    // key material: a partial copy of the body is caught too
    let pem = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDx8bYVjJdg2nD0tqdq3s1fsvbLB5mU3Fh1TXHm0VYuGwAAAJgYZ2ENGGdh\n-----END OPENSSH PRIVATE KEY-----\n";
    let inj = InjectedSecrets::from_files([("id_ed25519", &pem[..])]);
    assert!(inj.find(b"x = 'QyNTUxOQAAACDx8bYVjJdg2nD0tqdq3s1fsvbLB5mU3Fh1TXHm0VYuGwAAAJgYZ2ENGGdh'").is_some());
    assert!(inj.find(b"see the -----END OPENSSH PRIVATE KEY----- marker docs").is_none(), "generic armor is not a secret");
}

#[test]
fn injected_secrets_are_quarantined_in_every_tier_but_old_content_is_kept() {
    let mut repo = mem_repo();
    let base = MemoryBackend::from_files([
        (".veilpolicy", &b"private/ cloak team\n"[..]),
        ("readme.md", b"uses API_TOKEN\n"),
        ("legacy.txt", b"already had super-secret-isolated-value before\n"),
    ])
    .unwrap();
    repo.snapshot_workspace(WS, &base).unwrap();
    let parent = wc_tree(&repo);
    let env = b"API_TOKEN=super-secret-isolated-value\n";
    let inj = InjectedSecrets::from_files([(".env", &env[..])]);

    let fs = base.fork();
    fs.write(&p(".env"), env).unwrap();
    fs.write(&p("config.txt"), env).unwrap();
    fs.write(&p("private/copy.txt"), b"tok super-secret-isolated-value").unwrap();
    fs.write(&p("readme.md"), b"uses API_TOKEN=super-secret-isolated-value\n").unwrap();
    fs.write(&p("clean.txt"), b"nothing to see\n").unwrap();
    let out = repo.snapshot_workspace_injected(WS, &fs, None, Some(&inj)).unwrap();
    let t = wc_tree(&repo);
    assert!(entry(&repo, &t, ".env").is_none(), "isolated by policy");
    assert!(entry(&repo, &t, "config.txt").is_none(), "a renamed copy");
    assert!(entry(&repo, &t, "private/copy.txt").is_none(), "cloaking is no way out either");
    assert_eq!(entry(&repo, &t, "readme.md"), entry(&repo, &parent, "readme.md"), "the edit is held back");
    assert_eq!(entry(&repo, &t, "legacy.txt"), entry(&repo, &parent, "legacy.txt"), "unchanged content predates the injection");
    assert_eq!(entry(&repo, &t, "clean.txt").unwrap().visibility, Visibility::Public);
    let mut q: Vec<&str> = out.report.quarantined.iter().map(|(p, _)| p.as_str()).collect();
    q.sort();
    assert_eq!(q, vec!["config.txt", "private/copy.txt", "readme.md"]);
    assert!(out.report.quarantined.iter().all(|(_, f)| f[0].rule == INJECTED_RULE));

    // Without injection the same content is recorded as before.
    let mut repo2 = mem_repo();
    repo2.snapshot_workspace(WS, &fs).unwrap();
    assert!(entry(&repo2, &wc_tree(&repo2), "config.txt").is_some());
}

// ---- undo and op restore keep uncommitted edits -----------------------------

/// Snapshot like the CLI does before every command.
fn auto_snapshot(repo: &mut Repo, fs: &MemoryBackend) {
    repo.snapshot_workspace(WS, fs).unwrap();
}

fn materialise(repo: &Repo, fs: &MemoryBackend, from: &ObjectId) {
    repo.checkout_tree(fs, Some(from), &wc_tree(repo)).unwrap();
}

#[test]
fn undo_reverts_the_last_command_and_keeps_edits() {
    let mut repo = mem_repo();
    let fs = MemoryBackend::from_files([("a.txt", &b"a1\n"[..]), ("b.txt", b"b1\n")]).unwrap();
    auto_snapshot(&mut repo, &fs);
    let (committed, _) = repo.commit_working_copy(WS, "first").unwrap();
    let _ = committed;
    // a command that changes files on disk: edit b.txt in a new change, then
    // go back to the first one with `new`
    fs.write(&p("b.txt"), b"b2\n").unwrap();
    auto_snapshot(&mut repo, &fs);
    let before_new = wc_tree(&repo);
    let first = repo.snapshot(&wc(&repo)).unwrap().parents[0];
    repo.new_change(WS, vec![first], "").unwrap();
    materialise(&repo, &fs, &before_new);
    assert_eq!(fs.read(&p("b.txt")).unwrap(), b"b1\n");

    // uncommitted edits, auto-snapshotted by two later commands
    fs.write(&p("new-work.txt"), b"an hour of work\n").unwrap();
    auto_snapshot(&mut repo, &fs);
    fs.write(&p("a.txt"), b"a1 edited\n").unwrap();
    auto_snapshot(&mut repo, &fs);
    let disk_tree = wc_tree(&repo);

    let (_, undone) = repo.undo_keeping_edits(WS).unwrap();
    assert!(undone.starts_with("new change") || !undone.starts_with("snapshot"), "undid {undone}");
    materialise(&repo, &fs, &disk_tree);
    assert_eq!(fs.read(&p("b.txt")).unwrap(), b"b2\n", "the undone command is reverted");
    assert_eq!(fs.read(&p("new-work.txt")).unwrap(), b"an hour of work\n", "edits survive");
    assert_eq!(fs.read(&p("a.txt")).unwrap(), b"a1 edited\n");
    let t = wc_tree(&repo);
    assert!(entry(&repo, &t, "new-work.txt").is_some(), "edits are part of the restored working copy");

    // and a second undo is a redo, still keeping them
    let disk_tree = wc_tree(&repo);
    repo.undo_keeping_edits(WS).unwrap();
    materialise(&repo, &fs, &disk_tree);
    assert_eq!(fs.read(&p("b.txt")).unwrap(), b"b1\n");
    assert_eq!(fs.read(&p("new-work.txt")).unwrap(), b"an hour of work\n");
}

#[test]
fn undo_without_edits_is_a_plain_undo() {
    let mut repo = mem_repo();
    let fs = MemoryBackend::from_files([("a.txt", &b"a\n"[..])]).unwrap();
    auto_snapshot(&mut repo, &fs);
    let id = wc(&repo);
    repo.describe(id, "described").unwrap();
    let view_before = repo.view().clone();
    let (_, undone) = repo.undo_keeping_edits(WS).unwrap();
    assert!(undone.starts_with("describe"), "{undone}");
    assert_ne!(repo.view(), &view_before);
    assert_eq!(repo.description(&repo.snapshot(&wc(&repo)).unwrap()), "");
}

#[test]
fn op_restore_keeps_edits() {
    let mut repo = mem_repo();
    let fs = MemoryBackend::from_files([("a.txt", &b"a\n"[..])]).unwrap();
    auto_snapshot(&mut repo, &fs);
    let target = repo.op_id();
    let id = wc(&repo);
    repo.describe(id, "later").unwrap();
    fs.write(&p("wip.txt"), b"wip\n").unwrap();
    auto_snapshot(&mut repo, &fs);
    let disk_tree = wc_tree(&repo);
    repo.restore_operation_keeping_edits(WS, target).unwrap();
    materialise(&repo, &fs, &disk_tree);
    assert_eq!(fs.read(&p("wip.txt")).unwrap(), b"wip\n");
    assert_eq!(repo.description(&repo.snapshot(&wc(&repo)).unwrap()), "", "the view was restored");
}
