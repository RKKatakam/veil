//! Symlinks in the working copy (repository format 5; the
//! Git-parity round's stream W1, `docs/design/git-parity/6-symlinks.md`).
//!
//! Each numbered threat of the design's review is tested here (the mount's
//! threat 8 in `crates/vl/src/mount/fs.rs`, escapes in the CLI tests):
//!
//! 1. no write ever resolves through a symlink: the no-follow writer, a
//!    link-then-directory sequence across checkouts, a case-folding
//!    collision of a link and a directory, and a race that swaps a
//!    directory for a link mid-checkout;
//! 2. the builder records a link's target string only, never what it
//!    points at;
//! 3. a link to an isolated file records the name, never the content;
//! 4. a link named like a secret is isolated by its name;
//! 5. a token in a target is quarantined;
//! 6. a target outside the repository round-trips unchanged (and warns);
//! 7. a sandbox never materialises a link that leads out of it, alone,
//!    through a chain of links (BUG-708) or by absolute path (BUG-709);
//! 9. a tracked file replaced by a link keeps its history;
//! 10. a link Veil did not write is never replaced or removed;
//! 11. a link loop is a leaf;
//! 12. link/link and link/file conflicts are materialised as one side, as
//!     it is (never markers holding a target), and `resolve` gives the
//!     right kind;
//! 13. hostile targets (NUL, over PATH_MAX) fail per path, never panic;
//! 14. `.veilpolicy` is never recorded as a link.
//!
//! Plus confidentiality (a cloaked link's target never reaches a public
//! remote), the rename-protection
//! hardening, and a property test of random trees with links checked out
//! over random hostile states.

use crate::adversarial_support;
use crate::macos_support;

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    conflict::{set_entry, Pick},
    object::{Conflict, ConflictTerm, EntryKind, Snapshot, TermKind, Text, Tree, TreeEntry, Visibility},
    remote,
    tree::lookup,
    vfs::{NodeKind, SandboxFs},
    workspace::SnapshotOptions,
    ChangeId, DiskBackend, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

// ---- helpers ------------------------------------------------------------------

/// A working copy on disk next to an `outside` directory that nothing may
/// ever write to.
struct Disk {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    outside: PathBuf,
    fs: DiskBackend,
}

fn disk() -> Disk {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("wc");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"outside\n").unwrap();
    let fs = DiskBackend::new(&root);
    Disk { _tmp: tmp, root, outside, fs }
}

impl Disk {
    /// Nothing but `keep`, unchanged, is in `outside`.
    fn assert_outside_untouched(&self) {
        let names: Vec<String> = std::fs::read_dir(&self.outside).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(names, vec!["keep".to_string()], "something was written outside the working copy");
        assert_eq!(std::fs::read(self.outside.join("keep")).unwrap(), b"outside\n");
    }

    fn link(&self, path: &str, target: impl AsRef<Path>) {
        let full = self.root.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, full).unwrap();
    }

    fn write(&self, path: &str, data: &str) {
        let full = self.root.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, data).unwrap();
    }

    fn target(&self, path: &str) -> PathBuf {
        std::fs::read_link(self.root.join(path)).unwrap()
    }

    fn is_link(&self, path: &str) -> bool {
        std::fs::symlink_metadata(self.root.join(path)).is_ok_and(|m| m.file_type().is_symlink())
    }
}

fn team() -> Visibility {
    Visibility::Cloaked { scope: "team".into() }
}

fn leaf(repo: &Repo, name: &str, kind: EntryKind, content: &str, vis: Visibility) -> TreeEntry {
    TreeEntry {
        name: name.into(),
        kind,
        id: repo.store().store_file(content.as_bytes(), &vis).unwrap(),
        size: content.len() as u64,
        executable: false,
        visibility: vis,
        fallback: None,
    }
}

fn symlink(repo: &Repo, name: &str, target: &str) -> TreeEntry {
    leaf(repo, name, EntryKind::Symlink, target, Visibility::Public)
}

/// `tree` with `entry` at `path`, creating missing parent directories.
fn put_at(repo: &Repo, tree: ObjectId, path: &str, entry: TreeEntry) -> ObjectId {
    let store = repo.store();
    let path = p(path);
    let mut missing = Vec::new();
    let mut d = path.parent();
    while let Some(dir) = d.filter(|d| !d.is_root()) {
        if lookup(store, &tree, &dir).unwrap().is_some() {
            break;
        }
        missing.push(dir.clone());
        d = dir.parent();
    }
    let Some(top) = missing.last().cloned() else {
        return set_entry(store, &tree, &path, Some(entry)).unwrap();
    };
    // Build the missing directories bottom-up.
    let mut child = store.put_tree(&Tree { entries: vec![entry] }).unwrap();
    for dir in &missing[..missing.len() - 1] {
        child = store.put_tree(&Tree { entries: vec![TreeEntry::dir(dir.file_name(), child)] }).unwrap();
    }
    set_entry(store, &tree, &top, Some(TreeEntry::dir(top.file_name(), child))).unwrap()
}

fn tree_of(repo: &Repo, leaves: Vec<(&str, TreeEntry)>) -> ObjectId {
    let mut t = repo.store().empty_tree().unwrap();
    for (path, e) in leaves {
        t = put_at(repo, t, path, e);
    }
    t
}

fn file(repo: &Repo, name: &str, content: &str) -> TreeEntry {
    leaf(repo, name, EntryKind::File, content, Visibility::Public)
}

fn wc_tree(repo: &Repo) -> ObjectId {
    repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree
}

fn entry_at(repo: &Repo, tree: &ObjectId, path: &str) -> Option<TreeEntry> {
    lookup(repo.store(), tree, &p(path)).unwrap()
}

// ---- the no-follow writer (threat 1) ------------------------------------------------

#[test]
fn no_write_or_removal_goes_through_a_symlinked_directory() {
    let d = disk();
    d.link("vendor", &d.outside);
    let fs = &d.fs;
    let below = p("vendor/x");
    for (what, r) in [
        ("write", fs.write(&below, b"pwned")),
        ("write_unsynced", fs.write_unsynced(&below, b"pwned")),
        ("create_new", fs.create_new(&below, b"pwned").map(drop)),
        ("create_dir_all", fs.create_dir_all(&p("vendor/sub"))),
        ("write_link", fs.write_link(&below, b"/etc/passwd")),
        ("deep write", fs.write(&p("vendor/a/b/c"), b"pwned")),
    ] {
        let e = r.expect_err(what);
        assert!(e.to_string().contains("symbolic link"), "{what}: {e}");
    }
    // Removals below a link find nothing to remove.
    fs.remove_file(&p("vendor/keep")).unwrap();
    fs.remove_dir_all(&p("vendor/keep")).unwrap();
    assert!(fs.set_executable(&p("vendor/keep"), true).is_err());
    // Reads never go through it either.
    assert!(fs.read(&p("vendor/keep")).unwrap_err().is_not_found());
    d.assert_outside_untouched();
    // The link itself is a leaf: its target, never what it points at.
    assert_eq!(fs.metadata(&p("vendor")).unwrap().unwrap().kind, NodeKind::Symlink);
    assert_eq!(fs.read_link(&p("vendor")).unwrap(), d.outside.as_os_str().as_encoded_bytes());
    assert!(fs.read(&p("vendor")).unwrap_err().is_not_found());
    let listed = fs.list_dir(&VPath::root()).unwrap();
    assert_eq!(listed.iter().map(|e| (e.name.as_str(), e.kind)).collect::<Vec<_>>(), vec![("vendor", NodeKind::Symlink)]);
    // Removing the link removes the link, never its target.
    fs.remove_dir_all(&p("vendor")).unwrap();
    assert!(!d.is_link("vendor"));
    d.assert_outside_untouched();
}

#[test]
fn a_write_at_a_link_replaces_the_link_itself() {
    let d = disk();
    d.link("cfg", d.outside.join("keep"));
    d.fs.write(&p("cfg"), b"mine\n").unwrap();
    assert!(!d.is_link("cfg"));
    assert_eq!(std::fs::read(d.root.join("cfg")).unwrap(), b"mine\n");
    d.assert_outside_untouched();
    // And a link written over a file replaces the file, atomically.
    d.fs.write_link(&p("cfg"), b"../elsewhere").unwrap();
    assert_eq!(d.target("cfg"), PathBuf::from("../elsewhere"));
    // Never over a directory.
    d.write("dir/f", "x");
    assert!(d.fs.write_link(&p("dir"), b"x").is_err());
    assert_eq!(std::fs::read(d.root.join("dir/f")).unwrap(), b"x");
}

#[test]
fn hostile_link_targets_are_refused_before_anything_is_written() {
    let d = disk();
    let long = vec![b'a'; 4096];
    for (target, why) in [(&b""[..], "empty"), (b"a\0b", "NUL"), (&long[..], "4096 bytes"), (b"\xff\xfe", "UTF-8")] {
        let e = d.fs.write_link(&p("l"), target).unwrap_err();
        assert!(e.to_string().contains(why), "{e}");
        let m = MemoryBackend::new();
        assert!(m.write_link(&p("l"), target).is_err());
    }
    assert!(!d.root.join("l").exists() && !d.is_link("l"));
}

/// A thread swaps a directory for a link to `outside` and back, as fast
/// as it can, while files are written below it: not one write may land in
/// `outside` (the walker holds the directory it checked, never a path).
#[test]
fn a_directory_swapped_for_a_link_mid_write_never_redirects_it() {
    let d = disk();
    std::fs::create_dir_all(d.root.join("a")).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (root, outside) = (d.root.clone(), d.outside.clone());
    let swapper = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let (a, aside) = (root.join("a"), root.join("a.real"));
            let mut swaps = 0u32;
            while !stop.load(Ordering::Relaxed) {
                if std::fs::rename(&a, &aside).is_ok() {
                    let _ = std::os::unix::fs::symlink(&outside, &a);
                    std::thread::yield_now();
                    let _ = std::fs::remove_file(&a);
                    let _ = std::fs::rename(&aside, &a);
                    swaps += 1;
                }
            }
            swaps
        })
    };
    for i in 0..3000 {
        let _ = d.fs.write(&p(&format!("a/f{i}")), b"data");
        let _ = d.fs.write_link(&p(&format!("a/l{i}")), b"x");
        let _ = d.fs.create_dir_all(&p(&format!("a/d{i}/e")));
    }
    stop.store(true, Ordering::Relaxed);
    let swaps = swapper.join().unwrap();
    assert!(swaps > 0, "the race never ran");
    // Undo the last swap if it was mid-way.
    if d.is_link("a") {
        std::fs::remove_file(d.root.join("a")).unwrap();
    }
    d.assert_outside_untouched();
}

/// The same race against a whole checkout: every path below the swapped
/// directory is written, or reported failed or blocked, and nothing lands
/// outside.
#[test]
fn a_directory_swapped_for_a_link_mid_checkout_receives_nothing_outside() {
    // The safety property (nothing outside) is checked on every attempt.
    // Liveness (some file written despite the race) depends on scheduling:
    // a swapper that wins every race makes every write refused, which is
    // safe, so a few attempts are allowed before it counts as a failure.
    let mut wrote = false;
    for _ in 0..5 {
        let d = disk();
        let (repo, _, _) = new_repo("alice");
        let leaves: Vec<(String, TreeEntry)> = (0..400).map(|i| (format!("a/sub/f{i}"), file(&repo, &format!("f{i}"), "payload\n"))).collect();
        let tree = tree_of(&repo, leaves.iter().map(|(p, e)| (p.as_str(), e.clone())).collect());
        std::fs::create_dir_all(d.root.join("a/sub")).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (root, outside) = (d.root.clone(), d.outside.clone());
        let swapper = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let (a, aside) = (root.join("a/sub"), root.join("a/sub.real"));
                while !stop.load(Ordering::Relaxed) {
                    if std::fs::rename(&a, &aside).is_ok() {
                        let _ = std::os::unix::fs::symlink(&outside, &a);
                        std::thread::yield_now();
                        let _ = std::fs::remove_file(&a);
                        let _ = std::fs::rename(&aside, &a);
                    }
                }
            })
        };
        let r = repo.checkout_tree(&d.fs, None, &tree);
        stop.store(true, Ordering::Relaxed);
        swapper.join().unwrap();
        // Never an error that aborts it half-way (a refused write is per path).
        let r = r.unwrap();
        if d.is_link("a/sub") {
            std::fs::remove_file(d.root.join("a/sub")).unwrap();
        }
        d.assert_outside_untouched();
        if r.written > 0 {
            wrote = true;
            break;
        }
    }
    assert!(wrote, "no attempt wrote anything: the checkout never made progress against the swapper");
}

// ---- recording links (threats 2-6, 9, 11, 14) -------------------------------------

#[test]
fn a_link_is_recorded_as_its_target_never_what_it_points_at() {
    let d = disk();
    let (mut repo, _, _) = new_repo("alice");
    let etc = tempfile::tempdir().unwrap();
    let shadow = etc.path().join("shadow");
    std::fs::write(&shadow, b"root:SECRET-HASH-1234:19000::\n").unwrap();
    d.link("notes.txt", &shadow);
    d.link("docs/up", "..");
    d.write("README", "hi\n");
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    let tree = wc_tree(&repo);
    let e = entry_at(&repo, &tree, "notes.txt").unwrap();
    assert_eq!(e.kind, EntryKind::Symlink);
    assert!(!e.executable);
    assert_eq!(repo.store().read_entry(&e).unwrap(), shadow.as_os_str().as_encoded_bytes());
    assert_eq!(e.size, shadow.as_os_str().len() as u64);
    assert!(backend_contains(&**repo.backend(), b"SECRET-HASH-1234").is_empty(), "the builder read through the link");
    assert_eq!(repo.store().read_entry(&entry_at(&repo, &tree, "docs/up").unwrap()).unwrap(), b"..");
    // Threat 6: a target outside the repository warns, once.
    assert!(s.report.link_warnings.iter().any(|(p, w)| p.as_str() == "notes.txt" && w.contains("outside the repository")), "{:?}", s.report.link_warnings);
    let again = repo.snapshot_workspace(WS, &d.fs).unwrap();
    assert!(!again.changed);
    assert!(again.report.link_warnings.is_empty(), "{:?}", again.report.link_warnings);
    d.assert_outside_untouched();
}

#[test]
fn a_link_loop_is_a_leaf_recorded_once() {
    let d = disk();
    let (mut repo, _, _) = new_repo("alice");
    d.link("a", ".");
    d.link("loop/b", "b");
    d.link("loop/c", "../loop");
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    assert!(s.changed);
    let files: Vec<String> = veil_core::tree::walk_files(repo.store(), &wc_tree(&repo)).unwrap().into_iter().map(|(p, _)| p.to_string()).collect();
    assert_eq!(files, ["a", "loop/b", "loop/c"]);
}

#[test]
fn a_link_to_an_isolated_file_records_its_name_never_its_content() {
    let d = disk();
    let (mut repo, _, _) = new_repo("alice");
    d.write(".env", "DATABASE_PASSWORD=hunter2-very-secret-value\n");
    d.link("public/env", "../.env");
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    let tree = wc_tree(&repo);
    assert!(entry_at(&repo, &tree, ".env").is_none());
    assert_eq!(repo.store().read_entry(&entry_at(&repo, &tree, "public/env").unwrap()).unwrap(), b"../.env");
    assert!(backend_contains(&**repo.backend(), b"hunter2-very-secret-value").is_empty());
    assert!(s.report.link_warnings.iter().any(|(p, w)| p.as_str() == "public/env" && w.contains("isolates")), "{:?}", s.report.link_warnings);
}

#[test]
fn a_link_named_like_a_secret_is_isolated_and_a_token_in_a_target_is_quarantined() {
    let d = disk();
    let (mut repo, _, _) = new_repo("alice");
    d.link("deploy/id_ed25519", "../keys/k");
    const TOKEN: &str = "https://u:ghp_R8x2Lq9VtZ4mN7pK1wY6sD3fH5jB0cA2eG4u@github.com/acme/x";
    d.link("url", TOKEN);
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    let tree = wc_tree(&repo);
    assert!(s.report.isolated.iter().any(|p| p.as_str() == "deploy/id_ed25519"), "{:?}", s.report.isolated);
    assert!(entry_at(&repo, &tree, "deploy/id_ed25519").is_none());
    assert!(s.report.quarantined.iter().any(|(p, _)| p.as_str() == "url"), "{:?}", s.report.quarantined);
    assert!(entry_at(&repo, &tree, "url").is_none());
    assert!(backend_contains(&**repo.backend(), b"ghp_R8x2Lq9VtZ4mN7pK1wY6sD3fH5jB0cA2eG4u").is_empty());

    // A tracked link whose target becomes a token keeps its entry.
    std::fs::remove_file(d.root.join("url")).unwrap();
    d.link("url", "https://example.com/acme/x");
    repo.snapshot_workspace(WS, &d.fs).unwrap();
    std::fs::remove_file(d.root.join("url")).unwrap();
    d.link("url", TOKEN);
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    assert!(s.report.quarantine_kept.iter().any(|p| p.as_str() == "url"));
    let e = entry_at(&repo, &wc_tree(&repo), "url").unwrap();
    assert_eq!(repo.store().read_entry(&e).unwrap(), b"https://example.com/acme/x");
}

#[test]
fn vcs_metadata_links_and_a_linked_policy_are_never_recorded_as_links() {
    let d = disk();
    let (mut repo, _, _) = new_repo("alice");
    d.write("README", "hi\n");
    d.link(".git", &d.outside);
    d.link("sub/.jj", &d.outside);
    std::fs::write(d.outside.join("my.veilpolicy"), "secret/ cloak team\n").unwrap();
    d.link(".veilpolicy", d.outside.join("my.veilpolicy"));
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    let tree = wc_tree(&repo);
    for path in [".git", "sub/.jj", ".veilpolicy"] {
        assert!(entry_at(&repo, &tree, path).is_none(), "{path} was recorded");
    }
    // The linked policy is read (its rules apply), never recorded as a link.
    d.write("secret/k", "key\n");
    repo.snapshot_workspace(WS, &d.fs).unwrap();
    assert_eq!(entry_at(&repo, &wc_tree(&repo), "secret/k").unwrap().visibility, team());
    let _ = s;
}

#[test]
fn a_file_replaced_by_a_link_keeps_its_history() {
    let d = disk();
    let (mut repo, _, _) = new_repo("alice");
    d.write("config.yml", "port: 80\n");
    let first = repo.snapshot_workspace(WS, &d.fs).unwrap().snapshot;
    std::fs::remove_file(d.root.join("config.yml")).unwrap();
    d.link("config.yml", "config.d/default.yml");
    let second = repo.snapshot_workspace(WS, &d.fs).unwrap().snapshot;
    assert_ne!(first, second);
    let old = file_entry(&repo, &first, "config.yml").unwrap();
    assert_eq!((old.kind, repo.store().read_entry(&old).unwrap()), (EntryKind::File, b"port: 80\n".to_vec()));
    let new = file_entry(&repo, &second, "config.yml").unwrap();
    assert_eq!((new.kind, repo.store().read_entry(&new).unwrap()), (EntryKind::Symlink, b"config.d/default.yml".to_vec()));
}

#[test]
fn below_format_5_links_stay_special_files() {
    let fs = Arc::new(MemoryBackend::new());
    let repo = Repo::init(fs, Some(veil_core::Identity::generate("alice")), "alice").unwrap();
    // A format-4 store: the builder never records a link.
    repo.store().set_format(4);
    let wc = MemoryBackend::from_files([("a", &b"x"[..])]).unwrap();
    wc.write_link(&p("l"), b"a").unwrap();
    let (tree, report) = veil_core::builder::build_tree(
        repo.store(),
        &wc,
        &veil_core::builder::BuildOptions {
            policy: &veil_core::policy::Policy::builtin(),
            parent_tree: None,
            cloak: None,
            injected: None,
            rescan: false,
            materialised: None,
            line_base: None,
            line_endings: Default::default(),
        },
    )
    .unwrap();
    assert!(entry_at(&repo, &tree, "l").is_none());
    assert!(entry_at(&repo, &tree, "a").is_some());
    assert!(report.link_warnings.is_empty());
}

// ---- checkout (threats 1, 10, 13) -------------------------------------------------

#[test]
fn checkout_writes_links_as_links_and_replaces_only_its_own() {
    let d = disk();
    let (repo, _, _) = new_repo("alice");
    let t1 = tree_of(&repo, vec![("bin/tool", symlink(&repo, "tool", "../lib/tool.sh")), ("lib/tool.sh", file(&repo, "tool.sh", "echo\n"))]);
    let r = repo.checkout_tree(&d.fs, None, &t1).unwrap();
    assert!(r.failed.is_empty(), "{:?}", r.failed);
    assert_eq!(d.target("bin/tool"), PathBuf::from("../lib/tool.sh"));
    // Re-targeted in the next tree: the link checkout wrote is replaced.
    let t2 = put_at(&repo, t1, "bin/tool", symlink(&repo, "tool", "../lib/tool2.sh"));
    repo.checkout_tree(&d.fs, Some(&t1), &t2).unwrap();
    assert_eq!(d.target("bin/tool"), PathBuf::from("../lib/tool2.sh"));
    // A link the user re-pointed is theirs: kept, never replaced or removed.
    std::fs::remove_file(d.root.join("bin/tool")).unwrap();
    d.link("bin/tool", "/usr/bin/true");
    let t3 = put_at(&repo, t2, "bin/tool", symlink(&repo, "tool", "../lib/tool3.sh"));
    let r = repo.checkout_tree(&d.fs, Some(&t2), &t3).unwrap();
    assert!(r.kept_local.iter().any(|p| p.as_str() == "bin/tool"), "{r:?}");
    assert_eq!(d.target("bin/tool"), PathBuf::from("/usr/bin/true"));
    let t4 = set_entry(repo.store(), &t3, &p("bin/tool"), None).unwrap();
    let r = repo.checkout_tree(&d.fs, Some(&t3), &t4).unwrap();
    assert!(r.kept_local.iter().any(|p| p.as_str() == "bin/tool"), "{r:?}");
    assert!(d.is_link("bin/tool"));
}

#[test]
fn a_link_then_a_directory_across_two_checkouts_writes_nothing_outside() {
    let d = disk();
    let (repo, _, _) = new_repo("alice");
    // CVE-2014-9390 shape: `a -> outside`, then a tree with `a/` a
    // directory holding `authorized_keys`.
    let t1 = tree_of(&repo, vec![("a", symlink(&repo, "a", d.outside.to_str().unwrap()))]);
    repo.checkout_tree(&d.fs, None, &t1).unwrap();
    assert!(d.is_link("a"));
    let t2 = tree_of(&repo, vec![("a/authorized_keys", file(&repo, "authorized_keys", "ssh-ed25519 AAAA mallory\n"))]);
    let r = repo.checkout_tree(&d.fs, Some(&t1), &t2).unwrap();
    assert!(r.failed.is_empty() && r.blocked.is_empty(), "{r:?}");
    assert!(!d.is_link("a"));
    assert_eq!(std::fs::read(d.root.join("a/authorized_keys")).unwrap(), b"ssh-ed25519 AAAA mallory\n");
    d.assert_outside_untouched();

    // The same, when the user's own link sits there: blocked, untouched.
    let d = disk();
    d.link("a", &d.outside);
    let r = repo.checkout_tree(&d.fs, None, &t2).unwrap();
    assert!(r.blocked.iter().any(|p| p.as_str() == "a/authorized_keys"), "{r:?}");
    assert!(d.is_link("a"));
    d.assert_outside_untouched();
    // And from a tree that had the link (it is not the user's version).
    let d = disk();
    d.link("a", "/somewhere/else");
    let r = repo.checkout_tree(&d.fs, Some(&t1), &t2).unwrap();
    assert!(r.kept_local.iter().any(|p| p.as_str() == "a") || r.blocked.iter().any(|p| p.as_str() == "a/authorized_keys"), "{r:?}");
    assert_eq!(d.target("a"), PathBuf::from("/somewhere/else"));
    d.assert_outside_untouched();
}

#[test]
fn an_untracked_user_link_is_never_replaced_by_a_tracked_directory() {
    let d = disk();
    let (repo, _, _) = new_repo("alice");
    d.link("vendor", &d.outside);
    let t = tree_of(&repo, vec![("vendor/lib.rs", file(&repo, "lib.rs", "pub fn f() {}\n"))]);
    let r = repo.checkout_tree(&d.fs, None, &t).unwrap();
    assert!(r.blocked.iter().any(|p| p.as_str() == "vendor/lib.rs"), "{r:?}");
    assert!(d.is_link("vendor"));
    d.assert_outside_untouched();
    // And a tracked link over an untracked file of the user's: kept.
    d.write("cfg", "mine\n");
    let t = tree_of(&repo, vec![("cfg", symlink(&repo, "cfg", "cfg.d"))]);
    let r = repo.checkout_tree(&d.fs, None, &t).unwrap();
    assert!(r.kept_local.iter().any(|p| p.as_str() == "cfg"), "{r:?}");
    assert_eq!(std::fs::read(d.root.join("cfg")).unwrap(), b"mine\n");
}

/// CVE-2021-21300 shape: a link `A` and a directory `a/` in one tree, on a
/// case-insensitive filesystem. Checkout refuses the tree before writing
/// anything (`name_collisions` counts links as names).
#[test]
fn a_case_folding_collision_of_a_link_and_a_directory_is_refused() {
    let (repo, _, _) = new_repo("alice");
    let t = tree_of(&repo, vec![("A", symlink(&repo, "A", "/tmp/x")), ("a/file", file(&repo, "file", "x\n"))]);
    let found = veil_core::checkout::name_collisions(repo.store(), &t, veil_core::vfs::NameFolding::MACOS, None).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    let fs = macos_support::FoldingBackend::apfs();
    let e = repo.checkout_tree(&fs, None, &t).unwrap_err();
    assert!(matches!(e, veil_core::VeilError::NameCollision(_)), "{e}");
    assert!(fs.list_dir(&VPath::root()).unwrap().is_empty(), "something was written");
}

#[test]
fn hostile_targets_in_a_tree_fail_per_path_and_never_panic() {
    let d = disk();
    let (repo, _, _) = new_repo("alice");
    let long = "a".repeat(5000);
    let t = tree_of(
        &repo,
        vec![
            ("nul", symlink(&repo, "nul", "a\0b")),
            ("long", symlink(&repo, "long", &long)),
            ("empty", symlink(&repo, "empty", "")),
            ("ok", symlink(&repo, "ok", "nul")),
        ],
    );
    let r = repo.checkout_tree(&d.fs, None, &t).unwrap();
    let failed: Vec<&str> = r.failed.iter().map(|(p, _)| p.as_str()).collect();
    for path in ["nul", "long", "empty"] {
        assert!(failed.contains(&path), "{path}: {:?}", r.failed);
        assert!(!d.root.join(path).exists() && !d.is_link(path));
    }
    assert_eq!(d.target("ok"), PathBuf::from("nul"));
}

#[test]
fn a_backend_without_links_reports_them_and_the_builder_carries_them() {
    #[derive(Debug)]
    struct NoLinks(MemoryBackend);
    impl StorageBackend for NoLinks {
        fn kind(&self) -> &'static str {
            "nolinks"
        }
        fn read(&self, p: &VPath) -> veil_core::Result<Vec<u8>> {
            self.0.read(p)
        }
        fn write(&self, p: &VPath, d: &[u8]) -> veil_core::Result<()> {
            self.0.write(p, d)
        }
        fn create_new(&self, p: &VPath, d: &[u8]) -> veil_core::Result<bool> {
            self.0.create_new(p, d)
        }
        fn remove_file(&self, p: &VPath) -> veil_core::Result<()> {
            self.0.remove_file(p)
        }
        fn remove_dir_all(&self, p: &VPath) -> veil_core::Result<()> {
            self.0.remove_dir_all(p)
        }
        fn create_dir_all(&self, p: &VPath) -> veil_core::Result<()> {
            self.0.create_dir_all(p)
        }
        fn list_dir(&self, p: &VPath) -> veil_core::Result<Vec<veil_core::vfs::DirEntry>> {
            self.0.list_dir(p)
        }
        fn metadata(&self, p: &VPath) -> veil_core::Result<Option<veil_core::vfs::Metadata>> {
            self.0.metadata(p)
        }
        fn set_executable(&self, p: &VPath, e: bool) -> veil_core::Result<()> {
            self.0.set_executable(p, e)
        }
    }
    let (mut repo, _, _) = new_repo("alice");
    let t = tree_of(&repo, vec![("l", symlink(&repo, "l", "target")), ("f", file(&repo, "f", "x\n"))]);
    let fs = NoLinks(MemoryBackend::new());
    let mut record = veil_core::checkout::Materialised::default();
    let r = veil_core::checkout::checkout_recorded(repo.store(), &fs, None, &t, &mut record, None).unwrap();
    assert!(r.failed.iter().any(|(p, why)| p.as_str() == "l" && why.contains("cannot hold symlinks")), "{:?}", r.failed);
    assert!(record.hidden(&p("l")));
    // Snapshotting that working copy keeps the link (never a deletion).
    let snap = put_snapshot(&repo, t);
    repo.edit(WS, snap).unwrap();
    let s = repo.snapshot_workspace_with(WS, &fs, SnapshotOptions { materialised: Some(&record), ..Default::default() }).unwrap();
    let e = entry_at(&repo, &repo.snapshot(&s.snapshot).unwrap().tree, "l").unwrap();
    assert_eq!(e.kind, EntryKind::Symlink);
}

fn put_snapshot(repo: &Repo, tree: ObjectId) -> ObjectId {
    let parent = repo.workspace_wc(WS).unwrap();
    let mut s = Snapshot {
        parents: vec![parent],
        change_id: ChangeId::random(),
        tree,
        description: Text::Plain("links".into()),
        author: "alice".into(),
        timestamp: 1,
        conflicts: vec![],
        ..Snapshot::root(tree)
    };
    s.sign(repo.identity().unwrap());
    repo.store().put_snapshot(&s).unwrap()
}

// ---- conflicts (threat 12) ----------------------------------------------------------

fn term(e: &TreeEntry) -> Option<ConflictTerm> {
    Some(ConflictTerm::of(e))
}

/// The working copy moved onto a snapshot of `tree`, checked out on `fs`.
fn move_to(repo: &mut Repo, fs: &dyn StorageBackend, tree: ObjectId, conflicts: Vec<String>) {
    let old = wc_tree(repo);
    let parent = repo.workspace_wc(WS).unwrap();
    let mut s = Snapshot {
        parents: vec![parent],
        change_id: ChangeId::random(),
        tree,
        description: Text::Plain("merge".into()),
        author: "alice".into(),
        timestamp: 1,
        conflicts,
        ..Snapshot::root(tree)
    };
    s.sign(repo.identity().unwrap());
    let id = repo.store().put_snapshot(&s).unwrap();
    repo.edit(WS, id).unwrap();
    repo.checkout_tree(fs, Some(&old), &tree).unwrap();
}

#[test]
fn link_conflicts_are_written_as_one_side_never_as_markers() {
    let d = disk();
    let (mut repo, _, _) = new_repo("alice");
    const OURS: &str = "/srv/ours-private-target";
    const THEIRS: &str = "/srv/theirs-private-target";
    let base = symlink(&repo, "cur", "/srv/base");
    let ours = symlink(&repo, "cur", OURS);
    let theirs = symlink(&repo, "cur", THEIRS);
    let file_side = file(&repo, "cfg", "a file side\n");
    let link_side = symlink(&repo, "cfg", THEIRS);
    let c1 = repo.store().put_conflict(&Conflict { adds: vec![term(&ours), term(&theirs)], removes: vec![term(&base)] }).unwrap();
    let c2 = repo.store().put_conflict(&Conflict { adds: vec![term(&file_side), term(&link_side)], removes: vec![None] }).unwrap();
    let t = tree_of(&repo, vec![("cur", TreeEntry::conflict("cur", c1)), ("cfg", TreeEntry::conflict("cfg", c2))]);
    move_to(&mut repo, &d.fs, t, vec!["cur".into(), "cfg".into()]);
    // Ours, as it is: a link for `cur`, the file for `cfg`.
    assert_eq!(d.target("cur"), PathBuf::from(OURS));
    assert_eq!(std::fs::read(d.root.join("cfg")).unwrap(), b"a file side\n");
    let data = std::fs::read(d.root.join("cfg")).unwrap();
    assert!(!String::from_utf8_lossy(&data).contains(THEIRS) && !data.starts_with(b"<<<<<<<"), "markers in cfg");
    // Untouched, a snapshot keeps both conflicts.
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    assert!(!s.changed, "{:?}", s.report);
    assert_eq!(entry_at(&repo, &wc_tree(&repo), "cur").unwrap().kind, EntryKind::Conflict);
    // `vl resolve --theirs`: a link for both, with their target.
    let before = wc_tree(&repo);
    repo.resolve_conflicts(WS, &[p("cur"), p("cfg")], Pick::Theirs).unwrap();
    let after = wc_tree(&repo);
    repo.checkout_tree(&d.fs, Some(&before), &after).unwrap();
    for path in ["cur", "cfg"] {
        let e = entry_at(&repo, &after, path).unwrap();
        assert_eq!(e.kind, EntryKind::Symlink, "{path}");
        assert_eq!(d.target(path), PathBuf::from(THEIRS), "{path}");
    }
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    assert!(!s.changed);
}

#[test]
fn editing_a_link_conflict_resolves_it_and_resolve_ours_gives_a_file() {
    let d = disk();
    let (mut repo, _, _) = new_repo("alice");
    let file_side = file(&repo, "cfg", "file side\n");
    let link_side = symlink(&repo, "cfg", "cfg.d/x");
    let c = repo.store().put_conflict(&Conflict { adds: vec![term(&link_side), term(&file_side)], removes: vec![None] }).unwrap();
    let t = tree_of(&repo, vec![("cfg", TreeEntry::conflict("cfg", c))]);
    move_to(&mut repo, &d.fs, t, vec!["cfg".into()]);
    assert_eq!(d.target("cfg"), PathBuf::from("cfg.d/x"));
    // Replacing the link by a file resolves the conflict as that file.
    std::fs::remove_file(d.root.join("cfg")).unwrap();
    d.write("cfg", "resolved by hand\n");
    repo.snapshot_workspace(WS, &d.fs).unwrap();
    let e = entry_at(&repo, &wc_tree(&repo), "cfg").unwrap();
    assert_eq!((e.kind, repo.store().read_entry(&e).unwrap()), (EntryKind::File, b"resolved by hand\n".to_vec()));
    // `resolve --theirs` on the original conflict: the file side.
    move_to(&mut repo, &d.fs, t, vec!["cfg".into()]);
    let before = wc_tree(&repo);
    repo.resolve_conflicts(WS, &[p("cfg")], Pick::Theirs).unwrap();
    let after = wc_tree(&repo);
    let r = repo.checkout_tree(&d.fs, Some(&before), &after).unwrap();
    let e = entry_at(&repo, &after, "cfg").unwrap();
    assert_eq!(e.kind, EntryKind::File);
    assert!(r.kept_local.is_empty() && r.blocked.is_empty(), "{r:?}");
    assert_eq!(std::fs::read(d.root.join("cfg")).unwrap(), b"file side\n");
    let c = repo.store().conflict(&lookup(repo.store(), &t, &p("cfg")).unwrap().unwrap().id).unwrap();
    assert_eq!(c.adds.iter().flatten().map(|t| t.kind).collect::<Vec<_>>(), [TermKind::Symlink, TermKind::File]);
}

// ---- sandboxes (threat 7) ----------------------------------------------------------

#[test]
fn a_sandbox_never_materialises_a_link_leading_out_of_it() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let home = tmp.path().join("home");
    let sandbox = project.join(".veil/local/sandboxes/ws/files");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(project.join(".env"), b"SECRET=1\n").unwrap();
    let (repo, _, _) = new_repo("alice");
    let fs = SandboxFs::new(&sandbox, None, false).with_forbidden_targets([project.clone(), home.clone()]);
    let t = tree_of(
        &repo,
        vec![
            ("x", symlink(&repo, "x", "../../../../../.env")),
            ("deep/y", symlink(&repo, "y", "../../z")),
            ("abs", symlink(&repo, "abs", project.join(".env").to_str().unwrap())),
            ("dotdot", symlink(&repo, "dotdot", &format!("{}/../home/./identity.json", project.display()))),
            ("fine", symlink(&repo, "fine", "deep")),
            ("up/fine", symlink(&repo, "fine", "../deep/y")),
            // BUG-709: any absolute target, `/proc/self/cwd` above all.
            ("usr", symlink(&repo, "usr", "/usr/share/dict/words")),
            ("proc", symlink(&repo, "proc", "/proc/self/cwd/../../../../../.env")),
            // BUG-708: two links, each inside on its own, chained.
            ("s1/s2/s3/s4/u", symlink(&repo, "u", "../../../..")),
            ("s1/s2/s3/s4/x", symlink(&repo, "x", "u/../../../../../.env")),
        ],
    );
    let mut record = veil_core::checkout::Materialised::default();
    let r = veil_core::checkout::checkout_recorded(repo.store(), &fs, None, &t, &mut record, None).unwrap();
    for path in ["x", "deep/y", "abs", "dotdot", "usr", "proc", "s1/s2/s3/s4/x"] {
        assert!(r.failed.iter().any(|(p, why)| p.as_str() == path && why.contains("not materialised in this sandbox")), "{path}: {r:?}");
        assert!(std::fs::symlink_metadata(sandbox.join(path)).is_err(), "{path} was materialised");
        // Never materialised: recording the sandbox carries the link.
        assert!(record.hidden(&p(path)), "{path}");
    }
    assert!(r.failed.iter().any(|(_, w)| w.contains("x -> ../../../../../.env")), "{:?}", r.failed);
    assert_eq!(std::fs::read_link(sandbox.join("fine")).unwrap(), PathBuf::from("deep"));
    assert_eq!(std::fs::read_link(sandbox.join("up/fine")).unwrap(), PathBuf::from("../deep/y"));
    assert_eq!(std::fs::read_link(sandbox.join("s1/s2/s3/s4/u")).unwrap(), PathBuf::from("../../../.."));
    assert!(r.failed.iter().any(|(_, w)| w.contains("project")), "{:?}", r.failed);
}

/// Targets for the sandbox property: chains of `..` and names (some of
/// which are links of the same tree), and absolute ones through `/proc`.
fn sandbox_target_strategy() -> BoxedStrategy<String> {
    let part = prop::sample::select(vec!["..", "..", "a", "b", "u", ".", "", "s"]);
    let free = prop::collection::vec(part, 1..9).prop_map(|v| v.join("/")).prop_filter("not empty", |t| !t.is_empty());
    // A chain's shape: climb, a name (maybe a link), climb again, a tail.
    let chain = (0..6usize, prop::sample::select(vec!["a", "u", "s", "a/u"]), 0..8usize, prop::sample::select(vec![".env", "", "a"]))
        .prop_map(|(up, name, up2, tail)| {
            let mut v: Vec<&str> = vec![".."; up];
            v.push(name);
            v.extend(std::iter::repeat_n("..", up2));
            if !tail.is_empty() {
                v.push(tail);
            }
            v.join("/")
        });
    let relative = prop_oneof![free, chain];
    let absolute = prop::sample::select(vec![
        "/proc/self/cwd/../../../../../.env",
        "/proc/self/cwd/.env",
        "/proc/self/root/PROJECT/.env",
        "/proc/thread-self/cwd/../.env",
        "/dev/fd/3/.env",
        "PROJECT/.env",
        "/usr/share/dict/words",
    ])
    .prop_map(str::to_string);
    prop_oneof![8 => relative, 1 => absolute].boxed()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    /// Threat 7, BUG-708, BUG-709: whatever links a tree holds (chains of
    /// links that are each inside on their own, `/proc` magic links,
    /// absolute targets), every link a sandbox materialises is relative and
    /// resolves beneath the sandbox root, and nothing read through the
    /// sandbox is the project's isolated `.env`.
    #[test]
    fn a_sandbox_never_resolves_outside_itself_through_any_links(
        leaves in prop::collection::vec((
            prop::collection::vec(prop::sample::select(vec!["a", "b", "u", "s"]), 1..7).prop_map(|v| v.join("/")),
            prop_oneof![1 => any::<u8>().prop_map(Node::File), 4 => sandbox_target_strategy().prop_map(Node::Link)],
        ), 1..10),
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let sandbox = project.join(".veil/local/sandboxes/ws/files");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::write(project.join(".env"), b"SECRET=isolated\n").unwrap();
        let (repo, _, _) = new_repo("alice");
        let fs = SandboxFs::new(&sandbox, None, false).with_forbidden_targets([project.clone()]);
        let leaves: Vec<(String, Node)> = leaves
            .into_iter()
            .map(|(p, n)| match n {
                Node::Link(t) => (p, Node::Link(t.replace("PROJECT", project.to_str().unwrap()))),
                n => (p, n),
            })
            .collect();
        let t = random_tree(&repo, &leaves);
        let mut record = veil_core::checkout::Materialised::default();
        let r = veil_core::checkout::checkout_recorded(repo.store(), &fs, None, &t, &mut record, None);
        prop_assert!(r.is_ok(), "{:?}", r.err());
        let root = sandbox.canonicalize().unwrap();
        let mut stack = vec![sandbox.clone()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap() {
                let path = e.unwrap().path();
                let m = std::fs::symlink_metadata(&path).unwrap();
                if m.is_dir() {
                    stack.push(path.clone());
                }
                if m.file_type().is_symlink() {
                    let target = std::fs::read_link(&path).unwrap();
                    prop_assert!(target.is_relative(), "{} -> {} (absolute) was materialised", path.display(), target.display());
                    if let Ok(real) = path.canonicalize() {
                        prop_assert!(real.starts_with(&root), "{} resolves to {}", path.display(), real.display());
                    }
                }
                // Read through every name the tree gives (a command's own
                // `..` climbs out of any directory, links or not).
                for probe in [path.clone(), path.join(".env")] {
                    if let Ok(data) = std::fs::read(&probe) {
                        prop_assert!(data != b"SECRET=isolated\n", "{} reads the isolated .env", probe.display());
                    }
                }
            }
        }
    }
}

// ---- confidentiality --------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    /// Whatever the target, a link the policy cloaks is recorded sealed and
    /// its target never reaches a public remote (nor does a link on a
    /// cloaked line of work).
    #[test]
    fn a_cloaked_links_target_never_reaches_a_public_remote(target in "/srv/[a-z]{6,12}-merger/[a-z]{4,8}") {
        let d = disk();
        let (mut repo, _, _) = new_repo("alice");
        d.write(".veilpolicy", "private/ cloak team\n");
        d.write("README", "hi\n");
        d.link("private/current", &target);
        d.link("public/readme", "../README");
        let snap = repo.snapshot_workspace(WS, &d.fs).unwrap().snapshot;
        let e = file_entry(&repo, &snap, "private/current").unwrap();
        prop_assert_eq!(e.kind, EntryKind::Symlink);
        prop_assert_eq!(&e.visibility, &team());
        prop_assert!(backend_contains(&**repo.backend(), target.as_bytes()).is_empty(), "plaintext target in the store");
        repo.set_tag("main", snap, None, false).unwrap();
        let mirror = Arc::new(MemoryBackend::new());
        remote::push(&mut repo, mirror.clone(), true, &[], false).unwrap();
        prop_assert!(backend_contains(&*mirror, target.as_bytes()).is_empty());
        let m = Repo::open(mirror.clone(), None, "remote").unwrap();
        let tree = m.snapshot(&snap).unwrap().tree;
        let sealed = lookup(m.store(), &tree, &p("private/current")).unwrap().unwrap();
        prop_assert!(!m.store().has(&sealed.id));
        let public = lookup(m.store(), &tree, &p("public/readme")).unwrap().unwrap();
        prop_assert_eq!(m.store().read_entry(&public).unwrap(), b"../README".to_vec());
    }
}

#[test]
fn an_absolute_target_round_trips_through_push_pull_and_checkout() {
    let d = disk();
    let (mut alice, _, id) = new_repo("alice");
    d.link("fixtures/dict", "/usr/share/dict/words");
    let snap = alice.snapshot_workspace(WS, &d.fs).unwrap().snapshot;
    alice.set_tag("main", snap, None, false).unwrap();
    let r = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, r.clone(), false, &[], false).unwrap();
    let (mut bob, _) = repo_for("alice", &id);
    let bd = disk();
    pull_and_checkout(&mut bob, &bd.fs, r).unwrap();
    assert_eq!(bd.target("fixtures/dict"), PathBuf::from("/usr/share/dict/words"));
    let s = bob.snapshot_workspace(WS, &bd.fs).unwrap();
    assert!(!s.changed);
}

// ---- protection follows content across a rename -----------------------------------

#[test]
fn a_sealed_file_moved_to_a_public_path_stays_sealed() {
    let d = disk();
    let (mut repo, _, _) = new_repo("alice");
    d.write(".veilpolicy", "secrets/ cloak team\n");
    d.write("secrets/db.yml", "password: moved-secret-42\n");
    let first = repo.snapshot_workspace(WS, &d.fs).unwrap().snapshot;
    assert_eq!(file_entry(&repo, &first, "secrets/db.yml").unwrap().visibility, team());
    std::fs::create_dir_all(d.root.join("docs")).unwrap();
    std::fs::rename(d.root.join("secrets/db.yml"), d.root.join("docs/db.yml")).unwrap();
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    let e = file_entry(&repo, &s.snapshot, "docs/db.yml").unwrap();
    assert_eq!(e.visibility, team(), "the moved content became public");
    assert!(s.report.policy_warnings.iter().any(|w| w.contains("docs/db.yml") && w.contains("moved")), "{:?}", s.report.policy_warnings);
    // It stays sealed in the next snapshots, and is never pushed public.
    let again = repo.snapshot_workspace(WS, &d.fs).unwrap();
    assert!(!again.changed);
    repo.set_tag("main", again.snapshot, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut repo, mirror.clone(), true, &[], false).unwrap();
    assert!(backend_contains(&*mirror, b"moved-secret-42").is_empty());
    // An explicit public rule is the member's decision: it is honoured.
    let d2 = disk();
    let (mut repo2, _, _) = new_repo("alice");
    d2.write(".veilpolicy", "secrets/ cloak team\ndocs/ public\n");
    d2.write("secrets/db.yml", "shared: yes\n");
    repo2.snapshot_workspace(WS, &d2.fs).unwrap();
    std::fs::create_dir_all(d2.root.join("docs")).unwrap();
    std::fs::rename(d2.root.join("secrets/db.yml"), d2.root.join("docs/db.yml")).unwrap();
    let s = repo2.snapshot_workspace(WS, &d2.fs).unwrap();
    assert!(file_entry(&repo2, &s.snapshot, "docs/db.yml").unwrap().visibility.is_public());
}

// ---- the property: random trees over random hostile states ---------------------------

#[derive(Clone, Debug)]
enum Node {
    File(u8),
    Link(String),
    Dir,
}

fn path_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(vec!["a", "b", "c"]), 1..4).prop_map(|v| v.join("/"))
}

fn target_strategy(outside: bool) -> BoxedStrategy<String> {
    let mut opts = vec![".", "..", "../..", "a", "b/c", "../a", "../../../../x"];
    if outside {
        opts.push("OUTSIDE");
    }
    prop::sample::select(opts).prop_map(str::to_string).boxed()
}

fn node_strategy() -> impl Strategy<Value = Node> {
    prop_oneof![
        any::<u8>().prop_map(Node::File),
        target_strategy(true).prop_map(Node::Link),
        Just(Node::Dir),
    ]
}

/// Lay `nodes` out under `d` (the pre-existing, possibly hostile state),
/// skipping what conflicts with what is already there.
fn lay_out(d: &Disk, nodes: &[(String, Node)]) {
    'nodes: for (path, n) in nodes {
        let full = d.root.join(path);
        // The setup itself must never write through a link (or below a
        // file): every ancestor is a real directory, or missing.
        let mut dir = d.root.clone();
        let parts: Vec<&str> = path.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            dir.push(part);
            match std::fs::symlink_metadata(&dir) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => continue 'nodes,
                Err(_) => break,
            }
        }
        if std::fs::symlink_metadata(&full).is_ok() {
            continue;
        }
        let _ = std::fs::create_dir_all(full.parent().unwrap());
        let _ = match n {
            Node::File(b) => std::fs::write(&full, [*b]),
            Node::Dir => std::fs::create_dir(&full),
            Node::Link(t) if t == "OUTSIDE" => std::os::unix::fs::symlink(&d.outside, &full),
            Node::Link(t) => std::os::unix::fs::symlink(t, &full),
        };
    }
}

fn tree_strategy() -> impl Strategy<Value = Vec<(String, Node)>> {
    prop::collection::vec((path_strategy(), prop_oneof![any::<u8>().prop_map(Node::File), target_strategy(false).prop_map(Node::Link)]), 1..8)
}

/// A tree of `leaves` (later ones win; one that would sit below a leaf is
/// dropped).
fn random_tree(repo: &Repo, leaves: &[(String, Node)]) -> ObjectId {
    let mut kept: Vec<(String, Node)> = Vec::new();
    for (path, n) in leaves {
        let clash = kept.iter().any(|(q, _)| q == path || path.starts_with(&format!("{q}/")) || q.starts_with(&format!("{path}/")));
        if !clash {
            kept.push((path.clone(), n.clone()));
        }
    }
    let mut t = repo.store().empty_tree().unwrap();
    for (path, n) in &kept {
        let name = path.rsplit('/').next().unwrap();
        let e = match n {
            Node::File(b) => file(repo, name, &format!("{b}\n")),
            Node::Link(target) => symlink(repo, name, target),
            Node::Dir => continue,
        };
        t = put_at(repo, t, path, e);
    }
    t
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Random trees with links, checked out one after another over a
    /// working copy that already holds random files, directories and
    /// hostile links (some to `outside`): no checkout fails as a whole, no
    /// write ever lands outside the working copy or through a link, and
    /// whatever checkout writes as a link has the tree's target.
    #[test]
    fn checkouts_over_hostile_states_never_write_outside_or_through_a_link(
        existing in prop::collection::vec((path_strategy(), node_strategy()), 0..10),
        trees in prop::collection::vec(tree_strategy(), 1..4),
    ) {
        let d = disk();
        lay_out(&d, &existing);
        let (repo, _, _) = new_repo("alice");
        let mut from: Option<ObjectId> = None;
        for leaves in &trees {
            let to = random_tree(&repo, leaves);
            let r = repo.checkout_tree(&d.fs, from.as_ref(), &to);
            prop_assert!(r.is_ok(), "{:?}", r.err());
            let r = r.unwrap();
            // What checkout wrote as a link (a change it applied, and did
            // not report kept or refused) is the tree's link.
            for c in veil_core::tree::diff_trees(repo.store(), from.as_ref(), Some(&to)).unwrap() {
                let (path, Some(e)) = (c.path, c.new) else { continue };
                if e.kind != EntryKind::Symlink || r.blocked.contains(&path) || r.kept_local.contains(&path) || r.failed.iter().any(|(q, _)| *q == path) || r.obstructed.iter().any(|(q, _)| *q == path) {
                    continue;
                }
                if let Ok(t) = std::fs::read_link(d.root.join(path.as_str())) {
                    let want = repo.store().read_entry(&e).unwrap();
                    prop_assert_eq!(t.as_os_str().as_encoded_bytes(), &want[..], "{}", path);
                }
            }
            d.assert_outside_untouched();
            from = Some(to);
        }
    }
}

#[test]
fn memory_and_overlay_backends_hold_links_and_never_follow_them() {
    let m = Arc::new(MemoryBackend::from_files([("a/f", &b"x"[..])]).unwrap());
    m.write_link(&p("l"), b"a").unwrap();
    assert_eq!(m.metadata(&p("l")).unwrap().unwrap().kind, NodeKind::Symlink);
    assert!(m.read(&p("l")).unwrap_err().is_not_found());
    assert!(m.write(&p("l/x"), b"y").is_err(), "wrote below a link");
    assert!(m.write_link(&p("a"), b"x").is_err(), "replaced a directory");
    let o = veil_core::vfs::OverlayBackend::new(m.clone());
    assert_eq!(o.read_link(&p("l")).unwrap(), b"a");
    o.write_link(&p("a/f"), b"../l").unwrap();
    // The link written over a lower file is never read as that file.
    assert!(o.read(&p("a/f")).unwrap_err().is_not_found());
    assert_eq!(o.read_link(&p("a/f")).unwrap(), b"../l");
    assert!(o.write(&p("l/x"), b"y").is_err());
    assert_eq!(m.read(&p("a/f")).unwrap(), b"x", "the lower layer changed");
}

/// Threat 9: in format 4 a tracked file the user replaced by a link keeps
/// its entry (the link is a special file). After `vl upgrade` to format 5
/// the next snapshot records the link, and the parent still holds the
/// file's content (no data loss).
#[test]
fn after_an_upgrade_a_file_replaced_by_a_link_is_recorded_and_its_history_kept() {
    let d = disk();
    let backend = Arc::new(MemoryBackend::new());
    let id = veil_core::Identity::generate("alice");
    let mut repo = Repo::init_for_clone_at(backend.clone(), Some(id.clone()), "alice", 4).unwrap();
    d.write("config.yml", "port: 80\n");
    let before = repo.snapshot_workspace(WS, &d.fs).unwrap().snapshot;
    std::fs::remove_file(d.root.join("config.yml")).unwrap();
    d.link("config.yml", "config.d/default.yml");
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    assert!(!s.changed && s.report.shadowed.iter().any(|p| p.as_str() == "config.yml"), "{:?}", s.report);
    drop(repo);
    veil_core::upgrade::upgrade(backend.clone(), Some(id.clone()), &veil_core::upgrade::UpgradeOptions::default()).unwrap();
    let mut repo = Repo::open(backend, Some(id), "alice").unwrap();
    assert!(repo.format() >= 5);
    let s = repo.snapshot_workspace(WS, &d.fs).unwrap();
    assert!(s.changed && s.report.shadowed.is_empty());
    let e = file_entry(&repo, &s.snapshot, "config.yml").unwrap();
    assert_eq!((e.kind, repo.store().read_entry(&e).unwrap()), (EntryKind::Symlink, b"config.d/default.yml".to_vec()));
    let old = file_entry(&repo, &before, "config.yml").unwrap();
    assert_eq!(repo.store().read_entry(&old).unwrap(), b"port: 80\n");
}

/// Threat 14: a hostile tree whose `.veilpolicy` is a symlink entry. It is
/// never written to the working copy, and reading the tree's policy treats
/// it as unreadable (the accepted policy applies), never as "no policy".
#[test]
fn a_veilpolicy_symlink_entry_is_never_written_or_taken_for_no_policy() {
    let d = disk();
    let (repo, _, _) = new_repo("alice");
    let t = tree_of(&repo, vec![(".veilpolicy", symlink(&repo, ".veilpolicy", "../other/.veilpolicy")), ("a", file(&repo, "a", "x\n"))]);
    let r = repo.checkout_tree(&d.fs, None, &t).unwrap();
    assert!(r.failed.iter().any(|(p, _)| p.as_str() == ".veilpolicy"), "{r:?}");
    assert!(!d.is_link(".veilpolicy") && !d.root.join(".veilpolicy").exists());
    let view = veil_core::tree::TreeView::new(repo.store().clone(), t);
    assert!(matches!(veil_core::policy::read_policy_file(&view).unwrap(), veil_core::policy::PolicyFile::Unavailable(_)));
}
