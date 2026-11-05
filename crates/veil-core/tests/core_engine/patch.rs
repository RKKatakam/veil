//! `vl am` in the engine (`veil_core::patch::apply_series`): the import
//! threat review of `docs/design/git-parity/4-patches.md`, points 7–17,
//! through the repository API, plus a differential test against the
//! system `git format-patch` on random histories.

use crate::adversarial_support;

use std::{process::Command, sync::Arc};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    object::Visibility,
    patch::{self, AmOptions, AmReport, Limits},
    remote, Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

const POLICY: &str = "secrets/ cloak team\ntarget/ ignore\n";

/// Alice's repository: `.veilpolicy`, a public `a.txt`, a cloaked
/// `secrets/key.txt`, committed (`@-`), with an empty `@` on top.
fn base() -> (Repo, Arc<MemoryBackend>) {
    let (mut repo, fs, _) = new_repo("Alice <alice@example.com>");
    commit_files(
        &mut repo,
        &*fs,
        &[(".veilpolicy", POLICY), ("a.txt", "one\ntwo\nthree\n"), ("README", "hi\n"), ("secrets/key.txt", "SEALED-KEY-1\n")],
        "base",
    );
    (repo, fs)
}

fn mail(n: usize, total: usize, subject: &str, diff: &str) -> String {
    format!(
        "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\n\
         From: Mallory Writer <mallory@example.com>\n\
         Date: Wed, 4 Nov 2026 10:00:00 +0000\n\
         Subject: [PATCH {n}/{total}] {subject}\n\n\
         Why it matters.\n---\n{diff}-- \n2.43.0\n\n"
    )
}

fn am_with(repo: &mut Repo, text: &str, dest: &str, opts: &AmOptions) -> veil_core::Result<AmReport> {
    let s = patch::parse(text.as_bytes().to_vec(), &Limits::default())?;
    patch::apply_series(repo, WS, dest, &s, opts)
}

fn am(repo: &mut Repo, text: &str) -> veil_core::Result<AmReport> {
    am_with(repo, text, "@-", &AmOptions::default())
}

/// `am` fails, saying `what`, and records nothing at all.
fn refused(repo: &mut Repo, text: &str, what: &str) -> String {
    let op = repo.op_id();
    let heads = repo.view().heads.clone();
    let e = am(repo, text).expect_err("the patch should be refused").to_string();
    assert!(e.contains(what), "expected '{what}' in: {e}");
    repo.reload().unwrap();
    assert_eq!(repo.op_id(), op, "an operation was recorded: {e}");
    assert_eq!(repo.view().heads, heads);
    e
}

fn wc_parent(repo: &Repo) -> ObjectId {
    let wc = repo.workspace_wc(WS).unwrap();
    repo.snapshot(&wc).unwrap().parents[0]
}

const EDIT_A: &str = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n";

#[test]
fn one_change_per_patch_keeping_author_date_and_message() {
    let (mut repo, _) = base();
    let before = wc_parent(&repo);
    let series = format!(
        "{}{}",
        mail(1, 2, "edit a", EDIT_A),
        mail(
            2,
            2,
            "add b",
            "diff --git a/b.txt b/b.txt\nnew file mode 100755\n--- /dev/null\n+++ b/b.txt\n@@ -0,0 +1 @@\n+bee\n"
        )
    );
    let r = am(&mut repo, &series).unwrap();
    assert_eq!(r.changes.len(), 2);
    let (one, two) = (repo.snapshot(&r.changes[0]).unwrap(), repo.snapshot(&r.changes[1]).unwrap());
    assert_eq!(one.parents, vec![before]);
    assert_eq!(two.parents, vec![r.changes[0]]);
    // Author and date are the patch's claim; the signature is the importer's.
    assert_eq!(one.author, "Mallory Writer <mallory@example.com>");
    assert_eq!(one.timestamp, 1_793_786_400_000);
    assert!(one.signature.is_some());
    assert_eq!(repo.store().read_text(&one.description).unwrap(), "edit a\n\nWhy it matters.");
    assert_eq!(read_at(&repo, &r.changes[0], "a.txt"), b"one\nTWO\nthree\n");
    let b = file_entry(&repo, &r.changes[1], "b.txt").unwrap();
    assert!(b.executable);
    // The working copy sits on the series now, and nothing else moved.
    assert_eq!(wc_parent(&repo), r.changes[1]);
    assert!(r.rebased.is_some());
    // `--author-as-me` and `--signoff`.
    let r = am_with(
        &mut repo,
        &mail(1, 1, "again", "diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-hi\n+hello\n"),
        "@-",
        &AmOptions {
            author_as_me: true,
            signoff: true,
            ..AmOptions::default()
        },
    )
    .unwrap();
    let s = repo.snapshot(&r.changes[0]).unwrap();
    assert_eq!(s.author, "Alice <alice@example.com>");
    assert!(repo.store().read_text(&s.description).unwrap().ends_with("\n\nSigned-off-by: Alice <alice@example.com>"));
}

#[test]
fn a_failing_patch_records_nothing_and_undo_takes_back_a_whole_series() {
    let (mut repo, _) = base();
    let bad = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\n-NOT THERE\n+x\n three\n";
    let series = format!("{}{}{}", mail(1, 3, "ok", EDIT_A), mail(2, 3, "fine", "diff --git a/n b/n\nnew file mode 100644\n"), mail(3, 3, "bad", bad));
    let e = refused(&mut repo, &series, "patch 3/3 (bad): a.txt: hunk #1");
    assert!(e.contains("does not apply"), "{e}");
    // A good series, then undo.
    let before = wc_parent(&repo);
    am(&mut repo, &format!("{}{}", mail(1, 2, "ok", EDIT_A), mail(2, 2, "fine", "diff --git a/n b/n\nnew file mode 100644\n"))).unwrap();
    assert_ne!(wc_parent(&repo), before);
    repo.undo_keeping_edits(WS).unwrap();
    assert_eq!(wc_parent(&repo), before);
    let visible = repo.visible_snapshots().unwrap();
    for id in visible {
        let d = repo.store().read_text(&repo.snapshot(&id).unwrap().description).unwrap_or_default();
        assert!(!d.starts_with("ok") && !d.starts_with("fine"), "an undone change is still visible: {d}");
    }
}

#[test]
fn cover_letters_are_skipped_and_empty_patches_recorded_empty() {
    let (mut repo, _) = base();
    let cover = "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nFrom: A <a@x>\nDate: Wed, 4 Nov 2026 10:00:00 +0000\nSubject: [PATCH 0/1] *** SUBJECT HERE ***\n\n*** BLURB HERE ***\n\n-- \n2.43.0\n\n";
    let empty = "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nFrom: A <a@x>\nDate: Wed, 4 Nov 2026 10:00:00 +0000\nSubject: [PATCH] nothing\n\n---\n-- \n2.43.0\n\n";
    let r = am(&mut repo, &format!("{cover}{}", mail(1, 1, "x", EDIT_A))).unwrap();
    assert_eq!((r.changes.len(), r.skipped.clone()), (1, vec![1]));
    let r = am(&mut repo, empty).unwrap();
    assert_eq!(r.empty, vec![1]);
    assert!(repo.is_empty_change(&r.changes[0]).unwrap());
    assert!(am(&mut repo, cover).unwrap_err().to_string().contains("only a cover letter"));
}

#[test]
fn another_destination_leaves_the_working_copy_alone() {
    let (mut repo, fs) = base();
    let first = wc_parent(&repo);
    commit_files(&mut repo, &*fs, &[("c.txt", "c\n")], "second");
    let wc = repo.workspace_wc(WS).unwrap();
    let r = am_with(&mut repo, &mail(1, 1, "x", EDIT_A), &first.hex(), &AmOptions::default()).unwrap();
    assert_eq!(repo.snapshot(&r.changes[0]).unwrap().parents, vec![first]);
    assert!(r.rebased.is_none());
    assert_eq!(repo.workspace_wc(WS).unwrap(), wc);
}

// ---- threat review, import -------------------------------------------------

/// Point 7: what a patch creates must be free, below directories, and not
/// collide by case or Unicode normalisation with what is there.
#[test]
fn paths_that_collide_or_pass_through_files_are_refused() {
    let (mut repo, _) = base();
    let create = |path: &str| mail(1, 1, "c", &format!("diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n"));
    refused(&mut repo, &create("README"), "README already exists");
    refused(&mut repo, &create("a.txt/x"), "a.txt is not a directory");
    refused(&mut repo, &create("readme"), "only in case");
    refused(&mut repo, &create("A.TXT"), "only in case");
    refused(&mut repo, &create("SECRETS/x"), "only in case");
    // Within one patch, and in Unicode normalisation.
    let two = mail(
        1,
        1,
        "two",
        "diff --git a/caf\u{e9} b/caf\u{e9}\nnew file mode 100644\ndiff --git a/cafe\u{301} b/cafe\u{301}\nnew file mode 100644\n",
    );
    refused(&mut repo, &two, "differ only in case or Unicode normalisation");
    // Replacing a file by a directory in one patch is fine.
    let swap = mail(
        1,
        1,
        "swap",
        "diff --git a/README b/README\ndeleted file mode 100644\n--- a/README\n+++ /dev/null\n@@ -1 +0,0 @@\n-hi\n\
         diff --git a/README/inner b/README/inner\nnew file mode 100644\n--- /dev/null\n+++ b/README/inner\n@@ -0,0 +1 @@\n+in\n",
    );
    let r = am(&mut repo, &swap).unwrap();
    assert_eq!(read_at(&repo, &r.changes[0], "README/inner"), b"in\n");
}

/// Point 14: a mode on a file that is not there, a rename from a missing
/// file, a deletion that does not match.
#[test]
fn modes_and_sources_must_match_the_tree() {
    let (mut repo, _) = base();
    refused(&mut repo, &mail(1, 1, "m", "diff --git a/nope b/nope\nold mode 100644\nnew mode 100755\n"), "nope does not exist");
    refused(&mut repo, &mail(1, 1, "m", "diff --git a/a.txt b/a.txt\nold mode 100755\nnew mode 100644\n"), "expects mode 100755");
    refused(&mut repo, &mail(1, 1, "r", "diff --git a/gone b/new\nrename from gone\nrename to new\n"), "gone does not exist");
    refused(&mut repo, &mail(1, 1, "r", "diff --git a/a.txt b/README\nrename from a.txt\nrename to README\n"), "README already exists");
    refused(&mut repo, &mail(1, 1, "d", "diff --git a/README b/README\ndeleted file mode 100644\n"), "holds more than the patch removes");
    refused(&mut repo, &mail(1, 1, "d", "diff --git a/secrets b/secrets\nold mode 100644\nnew mode 100755\n"), "secrets is a directory");
    // Renames, copies and mode changes that do match.
    let ok = mail(
        1,
        1,
        "ok",
        "diff --git a/a.txt b/moved/a.txt\nsimilarity index 66%\nrename from a.txt\nrename to moved/a.txt\n--- a/a.txt\n+++ b/moved/a.txt\n@@ -1,3 +1,3 @@\n one\n-two\n+2\n three\n\
         diff --git a/README b/README.copy\ncopy from README\ncopy to README.copy\n\
         diff --git a/README b/README\nold mode 100644\nnew mode 100755\n",
    );
    let r = am(&mut repo, &ok).unwrap();
    let id = r.changes[0];
    assert!(file_entry(&repo, &id, "a.txt").is_none());
    assert_eq!(read_at(&repo, &id, "moved/a.txt"), b"one\n2\nthree\n");
    assert_eq!(read_at(&repo, &id, "README.copy"), b"hi\n");
    assert!(file_entry(&repo, &id, "README").unwrap().executable);
}

/// Point 9: a patch weakening `.veilpolicy` is held back, never taken as
/// the member's edit.
#[test]
fn a_policy_weakening_is_held_back() {
    let (mut repo, _) = base();
    let weaken = mail(
        1,
        1,
        "open up",
        "diff --git a/.veilpolicy b/.veilpolicy\n--- a/.veilpolicy\n+++ b/.veilpolicy\n@@ -1,2 +1,2 @@\n-secrets/ cloak team\n+secrets/ public!\n target/ ignore\n\
         diff --git a/secrets/new.txt b/secrets/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/secrets/new.txt\n@@ -0,0 +1 @@\n+STILL-SEALED-9\n",
    );
    let r = am(&mut repo, &weaken).unwrap();
    let id = r.changes[0];
    assert!(r.policy_held_back.iter().any(|h| h.path.as_str() == "secrets/new.txt"), "{:?}", r.policy_held_back);
    for f in ["secrets/new.txt", "secrets/key.txt"] {
        assert!(matches!(file_entry(&repo, &id, f).unwrap().visibility, Visibility::Cloaked { .. }), "{f}");
    }
    // The recorded policy is the patch's (it waits for `vl policy accept`).
    assert!(String::from_utf8(read_at(&repo, &id, ".veilpolicy")).unwrap().contains("public!"));
    // Nothing of it reaches a public remote.
    repo.set_tag("main", id, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut repo, mirror.clone(), true, &[], false).unwrap();
    assert!(backend_contains(&*mirror, b"STILL-SEALED-9").is_empty());
    assert!(backend_contains(&*mirror, b"SEALED-KEY-1").is_empty());
}

/// The device's accepted policy may predate a stricter rule that arrived
/// since and was never accepted: a patch dropping it is refused rather than
/// recording files under it as public.
#[test]
fn a_patch_never_records_less_protection_than_its_base_policy_gives() {
    let (mut repo, fs, _) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "base");
    // A cloak rule arrives by patch (never accepted on this device).
    let add_rule = mail(1, 1, "cloak", "diff --git a/.veilpolicy b/.veilpolicy\nnew file mode 100644\n--- /dev/null\n+++ b/.veilpolicy\n@@ -0,0 +1 @@\n+private/ cloak team\n");
    am(&mut repo, &add_rule).unwrap();
    let drop_rule = mail(
        1,
        1,
        "uncloak",
        "diff --git a/.veilpolicy b/.veilpolicy\n--- a/.veilpolicy\n+++ b/.veilpolicy\n@@ -1 +1 @@\n-private/ cloak team\n+private/ public!\n\
         diff --git a/private/x b/private/x\nnew file mode 100644\n--- /dev/null\n+++ b/private/x\n@@ -0,0 +1 @@\n+PRIVATE-77\n",
    );
    refused(&mut repo, &drop_rule, "private/x: the policy of the snapshot the patch applies to makes it cloaked:team");
}

/// Point 10: a secret in a patch is quarantined, the series aborts, and the
/// secret is never stored.
#[test]
fn a_secret_in_a_patch_aborts_the_series_and_is_never_stored() {
    let (mut repo, fs) = base();
    let series = format!(
        "{}{}{}",
        mail(1, 3, "one", EDIT_A),
        mail(2, 3, "two", "diff --git a/n b/n\nnew file mode 100644\n"),
        mail(3, 3, "creds", "diff --git a/config.yml b/config.yml\nnew file mode 100644\n--- /dev/null\n+++ b/config.yml\n@@ -0,0 +1 @@\n+aws_key: AKIAIOSFODNN7EXAMPLE\n"),
    );
    let e = refused(&mut repo, &series, "patch 3/3 (creds): config.yml quarantined (aws");
    assert!(!e.contains("AKIAIOSFODNN7EXAMPLE"), "{e}");
    assert!(backend_contains(&*fs, b"AKIAIOSFODNN7EXAMPLE").is_empty());
}

/// Isolated and ignored paths cannot be recorded by a patch.
#[test]
fn isolated_and_ignored_paths_are_refused() {
    let (mut repo, fs) = base();
    let create = |path: &str, body: &str| {
        mail(1, 1, "c", &format!("diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+{body}\n"))
    };
    refused(&mut repo, &create(".env", "ISOLATED-VALUE-31=x"), ".env is isolated by the policy");
    assert!(backend_contains(&*fs, b"ISOLATED-VALUE-31").is_empty());
    refused(&mut repo, &create("id_rsa", "ISOLATED-KEY-32"), "id_rsa is isolated");
    refused(&mut repo, &create("target/out.o", "x"), "target/out.o is ignored");
}

/// Point 11: an edit of a sealed file the reader can read stays sealed; one
/// it cannot read is refused (its public fallback is never the base).
#[test]
fn edits_of_sealed_files() {
    let (mut repo, _) = base();
    let edit = mail(1, 1, "k", "diff --git a/secrets/key.txt b/secrets/key.txt\n--- a/secrets/key.txt\n+++ b/secrets/key.txt\n@@ -1 +1 @@\n-SEALED-KEY-1\n+SEALED-KEY-2\n");
    let r = am(&mut repo, &edit).unwrap();
    let e = file_entry(&repo, &r.changes[0], "secrets/key.txt").unwrap();
    assert!(matches!(e.visibility, Visibility::Cloaked { .. }));
    assert_eq!(read_at(&repo, &r.changes[0], "secrets/key.txt"), b"SEALED-KEY-2\n");

    // Bob holds no key for `team`.
    let (mut alice, _) = base();
    let main = wc_parent(&alice);
    alice.set_tag("main", main, None, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let mut bob = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(Identity::generate("bob")), "bob").unwrap();
    remote::pull(&mut bob, "origin", hub).unwrap();
    bob.new_change(WS, vec![main], "").unwrap();
    refused(&mut bob, &edit, "cannot apply to sealed file secrets/key.txt");
    let create = mail(1, 1, "c", "diff --git a/secrets/key.txt b/secrets/key.txt\nnew file mode 100644\n--- /dev/null\n+++ b/secrets/key.txt\n@@ -0,0 +1 @@\n+x\n");
    refused(&mut bob, &create, "already exists (sealed");
}

/// Point 8 (CVE-2023-23946): patch 1 adds `link -> /home/u/.ssh`, patch 2
/// writes `link/authorized_keys`. Patch 2 fails ("not a directory": a link
/// is an entry, never traversed) and nothing at all is recorded. The full
/// set of link-then-write shapes is in `patch_phase2.rs`.
#[test]
fn symlink_then_write_is_refused() {
    let (mut repo, _) = base();
    let series = format!(
        "{}{}",
        mail(1, 2, "link", "diff --git a/link b/link\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+/home/u/.ssh\n\\ No newline at end of file\n"),
        mail(2, 2, "write", "diff --git a/link/authorized_keys b/link/authorized_keys\nnew file mode 100644\n--- /dev/null\n+++ b/link/authorized_keys\n@@ -0,0 +1 @@\n+ssh-ed25519 AAAA\n"),
    );
    refused(&mut repo, &series, "patch 2/2 (write): cannot create link/authorized_keys: link is not a directory");
    // A file standing where a directory would have to be.
    let series = format!(
        "{}{}",
        mail(1, 2, "file", "diff --git a/link b/link\nnew file mode 100644\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+/home/u/.ssh\n"),
        mail(2, 2, "write", "diff --git a/link/authorized_keys b/link/authorized_keys\nnew file mode 100644\n--- /dev/null\n+++ b/link/authorized_keys\n@@ -0,0 +1 @@\n+ssh-ed25519 AAAA\n"),
    );
    refused(&mut repo, &series, "link is not a directory");
}

/// Point 15: `am` takes the lock only after parsing, and runs as one
/// transaction: a commit racing it (another `Repo` on the same backend) is
/// never lost.
#[test]
fn am_and_a_racing_commit_both_survive() {
    let (mut repo, fs) = base();
    let s = patch::parse(mail(1, 1, "x", EDIT_A).into_bytes(), &Limits::default()).unwrap();
    // The other process commits between parse and apply.
    let mut other = Repo::open(fs.clone(), repo.identity().cloned(), "Alice <alice@example.com>").unwrap();
    fs.write(&p("raced.txt"), b"RACED\n").unwrap();
    other.snapshot_workspace(WS, &*fs).unwrap();
    other.commit_working_copy(WS, "raced").unwrap();
    let r = patch::apply_series(&mut repo, WS, "@-", &s, &AmOptions::default()).unwrap();
    let last = r.changes[0];
    // The series went onto the working copy's parent as it is now.
    assert_eq!(read_at(&repo, &last, "raced.txt"), b"RACED\n");
    assert_eq!(read_at(&repo, &last, "a.txt"), b"one\nTWO\nthree\n");
    assert_eq!(wc_parent(&repo), last);
}

// ---- the system git as an oracle -------------------------------------------

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success())
}

fn git(dir: &std::path::Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", dir)
        .env("GIT_AUTHOR_NAME", "Gita Hub")
        .env("GIT_AUTHOR_EMAIL", "gita@example.com")
        .env("GIT_COMMITTER_NAME", "Gita Hub")
        .env("GIT_COMMITTER_EMAIL", "gita@example.com")
        .env("GIT_AUTHOR_DATE", "2026-11-04T10:00:00Z")
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

/// A small random tree: path → (content, executable).
fn tree_strategy() -> impl Strategy<Value = std::collections::BTreeMap<String, (String, bool)>> {
    let name = prop_oneof![
        Just("a.txt"), Just("b.txt"), Just("dir/c.txt"), Just("dir/d e.txt"), Just("x/y/z.rs"), Just("caf\u{e9}.md"), Just("q\"uote"),
    ];
    let line = prop_oneof![Just("alpha"), Just("beta"), Just("gamma"), Just(""), Just("-- "), Just("+ plus"), Just("From x"), Just("\tindent")];
    let content = (proptest::collection::vec(line, 0..10), any::<bool>()).prop_map(|(l, nl)| {
        let mut s = l.join("\n");
        if nl {
            s.push('\n');
        }
        s
    });
    proptest::collection::btree_map(name.prop_map(String::from), (content, any::<bool>()), 0..6)
}

fn write_tree(dir: &std::path::Path, t: &std::collections::BTreeMap<String, (String, bool)>) {
    for (p, (c, x)) in t {
        let f = dir.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, c).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(if *x { 0o755 } else { 0o644 })).unwrap();
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// `git format-patch` (with or without rename and copy detection) of a
    /// random chain of commits applies through `vl am` to exactly what Git
    /// committed, commit by commit.
    #[test]
    fn git_format_patch_applies_to_what_git_committed(trees in proptest::collection::vec(tree_strategy(), 2..5), renames in any::<bool>()) {
        prop_assume!(git_available());
        prop_assume!(trees.windows(2).all(|w| w[0] != w[1]));
        let tmp = tempfile::tempdir().unwrap();
        let g = tmp.path().join("g");
        std::fs::create_dir_all(&g).unwrap();
        git(&g, &["init", "-q"]);
        let mut prev: Option<&std::collections::BTreeMap<String, (String, bool)>> = None;
        for (i, t) in trees.iter().enumerate() {
            for f in prev.into_iter().flat_map(|p| p.keys()) {
                let _ = std::fs::remove_file(g.join(f));
            }
            write_tree(&g, t);
            git(&g, &["add", "-A"]);
            git(&g, &["commit", "-q", "--allow-empty", "-m", &format!("commit {i}: the change\n\nwith a body")]);
            prev = Some(t);
        }
        let flags: &[&str] = if renames { &["-M30%", "-C"] } else { &["--no-renames"] };
        let range = format!("HEAD~{}..HEAD", trees.len() - 1);
        let mut args = vec!["format-patch", "--stdout", range.as_str()];
        args.extend_from_slice(flags);
        let mbox = git(&g, &args);

        let (mut repo, fs, _) = new_repo("alice");
        for (path, (c, x)) in &trees[0] {
            fs.write(&p(path), c.as_bytes()).unwrap();
            fs.set_executable(&p(path), *x).unwrap();
        }
        snap(&mut repo, &*fs);
        repo.commit_working_copy(WS, "a").unwrap();
        let s = patch::parse(mbox, &Limits::default()).unwrap();
        prop_assert_eq!(s.patches.len(), trees.len() - 1);
        let r = patch::apply_series(&mut repo, WS, "@-", &s, &AmOptions::default()).unwrap();
        for (i, id) in r.changes.iter().enumerate() {
            let snapshot = repo.snapshot(id).unwrap();
            let tree = snapshot.tree;
            let got: std::collections::BTreeMap<String, (String, bool)> = veil_core::tree::walk_files(repo.store(), &tree)
                .unwrap()
                .into_iter()
                .map(|(path, e)| (path.to_string(), (String::from_utf8(repo.store().read_entry(&e).unwrap()).unwrap(), e.executable)))
                .collect();
            prop_assert_eq!(&got, &trees[i + 1]);
            prop_assert_eq!(&snapshot.author, "Gita Hub <gita@example.com>");
            prop_assert_eq!(repo.store().read_text(&snapshot.description).unwrap(), format!("commit {}: the change\n\nwith a body", i + 1));
        }
    }
}
