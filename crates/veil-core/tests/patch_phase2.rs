//! `vl am`, phase 2 (`docs/design/git-parity/4-patches.md`): symlinks and
//! submodules in both kinds of section, type changes, `GIT binary patch`
//! literals and deltas, and `--3way`, through the repository API. The
//! hostile shapes of threat review points 8, 12 and 14, and confidentiality
//! of what a three-way merge records.

mod adversarial_support;

use std::{process::Command, sync::Arc};

use adversarial_support::*;
use veil_core::{
    object::{EntryKind, Visibility},
    patch::{self, AmOptions, AmReport, Limits},
    remote, Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

const POLICY: &str = "secrets/ cloak team\ntarget/ ignore\n";

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

fn one(diff: &str) -> String {
    mail(1, 1, "p", diff)
}

fn am_with(repo: &mut Repo, text: &str, opts: &AmOptions) -> veil_core::Result<AmReport> {
    let s = patch::parse(text.as_bytes().to_vec(), &Limits::default())?;
    patch::apply_series(repo, WS, "@-", &s, opts)
}

fn am(repo: &mut Repo, text: &str) -> veil_core::Result<AmReport> {
    am_with(repo, text, &AmOptions::default())
}

/// `am` fails, saying `what`, and records nothing at all.
fn refused_with(repo: &mut Repo, text: &str, opts: &AmOptions, what: &str) -> String {
    let op = repo.op_id();
    let heads = repo.view().heads.clone();
    let e = am_with(repo, text, opts).expect_err("the patch should be refused").to_string();
    assert!(e.contains(what), "expected '{what}' in: {e}");
    repo.reload().unwrap();
    assert_eq!(repo.op_id(), op, "an operation was recorded: {e}");
    assert_eq!(repo.view().heads, heads);
    e
}

fn refused(repo: &mut Repo, text: &str, what: &str) -> String {
    refused_with(repo, text, &AmOptions::default(), what)
}

fn kind_at(repo: &Repo, rev: &ObjectId, path: &str) -> Option<EntryKind> {
    file_entry(repo, rev, path).map(|e| e.kind)
}

fn new_link(path: &str, target: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\nnew file mode 120000\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+{target}\n\\ No newline at end of file\n"
    )
}

fn new_file(path: &str, line: &str) -> String {
    format!("diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+{line}\n")
}

const SHA_A: &str = "1234567890123456789012345678901234567890";
const SHA_B: &str = "abcdef7890123456789012345678901234567890";

fn new_gitlink(path: &str, sha: &str) -> String {
    format!("diff --git a/{path} b/{path}\nnew file mode 160000\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+Subproject commit {sha}\n")
}

// ---- symlinks ----------------------------------------------------------------

/// Links are created, retargeted, renamed, turned into files (and back)
/// and deleted, each as a symlink entry whose content is its target.
#[test]
fn symlinks_through_every_kind_of_section() {
    let (mut repo, _) = base();
    let r = am(&mut repo, &one(&new_link("docs/latest", "../a.txt"))).unwrap();
    let id = r.changes[0];
    assert_eq!(kind_at(&repo, &id, "docs/latest"), Some(EntryKind::Symlink));
    assert_eq!(read_at(&repo, &id, "docs/latest"), b"../a.txt");
    assert!(r.link_warnings.is_empty(), "{:?}", r.link_warnings);

    let retarget = "diff --git a/docs/latest b/docs/latest\nindex 1111111..2222222 120000\n--- a/docs/latest\n+++ b/docs/latest\n@@ -1 +1 @@\n-../a.txt\n\\ No newline at end of file\n+../README\n\\ No newline at end of file\n";
    let id = am(&mut repo, &one(retarget)).unwrap().changes[0];
    assert_eq!(read_at(&repo, &id, "docs/latest"), b"../README");

    let rename = "diff --git a/docs/latest b/docs/current\nsimilarity index 100%\nrename from docs/latest\nrename to docs/current\n";
    let id = am(&mut repo, &one(rename)).unwrap().changes[0];
    assert!(file_entry(&repo, &id, "docs/latest").is_none());
    assert_eq!(kind_at(&repo, &id, "docs/current"), Some(EntryKind::Symlink));

    // A type change, as Git writes it: the deletion and the creation.
    let to_file = "diff --git a/docs/current b/docs/current\ndeleted file mode 120000\n--- a/docs/current\n+++ /dev/null\n@@ -1 +0,0 @@\n-../README\n\\ No newline at end of file\n\
                   diff --git a/docs/current b/docs/current\nnew file mode 100644\n--- /dev/null\n+++ b/docs/current\n@@ -0,0 +1 @@\n+a file now\n";
    let id = am(&mut repo, &one(to_file)).unwrap().changes[0];
    assert_eq!(kind_at(&repo, &id, "docs/current"), Some(EntryKind::File));
    assert_eq!(read_at(&repo, &id, "docs/current"), b"a file now\n");
    let to_link = "diff --git a/README b/README\ndeleted file mode 100644\n--- a/README\n+++ /dev/null\n@@ -1 +0,0 @@\n-hi\n\
                   diff --git a/README b/README\nnew file mode 120000\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+a.txt\n\\ No newline at end of file\n";
    let id = am(&mut repo, &one(to_link)).unwrap().changes[0];
    assert_eq!(kind_at(&repo, &id, "README"), Some(EntryKind::Symlink));

    let delete = "diff --git a/README b/README\ndeleted file mode 120000\n--- a/README\n+++ /dev/null\n@@ -1 +0,0 @@\n-a.txt\n\\ No newline at end of file\n";
    let id = am(&mut repo, &one(delete)).unwrap().changes[0];
    assert!(file_entry(&repo, &id, "README").is_none());
    // `vl undo` takes back one series at a time.
    repo.undo().unwrap();
    let wc = repo.workspace_wc(WS).unwrap();
    let parent = repo.snapshot(&wc).unwrap().parents[0];
    assert_eq!(kind_at(&repo, &parent, "README"), Some(EntryKind::Symlink));
}

/// Point 8 (CVE-2023-23946 and its relatives): nothing is ever written
/// through a link, whether the link is in the tree the patch applies to,
/// made by an earlier patch of the series, or made by the same patch, in
/// either order. Each attempt records nothing.
#[test]
fn hostile_link_then_write_patches_are_refused() {
    let (mut repo, _) = base();
    let ssh = new_link("link", "/home/u/.ssh");
    let keys = new_file("link/authorized_keys", "ssh-ed25519 AAAA mallory");
    // Two patches of one series.
    let series = format!("{}{}", mail(1, 2, "link", &ssh), mail(2, 2, "keys", &keys));
    refused(&mut repo, &series, "patch 2/2 (keys): cannot create link/authorized_keys: link is not a directory");
    // One patch, both orders.
    refused(&mut repo, &one(&format!("{ssh}{keys}")), "cannot write link/authorized_keys: the same patch makes link a symlink");
    refused(&mut repo, &one(&format!("{keys}{ssh}")), "cannot write link/authorized_keys: the same patch makes link a symlink");
    // Deeper, and through a rename or a copy into the link.
    let deep = new_file("link/a/b/c", "x");
    refused(&mut repo, &one(&format!("{ssh}{deep}")), "the same patch makes link a symlink");
    let id = am(&mut repo, &one(&ssh)).unwrap().changes[0];
    assert_eq!(kind_at(&repo, &id, "link"), Some(EntryKind::Symlink));
    let into = "diff --git a/a.txt b/link/a.txt\nsimilarity index 100%\nrename from a.txt\nrename to link/a.txt\n";
    refused(&mut repo, &one(into), "link is not a directory");
    let copy = "diff --git a/a.txt b/link/a.txt\nsimilarity index 100%\ncopy from a.txt\ncopy to link/a.txt\n";
    refused(&mut repo, &one(copy), "link is not a directory");
    // Edits, deletions and mode changes "below" the link name nothing.
    let edit = "diff --git a/link/x b/link/x\n--- a/link/x\n+++ b/link/x\n@@ -1 +1 @@\n-a\n+b\n";
    refused(&mut repo, &one(edit), "link/x does not exist (link is not a directory)");
    let del = "diff --git a/link/x b/link/x\ndeleted file mode 100644\n--- a/link/x\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n";
    refused(&mut repo, &one(del), "link/x does not exist");
    let mode = "diff --git a/link/x b/link/x\nold mode 100644\nnew mode 100755\n";
    refused(&mut repo, &one(mode), "link/x does not exist");
    // A link edited as if it were a file, or the reverse.
    let as_file = "diff --git a/link b/link\n--- a/link\n+++ b/link\n@@ -1 +1 @@\n-/home/u/.ssh\n\\ No newline at end of file\n+/etc\n\\ No newline at end of file\n";
    let as_file = as_file.replace("--- a/link", "index 1111111..2222222 100644\n--- a/link");
    refused(&mut repo, &one(&as_file), "link: the patch expects a regular file, and it is a symlink");
    // Replacing the link by a directory in one patch is a deletion and a
    // creation: a real directory, nothing written anywhere else.
    let swap = format!(
        "diff --git a/link b/link\ndeleted file mode 120000\n--- a/link\n+++ /dev/null\n@@ -1 +0,0 @@\n-/home/u/.ssh\n\\ No newline at end of file\n{keys}"
    );
    let id = am(&mut repo, &one(&swap)).unwrap().changes[0];
    assert_eq!(kind_at(&repo, &id, "link"), Some(EntryKind::Dir));
    assert_eq!(read_at(&repo, &id, "link/authorized_keys"), b"ssh-ed25519 AAAA mallory\n");
}

/// Targets the recording refuses are refused; a link may not stand where
/// Veil's policy or Git's work-tree files are; a target leaving the
/// repository is recorded as it is (Veil never follows it), with a warning.
#[test]
fn link_targets_and_names() {
    let (mut repo, _) = base();
    let long = "x/".repeat(2100);
    refused(&mut repo, &one(&new_link("l", &long)), "more than 4095");
    let latin1 = "diff --git a/l b/l\nnew file mode 120000\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+caf\u{e9}\n\\ No newline at end of file\n";
    let mut bytes = one(latin1).into_bytes();
    let at = bytes.windows(2).position(|w| w == "\u{e9}".as_bytes()).unwrap();
    bytes.splice(at..at + 2, [0xe9]);
    let s = patch::parse(bytes, &Limits::default()).unwrap();
    let e = patch::apply_series(&mut repo, WS, "@-", &s, &AmOptions::default()).unwrap_err().to_string();
    assert!(e.contains("not valid UTF-8"), "{e}");
    let empty = "diff --git a/l b/l\nnew file mode 120000\n";
    refused(&mut repo, &one(empty), "it is empty");
    for name in ["sub/.gitmodules", ".GITMODULES", ".gitattributes", "x/.gitignore", ".mailmap"] {
        refused(&mut repo, &one(&new_link(name, "a.txt")), "a symlink may not be named");
    }
    // .veilpolicy is never a link, even by a type change.
    let tc = format!(
        "diff --git a/.veilpolicy b/.veilpolicy\ndeleted file mode 100644\n--- a/.veilpolicy\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-secrets/ cloak team\n-target/ ignore\n{}",
        new_link(".veilpolicy", "/dev/null")
    );
    refused(&mut repo, &one(&tc), "a symlink may not be named .veilpolicy");
    // Outside the repository: recorded, warned about.
    let r = am(&mut repo, &one(&format!("{}{}", new_link("abs", "/etc/passwd"), new_link("d/up", "../../outside")))).unwrap();
    let warned: Vec<&str> = r.link_warnings.iter().map(|(_, p, _)| p.as_str()).collect();
    assert_eq!(warned, ["abs", "d/up"]);
    assert!(r.link_warnings[0].2.contains("outside the repository"));
    assert_eq!(read_at(&repo, &r.changes[0], "abs"), b"/etc/passwd");
}

/// A link is classified by its own path: under a cloaked directory its
/// target is sealed; an isolated name is refused; a secret in a target is
/// quarantined (and never stored).
#[test]
fn links_are_classified_scanned_and_sealed_like_content() {
    let (mut repo, fs) = base();
    let r = am(&mut repo, &one(&new_link("secrets/where", "/srv/SEALED-TARGET-5"))).unwrap();
    let e = file_entry(&repo, &r.changes[0], "secrets/where").unwrap();
    assert_eq!(e.kind, EntryKind::Symlink);
    assert!(matches!(e.visibility, Visibility::Cloaked { .. }));
    assert!(backend_contains(&*fs, b"SEALED-TARGET-5").is_empty());
    refused(&mut repo, &one(&new_link("id_rsa", "k")), "id_rsa is isolated");
    let token = new_link("url", "https://u:ghp_R8x2Lq9VtZ4mN7pK1wY6sD3fH5jB0cA2eG4u@github.com/x");
    refused(&mut repo, &one(&token), "quarantined");
    assert!(backend_contains(&*fs, b"ghp_R8x2Lq9VtZ4mN7pK1wY6sD3fH5jB0cA2eG4u").is_empty());
}

/// Below repository format 5 there are no symlinks or submodules: such a
/// section is refused, naming the upgrade.
#[test]
fn links_need_format_5() {
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init_for_clone_at(fs.clone(), Some(Identity::generate("alice")), "alice", 4).unwrap();
    commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "base");
    refused(&mut repo, &one(&new_link("l", "a.txt")), "need repository format 5");
    refused(&mut repo, &one(&new_gitlink("sub", SHA_A)), "need repository format 5");
    am(&mut repo, &one(&new_file("b.txt", "b"))).unwrap();
}

// ---- submodules ----------------------------------------------------------------

/// A submodule is recorded as a pin: a gitlink entry naming the commit.
/// Nothing is fetched, cloned or created on disk, and nothing can be written
/// below it.
#[test]
fn submodules_are_pins_only() {
    let (mut repo, fs) = base();
    let id = am(&mut repo, &one(&new_gitlink("vendor/lib", SHA_A))).unwrap().changes[0];
    let e = file_entry(&repo, &id, "vendor/lib").unwrap();
    assert_eq!(e.kind, EntryKind::Gitlink);
    assert_eq!(repo.store().read_entry(&e).unwrap(), format!("{SHA_A}\n").as_bytes());
    assert!(!fs.exists(&p(".veil/local/submodules")).unwrap());
    let links = veil_core::submodule::gitlinks(repo.store(), &repo.snapshot(&id).unwrap().tree).unwrap();
    assert_eq!(links[0].commit.as_deref(), Some(SHA_A));

    let bump = format!(
        "diff --git a/vendor/lib b/vendor/lib\nindex {}..{} 160000\n--- a/vendor/lib\n+++ b/vendor/lib\n@@ -1 +1 @@\n-Subproject commit {SHA_A}\n+Subproject commit {SHA_B}\n",
        &SHA_A[..7],
        &SHA_B[..7]
    );
    let id = am(&mut repo, &one(&bump)).unwrap().changes[0];
    let e = file_entry(&repo, &id, "vendor/lib").unwrap();
    assert_eq!((e.kind, repo.store().read_entry(&e).unwrap()), (EntryKind::Gitlink, format!("{SHA_B}\n").into_bytes()));
    // The patch's old pin must be the recorded one.
    refused(&mut repo, &one(&bump), "hunk #1");
    // Nothing below a submodule, in the tree or in the same patch.
    refused(&mut repo, &one(&new_file("vendor/lib/x", "x")), "vendor/lib is not a directory");
    refused(&mut repo, &one(&format!("{}{}", new_gitlink("m", SHA_A), new_file("m/x", "x"))), "the same patch makes m a submodule");
    // A rename of the submodule (exact, as Git detects it), then deletion.
    let mv = "diff --git a/vendor/lib b/third_party/lib\nsimilarity index 100%\nrename from vendor/lib\nrename to third_party/lib\n";
    let id = am(&mut repo, &one(mv)).unwrap().changes[0];
    assert_eq!(kind_at(&repo, &id, "third_party/lib"), Some(EntryKind::Gitlink));
    assert!(file_entry(&repo, &id, "vendor/lib").is_none());
    let del = format!(
        "diff --git a/third_party/lib b/third_party/lib\ndeleted file mode 160000\n--- a/third_party/lib\n+++ /dev/null\n@@ -1 +0,0 @@\n-Subproject commit {SHA_B}\n"
    );
    let id = am(&mut repo, &one(&del)).unwrap().changes[0];
    assert!(file_entry(&repo, &id, "third_party").is_none());
}

/// Malformed pins, submodules where a file must be, and type changes.
#[test]
fn hostile_submodule_sections() {
    let (mut repo, _) = base();
    for bad in ["Subproject commit 1234567", "Subproject commit XYZ4567890123456789012345678901234567890", "Subproject commit", "evil"] {
        let s = format!("diff --git a/s b/s\nnew file mode 160000\n--- /dev/null\n+++ b/s\n@@ -0,0 +1 @@\n+{bad}\n");
        refused(&mut repo, &one(&s), "must be 'Subproject commit <full commit id>'");
    }
    let two_lines = format!("diff --git a/s b/s\nnew file mode 160000\n--- /dev/null\n+++ b/s\n@@ -0,0 +1,2 @@\n+Subproject commit {SHA_A}\n+more\n");
    refused(&mut repo, &one(&two_lines), "Subproject commit");
    refused(&mut repo, &one(&new_gitlink(".veilpolicy", SHA_A)), ".veilpolicy already exists");
    let tc = format!(
        "diff --git a/.veilpolicy b/.veilpolicy\ndeleted file mode 100644\n--- a/.veilpolicy\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-secrets/ cloak team\n-target/ ignore\n{}",
        new_gitlink(".veilpolicy", SHA_A)
    );
    refused(&mut repo, &one(&tc), ".veilpolicy is always a regular file");
    refused(&mut repo, &one(&new_gitlink(".env", SHA_A)), ".env is isolated");
    // A file turned into a submodule and back, by type changes.
    let to_sub = format!(
        "diff --git a/README b/README\ndeleted file mode 100644\n--- a/README\n+++ /dev/null\n@@ -1 +0,0 @@\n-hi\n{}",
        new_gitlink("README", SHA_A)
    );
    let id = am(&mut repo, &one(&to_sub)).unwrap().changes[0];
    assert_eq!(kind_at(&repo, &id, "README"), Some(EntryKind::Gitlink));
    // A submodule under a cloaked directory keeps its pin sealed.
    let id = am(&mut repo, &one(&new_gitlink("secrets/sub", SHA_B))).unwrap().changes[0];
    let e = file_entry(&repo, &id, "secrets/sub").unwrap();
    assert_eq!(e.kind, EntryKind::Gitlink);
    assert!(matches!(e.visibility, Visibility::Cloaked { .. }));
}

// ---- binary ----------------------------------------------------------------------

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
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// `git format-patch --binary` of `old` → `new` at `path` (both `None`:
/// absent), and the series it makes.
fn git_binary_patch(path: &str, old: Option<&[u8]>, new: Option<&[u8]>) -> String {
    let tmp = tempfile::tempdir().unwrap();
    let g = tmp.path();
    git(g, &["init", "-q"]);
    std::fs::write(g.join("keep"), "k\n").unwrap();
    if let Some(o) = old {
        std::fs::write(g.join(path), o).unwrap();
    }
    git(g, &["add", "-A"]);
    git(g, &["commit", "-q", "-m", "old"]);
    match new {
        Some(n) => std::fs::write(g.join(path), n).unwrap(),
        None => std::fs::remove_file(g.join(path)).unwrap(),
    }
    git(g, &["add", "-A"]);
    git(g, &["commit", "-q", "-m", "binary change"]);
    String::from_utf8(git(g, &["format-patch", "-1", "--stdout", "--binary"])).unwrap()
}

/// `GIT binary patch` literals and deltas from `git format-patch` apply:
/// created, changed by a delta, deleted; the result is exactly Git's.
#[test]
fn binary_literals_and_deltas_from_git_apply() {
    if !git_available() {
        return;
    }
    let (mut repo, fs) = base();
    let v1 = noise(20_000, 1);
    let mut v2 = v1.clone();
    v2[100] ^= 0xff;
    v2.extend_from_slice(b"\x00tail");
    let create = git_binary_patch("img.bin", None, Some(&v1));
    assert!(create.contains("GIT binary patch\nliteral 20000\n"), "{create}");
    let id = am(&mut repo, &create).unwrap().changes[0];
    assert_eq!(read_at(&repo, &id, "img.bin"), v1);
    let change = git_binary_patch("img.bin", Some(&v1), Some(&v2));
    assert!(change.contains("\ndelta "), "git chose a delta: {change}");
    let id = am(&mut repo, &change).unwrap().changes[0];
    assert_eq!(read_at(&repo, &id, "img.bin"), v2);
    // The same delta again: made for another version, refused.
    refused(&mut repo, &change, "img.bin: the binary patch was made for another version of the file");
    let delete = git_binary_patch("img.bin", Some(&v2), None);
    let id = am(&mut repo, &delete).unwrap().changes[0];
    assert!(file_entry(&repo, &id, "img.bin").is_none());
    // `Binary files … differ` holds no content.
    let differ = "diff --git a/b.bin b/b.bin\nnew file mode 100644\nindex 0000000..1111111\nBinary files /dev/null and b/b.bin differ\n";
    refused(&mut repo, &one(differ), "holds no content");
    // A secret inside a binary literal is scanned like any content.
    let mut leaky = noise(300, 9);
    leaky.extend_from_slice(b"\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\x00");
    let r = am(&mut repo, &git_binary_patch("blob.dat", None, Some(&leaky)));
    if let Ok(r) = r {
        // Not every binary file is scanned; then it must still never be public plaintext of a secret path.
        assert!(file_entry(&repo, &r.changes[0], "blob.dat").is_some());
    } else {
        assert!(backend_contains(&*fs, b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").is_empty());
    }
}

/// Point 12 for binary sections: the `index` ids are checked (the pre-image
/// and what the section makes), an abbreviated id is refused, and a
/// declared size above `VEIL_MAX_OBJECT` is refused before anything is
/// inflated.
#[test]
fn hostile_binary_sections() {
    if !git_available() {
        return;
    }
    let (mut repo, _) = base();
    let data = noise(500, 3);
    let create = git_binary_patch("x.bin", None, Some(&data));
    let idx = create.lines().find(|l| l.starts_with("index ")).unwrap().to_string();
    let new_id = idx.split("..").nth(1).unwrap().split(' ').next().unwrap().to_string();
    // Another post-image id.
    let forged = create.replace(&new_id, &"f".repeat(40));
    refused(&mut repo, &forged, "does not make the file its 'index' line names");
    // Abbreviated ids.
    let short = create.replace(&idx, "index 0000000..1234567");
    refused(&mut repo, &short, "full object ids");
    // No index line at all.
    let none = create.replace(&format!("{idx}\n"), "");
    refused(&mut repo, &none, "without an 'index' line");
    // A declared size above the limit, refused while parsing.
    let huge = create.replace("literal 500", "literal 17179869184");
    let e = patch::parse(huge.into_bytes(), &Limits::default()).unwrap_err().to_string();
    assert!(e.contains("declares 17179869184 bytes"), "{e}");
    let small = Limits {
        max_file_size: 100,
        ..Limits::default()
    };
    let e = patch::parse(create.clone().into_bytes(), &small).unwrap_err().to_string();
    assert!(e.contains("more than 100 (VEIL_MAX_OBJECT)"), "{e}");
    // A declared size the data does not have.
    let wrong = create.replace("literal 500", "literal 499");
    refused(&mut repo, &wrong, "more than the 499 bytes it declares");
    // Binary data for a symlink is malformed.
    let link = create.replace("new file mode 100644", "new file mode 120000");
    assert!(patch::parse(link.into_bytes(), &Limits::default()).unwrap_err().to_string().contains("binary data for a symlink"));
}

// ---- --3way ------------------------------------------------------------------------

fn three() -> AmOptions {
    AmOptions {
        three_way: true,
        ..AmOptions::default()
    }
}

fn blob_id(data: &[u8]) -> String {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("f"), data).unwrap();
    String::from_utf8(git(tmp.path(), &["hash-object", "f"])).unwrap().trim().to_string()
}

const V1: &str = "1\n2\n3\n4\n5\n6\n7\n8\n9\n";

/// A patch made against `from` (a version of `f.txt`) turning `edit` into
/// `to` on that version, with its real `index` line.
fn made_on(from: &str, edit: (&str, &str)) -> String {
    let to = from.replacen(edit.0, edit.1, 1);
    let (o, n) = (blob_id(from.as_bytes()), blob_id(to.as_bytes()));
    let mut diff = format!("diff --git a/f.txt b/f.txt\nindex {}..{} 100644\n--- a/f.txt\n+++ b/f.txt\n", &o[..7], &n[..7]);
    let lines: Vec<&str> = from.lines().collect();
    let at = lines.iter().position(|l| *l == edit.0.trim_end()).unwrap();
    let (s, e) = (at.saturating_sub(3), (at + 4).min(lines.len()));
    diff.push_str(&format!("@@ -{},{} +{},{} @@\n", s + 1, e - s, s + 1, e - s));
    for (i, l) in lines[s..e].iter().enumerate() {
        if s + i == at {
            diff.push_str(&format!("-{l}\n+{}\n", edit.1.trim_end()));
        } else {
            diff.push_str(&format!(" {l}\n"));
        }
    }
    one(&diff)
}

/// A hunk whose context changed since merges with the pre-image from this
/// repository's history (an ancestor, or a later version on another line);
/// without `--3way`, or without the pre-image, it does not apply.
#[test]
fn three_way_merges_cleanly_with_a_preimage_from_history() {
    if !git_available() {
        return;
    }
    let (mut repo, fs, _) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[("f.txt", V1)], "v1");
    let patch = made_on(V1, ("5\n", "FIVE\n"));
    // Here: line 2 changed (the hunk's context).
    let v2 = V1.replace("2\n", "TWO\n");
    commit_files(&mut repo, &*fs, &[("f.txt", &v2)], "v2");
    refused(&mut repo, &patch, "does not apply");
    let r = am_with(&mut repo, &patch, &three()).unwrap();
    assert_eq!(r.merged.len(), 1, "{r:?}\n{patch}");
    assert!(r.conflicts.is_empty());
    assert_eq!(read_at(&repo, &r.changes[0], "f.txt"), V1.replace("2\n", "TWO\n").replace("5\n", "FIVE\n").as_bytes());
    // The pre-image may be on a later line than the destination too: a
    // patch made on `v2`, applied on `v1`.
    let on_v2 = made_on(&v2, ("4\n", "FOUR\n"));
    let v1 = repo.snapshot(&r.changes[0]).unwrap().parents[0];
    let v1 = repo.snapshot(&v1).unwrap().parents[0];
    repo.new_change(WS, vec![v1], "").unwrap();
    let r = am_with(&mut repo, &on_v2, &three()).unwrap();
    assert_eq!(r.merged.len(), 1, "{r:?}");
    assert_eq!(read_at(&repo, &r.changes[0], "f.txt"), V1.replace("4\n", "FOUR\n").as_bytes());
    // A pre-image nobody here ever had: still refused.
    let unknown = made_on("x\n1\n2\n3\n4\n5\n6\n", ("3\n", "THREE\n"));
    refused_with(&mut repo, &unknown, &three(), "does not apply");
}

/// A real conflict is recorded as a first-class conflict (base, ours,
/// theirs), the series is applied, and the working copy shows it.
#[test]
fn three_way_conflicts_are_first_class() {
    if !git_available() {
        return;
    }
    let (mut repo, fs, _) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[("f.txt", V1)], "v1");
    let patch = made_on(V1, ("5\n", "FIVE-THEIRS\n"));
    commit_files(&mut repo, &*fs, &[("f.txt", &V1.replace("5\n", "FIVE-OURS\n"))], "ours");
    let r = am_with(&mut repo, &patch, &three()).unwrap();
    assert_eq!(r.conflicts.len(), 1);
    let id = r.changes[0];
    let e = file_entry(&repo, &id, "f.txt").unwrap();
    assert_eq!(e.kind, EntryKind::Conflict);
    let c = repo.store().conflict(&e.id).unwrap();
    assert_eq!((c.adds.len(), c.removes.len()), (2, 1));
    let text = String::from_utf8(read_at(&repo, &id, "f.txt")).unwrap();
    assert!(text.contains("FIVE-OURS") && text.contains("FIVE-THEIRS"), "{text}");
    assert!(repo.snapshot(&id).unwrap().conflicts.contains(&"f.txt".to_string()));
}

/// Confidentiality of `--3way`: a conflict in a cloaked file keeps every
/// version sealed (the patch's side too), so a public push holds none of
/// them; and a pre-image this reader cannot open is never used.
#[test]
fn three_way_keeps_sealed_files_sealed() {
    if !git_available() {
        return;
    }
    let (mut repo, fs) = base();
    let v1 = "S1\nS2\nS3\nS4\nS5\nS6\nS7\n";
    commit_files(&mut repo, &*fs, &[("secrets/conf.txt", v1)], "v1");
    let patch = made_on(v1, ("S4\n", "THEIRS-SEALED-44\n")).replace("f.txt", "secrets/conf.txt");
    commit_files(&mut repo, &*fs, &[("secrets/conf.txt", &v1.replace("S4\n", "OURS-SEALED-44\n"))], "ours");
    let r = am_with(&mut repo, &patch, &three()).unwrap();
    let id = r.changes[0];
    let e = file_entry(&repo, &id, "secrets/conf.txt").unwrap();
    assert_eq!(e.kind, EntryKind::Conflict);
    for (vis, data) in versions(&repo, &e) {
        assert!(matches!(vis, Visibility::Cloaked { .. }), "{vis:?} {data:?}");
    }
    // The store holds no plaintext of any version (the working copy holds
    // the markers, for its reader).
    for (_, raw) in all_objects(&*fs).into_iter().chain(packed_objects(&*fs)) {
        for s in [&b"THEIRS-SEALED-44"[..], b"OURS-SEALED-44", b"S1\nS2"] {
            assert!(!raw.windows(s.len()).any(|w| w == s));
        }
    }
    repo.set_tag("main", id, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut repo, mirror.clone(), true, &[], false).unwrap();
    for s in [&b"THEIRS-SEALED-44"[..], b"OURS-SEALED-44", b"S1\nS2"] {
        assert!(backend_contains(&*mirror, s).is_empty());
    }

    // Bob, without the key: the pre-image is sealed, so there is none.
    let main = repo.snapshot(&id).unwrap().parents[0];
    repo.set_tag("main", main, None, true).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut repo, hub.clone(), false, &[], false).unwrap();
    let mut bob = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(Identity::generate("bob")), "bob").unwrap();
    remote::pull(&mut bob, "origin", hub).unwrap();
    bob.new_change(WS, vec![main], "").unwrap();
    refused_with(&mut bob, &patch, &three(), "cannot apply to sealed file secrets/conf.txt");
}
