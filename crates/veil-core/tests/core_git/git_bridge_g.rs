//! Git-parity stream G: symlinks, submodules and tags through the Git
//! bridge, against a real Git repository driven with the system `git`
//! (offline: every remote is a local bare repository).
//!
//! The threat reviews of `docs/design/git-parity/8-bridge-tags.md`,
//! `5-hooks-submodules-signed-tags.md` (5b, 5c) and `6-symlinks.md` (the
//! bridge parts) are tested here point by point; the CLI side is in
//! `crates/vl/tests/cli_sync/git_parity_g_cli.rs`.

#![cfg(feature = "git")]

use crate::adversarial_support;

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use adversarial_support::*;
use veil_core::{
    commands::{EmbargoSpec, TagSpec},
    git::{self, FetchOptions, PushOptions, RefStatus},
    object::Text,
    oplog::Tag,
    tag_object::{AtagKind, AtagVerification},
    EntryKind, ObjectId, Repo, Snapshot, TreeEntry, Visibility,
};

// ---- helpers -------------------------------------------------------------------

fn git_cmd(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Vec<u8> {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Gita Hub")
        .env("GIT_AUTHOR_EMAIL", "gita@example.com")
        .env("GIT_COMMITTER_NAME", "Gita Hub")
        .env("GIT_COMMITTER_EMAIL", "gita@example.com")
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
        .args(["-c", "advice.detachedHead=false", "-c", "core.symlinks=true"])
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().expect("git is installed");
    if let Some(data) = stdin {
        child.stdin.take().unwrap().write_all(data).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

fn git(dir: &Path, args: &[&str]) -> String {
    String::from_utf8(git_cmd(dir, args, None)).unwrap().trim().to_string()
}

/// `git hash-object -w` of raw bytes as an object of `kind` (no checks:
/// hostile objects too).
fn put_object(dir: &Path, kind: &str, data: &[u8]) -> String {
    String::from_utf8(git_cmd(dir, &["hash-object", "-t", kind, "-w", "--stdin", "--literally"], Some(data)))
        .unwrap()
        .trim()
        .to_string()
}

/// A tree from `mktree` lines (`<mode> <type> <oid>\t<name>`).
fn mktree(dir: &Path, lines: &[String]) -> String {
    let text = lines.join("\n") + "\n";
    String::from_utf8(git_cmd(dir, &["mktree", "--missing"], Some(text.as_bytes())))
        .unwrap()
        .trim()
        .to_string()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Every object of a Git repository (loose and packed), decompressed.
fn all_git_objects(git_dir: &Path) -> Vec<u8> {
    git_cmd(git_dir, &["cat-file", "--batch-all-objects", "--batch"], None)
}

struct Env {
    tmp: tempfile::TempDir,
    bare: PathBuf,
    bridge: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let bare = tmp.path().join("remote.git");
        git(tmp.path(), &["init", "--bare", "-q", bare.to_str().unwrap()]);
        let bridge = tmp.path().join("bridge.git");
        Env { tmp, bare, bridge }
    }

    fn url(&self) -> &str {
        self.bare.to_str().unwrap()
    }

    fn clone_work(&self, name: &str) -> PathBuf {
        let work = self.tmp.path().join(name);
        git(self.tmp.path(), &["clone", "-q", self.url(), work.to_str().unwrap()]);
        work
    }

    fn connect(&self, repo: &mut Repo) {
        git::remote_add(repo, "github", self.url()).unwrap();
    }

    fn push(&self, repo: &mut Repo) -> git::PushReport {
        git::push(repo, &self.bridge, "github", &[], false).unwrap()
    }

    fn push_with(&self, repo: &mut Repo, opts: &PushOptions) -> git::PushReport {
        git::push_with(repo, &self.bridge, "github", opts).unwrap()
    }

    fn pull(&self, repo: &mut Repo) -> git::FetchReport {
        git::pull(repo, &self.bridge, "github").unwrap()
    }

    fn fetch(&self, repo: &mut Repo) -> git::FetchReport {
        git::fetch(repo, &self.bridge, "github").unwrap()
    }

    fn rev(&self, spec: &str) -> String {
        git(&self.bare, &["rev-parse", spec])
    }
}

const POLICY: &str = "secrets/ cloak team\n";

/// A project tagged `main` with a public file and a cloaked directory.
fn project() -> (Repo, std::sync::Arc<veil_core::MemoryBackend>, ObjectId) {
    let (mut r, fs, _) = new_repo("alice");
    let c1 = commit_files(&mut r, &*fs, &[(".veilpolicy", POLICY), ("README.md", "hello\n"), ("secrets/key.txt", "k\n")], "first");
    r.set_tag("main", c1, None, false).unwrap();
    (r, fs, c1)
}

/// Commit `@` with entry `path` set to a `kind` entry holding `content`
/// under `vis` (the working-copy builder cannot record links yet: stream
/// W1). Returns the committed snapshot.
fn commit_entry(r: &mut Repo, path: &str, kind: EntryKind, content: &[u8], vis: Visibility, msg: &str) -> ObjectId {
    let wc = r.workspace_wc(WS).unwrap();
    let s = r.snapshot(&wc).unwrap();
    let id = r.store().store_file(content, &vis).unwrap();
    let e = TreeEntry {
        name: p(path).file_name().to_string(),
        kind,
        id,
        size: content.len() as u64,
        executable: false,
        visibility: vis,
        fallback: None,
    };
    let tree = veil_core::selection::edit_tree(r.store(), &s.tree, vec![(p(path), Some(e))]).unwrap();
    let mut tx = r.transaction("test: set entry").unwrap();
    let nid = tx.rewrite(wc, Snapshot { tree, ..(*s).clone() }).unwrap();
    tx.set_workspace_wc(WS, nid).unwrap();
    tx.commit().unwrap();
    let (c, _) = r.commit_working_copy(WS, msg).unwrap();
    c
}

fn entry(r: &Repo, rev: &ObjectId, path: &str) -> TreeEntry {
    file_entry(r, rev, path).unwrap_or_else(|| panic!("{path} is not in the tree"))
}

fn annotate(r: &mut Repo, name: &str, target: ObjectId, msg: &str, cloak: Option<&str>) {
    r.set_tag_with(
        name,
        target,
        &TagSpec {
            annotate: Some(msg.into()),
            cloak: cloak.map(str::to_string),
            ..TagSpec::default()
        },
    )
    .unwrap();
}

fn ls_tree(dir: &Path, rev: &str) -> String {
    git(dir, &["ls-tree", "-r", rev])
}

// ---- symlinks and submodules ------------------------------------------------------

/// A Git repository with a symlink, an absolute symlink and a submodule
/// round-trips through Veil unchanged, and Git-side edits of them import.
#[test]
fn symlinks_and_submodules_round_trip_through_git() {
    let env = Env::new();
    let work = env.clone_work("work");
    std::fs::write(work.join("a.txt"), "hi\n").unwrap();
    std::os::unix::fs::symlink("a.txt", work.join("link")).unwrap();
    std::os::unix::fs::symlink("/usr/share/dict/words", work.join("abs")).unwrap();
    let pin = "1111111111111111111111111111111111111111";
    std::fs::write(work.join(".gitmodules"), "[submodule \"lib\"]\n\tpath = vendor/lib\n\turl = https://example.com/lib.git\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["update-index", "--add", "--cacheinfo", &format!("160000,{pin},vendor/lib")]);
    git(&work, &["commit", "-q", "-m", "links"]);
    git(&work, &["push", "-q", "origin", "main"]);
    let original = git(&work, &["rev-parse", "HEAD"]);

    let (mut r, _fs, _) = new_repo("alice");
    env.connect(&mut r);
    let rep = env.pull(&mut r);
    assert!(rep.import.left_in_git.is_empty(), "{:?}", rep.import.left_in_git);
    let main = r.view().tags["main"].target;
    let link = entry(&r, &main, "link");
    assert_eq!((link.kind, read_at(&r, &main, "link")), (EntryKind::Symlink, b"a.txt".to_vec()));
    assert_eq!(read_at(&r, &main, "abs"), b"/usr/share/dict/words");
    let sub = entry(&r, &main, "vendor/lib");
    assert_eq!((sub.kind, read_at(&r, &main, "vendor/lib")), (EntryKind::Gitlink, format!("{pin}\n").into_bytes()));

    // A Veil commit on top keeps them; Git gets them back byte for byte.
    r.new_change(WS, vec![main], "").unwrap();
    let c2 = commit_entry(&mut r, "a.txt", EntryKind::File, b"hi from veil\n", Visibility::Public, "veil edit");
    assert_eq!(r.snapshot(&c2).unwrap().parents, vec![main]);
    assert_eq!(r.view().tags["main"].target, c2, "the commit advanced main");
    let rep = env.push(&mut r);
    assert_eq!(rep.outcome.refs, vec![("main".into(), RefStatus::FastForward)], "{rep:?}");
    let tree = ls_tree(&env.bare, "main");
    assert!(tree.contains(&format!("160000 commit {pin}\tvendor/lib")), "{tree}");
    let old = ls_tree(&env.bare, &original);
    for line in old.lines().filter(|l| l.starts_with("120000") || l.starts_with("160000")) {
        assert!(tree.contains(line), "{line} changed in {tree}");
    }
    assert_eq!(git(&env.bare, &["rev-parse", "main^"]), original);

    // Git edits a link, deletes one and moves the pin: Veil follows.
    git(&work, &["pull", "-q", "origin", "main"]);
    std::fs::remove_file(work.join("link")).unwrap();
    std::os::unix::fs::symlink("README", work.join("link")).unwrap();
    std::fs::remove_file(work.join("abs")).unwrap();
    let pin2 = "2222222222222222222222222222222222222222";
    git(&work, &["add", "-A"]);
    git(&work, &["update-index", "--add", "--cacheinfo", &format!("160000,{pin2},vendor/lib")]);
    git(&work, &["commit", "-q", "-m", "move links"]);
    git(&work, &["push", "-q", "origin", "main"]);
    env.pull(&mut r);
    let m = r.view().tags["main"].target;
    assert_eq!(read_at(&r, &m, "link"), b"README");
    assert!(file_entry(&r, &m, "abs").is_none(), "Git deleted it");
    assert_eq!(read_at(&r, &m, "vendor/lib"), format!("{pin2}\n").into_bytes());
    assert_eq!(read_at(&r, &m, "a.txt"), b"hi from veil\n");
    // Pushing back changes nothing.
    assert_eq!(env.push(&mut r).export.written, 0);
}

/// Threat 6.6 / 5b.14: a cloaked symlink's target and a sealed gitlink's
/// commit never reach Git; a public `.gitmodules` naming the sealed
/// submodule is warned about, never rewritten.
#[test]
fn cloaked_links_never_reach_git() {
    let env = Env::new();
    let (mut r, fs, _) = project();
    commit_files(&mut r, &*fs, &[(".gitmodules", "[submodule \"p\"]\n\tpath = secrets/private\n\turl = https://example.com/p.git\n")], "gitmodules");
    let target = b"/srv/acme-secret-merger/build";
    let team = Visibility::Cloaked { scope: "team".into() };
    commit_entry(&mut r, "secrets/current", EntryKind::Symlink, target, team.clone(), "cloaked link");
    let sealed_pin = "5ea1ed5ea1ed5ea1ed5ea1ed5ea1ed5ea1ed5ea1";
    commit_entry(&mut r, "secrets/private", EntryKind::Gitlink, format!("{sealed_pin}\n").as_bytes(), team, "sealed pin");
    let c = commit_entry(&mut r, "docs", EntryKind::Symlink, b"README.md", Visibility::Public, "public link");
    r.set_tag("main", c, None, false).unwrap();
    env.connect(&mut r);
    let rep = env.push(&mut r);
    assert!(
        rep.export.warnings.iter().any(|w| w.contains(".gitmodules names 'secrets/private'")),
        "{:?}",
        rep.export.warnings
    );
    let tree = ls_tree(&env.bare, "main");
    assert!(tree.contains("120000 blob") && tree.contains("\tdocs"), "{tree}");
    assert!(!tree.contains("160000"), "a sealed gitlink reached Git: {tree}");
    assert!(!tree.contains("secrets/"), "{tree}");
    for dir in [&env.bare, &env.bridge] {
        let objects = all_git_objects(dir);
        assert!(!contains(&objects, target), "the cloaked target reached {}", dir.display());
        assert!(!contains(&objects, sealed_pin.as_bytes()), "the sealed pin reached {}", dir.display());
        let bin = hex::decode(sealed_pin).unwrap();
        assert!(!contains(&objects, &bin), "the sealed pin (binary) reached {}", dir.display());
    }
}

/// Threats 6.5, 6.13, 6.14, 5b.10 (on import): hostile Git links are left
/// in Git with a reason; nothing of them is recorded; a Veil commit on top
/// carries them over unchanged.
#[test]
fn hostile_git_links_are_left_in_git() {
    let env = Env::new();
    let b = &env.bare;
    let readme = put_object(b, "blob", b"hello\n");
    let nul = put_object(b, "blob", b"a\0b");
    let long = put_object(b, "blob", "x".repeat(5000).as_bytes());
    let latin1 = put_object(b, "blob", b"caf\xe9");
    let token = put_object(b, "blob", b"https://bob:ghp_0123456789abcdefghijABCDEFGHIJ012345@github.com/o/r");
    let fine = put_object(b, "blob", b"README");
    let deploy = mktree(b, &[format!("120000 blob {fine}\tid_ed25519")]);
    let tree = mktree(
        b,
        &[
            format!("100644 blob {readme}\tREADME"),
            format!("120000 blob {nul}\tnul"),
            format!("120000 blob {long}\tlong"),
            format!("120000 blob {latin1}\tlatin1"),
            format!("120000 blob {token}\ttoken"),
            format!("120000 blob {fine}\t.gitmodules"),
            format!("040000 tree {deploy}\tdeploy"),
            format!("120000 blob {fine}\tok"),
        ],
    );
    let commit = git(b, &["commit-tree", &tree, "-m", "hostile links"]);
    git(b, &["update-ref", "refs/heads/main", &commit]);

    let (mut r, fs, _) = new_repo("alice");
    env.connect(&mut r);
    let rep = env.pull(&mut r);
    assert!(rep.import.failed.is_empty(), "{:?}", rep.import.failed);
    let left = &rep.import.left_in_git;
    for (path, why) in [
        ("nul", "NUL"),
        ("long", "over 4096"),
        ("latin1", "UTF-8"),
        ("token", "quarantined"),
        (".gitmodules", ".gitmodules"),
        ("deploy/id_ed25519", "isolated"),
    ] {
        let reason = left.get(path).unwrap_or_else(|| panic!("{path} recorded: {left:?}"));
        assert!(reason.contains(why), "{path}: {reason}");
    }
    let main = r.view().tags["main"].target;
    assert_eq!(read_at(&r, &main, "ok"), b"README");
    for path in ["nul", "long", "latin1", "token", ".gitmodules", "deploy/id_ed25519"] {
        assert!(file_entry(&r, &main, path).is_none(), "{path} is in the tree");
    }
    assert!(backend_contains(&*fs, b"ghp_0123456789abcdefghij").is_empty(), "the token entered the store");
    // A Veil commit on top: Git keeps what Veil never recorded.
    r.new_change(WS, vec![main], "").unwrap();
    commit_entry(&mut r, "new-link", EntryKind::Symlink, b"ok", Visibility::Public, "veil");
    env.push(&mut r);
    let after = ls_tree(b, "main");
    for name in ["\tnul", "\tlong", "\tlatin1", "\ttoken", "\t.gitmodules", "deploy/id_ed25519", "\tnew-link"] {
        assert!(after.contains(name), "{name} lost: {after}");
    }
}

/// A Git symlink at a path the Veil policy cloaks is sealed under that
/// scope on import (its target can name private paths).
#[test]
fn a_git_link_at_a_cloaked_path_is_sealed() {
    let env = Env::new();
    let (mut r, _fs, _) = project();
    env.connect(&mut r);
    env.push(&mut r);
    let work = env.clone_work("work");
    std::fs::create_dir_all(work.join("secrets")).unwrap();
    std::os::unix::fs::symlink("/srv/private-target", work.join("secrets/current")).unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "link in a cloaked dir"]);
    git(&work, &["push", "-q", "origin", "main"]);
    env.pull(&mut r);
    let main = r.view().tags["main"].target;
    let e = entry(&r, &main, "secrets/current");
    assert_eq!((e.kind, e.visibility.clone()), (EntryKind::Symlink, Visibility::Cloaked { scope: "team".into() }));
    assert_eq!(read_at(&r, &main, "secrets/current"), b"/srv/private-target");
    // Git had it already (it was committed there); the next export keeps
    // Git's copy (carry-over) and never re-publishes it from Veil.
    env.push(&mut r);
    assert!(ls_tree(&env.bare, "main").contains("secrets/current"));
}

// ---- release tags --------------------------------------------------------------

fn junk_signed_tag(dir: &Path, name: &str, commit: &str) -> String {
    let raw = format!(
        "object {commit}\ntype commit\ntag {name}\ntagger Mallory <m@example.com> 1700000000 +0000\n\nsigned release\n-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEEjunkjunkjunk\n=abcd\n-----END PGP SIGNATURE-----\n"
    );
    put_object(dir, "tag", raw.as_bytes())
}

/// Lightweight, annotated and GPG-signed Git tags import as release tags
/// and export back byte for byte; a Veil annotated tag exports as a fresh
/// Git annotated tag. Threat 8.8 / 5c.19: a Git signature is kept, never
/// verified. Threat 8.12: with the map lost, nothing is re-imported or
/// re-pushed.
#[test]
fn git_tags_round_trip_as_release_tags() {
    let env = Env::new();
    let work = env.clone_work("work");
    std::fs::write(work.join("a.txt"), "1\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "one"]);
    git(&work, &["tag", "v0.1"]);
    git(&work, &["tag", "-a", "v1.0", "-m", "Release 1.0"]);
    let head = git(&work, &["rev-parse", "HEAD"]);
    git(&work, &["push", "-q", "origin", "main", "--tags"]);
    let signed = junk_signed_tag(&env.bare, "v1.1", &head);
    git(&env.bare, &["update-ref", "refs/tags/v1.1", &signed]);
    let annotated = env.rev("refs/tags/v1.0");

    let (mut r, _fs, _) = new_repo("alice");
    env.connect(&mut r);
    let rep = env.pull(&mut r);
    assert!(rep.tags_skipped.is_empty(), "{:?}", rep.tags_skipped);
    let mut created: Vec<&str> = rep.release_tags_created.iter().map(|(n, _)| n.as_str()).collect();
    created.sort();
    assert_eq!(created, ["v0.1", "v1.0", "v1.1"]);
    let main = r.view().tags["main"].target;
    for t in ["v0.1", "v1.0", "v1.1"] {
        assert_eq!(r.view().tags[t].target, main);
        assert!(r.view().tags[t].annotation.is_some());
        assert!(r.view().remote_release_tags.contains_key(&format!("github/{t}")));
    }
    let c = r.tag_annotation("v0.1").unwrap().unwrap();
    assert_eq!(c.atag.kind, AtagKind::LightweightGit);
    let c = r.tag_annotation("v1.0").unwrap().unwrap();
    assert_eq!((c.atag.kind, c.message.as_deref()), (AtagKind::Annotated, Some("Release 1.0")));
    assert_eq!(c.atag.tagger, "Gita Hub <gita@example.com>");
    let c = r.tag_annotation("v1.1").unwrap().unwrap();
    assert_eq!(c.verification, AtagVerification::GitSignatureNotVerified);
    assert!(!c.verified);
    // `origin/<tag>` and `tag:origin/<tag>` resolve.
    assert_eq!(veil_core::revset::resolve(&r, "github/v1.0", WS).unwrap(), main);
    assert_eq!(veil_core::revset::resolve(&r, "tag:github/v1.1", WS).unwrap(), main);

    // A Veil release tag, signed by alice.
    annotate(&mut r, "v2.0", main, "Veil release\n\nNotes.", None);
    let c = r.tag_annotation("v2.0").unwrap().unwrap();
    assert!(c.verified, "{:?}", c.verification);
    let rep = env.push(&mut r);
    let mut tags: Vec<(String, RefStatus)> = rep.outcome.tags.clone();
    tags.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        tags,
        vec![
            ("v0.1".into(), RefStatus::UpToDate),
            ("v1.0".into(), RefStatus::UpToDate),
            ("v1.1".into(), RefStatus::UpToDate),
            ("v2.0".into(), RefStatus::Created),
        ]
    );
    assert_eq!(env.rev("refs/tags/v1.0"), annotated, "the annotated tag object is kept byte for byte");
    assert_eq!(env.rev("refs/tags/v1.1"), signed, "the signed tag object is kept byte for byte");
    assert_eq!(env.rev("refs/tags/v0.1"), head, "a lightweight tag stays lightweight");
    let v2 = env.rev("refs/tags/v2.0");
    let raw = git(&env.bare, &["cat-file", "tag", &v2]);
    assert!(raw.starts_with(&format!("object {head}\ntype commit\ntag v2.0\ntagger alice <> ")), "{raw}");
    assert!(raw.ends_with("Veil release\n\nNotes."), "{raw}");
    assert!(!raw.contains("BEGIN"), "Veil never signs Git tags: {raw}");

    // Map lost: fetching and pushing again changes nothing.
    let atags = r.view().remote_release_tags.clone();
    r.backend().remove_file(&p(".veil/git/map")).unwrap();
    let rep = env.fetch(&mut r);
    assert!(rep.release_tags.is_empty() && rep.tags_moved.is_empty(), "{rep:?}");
    assert_eq!(r.view().remote_release_tags, atags);
    let rep = env.push(&mut r);
    assert!(rep.outcome.tags.iter().all(|(_, s)| *s == RefStatus::UpToDate), "{:?}", rep.outcome.tags);
    assert_eq!(env.rev("refs/tags/v2.0"), v2, "export is deterministic");
}

/// Threats 8.1 and 5c.18: a cloaked annotated tag and its message never
/// reach Git.
#[test]
fn cloaked_tags_and_their_messages_never_reach_git() {
    let env = Env::new();
    let (mut r, _fs, c1) = project();
    annotate(&mut r, "v-secret", c1, "CLOAKED-TAG-MESSAGE-9f1e", Some("team"));
    annotate(&mut r, "v1.0", c1, "PUBLIC-TAG-MESSAGE-11aa", None);
    assert!(matches!(
        r.store().atag(&r.view().tags["v-secret"].annotation.unwrap()).unwrap().message,
        Text::Sealed(_)
    ));
    env.connect(&mut r);
    let rep = env.push(&mut r);
    assert!(rep.export.skipped.iter().any(|(t, why)| t == "v-secret" && why.contains("cloaked")), "{:?}", rep.export.skipped);
    let refs = git(&env.bare, &["for-each-ref", "--format=%(refname)"]);
    assert_eq!(refs, "refs/heads/main\nrefs/tags/v1.0");
    for dir in [&env.bare, &env.bridge] {
        let objects = all_git_objects(dir);
        assert!(!contains(&objects, b"CLOAKED-TAG-MESSAGE-9f1e"), "{}", dir.display());
        assert!(!contains(&objects, b"v-secret"), "{}", dir.display());
        assert!(contains(&objects, b"PUBLIC-TAG-MESSAGE-11aa"));
    }
    // A sealed message on an uncloaked tag (a forged view) is not exported
    // either.
    let sealed = r.store().make_text("SEALED-ON-PUBLIC-TAG", Some("team")).unwrap();
    let mut a = veil_core::tag_object::Atag::annotated("v-forged", c1, sealed, "alice", 1);
    a.sign(r.identity().unwrap());
    let id = r.store().put_atag(&a).unwrap();
    let mut tx = r.transaction("forge").unwrap();
    tx.view.tags.insert(
        "v-forged".into(),
        Tag {
            target: c1,
            cloak: None,
            annotation: Some(id),
        },
    );
    tx.commit().unwrap();
    let rep = env.push(&mut r);
    assert!(rep.export.skipped.iter().any(|(t, why)| t == "v-forged" && why.contains("sealed")), "{:?}", rep.export.skipped);
    assert!(!contains(&all_git_objects(&env.bare), b"v-forged"));
}

/// Threats 8.2 and 8.3: a release tag on the fix of an unreleased embargo
/// is skipped with the push reason; one on the embargoed merge waits for
/// the release, then names the publication commit (with the fix).
#[test]
fn release_tags_wait_for_embargoes() {
    let env = Env::new();
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "fn check() -> bool { verify_signature() }\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "the fix").unwrap();
    drop(ws);
    let spec = EmbargoSpec {
        scope: "team".into(),
        until: None,
    };
    let res = alice.merge(WS, main, vec![fix], "security release", Some(spec)).unwrap();
    let embargo = res.embargo.unwrap();
    alice.set_tag("main", res.snapshot, None, false).unwrap();
    annotate(&mut alice, "fix-tag", fix, "the fix itself", None);
    annotate(&mut alice, "v1.2.1", res.snapshot, "Security release 1.2.1", None);

    env.connect(&mut alice);
    let rep = env.push(&mut alice);
    let skipped = |rep: &git::PushReport, t: &str| rep.export.skipped.iter().find(|(n, _)| n == t).map(|(_, w)| w.clone());
    assert!(skipped(&rep, "fix-tag").is_some(), "{:?}", rep.export.skipped);
    let why = skipped(&rep, "v1.2.1").expect("held back");
    assert!(why.contains(&embargo) && why.contains("waits"), "{why}");
    let refs = git(&env.bare, &["for-each-ref", "--format=%(refname)"]);
    assert_eq!(refs, "refs/heads/main", "no tag before the release");
    assert!(!contains(&all_git_objects(&env.bare), b"verify_signature"));

    alice.release_embargo(&embargo).unwrap();
    let rep = env.push(&mut alice);
    assert!(rep.outcome.tags.iter().any(|(t, s)| t == "v1.2.1" && *s == RefStatus::Created), "{:?}", rep.outcome.tags);
    let published = env.rev("refs/heads/main");
    assert_eq!(env.rev("v1.2.1^{commit}"), published, "the tag names the publication commit");
    assert!(git(&env.bare, &["show", "v1.2.1:auth.rs"]).contains("verify_signature"));
}

/// Threats 8.4, 8.5, 8.9 and 5c.21: hostile Git tags are skipped and
/// reported; the pull succeeds; no tag shadows a change id or `main`.
#[test]
fn hostile_git_tags_are_skipped() {
    let env = Env::new();
    let (mut r, _fs, c1) = project();
    env.connect(&mut r);
    env.push(&mut r);
    let b = &env.bare;
    let head = env.rev("main");
    let blob = put_object(b, "blob", b"not a commit\n");
    let tree = env.rev("main^{tree}");
    let tag_to = |name: &str, oid: &str, kind: &str| {
        let raw = format!("object {oid}\ntype {kind}\ntag {name}\ntagger M <m@x> 1 +0000\n\nm\n");
        put_object(b, "tag", raw.as_bytes())
    };
    git(b, &["update-ref", "refs/tags/to-blob", &tag_to("to-blob", &blob, "blob")]);
    git(b, &["update-ref", "refs/tags/to-tree", &tag_to("to-tree", &tree, "tree")]);
    git(b, &["update-ref", "refs/tags/lw-blob", &blob]);
    // Chains: 8 tag objects is fine, 9 is too deep.
    let mut cur = head.clone();
    let mut kind = "commit";
    for i in 0..9 {
        cur = tag_to(&format!("chain{i}"), &cur, kind);
        kind = "tag";
        if i == 7 {
            git(b, &["update-ref", "refs/tags/chain8", &cur]);
        }
    }
    git(b, &["update-ref", "refs/tags/chain9", &cur]);
    // A message over 1 MiB (the bound is checked from the object header).
    let big = format!("object {head}\ntype commit\ntag big\ntagger M <m@x> 1 +0000\n\n{}\n", "A".repeat(3 << 20));
    git(b, &["update-ref", "refs/tags/big", &put_object(b, "tag", big.as_bytes())]);
    // Terminal escapes in a message: stored as data.
    let esc = format!("object {head}\ntype commit\ntag esc\ntagger M\u{1b}[31m <m@x> 1 +0000\n\n\u{1b}]8;;http://evil\u{7}click\n");
    git(b, &["update-ref", "refs/tags/esc", &put_object(b, "tag", esc.as_bytes())]);
    // A tag named like one of this repository's change ids, and one named
    // like the branch.
    let change = r.snapshot(&c1).unwrap().change_id.display();
    let prefix = &change[..8];
    git(b, &["update-ref", &format!("refs/tags/{prefix}"), &head]);
    git(b, &["update-ref", "refs/tags/main", &head]);
    // Names Git allows and Veil refuses.
    git(b, &["update-ref", "refs/tags/v1@x", &head]);

    let rep = env.pull(&mut r);
    let skipped: std::collections::BTreeMap<String, String> = rep.tags_skipped.iter().cloned().collect();
    for (name, why) in [
        ("to-blob", "blob"),
        ("to-tree", "tree"),
        ("lw-blob", "blob"),
        ("chain9", "deeper than 8"),
        ("big", "over"),
        ("v1@x", "not a valid"),
    ] {
        let reason = skipped.get(name).unwrap_or_else(|| panic!("{name} not skipped: {skipped:?}"));
        assert!(reason.contains(why), "{name}: {reason}");
    }
    assert!(r.view().tags["chain8"].annotation.is_some(), "an 8-deep chain peels");
    assert!(r.view().tags.contains_key("esc"));
    let esc = r.tag_annotation("esc").unwrap().unwrap();
    assert!(!esc.atag.tagger.contains('\u{1b}'), "{:?}", esc.atag.tagger);
    // No shadowing: the change-id-like name is only github/<prefix>.
    assert!(!r.view().tags.contains_key(prefix), "a Git tag shadows a change id");
    assert!(r.view().remote_release_tags.contains_key(&format!("github/{prefix}")));
    assert!(rep.warnings.iter().any(|w| w.contains(prefix)), "{:?}", rep.warnings);
    // `main` stays the branch tag; the Git tag is github/main.
    assert!(r.view().tags["main"].annotation.is_none());
    assert!(r.view().remote_release_tags.contains_key("github/main"));
    assert!(rep.warnings.iter().any(|w| w.contains("both a branch and a tag named 'main'")), "{:?}", rep.warnings);
    // `main` still resolves to the branch; `tag:github/main` to the tag.
    assert_eq!(veil_core::revset::resolve(&r, "github/main", WS).unwrap(), r.view().remote_tags["github/main"]);
    veil_core::revset::resolve(&r, "tag:github/main", WS).unwrap();
}

/// Threat 8.7: a tag the remote moved is reported, recorded as the
/// remote's, and the local release tag never follows.
#[test]
fn a_moved_remote_tag_is_reported_and_never_followed() {
    let env = Env::new();
    let (mut r, fs, c1) = project();
    annotate(&mut r, "v1.0", c1, "Release", None);
    env.connect(&mut r);
    env.push(&mut r);
    let work = env.clone_work("work");
    std::fs::write(work.join("backdoor.txt"), "evil\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "evil"]);
    git(&work, &["tag", "-f", "-a", "v1.0", "-m", "Release"]);
    git(&work, &["push", "-q", "-f", "origin", "refs/tags/v1.0"]);
    git(&work, &["push", "-q", "origin", "main"]);

    let before = r.view().tags["v1.0"].clone();
    let rep = env.pull(&mut r);
    assert_eq!(rep.tags_moved.len(), 1, "{rep:?}");
    let (name, from, to) = &rep.tags_moved[0];
    assert_eq!((name.as_str(), *from), ("v1.0", c1));
    assert_ne!(*to, c1);
    assert_eq!(r.view().tags["v1.0"], before, "the local release tag moved");
    assert_eq!(rep.release_tags_kept, vec![("v1.0".to_string(), c1, *to)]);
    let remote = r.store().atag(&r.view().remote_release_tags["github/v1.0"]).unwrap();
    assert_eq!(remote.target, *to);
    // The old atag still names the old target.
    assert_eq!(r.store().atag(&before.annotation.unwrap()).unwrap().target, c1);
    let _ = fs;
    // Pushing never moves it back silently: rejected, named.
    let rep = env.push(&mut r);
    assert!(
        rep.outcome.tags.iter().any(|(t, s)| t == "v1.0" && matches!(s, RefStatus::Rejected(why) if why.contains("another target"))),
        "{:?}",
        rep.outcome.tags
    );
}

/// Git tags are never forced: a moved local release tag is rejected until
/// `--force-tags`, which is leased; `--delete-tag` needs the local tag
/// deleted first; `--prune-tags` forgets remote deletions.
#[test]
fn tag_push_is_never_forced_without_force_tags() {
    let env = Env::new();
    let (mut r, fs, c1) = project();
    annotate(&mut r, "v1.0", c1, "Release", None);
    env.connect(&mut r);
    env.push(&mut r);
    let old = env.rev("refs/tags/v1.0");
    let c2 = commit_files(&mut r, &*fs, &[("README.md", "two\n")], "two");
    r.set_tag("main", c2, None, false).unwrap();
    // Immutable here too.
    let err = r.set_tag_with("v1.0", c2, &TagSpec::default()).unwrap_err();
    assert!(err.to_string().contains("immutable"), "{err}");
    r.set_tag_with(
        "v1.0",
        c2,
        &TagSpec {
            force: true,
            ..TagSpec::default()
        },
    )
    .unwrap();
    let a = r.tag_annotation("v1.0").unwrap().unwrap();
    assert_eq!(a.message.as_deref(), Some("Release"), "--force without -m keeps the message");
    let rep = env.push(&mut r);
    assert!(matches!(&rep.outcome.tags[..], [(t, RefStatus::Rejected(_))] if t == "v1.0"), "{:?}", rep.outcome.tags);
    assert_eq!(env.rev("refs/tags/v1.0"), old);
    let rep = env.push_with(
        &mut r,
        &PushOptions {
            force_tags: true,
            ..PushOptions::default()
        },
    );
    assert!(matches!(&rep.outcome.tags[..], [(t, s)] if t == "v1.0" && s.accepted()), "{:?}", rep.outcome.tags);
    assert_eq!(env.rev("v1.0^{commit}"), env.rev("main"));
    // Delete: refused while the local tag exists, then done.
    let err = git::push_with(
        &mut r,
        &env.bridge,
        "github",
        &PushOptions {
            delete_tags: vec!["v1.0".into()],
            ..PushOptions::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("vl tag delete"), "{err}");
    r.delete_tag("v1.0").unwrap();
    let rep = env.push_with(
        &mut r,
        &PushOptions {
            delete_tags: vec!["v1.0".into()],
            ..PushOptions::default()
        },
    );
    assert_eq!(rep.outcome.tags, vec![("v1.0".into(), RefStatus::Deleted)]);
    assert!(git(&env.bare, &["tag", "-l"]).is_empty());
    assert!(!r.view().remote_release_tags.contains_key("github/v1.0"));
    // A tag deleted on the remote: kept until --prune-tags.
    annotate(&mut r, "v2.0", c2, "two", None);
    env.push(&mut r);
    env.fetch(&mut r);
    git(&env.bare, &["tag", "-d", "v2.0"]);
    let rep = env.fetch(&mut r);
    assert_eq!(rep.tags_deleted, vec!["v2.0".to_string()]);
    assert!(r.view().remote_release_tags.contains_key("github/v2.0"));
    let rep = git::fetch_with(
        &mut r,
        &env.bridge,
        "github",
        &FetchOptions {
            prune_tags: true,
            ..FetchOptions::default()
        },
    )
    .unwrap();
    assert_eq!(rep.tags_pruned, vec!["v2.0".to_string()]);
    assert!(!r.view().remote_release_tags.contains_key("github/v2.0"));
    assert!(r.view().tags.contains_key("v2.0"), "--prune-tags never deletes a local tag");
    // --no-tags: nothing about tags changes.
    git(&env.bare, &["tag", "v3.0", "main"]);
    let rep = git::fetch_with(
        &mut r,
        &env.bridge,
        "github",
        &FetchOptions {
            no_tags: true,
            ..FetchOptions::default()
        },
    )
    .unwrap();
    assert!(rep.release_tags.is_empty());
    assert!(!r.view().remote_release_tags.contains_key("github/v3.0"));
}

/// Threat 8.10: below format 5 tags are neither fetched into the view nor
/// an error, and one notice names `vl upgrade`.
#[test]
fn format_4_repositories_do_not_import_git_tags() {
    let env = Env::new();
    let work = env.clone_work("work");
    std::fs::write(work.join("a.txt"), "1\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "one"]);
    git(&work, &["tag", "-a", "v1.0", "-m", "r"]);
    git(&work, &["push", "-q", "origin", "main", "--tags"]);
    let fs = std::sync::Arc::new(veil_core::MemoryBackend::new());
    let mut r = Repo::init_for_clone_at(fs, Some(veil_core::Identity::generate("alice")), "alice", 4).unwrap();
    env.connect(&mut r);
    let rep = env.pull(&mut r);
    assert!(r.view().remote_release_tags.is_empty());
    assert!(!r.view().tags.contains_key("v1.0"));
    assert!(rep.warnings.iter().any(|w| w.contains("vl upgrade")), "{:?}", rep.warnings);
    // Annotated tags and gitlinks are refused below format 5.
    let main = r.view().tags["main"].target;
    let err = r
        .set_tag_with(
            "v2",
            main,
            &TagSpec {
                annotate: Some("x".into()),
                ..TagSpec::default()
            },
        )
        .unwrap_err();
    assert!(err.to_string().contains("vl upgrade"), "{err}");
    let err = veil_core::submodule::set_pin(&mut r, WS, &p("vendor/x"), &"a".repeat(40), true).unwrap_err();
    assert!(err.to_string().contains("vl upgrade"), "{err}");
}

// ---- immutability --------------------------------------------------------------

/// Feature 5c: a release tag is immutable (set refused without --force),
/// commits, merges and rewrites never move it, and a transplanted atag is
/// "name mismatch" (threat 5c.17).
#[test]
fn release_tags_are_immutable() {
    let (mut r, fs, c1) = project();
    annotate(&mut r, "v1.0", c1, "first release", None);
    let t = r.view().tags["v1.0"].clone();
    // Setting it again: no-op when unchanged, refused when moved.
    r.set_tag_with("v1.0", c1, &TagSpec::default()).unwrap();
    assert_eq!(r.view().tags["v1.0"], t);
    let err = r
        .set_tag_with(
            "v1.0",
            c1,
            &TagSpec {
                annotate: Some("other".into()),
                ..TagSpec::default()
            },
        )
        .unwrap_err();
    assert!(err.to_string().contains("immutable"), "{err}");
    // Annotating a plain tag needs --force.
    let err = r
        .set_tag_with(
            "main",
            c1,
            &TagSpec {
                annotate: Some("x".into()),
                ..TagSpec::default()
            },
        )
        .unwrap_err();
    assert!(err.to_string().contains("--force"), "{err}");
    // A commit on top of the tagged snapshot moves `main`, never `v1.0`.
    let c2 = commit_files(&mut r, &*fs, &[("README.md", "two\n")], "two");
    assert_eq!(r.view().tags["main"].target, c2);
    assert_eq!(r.view().tags["v1.0"], t);
    // Rewriting the tagged snapshot leaves the release tag where it was.
    r.describe(c1, "reworded").unwrap();
    assert_eq!(r.view().tags["v1.0"], t);
    let check = r.tag_annotation("v1.0").unwrap().unwrap();
    assert!(check.verified, "{:?}", check.verification);
    // A view entry naming another tag's atag is a name mismatch.
    let mut tx = r.transaction("forge").unwrap();
    tx.view.tags.insert(
        "v9.9".into(),
        Tag {
            target: c1,
            cloak: None,
            annotation: t.annotation,
        },
    );
    tx.commit().unwrap();
    let forged = r.tag_annotation("v9.9").unwrap().unwrap();
    assert!(matches!(forged.verification, AtagVerification::NameMismatch { .. }), "{:?}", forged.verification);
    assert!(!forged.verified);
}

// ---- property: nothing sealed reaches Git ----------------------------------------

/// Random mixes of tags (plain/annotated × cloaked/public) and links
/// (symlink/gitlink × cloaked/public): after every push, no sealed canary
/// is in any object of the Git remote or the bridge.
#[test]
fn property_sealed_tags_and_links_never_reach_git() {
    let mut seed: u64 = 0x5eed_6a7e;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for round in 0..6 {
        let env = Env::new();
        let (mut r, _fs, mut head) = project();
        env.connect(&mut r);
        let mut sealed: Vec<String> = Vec::new();
        for i in 0..5 {
            let cloaked = next() % 2 == 0;
            let canary = format!("CANARY-{round}-{i}-{}", if cloaked { "SEALED" } else { "PUBLIC" });
            let vis = if cloaked { Visibility::Cloaked { scope: "team".into() } } else { Visibility::Public };
            match next() % 3 {
                0 => {
                    let dir = if cloaked { "secrets" } else { "pub" };
                    head = commit_entry(&mut r, &format!("{dir}/l{i}"), EntryKind::Symlink, canary.as_bytes(), vis, "link");
                    r.set_tag("main", head, None, false).unwrap();
                }
                1 => {
                    let pin: String = format!("{:040x}", next() as u128 * 0x1_0000_0001 + i as u128);
                    let pin = &pin[pin.len() - 40..];
                    let dir = if cloaked { "secrets" } else { "pub" };
                    head = commit_entry(&mut r, &format!("{dir}/g{i}"), EntryKind::Gitlink, format!("{pin}\n").as_bytes(), vis, "pin");
                    r.set_tag("main", head, None, false).unwrap();
                    if cloaked {
                        sealed.push(pin.to_string());
                    }
                    continue;
                }
                _ => annotate(&mut r, &format!("t{round}x{i}"), head, &canary, cloaked.then_some("team")),
            }
            if cloaked {
                sealed.push(canary);
            }
        }
        env.push(&mut r);
        for dir in [&env.bare, &env.bridge] {
            let objects = all_git_objects(dir);
            for c in &sealed {
                assert!(!contains(&objects, c.as_bytes()), "round {round}: {c} reached {}", dir.display());
            }
        }
    }
}
