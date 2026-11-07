//! macOS filesystem semantics, simulated on any OS with
//! `macos_support::FoldingBackend` (APFS- and HFS+-like name folding over
//! `MemoryBackend`).
//!
//! * Engine scenarios (snapshots, commits, rebase, undo + checkout, secrets,
//!   cloaking, merges) run unchanged on a byte-exact backend and on both
//!   folding flavours.
//! * Names handed back in another normalisation form or case are not
//!   recorded as renames; new names are recorded in NFC.
//! * Trees whose names would collide on a folding filesystem are refused
//!   at checkout, before anything is written, and reported when created.
//! * `.veil` is reserved in every alias form.

use crate::macos_support;

use std::sync::Arc;

use macos_support::FoldingBackend;
use veil_core::{
    checkout::name_collisions,
    object::{is_reserved_name, Object, Tree, TreeEntry, Visibility},
    revset::resolve,
    tree::{lookup, walk_files},
    vfs::NameFolding,
    EntryKind, Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath, VeilError,
};

const WS: &str = "default";
const NFC: &str = "caf\u{e9}.txt";
const NFD: &str = "cafe\u{301}.txt";

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

type Make = fn() -> Arc<dyn StorageBackend>;

fn backends() -> [(&'static str, Make); 3] {
    [
        ("exact", || Arc::new(MemoryBackend::new())),
        ("apfs", || Arc::new(FoldingBackend::apfs())),
        ("hfs+", || Arc::new(FoldingBackend::hfs_plus())),
    ]
}

fn new_repo(make: Make) -> (Repo, Arc<dyn StorageBackend>) {
    let fs = make();
    let repo = Repo::init(fs.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    (repo, fs)
}

fn snap(repo: &mut Repo, fs: &Arc<dyn StorageBackend>) -> ObjectId {
    repo.snapshot_workspace(WS, &**fs).unwrap().snapshot
}

fn tree_of(repo: &Repo, rev: &ObjectId) -> ObjectId {
    repo.snapshot(rev).unwrap().tree
}

fn names(repo: &Repo, tree: &ObjectId) -> Vec<String> {
    walk_files(repo.store(), tree)
        .unwrap()
        .into_iter()
        .map(|(p, _)| p.to_string())
        .collect()
}

fn entry(repo: &Repo, tree: &ObjectId, path: &str) -> Option<TreeEntry> {
    lookup(repo.store(), tree, &p(path)).unwrap()
}

/// A tree built on a byte-exact backend (as a Linux teammate would).
fn exact_tree(repo: &mut Repo, files: &[(&str, &str)]) -> ObjectId {
    let ws = repo.ephemeral_workspace(repo.root_id()).unwrap();
    for (path, data) in files {
        ws.write(path, data).unwrap();
    }
    let (s, _) = repo.commit_ephemeral(&ws, "from linux").unwrap();
    tree_of(repo, &s)
}

// ---- engine scenarios on every backend ---------------------------------------

#[test]
fn snapshots_commits_and_rebase_behave_the_same_on_every_backend() {
    for (kind, make) in backends() {
        let (mut repo, fs) = new_repo(make);
        fs.write(&p("src/Main.rs"), b"fn main() {}\n").unwrap();
        fs.write(&p("README.md"), b"hello\n").unwrap();
        let wc1 = snap(&mut repo, &fs);
        let op = repo.op_id();
        assert_eq!(snap(&mut repo, &fs), wc1, "{kind}: no-op snapshot");
        assert_eq!(repo.op_id(), op, "{kind}: no new operation");
        let (first, _) = repo.commit_working_copy(WS, "first").unwrap();
        fs.write(&p("src/lib.rs"), b"pub fn f() {}\n").unwrap();
        snap(&mut repo, &fs);
        let (second, _) = repo.commit_working_copy(WS, "second").unwrap();
        assert_eq!(
            names(&repo, &tree_of(&repo, &second)),
            vec!["README.md", "src/Main.rs", "src/lib.rs"],
            "{kind}"
        );
        let new_first = repo.describe(first, "first, reworded").unwrap();
        let second_now = resolve(&repo, "@-", WS).unwrap();
        assert_ne!(second_now, second, "{kind}: child was rebased");
        assert_eq!(repo.snapshot(&second_now).unwrap().parents, vec![new_first], "{kind}");
    }
}

#[test]
fn moving_the_working_copy_between_changes_round_trips_on_every_backend() {
    for (kind, make) in backends() {
        let (mut repo, fs) = new_repo(make);
        fs.write(&p("Docs/Guide.md"), b"v1\n").unwrap();
        fs.write(&p(NFC), b"accent\n").unwrap();
        snap(&mut repo, &fs);
        let (first, _) = repo.commit_working_copy(WS, "first").unwrap();
        fs.write(&p("Docs/Guide.md"), b"v2\n").unwrap();
        fs.remove_file(&p(NFC)).unwrap();
        fs.write(&p("docs2/new.md"), b"new\n").unwrap();
        let wc = snap(&mut repo, &fs);
        let (t_first, t_wc) = (tree_of(&repo, &first), tree_of(&repo, &wc));

        // Go back to `first` (what `vl edit` does) and forth again.
        let co = repo.checkout_tree(&*fs, Some(&t_wc), &t_first).unwrap();
        assert!(co.kept_local.is_empty() && co.blocked.is_empty(), "{kind}: {co:?}");
        assert_eq!(fs.read(&p("Docs/Guide.md")).unwrap(), b"v1\n", "{kind}");
        assert!(!fs.exists(&p("docs2/new.md")).unwrap(), "{kind}");
        let (rebuilt, _) = repo.build_from(&*fs, Some(t_first)).unwrap();
        assert_eq!(rebuilt, t_first, "{kind}: checkout then snapshot changes nothing");

        repo.checkout_tree(&*fs, Some(&t_first), &t_wc).unwrap();
        let (rebuilt, _) = repo.build_from(&*fs, Some(t_wc)).unwrap();
        assert_eq!(rebuilt, t_wc, "{kind}");

        repo.undo().unwrap();
        assert!(repo.op_log(5).unwrap()[0].1.description.starts_with("undo"), "{kind}");
    }
}

#[test]
fn secrets_and_cloaking_are_enforced_on_every_backend() {
    for (kind, make) in backends() {
        let (mut repo, fs) = new_repo(make);
        // The pattern is typed in NFC, the directory created in NFD.
        fs.write(&p(".veilpolicy"), "Caf\u{e9}/ cloak team\n".as_bytes()).unwrap();
        fs.write(&p("Cafe\u{301}/.env.db"), b"password: hunter2\n").unwrap();
        fs.write(&p(".ENV"), b"DATABASE_URL=postgres://u:pw@db/prod\n").unwrap();
        fs.write(&p("config.js"), b"const key = 'AKIAIOSFODNN7EXAMPLE';\n").unwrap();
        let out = repo.snapshot_workspace(WS, &*fs).unwrap();
        let tree = tree_of(&repo, &out.snapshot);
        let files = names(&repo, &tree);
        assert!(!files.iter().any(|f| f.eq_ignore_ascii_case(".env")), "{kind}: {files:?}");
        assert!(!files.contains(&"config.js".to_string()), "{kind}: quarantined");
        let db = files.iter().find(|f| f.ends_with("/.env.db")).expect(".env.db recorded");
        let e = entry(&repo, &tree, db).unwrap();
        assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() }, "{kind}: {db}");
    }
}

#[test]
fn merges_work_on_every_backend() {
    for (kind, make) in backends() {
        let (mut repo, fs) = new_repo(make);
        fs.write(&p("pkg/A.txt"), b"a\n").unwrap();
        snap(&mut repo, &fs);
        let (base, _) = repo.commit_working_copy(WS, "base").unwrap();
        let a = repo.ephemeral_workspace(base).unwrap();
        a.write("pkg/A.txt", "agent a\n").unwrap();
        let b = repo.ephemeral_workspace(base).unwrap();
        b.write(NFC, "agent b\n").unwrap();
        let (sa, _) = repo.commit_ephemeral(&a, "a").unwrap();
        let (sb, _) = repo.commit_ephemeral(&b, "b").unwrap();
        let merged = repo.merge(WS, sa, vec![sb], "combine", None).unwrap();
        assert!(merged.conflicts.is_empty(), "{kind}");
        let t = tree_of(&repo, &merged.snapshot);
        let co = repo.checkout_tree(&*fs, Some(&tree_of(&repo, &base)), &t).unwrap();
        assert!(co.kept_local.is_empty(), "{kind}");
        assert_eq!(repo.build_from(&*fs, Some(t)).unwrap().0, t, "{kind}");
    }
}

// ---- normalisation: no phantom renames ------------------------------------------

#[test]
fn hfs_plus_hands_back_nfd_without_a_rename_being_recorded() {
    let (mut repo, fs) = new_repo(|| Arc::new(FoldingBackend::hfs_plus()));
    fs.write(&p(&format!("dir/{NFC}")), b"one\n").unwrap();
    // HFS+ stores (and lists) the decomposed form.
    let listed = fs.list_dir(&p("dir")).unwrap();
    assert_eq!(listed[0].name, NFD);
    let wc = snap(&mut repo, &fs);
    assert_eq!(names(&repo, &tree_of(&repo, &wc)), vec![format!("dir/{NFC}")], "new names are recorded in NFC");
    repo.commit_working_copy(WS, "add").unwrap();

    fs.write(&p(&format!("dir/{NFD}")), b"two\n").unwrap();
    let wc = snap(&mut repo, &fs);
    let parent = resolve(&repo, "@-", WS).unwrap();
    let changes =
        veil_core::tree::diff_trees(repo.store(), Some(&tree_of(&repo, &parent)), Some(&tree_of(&repo, &wc))).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].status(), 'M', "an edit, not a delete + add: {changes:?}");
    assert_eq!(changes[0].path.as_str(), format!("dir/{NFC}"));
}

#[test]
fn a_tree_recorded_in_either_form_checks_out_and_snapshots_unchanged() {
    for form in [NFC, NFD] {
        let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("a")), "a").unwrap();
        let tree = exact_tree(&mut repo, &[(&format!("Caf\u{e9}/{form}") as &str, "x\n"), ("b.txt", "b\n")]);
        for wc in [FoldingBackend::apfs(), FoldingBackend::hfs_plus()] {
            repo.checkout_tree(&wc, None, &tree).unwrap();
            let (rebuilt, _) = repo.build_from(&wc, Some(tree)).unwrap();
            assert_eq!(rebuilt, tree, "{:?} with {form:?}: spelling kept", wc.flavor());
        }
    }
}

#[test]
fn case_drift_keeps_the_recorded_spelling() {
    // On a case-insensitive filesystem a name that differs from the
    // recorded one only in case keeps the recorded spelling (as Git does
    // with core.ignorecase): it cannot be told from a checkout artefact.
    let (mut repo, fs) = new_repo(|| Arc::new(FoldingBackend::apfs()));
    fs.write(&p("readme"), b"hi\n").unwrap();
    snap(&mut repo, &fs);
    repo.commit_working_copy(WS, "add").unwrap();
    fs.remove_file(&p("readme")).unwrap();
    fs.write(&p("README"), b"hi\n").unwrap();
    assert_eq!(fs.list_dir(&VPath::root()).unwrap().iter().filter(|e| e.name == "README").count(), 1);
    let wc = snap(&mut repo, &fs);
    assert!(repo.is_empty_change(&wc).unwrap(), "no rename recorded");

    // A rename through an intermediate name is recorded.
    fs.remove_file(&p("README")).unwrap();
    snap(&mut repo, &fs);
    fs.write(&p("README"), b"hi\n").unwrap();
    let wc = snap(&mut repo, &fs);
    assert_eq!(names(&repo, &tree_of(&repo, &wc)), vec!["README"]);
}

#[test]
fn case_renames_from_a_teammate_check_out_exactly() {
    let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("a")), "a").unwrap();
    let before = exact_tree(&mut repo, &[("readme", "same\n"), ("Docs/a.md", "a\n"), ("Docs/b.md", "b\n")]);
    let after = exact_tree(&mut repo, &[("README", "same\n"), ("docs/a.md", "a\n"), ("docs/b.md", "b\n")]);
    for wc in [FoldingBackend::apfs(), FoldingBackend::hfs_plus()] {
        repo.checkout_tree(&wc, None, &before).unwrap();
        let co = repo.checkout_tree(&wc, Some(&before), &after).unwrap();
        assert!(co.kept_local.is_empty(), "{co:?}");
        let root: Vec<String> = wc.inner().list_dir(&VPath::root()).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(root, vec!["README", "docs"], "{:?}: new spelling on disk", wc.flavor());
        assert_eq!(repo.build_from(&wc, Some(after)).unwrap().0, after);
    }
}

#[test]
fn an_untracked_case_alias_is_never_overwritten() {
    let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("a")), "a").unwrap();
    let empty = exact_tree(&mut repo, &[("other", "o\n")]);
    let incoming = exact_tree(&mut repo, &[("other", "o\n"), ("NOTES.txt", "theirs\n")]);
    let wc = FoldingBackend::apfs();
    repo.checkout_tree(&wc, None, &empty).unwrap();
    wc.write(&p("notes.txt"), b"my local notes\n").unwrap();
    let co = repo.checkout_tree(&wc, Some(&empty), &incoming).unwrap();
    assert_eq!(co.kept_local, vec![p("NOTES.txt")]);
    assert_eq!(wc.read(&p("notes.txt")).unwrap(), b"my local notes\n");
}

// ---- collisions -----------------------------------------------------------------

#[test]
fn colliding_trees_are_refused_on_folding_backends_before_anything_is_written() {
    let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("a")), "a").unwrap();
    let cases: [&[(&str, &str)]; 3] = [
        &[("README", "upper\n"), ("readme", "lower\n"), ("z.txt", "z\n")],
        &[(NFC, "composed\n"), (NFD, "decomposed\n"), ("z.txt", "z\n")],
        &[("Src/a.rs", "a\n"), ("src/b.rs", "b\n"), ("z.txt", "z\n")],
    ];
    for files in cases {
        let tree = exact_tree(&mut repo, files);
        // Fine where names are byte-exact (Linux).
        let linux = MemoryBackend::new();
        repo.checkout_tree(&linux, None, &tree).unwrap();
        assert_eq!(repo.build_from(&linux, Some(tree)).unwrap().0, tree);

        for wc in [FoldingBackend::apfs(), FoldingBackend::hfs_plus()] {
            let err = repo.checkout_tree(&wc, None, &tree).unwrap_err();
            assert!(matches!(err, VeilError::NameCollision(_)), "{err}");
            let msg = err.to_string();
            assert!(msg.contains("Nothing in the working copy was changed"), "{msg}");
            assert!(wc.list_dir(&VPath::root()).unwrap().is_empty(), "nothing written: {files:?}");
        }
        assert_eq!(name_collisions(repo.store(), &tree, NameFolding::MACOS, None).unwrap().len(), 1);
        assert!(name_collisions(repo.store(), &tree, NameFolding::EXACT, None).unwrap().is_empty());
    }
}

#[test]
fn an_incremental_checkout_introducing_a_collision_is_refused() {
    let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("a")), "a").unwrap();
    let a = exact_tree(&mut repo, &[("lib/Util.rs", "1\n")]);
    let b = exact_tree(&mut repo, &[("lib/Util.rs", "2\n"), ("lib/util.rs", "3\n")]);
    let wc = FoldingBackend::apfs();
    repo.checkout_tree(&wc, None, &a).unwrap();
    let err = repo.checkout_tree(&wc, Some(&a), &b).unwrap_err();
    assert!(err.to_string().contains("'lib/Util.rs' and 'lib/util.rs'"), "{err}");
    assert_eq!(wc.read(&p("lib/Util.rs")).unwrap(), b"1\n", "untouched");
}

#[test]
fn the_builder_reports_collisions_it_records() {
    let (mut repo, fs) = new_repo(|| Arc::new(MemoryBackend::new()));
    fs.write(&p("a/Makefile"), b"x\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(out.report.name_collisions.is_empty());
    fs.write(&p("a/makefile"), b"y\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert_eq!(out.report.name_collisions, vec![(p("a/Makefile"), p("a/makefile"))]);
    // Reported while new, not on every later snapshot of an edited sibling.
    repo.commit_working_copy(WS, "both").unwrap();
    fs.write(&p("a/other"), b"z\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(out.report.name_collisions.is_empty(), "{:?}", out.report.name_collisions);
}

// ---- the reserved name ---------------------------------------------------------

#[test]
fn every_alias_of_dot_veil_is_reserved() {
    for alias in [
        ".veil",
        ".VEIL",
        ".Veil",
        ".v\u{200C}eil",
        ".vei\u{200D}l",
        "\u{FEFF}.veil",
        ".veil\u{200E}",
        ".\u{202A}v\u{206F}e\u{200F}i\u{202E}l",
    ] {
        assert!(is_reserved_name(alias), "{alias:?}");
    }
    for other in [".veil2", "veil", ".vei", ".v\u{e9}il", ".ve\u{301}il", "..veil", ".veil.", "x.veil"] {
        assert!(!is_reserved_name(other), "{other:?}");
    }
}

#[test]
fn trees_naming_a_dot_veil_alias_are_refused_on_decode() {
    let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("a")), "a").unwrap();
    let t = exact_tree(&mut repo, &[("f", "x\n")]);
    let blob = entry(&repo, &t, "f").unwrap().id;
    for alias in [".v\u{200C}eil", "\u{FEFF}.VEIL"] {
        let tree = Tree {
            entries: vec![TreeEntry {
                name: alias.into(),
                kind: EntryKind::File,
                id: blob,
                size: 2,
                executable: false,
                visibility: Visibility::Public,
            }],
        };
        assert!(Object::decode(&Object::Tree(tree.clone()).encode()).is_err(), "{alias:?}");
        assert!(repo.store().put_tree(&tree).is_err(), "{alias:?}");
    }
}

#[test]
fn the_builder_never_records_a_dot_veil_alias() {
    for (kind, make) in backends() {
        let (mut repo, fs) = new_repo(make);
        fs.write(&p(".v\u{200C}eil/config"), b"x\n").unwrap();
        fs.write(&p("sub/.VEIL/config"), b"x\n").unwrap();
        fs.write(&p("ok.txt"), b"ok\n").unwrap();
        let wc = snap(&mut repo, &fs);
        assert_eq!(names(&repo, &tree_of(&repo, &wc)), vec!["ok.txt"], "{kind}");
    }
}
