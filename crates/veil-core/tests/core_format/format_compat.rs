//! Repository format compatibility (see `docs/FORMAT.md`).
//!
//! * The golden fixture sets under `tests/fixtures/format-N/` were written
//!   by the release that introduced format N (`generate.sh`). This build
//!   opens format 8 only: it must open, read, verify and `fsck` the
//!   format-8 set, refuse formats 1 to 5 with what to do, and bring formats
//!   6 and 7 to format 8 with `vl upgrade` only when they hold nothing the
//!   removed encryption of non-secret content wrote, naming each thing it
//!   finds otherwise (the format-6 and format-7 sets hold such things). An
//!   old set is never changed by any of that.
//! * Every format must have a fixture set, and every encoding is pinned by
//!   `tests/fixtures/encodings.txt`: changing what is written fails here
//!   until the change ships as a new format with its own fixture. The lines
//!   of encodings that only removed features wrote stay in the file, and
//!   must be refused.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use veil_core::{
    crypto::{Envelope, Suite},
    fsck::{fsck, Severity},
    id::ChangeId,
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEncoding, TreeEntry, Visibility},
    pack::{IDX_MAGIC, PACK_MAGIC},
    remote,
    keychain::{RingOp, RING_FORMAT},
    repo::{read_config, MIN_REPO_FORMAT, MIN_UPGRADE_FORMAT, REPO_FORMAT},
    tree::{lookup, walk_files},
    upgrade::{upgrade, UpgradeOptions},
    DiskBackend, Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath, VeilError,
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dst = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), &dst).unwrap();
        }
    }
}

/// A private copy of fixture set `format-N` (opening a repository may write).
struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new(format: u32) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(format!("format-{format}"));
        copy_dir(&fixtures().join(format!("format-{format}")), &root);
        Fixture { _tmp: tmp, root }
    }

    fn backend(&self, name: &str) -> Arc<DiskBackend> {
        Arc::new(DiskBackend::new(self.root.join(name)))
    }

    fn identity(&self, who: &str) -> Identity {
        let s = std::fs::read_to_string(self.root.join(format!("home-{who}/identity.json"))).unwrap();
        Identity::from_json(&s).unwrap()
    }

    fn open(&self, name: &str, who: Option<&str>) -> Repo {
        let id = who.map(|w| self.identity(w));
        Repo::open(self.backend(name), id, who.unwrap_or("remote")).unwrap()
    }
}

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

fn tag(repo: &Repo, name: &str) -> ObjectId {
    repo.view()
        .tags
        .get(name)
        .unwrap_or_else(|| panic!("tag {name} missing"))
        .target
}

fn read(repo: &Repo, rev: &ObjectId, path: &str) -> Option<Vec<u8>> {
    let tree = repo.snapshot(rev).unwrap().tree;
    let e = lookup(repo.store(), &tree, &p(path)).unwrap()?;
    repo.store().read_entry(&e).ok()
}

fn read_str(repo: &Repo, rev: &ObjectId, path: &str) -> Option<String> {
    read(repo, rev, path).map(|b| String::from_utf8(b).unwrap())
}

fn assert_fsck_clean(backend: Arc<dyn StorageBackend>, identity: Option<Identity>) {
    let r = fsck(backend, identity).unwrap();
    let bad: Vec<String> = r
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Corrupt | Severity::Warning))
        .map(|f| f.to_string())
        .collect();
    assert!(bad.is_empty(), "fsck: {bad:#?}");
}

/// Everything below `.veil/`, as (path, bytes), to prove a step wrote nothing.
fn veil_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(d: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for e in std::fs::read_dir(d).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                walk(&e.path(), out);
            } else {
                out.push((e.path(), std::fs::read(e.path()).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(&root.join(".veil"), &mut out);
    out.sort();
    out
}

const UNIVERSAL_ROOT: &str = "72edc798";

// ---- every format has a fixture --------------------------------------------

#[test]
fn every_repository_format_has_a_fixture_set() {
    for f in 1..=REPO_FORMAT {
        let dir = fixtures().join(format!("format-{f}"));
        // Format 9 is only ever a thin clone, which only a clone from a
        // server makes (no set on disk can be made by `generate.sh`): the
        // server's `thin` tests make one with S3's clone code, numbered as
        // S3's release wrote it, and upgrade it to 10.
        if f == veil_core::repo::PARTIAL_FORMAT && !dir.exists() {
            continue;
        }
        let cfg = read_config(&DiskBackend::new(dir.join("alice")))
            .unwrap_or_else(|e| panic!("format {f} has no fixture set at {} ({e}); run tests/fixtures/generate.sh with the release that introduces it", dir.display()));
        assert_eq!(
            cfg.format, f,
            "fixture format-{f} holds a format-{} repository",
            cfg.format
        );
        for part in ["team-remote", "public-mirror", "home-alice", "home-bob", "home-carol"] {
            assert!(dir.join(part).exists(), "fixture format-{f} lacks {part}");
        }
    }
    assert!(
        !fixtures().join(format!("format-{}", REPO_FORMAT + 1)).exists(),
        "a fixture set for a format this build does not know"
    );
}

// ---- golden encodings ------------------------------------------------------

fn sample_tree() -> Tree {
    let id = |b: u8| ObjectId([b; 32]);
    let mut t = Tree::default();
    t.insert(TreeEntry {
        name: "bin".into(),
        kind: EntryKind::Dir,
        id: id(1),
        size: 0,
        executable: false,
        visibility: Visibility::Public,
    });
    t.insert(TreeEntry {
        name: "run.sh".into(),
        kind: EntryKind::File,
        id: id(2),
        size: 300,
        executable: true,
        visibility: Visibility::Public,
    });
    t.insert(TreeEntry {
        name: ".env".into(),
        kind: EntryKind::File,
        id: id(3),
        size: 5,
        executable: false,
        visibility: Visibility::Cloaked { scope: "team".into() },
    });
    t.insert(TreeEntry {
        name: "fix.rs".into(),
        kind: EntryKind::File,
        id: id(4),
        size: 1 << 40,
        executable: false,
        visibility: Visibility::Public,
    });
    t.insert(TreeEntry {
        name: "é \"q\"\n".into(),
        kind: EntryKind::File,
        id: id(6),
        size: 0,
        executable: false,
        visibility: Visibility::Public,
    });
    t
}

fn sample_snapshot() -> Snapshot {
    let identity = Identity::from_json(
        r#"{"name":"golden","public":"veil1d0b0f3eacb2e8ab6c7b4b0d8f1b05f0a4c8a7d6e1c0e2f9b3a2a1c4d5e6f7081","secret":"0101010101010101010101010101010101010101010101010101010101010101"}"#,
    );
    let mut s = Snapshot {
        parents: vec![ObjectId([7; 32])],
        change_id: ChangeId([9; 16]),
        tree: ObjectId([8; 32]),
        description: Text::Plain("Fix the bounds check\n\nA plain description.".into()),
        author: "golden".into(),
        timestamp: 1_790_000_000_000,
        predecessors: vec![ObjectId([6; 32])],
        conflicts: vec!["a.txt".into()],
        embargo: Some("0123456789".into()),
        agent: None,
        abandoned: None,
        attempts: vec![],
        signature: None,
    };
    s.sign(&identity.unwrap());
    s
}

/// Format 10: [`sample_snapshot`] made by an agent, listing an attempt; or
/// (`abandoned`) the attempt itself.
fn golden_attributed(abandoned: bool) -> Snapshot {
    let identity = Identity::from_json(
        r#"{"name":"golden","public":"veil1d0b0f3eacb2e8ab6c7b4b0d8f1b05f0a4c8a7d6e1c0e2f9b3a2a1c4d5e6f7081","secret":"0101010101010101010101010101010101010101010101010101010101010101"}"#,
    )
    .unwrap();
    let mut s = sample_snapshot();
    s.embargo = None;
    s.agent = Some(veil_core::object::Attribution {
        agent: "claude-code/2.3 opus-5.5".into(),
        task: Some("fix the bounds check".into()),
        prompt: Some("transcript:7f3a".into()),
        run: Some("run-41".into()),
    });
    match abandoned {
        true => s.abandoned = Some("deadlocks holding the lease across memo_tips".into()),
        false => s.attempts = vec![ObjectId([5; 32])],
    }
    s.sign(&identity);
    s
}

/// The golden lines of encodings that only removed features wrote
/// (encrypted descriptions, tag messages and embargoes, fallback versions,
/// cloaked lines and workspaces; removed in format 8). They stay in the
/// file, and the objects among them must be refused.
const RETIRED: &[&str] = &[
    "tree-v1-json",
    "tree-v2-binary",
    "snapshot-full",
    "conflict",
    "tree-v2-binary-symlink",
    "atag-sealed",
    "operation-format-6",
    "operation-merge",
];

/// `name hex` per line: every encoding this build writes, pinned. Names
/// ending in `-8` replace a [`RETIRED`] line (format 8).
fn golden_encodings() -> Vec<(String, Vec<u8>)> {
    let tree = Object::Tree(sample_tree());
    vec![
        ("blob".into(), Object::Blob(b"hello\n".to_vec()).encode()),
        (
            "tree-empty".into(),
            Object::Tree(Tree::default()).encode_with(TreeEncoding::Binary),
        ),
        (
            "snapshot-root".into(),
            Object::Snapshot(Snapshot::root(ObjectId::hash(&Object::Tree(Tree::default()).encode()))).encode(),
        ),
        (
            "sealed".into(),
            Object::Sealed(Envelope {
                scope: "embargo/0123456789".into(),
                suite: Suite::XChaCha20Poly1305 { nonce: [4; 24] },
                ciphertext: vec![9; 20],
            })
            .encode(),
        ),
        // Format 3: AES-SIV (computed, so the KDF and the cipher are pinned too).
        (
            "sealed-aes-siv".into(),
            Object::Sealed(
                Envelope::seal_deterministic(&[0x42; 32], "team#0011223344556677", &Object::Blob(b"hello\n".to_vec()).encode())
                    .unwrap(),
            )
            .encode(),
        ),
        // Format 4: a binary tree holding a conflict entry.
        (
            "tree-v2-binary-conflict".into(),
            Object::Tree(Tree {
                entries: vec![
                    TreeEntry::conflict("both.txt", ObjectId([0x0c; 32])),
                    TreeEntry {
                        name: "plain.txt".into(),
                        kind: EntryKind::File,
                        id: ObjectId([0x0d; 32]),
                        size: 3,
                        executable: false,
                        visibility: Visibility::Public,
                    },
                ],
            })
            .encode_with(TreeEncoding::Binary),
        ),
        // Format 5: a conflict with symlink terms, and an annotated tag
        // (signed, with a plain message).
        ("conflict-symlink-term".into(), Object::Conflict(golden_link_conflict()).encode()),
        ("atag".into(), Object::Atag(golden_atag()).encode()),
        // Format 8: what replaces the retired lines.
        ("tree-v1-json-8".into(), tree.encode_with(TreeEncoding::Json)),
        ("tree-v2-binary-8".into(), tree.encode_with(TreeEncoding::Binary)),
        ("snapshot-full-8".into(), Object::Snapshot(sample_snapshot()).encode()),
        ("conflict-8".into(), Object::Conflict(golden_conflict()).encode()),
        ("tree-v2-binary-symlink-8".into(), Object::Tree(golden_special_tree(EntryKind::Symlink)).encode_with(TreeEncoding::Binary)),
        // Format 10: a snapshot with agent attribution and an attempt, and
        // the abandoned snapshot that records an attempt.
        ("snapshot-agent-attempts-10".into(), Object::Snapshot(golden_attributed(false)).encode()),
        ("snapshot-abandoned-10".into(), Object::Snapshot(golden_attributed(true)).encode()),
        // An operation (not an object: `.veil/ops/<id>`, its id the BLAKE3
        // of these bytes) with a workspace and rewrites (format 6), and a
        // merge of two concurrent operations.
        ("operation-format-6-8".into(), serde_json::to_vec(&golden_operation()).unwrap()),
        (
            "operation-merge-8".into(),
            serde_json::to_vec(&veil_core::oplog::Operation {
                parents: vec![ObjectId([0x61; 32]), ObjectId([0x62; 32])],
                user: "veil".into(),
                description: "merge 2 concurrent operations".into(),
                workspace: None,
                ..golden_operation()
            })
            .unwrap(),
        ),
    ]
}

/// A format-6 operation: every field set.
fn golden_operation() -> veil_core::oplog::Operation {
    let mut view = veil_core::oplog::View::default();
    view.heads.insert(ObjectId([0x51; 32]));
    view.workspaces.insert("agent-1".into(), veil_core::oplog::WorkspaceState { wc: ObjectId([0x52; 32]), id: None });
    view.tags.insert("main".into(), veil_core::oplog::Tag::new(ObjectId([0x53; 32])));
    view.remote_tags.insert("origin/main".into(), ObjectId([0x53; 32]));
    let mut rewritten = std::collections::BTreeMap::new();
    rewritten.insert(ObjectId([0x54; 32]), vec![ObjectId([0x55; 32])]);
    rewritten.insert(ObjectId([0x56; 32]), vec![]);
    veil_core::oplog::Operation {
        parents: vec![ObjectId([0x60; 32])],
        timestamp: 1_790_000_000_000,
        user: "golden".into(),
        description: "commit".into(),
        view,
        manual_undo: None,
        undo_of: Some(ObjectId([0x57; 32])),
        redo_of: None,
        workspace: Some("agent-1".into()),
        rewritten,
        restore_of: None,
    }
}

/// A tree holding `kind` entries (format 5): public with a size, and
/// sealed (a secret's link), next to a file.
fn golden_special_tree(kind: EntryKind) -> Tree {
    let e = |name: &str, n: u8| TreeEntry {
        name: name.into(),
        kind,
        id: ObjectId([n; 32]),
        size: 12,
        executable: false,
        visibility: Visibility::Public,
    };
    Tree {
        entries: vec![
            TreeEntry {
                visibility: Visibility::Cloaked { scope: "team".into() },
                ..e(".env.private", 0x33)
            },
            e("current", 0x31),
            TreeEntry {
                name: "file.txt".into(),
                kind: EntryKind::File,
                id: ObjectId([0x32; 32]),
                size: 3,
                executable: false,
                visibility: Visibility::Public,
            },
        ],
    }
}

/// A link/file conflict: ours a symlink, theirs a file, the base a cloaked
/// symlink.
fn golden_link_conflict() -> veil_core::Conflict {
    use veil_core::{object::TermKind, ConflictTerm};
    let t = |kind: TermKind, n: u8| ConflictTerm {
        kind,
        id: ObjectId([n; 32]),
        size: 7,
        executable: false,
        visibility: Visibility::Public,
    };
    veil_core::Conflict {
        adds: vec![
            Some(t(TermKind::Symlink, 0x41)),
            Some(ConflictTerm { executable: true, ..t(TermKind::File, 0x42) }),
        ],
        removes: vec![Some(ConflictTerm {
            visibility: Visibility::Cloaked { scope: "team".into() },
            ..t(TermKind::Symlink, 0x43)
        })],
    }
}

fn golden_atag() -> veil_core::tag_object::Atag {
    veil_core::tag_object::Atag {
        name: "v1.0".into(),
        target: ObjectId([0x51; 32]),
        kind: veil_core::tag_object::AtagKind::Annotated,
        message: Text::Plain("Release 1.0\n".into()),
        tagger: "alice".into(),
        timestamp: 1_767_225_600_000,
        signature: Some(veil_core::identity::Signature {
            signer: "ab".repeat(32),
            key: "cd".repeat(32),
            sig: "ef".repeat(64),
        }),
    }
}

fn golden_conflict() -> veil_core::Conflict {
    use veil_core::ConflictTerm;
    let t = |n: u8| ConflictTerm {
        kind: veil_core::object::TermKind::File,
        id: ObjectId([n; 32]),
        size: 0,
        executable: false,
        visibility: Visibility::Public,
    };
    veil_core::Conflict {
        adds: vec![
            Some(ConflictTerm { executable: true, size: 300, ..t(0x21) }),
            Some(ConflictTerm {
                visibility: Visibility::Cloaked { scope: "team".into() },
                ..t(0x22)
            }),
            None,
        ],
        removes: vec![Some(t(0x24)), Some(ConflictTerm { visibility: Visibility::Cloaked { scope: "ops".into() }, ..t(0x25) })],
    }
}

#[test]
fn encodings_match_the_golden_file() {
    let path = fixtures().join("encodings.txt");
    let actual = golden_encodings();
    let file = std::fs::read_to_string(&path).expect("tests/fixtures/encodings.txt");
    if std::env::var_os("VEIL_BLESS_ENCODINGS").is_some() {
        // Only by appending lines.
        let mut text = file.clone();
        for (n, b) in &actual {
            if !file.lines().any(|l| l.split(' ').next() == Some(n.as_str())) {
                text.push_str(&format!("{n} {}\n", hex::encode(b)));
            }
        }
        std::fs::write(&path, &text).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<(&str, &str)> = expected.lines().map(|l| l.split_once(' ').expect("`name hex`")).collect();
    for (name, bytes) in &actual {
        let line = lines.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("no golden line {name}"));
        assert_eq!(
            line.1,
            hex::encode(bytes),
            "the encoding {name} changed. That is a format change: it needs a new repository format \
             (repo::REPO_FORMAT), read support for the old encoding, a fixture set written by the \
             new release (tests/fixtures/generate.sh) and docs/FORMAT.md. Only then re-bless with \
             VEIL_BLESS_ENCODINGS=1, which only appends lines."
        );
    }
    for (name, hexed) in &lines {
        let known = actual.iter().any(|(n, _)| n == name);
        assert!(known || RETIRED.contains(name), "golden line {name} is neither written nor retired");
        if RETIRED.contains(name) {
            assert!(!known, "{name} is retired but still written");
            // What only a removed feature wrote is refused, never read.
            if !name.starts_with("operation") {
                let raw = hex::decode(hexed).unwrap();
                assert!(Object::decode(&raw).is_err(), "{name} still decodes");
            }
        }
    }
    // Every golden encoding still decodes, and decodes back to itself.
    for (name, raw) in actual {
        if name.starts_with("operation") {
            // An operation (format 6 fields): JSON, re-encodes to itself.
            let op: veil_core::oplog::Operation = serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(serde_json::to_vec(&op).unwrap(), raw, "{name} does not re-encode to itself");
            continue;
        }
        let obj = Object::decode(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
        let enc = Object::tree_encoding(&raw).unwrap_or(TreeEncoding::Json);
        assert_eq!(obj.encode_with(enc), raw, "{name} does not re-encode to itself");
    }
}

#[test]
fn universal_root_id_never_changes() {
    for enc in [TreeEncoding::Json, TreeEncoding::Binary] {
        let empty = ObjectId::hash(&Object::Tree(Tree::default()).encode_with(enc));
        let root = ObjectId::hash(&Object::Snapshot(Snapshot::root(empty)).encode());
        assert!(root.hex().starts_with(UNIVERSAL_ROOT), "{enc:?}: {root}");
    }
    for f in MIN_REPO_FORMAT..=REPO_FORMAT {
        let repo = Repo::init_bare_at(Arc::new(MemoryBackend::new()), f).unwrap();
        assert!(repo.root_id().hex().starts_with(UNIVERSAL_ROOT), "format {f}");
    }
}

// ---- formats before 8 ---------------------------------------------------------

/// Every set before format 8 is refused, by opening and by `fsck` as by
/// `vl upgrade`, with what to do, and left exactly as it was: formats 1 to
/// 5 are no longer read; formats 6 and 7 are upgraded only when they hold
/// none of what the removed encryption of non-secret content wrote, and
/// these sets hold some (an embargo record with a key, a cloaked tag, a
/// cloaked directory), each of which the refusal names.
#[test]
fn every_set_before_format_8_is_refused_and_left_unchanged() {
    for f in 1..veil_core::repo::ONLY_SECRETS_REPO_FORMAT {
        let fx = Fixture::new(f);
        let root = fx.root.join("alice");
        let before = veil_files(&root);
        let err = Repo::open(fx.backend("alice"), Some(fx.identity("alice")), "alice").unwrap_err();
        assert!(matches!(err, VeilError::Unsupported(_)), "format {f}: {err}");
        let why = err.to_string();
        let err = upgrade(fx.backend("alice"), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap_err().to_string();
        if f < MIN_UPGRADE_FORMAT {
            assert!(why.contains("no longer reads") && why.contains("vl upgrade"), "format {f}: {why}");
            assert!(err.contains("no longer reads") && err.contains("Nothing was changed"), "format {f}: {err}");
        } else {
            assert!(why.contains("Run `vl upgrade`"), "format {f}: {why}");
            assert!(err.contains("upgrade refused") && err.contains("Nothing was changed"), "format {f}: {err}");
            for named in ["embargo ", "tag 'team-only': cloaked"] {
                assert!(err.contains(named), "format {f}: the refusal does not name {named:?}: {err}");
            }
        }
        assert!(!fx.root.join("alice").join(veil_core::upgrade::JOURNAL_PATH).exists(), "format {f}: a journal was left");
        assert_eq!(veil_files(&root), before, "format {f}: a refused open or upgrade changed .veil/");
        let report = fsck(fx.backend("alice"), Some(fx.identity("alice"))).unwrap();
        if f < MIN_UPGRADE_FORMAT {
            assert!(!report.is_ok(), "format {f}: fsck accepted a format it does not read");
        }
    }
}

/// `vl upgrade --dry-run` of a set that holds removed content lists every
/// kind of it, and writes nothing.
#[test]
fn a_dry_run_lists_what_only_the_removed_encryption_wrote() {
    let fx = Fixture::new(7);
    let root = fx.root.join("alice");
    let before = veil_files(&root);
    let r = upgrade(fx.backend("alice"), Some(fx.identity("alice")), &UpgradeOptions { dry_run: true, ..Default::default() }).unwrap();
    assert_eq!((r.from, r.to), (7, REPO_FORMAT));
    let has = |s: &str| r.removed.iter().any(|f| f.contains(s));
    assert!(has("its record holds an embargo key"), "{:#?}", r.removed);
    assert!(has("tag 'team-only': cloaked"), "{:#?}", r.removed);
    assert!(has("tag 'team-release': cloaked"), "{:#?}", r.removed);
    assert!(has("annotated tag "), "{:#?}", r.removed);
    assert!(has("under an embargo") || has("encrypted directory"), "{:#?}", r.removed);
    assert!(r.notes.iter().any(|n| n.contains("would be refused")), "{:?}", r.notes);
    assert_eq!(veil_files(&root), before, "a dry run changed .veil/");
}

/// A format-6 or format-7 repository that holds only what format 8 keeps
/// (here: written by this build, then marked with the older format, as
/// such a repository is) upgrades to 8 rewriting nothing: every object,
/// operation and id stays; a secret stays sealed and readable.
#[test]
fn a_clean_format_6_or_7_repository_upgrades_keeping_every_id() {
    for from in [6, 7] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("p");
        std::fs::create_dir_all(&root).unwrap();
        let alice = Identity::generate("alice");
        let fs = Arc::new(DiskBackend::new(&root));
        let mut repo = Repo::init(fs.clone(), Some(alice.clone()), "alice").unwrap();
        std::fs::write(root.join(".veilpolicy"), ".env cloak team\n").unwrap();
        std::fs::write(root.join(".env"), "TOKEN=fixture-not-a-secret-9911\n").unwrap();
        std::fs::write(root.join("README.md"), "hello\n").unwrap();
        repo.snapshot_workspace("default", &*fs).unwrap();
        let (c, _) = repo.commit_working_copy("default", "first").unwrap();
        repo.set_tag("main", c, false).unwrap();
        drop(repo);
        let mut cfg = read_config(&*fs).unwrap();
        cfg.format = from;
        cfg.min_vl = Some(veil_core::repo::min_vl_for_format(from).into());
        fs.write(&p(".veil/repo.json"), &serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        assert!(Repo::open(fs.clone(), Some(alice.clone()), "alice").is_err(), "format {from} opened");
        let objects = |r: &Path| veil_files(r).into_iter().filter(|(p, _)| p.to_string_lossy().contains("/objects/")).collect::<Vec<_>>();
        let before = objects(&root);
        let r = upgrade(fs.clone(), Some(alice.clone()), &UpgradeOptions::default()).unwrap();
        assert!(r.removed.is_empty(), "{:?}", r.removed);
        assert_eq!((r.from, r.to), (from, REPO_FORMAT));
        assert_eq!(objects(&root), before, "the upgrade rewrote objects");
        let repo = Repo::open(fs.clone(), Some(alice), "alice").unwrap();
        assert_eq!(repo.format(), REPO_FORMAT);
        assert_eq!(tag(&repo, "main"), c);
        let tree = repo.snapshot(&c).unwrap().tree;
        let e = lookup(repo.store(), &tree, &p(".env")).unwrap().unwrap();
        assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() });
        assert!(read_str(&repo, &c, ".env").unwrap().contains("9911"));
        assert_fsck_clean(fs, None);
    }
}

// ---- format 10: agent attribution and attempts -----------------------------------

/// A format-8 repository (here: written by this build and marked with the
/// older format, as one is) opens and works as it is, but
/// refuses to store a format-10 snapshot (an attributed one, an attempt)
/// with what to do; `vl upgrade` then moves it to 10 rewriting nothing,
/// after which the same commit is stored.
#[test]
fn a_format_8_or_9_repository_refuses_format_10_snapshots_and_upgrades_rewriting_nothing() {
    // (A format-9 repository is always a thin clone: the test below, and
    // the server's `thin` tests with a clone of S3's code.)
    let from = 8;
    let (_tmp, root, fs, alice) = written_then_marked(from, |repo, root, fs| {
        std::fs::write(root.join("README.md"), "hello\n").unwrap();
        repo.snapshot_workspace("default", &**fs).unwrap();
        let (c, _) = repo.commit_working_copy("default", "first").unwrap();
        repo.set_tag("main", c, false).unwrap();
    });
    let mut repo = Repo::open(fs.clone(), Some(alice.clone()), "alice").unwrap();
    assert_eq!(repo.format(), from);
    repo.set_attribution(Some(veil_core::object::Attribution { agent: "claude-code".into(), task: None, prompt: None, run: None }));
    std::fs::write(root.join("README.md"), "by an agent\n").unwrap();
    let err = repo.snapshot_workspace("default", &*fs).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)), "format {from}: {err}");
    assert!(err.to_string().contains("vl upgrade"), "format {from}: {err}");
    // Without attribution the repository works as before.
    repo.set_attribution(None);
    let wc = repo.snapshot_workspace("default", &*fs).unwrap().snapshot;
    let e = repo.drop_attempt(wc, "dead end").unwrap_err();
    assert!(matches!(e, VeilError::Unsupported(_)), "format {from}: an attempt was stored: {e}");
    drop(repo);
    let objects = |r: &Path| veil_files(r).into_iter().filter(|(p, _)| p.to_string_lossy().contains("/objects/")).collect::<Vec<_>>();
    let before = objects(&root);
    let r = upgrade(fs.clone(), Some(alice.clone()), &UpgradeOptions::default()).unwrap();
    assert_eq!((r.from, r.to), (from, REPO_FORMAT));
    assert!(r.removed.is_empty(), "{:?}", r.removed);
    assert!(r.notes.iter().any(|n| n.contains("agent attribution")), "{:?}", r.notes);
    assert_eq!(objects(&root), before, "format {from}: the upgrade rewrote objects");
    let mut repo = Repo::open(fs.clone(), Some(alice.clone()), "alice").unwrap();
    assert_eq!(repo.format(), REPO_FORMAT);
    repo.set_attribution(Some(veil_core::object::Attribution { agent: "claude-code".into(), task: None, prompt: None, run: None }));
    std::fs::write(root.join("README.md"), "by an agent, after the upgrade\n").unwrap();
    let wc = repo.snapshot_workspace("default", &*fs).unwrap().snapshot;
    assert_eq!(repo.snapshot(&wc).unwrap().agent.as_ref().map(|a| a.agent.as_str()), Some("claude-code"));
    let out = repo.drop_attempt(wc, "dead end").unwrap();
    assert!(repo.snapshot(&out.attempt).unwrap().abandoned.is_some());
    drop(repo);
    assert_fsck_clean(fs, None);
}

/// The format-8 set upgrades to format 10 rewriting nothing, and a
/// format-8 clone refuses to pull an attributed snapshot, naming the fix.
#[test]
fn the_format_8_set_upgrades_to_10_and_a_format_8_clone_refuses_attributed_history() {
    let fx = Fixture::new(8);
    let root = fx.root.join("alice");
    let objects = |r: &Path| veil_files(r).into_iter().filter(|(p, _)| p.to_string_lossy().contains("/objects/")).collect::<Vec<_>>();
    let before = objects(&root);
    let r = upgrade(fx.backend("alice"), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap();
    assert_eq!((r.from, r.to), (8, REPO_FORMAT));
    assert_eq!(objects(&root), before);
    assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));
    // An attributed snapshot on a format-10 remote; a format-8 clone pulls.
    let remote = Arc::new(MemoryBackend::new());
    let alice = Identity::generate("alice");
    let mut a = Repo::init(Arc::new(MemoryBackend::new()), Some(alice.clone()), "alice").unwrap();
    a.set_attribution(Some(veil_core::object::Attribution { agent: "claude-code".into(), task: Some("TASK-61".into()), prompt: None, run: None }));
    let wc = a.workspace_wc("default").unwrap();
    let base = a.snapshot(&wc).unwrap().parents[0];
    let c = a.new_change("default", vec![base], "made by an agent").unwrap();
    a.set_tag("main", c, false).unwrap();
    remote::push(&mut a, remote.clone(), false, &["main".into()], false).unwrap();
    let mut old = Repo::init_for_clone_at(Arc::new(MemoryBackend::new()), Some(Identity::generate("bob")), "bob", 8).unwrap();
    let err = remote::pull(&mut old, "origin", remote).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)) && err.to_string().contains("vl upgrade"), "{err}");
    assert!(!old.view().remote_tags.contains_key("origin/main"), "the refused pull moved a tag");
}

/// The format-10 set: alice's `agent-work` carries the agent's
/// attribution, signed, and lists one attempt with its reason; both remotes
/// received both; every repository `fsck`s clean, and `upgraded/` (the
/// format-8 set after `vl upgrade`) opens at format 10.
#[test]
fn the_format_10_set_holds_attribution_and_an_attempt() {
    let fx = Fixture::new(10);
    for (name, who) in [("alice", Some("alice")), ("team-remote", None), ("public-mirror", None)] {
        let repo = fx.open(name, who);
        assert_eq!(repo.format(), 10, "{name}");
        let c = tag(&repo, "agent-work");
        let s = repo.snapshot(&c).unwrap();
        let a = s.agent.as_ref().unwrap_or_else(|| panic!("{name}: no attribution"));
        assert_eq!((a.agent.as_str(), a.task.as_deref(), a.run.as_deref()), ("fixture-agent/1.0", Some("lease fix"), Some("run-10")), "{name}");
        assert_eq!(s.signature_valid(), Some(true), "{name}");
        assert_eq!(s.attempts.len(), 1, "{name}");
        let at = repo.snapshot(&s.attempts[0]).unwrap();
        assert_eq!(at.abandoned.as_deref(), Some("deadlocks holding the lease across memo_tips"), "{name}");
        assert_eq!(at.change_id, s.change_id, "{name}");
        assert_eq!(at.signature_valid(), Some(true), "{name}");
        assert!(!repo.view().refs().contains(&s.attempts[0]), "{name}: the attempt is visible");
        drop(repo);
        assert_fsck_clean(fx.backend(name), who.map(|w| fx.identity(w)));
    }
    let id = Identity::from_json(&std::fs::read_to_string(fx.root.join("upgraded/home-alice/identity.json")).unwrap()).unwrap();
    let up = Repo::open(Arc::new(DiskBackend::new(fx.root.join("upgraded/alice"))), Some(id.clone()), "alice").unwrap();
    assert_eq!(up.format(), 10);
    drop(up);
    assert_fsck_clean(Arc::new(DiskBackend::new(fx.root.join("upgraded/alice"))), Some(id));
}

// ---- the format-8 set ------------------------------------------------------------

#[test]
fn the_format_8_set_opens_reads_and_verifies() {
    let fx = Fixture::new(8);
    let repo = fx.open("alice", Some("alice"));
    assert_eq!(repo.format(), 8);
    assert!(repo.root_id().hex().starts_with(UNIVERSAL_ROOT));
    let main = tag(&repo, "main");
    assert_eq!(read_str(&repo, &main, "README.md").as_deref(), Some("Fixture project\n"));
    assert!(read_str(&repo, &main, "src/main.rs").unwrap().contains("v3"));
    assert!(read_str(&repo, &main, "src/util/strings.rs").unwrap().contains("to_uppercase"));
    let tree = repo.snapshot(&main).unwrap().tree;
    assert!(lookup(repo.store(), &tree, &p("bin/run.sh")).unwrap().unwrap().executable);
    // A secret sealed for `team` (key generation 2), a released and an
    // unreleased embargo: plain files.
    let notes = lookup(repo.store(), &tree, &p("secrets/.env.notes")).unwrap().unwrap();
    assert_eq!(notes.visibility, Visibility::Cloaked { scope: "team".into() });
    assert_eq!(read_str(&repo, &main, "secrets/.env.notes").as_deref(), Some("team-only notes v2\n"));
    for f in ["src/fix_a.rs", "src/fix_b.rs"] {
        let e = lookup(repo.store(), &tree, &p(f)).unwrap().unwrap();
        assert!(e.visibility.is_public(), "{f}");
    }
    assert_eq!(read_str(&repo, &main, "src/fix_b.rs").as_deref(), Some("pub fn fix_b() {}\n"));
    // `vl init` seals and syncs `.env` (`cloak rule`: with no access line,
    // the admins' `team` key).
    let e = lookup(repo.store(), &tree, &p(".env")).unwrap().unwrap();
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() });
    // Nothing but secret files is sealed.
    for (path, e) in walk_files(repo.store(), &tree).unwrap() {
        assert!(e.visibility.is_public() || veil_core::policy::names_secret(path.as_str()), "{path} is sealed");
    }
    for id in repo.exact().topo_children_first([main]).unwrap() {
        let s = repo.snapshot(&id).unwrap();
        if s.parents.is_empty() {
            continue;
        }
        assert!(repo.keys().snapshot_status(&s).is_good(), "snapshot {} signature", id.short());
    }
    let ring = repo.keys().ring_state("team").unwrap().unwrap().unwrap();
    assert_eq!(ring.generation, 2);
    assert!(ring.members.values().any(|m| m.name == "bob"));
    assert!(!ring.members.values().any(|m| m.name == "carol"));
    let embargoes = repo.keys().embargoes().unwrap();
    assert_eq!(embargoes.len(), 2);
    assert_eq!(embargoes.iter().filter(|r| r.is_released()).count(), 1);
    assert_eq!(repo.vault_load().unwrap().secrets.get("API_TOKEN").map(String::as_str), Some("fixture-value"));
    let stats = repo.store().stats().unwrap();
    assert!(stats.packs >= 1 && stats.packed_objects > 0 && stats.loose_objects > 0, "{stats:?}");
    assert!(repo.store().verify_packs().unwrap().is_empty());
    assert!(veil_core::upgrade::removed_content(&(fx.backend("alice") as Arc<dyn StorageBackend>)).unwrap().is_empty());
    assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));
}

#[test]
fn the_format_8_set_keeps_key_generations_and_audiences() {
    let fx = Fixture::new(8);
    let bob = fx.open("alice", Some("bob"));
    let main = tag(&bob, "main");
    assert_eq!(read_str(&bob, &main, "secrets/.env.notes").as_deref(), Some("team-only notes v2\n"));
    // Carol was revoked before the second commit: generation 0 content only.
    let carol = fx.open("alice", Some("carol"));
    assert_eq!(read_str(&carol, &main, "secrets/.env.notes"), None);
    let first = carol
        .exact().topo_children_first([main])
        .unwrap()
        .into_iter()
        .find(|id| carol.description(&carol.snapshot(id).unwrap()) == "initial import")
        .unwrap();
    assert_eq!(read_str(&carol, &first, "secrets/.env.notes").as_deref(), Some("team-only notes v1\n"));
    let outsider = Repo::open(fx.backend("alice"), Some(Identity::generate("eve")), "eve").unwrap();
    assert_eq!(read_str(&outsider, &main, "secrets/.env.notes"), None);
}

/// The remotes: the unreleased embargo's merge and fix never left alice/
/// (nor `main`, which it holds), the public mirror holds no secret, and
/// both verify.
#[test]
fn the_format_8_set_remotes_read_and_verify() {
    let fx = Fixture::new(8);
    let alice = fx.open("alice", Some("alice"));
    let fix_b = tag(&alice, "main");
    for name in ["team-remote", "public-mirror"] {
        let r = fx.open(name, None);
        assert_eq!(r.format(), 8);
        assert_fsck_clean(fx.backend(name), None);
        assert!(r.exact().snapshot(&fix_b).unwrap().is_none(), "{name} holds the unreleased embargo's merge");
        assert!(!r.view().tags.contains_key("main"), "{name}: main builds on the unreleased embargo");
        let links = tag(&r, "links");
        assert_eq!(read_str(&r, &links, "README.md").as_deref(), Some("Fixture project\n"));
        assert_eq!(read_str(&r, &links, "src/fix_a.rs").as_deref(), Some("pub fn fix_a() {}\n"), "{name}: the released fix");
        assert_eq!(read_str(&r, &links, "secrets/.env.notes"), None, "{name}");
        for (id, bytes) in readable_bytes(&r) {
            for needle in ["fix_b", "team-only notes"] {
                assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_bytes()), "{name}: {} holds {needle:?}", id.short());
            }
        }
    }
}

// ---- format 6 and 7 additions (in the format-8 set) ---------------------------

/// Fixture generator (format 6, `generate.sh` runs it last on `alice/`):
/// concurrent operations, made with two handles whose transactions
/// interleave. First an amend of `main`'s change racing a new workspace on
/// it (merged by the next open: the merge's side carries `rewritten` and
/// `workspace`); then two tag sets left as two heads, not merged.
#[test]
#[ignore = "fixture generator: run by tests/fixtures/generate.sh"]
fn write_format_6_extras() {
    // Only as the generator (a run of every ignored test passes it by).
    let Ok(out) = std::env::var("VEIL_FIXTURE_DIR") else { return };
    let out = PathBuf::from(out);
    let identity = Identity::from_json(&std::fs::read_to_string(out.join("home-alice/identity.json")).unwrap()).unwrap();
    let open = || {
        let mut r = Repo::open(Arc::new(DiskBackend::new(out.join("alice"))), Some(identity.clone()), "alice").unwrap();
        r.set_command_workspace(Some("default".into()));
        r
    };
    let (mut a, mut b) = (open(), open());
    assert!(a.format() >= 6, "the format-6 extras go into a format-6 set or later");
    // A public change (`links`, from the format-5 extras), not `main`,
    // which an unreleased embargo withholds.
    let x = tag(&a, "links");
    let mut tx_a = a.transaction("describe").unwrap();
    let mut amended = (*tx_a.repo().snapshot(&x).unwrap()).clone();
    amended.description = Text::Plain("format 6: amended while a workspace was created on it".into());
    amended.predecessors = vec![x];
    tx_a.rewrite(x, amended).unwrap();
    let mut tx_b = b.transaction("create workspace 'concurrent'").unwrap();
    tx_b.for_workspace("concurrent");
    let wc = tx_b.new_change(vec![x], "").unwrap();
    tx_b.view.workspaces.insert("concurrent".into(), veil_core::oplog::WorkspaceState { wc, id: None });
    tx_a.commit().unwrap();
    tx_b.commit().unwrap();
    drop((a, b));
    // The next open merges them.
    let main = tag(&open(), "main");
    let (mut c, mut d) = (open(), open());
    let mut tx_c = c.transaction("set tag head-c").unwrap();
    tx_c.repository_wide();
    tx_c.view.tags.insert("head-c".into(), veil_core::oplog::Tag::new(main));
    let mut tx_d = d.transaction("set tag head-d").unwrap();
    tx_d.repository_wide();
    tx_d.view.tags.insert("head-d".into(), veil_core::oplog::Tag::new(main));
    tx_c.commit().unwrap();
    tx_d.commit().unwrap();
}

/// The fixed secret of the format-7 set's invite (a test value).
const FORMAT_7_INVITE: &str = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f";
/// The scope of the format-7 set's ring of format 4.
const FORMAT_7_SCOPE: &str = "rule-fixture";

/// Fixture generator (format 7, `generate.sh` runs it on `alice/` before
/// the pushes): a ring of format 4 (`docs/HUB.md` §13.12). alice starts
/// `rule-fixture`, invites bob, and shares the key with bob's device under
/// his join; bob (a member) shares it with a laptop of his he vouched for,
/// then removes the laptop again (`revoke_own`), rotating the key.
#[test]
#[ignore = "fixture generator: run by tests/fixtures/generate.sh"]
fn write_format_7_extras() {
    use veil_core::{
        hub::wire::{vouch_message, InviteKey},
        keychain::ShareProof,
    };
    let Ok(out) = std::env::var("VEIL_FIXTURE_DIR") else { return };
    let out = PathBuf::from(out);
    let who = |h: &str| Identity::from_json(&std::fs::read_to_string(out.join(format!("home-{h}/identity.json"))).unwrap()).unwrap();
    let (alice, bob) = (who("alice"), who("bob"));
    let repo = |id: &Identity| Repo::open(Arc::new(DiskBackend::new(out.join("alice"))), Some(id.clone()), &id.name).unwrap();
    let a = repo(&alice);
    assert!(a.format() >= 7, "the format-7 extras go into a format-7 set or later");
    let key = InviteKey::from_hex(FORMAT_7_INVITE).unwrap();
    a.keys().create_scope(FORMAT_7_SCOPE).unwrap();
    a.keys().invite(FORMAT_7_SCOPE, "bob", &key.public_hex(), 4_102_444_800_000).unwrap();
    let pid = |i: &Identity| veil_core::identity::parse_public_identity(&i.public_id()).unwrap();
    let join = ShareProof::Invite {
        key: key.public_hex(),
        signature: key.sign_join("bob", &pid(&bob)).unwrap(),
    };
    a.keys().share(FORMAT_7_SCOPE, &bob.public_id(), "bob", join).unwrap();
    drop(a);
    let b = repo(&bob);
    let laptop = Identity::generate("bob");
    let vouch = ShareProof::Vouch {
        by: bob.verifying_hex(),
        signature: bob.sign(veil_core::crypto::domains::SIG_CONTEXT_HUB_DEVICE, &vouch_message(&pid(&laptop)).unwrap()),
    };
    b.keys().share(FORMAT_7_SCOPE, &laptop.public_id(), "bob", vouch).unwrap();
    assert!(b.keys().revoke_device(FORMAT_7_SCOPE, &laptop.public_hex()).unwrap());
}

/// The format-8 set's ring of format 4 (written by the format-7 extras) verifies on this build: bob holds
/// the key through his invite, the invite is used, the laptop he removed
/// holds no current key, and the ring names its project.
#[test]
fn format_8_fixture_ring_of_format_4_verifies() {
    let fx = Fixture::new(8);
    let ring = fx.open("alice", Some("alice")).keys().load_ring(FORMAT_7_SCOPE).unwrap().expect("the set has the format-4 ring");
    assert_eq!(ring.format, veil_core::keychain::RING_FORMAT_SHARES);
    let st = ring.verify().unwrap();
    assert!(st.invites.values().all(|i| i.used));
    assert!(matches!(ring.log.last().unwrap().op, RingOp::RevokeOwn { .. }));
    assert_eq!(st.members.values().filter(|m| m.name == "bob").count(), 1);
    let bob = fx.open("alice", Some("bob"));
    assert!(bob.keys().sealing_key(FORMAT_7_SCOPE).is_ok(), "bob cannot open the key his invite gave him");
    // It names its project: the hash of the set's `team` ring's genesis
    // (BUG-845); `team` names none.
    let team = fx.open("alice", Some("alice")).keys().load_ring("team").unwrap().unwrap();
    assert!(matches!(&ring.log[0].op, RingOp::Genesis { project: Some(p), .. } if *p == team.log[0].hash("team")));
    assert!(matches!(&team.log[0].op, RingOp::Genesis { project: None, .. }));
    // The team remote holds it too.
    let remote = Repo::open(fx.backend("team-remote"), None, "remote").unwrap();
    assert_eq!(remote.keys().load_ring(FORMAT_7_SCOPE).unwrap().unwrap(), ring);
}

/// Format-6 operation fields are refused below format 6, as format-5
/// fields are below 5: an older vl must never read an operation it would
/// rewrite without them.
#[test]
fn format_6_operation_fields_are_refused_below_6() {
    let ops = veil_core::oplog::OpStore::new(Arc::new(MemoryBackend::new()));
    ops.set_format(5);
    let err = ops.put(&golden_operation()).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)), "{err}");
    let mut plain = golden_operation();
    plain.workspace = None;
    plain.rewritten.clear();
    ops.put(&plain).unwrap();
}

/// The format-8 set records concurrent operations (the format-6 extras): a merge whose side
/// carries `rewritten` and `workspace`, and two heads not merged yet. The
/// next open merges them; nothing recorded is lost.
#[test]
fn format_8_fixture_heads_merge() {
    let fx = Fixture::new(8);
    let dir = fx.root.join("alice");
    let heads: Vec<String> = std::fs::read_dir(dir.join(".veil/op_heads")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(heads.len(), 2, "the set keeps two heads: {heads:?}");
    let ops = veil_core::oplog::OpStore::new(fx.backend("alice"));
    let all: Vec<veil_core::oplog::Operation> = std::fs::read_dir(dir.join(".veil/ops")).unwrap().flatten().map(|e| ops.get(&ObjectId::from_hex(&e.file_name().to_string_lossy()).unwrap()).unwrap()).collect();
    assert!(all.iter().any(|o| o.is_merge()), "no merge operation");
    assert!(all.iter().any(|o| !o.rewritten.is_empty()), "no operation with rewrites");
    assert!(all.iter().any(|o| o.workspace.is_some()), "no operation with a workspace");
    let tags: Vec<String> = heads.iter().flat_map(|h| ops.get(&ObjectId::from_hex(h).unwrap()).unwrap().view.tags.into_keys()).collect();
    let repo = fx.open("alice", Some("alice"));
    assert_eq!(repo.heads().len(), 1);
    for t in tags {
        assert!(repo.view().tags.contains_key(&t), "tag {t} of a head was lost");
    }
    assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));
}

// ---- newer formats fail clearly ----------------------------------------------

#[test]
fn newer_repository_format_is_refused_with_the_release_it_needs() {
    let fx = Fixture::new(8);
    let fs = fx.backend("alice");
    let mut cfg = read_config(&*fs).unwrap();
    // Format 9 is a thin clone's (S3): the first unknown one is past it.
    cfg.format = veil_core::repo::MAX_REPO_FORMAT + 1;
    cfg.min_vl = None;
    fs.write(&p(".veil/repo.json"), &serde_json::to_vec_pretty(&cfg).unwrap())
        .unwrap();
    let err = Repo::open(fs.clone(), None, "x").unwrap_err();
    assert!(
        matches!(err, VeilError::Unsupported(_)) && err.to_string().contains("newer vl"),
        "{err}"
    );
    cfg.min_vl = Some("9.9.0".into());
    fs.write(&p(".veil/repo.json"), &serde_json::to_vec_pretty(&cfg).unwrap())
        .unwrap();
    let err = Repo::open(fs.clone(), None, "x").unwrap_err();
    assert!(err.to_string().contains("needs vl 9.9.0 or later"), "{err}");
    assert!(upgrade(fs.clone(), None, &UpgradeOptions::default()).is_err());
    let report = fsck(fs, None).unwrap();
    assert!(!report.is_ok());
}

#[test]
fn newer_object_encodings_are_unsupported_not_corrupt() {
    let unsupported = |raw: &[u8]| match Object::decode(raw) {
        Err(VeilError::Unsupported(m)) => assert!(m.contains("newer vl"), "{m}"),
        other => panic!("{:?} decoded as {other:?}", String::from_utf8_lossy(raw)),
    };
    unsupported(b"veil:tree\n\x03anything");
    unsupported(b"veil:tree\n\x1f");
    unsupported(b"veil:snap\n\x02");
    unsupported(b"veil:xtra\npayload");
    unsupported(b"veil:conf\n\x05");
    unsupported(b"veil:conf\n\x1f");
    unsupported(b"veil:atag\n\x05");
    unsupported(b"veil:atag\n\x1f");
    // Reserved tier in a binary tree.
    let mut t = Tree::default();
    t.insert(TreeEntry::dir("a", ObjectId([1; 32])));
    let good = Object::Tree(t).encode_with(TreeEncoding::Binary);
    let flags_at = 10 + 1 + 1 + 1 + 1; // tag, version, count, name_len, name
    // (Bit 6 is the conflict flag of format 4 and bit 7 the kind flag of
    // format 5; with a flag they exclude it is corrupt, see
    // `tree_encoding.rs`.)
    let mut raw = good.clone();
    raw[flags_at] = 0x31;
    unsupported(&raw);
    // An entry kind this build does not know (format 5: 1 symlink; 2 is
    // reserved, never reused): the kind byte follows the flags.
    for kind in [0u8, 2, 3, 0x7f, 0xff] {
        let mut raw = good.clone();
        raw[flags_at] = 0x80;
        raw.insert(flags_at + 1, kind);
        unsupported(&raw);
    }
    // A conflict term kind this build does not know (bits 6-7 = 3, or the
    // reserved 2).
    for bits in [0xC0u8, 0x80] {
        let mut c = Object::Conflict(golden_conflict()).encode();
        let first_term = 10 + 1 + 1; // tag, version, removes
        c[first_term] |= bits;
        c[first_term] &= !0x02; // and not executable
        unsupported(&c);
    }
    // But garbage is still corruption.
    for raw in [
        &b"veil:tree\n {}"[..],
        b"veil:tree\n\x00",
        b"veil:tree\n",
        b"VEIL:TREE\nx",
    ] {
        assert!(
            matches!(
                Object::decode(raw),
                Err(VeilError::Corrupt(..)) | Err(VeilError::Json(_))
            ),
            "{raw:?}"
        );
    }
    assert_eq!(PACK_MAGIC, b"VEILPAK1");
    assert_eq!(IDX_MAGIC, b"VEILIDX1");
}

#[test]
fn newer_pack_version_is_unsupported() {
    let fx = Fixture::new(8);
    // Opened once by this vl while its pack reads: the fixture's history
    // index, an older vl's (`VEILCG01`), is computed again (BUG-1381), and
    // its two operation heads merged. A repository whose index and pack are
    // both unreadable cannot settle; this test is of the pack alone.
    drop(fx.open("alice", Some("alice")));
    let dir = fx.root.join("alice/.veil/objects/pack");
    let idx = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().ends_with(".idx"))
        .unwrap()
        .path();
    let mut raw = std::fs::read(&idx).unwrap();
    raw[7] = b'2';
    std::fs::write(&idx, raw).unwrap();
    let repo = fx.open("alice", Some("alice"));
    let broken = repo.store().broken_packs().unwrap();
    assert_eq!(broken.len(), 1);
    assert!(broken[0].1.contains("newer vl"), "{broken:?}");
}

#[test]
fn newer_ring_and_embargo_formats_are_refused() {
    let fx = Fixture::new(8);
    let root = fx.root.join("alice/.veil/meta");
    let ring_path = root.join("keyrings/team.json");
    let ring = std::fs::read_to_string(&ring_path)
        .unwrap()
        .replacen("\"format\": 3", &format!("\"format\": {}", RING_FORMAT + 1), 1);
    std::fs::write(&ring_path, ring).unwrap();
    let rec = std::fs::read_dir(root.join("embargoes"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&rec).unwrap()).unwrap();
    v["format"] = (veil_core::keychain::EMBARGO_FORMAT + 1).into();
    std::fs::write(&rec, serde_json::to_vec(&v).unwrap()).unwrap();
    let repo = fx.open("alice", Some("alice"));
    let state = repo.keys().ring_state("team").unwrap().unwrap();
    assert!(state.unwrap_err().contains("newer vl"));
    let id = rec.file_stem().unwrap().to_string_lossy().to_string();
    let err = repo.keys().load_embargo(&id).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)), "{err}");
}

// ---- format 5 additions (in the format-8 set) --------------------------------

const LINK_TARGET: &str = "../README.md";
const ABSOLUTE_TARGET: &str = "/usr/share/dict/words";
/// The sealed symlink target: it names a private path.
const SEALED_TARGET: &str = "/srv/acme-secret-merger/build";
const TEAM_RELEASE_NOTES: &str = "team-only release notes: the acme merger\n";

fn special_entry(repo: &Repo, name: &str, kind: EntryKind, content: &str, vis: Visibility) -> TreeEntry {
    TreeEntry {
        name: name.into(),
        kind,
        id: repo.store().store_file(content.as_bytes(), &vis).unwrap(),
        size: content.len() as u64,
        executable: false,
        visibility: vis,
    }
}

/// The format-5 additions of the fixture set, written through the engine
/// into the `alice/` that `generate.sh` is building. `generate.sh` runs
/// it, once, with `VEIL_FIXTURE_DIR=<the set being written>`:
///
/// * tag `links`: `main` plus `links/readme` → `../README.md`,
///   `links/words` → an absolute target and `secrets/.env.current` → a
///   target sealed for `team` (a secret's link);
/// * tag `link-conflict`: a child of it whose `links/both` is a link/file
///   conflict (ours a symlink, theirs a file);
/// * annotated tags on `links`, signed by alice: `v5.0` and
///   `team-release` (before format 8, `team-release` was cloaked, with a
///   sealed message).
#[test]
#[ignore = "fixture generator: run by tests/fixtures/generate.sh"]
fn write_format_5_extras() {
    use veil_core::{conflict::set_entry, object::TermKind, oplog::Tag, tag_object::Atag, ConflictTerm};
    let out = PathBuf::from(std::env::var("VEIL_FIXTURE_DIR").expect("VEIL_FIXTURE_DIR"));
    let identity = Identity::from_json(&std::fs::read_to_string(out.join("home-alice/identity.json")).unwrap()).unwrap();
    let mut repo = Repo::open(Arc::new(DiskBackend::new(out.join("alice"))), Some(identity.clone()), "alice").unwrap();
    assert!(repo.format() >= 8, "the format-5 extras of this build go into a format-8 set");
    let main = tag(&repo, "main");
    let store = repo.store().clone();
    let base_tree = repo.snapshot(&main).unwrap().tree;
    let team = Visibility::Cloaked { scope: "team".into() };
    let mut tree = base_tree;
    for (path, e) in [
        ("links/readme", special_entry(&repo, "readme", EntryKind::Symlink, LINK_TARGET, Visibility::Public)),
        ("links/words", special_entry(&repo, "words", EntryKind::Symlink, ABSOLUTE_TARGET, Visibility::Public)),
        ("secrets/.env.current", special_entry(&repo, ".env.current", EntryKind::Symlink, SEALED_TARGET, team.clone())),
    ] {
        let path = p(path);
        let parent = path.parent().unwrap();
        tree = if lookup(&store, &tree, &parent).unwrap().is_some() {
            set_entry(&store, &tree, &path, Some(e)).unwrap()
        } else {
            // A new directory holding just this entry.
            let dir = store.put_tree(&Tree { entries: vec![e] }).unwrap();
            set_entry(&store, &tree, &parent, Some(TreeEntry::dir(parent.file_name(), dir))).unwrap()
        };
    }
    let snap = |parent: ObjectId, tree: ObjectId, msg: &str, conflicts: Vec<String>| {
        let mut s = Snapshot {
            parents: vec![parent],
            change_id: ChangeId::random(),
            tree,
            description: Text::Plain(msg.into()),
            author: "alice".into(),
            timestamp: veil_core::now_millis(),
            conflicts,
            ..Snapshot::root(tree)
        };
        s.sign(&identity);
        store.put_snapshot(&s).unwrap()
    };
    let links = snap(main, tree, "format 5: symlinks", vec![]);
    // A link/file conflict.
    let blob = |data: &str| store.store_file(data.as_bytes(), &Visibility::Public).unwrap();
    let term = |kind: TermKind, data: &str| ConflictTerm {
        kind,
        id: blob(data),
        size: data.len() as u64,
        executable: false,
        visibility: Visibility::Public,
    };
    let conflict = veil_core::Conflict {
        adds: vec![Some(term(TermKind::Symlink, "readme")), Some(term(TermKind::File, "a file now\n"))],
        removes: vec![Some(term(TermKind::File, "the base\n"))],
    };
    let cid = store.put_conflict(&conflict).unwrap();
    let ctree = set_entry(&store, &tree, &p("links/both"), Some(TreeEntry::conflict("both", cid))).unwrap();
    let conflicted = snap(links, ctree, "a link/file conflict", vec!["links/both".into()]);
    // Annotated tags.
    let now = veil_core::now_millis();
    let mut v5 = Atag::annotated("v5.0", links, Text::Plain("Release 5.0: links\n".into()), "alice", now);
    v5.sign(&identity);
    let mut team_release = Atag::annotated("team-release", links, Text::Plain(TEAM_RELEASE_NOTES.into()), "alice", now);
    team_release.sign(&identity);
    let (v5, team_release) = (store.put_atag(&v5).unwrap(), store.put_atag(&team_release).unwrap());
    let mut tx = repo.transaction("format 5 fixture: links, annotated tags").unwrap();
    tx.view.heads.insert(conflicted);
    let tag_at = |target, annotation| Tag { target, annotation };
    tx.view.tags.insert("links".into(), tag_at(links, None));
    tx.view.tags.insert("link-conflict".into(), tag_at(conflicted, None));
    tx.view.tags.insert("v5.0".into(), tag_at(links, Some(v5)));
    tx.view.tags.insert("team-release".into(), tag_at(links, Some(team_release)));
    tx.commit().unwrap();
}

/// Every object of `repo` that decodes (after opening, when it can), as
/// bytes to search for plaintext.
fn readable_bytes(repo: &Repo) -> Vec<(ObjectId, Vec<u8>)> {
    let mut out = Vec::new();
    for id in repo.store().list_objects().unwrap() {
        let raw = repo.store().get_raw(&id).unwrap();
        let mut bytes = raw.clone();
        if let Ok(o) = repo.store().open(&id) {
            bytes.extend(o.encode());
        }
        out.push((id, bytes));
    }
    out
}

/// The format-8 set's links and annotated tags, for their audiences: the
/// public links everywhere, the secret's link only for `team`, the
/// annotated tags signed by alice and plain.
#[test]
fn the_format_8_set_holds_links_and_annotated_tags_for_their_audiences() {
    use veil_core::tag_object::AtagVerification;
    let fx = Fixture::new(8);
    let alice_key = fx.identity("alice").verifying_hex();
    for who in ["alice", "bob"] {
        let repo = fx.open("alice", Some(who));
        let links = tag(&repo, "links");
        let tree = repo.snapshot(&links).unwrap().tree;
        let entry = |path: &str| lookup(repo.store(), &tree, &p(path)).unwrap().unwrap_or_else(|| panic!("{path}"));
        for (path, content) in [("links/readme", LINK_TARGET), ("links/words", ABSOLUTE_TARGET), ("secrets/.env.current", SEALED_TARGET)] {
            let e = entry(path);
            assert_eq!(e.kind, EntryKind::Symlink, "{who} {path}");
            assert_eq!(repo.store().read_entry(&e).unwrap(), content.as_bytes(), "{who} {path}");
        }
        assert!(!entry("secrets/.env.current").visibility.is_public());
        let c = tag(&repo, "link-conflict");
        let ce = lookup(repo.store(), &repo.snapshot(&c).unwrap().tree, &p("links/both")).unwrap().unwrap();
        assert!(repo.store().conflict(&ce.id).unwrap().has_special_terms());
        for name in ["v5.0", "team-release"] {
            let t = repo.view().tags[name].clone();
            let atag = repo.store().atag(&t.annotation.unwrap()).unwrap();
            assert!(matches!(atag.verify(name, &t.target), AtagVerification::Signed { ref key, .. } if *key == alice_key), "{who} {name}");
        }
    }
    let carol = fx.open("alice", Some("carol"));
    let tree = carol.snapshot(&tag(&carol, "links")).unwrap().tree;
    let e = lookup(carol.store(), &tree, &p("secrets/.env.current")).unwrap().unwrap();
    assert!(carol.store().read_entry(&e).is_err(), "carol reads the sealed target");
    let mirror = fx.open("public-mirror", None);
    let tree = mirror.snapshot(&tag(&mirror, "links")).unwrap().tree;
    let e = lookup(mirror.store(), &tree, &p("secrets/.env.current")).unwrap().unwrap();
    assert!(!mirror.store().has(&e.id), "the sealed link reached the public mirror");
    assert_eq!(mirror.store().atag(&mirror.view().tags["team-release"].annotation.unwrap()).unwrap().message.as_str(), TEAM_RELEASE_NOTES);
    for (id, bytes) in readable_bytes(&mirror) {
        assert!(!bytes.windows(SEALED_TARGET.len()).any(|w| w == SEALED_TARGET.as_bytes()), "{} holds the sealed target", id.short());
    }
}

// ---- adversarial pass: simplification part 2 ----------------------------------------

/// A repository this build writes at format 8, then marked `from` (as a
/// format-7 repository holding the same objects is): `(tmp, root, fs, alice)`.
fn written_then_marked(from: u32, build: impl FnOnce(&mut Repo, &Path, &Arc<DiskBackend>)) -> (tempfile::TempDir, PathBuf, Arc<DiskBackend>, Identity) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("p");
    std::fs::create_dir_all(&root).unwrap();
    let alice = Identity::generate("alice");
    let fs = Arc::new(DiskBackend::new(&root));
    let mut repo = Repo::init(fs.clone(), Some(alice.clone()), "alice").unwrap();
    build(&mut repo, &root, &fs);
    drop(repo);
    let mut cfg = read_config(&*fs).unwrap();
    cfg.format = from;
    cfg.min_vl = Some(veil_core::repo::min_vl_for_format(from).into());
    fs.write(&p(".veil/repo.json"), &serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    (tmp, root, fs, alice)
}

/// BUG-940: a secret renamed to an ordinary path stays sealed there
/// (protection follows a secret across a rename: format 8 writes this
/// itself, as format 7 did), but `vl upgrade` names it as content "only
/// the removed encryption wrote" and refuses the repository, telling its
/// owner to start a new one.
#[test]
fn a_renamed_secret_does_not_block_the_upgrade() {
    let (_tmp, _root, fs, alice) = written_then_marked(7, |repo, root, fs| {
        std::fs::write(root.join(".veilpolicy"), ".env cloak team\n").unwrap();
        std::fs::write(root.join(".env"), "TOKEN=fixture-not-a-secret-4471\n").unwrap();
        repo.snapshot_workspace("default", &**fs).unwrap();
        repo.commit_working_copy("default", "first").unwrap();
        std::fs::rename(root.join(".env"), root.join("settings.txt")).unwrap();
        repo.snapshot_workspace("default", &**fs).unwrap();
        let (c, _) = repo.commit_working_copy("default", "rename").unwrap();
        let tree = repo.snapshot(&c).unwrap().tree;
        let e = lookup(repo.store(), &tree, &p("settings.txt")).unwrap().expect("renamed");
        assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() }, "control: format 8 keeps the moved secret sealed");
    });
    let r = upgrade(fs.clone(), Some(alice), &UpgradeOptions::default());
    assert!(r.is_ok(), "a repository holding only what format 8 writes was refused: {}", r.unwrap_err());
}

/// BUG-941: the removed-content check reads a conflict entry's object only
/// to see that it decodes, so a conflict whose side is encrypted for a
/// cloaked folder (`billing/ cloak finance` before format 8: an encrypted
/// file that is not a secret file) passes, and the format-8 repository
/// keeps encrypted code, which the check exists to refuse (docs/FORMAT.md
/// §5 "Format 8").
#[test]
fn an_encrypted_conflict_side_of_an_ordinary_file_is_named() {
    let (_tmp, _root, fs, alice) = written_then_marked(7, |repo, _, _| {
        let store = repo.store();
        let public = store.put(&Object::Blob(b"public side\n".to_vec())).unwrap();
        // The structure only: the check reads labels, never content.
        let sealed = store.put(&Object::Blob(b"stands for a sealed side\n".to_vec())).unwrap();
        let term = |id: ObjectId, visibility: Visibility| veil_core::ConflictTerm {
            kind: veil_core::object::TermKind::File,
            id,
            size: 0,
            executable: false,
            visibility,
        };
        let conflict = veil_core::Conflict {
            adds: vec![Some(term(public, Visibility::Public)), Some(term(sealed, Visibility::Cloaked { scope: "finance".into() }))],
            removes: vec![Some(term(public, Visibility::Public))],
        };
        let cid = store.put_conflict(&conflict).unwrap();
        let billing = store
            .put(&Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: "report.txt".into(),
                    kind: EntryKind::Conflict,
                    id: cid,
                    size: 0,
                    executable: false,
                    visibility: Visibility::Public,
                }],
            }))
            .unwrap();
        let root_tree = store.put(&Object::Tree(Tree { entries: vec![TreeEntry::dir("billing", billing)] })).unwrap();
        let s = Snapshot {
            parents: vec![repo.root_id()],
            change_id: ChangeId::random(),
            tree: root_tree,
            description: Text::Plain("merge with a conflict".into()),
            author: "alice".into(),
            timestamp: 1,
            predecessors: vec![],
            conflicts: vec!["billing/report.txt".into()],
            embargo: None,
            agent: None,
            abandoned: None,
            attempts: vec![],
            signature: None,
        };
        let id = store.put_snapshot(&s).unwrap();
        repo.set_tag("main", id, false).unwrap();
    });
    let r = upgrade(fs, Some(alice), &UpgradeOptions { dry_run: true, ..Default::default() }).unwrap();
    assert!(
        r.removed.iter().any(|f| f.contains("billing/report.txt")),
        "the encrypted side of billing/report.txt was not named: {:?}",
        r.removed
    );
}

// ---- S11 review, cycle 1 ----------------------------------------------------------

/// Format 9 is S3's thin clone: its `repo.json` carries the `partial`
/// marker (`{remote, cache_limit}`), and objects not in the store are
/// fetched from its server when read. Format 10 has everything format 9
/// has (BUG-1390's coordination, S3 merged): this build opens such a
/// repository, and `vl upgrade` brings it to 10 keeping the marker byte for
/// byte and rewriting no object. (The server's `thin` tests do the same
/// with a thin clone S3's clone code made, and fetch on demand after.)
#[test]
fn a_thin_clone_of_format_9_opens_and_upgrades_to_10_keeping_its_marker() {
    let (_tmp, root, fs, alice) = written_then_marked(9, |repo, root, fs| {
        std::fs::write(root.join("README.md"), "hello\n").unwrap();
        repo.snapshot_workspace("default", &**fs).unwrap();
        repo.commit_working_copy("default", "first").unwrap();
    });
    // The marker as S3's `vl clone` writes it (`RepoConfig::partial`).
    let path = root.join(".veil/repo.json");
    let mut cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    cfg["partial"] = serde_json::json!({"remote": "origin", "cache_limit": 1u64 << 30});
    std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    let marker = serde_json::to_vec(&cfg["partial"]).unwrap();
    assert_eq!(Repo::open(fs.clone(), Some(alice.clone()), "alice").map(|r| r.format()).unwrap(), 9);
    let objects = |r: &Path| veil_files(r).into_iter().filter(|(p, _)| p.to_string_lossy().contains("/objects/")).collect::<Vec<_>>();
    let before = objects(&root);
    let r = upgrade(fs.clone(), Some(alice.clone()), &UpgradeOptions::default()).unwrap();
    assert_eq!((r.from, r.to), (9, REPO_FORMAT));
    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(after["format"], REPO_FORMAT, "{after}");
    assert_eq!(serde_json::to_vec(&after["partial"]).unwrap(), marker, "the marker changed: {after}");
    assert_eq!(objects(&root), before, "the upgrade rewrote objects");
    let repo = Repo::open(fs.clone(), Some(alice), "alice").unwrap();
    assert!(repo.config().is_partial(), "the upgraded repository is no longer a thin clone");
}

/// BUG-1390's class: `repo.json` keeps every field this build does not
/// know, its remotes' included, through a parse and a rewrite, and such a
/// configuration is never taken as one this build understands.
#[test]
fn repo_json_keeps_the_fields_this_build_does_not_know() {
    let raw = br#"{"format":10,"repo_id":"ab","remotes":{"origin":{"url":"veil://h/p","later":1}},"later_top":{"x":5},"partial":{"remote":"origin","cache_limit":5}}"#;
    let c: veil_core::repo::RepoConfig = serde_json::from_slice(raw).unwrap();
    assert!(c.is_partial(), "`partial` is a field this build knows");
    let back = serde_json::to_value(&c).unwrap();
    assert_eq!(back["later_top"], serde_json::json!({"x": 5}), "{back}");
    assert_eq!(back["partial"], serde_json::json!({"remote": "origin", "cache_limit": 5}), "{back}");
    assert_eq!(back["remotes"]["origin"]["later"], 1, "{back}");
    let e = c.check_known().unwrap_err();
    let m = e.to_string();
    assert!(matches!(e, VeilError::Unsupported(_)) && m.contains("\"later_top\"") && m.contains("\"later\"") && !m.contains("partial"), "{e}");
    let known: veil_core::repo::RepoConfig = serde_json::from_slice(br#"{"format":10,"repo_id":"ab"}"#).unwrap();
    assert!(known.check_known().is_ok());
}
