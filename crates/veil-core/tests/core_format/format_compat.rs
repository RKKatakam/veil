//! Repository format compatibility (see `docs/FORMAT.md`).
//!
//! * The golden fixture sets under `tests/fixtures/format-N/` were written
//!   by the release that introduced format N (`generate.sh`). This build
//!   must open, read, verify, `fsck`, upgrade and sync every one of them.
//! * Every format this build knows must have a fixture set, and every
//!   encoding is pinned by `tests/fixtures/encodings.txt`: changing what is
//!   written fails here until the change ships as a new format with its own
//!   fixture.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use veil_core::{
    crypto::{Envelope, Suite},
    embargo::wrapper_of,
    fsck::{fsck, Severity},
    id::ChangeId,
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEncoding, TreeEntry, Visibility},
    pack::{IDX_MAGIC, PACK_MAGIC},
    remote,
    identity::WrappedKey,
    keychain::{current_key_has_legacy_wraps, HpkeMigration, KeyRing, RingOp, RING_FORMAT},
    repo::{read_config, MIN_REPO_FORMAT, REPO_FORMAT},
    tree::{lookup, walk_files},
    upgrade::{upgrade, UpgradeOptions, JOURNAL_PATH},
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

    /// An identity of a nested set (`upgraded/home-<who>`).
    fn identity_at(&self, dir: &str, who: &str) -> Identity {
        let s = std::fs::read_to_string(self.root.join(format!("{dir}/home-{who}/identity.json"))).unwrap();
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

/// `(json, binary)` counts of the plaintext trees in a store.
fn tree_census(repo: &Repo) -> (usize, usize) {
    let mut n = (0, 0);
    for id in repo.store().list_objects().unwrap() {
        match Object::tree_encoding(&repo.store().get_raw(&id).unwrap()) {
            Some(TreeEncoding::Json) => n.0 += 1,
            Some(TreeEncoding::Binary) => n.1 += 1,
            None => {}
        }
    }
    n
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
    for f in MIN_REPO_FORMAT..=REPO_FORMAT {
        let dir = fixtures().join(format!("format-{f}"));
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
        fallback: None,
    });
    t.insert(TreeEntry {
        name: "run.sh".into(),
        kind: EntryKind::File,
        id: id(2),
        size: 300,
        executable: true,
        visibility: Visibility::Public,
        fallback: None,
    });
    t.insert(TreeEntry {
        name: "secret.txt".into(),
        kind: EntryKind::File,
        id: id(3),
        size: 5,
        executable: false,
        visibility: Visibility::Cloaked { scope: "team".into() },
        fallback: None,
    });
    t.insert(TreeEntry {
        name: "fix.rs".into(),
        kind: EntryKind::File,
        id: id(4),
        size: 1 << 40,
        executable: false,
        visibility: Visibility::Embargoed {
            embargo: "0123456789".into(),
        },
        fallback: Some(id(5)),
    });
    t.insert(TreeEntry {
        name: "é \"q\"\n".into(),
        kind: EntryKind::File,
        id: id(6),
        size: 0,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
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
        description: Text::Sealed(Envelope {
            scope: "team#0011223344556677".into(),
            suite: Suite::XChaCha20Poly1305 { nonce: [3; 24] },
            ciphertext: vec![1, 2, 3],
        }),
        author: "golden".into(),
        timestamp: 1_790_000_000_000,
        predecessors: vec![ObjectId([6; 32])],
        conflicts: vec!["a.txt".into()],
        cloak: Some("team".into()),
        embargo: Some("0123456789".into()),
        signature: None,
    };
    s.sign(&identity.unwrap());
    s
}

/// `name hex` per line: every encoding this build writes, pinned.
fn golden_encodings() -> Vec<(String, Vec<u8>)> {
    let tree = Object::Tree(sample_tree());
    vec![
        ("blob".into(), Object::Blob(b"hello\n".to_vec()).encode()),
        (
            "tree-empty".into(),
            Object::Tree(Tree::default()).encode_with(TreeEncoding::Binary),
        ),
        ("tree-v1-json".into(), tree.encode_with(TreeEncoding::Json)),
        ("tree-v2-binary".into(), tree.encode_with(TreeEncoding::Binary)),
        (
            "snapshot-root".into(),
            Object::Snapshot(Snapshot::root(ObjectId::hash(&Object::Tree(Tree::default()).encode()))).encode(),
        ),
        ("snapshot-full".into(), Object::Snapshot(sample_snapshot()).encode()),
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
        // Format 4: a conflict object (every term kind: absent, public,
        // executable with a size, cloaked with a fallback, embargoed), and
        // a binary tree holding a conflict entry.
        ("conflict".into(), Object::Conflict(golden_conflict()).encode()),
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
                        fallback: None,
                    },
                ],
            })
            .encode_with(TreeEncoding::Binary),
        ),
        // Format 5: a binary tree with symlinks (public and cloaked, one
        // with a fallback), a conflict with symlink terms, and annotated
        // tags (signed with a plain message, and with a sealed message).
        ("tree-v2-binary-symlink".into(), Object::Tree(golden_special_tree(EntryKind::Symlink)).encode_with(TreeEncoding::Binary)),
        ("conflict-symlink-term".into(), Object::Conflict(golden_link_conflict()).encode()),
        ("atag".into(), Object::Atag(golden_atag()).encode()),
        (
            "atag-sealed".into(),
            Object::Atag(veil_core::tag_object::Atag {
                name: "team-release".into(),
                message: Text::Sealed(Envelope {
                    scope: "team#0011223344556677".into(),
                    suite: Suite::XChaCha20Poly1305 { nonce: [6; 24] },
                    ciphertext: vec![7; 26],
                }),
                signature: None,
                ..golden_atag()
            })
            .encode(),
        ),
        // Format 6: an operation (not an object: `.veil/ops/<id>`, its id
        // the BLAKE3 of these bytes) with a workspace and rewrites, and a
        // merge of two concurrent operations.
        ("operation-format-6".into(), serde_json::to_vec(&golden_operation()).unwrap()),
        (
            "operation-merge".into(),
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
    view.workspaces.insert("agent-1".into(), veil_core::oplog::WorkspaceState { wc: ObjectId([0x52; 32]), cloak: Some("team".into()) });
    view.tags.insert("main".into(), veil_core::oplog::Tag::new(ObjectId([0x53; 32]), None));
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
    }
}

// ---- format 6: the lock-free op log ---------------------------------------------

/// `vl upgrade` 5 → 6 rewrites nothing: every object, operation and id
/// stays; the head moves from `op_head` to `op_heads/` (before the commit
/// point its head file is created, after it `op_head` is removed).
#[test]
fn upgrade_5_to_6_keeps_every_id() {
    let fx = Fixture::new(5);
    let dir = fx.root.join("alice");
    let before_view = fx.open("alice", Some("alice")).view().clone();
    let head = String::from_utf8(std::fs::read(dir.join(".veil/op_head")).unwrap()).unwrap();
    let before: Vec<(PathBuf, Vec<u8>)> = veil_files(&dir)
        .into_iter()
        .filter(|(p, _)| {
            let p = p.to_string_lossy();
            p.contains("/.veil/ops/") || p.contains("/.veil/objects/") && !p.contains("/gc/")
        })
        .collect();
    let r = upgrade(fx.backend("alice"), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap();
    assert_eq!((r.from, r.to), (5, 6));
    assert!(r.steps.contains(&"5->6:op-heads".to_string()) && r.steps.contains(&"6:remove-op-head".to_string()), "{:?}", r.steps);
    assert!(r.notes.iter().any(|n| n.contains("no longer wait")), "{:#?}", r.notes);
    assert!(!dir.join(".veil/op_head").exists());
    assert!(dir.join(".veil/op_heads").join(head.trim()).exists());
    let after = veil_files(&dir);
    for (p, bytes) in &before {
        let now = after.iter().find(|(q, _)| q == p).map(|(_, b)| b);
        assert_eq!(now, Some(bytes), "{} changed or vanished", p.display());
    }
    let repo = fx.open("alice", Some("alice"));
    assert_eq!(repo.format(), 6);
    assert_eq!(repo.view(), &before_view);
    assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));
}

/// Threat 9 of the lock-free op log: a format-5 writer racing the upgrade
/// (an older vl, or this vl opened before it) writes an operation and
/// `op_head` after the commit point. At format 6 a present `op_head` is one
/// more head: the next command merges it in and removes the file.
#[test]
fn op_head_written_after_upgrade_is_merged() {
    let fx = Fixture::new(5);
    let dir = fx.root.join("alice");
    let backend = fx.backend("alice");
    // The late writer read the view before the upgrade.
    let mut late = fx.open("alice", Some("alice")).ops().get(&fx.open("alice", Some("alice")).op_id()).unwrap();
    let parent = fx.open("alice", Some("alice")).op_id();
    upgrade(backend.clone(), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap();
    let mut repo = fx.open("alice", Some("alice"));
    let main = repo.view().tags["main"].target;
    repo.set_tag("after-upgrade", main, None, false).unwrap();
    drop(repo);
    // ...and writes its operation the way format 5 does.
    late.parents = vec![parent];
    late.description = "set tag late".into();
    late.timestamp += 1;
    late.view.tags.insert("late".into(), veil_core::oplog::Tag::new(main, None));
    let raw = serde_json::to_vec(&late).unwrap();
    let id = ObjectId::hash(&raw);
    std::fs::write(dir.join(format!(".veil/ops/{}", id.hex())), &raw).unwrap();
    std::fs::write(dir.join(".veil/op_head"), id.hex()).unwrap();
    let repo = fx.open("alice", Some("alice"));
    assert!(repo.view().tags.contains_key("late"), "the late writer's operation was ignored");
    assert!(repo.view().tags.contains_key("after-upgrade"));
    assert_eq!(repo.heads().len(), 1);
    assert!(!dir.join(".veil/op_head").exists(), "op_head was not removed once merged");
    assert_fsck_clean(backend, Some(fx.identity("alice")));
}

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
    assert_eq!(a.format(), 6, "the format-6 extras go into a format-6 set");
    // A public change (`links`, from the format-5 extras), not `main`,
    // whose line is under an unreleased embargo.
    let x = tag(&a, "links");
    let mut tx_a = a.transaction("describe").unwrap();
    let mut amended = (*tx_a.repo().snapshot(&x).unwrap()).clone();
    amended.description = Text::Plain("format 6: amended while a workspace was created on it".into());
    amended.predecessors = vec![x];
    tx_a.rewrite(x, amended).unwrap();
    let mut tx_b = b.transaction("create workspace 'concurrent'").unwrap();
    tx_b.for_workspace("concurrent");
    let wc = tx_b.new_change(vec![x], "", None).unwrap();
    tx_b.view.workspaces.insert("concurrent".into(), veil_core::oplog::WorkspaceState { wc, cloak: None });
    tx_a.commit().unwrap();
    tx_b.commit().unwrap();
    drop((a, b));
    // The next open merges them.
    let main = tag(&open(), "main");
    let (mut c, mut d) = (open(), open());
    let mut tx_c = c.transaction("set tag head-c").unwrap();
    tx_c.repository_wide();
    tx_c.view.tags.insert("head-c".into(), veil_core::oplog::Tag::new(main, None));
    let mut tx_d = d.transaction("set tag head-d").unwrap();
    tx_d.repository_wide();
    tx_d.view.tags.insert("head-d".into(), veil_core::oplog::Tag::new(main, None));
    tx_c.commit().unwrap();
    tx_d.commit().unwrap();
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

/// The format-6 set records concurrent operations: a merge whose side
/// carries `rewritten` and `workspace`, and two heads not merged yet. The
/// next open merges them; nothing recorded is lost.
#[test]
fn format_6_fixture_heads_merge() {
    let fx = Fixture::new(6);
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

/// A tree holding `kind` entries (format 5): public with a size, and
/// cloaked with a fallback, next to a file.
fn golden_special_tree(kind: EntryKind) -> Tree {
    let e = |name: &str, n: u8| TreeEntry {
        name: name.into(),
        kind,
        id: ObjectId([n; 32]),
        size: 12,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
    };
    Tree {
        entries: vec![
            e("current", 0x31),
            TreeEntry {
                name: "file.txt".into(),
                kind: EntryKind::File,
                id: ObjectId([0x32; 32]),
                size: 3,
                executable: false,
                visibility: Visibility::Public,
                fallback: None,
            },
            TreeEntry {
                visibility: Visibility::Cloaked { scope: "team".into() },
                fallback: Some(ObjectId([0x34; 32])),
                ..e("private", 0x33)
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
        fallback: None,
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
        fallback: None,
    };
    veil_core::Conflict {
        adds: vec![
            Some(ConflictTerm { executable: true, size: 300, ..t(0x21) }),
            Some(ConflictTerm {
                visibility: Visibility::Cloaked { scope: "team".into() },
                fallback: Some(ObjectId([0x23; 32])),
                ..t(0x22)
            }),
            None,
        ],
        removes: vec![
            Some(t(0x24)),
            Some(ConflictTerm { visibility: Visibility::Embargoed { embargo: "0123456789".into() }, ..t(0x25) }),
        ],
    }
}

#[test]
fn encodings_match_the_golden_file() {
    let path = fixtures().join("encodings.txt");
    let actual: String = golden_encodings()
        .into_iter()
        .map(|(n, b)| format!("{n} {}\n", hex::encode(b)))
        .collect();
    if std::env::var_os("VEIL_BLESS_ENCODINGS").is_some() {
        std::fs::write(&path, &actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path).expect("tests/fixtures/encodings.txt");
    for (a, e) in actual.lines().zip(expected.lines()) {
        assert_eq!(
            a, e,
            "an object encoding changed. That is a format change: it needs a new repository format \
             (repo::REPO_FORMAT), read support for the old encoding, a fixture set written by the \
             new release (tests/fixtures/generate.sh) and docs/FORMAT.md. Only then re-bless with \
             VEIL_BLESS_ENCODINGS=1 — and only by appending lines."
        );
    }
    assert_eq!(
        actual.lines().count(),
        expected.lines().count(),
        "golden entries added or removed"
    );
    // Every golden encoding still decodes, and decodes back to itself.
    for (name, raw) in golden_encodings() {
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

// ---- reading format-1 repositories -----------------------------------------

#[test]
fn every_fixture_set_opens_reads_and_verifies() {
    for f in MIN_REPO_FORMAT..=REPO_FORMAT {
        check_fixture_reads(f);
    }
}

fn check_fixture_reads(format: u32) {
    let fx = Fixture::new(format);
    let repo = fx.open("alice", Some("alice"));
    assert_eq!(repo.format(), format);
    assert!(repo.root_id().hex().starts_with(UNIVERSAL_ROOT));
    let main = tag(&repo, "main");
    assert_eq!(
        read_str(&repo, &main, "README.md").as_deref(),
        Some("Fixture project\n")
    );
    assert!(read_str(&repo, &main, "src/main.rs").unwrap().contains("v3"));
    assert!(read_str(&repo, &main, "src/util/strings.rs")
        .unwrap()
        .contains("to_uppercase"));
    let tree = repo.snapshot(&main).unwrap().tree;
    assert!(
        lookup(repo.store(), &tree, &p("bin/run.sh"))
            .unwrap()
            .unwrap()
            .executable
    );
    // Cloaked (key generation 2), released embargo, unreleased embargo (key holder).
    assert_eq!(
        read_str(&repo, &main, "secrets/notes.txt").as_deref(),
        Some("team-only notes v2\n")
    );
    assert_eq!(
        read_str(&repo, &main, "src/fix_a.rs").as_deref(),
        Some("pub fn fix_a() {}\n")
    );
    assert_eq!(
        read_str(&repo, &main, "src/fix_b.rs").as_deref(),
        Some("pub fn fix_b() {}\n")
    );
    assert!(
        wrapper_of(repo.store(), &tree).unwrap().is_some(),
        "main is under an embargo wrapper"
    );
    // Isolated files never entered history.
    assert!(read(&repo, &main, ".env").is_none());
    // Signatures, ring, embargo records, vault.
    for id in repo.topo_children_first([main]).unwrap() {
        let s = repo.snapshot(&id).unwrap();
        if s.parents.is_empty() {
            continue;
        }
        assert!(
            repo.keys().snapshot_status(&s).is_good(),
            "snapshot {} signature",
            id.short()
        );
    }
    let ring = repo.keys().ring_state("team").unwrap().unwrap().unwrap();
    assert_eq!(ring.generation, 2);
    assert!(ring.members.values().any(|m| m.name == "bob"));
    assert!(!ring.members.values().any(|m| m.name == "carol"));
    let embargoes = repo.keys().embargoes().unwrap();
    assert_eq!(embargoes.len(), 2);
    assert_eq!(embargoes.iter().filter(|r| r.is_released()).count(), 1);
    assert!(embargoes.iter().all(|r| repo.keys().embargo_status(r).is_good()));
    assert_eq!(
        repo.vault_load().unwrap().secrets.get("API_TOKEN").map(String::as_str),
        Some("fixture-value")
    );
    // Packed and loose; the trees of the fixture's format (format 2 still
    // has the format-1 empty tree).
    let stats = repo.store().stats().unwrap();
    assert!(
        stats.packs >= 1 && stats.packed_objects > 0 && stats.loose_objects > 0,
        "{stats:?}"
    );
    assert!(repo.store().verify_packs().unwrap().is_empty());
    let (json, binary) = tree_census(&repo);
    assert!(json > 0);
    match format {
        1 => assert_eq!(binary, 0),
        _ => assert!(binary > json, "{binary} binary, {json} JSON trees"),
    }
    assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));
}

#[test]
fn every_fixture_set_keeps_key_generations_and_audiences() {
    for f in MIN_REPO_FORMAT..=REPO_FORMAT {
        check_audiences(f);
    }
}

fn check_audiences(format: u32) {
    let fx = Fixture::new(format);
    let bob = fx.open("alice", Some("bob"));
    let main = tag(&bob, "main");
    assert_eq!(
        read_str(&bob, &main, "secrets/notes.txt").as_deref(),
        Some("team-only notes v2\n")
    );
    // Carol was revoked before the second commit: generation 0 content only.
    let carol = fx.open("alice", Some("carol"));
    assert_eq!(read_str(&carol, &main, "secrets/notes.txt"), None);
    let first = carol
        .topo_children_first([main])
        .unwrap()
        .into_iter()
        .find(|id| carol.description(&carol.snapshot(id).unwrap()) == "initial import")
        .unwrap();
    assert_eq!(
        read_str(&carol, &first, "secrets/notes.txt").as_deref(),
        Some("team-only notes v1\n")
    );
    // An outsider sees the pre-merge tree of the unreleased embargo.
    let outsider = Repo::open(fx.backend("alice"), Some(Identity::generate("eve")), "eve").unwrap();
    assert_eq!(read_str(&outsider, &main, "src/fix_b.rs"), None);
    assert_eq!(
        read_str(&outsider, &main, "src/fix_a.rs").as_deref(),
        Some("pub fn fix_a() {}\n")
    );
    assert_eq!(read_str(&outsider, &main, "secrets/notes.txt"), None);
}

#[test]
fn every_fixture_set_remotes_read_and_verify() {
    for f in MIN_REPO_FORMAT..=REPO_FORMAT {
        check_remotes(f);
    }
}

fn check_remotes(format: u32) {
    let fx = Fixture::new(format);
    let team = fx.open("team-remote", None);
    let public = fx.open("public-mirror", None);
    for (r, name) in [(&team, "team-remote"), (&public, "public-mirror")] {
        assert_eq!(r.format(), format);
        assert_fsck_clean(fx.backend(name), None);
    }
    assert!(!public.view().tags.contains_key("team-only"), "cloaked tag published");
    let main = tag(&public, "main");
    assert_eq!(
        read_str(&public, &main, "README.md").as_deref(),
        Some("Fixture project\n")
    );
    assert_eq!(read_str(&public, &main, "src/fix_b.rs"), None);
    assert_eq!(read_str(&public, &main, "secrets/notes.txt"), None);
}

#[test]
fn format1_repository_keeps_writing_format1() {
    let fx = Fixture::new(1);
    let mut repo = fx.open("alice", Some("alice"));
    let before = tree_census(&repo);
    std::fs::write(fx.root.join("alice/src/new_dir_file.rs"), "// new\n").unwrap();
    std::fs::create_dir_all(fx.root.join("alice/deep/er")).unwrap();
    std::fs::write(fx.root.join("alice/deep/er/x.txt"), "x\n").unwrap();
    let fs = fx.backend("alice");
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (c, _) = repo.commit_working_copy("default", "format-1 commit").unwrap();
    assert_eq!(read_str(&repo, &c, "deep/er/x.txt").as_deref(), Some("x\n"));
    let after = tree_census(&repo);
    assert!(after.0 > before.0, "new JSON trees were written");
    assert_eq!(after.1, 0, "a format-1 repository wrote binary trees");
    assert_eq!(read_config(&*fs).unwrap().format, 1);
    assert_fsck_clean(fs, Some(fx.identity("alice")));
}

// ---- upgrade ---------------------------------------------------------------

#[test]
fn upgrade_dry_run_writes_nothing() {
    let fx = Fixture::new(1);
    let root = fx.root.join("alice");
    let before = veil_files(&root);
    let r = upgrade(
        fx.backend("alice"),
        Some(fx.identity("alice")),
        &UpgradeOptions {
            dry_run: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!((r.from, r.to), (1, REPO_FORMAT));
    assert!(r.corrupt.is_empty(), "{:?}", r.corrupt);
    assert!(r.trees_json > 0);
    assert!(r.steps.contains(&"set-format".to_string()), "{:?}", r.steps);
    assert!(r.steps.contains(&"3:hpke-ring-keys".to_string()), "{:?}", r.steps);
    assert_eq!(r.steps.last().map(String::as_str), Some("6:remove-op-head"));
    assert_eq!(veil_files(&root), before, "a dry run changed .veil/");
}

#[test]
fn upgrade_keeps_ids_and_switches_new_trees_to_binary() {
    let fx = Fixture::new(1);
    let old = fx.open("alice", Some("alice"));
    let old_view = old.view().clone();
    let old_main = tag(&old, "main");
    let old_files = walk_files(old.store(), &old.snapshot(&old_main).unwrap().tree).unwrap();
    drop(old);

    let r = upgrade(
        fx.backend("alice"),
        Some(fx.identity("alice")),
        &UpgradeOptions::default(),
    )
    .unwrap();
    assert_eq!((r.from, r.to, r.up_to_date), (1, REPO_FORMAT, false));
    assert!(!fx.root.join("alice").join(JOURNAL_PATH).exists());
    let cfg = read_config(&*fx.backend("alice")).unwrap();
    assert_eq!(cfg.format, REPO_FORMAT);
    assert_eq!(cfg.min_vl.as_deref(), Some(veil_core::repo::min_vl_for_format(REPO_FORMAT)));

    let mut repo = fx.open("alice", Some("alice"));
    assert_eq!(repo.view(), &old_view, "upgrade changed the view");
    assert_eq!(
        walk_files(repo.store(), &repo.snapshot(&old_main).unwrap().tree).unwrap(),
        old_files
    );
    assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));

    // Running it again is a no-op.
    assert!(
        upgrade(fx.backend("alice"), None, &UpgradeOptions::default())
            .unwrap()
            .up_to_date
    );

    std::fs::write(fx.root.join("alice/src/after.rs"), "// after upgrade\n").unwrap();
    let fs = fx.backend("alice");
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (c, _) = repo.commit_working_copy("default", "first format-2 commit").unwrap();
    let raw = repo.store().get_raw(&repo.snapshot(&c).unwrap().tree).unwrap();
    // The root is an embargo wrapper (main is under an unreleased embargo);
    // either way it is new, so it is binary.
    assert_eq!(Object::tree_encoding(&raw), Some(TreeEncoding::Binary));
    assert_eq!(
        read_str(&repo, &c, "src/after.rs").as_deref(),
        Some("// after upgrade\n")
    );
    assert_eq!(
        read_str(&repo, &c, "secrets/notes.txt").as_deref(),
        Some("team-only notes v2\n")
    );
    // Unchanged directories keep their format-1 trees (and ids).
    let old_util = lookup(repo.store(), &repo.snapshot(&old_main).unwrap().tree, &p("src/util"))
        .unwrap()
        .unwrap();
    let new_util = lookup(repo.store(), &repo.snapshot(&c).unwrap().tree, &p("src/util"))
        .unwrap()
        .unwrap();
    assert_eq!(old_util.id, new_util.id);
    assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));
}

#[test]
fn upgrade_refuses_a_corrupt_repository_and_changes_nothing() {
    let fx = Fixture::new(1);
    let root = fx.root.join("alice");
    // Damage one loose object.
    let objects = root.join(".veil/objects");
    let victim = std::fs::read_dir(&objects)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().len() == 2)
        .unwrap()
        .path();
    let file = std::fs::read_dir(&victim).unwrap().next().unwrap().unwrap().path();
    let mut bytes = std::fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&file, &bytes).unwrap();
    let before = veil_files(&root);
    let err = upgrade(
        fx.backend("alice"),
        Some(fx.identity("alice")),
        &UpgradeOptions::default(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("upgrade refused"), "{err}");
    let mut after = veil_files(&root);
    after.retain(|(p, _)| !p.ends_with("upgrade.json"));
    assert_eq!(after, before);
    assert_eq!(read_config(&*fx.backend("alice")).unwrap().format, 1);
}

#[test]
fn interrupted_upgrade_resumes() {
    // Crash after the commit point (repo.json written, journal left behind).
    let fx = Fixture::new(1);
    let fs = fx.backend("alice");
    let mut cfg = read_config(&*fs).unwrap();
    cfg.format = REPO_FORMAT;
    fs.write(&p(".veil/repo.json"), &serde_json::to_vec_pretty(&cfg).unwrap())
        .unwrap();
    fs.write(
        &p(JOURNAL_PATH),
        format!(r#"{{"from":1,"to":{REPO_FORMAT},"started":1,"done":["verify"]}}"#).as_bytes(),
    )
    .unwrap();
    let r = upgrade(fs.clone(), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap();
    assert!(r.resumed && !r.up_to_date);
    assert!(
        !r.steps.contains(&"verify".to_string()),
        "verification repeated: {:?}",
        r.steps
    );
    assert!(!fs.exists(&p(JOURNAL_PATH)).unwrap());

    // Crash before the commit point: the repository is still format 1.
    let fx = Fixture::new(1);
    let fs = fx.backend("alice");
    fs.write(
        &p(JOURNAL_PATH),
        format!(r#"{{"from":1,"to":{REPO_FORMAT},"started":1,"done":[]}}"#).as_bytes(),
    )
    .unwrap();
    assert_eq!(
        fx.open("alice", Some("alice")).format(),
        1,
        "half an upgrade is still the old format"
    );
    let r = upgrade(fs.clone(), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap();
    assert!(r.resumed);
    assert_eq!(read_config(&*fs).unwrap().format, REPO_FORMAT);
    assert!(!fs.exists(&p(JOURNAL_PATH)).unwrap());
}

// ---- sync across formats ----------------------------------------------------

#[test]
fn format2_clone_of_every_fixture_remote_reads_everything() {
    for f in MIN_REPO_FORMAT..=REPO_FORMAT {
        clone_and_read(f);
    }
}

fn clone_and_read(format: u32) {
    let fx = Fixture::new(format);
    let fs = Arc::new(MemoryBackend::new());
    let mut bob = Repo::init_for_clone(fs, Some(fx.identity("bob")), "bob").unwrap();
    assert_eq!(bob.format(), REPO_FORMAT);
    remote::pull(&mut bob, "origin", fx.backend("team-remote")).unwrap();
    let main = tag(&bob, "main");
    assert_eq!(
        read_str(&bob, &main, "secrets/notes.txt").as_deref(),
        Some("team-only notes v2\n")
    );
    assert_eq!(
        read_str(&bob, &main, "src/fix_b.rs").as_deref(),
        Some("pub fn fix_b() {}\n")
    );
    assert_fsck_clean(bob.backend().clone(), Some(fx.identity("bob")));
}

#[test]
fn binary_trees_never_reach_a_format1_repository() {
    let fx = Fixture::new(1);
    upgrade(
        fx.backend("alice"),
        Some(fx.identity("alice")),
        &UpgradeOptions::default(),
    )
    .unwrap();
    let mut alice = fx.open("alice", Some("alice"));
    std::fs::write(fx.root.join("alice/NEW.md"), "new\n").unwrap();
    let fs = fx.backend("alice");
    alice.snapshot_workspace("default", &*fs).unwrap();
    let (c, _) = alice.commit_working_copy("default", "binary").unwrap();
    alice.set_tag("main", c, None, true).unwrap();

    // Push to the format-1 team remote: refused, the remote stays readable.
    let err = remote::push(&mut alice, fx.backend("team-remote"), false, &[], false).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)), "{err}");
    assert!(err.to_string().contains("vl upgrade"), "{err}");
    assert_eq!(fx.open("team-remote", None).format(), 1);
    assert_fsck_clean(fx.backend("team-remote"), None);

    // A format-1 repository cannot pull binary trees either.
    let mid = Arc::new(MemoryBackend::new());
    let mut up = Repo::init_bare(mid.clone()).unwrap();
    assert_eq!(up.format(), REPO_FORMAT);
    drop(up);
    remote::push(&mut alice, mid.clone(), false, &[], false).unwrap();
    let mut old = Repo::init_for_clone_at(Arc::new(MemoryBackend::new()), Some(fx.identity("bob")), "bob", 1).unwrap();
    let err = remote::pull(&mut old, "origin", mid.clone()).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)), "{err}");

    // After upgrading the remote, the push goes through and a clone reads it.
    upgrade(fx.backend("team-remote"), None, &UpgradeOptions::default()).unwrap();
    remote::push(&mut alice, fx.backend("team-remote"), false, &[], false).unwrap();
    assert_fsck_clean(fx.backend("team-remote"), None);
    up = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(fx.identity("bob")), "bob").unwrap();
    remote::pull(&mut up, "origin", fx.backend("team-remote")).unwrap();
    let main = tag(&up, "main");
    assert_eq!(read_str(&up, &main, "NEW.md").as_deref(), Some("new\n"));
    assert_eq!(
        read_str(&up, &main, "secrets/notes.txt").as_deref(),
        Some("team-only notes v2\n")
    );
    // The format-1 public mirror still accepts pushes of JSON-only history.
    let mut f1 = fx.open("public-mirror", None);
    assert_eq!(f1.format(), 1);
    drop(f1);
    f1 = Repo::init_for_clone_at(Arc::new(MemoryBackend::new()), None, "x", 1).unwrap();
    remote::pull(&mut f1, "mirror", fx.backend("public-mirror")).unwrap();
}

// ---- newer formats fail clearly ----------------------------------------------

#[test]
fn newer_repository_format_is_refused_with_the_release_it_needs() {
    let fx = Fixture::new(1);
    let fs = fx.backend("alice");
    let mut cfg = read_config(&*fs).unwrap();
    cfg.format = REPO_FORMAT + 1;
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
    let fx = Fixture::new(1);
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
    let fx = Fixture::new(1);
    let root = fx.root.join("alice/.veil/meta");
    let ring_path = root.join("keyrings/team.json");
    let ring = std::fs::read_to_string(&ring_path)
        .unwrap()
        .replacen("\"format\": 2", &format!("\"format\": {}", RING_FORMAT + 1), 1);
    std::fs::write(&ring_path, ring).unwrap();
    let rec = std::fs::read_dir(root.join("embargoes"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&rec).unwrap()).unwrap();
    v["format"] = 2.into();
    std::fs::write(&rec, serde_json::to_vec(&v).unwrap()).unwrap();
    let repo = fx.open("alice", Some("alice"));
    let state = repo.keys().ring_state("team").unwrap().unwrap();
    assert!(state.unwrap_err().contains("newer vl"));
    let id = rec.file_stem().unwrap().to_string_lossy().to_string();
    let err = repo.keys().load_embargo(&id).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)), "{err}");
}

// ---- format 3: standard cryptography (docs/CRYPTO.md) ------------------------

/// `(veil:seal, veil:sea2)` counts of the sealed objects in a store.
fn sealed_census(repo: &Repo) -> (usize, usize) {
    let mut n = (0, 0);
    for id in repo.store().list_objects().unwrap() {
        let raw = repo.store().get_raw(&id).unwrap();
        if raw.starts_with(b"veil:seal\n") {
            n.0 += 1;
        } else if raw.starts_with(b"veil:sea2\n") {
            n.1 += 1;
        }
    }
    n
}

fn ring_of(repo: &Repo, scope: &str) -> KeyRing {
    repo.keys().load_ring(scope).unwrap().unwrap()
}

/// Every wrapped key in a ring's log, with the change kind.
fn wraps(ring: &KeyRing) -> Vec<(&'static str, WrappedKey)> {
    let mut out = Vec::new();
    for c in &ring.log {
        match &c.op {
            RingOp::Genesis { members, .. } => out.extend(members.iter().map(|m| ("genesis", m.wrapped.clone()))),
            RingOp::Grant { member } => out.push(("grant", member.wrapped.clone())),
            RingOp::Revoke { rotation, .. } => out.extend(rotation.wrapped.values().map(|w| ("revoke", w.clone()))),
            RingOp::Rotate { rotation } => out.extend(rotation.wrapped.values().map(|w| ("rotate", w.clone()))),
        }
    }
    out
}

fn commit_edit(fx: &Fixture, repo: &mut Repo, files: &[(&str, &str)], msg: &str) -> ObjectId {
    for (path, text) in files {
        std::fs::write(fx.root.join("alice").join(path), text).unwrap();
    }
    let fs = fx.backend("alice");
    repo.snapshot_workspace("default", &*fs).unwrap();
    repo.commit_working_copy("default", msg).unwrap().0
}

fn entry_id(repo: &Repo, rev: &ObjectId, path: &str) -> ObjectId {
    let tree = repo.snapshot(rev).unwrap().tree;
    lookup(repo.store(), &tree, &p(path)).unwrap().unwrap().id
}

#[test]
fn format3_fixture_uses_only_the_standard_constructions() {
    let fx = Fixture::new(3);
    let alice = fx.open("alice", Some("alice"));
    let (legacy, siv) = sealed_census(&alice);
    assert_eq!(legacy, 0, "a format-3 repository wrote legacy sealed objects");
    assert!(siv > 0);
    let ring = ring_of(&alice, "team");
    assert_eq!(ring.format, RING_FORMAT);
    assert!(wraps(&ring).iter().all(|(_, w)| w.is_hpke()), "legacy key wrapping in a format-3 ring");
    for who in ["alice", "bob", "carol"] {
        assert!(!fx.identity(who).signing_key_is_derived(), "{who}: new identities have independent keys");
    }
    // Dave keeps a legacy identity (derived signing key): a member like any other.
    let dave_id = fx.identity("dave");
    assert!(dave_id.signing_key_is_derived());
    let state = ring.verify().unwrap();
    assert_eq!(
        state.members[&dave_id.public_hex()].signing_key.as_deref(),
        Some(dave_id.verifying_hex().as_str())
    );
    let dave = fx.open("alice", Some("dave"));
    let main = tag(&dave, "main");
    assert_eq!(read_str(&dave, &main, "secrets/notes.txt").as_deref(), Some("team-only notes v2\n"));
    for r in [&alice, &fx.open("team-remote", None)] {
        assert_eq!(sealed_census(r).0, 0);
    }
    // The vault, descriptions, embargo and older-generation keys still use
    // XChaCha20-Poly1305 with random nonces (unchanged formats).
    assert_eq!(
        alice.vault_load().unwrap().secrets.get("API_TOKEN").map(String::as_str),
        Some("fixture-value")
    );
}

#[test]
fn upgraded_fixture_mixes_constructions_and_everyone_reads_their_share() {
    let fx = Fixture::new(3);
    let open = |who: &str| {
        let s = std::fs::read_to_string(fx.root.join(format!("upgraded/home-{who}/identity.json"))).unwrap();
        let id = Identity::from_json(&s).unwrap();
        assert!(id.signing_key_is_derived(), "the format-2 identities are legacy");
        Repo::open(fx.backend("upgraded/alice"), Some(id), who).unwrap()
    };
    let alice = open("alice");
    assert_eq!(alice.format(), 3);
    let (legacy, siv) = sealed_census(&alice);
    assert!(legacy > 0 && siv > 0, "({legacy}, {siv})");
    let main = tag(&alice, "main");
    assert_eq!(read_str(&alice, &main, "secrets/notes.txt").as_deref(), Some("team-only notes v3 (after the upgrade)\n"));
    let ring = ring_of(&alice, "team");
    let state = ring.verify().unwrap();
    assert_eq!(state.generation, 3, "the upgrade rotated to a new generation");
    assert!(matches!(ring.log.last().unwrap().op, RingOp::Rotate { .. }));
    assert!(!current_key_has_legacy_wraps(&ring, &state));
    assert!(wraps(&ring).iter().any(|(_, w)| !w.is_hpke()), "old changes keep their legacy wraps");
    // Bob reads old and new; Carol (revoked before the upgrade) only generation 0.
    let bob = open("bob");
    assert_eq!(read_str(&bob, &main, "secrets/notes.txt").as_deref(), Some("team-only notes v3 (after the upgrade)\n"));
    let carol = open("carol");
    assert_eq!(read_str(&carol, &main, "secrets/notes.txt"), None);
    let first = carol
        .topo_children_first([main])
        .unwrap()
        .into_iter()
        .find(|id| carol.description(&carol.snapshot(id).unwrap()) == "initial import")
        .unwrap();
    assert_eq!(read_str(&carol, &first, "secrets/notes.txt").as_deref(), Some("team-only notes v1\n"));
    for id in alice.topo_children_first([main]).unwrap() {
        let s = alice.snapshot(&id).unwrap();
        assert!(s.parents.is_empty() || alice.keys().snapshot_status(&s).is_good());
    }
    assert_fsck_clean(fx.backend("upgraded/alice"), Some(fx.identity_at("upgraded", "alice")));
    let remote = fx.open("upgraded/team-remote", None);
    assert_eq!(remote.format(), 3);
    assert_eq!(ring_of(&remote, "team"), ring);
    assert_fsck_clean(fx.backend("upgraded/team-remote"), None);
}

#[test]
fn format2_repository_keeps_writing_the_legacy_constructions() {
    let fx = Fixture::new(2);
    let mut repo = fx.open("alice", Some("alice"));
    let before = sealed_census(&repo);
    let c = commit_edit(&fx, &mut repo, &[("secrets/notes.txt", "team-only notes v3\n")], "format-2 commit");
    assert_eq!(read_str(&repo, &c, "secrets/notes.txt").as_deref(), Some("team-only notes v3\n"));
    let after = sealed_census(&repo);
    assert!(after.0 > before.0, "new legacy sealed objects were written");
    assert_eq!(after.1, 0, "a format-2 repository wrote AES-SIV objects");
    // Granting a new (independent-key) identity wraps with the legacy box.
    let erin = Identity::generate("erin");
    repo.keys().grant("team", &erin.public_id(), "erin").unwrap();
    let ring = ring_of(&repo, "team");
    assert_eq!(ring.format, 2);
    assert!(wraps(&ring).iter().all(|(_, w)| !w.is_hpke()));
    let erins = Repo::open(fx.backend("alice"), Some(erin), "erin").unwrap();
    assert_eq!(read_str(&erins, &c, "secrets/notes.txt").as_deref(), Some("team-only notes v3\n"));
    assert_eq!(read_config(&*fx.backend("alice")).unwrap().format, 2);
    assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));
}

#[test]
fn upgrade_to_3_rotates_rings_to_hpke_and_reseals_nothing() {
    for from in [1, 2] {
        let fx = Fixture::new(from);
        let old = fx.open("alice", Some("alice"));
        let old_view = old.view().clone();
        let old_ids: Vec<ObjectId> = old.store().list_objects().unwrap();
        let old_ring = ring_of(&old, "team");
        let main = tag(&old, "main");
        drop(old);

        let r = upgrade(fx.backend("alice"), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap();
        assert_eq!((r.from, r.to), (from, REPO_FORMAT));
        assert!(r.steps.contains(&"3:hpke-ring-keys".to_string()), "{:?}", r.steps);
        assert!(r.notes.iter().any(|n| n.contains("scope 'team': new key generation 3")), "{:#?}", r.notes);
        assert!(r.notes.iter().any(|n| n.contains("nothing is re-sealed")), "{:#?}", r.notes);

        let mut repo = fx.open("alice", Some("alice"));
        assert_eq!(repo.view(), &old_view);
        let now: std::collections::BTreeSet<ObjectId> = repo.store().list_objects().unwrap().into_iter().collect();
        assert!(old_ids.iter().all(|id| now.contains(id)), "an object disappeared");
        // The ring grew by exactly one signed rotation, wrapped with HPKE.
        let ring = ring_of(&repo, "team");
        assert_eq!(ring.format, RING_FORMAT);
        assert_eq!(ring.log[..old_ring.log.len()], old_ring.log[..]);
        assert_eq!(ring.log.len(), old_ring.log.len() + 1);
        let RingOp::Rotate { rotation } = &ring.log.last().unwrap().op else { panic!() };
        assert!(rotation.wrapped.values().all(WrappedKey::is_hpke));
        assert_eq!(ring.verify().unwrap().generation, 3);

        // An unchanged cloaked file keeps its legacy sealing (and id); a
        // changed one is sealed with AES-SIV under the new generation.
        let old_notes = entry_id(&repo, &main, "secrets/notes.txt");
        let c = commit_edit(&fx, &mut repo, &[("README.md", "Fixture project, upgraded\n")], "after upgrade");
        assert_eq!(entry_id(&repo, &c, "secrets/notes.txt"), old_notes);
        let c = commit_edit(&fx, &mut repo, &[("secrets/notes.txt", "notes after upgrade\n")], "after upgrade 2");
        let new_notes = repo.store().get_raw(&entry_id(&repo, &c, "secrets/notes.txt")).unwrap();
        assert!(new_notes.starts_with(b"veil:sea2\n"));
        assert!(Object::sealed_scope(&new_notes).unwrap().starts_with("team#"));
        let bob = fx.open("alice", Some("bob"));
        assert_eq!(read_str(&bob, &c, "secrets/notes.txt").as_deref(), Some("notes after upgrade\n"));
        assert_eq!(read_str(&bob, &main, "secrets/notes.txt").as_deref(), Some("team-only notes v2\n"));
        let carol = fx.open("alice", Some("carol"));
        assert_eq!(read_str(&carol, &c, "secrets/notes.txt"), None, "revoked before the upgrade");
        assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));

        // Idempotent: nothing left to do, and the step itself is a no-op.
        assert!(upgrade(fx.backend("alice"), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap().up_to_date);
        assert_eq!(repo.keys().migrate_to_hpke("team").unwrap(), HpkeMigration::AlreadyHpke);
    }
}

#[test]
fn upgrade_by_a_non_admin_leaves_the_ring_and_says_who_can_finish() {
    let fx = Fixture::new(2);
    let before = ring_of(&fx.open("alice", Some("alice")), "team");
    let r = upgrade(fx.backend("alice"), Some(fx.identity("bob")), &UpgradeOptions::default()).unwrap();
    assert!(r.notes.iter().any(|n| n.contains("an admin should run")), "{:#?}", r.notes);
    let repo = fx.open("alice", Some("alice"));
    assert_eq!(repo.format(), REPO_FORMAT);
    assert_eq!(ring_of(&repo, "team"), before, "a non-admin changed the ring");
    // The admin finishes it later (also what `vl scope rotate` does).
    assert_eq!(repo.keys().migrate_to_hpke("team").unwrap(), HpkeMigration::Rotated(3));
    assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));
}

#[test]
fn interrupted_upgrade_to_3_resumes_the_ring_step() {
    let fx = Fixture::new(2);
    let fs = fx.backend("alice");
    let mut cfg = read_config(&*fs).unwrap();
    cfg.format = 3;
    fs.write(&p(".veil/repo.json"), &serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    fs.write(
        &p(JOURNAL_PATH),
        br#"{"from":2,"to":3,"started":1,"done":["verify","set-format"]}"#,
    )
    .unwrap();
    let r = upgrade(fs.clone(), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap();
    assert_eq!(r.steps, vec!["3:hpke-ring-keys".to_string()]);
    assert!(!fs.exists(&p(JOURNAL_PATH)).unwrap());
    let repo = fx.open("alice", Some("alice"));
    assert_eq!(ring_of(&repo, "team").verify().unwrap().generation, 3);
}

#[test]
fn aes_siv_objects_and_hpke_rings_never_reach_a_format2_repository() {
    for full in [false, true] {
        let opts = remote::SyncOptions { full, ..Default::default() };
        let fx = Fixture::new(2);
        upgrade(fx.backend("alice"), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap();
        let mut alice = fx.open("alice", Some("alice"));
        // Ring only (the upgrade's rotation), no new objects yet: refused.
        let err = remote::push_with(&mut alice, fx.backend("team-remote"), false, &[], false, &opts).unwrap_err();
        assert!(matches!(err, VeilError::Unsupported(_)) && err.to_string().contains("vl upgrade"), "{err}");
        // With AES-SIV objects: refused too, by the store (pack sink or put_raw).
        let c = commit_edit(&fx, &mut alice, &[("secrets/notes.txt", "sealed with AES-SIV\n")], "siv");
        alice.set_tag("main", c, None, true).unwrap();
        let err = remote::push_with(&mut alice, fx.backend("team-remote"), false, &[], false, &opts).unwrap_err();
        assert!(matches!(err, VeilError::Unsupported(_)) && err.to_string().contains("vl upgrade"), "{err}");
        let team = fx.open("team-remote", None);
        assert_eq!(team.format(), 2);
        assert_eq!(sealed_census(&team).1, 0, "an AES-SIV object reached the format-2 remote");
        assert_eq!(ring_of(&team, "team").format, 2);
        assert_fsck_clean(fx.backend("team-remote"), None);

        // A format-2 clone cannot pull them either.
        let mid = Arc::new(MemoryBackend::new());
        drop(Repo::init_bare(mid.clone()).unwrap());
        remote::push_with(&mut alice, mid.clone(), false, &[], false, &opts).unwrap();
        let mut old = Repo::init_for_clone_at(Arc::new(MemoryBackend::new()), Some(fx.identity("bob")), "bob", 2).unwrap();
        let err = remote::pull_with(&mut old, "origin", mid.clone(), &opts).unwrap_err();
        assert!(matches!(err, VeilError::Unsupported(_)), "{err}");

        // Once the remote is upgraded, the push goes through and Bob reads it.
        upgrade(fx.backend("team-remote"), None, &UpgradeOptions::default()).unwrap();
        remote::push_with(&mut alice, fx.backend("team-remote"), false, &[], false, &opts).unwrap();
        let mut bob = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(fx.identity("bob")), "bob").unwrap();
        remote::pull(&mut bob, "origin", fx.backend("team-remote")).unwrap();
        let main = tag(&bob, "main");
        assert_eq!(read_str(&bob, &main, "secrets/notes.txt").as_deref(), Some("sealed with AES-SIV\n"));
        assert_fsck_clean(fx.backend("team-remote"), None);
    }
}

#[test]
fn fsck_reports_format3_crypto_in_a_format2_repository() {
    let fx = Fixture::new(2);
    let fs = fx.backend("alice");
    let siv = Object::Sealed(Envelope::seal_deterministic(&[1; 32], "team", b"veil:blob\nx").unwrap()).encode();
    let id = ObjectId::hash(&siv);
    let hex = id.hex();
    fs.write(&p(&format!(".veil/objects/{}/{}", &hex[..2], &hex[2..])), &siv).unwrap();
    let report = fsck(fs.clone(), None).unwrap();
    assert!(
        report.findings.iter().any(|f| f.severity == Severity::Corrupt && f.message.contains("format-3 sealed object")),
        "{:#?}",
        report.findings
    );
    // The store refuses to accept it, too.
    let repo = fx.open("alice", Some("alice"));
    let other = Object::Sealed(Envelope::seal_deterministic(&[2; 32], "team", b"veil:blob\ny").unwrap()).encode();
    let err = repo.store().put_raw(&ObjectId::hash(&other), &other).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)), "{err}");
    // An HPKE ring planted in a format-2 repository is reported, and refused by the keychain.
    let fx3 = Fixture::new(3);
    let ring = std::fs::read(fx3.root.join("alice/.veil/meta/keyrings/team.json")).unwrap();
    let r: KeyRing = serde_json::from_slice(&ring).unwrap();
    assert!(matches!(repo.keys().save_ring(&r), Err(VeilError::Unsupported(_))));
    fs.write(&p(".veil/meta/keyrings/team.json"), &ring).unwrap();
    let report = fsck(fs, None).unwrap();
    assert!(
        report.findings.iter().any(|f| f.severity == Severity::Corrupt && f.message.contains("needs ring format 3")),
        "{:#?}",
        report.findings
    );
}

// ---- format 4: first-class conflicts ---------------------------------------------

/// The format-4 set's `conflicted` tag holds a conflict entry for the
/// cloaked `secrets/notes.txt` (both sides sealed for `team`) and the
/// resolution of `src/util/strings.rs` (`vl resolve --theirs`). Members read
/// both sides; the revoked member and the public mirror's readers see
/// neither, only the conflict naming them.
#[test]
fn format_4_fixture_holds_conflicts_as_data_for_their_audiences() {
    use veil_core::conflict::{materialize_entry, Audience};
    let fx = Fixture::new(4);
    for who in ["alice", "bob", "dave"] {
        let repo = fx.open("alice", Some(who));
        let c = tag(&repo, "conflicted");
        let tree = repo.snapshot(&c).unwrap().tree;
        assert_eq!(repo.snapshot(&c).unwrap().conflicts, vec!["secrets/notes.txt".to_string()], "{who}");
        let e = lookup(repo.store(), &tree, &p("secrets/notes.txt")).unwrap().unwrap();
        assert_eq!(e.kind, EntryKind::Conflict, "{who}");
        let m = materialize_entry(repo.store(), &e, Audience::Reader).unwrap();
        let text = String::from_utf8(m.content).unwrap();
        assert!(text.contains("<<<<<<<") && text.contains("side a") && text.contains("side b"), "{who}: {text}");
        assert_eq!(m.visibility, Visibility::Cloaked { scope: "team".into() });
        let s = lookup(repo.store(), &tree, &p("src/util/strings.rs")).unwrap().unwrap();
        assert_eq!(s.kind, EntryKind::File);
        assert!(read_str(&repo, &c, "src/util/strings.rs").unwrap().contains("to_ascii_uppercase"));
    }
    // Carol was revoked before the sides were sealed: redacted.
    let carol = fx.open("alice", Some("carol"));
    let e = lookup(carol.store(), &carol.snapshot(&tag(&carol, "conflicted")).unwrap().tree, &p("secrets/notes.txt")).unwrap().unwrap();
    let m = materialize_entry(carol.store(), &e, Audience::Reader).unwrap();
    assert!(m.unreadable_side);
    assert!(!String::from_utf8_lossy(&m.content).contains("side a"));
    // The public mirror has the conflict, never a sealed side.
    let mirror = fx.open("public-mirror", None);
    let c = tag(&mirror, "conflicted");
    let e = lookup(mirror.store(), &mirror.snapshot(&c).unwrap().tree, &p("secrets/notes.txt")).unwrap().unwrap();
    let conflict = mirror.store().conflict(&e.id).unwrap();
    for t in conflict.interleaved().flatten() {
        assert!(!mirror.store().has(&t.id), "a sealed side reached the public mirror");
    }
    let m = materialize_entry(mirror.store(), &e, Audience::Public).unwrap();
    assert!(!String::from_utf8_lossy(&m.content).contains("team-only"));
    for f in ["alice", "team-remote", "public-mirror"] {
        let id = (f == "alice").then(|| fx.identity("alice"));
        assert_fsck_clean(fx.backend(f), id);
    }
}

/// A format-3 remote or clone never receives a conflict entry: the push is
/// refused (naming `vl upgrade --remote`) and nothing is recorded; after
/// the upgrade it goes through.
#[test]
fn conflicts_never_reach_a_format_3_repository() {
    let f4 = Fixture::new(4);
    let mut alice = f4.open("alice", Some("alice"));
    let remote: Arc<MemoryBackend> = Arc::new(MemoryBackend::new());
    drop(Repo::init_bare_at(remote.clone(), 3).unwrap());
    let before = Repo::open(remote.clone(), None, "remote").unwrap().view().clone();
    let err = remote::push(&mut alice, remote.clone(), false, &["conflicted".into()], false).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)), "{err}");
    assert!(err.to_string().contains("vl upgrade"), "{err}");
    assert_eq!(Repo::open(remote.clone(), None, "remote").unwrap().view(), &before, "the refused push recorded something");
    assert_fsck_clean(remote.clone(), None);
    // A format-3 clone cannot pull it from a format-4 remote either.
    let mut old = Repo::init_for_clone_at(Arc::new(MemoryBackend::new()), Some(f4.identity("bob")), "bob", 3).unwrap();
    let err = remote::pull(&mut old, "origin", f4.backend("team-remote")).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)), "{err}");
    // Upgraded, the remote takes it.
    upgrade(remote.clone(), None, &UpgradeOptions::default()).unwrap();
    remote::push(&mut alice, remote.clone(), false, &["conflicted".into()], false).unwrap();
    assert_fsck_clean(remote, None);
}

/// Upgrading 3 → 4 rewrites nothing: conflicts recorded as markers stay
/// markers (and listed on their snapshots), every id is kept; a merge made
/// afterwards records a conflict entry.
#[test]
fn upgrade_3_to_4_keeps_marker_conflicts_and_records_new_ones_as_data() {
    let fs = Arc::new(MemoryBackend::new());
    let alice = Identity::generate("alice");
    let mut repo = Repo::init_for_clone_at(fs.clone(), Some(alice.clone()), "alice", 3).unwrap();
    repo.keys().create_scope("team").unwrap();
    let w = |repo: &mut Repo, text: &str| {
        fs.write(&p("f.txt"), text.as_bytes()).unwrap();
        repo.snapshot_workspace("default", &*fs).unwrap();
        repo.commit_working_copy("default", "c").unwrap().0
    };
    let base = w(&mut repo, "a\nb\nc\n");
    let ours = w(&mut repo, "a\nOURS\nc\n");
    repo.new_change("default", vec![base], "").unwrap();
    repo.checkout_tree(&*fs, Some(&repo.snapshot(&ours).unwrap().tree), &repo.snapshot(&base).unwrap().tree).unwrap();
    let theirs = w(&mut repo, "a\nTHEIRS\nc\n");
    let m = repo.merge("default", ours, vec![theirs], "merge", None).unwrap();
    assert_eq!(m.conflicts, vec!["f.txt".to_string()]);
    let e = lookup(repo.store(), &repo.snapshot(&m.snapshot).unwrap().tree, &p("f.txt")).unwrap().unwrap();
    assert_eq!(e.kind, EntryKind::File, "format 3 writes markers");
    let ids: Vec<ObjectId> = repo.store().list_objects().unwrap();
    drop(repo);
    let r = upgrade(fs.clone(), Some(alice.clone()), &UpgradeOptions { to: 4, ..UpgradeOptions::default() }).unwrap();
    assert_eq!((r.from, r.to), (3, 4));
    assert!(r.notes.iter().any(|n| n.contains("conflicts recorded before")), "{:#?}", r.notes);
    let mut repo = Repo::open(fs.clone(), Some(alice), "alice").unwrap();
    for id in ids {
        assert!(repo.store().has(&id));
    }
    let s = repo.snapshot(&m.snapshot).unwrap();
    assert_eq!(s.conflicts, vec!["f.txt".to_string()], "the marker conflict stays recorded");
    // A new merge of the same lines: a conflict entry.
    let m2 = repo.merge("default", ours, vec![theirs], "merge again", None).unwrap();
    let e = lookup(repo.store(), &repo.snapshot(&m2.snapshot).unwrap().tree, &p("f.txt")).unwrap().unwrap();
    assert_eq!(e.kind, EntryKind::Conflict);
}

// ---- format 5: symlinks, annotated tags ---------------------------------------

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
        fallback: None,
    }
}

/// The format-5 additions of the fixture set, written through the engine
/// into the `alice/` that `generate.sh` is building (the CLI for links and
/// annotated tags comes later in this round). `generate.sh` runs it, once,
/// with `VEIL_FIXTURE_DIR=<the set being written>`:
///
/// * tag `links`: `main` plus `links/readme` → `../README.md`,
///   `links/words` → an absolute target and `secrets/current` → a target
///   sealed for `team`;
/// * tag `link-conflict`: a child of it whose `links/both` is a link/file
///   conflict (ours a symlink, theirs a file);
/// * annotated tags on `links`: `v5.0` (signed by alice) and
///   `team-release` (cloaked for `team`, its message sealed, signed).
#[test]
#[ignore = "fixture generator: run by tests/fixtures/generate.sh"]
fn write_format_5_extras() {
    use veil_core::{conflict::set_entry, object::TermKind, oplog::Tag, tag_object::Atag, ConflictTerm};
    let out = PathBuf::from(std::env::var("VEIL_FIXTURE_DIR").expect("VEIL_FIXTURE_DIR"));
    let identity = Identity::from_json(&std::fs::read_to_string(out.join("home-alice/identity.json")).unwrap()).unwrap();
    let mut repo = Repo::open(Arc::new(DiskBackend::new(out.join("alice"))), Some(identity.clone()), "alice").unwrap();
    assert!(repo.format() >= 5, "the format-5 extras go into a format-5 (or later) set");
    let main = tag(&repo, "main");
    let store = repo.store().clone();
    let base_tree = repo.snapshot(&main).unwrap().tree;
    let base_tree = match wrapper_of(&store, &base_tree).unwrap() {
        Some(w) => w.inner,
        None => base_tree,
    };
    let team = Visibility::Cloaked { scope: "team".into() };
    let mut tree = base_tree;
    for (path, e) in [
        ("links/readme", special_entry(&repo, "readme", EntryKind::Symlink, LINK_TARGET, Visibility::Public)),
        ("links/words", special_entry(&repo, "words", EntryKind::Symlink, ABSOLUTE_TARGET, Visibility::Public)),
        ("secrets/current", special_entry(&repo, "current", EntryKind::Symlink, SEALED_TARGET, team.clone())),
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
        fallback: None,
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
    let mut team_release = Atag::annotated("team-release", links, store.make_text(TEAM_RELEASE_NOTES, Some("team")).unwrap(), "alice", now);
    team_release.sign(&identity);
    let (v5, team_release) = (store.put_atag(&v5).unwrap(), store.put_atag(&team_release).unwrap());
    let mut tx = repo.transaction("format 5 fixture: links, annotated tags").unwrap();
    tx.view.heads.insert(conflicted);
    let tag_at = |target, cloak: Option<&str>, annotation| Tag {
        target,
        cloak: cloak.map(str::to_string),
        annotation,
    };
    tx.view.tags.insert("links".into(), tag_at(links, None, None));
    tx.view.tags.insert("link-conflict".into(), tag_at(conflicted, None, None));
    tx.view.tags.insert("v5.0".into(), tag_at(links, None, Some(v5)));
    tx.view.tags.insert("team-release".into(), tag_at(links, Some("team"), Some(team_release)));
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

#[test]
fn format_5_fixture_holds_links_and_annotated_tags_for_their_audiences() {
    use veil_core::tag_object::AtagVerification;
    let fx = Fixture::new(5);
    let alice_key = fx.identity("alice").verifying_hex();
    for who in ["alice", "bob", "dave"] {
        let repo = fx.open("alice", Some(who));
        let links = tag(&repo, "links");
        let tree = repo.snapshot(&links).unwrap().tree;
        let entry = |path: &str| lookup(repo.store(), &tree, &p(path)).unwrap().unwrap_or_else(|| panic!("{path}"));
        for (path, kind, content) in [
            ("links/readme", EntryKind::Symlink, LINK_TARGET),
            ("links/words", EntryKind::Symlink, ABSOLUTE_TARGET),
            ("secrets/current", EntryKind::Symlink, SEALED_TARGET),
        ] {
            let e = entry(path);
            assert_eq!(e.kind, kind, "{who} {path}");
            assert!(!e.executable);
            assert_eq!(repo.store().read_entry(&e).unwrap(), content.as_bytes(), "{who} {path}");
        }
        assert!(!entry("secrets/current").visibility.is_public());
        // `walk_files` and diffs see the links (carried by every algorithm).
        let walked: Vec<String> = walk_files(repo.store(), &tree).unwrap().into_iter().map(|(p, _)| p.to_string()).collect();
        assert!(walked.contains(&"links/readme".to_string()) && walked.contains(&"secrets/current".to_string()));
        let main = tag(&repo, "main");
        let changed: Vec<String> = veil_core::tree::diff_trees(repo.store(), Some(&repo.snapshot(&main).unwrap().tree), Some(&tree))
            .unwrap()
            .into_iter()
            .map(|c| c.path.to_string())
            .collect();
        assert!(changed.contains(&"links/readme".to_string()), "{changed:?}");
        // The link/file conflict.
        let c = tag(&repo, "link-conflict");
        assert_eq!(repo.snapshot(&c).unwrap().conflicts, vec!["links/both".to_string()]);
        let ce = lookup(repo.store(), &repo.snapshot(&c).unwrap().tree, &p("links/both")).unwrap().unwrap();
        let conflict = repo.store().conflict(&ce.id).unwrap();
        assert_eq!(conflict.adds[0].as_ref().unwrap().kind, veil_core::object::TermKind::Symlink);
        assert!(conflict.has_special_terms());
        // Annotated tags: signed by alice, the sealed one readable here.
        let v5 = repo.view().tags["v5.0"].clone();
        let atag = repo.store().atag(&v5.annotation.unwrap()).unwrap();
        assert!(matches!(atag.verify("v5.0", &v5.target), AtagVerification::Signed { ref key, .. } if *key == alice_key), "{who}");
        let tr = repo.view().tags["team-release"].clone();
        assert_eq!(tr.cloak.as_deref(), Some("team"));
        let atag = repo.store().atag(&tr.annotation.unwrap()).unwrap();
        assert!(atag.is_sealed());
        assert_eq!(repo.store().read_text(&atag.message).as_deref(), Some(TEAM_RELEASE_NOTES), "{who}");
        assert!(atag.verify("team-release", &tr.target).is_signed());
    }
    // Carol (revoked) and an outsider: the links' names, never the sealed
    // target or the sealed release notes.
    let outsider = Repo::open(fx.backend("alice"), Some(Identity::generate("eve")), "eve").unwrap();
    for (who, repo) in [("carol", fx.open("alice", Some("carol"))), ("eve", outsider)] {
        let tree = repo.snapshot(&tag(&repo, "links")).unwrap().tree;
        let e = lookup(repo.store(), &tree, &p("secrets/current")).unwrap().unwrap();
        assert!(repo.store().read_entry(&e).is_err(), "{who} reads the sealed target");
        let tr = repo.view().tags["team-release"].clone();
        let atag = repo.store().atag(&tr.annotation.unwrap()).unwrap();
        assert_eq!(repo.store().read_text(&atag.message), None, "{who}");
    }
    // The team remote has everything (ciphertext for the sealed parts).
    let team = fx.open("team-remote", None);
    assert!(team.view().tags["team-release"].annotation.is_some());
    assert!(team.view().tags["v5.0"].annotation.is_some());
    // The public mirror: the public release tags with their atags; never
    // the cloaked tag, its atag or the sealed target.
    let mirror = fx.open("public-mirror", None);
    assert!(!mirror.view().tags.contains_key("team-release"), "a cloaked annotated tag was published");
    let v5 = mirror.view().tags["v5.0"].clone();
    assert!(mirror.store().atag(&v5.annotation.unwrap()).unwrap().verify("v5.0", &v5.target).is_signed());
    let alice = fx.open("alice", Some("alice"));
    let sealed_atag = alice.view().tags["team-release"].annotation.unwrap();
    assert!(!mirror.store().has(&sealed_atag), "the sealed atag reached the public mirror");
    let tree = mirror.snapshot(&tag(&mirror, "links")).unwrap().tree;
    let e = lookup(mirror.store(), &tree, &p("secrets/current")).unwrap().unwrap();
    assert!(!mirror.store().has(&e.id), "secrets/current's sealed object reached the public mirror");
    assert_eq!(read_str(&mirror, &tag(&mirror, "links"), "links/readme").as_deref(), Some(LINK_TARGET));
    for (id, bytes) in readable_bytes(&mirror) {
        for secret in [SEALED_TARGET, TEAM_RELEASE_NOTES.trim()] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()), "{} holds {secret:?}", id.short());
        }
    }
    for f in ["alice", "team-remote", "public-mirror"] {
        let id = (f == "alice").then(|| fx.identity("alice"));
        assert_fsck_clean(fx.backend(f), id);
    }
}

/// What a format-4 vl cannot read is refused by a format-4 repository:
/// every format-5 object of the fixture is `Unsupported` there (the only
/// way to simulate the older build: its decoder refuses bit 7 and the
/// term-kind bits, `newer_object_encodings_are_unsupported_not_corrupt`),
/// and a push of one to a format-4 remote fails with the upgrade hint and
/// records nothing; a format-4 clone cannot pull one either.
#[test]
fn format_5_objects_never_reach_a_format_4_repository() {
    let f5 = Fixture::new(5);
    let mut alice = f5.open("alice", Some("alice"));
    let old: Arc<MemoryBackend> = Arc::new(MemoryBackend::new());
    let old_repo = Repo::init_bare_at(old.clone(), 4).unwrap();
    let mut format5 = 0;
    for id in alice.store().list_objects().unwrap() {
        let raw = alice.store().get_raw(&id).unwrap();
        if Object::min_repo_format(&raw) == 5 {
            format5 += 1;
            let err = old_repo.store().put_raw(&id, &raw).unwrap_err();
            assert!(matches!(err, VeilError::Unsupported(ref m) if m.contains("vl upgrade")), "{err}");
        }
    }
    // Trees with links (two directories and their parents), the conflict,
    // two atags, and the trees above them.
    assert!(format5 >= 6, "{format5} format-5 objects in the fixture");
    // Writing them through the API is refused too.
    let a = alice.store().atag(&alice.view().tags["v5.0"].annotation.unwrap()).unwrap();
    assert!(matches!(old_repo.store().put_atag(&a), Err(VeilError::Unsupported(_))));
    let links_tree = alice.snapshot(&tag(&alice, "links")).unwrap().tree;
    let links_dir = lookup(alice.store(), &links_tree, &p("links")).unwrap().unwrap();
    let t = (*alice.store().tree(&links_dir.id).unwrap()).clone();
    assert!(matches!(old_repo.store().put_tree(&t), Err(VeilError::Unsupported(_))));
    drop(old_repo);
    let before = Repo::open(old.clone(), None, "remote").unwrap().view().clone();
    for tags in [vec!["links".to_string()], vec!["v5.0".to_string()], vec!["link-conflict".to_string()]] {
        let err = remote::push(&mut alice, old.clone(), false, &tags, false).unwrap_err();
        assert!(matches!(err, VeilError::Unsupported(_)), "{tags:?}: {err}");
        assert!(err.to_string().contains("vl upgrade"), "{err}");
        assert_eq!(Repo::open(old.clone(), None, "remote").unwrap().view(), &before, "the refused push recorded something");
    }
    assert_fsck_clean(old.clone(), None);
    // A view with an annotation cannot be recorded below format 5 either.
    let mut r4 = Repo::open(old.clone(), None, "remote").unwrap();
    let mut tx = r4.transaction("forge").unwrap();
    tx.view.tags.insert(
        "x1".into(),
        veil_core::oplog::Tag {
            target: r4_root(&old),
            cloak: None,
            annotation: Some(ObjectId([1; 32])),
        },
    );
    assert!(matches!(tx.commit(), Err(VeilError::Unsupported(_))));
    // A format-4 clone cannot pull them from the format-5 remote.
    let mut clone = Repo::init_for_clone_at(Arc::new(MemoryBackend::new()), Some(f5.identity("bob")), "bob", 4).unwrap();
    let err = remote::pull(&mut clone, "origin", f5.backend("team-remote")).unwrap_err();
    assert!(matches!(err, VeilError::Unsupported(_)), "{err}");
    // Upgraded to 5, the remote takes everything.
    upgrade(old.clone(), None, &UpgradeOptions::default()).unwrap();
    remote::push(&mut alice, old.clone(), false, &[], false).unwrap();
    let r = Repo::open(old.clone(), None, "remote").unwrap();
    assert!(r.view().tags["v5.0"].annotation.is_some());
    assert_fsck_clean(old, None);
}

fn r4_root(b: &Arc<MemoryBackend>) -> ObjectId {
    Repo::open(b.clone(), None, "remote").unwrap().root_id()
}

/// `vl upgrade` 4 → 5 rewrites nothing: every object, operation and the
/// view keep their bytes; afterwards format-5 objects may be stored.
#[test]
fn upgrade_4_to_5_rewrites_nothing() {
    let fx = Fixture::new(4);
    let alice_dir = fx.root.join("alice");
    let before_objects: Vec<ObjectId> = fx.open("alice", Some("alice")).store().list_objects().unwrap();
    let before_view = fx.open("alice", Some("alice")).view().clone();
    let ops_before: Vec<(PathBuf, Vec<u8>)> = veil_files(&alice_dir).into_iter().filter(|(p, _)| p.to_string_lossy().contains("/.veil/ops/")).collect();
    let r = upgrade(fx.backend("alice"), Some(fx.identity("alice")), &UpgradeOptions { to: 5, ..Default::default() }).unwrap();
    assert_eq!((r.from, r.to), (4, 5));
    assert!(r.notes.iter().any(|n| n.contains("symlinks")), "{:#?}", r.notes);
    let repo = fx.open("alice", Some("alice"));
    assert_eq!(repo.format(), 5);
    assert_eq!(read_config(&*fx.backend("alice")).unwrap().min_vl.as_deref(), Some(veil_core::repo::min_vl_for_format(5)));
    let after: Vec<ObjectId> = repo.store().list_objects().unwrap();
    for id in &before_objects {
        assert!(after.contains(id), "{} lost", id.short());
    }
    assert_eq!(repo.view(), &before_view, "the view changed");
    let ops_after: Vec<(PathBuf, Vec<u8>)> = veil_files(&alice_dir).into_iter().filter(|(p, _)| p.to_string_lossy().contains("/.veil/ops/")).collect();
    for op in &ops_before {
        assert!(ops_after.contains(op), "operation {} rewritten", op.0.display());
    }
    // Idempotent, and now an atag can be stored.
    let again = upgrade(fx.backend("alice"), Some(fx.identity("alice")), &UpgradeOptions::default()).unwrap();
    assert_eq!(again.from, 5);
    let a = veil_core::tag_object::Atag::annotated("v1", tag(&repo, "main"), Text::Plain("x".into()), "alice", 1);
    repo.store().put_atag(&a).unwrap();
    assert_fsck_clean(fx.backend("alice"), Some(fx.identity("alice")));
    // The fixture's `upgraded/` set (format 4's alice after the upgrade).
    let f5 = Fixture::new(5);
    let up = Repo::open(f5.backend("upgraded/alice"), Some(f5.identity_at("upgraded", "alice")), "alice").unwrap();
    assert_eq!(up.format(), 5);
    assert!(read_str(&up, &tag(&up, "main"), "UPGRADED.md").is_some());
}
