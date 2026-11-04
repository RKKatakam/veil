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
    ]
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
    assert_eq!(r.steps.last().map(String::as_str), Some("3:hpke-ring-keys"));
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
    assert_eq!(cfg.min_vl.as_deref(), Some("1.0.0"));

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
    // Reserved flag bits and tier in a binary tree.
    let mut t = Tree::default();
    t.insert(TreeEntry::dir("a", ObjectId([1; 32])));
    let good = Object::Tree(t).encode_with(TreeEncoding::Binary);
    let flags_at = 10 + 1 + 1 + 1 + 1; // tag, version, count, name_len, name
    for bad_flags in [0x41u8, 0x81, 0x31] {
        let mut raw = good.clone();
        raw[flags_at] = bad_flags;
        unsupported(&raw);
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
        assert_eq!((r.from, r.to), (from, 3));
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
    assert_eq!(repo.format(), 3);
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
        let opts = remote::SyncOptions { full };
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
