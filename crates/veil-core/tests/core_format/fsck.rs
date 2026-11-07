//! `fsck` against deliberately corrupted repositories (all in memory).

use std::sync::Arc;

use veil_core::{
    commands::EmbargoSpec,
    fsck::{fsck, fsck_repo, FsckReport, Severity},
    object::{Object, Tree, TreeEntry},
    remote,
    tree::lookup,
    EntryKind, Identity, MemoryBackend, ObjectId, Repo, Snapshot, StorageBackend, VPath, Visibility,
};

const WS: &str = "default";

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

struct Fixture {
    repo: Repo,
    fs: Arc<MemoryBackend>,
    id: Identity,
    main: ObjectId,
}

/// A repository with public content, a sealed secret, an embargo, a tag, a virtual
/// workspace and some rewritten history.
fn fixture() -> Fixture {
    let fs = Arc::new(MemoryBackend::new());
    let id = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    fs.write(&p("src/lib.rs"), b"pub fn f() {}\n").unwrap();
    fs.write(&p("secrets/.env.db"), b"password: hunter2\n").unwrap();
    repo.snapshot_workspace(WS, &*fs).unwrap();
    let (v1, _) = repo.commit_working_copy(WS, "v1").unwrap();
    repo.describe(v1, "v1, reworded").unwrap();
    let v1 = repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().parents[0];
    repo.set_tag("main", v1, false).unwrap();
    let ws = repo.ephemeral_workspace(v1).unwrap();
    ws.write("src/lib.rs", "pub fn f() { fixed() }\n").unwrap();
    let (fix, _) = repo.commit_ephemeral(&ws, "fix").unwrap();
    let m = repo
        .merge(
            WS,
            v1,
            vec![fix],
            "embargoed fix",
            Some(EmbargoSpec {
                scope: "team".into(),
                until: None,
            }),
        )
        .unwrap();
    repo.create_workspace("agent", vec![m.snapshot]).unwrap();
    Fixture {
        repo,
        fs,
        id,
        main: m.snapshot,
    }
}

fn object_path(id: &ObjectId) -> VPath {
    let h = id.hex();
    p(&format!(".veil/objects/{}/{}", &h[..2], &h[2..]))
}

fn entry(repo: &Repo, snap: &ObjectId, path: &str) -> TreeEntry {
    lookup(repo.store(), &repo.snapshot(snap).unwrap().tree, &p(path))
        .unwrap()
        .unwrap()
}

fn corrupt_messages(r: &FsckReport) -> Vec<String> {
    r.of(Severity::Corrupt).map(|f| f.message.clone()).collect()
}

fn assert_clean(r: &FsckReport) {
    let bad: Vec<String> = r
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Corrupt | Severity::Warning))
        .map(|f| f.to_string())
        .collect();
    assert!(bad.is_empty(), "unexpected findings: {bad:#?}");
}

fn has(r: &FsckReport, sev: Severity, needle: &str) -> bool {
    r.of(sev).any(|f| f.message.contains(needle))
}

#[test]
fn healthy_repository_is_clean() {
    let f = fixture();
    let r = fsck_repo(&f.repo).unwrap();
    assert_clean(&r);
    assert!(r.is_ok());
    assert!(r.snapshots >= 6 && r.operations >= 8 && r.keyrings == 1 && r.embargoes == 1);
    assert_eq!(r.sealed_unreadable, 0, "the owner can open everything");
    // An outsider can open nothing sealed, but nothing is wrong either.
    let outsider = fsck(f.fs.clone(), Some(Identity::generate("eve"))).unwrap();
    assert_clean(&outsider);
    assert!(outsider.sealed_unreadable > 0);
}

#[test]
fn flipped_bytes_are_a_hash_mismatch() {
    let f = fixture();
    let e = entry(&f.repo, &f.main, ".veilpolicy");
    let mut raw = f.fs.read(&object_path(&e.id)).unwrap();
    raw[12] ^= 0x20;
    f.fs.write(&object_path(&e.id), &raw).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(!r.is_ok());
    assert!(
        has(&r, Severity::Corrupt, "does not match its hash"),
        "{:#?}",
        r.findings
    );
}

#[test]
fn undecodable_objects_are_corrupt_even_if_unreachable() {
    let f = fixture();
    let raw = b"veil:tree\n{not json".to_vec();
    let id = ObjectId::hash(&raw);
    f.fs.write(&object_path(&id), &raw).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(has(&r, Severity::Corrupt, "cannot be decoded"), "{:#?}", r.findings);
    assert_eq!(r.objects_unreachable, 1);
}

#[test]
fn missing_public_content_is_corrupt_but_missing_cloaked_content_is_redacted() {
    let f = fixture();
    let cloaked = entry(&f.repo, &f.main, "secrets/.env.db");
    assert!(matches!(cloaked.visibility, Visibility::Cloaked { .. }));
    f.fs.remove_file(&object_path(&cloaked.id)).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(r.is_ok(), "{:#?}", corrupt_messages(&r));
    assert!(has(&r, Severity::Redacted, "secrets/.env.db"));

    let public = entry(&f.repo, &f.main, ".veilpolicy");
    f.fs.remove_file(&object_path(&public.id)).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(!r.is_ok());
    assert!(has(&r, Severity::Corrupt, ".veilpolicy"), "{:#?}", r.findings);
}

#[test]
fn missing_trees_and_parents_are_corrupt() {
    let f = fixture();
    let src = entry(&f.repo, &f.main, "src");
    assert_eq!(src.kind, EntryKind::Dir);
    f.fs.remove_file(&object_path(&src.id)).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(has(&r, Severity::Corrupt, "tree"), "{:#?}", r.findings);

    let f = fixture();
    let parent = f.repo.snapshot(&f.main).unwrap().parents[0];
    f.fs.remove_file(&object_path(&parent)).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(
        has(&r, Severity::Corrupt, &format!("snapshot {parent}")),
        "{:#?}",
        r.findings
    );
}

#[test]
fn clone_of_a_public_mirror_only_has_expected_redactions() {
    let mut f = fixture();
    let main = f.main;
    f.repo.set_tag("main", main, false).unwrap();
    // Below the embargoed merge (withheld from every remote until its
    // release): the history with the secret.
    let v1 = f.repo.snapshot(&main).unwrap().parents[0];
    f.repo.set_tag("v1", v1, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut f.repo, mirror.clone(), true, &[], false).unwrap();

    // The mirror itself lacks the sealed secret: expected.
    let r = fsck(mirror.clone(), None).unwrap();
    assert!(r.is_ok(), "{:#?}", corrupt_messages(&r));
    assert!(has(&r, Severity::Redacted, "sealed under 'team'"), "{:#?}", r.findings);

    // So does a stranger's clone of it.
    let carol_fs = Arc::new(MemoryBackend::new());
    let mut carol = Repo::init(carol_fs, Some(Identity::generate("carol")), "carol").unwrap();
    remote::pull(&mut carol, "origin", mirror).unwrap();
    let r = fsck_repo(&carol).unwrap();
    assert!(r.is_ok(), "{:#?}", corrupt_messages(&r));
    assert!(r.count(Severity::Redacted) >= 1);
}

#[test]
fn broken_key_rings_and_embargo_records_are_corrupt() {
    let f = fixture();
    let ring = p(".veil/meta/keyrings/team.json");
    let original = f.fs.read(&ring).unwrap();
    f.fs.write(&ring, b"{\"scope\": ").unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(has(&r, Severity::Corrupt, "key ring"), "{:#?}", r.findings);

    // A valid ring filed under the wrong name.
    f.fs.write(&ring, &original).unwrap();
    f.fs.write(&p(".veil/meta/keyrings/ops.json"), &original).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(has(&r, Severity::Corrupt, "filed as 'ops'"), "{:#?}", r.findings);
    f.fs.remove_file(&p(".veil/meta/keyrings/ops.json")).unwrap();

    let records = f.fs.list_dir(&p(".veil/meta/embargoes")).unwrap();
    let rec = p(&format!(".veil/meta/embargoes/{}", records[0].name));
    f.fs.write(&rec, b"[]").unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(has(&r, Severity::Corrupt, "embargo record"), "{:#?}", r.findings);
    // The history still uses that embargo, which now has no record.
    assert!(has(&r, Severity::Warning, "has no record"));
}

#[test]
fn op_log_damage_is_detected() {
    // A missing operation in the middle breaks a parent link.
    let f = fixture();
    let log = f.repo.op_log(3).unwrap();
    let middle = log[1].0;
    f.fs.remove_file(&p(&format!(".veil/ops/{}", middle.hex()))).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(
        has(
            &r,
            Severity::Corrupt,
            &format!("parent operation {} is missing", middle.short())
        ),
        "{:#?}",
        r.findings
    );

    // A tampered operation no longer matches its id.
    let f = fixture();
    let head = f.repo.op_id();
    let path = p(&format!(".veil/ops/{}", head.hex()));
    let mut raw = f.fs.read(&path).unwrap();
    raw.extend_from_slice(b" ");
    f.fs.write(&path, &raw).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(has(&r, Severity::Corrupt, "does not match its id"), "{:#?}", r.findings);

    // A garbage head; fsck still checks everything else (no Repo::open).
    let f = fixture();
    f.fs.write(&p(".veil/op_head"), b"not an id").unwrap();
    assert!(Repo::open(f.fs.clone(), Some(f.id.clone()), "alice").is_err());
    let r = fsck(f.fs.clone(), Some(f.id.clone())).unwrap();
    assert!(has(&r, Severity::Corrupt, "op_head"));
    assert!(r.snapshots > 0, "retained operations are still walked");

    // A dangling operation (crash between writing an op and moving the head)
    // is only a note.
    let f = fixture();
    let mut op = f.repo.ops().get(&f.repo.op_id()).unwrap();
    op.description = "never committed".into();
    op.parents = vec![f.repo.op_id()];
    f.repo.ops().put(&op).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert_clean(&r);
    assert!(has(&r, Severity::Note, "not reachable from the head"));
}

#[test]
fn hostile_tree_entry_names_are_corrupt() {
    let mut f = fixture();
    let blob = f.repo.store().put(&Object::Blob(b"x".to_vec())).unwrap();
    let mut evil = TreeEntry::dir("..", blob);
    evil.kind = EntryKind::File;
    let tree = f.repo.store().put(&Object::Tree(Tree { entries: vec![evil] })).unwrap();
    let parent = f.main;
    let snap = Snapshot {
        parents: vec![parent],
        tree,
        ..(*f.repo.snapshot(&parent).unwrap()).clone()
    };
    let mut tx = f.repo.transaction("plant").unwrap();
    tx.write_snapshot(&snap).unwrap();
    tx.commit().unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert!(has(&r, Severity::Corrupt, "invalid entry name"), "{:#?}", r.findings);
}

#[test]
fn leftovers_of_interrupted_commands_are_notes() {
    let f = fixture();
    f.fs.write(&p(".veil/objects/ab/.cdef.vltmp1234"), b"partial").unwrap();
    f.fs.write(&p(".veil/lock"), b"1 0").unwrap();
    let orphan = f.repo.store().put(&Object::Blob(b"orphan".to_vec())).unwrap();
    let r = fsck_repo(&f.repo).unwrap();
    assert_clean(&r);
    assert!(has(&r, Severity::Note, "temporary file"));
    assert!(has(&r, Severity::Note, "repository lock present"));
    assert!(has(&r, Severity::Note, "unreachable object"));
    assert!(r.objects_unreachable >= 1 && f.repo.store().has(&orphan));
}
