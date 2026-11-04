//! Repository format 5 (the Git-parity round): symlink and gitlink tree
//! entries and conflict terms, annotated tags (`veil:atag`), and how every
//! algorithm carries them before the working-copy and Git-bridge streams
//! implement them (see `docs/FORMAT.md` §3.7–3.8).
//!
//! Security properties tested here:
//!
//! * a sealed symlink target, a sealed gitlink pointer and a cloaked tag's
//!   annotation (its sealed message) never reach a public remote, by any
//!   route (property test over the secret strings);
//! * an atag is pushed only with its tag, so an atag whose target is
//!   withheld by an embargo stays here with it;
//! * a forged, re-targeted or transplanted annotation is never pushed,
//!   never taken from a hostile remote, and never reported as signed;
//! * gc keeps atags, their targets and link objects; fsck checks them;
//! * checkout never writes a link target as a file, and the builder keeps
//!   the entry (no data loss), merges never merge link targets by line.

mod adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    conflict::set_entry,
    commands::EmbargoSpec,
    fsck::{fsck, Severity},
    gc::{gc, GcOptions},
    object::{EntryKind, Object, Snapshot, TermKind, Text, Tree, TreeEntry, Visibility},
    oplog::Tag,
    remote,
    tag_object::{Atag, AtagVerification},
    tree::lookup,
    ChangeId, MemoryBackend, ObjectId, Repo, StorageBackend, VeilError,
};

fn team() -> Visibility {
    Visibility::Cloaked { scope: "team".into() }
}

fn link(repo: &Repo, name: &str, kind: EntryKind, content: &str, vis: Visibility) -> TreeEntry {
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

/// `tree` with `entry` at `path` (creating a missing parent directory).
fn put_at(repo: &Repo, tree: ObjectId, path: &str, entry: TreeEntry) -> ObjectId {
    let store = repo.store();
    let path = p(path);
    let parent = path.parent().unwrap();
    if parent.is_root() || lookup(store, &tree, &parent).unwrap().is_some() {
        set_entry(store, &tree, &path, Some(entry)).unwrap()
    } else {
        let dir = store.put_tree(&Tree { entries: vec![entry] }).unwrap();
        set_entry(store, &tree, &parent, Some(TreeEntry::dir(parent.file_name(), dir))).unwrap()
    }
}

/// A signed snapshot of `tree` on `parent`.
fn snapshot(repo: &Repo, parent: ObjectId, tree: ObjectId, conflicts: Vec<String>) -> ObjectId {
    let mut s = Snapshot {
        parents: vec![parent],
        change_id: ChangeId::random(),
        tree,
        description: Text::Plain("links".into()),
        author: "alice".into(),
        timestamp: 1,
        conflicts,
        ..Snapshot::root(tree)
    };
    s.sign(repo.identity().unwrap());
    repo.store().put_snapshot(&s).unwrap()
}

fn set_view_tag(repo: &mut Repo, name: &str, tag: Tag) {
    let mut tx = repo.transaction("tag").unwrap();
    tx.view.heads.insert(tag.target);
    tx.view.tags.insert(name.into(), tag);
    tx.commit().unwrap();
}

fn annotate(repo: &Repo, name: &str, target: ObjectId, message: Text) -> ObjectId {
    let mut a = Atag::annotated(name, target, message, "alice", 7);
    a.sign(repo.identity().unwrap());
    repo.store().put_atag(&a).unwrap()
}

/// Alice's format-5 repository: `main` (a public file), and `links` on it
/// with a public symlink, a sealed symlink, a public and a sealed gitlink.
fn links_repo(sealed_target: &str, sealed_pointer: &str) -> (Repo, Arc<MemoryBackend>, ObjectId, ObjectId) {
    let (mut alice, fs, _) = new_repo("alice");
    assert_eq!(alice.format(), 5);
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let mut tree = alice.snapshot(&main).unwrap().tree;
    for (path, kind, content, vis) in [
        ("links/readme", EntryKind::Symlink, "../README", Visibility::Public),
        ("links/private", EntryKind::Symlink, sealed_target, team()),
        ("vendor/sdk", EntryKind::Gitlink, "0123456789abcdef0123456789abcdef01234567\n", Visibility::Public),
        ("vendor/private", EntryKind::Gitlink, sealed_pointer, team()),
    ] {
        let name = path.rsplit('/').next().unwrap();
        tree = put_at(&alice, tree, path, link(&alice, name, kind, content, vis));
    }
    let links = snapshot(&alice, main, tree, vec![]);
    set_view_tag(&mut alice, "links", Tag::new(links, None));
    (alice, fs, main, links)
}

// ---- confidentiality --------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    /// Whatever the secret strings, a public push carries none of them: not
    /// the sealed symlink target, not the sealed gitlink pointer, not the
    /// cloaked tag's sealed message (nor its atag), not a sealed message
    /// smuggled into a non-cloaked tag's atag. A team push carries them all
    /// (as ciphertext).
    #[test]
    fn a_public_push_never_carries_sealed_link_targets_or_cloaked_annotations(
        target in "/srv/[a-z]{6,12}-secret",
        pointer in "[0-9a-f]{40}",
        notes in "release notes [a-z]{8,16}",
    ) {
        let pointer = format!("{pointer}\n");
        let (mut alice, _fs, _, links) = links_repo(&target, &pointer);
        let sealed = alice.store().make_text(&notes, Some("team")).unwrap();
        let cloaked_atag = annotate(&alice, "team-release", links, sealed.clone());
        set_view_tag(&mut alice, "team-release", Tag { target: links, cloak: Some("team".into()), annotation: Some(cloaked_atag) });
        // A non-cloaked tag whose atag holds a sealed message (only a bug or
        // a hostile edit makes one): withheld from the public remote too.
        let smuggled = annotate(&alice, "smuggled", links, sealed);
        set_view_tag(&mut alice, "smuggled", Tag { target: links, cloak: None, annotation: Some(smuggled) });
        let public_atag = annotate(&alice, "v1.0", links, Text::Plain("public notes\n".into()));
        set_view_tag(&mut alice, "v1.0", Tag { target: links, cloak: None, annotation: Some(public_atag) });

        let mirror = Arc::new(MemoryBackend::new());
        let report = remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
        let skipped: Vec<&str> = report.tags_skipped.iter().map(|(n, _)| n.as_str()).collect();
        prop_assert!(skipped.contains(&"team-release") && skipped.contains(&"smuggled"), "{:?}", report.tags_skipped);
        for secret in [target.as_bytes(), pointer.trim().as_bytes(), notes.as_bytes()] {
            prop_assert!(backend_contains(&*mirror, secret).is_empty(), "{:?} reached the public mirror", String::from_utf8_lossy(secret));
        }
        let m = Repo::open(mirror.clone(), None, "remote").unwrap();
        prop_assert!(!m.store().has(&cloaked_atag) && !m.store().has(&smuggled));
        prop_assert!(!m.view().tags.contains_key("team-release") && !m.view().tags.contains_key("smuggled"));
        let v1 = &m.view().tags["v1.0"];
        prop_assert_eq!(v1.annotation, Some(public_atag));
        prop_assert!(m.store().atag(&public_atag).unwrap().verify("v1.0", &links).is_signed());
        // The public link is there; the sealed ones are named, not sent.
        let tree = m.snapshot(&links).unwrap().tree;
        let e = lookup(m.store(), &tree, &p("links/readme")).unwrap().unwrap();
        prop_assert_eq!(m.store().read_entry(&e).unwrap(), b"../README".to_vec());
        let e = lookup(m.store(), &tree, &p("links/private")).unwrap().unwrap();
        prop_assert!(!m.store().has(&e.id));

        // A team remote gets everything, sealed.
        let team_remote = Arc::new(MemoryBackend::new());
        remote::push(&mut alice, team_remote.clone(), false, &[], false).unwrap();
        let t = Repo::open(team_remote.clone(), None, "remote").unwrap();
        prop_assert!(t.store().has(&cloaked_atag));
        prop_assert_eq!(t.view().tags["team-release"].annotation, Some(cloaked_atag));
        for secret in [target.as_bytes(), notes.as_bytes()] {
            prop_assert!(backend_contains(&*team_remote, secret).is_empty(), "plaintext on the team remote");
        }
    }
}

/// An atag is sent only with its tag: one on the embargoed fix (withheld
/// history) stays here, on the team remote as on the public one, until the
/// release; its message never travels ahead of its target.
#[test]
fn an_annotation_of_embargo_withheld_history_stays_with_it() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    alice.create_workspace("fix", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify() }\n").unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let r = alice
        .merge(WS, main, vec![fix], "merge", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    alice.set_tag("main", r.snapshot, None, false).unwrap();
    const NOTES: &str = "fixes the auth bypass in check()";
    let a = annotate(&alice, "v1.2.1", fix, Text::Plain(NOTES.into()));
    set_view_tag(&mut alice, "v1.2.1", Tag { target: fix, cloak: None, annotation: Some(a) });
    let mirror = Arc::new(MemoryBackend::new());
    let report = remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(report.tags_skipped.iter().any(|(n, why)| n == "v1.2.1" && why.contains("embargo")), "{:?}", report.tags_skipped);
    assert!(backend_contains(&*mirror, NOTES.as_bytes()).is_empty(), "the annotation travelled ahead of its target");
    let m = Repo::open(mirror, None, "remote").unwrap();
    assert!(!m.store().has(&a));
}

// ---- forged, re-targeted and transplanted annotations ----------------------

#[test]
fn forged_retargeted_and_transplanted_annotations_are_never_pushed() {
    let (mut alice, _fs, main, links) = links_repo("/x", "fedcba9876543210fedcba9876543210fedcba98\n");
    // Transplanted: v2's view entry names v1's genuine atag.
    let v1 = annotate(&alice, "v1", links, Text::Plain("one".into()));
    set_view_tag(&mut alice, "v2", Tag { target: links, cloak: None, annotation: Some(v1) });
    // Re-targeted: the entry moved to main, the atag still says links.
    let moved = annotate(&alice, "moved", links, Text::Plain("m".into()));
    set_view_tag(&mut alice, "moved", Tag { target: main, cloak: None, annotation: Some(moved) });
    // Missing, and not an atag at all.
    set_view_tag(&mut alice, "gone", Tag { target: links, cloak: None, annotation: Some(ObjectId([9; 32])) });
    set_view_tag(&mut alice, "notatag", Tag { target: links, cloak: None, annotation: Some(links) });
    let r = Arc::new(MemoryBackend::new());
    let report = remote::push(&mut alice, r.clone(), false, &[], false).unwrap();
    for name in ["v2", "moved", "gone", "notatag"] {
        assert!(report.tags_skipped.iter().any(|(n, _)| n == name), "{name}: {:?}", report.tags_skipped);
    }
    let rr = Repo::open(r, None, "remote").unwrap();
    for name in ["v2", "moved", "gone", "notatag"] {
        assert!(!rr.view().tags.contains_key(name), "{name} was pushed");
    }
    assert!(rr.view().tags.contains_key("links"));
    // fsck of the local repository names each problem.
    let report = fsck(alice.backend().clone(), alice.identity().cloned()).unwrap();
    let text: Vec<String> = report.findings.iter().map(|f| f.to_string()).collect();
    assert!(text.iter().any(|f| f.contains("'v2'") && f.contains("name mismatch")), "{text:#?}");
    assert!(text.iter().any(|f| f.contains("'moved'") && f.contains("target mismatch")), "{text:#?}");
    assert!(report.findings.iter().any(|f| f.severity == Severity::Corrupt && f.message.contains("is missing")), "{text:#?}");
}

/// A hostile remote serving a transplanted, re-targeted or forged-signature
/// annotation: the tag is received without the transplanted ones (with a
/// warning), and a forged signature is never reported as signed.
#[test]
fn a_hostile_remotes_annotations_are_checked_on_pull() {
    let (mut mallory, _fs, main, links) = links_repo("/x", "fedcba9876543210fedcba9876543210fedcba98\n");
    let genuine = annotate(&mallory, "v1", links, Text::Plain("one".into()));
    let retargeted = annotate(&mallory, "v3", links, Text::Plain("three".into()));
    // A forged signature: alice's key claimed, mallory's signature.
    let alice = veil_core::Identity::generate("alice");
    let mut forged = Atag::annotated("v4", links, Text::Plain("four".into()), "alice", 1);
    forged.sign(mallory.identity().unwrap());
    let mut sig = forged.signature.clone().unwrap();
    sig.key = alice.verifying_hex();
    sig.signer = alice.public_hex();
    forged.signature = Some(sig);
    let forged = mallory.store().put_atag(&forged).unwrap();
    // Plant the hostile view directly on a bare remote.
    let r = Arc::new(MemoryBackend::new());
    remote::push(&mut mallory, r.clone(), false, &[], false).unwrap();
    for id in [genuine, retargeted, forged] {
        let raw = mallory.store().get_raw(&id).unwrap();
        let rr = Repo::open(r.clone(), None, "remote").unwrap();
        rr.store().put_raw(&id, &raw).unwrap();
    }
    let mut rr = Repo::open(r.clone(), None, "remote").unwrap();
    let mut tx = rr.transaction("evil").unwrap();
    tx.view.tags.insert("v2".into(), Tag { target: links, cloak: None, annotation: Some(genuine) });
    tx.view.tags.insert("v3".into(), Tag { target: main, cloak: None, annotation: Some(retargeted) });
    tx.view.tags.insert("v4".into(), Tag { target: links, cloak: None, annotation: Some(forged) });
    tx.view.tags.insert("v5".into(), Tag { target: links, cloak: None, annotation: Some(ObjectId([7; 32])) });
    tx.commit().unwrap();
    let (mut victim, _, _) = new_repo("victim");
    let report = remote::pull(&mut victim, "origin", r).unwrap();
    for name in ["v2", "v3", "v5"] {
        assert_eq!(victim.view().tags[name].annotation, None, "{name} kept a transplanted or missing annotation");
        assert!(report.warnings.iter().any(|w| w.contains(&format!("'{name}'"))), "{name}: {:?}", report.warnings);
    }
    let v4 = victim.view().tags["v4"].clone();
    let atag = victim.store().atag(&v4.annotation.unwrap()).unwrap();
    assert_eq!(atag.verify("v4", &v4.target), AtagVerification::BadSignature);
    // fsck warns about it.
    let f = fsck(victim.backend().clone(), victim.identity().cloned()).unwrap();
    assert!(f.findings.iter().any(|f| f.severity == Severity::Warning && f.message.contains("'v4'") && f.message.contains("bad signature")), "{:#?}", f.findings);
}

/// A tag name is attacker-controlled on pull: the fsck message quoting it
/// escapes control characters; atag names with them never decode.
#[test]
fn hostile_atag_names_never_decode() {
    for name in ["v1\u{1b}[2J", "a\nb", "../../x", "", "root", "x\u{0}y"] {
        let a = Atag::annotated(name, ObjectId([1; 32]), Text::Plain(String::new()), "t", 0);
        let raw = Object::Atag(a).encode();
        assert!(matches!(Object::decode(&raw), Err(VeilError::Corrupt(..))), "{name:?}");
    }
}

// ---- gc and fsck --------------------------------------------------------------

#[test]
fn gc_keeps_annotations_their_targets_and_link_objects() {
    let (mut alice, _fs, main, links) = links_repo("/srv/x", "fedcba9876543210fedcba9876543210fedcba98\n");
    // A target reachable only through a remote release tag's atag.
    let only_tree = put_at(&alice, alice.snapshot(&main).unwrap().tree, "only/link", link(&alice, "link", EntryKind::Symlink, "../x", Visibility::Public));
    let only = snapshot(&alice, main, only_tree, vec![]);
    let release = annotate(&alice, "v0.9", only, Text::Plain("imported".into()));
    let v1 = annotate(&alice, "v1.0", links, Text::Plain("one".into()));
    let mut tx = alice.transaction("tags").unwrap();
    tx.view.tags.insert("v1.0".into(), Tag { target: links, cloak: None, annotation: Some(v1) });
    tx.view.remote_release_tags.insert("github/v0.9".into(), release);
    tx.commit().unwrap();
    let opts = GcOptions {
        grace: std::time::Duration::ZERO,
        keep_ops: Some(std::time::Duration::ZERO),
        ..GcOptions::default()
    };
    let report = gc(&mut alice, &opts).unwrap();
    assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);
    for id in [v1, release, only, links] {
        assert!(alice.store().has(&id), "gc deleted {}", id.short());
    }
    let tree = alice.snapshot(&links).unwrap().tree;
    for path in ["links/readme", "links/private", "vendor/sdk", "vendor/private"] {
        let e = lookup(alice.store(), &tree, &p(path)).unwrap().unwrap();
        assert!(alice.store().has(&e.id), "gc deleted {path}");
    }
    let e = lookup(alice.store(), &only_tree, &p("only/link")).unwrap().unwrap();
    assert!(alice.store().has(&e.id));
    let f = fsck(alice.backend().clone(), alice.identity().cloned()).unwrap();
    assert!(f.findings.iter().all(|f| !matches!(f.severity, Severity::Corrupt | Severity::Warning)), "{:#?}", f.findings);
}

#[test]
fn fsck_checks_link_and_gitlink_content() {
    let (mut alice, _fs, main, _) = links_repo("/x", "fedcba9876543210fedcba9876543210fedcba98\n");
    let mut tree = alice.snapshot(&main).unwrap().tree;
    for (path, kind, content) in [
        ("bad/nul", EntryKind::Symlink, "a\0b"),
        ("bad/pointer", EntryKind::Gitlink, "not a commit\n"),
        ("bad/upper", EntryKind::Gitlink, "0123456789ABCDEF0123456789abcdef01234567\n"),
    ] {
        let name = path.rsplit('/').next().unwrap();
        tree = put_at(&alice, tree, path, link(&alice, name, kind, content, Visibility::Public));
    }
    let long = "x".repeat(veil_core::fsck::MAX_LINK_TARGET + 1);
    tree = put_at(&alice, tree, "bad/long", link(&alice, "long", EntryKind::Symlink, &long, Visibility::Public));
    let s = snapshot(&alice, main, tree, vec![]);
    set_view_tag(&mut alice, "bad", Tag::new(s, None));
    let f = fsck(alice.backend().clone(), alice.identity().cloned()).unwrap();
    for (path, why) in [("bad/nul", "NUL"), ("bad/pointer", "Git commit id"), ("bad/upper", "Git commit id"), ("bad/long", "over")] {
        assert!(
            f.findings.iter().any(|x| x.severity == Severity::Warning && x.message.contains(path) && x.message.contains(why)),
            "{path}: {:#?}",
            f.findings
        );
    }
}

// ---- carried, never misread -----------------------------------------------------

/// Checkout writes a link as a link (replacing the file version it wrote
/// before) and a gitlink as its submodule's empty directory, and the next
/// snapshot keeps both entries unchanged (stream W1).
#[test]
fn checkout_writes_links_and_the_builder_keeps_them() {
    let (mut alice, fs, main, _) = links_repo("/x", "fedcba9876543210fedcba9876543210fedcba98\n");
    // `links/readme` is a file in `main`'s child, then a symlink.
    let file_tree = put_at(&alice, alice.snapshot(&main).unwrap().tree, "links/readme", TreeEntry {
        name: "readme".into(),
        kind: EntryKind::File,
        id: alice.store().store_file(b"a file\n", &Visibility::Public).unwrap(),
        size: 7,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
    });
    let link_tree = put_at(&alice, file_tree, "links/readme", link(&alice, "readme", EntryKind::Symlink, "../README", Visibility::Public));
    let link_tree = put_at(&alice, link_tree, "vendor/sdk", link(&alice, "sdk", EntryKind::Gitlink, "0123456789abcdef0123456789abcdef01234567\n", Visibility::Public));
    let main_tree = alice.snapshot(&main).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&main_tree), &file_tree).unwrap();
    assert_eq!(fs.read(&p("links/readme")).unwrap(), b"a file\n");
    let r = alice.checkout_tree(&*fs, Some(&file_tree), &link_tree).unwrap();
    assert!(r.failed.is_empty() && r.kept_local.is_empty(), "{r:?}");
    assert_eq!(fs.read_link(&p("links/readme")).unwrap(), b"../README");
    assert_eq!(fs.metadata(&p("vendor/sdk")).unwrap().unwrap().kind, veil_core::vfs::NodeKind::Dir);
    // The working copy's snapshot keeps both entries, unchanged.
    let wc = snapshot(&alice, main, link_tree, vec![]);
    let mut tx = alice.transaction("wc").unwrap();
    tx.view.workspaces.get_mut(WS).unwrap().wc = wc;
    tx.view.heads.insert(wc);
    tx.commit().unwrap();
    let s = alice.snapshot_workspace(WS, &*fs).unwrap();
    let tree = alice.snapshot(&s.snapshot).unwrap().tree;
    for path in ["links/readme", "vendor/sdk"] {
        let want = lookup(alice.store(), &link_tree, &p(path)).unwrap().unwrap();
        assert_eq!(lookup(alice.store(), &tree, &p(path)).unwrap(), Some(want), "{path} lost by the snapshot");
    }
}

/// Merges carry links: one side's change wins trivially; two different
/// targets are a conflict entry with symlink terms (never a line merge of
/// the targets), which checkout writes as our side, as it is (never a file
/// of markers holding link targets).
#[test]
fn merges_never_merge_link_targets_by_line() {
    let (mut alice, fs, main, _) = links_repo("/x", "fedcba9876543210fedcba9876543210fedcba98\n");
    let base_tree = put_at(&alice, alice.snapshot(&main).unwrap().tree, "l", link(&alice, "l", EntryKind::Symlink, "a\nb\nc\n", Visibility::Public));
    let base = snapshot(&alice, main, base_tree, vec![]);
    let side = |t: &str| {
        let tree = put_at(&alice, base_tree, "l", link(&alice, "l", EntryKind::Symlink, t, Visibility::Public));
        snapshot(&alice, base, tree, vec![])
    };
    let (ours, theirs, same) = (side("A\nb\nc\n"), side("a\nb\nC\n"), side("a\nb\nc\n"));
    for s in [base, ours, theirs, same] {
        let mut tx = alice.transaction("h").unwrap();
        tx.view.heads.insert(s);
        tx.commit().unwrap();
    }
    // One side changed: trivially the change.
    let m = alice.merge(WS, ours, vec![same], "merge", None).unwrap();
    let e = lookup(alice.store(), &alice.snapshot(&m.snapshot).unwrap().tree, &p("l")).unwrap().unwrap();
    assert_eq!(e.kind, EntryKind::Symlink);
    assert_eq!(alice.store().read_entry(&e).unwrap(), b"A\nb\nc\n");
    // Both changed (a line merge would succeed): a conflict entry.
    let m = alice.merge(WS, ours, vec![theirs], "merge", None).unwrap();
    assert_eq!(m.conflicts, vec!["l".to_string()]);
    let e = lookup(alice.store(), &alice.snapshot(&m.snapshot).unwrap().tree, &p("l")).unwrap().unwrap();
    assert_eq!(e.kind, EntryKind::Conflict);
    let c = alice.store().conflict(&e.id).unwrap();
    assert!(c.interleaved().flatten().all(|t| t.kind == TermKind::Symlink));
    // Checkout writes our side as it is: a link, no markers.
    let r = alice.checkout_tree(&*fs, None, &alice.snapshot(&m.snapshot).unwrap().tree).unwrap();
    assert!(r.failed.is_empty(), "{:?}", r.failed);
    assert_eq!(fs.read_link(&p("l")).unwrap(), b"A\nb\nc\n");
    assert!(fs.read(&p("l")).is_err());
}

/// Below format 5 nothing of this can be written, even through the API.
#[test]
fn format_4_repositories_refuse_links_annotations_and_link_terms() {
    let fs = Arc::new(MemoryBackend::new());
    let mut r = Repo::init_for_clone_at(fs, Some(veil_core::Identity::generate("a")), "a", 4).unwrap();
    let e = TreeEntry {
        name: "l".into(),
        kind: EntryKind::Symlink,
        id: ObjectId([1; 32]),
        size: 1,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
    };
    assert!(matches!(r.store().put_tree(&Tree { entries: vec![e] }), Err(VeilError::Unsupported(_))));
    let a = Atag::annotated("v1", r.root_id(), Text::Plain(String::new()), "a", 0);
    assert!(matches!(r.store().put_atag(&a), Err(VeilError::Unsupported(_))));
    let t = |kind| Some(veil_core::ConflictTerm { kind, id: ObjectId([2; 32]), size: 0, executable: false, visibility: Visibility::Public, fallback: None });
    let c = veil_core::Conflict { adds: vec![t(TermKind::Symlink), t(TermKind::File)], removes: vec![None] };
    assert!(matches!(r.store().put_conflict(&c), Err(VeilError::Unsupported(_))));
    let root = r.root_id();
    let mut tx = r.transaction("t").unwrap();
    tx.view.remote_release_tags.insert("github/v1".into(), ObjectId([3; 32]));
    tx.view.heads.insert(root);
    assert!(matches!(tx.commit(), Err(VeilError::Unsupported(_))));
}

/// The view fields are additive: a view without them serialises exactly as
/// before (so format-4 operations keep their ids), with them it names them.
#[test]
fn view_fields_are_omitted_when_empty() {
    let mut v = veil_core::oplog::View::default();
    v.tags.insert("main".into(), Tag::new(ObjectId([1; 32]), None));
    let json = serde_json::to_string(&v).unwrap();
    assert!(!json.contains("annotation") && !json.contains("remote_release_tags"), "{json}");
    assert_eq!(json, format!(r#"{{"heads":[],"workspaces":{{}},"tags":{{"main":{{"target":"{}"}}}},"remote_tags":{{}}}}"#, "01".repeat(32)));
    v.tags.get_mut("main").unwrap().annotation = Some(ObjectId([2; 32]));
    v.remote_release_tags.insert("github/v1".into(), ObjectId([3; 32]));
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains(&format!(r#""annotation":"{}""#, "02".repeat(32))), "{json}");
    assert!(json.contains(&format!(r#""remote_release_tags":{{"github/v1":"{}"}}"#, "03".repeat(32))), "{json}");
    assert_eq!(serde_json::from_str::<veil_core::oplog::View>(&json).unwrap(), v);
}

/// `walk_files`, the tree view and the reader-facing VFS: links are leaves,
/// never directories, never read as file content (only their target, by
/// `read_link`); a gitlink is its submodule's empty directory.
#[test]
fn tree_views_do_not_serve_links_as_files() {
    let (alice, _fs, _, links) = links_repo("/x", "fedcba9876543210fedcba9876543210fedcba98\n");
    let tree = alice.snapshot(&links).unwrap().tree;
    let view = veil_core::tree::TreeView::new(alice.store().clone(), tree);
    let listed: Vec<(String, veil_core::vfs::NodeKind)> = view.list_dir(&p("links")).unwrap().into_iter().map(|e| (e.name, e.kind)).collect();
    assert_eq!(listed, vec![("private".into(), veil_core::vfs::NodeKind::Symlink), ("readme".into(), veil_core::vfs::NodeKind::Symlink)]);
    assert_eq!(view.metadata(&p("links/readme")).unwrap().unwrap().kind, veil_core::vfs::NodeKind::Symlink);
    assert!(view.read(&p("links/readme")).unwrap_err().is_not_found());
    assert_eq!(view.read_link(&p("links/readme")).unwrap(), b"../README");
    assert_eq!(view.metadata(&p("vendor/sdk")).unwrap().unwrap().kind, veil_core::vfs::NodeKind::Dir);
    assert!(view.list_dir(&p("vendor/sdk")).unwrap().is_empty());
    // `lookup` never descends into a link.
    assert!(lookup(alice.store(), &tree, &p("links/readme/x")).unwrap().is_none());
}
