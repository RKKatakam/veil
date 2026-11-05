//! `vl push --dry-run` (`push_plan::plan_push`): the plan is what the real
//! push then sends, object for object and tag for tag, and planning never
//! writes to the remote.

use crate::adversarial_support;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    commands::EmbargoSpec,
    push_plan::{plan_push, Exposure, PushPlan, TagAction, WithheldReason},
    remote, Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

/// The objects of every pack on `backend`, by pack.
fn packs(backend: &dyn StorageBackend) -> BTreeMap<String, Vec<ObjectId>> {
    use veil_core::{pack, VPath};
    let dir = VPath::new(".veil/objects/pack").unwrap();
    let Ok(entries) = backend.list_dir(&dir) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for e in entries {
        let Some(name) = pack::name_from_index_file(&e.name) else { continue };
        let p = pack::Pack::open(backend, &dir, name).unwrap();
        out.insert(e.name.clone(), p.index().ids().to_vec());
    }
    out
}

/// Every file on `backend` with its bytes.
fn dump(backend: &dyn StorageBackend) -> BTreeMap<String, Vec<u8>> {
    let files = veil_core::vfs::walk_files(backend, &veil_core::VPath::root(), &|_| false).unwrap();
    files.into_iter().map(|f| (f.to_string(), backend.read(&f).unwrap())).collect()
}

/// Plan a push, check the plan wrote nothing, push for real, and check
/// they agree: the objects sent, the bytes, and what happened to each tag.
fn plan_then_push(local: &mut Repo, remote_fs: &Arc<MemoryBackend>, public: bool, tags: &[String], force: bool) -> PushPlan {
    let before = dump(&**remote_fs);
    let plan = plan_push(local, remote_fs.clone(), public, tags, force).unwrap();
    assert_eq!(dump(&**remote_fs), before, "planning wrote to the remote");
    let packs_before = packs(&**remote_fs);
    let report = remote::push(local, remote_fs.clone(), public, tags, force).unwrap();

    let planned: BTreeSet<ObjectId> = plan.objects.iter().map(|o| o.id).collect();
    assert_eq!(planned.len(), plan.objects.len(), "an object planned twice");
    // What the push wrote: its new packs (it may re-send an object an older
    // pack holds, when the remote's view does not prove it is there).
    let sent: Vec<ObjectId> = packs(&**remote_fs)
        .into_iter()
        .filter(|(name, _)| !packs_before.contains_key(name))
        .flat_map(|(_, ids)| ids)
        .collect();
    assert_eq!(sent.len(), plan.objects.len(), "as many objects packed as planned");
    let sent: BTreeSet<ObjectId> = sent.into_iter().collect();
    assert_eq!(planned, sent, "the plan's objects are exactly what the push packed");
    assert_eq!(plan.objects.len(), report.objects_copied);
    assert_eq!(plan.redacted, report.redacted);
    assert_eq!(plan.pack_bytes, report.bytes_transferred, "the plan's pack size is the real one");
    assert_eq!(plan.creates_remote, before.is_empty());

    let with = |a: &[TagAction]| -> BTreeSet<(String, ObjectId)> {
        plan.tags.iter().filter(|t| a.contains(&t.action)).map(|t| (t.name.clone(), t.target)).collect()
    };
    let updated: BTreeSet<(String, ObjectId)> = report.tags_updated.iter().cloned().collect();
    assert_eq!(with(&[TagAction::Create, TagAction::Update]), updated, "{plan:#?}\n{report:#?}");
    let rejected: BTreeSet<String> = report.tags_rejected.iter().cloned().collect();
    let planned_rejected: BTreeSet<String> =
        plan.tags.iter().filter(|t| t.action == TagAction::Rejected).map(|t| t.name.clone()).collect();
    assert_eq!(planned_rejected, rejected);
    let skipped: BTreeSet<String> = report.tags_skipped.iter().map(|(t, _)| t.clone()).collect();
    let planned_skipped: BTreeSet<String> = plan
        .tags
        .iter()
        .filter(|t| matches!(t.action, TagAction::Skipped | TagAction::Rejected))
        .map(|t| t.name.clone())
        .collect();
    assert_eq!(planned_skipped, skipped);
    let snaps: BTreeSet<ObjectId> = plan.snapshots.iter().copied().collect();
    assert!(snaps.is_subset(&planned), "every planned snapshot is sent");
    if public {
        never_withheld_but_sent(local, &plan, &planned);
    }

    // Nothing changed since: a second plan sends nothing.
    let again = plan_push(local, remote_fs.clone(), public, tags, force).unwrap();
    assert!(again.objects.is_empty(), "{again:#?}");
    assert!(again.tags.iter().all(|t| t.action != TagAction::Create && t.action != TagAction::Update));
    plan
}

/// The plan never calls a file withheld (and not published) while the
/// push sends a plaintext object at that path: labels are claims, and the
/// push sends an object by what it is (BUG-482).
fn never_withheld_but_sent(local: &Repo, plan: &PushPlan, sent: &BTreeSet<ObjectId>) {
    let files = plan.files.as_ref().expect("a public plan lists files");
    let published: BTreeSet<String> = files.published.iter().map(|f| f.path.to_string()).collect();
    for w in &files.withheld {
        let path = w.path.to_string();
        if published.contains(&path) {
            continue;
        }
        for s in &plan.snapshots {
            let tree = local.snapshot(s).unwrap().tree;
            let Ok(Some(e)) = veil_core::tree::lookup(local.store(), &tree, &w.path) else { continue };
            if e.kind != veil_core::EntryKind::File || !sent.contains(&e.id) {
                continue;
            }
            let raw = local.store().get_raw(&e.id).unwrap();
            assert!(
                veil_core::builder::object_visibility(&raw) != Some(veil_core::Visibility::Public),
                "the plan calls {path} withheld, but the push sends its plaintext ({:?} label): {plan:#?}",
                e.visibility
            );
        }
    }
}

/// Commit, on top of `parent`, a tree with `forged-f{i}` whose label lies:
/// `cloaked:team` over a plaintext blob, or `public` over an object sealed
/// for `team` (a writer of a remote, or an import, can record either).
fn forge(repo: &Repo, parent: ObjectId, i: u8, cloaked_label: bool) -> ObjectId {
    use veil_core::{object::Visibility, TreeEntry};
    let data = format!("forged {i} {cloaked_label}\n");
    let team = Visibility::Cloaked { scope: "team".into() };
    let (id, visibility) = match cloaked_label {
        true => (blob(repo, data.as_bytes()), team),
        false => (repo.store().store_file(data.as_bytes(), &team).unwrap(), Visibility::Public),
    };
    let e = TreeEntry { size: data.len() as u64, visibility, ..file(&format!("forged-f{i}"), id) };
    let tree = repo.snapshot(&parent).unwrap().tree;
    let tree = veil_core::conflict::set_entry(repo.store(), &tree, &p(&format!("forged-f{i}")), Some(e)).unwrap();
    raw_snapshot(repo, vec![parent], tree, "forged")
}

const POLICY: &str = "secrets/ cloak team\n";

fn published(plan: &PushPlan) -> BTreeMap<String, Exposure> {
    plan.files.as_ref().unwrap().published.iter().map(|f| (f.path.to_string(), f.exposure)).collect()
}

fn withheld(plan: &PushPlan) -> BTreeMap<String, WithheldReason> {
    plan.files.as_ref().unwrap().withheld.iter().map(|f| (f.path.to_string(), f.reason.clone())).collect()
}

#[test]
fn plans_match_pushes_to_team_and_public_remotes() {
    let (mut alice, fs, _) = new_repo("alice");
    let c1 = commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", POLICY), ("src/a.rs", "fn a() {}\n"), ("secrets/db.yml", "password: hunter2-but-long\n")],
        "one",
    );
    alice.set_tag("main", c1, None, false).unwrap();
    alice.set_tag("ops", c1, Some("team".into()), false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    let mirror = Arc::new(MemoryBackend::new());

    let t = plan_then_push(&mut alice, &team, false, &[], false);
    assert!(t.files.is_none(), "file lists are for public remotes");
    assert!(t.objects.iter().any(|o| o.sealed), "a team remote receives the ciphertext");
    assert_eq!(t.redacted, 0);

    let m = plan_then_push(&mut alice, &mirror, true, &[], false);
    assert!(m.objects.iter().all(|o| !o.sealed), "no ciphertext for a public remote");
    assert_eq!(m.redacted, 1);
    let ops = m.tags.iter().find(|t| t.name == "ops").unwrap();
    assert_eq!(ops.action, TagAction::Skipped);
    assert_eq!(
        published(&m),
        BTreeMap::from([(".veilpolicy".into(), Exposure::New), ("src/a.rs".into(), Exposure::New)])
    );
    assert_eq!(
        withheld(&m),
        BTreeMap::from([("secrets/db.yml".into(), WithheldReason::Cloaked { scope: "team".into() })])
    );

    // An edit, a cloaked edit, and an exposure.
    let c2 = commit_files(&mut alice, &*fs, &[("src/a.rs", "fn a() { 1 }\n"), ("src/b.rs", "fn b() {}\n")], "two");
    alice.set_tag("main", c2, None, false).unwrap();
    let m = plan_then_push(&mut alice, &mirror, true, &[], false);
    assert_eq!(
        published(&m),
        BTreeMap::from([("src/a.rs".into(), Exposure::Modified), ("src/b.rs".into(), Exposure::New)])
    );
    assert!(withheld(&m).is_empty(), "the unchanged cloaked file is not listed again: {m:#?}");
    let c3 = commit_files(&mut alice, &*fs, &[(".veilpolicy", "secrets/ cloak team\nsecrets/db.yml public!\n")], "expose");
    alice.set_tag("main", c3, None, false).unwrap();
    let m = plan_then_push(&mut alice, &mirror, true, &[], false);
    assert_eq!(published(&m)["secrets/db.yml"], Exposure::Exposed, "{m:#?}");
    plan_then_push(&mut alice, &team, false, &[], false);
}

#[test]
fn a_rejected_tag_is_planned_as_rejected_and_its_history_not_counted() {
    let (mut alice, fs, alice_id) = new_repo("alice");
    let c1 = commit_files(&mut alice, &*fs, &[("a", "1\n")], "one");
    alice.set_tag("main", c1, None, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();

    // Bob overwrites main on the hub with unrelated work.
    let (mut bob, bfs) = repo_for("bob", &Identity::generate("bob"));
    let _ = alice_id;
    let b = commit_files(&mut bob, &*bfs, &[("b", "bob\n")], "bob");
    bob.set_tag("main", b, None, false).unwrap();
    remote::push(&mut bob, hub.clone(), false, &[], true).unwrap();

    // Alice diverges; plus a new tag that is fine.
    let c2 = commit_files(&mut alice, &*fs, &[("a", "2\n")], "two");
    alice.set_tag("main", c2, None, false).unwrap();
    alice.set_tag("other", c1, None, false).unwrap();
    let plan = plan_then_push(&mut alice, &hub, false, &[], false);
    let main = plan.tags.iter().find(|t| t.name == "main").unwrap();
    assert_eq!(main.action, TagAction::Rejected);
    assert_eq!(main.remote, Some(b));
    assert_eq!(plan.tags.iter().find(|t| t.name == "other").unwrap().action, TagAction::Create);
    assert!(plan.objects.is_empty(), "the rejected tag's history is not sent: {plan:#?}");

    let forced = plan_then_push(&mut alice, &hub, false, &[], true);
    assert_eq!(forced.tags.iter().find(|t| t.name == "main").unwrap().action, TagAction::Update);
}

#[test]
fn planning_a_push_to_a_missing_remote_creates_nothing_and_foreign_directories_fail_alike() {
    let (mut alice, fs, _) = new_repo("alice");
    let c = commit_files(&mut alice, &*fs, &[("a", "1\n")], "one");
    alice.set_tag("main", c, None, false).unwrap();
    let empty = Arc::new(MemoryBackend::new());
    let plan = plan_push(&alice, empty.clone(), false, &[], false).unwrap();
    assert!(plan.creates_remote);
    assert!(dump(&*empty).is_empty(), "nothing was created");

    let foreign = Arc::new(MemoryBackend::new());
    foreign.write(&p("notes.txt"), b"mine").unwrap();
    let planned = plan_push(&alice, foreign.clone(), false, &[], false).unwrap_err().to_string();
    let pushed = remote::push(&mut alice, foreign.clone(), false, &[], false).unwrap_err().to_string();
    assert_eq!(planned, pushed);

    let missing = plan_push(&alice, empty.clone(), false, &["nope".into()], false).unwrap_err().to_string();
    assert!(missing.contains("nope"), "{missing}");
}

/// Alice (in `team`) with `main` carrying an embargoed fix of `auth.rs`.
fn embargoed() -> (Repo, Arc<MemoryBackend>, String, ObjectId) {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n"), ("README", "hi\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    alice.create_workspace("fix", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let r = alice
        .merge(WS, main, vec![fix], "merge", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    alice.set_tag("main", r.snapshot, None, false).unwrap();
    (alice, fs, r.embargo.unwrap(), fix)
}

#[test]
fn embargoed_history_and_files_are_planned_as_withheld_until_the_release() {
    let (mut alice, _fs, e, fix) = embargoed();
    let mirror = Arc::new(MemoryBackend::new());
    let team = Arc::new(MemoryBackend::new());

    let m = plan_then_push(&mut alice, &mirror, true, &[], false);
    assert!(m.withheld_snapshots.iter().any(|(id, em)| *id == fix && *em == e), "{m:#?}");
    assert!(!m.snapshots.contains(&fix));
    assert_eq!(withheld(&m).get("auth.rs"), Some(&WithheldReason::Embargoed { embargo: e.clone() }), "{m:#?}");
    // The fix's content is not public yet: only the pre-merge files are.
    assert_eq!(
        published(&m),
        BTreeMap::from([("README".into(), Exposure::New), ("auth.rs".into(), Exposure::New)])
    );
    let t = plan_then_push(&mut alice, &team, false, &[], false);
    assert!(t.snapshots.contains(&fix), "the fix is cloaked under the embargo's scope: a team remote gets it");

    alice.release_embargo(&e).unwrap();
    let m = plan_then_push(&mut alice, &mirror, true, &[], false);
    assert_eq!(m.releases, vec![e.clone()], "the release is published by this push");
    assert!(m.snapshots.contains(&fix), "the fix's history follows the release: {m:#?}");
    let pubd = &m.files.as_ref().unwrap().published;
    let auth = pubd.iter().find(|f| f.path.as_str() == "auth.rs").expect("the fix becomes public");
    assert_eq!(auth.exposure, Exposure::Modified);
    assert_eq!(auth.released_embargo.as_deref(), Some(e.as_str()));
}

#[test]
fn a_reader_without_the_embargo_key_learns_nothing_about_the_fix() {
    let (mut alice, _fs, e, _) = embargoed();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    // Carol is not in `team`: she clones the team hub, then plans a push
    // of it to a public mirror.
    let carol_id = Identity::generate("carol");
    let mut carol = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(carol_id), "carol").unwrap();
    remote::pull(&mut carol, "origin", hub).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    let m = plan_then_push(&mut carol, &mirror, true, &[], false);
    let f = m.files.as_ref().unwrap();
    assert!(f.withheld.iter().all(|w| !matches!(w.reason, WithheldReason::Embargoed { .. })), "{m:#?}");
    assert!(f.embargoed_trees.iter().any(|(_, em)| *em == e), "{m:#?}");
    let dbg = format!("{m:?}");
    assert!(!dbg.contains("verify_signature"));
}

// ---- property: plan == push, over random histories --------------------------------

#[derive(Clone, Debug)]
enum Op {
    /// Write a public file (index) with content (seed).
    Public(u8, u8),
    /// Write a cloaked file.
    Cloaked(u8, u8),
    /// Expose cloaked file (index) from now on.
    Expose(u8),
    /// Commit, and point tag (index) at the commit, cloaked or not.
    Commit(u8, bool),
    /// Move tag (index) back to an earlier commit (diverging if pushed).
    Rewind(u8, u8),
    /// Push everything, or one tag, to the team or the public remote.
    Push { public: bool, tag: Option<u8>, force: bool },
    /// Merge a fix line (cloaked under `team`) into the last commit under
    /// an embargo, and point tag (index) at the merge.
    Embargo(u8, u8),
    /// Release every embargo.
    Release,
    /// Commit a forged label (index; a `cloaked` label over plaintext, or
    /// a `public` one over a sealed object) on top of the last commit, and
    /// point tag (index) at it.
    Forged(u8, bool, u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..4u8, any::<u8>()).prop_map(|(i, s)| Op::Public(i, s)),
        2 => (0..3u8, any::<u8>()).prop_map(|(i, s)| Op::Cloaked(i, s)),
        1 => (0..3u8).prop_map(Op::Expose),
        3 => (0..3u8, prop::bool::weighted(0.2)).prop_map(|(t, c)| Op::Commit(t, c)),
        1 => (0..3u8, 0..4u8).prop_map(|(t, b)| Op::Rewind(t, b)),
        3 => (any::<bool>(), prop::option::weighted(0.3, 0..3u8), prop::bool::weighted(0.2))
            .prop_map(|(public, tag, force)| Op::Push { public, tag, force }),
        1 => (0..3u8, any::<u8>()).prop_map(|(t, s)| Op::Embargo(t, s)),
        1 => Just(Op::Release),
        1 => (0..2u8, any::<bool>(), 0..3u8).prop_map(|(i, c, t)| Op::Forged(i, c, t)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 40, ..ProptestConfig::default() })]

    #[test]
    fn the_dry_run_sends_what_the_push_sends(ops in prop::collection::vec(op(), 1..24)) {
        let (mut alice, fs, _) = new_repo("alice");
        let team = Arc::new(MemoryBackend::new());
        let mirror = Arc::new(MemoryBackend::new());
        let mut exposed: BTreeSet<u8> = BTreeSet::new();
        let mut commits: Vec<ObjectId> = Vec::new();
        let policy = |exposed: &BTreeSet<u8>| {
            let mut s = POLICY.to_string();
            for i in exposed {
                s.push_str(&format!("secrets/s{i} public!\n"));
            }
            s
        };
        fs.write(&p(".veilpolicy"), policy(&exposed).as_bytes()).unwrap();
        for op in ops {
            match op {
                Op::Public(i, s) => fs.write(&p(&format!("src/f{i}")), format!("public {s}\n").as_bytes()).unwrap(),
                Op::Cloaked(i, s) => fs.write(&p(&format!("secrets/s{i}")), format!("cloaked {s}\n").as_bytes()).unwrap(),
                Op::Expose(i) => {
                    exposed.insert(i);
                    fs.write(&p(".veilpolicy"), policy(&exposed).as_bytes()).unwrap();
                }
                Op::Commit(t, cloak) => {
                    snap(&mut alice, &*fs);
                    let c = alice.commit_working_copy(WS, "c").unwrap().0;
                    commits.push(c);
                    let name = format!("t{t}");
                    let cl = cloak.then(|| "team".to_string());
                    let keep = alice.view().tags.get(&name).map(|x| x.cloak.clone());
                    alice.set_tag(&name, c, keep.unwrap_or(cl), true).unwrap();
                }
                Op::Rewind(t, back) => {
                    let name = format!("t{t}");
                    if let (Some(tag), Some(c)) = (alice.view().tags.get(&name).cloned(), commits.iter().rev().nth(back as usize)) {
                        alice.set_tag(&name, *c, tag.cloak, true).unwrap();
                    }
                }
                Op::Embargo(t, seed) => {
                    let Some(base) = commits.last().copied() else { continue };
                    let ws = format!("fx{}", commits.len());
                    if alice.create_workspace(&ws, vec![base], Some("team".into())).is_err() {
                        continue;
                    }
                    let ov = alice.workspace_overlay(&ws).unwrap();
                    ov.write(&p("src/f0"), format!("fixed {seed}\n").as_bytes()).unwrap();
                    ov.write(&p("src/fix"), b"new file\n").unwrap();
                    let fix = alice.snapshot_workspace(&ws, &ov).unwrap().snapshot;
                    let spec = EmbargoSpec { scope: "team".into(), until: None };
                    if let Ok(r) = alice.merge(WS, base, vec![fix], "merge", Some(spec)) {
                        commits.push(r.snapshot);
                        let name = format!("t{t}");
                        let cl = alice.view().tags.get(&name).and_then(|x| x.cloak.clone());
                        alice.set_tag(&name, r.snapshot, cl, true).unwrap();
                    }
                }
                Op::Forged(i, cloaked_label, t) => {
                    let Some(base) = commits.last().copied() else { continue };
                    if alice.store().tree_object(&alice.snapshot(&base).unwrap().tree).is_ok_and(|t| veil_core::embargo::wrapper_parts(&t).is_some()) {
                        continue;
                    }
                    let f = forge(&alice, base, i, cloaked_label);
                    commits.push(f);
                    let name = format!("t{t}");
                    let cl = alice.view().tags.get(&name).and_then(|x| x.cloak.clone());
                    alice.set_tag(&name, f, cl, true).unwrap();
                }
                Op::Release => {
                    for rec in alice.keys().embargoes().unwrap() {
                        if !alice.keys().embargo_released(&rec.id) {
                            alice.release_embargo(&rec.id).unwrap();
                        }
                    }
                }
                Op::Push { public, tag, force } => {
                    let tags: Vec<String> = match tag {
                        Some(t) if alice.view().tags.contains_key(&format!("t{t}")) => vec![format!("t{t}")],
                        _ => vec![],
                    };
                    let target = if public { &mirror } else { &team };
                    plan_then_push(&mut alice, target, public, &tags, force);
                }
            }
        }
        plan_then_push(&mut alice, &team, false, &[], true);
        plan_then_push(&mut alice, &mirror, true, &[], true);
    }
}

/// BUG-482: a `cloaked:team` label over a plaintext blob is published by
/// the push, and the plan says so; a `public` label over a sealed object
/// is withheld by the push, and is never sent.
#[test]
fn forged_labels_are_planned_as_the_push_treats_them() {
    let (mut alice, fs, _) = new_repo("alice");
    let c = commit_files(&mut alice, &*fs, &[("src/a.rs", "fn a() {}\n")], "one");
    let f = forge(&alice, c, 0, true);
    let g = forge(&alice, f, 1, false);
    alice.set_tag("main", g, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    let m = plan_then_push(&mut alice, &mirror, true, &[], false);
    assert!(published(&m).contains_key("forged-f0"), "{m:#?}");
    assert!(!withheld(&m).contains_key("forged-f0"), "{m:#?}");
    assert!(!backend_contains(&*mirror, b"forged 0 true").is_empty(), "setup: the plaintext is sent");
    assert!(backend_contains(&*mirror, b"forged 1 false").is_empty());
}
