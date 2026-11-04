//! Visibility never silently downgrades. Declassification (cloaked or
//! embargoed → more visible) happens only through an explicit merge or
//! `expose` by a member, with the secret scanner applied. These tests close
//! the side doors: rebase, `new`, squash, policy edits that arrive by merge,
//! and pushes of embargoed history.

mod adversarial_support;

use std::{sync::Arc, time::Duration};

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    gc::{gc, GcOptions},
    object::{Text, Visibility},
    remote,
    tree::walk_files,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

fn team_embargo() -> Option<EmbargoSpec> {
    Some(EmbargoSpec {
        scope: "team".into(),
        until: None,
    })
}

fn listing(r: &Repo, id: &ObjectId) -> Vec<(String, u64)> {
    let tree = r.snapshot(id).unwrap().tree;
    walk_files(r.store(), &tree)
        .unwrap()
        .into_iter()
        .map(|(p, e)| (p.to_string(), e.size))
        .collect()
}

fn anon(backend: Arc<MemoryBackend>) -> Repo {
    Repo::open(backend, Some(Identity::generate("anon")), "anon").unwrap()
}

fn clone_of(name: &str, from: Arc<MemoryBackend>) -> (Repo, Arc<MemoryBackend>) {
    let fs = Arc::new(MemoryBackend::new());
    let id = Identity::generate(name);
    let mut r = Repo::init_for_clone(fs.clone(), Some(id), name).unwrap();
    remote::pull(&mut r, "origin", from).unwrap();
    (r, fs)
}

struct Embargoed {
    alice: Repo,
    fs: Arc<MemoryBackend>,
    main: ObjectId,
    fix: ObjectId,
    merge: ObjectId,
    embargo: String,
}

/// The README flow: the fix is an ordinary change, merged under embargo.
/// Alice's working copy is checked out on the merge.
fn embargoed_fix() -> Embargoed {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(
        &mut alice,
        &*fs,
        &[("auth.rs", "fn check() -> bool { true }\n"), ("README", "hello\n")],
        "v1",
    );
    alice.set_tag("main", main, None, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "fn check() -> bool { verify_signature() }\n").unwrap();
    ws.write("CVE-2026-0001.md", "details\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let res = alice.merge(WS, main, vec![fix], "merge fix", team_embargo()).unwrap();
    let wc = alice.workspace_wc(WS).unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&alice.snapshot(&main).unwrap().tree), &to).unwrap();
    Embargoed {
        alice,
        fs,
        main,
        fix,
        merge: res.snapshot,
        embargo: res.embargo.unwrap(),
    }
}

// ---- BUG-003: pushing embargoed history ----------------------------------------

#[test]
fn a_tag_on_the_embargoed_fix_is_not_pushed_until_release() {
    let mut e = embargoed_fix();
    e.alice.set_tag("fix", e.fix, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    let r = remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    assert!(r.tags_skipped.iter().any(|(t, _)| t == "fix"), "{:?}", r.tags_skipped);
    assert!(r.tags_updated.iter().any(|(t, _)| t == "main"));
    assert!(backend_contains(&*mirror, b"verify_signature").is_empty());
    assert!(anon(mirror.clone()).snapshot_opt(&e.fix).unwrap().is_none());

    e.alice.release_embargo(&e.embargo).unwrap();
    let r = remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    assert!(r.tags_skipped.is_empty(), "{:?}", r.tags_skipped);
    let pubrepo = anon(mirror);
    assert!(pubrepo.snapshot_opt(&e.fix).unwrap().is_some(), "the fix's history follows the release");
    assert!(String::from_utf8(read_at(&pubrepo, &e.fix, "auth.rs")).unwrap().contains("verify_signature"));
}

#[test]
fn a_snapshot_building_on_the_embargoed_fix_is_not_pushed() {
    let mut e = embargoed_fix();
    // The fix branch goes on after the merge (e.g. a follow-up test).
    let ws = e.alice.ephemeral_workspace(e.fix).unwrap();
    ws.write("auth_test.rs", "assert!(verify_signature_rejects_unsigned())\n").unwrap();
    let (f2, _) = e.alice.commit_ephemeral(&ws, "test for the fix").unwrap();
    e.alice.set_tag("fix-tests", f2, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    let r = remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    assert!(r.tags_skipped.iter().any(|(t, _)| t == "fix-tests"), "{:?}", r.tags_skipped);
    assert!(backend_contains(&*mirror, b"verify_signature").is_empty());
}

#[test]
fn a_team_remote_does_not_get_a_plaintext_fix_before_release() {
    let mut e = embargoed_fix();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut e.alice, team.clone(), false, &[], false).unwrap();
    assert!(backend_contains(&*team, b"verify_signature").is_empty());
    // Team members who hold the embargo key still read the merge.
    let bob = anon(team);
    assert!(bob.snapshot_opt(&e.fix).unwrap().is_none());
    assert_eq!(bob.view().tags["main"].target, e.merge);
}

#[test]
fn a_cloaked_fix_reaches_the_team_remote_but_not_the_mirror() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    alice.create_workspace("fix", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"v2 verify_signature\n").unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    alice.merge(WS, main, vec![fix], "m", team_embargo()).unwrap();

    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &["main".to_string()], false).unwrap();
    assert!(anon(team.clone()).snapshot_opt(&fix).unwrap().is_some(), "sealed history may go to the team");
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    assert!(anon(mirror).snapshot_opt(&fix).unwrap().is_none(), "nothing of the fix reaches the mirror");
}

#[test]
fn a_clone_of_the_mirror_works_with_the_redacted_parent_and_fills_it_on_release() {
    let mut e = embargoed_fix();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    let (mut carol, _cfs) = clone_of("carol", mirror.clone());
    assert!(carol.visible_snapshots().unwrap().contains(&e.merge));
    assert!(carol.is_ancestor(&e.main, &e.merge).unwrap());
    assert_eq!(listing(&carol, &e.merge), listing(&carol, &e.main));
    // gc and fsck on the clone accept the withheld history.
    let r = gc(
        &mut carol,
        &GcOptions {
            grace: Duration::ZERO,
            ..GcOptions::default()
        },
    )
    .unwrap();
    assert!(r.incomplete.is_empty(), "{:?}", r.incomplete);
    let report = veil_core::fsck::fsck_repo(&carol).unwrap();
    assert!(report.is_ok(), "{:#?}", report.findings);

    e.alice.release_embargo(&e.embargo).unwrap();
    remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    remote::pull(&mut carol, "origin", mirror).unwrap();
    assert!(carol.snapshot_opt(&e.fix).unwrap().is_some());
    assert!(String::from_utf8(read_at(&carol, &e.merge, "auth.rs")).unwrap().contains("verify_signature"));
}

// ---- BUG-018: what an embargoed line shows outsiders -----------------------------

#[test]
fn follow_up_commits_stay_under_the_embargo_until_release() {
    let mut e = embargoed_fix();
    e.fs.write(&p("README"), b"hello, world\n").unwrap();
    e.fs.write(&p("CHANGELOG"), b"- fixed CVE-2026-0001\n").unwrap();
    snap(&mut e.alice, &*e.fs);
    let (next, _) = e.alice.commit_working_copy(WS, "follow-up").unwrap();
    assert_eq!(e.alice.view().tags["main"].target, next);
    assert!(String::from_utf8(read_at(&e.alice, &next, "auth.rs")).unwrap().contains("verify_signature"));

    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut e.alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let pubrepo = anon(mirror.clone());
    assert_eq!(listing(&pubrepo, &next), listing(&e.alice, &e.main), "outsiders still see the pre-merge tree");
    assert!(backend_contains(&*mirror, b"CVE-2026-0001").is_empty());

    e.alice.release_embargo(&e.embargo).unwrap();
    remote::push(&mut e.alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let pubrepo = anon(mirror);
    assert_eq!(read_at(&pubrepo, &next, "CHANGELOG"), b"- fixed CVE-2026-0001\n");
    assert_eq!(listing(&pubrepo, &next), listing(&e.alice, &next));
}

#[test]
fn merging_into_an_embargoed_line_stays_embargoed() {
    let mut e = embargoed_fix();
    let ws = e.alice.ephemeral_workspace(e.main).unwrap();
    ws.write("feature.rs", "pub fn feature() {}\n").unwrap();
    let (feature, _) = e.alice.commit_ephemeral(&ws, "feature").unwrap();
    let res = e.alice.merge(WS, e.merge, vec![feature], "merge feature", None).unwrap();
    assert!(read_at(&e.alice, &res.snapshot, "feature.rs").starts_with(b"pub fn"));
    assert!(String::from_utf8(read_at(&e.alice, &res.snapshot, "auth.rs")).unwrap().contains("verify_signature"));

    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut e.alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let pubrepo = anon(mirror.clone());
    let m = pubrepo.view().tags["main"].target;
    assert_eq!(m, res.snapshot);
    // Outsiders see the public feature merged onto the pre-merge tree.
    assert_eq!(read_at(&pubrepo, &m, "auth.rs"), b"fn check() -> bool { true }\n");
    assert!(file_entry(&pubrepo, &m, "feature.rs").is_some());
    assert!(file_entry(&pubrepo, &m, "CVE-2026-0001.md").is_none());
    assert!(backend_contains(&*mirror, b"verify_signature").is_empty());
}

#[test]
fn an_outsider_cannot_record_edits_on_top_of_an_embargo_or_merge_it() {
    let mut e = embargoed_fix();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    let (mut carol, cfs) = clone_of("carol", mirror);
    let wc = carol.new_change(WS, vec![e.merge], "").unwrap();
    let tree = carol.snapshot(&wc).unwrap().tree;
    carol.checkout_tree(&*cfs, None, &tree).unwrap();
    assert_eq!(cfs.read(&p("auth.rs")).unwrap(), b"fn check() -> bool { true }\n");
    // Unchanged: nothing to record, nothing held back.
    let out = carol.snapshot_workspace(WS, &*cfs).unwrap();
    assert!(!out.changed && out.report.cloak_failures.is_empty());
    // Recording this edit would revert the hidden fix for everyone: held back.
    cfs.write(&p("auth.rs"), b"fn check() -> bool { false }\n").unwrap();
    let out = carol.snapshot_workspace(WS, &*cfs).unwrap();
    assert!(!out.changed, "an outsider's edit on top of the embargo was recorded");
    assert!(out.report.cloak_failures.iter().any(|(p, _)| p.as_str() == "auth.rs"));

    let ws = carol.ephemeral_workspace(e.main).unwrap();
    ws.write("other.rs", "x\n").unwrap();
    let (other, _) = carol.commit_ephemeral(&ws, "other").unwrap();
    let err = carol.merge(WS, e.merge, vec![other], "m", None).unwrap_err();
    assert!(err.to_string().contains("embargo"), "{err}");
}

#[test]
fn releasing_an_embargo_never_declassifies_scope_cloaked_files() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", "secrets/ cloak team\n"), ("auth.rs", "v1\n"), ("secrets/k", "old-key\n")],
        "v1",
    );
    alice.set_tag("main", main, None, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2\n").unwrap();
    ws.write("secrets/k", "rotated-team-only-key\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let res = alice.merge(WS, main, vec![fix], "m", team_embargo()).unwrap();
    let e = file_entry(&alice, &res.snapshot, "secrets/k").unwrap();
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() });
    alice.release_embargo(res.embargo.as_deref().unwrap()).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let pubrepo = anon(mirror.clone());
    assert_eq!(read_at(&pubrepo, &res.snapshot, "auth.rs"), b"v2\n");
    assert!(backend_contains(&*mirror, b"rotated-team-only-key").is_empty());
}

// ---- BUG-016: messages ------------------------------------------------------------

#[test]
fn the_embargoed_merge_message_is_readable_by_key_holders_and_after_release() {
    let mut e = embargoed_fix();
    let s = e.alice.snapshot(&e.merge).unwrap();
    assert!(matches!(s.description, Text::Sealed(_)));
    assert_eq!(e.alice.description(&s), "merge fix");
    let rec = e.alice.keys().load_embargo(&e.embargo).unwrap().unwrap();
    assert!(rec.description.is_empty(), "the synced record carries no message");

    e.alice.release_embargo(&e.embargo).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    let pubrepo = anon(mirror);
    let s = pubrepo.snapshot(&e.merge).unwrap();
    assert_eq!(pubrepo.description(&s), "merge fix");
}

// ---- BUG-004: merging a cloaked line ----------------------------------------------

#[test]
fn merging_a_cloaked_line_reports_what_it_publishes_and_quarantines() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    alice.create_workspace("exp", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("exp").unwrap();
    ov.write(&p("plan.md"), b"ship it\n").unwrap();
    ov.write(&p("cfg.js"), b"const k = \"AKIAIOSFODNN7EXAMPLE\";\n").unwrap();
    let exp = alice.snapshot_workspace("exp", &ov).unwrap().snapshot;
    let res = alice.merge(WS, main, vec![exp], "merge exp", None).unwrap();
    assert_eq!(res.declassified, vec!["plan.md".to_string()]);
    assert!(res.quarantined.iter().any(|q| q.starts_with("cfg.js")), "{:?}", res.quarantined);
    assert!(file_entry(&alice, &res.snapshot, "plan.md").unwrap().visibility.is_public());
    assert!(file_entry(&alice, &res.snapshot, "cfg.js").is_none());
}

#[test]
fn merging_a_public_line_does_not_publish_files_cloaked_by_policy() {
    // A cloaked workspace under `team` whose file is cloaked under `ops` by
    // policy: merging the workspace publishes its own files, not `ops` ones.
    let (mut alice, fs, _) = new_repo("alice");
    alice.keys().create_scope("ops").unwrap();
    let main = commit_files(&mut alice, &*fs, &[(".veilpolicy", "prod/ cloak ops\n")], "v1");
    alice.create_workspace("exp", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("exp").unwrap();
    ov.write(&p("prod/db.yml"), b"ops-password\n").unwrap();
    let exp = alice.snapshot_workspace("exp", &ov).unwrap().snapshot;
    let res = alice.merge(WS, main, vec![exp], "merge exp", None).unwrap();
    let e = file_entry(&alice, &res.snapshot, "prod/db.yml").unwrap();
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "ops".into() });
}

// ---- BUG-009: policy that arrives by merge, vs. a deliberate policy edit -----------

#[test]
fn a_merged_policy_rekey_is_refused_and_reported() {
    let (mut alice, fs, _) = new_repo("alice");
    alice.keys().create_scope("ops").unwrap();
    alice.keys().create_scope("opz").unwrap();
    let main = commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", "prod/ cloak ops\n"), ("prod/db.yml", "ops-only\n")],
        "v1",
    );
    let pr_ws = alice.ephemeral_workspace(main).unwrap();
    pr_ws.write(".veilpolicy", "prod/ cloak opz\n").unwrap();
    let (pr, _) = alice.commit_ephemeral(&pr_ws, "policy PR").unwrap();
    let res = alice.merge(WS, main, vec![pr], "merge PR", None).unwrap();
    assert!(res.warnings.iter().any(|w| w.contains(".veilpolicy") && w.contains("prod/db.yml")), "{:?}", res.warnings);
    assert_eq!(read_at(&alice, &res.snapshot, ".veilpolicy"), b"prod/ cloak ops\n");
    assert_eq!(
        file_entry(&alice, &res.snapshot, "prod/db.yml").unwrap().visibility,
        Visibility::Cloaked { scope: "ops".into() }
    );
}

/// A PR built by someone without the key carries a policy that says
/// `public!` while the entry stays sealed. Checking it out and snapshotting
/// must not publish it; only Alice's own policy edit may, with scanning.
#[test]
fn a_policy_that_arrived_with_history_does_not_declassify_at_the_next_snapshot() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", "secrets/ cloak team\n"), ("secrets/db.yml", "db-password-xyz\n")],
        "v1",
    );
    alice.set_tag("main", main, None, false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();
    let (mut mallory, mfs) = clone_of("mallory", team.clone());
    let wc = mallory.new_change(WS, vec![main], "").unwrap();
    let tree = mallory.snapshot(&wc).unwrap().tree;
    mallory.checkout_tree(&*mfs, None, &tree).unwrap();
    mfs.write(&p(".veilpolicy"), b"secrets/ public!\n").unwrap();
    let pr = snap(&mut mallory, &*mfs);
    assert!(!file_entry(&mallory, &pr, "secrets/db.yml").unwrap().visibility.is_public());
    mallory.set_tag("pr", pr, None, false).unwrap();
    remote::push(&mut mallory, team.clone(), false, &["pr".to_string()], false).unwrap();

    remote::pull(&mut alice, "origin", team).unwrap();
    let old = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = alice.new_change(WS, vec![pr], "").unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&old), &to).unwrap();
    assert_eq!(fs.read(&p("secrets/db.yml")).unwrap(), b"db-password-xyz\n");
    fs.write(&p("secrets/db.yml"), b"db-password-rotated\n").unwrap();
    let wc = snap(&mut alice, &*fs);
    let e = file_entry(&alice, &wc, "secrets/db.yml").unwrap();
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() }, "sticky: still sealed");

    // Alice's own, deliberate edit of the policy does expose it (scanned).
    fs.write(&p(".veilpolicy"), b"secrets/ public\n").unwrap();
    let wc = snap(&mut alice, &*fs);
    assert!(file_entry(&alice, &wc, "secrets/db.yml").unwrap().visibility.is_public());
}

#[test]
fn a_deliberate_expose_still_runs_the_secret_scanner() {
    let (mut alice, fs, _) = new_repo("alice");
    commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", "secrets/ cloak team\n"), ("secrets/k.js", "k = \"AKIAIOSFODNN7EXAMPLE\"\n")],
        "v1",
    );
    fs.write(&p(".veilpolicy"), b"secrets/ public\n").unwrap();
    let out = alice.snapshot_workspace(WS, &*fs).unwrap();
    assert!(out.report.quarantined.iter().any(|(p, _)| p.as_str() == "secrets/k.js"));
    let e = file_entry(&alice, &out.snapshot, "secrets/k.js").unwrap();
    assert!(!e.visibility.is_public(), "the previous sealed version is kept");
}

// ---- BUG-005 / BUG-006 / BUG-017: rebase, new, squash -------------------------------

#[test]
fn an_explicit_rebase_keeps_cloaked_content_sealed() {
    let (mut alice, fs, _) = new_repo("alice");
    let lines: String = (1..=12).map(|i| format!("line {i}\n")).collect();
    let base = commit_files(&mut alice, &*fs, &[("conf", &lines)], "base");
    alice.create_workspace("sec", vec![base], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("sec").unwrap();
    ov.write(&p("conf"), lines.replace("line 12\n", "secret 12\n").as_bytes()).unwrap();
    let c = alice.snapshot_workspace("sec", &ov).unwrap().snapshot;
    let ws = alice.ephemeral_workspace(base).unwrap();
    ws.write("conf", lines.replace("line 1\n", "line one\n")).unwrap();
    let (dest, _) = alice.commit_ephemeral(&ws, "public edit").unwrap();
    let c2 = alice.rebase(c, vec![dest]).unwrap();
    let e = file_entry(&alice, &c2, "conf").unwrap();
    assert!(!e.visibility.is_public(), "{:?}", e.visibility);
    let text = String::from_utf8(alice.store().read_entry(&e).unwrap()).unwrap();
    assert!(text.contains("line one") && text.contains("secret 12"));
}

#[test]
fn new_files_in_an_ordinary_change_on_a_cloaked_one_are_public_but_inherited_ones_stay_sealed() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    alice.create_workspace("exp", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("exp").unwrap();
    ov.write(&p("plan.md"), b"plan\n").unwrap();
    let exp = alice.snapshot_workspace("exp", &ov).unwrap().snapshot;
    let old = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = alice.new_change(WS, vec![exp], "").unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&old), &to).unwrap();
    fs.write(&p("plan.md"), b"plan v2\n").unwrap();
    fs.write(&p("notes.md"), b"public notes\n").unwrap();
    let wc = snap(&mut alice, &*fs);
    assert_eq!(
        file_entry(&alice, &wc, "plan.md").unwrap().visibility,
        Visibility::Cloaked { scope: "team".into() },
        "an edit of an inherited sealed file stays sealed"
    );
    assert!(file_entry(&alice, &wc, "notes.md").unwrap().visibility.is_public());
}

#[test]
fn squashing_a_public_change_into_a_cloaked_one_seals_what_it_brings() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    alice.create_workspace("sec", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("sec").unwrap();
    ov.write(&p("plan.md"), b"plan\n").unwrap();
    alice.snapshot_workspace("sec", &ov).unwrap();
    let (cloaked, _) = alice.commit_working_copy("sec", "cloaked").unwrap();
    // A public child: an ordinary workspace on the cloaked change.
    let old = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = alice.new_change(WS, vec![cloaked], "").unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&old), &to).unwrap();
    fs.write(&p("public.md"), b"written in an ordinary workspace\n").unwrap();
    let wc = snap(&mut alice, &*fs);
    assert!(file_entry(&alice, &wc, "public.md").unwrap().visibility.is_public());
    let squashed = alice.squash(wc).unwrap();
    assert_eq!(
        file_entry(&alice, &squashed, "public.md").unwrap().visibility,
        Visibility::Cloaked { scope: "team".into() }
    );
}

#[test]
fn squashing_a_cloaked_change_into_a_public_one_seals_the_joined_description() {
    let (mut alice, fs, _) = new_repo("alice");
    let base = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "public base");
    alice.create_workspace("sec", vec![base], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("sec").unwrap();
    ov.write(&p("plan.md"), b"x\n").unwrap();
    let wc = alice.snapshot_workspace("sec", &ov).unwrap().snapshot;
    let wc = alice.describe(wc, "secret plan").unwrap();
    let parent = alice.squash(wc).unwrap();
    let s = alice.snapshot(&parent).unwrap();
    assert!(matches!(s.description, Text::Sealed(_)));
    assert_eq!(alice.description(&s), "public base\n\nsecret plan");
}
