//! Visibility never silently downgrades. A sealed secret file is exposed
//! only through a deliberate policy edit by a member, and embargoed history
//! is pushed only after its release. These tests close the side doors:
//! rebase, `new`, squash, policy edits that arrive by merge, and pushes of
//! embargoed history.

use crate::adversarial_support;

use std::{sync::Arc, time::Duration};

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    gc::{gc, GcOptions},
    object::Visibility,
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
    alice.set_tag("main", main, false).unwrap();
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
    e.alice.set_tag("fix", e.fix, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    let r = remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    assert!(r.tags_skipped.iter().any(|(t, _)| t == "fix"), "{:?}", r.tags_skipped);
    assert!(r.tags_skipped.iter().any(|(t, _)| t == "main"), "{:?}", r.tags_skipped);
    assert!(backend_contains(&*mirror, b"verify_signature").is_empty());
    assert!(anon(mirror.clone()).exact().snapshot(&e.fix).unwrap().is_none());

    e.alice.release_embargo(&e.embargo).unwrap();
    let r = remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    assert!(r.tags_skipped.is_empty(), "{:?}", r.tags_skipped);
    let pubrepo = anon(mirror);
    assert!(pubrepo.exact().snapshot(&e.fix).unwrap().is_some(), "the fix's history follows the release");
    assert!(String::from_utf8(read_at(&pubrepo, &e.fix, "auth.rs")).unwrap().contains("verify_signature"));
}

#[test]
fn a_snapshot_building_on_the_embargoed_fix_is_not_pushed() {
    let mut e = embargoed_fix();
    // The fix branch goes on after the merge (e.g. a follow-up test).
    let ws = e.alice.ephemeral_workspace(e.fix).unwrap();
    ws.write("auth_test.rs", "assert!(verify_signature_rejects_unsigned())\n").unwrap();
    let (f2, _) = e.alice.commit_ephemeral(&ws, "test for the fix").unwrap();
    e.alice.set_tag("fix-tests", f2, false).unwrap();
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
    // The embargoed history is withheld from every push, team remotes too.
    let bob = anon(team.clone());
    assert!(bob.exact().snapshot(&e.fix).unwrap().is_none());
    assert!(bob.exact().snapshot(&e.merge).unwrap().is_none());
    assert!(bob.view().tags.get("main").is_none_or(|t| t.target == e.main));
    // Released, the team remote receives it.
    e.alice.release_embargo(&e.embargo).unwrap();
    remote::push(&mut e.alice, team.clone(), false, &[], false).unwrap();
    let bob = anon(team);
    assert_eq!(bob.view().tags["main"].target, e.merge);
    assert!(bob.exact().snapshot(&e.fix).unwrap().is_some());
}

#[test]
fn a_clone_of_the_mirror_works_without_the_withheld_history_and_fills_it_on_release() {
    let mut e = embargoed_fix();
    e.alice.set_tag("stable", e.main, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    let (mut carol, _cfs) = clone_of("carol", mirror.clone());
    assert!(!carol.exact().visible().unwrap().contains(&e.merge));
    assert!(carol.exact().snapshot(&e.merge).unwrap().is_none());
    assert!(carol.exact().visible().unwrap().contains(&e.main));
    // gc and fsck on the clone are fine without the withheld history.
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
    assert!(carol.exact().snapshot(&e.fix).unwrap().is_some());
    assert!(carol.is_ancestor(&e.main, &e.merge).unwrap());
    assert!(String::from_utf8(read_at(&carol, &e.merge, "auth.rs")).unwrap().contains("verify_signature"));
}

// ---- BUG-018: an embargoed line is withheld from outsiders ------------------------

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
    assert!(pubrepo.exact().snapshot(&next).unwrap().is_none(), "the follow-up reached the mirror");
    assert!(pubrepo.exact().snapshot(&e.merge).unwrap().is_none(), "the embargoed merge reached the mirror");
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

    assert_eq!(e.alice.view().tags["main"].target, res.snapshot);
    let mirror = Arc::new(MemoryBackend::new());
    let r = remote::push(&mut e.alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    assert!(r.tags_skipped.iter().any(|(t, why)| t == "main" && why.contains(&e.embargo)), "{r:?}");
    let pubrepo = anon(mirror.clone());
    assert!(pubrepo.exact().snapshot(&res.snapshot).unwrap().is_none(), "the merge on the embargoed line reached the mirror");
    assert!(backend_contains(&*mirror, b"verify_signature").is_empty());
    assert!(backend_contains(&*mirror, b"CVE-2026-0001").is_empty());

    e.alice.release_embargo(&e.embargo).unwrap();
    remote::push(&mut e.alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let pubrepo = anon(mirror);
    assert_eq!(pubrepo.view().tags["main"].target, res.snapshot);
    assert!(read_at(&pubrepo, &res.snapshot, "feature.rs").starts_with(b"pub fn"));
}

#[test]
fn an_outsider_cannot_record_edits_on_top_of_an_embargo_or_merge_it() {
    let mut e = embargoed_fix();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut e.alice, mirror.clone(), true, &[], false).unwrap();
    // The embargoed merge never reaches an outsider: there is nothing to
    // record edits on top of, or to merge into.
    let (carol, _cfs) = clone_of("carol", mirror);
    assert!(carol.exact().snapshot(&e.merge).unwrap().is_none(), "the embargoed merge reached the mirror");
}

#[test]
fn releasing_an_embargo_never_declassifies_scope_cloaked_files() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", "secrets/ cloak team\n"), ("auth.rs", "v1\n"), ("secrets/.env.k", "old-key\n")],
        "v1",
    );
    alice.set_tag("main", main, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2\n").unwrap();
    ws.write("secrets/.env.k", "rotated-team-only-key\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let res = alice.merge(WS, main, vec![fix], "m", team_embargo()).unwrap();
    let e = file_entry(&alice, &res.snapshot, "secrets/.env.k").unwrap();
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() });
    alice.release_embargo(res.embargo.as_deref().unwrap()).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let pubrepo = anon(mirror.clone());
    assert_eq!(read_at(&pubrepo, &res.snapshot, "auth.rs"), b"v2\n");
    assert!(backend_contains(&*mirror, b"rotated-team-only-key").is_empty());
}

// ---- BUG-004: merging a line --------------------------------------------------------

#[test]
fn merging_a_public_line_does_not_publish_files_cloaked_by_policy() {
    // A workspace whose secret file is cloaked under `ops` by policy:
    // merging the workspace keeps it sealed for `ops`.
    let (mut alice, fs, _) = new_repo("alice");
    alice.keys().create_scope("ops").unwrap();
    let main = commit_files(&mut alice, &*fs, &[(".veilpolicy", "prod/ cloak ops\n")], "v1");
    alice.create_workspace("exp", vec![main]).unwrap();
    let ov = alice.workspace_overlay("exp").unwrap();
    ov.write(&p("prod/.env.db"), b"ops-password\n").unwrap();
    let exp = alice.snapshot_workspace("exp", &ov).unwrap().snapshot;
    let res = alice.merge(WS, main, vec![exp], "merge exp", None).unwrap();
    let e = file_entry(&alice, &res.snapshot, "prod/.env.db").unwrap();
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
        &[(".veilpolicy", "prod/ cloak ops\n"), ("prod/.env.db", "ops-only\n")],
        "v1",
    );
    let pr_ws = alice.ephemeral_workspace(main).unwrap();
    pr_ws.write(".veilpolicy", "prod/ cloak opz\n").unwrap();
    let (pr, _) = alice.commit_ephemeral(&pr_ws, "policy PR").unwrap();
    let res = alice.merge(WS, main, vec![pr], "merge PR", None).unwrap();
    assert!(res.warnings.iter().any(|w| w.contains(".veilpolicy") && w.contains("prod/.env.db")), "{:?}", res.warnings);
    assert_eq!(read_at(&alice, &res.snapshot, ".veilpolicy"), b"prod/ cloak ops\n");
    assert_eq!(
        file_entry(&alice, &res.snapshot, "prod/.env.db").unwrap().visibility,
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
        &[(".veilpolicy", "secrets/ cloak team\n"), ("secrets/.env.db", "db-password-xyz\n")],
        "v1",
    );
    alice.set_tag("main", main, false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();
    let (mut mallory, mfs) = clone_of("mallory", team.clone());
    let wc = mallory.new_change(WS, vec![main], "").unwrap();
    let tree = mallory.snapshot(&wc).unwrap().tree;
    mallory.checkout_tree(&*mfs, None, &tree).unwrap();
    mfs.write(&p(".veilpolicy"), b"secrets/ public!\n").unwrap();
    let pr = snap(&mut mallory, &*mfs);
    assert!(!file_entry(&mallory, &pr, "secrets/.env.db").unwrap().visibility.is_public());
    mallory.set_tag("pr", pr, false).unwrap();
    remote::push(&mut mallory, team.clone(), false, &["pr".to_string()], false).unwrap();

    remote::pull(&mut alice, "origin", team).unwrap();
    let old = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = alice.new_change(WS, vec![pr], "").unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&old), &to).unwrap();
    assert_eq!(fs.read(&p("secrets/.env.db")).unwrap(), b"db-password-xyz\n");
    fs.write(&p("secrets/.env.db"), b"db-password-rotated\n").unwrap();
    let wc = snap(&mut alice, &*fs);
    let e = file_entry(&alice, &wc, "secrets/.env.db").unwrap();
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() }, "sticky: still sealed");

    // Alice's own, deliberate edit of the policy does expose it.
    fs.write(&p(".veilpolicy"), b"secrets/.env.db public!\n").unwrap();
    let wc = snap(&mut alice, &*fs);
    assert!(file_entry(&alice, &wc, "secrets/.env.db").unwrap().visibility.is_public());
}

/// Only `public!` exposes a secret file: a plain `public` line over a
/// sealed one is refused, and the file is never recorded in plaintext.
#[test]
fn a_plain_public_line_never_exposes_a_sealed_secret_file() {
    let (mut alice, fs, _) = new_repo("alice");
    commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", "secrets/ cloak team\n"), ("secrets/.env.k", "k = \"AKIAIOSFODNN7EXAMPLE\"\n")],
        "v1",
    );
    fs.write(&p(".veilpolicy"), b"secrets/ public\n").unwrap();
    let out = alice.snapshot_workspace(WS, &*fs).unwrap();
    assert!(out.report.blocked_exposures.iter().any(|p| p.as_str() == "secrets/.env.k"), "{:?}", out.report);
    // Kept local from now on (nothing of it is recorded), never public.
    let e = file_entry(&alice, &out.snapshot, "secrets/.env.k");
    assert!(e.as_ref().is_none_or(|e| !e.visibility.is_public()), "{e:?}");
    let mirror = Arc::new(MemoryBackend::new());
    alice.set_tag("main", out.snapshot, false).unwrap();
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(backend_contains(&*mirror, b"AKIAIOSFODNN7EXAMPLE").is_empty());
}

// ---- BUG-005 / BUG-006 / BUG-017: rebase, new, squash -------------------------------

#[test]
fn an_explicit_rebase_keeps_cloaked_content_sealed() {
    let (mut alice, fs, _) = new_repo("alice");
    alice.keys().create_scope("ops").unwrap();
    let lines: String = (1..=12).map(|i| format!("line {i}\n")).collect();
    let base = commit_files(&mut alice, &*fs, &[(".veilpolicy", ".env.conf cloak ops\n"), (".env.conf", &lines)], "base");
    let ws = alice.ephemeral_workspace(base).unwrap();
    ws.write(".env.conf", lines.replace("line 12\n", "secret 12\n")).unwrap();
    let (c, _) = alice.commit_ephemeral(&ws, "ops edit").unwrap();
    let ws = alice.ephemeral_workspace(base).unwrap();
    ws.write(".env.conf", lines.replace("line 1\n", "line one\n")).unwrap();
    let (dest, _) = alice.commit_ephemeral(&ws, "another edit").unwrap();
    let c2 = alice.rebase(c, vec![dest]).unwrap();
    let e = file_entry(&alice, &c2, ".env.conf").unwrap();
    assert!(!e.visibility.is_public(), "{:?}", e.visibility);
    let text = String::from_utf8(alice.store().read_entry(&e).unwrap()).unwrap();
    assert!(text.contains("line one") && text.contains("secret 12"));
}
