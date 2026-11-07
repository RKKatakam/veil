//! Round-2 adversarial tests: withheld history, nested
//! embargoes and the routes by which an embargoed fix could leave the
//! repository before its release.
//!
//! Every test asserts the secure behaviour; the BUG-NNN references point at
//! `docs/BUGS.md`. Overlapping embargoes are refused in Veil 1.0, so the
//! nested-embargo tests (BUG-041, BUG-047) assert that refusal and that
//! nothing leaks before or after it.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    commands::{EmbargoSpec, MergeResult},
    object::Object,
    remote,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

fn embargo(scope: &str) -> Option<EmbargoSpec> {
    Some(EmbargoSpec {
        scope: scope.into(),
        until: None,
    })
}

/// A reader of `backend` holding `identity` (or a fresh, unrelated one).
fn reader(backend: Arc<MemoryBackend>, identity: Option<Identity>) -> Repo {
    Repo::open(backend, Some(identity.unwrap_or_else(|| Identity::generate("anon"))), "reader").unwrap()
}

/// Every object of `r`'s store that `r` can decrypt (blobs, possibly after
/// peeling sealed layers) and that contains `needle`. This is what an
/// outsider can actually *read* from a remote: ciphertext under a published
/// key counts as plaintext.
fn readable_containing(r: &Repo, needle: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for id in r.store().list_objects().unwrap() {
        let Ok(obj) = r.store().open(&id) else { continue };
        let bytes = match obj {
            Object::Blob(b) => b,
            Object::Tree(t) => serde_json::to_vec(&t).unwrap(),
            Object::Snapshot(s) => {
                let mut b = serde_json::to_vec(s.description.as_str()).unwrap();
                b.extend(serde_json::to_vec(&s).unwrap());
                b
            }
            Object::Conflict(c) => format!("{c:?}").into_bytes(),
            Object::Atag(a) => serde_json::to_vec(&a).unwrap(),
            Object::Sealed(_) => continue,
        };
        if bytes.windows(needle.len()).any(|w| w == needle) {
            out.push(id.short());
        }
    }
    out
}

fn wc_checkout(repo: &mut Repo, fs: &dyn StorageBackend, from: ObjectId) {
    let wc = repo.workspace_wc(WS).unwrap();
    let to = repo.snapshot(&wc).unwrap().tree;
    let from = repo.snapshot(&from).unwrap().tree;
    repo.checkout_tree(fs, Some(&from), &to).unwrap();
}

struct Two {
    alice: Repo,
    m1: ObjectId,
    e1: String,
    fix2: ObjectId,
    /// Merging fix 2 under a second embargo while E1 is unreleased.
    second: veil_core::Result<MergeResult>,
}

/// Two security fixes in flight on `main`: fix 1 is merged under embargo
/// E1, then fix 2 (an independent bug) is to be merged on top under
/// embargo E2. Both fixes are developed in their own workspaces.
///
/// Overlapping embargoes are refused in Veil 1.0 (BUG-041, BUG-047): the
/// second merge fails while E1 is unreleased, and goes ahead once E1 is
/// released ([`merge_second_after_release`]).
fn two_embargoes(scope1: &str, scope2: &str, alice_id: Identity) -> Two {
    let (mut alice, fs) = repo_for("alice", &alice_id);
    for s in [scope1, scope2] {
        if s != "team" && alice.keys().ring_state(s).unwrap().is_none() {
            alice.keys().create_scope(s).unwrap();
        }
    }
    let main = commit_files(
        &mut alice,
        &*fs,
        &[("auth.rs", "fn check() -> bool { true }\n"), ("crypto.rs", "fn eq(a, b) { a == b }\n")],
        "v1",
    );
    alice.set_tag("main", main, false).unwrap();

    alice.create_workspace("fix1", vec![main]).unwrap();
    let ov = alice.workspace_overlay("fix1").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature_FIX1() }\n").unwrap();
    let fix1 = alice.snapshot_workspace("fix1", &ov).unwrap().snapshot;
    let r1 = alice.merge(WS, main, vec![fix1], "fix one", embargo(scope1)).unwrap();

    alice.create_workspace("fix2", vec![main]).unwrap();
    let ov = alice.workspace_overlay("fix2").unwrap();
    ov.write(&p("crypto.rs"), b"fn eq(a, b) { constant_time_eq_FIX2(a, b) }\n").unwrap();
    let fix2 = alice.snapshot_workspace("fix2", &ov).unwrap().snapshot;
    let main_now = alice.view().tags["main"].target;
    assert_eq!(main_now, r1.snapshot);
    let second = alice.merge(WS, main_now, vec![fix2], "fix two", embargo(scope2));
    Two {
        alice,
        m1: r1.snapshot,
        e1: r1.embargo.unwrap(),
        fix2,
        second,
    }
}

/// The second embargoed merge was refused, with a message naming the
/// earlier embargo and the way out, and left nothing behind.
fn assert_overlap_refused(t: &Two) {
    let err = t.second.as_ref().map(|r| r.snapshot).unwrap_err().to_string();
    assert!(
        err.contains(&t.e1) && err.contains("release the earlier embargo first"),
        "unexpected refusal: {err}"
    );
    assert_eq!(t.alice.view().tags["main"].target, t.m1, "the refused merge moved main");
    assert_eq!(t.alice.keys().embargoes().unwrap().len(), 1, "the refused merge created an embargo record");
}

/// What the message says to do: release E1, then merge fix 2 under E2.
fn merge_second_after_release(t: &mut Two, scope2: &str) -> (ObjectId, String) {
    t.alice.release_embargo(&t.e1).unwrap();
    let r = t.alice.merge(WS, t.m1, vec![t.fix2], "fix two", embargo(scope2)).unwrap();
    assert!(String::from_utf8(read_at(&t.alice, &r.snapshot, "crypto.rs")).unwrap().contains("FIX2"));
    (r.snapshot, r.embargo.unwrap())
}

// ---- nested embargoes (refused in 1.0) -------------------------------------------

/// Control: the refused second embargo publishes nothing, and nothing of
/// the first fix can be read on the public mirror before its release.
#[test]
fn two_unreleased_embargoes_publish_nothing() {
    let mut t = two_embargoes("team", "team", Identity::generate("alice"));
    assert_overlap_refused(&t);
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut t.alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    assert!(readable_containing(&anon, b"FIX1").is_empty());
    assert!(readable_containing(&anon, b"FIX2").is_empty());
}

/// BUG-041: releasing the first embargo published the second fix, which
/// had been wrapped under the first embargo's key. Adapted to the 1.0
/// design (overlap refused): the second merge is refused while E1 is
/// unreleased; after E1's release it goes ahead under E2, and the public
/// mirror then reads fix 1 (tagged on the released merge) but not fix 2,
/// until E2 is released too.
#[test]
fn releasing_the_first_embargo_does_not_publish_the_second_fix() {
    let mut t = two_embargoes("team", "team", Identity::generate("alice"));
    assert_overlap_refused(&t);
    let (m2, e2) = merge_second_after_release(&mut t, "team");
    assert!(!t.alice.keys().embargo_released(&e2));
    t.alice.set_tag("released", t.m1, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut t.alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror.clone(), None);
    // Fix 1 is public now, as intended.
    assert!(!readable_containing(&anon, b"FIX1").is_empty());
    // Fix 2 is still under embargo E2.
    let leaked = readable_containing(&anon, b"FIX2");
    assert!(leaked.is_empty(), "objects of the unreleased fix readable on the public mirror: {leaked:?}");
    assert!(anon.snapshot_opt(&m2).unwrap().is_none(), "the merge under E2 reached the mirror");
    // Released, it is pushed.
    t.alice.release_embargo(&e2).unwrap();
    remote::push(&mut t.alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    assert!(!readable_containing(&anon, b"FIX2").is_empty());
}

/// BUG-041, same root cause without a release: a team member who holds the
/// first embargo's scope but not the second's read the second fix from the
/// team remote. Adapted: the overlap is refused, and neither the refused
/// attempt nor the later, legitimate E2 merge lets bob read fix 2.
#[test]
fn a_member_of_the_first_embargo_scope_cannot_read_the_second_fix() {
    let alice_id = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let mut t = two_embargoes("team", "sec", alice_id);
    assert_overlap_refused(&t);
    t.alice.keys().grant("team", &bob.public_id(), "bob").unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut t.alice, team.clone(), false, &[], false).unwrap();
    let bob_repo = reader(team.clone(), Some(bob.clone()));
    assert!(!bob_repo.keys().has("sec"));
    let leaked = readable_containing(&bob_repo, b"FIX2");
    assert!(leaked.is_empty(), "bob (team, not sec) reads the sec fix: {leaked:?}");

    let (_, e2) = merge_second_after_release(&mut t, "sec");
    remote::push(&mut t.alice, team.clone(), false, &[], false).unwrap();
    let bob_repo = reader(team, Some(bob));
    assert!(!bob_repo.keys().has(&format!("embargo/{e2}")));
    let leaked = readable_containing(&bob_repo, b"FIX2");
    assert!(leaked.is_empty(), "bob (team, not sec) reads the sec-embargoed fix: {leaked:?}");
}

/// BUG-047: releasing a newer embargo first revealed what the older one
/// changed (file names, sizes). With overlap refused there is no newer
/// embargo on the line to release: the mirror receives nothing of E1's
/// merge, and a line built on top of E1 cannot be merged in under another
/// embargo either.
#[test]
fn releasing_the_second_embargo_first_hides_the_first_fix_metadata() {
    let mut t = two_embargoes("team", "team", Identity::generate("alice"));
    assert_overlap_refused(&t);
    // Merging in a line that carries E1 (instead of merging into it).
    let main0 = t.alice.snapshot(&t.m1).unwrap().parents[0];
    let ws = t.alice.ephemeral_workspace(t.m1).unwrap();
    ws.write("notes.md", "built on the fix\n").unwrap();
    let (on_e1, _) = t.alice.commit_ephemeral(&ws, "on top of fix one").unwrap();
    let err = t.alice.merge(WS, main0, vec![on_e1], "m", embargo("team")).unwrap_err().to_string();
    assert!(err.contains("a line it merges in") && err.contains(&t.e1), "{err}");
    assert_eq!(t.alice.keys().embargoes().unwrap().len(), 1);

    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut t.alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    assert_eq!(t.alice.view().tags["main"].target, t.m1);
    assert!(anon.snapshot_opt(&t.m1).unwrap().is_none(), "the mirror received E1's merge");
    assert!(anon.snapshot_opt(&on_e1).unwrap().is_none(), "the mirror received a line built on E1");
    assert!(readable_containing(&anon, b"FIX1").is_empty());
}

/// Two embargoes on separate lines are allowed (neither line carries the
/// other's). A new embargo over either line is refused; a plain merge of
/// the two carries both, and is withheld until both are released: nothing
/// leaks.
#[test]
fn lines_under_different_unreleased_embargoes_cannot_be_combined() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("a.rs", "a\n"), ("b.rs", "b\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("a.rs", "a FIX1\n").unwrap();
    let (fix1, _) = alice.commit_ephemeral(&ws, "fix1").unwrap();
    let r1 = alice.merge(WS, main, vec![fix1], "m1", embargo("team")).unwrap();
    let e1 = r1.embargo.clone().unwrap();
    // A release branch cut before the merge gets its own embargoed fix.
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("b.rs", "b FIX2\n").unwrap();
    let (fix2, _) = alice.commit_ephemeral(&ws, "fix2").unwrap();
    let r2 = alice.merge(WS, main, vec![fix2], "m2", embargo("team")).unwrap();
    let e2 = r2.embargo.clone().unwrap();
    alice.set_tag("release", r2.snapshot, false).unwrap();

    // A new embargo over either line is refused.
    let err = alice.merge(WS, r1.snapshot, vec![r2.snapshot], "combine", embargo("team")).unwrap_err().to_string();
    assert!(err.contains("cannot overlap") && err.contains(&e1), "{err}");

    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror.clone(), None);
    assert!(readable_containing(&anon, b"FIX1").is_empty());
    assert!(readable_containing(&anon, b"FIX2").is_empty());

    // Combine the lines and release one: the other fix stays hidden.
    let m = alice.merge(WS, r1.snapshot, vec![r2.snapshot], "combine", None).unwrap();
    assert!(String::from_utf8(read_at(&alice, &m.snapshot, "b.rs")).unwrap().contains("FIX2"));
    alice.set_tag("main", m.snapshot, true).unwrap();
    alice.release_embargo(&e1).unwrap();
    let r = remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(r.tags_skipped.iter().any(|(t, why)| t == "main" && why.contains(&e2)), "{r:?}");
    let anon = reader(mirror.clone(), None);
    assert!(anon.snapshot_opt(&m.snapshot).unwrap().is_none());
    assert!(readable_containing(&anon, b"FIX2").is_empty());
    // Both released: everything is pushed.
    alice.release_embargo(&e2).unwrap();
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    assert!(!readable_containing(&anon, b"FIX1").is_empty());
    assert!(!readable_containing(&anon, b"FIX2").is_empty());
}

// ---- secret scanning of content that a release publishes -------------------------

/// A key holder's edit to a file that is under an unreleased embargo is
/// sealed under the embargo key without being secret-scanned. Releasing
/// the embargo then publishes it: a declassification that never went
/// through the scanner.
#[test]
fn an_edit_on_an_embargoed_file_is_secret_scanned_before_release_publishes_it() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "fn check() -> bool { verify() }\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let r = alice.merge(WS, main, vec![fix], "fix", embargo("team")).unwrap();
    wc_checkout(&mut alice, &*fs, main);
    // Follow-up on the embargoed line: a debugging key slips in.
    fs.write(
        &p("auth.rs"),
        b"fn check() -> bool { verify() }\nconst AWS: &str = \"AKIAIOSFODNN7EXAMPLE\";\n",
    )
    .unwrap();
    let out = alice.snapshot_workspace(WS, &*fs).unwrap();
    let quarantined = out.report.quarantined.iter().any(|(p, _)| p.as_str() == "auth.rs");
    alice.commit_working_copy(WS, "follow-up").unwrap();
    alice.release_embargo(r.embargo.as_deref().unwrap()).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    let leaked = readable_containing(&anon, b"AKIAIOSFODNN7EXAMPLE");
    assert!(
        quarantined && leaked.is_empty(),
        "quarantined: {quarantined}; AWS key readable on the public mirror: {leaked:?}"
    );
}

/// Control: a *new* file on the embargoed line is scanned.
#[test]
fn a_new_file_on_an_embargoed_line_is_secret_scanned() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n")], "v1");
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    alice.merge(WS, main, vec![fix], "fix", embargo("team")).unwrap();
    wc_checkout(&mut alice, &*fs, main);
    fs.write(&p("new.rs"), b"const AWS: &str = \"AKIAIOSFODNN7EXAMPLE\";\n").unwrap();
    let out = alice.snapshot_workspace(WS, &*fs).unwrap();
    assert!(out.report.quarantined.iter().any(|(p, _)| p.as_str() == "new.rs"));
}

// ---- edits after a release ---------------------------------------------------------

/// A file edited on an embargoed line carries the pre-embargo object as its
/// fallback. After the release, writing the file back to that old content
/// is a real edit (a revert), but the snapshot takes it for a stale working
/// copy and keeps the embargoed version. On `.veilpolicy` this silently
/// drops a re-cloak: disk says `cloak`, history says `public` (and the
/// `adversarial2_props` model turns that into a public leak of cloaked
/// content).
#[test]
fn reverting_a_file_to_its_pre_embargo_content_after_release_is_recorded() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("a.txt", "v1\n")], "v1");
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("fix.rs", "fix\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let r = alice.merge(WS, main, vec![fix], "fix", embargo("team")).unwrap();
    wc_checkout(&mut alice, &*fs, main);
    // An edit on the embargoed line: sealed under the embargo, fallback v1.
    fs.write(&p("a.txt"), b"v2\n").unwrap();
    snap(&mut alice, &*fs);
    alice.commit_working_copy(WS, "v2").unwrap();
    alice.release_embargo(r.embargo.as_deref().unwrap()).unwrap();
    // Deliberately revert to v1.
    fs.write(&p("a.txt"), b"v1\n").unwrap();
    snap(&mut alice, &*fs);
    let wc = alice.workspace_wc(WS).unwrap();
    let recorded = String::from_utf8(read_at(&alice, &wc, "a.txt")).unwrap();
    assert_eq!(recorded, "v1\n", "the revert on disk was not recorded; history still says {recorded:?}");
}

// ---- metadata in the merge snapshot ------------------------------------------------

/// The merge snapshot's `conflicts` list names files of the fix in
/// plaintext, so the merge never reaches the mirror before release.
#[test]
fn an_embargoed_merge_does_not_name_the_fix_files_in_its_conflict_list() {
    let (mut alice, fs, _) = new_repo("alice");
    let main0 = commit_files(&mut alice, &*fs, &[("src/session_token_validation.rs", "a\nb\nc\n")], "v1");
    let ws = alice.ephemeral_workspace(main0).unwrap();
    ws.write("src/session_token_validation.rs", "a\nFIXED\nc\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    // Main moved on and touched the same line: the merge conflicts.
    let main = commit_files(&mut alice, &*fs, &[("src/session_token_validation.rs", "a\nmain\nc\n")], "v2");
    alice.set_tag("main", main, false).unwrap();
    let r = alice.merge(WS, main, vec![fix], "fix", embargo("team")).unwrap();
    assert!(!r.conflicts.is_empty());
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let hits = backend_contains(&*mirror, b"session_token_validation");
    assert!(hits.is_empty(), "the mirror names the fix's file: {hits:?}");
    let anon = reader(mirror, None);
    assert!(anon.snapshot_opt(&r.snapshot).unwrap().is_none(), "the embargoed merge reached the mirror");
}

/// Follow-up commits a key holder makes on top of an embargoed merge stay
/// hidden "because everything below the embargoed root is sealed"; their
/// descriptions do not.
#[test]
fn follow_up_commit_messages_on_an_embargoed_line_are_not_public() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    alice.merge(WS, main, vec![fix], "fix", embargo("team")).unwrap();
    wc_checkout(&mut alice, &*fs, main);
    fs.write(&p("auth.rs"), b"v3\n").unwrap();
    snap(&mut alice, &*fs);
    alice
        .commit_working_copy(WS, "also reject unsigned tokens in the refresh path (CVE-2026-9999)")
        .unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let hits = backend_contains(&*mirror, b"CVE-2026-9999");
    assert!(hits.is_empty(), "follow-up message on the public mirror: {hits:?}");
    // Packs are compressed, so the raw scan above can miss a plain
    // description: read every snapshot as an outsider too.
    let anon = reader(mirror, None);
    let readable = readable_containing(&anon, b"CVE-2026-9999");
    assert!(readable.is_empty(), "follow-up message readable on the public mirror: {readable:?}");
    // Key holders still read it.
    let main = alice.view().tags["main"].target;
    assert!(alice.description(&alice.snapshot(&main).unwrap()).contains("CVE-2026-9999"));
}

// ---- embargo scope vs. the cloak of the fix line --------------------------------------

/// The README flow with an embargo scope narrower than the fix line's cloak
/// (`--cloak team`, `--embargo --scope sec`). Before release the team remote
/// receives the cloaked fix history, which every `team` member can read,
/// although only `sec` members are supposed to see the fix.
#[test]
fn the_fix_history_is_not_readable_outside_the_embargo_scope() {
    let alice_id = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let (mut alice, fs) = repo_for("alice", &alice_id);
    alice.keys().create_scope("sec").unwrap();
    alice.keys().grant("team", &bob.public_id(), "bob").unwrap();
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    alice.create_workspace("fix", vec![main]).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature_SECONLY() }\n").unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    alice.merge(WS, main, vec![fix], "fix", embargo("sec")).unwrap();

    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &["main".to_string()], false).unwrap();
    let bob_repo = reader(team, Some(bob));
    assert!(!bob_repo.keys().has("sec"));
    let leaked = readable_containing(&bob_repo, b"SECONLY");
    assert!(leaked.is_empty(), "bob (team, not sec) reads the embargoed fix: {leaked:?}");
}

// ---- withheld history: other routes ------------------------------------------------------

/// Rebasing the fix line after the merge (a common "clean up the branch"
/// step) rebases the embargoed merge too; the merge must keep withholding
/// the (rewritten) fix.
#[test]
fn rebasing_the_fix_after_the_merge_keeps_it_withheld() {
    let (mut alice, fs, _) = new_repo("alice");
    let base = commit_files(&mut alice, &*fs, &[("README", "r\n")], "v0");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2 SECRETFIX\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    alice.merge(WS, main, vec![fix], "m", embargo("team")).unwrap();
    // Describe the fix after the fact: rewrites it, auto-rebases the merge.
    alice.describe(fix, "fix: details of the bug").unwrap();
    let _ = base;
    let mirror = Arc::new(MemoryBackend::new());
    let r = remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(r.tags_skipped.iter().any(|(t, _)| t == "main"), "{r:?}");
    let anon = reader(mirror.clone(), None);
    assert!(readable_containing(&anon, b"SECRETFIX").is_empty());
    assert!(backend_contains(&*mirror, b"details of the bug").is_empty());
}

/// `vl squash` of the follow-up into the embargoed merge keeps the wrapper.
#[test]
fn squashing_into_the_embargoed_merge_keeps_it_sealed() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2 SECRETFIX\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    alice.merge(WS, main, vec![fix], "m", embargo("team")).unwrap();
    wc_checkout(&mut alice, &*fs, main);
    fs.write(&p("auth.rs"), b"v3 SECRETFIX more\n").unwrap();
    let wc = snap(&mut alice, &*fs);
    alice.squash(wc).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    assert!(readable_containing(&anon, b"SECRETFIX").is_empty());
}

/// Explicitly rebasing the embargoed merge onto a newer main (instead of
/// merging main into it) keeps it sealed for outsiders.
#[test]
fn rebasing_the_embargoed_merge_itself_keeps_the_fix_sealed() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n"), ("other", "o\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2 SECRETFIX\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let r = alice.merge(WS, main, vec![fix], "m", embargo("team")).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("other", "o2\n").unwrap();
    let (newer, _) = alice.commit_ephemeral(&ws, "newer main").unwrap();
    let m2 = alice.rebase(r.snapshot, vec![newer]).unwrap();
    alice.set_tag("main", m2, true).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    assert!(readable_containing(&anon, b"SECRETFIX").is_empty());
}

// ---- adversarial pass: simplification part 2 ----------------------------------------

/// The fix merged under an unreleased embargo, and a follow-up change on
/// `main` built on the merge: `(alice, main before the merge, the merge,
/// the follow-up)`.
fn embargoed_with_follow_up() -> (Repo, ObjectId, ObjectId, ObjectId) {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n"), ("other", "o\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2 SIMPADV-EMBARGOED-FIX-7741\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let r = alice.merge(WS, main, vec![fix], "m", embargo("team")).unwrap();
    let ws = alice.ephemeral_workspace(r.snapshot).unwrap();
    ws.write("other", "o2\n").unwrap();
    let (follow, _) = alice.commit_ephemeral(&ws, "follow-up").unwrap();
    alice.set_tag("main", follow, false).unwrap();
    // Control: the follow-up is withheld (it builds on the embargoed merge).
    let tip = alice.view().tags["main"].target;
    assert!(remote::embargo_blocks(&alice, &[tip]).unwrap()[0].is_some(), "control: main is withheld before the rewrite");
    (alice, main, r.snapshot, follow)
}

/// After a rewrite of the embargoed merge: `main` still holds the fix, so
/// it is still withheld from every remote (what `vl push` to the Veil
/// server checks, `remote::embargo_blocks`), and a push to a mirror
/// carries none of it.
fn assert_fix_still_withheld(alice: &mut Repo) {
    let tip = alice.view().tags["main"].target;
    assert!(
        String::from_utf8(read_at(alice, &tip, "auth.rs")).unwrap().contains("SIMPADV-EMBARGOED-FIX-7741"),
        "control: main still holds the fix"
    );
    let blocks = remote::embargo_blocks(alice, &[tip]).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    let _ = remote::push(alice, mirror.clone(), true, &[], false);
    let anon = reader(mirror, None);
    let leaked = readable_containing(&anon, b"SIMPADV-EMBARGOED-FIX-7741");
    assert!(
        blocks[0].is_some() && leaked.is_empty(),
        "the unreleased fix left its embargo: `vl push` would upload main ({:?}); the mirror reads it in {leaked:?}",
        blocks[0]
    );
}

/// BUG-943 (pre-existing: the same leak on `integration` 1b39297, to a
/// public remote): `vl abandon` of the embargoed merge rebases the
/// follow-up onto the merge's parents (`main` and the fix), a plain merge
/// of the fix with no embargoed ancestor, so nothing withholds it any more
/// and `vl push` uploads it.
#[test]
#[ignore = "BUG-943: abandoning the embargoed merge leaves its fix in the follow-up's tree, unwithheld"]
fn abandoning_the_embargoed_merge_keeps_the_fix_withheld() {
    let (mut alice, _, m, _) = embargoed_with_follow_up();
    alice.abandon(m).unwrap();
    assert_fix_still_withheld(&mut alice);
}

/// BUG-942: the embargoed merge squashed into its follow-up (a descendant
/// inside the embargo, so the copy check lets it through) is abandoned,
/// and the follow-up keeps the fix with no embargoed ancestor: `vl push`
/// uploads it. `integration` 1b39297 refused this squash ("a change under
/// an embargo can only be squashed whole into its parent", a check on the
/// wrapper tree that format 8 removed with it).
#[test]
#[ignore = "BUG-942: squashing the embargoed merge into its follow-up leaves the fix unwithheld"]
fn squashing_the_embargoed_merge_into_its_follow_up_keeps_the_fix_withheld() {
    let (mut alice, _, m, follow) = embargoed_with_follow_up();
    alice.squash_into(m, Some(follow), None).unwrap();
    assert_fix_still_withheld(&mut alice);
}
