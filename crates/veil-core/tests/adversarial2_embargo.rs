//! Round-2 adversarial tests: embargo wrappers, withheld history, nested
//! embargoes and the routes by which an embargoed fix could leave the
//! repository before its release.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md`.

mod adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    object::Object,
    remote,
    tree::walk_files,
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
                let mut b = serde_json::to_vec(&s_desc(r, &s)).unwrap();
                b.extend(serde_json::to_vec(&s).unwrap());
                b
            }
            Object::Sealed(_) => continue,
        };
        if bytes.windows(needle.len()).any(|w| w == needle) {
            out.push(id.short());
        }
    }
    out
}

fn s_desc(r: &Repo, s: &veil_core::object::Snapshot) -> String {
    r.store().read_text(&s.description).unwrap_or_default()
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
    m2: ObjectId,
    e1: String,
    e2: String,
}

/// Two security fixes in flight on `main`: fix 1 is merged under embargo
/// E1, then fix 2 (an independent bug) is merged on top under embargo E2.
/// Both fixes are developed as cloaked lines of work, as the README
/// recommends.
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
    alice.set_tag("main", main, None, false).unwrap();

    alice.create_workspace("fix1", vec![main], Some(scope1.into())).unwrap();
    let ov = alice.workspace_overlay("fix1").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature_FIX1() }\n").unwrap();
    let fix1 = alice.snapshot_workspace("fix1", &ov).unwrap().snapshot;
    let r1 = alice.merge(WS, main, vec![fix1], "fix one", embargo(scope1)).unwrap();

    alice.create_workspace("fix2", vec![main], Some(scope2.into())).unwrap();
    let ov = alice.workspace_overlay("fix2").unwrap();
    ov.write(&p("crypto.rs"), b"fn eq(a, b) { constant_time_eq_FIX2(a, b) }\n").unwrap();
    let fix2 = alice.snapshot_workspace("fix2", &ov).unwrap().snapshot;
    let main_now = alice.view().tags["main"].target;
    assert_eq!(main_now, r1.snapshot);
    let r2 = alice.merge(WS, main_now, vec![fix2], "fix two", embargo(scope2)).unwrap();
    assert!(String::from_utf8(read_at(&alice, &r2.snapshot, "crypto.rs")).unwrap().contains("FIX2"));
    Two {
        alice,
        m1: r1.snapshot,
        m2: r2.snapshot,
        e1: r1.embargo.unwrap(),
        e2: r2.embargo.unwrap(),
    }
}

// ---- nested embargoes ----------------------------------------------------------

/// Control: before any release nothing of either fix can be read on the
/// public mirror.
#[test]
fn two_unreleased_embargoes_publish_nothing() {
    let mut t = two_embargoes("team", "team", Identity::generate("alice"));
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut t.alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    assert!(readable_containing(&anon, b"FIX1").is_empty());
    assert!(readable_containing(&anon, b"FIX2").is_empty());
}

/// Releasing the *first* embargo must not publish the second fix. The
/// second fix's files were sealed under the first embargo's key when the
/// merge re-wrapped the line (sticky embargo), and the second wrapper lists
/// them, so the public push carries them under a key that is now public.
#[test]
#[ignore = "BUG-041: releasing an older embargo publishes the content of a newer, unreleased one"]
fn releasing_the_first_embargo_does_not_publish_the_second_fix() {
    let mut t = two_embargoes("team", "team", Identity::generate("alice"));
    t.alice.release_embargo(&t.e1).unwrap();
    assert!(!t.alice.keys().embargo_released(&t.e2));
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut t.alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    // Fix 1 is public now, as intended.
    assert!(!readable_containing(&anon, b"FIX1").is_empty());
    // Fix 2 is still under embargo E2.
    let leaked = readable_containing(&anon, b"FIX2");
    assert!(leaked.is_empty(), "objects of the unreleased fix readable on the public mirror: {leaked:?}");
}

/// Same root cause, no release needed: a team member who holds the first
/// embargo's scope but not the second's reads the second fix from the team
/// remote.
#[test]
#[ignore = "BUG-041: releasing an older embargo publishes the content of a newer, unreleased one"]
fn a_member_of_the_first_embargo_scope_cannot_read_the_second_fix() {
    let alice_id = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let mut t = two_embargoes("team", "sec", alice_id);
    t.alice.keys().grant("team", &bob.public_id(), "bob").unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut t.alice, team.clone(), false, &[], false).unwrap();
    let bob_repo = reader(team, Some(bob));
    assert!(!bob_repo.keys().has("sec"));
    assert!(!bob_repo.keys().has(&format!("embargo/{}", t.e2)));
    let leaked = readable_containing(&bob_repo, b"FIX2");
    assert!(leaked.is_empty(), "bob (team, not sec) reads the sec-embargoed fix: {leaked:?}");
}

/// Releasing the *second* embargo first must not reveal what the first
/// one changed: its new file names and sizes, or which files it touched.
#[test]
#[ignore = "BUG-047: releasing a newer embargo first reveals the older one's changed files and sizes"]
fn releasing_the_second_embargo_first_hides_the_first_fix_metadata() {
    let mut t = two_embargoes("team", "team", Identity::generate("alice"));
    t.alice.release_embargo(&t.e2).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut t.alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    let tree = anon.snapshot(&t.m2).unwrap().tree;
    let files: Vec<(String, u64, String)> = walk_files(anon.store(), &tree)
        .unwrap()
        .into_iter()
        .map(|(p, e)| (p.to_string(), e.size, e.visibility.label()))
        .collect();
    // What outsiders may see of auth.rs is the pre-E1 version, exactly.
    let auth = files.iter().find(|f| f.0 == "auth.rs").unwrap();
    assert_eq!(
        (auth.1, auth.2.as_str()),
        ("fn check() -> bool { true }\n".len() as u64, "public"),
        "the mirror reveals that E1 changed auth.rs and its new size: {files:?}"
    );
    let _ = t.m1;
}

// ---- secret scanning of content that a release publishes -------------------------

/// A key holder's edit to a file that is under an unreleased embargo is
/// sealed under the embargo key without being secret-scanned. Releasing
/// the embargo then publishes it: a declassification that never went
/// through the scanner.
#[test]
#[ignore = "BUG-042: edits of embargoed files skip the secret scanner and are published by the release"]
fn an_edit_on_an_embargoed_file_is_secret_scanned_before_release_publishes_it() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
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
#[ignore = "BUG-050: after a release, reverting a file to its pre-embargo content is silently not recorded"]
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

/// The merge snapshot is public (its parents' ids, author and time are
/// documented as visible), but its `conflicts` list names files of the
/// fix in plaintext.
#[test]
#[ignore = "BUG-048: an embargoed merge's conflict list names the fix's files in plaintext"]
fn an_embargoed_merge_does_not_name_the_fix_files_in_its_conflict_list() {
    let (mut alice, fs, _) = new_repo("alice");
    let main0 = commit_files(&mut alice, &*fs, &[("src/session_token_validation.rs", "a\nb\nc\n")], "v1");
    let ws = alice.ephemeral_workspace(main0).unwrap();
    ws.write("src/session_token_validation.rs", "a\nFIXED\nc\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    // Main moved on and touched the same line: the merge conflicts.
    let main = commit_files(&mut alice, &*fs, &[("src/session_token_validation.rs", "a\nmain\nc\n")], "v2");
    alice.set_tag("main", main, None, false).unwrap();
    let r = alice.merge(WS, main, vec![fix], "fix", embargo("team")).unwrap();
    assert!(!r.conflicts.is_empty());
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let hits = backend_contains(&*mirror, b"session_token_validation");
    let anon = reader(mirror, None);
    let s = anon.snapshot(&r.snapshot).unwrap();
    assert!(
        s.conflicts.is_empty(),
        "public merge snapshot lists {:?} (raw hits {hits:?})",
        s.conflicts
    );
}

/// Follow-up commits a key holder makes on top of an embargoed merge stay
/// hidden "because everything below the embargoed root is sealed"; their
/// descriptions do not.
#[test]
#[ignore = "BUG-053: commit messages on an embargoed line are public before release"]
fn follow_up_commit_messages_on_an_embargoed_line_are_not_public() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
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
}

// ---- embargo scope vs. the cloak of the fix line --------------------------------------

/// The README flow with an embargo scope narrower than the fix line's cloak
/// (`--cloak team`, `--embargo --scope sec`). Before release the team remote
/// receives the cloaked fix history, which every `team` member can read,
/// although only `sec` members are supposed to see the fix.
#[test]
#[ignore = "BUG-043: a fix cloaked under a wider scope than the embargo reaches every member of that scope"]
fn the_fix_history_is_not_readable_outside_the_embargo_scope() {
    let alice_id = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let (mut alice, fs) = repo_for("alice", &alice_id);
    alice.keys().create_scope("sec").unwrap();
    alice.keys().grant("team", &bob.public_id(), "bob").unwrap();
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    alice.create_workspace("fix", vec![main], Some("team".into())).unwrap();
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
    alice.set_tag("main", main, None, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2 SECRETFIX\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    alice.merge(WS, main, vec![fix], "m", embargo("team")).unwrap();
    // Describe the fix after the fact: rewrites it, auto-rebases the merge.
    alice.describe(fix, "fix: details of the bug").unwrap();
    let _ = base;
    let mirror = Arc::new(MemoryBackend::new());
    let r = remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(r.tags_updated.iter().any(|(t, _)| t == "main"), "{r:?}");
    let anon = reader(mirror.clone(), None);
    assert!(readable_containing(&anon, b"SECRETFIX").is_empty());
    assert!(backend_contains(&*mirror, b"details of the bug").is_empty());
}

/// `vl squash` of the follow-up into the embargoed merge keeps the wrapper.
#[test]
fn squashing_into_the_embargoed_merge_keeps_it_sealed() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
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
    alice.set_tag("main", main, None, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2 SECRETFIX\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let r = alice.merge(WS, main, vec![fix], "m", embargo("team")).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("other", "o2\n").unwrap();
    let (newer, _) = alice.commit_ephemeral(&ws, "newer main").unwrap();
    let m2 = alice.rebase(r.snapshot, vec![newer]).unwrap();
    alice.set_tag("main", m2, None, true).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let anon = reader(mirror, None);
    assert!(readable_containing(&anon, b"SECRETFIX").is_empty());
}
