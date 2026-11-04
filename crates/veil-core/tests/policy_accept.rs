//! The accepted policy of a working copy (BUG-045): a `.veilpolicy` that
//! arrives from someone else never weakens the protection of local files
//! silently, by any route, until the member accepts it.

mod adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    object::Visibility,
    policy::{load_accepted, HeldBack, ACCEPTED_POLICY},
    remote, MemoryBackend, ObjectId, Repo, StorageBackend,
};

const ENV: &[u8] = b"DB_PASSWORD=prod-hunter2-Xk9mQ2vL7pR4\n";

/// Commit `policy` as `.veilpolicy` on `base` from "someone else" (an
/// ephemeral workspace: not this member's working copy).
fn incoming(repo: &mut Repo, base: ObjectId, files: &[(&str, &str)]) -> ObjectId {
    let ws = repo.ephemeral_workspace(base).unwrap();
    for (p, d) in files {
        ws.write(p, d).unwrap();
    }
    repo.commit_ephemeral(&ws, "incoming").unwrap().0
}

/// Move the working copy to a new change on `to` and check it out.
fn move_to(repo: &mut Repo, fs: &dyn StorageBackend, to: ObjectId) -> veil_core::builder::BuildReport {
    let old = repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = repo.new_change(WS, vec![to], "").unwrap();
    let new = repo.snapshot(&wc).unwrap().tree;
    repo.checkout_tree(fs, Some(&old), &new).unwrap();
    repo.snapshot_workspace(WS, fs).unwrap().report
}

fn setup() -> (Repo, Arc<MemoryBackend>, ObjectId) {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(".env"), ENV).unwrap();
    let main = commit_files(&mut repo, &*fs, &[("README", "hi\n")], "v1");
    (repo, fs, main)
}

#[test]
fn an_incoming_weakening_is_held_back_reported_and_applied_only_once_accepted() {
    let (mut repo, fs, main) = setup();
    let pr = incoming(&mut repo, main, &[(".veilpolicy", ".env public!\n")]);
    let report = move_to(&mut repo, &*fs, pr);
    let wc = snap(&mut repo, &*fs);
    assert!(file_entry(&repo, &wc, ".env").is_none());
    let want = HeldBack {
        path: p(".env"),
        accepted: "isolate".into(),
        wanted: "public!".into(),
    };
    assert_eq!(report.policy_held_back, vec![want]);
    assert!(report.isolated.contains(&p(".env")), "still local-only (and backed up)");
    let held = repo.policy_held_back(&*fs).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].path, p(".env"));

    // Deliberate acceptance applies it.
    let accepted = repo.accept_policy(&*fs).unwrap();
    assert_eq!(accepted, held);
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(out.report.policy_held_back.is_empty());
    assert!(file_entry(&repo, &out.snapshot, ".env").is_some(), "accepted public! applies");
}

#[test]
fn the_members_own_edit_of_the_policy_applies_at_once() {
    let (mut repo, fs, _) = setup();
    fs.write(&p(".veilpolicy"), b".env public!\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(out.report.policy_held_back.is_empty());
    assert!(file_entry(&repo, &out.snapshot, ".env").is_some());
    assert_eq!(load_accepted(&*fs).unwrap().unwrap(), b".env public!\n");
}

#[test]
fn an_own_edit_on_top_of_an_unaccepted_policy_does_not_accept_it() {
    let (mut repo, fs, main) = setup();
    let pr = incoming(&mut repo, main, &[(".veilpolicy", ".env public!\n")]);
    move_to(&mut repo, &*fs, pr);
    fs.write(&p(".veilpolicy"), b".env public!\nbuild/ ignore\nnotes/ cloak\n").unwrap();
    let wc = snap(&mut repo, &*fs);
    assert!(file_entry(&repo, &wc, ".env").is_none());
}

#[test]
fn incoming_rules_that_only_isolate_or_ignore_are_accepted_silently() {
    let (mut repo, fs, main) = setup();
    fs.write(&p(".veilpolicy"), b"fixtures/ public!\n").unwrap();
    let main2 = commit_files(&mut repo, &*fs, &[], "own policy");
    let _ = main;
    let pr = incoming(&mut repo, main2, &[(".veilpolicy", "fixtures/ public!\n# from a teammate\ndrafts/ isolate\nbuild/ ignore\n")]);
    let report = move_to(&mut repo, &*fs, pr);
    assert!(report.policy_held_back.is_empty());
    let acc = load_accepted(&*fs).unwrap().unwrap();
    assert!(String::from_utf8_lossy(&acc).contains("drafts/ isolate"), "accepted policy moved forward");
}

#[test]
fn a_tracked_decoy_does_not_carry_the_local_secret_into_history() {
    // The PR adds a harmless `.env` *and* publishes it: the member's own
    // `.env` is kept by checkout, and must not be recorded as an edit of it.
    let (mut repo, fs, main) = setup();
    let pr = incoming(&mut repo, main, &[(".veilpolicy", ".env public!\n"), (".env", "EXAMPLE=1\n")]);
    let report = move_to(&mut repo, &*fs, pr);
    assert_eq!(fs.read(&p(".env")).unwrap(), ENV, "checkout kept the local file");
    let wc = snap(&mut repo, &*fs);
    assert_eq!(read_at(&repo, &wc, ".env"), b"EXAMPLE=1\n", "the tracked decoy stays as it was, no deletion");
    assert!(!report.policy_held_back.is_empty());
}

#[test]
fn an_incoming_policy_cannot_uncloak_or_re_scope_new_local_files() {
    let (mut repo, fs, _) = setup();
    repo.keys().create_scope("ops").unwrap();
    fs.write(&p(".veilpolicy"), b"secrets/ cloak ops\nprivate/ cloak ops\n").unwrap();
    let main = commit_files(&mut repo, &*fs, &[], "policy");
    let pr = incoming(&mut repo, main, &[(".veilpolicy", "private/ cloak team\n")]);
    move_to(&mut repo, &*fs, pr);
    fs.write(&p("secrets/db.yml"), b"host: db\n").unwrap();
    fs.write(&p("private/notes.md"), b"plans\n").unwrap();
    let wc = snap(&mut repo, &*fs);
    for path in ["secrets/db.yml", "private/notes.md"] {
        let e = file_entry(&repo, &wc, path).unwrap();
        assert_eq!(e.visibility, Visibility::Cloaked { scope: "ops".into() }, "{path}");
    }
}

#[test]
fn an_incoming_public_bang_does_not_turn_scanning_off_for_local_files() {
    let (mut repo, fs, main) = setup();
    let pr = incoming(&mut repo, main, &[(".veilpolicy", "tools/ public!\n")]);
    move_to(&mut repo, &*fs, pr);
    fs.write(&p("tools/deploy.sh"), b"export AWS=AKIAIOSFODNN7EXAMPLE\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(file_entry(&repo, &out.snapshot, "tools/deploy.sh").is_none());
    assert_eq!(out.report.quarantined.len(), 1);
}

#[test]
fn checking_out_an_older_line_with_a_weaker_policy_holds_back() {
    // The member deliberately isolates `notes/`; going back to a change from
    // before that rule must not publish the notes.
    let (mut repo, fs, main) = setup();
    fs.write(&p(".veilpolicy"), b"notes/ isolate\n").unwrap();
    commit_files(&mut repo, &*fs, &[("notes/plan.md", "secret plans\n")], "isolate notes");
    move_to(&mut repo, &*fs, main);
    assert_eq!(fs.read(&p("notes/plan.md")).unwrap(), b"secret plans\n");
    let wc = snap(&mut repo, &*fs);
    assert!(file_entry(&repo, &wc, "notes/plan.md").is_none());
}

#[test]
fn undo_back_to_a_weaker_policy_holds_back() {
    let (mut repo, fs, _) = setup();
    let before = repo.op_id();
    fs.write(&p(".veilpolicy"), b"notes/ isolate\n").unwrap();
    fs.write(&p("notes/plan.md"), b"secret plans\n").unwrap();
    snap(&mut repo, &*fs);
    let old = repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree;
    repo.restore_operation(before).unwrap();
    let new = repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree;
    repo.checkout_tree(&*fs, Some(&old), &new).unwrap();
    assert!(!fs.exists(&p(".veilpolicy")).unwrap());
    let wc = snap(&mut repo, &*fs);
    assert!(file_entry(&repo, &wc, "notes/plan.md").is_none());
}

#[test]
fn a_pull_into_a_fresh_member_records_nothing_until_accepted() {
    let (mut mallory, mfs, _) = new_repo("mallory");
    commit_files(&mut mallory, &*mfs, &[("README", "hi\n")], "v1");
    let main = commit_files(&mut mallory, &*mfs, &[(".veilpolicy", "keys/ public!\n")], "policy");
    mallory.set_tag("main", main, None, false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut mallory, team.clone(), false, &[], false).unwrap();

    let (mut bob, bfs, _) = new_repo("bob");
    bfs.write(&p("keys/deploy.pem"), b"-----BEGIN PRIVATE KEY-----\nMIIE\n").unwrap();
    snap(&mut bob, &*bfs);
    pull_and_checkout(&mut bob, &*bfs, team).unwrap();
    let wc = snap(&mut bob, &*bfs);
    assert!(file_entry(&bob, &wc, "keys/deploy.pem").is_none());
}

#[test]
fn other_backends_keep_their_own_policy_and_never_move_the_accepted_one() {
    let (mut repo, fs, main) = setup();
    let acc = load_accepted(&*fs).unwrap();
    // An agent edits the policy in an overlay of another workspace.
    repo.create_workspace("agent", vec![main], None).unwrap();
    let overlay = repo.workspace_overlay("agent").unwrap();
    overlay.write(&p(".veilpolicy"), b".env public!\n").unwrap();
    overlay.write(&p(".env"), b"FIXTURE=1\n").unwrap();
    let out = repo.snapshot_workspace("agent", &overlay).unwrap();
    assert!(file_entry(&repo, &out.snapshot, ".env").is_some(), "the overlay's own policy applies there");
    assert_eq!(load_accepted(&*fs).unwrap(), acc);
    assert!(fs.exists(&p(ACCEPTED_POLICY)).unwrap());
}

#[test]
fn an_own_edit_on_top_of_an_unaccepted_policy_applies_only_that_edit_and_sticks() {
    let (mut repo, fs, main) = setup();
    fs.write(&p(".envrc"), b"export TOKEN=dev-only-fixture\n").unwrap();
    let pr = incoming(&mut repo, main, &[(".veilpolicy", ".env public!\n")]);
    move_to(&mut repo, &*fs, pr);
    fs.write(&p(".veilpolicy"), b".env public!\n.envrc public!\n").unwrap();
    for _ in 0..2 {
        let wc = snap(&mut repo, &*fs);
        assert!(file_entry(&repo, &wc, ".envrc").is_some(), "the member's own exposure applies");
        assert!(file_entry(&repo, &wc, ".env").is_none(), "the incoming one does not");
    }
}

#[test]
fn an_incoming_removal_of_an_accepted_public_bang_is_accepted_so_it_cannot_return_silently() {
    let (mut repo, fs, _) = setup();
    fs.write(&p(".veilpolicy"), b".env public!\n").unwrap();
    let exposed = commit_files(&mut repo, &*fs, &[], "expose .env");
    // A teammate reverts the exposure; then someone re-adds it.
    let revert = incoming(&mut repo, exposed, &[(".veilpolicy", "")]);
    move_to(&mut repo, &*fs, revert);
    assert_eq!(load_accepted(&*fs).unwrap().unwrap(), b"");
    let readd = incoming(&mut repo, revert, &[(".veilpolicy", ".env public!\n")]);
    move_to(&mut repo, &*fs, readd);
    let wc = snap(&mut repo, &*fs);
    assert!(file_entry(&repo, &wc, ".env").is_none());
}

#[test]
fn an_incoming_policy_cannot_record_the_members_vcs_metadata() {
    // BUG-076: VCS metadata is ignored by the engine; only a `public!` rule
    // naming the directory records it, and one that arrives from someone
    // else is held back like any weakening.
    let (mut repo, fs, main) = setup();
    fs.write(&p(".git/config"), b"[remote \"origin\"]\n  url = https://token@example.com/x\n").unwrap();
    fs.write(&p("sub/.git"), b"gitdir: ../.git/modules/sub\n").unwrap();
    let wc = snap(&mut repo, &*fs);
    assert!(file_entry(&repo, &wc, ".git/config").is_none());
    assert!(file_entry(&repo, &wc, "sub/.git").is_none());
    let pr = incoming(&mut repo, main, &[(".veilpolicy", ".git public!\n**/.git public!\n")]);
    move_to(&mut repo, &*fs, pr);
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(file_entry(&repo, &out.snapshot, ".git/config").is_none());
    assert!(file_entry(&repo, &out.snapshot, "sub/.git").is_none());
    let held: Vec<&str> = out.report.policy_held_back.iter().map(|h| h.path.as_str()).collect();
    assert!(held.contains(&".git/config") || held.contains(&"sub/.git"), "{held:?}");
}

#[test]
fn checking_out_a_snapshot_that_recorded_git_metadata_leaves_the_git_directory_alone() {
    // Snapshots made before VCS metadata was ignored (BUG-076) may hold
    // `.git/…`: checking them out neither writes into nor removes from the
    // working copy's own `.git/`, and the next snapshot drops it.
    let (mut repo, fs, _) = setup();
    fs.write(&p(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    let head = blob(&repo, b"ref: refs/heads/stale\n");
    let lock = blob(&repo, b"");
    let git = raw_tree(&repo, vec![file("HEAD", head), file("index.lock", lock)]);
    let readme = blob(&repo, b"old\n");
    let tree = raw_tree(&repo, vec![dir(".git", git), file("README", readme)]);
    let old = raw_snapshot(&repo, vec![], tree, "made by an older vl");
    move_to(&mut repo, &*fs, old);
    assert_eq!(fs.read(&p("README")).unwrap(), b"old\n");
    assert_eq!(fs.read(&p(".git/HEAD")).unwrap(), b"ref: refs/heads/main\n");
    assert!(!fs.exists(&p(".git/index.lock")).unwrap(), "nothing written into .git");
    let wc = snap(&mut repo, &*fs);
    assert!(file_entry(&repo, &wc, ".git/HEAD").is_none(), "no longer recorded");
}
