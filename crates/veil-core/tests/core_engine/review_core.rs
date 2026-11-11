//! Reproductions from the whole-codebase review of the engine (`rv-core`,
//! 2026-11-10): each test shows one guarantee failing, and is ignored under
//! its `docs/BUGS.md` row until the bug is fixed.

use veil_core::{policy::Policy, policy::Tier, ObjectId, Repo, StorageBackend};

use crate::adversarial_support::*;

const WS: &str = "default";

/// A change with one file of its own on `base`, made without a working copy.
fn change_on(repo: &mut Repo, base: ObjectId, file: &str) -> ObjectId {
    let ws = repo.ephemeral_workspace(base).unwrap();
    ws.write(file, format!("{file}\n")).unwrap();
    repo.commit_ephemeral(&ws, file).unwrap().0
}

/// No change is lost: moving a change elsewhere leaves the change it stood
/// on in the history, as abandoning it would.
#[test]
#[ignore = "BUG-1830: `vl rebase` of a change's only child drops the change from the view"]
fn bug_1830_a_change_stays_visible_when_its_only_child_is_rebased_away() {
    let (mut repo, _fs, _) = new_repo("alice");
    let root = repo.root_id();
    let a = change_on(&mut repo, root, "a.txt");
    let b = change_on(&mut repo, a, "b.txt");
    let c = change_on(&mut repo, root, "c.txt");
    assert!(repo.held().visible().unwrap().contains(&a), "A is visible before the rebase");

    let moved = repo.rebase(b, vec![c]).unwrap();
    assert_ne!(moved, b, "the rebase rewrote B");
    assert_eq!(repo.snapshot(&moved).unwrap().parents, vec![c], "B stands on C");

    let visible = repo.held().visible().unwrap();
    assert!(visible.contains(&moved) && visible.contains(&c));
    assert!(
        visible.contains(&a),
        "change A (a.txt) left the view: nothing but `vl undo` shows it again, and gc removes it once the operation is pruned"
    );
}

/// The same through a working copy, as `vl commit`, `vl commit`, `vl rebase
/// -s B -d C` records it.
#[test]
#[ignore = "BUG-1830: `vl rebase` of a change's only child drops the change from the view"]
fn bug_1830_a_committed_change_stays_visible_when_the_working_copy_line_moves_off_it() {
    let (mut repo, fs, _) = new_repo("alice");
    let a = commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "A");
    let b = commit_files(&mut repo, &*fs, &[("b.txt", "b\n")], "B");
    let root = repo.root_id();
    let c = change_on(&mut repo, root, "c.txt");

    let moved = repo.rebase(b, vec![c]).unwrap();
    assert_eq!(repo.snapshot(&moved).unwrap().parents, vec![c], "B stands on C");
    let wc = repo.workspace_wc(WS).unwrap();
    assert_eq!(repo.snapshot(&wc).unwrap().parents, vec![moved], "the working copy followed B");

    assert!(repo.held().visible().unwrap().contains(&a), "change A (a.txt) left the view");
}

/// Invalid rules fail safe: a protective rule that can match no path is
/// never accepted in silence.
#[test]
#[ignore = "BUG-1831: a protective `.veilpolicy` rule spelled `./dir/`, or behind a byte order mark, protects nothing and warns of nothing"]
fn bug_1831_a_protective_rule_that_can_match_nothing_fails_safe() {
    for (what, text) in [
        ("a byte order mark before the first rule", "\u{feff}private/ isolate\n"),
        ("a leading `./`", "./private/ isolate\n"),
        ("a leading `./` on a file", "./private/notes.txt isolate\n"),
    ] {
        let policy = Policy::parse(text);
        let class = policy.classify(&p("private/notes.txt"), false);
        assert!(
            class.tier == Tier::Isolated || !policy.warnings.is_empty(),
            "{what}: `private/notes.txt` is {:?} and the policy has no warning",
            class.tier
        );
    }
}

/// The same end to end: what the member's rule keeps on the device is not
/// recorded.
#[test]
#[ignore = "BUG-1831: a protective `.veilpolicy` rule spelled `./dir/`, or behind a byte order mark, protects nothing and warns of nothing"]
fn bug_1831_a_file_under_a_dot_slash_rule_is_not_recorded() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"./private/ isolate\n").unwrap();
    fs.write(&p("private/notes.txt"), b"kept on this device only\n").unwrap();
    fs.write(&p("README.md"), b"hello\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(file_entry(&repo, &out.snapshot, "README.md").is_some(), "the snapshot recorded the working copy");
    assert!(
        file_entry(&repo, &out.snapshot, "private/notes.txt").is_none() || !out.report.policy_warnings.is_empty(),
        "private/notes.txt was recorded as plain text, with no warning"
    );
}
