//! Reproductions from the whole-codebase review of the engine (`rv-core`,
//! 2026-11-10): each test shows one guarantee failing, and is ignored under
//! its `docs/BUGS.md` row until the bug is fixed.

use veil_core::{object::Visibility, policy::Policy, policy::Tier, ObjectId, Repo, StorageBackend};

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

    // When A still has another descendant D, A stays visible through D without
    // lingering as a redundant head beside D.
    let d1 = change_on(&mut repo, a, "d1.txt");
    let d2 = change_on(&mut repo, a, "d2.txt");
    let d1_moved = repo.rebase(d1, vec![c]).unwrap();
    assert!(repo.held().visible().unwrap().contains(&a));
    assert!(!repo.view().heads.contains(&a), "A has child d2, so A is not a maximal head");
    assert!(repo.view().heads.contains(&d2) && repo.view().heads.contains(&d1_moved));
}

/// The same through a working copy, as `vl commit`, `vl commit`, `vl rebase
/// -s B -d C` (and `vl rebase -s @ -d C`) records it.
#[test]
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

    // Moving `@` itself off `moved` (`vl rebase -d A`) leaves `moved` visible too.
    let wc_moved = repo.rebase(wc, vec![a]).unwrap();
    assert_eq!(repo.workspace_wc(WS).unwrap(), wc_moved);
    assert!(repo.held().visible().unwrap().contains(&moved), "committed change B left the view when @ moved off it");

    // Abandoning `moved` still removes `moved` itself while keeping its parent C visible.
    repo.abandon(moved).unwrap();
    let vis = repo.held().visible().unwrap();
    assert!(!vis.contains(&moved), "abandoned change B left the view");
    assert!(vis.contains(&c), "its parent C stayed visible");
}

/// Invalid rules fail safe: a protective rule that can match no path is
/// never accepted in silence, while a leading BOM and `./` normalise cleanly.
#[test]
fn bug_1831_a_protective_rule_that_can_match_nothing_fails_safe() {
    for (what, text) in [
        ("a byte order mark before the first rule", "\u{feff}private/ isolate\n"),
        ("a leading `./`", "./private/ isolate\n"),
        ("a leading `./` on a file", "./private/notes.txt isolate\n"),
    ] {
        let policy = Policy::parse(text);
        let class = policy.classify(&p("private/notes.txt"), false);
        assert_eq!(class.tier, Tier::Isolated, "{what}: `private/notes.txt` was not isolated");
        assert!(policy.warnings.is_empty(), "{what}: unexpected warning {:?}", policy.warnings);
    }
    // `./` means the project root, not every directory of that name.
    let anchored = Policy::parse("./private/ isolate\n");
    assert_eq!(anchored.classify(&p("sub/private/notes.txt"), false).tier, Tier::Public);

    for (what, text) in [
        ("zero-width space before pattern", "\u{200b}private/ isolate\n"),
        ("byte order mark on a later line", "README.md public\n\u{feff}private/ isolate\n"),
        ("double-quoted pattern", "\"private/\" isolate\n"),
        ("single-quoted pattern", "'private/' isolate\n"),
        ("trailing dot component", "private/. isolate\n"),
        ("interior dot component", "private/./notes.txt isolate\n"),
        ("parent-dir component", "../private/ isolate\n"),
        ("empty slash component", "private//notes.txt isolate\n"),
        ("bare dot-slash", "./ isolate\n"),
    ] {
        let policy = Policy::parse(text);
        let class = policy.classify(&p("private/notes.txt"), false);
        assert_eq!(class.tier, Tier::Isolated, "{what}: did not isolate `private/notes.txt`");
        assert!(!policy.warnings.is_empty(), "{what}: accepted in silence with no warning");
    }
}

/// The same end to end: what the member's rule keeps on the device is not
/// recorded.
#[test]
fn bug_1831_a_file_under_a_dot_slash_rule_is_not_recorded() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"./private/ isolate\n").unwrap();
    fs.write(&p("private/notes.txt"), b"kept on this device only\n").unwrap();
    fs.write(&p("README.md"), b"hello\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(file_entry(&repo, &out.snapshot, "README.md").is_some(), "the snapshot recorded the working copy");
    assert!(
        file_entry(&repo, &out.snapshot, "private/notes.txt").is_none(),
        "private/notes.txt was recorded despite `./private/ isolate`"
    );
}

/// Secrets are only ever stored encrypted: a secret that moves to a path no
/// rule names stays sealed, and its plain text is never written to the
/// object store on the way.
#[test]
fn bug_1832_a_moved_secret_is_never_stored_as_plain_text() {
    // Not token-shaped: the scanner has nothing to say about it (a moved
    // file it flags is quarantined, never recorded).
    const SECRET: &str = "REGION=review-marker-of-a-moved-secret-0001\nTIER=review-marker-of-a-moved-secret-0002\n";
    const LINK_TARGET: &[u8] = b"internal/review-marker-of-a-moved-link-0003";
    let (mut repo, fs, _) = new_repo("alice");
    fs.write_link(&p(".env.link"), LINK_TARGET).unwrap();
    commit_files(&mut repo, &*fs, &[(".veilpolicy", ".env* cloak team\n"), (".env", SECRET)], "base");
    let hits = |fs: &veil_core::MemoryBackend| -> Vec<String> {
        let mut h: Vec<String> = backend_contains(fs, b"review-marker-of-a-moved-secret-0001")
            .into_iter()
            .chain(backend_contains(fs, b"review-marker-of-a-moved-link-0003"))
            .filter(|f| f.starts_with(".veil/"))
            .collect();
        h.sort();
        h
    };
    assert_eq!(hits(&fs), Vec::<String>::new(), "the committed secret is stored sealed only");

    // `mv .env conf/settings.txt` and `mv .env.link conf/settings.link`.
    fs.remove_file(&p(".env")).unwrap();
    fs.write(&p("conf/settings.txt"), SECRET.as_bytes()).unwrap();
    fs.remove_file(&p(".env.link")).unwrap();
    fs.write_link(&p("conf/settings.link"), LINK_TARGET).unwrap();
    let wc = snap(&mut repo, &*fs);
    let e = file_entry(&repo, &wc, "conf/settings.txt").expect("the moved file is recorded");
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() }, "protection followed the content");
    assert_eq!(repo.store().read_entry(&e).unwrap(), SECRET.as_bytes());
    let le = veil_core::tree::lookup(repo.store(), &repo.snapshot(&wc).unwrap().tree, &p("conf/settings.link")).unwrap().expect("moved link");
    assert_eq!(le.visibility, Visibility::Cloaked { scope: "team".into() }, "protection followed the link target");

    assert_eq!(hits(&fs), Vec::<String>::new(), "the secret's plain text is in the object store");
}

/// `vl upgrade` converts what format 8 itself writes: an editor's or a
/// patch tool's backup of a secret (`.envrc.orig` beside `.envrc`) takes
/// its secret's protection, so `vl` seals it, in format 7 as now.
#[test]
fn bug_1834_a_sealed_backup_of_a_secret_does_not_block_the_upgrade() {
    use veil_core::upgrade::{upgrade, UpgradeOptions};
    let (mut repo, fs, alice) = new_repo("alice");
    let c = commit_files(
        &mut repo,
        &*fs,
        &[
            (".veilpolicy", ".envrc cloak team\n.npmrc cloak team\n*.pem cloak team\n*~\tpublic!\n"),
            (".envrc", "export REGION=review-marker-backup-new\n"),
            (".envrc.orig", "export REGION=review-marker-backup-old\n"),
            (".npmrc.bak", "registry=https://example.invalid/\n"),
            ("db.pem.old", "CERT-PLACEHOLDER\n"),
            (".envrc.bak~", "export REGION=review-marker-backup-twice\n"),
        ],
        "first",
    );
    let team = Visibility::Cloaked { scope: "team".into() };
    for path in [".envrc", ".envrc.orig", ".npmrc.bak", "db.pem.old", ".envrc.bak~"] {
        assert_eq!(file_entry(&repo, &c, path).unwrap().visibility, team, "control: vl seals {path}");
    }
    assert!(!veil_core::policy::seals_secret("notes.txt.orig"));
    assert!(!veil_core::policy::seals_secret(".veilpolicy.orig"));
    drop(repo);
    // The same objects in a repository marked format 7 (as
    // `format_compat::a_renamed_secret_does_not_block_the_upgrade` does).
    let mut cfg = veil_core::repo::read_config(&*fs).unwrap();
    cfg.format = 7;
    cfg.min_vl = Some(veil_core::repo::min_vl_for_format(7).into());
    fs.write(&p(".veil/repo.json"), &serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

    let r = upgrade(fs.clone(), Some(alice.clone()), &UpgradeOptions::default());
    assert!(r.is_ok(), "a repository holding only what format 8 writes was refused: {}", r.unwrap_err());
    let repo = Repo::open(fs.clone(), Some(alice), "alice").unwrap();
    assert_eq!(repo.store().read_entry(&file_entry(&repo, &c, ".envrc.orig").unwrap()).unwrap(), b"export REGION=review-marker-backup-old\n");
}

/// Corrupt data is refused, never returned: an operation is named by the
/// BLAKE3 of its bytes, like an object, and a file that no longer matches
/// its name is not read as the repository's state.
#[test]
fn bug_1835_an_operation_that_does_not_match_its_id_is_refused() {
    let (mut repo, fs, alice) = new_repo("alice");
    let a = commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "A");
    let b = commit_files(&mut repo, &*fs, &[("b.txt", "b\n")], "B");
    repo.set_tag("v1", a, false).unwrap();
    assert_eq!(repo.view().tags["v1"].target, a);
    let op = repo.op_id();
    drop(repo);
    // Damage on disk: the newest operation now says `v1` is at B.
    let path = p(&format!(".veil/ops/{}", op.hex()));
    let raw = String::from_utf8(fs.read(&path).unwrap()).unwrap();
    let was = format!("\"v1\":{{\"target\":\"{}\"", a.hex());
    assert!(raw.contains(&was), "the operation records the tag");
    let damaged = raw.replace(&was, &format!("\"v1\":{{\"target\":\"{}\"", b.hex()));
    assert_ne!(ObjectId::hash(damaged.as_bytes()), op, "the file no longer matches its id");
    fs.write(&path, damaged.as_bytes()).unwrap();

    match Repo::open(fs.clone(), Some(alice), "alice") {
        Err(e) => assert!(matches!(e, veil_core::VeilError::Corrupt(..)), "refused, but not as corrupt: {e}"),
        Ok(repo) => panic!(
            "the damaged operation was read as the repository's state: tag v1 is at {} (it was set to {})",
            repo.view().tags["v1"].target.short(),
            a.short()
        ),
    }
}

/// P (with `notes.txt`) and X on it; with `attempt`, X records its content
/// as an attempt and starts again; then P is amended to drop `notes.txt`
/// (`vl edit P`, `rm notes.txt`) and `main` is pushed to a new remote. Where
/// the remote holds the text of `notes.txt`.
fn amended_away_then_pushed(attempt: bool) -> Vec<String> {
    const MARKER: &[u8] = b"review-marker-amended-away-0001";
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("README.md", "hi\n")], "base");
    let parent = commit_files(&mut repo, &*fs, &[("notes.txt", "review-marker-amended-away-0001\n"), ("lib.rs", "fn a() {}\n")], "P");
    let x = commit_files(&mut repo, &*fs, &[("x.txt", "first try\n")], "X");
    let change = repo.snapshot(&x).unwrap().change_id;
    if attempt {
        let dropped = repo.drop_attempt(x, "did not work").unwrap();
        assert_eq!(repo.snapshot(&dropped.change).unwrap().attempts, vec![dropped.attempt], "X keeps its attempt");
    }

    let old = repo.snapshot(&parent).unwrap();
    let ws = repo.ephemeral_workspace(parent).unwrap();
    ws.remove("notes.txt").unwrap();
    let mut tx = repo.transaction("amend P").unwrap();
    let (tree, _) = tx.repo().build_from(&**ws.fs(), Some(old.tree)).unwrap();
    let mut amended = (*old).clone();
    amended.tree = tree;
    amended.predecessors = vec![parent];
    let amended = tx.rewrite(parent, amended).unwrap();
    tx.commit().unwrap();
    assert_ne!(amended, parent, "P was rewritten");
    assert_eq!(repo.snapshot(&amended).unwrap().parents, vec![base]);
    let x_now = repo.workspace_wc(WS).map(|wc| repo.snapshot(&wc).unwrap().parents[0]).unwrap();
    let xs = repo.snapshot(&x_now).unwrap();
    assert_eq!((xs.change_id, xs.parents.clone()), (change, vec![amended]), "X followed the amended P");
    assert_eq!(xs.attempts.len(), usize::from(attempt), "X still keeps its attempt");
    for rev in [&amended, &x_now] {
        assert!(file_entry(&repo, rev, "notes.txt").is_none(), "notes.txt is in no visible change");
    }

    repo.set_tag("main", x_now, false).unwrap();
    let remote: std::sync::Arc<veil_core::MemoryBackend> = std::sync::Arc::new(veil_core::MemoryBackend::new());
    Repo::init_bare(remote.clone()).unwrap();
    veil_core::remote::push(&mut repo, remote.clone(), false, &[], false).unwrap();
    let remote_repo = Repo::open_remote(remote.clone()).unwrap();
    assert_eq!(remote_repo.view().tags["main"].target, x_now, "the push moved main");
    if attempt {
        let att_id = remote_repo.snapshot(&x_now).unwrap().attempts[0];
        let att_entry = file_entry(&remote_repo, &att_id, "x.txt").expect("the attempt still holds what it recorded on purpose");
        assert_eq!(remote_repo.store().read_entry(&att_entry).unwrap(), b"first try\n");
        assert!(file_entry(&remote_repo, &att_id, "notes.txt").is_none(), "amended-away ancestor file left the attempt");
    }
    backend_contains(&*remote, MARKER)
}

/// Rewritten snapshots stop being reachable, so what a change's author
/// amends away before a push never leaves the device: also when a change
/// built on it keeps a recorded attempt (`vl attempt drop`) made on the
/// earlier version, or when the change itself is rebased off an unpushed
/// parent.
#[test]
fn bug_1836_content_amended_away_under_a_recorded_attempt_is_not_pushed() {
    assert_eq!(amended_away_then_pushed(false), Vec::<String>::new(), "control: without an attempt the amended-away text is not pushed");
    assert_eq!(
        amended_away_then_pushed(true),
        Vec::<String>::new(),
        "the remote received the text its author amended out of P before pushing"
    );

    // Direct rebase of X off an unpushed parent P onto `base`: P's text is not pushed,
    // while X's attempt keeps its own `x.txt`.
    const DIRECT_MARKER: &[u8] = b"review-marker-rebased-off-parent-0002";
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("README.md", "hi\n")], "base");
    commit_files(&mut repo, &*fs, &[("sub/draft.txt", "review-marker-rebased-off-parent-0002\n")], "draft P");
    let x = commit_files(&mut repo, &*fs, &[("sub/x.txt", "attempt content\n")], "X");
    let dropped = repo.drop_attempt(x, "retry").unwrap();
    let rebased = repo.rebase(dropped.change, vec![base]).unwrap();
    repo.set_tag("main", rebased, false).unwrap();
    let remote: std::sync::Arc<veil_core::MemoryBackend> = std::sync::Arc::new(veil_core::MemoryBackend::new());
    Repo::init_bare(remote.clone()).unwrap();
    veil_core::remote::push(&mut repo, remote.clone(), false, &[], false).unwrap();
    let remote_repo = Repo::open_remote(remote.clone()).unwrap();
    assert_eq!(remote_repo.view().tags["main"].target, rebased);
    let att_id = remote_repo.snapshot(&rebased).unwrap().attempts[0];
    assert_eq!(remote_repo.store().read_entry(&file_entry(&remote_repo, &att_id, "sub/x.txt").unwrap()).unwrap(), b"attempt content\n");
    assert!(file_entry(&remote_repo, &att_id, "sub/draft.txt").is_none());
    assert_eq!(backend_contains(&*remote, DIRECT_MARKER), Vec::<String>::new());
}

/// What a clone of `repo`'s tagged history holds that only the removed
/// encryption wrote, by the one rule of `vl upgrade` and of the server's
/// push check (`policy::sealed_secret`).
fn named_by_the_only_secrets_rule(repo: &mut Repo) -> Vec<String> {
    let remote: std::sync::Arc<veil_core::MemoryBackend> = std::sync::Arc::new(veil_core::MemoryBackend::new());
    Repo::init_bare(remote.clone()).unwrap();
    veil_core::remote::push(repo, remote.clone(), false, &[], false).unwrap();
    veil_core::upgrade::removed_content(&(remote as std::sync::Arc<dyn StorageBackend>)).unwrap()
}

/// Only secret files are encrypted, and `vl` writes nothing its own rule
/// for that refuses: a secret made and renamed within one change (the
/// working copy recorded in between, as any command does).
#[test]
fn bug_1833_a_secret_made_and_renamed_within_one_change_is_what_the_rule_accepts() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[(".veilpolicy", ".env cloak team\n"), ("README.md", "hi\n")], "base");
    fs.write(&p(".env"), b"REGION=review-marker-made-and-renamed-0001\n").unwrap();
    let recorded = snap(&mut repo, &*fs);
    assert_eq!(file_entry(&repo, &recorded, ".env").unwrap().visibility, Visibility::Cloaked { scope: "team".into() });
    let data = fs.read(&p(".env")).unwrap();
    fs.remove_file(&p(".env")).unwrap();
    fs.write(&p("settings.txt"), &data).unwrap();
    snap(&mut repo, &*fs);
    let (c, _) = repo.commit_working_copy(WS, "settings").unwrap();
    assert_eq!(repo.snapshot(&c).unwrap().parents, vec![base]);
    assert_eq!(file_entry(&repo, &c, "settings.txt").unwrap().visibility, Visibility::Public, "decided from its final path");
    repo.set_tag("main", c, false).unwrap();

    assert_eq!(named_by_the_only_secrets_rule(&mut repo), Vec::<String>::new(), "vl recorded what its own rule calls encrypted non-secret content");
}

/// The same when the rename is its own change, folded into the change
/// that added the secret (`vl squash`), or rebased directly onto `base`,
/// and secret-looking content arriving at an ordinary path is still scanned.
#[test]
fn bug_1833_a_rename_squashed_into_the_change_that_added_the_secret_is_what_the_rule_accepts() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[(".veilpolicy", ".env cloak team\n"), ("README.md", "hi\n")], "base");
    commit_files(&mut repo, &*fs, &[(".env", "REGION=review-marker-made-and-renamed-0002\n")], "add the secret");
    let data = fs.read(&p(".env")).unwrap();
    fs.remove_file(&p(".env")).unwrap();
    fs.write(&p("settings.txt"), &data).unwrap();
    snap(&mut repo, &*fs);
    let (rename, _) = repo.commit_working_copy(WS, "rename it").unwrap();
    // Control: the rename alone is what the rule accepts (BUG-940, BUG-1055).
    repo.set_tag("main", rename, false).unwrap();
    assert_eq!(named_by_the_only_secrets_rule(&mut repo), Vec::<String>::new(), "control: a renamed secret is accepted");

    // Rebasing an edit of the renamed file onto `base` (past the changes that
    // added and renamed `.env`) also reconciles sealing from the final path.
    let saved_op = repo.op_id();
    let edited = commit_files(&mut repo, &*fs, &[("settings.txt", "REGION=updated-0002\n")], "edit settings");
    let rebased = repo.rebase(edited, vec![base]).unwrap();
    assert_eq!(repo.snapshot(&rebased).unwrap().parents, vec![base]);
    repo.set_tag("main", rebased, true).unwrap();
    assert_eq!(named_by_the_only_secrets_rule(&mut repo), Vec::<String>::new(), "rebased onto base: conflict sides reconciled to public");
    repo.restore_operation(saved_op).unwrap();

    let squashed = repo.squash(rename).unwrap();
    assert_eq!(repo.snapshot(&squashed).unwrap().parents, vec![base], "the two changes are one, on the base");
    assert_eq!(file_entry(&repo, &squashed, "settings.txt").unwrap().visibility, Visibility::Public, "decided from its final path");
    repo.set_tag("main", squashed, true).unwrap();

    assert_eq!(named_by_the_only_secrets_rule(&mut repo), Vec::<String>::new(), "vl recorded what its own rule calls encrypted non-secret content");

    // Secret-looking content arriving at an ordinary path goes through the scanner.
    let (mut repo2, fs2, _) = new_repo("alice");
    commit_files(&mut repo2, &*fs2, &[(".veilpolicy", ".env cloak team\n"), ("README.md", "hi\n")], "base");
    commit_files(&mut repo2, &*fs2, &[(".env", "REGION=initial\n")], "add secret");
    fs2.remove_file(&p(".env")).unwrap();
    fs2.write(&p("settings.txt"), b"REGION=initial\n").unwrap();
    snap(&mut repo2, &*fs2);
    let (ren2, _) = repo2.commit_working_copy(WS, "rename").unwrap();
    assert_eq!(file_entry(&repo2, &ren2, "settings.txt").unwrap().visibility, Visibility::Cloaked { scope: "team".into() });
    let tok = "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\n";
    let with_tok = commit_files(&mut repo2, &*fs2, &[("settings.txt", tok)], "put token in sealed settings");
    let ren2 = repo2.squash(with_tok).unwrap();
    let err = repo2.squash(ren2).unwrap_err();
    assert!(matches!(err, veil_core::VeilError::Policy(_)), "scanner must refuse secret token at ordinary path: {err:?}");
}

type AttemptSummary = (String, Option<veil_core::object::Attribution>, Vec<(String, Vec<u8>)>);

fn attempt_summary(repo: &Repo, att_id: &ObjectId) -> AttemptSummary {
    let at = repo.snapshot(att_id).unwrap();
    let base = repo.parents_tree(&at.parents).unwrap().tree;
    let diffs = veil_core::tree::diff_trees(repo.store(), Some(&base), Some(&at.tree)).unwrap();
    let files = diffs
        .into_iter()
        .map(|c| {
            let bytes = c
                .new
                .as_ref()
                .map(|e| repo.store().read_blob(&e.id).unwrap())
                .unwrap_or_default();
            (c.path.to_string(), bytes)
        })
        .collect();
    (at.abandoned.clone().unwrap_or_default(), at.agent.clone(), files)
}

fn agent_attr(name: &str, task: &str) -> veil_core::object::Attribution {
    veil_core::object::Attribution {
        agent: name.to_string(),
        task: Some(task.to_string()),
        prompt: None,
        run: None,
    }
}

/// BUG-1837: squashing an emptied change (whole, `--into DEST`, by paths or by
/// hunks) carries its recorded attempts onto the destination after the
/// destination's own, keeping each attempt's reason, attribution and changed
/// files, and `undo` restores both changes' attempts exactly.
#[test]
fn bug_1837_squash_carries_attempts_after_destinations_and_undo_restores_them() {
    use veil_core::selection::{Pick, Selection};

    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("hunk.txt", "a\n1\n2\n3\n4\nz\n")], "base");

    // Destination change `dest`, with one recorded attempt of its own.
    repo.new_change(WS, vec![base], "dest").unwrap();
    repo.set_attribution(Some(agent_attr("claude-code/1", "dest-task")));
    fs.write(&p("dest_try.txt"), b"dest dead end\n").unwrap();
    let tried_d = snap(&mut repo, &*fs);
    let d_drop = repo.drop_attempt(tried_d, "dest approach deadlocked").unwrap();
    fs.remove_file(&p("dest_try.txt")).unwrap();
    fs.write(&p("dest.txt"), b"dest ok\n").unwrap();
    let dest = snap(&mut repo, &*fs);
    repo.set_attribution(None);
    let orig_dest_attempts = repo.snapshot(&dest).unwrap().attempts.clone();
    assert_eq!(orig_dest_attempts, vec![d_drop.attempt]);

    // Source change `src` on `dest`, with two recorded attempts by distinct agents,
    // and two hunks in `hunk.txt` so whole, path and hunk squashes can all empty it.
    repo.new_change(WS, vec![dest], "src").unwrap();
    repo.set_attribution(Some(agent_attr("codex/2", "src-task-1")));
    fs.write(&p("src_try1.txt"), b"first dead end\n").unwrap();
    let tried_s1 = snap(&mut repo, &*fs);
    let s_drop1 = repo.drop_attempt(tried_s1, "first try overflowed").unwrap();
    fs.remove_file(&p("src_try1.txt")).unwrap();

    repo.set_attribution(Some(agent_attr("gemini/3", "src-task-2")));
    fs.write(&p("src_try2.txt"), b"second dead end\n").unwrap();
    let tried_s2 = snap(&mut repo, &*fs);
    let s_drop2 = repo.drop_attempt(tried_s2, "second try timed out").unwrap();
    fs.remove_file(&p("src_try2.txt")).unwrap();

    repo.set_attribution(Some(agent_attr("merger-bot", "squash-run")));
    fs.write(&p("hunk.txt"), b"A\n1\n2\n3\n4\nZ\n").unwrap();
    let src = snap(&mut repo, &*fs);
    let orig_src_attempts = repo.snapshot(&src).unwrap().attempts.clone();
    assert_eq!(orig_src_attempts, vec![s_drop1.attempt, s_drop2.attempt]);

    let expected = vec![
        (
            "dest approach deadlocked".to_string(),
            Some(agent_attr("claude-code/1", "dest-task")),
            vec![("dest_try.txt".to_string(), b"dest dead end\n".to_vec())],
        ),
        (
            "first try overflowed".to_string(),
            Some(agent_attr("codex/2", "src-task-1")),
            vec![("src_try1.txt".to_string(), b"first dead end\n".to_vec())],
        ),
        (
            "second try timed out".to_string(),
            Some(agent_attr("gemini/3", "src-task-2")),
            vec![("src_try2.txt".to_string(), b"second dead end\n".to_vec())],
        ),
    ];

    let check_dest_and_undo = |repo: &mut Repo, new_dest: ObjectId, label: &str| {
        let ds = repo.snapshot(&new_dest).unwrap();
        assert_eq!(ds.attempts.len(), 3, "{label}: destination must list dest's + src's attempts");
        assert_eq!(ds.attempts[0], d_drop.attempt, "{label}: dest's own attempt stays first");
        for a in &ds.attempts {
            let at = repo.snapshot(a).unwrap();
            assert_eq!(at.change_id, ds.change_id, "{label}: attempt change_id matches destination");
            assert_eq!(at.parents, ds.parents, "{label}: attempt stands on destination's parents");
        }
        let got: Vec<_> = ds.attempts.iter().map(|a| attempt_summary(repo, a)).collect();
        assert_eq!(got, expected, "{label}: reason, attribution and changed files preserved");

        repo.undo().unwrap();
        assert_eq!(repo.snapshot(&dest).unwrap().attempts, orig_dest_attempts, "{label}: undo restores dest attempts");
        assert_eq!(repo.snapshot(&src).unwrap().attempts, orig_src_attempts, "{label}: undo restores src attempts");
        assert!(repo.held().visible().unwrap().contains(&src), "{label}: undo restores src in view");
    };

    // 1a. Whole squash into parent (`vl squash`).
    let new_dest = repo.squash(src).unwrap();
    check_dest_and_undo(&mut repo, new_dest, "whole squash");

    // 1b. Squash by path (`vl squash hunk.txt`).
    let parts = repo.change_parts(&src, false).unwrap();
    let path_sel = Selection::from([(p("hunk.txt"), Pick { whole: true, ..Pick::default() })]);
    let res = repo.squash_into(src, None, Some((&parts, &path_sel))).unwrap();
    assert!(res.emptied);
    check_dest_and_undo(&mut repo, res.destination, "path squash");

    // 1c. Squash by hunks (`vl squash -i` choosing all hunks).
    let hparts = repo.change_parts(&src, true).unwrap();
    let hunk_sel = Selection::from([(p("hunk.txt"), hparts.units[0].everything())]);
    let res = repo.squash_into(src, None, Some((&hparts, &hunk_sel))).unwrap();
    assert!(res.emptied);
    check_dest_and_undo(&mut repo, res.destination, "hunk squash");

    // 1d. `--into DEST` across an intermediate change (`dest -> mid -> leaf`),
    // forward into a descendant (`dest --into src`), and across sibling branches.
    repo.set_attribution(None);
    let saved_op = repo.op_id();

    let mid = change_on(&mut repo, dest, "mid.txt");
    let leaf_rebased = repo.rebase(src, vec![mid]).unwrap();
    let leaf_attempts = repo.snapshot(&leaf_rebased).unwrap().attempts.clone();
    let res = repo.squash_into(leaf_rebased, Some(dest), None).unwrap();
    assert!(res.emptied);
    let got: Vec<_> = repo.snapshot(&res.destination).unwrap().attempts.iter().map(|a| attempt_summary(&repo, a)).collect();
    assert_eq!(got, expected, "--into ancestor across middle change");
    repo.undo().unwrap();
    assert_eq!(repo.snapshot(&dest).unwrap().attempts, orig_dest_attempts);
    assert_eq!(repo.snapshot(&leaf_rebased).unwrap().attempts, leaf_attempts);
    repo.restore_operation(saved_op).unwrap();

    // Forward `--into` descendant (`dest` squashed into `src`).
    let res_fwd = repo.squash_into(dest, Some(src), None).unwrap();
    assert!(res_fwd.emptied);
    let fwd_snap = repo.snapshot(&res_fwd.destination).unwrap();
    let got_fwd: Vec<_> = fwd_snap.attempts.iter().map(|a| attempt_summary(&repo, a)).collect();
    assert_eq!(
        got_fwd,
        vec![expected[1].clone(), expected[2].clone(), expected[0].clone()],
        "--into descendant lists destination's attempts first, then source's"
    );
    for a in &fwd_snap.attempts {
        assert_eq!(repo.snapshot(a).unwrap().change_id, fwd_snap.change_id);
    }
    repo.undo().unwrap();
    assert_eq!(repo.snapshot(&dest).unwrap().attempts, orig_dest_attempts);
    assert_eq!(repo.snapshot(&src).unwrap().attempts, orig_src_attempts);

    // Unrelated branch (`src` rebased onto `base` as a sibling of `dest`, then `--into dest`).
    let sib = repo.rebase(src, vec![base]).unwrap();
    let sib_attempts = repo.snapshot(&sib).unwrap().attempts.clone();
    let res_sib = repo.squash_into(sib, Some(dest), None).unwrap();
    assert!(res_sib.emptied);
    let sib_dest_snap = repo.snapshot(&res_sib.destination).unwrap();
    let got_sib: Vec<_> = sib_dest_snap.attempts.iter().map(|a| attempt_summary(&repo, a)).collect();
    assert_eq!(got_sib, expected, "--into unrelated sibling change");
    for a in &sib_dest_snap.attempts {
        assert_eq!(repo.snapshot(a).unwrap().change_id, sib_dest_snap.change_id);
    }
    repo.undo().unwrap();
    assert_eq!(repo.snapshot(&dest).unwrap().attempts, orig_dest_attempts);
    assert_eq!(repo.snapshot(&sib).unwrap().attempts, sib_attempts);
}

/// BUG-1837 guarantee 2: if a partial squash does not empty the source (by
/// path or by hunk), the source keeps its attempts and the destination gets
/// none of them.
#[test]
fn bug_1837_partial_squash_leaves_attempts_on_the_source() {
    use veil_core::selection::{Pick, Selection};

    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("multi.txt", "top\n1\n2\n3\n4\nbot\n")], "base");

    repo.new_change(WS, vec![base], "dest").unwrap();
    fs.write(&p("d_try.txt"), b"d dead end\n").unwrap();
    let td = snap(&mut repo, &*fs);
    let d_att = repo.drop_attempt(td, "dest try").unwrap().attempt;
    fs.remove_file(&p("d_try.txt")).unwrap();
    fs.write(&p("dest.txt"), b"dest\n").unwrap();
    let dest = snap(&mut repo, &*fs);

    repo.new_change(WS, vec![dest], "src").unwrap();
    repo.set_attribution(Some(agent_attr("codex/2", "partial")));
    fs.write(&p("s_try.txt"), b"s dead end\n").unwrap();
    let ts = snap(&mut repo, &*fs);
    let _s_att = repo.drop_attempt(ts, "src try").unwrap().attempt;
    fs.remove_file(&p("s_try.txt")).unwrap();
    repo.set_attribution(None);

    fs.write(&p("multi.txt"), b"TOP\n1\n2\n3\n4\nBOT\n").unwrap();
    fs.write(&p("stay.txt"), b"stays on src\n").unwrap();
    let src = snap(&mut repo, &*fs);

    // Partial by path: move `multi.txt`, leave `stay.txt`.
    let parts = repo.change_parts(&src, false).unwrap();
    let sel = Selection::from([(p("multi.txt"), Pick { whole: true, ..Pick::default() })]);
    let res = repo.squash_into(src, None, Some((&parts, &sel))).unwrap();
    assert!(!res.emptied);
    let new_src = res.source.expect("source remains");
    assert_eq!(repo.snapshot(&res.destination).unwrap().attempts, vec![d_att], "destination gets none of src's attempts");
    let src_atts = &repo.snapshot(&new_src).unwrap().attempts;
    assert_eq!(src_atts.len(), 1, "source keeps its attempt");
    assert_eq!(
        attempt_summary(&repo, &src_atts[0]),
        ("src try".into(), Some(agent_attr("codex/2", "partial")), vec![("s_try.txt".into(), b"s dead end\n".to_vec())])
    );
    repo.undo().unwrap();

    // Partial by hunk: move only the first block of `multi.txt`.
    let hparts = repo.change_parts(&src, true).unwrap();
    let multi_unit = hparts.units.iter().find(|u| u.path == p("multi.txt")).unwrap();
    let first_block = *multi_unit.text().unwrap().diff.all_blocks().iter().next().unwrap();
    let hsel = Selection::from([(
        p("multi.txt"),
        Pick { whole: false, mode: false, blocks: [first_block].into_iter().collect() },
    )]);
    let res = repo.squash_into(src, None, Some((&hparts, &hsel))).unwrap();
    assert!(!res.emptied);
    let new_src = res.source.expect("source remains");
    assert_eq!(repo.snapshot(&res.destination).unwrap().attempts, vec![d_att]);
    assert_eq!(repo.snapshot(&new_src).unwrap().attempts.len(), 1);
}

/// BUG-1837 guarantee 3: the 32-attempt cap (`object::MAX_ATTEMPTS`) holds;
/// exceeding it refuses with a clear message naming how many would be kept and
/// changes nothing.
#[test]
fn bug_1837_squash_refuses_when_attempts_would_exceed_cap() {
    use veil_core::object::MAX_ATTEMPTS;

    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("README.md", "hi\n")], "base");

    repo.new_change(WS, vec![base], "dest").unwrap();
    for i in 0..20 {
        fs.write(&p("d.txt"), format!("d try {i}\n").as_bytes()).unwrap();
        let t = snap(&mut repo, &*fs);
        repo.drop_attempt(t, &format!("dest try {i}")).unwrap();
    }
    fs.write(&p("d.txt"), b"dest ok\n").unwrap();
    let dest = snap(&mut repo, &*fs);
    assert_eq!(repo.snapshot(&dest).unwrap().attempts.len(), 20);

    repo.new_change(WS, vec![dest], "src").unwrap();
    for i in 0..15 {
        fs.write(&p("s.txt"), format!("s try {i}\n").as_bytes()).unwrap();
        let t = snap(&mut repo, &*fs);
        repo.drop_attempt(t, &format!("src try {i}")).unwrap();
    }
    fs.write(&p("s.txt"), b"src ok\n").unwrap();
    let src = snap(&mut repo, &*fs);
    assert_eq!(repo.snapshot(&src).unwrap().attempts.len(), 15);

    let view_before = repo.view().clone();
    let op_before = repo.op_id();

    let err = repo.squash(src).unwrap_err().to_string();
    assert!(err.contains("35") && err.contains(&MAX_ATTEMPTS.to_string()), "expected total (35) and cap ({MAX_ATTEMPTS}) in refusal: {err}");
    assert_eq!(repo.view(), &view_before, "refused squash must change nothing in the view");
    assert_eq!(repo.op_id(), op_before, "refused squash must record no operation");
    assert_eq!(repo.snapshot(&dest).unwrap().attempts.len(), 20);
    assert_eq!(repo.snapshot(&src).unwrap().attempts.len(), 15);

    // Exact cap (20 + 12 = 32) succeeds without dropping any attempt.
    repo.new_change(WS, vec![dest], "src32").unwrap();
    for i in 0..12 {
        fs.write(&p("s32.txt"), format!("s32 try {i}\n").as_bytes()).unwrap();
        let t = snap(&mut repo, &*fs);
        repo.drop_attempt(t, &format!("src32 try {i}")).unwrap();
    }
    fs.write(&p("s32.txt"), b"src32 ok\n").unwrap();
    let src32 = snap(&mut repo, &*fs);
    let combined = repo.squash(src32).unwrap();
    assert_eq!(repo.snapshot(&combined).unwrap().attempts.len(), MAX_ATTEMPTS);
}

/// BUG-1837 split check: `split` leaves `first` with no attempts and keeps the
/// original change's attempts on `second` (the half that keeps its change id).
#[test]
fn bug_1837_split_keeps_attempts_on_the_original_change_id() {
    use veil_core::selection::{Pick, Selection};

    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("README.md", "hi\n")], "base");
    repo.new_change(WS, vec![base], "both").unwrap();
    repo.set_attribution(Some(agent_attr("claude-code/1", "split-task")));
    fs.write(&p("try.txt"), b"dead end\n").unwrap();
    let tried = snap(&mut repo, &*fs);
    let _drop = repo.drop_attempt(tried, "dead end before split").unwrap();
    fs.remove_file(&p("try.txt")).unwrap();
    repo.set_attribution(None);

    fs.write(&p("first.txt"), b"first\n").unwrap();
    fs.write(&p("second.txt"), b"second\n").unwrap();
    let orig = snap(&mut repo, &*fs);
    let orig_cid = repo.snapshot(&orig).unwrap().change_id;

    let parts = repo.change_parts(&orig, false).unwrap();
    let sel = Selection::from([(p("first.txt"), Pick { whole: true, ..Pick::default() })]);
    let split = repo.split(&parts, &sel, Some("first half")).unwrap();

    let first = repo.snapshot(&split.first).unwrap();
    let second = repo.snapshot(&split.second).unwrap();
    assert_ne!(first.change_id, orig_cid);
    assert_eq!(second.change_id, orig_cid);
    assert!(first.attempts.is_empty(), "first part gets a new change id and no attempts");
    assert_eq!(second.attempts.len(), 1, "second part keeps the original change's attempts");
    assert_eq!(
        attempt_summary(&repo, &second.attempts[0]),
        ("dead end before split".into(), Some(agent_attr("claude-code/1", "split-task")), vec![("try.txt".into(), b"dead end\n".to_vec())])
    );
}

/// BUG-1910: `Transaction::supersede` records that a snapshot became one
/// the repository already holds: a change as the server landed it, made
/// again on a newer tip, with the local version as its predecessor. The
/// local version leaves the view (it is still there by its id); what stood
/// on it, a later change, a tag and the working copy, follows at commit
/// and holds what else landed; one undo restores the view.
#[test]
fn bug_1910_a_superseded_snapshot_leaves_the_view_and_what_stood_on_it_follows() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "base");
    let c = commit_files(&mut repo, &*fs, &[("b.txt", "b\n")], "the change");
    let d = commit_files(&mut repo, &*fs, &[("c.txt", "c\n")], "on it");
    repo.set_tag("mine", c, false).unwrap();
    // The tip moved meanwhile (`other`, on the base) ...
    repo.create_workspace("o", vec![base]).unwrap();
    let ov = repo.workspace_overlay("o").unwrap();
    ov.write(&p("x.txt"), b"x\n").unwrap();
    repo.snapshot_workspace("o", &ov).unwrap();
    let (other, _) = repo.commit_working_copy("o", "what else landed").unwrap();
    // ... and the change was made again on it, as a landing does.
    let landed = {
        let tree_of = |id: &ObjectId| repo.snapshot(id).unwrap().tree;
        let tree = veil_core::merge::merge_trees(repo.store(), Some(tree_of(&base)), tree_of(&other), tree_of(&c)).unwrap().tree;
        let mut s = (*repo.snapshot(&c).unwrap()).clone();
        s.parents = vec![other];
        s.tree = tree;
        s.predecessors = vec![c];
        s.signature = None;
        let mut tx = repo.transaction("what the server landed").unwrap();
        let id = tx.write_snapshot(&s).unwrap();
        tx.commit().unwrap();
        id
    };
    assert_ne!(landed, c);
    let view0 = repo.view().clone();

    let mut tx = repo.transaction("landed").unwrap();
    tx.supersede(c, landed).unwrap();
    tx.commit().unwrap();

    assert_eq!(repo.view().tags["mine"].target, landed, "the tag follows");
    let wc = repo.workspace_wc(WS).unwrap();
    let on_it = repo.snapshot(&wc).unwrap().parents.clone();
    assert_eq!(on_it.len(), 1);
    let d2 = repo.snapshot(&on_it[0]).unwrap();
    assert_ne!(on_it[0], d, "the later change was rebased");
    assert_eq!((repo.description(&d2).as_str(), d2.parents.clone()), ("on it", vec![landed]));
    for (f, text) in [("a.txt", "a\n"), ("b.txt", "b\n"), ("c.txt", "c\n"), ("x.txt", "x\n")] {
        assert_eq!(read_at(&repo, &wc, f), text.as_bytes(), "{f}");
    }
    let visible = repo.exact().visible().unwrap();
    assert!(visible.contains(&landed) && !visible.contains(&c) && !visible.contains(&d), "the local versions left the view");
    assert_eq!(repo.description(&repo.snapshot(&c).unwrap()), "the change", "and are still there by id");
    repo.undo().unwrap();
    assert_eq!(repo.view(), &view0, "one undo restores the view");
}
