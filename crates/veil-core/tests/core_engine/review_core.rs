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
#[ignore = "BUG-1832: a moved secret is first stored as a plain-text blob, which stays in the object store"]
fn bug_1832_a_moved_secret_is_never_stored_as_plain_text() {
    // Not token-shaped: the scanner has nothing to say about it (a moved
    // file it flags is quarantined, never recorded).
    const SECRET: &str = "REGION=review-marker-of-a-moved-secret-0001\nTIER=review-marker-of-a-moved-secret-0002\n";
    let (mut repo, fs, _) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[(".veilpolicy", ".env cloak team\n"), (".env", SECRET)], "base");
    let hits = |fs: &veil_core::MemoryBackend| -> Vec<String> {
        backend_contains(fs, b"review-marker-of-a-moved-secret-0001").into_iter().filter(|f| f.starts_with(".veil/")).collect()
    };
    assert_eq!(hits(&fs), Vec::<String>::new(), "the committed secret is stored sealed only");

    // `mv .env conf/settings.txt`.
    fs.remove_file(&p(".env")).unwrap();
    fs.write(&p("conf/settings.txt"), SECRET.as_bytes()).unwrap();
    let wc = snap(&mut repo, &*fs);
    let e = file_entry(&repo, &wc, "conf/settings.txt").expect("the moved file is recorded");
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() }, "protection followed the content");
    assert_eq!(repo.store().read_entry(&e).unwrap(), SECRET.as_bytes());

    assert_eq!(hits(&fs), Vec::<String>::new(), "the secret's plain text is in the object store");
}

/// `vl upgrade` converts what format 8 itself writes: an editor's or a
/// patch tool's backup of a secret (`.envrc.orig` beside `.envrc`) takes
/// its secret's protection, so `vl` seals it, in format 7 as now.
#[test]
#[ignore = "BUG-1834: `vl upgrade` refuses a format-6 or -7 repository that holds a sealed backup of a secret (`.envrc.orig`)"]
fn bug_1834_a_sealed_backup_of_a_secret_does_not_block_the_upgrade() {
    use veil_core::upgrade::{upgrade, UpgradeOptions};
    let (mut repo, fs, alice) = new_repo("alice");
    let c = commit_files(
        &mut repo,
        &*fs,
        &[
            (".veilpolicy", ".envrc cloak team\n"),
            (".envrc", "export REGION=review-marker-backup-new\n"),
            (".envrc.orig", "export REGION=review-marker-backup-old\n"),
        ],
        "first",
    );
    let team = Visibility::Cloaked { scope: "team".into() };
    assert_eq!(file_entry(&repo, &c, ".envrc").unwrap().visibility, team);
    assert_eq!(file_entry(&repo, &c, ".envrc.orig").unwrap().visibility, team, "control: vl seals the backup as it seals the secret");
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
#[ignore = "BUG-1835: an operation file whose bytes do not match its id is read and used; only `vl fsck` notices"]
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
    assert_eq!(Repo::open_remote(remote.clone()).unwrap().view().tags["main"].target, x_now, "the push moved main");
    backend_contains(&*remote, MARKER)
}

/// Rewritten snapshots stop being reachable, so what a change's author
/// amends away before a push never leaves the device: also when a change
/// built on it keeps a recorded attempt (`vl attempt drop`) made on the
/// earlier version.
#[test]
#[ignore = "BUG-1836: a recorded attempt keeps the old version of an amended ancestor, and a push sends it"]
fn bug_1836_content_amended_away_under_a_recorded_attempt_is_not_pushed() {
    assert_eq!(amended_away_then_pushed(false), Vec::<String>::new(), "control: without an attempt the amended-away text is not pushed");
    assert_eq!(
        amended_away_then_pushed(true),
        Vec::<String>::new(),
        "the remote received the text its author amended out of P before pushing"
    );
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
#[ignore = "BUG-1833: a secret made and renamed within one change is committed sealed at an ordinary path, which the only-secrets rule refuses"]
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
    assert!(file_entry(&repo, &c, "settings.txt").is_some(), "the renamed file is recorded");
    repo.set_tag("main", c, false).unwrap();

    assert_eq!(named_by_the_only_secrets_rule(&mut repo), Vec::<String>::new(), "vl recorded what its own rule calls encrypted non-secret content");
}

/// The same when the rename is its own change, folded into the change
/// that added the secret (`vl squash`).
#[test]
#[ignore = "BUG-1833: a secret made and renamed within one change is committed sealed at an ordinary path, which the only-secrets rule refuses"]
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

    let squashed = repo.squash(rename).unwrap();
    assert_eq!(repo.snapshot(&squashed).unwrap().parents, vec![base], "the two changes are one, on the base");
    assert!(file_entry(&repo, &squashed, "settings.txt").is_some(), "the renamed file is recorded");
    repo.set_tag("main", squashed, true).unwrap();

    assert_eq!(named_by_the_only_secrets_rule(&mut repo), Vec::<String>::new(), "vl recorded what its own rule calls encrypted non-secret content");
}
