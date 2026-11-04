//! End-to-end engine tests. Everything runs on `MemoryBackend` — no disk.

use std::sync::Arc;

use veil_core::{
    commands::EmbargoSpec,
    object::Visibility,
    remote,
    revset::resolve,
    tree::{lookup, walk_files},
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

const WS: &str = "default";

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

fn new_repo(name: &str) -> (Repo, Arc<MemoryBackend>, Identity) {
    let fs = Arc::new(MemoryBackend::new());
    let id = Identity::generate(name);
    let repo = Repo::init(fs.clone(), Some(id.clone()), name).unwrap();
    (repo, fs, id)
}

fn snap(repo: &mut Repo, fs: &MemoryBackend) -> ObjectId {
    repo.snapshot_workspace(WS, fs).unwrap().snapshot
}

fn file_entry(repo: &Repo, rev: &ObjectId, path: &str) -> Option<veil_core::TreeEntry> {
    let tree = repo.snapshot(rev).unwrap().tree;
    lookup(repo.store(), &tree, &p(path)).unwrap()
}

#[test]
fn automatic_snapshots_and_stable_change_ids() {
    let (mut repo, fs, _) = new_repo("alice");
    let wc0 = repo.workspace_wc(WS).unwrap();
    let change = repo.snapshot(&wc0).unwrap().change_id;

    fs.write(&p("src/main.rs"), b"fn main() {}\n").unwrap();
    let wc1 = snap(&mut repo, &fs);
    assert_ne!(wc0, wc1, "editing a file records a new snapshot");
    assert_eq!(repo.snapshot(&wc1).unwrap().change_id, change, "same logical change");
    assert_eq!(repo.snapshot(&wc1).unwrap().predecessors, vec![wc0]);

    // No change -> no new snapshot, no new operation.
    let op = repo.op_id();
    assert_eq!(snap(&mut repo, &fs), wc1);
    assert_eq!(repo.op_id(), op);

    let (committed, wc2) = repo.commit_working_copy(WS, "initial").unwrap();
    assert_eq!(repo.description(&repo.snapshot(&committed).unwrap()), "initial");
    assert_eq!(repo.snapshot(&wc2).unwrap().parents, vec![committed]);
    assert!(repo.is_empty_change(&wc2).unwrap());
}

#[test]
fn rewriting_a_parent_rebases_descendants() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p("a.txt"), b"one\n").unwrap();
    snap(&mut repo, &fs);
    let (first, _) = repo.commit_working_copy(WS, "first").unwrap();
    fs.write(&p("b.txt"), b"two\n").unwrap();
    snap(&mut repo, &fs);
    let (second, _) = repo.commit_working_copy(WS, "second").unwrap();

    let new_first = repo.describe(first, "first, reworded").unwrap();
    let second_now = resolve(&repo, "@-", WS).unwrap();
    assert_ne!(second_now, second, "child was rebased");
    let s = repo.snapshot(&second_now).unwrap();
    assert_eq!(s.parents, vec![new_first]);
    assert_eq!(repo.description(&s), "second");
    assert!(file_entry(&repo, &second_now, "b.txt").is_some());
}

#[test]
fn undo_restores_previous_view() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p("a.txt"), b"x").unwrap();
    snap(&mut repo, &fs);
    let before = repo.view().clone();
    repo.commit_working_copy(WS, "msg").unwrap();
    assert_ne!(repo.view(), &before);
    repo.undo().unwrap();
    assert_eq!(repo.view(), &before);
    assert!(repo.op_log(10).unwrap()[0].1.description.starts_with("undo"));
}

#[test]
fn secrets_never_enter_the_graph() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(".env"), b"DATABASE_URL=postgres://u:pw@db/prod\n").unwrap();
    fs.write(&p("svc/.env.production"), b"X=1").unwrap();
    fs.write(&p(".env.example"), b"DATABASE_URL=\n").unwrap();
    fs.write(&p("config.js"), b"const key = 'AKIAIOSFODNN7EXAMPLE';\n").unwrap();
    fs.write(&p("main.rs"), b"fn main() {}\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();

    let files: Vec<String> = walk_files(repo.store(), &repo.snapshot(&out.snapshot).unwrap().tree)
        .unwrap()
        .into_iter()
        .map(|(p, _)| p.to_string())
        .collect();
    assert_eq!(files, vec![".env.example", "main.rs"]);
    assert_eq!(out.report.isolated, vec![p(".env"), p("svc/.env.production")]);
    assert_eq!(out.report.quarantined[0].0, p("config.js"));
    assert_eq!(out.report.quarantined[0].1[0].rule, "aws-access-key-id");

    // Local-only files are backed up in the encrypted vault.
    repo.capture_local_files(&*fs, &out.report).unwrap();
    let vault = repo.vault_load().unwrap();
    assert!(vault.files.contains_key(".env"));
    assert!(vault.files.contains_key("config.js"));
}

#[test]
fn policy_cannot_casually_expose_builtin_secrets() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b".env public\n").unwrap();
    fs.write(&p(".env"), b"X=1").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(file_entry(&repo, &out.snapshot, ".env").is_none());
    assert_eq!(out.report.blocked_exposures, vec![p(".env")]);

    fs.write(&p(".veilpolicy"), b".env cloak\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    let e = file_entry(&repo, &out.snapshot, ".env").expect("cloaked .env is shared encrypted");
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() });
}

#[test]
fn cloaked_files_are_ciphertext_for_non_members() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    fs.write(&p("secrets/db.yml"), b"password: hunter2\n").unwrap();
    fs.write(&p("README.md"), b"hello\n").unwrap();
    let wc = snap(&mut alice, &fs);
    let e = file_entry(&alice, &wc, "secrets/db.yml").unwrap();
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() });
    // Raw object is ciphertext.
    let raw = alice.store().get_raw(&e.id).unwrap();
    assert!(!raw.windows(7).any(|w| w == b"hunter2"));
    assert_eq!(alice.store().read_entry(&e).unwrap(), b"password: hunter2\n");

    // Re-snapshotting unchanged cloaked content is a no-op (deterministic sealing).
    let op = alice.op_id();
    snap(&mut alice, &fs);
    assert_eq!(alice.op_id(), op);

    // Bob opens the same repo bytes with his own identity: no key.
    let bob = Identity::generate("bob");
    let bob_repo = Repo::open(fs.clone(), Some(bob.clone()), "bob").unwrap();
    assert!(bob_repo.store().read_entry(&e).unwrap_err().is_unreadable());

    // Alice grants Bob the team scope; now he can read.
    alice.keys().grant("team", &bob.public_hex(), "bob").unwrap();
    let bob_repo = Repo::open(fs.clone(), Some(bob), "bob").unwrap();
    assert_eq!(bob_repo.store().read_entry(&e).unwrap(), b"password: hunter2\n");
}

#[test]
fn cloaked_workspace_seals_files_and_descriptions() {
    let (mut repo, _fs, _) = new_repo("alice");
    let base = repo.root_id();
    repo.create_workspace("stealth", vec![base], Some("team".into())).unwrap();
    let overlay = repo.workspace_overlay("stealth").unwrap();
    overlay.write(&p("plan.md"), b"launch on friday").unwrap();
    let out = repo.snapshot_workspace("stealth", &overlay).unwrap();
    let id = repo.describe(out.snapshot, "secret launch").unwrap();
    let s = repo.snapshot(&id).unwrap();
    assert!(matches!(s.description, veil_core::object::Text::Sealed(_)));
    assert_eq!(repo.description(&s), "secret launch");
    let e = file_entry(&repo, &id, "plan.md").unwrap();
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() });

    let outsider = Repo::open(repo.backend().clone(), Some(Identity::generate("eve")), "eve").unwrap();
    assert_eq!(outsider.description(&s), "[cloaked:team]");
}

#[test]
fn ephemeral_workspaces_are_isolated_and_cheap() {
    let (mut repo, fs, _) = new_repo("alice");
    for i in 0..50 {
        fs.write(&p(&format!("pkg{}/file{i}.txt", i % 5)), format!("{i}\n").as_bytes()).unwrap();
    }
    snap(&mut repo, &fs);
    let (base, _) = repo.commit_working_copy(WS, "base").unwrap();
    let dev_view = repo.workspace_wc(WS).unwrap();

    // Two agents work concurrently on the same base, entirely in memory.
    let a = repo.ephemeral_workspace(base).unwrap();
    let b = repo.ephemeral_workspace(base).unwrap();
    a.write("pkg0/file0.txt", "agent a\n").unwrap();
    b.write("pkg1/file1.txt", "agent b\n").unwrap();
    b.remove("pkg2").unwrap();
    let (sa, _) = repo.commit_ephemeral(&a, "agent a work").unwrap();
    let (sb, _) = repo.commit_ephemeral(&b, "agent b work").unwrap();

    assert_eq!(repo.snapshot(&sa).unwrap().parents, vec![base]);
    assert_eq!(repo.store().read_entry(&file_entry(&repo, &sa, "pkg0/file0.txt").unwrap()).unwrap(), b"agent a\n");
    assert!(file_entry(&repo, &sa, "pkg2/file2.txt").is_some());
    assert!(file_entry(&repo, &sb, "pkg2/file2.txt").is_none());
    // Unchanged subtrees are shared by id with the base.
    assert_eq!(file_entry(&repo, &sa, "pkg3"), file_entry(&repo, &base, "pkg3"));
    // The developer's working copy and disk state were never touched.
    assert_eq!(repo.workspace_wc(WS).unwrap(), dev_view);
    assert_eq!(fs.read(&p("pkg0/file0.txt")).unwrap(), b"0\n");

    // Both lines of work can be merged.
    let merged = repo.merge(WS, sa, vec![sb], "combine agents", None).unwrap();
    assert!(merged.conflicts.is_empty());
    assert!(file_entry(&repo, &merged.snapshot, "pkg2/file2.txt").is_none());
    assert!(file_entry(&repo, &merged.snapshot, "pkg0/file0.txt").is_some());
}

#[test]
fn rebase_reports_conflicts() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p("f.txt"), b"a\nb\nc\n").unwrap();
    snap(&mut repo, &fs);
    let (base, _) = repo.commit_working_copy(WS, "base").unwrap();
    fs.write(&p("f.txt"), b"a\nOURS\nc\n").unwrap();
    snap(&mut repo, &fs);
    let (ours, _) = repo.commit_working_copy(WS, "ours").unwrap();

    let ws = repo.ephemeral_workspace(base).unwrap();
    ws.write("f.txt", "a\nTHEIRS\nc\n").unwrap();
    let (theirs, _) = repo.commit_ephemeral(&ws, "theirs").unwrap();

    let rebased = repo.rebase(theirs, vec![ours]).unwrap();
    let s = repo.snapshot(&rebased).unwrap();
    assert_eq!(s.conflicts, vec!["f.txt"]);
    let e = file_entry(&repo, &rebased, "f.txt").unwrap();
    assert_eq!(e.kind, veil_core::EntryKind::Conflict, "recorded as data, not markers");
    let text = String::from_utf8(veil_core::conflict::read_file_like(repo.store(), &e).unwrap()).unwrap();
    assert!(text.contains("<<<<<<<") && text.contains("OURS") && text.contains("THEIRS"));
}

#[test]
fn public_remote_never_receives_cloaked_or_isolated_content() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"internal/ cloak\n").unwrap();
    fs.write(&p("internal/roadmap.md"), b"acquire competitor\n").unwrap();
    fs.write(&p("lib.rs"), b"pub fn f() {}\n").unwrap();
    fs.write(&p(".env"), b"TOKEN=abc").unwrap();
    snap(&mut alice, &fs);
    let (c, _) = alice.commit_working_copy(WS, "release").unwrap();
    alice.set_tag("main", c, None, false).unwrap();
    alice.set_tag("wip", c, Some("team".into()), false).unwrap();

    let public_backend = Arc::new(MemoryBackend::new());
    let rep = remote::push(&mut alice, public_backend.clone(), true, &[], false).unwrap();
    assert_eq!(rep.redacted, 1, "the cloaked blob is withheld");
    assert!(rep.tags_skipped.iter().any(|(t, _)| t == "wip"));

    // Nothing in the public remote contains the cloaked plaintext or .env.
    for path in veil_core::vfs::walk_files(&*public_backend, &VPath::root(), &|_| false).unwrap() {
        let data = public_backend.read(&path).unwrap();
        assert!(!data.windows(10).any(|w| w == b"competitor"));
        assert!(!data.windows(9).any(|w| w == b"TOKEN=abc"));
    }

    // A stranger clones the public remote: they see the tree, the cloaked entry
    // is redacted, and snapshotting does not delete it.
    let (mut carol, carol_fs, _) = new_repo("carol");
    remote::pull(&mut carol, "origin", public_backend.clone()).unwrap();
    let main = resolve(&carol, "main", WS).unwrap();
    let wc = carol.new_change(WS, vec![main], "").unwrap();
    let report = carol.checkout_tree(&*carol_fs, None, &carol.snapshot(&wc).unwrap().tree).unwrap();
    assert_eq!(report.redacted, vec![p("internal/roadmap.md")]);
    assert!(carol_fs.exists(&p("lib.rs")).unwrap());
    carol_fs.write(&p("lib.rs"), b"pub fn f() { /* carol */ }\n").unwrap();
    let out = carol.snapshot_workspace(WS, &*carol_fs).unwrap();
    assert!(file_entry(&carol, &out.snapshot, "internal/roadmap.md").is_some(), "redacted entry carried over");
    assert_eq!(out.report.carried, vec![p("internal/roadmap.md")]);
}

#[test]
fn embargoed_merge_hides_changes_until_release() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p("auth.rs"), b"fn check() -> bool { true }\n").unwrap();
    snap(&mut alice, &fs);
    let (main, _) = alice.commit_working_copy(WS, "v1").unwrap();
    alice.set_tag("main", main, None, false).unwrap();

    // Security fix developed out of sight.
    let fix_ws = alice.ephemeral_workspace(main).unwrap();
    fix_ws.write("auth.rs", "fn check() -> bool { verify_signature() }\n").unwrap();
    fix_ws.write("CVE.md", "details\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&fix_ws, "fix CVE").unwrap();

    let res = alice
        .merge(WS, main, vec![fix], "merge security fix", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    let embargo = res.embargo.clone().unwrap();
    let e = file_entry(&alice, &res.snapshot, "auth.rs").unwrap();
    assert_eq!(e.visibility, Visibility::Embargoed { embargo: embargo.clone() });
    assert!(String::from_utf8(alice.store().read_entry(&e).unwrap()).unwrap().contains("verify_signature"));
    assert_eq!(resolve(&alice, "main", WS).unwrap(), res.snapshot, "tag advanced");

    // Publish to a public mirror before release.
    let public_backend = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, public_backend.clone(), true, &[], false).unwrap();
    let mirror = Repo::open(public_backend.clone(), Some(Identity::generate("public")), "public").unwrap();
    let e_pub = file_entry(&mirror, &res.snapshot, "auth.rs").unwrap();
    assert_eq!(mirror.store().read_entry(&e_pub).unwrap(), b"fn check() -> bool { true }\n", "public sees pre-merge content");
    // The embargoed tree is sealed whole: the mirror does not even learn the
    // name of the file the fix adds (BUG-018).
    assert!(file_entry(&mirror, &res.snapshot, "CVE.md").is_none());

    // Release and push again: the public now sees the fix, same snapshot ids.
    alice.release_embargo(&embargo).unwrap();
    remote::push(&mut alice, public_backend.clone(), true, &[], false).unwrap();
    let mirror = Repo::open(public_backend, Some(Identity::generate("public")), "public").unwrap();
    let text = mirror.store().read_entry(&file_entry(&mirror, &res.snapshot, "auth.rs").unwrap()).unwrap();
    assert!(String::from_utf8(text).unwrap().contains("verify_signature"));
}

#[test]
fn snapshot_in_memory_repo_through_overlay_is_o_changes() {
    // Hints let the builder reuse unchanged subtrees without reading them.
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p("big/a"), b"1").unwrap();
    fs.write(&p("small/b"), b"2").unwrap();
    snap(&mut repo, &fs);
    let (base, _) = repo.commit_working_copy(WS, "base").unwrap();
    let ws = repo.ephemeral_workspace(base).unwrap();
    ws.write("small/b", "3").unwrap();
    let (s, report) = repo.commit_ephemeral(&ws, "edit").unwrap();
    assert_eq!(report.files, 1, "only the changed file was read and hashed");
    assert_eq!(file_entry(&repo, &s, "big"), file_entry(&repo, &base, "big"));
}

#[test]
fn releasing_an_embargo_does_not_dirty_the_working_copy() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p("a.txt"), b"v1\n").unwrap();
    snap(&mut repo, &fs);
    let (base, _) = repo.commit_working_copy(WS, "v1").unwrap();
    let ws = repo.ephemeral_workspace(base).unwrap();
    ws.write("a.txt", "v2\n").unwrap();
    let (fix, _) = repo.commit_ephemeral(&ws, "fix").unwrap();
    let res = repo
        .merge(WS, base, vec![fix], "embargoed", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    let wc = repo.workspace_wc(WS).unwrap();
    let tree = repo.snapshot(&wc).unwrap().tree;
    repo.checkout_tree(&*fs, Some(&repo.snapshot(&base).unwrap().tree), &tree).unwrap();
    assert_eq!(fs.read(&p("a.txt")).unwrap(), b"v2\n", "key holder sees merged content");
    assert_eq!(snap(&mut repo, &fs), wc, "no spurious change before release");

    repo.release_embargo(res.embargo.as_deref().unwrap()).unwrap();
    assert_eq!(snap(&mut repo, &fs), wc, "no spurious change after release");
}
