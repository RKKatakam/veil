//! Reproductions from the re-check of the client and engine fixes
//! (`rc-client`, 2026-11-11): each test shows a fix that is incomplete or
//! that another fix broke, and is ignored under its `docs/BUGS.md` row
//! until the bug is fixed.

use veil_core::{
    object::{EntryKind, Visibility},
    ObjectId, Repo, StorageBackend, VPath,
};

use crate::adversarial_support::*;

const WS: &str = "default";

fn team() -> Visibility {
    Visibility::Cloaked { scope: "team".into() }
}

/// The sealed content snapshot `id` holds that the server's push check
/// refuses with "is not a secret file: only secret files are encrypted"
/// (`veil-server` `sync.rs`, `check_changes` and `sealed_secret_here`): for
/// every path that differs from the first parent's, each sealed file, link
/// or conflict term there must be at a secret's path, or at a path where a
/// parent holds a sealed file or a conflict with a sealed version (BUG-1930:
/// a conflict entry's own label is always public), or the snapshot must
/// move a secret of that scope away (`policy::sealed_secret` with `known =
/// false`).
fn refused_by_the_push_check(repo: &Repo, id: &ObjectId) -> Vec<String> {
    let s = repo.snapshot(id).unwrap();
    let parents: Vec<ObjectId> = s.parents.iter().map(|p| repo.snapshot(p).unwrap().tree).collect();
    let changes = veil_core::tree::diff_trees(repo.store(), parents.first(), Some(&s.tree)).unwrap();
    let mut out = vec![];
    for c in &changes {
        let Some(e) = &c.new else { continue };
        let labels: Vec<Visibility> = match e.kind {
            EntryKind::Conflict => {
                let cf = repo.store().conflict(&e.id).unwrap();
                cf.adds.iter().chain(&cf.removes).flatten().map(|t| t.visibility.clone()).collect()
            }
            k if k.holds_blob() => vec![e.visibility.clone()],
            _ => continue,
        };
        for v in labels {
            let Visibility::Cloaked { scope } = &v else { continue };
            let explained = veil_core::policy::sealed_secret::<std::convert::Infallible>(
                c.path.as_str(),
                scope,
                false,
                |_| {
                    Ok(parents.iter().any(|t| {
                        veil_core::tree::lookup(repo.store(), t, &c.path).unwrap().is_some_and(|e| match e.kind {
                            EntryKind::Conflict => {
                                let cf = repo.store().conflict(&e.id).unwrap();
                                cf.adds.iter().chain(&cf.removes).flatten().any(|t| !t.visibility.is_public())
                            }
                            _ => !e.visibility.is_public(),
                        })
                    }))
                },
                |scope| {
                    Ok(changes
                        .iter()
                        .any(|o| o.new.is_none() && o.old.as_ref().is_some_and(|e| matches!(&e.visibility, Visibility::Cloaked { scope: s } if s == scope))))
                },
            )
            .unwrap();
            if !explained {
                out.push(format!("'{}' is not a secret file: only secret files are encrypted", c.path));
            }
        }
    }
    out
}

/// `base` holds the secret `.env`; `rename` renames it to `settings.txt`
/// (kept sealed: protection follows a secret across a rename, and the push
/// check takes it: the snapshot moves the secret away).
fn renamed_secret() -> (Repo, std::sync::Arc<veil_core::MemoryBackend>, ObjectId, ObjectId) {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[(".veilpolicy", ".env cloak team\n"), (".env", "REGION=one\n"), ("README.md", "hi\n")], "base");
    fs.remove_file(&p(".env")).unwrap();
    fs.write(&p("settings.txt"), b"REGION=one\n").unwrap();
    snap(&mut repo, &*fs);
    let (rename, _) = repo.commit_working_copy(WS, "rename the settings").unwrap();
    assert_eq!(file_entry(&repo, &rename, "settings.txt").unwrap().visibility, team(), "control: the renamed secret stays sealed");
    assert_eq!(refused_by_the_push_check(&repo, &rename), Vec::<String>::new(), "control: and the push check takes it");
    (repo, fs, base, rename)
}

fn edit_on(repo: &mut Repo, base: ObjectId, path: &str, text: &str, msg: &str) -> ObjectId {
    let ws = repo.ephemeral_workspace(base).unwrap();
    ws.write(path, text).unwrap();
    repo.commit_ephemeral(&ws, msg).unwrap().0
}

/// `vl` writes nothing the server's push check refuses for good (BUG-1833's
/// guarantee, `Transaction::reconcile_sealing`: "the rule is asked exactly
/// as the server's push check asks it"). Two changes edit a renamed secret,
/// the rebase of one onto the other conflicts, and the conflict is resolved
/// in a change of its own (a sandbox run on the conflicted change, or the
/// working copy committed on it). The resolution is recorded sealed, as
/// the secret's content it is; its parent holds a *conflict* at the path,
/// which `vl` counts as "a parent holds a sealed file there" (the conflict's
/// versions are sealed) and the server did not (a conflict entry's own
/// label is public), so the server refused that push and every later one.
/// Fixed on the server (recording the resolution plain would publish an
/// edit of a secret): its check reads a parent's conflict as `vl` does.
/// And nothing wider: on a parent whose conflict has no sealed version, the
/// engine records the resolution plain.
#[test]
fn bug_1930_a_conflict_in_a_renamed_secret_resolved_in_its_own_change_is_what_the_push_check_takes() {
    let (mut repo, fs, _base, rename) = renamed_secret();
    let x = edit_on(&mut repo, rename, "settings.txt", "REGION=two\n", "x");
    assert_eq!(file_entry(&repo, &x, "settings.txt").unwrap().visibility, team(), "control: an edit of the renamed secret stays sealed");
    assert_eq!(refused_by_the_push_check(&repo, &x), Vec::<String>::new(), "control: and the push check takes it");
    let y = edit_on(&mut repo, rename, "settings.txt", "REGION=three\n", "y");
    let y2 = repo.rebase(y, vec![x]).unwrap();
    let e = veil_core::tree::lookup(repo.store(), &repo.snapshot(&y2).unwrap().tree, &VPath::new("settings.txt").unwrap()).unwrap().unwrap();
    assert_eq!(e.kind, EntryKind::Conflict, "control: the rebase conflicts");
    assert_eq!(refused_by_the_push_check(&repo, &y2), Vec::<String>::new(), "control: the conflicted change is taken");

    // Resolved in a change of its own, in a sandbox (`vl ws exec`).
    let r = edit_on(&mut repo, y2, "settings.txt", "REGION=four\n", "resolve");
    assert_eq!(repo.snapshot(&r).unwrap().parents, vec![y2]);
    let e = file_entry(&repo, &r, "settings.txt").unwrap();
    assert_eq!((e.kind, read_at(&repo, &r, "settings.txt")), (EntryKind::File, b"REGION=four\n".to_vec()), "the resolution is recorded");
    let sandbox = refused_by_the_push_check(&repo, &r);

    // Resolved in the working copy, committed (`vl new`, edit, `vl commit`).
    let from = repo.snapshot(&repo.view().workspaces[WS].wc).unwrap().tree;
    repo.new_change(WS, vec![y2], "").unwrap();
    let to = repo.snapshot(&repo.view().workspaces[WS].wc).unwrap().tree;
    repo.checkout_tree(&*fs, Some(&from), &to).unwrap();
    fs.write(&p("settings.txt"), b"REGION=five\n").unwrap();
    snap(&mut repo, &*fs);
    let (c, _) = repo.commit_working_copy(WS, "resolved").unwrap();
    assert_eq!(repo.snapshot(&c).unwrap().parents, vec![y2]);
    assert_eq!(read_at(&repo, &c, "settings.txt"), b"REGION=five\n", "the resolution is recorded");
    let working_copy = refused_by_the_push_check(&repo, &c);

    assert_eq!(
        (sandbox, working_copy),
        (Vec::<String>::new(), Vec::<String>::new()),
        "vl recorded a resolution the server's push check refuses (in a sandbox; in the working copy)"
    );

    // Nothing wider: the resolution of an ordinary file's conflict (no
    // version sealed) is recorded plain, and taken.
    let a = edit_on(&mut repo, rename, "README.md", "one\n", "a");
    let b = edit_on(&mut repo, rename, "README.md", "two\n", "b");
    let b2 = repo.rebase(b, vec![a]).unwrap();
    let e = veil_core::tree::lookup(repo.store(), &repo.snapshot(&b2).unwrap().tree, &VPath::new("README.md").unwrap()).unwrap().unwrap();
    assert_eq!(e.kind, EntryKind::Conflict, "control: the rebase conflicts");
    let r = edit_on(&mut repo, b2, "README.md", "three\n", "resolve");
    let e = file_entry(&repo, &r, "README.md").unwrap();
    assert_eq!((e.kind, e.visibility.clone(), read_at(&repo, &r, "README.md")), (EntryKind::File, Visibility::Public, b"three\n".to_vec()));
    assert_eq!(refused_by_the_push_check(&repo, &r), Vec::<String>::new());
}
