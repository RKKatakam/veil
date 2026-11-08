//! Round-2 adversarial tests: policy that arrives by merge or pull, gc and
//! fsck over stores full of embargo wrappers, and push availability.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md`.

use crate::adversarial_support;

use std::{sync::Arc, time::Duration};

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    gc::{gc, GcOptions},
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

fn checkout_wc(repo: &mut Repo, fs: &dyn StorageBackend, from_snapshot: ObjectId) {
    let wc = repo.workspace_wc(WS).unwrap();
    let to = repo.snapshot(&wc).unwrap().tree;
    let from = repo.snapshot(&from_snapshot).unwrap().tree;
    repo.checkout_tree(fs, Some(&from), &to).unwrap();
}

// ---- a policy that arrives by merge publishes isolated secrets ---------------------

/// A pull request that only edits `.veilpolicy` (`.env public!`) is merged.
/// The merge refuses policy edits that would re-key or publish *cloaked*
/// files, but isolated files are not in any tree, so the check sees
/// nothing. At the merging member's next snapshot their real `.env` is
/// recorded in plaintext, unscanned (`public!` turns scanning off), and is
/// pushed with the next push. No warning is given.
#[test]
fn a_merged_policy_cannot_publish_the_merging_members_isolated_files() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".env"), b"DB_PASSWORD=prod-hunter2-Xk9mQ2vL7pR4\n").unwrap();
    fs.write(&p("deploy/id_rsa"), b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n").unwrap();
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    assert!(file_entry(&alice, &main, ".env").is_none());
    alice.set_tag("main", main, false).unwrap();

    // Mallory's PR: "tidy up the policy".
    let pr_ws = alice.ephemeral_workspace(main).unwrap();
    pr_ws.write(".veilpolicy", "# fixtures are deliberately public\n.env public!\ndeploy/ public!\n").unwrap();
    let (pr, _) = alice.commit_ephemeral(&pr_ws, "policy cleanup").unwrap();

    let res = alice.merge(WS, main, vec![pr], "merge PR", None).unwrap();
    checkout_wc(&mut alice, &*fs, main);
    let out = alice.snapshot_workspace(WS, &*fs).unwrap();
    let leaked: Vec<String> = walk_files(alice.store(), &alice.snapshot(&out.snapshot).unwrap().tree)
        .unwrap()
        .into_iter()
        .map(|(p, _)| p.to_string())
        .filter(|p| p == ".env" || p.starts_with("deploy/"))
        .collect();
    assert!(
        leaked.is_empty(),
        "isolated files recorded after merging a policy PR: {leaked:?} (merge warnings: {:?})",
        res.warnings
    );
}

/// The same through `pull` + `new origin/main`: whoever can push to the
/// shared remote can make every teammate's `.env` part of their next
/// snapshot.
#[test]
fn a_pulled_policy_cannot_publish_isolated_files() {
    let (mut mallory, mfs, _) = new_repo("mallory");
    let main = commit_files(&mut mallory, &*mfs, &[("README", "hi\n")], "v1");
    let main2 = commit_files(&mut mallory, &*mfs, &[(".veilpolicy", ".env public!\n")], "policy");
    let _ = main;
    mallory.set_tag("main", main2, false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut mallory, team.clone(), false, &[], false).unwrap();

    let (mut bob, bfs, _) = new_repo("bob");
    bfs.write(&p(".env"), b"STRIPE=sk_test_not_a_live_key_1234567890\nDB_PASSWORD=bob-local-Xk9mQ2vL7pR4\n").unwrap();
    snap(&mut bob, &*bfs);
    pull_and_checkout(&mut bob, &*bfs, team).unwrap();
    let wc = snap(&mut bob, &*bfs);
    assert!(file_entry(&bob, &wc, ".env").is_none(), "bob's .env was recorded after pulling a policy");
}

/// Control: a plain `public` rule from a merge cannot override a built-in
/// secret rule.
#[test]
fn a_merged_plain_public_rule_cannot_publish_dotenv() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".env"), b"DB_PASSWORD=prod-hunter2-Xk9mQ2vL7pR4\n").unwrap();
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    let pr_ws = alice.ephemeral_workspace(main).unwrap();
    pr_ws.write(".veilpolicy", ".env public\n").unwrap();
    let (pr, _) = alice.commit_ephemeral(&pr_ws, "policy").unwrap();
    alice.merge(WS, main, vec![pr], "merge PR", None).unwrap();
    checkout_wc(&mut alice, &*fs, main);
    let wc = snap(&mut alice, &*fs);
    assert!(file_entry(&alice, &wc, ".env").is_none());
}

// ---- gc and fsck over embargo wrappers ------------------------------------------------

/// Every file of every visible snapshot can be read.
fn all_readable(r: &Repo) -> Result<usize, String> {
    let mut n = 0;
    for id in r.exact().visible().map_err(|e| e.to_string())? {
        let Some(s) = r.exact().snapshot(&id).map_err(|e| e.to_string())? else { continue };
        let files = walk_files(r.store(), &s.tree).map_err(|e| format!("{}: {e}", id.short()))?;
        for (path, e) in files {
            r.store().read_entry(&e).map_err(|err| format!("{} {path}: {err}", id.short()))?;
            n += 1;
        }
    }
    Ok(n)
}

fn prune(r: &mut Repo) {
    let rep = gc(
        r,
        &GcOptions {
            grace: Duration::ZERO,
            ..GcOptions::default()
        },
    )
    .unwrap();
    assert!(rep.incomplete.is_empty(), "{:?}", rep.incomplete);
}

/// Two embargoes, follow-up commits, releases in both orders, with gc
/// --prune-now after every step: nothing a key holder can see may be
/// collected, and fsck stays clean. (Overlapping embargoes are refused in
/// Veil 1.0, so the second fix is embargoed on a separate line cut from the
/// pre-merge `main`, where it may legitimately coexist with the first.)
#[test]
fn gc_on_a_store_full_of_wrappers_keeps_everything_readable() {
    for release_first in [0usize, 1] {
        let (mut alice, fs, _) = new_repo("alice");
        let main = commit_files(
            &mut alice,
            &*fs,
            &[("a/x.rs", "x1\n"), ("a/y.rs", "y1\n"), ("b/z.rs", "z1\n"), ("README", "r\n")],
            "v1",
        );
        alice.set_tag("main", main, false).unwrap();
        let mut embargoes = Vec::new();
        for (i, path) in ["a/x.rs", "b/z.rs"].into_iter().enumerate() {
            let tip = if i == 0 { alice.view().tags["main"].target } else { main };
            let ws = alice.ephemeral_workspace(main).unwrap();
            ws.write(path, format!("fixed {i}\n")).unwrap();
            ws.write(&format!("a/new{i}/deep/file.rs"), format!("new {i}\n")).unwrap();
            let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
            let r = alice.merge(WS, tip, vec![fix], "fix", embargo("team")).unwrap();
            if i == 1 {
                alice.set_tag("release", r.snapshot, false).unwrap();
            }
            embargoes.push(r.embargo.unwrap());
            prune(&mut alice);
            assert!(all_readable(&alice).is_ok(), "{:?}", all_readable(&alice));
        }
        let tip = alice.view().tags["main"].target;
        checkout_wc(&mut alice, &*fs, main);
        fs.write(&p("a/y.rs"), b"y2 follow-up\n").unwrap();
        snap(&mut alice, &*fs);
        alice.commit_working_copy(WS, "follow-up").unwrap();
        let _ = tip;
        prune(&mut alice);
        assert!(all_readable(&alice).is_ok(), "{:?}", all_readable(&alice));
        let order = if release_first == 0 { [0, 1] } else { [1, 0] };
        for i in order {
            alice.release_embargo(&embargoes[i]).unwrap();
            prune(&mut alice);
            assert!(all_readable(&alice).is_ok(), "{:?}", all_readable(&alice));
            let f = veil_core::fsck::fsck_repo(&alice).unwrap();
            assert!(f.is_ok(), "{:#?}", f.findings);
        }
        // A public clone of the fully released history is complete too.
        let mirror = Arc::new(MemoryBackend::new());
        remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
        let anon = Repo::open(mirror, Some(Identity::generate("anon")), "anon").unwrap();
        assert!(all_readable(&anon).is_ok(), "{:?}", all_readable(&anon));
    }
}

/// A non-holder's clone of a team remote (it holds wrappers it cannot open)
/// collects nothing it would need after the release.
#[test]
fn gc_by_a_non_holder_keeps_what_the_release_will_reveal() {
    let (mut alice, fs, _) = new_repo("alice");
    alice.keys().create_scope("sec").unwrap();
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2 fixed\n").unwrap();
    ws.write("docs/advisory.md", "advisory\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let r = alice.merge(WS, main, vec![fix], "fix", embargo("sec")).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();

    let bfs = Arc::new(MemoryBackend::new());
    let mut bob = Repo::init_for_clone(bfs, Some(Identity::generate("bob")), "bob").unwrap();
    remote::pull(&mut bob, "origin", team.clone()).unwrap();
    prune(&mut bob);
    alice.release_embargo(r.embargo.as_deref().unwrap()).unwrap();
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();
    // Bob learns of the release but pulls from a remote that, by now, has
    // nothing new for him except the record.
    remote::pull(&mut bob, "origin", team).unwrap();
    assert_eq!(read_at(&bob, &r.snapshot, "docs/advisory.md"), b"advisory\n");
}
