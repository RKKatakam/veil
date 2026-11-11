//! Reproductions from the re-check of the client and engine fixes
//! (`rc-client`, 2026-11-11) that need the server: each test shows a fix
//! that is incomplete or that another fix broke, and is ignored under its
//! `docs/BUGS.md` row until the bug is fixed.

use veil_core::object::{Conflict, ConflictTerm, EntryKind, Object as O, Visibility};

use crate::support::*;

/// `vl` writes nothing the server refuses for good (BUG-1833's guarantee):
/// a secret renamed to an ordinary name stays sealed, two changes edit it,
/// and the conflict between them is resolved in a change of its own, as
/// `vl commit` after a conflicting `vl rebase` records it. The resolution
/// is a sealed file whose parent holds a conflict of sealed versions at
/// that path, which is a secret's content by `vl`'s own reading of the
/// rule (`Transaction::reconcile_sealing`, `upgrade::removed_content`), and
/// not by the server's (`sync.rs`, `sealed_secret_here`: a conflict entry's
/// own label is public): "'settings-staging.txt' is not a secret file: only
/// secret files are encrypted", for that push and every later one.
#[test]
fn bug_1930_a_resolved_conflict_in_a_renamed_secret_is_accepted() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let secret = format!("{BILL_DIR}/.env.staging");
    let name = "settings-staging.txt";
    write_files(&p.dir, &[(&secret, "REGION=one\n")]);
    p.admin.commit_main(&p.dir, "the staging secret");
    p.admin.ok(&p.dir, &["push"]);
    std::fs::rename(p.dir.join(&secret), p.dir.join(name)).unwrap();
    p.admin.commit_main(&p.dir, "rename the staging settings");
    p.admin.ok(&p.dir, &["push"]);
    // Two edits of the renamed secret, side by side.
    write_files(&p.dir, &[(name, "REGION=two\n")]);
    p.admin.commit_main(&p.dir, "region two");
    p.admin.ok(&p.dir, &["push"]);
    p.admin.ok(&p.dir, &["new", "main-"]);
    write_files(&p.dir, &[(name, "REGION=three\n")]);
    p.admin.ok(&p.dir, &["commit", "-m", "region three"]);
    let out = p.admin.ok(&p.dir, &["rebase", "-s", "@-", "-d", "main"]);
    assert!(out.contains("conflicts in: settings-staging.txt"), "control: the rebase conflicts: {out}");
    // Resolved in the working copy, committed as its own change.
    write_files(&p.dir, &[(name, "REGION=four\n")]);
    p.admin.commit_main(&p.dir, "region four, resolved");
    let files = p.admin.ok(&p.dir, &["files", "-r", "main"]);
    assert!(files.lines().any(|l| l.contains(name) && l.contains("cloaked:")), "control: the resolution stays sealed: {files}");
    let out = p.admin.run(&p.dir, &["push"]);
    let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "the push of what vl itself recorded was refused: {all}");
}

/// BUG-1930's fix widens nothing else: "only secret files are encrypted".
/// A parent's conflict explains a sealed file at its path only if one of
/// its versions is sealed. On a parent that holds an ordinary conflict
/// there (every version plain), a sealed file at an ordinary path is still
/// refused, and so is one beside a parent's conflict at another path.
#[test]
fn bug_1930_a_sealed_file_on_an_ordinary_conflict_is_still_refused() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    // An ordinary conflict at an ordinary path, accepted.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let term = |c: &mut Craft, t: &str| {
        let id = c.put(O::Blob(t.as_bytes().to_vec()));
        Some(ConflictTerm { kind: Default::default(), id, size: t.len() as u64, executable: false, visibility: Visibility::Public })
    };
    let (a, b, base) = (term(&mut c, "ours\n"), term(&mut c, "theirs\n"), term(&mut c, "base\n"));
    c.set_kind("src/notes.txt", O::Conflict(Conflict { adds: vec![a, b], removes: vec![base] }), EntryKind::Conflict, Visibility::Public);
    let r = c.push("main", "an ordinary conflict");
    assert_eq!(r.status, 200, "control: the ordinary conflict is accepted: {}", String::from_utf8_lossy(&r.body));
    let tip = || api.tips(Some(&token), &p.name).unwrap().branches["main"];
    let conflicted = tip();

    let env = veil_core::crypto::Envelope::seal_random(&[7u8; 32], "team#k1", b"fn hidden() {}").unwrap();
    for path in ["src/notes.txt", "src/other.txt"] {
        let mut c = Craft::new(&api, &p.dev, &p.name, "main");
        assert_eq!(c.tip, conflicted, "control: built on the conflicted snapshot");
        c.set(path, O::Sealed(env.clone()), Visibility::Cloaked { scope: "team".into() });
        let r = c.push("main", "sealed code where a conflict was");
        assert_eq!(r.status, 403, "{path}: {}", String::from_utf8_lossy(&r.body));
        assert!(
            String::from_utf8_lossy(&r.body).contains(&format!("'{path}' is not a secret file: only secret files are encrypted")),
            "{path}: {}",
            String::from_utf8_lossy(&r.body)
        );
    }
    assert_eq!(tip(), conflicted);
}
