//! After the secret scanner's rules change, files an older scanner let
//! through must be re-scanned once instead of being trusted forever.

use std::sync::Arc;

use veil_core::{
    object::{EntryKind, Tree, TreeEntry, Visibility},
    tree::lookup,
    Identity, MemoryBackend, Repo, StorageBackend, VPath,
};

const WS: &str = "default";

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

#[test]
fn files_trusted_by_an_older_scanner_are_rescanned_once() {
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(Identity::generate("a")), "a").unwrap();
    repo.snapshot_workspace(WS, &*fs).unwrap();

    // Plant history as an older, weaker scanner would have recorded it: a
    // public file that contains a credential.
    let secret = b"aws = AKIAIOSFODNN7EXAMPLE\n";
    let blob = repo.store().store_file(secret, &Visibility::Public).unwrap();
    let mut t = Tree::default();
    t.insert(TreeEntry {
        name: "leak.txt".into(),
        kind: EntryKind::File,
        id: blob,
        size: secret.len() as u64,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
    });
    let tree = repo.store().put_tree(&t).unwrap();
    let wc = repo.workspace_wc(WS).unwrap();
    {
        let mut tx = repo.transaction("plant").unwrap();
        let mut s = (*tx.repo().snapshot(&wc).unwrap()).clone();
        s.tree = tree;
        s.predecessors = vec![wc];
        tx.rewrite(wc, s).unwrap();
        tx.commit().unwrap();
    }
    fs.write(&p("leak.txt"), secret).unwrap();
    let in_tree = |repo: &Repo| {
        let t = repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree;
        lookup(repo.store(), &t, &p("leak.txt")).unwrap().is_some()
    };

    // Same scanner as recorded: unchanged content is trusted (and cheap).
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(out.report.quarantined.is_empty());
    assert!(in_tree(&repo));

    // The device last scanned with older rules: everything is re-scanned.
    fs.write(&p(".veil/local/scanned/default.version"), b"1").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert_eq!(out.report.quarantined.len(), 1, "{:?}", out.report.quarantined);
    assert!(!in_tree(&repo), "an unsafe previous version must not be carried forward");

    // And only once.
    let marker = fs.read(&p(".veil/local/scanned/default.version")).unwrap();
    assert_eq!(String::from_utf8(marker).unwrap(), veil_core::secrets::RULES_VERSION.to_string());
}
