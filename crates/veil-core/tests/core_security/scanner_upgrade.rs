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

/// BUG-1985's rules version 8: the rescan after the upgrade releases a file
/// the old `url-password` rule held back for random bytes, and only that:
/// a file that also holds another rule's match, or a real URL password,
/// stays quarantined (and is not carried forward).
#[test]
fn the_rescan_after_bug_1985_releases_only_files_the_new_rules_pass() {
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(Identity::generate("a")), "a").unwrap();
    // 68 random bytes the rules version 7 took for a URL password.
    let hex = "155a96f6c76843cd3a2f2f641a8342768e7eb7e79503483a8cd60489138f0eb0b130f3d453dc588a3d8494aaa6b32e51c4d1f3fedf934db59ef3043894d493dd40732df5";
    let random: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    let mut with_key = random.clone();
    with_key.extend(b"\naws = AKIAIOSFODNN7EXAMPLE\n");
    let mut with_url = random.clone();
    with_url.extend(b"\nDATABASE_URL=postgres://app:Xk9mQ2vL7pR4@db.example.com/app\n");
    fs.write(&p("random.bin"), &random).unwrap();
    fs.write(&p("key.bin"), &with_key).unwrap();
    fs.write(&p("url.bin"), &with_url).unwrap();
    // The device last scanned with rules version 7.
    fs.write(&p(".veil/local/scanned/default.version"), b"7").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    let mut held: Vec<String> = out.report.quarantined.iter().map(|(p, _)| p.to_string()).collect();
    held.sort();
    assert_eq!(held, ["key.bin", "url.bin"], "{:?}", out.report.quarantined);
    let rules = |path: &str| -> Vec<&str> {
        let (_, f) = out.report.quarantined.iter().find(|(p, _)| p.as_str() == path).unwrap();
        f.iter().map(|f| f.rule).collect()
    };
    assert_eq!(rules("key.bin"), ["aws-access-key-id"]);
    assert_eq!(rules("url.bin"), ["url-password"]);
    let tree = repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree;
    let in_tree = |path: &str| lookup(repo.store(), &tree, &p(path)).unwrap().is_some();
    assert!(in_tree("random.bin"), "the random file is released");
    assert!(!in_tree("key.bin") && !in_tree("url.bin"));
    let marker = fs.read(&p(".veil/local/scanned/default.version")).unwrap();
    assert_eq!(String::from_utf8(marker).unwrap(), "8");
}
