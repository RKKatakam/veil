//! Rename and copy detection (`rename.rs`, Git-parity feature 2, milestone
//! H1): the passes, the limits, and every point of the design's threat
//! review that detection itself owns (`docs/design/git-parity/2-renames.md`).

use crate::adversarial_support;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    blame::Reader,
    commands::EmbargoSpec,
    object::{EntryKind, TreeEntry, Visibility},
    remote,
    rename::{detect, detect_with_sources, Item, RenameOptions},
    tree::{diff_trees, TreeChange},
    Identity, MemoryBackend, ObjectId, Repo,
};

fn opts() -> RenameOptions {
    RenameOptions::default()
}

fn copies() -> RenameOptions {
    RenameOptions { copies: true, ..RenameOptions::default() }
}

fn entry(name: &str, id: ObjectId, size: usize) -> TreeEntry {
    TreeEntry { size: size as u64, ..file(name, id) }
}

fn added(repo: &Repo, path: &str, data: &str) -> TreeChange {
    let name = path.rsplit('/').next().unwrap();
    TreeChange { path: p(path), old: None, new: Some(entry(name, blob(repo, data.as_bytes()), data.len())) }
}

fn deleted(repo: &Repo, path: &str, data: &str) -> TreeChange {
    let name = path.rsplit('/').next().unwrap();
    TreeChange { path: p(path), old: Some(entry(name, blob(repo, data.as_bytes()), data.len())), new: None }
}

fn modified(repo: &Repo, path: &str, old: &str, new: &str) -> TreeChange {
    let name = path.rsplit('/').next().unwrap();
    TreeChange {
        path: p(path),
        old: Some(entry(name, blob(repo, old.as_bytes()), old.len())),
        new: Some(entry(name, blob(repo, new.as_bytes()), new.len())),
    }
}

fn lines(prefix: &str, n: usize) -> String {
    (0..n).map(|i| format!("{prefix} line number {i}\n")).collect()
}

/// `(from, to, score, copy)` of every pair.
fn pairs(d: &veil_core::rename::Detected) -> Vec<(String, String, u8, bool)> {
    d.pairs.iter().map(|p| (p.from.as_str().to_string(), p.to.as_str().to_string(), p.score, p.copy)).collect()
}

#[test]
fn an_exact_move_is_a_rename_and_leaves_no_deletion_or_addition() {
    let (r, _, _) = new_repo("alice");
    let body = lines("a", 20);
    let changes = vec![deleted(&r, "old/a.rs", &body), added(&r, "new/a.rs", &body), added(&r, "z.rs", "other\n")];
    let d = detect(r.store(), None, None, &changes, Reader::Me, &opts()).unwrap();
    assert_eq!(pairs(&d), [("old/a.rs".into(), "new/a.rs".into(), 100, false)]);
    assert_eq!(d.changes.iter().map(|c| c.path.as_str()).collect::<Vec<_>>(), ["z.rs"]);
    assert!(!d.truncated);
    // In the place of the destination's addition.
    let items = d.items();
    assert!(matches!(&items[0], Item::Pair(p) if p.to.as_str() == "new/a.rs"));
    assert!(matches!(&items[1], Item::Change(c) if c.path.as_str() == "z.rs"));
    assert_eq!(items.len(), 2);
}

#[test]
fn a_moved_and_edited_file_is_an_inexact_rename_with_its_score() {
    let (r, _, _) = new_repo("alice");
    let old = lines("a", 10);
    let new = format!("{}changed\n", lines("a", 9));
    let changes = vec![deleted(&r, "a.rs", &old), added(&r, "b.rs", &new)];
    let d = detect(r.store(), None, None, &changes, Reader::Me, &opts()).unwrap();
    let got = pairs(&d);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!((got[0].0.as_str(), got[0].1.as_str(), got[0].3), ("a.rs", "b.rs", false));
    assert!((80..100).contains(&got[0].2), "{got:?}");
    // Above the threshold: none.
    let strict = RenameOptions { threshold: 95, ..opts() };
    assert!(detect(r.store(), None, None, &changes, Reader::Me, &strict).unwrap().pairs.is_empty());
    // A wholly different file is never a rename.
    let unrelated = vec![deleted(&r, "a.rs", &old), added(&r, "b.rs", &lines("zzz", 10))];
    assert!(detect(r.store(), None, None, &unrelated, Reader::Me, &opts()).unwrap().pairs.is_empty());
}

#[test]
fn copies_are_detected_only_when_asked_and_keep_their_source() {
    let (r, _, _) = new_repo("alice");
    let body = lines("lib", 30);
    // `lib.rs` is modified and copied to `lib2.rs`.
    let changes = vec![modified(&r, "lib.rs", &body, &format!("{body}more\n")), added(&r, "lib2.rs", &body)];
    assert!(detect(r.store(), None, None, &changes, Reader::Me, &opts()).unwrap().pairs.is_empty());
    let d = detect(r.store(), None, None, &changes, Reader::Me, &copies()).unwrap();
    assert_eq!(pairs(&d), [("lib.rs".into(), "lib2.rs".into(), 100, true)]);
    assert_eq!(d.changes.len(), 1, "the source's own change stays");
    // From an unchanged file of the old tree (with its tree).
    let (mut r, fs, _) = new_repo("bob");
    let c = commit_files(&mut r, &*fs, &[("keep.rs", &body)], "v1");
    let tree = r.snapshot(&c).unwrap().tree;
    let changes = vec![added(&r, "copy.rs", &body)];
    let d = detect_with_sources(r.store(), Some(&tree), None, &changes, Reader::Me, &copies()).unwrap();
    assert_eq!(pairs(&d), [("keep.rs".into(), "copy.rs".into(), 100, true)]);
}

#[test]
fn a_deleted_source_is_renamed_once_and_otherwise_copied() {
    let (r, _, _) = new_repo("alice");
    let body = lines("x", 10);
    let changes = vec![deleted(&r, "a", &body), added(&r, "b", &body), added(&r, "c", &body)];
    let d = detect(r.store(), None, None, &changes, Reader::Me, &opts()).unwrap();
    assert_eq!(pairs(&d), [("a".into(), "b".into(), 100, false)]);
    assert_eq!(d.changes.iter().map(|c| c.path.as_str()).collect::<Vec<_>>(), ["c"]);
    let d = detect(r.store(), None, None, &changes, Reader::Me, &copies()).unwrap();
    assert_eq!(pairs(&d), [("a".into(), "b".into(), 100, false), ("a".into(), "c".into(), 100, true)]);
    assert!(d.changes.is_empty());
}

#[test]
fn the_same_file_name_is_preferred_among_equal_sources() {
    let (r, _, _) = new_repo("alice");
    let body = lines("x", 10);
    let changes = vec![deleted(&r, "a/one.rs", &body), deleted(&r, "b/two.rs", &body), added(&r, "c/two.rs", &body)];
    let d = detect(r.store(), None, None, &changes, Reader::Me, &opts()).unwrap();
    assert_eq!(pairs(&d), [("b/two.rs".into(), "c/two.rs".into(), 100, false)]);
}

#[test]
fn empty_files_never_pair() {
    let (r, _, _) = new_repo("alice");
    let changes = vec![deleted(&r, "a", ""), added(&r, "b", "")];
    let d = detect(r.store(), None, None, &changes, Reader::Me, &copies()).unwrap();
    assert!(d.pairs.is_empty());
    assert_eq!(d.changes.len(), 2);
}

/// Threat review 7: several deleted files are similar to one added file
/// (each destination gets one source, best score first), and one source
/// copied 10 000 times stays linear in the output.
#[test]
fn many_to_one_pairs_are_assigned_greedily_and_linearly() {
    let (r, _, _) = new_repo("alice");
    let base = lines("m", 20);
    let near = format!("{}tail\n", lines("m", 19));
    let far = format!("{}t1\nt2\nt3\nt4\n", lines("m", 16));
    let changes = vec![deleted(&r, "far", &far), deleted(&r, "near", &near), added(&r, "dst", &base)];
    let d = detect(r.store(), None, None, &changes, Reader::Me, &opts()).unwrap();
    assert_eq!(d.pairs.len(), 1);
    assert_eq!(d.pairs[0].from.as_str(), "near");
    // 10 000 identical copies of one deleted file.
    let body = lines("copy", 3);
    let mut changes = vec![deleted(&r, "src", &body)];
    let id = blob(&r, body.as_bytes());
    for i in 0..10_000 {
        let name = format!("c{i:05}");
        changes.push(TreeChange { path: p(&name), old: None, new: Some(entry(&name, id, body.len())) });
    }
    let t = Instant::now();
    let d = detect(r.store(), None, None, &changes, Reader::Me, &copies()).unwrap();
    eprintln!("measured: 10 000 copies of one file: {:?}", t.elapsed());
    assert_eq!(d.pairs.len(), 10_000);
    assert_eq!(d.pairs.iter().filter(|p| !p.copy).count(), 1, "renamed once");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
}

/// Threat review 6: a change deleting 50 000 files and adding 50 000
/// similar ones. The inexact pass is skipped (`truncated`), exact pairs are
/// still found, quickly.
#[test]
fn a_hostile_number_of_files_skips_the_inexact_pass() {
    let (r, _, _) = new_repo("alice");
    let mut changes = Vec::new();
    let shared = blob(&r, b"exactly the same\n");
    for i in 0..50_000 {
        let (a, b) = (format!("old/f{i:05}"), format!("new/f{i:05}"));
        // Distinct ids, but similar content (never read).
        let old = blob(&r, format!("{}{i}\n", lines("h", 3)).as_bytes());
        let new = blob(&r, format!("{}{i}x\n", lines("h", 3)).as_bytes());
        changes.push(TreeChange { path: p(&a), old: Some(entry(&format!("f{i:05}"), old, 80)), new: None });
        changes.push(TreeChange { path: p(&b), old: None, new: Some(entry(&format!("f{i:05}"), new, 80)) });
    }
    changes.push(TreeChange { path: p("x/same"), old: Some(entry("same", shared, 17)), new: None });
    changes.push(TreeChange { path: p("y/same"), old: None, new: Some(entry("same", shared, 17)) });
    changes.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    let t = Instant::now();
    let d = detect(r.store(), None, None, &changes, Reader::Me, &opts()).unwrap();
    let took = t.elapsed();
    eprintln!("measured: rename detection over 50 000 deletions + 50 000 additions: {took:?}");
    assert!(d.truncated);
    assert_eq!(pairs(&d), [("x/same".into(), "y/same".into(), 100, false)]);
    assert_eq!(d.changes.len(), 100_000);
    // Release builds take a few milliseconds; debug builds are much slower.
    assert!(took < Duration::from_secs(if cfg!(debug_assertions) { 20 } else { 1 }), "{took:?}");
}

/// The byte budget and the size cap stop the inexact pass too.
#[test]
fn the_byte_budget_stops_the_inexact_pass() {
    let (r, _, _) = new_repo("alice");
    let old = lines("b", 200);
    let new = format!("{}x\n", lines("b", 199));
    let changes = vec![deleted(&r, "a", &old), added(&r, "b", &new)];
    let tight = RenameOptions { budget: 100, ..opts() };
    let d = detect(r.store(), None, None, &changes, Reader::Me, &tight).unwrap();
    assert!(d.truncated && d.pairs.is_empty());
    let few = RenameOptions { limit: 0, ..opts() };
    assert!(detect(r.store(), None, None, &changes, Reader::Me, &few).unwrap().truncated);
    assert_eq!(detect(r.store(), None, None, &changes, Reader::Me, &opts()).unwrap().pairs.len(), 1);
}

/// Doubling the number of files about doubles the time of the exact pass
/// (no quadratic path), on the worst shape: every file has the same id.
#[test]
fn exact_detection_time_is_linear_in_the_files() {
    let (r, _, _) = new_repo("alice");
    let id = blob(&r, b"same\n");
    let make = |n: usize| -> Vec<TreeChange> {
        let mut v = Vec::new();
        for i in 0..n {
            v.push(TreeChange { path: p(&format!("d/f{i:06}")), old: Some(entry(&format!("f{i:06}"), id, 5)), new: None });
            v.push(TreeChange { path: p(&format!("e/g{i:06}")), old: None, new: Some(entry(&format!("g{i:06}"), id, 5)) });
        }
        v
    };
    let time = |c: &[TreeChange]| {
        let t = Instant::now();
        std::hint::black_box(detect(r.store(), None, None, c, Reader::Me, &copies()).unwrap());
        t.elapsed()
    };
    let (small, large) = (make(4_000), make(32_000));
    let ts = time(&small).min(time(&small));
    let tl = time(&large);
    assert!(tl < ts * 24 + Duration::from_millis(300), "superlinear: 4k {ts:?}, 32k {tl:?}");
}

// ---- confidentiality -------------------------------------------------------------------

const SECRET: &str = "CLOAKED-RENAME-PLAINTEXT-5521";

/// Alice's repository with a cloaked file, and a reader of the same store
/// who holds no key.
fn sealed_world() -> (Repo, Repo, ObjectId, ObjectId) {
    let (alice, fs, _) = new_repo("alice");
    let vis = Visibility::Cloaked { scope: "team".into() };
    let body = format!("{SECRET}\n{}", lines("s", 20));
    let sealed = alice.store().store_file(body.as_bytes(), &vis).unwrap();
    let edited = alice.store().store_file(format!("{body}one more\n").as_bytes(), &vis).unwrap();
    let outsider = Repo::open(fs, Some(Identity::generate("mallory")), "mallory").unwrap();
    (alice, outsider, sealed, edited)
}

fn sealed_entry(name: &str, id: ObjectId) -> TreeEntry {
    TreeEntry { visibility: Visibility::Cloaked { scope: "team".into() }, size: 900, ..file(name, id) }
}

/// Threat review 5: a reader without the key pairs sealed files by exact
/// id only, and never opens a sealed object (or tries to). A member pairs
/// the edited copy too.
#[test]
fn sealed_content_pairs_only_by_exact_id_without_the_key() {
    let (alice, outsider, sealed, edited) = sealed_world();
    let changes = vec![
        TreeChange { path: p("secrets/a.yml"), old: Some(sealed_entry("a.yml", sealed)), new: None },
        TreeChange { path: p("secrets/b.yml"), old: Some(sealed_entry("b.yml", sealed)), new: None },
        TreeChange { path: p("config/a.yml"), old: None, new: Some(sealed_entry("a.yml", sealed)) },
        TreeChange { path: p("config/b.yml"), old: None, new: Some(sealed_entry("b.yml", edited)) },
    ];
    let d = detect(outsider.store(), None, None, &changes, Reader::Me, &opts()).unwrap();
    assert_eq!(pairs(&d), [("secrets/a.yml".into(), "config/a.yml".into(), 100, false)]);
    assert_eq!(d.stats.sealed_opened, 0, "{:?}", d.stats);
    assert_eq!(d.stats.open_failed, 0, "{:?}", d.stats);
    // The member reads both and pairs the edit.
    let d = detect(alice.store(), None, None, &changes, Reader::Me, &opts()).unwrap();
    assert_eq!(d.pairs.len(), 2, "{:?}", pairs(&d));
    // As the public sees it, the member pairs exactly too, and opens nothing.
    let d = detect(alice.store(), None, None, &changes, Reader::Public, &opts()).unwrap();
    assert_eq!(d.pairs.len(), 1);
    assert_eq!(d.stats.sealed_opened, 0);
}

/// Threat review 9: a conflict entry pairs only with an equal conflict id,
/// and never with a file of the same content.
#[test]
fn conflict_entries_pair_only_by_exact_id() {
    let (r, _, _) = new_repo("alice");
    let id = blob(&r, lines("c", 10).as_bytes());
    let conflict = TreeEntry { kind: EntryKind::Conflict, ..file("c", id) };
    let changes = vec![
        TreeChange { path: p("a"), old: Some(conflict.clone()), new: None },
        TreeChange { path: p("b"), old: None, new: Some(file("b", id)) },
        TreeChange { path: p("c"), old: None, new: Some(conflict) },
    ];
    let d = detect(r.store(), None, None, &changes, Reader::Me, &copies()).unwrap();
    assert_eq!(pairs(&d), [("a".into(), "c".into(), 100, false)]);
}

/// Threat review 8: an embargoed fix renames `a.c` to `b.c`. The key
/// holder's detection on the merge sees it; the public mirror receives
/// nothing of the merge (no rename, no `b.c`) before the release.
#[test]
fn a_rename_inside_an_embargo_is_invisible_to_outsiders() {
    let (mut alice, fs, _) = new_repo("alice");
    let body = lines("vuln", 20);
    let main = commit_files(&mut alice, &*fs, &[("a.c", &body), ("README", "hi\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    alice.create_workspace("fix", vec![main]).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    veil_core::StorageBackend::remove_file(&ov, &p("a.c")).unwrap();
    veil_core::StorageBackend::write(&ov, &p("b.c"), format!("{body}patched\n").as_bytes()).unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let m = alice.merge(WS, main, vec![fix], "embargoed fix", Some(EmbargoSpec { scope: "team".into(), until: None })).unwrap();
    let s = alice.snapshot(&m.snapshot).unwrap();
    let first = alice.snapshot(&s.parents[0]).unwrap().tree;
    let changes = diff_trees(alice.store(), Some(&first), Some(&s.tree)).unwrap();
    let d = detect(alice.store(), None, None, &changes, Reader::Me, &opts()).unwrap();
    assert!(d.pairs.iter().any(|p| p.to.as_str() == "b.c") || d.changes.iter().any(|c| c.path.as_str() == "b.c"), "alice sees the fix");
    // The public mirror.
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    let carol = Repo::open(mirror.clone(), Some(Identity::generate("carol")), "carol").unwrap();
    assert!(carol.exact().snapshot(&m.snapshot).unwrap().is_none(), "the embargoed merge reached the mirror");
    assert!(carol.exact().snapshot(&fix).unwrap().is_none(), "the fix reached the mirror");
    assert!(backend_contains(&*mirror, b"patched").is_empty(), "the fix's content reached the mirror");
}

// ---- properties --------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// On random change sets: each destination has at most one source; a
    /// deleted source is renamed at most once; renames pair a deletion with
    /// an addition; every input change is accounted for exactly once.
    #[test]
    fn pairs_are_a_partial_matching(
        dels in proptest::collection::vec(0u8..6, 0..12),
        adds in proptest::collection::vec(0u8..6, 0..12),
        with_copies in any::<bool>(),
    ) {
        let (r, _, _) = new_repo("alice");
        let content = |k: u8| format!("{}{k}\n", lines(&format!("c{}", k / 2), 6));
        let mut changes: Vec<TreeChange> = Vec::new();
        for (i, k) in dels.iter().enumerate() {
            changes.push(deleted(&r, &format!("d{i:02}"), &content(*k)));
        }
        for (i, k) in adds.iter().enumerate() {
            changes.push(added(&r, &format!("n{i:02}"), &content(*k)));
        }
        let o = RenameOptions { copies: with_copies, ..RenameOptions::default() };
        let d = detect(r.store(), None, None, &changes, Reader::Me, &o).unwrap();
        let mut to: Vec<&str> = d.pairs.iter().map(|p| p.to.as_str()).collect();
        to.sort();
        let n = to.len();
        to.dedup();
        prop_assert_eq!(n, to.len());
        let mut renamed: Vec<&str> = d.pairs.iter().filter(|p| !p.copy).map(|p| p.from.as_str()).collect();
        renamed.sort();
        let n = renamed.len();
        renamed.dedup();
        prop_assert_eq!(n, renamed.len());
        for p in &d.pairs {
            prop_assert!(p.from.as_str().starts_with('d'));
            prop_assert!(p.to.as_str().starts_with('n'));
            prop_assert!(p.score >= o.threshold);
            prop_assert!(with_copies || !p.copy);
        }
        // Accounting: kept changes + renamed sources + destinations = input.
        prop_assert_eq!(d.changes.len() + d.pairs.len() + renamed.len(), changes.len());
        prop_assert_eq!(d.items().len(), d.changes.len() + d.pairs.len());
    }
}
