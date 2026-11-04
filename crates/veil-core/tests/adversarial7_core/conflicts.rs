//! Hostile (or merely large) conflict objects.

use std::{sync::mpsc, time::Duration};

use veil_core::{
    conflict::{materialize, Audience},
    object::{Conflict, ConflictTerm},
};

use crate::adversarial_support::{blob, file, new_repo};

/// `n` lines, each `prefix` and its number.
fn lines(prefix: &str, n: usize) -> Vec<u8> {
    (0..n).map(|i| format!("{prefix} line {i}\n")).collect::<String>().into_bytes()
}

/// Run `f` on a thread; `None` if it takes longer than `limit`.
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).ok()
}

/// Control: a small conflict of the same shape materialises at once, with
/// markers.
#[test]
fn a_small_conflict_of_rewritten_files_materialises() {
    let (repo, _fs, _id) = new_repo("alice");
    let term = |data: &[u8]| {
        let mut e = file("a.txt", blob(&repo, data));
        e.size = data.len() as u64;
        Some(ConflictTerm::of(&e))
    };
    let c = Conflict { adds: vec![term(&lines("ours", 200)), term(&lines("theirs", 200))], removes: vec![term(&lines("base", 200))] };
    let m = materialize(repo.store(), &c, Audience::Reader).unwrap();
    assert!(String::from_utf8_lossy(&m.content).contains("<<<<<<<"));
}

/// A conflict entry is materialised (`conflict::materialize`, diffy's
/// `merge_bytes` at `conflict.rs:493`) by every command that looks at it,
/// for every reader: the checkout, and `vl status`, `vl ls` (three times
/// per entry: `entry_tier`, `conflict_view`, `conflict_info`), `vl diff`,
/// `vl show`, `vl resolve --list`, the Git export, and the builder on each
/// snapshot that sees the file changed. diffy's three-way merge is
/// quadratic in the number of differing lines: two rewritten versions of a
/// 10,000-line file take 25 s per `vl status` and 38 s per `vl ls` (debug
/// build), 5,000 lines a quarter of that. A teammate's (or a hostile
/// remote's) conflicted merge of a large generated file (a lockfile, a
/// minified bundle) therefore stalls every command of everyone who checks
/// it out, and keeps doing so until someone resolves it; nothing caps the
/// size or falls back to a whole-file conflict. 20,000 lines of about 20
/// bytes (400 KB) a side should take well under the 20 s allowed here.
#[test]
#[ignore = "BUG-484: materialising a conflict of two large rewrites is quadratic (remote-triggerable stall)"]
fn a_conflict_of_two_large_rewrites_materialises_in_reasonable_time() {
    let (repo, _fs, _id) = new_repo("alice");
    let term = |data: &[u8]| {
        let mut e = file("big.lock", blob(&repo, data));
        e.size = data.len() as u64;
        Some(ConflictTerm::of(&e))
    };
    let n = 20_000;
    let c = Conflict { adds: vec![term(&lines("ours", n)), term(&lines("theirs", n))], removes: vec![term(&lines("base", n))] };
    let store = repo.store().clone();
    let done = within(Duration::from_secs(20), move || materialize(&store, &c, Audience::Reader).map(|m| m.content.len()));
    assert!(done.is_some(), "materialising a {n}-line conflict took more than 20 s");
}
