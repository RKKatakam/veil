//! Hostile (or merely large) conflict objects.

use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

use veil_core::{
    conflict::{inspect, materialize, parse_markers, Audience, Style},
    object::{Conflict, ConflictTerm},
    textmerge,
};

use super::adversarial_support::{blob, file, new_repo};

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
///
/// Fixed: diffs and merges are bounded (`veil_core::textmerge`); past the
/// work limit the conflict holds every side whole.
#[test]
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
    let done = within(Duration::from_secs(20), move || materialize(&store, &c, Audience::Reader));
    let m = done.expect("materialising a 20,000-line conflict took more than 20 s").unwrap();
    // One conflict, every version whole, parsed back exactly.
    assert!(matches!(m.style, Style::Diff3 { base_shown: true, .. }));
    let (o, b, t) = parse_markers(&m.content, &m.style).expect("markers parse");
    assert_eq!((o, b, t), (lines("ours", n), lines("base", n), lines("theirs", n)));
}

/// A named `(base, ours, theirs)`.
type Crafted = (&'static str, Vec<u8>, Vec<u8>, Vec<u8>);

/// Crafted versions for a three-way merge of `n` lines: `(base, ours,
/// theirs)` shaped against Myers's diff (no line shared, the order
/// reversed or interleaved, every other line changed on each side,
/// repeated lines in another rhythm).
fn crafted(n: usize) -> Vec<Crafted> {
    let join = |v: Vec<String>| v.concat().into_bytes();
    let numbered: Vec<String> = (0..n).map(|i| format!("entry {i}\n")).collect();
    let reversed: Vec<String> = numbered.iter().rev().cloned().collect();
    let rotated: Vec<String> = numbered[n / 2..].iter().chain(&numbered[..n / 2]).cloned().collect();
    let evens_first: Vec<String> = numbered.iter().step_by(2).chain(numbered.iter().skip(1).step_by(2)).cloned().collect();
    let odds_first: Vec<String> = numbered.iter().skip(1).step_by(2).chain(numbered.iter().step_by(2)).cloned().collect();
    let every_other = |side: &str, parity: usize| -> Vec<u8> {
        join(numbered.iter().enumerate().map(|(i, l)| if i % 2 == parity { format!("{side} {i}\n") } else { l.clone() }).collect())
    };
    vec![
        ("rewrites", lines("base", n), lines("ours", n), lines("theirs", n)),
        ("reversed", join(numbered.clone()), join(reversed), join(rotated)),
        ("interleaved", join(numbered.clone()), join(evens_first), join(odds_first)),
        ("every other line", join(numbered.clone()), every_other("ours", 0), every_other("theirs", 1)),
        ("rhythm", "a\n".repeat(n).into_bytes(), "a\nb\n".repeat(n / 2).into_bytes(), "b\na\nc\n".repeat(n / 3).into_bytes()),
    ]
}

/// BUG-484, as BUG-090's test for the scanner: rendering a conflict, a
/// clean three-way merge (`vl merge`, rebases, virtual bases) and a diff
/// (`vl diff`, `vl split`) take time linear in the input on input crafted
/// against Myers's diff: 8 times the lines must not take much more than 8
/// times as long. (diffy alone took 64 times as long: 25 s for two
/// rewritten 10,000-line versions.)
#[test]
fn conflict_and_diff_time_is_linear_on_crafted_input() {
    let (repo, _fs, _id) = new_repo("alice");
    let term = |data: &[u8]| {
        let mut e = file("big.lock", blob(&repo, data));
        e.size = data.len() as u64;
        Some(ConflictTerm::of(&e))
    };
    let time = |f: &dyn Fn()| {
        let t = Instant::now();
        f();
        t.elapsed()
    };
    let (small, large) = (2_500, 20_000);
    let mut report = Vec::new();
    for ((name, b1, o1, t1), (_, b8, o8, t8)) in crafted(small).into_iter().zip(crafted(large)) {
        let render = |b: &[u8], o: &[u8], t: &[u8]| {
            let c = Conflict { adds: vec![term(o), term(t)], removes: vec![term(b)] };
            std::hint::black_box(materialize(repo.store(), &c, Audience::Reader).unwrap());
        };
        let merge = |b: &[u8], o: &[u8], t: &[u8]| {
            let _ = std::hint::black_box(textmerge::merge(b, o, t, 7, textmerge::Style::Diff3));
        };
        let diff = |b: &[u8], o: &[u8]| {
            let (b, o) = (String::from_utf8_lossy(b), String::from_utf8_lossy(o));
            let d = veil_core::hunks::diff_text(&b, &o);
            std::hint::black_box(d);
        };
        type Timed<'a> = (&'a str, &'a dyn Fn(), &'a dyn Fn());
        let cases: [Timed; 3] = [
            ("render", &|| render(&b1, &o1, &t1), &|| render(&b8, &o8, &t8)),
            ("merge", &|| merge(&b1, &o1, &t1), &|| merge(&b8, &o8, &t8)),
            ("diff", &|| diff(&b1, &o1), &|| diff(&b8, &o8)),
        ];
        for (what, f1, f8) in cases {
            let ts = time(f1).min(time(f1));
            let tl = time(f8);
            eprintln!("{what} {name}: {small} lines {ts:?}, {large} lines {tl:?}");
            if tl > ts * 24 + Duration::from_millis(300) {
                report.push(format!("{what} {name}: {small} lines {ts:?}, {large} lines {tl:?}"));
            }
        }
    }
    assert!(report.is_empty(), "superlinear:\n{}", report.join("\n"));
}

/// `vl status`, `vl ls`, `vl log` and the JSON output describe a conflict
/// with `conflict::inspect`, which never merges the sides' text, and
/// agrees with what checkout materialises.
#[test]
fn inspecting_a_conflict_agrees_with_materialising_it_and_never_merges() {
    let (repo, _fs, _id) = new_repo("alice");
    let term = |data: &[u8], exec: bool| {
        let mut e = file("f", blob(&repo, data));
        e.size = data.len() as u64;
        e.executable = exec;
        Some(ConflictTerm::of(&e))
    };
    let shapes = [
        Conflict { adds: vec![term(b"a\nB\n", false), term(b"a\nC\n", true)], removes: vec![term(b"a\nb\n", false)] },
        Conflict { adds: vec![term(b"x\n", true), None], removes: vec![term(b"y\n", true)] },
        Conflict { adds: vec![term(b"\0bin", false), term(b"\0other", false)], removes: vec![None] },
        Conflict { adds: vec![term(b"1\n", false), term(b"2\n", false), term(b"3\n", false)], removes: vec![term(b"0\n", false), term(b"0\n", false)] },
    ];
    for c in &shapes {
        let m = materialize(repo.store(), c, Audience::Reader).unwrap();
        let v = inspect(repo.store(), c, Audience::Reader).unwrap();
        assert_eq!(
            (v.executable, v.visibility, v.fallback, v.winner, v.redacted, v.unreadable_side),
            (m.executable, m.visibility, m.fallback, m.winner, m.redacted, m.unreadable_side)
        );
    }
    // A conflict whose rendering spends the whole work limit (the order
    // of 200,000 lines reversed): inspecting it reads the versions only.
    let n = 200_000;
    let numbered: Vec<String> = (0..n).map(|i| format!("entry {i}\n")).collect();
    let base = numbered.concat().into_bytes();
    let ours = numbered.iter().rev().cloned().collect::<String>().into_bytes();
    let theirs = numbered[1..].concat().into_bytes();
    let c = Conflict { adds: vec![term(&ours, false), term(&theirs, false)], removes: vec![term(&base, false)] };
    let t = Instant::now();
    let m = materialize(repo.store(), &c, Audience::Reader).unwrap();
    let rendering = t.elapsed();
    let t = Instant::now();
    let v = inspect(repo.store(), &c, Audience::Reader).unwrap();
    let inspecting = t.elapsed();
    assert_eq!((v.redacted, v.unreadable_side), (m.redacted, m.unreadable_side));
    assert!(inspecting * 3 < rendering, "inspect {inspecting:?}, materialize {rendering:?}");
}
