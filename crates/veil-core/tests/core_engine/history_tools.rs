//! The history read tools of the Git-parity round (stream H): `blame`,
//! `grep`, the `log` filters (`search`), revset ranges and `bisect`'s graph
//! functions. Each point of the designs' threat reviews that the engine
//! owns is a test here (`docs/design/git-parity/1-…`, `3-…`); the CLI suite
//! (`crates/vl/tests/cli_features/history_cli.rs`) covers the rest.

use crate::adversarial_support;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    bisect::{self, Step},
    blame::{blame, BlameOptions, Origin, Reader, Stop, Unattributed},
    commands::EmbargoSpec,
    grep::{self, GrepOptions, Tier},
    object::{TreeEntry, Visibility},
    remote, revset,
    search::{LogFilter, Match, Pickaxe, Searcher},
    vfs::OverlayBackend,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

const TEAM: &str = "team";
const SECRET: &str = "SECRET-PLAN-77310";

/// Write `files` in workspace `ws` (an overlay over its working copy) and
/// record them. Returns the workspace's new snapshot.
fn record_in(repo: &mut Repo, ws: &str, files: &[(&str, &str)]) -> ObjectId {
    let overlay: OverlayBackend = repo.workspace_overlay(ws).unwrap();
    for (path, data) in files {
        overlay.write(&p(path), data.as_bytes()).unwrap();
    }
    repo.snapshot_workspace(ws, &overlay).unwrap().snapshot
}

fn commit_in(repo: &mut Repo, ws: &str, files: &[(&str, &str)], msg: &str) -> ObjectId {
    record_in(repo, ws, files);
    repo.commit(ws, msg, true).unwrap().committed
}

/// A reader of the same store who holds no key.
fn outsider_of(fs: Arc<MemoryBackend>) -> Repo {
    Repo::open(fs, Some(Identity::generate("mallory")), "mallory").unwrap()
}

fn mirror_of(alice: &mut Repo) -> Repo {
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(alice, mirror.clone(), true, &[], false).unwrap();
    Repo::open(mirror, Some(Identity::generate("carol")), "carol").unwrap()
}

/// The snapshot each line is attributed to (`None`: unattributed).
fn origins(r: &Repo, rev: &ObjectId, path: &str, o: &BlameOptions) -> Vec<Option<ObjectId>> {
    blame(r, rev, &p(path), o)
        .unwrap()
        .lines
        .iter()
        .map(|l| match &l.origin {
            Origin::Snapshot { id, .. } => Some(*id),
            Origin::Unattributed(_) => None,
        })
        .collect()
}

fn me() -> BlameOptions {
    BlameOptions::default()
}

// ---- blame -------------------------------------------------------------------------------

#[test]
fn blame_attributes_each_line_to_the_change_that_introduced_it() {
    let (mut r, fs, _) = new_repo("alice");
    let c1 = commit_files(&mut r, &*fs, &[("f", "a\nb\nc\n")], "one");
    let c2 = commit_files(&mut r, &*fs, &[("f", "a\nB\nc\nd\n")], "two");
    let c3 = commit_files(&mut r, &*fs, &[("f", "z\na\nB\nc\nd\n"), ("other", "x\n")], "three");
    assert_eq!(origins(&r, &c3, "f", &me()), [Some(c3), Some(c1), Some(c2), Some(c1), Some(c2)]);
    // -L: only those lines.
    let o = BlameOptions { lines: Some((2, 3)), ..me() };
    let b = blame(&r, &c3, &p("f"), &o).unwrap();
    assert_eq!(b.lines.iter().map(|l| l.number).collect::<Vec<_>>(), [2, 3]);
    assert_eq!(b.lines[0].text, b"a\n");
    // An unchanged file: every line from its one change.
    assert_eq!(origins(&r, &c3, "other", &me()), [Some(c3)]);
}

#[test]
fn blame_follows_a_rename_only_when_asked() {
    let (mut r, fs, _) = new_repo("alice");
    let c1 = commit_files(&mut r, &*fs, &[("old.rs", "one\ntwo\nthree\nfour\n")], "one");
    fs.remove_file(&p("old.rs")).unwrap();
    let c2 = commit_files(&mut r, &*fs, &[("new.rs", "one\ntwo\nthree\nfour\nfive\n")], "moved");
    assert_eq!(origins(&r, &c2, "new.rs", &me()), vec![Some(c2); 5]);
    let follow = BlameOptions { follow: true, ..me() };
    let b = blame(&r, &c2, &p("new.rs"), &follow).unwrap();
    assert!(matches!(&b.lines[0].origin, Origin::Snapshot { id, path } if *id == c1 && path.as_str() == "old.rs"));
    assert!(matches!(&b.lines[4].origin, Origin::Snapshot { id, .. } if *id == c2));
}

#[test]
fn blame_through_a_merge_takes_the_first_parent_holding_a_line() {
    let (mut r, fs, _) = new_repo("alice");
    let base = commit_files(&mut r, &*fs, &[("f", "1\n2\n3\n")], "base");
    r.set_tag("main", base, false).unwrap();
    r.create_workspace("side", vec![base]).unwrap();
    let s1 = commit_in(&mut r, "side", &[("f", "1\n2\n3\nside\n")], "side");
    let ours = commit_files(&mut r, &*fs, &[("f", "top\n1\n2\n3\n")], "ours");
    let m = r.merge(WS, ours, vec![s1], "merge", None).unwrap().snapshot;
    let got = origins(&r, &m, "f", &me());
    assert_eq!(got, [Some(ours), Some(base), Some(base), Some(base), Some(s1)]);
}

/// Past the line-diff work limit, the differing middle goes to the
/// snapshot whole (`coarse`), the shared start and end still pass on.
#[test]
fn a_diff_past_its_limit_is_coarse_not_wrong() {
    let (mut r, fs, _) = new_repo("alice");
    let body = |tag: &str| -> String { (0..20_000).map(|i| format!("{tag} {i}\n")).collect() };
    let c1 = commit_files(&mut r, &*fs, &[("f", &format!("head\n{}tail\n", body("a")))], "one");
    let c2 = commit_files(&mut r, &*fs, &[("f", &format!("head\n{}tail\n", body("b")))], "two");
    let b = blame(&r, &c2, &p("f"), &me()).unwrap();
    assert!(b.coarse);
    assert!(matches!(&b.lines[0].origin, Origin::Snapshot { id, .. } if *id == c1));
    assert!(matches!(&b.lines.last().unwrap().origin, Origin::Snapshot { id, .. } if *id == c1));
    assert!(matches!(&b.lines[1].origin, Origin::Snapshot { id, .. } if *id == c2));
}

/// A chain of raw snapshots, each with `f` = `content(i)`.
fn raw_chain(r: &Repo, n: usize, content: impl Fn(usize) -> String) -> ObjectId {
    let mut parent = r.root_id();
    for i in 0..n {
        let tree = raw_tree(r, vec![file("f", blob(r, content(i).as_bytes()))]);
        parent = raw_snapshot(r, vec![parent], tree, "x");
    }
    parent
}

/// Threat review 4: a long hostile history. Each snapshot rewriting the
/// whole file ends the walk at once; each keeping one old line open (and
/// forcing a full diff) is stopped by the work budget, reported, never
/// guessed.
#[test]
fn hostile_histories_are_bounded_by_the_budget() {
    let (r, _, _) = new_repo("alice");
    let n_lines = 2_000;
    let rewrite = raw_chain(&r, 300, |i| (0..n_lines).map(|l| format!("v{i} line {l}\n")).collect());
    let t = Instant::now();
    let b = blame(&r, &rewrite, &p("f"), &me()).unwrap();
    assert_eq!(b.visited, 1, "everything is attributed at the first step");
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    // One line survives every rewrite, at the very end; the rest changes.
    let keep_one = raw_chain(&r, 300, |i| {
        let mut s: String = (0..n_lines).map(|l| format!("v{i} line {l}\n")).collect();
        s.push_str("the one old line\n");
        s
    });
    let o = BlameOptions { work_budget: 50_000_000, ..me() };
    let t = Instant::now();
    let b = blame(&r, &keep_one, &p("f"), &o).unwrap();
    let took = t.elapsed();
    eprintln!("measured: blame of a hostile 300-snapshot, 2 000-line history (budget 5e7): {took:?}, {} visits", b.visited);
    assert!(b.visited < 300);
    assert_eq!(b.stopped, Some(Stop::Budget));
    assert_eq!(b.lines.last().unwrap().origin, Origin::Unattributed(Unattributed::Budget));
    assert!(took < Duration::from_secs(if cfg!(debug_assertions) { 30 } else { 2 }), "{took:?}");
    // The default budget, in a release build: bounded in time too.
    if !cfg!(debug_assertions) {
        let t = Instant::now();
        let b = blame(&r, &keep_one, &p("f"), &me()).unwrap();
        eprintln!("measured: the same with the default budget: {:?}, {} visits", t.elapsed(), b.visited);
        assert_eq!(b.stopped, Some(Stop::Budget));
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    }
    // --max-changes.
    let o = BlameOptions { max_changes: 3, ..me() };
    let b = blame(&r, &keep_one, &p("f"), &o).unwrap();
    assert_eq!((b.visited, b.stopped), (3, Some(Stop::MaxChanges)));
    assert_eq!(b.unattributed(), 1);
}

/// Linear in the history's length: 8 times the snapshots (each editing
/// one line, the rest passed on) take about 8 times as long.
#[test]
fn blame_time_is_linear_in_the_history() {
    let (r, _, _) = new_repo("alice");
    let content = |i: usize| -> String {
        let mut s: String = (0..400).map(|l| format!("line {l}\n")).collect();
        s.push_str(&format!("changed {i}\n"));
        s
    };
    let small = raw_chain(&r, 150, content);
    let large = raw_chain(&r, 1_200, content);
    let time = |id: &ObjectId| {
        let t = Instant::now();
        let b = blame(&r, id, &p("f"), &me()).unwrap();
        assert!(b.stopped.is_none(), "ordinary edits stay far below the budget");
        std::hint::black_box(b);
        t.elapsed()
    };
    let ts = time(&small).min(time(&small));
    let tl = time(&large);
    assert!(tl < ts * 24 + Duration::from_millis(500), "superlinear: 150 {ts:?}, 1200 {tl:?}");
}

/// Threat review 5: an octopus merge of 64 parents and a 1 000-deep
/// criss-cross finish within the budget, each snapshot visited once.
#[test]
fn octopus_and_criss_cross_histories_visit_each_snapshot_once() {
    let (r, _, _) = new_repo("alice");
    let base_text: String = (0..64).map(|i| format!("line {i}\n")).collect();
    let base = raw_snapshot(&r, vec![r.root_id()], raw_tree(&r, vec![file("f", blob(&r, base_text.as_bytes()))]), "base");
    let mut parents = Vec::new();
    for k in 0..64 {
        let t: String = (0..64).map(|i| if i == k { format!("edited {i}\n") } else { format!("line {i}\n") }).collect();
        parents.push(raw_snapshot(&r, vec![base], raw_tree(&r, vec![file("f", blob(&r, t.as_bytes()))]), "p"));
    }
    let all: String = (0..64).map(|i| format!("edited {i}\n")).collect();
    let octopus = raw_snapshot(&r, parents.clone(), raw_tree(&r, vec![file("f", blob(&r, all.as_bytes()))]), "octopus");
    let b = blame(&r, &octopus, &p("f"), &me()).unwrap();
    assert!(b.stopped.is_none());
    for (k, l) in b.lines.iter().enumerate() {
        assert!(matches!(&l.origin, Origin::Snapshot { id, .. } if *id == parents[k]), "line {k}");
    }
    // A criss-cross ladder: each rung merges both previous rungs.
    let mut a = base;
    let mut c = base;
    for i in 0..1_000 {
        let t = format!("{base_text}rung {i}\n");
        let tree = raw_tree(&r, vec![file("f", blob(&r, t.as_bytes()))]);
        let na = raw_snapshot(&r, vec![a, c], tree, "a");
        let nc = raw_snapshot(&r, vec![c, a], tree, "c");
        a = na;
        c = nc;
    }
    let t = Instant::now();
    let b = blame(&r, &a, &p("f"), &me()).unwrap();
    eprintln!("measured: blame through a 1 000-rung criss-cross: {:?}, {} visits", t.elapsed(), b.visited);
    assert!(b.stopped.is_none());
    assert!(b.visited <= 2_002, "each snapshot at most once: {}", b.visited);
    assert!(t.elapsed() < Duration::from_secs(if cfg!(debug_assertions) { 30 } else { 2 }), "{:?}", t.elapsed());
}

// ---- blame and confidentiality --------------------------------------------------------------

struct Cloaked {
    alice: Repo,
    fs: Arc<MemoryBackend>,
    edit: ObjectId,
}

/// Alice: `README.md` public on `main` (v1), then edited (publicly) in
/// workspace `p`, and a secret `.env.plan` (sealed for `team` by the
/// policy) edited twice there.
fn cloaked() -> Cloaked {
    let (mut alice, fs, _) = new_repo("alice");
    let v1 = commit_files(&mut alice, &*fs, &[("README.md", "a\nb\nc\n"), (".veilpolicy", ".env.plan cloak team\n")], "v1");
    alice.set_tag("main", v1, false).unwrap();
    alice.create_workspace("p", vec![v1]).unwrap();
    commit_in(&mut alice, "p", &[("README.md", "a\nb\nd 1\nc\n"), (".env.plan", &format!("{SECRET} plan\n"))], "plan");
    let edit = commit_in(&mut alice, "p", &[("README.md", "a\nb\nd 1\nc\nd 2\n"), (".env.plan", &format!("{SECRET} plan\n{SECRET} more\n"))], "plan 2");
    Cloaked { alice, fs, edit }
}

fn blame_text(r: &Repo, rev: &ObjectId, path: &str, o: &BlameOptions) -> String {
    let b = blame(r, rev, &p(path), o).unwrap();
    b.lines.iter().map(|l| format!("{:?} {}", l.origin, String::from_utf8_lossy(&l.text))).collect()
}

/// Threat review 3: an embargoed fix of line 10. The holder's blame sees
/// the fix; a mirror never receives the merge before the release (its
/// `main` is withheld with it; `stable` stays on v1).
#[test]
fn an_embargoed_fix_is_not_attributed_for_readers_without_the_key() {
    let (mut alice, fs, _) = new_repo("alice");
    let text: String = (1..=20).map(|i| format!("line {i}\n")).collect();
    let v1 = commit_files(&mut alice, &*fs, &[("src/vuln.c", &text)], "v1");
    alice.set_tag("main", v1, false).unwrap();
    alice.create_workspace("fix", vec![v1]).unwrap();
    let fixed = text.replace("line 10\n", "line 10 FIXED-BOUNDS-CHECK\n");
    let fix = commit_in(&mut alice, "fix", &[("src/vuln.c", &fixed)], "fix");
    let m = alice.merge(WS, v1, vec![fix], "embargoed", Some(EmbargoSpec { scope: TEAM.into(), until: None })).unwrap().snapshot;
    let got = origins(&alice, &m, "src/vuln.c", &me());
    assert_eq!(got[9], Some(fix), "the holder sees the fix");
    alice.set_tag("stable", v1, false).unwrap();
    let carol = mirror_of(&mut alice);
    assert!(carol.snapshot_opt(&m).unwrap().is_none() && carol.snapshot_opt(&fix).unwrap().is_none());
    assert!(!carol.view().tags.contains_key("main"), "main, moved onto the embargoed merge, was pushed");
    let stable = carol.view().tags["stable"].target;
    assert_eq!(stable, v1);
    assert!(!blame_text(&carol, &stable, "src/vuln.c", &me()).contains("FIXED"));
    drop(fs);
}

// ---- grep --------------------------------------------------------------------------------

fn grep_of(r: &Repo, rev: &ObjectId, pattern: &str, o: &GrepOptions) -> grep::Grep {
    let tree = r.snapshot(rev).unwrap().tree;
    grep::grep(r.store(), &tree, &grep::compile(pattern, o).unwrap(), o).unwrap()
}

#[test]
fn grep_searches_the_snapshot_with_its_options() {
    let (mut r, fs, _) = new_repo("alice");
    let c = commit_files(&mut r, &*fs, &[("a.txt", "Key one\nkey two\nmonkey\n"), ("dir/b.txt", "no\nkey\n"), ("bin", "key\0binary\n")], "c");
    let g = grep_of(&r, &c, "key", &GrepOptions::default());
    let files: Vec<(&str, usize)> = g.files.iter().map(|f| (f.path.as_str(), f.count)).collect();
    assert_eq!(files, [("a.txt", 2), ("bin", 1), ("dir/b.txt", 1)]);
    assert!(g.files[1].binary && g.files[1].lines.is_empty());
    assert_eq!(g.skipped.binary, 1);
    let ci = GrepOptions { ignore_case: true, word: true, ..GrepOptions::default() };
    assert_eq!(grep_of(&r, &c, "key", &ci).files[0].count, 2);
    let only = GrepOptions { paths: vec![p("dir")], ..GrepOptions::default() };
    assert_eq!(grep_of(&r, &c, "key", &only).files.len(), 1);
    let one = GrepOptions { max_count: Some(1), ..GrepOptions::default() };
    assert_eq!(grep_of(&r, &c, "key", &one).files[0].count, 1);
    let text = GrepOptions { text: true, ..GrepOptions::default() };
    assert_eq!(grep_of(&r, &c, "key", &text).files[1].lines.len(), 1);
    assert_eq!(grep_of(&r, &c, "key", &text).files[0].lines[0].number, 2);
}

/// Threat review 2 and 12: grep without the key opens no sealed object,
/// counts the secrets as sealed, and finds no sealed text.
#[test]
fn grep_without_the_key_never_reads_ciphertext() {
    let Cloaked { alice, fs, edit, .. } = cloaked();
    let mallory = outsider_of(fs);
    let g = grep_of(&mallory, &edit, ".", &GrepOptions::default());
    assert_eq!(g.stats.sealed_opened, 0);
    assert_eq!(g.stats.open_failed, 0);
    assert_eq!(g.skipped.sealed, 1, ".env.plan");
    let readme = g.files.iter().find(|f| f.path.as_str() == "README.md").unwrap();
    assert_eq!(readme.tier, Tier::Public);
    assert!(grep_of(&mallory, &edit, SECRET, &GrepOptions::default()).files.is_empty());
    let public = GrepOptions { reader: Reader::Public, ..GrepOptions::default() };
    let g = grep_of(&alice, &edit, SECRET, &public);
    assert!(g.files.is_empty() && g.stats.sealed_opened == 0);
    // The member finds the secret, labelled cloaked.
    let g = grep_of(&alice, &edit, SECRET, &GrepOptions::default());
    assert_eq!(g.files.len(), 1);
    assert!(g.files.iter().all(|f| f.tier == Tier::Cloaked(TEAM.into())));
}

/// Threat review 6: a pathological pattern over a large file is linear;
/// a huge pattern is refused; a long line is cut.
#[test]
fn grep_is_linear_on_hostile_patterns_and_input() {
    let (mut r, fs, _) = new_repo("alice");
    let mb = if cfg!(debug_assertions) { 8 } else { 50 };
    let big = "a".repeat(mb << 20);
    let c = commit_files(&mut r, &*fs, &[("big", &big)], "big");
    for pattern in ["(a*)*b", "(a|aa)+$b", "a{1,1000}b"] {
        let t = Instant::now();
        let g = grep_of(&r, &c, pattern, &GrepOptions::default());
        eprintln!("measured: grep {pattern:?} over {mb} MiB: {:?}", t.elapsed());
        assert!(g.files.is_empty(), "{pattern}");
        assert!(t.elapsed() < Duration::from_secs(if cfg!(debug_assertions) { 60 } else { 2 }), "{pattern}: {:?}", t.elapsed());
    }
    let g = grep_of(&r, &c, "a", &GrepOptions::default());
    assert!(g.files[0].lines[0].truncated);
    assert_eq!(g.files[0].lines[0].text.len(), grep::MAX_LINE);
    assert!(grep::compile(&"x".repeat(100 << 10), &GrepOptions::default()).is_err());
    assert!(grep::compile(&"x".repeat(100 << 10), &GrepOptions { fixed: true, ..GrepOptions::default() }).is_err());
}

// ---- log filters --------------------------------------------------------------------------

fn search(r: &Repo, f: LogFilter) -> Vec<(ObjectId, Match)> {
    let mut s = Searcher::new(r, f);
    r.visible_snapshots().unwrap().into_iter().map(|id| (id, s.check(&id).unwrap())).filter(|(_, m)| *m != Match::No).collect()
}

fn listed(v: &[(ObjectId, Match)]) -> Vec<ObjectId> {
    v.iter().filter(|(_, m)| matches!(m, Match::Yes { .. })).map(|(id, _)| *id).collect()
}

#[test]
fn path_author_and_pickaxe_filters() {
    let (mut r, fs, _) = new_repo("alice");
    let c1 = commit_files(&mut r, &*fs, &[("src/a.rs", "fn a() {}\n"), ("doc.md", "x\n")], "one");
    let c2 = commit_files(&mut r, &*fs, &[("doc.md", "y\n")], "two");
    let c3 = commit_files(&mut r, &*fs, &[("src/a.rs", "fn a() {}\nfn needle() {}\n")], "three");
    let c4 = commit_files(&mut r, &*fs, &[("src/a.rs", "fn a() {}\nfn needle() { 1 }\n")], "four");
    let paths = LogFilter { paths: vec![p("src")], ..LogFilter::default() };
    assert_eq!(listed(&search(&r, paths)), [c4, c3, c1]);
    let s = LogFilter { pickaxe: Some(Pickaxe::string("needle", false).unwrap()), ..LogFilter::default() };
    assert_eq!(listed(&search(&r, s)), [c3], "-S: only where the count changes");
    let g = LogFilter { pickaxe: Some(Pickaxe::regex("needle", false).unwrap()), ..LogFilter::default() };
    assert_eq!(listed(&search(&r, g)), [c4, c3], "-G: any added or removed line");
    let ci = LogFilter { pickaxe: Some(Pickaxe::string("NEEDLE", true).unwrap()), ..LogFilter::default() };
    assert_eq!(listed(&search(&r, ci)), [c3]);
    let author = LogFilter { author: Some(veil_core::search::compile_regex("^ali", false).unwrap()), paths: vec![p("doc.md")], ..LogFilter::default() };
    assert_eq!(listed(&search(&r, author)), [c2, c1]);
    let nobody = LogFilter { author: Some(veil_core::search::compile_regex("^bob$", false).unwrap()), ..LogFilter::default() };
    assert!(listed(&search(&r, nobody)).is_empty());
    // A pure rename changes no count.
    fs.remove_file(&p("doc.md")).unwrap();
    let c5 = commit_files(&mut r, &*fs, &[("moved.md", "y\n")], "move");
    let s = LogFilter { pickaxe: Some(Pickaxe::string("y", false).unwrap()), ..LogFilter::default() };
    assert!(!listed(&search(&r, s)).contains(&c5));
    // --follow: the moved file's history goes on under its old name.
    let follow = LogFilter { paths: vec![p("moved.md")], follow: true, ..LogFilter::default() };
    assert_eq!(listed(&search(&r, follow)), [c5, c2, c1]);
}

/// Threat review 9: authors are claims; `--signed-by` checks signatures.
#[test]
fn signed_by_matches_the_verified_signer_not_the_author_claim() {
    let (mut r, fs, _) = new_repo("alice");
    let good = commit_files(&mut r, &*fs, &[("f", "1\n")], "real");
    let tree = r.snapshot(&good).unwrap().tree;
    // Mallory writes "alice" as the author, unsigned.
    let mut forged = (*r.snapshot(&good).unwrap()).clone();
    forged.parents = vec![good];
    forged.signature = None;
    forged.tree = tree;
    forged.description = veil_core::object::Text::Plain("forged".into());
    let forged = r.store().put_snapshot(&forged).unwrap();
    let mut s = Searcher::new(&r, LogFilter { signed_by: Some("alice".into()), ..LogFilter::default() });
    assert_eq!(s.check(&good).unwrap(), Match::Yes { files: vec![] });
    assert_eq!(s.check(&forged).unwrap(), Match::No);
    let mut s = Searcher::new(&r, LogFilter { author: Some(veil_core::search::compile_regex("alice", false).unwrap()), ..LogFilter::default() });
    assert!(matches!(s.check(&forged).unwrap(), Match::Yes { .. }), "the claim matches --author");
}

/// Threat review 3: `-S` on a sealed string. A member finds the change;
/// a non-member and the public view never do (the snapshot is skipped,
/// not counted on ciphertext).
#[test]
fn pickaxe_never_counts_what_the_reader_cannot_read() {
    let Cloaked { alice, fs, edit, .. } = cloaked();
    let f = |reader| LogFilter { pickaxe: Some(Pickaxe::string(SECRET, false).unwrap()), reader, ..LogFilter::default() };
    let mine = search(&alice, f(Reader::Me));
    assert!(listed(&mine).contains(&edit));
    let mallory = outsider_of(fs);
    for (who, r, reader) in [("mallory", &mallory, Reader::Me), ("alice as public", &alice, Reader::Public)] {
        let got = search(r, f(reader));
        assert!(listed(&got).is_empty(), "{who}: {got:?}");
        assert!(got.iter().any(|(id, m)| *id == edit && matches!(m, Match::Skipped { .. })), "{who}: {got:?}");
    }
    let g = |reader| LogFilter { pickaxe: Some(Pickaxe::regex(SECRET, false).unwrap()), reader, ..LogFilter::default() };
    assert!(listed(&search(&mallory, g(Reader::Me))).is_empty());
}

/// Threat review 4: an embargoed fix of `src/vuln.c`. Neither the path
/// filter nor `-S` on the fixed line lists the fix or the merge for a
/// mirror reader (the mirror never receives them before the release).
#[test]
fn log_filters_do_not_reveal_an_embargoed_fix() {
    let (mut alice, fs, _) = new_repo("alice");
    let v1 = commit_files(&mut alice, &*fs, &[("src/vuln.c", "check(x);\n"), ("README", "r\n")], "v1");
    alice.set_tag("main", v1, false).unwrap();
    alice.create_workspace("fix", vec![v1]).unwrap();
    let fix = commit_in(&mut alice, "fix", &[("src/vuln.c", "check(x); BOUNDS-FIX-4411\n")], "fix");
    let m = alice.merge(WS, v1, vec![fix], "embargoed", Some(EmbargoSpec { scope: TEAM.into(), until: None })).unwrap().snapshot;
    let path = || LogFilter { paths: vec![p("src/vuln.c")], ..LogFilter::default() };
    let pick = || LogFilter { pickaxe: Some(Pickaxe::string("BOUNDS-FIX-4411", false).unwrap()), ..LogFilter::default() };
    assert!(listed(&search(&alice, path())).contains(&fix));
    assert!(listed(&search(&alice, pick())).contains(&fix));
    alice.set_tag("stable", v1, false).unwrap();
    let carol = mirror_of(&mut alice);
    drop(fs);
    let got = listed(&search(&carol, path()));
    assert!(!got.contains(&m) && !got.contains(&fix), "{got:?}");
    let got = search(&carol, pick());
    assert!(listed(&got).is_empty(), "{got:?}");
    assert!(!got.iter().any(|(id, _)| *id == m || *id == fix), "the merge is not even skipped");
}

// ---- revsets ----------------------------------------------------------------------------

#[test]
fn ranges_are_dag_differences() {
    let (mut r, fs, _) = new_repo("alice");
    let c1 = commit_files(&mut r, &*fs, &[("f", "1\n")], "1");
    let c2 = commit_files(&mut r, &*fs, &[("f", "2\n")], "2");
    let c3 = commit_files(&mut r, &*fs, &[("f", "3\n")], "3");
    r.set_tag("one", c1, false).unwrap();
    r.set_tag("three", c3, false).unwrap();
    let set = |s: &str| revset::resolve_set(&r, s, WS).unwrap();
    assert_eq!(set("one..three"), [c3, c2]);
    assert_eq!(set("::one"), [c1, r.root_id()]);
    assert_eq!(set("..one"), [c1]);
    assert_eq!(set("three"), [c3]);
    assert!(set("three..").iter().all(|id| *id != c3 && *id != c1));
    for bad in ["one..two..three", "::", "nope..three", ""] {
        assert!(revset::resolve_set(&r, bad, WS).is_err(), "{bad:?}");
    }
}

// ---- bisect ------------------------------------------------------------------------------

#[test]
fn bisect_finds_the_first_bad_snapshot_in_log_steps() {
    let (r, _, _) = new_repo("alice");
    let mut chain = vec![r.root_id()];
    for i in 0..100 {
        let tree = raw_tree(&r, vec![file("f", blob(&r, format!("{i}\n").as_bytes()))]);
        chain.push(raw_snapshot(&r, vec![*chain.last().unwrap()], tree, "x"));
    }
    let first_bad = 63;
    let (mut good, mut bad, mut steps) = (vec![chain[1]], chain[100], 0);
    loop {
        match bisect::next(&r, &bad, &good, &[]).unwrap() {
            Step::Test { candidate, .. } => {
                steps += 1;
                let i = chain.iter().position(|c| *c == candidate).unwrap();
                if i >= first_bad {
                    bad = candidate;
                } else {
                    good.push(candidate);
                }
            }
            Step::Found(id) => {
                assert_eq!(id, chain[first_bad]);
                break;
            }
            s => panic!("{s:?}"),
        }
    }
    assert!(steps <= 8, "{steps} steps for 99 candidates");
    // All skipped: undecided.
    let s = bisect::next(&r, &chain[3], &[chain[1]], &[chain[2]]).unwrap();
    assert_eq!(s, Step::Undecided { bad: chain[3], skipped: vec![chain[2]] });
    // A bad snapshot that is an ancestor of a good one.
    assert!(bisect::next(&r, &chain[2], &[chain[5]], &[]).is_err());
}

#[test]
fn bisect_over_a_merge_searches_the_whole_dag_difference() {
    let (r, _, _) = new_repo("alice");
    let t = |s: &str| raw_tree(&r, vec![file("f", blob(&r, s.as_bytes()))]);
    let base = raw_snapshot(&r, vec![r.root_id()], t("b"), "base");
    let a = raw_snapshot(&r, vec![base], t("a"), "a");
    let b = raw_snapshot(&r, vec![base], t("bb"), "b");
    let m = raw_snapshot(&r, vec![a, b], t("m"), "m");
    let c = bisect::candidates(&r, &m, &[base]).unwrap();
    assert_eq!(c.len(), 3);
    assert!(c.contains(&a) && c.contains(&b) && c[0] == m);
}

// ---- properties: confidentiality ---------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Random histories mixing public commits and edits of secret files
    /// sealed for `team` (some carrying the secret marker): an outsider's
    /// and the public view's blame, grep and pickaxe never return the
    /// marker, never open a sealed object, and never fail.
    #[test]
    fn history_tools_never_return_sealed_text_to_readers_without_the_key(
        steps in proptest::collection::vec((any::<bool>(), 0u8..3, 0u8..4), 1..8),
    ) {
        let (mut alice, fs, _) = new_repo("alice");
        let base = commit_files(
            &mut alice,
            &*fs,
            &[("a.txt", "one\ntwo\n"), ("b.txt", "x\n"), (".env.a", "one\ntwo\n"), (".veilpolicy", ".env.* cloak team\n")],
            "base",
        );
        alice.set_tag("main", base, false).unwrap();
        alice.create_workspace("p", vec![base]).unwrap();
        let mut last = base;
        for (i, (cloaked, file, kind)) in steps.iter().enumerate() {
            let name = if *cloaked { [".env.a", ".env.b", ".env.c"] } else { ["a.txt", "b.txt", "c.txt"] }[*file as usize];
            let text = match kind {
                0 => format!("one\ntwo\nline {i}\n"),
                1 => format!("one\n{SECRET} {i}\ntwo\n"),
                2 => format!("{SECRET}\n"),
                _ => "one\n".to_string(),
            };
            if *cloaked {
                last = commit_in(&mut alice, "p", &[(name, &text)], "cloaked");
            } else if !text.contains(SECRET) {
                last = commit_files(&mut alice, &*fs, &[(name, &text)], "public");
            }
        }
        let mallory = outsider_of(fs);
        for (r, reader) in [(&mallory, Reader::Me), (&alice, Reader::Public)] {
            for rev in r.visible_snapshots().unwrap() {
                let tree = r.snapshot(&rev).unwrap().tree;
                for (path, e) in veil_core::tree::walk_files(r.store(), &tree).unwrap() {
                    let o = BlameOptions { reader, ..BlameOptions::default() };
                    match blame(r, &rev, &path, &o) {
                        Ok(b) => {
                            prop_assert_eq!(b.stats.sealed_opened, 0);
                            for l in &b.lines {
                                prop_assert!(!String::from_utf8_lossy(&l.text).contains(SECRET));
                            }
                        }
                        Err(err) => prop_assert!(err.is_unreadable(), "{err}"),
                    }
                    let _: &TreeEntry = &e;
                }
                let go = GrepOptions { reader, ..GrepOptions::default() };
                let g = grep::grep(r.store(), &tree, &grep::compile(SECRET, &go).unwrap(), &go).unwrap();
                prop_assert!(g.files.is_empty());
                prop_assert_eq!(g.stats.sealed_opened, 0);
            }
            let f = LogFilter { pickaxe: Some(Pickaxe::string(SECRET, false).unwrap()), reader, ..LogFilter::default() };
            prop_assert!(listed(&search(r, f)).is_empty());
        }
        let _ = (last, Visibility::Public);
    }
}

/// Design 3, threat 7: `-S` over a long history with large files is lazy
/// (the first match comes back without searching the rest) and linear in
/// the size of what it reads.
#[test]
fn pickaxe_is_lazy_and_linear() {
    let (r, _, _) = new_repo("alice");
    let big = blob(&r, &vec![b'y'; 1 << 20]);
    let mut parent = r.root_id();
    for i in 0..10_000 {
        let small = blob(&r, format!("{i}{}\n", if i == 9_999 { " needle" } else { "" }).as_bytes());
        let tree = raw_tree(&r, vec![file("big", big), file("small", small)]);
        parent = raw_snapshot(&r, vec![parent], tree, "x");
    }
    let mut s = Searcher::new(&r, LogFilter { pickaxe: Some(Pickaxe::string("needle", false).unwrap()), ..LogFilter::default() });
    let t = Instant::now();
    assert!(matches!(s.check(&parent).unwrap(), Match::Yes { .. }));
    assert_eq!(s.searched, 1);
    eprintln!("measured: log -S first match in a 10 000-snapshot history with a 1 MiB file: {:?}", t.elapsed());
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    // Counting is linear in the blob size.
    let time = |n: usize| {
        let (r, fs, _) = new_repo("bob");
        let _ = fs;
        let a = raw_snapshot(&r, vec![r.root_id()], raw_tree(&r, vec![file("f", blob(&r, &vec![b'a'; n]))]), "a");
        let b = raw_snapshot(&r, vec![a], raw_tree(&r, vec![file("f", blob(&r, &[vec![b'a'; n], b"needle".to_vec()].concat()))]), "b");
        let mut s = Searcher::new(&r, LogFilter { pickaxe: Some(Pickaxe::string("aaneedle", true).unwrap()), ..LogFilter::default() });
        let t = Instant::now();
        assert!(matches!(s.check(&b).unwrap(), Match::Yes { .. }));
        t.elapsed()
    };
    let (ts, tl) = (time(1 << 20).min(time(1 << 20)), time(8 << 20));
    assert!(tl < ts * 24 + Duration::from_millis(300), "superlinear: 1 MiB {ts:?}, 8 MiB {tl:?}");
}
