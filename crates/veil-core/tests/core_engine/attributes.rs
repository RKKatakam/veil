//! Feature 7 (`.veilattributes`, line endings, diff and merge drivers): the
//! threat review of `docs/design/git-parity/7-attributes-line-endings.md`,
//! point by point, plus hostile attributes files and property tests.
//! The differential tests against Git are in `attributes_git.rs`; the CLI
//! side (device-local drivers, `vl attr`, `vl renormalize`) in
//! `crates/vl/tests/cli_features/attributes_cli.rs`.

use crate::adversarial_support;

use std::sync::{Arc, Mutex};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    attributes::{self, lf_to_crlf, Attrs, AttrSource, DeviceDrivers, DriverInput, DriverMerge},
    builder::LineEndings,
    checkout::Materialised,
    object::Visibility,
    remote,
    workspace::SnapshotOptions,
    EntryKind, Identity, MemoryBackend, ObjectId, Repo, StorageBackend, TreeEntry, VPath,
};

const AWS: &str = "aws_key=AKIAIOSFODNN7EXAMPLE";

fn tree_of(repo: &Repo, files: &[(&str, &[u8])]) -> ObjectId {
    let fs = MemoryBackend::new();
    for (path, data) in files {
        fs.write(&p(path), data).unwrap();
    }
    repo.build_from(&fs, None).unwrap().0
}

fn bytes_at(repo: &Repo, tree: &ObjectId, path: &str) -> Vec<u8> {
    let e = veil_core::tree::lookup(repo.store(), tree, &p(path)).unwrap().unwrap();
    repo.store().read_entry(&e).unwrap()
}

fn entry_at(repo: &Repo, tree: &ObjectId, path: &str) -> Option<TreeEntry> {
    veil_core::tree::lookup(repo.store(), tree, &p(path)).unwrap()
}

/// Snapshot `fs` (checked out as `rec` says) onto the default workspace.
fn snap_rec(repo: &mut Repo, fs: &dyn StorageBackend, rec: &Materialised) -> ObjectId {
    let out = repo
        .snapshot_workspace_with(WS, fs, SnapshotOptions { materialised: Some(rec), ..Default::default() })
        .unwrap();
    repo.snapshot(&out.snapshot).unwrap().tree
}

fn wc_tree(repo: &Repo) -> ObjectId {
    repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree
}

// ---- 1. attributes never disable secret scanning ----------------------------------------

#[test]
fn binary_attributes_never_switch_the_scanner_off() {
    for ga in ["* binary\n", "config.yml -text -diff -merge\n", "* text eol=crlf\n", "*.yml text=auto\n"] {
        let (mut repo, fs, _) = new_repo("alice");
        fs.write(&p(".veilattributes"), ga.as_bytes()).unwrap();
        fs.write(&p("config.yml"), format!("db: x\r\n{AWS}\r\n").as_bytes()).unwrap();
        let out = repo.snapshot_workspace(WS, &*fs).unwrap();
        assert!(
            out.report.quarantined.iter().any(|(q, _)| q.as_str() == "config.yml"),
            "{ga:?}: the key must be quarantined"
        );
        assert!(entry_at(&repo, &wc_tree(&repo), "config.yml").is_none());
    }
}

// ---- 2. the scanner sees exactly what is recorded ---------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Random CRLF/LF content with a secret planted on a random line, under
    /// random attributes: the secret is always found (the scanner reads the
    /// bytes about to be recorded, after conversion).
    #[test]
    fn planted_secrets_are_found_whatever_the_line_endings(
        lines in proptest::collection::vec("[a-z ]{0,12}", 1..8),
        at in 0usize..8,
        endings in proptest::collection::vec(0u8..3, 8),
        ga in prop::sample::select(vec!["", "* text\n", "* text=auto\n", "* eol=crlf\n", "* binary\n", "* -text\n", "* text eol=lf\n"]),
    ) {
        let (mut repo, fs, _) = new_repo("alice");
        let mut content = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            if i == at % lines.len() {
                content.extend_from_slice(AWS.as_bytes());
            }
            content.extend_from_slice(l.as_bytes());
            content.extend_from_slice(match endings[i] { 0 => b"\n" as &[u8], 1 => b"\r\n", _ => b"\r\n" });
        }
        fs.write(&p(".veilattributes"), ga.as_bytes()).unwrap();
        fs.write(&p("f.txt"), &content).unwrap();
        let out = repo.snapshot_workspace(WS, &*fs).unwrap();
        prop_assert!(out.report.quarantined.iter().any(|(q, _)| q.as_str() == "f.txt"));
    }

    /// Arbitrary bytes under every attribute combination: what is recorded
    /// is either the bytes themselves or their lossless LF form (every line
    /// ending CRLF, no lone CR), and a checkout under `eol=crlf` gives the
    /// original bytes back. Recording again changes nothing.
    #[test]
    fn conversion_is_lossless_or_does_not_happen(
        data in proptest::collection::vec(prop::sample::select(vec![b'a', b'\r', b'\n', 0u8, 0x1a, b' ', 0xff]), 0..40),
        ga in prop::sample::select(vec![
            "", "* text\n", "* -text\n", "* text=auto\n", "* eol=crlf\n", "* eol=lf\n", "* text=auto eol=crlf\n",
            "* binary\n", "* crlf\n", "* -crlf\n", "* text=input\n", "* binary eol=crlf\n",
        ]),
    ) {
        let (mut repo, fs, _) = new_repo("alice");
        fs.write(&p(".veilattributes"), ga.as_bytes()).unwrap();
        fs.write(&p("f.bin"), &data).unwrap();
        let out = repo.snapshot_workspace(WS, &*fs).unwrap();
        prop_assume!(out.report.quarantined.is_empty());
        let tree = wc_tree(&repo);
        let rec = bytes_at(&repo, &tree, "f.bin");
        if rec != data {
            let st = attributes::TextStat::of(&data);
            prop_assert!(st.lonecr == 0 && st.lonelf == 0, "a lossy conversion happened");
            prop_assert_eq!(lf_to_crlf(&rec), data.clone());
        }
        // Stable: recording the same working copy again changes nothing.
        let again = repo.snapshot_workspace(WS, &*fs).unwrap();
        prop_assert!(!again.changed);
        // A fresh checkout writes what the attributes say for it.
        let fresh = MemoryBackend::new();
        repo.checkout_tree(&fresh, None, &tree).unwrap();
        let conv = Attrs::for_backend(repo.store(), &*fs).for_path(&p("f.bin")).conversion;
        let want = attributes::to_worktree(&rec, conv).unwrap_or(rec.clone());
        prop_assert_eq!(fresh.read(&p("f.bin")).unwrap(), want.clone());
        if rec != data && conv.writes_crlf() {
            prop_assert_eq!(want, data);
        }
    }

    /// Byte-exactness: adding or changing `.veilattributes` never re-records
    /// a file by itself; only `vl renormalize` does, and only to the
    /// lossless form.
    #[test]
    fn attributes_alone_never_change_recorded_content(
        files in proptest::collection::vec(proptest::collection::vec(prop::sample::select(vec![b'x', b'\r', b'\n', 0u8]), 0..24), 1..5),
        ga in prop::sample::select(vec!["* text\n", "* text=auto\n", "* eol=crlf\n", "* -text\n", "* text eol=lf\n", "[attr]t text\n* t\n"]),
    ) {
        let (mut repo, fs, _) = new_repo("alice");
        for (i, f) in files.iter().enumerate() {
            fs.write(&p(&format!("f{i}")), f).unwrap();
        }
        snap(&mut repo, &*fs);
        let before = wc_tree(&repo);
        fs.write(&p(".veilattributes"), ga.as_bytes()).unwrap();
        snap(&mut repo, &*fs);
        let after = wc_tree(&repo);
        for i in 0..files.len() {
            let path = format!("f{i}");
            prop_assert_eq!(entry_at(&repo, &before, &path), entry_at(&repo, &after, &path));
        }
        // Renormalize everything.
        let all = |_: &VPath| true;
        repo.snapshot_workspace_with(WS, &*fs, SnapshotOptions { line_endings: LineEndings::Renormalize(&all), description: Some("renormalize".into()), ..Default::default() }).unwrap();
        let renorm = wc_tree(&repo);
        let attrs = Attrs::for_backend(repo.store(), &*fs);
        for (i, f) in files.iter().enumerate() {
            let path = format!("f{i}");
            let conv = attrs.for_path(&p(&path)).conversion;
            let want = match attributes::to_odb(f, conv, || false) {
                attributes::ToOdb::Converted(v) => v,
                _ => f.clone(),
            };
            prop_assert_eq!(bytes_at(&repo, &renorm, &path), want);
        }
    }
}

// ---- 4. checkout never overwrites an edit after an attribute change ---------------------

/// A working copy checked out (recorded) from a tree whose `.veilattributes`
/// says `eol=crlf`, then recorded with `-text`.
fn crlf_then_text_off() -> (Repo, Arc<MemoryBackend>, Materialised, ObjectId) {
    let (mut repo, fs, _) = new_repo("alice");
    let t1 = tree_of(&repo, &[(".veilattributes", b"*.txt eol=crlf\n"), ("a.txt", b"x\ny\n")]);
    let mut rec = Materialised::default();
    let empty = wc_tree(&repo);
    repo.checkout_tree_recorded(&*fs, Some(&empty), &t1, &mut rec, None).unwrap();
    assert_eq!(fs.read(&p("a.txt")).unwrap(), b"x\r\ny\r\n", "written with CRLF");
    assert!(rec.wrote_crlf(&p("a.txt")));
    let s1 = snap_rec(&mut repo, &*fs, &rec);
    assert_eq!(bytes_at(&repo, &s1, "a.txt"), b"x\ny\n", "the CRLF copy stands for the LF version");
    // The attributes change: the file is not re-recorded (it is still
    // exactly what checkout wrote).
    fs.write(&p(".veilattributes"), b"*.txt -text\n").unwrap();
    let s2 = snap_rec(&mut repo, &*fs, &rec);
    assert_eq!(entry_at(&repo, &s1, "a.txt"), entry_at(&repo, &s2, "a.txt"), "no silent re-recording");
    (repo, fs, rec, s2)
}

#[test]
fn an_unedited_file_is_updated_after_an_attribute_change() {
    let (repo, fs, mut rec, s2) = crlf_then_text_off();
    let t3 = tree_of(&repo, &[(".veilattributes", b"*.txt -text\n"), ("a.txt", b"x\ny\nz\n")]);
    let r = repo.checkout_tree_recorded(&*fs, Some(&s2), &t3, &mut rec, None).unwrap();
    assert!(r.kept_local.is_empty(), "{:?}", r.kept_local);
    assert_eq!(fs.read(&p("a.txt")).unwrap(), b"x\ny\nz\n");
    assert!(!rec.wrote_crlf(&p("a.txt")));
}

#[test]
fn an_edit_is_kept_after_an_attribute_change() {
    let (repo, fs, mut rec, s2) = crlf_then_text_off();
    fs.write(&p("a.txt"), b"x\r\ny\r\nmine\r\n").unwrap();
    let t3 = tree_of(&repo, &[(".veilattributes", b"*.txt -text\n"), ("a.txt", b"x\ny\nz\n")]);
    let r = repo.checkout_tree_recorded(&*fs, Some(&s2), &t3, &mut rec, None).unwrap();
    assert_eq!(r.kept_local, vec![p("a.txt")]);
    assert_eq!(fs.read(&p("a.txt")).unwrap(), b"x\r\ny\r\nmine\r\n");
}

#[test]
fn a_file_the_user_wrote_with_crlf_is_not_wedged() {
    // Recorded LF by normalisation (never checked out), then switched away
    // under the same attributes: the file is ours to replace.
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(".veilattributes"), b"* text\n").unwrap();
    fs.write(&p("a.txt"), b"one\r\ntwo\r\n").unwrap();
    snap(&mut repo, &*fs);
    let t1 = wc_tree(&repo);
    assert_eq!(bytes_at(&repo, &t1, "a.txt"), b"one\ntwo\n");
    let t2 = tree_of(&repo, &[(".veilattributes", b"* text\n"), ("a.txt", b"three\n")]);
    let r = repo.checkout_tree(&*fs, Some(&t1), &t2).unwrap();
    assert!(r.kept_local.is_empty(), "{:?}", r.kept_local);
    assert_eq!(fs.read(&p("a.txt")).unwrap(), b"three\n");
}

// ---- 5. code execution through drivers --------------------------------------------------

#[test]
fn without_device_drivers_named_drivers_are_built_ins() {
    // A teammate's `.veilattributes` names a driver, and a tracked
    // `config.toml` / `.veil.toml` "defines" it: the core knows only what
    // the device registered (nothing here), so the merge is the built-in
    // text merge.
    let (repo, _fs, _) = new_repo("alice");
    let cfg: &[u8] = b"[merge.pwn]\ncommand = [\"/bin/sh\", \"-c\", \"touch PWNED\"]\n";
    let ga: &[u8] = b"* merge=pwn diff=pwn\n";
    let base = tree_of(&repo, &[(".veilattributes", ga), ("config.toml", cfg), (".veil.toml", cfg), ("a.txt", b"1\n2\n3\n")]);
    let ours = tree_of(&repo, &[(".veilattributes", ga), ("config.toml", cfg), (".veil.toml", cfg), ("a.txt", b"one\n2\n3\n")]);
    let theirs = tree_of(&repo, &[(".veilattributes", ga), ("config.toml", cfg), (".veil.toml", cfg), ("a.txt", b"1\n2\nthree\n")]);
    let out = veil_core::merge::merge_trees(repo.store(), Some(base), ours, theirs).unwrap();
    assert!(out.conflicts.is_empty());
    assert_eq!(bytes_at(&repo, &out.tree, "a.txt"), b"one\n2\nthree\n");
}

/// Device drivers that record what they were given, and merge by
/// concatenation.
/// One driver call: name, base, ours, theirs.
type Call = (String, Vec<u8>, Vec<u8>, Vec<u8>);

#[derive(Default)]
struct Spy {
    calls: Mutex<Vec<Call>>,
    undefined: Mutex<Vec<(String, String)>>,
}

impl DeviceDrivers for Spy {
    fn has_merge(&self, name: &str) -> bool {
        name == "spy"
    }
    fn merge(&self, name: &str, i: &DriverInput<'_>) -> DriverMerge {
        self.calls.lock().unwrap().push((name.into(), i.base.to_vec(), i.ours.to_vec(), i.theirs.to_vec()));
        let mut m = i.ours.to_vec();
        m.extend_from_slice(i.theirs);
        DriverMerge::Clean(m)
    }
    fn has_textconv(&self, _: &str) -> bool {
        false
    }
    fn textconv(&self, _: &str, _: &VPath, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn undefined(&self, kind: &str, name: &str, _: &VPath) {
        self.undefined.lock().unwrap().push((kind.into(), name.into()));
    }
}

#[test]
fn an_undefined_driver_name_is_reported_and_never_run() {
    let (repo, _fs, _) = new_repo("alice");
    let spy = Arc::new(Spy::default());
    repo.store().set_device_drivers(spy.clone());
    let ga: &[u8] = b"* merge=$(touch${IFS}x) diff=../../bin/sh\n";
    let base = tree_of(&repo, &[(".veilattributes", ga), ("a.txt", b"1\n2\n3\n")]);
    let ours = tree_of(&repo, &[(".veilattributes", ga), ("a.txt", b"one\n2\n3\n")]);
    let theirs = tree_of(&repo, &[(".veilattributes", ga), ("a.txt", b"1\n2\nthree\n")]);
    let out = veil_core::merge::merge_trees(repo.store(), Some(base), ours, theirs).unwrap();
    assert_eq!(bytes_at(&repo, &out.tree, "a.txt"), b"one\n2\nthree\n");
    assert!(spy.calls.lock().unwrap().is_empty());
    assert!(spy.undefined.lock().unwrap().iter().any(|(k, _)| k == "merge"));
}

// ---- 6. merge drivers and audiences -----------------------------------------------------

const BASE_LINE: &str = "BASE-ONLY-LINE-5521";

fn sealed_tree(repo: &Repo, ga: &str, text: &str, v: &Visibility) -> ObjectId {
    let store = repo.store();
    let id = store.store_file(text.as_bytes(), v).unwrap();
    let mut e = file("notes.txt", id);
    e.size = text.len() as u64;
    e.visibility = v.clone();
    let gid = store.store_file(ga.as_bytes(), &Visibility::Public).unwrap();
    let mut g = file(".veilattributes", gid);
    g.size = ga.len() as u64;
    raw_tree(repo, vec![g, e])
}

fn team() -> Visibility {
    Visibility::Cloaked { scope: "team".into() }
}

#[test]
fn a_union_merge_never_puts_a_sealed_base_in_a_public_result() {
    let (repo, _fs, _) = new_repo("alice");
    let ga = "notes.txt merge=union\n";
    let base = sealed_tree(&repo, ga, &format!("intro\n{BASE_LINE}\noutro\n"), &team());
    let ours = sealed_tree(&repo, ga, "intro\nOURS\noutro\n", &Visibility::Public);
    let theirs = sealed_tree(&repo, ga, "intro\nTHEIRS\noutro\n", &Visibility::Public);
    let out = veil_core::merge::merge_trees(repo.store(), Some(base), ours, theirs).unwrap();
    let e = entry_at(&repo, &out.tree, "notes.txt").unwrap();
    assert!(e.visibility.is_public());
    let text = String::from_utf8(repo.store().read_entry(&e).unwrap()).unwrap();
    assert!(!text.contains(BASE_LINE), "{text}");
    assert!(text.contains("OURS") && text.contains("THEIRS"), "{text}");
    // With a public base, union keeps both sides' lines around the base's
    // common lines.
    let pbase = sealed_tree(&repo, ga, "intro\nmiddle\noutro\n", &Visibility::Public);
    let out = veil_core::merge::merge_trees(repo.store(), Some(pbase), ours, theirs).unwrap();
    assert!(out.conflicts.is_empty());
    assert_eq!(bytes_at(&repo, &out.tree, "notes.txt"), b"intro\nOURS\nTHEIRS\noutro\n");
}

#[test]
fn a_merge_driver_gets_the_base_only_where_its_audience_is_the_results() {
    let (repo, _fs, _) = new_repo("alice");
    repo.keys().create_scope("ops").unwrap();
    let spy = Arc::new(Spy::default());
    repo.store().set_device_drivers(spy.clone());
    let ga = "notes.txt merge=spy\n";
    let base_text = format!("intro\n{BASE_LINE}\noutro\n");
    let ops = Visibility::Cloaked { scope: "ops".into() };
    // A base sealed for `team`, sides public: an empty base.
    let base = sealed_tree(&repo, ga, &base_text, &team());
    let ours = sealed_tree(&repo, ga, "intro\nOURS\noutro\n", &Visibility::Public);
    let theirs = sealed_tree(&repo, ga, "intro\nTHEIRS\noutro\n", &Visibility::Public);
    let out = veil_core::merge::merge_trees(repo.store(), Some(base), ours, theirs).unwrap();
    {
        let calls = spy.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].1.is_empty(), "the sealed base must not reach the driver");
    }
    let e = entry_at(&repo, &out.tree, "notes.txt").unwrap();
    assert!(e.visibility.is_public());
    assert!(!String::from_utf8_lossy(&repo.store().read_entry(&e).unwrap()).contains(BASE_LINE));
    // The same base, with a result sealed for `team` too: given.
    let ours_t = sealed_tree(&repo, ga, "intro\nOURS\noutro\n", &team());
    veil_core::merge::merge_trees(repo.store(), Some(base), ours_t, theirs).unwrap();
    assert_eq!(spy.calls.lock().unwrap()[1].1, base_text.as_bytes());
    let merged = entry_at(&repo, &veil_core::merge::merge_trees(repo.store(), Some(base), ours_t, theirs).unwrap().tree, "notes.txt").unwrap();
    assert_eq!(merged.visibility, team(), "the driver's output is sealed as merged content is");
    // Two scopes clash: the driver is never invoked; a conflict.
    let n = spy.calls.lock().unwrap().len();
    let theirs_o = sealed_tree(&repo, ga, "intro\nTHEIRS\noutro\n", &ops);
    let out = veil_core::merge::merge_trees(repo.store(), Some(base), ours_t, theirs_o).unwrap();
    assert_eq!(spy.calls.lock().unwrap().len(), n, "no driver across an audience clash");
    assert_eq!(out.conflicts, vec![p("notes.txt")]);
}

#[test]
fn binary_and_no_merge_attributes_make_whole_file_conflicts() {
    let (repo, _fs, _) = new_repo("alice");
    for ga in ["notes.txt binary\n", "notes.txt -merge\n", "notes.txt merge=binary\n"] {
        let base = sealed_tree(&repo, ga, "1\n2\n3\n", &Visibility::Public);
        let ours = sealed_tree(&repo, ga, "one\n2\n3\n", &Visibility::Public);
        let theirs = sealed_tree(&repo, ga, "1\n2\nthree\n", &Visibility::Public);
        let out = veil_core::merge::merge_trees(repo.store(), Some(base), ours, theirs).unwrap();
        assert_eq!(out.conflicts, vec![p("notes.txt")], "{ga}");
    }
}

// ---- 10. denial of service --------------------------------------------------------------

#[test]
fn a_huge_attributes_file_is_ignored_with_a_warning() {
    let (repo, fs, _) = new_repo("alice");
    let mut big = "* text eol=crlf\n".repeat((attributes::MAX_FILE / 16) + 1).into_bytes();
    big.truncate(attributes::MAX_FILE + 10);
    fs.write(&p(".veilattributes"), &big).unwrap();
    let a = Attrs::for_backend(repo.store(), &*fs);
    assert_eq!(a.for_path(&p("x.txt")).conversion, attributes::Conversion::None);
    assert!(a.warnings().iter().any(|w| w.contains("larger than")), "{:?}", a.warnings());
}

#[test]
fn hostile_attributes_lines_are_bounded() {
    // Long lines (Git's 2048-byte limit), NUL bytes, invalid UTF-8,
    // pathological wildcards, cyclic macros, deep paths.
    let mut ga = Vec::new();
    ga.extend_from_slice(&[b'a'; 3000]);
    ga.extend_from_slice(b" text\n");
    ga.extend_from_slice(b"[attr]m1 m2\n[attr]m2 m1 eol=crlf\n*.m m1\n");
    ga.extend_from_slice(b"\xff\xfe* -text\n");
    let star = "*a".repeat(900) + "b";
    ga.extend_from_slice(format!("{star} text\n").as_bytes());
    ga.extend_from_slice(b"*.txt text\0* binary\n");
    let (repo, fs, _) = new_repo("alice");
    fs.write(&p(".veilattributes"), &ga).unwrap();
    let a = Attrs::for_backend(repo.store(), &*fs);
    let start = std::time::Instant::now();
    let deep = format!("{}{}.m", "d/".repeat(200), "a".repeat(200));
    assert_eq!(a.for_path(&p(&deep)).conversion, attributes::Conversion::Text { crlf: true }, "cyclic macros expand once");
    assert_eq!(a.for_path(&p("x.txt")).conversion, attributes::Conversion::Text { crlf: false });
    // Everything after the NUL is ignored, as by Git.
    assert_ne!(a.for_path(&p("x.bin")).diff, attributes::DiffAttr::Binary);
    let long = "a".repeat(4000);
    a.for_path(&p(&long));
    assert!(start.elapsed() < std::time::Duration::from_secs(5), "{:?}", start.elapsed());
    assert!(a.warnings().iter().any(|w| w.contains("2048")), "{:?}", a.warnings());
}

#[test]
fn many_nested_attributes_files_are_read_lazily() {
    struct Counting(Mutex<usize>);
    impl AttrSource for Counting {
        fn read_attributes(&self, _: &VPath) -> Result<Option<Vec<u8>>, String> {
            *self.0.lock().unwrap() += 1;
            Ok(Some(b"* text\n".to_vec()))
        }
    }
    let src = Arc::new(Counting(Mutex::new(0)));
    struct Shared(Arc<Counting>);
    impl AttrSource for Shared {
        fn read_attributes(&self, d: &VPath) -> Result<Option<Vec<u8>>, String> {
            self.0.read_attributes(d)
        }
    }
    let a = Attrs::with_source(Box::new(Shared(src.clone())), None);
    for i in 0..2000 {
        a.for_path(&p(&format!("x/y/f{i}")));
    }
    assert_eq!(*src.0.lock().unwrap(), 3, "each directory's file is read once");
}

#[test]
fn a_megabyte_of_patterns_slows_a_snapshot_little() {
    // 20 000 files (some with CRLF), recorded once; then each snapshot
    // with and without a 1 MiB `.veilattributes`.
    let (mut repo, fs, _) = new_repo("alice");
    for i in 0..20_000 {
        let crlf = i % 50 == 0;
        let body = if crlf { format!("line {i}\r\n") } else { format!("line {i}\n") };
        fs.write(&p(&format!("d{}/f{i}.e{}", i % 100, i % 7)), body.as_bytes()).unwrap();
    }
    let mut cache = veil_core::statcache::StatCache::new();
    let time = |repo: &mut Repo, cache: &mut veil_core::statcache::StatCache| {
        let start = std::time::Instant::now();
        repo.snapshot_workspace_with(WS, &*fs, SnapshotOptions { cache: Some(cache), ..Default::default() }).unwrap();
        start.elapsed()
    };
    time(&mut repo, &mut cache);
    let plain = (0..5).map(|_| time(&mut repo, &mut cache)).min().unwrap();
    let mut ga = String::new();
    let mut i = 0;
    while ga.len() < attributes::MAX_FILE - 64 {
        ga.push_str(&format!("*.x{i} text eol=crlf\n"));
        i += 1;
    }
    ga.push_str("*.e3 text\n");
    fs.write(&p(".veilattributes"), ga.as_bytes()).unwrap();
    time(&mut repo, &mut cache);
    let with = (0..5).map(|_| time(&mut repo, &mut cache)).min().unwrap();
    eprintln!("20 000 files: {plain:?} without, {with:?} with a 1 MiB .veilattributes ({i} patterns)");
    // A loose bound (BUG-758: 1.2× failed under a loaded full suite). What
    // it guards against is matching every file against every pattern:
    // 20 000 files × tens of thousands of patterns, far slower than 2×.
    assert!(with.as_secs_f64() <= plain.as_secs_f64() * 2.0 + 0.1, "{plain:?} -> {with:?}");
}

// ---- 11. an unreadable .veilattributes ---------------------------------------------------

#[test]
fn an_outsider_with_a_sealed_gitattributes_checks_out_clean() {
    let (mut alice, fs, _) = new_repo("alice");
    let v1 = commit_files(&mut alice, &*fs, &[(".veilattributes", "*.txt eol=crlf\n"), ("a.txt", "one\ntwo\n")], "v1");
    // `.veilattributes` sealed for `team` (only a secret file is sealed
    // through the policy: the version is stored as is, as a hostile or
    // earlier writer could).
    let store = alice.store();
    let mut root = (*store.tree(&store.snapshot(&v1).unwrap().tree).unwrap()).clone();
    let mut e = root.get(".veilattributes").unwrap().clone();
    e.id = store.store_file(b"*.txt eol=crlf\n", &team()).unwrap();
    e.visibility = team();
    root.insert(e);
    let main = raw_snapshot(&alice, vec![v1], store.put_tree(&root).unwrap(), "seal the attributes");
    alice.set_tag("main", main, false).unwrap();
    let team_remote = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team_remote.clone(), false, &[], false).unwrap();
    // Bob holds no `team` key.
    let bfs = Arc::new(MemoryBackend::new());
    let mut bob = Repo::init_for_clone(bfs.clone(), Some(Identity::generate("bob")), "bob").unwrap();
    remote::pull(&mut bob, "origin", team_remote).unwrap();
    let tree = bob.snapshot(&main).unwrap().tree;
    let wc = MemoryBackend::new();
    let mut rec = Materialised::default();
    let r = bob.checkout_tree_recorded(&wc, None, &tree, &mut rec, None).unwrap();
    assert!(r.redacted.contains(&p(".veilattributes")));
    assert_eq!(wc.read(&p("a.txt")).unwrap(), b"one\ntwo\n", "defaults apply: no conversion");
    let (now, report) = bob.build_from_recorded(&wc, Some(tree), None, Some(&rec)).unwrap();
    assert_eq!(now, tree, "nothing to record: {report:?}");
    // Alice, a member, gets CRLF; her copy is not an edit either.
    let awc = MemoryBackend::new();
    let mut arec = Materialised::default();
    alice.checkout_tree_recorded(&awc, None, &tree, &mut arec, None).unwrap();
    assert_eq!(awc.read(&p("a.txt")).unwrap(), b"one\r\ntwo\r\n");
    assert_eq!(alice.build_from_recorded(&awc, Some(tree), None, Some(&arec)).unwrap().0, tree);
}

// ---- 12. first-class conflicts ----------------------------------------------------------

#[test]
fn an_eol_crlf_conflict_resolves_in_an_editor_that_keeps_crlf() {
    let (mut repo, fs, _) = new_repo("alice");
    let ga: &[u8] = b"*.txt eol=crlf\n";
    let base = tree_of(&repo, &[(".veilattributes", ga), ("a.txt", b"1\n2\n3\n")]);
    let ours = tree_of(&repo, &[(".veilattributes", ga), ("a.txt", b"1\nOURS\n3\n")]);
    let theirs = tree_of(&repo, &[(".veilattributes", ga), ("a.txt", b"1\nTHEIRS\n3\n")]);
    let m = veil_core::merge::merge_trees(repo.store(), Some(base), ours, theirs).unwrap();
    assert_eq!(entry_at(&repo, &m.tree, "a.txt").unwrap().kind, EntryKind::Conflict);
    let mut rec = Materialised::default();
    let empty = wc_tree(&repo);
    repo.checkout_tree_recorded(&*fs, Some(&empty), &m.tree, &mut rec, None).unwrap();
    let copy = fs.read(&p("a.txt")).unwrap();
    assert!(copy.windows(2).any(|w| w == b"\r\n") && !attributes::TextStat::of(&copy).lonelf > 0, "markers in CRLF");
    // Untouched: still the conflict.
    let (t, _) = repo.build_from_recorded(&*fs, Some(m.tree), None, Some(&rec)).unwrap();
    assert_eq!(entry_at(&repo, &t, "a.txt").unwrap().kind, EntryKind::Conflict);
    // Edited, CRLF kept: a resolution, recorded with LF.
    fs.write(&p("a.txt"), b"1\r\nRESOLVED\r\n3\r\n").unwrap();
    let (t, _) = repo.build_from_recorded(&*fs, Some(m.tree), None, Some(&rec)).unwrap();
    let e = entry_at(&repo, &t, "a.txt").unwrap();
    assert_eq!(e.kind, EntryKind::File);
    assert_eq!(repo.store().read_entry(&e).unwrap(), b"1\nRESOLVED\n3\n");
    let _ = &mut repo;
}

// ---- 13. overlays (mounts, `ws exec`) ---------------------------------------------------

#[test]
fn an_overlay_writing_the_recorded_bytes_back_records_nothing() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[(".veilattributes", "*.txt eol=crlf\n"), ("a.txt", "x\ny\n")], "v1");
    let mut eph = repo.ephemeral_workspace(base).unwrap();
    // A mount shows the recorded (LF) bytes; writing them back is no edit,
    // and neither is writing the CRLF form.
    eph.fs().write(&p("a.txt"), b"x\ny\n").unwrap();
    let (s, _) = repo.commit_ephemeral(&eph, "same").unwrap();
    assert_eq!(repo.snapshot(&s).unwrap().tree, repo.snapshot(&base).unwrap().tree);
    eph = repo.ephemeral_workspace(base).unwrap();
    eph.fs().write(&p("a.txt"), b"x\r\ny\r\n").unwrap();
    let (s, _) = repo.commit_ephemeral(&eph, "crlf").unwrap();
    assert_eq!(repo.snapshot(&s).unwrap().tree, repo.snapshot(&base).unwrap().tree);
}

// ---- 14. the upgrade path ---------------------------------------------------------------

#[test]
fn files_recorded_with_crlf_before_attributes_stay_until_edited() {
    let (mut repo, fs, _) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[("a.txt", "x\r\ny\r\n"), ("b.txt", "p\r\nq\r\n")], "old");
    fs.write(&p(".veilattributes"), b"*.txt text\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    let t = wc_tree(&repo);
    assert_eq!(bytes_at(&repo, &t, "a.txt"), b"x\r\ny\r\n", "never re-recorded by itself");
    let mut hint = out.report.renormalizable.clone();
    hint.sort();
    assert_eq!(hint, vec![p("a.txt"), p("b.txt")], "status can say `vl renormalize`");
    // The first edit records LF.
    fs.write(&p("a.txt"), b"x\r\ny\r\nz\r\n").unwrap();
    snap(&mut repo, &*fs);
    let t = wc_tree(&repo);
    assert_eq!(bytes_at(&repo, &t, "a.txt"), b"x\ny\nz\n");
    assert_eq!(bytes_at(&repo, &t, "b.txt"), b"p\r\nq\r\n");
    // `text=auto` keeps CRLF on an edit of a file recorded with CR (Git's
    // safer autocrlf), until renormalised.
    fs.write(&p(".veilattributes"), b"*.txt text=auto\n").unwrap();
    fs.write(&p("b.txt"), b"p\r\nq\r\nr\r\n").unwrap();
    snap(&mut repo, &*fs);
    assert_eq!(bytes_at(&repo, &wc_tree(&repo), "b.txt"), b"p\r\nq\r\nr\r\n");
}

#[test]
fn mixed_line_endings_are_recorded_unchanged_with_a_warning() {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(".veilattributes"), b"* text\n").unwrap();
    fs.write(&p("mixed.txt"), b"a\r\nb\nc\r\n").unwrap();
    fs.write(&p("cr.txt"), b"a\rb\r\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    let t = wc_tree(&repo);
    assert_eq!(bytes_at(&repo, &t, "mixed.txt"), b"a\r\nb\nc\r\n");
    assert_eq!(bytes_at(&repo, &t, "cr.txt"), b"a\rb\r\n");
    let mut warned: Vec<&str> = out.report.line_endings.iter().map(|(p, _)| p.as_str()).collect();
    warned.sort();
    assert_eq!(warned, vec!["cr.txt", "mixed.txt"]);
    // Once recorded, no more warnings: the file holds its recorded version.
    let again = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert!(again.report.line_endings.is_empty());
}

#[test]
fn the_stat_cache_agrees_with_a_fresh_read() {
    // A converted file is recorded through the cache exactly as without
    // it, also after the attributes change.
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(".veilattributes"), b"*.txt text\n").unwrap();
    fs.write(&p("a.txt"), b"x\r\ny\r\n").unwrap();
    fs.write(&p("i.png"), b"\x89PNG\r\n\x1a\n").unwrap();
    let mut cache = veil_core::statcache::StatCache::new();
    let run = |repo: &mut Repo, cache: &mut veil_core::statcache::StatCache| {
        repo.snapshot_workspace_with(WS, &*fs, SnapshotOptions { cache: Some(cache), ..Default::default() }).unwrap();
        wc_tree(repo)
    };
    let t1 = run(&mut repo, &mut cache);
    let t2 = run(&mut repo, &mut cache);
    assert_eq!(t1, t2);
    assert_eq!(bytes_at(&repo, &t1, "a.txt"), b"x\ny\n");
    fs.write(&p(".veilattributes"), b"*.txt -text\n* text=auto\n").unwrap();
    let t3 = run(&mut repo, &mut cache);
    let fresh = repo.build_from(&*fs, Some(t1)).unwrap().0;
    assert_eq!(entry_at(&repo, &t3, "a.txt"), entry_at(&repo, &fresh, "a.txt"));
    assert_eq!(entry_at(&repo, &t3, "i.png"), entry_at(&repo, &t1, "i.png"));
}

// ---- renames: the attributes of the path the content merges at ---------------------------

fn lines_with(n: usize, at: usize, s: &str) -> Vec<u8> {
    (0..n).map(|i| if i == at { format!("{s}\n") } else { format!("line {i} of a fairly long file\n") }).collect::<String>().into_bytes()
}

#[test]
fn a_followed_rename_merges_under_the_attributes_of_its_new_path() {
    for (ga, clean) in [("new/*.txt merge=union\n", true), ("old/*.txt merge=union\n", false)] {
        let (repo, _fs, _) = new_repo("alice");
        let g = ga.as_bytes();
        let base = tree_of(&repo, &[(".veilattributes", g), ("old/a.txt", &lines_with(12, 5, "middle"))]);
        // Ours moves the file and edits a line; theirs edits the same line.
        let ours = tree_of(&repo, &[(".veilattributes", g), ("new/a.txt", &lines_with(12, 5, "OURS"))]);
        let theirs = tree_of(&repo, &[(".veilattributes", g), ("old/a.txt", &lines_with(12, 5, "THEIRS"))]);
        let out = veil_core::merge::merge_trees(repo.store(), Some(base), ours, theirs).unwrap();
        assert!(entry_at(&repo, &out.tree, "old/a.txt").is_none(), "{ga}: the rename was followed");
        if clean {
            assert!(out.conflicts.is_empty(), "{ga}: {:?}", out.conflicts);
            let text = String::from_utf8(bytes_at(&repo, &out.tree, "new/a.txt")).unwrap();
            assert!(text.contains("OURS\nTHEIRS\n") && !text.contains("middle"), "{text}");
        } else {
            assert_eq!(out.conflicts, vec![p("new/a.txt")], "{ga}");
        }
    }
}
