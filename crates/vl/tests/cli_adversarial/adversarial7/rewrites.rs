//! Property: no rewrite moves sealed content to a public audience.
//!
//! Random sequences of the commands that move recorded content between
//! changes and audiences (`vl squash` whole and partial, into a cloaked
//! change or out of one, `vl split`, `vl rebase` onto a cloaked change,
//! `vl restore` with and without `--from`, `vl resolve --ours/--theirs`),
//! through the real binary, on a project with a workspace `sec` cloaked
//! for `team`.
//!
//! Two kinds of text carry unique markers:
//!
//! * `SEALED-n`, written in the cloaked workspace: sealed from the start;
//! * `DRAFT-n`, written in the (public) working copy `@` and not
//!   committed. `@` itself is never published, so a draft is on no public
//!   remote until a command moves it into a published change. A draft that
//!   reaches the cloaked change `sec@` while it is still on no public
//!   remote (squashed into it, BUG-480/483) is sealed content from then on.
//!
//! After each command, `@-`, `@--` and `sec@` are tagged and pushed to a
//! public mirror, and the mirror's bytes (packed objects decoded) are
//! searched for every sealed marker. The working copy's files recorded as
//! public are checked too.

use std::path::Path;

use proptest::prelude::*;
use veil_core::{cache::LruCache, pack, StorageBackend, VPath};

use super::{
    adversarial_support::{write, Env},
    ws_write, U,
};

#[derive(Clone, Debug)]
enum Op {
    /// The cloaked workspace rewrites file `f` (line 2 of `a.txt`, or all
    /// of `b.txt`) with a new sealed marker.
    SealedEdit(u8),
    /// The working copy rewrites file `f` with a new draft marker; with
    /// `true`, then commits it (`--no-advance`).
    Draft(u8, bool),
    /// The working copy goes to a new change on the cloaked change, or on
    /// the fixed public `base`.
    NewOn(bool),
    /// Rebase `@` (`true`) or `@-` with its descendants onto the cloaked
    /// change (conflicts when both rewrote a file).
    RebaseOntoSealed(bool),
    /// Squash `@` (`true`) or `@-` into the cloaked change: whole, or
    /// file `f` only.
    SquashIntoSealed(bool, Option<u8>),
    /// Squash file `f` of `@` into its parent (whatever it is).
    SquashPath(u8),
    /// Squash the cloaked change's file `f` into `@-`.
    SquashOutOfSealed(u8),
    /// Split `@` (`true`) or `@-`, file `f` first.
    Split(bool, u8),
    /// `vl restore --from` the cloaked change (or `@--`) file `f`.
    RestoreFrom(bool, u8),
    /// `vl restore` with no `--from`.
    Restore,
    /// `vl resolve` every conflicted file of `@`, ours or theirs.
    Resolve(bool),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..2u8).prop_map(Op::SealedEdit),
        4 => (0..2u8, any::<bool>()).prop_map(|(f, c)| Op::Draft(f, c)),
        2 => any::<bool>().prop_map(Op::NewOn),
        2 => any::<bool>().prop_map(Op::RebaseOntoSealed),
        3 => (any::<bool>(), prop::option::of(0..2u8)).prop_map(|(w, f)| Op::SquashIntoSealed(w, f)),
        2 => (0..2u8).prop_map(Op::SquashPath),
        1 => (0..2u8).prop_map(Op::SquashOutOfSealed),
        1 => (any::<bool>(), 0..2u8).prop_map(|(w, f)| Op::Split(w, f)),
        2 => (any::<bool>(), 0..2u8).prop_map(|(s, f)| Op::RestoreFrom(s, f)),
        1 => Just(Op::Restore),
        1 => any::<bool>().prop_map(Op::Resolve),
    ]
}

const FILES: [&str; 2] = ["a.txt", "b.txt"];

fn body(f: u8, mark: &str) -> String {
    match f {
        0 => format!("one\n{mark}\nthree\n"),
        _ => format!("{mark}\n"),
    }
}

fn rev(wc: bool) -> &'static str {
    if wc {
        "@"
    } else {
        "@-"
    }
}

/// Every place `needle` occurs in the repository at `dir`: raw file bytes
/// and the decoded bytes of every packed object (packs are compressed).
pub(crate) fn mirror_contains(dir: &Path, needle: &[u8]) -> Vec<String> {
    if !dir.exists() {
        return vec![];
    }
    let backend = veil_core::DiskBackend::new(dir);
    let has = |data: &[u8]| data.windows(needle.len()).any(|w| w == needle);
    let mut hits: Vec<String> = veil_core::vfs::walk_files(&backend, &VPath::root(), &|_| false)
        .unwrap()
        .into_iter()
        .filter(|f| has(&backend.read(f).unwrap()))
        .map(|f| f.to_string())
        .collect();
    let pdir = VPath::new(".veil/objects/pack").unwrap();
    if let Ok(entries) = backend.list_dir(&pdir) {
        let bases = LruCache::new(64 << 20);
        for e in entries {
            let Some(name) = pack::name_from_index_file(&e.name) else { continue };
            let p = pack::Pack::open(&backend, &pdir, name).unwrap();
            for id in p.index().ids() {
                let raw = p.get(&backend, id, &bases).unwrap().expect("indexed");
                if has(&raw) {
                    hits.push(format!("{}#{}", e.name, id.short()));
                }
            }
        }
    }
    hits
}

fn run(ops: Vec<Op>) -> Result<(), TestCaseError> {
    let debug = std::env::var_os("VEIL_TEST_DEBUG").is_some();
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "one\ntwo\nthree\n"), ("b.txt", "b\n")]);
    env.ok(U, &proj, &["tag", "set", "base", "-r", "main"]);
    env.ok(U, &proj, &["ws", "new", "sec", "-r", "base", "--cloak", "team"]);
    let mirror = env.root.join("pub");
    env.ok(U, &proj, &["remote", "add", "pub", mirror.to_str().unwrap(), "--public"]);
    let mut sealed: Vec<String> = Vec::new();
    let mut drafts: Vec<String> = Vec::new();
    let mut n = 0;
    let mut mark = |what: &str| {
        n += 1;
        format!("{what}-{n:04}")
    };
    for (i, o) in ops.iter().enumerate() {
        let out = match o {
            Op::SealedEdit(f) => {
                let m = mark("SEALED");
                ws_write(&env, &proj, "sec", FILES[*f as usize], &body(*f, &m));
                sealed.push(m);
                None
            }
            Op::Draft(f, commit) => {
                let m = mark("DRAFT");
                write(&proj, FILES[*f as usize], &body(*f, &m));
                drafts.push(m);
                commit.then(|| env.vl(U, &proj, &["commit", "--no-advance", "-m", "draft"]))
            }
            Op::NewOn(s) => Some(env.vl(U, &proj, &["new", if *s { "sec@" } else { "base" }])),
            Op::RebaseOntoSealed(w) => Some(env.vl(U, &proj, &["rebase", "-s", rev(*w), "-d", "sec@"])),
            Op::SquashIntoSealed(w, None) => Some(env.vl(U, &proj, &["squash", "-r", rev(*w), "--into", "sec@"])),
            Op::SquashIntoSealed(w, Some(f)) => {
                Some(env.vl(U, &proj, &["squash", FILES[*f as usize], "-r", rev(*w), "--into", "sec@"]))
            }
            Op::SquashPath(f) => Some(env.vl(U, &proj, &["squash", FILES[*f as usize]])),
            Op::SquashOutOfSealed(f) => Some(env.vl(U, &proj, &["squash", FILES[*f as usize], "-r", "sec@", "--into", "@-"])),
            Op::Split(w, f) => Some(env.vl(U, &proj, &["split", FILES[*f as usize], "-r", rev(*w), "-m", "first"])),
            Op::RestoreFrom(s, f) => {
                Some(env.vl(U, &proj, &["restore", "--from", if *s { "sec@" } else { "@--" }, FILES[*f as usize]]))
            }
            Op::Restore => Some(env.vl(U, &proj, &["restore"])),
            Op::Resolve(ours) => {
                let list = env.stdout(U, &proj, &["resolve", "--list", "--json"]);
                let v: serde_json::Value = serde_json::from_str(&list).unwrap();
                let paths: Vec<String> = v["conflicts"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|c| c["path"].as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                if paths.is_empty() {
                    None
                } else {
                    let mut args = vec!["resolve", if *ours { "--ours" } else { "--theirs" }];
                    args.extend(paths.iter().map(String::as_str));
                    Some(env.vl(U, &proj, &args))
                }
            }
        };
        // Whether the command succeeds is not the point (a squash with
        // nothing to move is refused); it must never crash.
        if let Some(out) = &out {
            if debug {
                eprintln!("step {i} {o:?}: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            }
            prop_assert!(
                out.status.code().is_some_and(|c| c != 101),
                "step {i} {o:?} crashed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        // A draft that the cloaked change itself took in (it is there, and
        // not in its parent) before any public remote saw it is sealed
        // content from now on.
        for f in FILES {
            let cat = |r: &str| String::from_utf8_lossy(&env.vl(U, &proj, &["cat", "-r", r, f]).stdout).into_owned();
            let (text, below) = (cat("sec@"), cat("sec@-"));
            for d in &drafts {
                if text.contains(d.as_str())
                    && !below.contains(d.as_str())
                    && !sealed.contains(d)
                    && mirror_contains(&mirror, d.as_bytes()).is_empty()
                {
                    if debug {
                        eprintln!("  {d} is now sealed content (in sec@:{f})");
                    }
                    sealed.push(d.clone());
                }
            }
        }
        // Publish every committed change near the working copy, and the
        // cloaked change (its sealed files are withheld, its public ones
        // not). `@` holds the drafts and is not published.
        let mut tags = vec![];
        for (t, r) in [("w1", "@-"), ("w2", "@--"), ("s", "sec@")] {
            if env.vl(U, &proj, &["tag", "set", t, "-r", r, "--allow-backwards"]).status.success() {
                tags.push(t);
            }
        }
        let push = env.vl(U, &proj, &["push", "pub", "--force"]);
        if debug {
            eprintln!("  tags {tags:?}; push: {}{}", String::from_utf8_lossy(&push.stdout), String::from_utf8_lossy(&push.stderr));
        }
        prop_assert!(push.status.success(), "push after step {i} {o:?}: {}", String::from_utf8_lossy(&push.stderr));
        for m in &sealed {
            let hits = mirror_contains(&mirror, m.as_bytes());
            prop_assert!(hits.is_empty(), "after step {i} ({o:?}) of {ops:?}, sealed {m} is on the public mirror: {hits:?}");
        }
        // The working copy's files the repository holds public.
        let files = env.stdout(U, &proj, &["files"]);
        for l in files.lines().filter(|l| l.starts_with("public") && !l.ends_with("(conflict)")) {
            let Some(path) = l.split_whitespace().last() else { continue };
            let data = std::fs::read_to_string(proj.join(path)).unwrap_or_default();
            for m in &sealed {
                prop_assert!(
                    !data.contains(m.as_str()),
                    "after step {i} ({o:?}) of {ops:?}, {path} is recorded public and holds {m}:\n{files}"
                );
            }
        }
    }
    Ok(())
}

proptest! {
    // `PROPTEST_CASES` runs more (every case runs the binary dozens of times).
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(24),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn no_rewrite_publishes_sealed_content(ops in prop::collection::vec(op(), 1..10)) {
        run(ops)?;
    }
}

/// BUG-480: a draft rebased onto the cloaked change (a conflict) and
/// squashed into it.
#[test]
fn a_conflict_squashed_into_the_cloaked_change_publishes_nothing_sealed() {
    run(vec![Op::SealedEdit(0), Op::Draft(0, false), Op::RebaseOntoSealed(true), Op::SquashIntoSealed(true, None)]).unwrap();
}

/// BUG-481: a sealed version, and a conflict with a sealed side, restored
/// into a public change, then committed.
#[test]
fn restored_sealed_versions_publish_nothing_sealed() {
    run(vec![
        Op::SealedEdit(0),
        Op::RestoreFrom(true, 0),
        Op::Draft(1, true),
        Op::Draft(0, true),
        Op::NewOn(false),
        Op::Draft(0, false),
        Op::RebaseOntoSealed(true),
        Op::SquashIntoSealed(true, None),
        Op::NewOn(false),
        Op::RestoreFrom(true, 0),
        Op::Draft(1, true),
    ])
    .unwrap();
}

/// BUG-483: a draft squashed (by path) from a public change into its
/// cloaked parent, then committed.
#[test]
fn a_path_squashed_into_the_cloaked_parent_publishes_nothing_sealed() {
    run(vec![
        Op::SealedEdit(1),
        Op::NewOn(true),
        Op::Draft(0, false),
        Op::Draft(1, false),
        Op::SquashPath(0),
        Op::Draft(1, true),
        Op::Split(false, 1),
        Op::Resolve(false),
        Op::Restore,
    ])
    .unwrap();
}

/// BUG-682: a draft committed and squashed into the cloaked change, then
/// a second draft of the same line (left in `@` as a conflict by the
/// rebase) squashed in too: the merged sealed version's fallback was the
/// second draft's plaintext, which the push of the cloaked change sent.
#[test]
fn a_draft_squashed_into_a_sealed_edit_publishes_nothing_sealed() {
    run(vec![Op::Draft(0, true), Op::Draft(0, false), Op::SquashIntoSealed(false, None), Op::SquashIntoSealed(true, None)])
        .unwrap();
}
