//! Property tests for folding a member's own `.veilpolicy` edit into the
//! accepted policy while a teammate's change is pending (BUG-073).
//!
//! Random accepted policy `A`, a random pending change `A → P` (the policy
//! the working copy was checked out with), and a random edit by the member
//! `P → C`. Whatever `working_copy_policy` records as the new accepted
//! policy `A'`:
//!
//! * no path is classified by `A'` more weakly than by both `A` and `C`
//!   (the accepted protection and the member's own intent), so a later
//!   policy that the member has not accepted cannot publish a file both of
//!   them protect;
//! * the snapshot taken now applies nothing weaker than both either;
//! * `A'` holds no rule the member did not see accepted or write
//!   themselves: nothing of the pending change is accepted with the edit;
//! * folding is idempotent (a second snapshot of the same files does not
//!   move `A'` again).
//!
//! Patterns and paths come from a small vocabulary that overlaps a lot
//! (`notes/**` vs `notes/private.md`, `.env` vs `notes/.env`, built-in
//! secrets, VCS metadata), which is where rule order matters.

use proptest::prelude::*;
use veil_core::{
    policy::{save_accepted, weakens, working_copy_policy, Classification, Policy, POLICY_FILE},
    vpath::VPath,
    MemoryBackend, StorageBackend,
};

const PATTERNS: &[&str] = &[
    "notes/**",
    "notes/",
    "notes/private.md",
    "*.md",
    ".env",
    "*.pem",
    "a/",
    "a/x",
    "**",
    "b/*.txt",
    "secrets/",
    ".git",
    "keys/id_rsa",
];

const TIERS: &[&str] = &["public", "public!", "cloak team", "cloak ops", "isolate", "ignore"];

const PATHS: &[(&str, bool)] = &[
    ("notes/private.md", false),
    ("notes/a.md", false),
    ("notes/.env", false),
    ("notes/secrets/k.pem", false),
    ("a/x", false),
    ("a/x/k.pem", false),
    ("a/y.md", false),
    (".env", false),
    ("b/c.txt", false),
    ("b/k.pem", false),
    ("k.pem", false),
    ("keys/id_rsa", false),
    ("README.md", false),
    ("secrets/db.yml", false),
    ("a/secrets/x.md", false),
    (".git/config", false),
    ("sub/.git", false),
    ("notes/.git/HEAD", false),
    ("notes", true),
    ("a", true),
    ("a/x", true),
    ("secrets", true),
];

fn rule() -> impl Strategy<Value = String> {
    (0..PATTERNS.len(), 0..TIERS.len()).prop_map(|(p, t)| format!("{} {}", PATTERNS[p], TIERS[t]))
}

#[derive(Clone, Debug)]
enum Edit {
    Insert(usize, String),
    Remove(usize),
    Move(usize, usize),
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        (any::<usize>(), rule()).prop_map(|(i, r)| Edit::Insert(i, r)),
        any::<usize>().prop_map(Edit::Remove),
        (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Edit::Move(a, b)),
    ]
}

fn apply(mut lines: Vec<String>, edits: &[Edit]) -> Vec<String> {
    for e in edits {
        match e {
            Edit::Insert(i, r) => {
                let i = i % (lines.len() + 1);
                lines.insert(i, r.clone());
            }
            Edit::Remove(i) if !lines.is_empty() => {
                let i = i % lines.len();
                lines.remove(i);
            }
            Edit::Move(a, b) if !lines.is_empty() => {
                let l = lines.remove(a % lines.len());
                lines.insert(b % (lines.len() + 1), l);
            }
            _ => {}
        }
    }
    lines
}

fn text(lines: &[String]) -> String {
    lines.iter().map(|l| format!("{l}\n")).collect()
}

fn classify(p: &Policy, path: &str, dir: bool) -> Classification {
    p.classify(&VPath::new(path).unwrap(), dir)
}

/// The accepted policy after one snapshot of a working copy holding
/// `current`, checked out with `parent`, by a member who accepted `accepted`.
fn snapshot(accepted: &str, parent: &str, current: &str) -> (Policy, String) {
    let local = MemoryBackend::new();
    let fs = MemoryBackend::new();
    save_accepted(&local, accepted.as_bytes()).unwrap();
    fs.write(&VPath::new(POLICY_FILE).unwrap(), current.as_bytes()).unwrap();
    let wp = working_copy_policy(&local, &fs, Some(Some(parent.as_bytes()))).unwrap();
    let pin = wp.accept.map_or_else(|| accepted.to_string(), |t| String::from_utf8(t).unwrap());
    (wp.policy, pin)
}

fn check(a: &[String], pending: &[Edit], mine: &[Edit]) -> Result<(), TestCaseError> {
    let p = apply(a.to_vec(), pending);
    let c = apply(p.clone(), mine);
    let (at, pt, ct) = (text(a), text(&p), text(&c));
    let (effective, pin) = snapshot(&at, &pt, &ct);
    let (acc, cur, new) = (Policy::parse(&at), Policy::parse(&ct), Policy::parse(&pin));
    for &(path, dir) in PATHS {
        let (ka, kc, kn) = (classify(&acc, path, dir), classify(&cur, path, dir), classify(&new, path, dir));
        prop_assert!(
            !(weakens(&ka, &kn) && weakens(&kc, &kn)),
            "{path}: the new accepted policy says {:?}, weaker than both the accepted {:?} and the member's {:?}\n\
             accepted:\n{at}pending:\n{pt}member:\n{ct}new accepted:\n{pin}",
            kn.tier,
            ka.tier,
            kc.tier
        );
        let ke = effective.classify(&VPath::new(path).unwrap(), dir);
        prop_assert!(
            !(weakens(&ka, &ke) && weakens(&kc, &ke)),
            "{path}: the snapshot applies {:?}\naccepted:\n{at}pending:\n{pt}member:\n{ct}",
            ke.tier
        );
    }
    // Only rules the member accepted before or wrote themselves (unless the
    // accepted policy moved forward on its own: the same rules, or only
    // `isolate`/`ignore` rules appended and `public!` rules dropped).
    let auto = cur.same_rules(&acc) || cur.only_adds_protection_to(&acc) || Policy::parse(&pt).same_rules(&acc);
    let lines = |t: &str| Policy::parse(t).rules().iter().filter(|r| !r.builtin).map(|r| r.to_line()).collect::<Vec<_>>();
    let (la, lp, lc) = (lines(&at), lines(&pt), lines(&ct));
    for l in lines(&pin) {
        let added_by_member = lc.iter().filter(|x| **x == l).count() > lp.iter().filter(|x| **x == l).count();
        // When the edit cannot be folded, the `isolate`/`ignore` rules of
        // the member's file are appended (they only add protection).
        let protective = lc.contains(&l) && (l.ends_with(" isolate") || l.ends_with(" ignore"));
        prop_assert!(
            auto || la.contains(&l) || added_by_member || protective,
            "'{l}' came from the pending change\naccepted:\n{at}pending:\n{pt}member:\n{ct}new accepted:\n{pin}"
        );
    }
    // Idempotent: a second snapshot of the same files folds nothing again
    // (unless the accepted policy now moves forward on its own: the
    // member's file is the new accepted policy plus only protection, or
    // the pending policy is no longer pending).
    let (_, again) = snapshot(&pin, &pt, &ct);
    let moves_on = cur.same_rules(&new) || cur.only_adds_protection_to(&new) || Policy::parse(&pt).same_rules(&new);
    prop_assert!(
        moves_on || new.same_rules(&Policy::parse(&again)),
        "a second snapshot moved the accepted policy again:\n{pin}then\n{again}"
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(1000),
        ..ProptestConfig::default()
    })]

    #[test]
    fn a_folded_edit_is_never_weaker_than_both_policies(
        a in prop::collection::vec(rule(), 0..6),
        pending in prop::collection::vec(edit(), 1..4),
        mine in prop::collection::vec(edit(), 1..4),
    ) {
        check(&a, &pending, &mine)?;
    }
}

/// The folds the fix must keep doing (not refuse): the edits of everyday use.
#[test]
fn everyday_edits_during_a_pending_change_are_folded() {
    let cases = [
        // BUG-073: a general rule above the exception for the member's file.
        (
            "notes/private.md isolate\n",
            "notes/private.md isolate\n.env public!\n",
            "notes/** public\nnotes/private.md isolate\n.env public!\n",
            "notes/** public\nnotes/private.md isolate\n",
        ),
        // An exposure appended after the pending change's rule.
        ("", ".env public!\n", ".env public!\n.envrc public!\n", ".envrc public!\n"),
        // A cloak inserted between accepted rules.
        (
            "a/ isolate\nb/ public!\n",
            "a/ isolate\nb/ public!\n.env public!\n",
            "a/ isolate\nsecrets/ cloak\nb/ public!\n.env public!\n",
            "a/ isolate\nsecrets/ cloak\nb/ public!\n",
        ),
        // A rule removed that the pending change left alone.
        ("a/ isolate\nb/ cloak\n", "a/ isolate\nb/ cloak\n.env public!\n", "b/ cloak\n.env public!\n", "b/ cloak\n"),
    ];
    for (a, p, c, want) in cases {
        let (_, pin) = snapshot(a, p, c);
        assert!(Policy::parse(&pin).same_rules(&Policy::parse(want)), "accepted {a:?}, pending {p:?}, member {c:?}: got\n{pin}");
    }
}

