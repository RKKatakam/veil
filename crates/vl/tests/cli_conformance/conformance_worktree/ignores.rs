//! Ignore rules (`ignore` tier of `.veilpolicy`): git t0008-ignores,
//! t3001/t3003 ls-files exclude, t2204 add-ignored, t7061 wtstatus-ignore,
//! t7521 ignored-mode; jj test_gitignores.

use super::*;

fn with_rules<'a>(env: &'a Env, rules: &str) -> R<'a> {
    let r = env.repo("p");
    let mut p = r.read(".veilpolicy");
    p.push_str(rules);
    r.write(".veilpolicy", p);
    r
}

// Scenario from git t0008-ignores.sh: a pattern without a slash matches at
// any depth.
#[test]
fn basename_pattern_matches_at_any_depth() {
    let env = Env::new();
    let r = with_rules(&env, "*.log ignore\n");
    for p in ["x.log", "sub/y.log", "a/b/c/z.log", "keep.txt"] {
        r.write(p, "c\n");
    }
    assert_eq!(r.paths("@"), vec!["keep.txt"]);
}

// Scenario from git t0008-ignores.sh "exact prefix matching (with root)".
#[test]
fn pattern_with_a_slash_is_anchored_to_the_root() {
    let env = Env::new();
    let r = with_rules(&env, "docs/*.tmp ignore\n");
    for p in ["docs/t.tmp", "docs/x/t.tmp", "other/docs/t.tmp"] {
        r.write(p, "c\n");
    }
    assert_eq!(r.paths("@"), vec!["docs/x/t.tmp", "other/docs/t.tmp"]);
}

// Scenario from git t0008-ignores.sh: a leading slash anchors a bare name.
#[test]
fn leading_slash_anchors_a_bare_name() {
    let env = Env::new();
    let r = with_rules(&env, "/rootonly ignore\n");
    r.write("rootonly", "c\n");
    r.write("sub/rootonly", "c\n");
    assert_eq!(r.paths("@"), vec!["sub/rootonly"]);
}

// Scenario from git t0008-ignores.sh "existing file and directory": a
// trailing slash matches directories only.
#[test]
fn trailing_slash_matches_directories_only() {
    let env = Env::new();
    let r = with_rules(&env, "foo/ ignore\n");
    r.write("foo/in.txt", "c\n");
    r.write("sub/foo/in.txt", "c\n");
    r.write("other/foo", "a file named foo\n");
    assert_eq!(r.paths("@"), vec!["other/foo"]);
}

// Scenario from git t0008-ignores.sh "directories and ** matches".
#[test]
fn double_star_in_the_middle_matches_zero_or_more_directories() {
    let env = Env::new();
    let r = with_rules(&env, "a/**/z ignore\n");
    for p in ["a/z", "a/b/z", "a/b/c/z", "a/zz", "b/a/z"] {
        r.write(p, "c\n");
    }
    assert_eq!(r.paths("@"), vec!["a/zz", "b/a/z"]);
}

// Scenario from git t0008-ignores.sh "** not confused by matching leading prefix".
#[test]
fn double_star_prefix_does_not_match_a_longer_name() {
    let env = Env::new();
    let r = with_rules(&env, "**/data ignore\n");
    r.write("data/x", "c\n");
    r.write("deep/data/x", "c\n");
    r.write("database/x", "c\n");
    r.write("mydata/x", "c\n");
    assert_eq!(r.paths("@"), vec!["database/x", "mydata/x"]);
}

// Scenario from git t0008-ignores.sh "nested include of negated pattern":
// Veil has no `!`; a later rule wins instead.
#[test]
fn a_later_public_rule_re_includes_a_file() {
    let env = Env::new();
    let r = with_rules(&env, "*.log ignore\nkeep.log public\n");
    r.write("x.log", "c\n");
    r.write("keep.log", "c\n");
    r.write("sub/keep.log", "c\n");
    assert_eq!(r.paths("@"), vec!["keep.log", "sub/keep.log"]);
}

// Scenario from git t0008-ignores.sh: rule order matters (last match wins).
#[test]
fn rule_order_decides_last_match_wins() {
    let env = Env::new();
    let r = with_rules(&env, "keep.log public\n*.log ignore\n");
    r.write("keep.log", "c\n");
    assert!(r.paths("@").is_empty());
    let out = r.out(&["policy", "check", "keep.log"]);
    assert!(out.contains("ignored via rule '*.log'"), "{out}");
}

// Scenario from git t0008-ignores.sh "nested include of negated pattern"
// under an excluded directory. Git documents that a file cannot be
// re-included below an excluded directory; Veil documents "the last
// matching rule wins", and `vl policy check` agrees, but the snapshot
// never descends into the ignored directory.
#[test]
fn policy_check_and_the_snapshot_agree_below_an_ignored_directory() {
    let env = Env::new();
    let r = with_rules(&env, "build/ ignore\nbuild/keep.txt public\n");
    r.write("build/out.o", "c\n");
    r.write("build/keep.txt", "keep me\n");
    let check = r.out(&["policy", "check", "build/keep.txt"]);
    let recorded = r.paths("@").contains(&"build/keep.txt".to_string());
    let says_public = check.contains("public via");
    assert_eq!(
        says_public, recorded,
        "`vl policy check` says {check:?}, but the snapshot {} it",
        if recorded { "records" } else { "does not record" }
    );
}

// Scenario from git t0008-ignores.sh (patterns with escapes): spaces and
// a leading `#` are escaped with a backslash.
#[test]
fn escaped_space_and_hash_patterns() {
    let env = Env::new();
    let r = with_rules(&env, "my\\ notes.txt ignore\n\\#hash ignore\n");
    r.write("my notes.txt", "c\n");
    r.write("#hash", "c\n");
    r.write("my", "c\n");
    assert_eq!(r.paths("@"), vec!["my"]);
}

// Scenario from git t0008-ignores.sh: comments and blank lines are not rules.
#[test]
fn comments_and_blank_lines_are_not_rules() {
    let env = Env::new();
    let r = with_rules(&env, "\n\n# a comment\n   # indented comment\n\n*.o ignore   # trailing comment\n");
    r.write("x.o", "c\n");
    r.write("# a comment", "c\n");
    let st = r.ok(&["status"]);
    assert!(!st.contains("warning"), "no rule warnings: {st}");
    assert_eq!(r.paths("@"), vec!["# a comment"]);
}

// Scenario from git t0008-ignores.sh (glob syntax): `?`, `[...]` and `{a,b}`.
#[test]
fn character_classes_question_marks_and_alternatives() {
    let env = Env::new();
    let r = with_rules(&env, "file?.c ignore\n[ab].txt ignore\n*.{tmp,bak2} ignore\n");
    for p in ["file1.c", "file10.c", "a.txt", "c.txt", "x.tmp", "x.bak2", "x.tmq"] {
        r.write(p, "c\n");
    }
    assert_eq!(r.paths("@"), vec!["c.txt", "file10.c", "x.tmq"]);
}

// Scenario from git t0008-ignores.sh: ignore rules are case-sensitive
// (documented for Veil: `ignore` rules match case-sensitively).
#[test]
fn ignore_rules_are_case_sensitive() {
    let env = Env::new();
    let r = with_rules(&env, "*.log ignore\n");
    r.write("x.log", "c\n");
    r.write("X.LOG", "c\n");
    assert_eq!(r.paths("@"), vec!["X.LOG"]);
}

// Scenario from git t3001-ls-files-others-exclude.sh: the default policy
// ignores build output at any depth.
#[test]
fn default_policy_ignores_build_output_at_any_depth() {
    let env = Env::new();
    let r = env.repo("p");
    for p in ["target/debug/x", "crates/a/target/y", "node_modules/m/i.js", "web/node_modules/n.js", "targets/keep"] {
        r.write(p, "c\n");
    }
    assert_eq!(r.paths("@"), vec!["targets/keep"]);
}

// Scenario from git t3600-rm.sh `rm --cached` / jj test_file_track_untrack:
// ignoring a tracked file drops it from the next snapshot, keeps it on disk.
#[test]
fn ignoring_a_tracked_file_untracks_it_and_keeps_it_on_disk() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("generated.json", "{}\n");
    r.write("src.rs", "x\n");
    r.commit("one");
    r.ok(&["ignore", "generated.json"]);
    let ch = r.changes();
    assert!(ch.contains(&"D generated.json".to_string()) && ch.contains(&"M .veilpolicy".to_string()), "{ch:?}");
    assert_eq!(r.read("generated.json"), "{}\n");
    r.commit("untrack");
    assert_eq!(r.paths("@-"), vec!["src.rs"]);
    // It survives checkouts it is ignored in.
    r.write("generated.json", "{\"v\":2}\n");
    r.ok(&["new", "@-"]);
    assert_eq!(r.read("generated.json"), "{\"v\":2}\n");
}

// Scenario from jj test_gitignores.rs: ignored files are left alone by
// checkouts of other revisions, including the root.
#[test]
fn ignored_files_survive_checkouts() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("src.rs", "x\n");
    r.write("target/build.bin", "artefact\n");
    let one = r.commit("one");
    r.ok(&["new", "root"]);
    assert!(!r.exists("src.rs"));
    assert_eq!(r.read("target/build.bin"), "artefact\n");
    r.ok(&["edit", one.as_str()]);
    assert_eq!(r.read("src.rs"), "x\n");
    assert_eq!(r.read("target/build.bin"), "artefact\n");
}

// Scenario from git t2204-add-ignored.sh: an ignored file is never
// recorded, even when it holds a secret, and is not quarantined.
#[test]
fn ignored_files_are_not_scanned_or_quarantined() {
    let env = Env::new();
    let r = with_rules(&env, "scratch/ ignore\n");
    r.write("scratch/notes.js", LEAKY);
    let st = r.status();
    assert!(!st.contains("quarantined"), "{st}");
    assert!(!st.contains("scratch"), "{st}");
    assert!(r.paths("@").is_empty());
}

// Scenario from git t0008-ignores.sh (policy explanation, `check-ignore -v`).
#[test]
fn policy_check_names_the_matching_rule() {
    let env = Env::new();
    let r = with_rules(&env, "*.log ignore\n");
    let out = r.out(&["policy", "check", "x.log", "sub/dir/y.log", "app.py", "target/x"]);
    assert!(out.contains("x.log: ignored via rule '*.log'"), "{out}");
    assert!(out.contains("sub/dir/y.log: ignored via rule '*.log'"), "{out}");
    assert!(out.contains("app.py: public via default"), "{out}");
    assert!(out.contains("target/x: ignored via rule 'target/'"), "{out}");
}

// Scenario from git t0008-ignores.sh "sub-directory local ignore": Veil
// reads one policy, at the root; a `.veilpolicy` deeper down is an
// ordinary file (a deliberate difference from per-directory .gitignore).
#[test]
fn a_policy_file_in_a_subdirectory_is_an_ordinary_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("sub/.veilpolicy", "*.txt ignore\n");
    r.write("sub/a.txt", "c\n");
    assert_eq!(r.paths("@"), vec!["sub/.veilpolicy", "sub/a.txt"]);
}

// Scenario from jj test_gitignores.rs: removing an ignore rule starts
// tracking the file again.
#[test]
fn removing_an_ignore_rule_tracks_the_file_again() {
    let env = Env::new();
    let r = env.repo("p");
    let base = r.read(".veilpolicy");
    r.write(".veilpolicy", format!("{base}*.gen ignore\n"));
    r.write("x.gen", "c\n");
    r.commit("ignore gen");
    assert!(r.paths("@-").is_empty());
    r.write(".veilpolicy", base);
    let ch = r.changes();
    assert!(ch.contains(&"A x.gen".to_string()), "{ch:?}");
}

// Scenario from git t0008-ignores.sh with editor scratch files (Veil's
// built-in rules for swap and backup files).
#[test]
fn editor_scratch_files_are_ignored_by_default() {
    let env = Env::new();
    let r = env.repo("p");
    for p in ["main.rs", ".main.rs.swp", ".main.rs.swo", "main.rs~", "#main.rs#", ".#main.rs", "main.rs.bak"] {
        r.write(p, "c\n");
    }
    // Backups of a public file are ordinary files.
    assert_eq!(r.paths("@"), vec!["main.rs", "main.rs.bak"]);
}

// Scenario from git t3700-add.sh (`add` of a file whose name has glob
// characters): `vl ignore <existing path>` escapes it literally.
#[test]
fn vl_ignore_escapes_an_existing_name_with_glob_characters() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("config[prod].yml", "c\n");
    r.write("configp.yml", "c\n");
    let out = r.ok(&["ignore", "config[prod].yml"]);
    assert!(out.contains("literal path"), "{out}");
    assert_eq!(r.paths("@"), vec!["configp.yml"]);
}

// Scenario from git t3700-add.sh / t2204: `vl ignore` is an operation that
// `vl undo` takes back, and the file is tracked again.
#[test]
fn undo_takes_back_an_ignore_rule() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "c\n");
    r.commit("one");
    let policy = r.read(".veilpolicy");
    r.ok(&["ignore", "a.txt"]);
    assert!(r.paths("@").is_empty());
    let out = r.ok(&["undo"]);
    assert!(out.contains("Undid"), "{out}");
    assert_eq!(r.read(".veilpolicy"), policy);
    assert_eq!(r.paths("@"), vec!["a.txt"]);
    assert_eq!(r.read("a.txt"), "c\n");
}

// Scenario from git t0008-ignores.sh "trailing whitespace is ignored".
#[test]
fn trailing_whitespace_after_a_rule_is_ignored() {
    let env = Env::new();
    let r = with_rules(&env, "*.o    ignore   \t \n");
    r.write("x.o", "c\n");
    let st = r.status();
    assert!(!st.contains("warning"), "{st}");
    assert!(r.paths("@").is_empty());
}

// Scenario from git t0008-ignores.sh "multiple files inside ignored
// sub-directory" with Veil's fail-safe rule parsing: an unknown tier
// keeps the files out (isolated), never public.
#[test]
fn a_misspelt_ignore_rule_fails_safe() {
    let env = Env::new();
    let r = with_rules(&env, "scratch/ ingore\n");
    r.write("scratch/a.txt", "c\n");
    let st = r.status();
    assert!(st.contains("warning"), "{st}");
    assert!(r.paths("@").is_empty());
}
