//! `vl diff` / `vl show`: Git t4xxx (diff) and jj test_diff_command.rs.

use super::support::*;

fn body(out: &str) -> Vec<&str> {
    out.lines().collect()
}

// Scenario from git t4017-diff-retval.sh / jj test_diff_empty: no change, no hunks.
#[test]
fn diff_of_an_empty_working_copy_says_no_changes() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("a.txt", "a\n")]);
    let out = r.out(&["diff"]);
    assert_eq!(out.trim(), "(no changes)", "{out}");
    assert_eq!(r.out(&["diff", "--stat"]).trim(), "(no changes)");
}

// Scenario from jj test_diff_empty: diff of the root snapshot.
#[test]
fn diff_of_the_root_is_empty() {
    let env = Env::new();
    let r = env.repo("p");
    assert_eq!(r.out(&["diff", "-r", "root"]).trim(), "(no changes)");
    let show = r.out(&["show", "root"]);
    assert!(show.contains("(no changes)"), "{show}");
}

// Scenario from git t4000-diff-format.sh: a modified line becomes -old/+new in one hunk.
#[test]
fn modified_line_shows_minus_and_plus() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("f.txt", "one\ntwo\nthree\n")]);
    r.write("f.txt", "one\nTWO\nthree\n");
    let out = r.out(&["diff"]);
    let l = body(&out);
    assert_eq!(l[0], "diff --veil a/f.txt b/f.txt", "{out}");
    assert!(l.contains(&"-two") && l.contains(&"+TWO"), "{out}");
    assert!(
        l.contains(&" one") && l.contains(&" three"),
        "context lines: {out}"
    );
    assert_eq!(l.iter().filter(|x| x.starts_with("@@")).count(), 1, "{out}");
    assert!(l.iter().any(|x| x.starts_with("@@ -1,3 +1,3 @@")), "{out}");
}

// Scenario from git t4000-diff-format.sh / jj test_diff_basic: added and deleted files.
#[test]
fn added_and_deleted_files_are_labelled() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("gone.txt", "bye\n"), ("keep.txt", "k\n")]);
    r.rm("gone.txt");
    r.write("new.txt", "hello\n");
    let out = r.out(&["diff"]);
    assert!(
        out.contains("diff --veil a/gone.txt b/gone.txt\ndeleted file\n"),
        "{out}"
    );
    assert!(out.contains("-bye"), "{out}");
    assert!(
        out.contains("diff --veil a/new.txt b/new.txt\nadded file"),
        "{out}"
    );
    assert!(out.contains("+hello"), "{out}");
    assert!(!out.contains("keep.txt"), "{out}");
    let stat = r.out(&["diff", "--stat"]);
    assert_eq!(
        stat.lines().collect::<Vec<_>>(),
        vec!["D gone.txt", "A new.txt"],
        "{stat}"
    );
}

// Scenario from git t4013-diff-various.sh: several hunks in one file.
#[test]
fn distant_edits_make_separate_hunks() {
    let env = Env::new();
    let r = env.repo("p");
    let base = lines("line", 40);
    r.commit("first", &[("f.txt", &base)]);
    let edited = base
        .replace("line2\n", "LINE2\n")
        .replace("line38\n", "LINE38\n");
    r.write("f.txt", &edited);
    let out = r.out(&["diff"]);
    assert_eq!(
        out.lines().filter(|l| l.starts_with("@@")).count(),
        2,
        "{out}"
    );
    assert!(
        !out.contains(" line20\n"),
        "far context must not be printed: {out}"
    );
}

// Scenario from git t4055-diff-context.sh: nearby edits merge into one hunk.
#[test]
fn nearby_edits_share_one_hunk() {
    let env = Env::new();
    let r = env.repo("p");
    let base = lines("l", 20);
    r.commit("first", &[("f.txt", &base)]);
    r.write(
        "f.txt",
        base.replace("l5\n", "L5\n").replace("l9\n", "L9\n"),
    );
    let out = r.out(&["diff"]);
    assert_eq!(
        out.lines().filter(|l| l.starts_with("@@")).count(),
        1,
        "{out}"
    );
}

// Scenario from git t4101-apply-nonl.sh / jj test_diff_missing_newline: final line without newline.
#[test]
fn missing_trailing_newline_is_marked() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("f.txt", "a\nb\n")]);
    r.write("f.txt", "a\nb");
    let out = r.out(&["diff"]);
    assert!(out.contains("\\ No newline at end of file"), "{out}");
    assert!(out.contains("-b\n") && out.contains("+b\n"), "{out}");
}

// Scenario from git t4101-apply-nonl.sh: adding the newline back.
#[test]
fn adding_a_trailing_newline_is_a_change() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("f.txt", "a\nb")]);
    r.write("f.txt", "a\nb\n");
    let out = r.out(&["diff"]);
    assert!(out.contains("\\ No newline at end of file"), "{out}");
    assert_eq!(r.out(&["diff", "--stat"]).trim(), "M f.txt");
}

// Scenario from jj test_diff_missing_newline: both versions lack the newline.
#[test]
fn edit_of_a_file_without_newline_on_both_sides() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("f.txt", "x\ny")]);
    r.write("f.txt", "x\nz");
    let out = r.out(&["diff"]);
    assert!(out.contains("-y") && out.contains("+z"), "{out}");
}

// Scenario from git t4012-diff-binary.sh / jj test_diff_binary: binary content is not printed.
#[test]
fn binary_change_is_summarised() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("b.bin", [0u8, 1, 2, 3, 255, 0, 9]);
    r.ok(&["commit", "-m", "bin"]);
    r.write("b.bin", [0u8, 1, 2, 4, 255, 0, 9, 10]);
    let out = r.out(&["diff"]);
    assert!(out.contains("diff --veil a/b.bin b/b.bin"), "{out}");
    assert!(out.contains("(binary content differs)"), "{out}");
    assert!(!out.contains('\0'), "raw binary in the diff");
    assert_eq!(r.out(&["diff", "--stat"]).trim(), "M b.bin");
}

// Scenario from git t4012-diff-binary.sh: a new binary file.
#[test]
fn added_binary_file_is_summarised() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("img.png", b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR");
    let out = r.out(&["diff"]);
    assert!(out.contains("added file"), "{out}");
    assert!(out.contains("(binary content differs)"), "{out}");
}

// Scenario from git t4031-diff-rewrite-binary.sh: text rewritten to binary.
#[test]
fn text_turned_binary_is_summarised() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("f", "plain text\n")]);
    r.write("f", b"plain\0text\n");
    let out = r.out(&["diff"]);
    assert!(out.contains("(binary content differs)"), "{out}");
}

// Scenario from jj test_diff_stat_binary_and_text: --stat lists text and binary alike.
#[test]
fn stat_lists_binary_and_text_changes() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.bin", [0u8, 1]);
    r.write("b.txt", "t\n");
    let stat = r.out(&["diff", "--stat"]);
    assert!(
        stat.contains("A a.bin") && stat.contains("A b.txt"),
        "{stat}"
    );
}

// Scenario from git t4006-diff-mode.sh / jj test_diff_file_mode: an executable-bit change is a change.
#[test]
fn mode_only_change_is_listed_by_stat() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("run.sh", "echo hi\n")]);
    r.chmod_x("run.sh", true);
    assert_eq!(r.out(&["diff", "--stat"]).trim(), "M run.sh");
    let files = r.tree_files("@");
    assert!(
        files.iter().any(|f| f.0 == "run.sh" && f.3),
        "executable bit not recorded"
    );
}

// Scenario from git t4006-diff-mode.sh / jj test_diff_file_mode: the full diff names the mode change.
#[test]
fn mode_only_change_is_described_in_the_diff() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("run.sh", "echo hi\n")]);
    r.chmod_x("run.sh", true);
    let out = r.out(&["diff"]);
    let after_header: Vec<&str> = out.lines().skip(1).collect();
    assert!(
        after_header
            .iter()
            .any(|l| l.contains("mode") || l.contains("executable")),
        "the diff of a chmod +x says nothing beyond its header:\n{out}"
    );
}

// Scenario from git t4006-diff-mode.sh: removing the executable bit is recorded too.
#[test]
fn removing_the_executable_bit_is_recorded() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("run.sh", "echo\n");
    r.chmod_x("run.sh", true);
    r.ok(&["commit", "-m", "x"]);
    r.chmod_x("run.sh", false);
    assert_eq!(r.out(&["diff", "--stat"]).trim(), "M run.sh");
    assert!(r.tree_files("@").iter().any(|f| f.0 == "run.sh" && !f.3));
}

// Scenario from git t4015-diff-whitespace.sh: whitespace-only edits are real changes.
#[test]
fn whitespace_only_edits_are_shown() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("f.txt", "a b\nc\n")]);
    r.write("f.txt", "a  b\nc \n");
    let out = r.out(&["diff"]);
    assert!(out.contains("-a b") && out.contains("+a  b"), "{out}");
    assert!(out.contains("+c \n"), "trailing space kept: {out:?}");
}

// Scenario from git t4015-diff-whitespace.sh: CRLF vs LF is a change (no autocrlf in Veil).
#[test]
fn line_ending_change_is_shown() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("f.txt", "a\nb\n")]);
    r.write("f.txt", "a\r\nb\r\n");
    assert_eq!(r.out(&["diff", "--stat"]).trim(), "M f.txt");
    assert_eq!(r.read_bytes("f.txt"), b"a\r\nb\r\n");
    assert_eq!(r.cat("@", "f.txt").as_bytes(), b"a\r\nb\r\n");
}

// Scenario from git t4029-diff-trailing-space.sh: tabs are preserved in diff lines.
#[test]
fn tabs_survive_in_diff_lines() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("Makefile", "all:\n\techo a\n")]);
    r.write("Makefile", "all:\n\techo b\n");
    let out = r.out(&["diff"]);
    assert!(out.contains("+\techo b"), "{out:?}");
}

// Scenario from jj test_diff_basic: empty file added and removed.
#[test]
fn empty_files_are_added_and_removed() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("empty", "");
    let out = r.out(&["diff"]);
    assert!(
        out.contains("diff --veil a/empty b/empty\nadded file"),
        "{out}"
    );
    r.ok(&["commit", "-m", "e"]);
    r.rm("empty");
    assert_eq!(r.out(&["diff", "--stat"]).trim(), "D empty");
}

// Scenario from git t4022-diff-rewrite.sh: emptying a file and filling an empty one.
#[test]
fn file_emptied_and_filled() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("a", "content\n"), ("b", "")]);
    r.write("a", "");
    r.write("b", "now\n");
    let out = r.out(&["diff"]);
    assert!(out.contains("-content"), "{out}");
    assert!(out.contains("+now"), "{out}");
    assert_eq!(r.out(&["diff", "--stat"]).lines().count(), 2);
}

// Scenario from git t4037-diff-r-t-dirs.sh / jj test_diff_types: a file replaced by a directory.
#[test]
fn file_replaced_by_directory() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("thing", "i am a file\n")]);
    r.rm("thing");
    r.write("thing/inner.txt", "i am inside\n");
    let stat = r.out(&["diff", "--stat"]);
    assert!(stat.contains("D thing\n"), "{stat}");
    assert!(stat.contains("A thing/inner.txt"), "{stat}");
    let out = r.out(&["diff"]);
    assert!(
        out.contains("-i am a file") && out.contains("+i am inside"),
        "{out}"
    );
}

// Scenario from git t4037-diff-r-t-dirs.sh / jj test_diff_types: a directory replaced by a file.
#[test]
fn directory_replaced_by_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit(
        "first",
        &[("thing/a.txt", "a\n"), ("thing/sub/b.txt", "b\n")],
    );
    r.rm("thing");
    r.write("thing", "now a file\n");
    let stat = r.out(&["diff", "--stat"]);
    for want in ["D thing/a.txt", "D thing/sub/b.txt", "A thing"] {
        assert!(stat.lines().any(|l| l == want), "missing {want}: {stat}");
    }
    assert_eq!(r.paths("@"), vec![".veilpolicy", "thing"]);
}

// Scenario from git t4016-diff-quote.sh: unusual but legal file names.
#[test]
fn unusual_names_appear_in_the_diff() {
    let env = Env::new();
    let r = env.repo("p");
    let names = [
        "with space.txt",
        "-leading-dash",
        "ünïcödé.txt",
        "日本語.md",
        "a\"quote",
        "tab\there",
    ];
    for n in names {
        r.write(n, "x\n");
    }
    let stat = r.out(&["diff", "--stat"]);
    for n in names {
        let shown = n.replace('\t', "\\t");
        assert!(
            stat.contains(n) || stat.contains(&shown),
            "{n:?} missing from:\n{stat}"
        );
    }
    r.ok(&["commit", "-m", "names"]);
    assert_eq!(r.out(&["cat", "-r", "@-", "--", "-leading-dash"]), "x\n");
}

// Scenario from git t4016-diff-quote.sh: a newline inside a file name cannot forge diff lines.
#[test]
fn newline_in_a_file_name_is_escaped() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("evil\n+forged", "x\n");
    let out = r.out(&["diff"]);
    assert!(!out.lines().any(|l| l == "+forged b/evil"), "{out}");
    assert!(
        !out.lines().any(|l| l.starts_with("+forged")),
        "a file name forged a diff line:\n{out}"
    );
}

// Scenario from git t4013-diff-various.sh: deep paths.
#[test]
fn deep_paths_are_diffed() {
    let env = Env::new();
    let r = env.repo("p");
    let deep = (0..40)
        .map(|i| format!("d{i}"))
        .collect::<Vec<_>>()
        .join("/")
        + "/leaf.txt";
    r.write(&deep, "deep\n");
    let stat = r.out(&["diff", "--stat"]);
    assert!(stat.contains(&deep), "{stat}");
}

// Scenario from jj test_diff_revisions: diff between two arbitrary snapshots, both directions.
#[test]
fn diff_from_to_and_its_reverse() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    r.commit("two", &[("f", "2\n"), ("g", "g\n")]);
    r.commit("three", &[("f", "3\n")]);
    let fwd = r.out(&["diff", "--from", "@---", "--to", "@-"]);
    assert!(
        fwd.contains("-1") && fwd.contains("+3") && fwd.contains("+g"),
        "{fwd}"
    );
    assert!(!fwd.contains("2\n"), "intermediate version shown: {fwd}");
    let back = r.out(&["diff", "--from", "@-", "--to", "@---"]);
    assert!(
        back.contains("-3") && back.contains("+1") && back.contains("-g"),
        "{back}"
    );
    let stat = r.out(&["diff", "--from", "@-", "--to", "@---", "--stat"]);
    assert!(stat.contains("D g") && stat.contains("M f"), "{stat}");
}

// Scenario from git t4017-diff-retval.sh: comparing a snapshot with itself.
#[test]
fn diff_of_a_snapshot_with_itself_is_empty() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    assert_eq!(
        r.out(&["diff", "--from", "@-", "--to", "@-"]).trim(),
        "(no changes)"
    );
}

// Scenario from jj test_diff_revisions: only --from given compares against @.
#[test]
fn diff_from_alone_compares_with_the_working_copy() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    r.commit("two", &[("f", "2\n")]);
    r.write("f", "3\n");
    let out = r.out(&["diff", "--from", "@--"]);
    assert!(out.contains("-1") && out.contains("+3"), "{out}");
}

// Scenario from jj test_diff_bad_args: unknown revisions fail cleanly.
#[test]
fn diff_of_an_unknown_revision_fails() {
    let env = Env::new();
    let r = env.repo("p");
    let err = r.fails(&["diff", "-r", "nosuchtag"]);
    assert!(err.contains("not found"), "{err}");
    r.fails(&["diff", "--from", "zzzzkkkkzzzz", "--to", "@"]);
    r.fails(&["show", "deadbeef"]);
}

// Scenario from jj test_diff_bad_args: -r together with --from/--to is ambiguous.
#[test]
fn diff_rev_with_from_is_refused() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    r.commit("two", &[("f", "2\n")]);
    r.fails(&["diff", "-r", "@-", "--from", "@--"]);
}

// Scenario from git t4038-diff-combined.sh: a clean merge has no changes of its own.
#[test]
fn diff_of_a_clean_merge_is_empty() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("a", "a\n"), ("b", "b\n")]);
    r.tag("base", "@-");
    r.commit("left", &[("a", "A\n")]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    r.commit("right", &[("b", "B\n")]);
    r.ok(&["merge", "left", "-m", "m"]);
    assert_eq!(r.out(&["diff", "-r", "@-"]).trim(), "(no changes)");
    let show = r.out(&["show", "@-"]);
    assert_eq!(show.matches("Parent    :").count(), 2, "{show}");
}

// Scenario from git t4038-diff-combined.sh / jj test_diff_conflict_*: a conflicted merge's own diff
// is relative to the merged parents, which already hold the markers; its child shows the resolution.
#[test]
fn diff_of_a_conflicted_merge_and_its_resolution() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("f", "base\n")]);
    r.tag("base", "@-");
    r.commit("left", &[("f", "left\n")]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    r.commit("right", &[("f", "right\n")]);
    r.ok(&["merge", "left"]);
    assert_eq!(r.out(&["diff", "-r", "@-"]).trim(), "(no changes)");
    r.write("f", "resolved\n");
    let d = r.out(&["diff"]);
    assert!(
        d.contains("-<<<<<<< ours") && d.contains("+resolved"),
        "{d}"
    );
}

// Scenario from jj test_diff_conflict_* / test_log (conflict marker): `vl show` of a conflicted snapshot says so.
#[test]
fn show_of_a_conflicted_merge_names_the_conflicts() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("f", "base\n")]);
    r.tag("base", "@-");
    r.commit("left", &[("f", "left\n")]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    r.commit("right", &[("f", "right\n")]);
    r.ok(&["merge", "left"]);
    assert_eq!(r.snap("@-").conflicts, vec!["f".to_string()]);
    let show = r.out(&["show", "@-"]);
    assert!(
        show.to_lowercase().contains("conflict"),
        "show says nothing about the conflict in f:\n{show}"
    );
}

// Scenario from git t4013-diff-various.sh (show): metadata then diff.
#[test]
fn show_prints_metadata_then_the_diff() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("Add greeting\n\nLonger body.", &[("hello.txt", "hi\n")]);
    let out = r.out(&["show", "@-"]);
    let change = r.cid("@-");
    assert!(out.contains(&format!("Change ID : {change}")), "{out}");
    assert!(
        out.contains("    Add greeting\n") && out.contains("    Longer body."),
        "{out}"
    );
    let d = out.find("diff --veil a/hello.txt").expect("diff part");
    assert!(out.find("Add greeting").unwrap() < d);
    let stat = r.out(&["show", "@-", "--stat"]);
    assert!(
        stat.contains("A hello.txt") && !stat.contains("+hi"),
        "{stat}"
    );
}

// Scenario from git t4013-diff-various.sh: diff of an older change with -r.
#[test]
fn diff_r_shows_that_changes_own_diff() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("zero", &[]);
    r.commit("one", &[("f", "1\n")]);
    r.commit("two", &[("g", "2\n")]);
    let out = r.out(&["diff", "-r", "@--", "--stat"]);
    assert_eq!(out.trim(), "A f");
}

// Scenario from git t4033-diff-patience.sh: large file with one change stays quick and minimal.
#[test]
fn large_file_with_one_edit() {
    let env = Env::new();
    let r = env.repo("p");
    let base = lines("row ", 20_000);
    r.commit("big", &[("big.txt", &base)]);
    r.write("big.txt", base.replace("row 10000\n", "ROW 10000\n"));
    let start = std::time::Instant::now();
    let out = r.out(&["diff"]);
    assert!(start.elapsed().as_secs() < 30);
    assert_eq!(
        out.lines()
            .filter(|l| l.starts_with('+') || l.starts_with('-'))
            .count(),
        2,
        "{out}"
    );
}

// Scenario from git t4013-diff-various.sh: non-UTF-8 text is shown without crashing.
#[test]
fn latin1_text_is_diffed() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("l1.txt", b"caf\xe9\n");
    r.ok(&["commit", "-m", "l1"]);
    r.write("l1.txt", b"caf\xe9 au lait\n");
    let out = r.run(&["diff"]);
    assert!(
        out.status.success() && exited_cleanly(&out),
        "{}",
        text(&out)
    );
    assert_eq!(r.read_bytes("l1.txt"), b"caf\xe9 au lait\n");
    let cat = r.run(&["cat", "l1.txt", "-r", "@-"]);
    assert!(cat.status.success(), "{}", text(&cat));
    assert_eq!(
        cat.stdout,
        b"caf\xe9\n",
        "cat must return the raw bytes"
    );
}

// Scenario from git t4016-diff-quote.sh: terminal escapes in content are neutralised.
#[test]
fn escape_sequences_in_content_are_neutralised() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("f", "before\x1b]0;pwned\x07after\n");
    let out = r.out(&["diff"]);
    assert!(!out.contains('\x1b'), "raw ESC in diff output: {out:?}");
}
