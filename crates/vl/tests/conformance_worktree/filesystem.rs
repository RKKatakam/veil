//! File names and filesystem behaviour: git t0050-filesystem,
//! t3910-mac-os-precompose, t3300-funny-names, t3902-quoted,
//! t7450-bad-git-dotfiles (reserved names); jj test_working_copy.

use crate::*;

const NFC: &str = "caf\u{e9}";
const NFD: &str = "cafe\u{301}";

// Scenario from git t0050-filesystem.sh "setup case tests": a pair of
// names that differ only in case is recorded on Linux, with a warning.
#[test]
fn case_only_pair_is_recorded_with_a_warning() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("README", "upper\n");
    r.write("readme", "lower\n");
    let st = r.ok(&["status"]);
    assert!(st.contains("README and readme differ only in case"), "{st}");
    assert_eq!(r.paths("@"), vec!["README", "readme"]);
    assert_eq!(r.cat("README", "@"), "upper\n");
    assert_eq!(r.cat("readme", "@"), "lower\n");
}

// Scenario from git t0050-filesystem.sh "setup unicode normalization tests".
#[test]
fn nfc_and_nfd_spellings_are_two_files_on_linux_with_a_warning() {
    let env = Env::new();
    let r = env.repo("p");
    r.write(NFC, "nfc\n");
    r.write(NFD, "nfd\n");
    let st = r.ok(&["status"]);
    assert!(st.contains("differ only in case or Unicode normalisation"), "{st}");
    let paths = r.paths("@");
    assert_eq!(paths.len(), 2, "{paths:?}");
    assert_eq!(r.cat(NFC, "@"), "nfc\n");
    assert_eq!(r.cat(NFD, "@"), "nfd\n");
}

// Scenario from git t0050-filesystem.sh "checkout with no pathspec and a
// case insensitive fs": the checkout is refused, and nothing is changed.
#[test]
fn checkout_of_a_case_collision_is_refused_on_a_folding_filesystem() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("README", "upper\n");
    r.write("readme", "lower\n");
    r.write("other.txt", "keep\n");
    let pairs = r.commit("pairs");
    r.ok(&["new", "root"]);
    r.write("wip.txt", "unrecorded work\n");
    let before = r.disk();
    let out = r.cmd(&["new", pairs.as_str()]).env("VEIL_FS_FOLDING", "case").output().unwrap();
    let t = text(&out);
    assert!(!out.status.success() && clean_exit(&out), "{t}");
    assert!(t.contains("'README' and 'readme'"), "{t}");
    assert!(t.contains("Nothing in the working copy was changed"), "{t}");
    assert_eq!(r.disk(), before);
    // Moving back without touching files works, as the hint says.
    let back = r.cmd(&["--no-snapshot", "undo"]).env("VEIL_FS_FOLDING", "case").output().unwrap();
    assert!(back.status.success(), "{}", text(&back));
    assert_eq!(r.read("wip.txt"), "unrecorded work\n");
}

// Scenario from git t3910-mac-os-precompose.sh: a precomposed/decomposed
// pair is refused where the filesystem folds Unicode, but not where it
// only folds case.
#[test]
fn unicode_collision_is_refused_only_where_the_filesystem_normalises() {
    let env = Env::new();
    let r = env.repo("p");
    r.write(NFC, "nfc\n");
    r.write(NFD, "nfd\n");
    let pairs = r.commit("pairs");
    r.ok(&["new", "root"]);
    let case_only = r.cmd(&["new", pairs.as_str()]).env("VEIL_FS_FOLDING", "case").output().unwrap();
    assert!(case_only.status.success(), "{}", text(&case_only));
    r.ok(&["new", "root"]);
    let unicode = r.cmd(&["new", pairs.as_str()]).env("VEIL_FS_FOLDING", "unicode").output().unwrap();
    assert!(!unicode.status.success() && clean_exit(&unicode), "{}", text(&unicode));
}

// Scenario from git t0050-filesystem.sh "rename (case change)": on a
// case-sensitive filesystem a case-only rename is a delete and an add.
#[test]
fn case_only_rename_on_linux_is_a_delete_and_an_add() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("README.md", "doc\n");
    r.commit("one");
    std::fs::rename(r.path("README.md"), r.path("Readme.md")).unwrap();
    assert_eq!(r.changes(), vec!["D README.md", "A Readme.md"]);
    r.commit("rename");
    assert_eq!(r.paths("@-"), vec!["Readme.md"]);
}

// Scenario from git t3910-mac-os-precompose.sh: names keep the spelling
// they were recorded with (no re-normalisation of existing entries).
#[test]
fn recorded_spelling_is_kept_across_checkouts() {
    let env = Env::new();
    let r = env.repo("p");
    r.write(&format!("{NFD}/menu.txt"), "x\n");
    let c = r.commit("nfd dir");
    r.ok(&["new", "root"]);
    r.ok(&["new", c.as_str()]);
    let names: Vec<String> = std::fs::read_dir(&r.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(names.contains(&NFD.to_string()), "{names:?}");
    assert_eq!(r.paths("@"), vec![format!("{NFD}/menu.txt")]);
}

// Scenario from git t3300-funny-names.sh: spaces, tabs, quotes,
// backslashes, glob characters and leading dashes.
#[test]
fn funny_names_round_trip_through_a_checkout() {
    let env = Env::new();
    let r = env.repo("p");
    let names = [
        "with space",
        "  leading spaces",
        "trailing space ",
        "tab\there",
        "quote\"d",
        "single'q",
        "star*q?[x]",
        "-rf",
        "--",
        "@",
        "root",
        "..dots",
        "a:b",
        "emoji-\u{1f600}",
        "\u{65e5}\u{672c}\u{8a9e}/\u{30d5}\u{30a1}\u{30a4}\u{30eb}",
    ];
    for (i, n) in names.iter().enumerate() {
        r.write(n, format!("content {i}\n"));
    }
    let c = r.commit("funny");
    let mut want: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    want.sort();
    let got = r.paths("@-");
    assert_eq!(got.len(), names.len(), "{got:?}");
    r.ok(&["new", "root"]);
    assert!(r.disk_files().is_empty());
    r.ok(&["new", c.as_str()]);
    for (i, n) in names.iter().enumerate() {
        assert_eq!(r.read(n), format!("content {i}\n"), "{n:?}");
        assert_eq!(r.cat(n, c.as_str()), format!("content {i}\n"), "{n:?}");
    }
}

// Scenario from git t3300-funny-names.sh: a backslash is an ordinary
// character in a file name on Linux and macOS; commands that take a path
// must address that file, not `back/slash`.
#[test]
fn a_backslash_in_a_path_argument_names_that_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("back\\slash", "backslash file\n");
    r.write("back/slash", "nested file\n");
    r.commit("both");
    assert_eq!(r.paths("@-").len(), 2);
    let out = r.run(&["cat", "-r", "@-", "back\\slash"]);
    assert_eq!(stdout_of(&out), "backslash file\n", "{}", text(&out));
    // Restoring the backslash file must not touch the other one.
    r.write("back\\slash", "edit A\n");
    r.write("back/slash", "edit B\n");
    r.ok(&["restore", "back\\slash"]);
    assert_eq!(r.read("back\\slash"), "backslash file\n");
    assert_eq!(r.read("back/slash"), "edit B\n", "restore discarded the edit of another file");
}

// Scenario from git t3300-funny-names.sh / t3902-quoted.sh: a newline and
// an escape sequence in a name are recorded, and printed escaped.
#[test]
fn control_characters_in_names_are_recorded_and_printed_escaped() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a\nb", "nl\n");
    r.write("esc\u{1b}[31mred", "esc\n");
    let st = r.out(&["status"]);
    assert!(!st.contains('\u{1b}'), "raw escape printed: {st:?}");
    assert!(st.contains("A a\\nb"), "{st}");
    let files = r.out(&["files"]);
    assert!(!files.contains('\u{1b}') && files.contains("esc\\x1b[31mred"), "{files:?}");
    let c = r.commit("ctl");
    r.ok(&["new", "root"]);
    r.ok(&["new", c.as_str()]);
    assert_eq!(r.read("a\nb"), "nl\n");
}

// Scenario from git t3300-funny-names.sh with an invalid UTF-8 name:
// Veil reports and skips it (documented), and never deletes it.
#[cfg(target_os = "linux")]
#[test]
fn non_utf8_names_are_reported_and_left_alone() {
    use std::os::unix::ffi::OsStrExt;
    let env = Env::new();
    let r = env.repo("p");
    let bad = r.dir.join(std::ffi::OsStr::from_bytes(b"bad\xffname"));
    std::fs::write(&bad, "x").unwrap();
    r.write("good.txt", "g\n");
    let st = r.ok(&["status"]);
    assert!(st.contains("not valid UTF-8"), "{st}");
    let c = r.commit("one");
    r.ok(&["new", "root"]);
    assert!(bad.exists(), "the unrecordable file is not removed by a checkout");
    r.ok(&["new", c.as_str()]);
    assert!(bad.exists());
    assert_eq!(r.paths("@"), vec!["good.txt"]);
}

// Scenario from git t7450-bad-git-dotfiles.sh: the metadata directory
// name is reserved at any depth and in any case.
#[test]
fn reserved_metadata_names_are_never_recorded() {
    let env = Env::new();
    let r = env.repo("p");
    for p in ["sub/.veil/objects/x", ".VEIL/x", "a/.Veil/y", "ok/.veilx/z"] {
        r.write(p, "c\n");
    }
    assert_eq!(r.paths("@"), vec!["ok/.veilx/z"]);
}

// Scenario from git t3300-funny-names.sh with a maximal file name: names
// up to the filesystem's 255-byte limit can be recorded, so they must be
// checked out too.
#[test]
fn a_name_of_240_bytes_round_trips() {
    let env = Env::new();
    let r = env.repo("p");
    let name = "n".repeat(240);
    r.write(&name, "long\n");
    let c = r.commit("long");
    r.ok(&["new", "root"]);
    r.ok(&["new", c.as_str()]);
    assert_eq!(r.read(&name), "long\n");
}

// Scenario from git t3300-funny-names.sh with a 250-byte file name (legal
// on ext4, APFS and most filesystems: the limit is 255 bytes). Veil records
// it, but checkout writes a temporary `.<name>.vltmpXXXXXXXX` next to it,
// which exceeds the limit: every later command fails on the stale working
// copy.
#[test]
fn a_name_of_250_bytes_round_trips() {
    let env = Env::new();
    let r = env.repo("p");
    let name = "n".repeat(250);
    r.write(&name, "long\n");
    let c = r.commit("long");
    r.ok(&["new", "root"]);
    let out = r.run(&["new", c.as_str()]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.read(&name), "long\n");
    // And the repository keeps working.
    r.ok(&["status"]);
}

// Scenario from git t3300-funny-names.sh: restore writes long names too.
#[test]
fn restore_of_a_250_byte_name() {
    let env = Env::new();
    let r = env.repo("p");
    let name = "r".repeat(250);
    r.write(&name, "v1\n");
    r.commit("one");
    r.write(&name, "v2\n");
    let out = r.run(&["restore", "--", name.as_str()]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.read(&name), "v1\n");
}

// Scenario from git t3300-funny-names.sh: a file name that looks like an
// option is handled after `--`.
#[test]
fn option_like_names_work_after_a_double_dash() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("-r", "dash r\n");
    r.write("--help", "dash help\n");
    r.commit("dashes");
    assert_eq!(r.out(&["cat", "--", "-r"]), "dash r\n");
    assert_eq!(r.out(&["cat", "-r", "@-", "--", "--help"]), "dash help\n");
    r.write("-r", "edited\n");
    r.ok(&["restore", "--", "-r"]);
    assert_eq!(r.read("-r"), "dash r\n");
}

// Scenario from jj test_working_copy.rs / git t0050: a deep directory
// hierarchy is recorded and checked out.
#[test]
fn deep_paths_round_trip() {
    let env = Env::new();
    let r = env.repo("p");
    let deep: String = (0..80).map(|i| format!("d{i}/")).collect::<String>() + "leaf.txt";
    r.write(&deep, "deep\n");
    let c = r.commit("deep");
    r.ok(&["new", "root"]);
    assert!(!r.exists("d0"), "empty parent directories are removed");
    r.ok(&["new", c.as_str()]);
    assert_eq!(r.read(&deep), "deep\n");
}

// Scenario from jj test_working_copy.rs: empty directories are not
// recorded, and a directory left empty by a checkout is removed.
#[test]
fn empty_directories_are_not_recorded() {
    let env = Env::new();
    let r = env.repo("p");
    r.mkdir("empty/inner");
    r.write("dir/f.txt", "x\n");
    let c = r.commit("dirs");
    assert_eq!(r.paths("@-"), vec!["dir/f.txt"]);
    r.ok(&["new", "root"]);
    assert!(!r.exists("dir"));
    r.ok(&["new", c.as_str()]);
    assert!(r.exists("dir/f.txt"));
}
