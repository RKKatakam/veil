//! `vl log`: Git t4202-log.sh, t4214/t4215/t4218 (graph), t6003 (topo
//! order); jj test_log_command.rs.

use super::merge::fork;
use super::support::*;

/// Row index of each change's node line in `vl log` output.
fn row_of(log: &str, change: &str) -> usize {
    let short = &change[..8];
    log.lines()
        .position(|l| {
            l.split_whitespace().any(|w| w == short) && (l.contains(" alice ") || l.contains("◆"))
        })
        .unwrap_or_else(|| panic!("{short} not in log:\n{log}"))
}

fn assert_topological(r: &R, log: &str) {
    let repo = r.core();
    let root = repo.root_id();
    for id in repo.exact().visible().unwrap() {
        if id == root {
            continue;
        }
        let s = snap_of(&repo, &id);
        for p in s.parent_changes.iter().filter(|p| !p.is_empty()) {
            assert!(
                row_of(log, &s.change) < row_of(log, p),
                "{} shown after its parent {}:\n{log}",
                &s.change[..8],
                &p[..8]
            );
        }
    }
}

// Scenario from jj test_log_with_empty_revision / git t4202: a fresh repository shows @ and the root.
#[test]
fn log_of_a_fresh_repository() {
    let env = Env::new();
    let r = env.repo("p");
    let log = r.out(&["log"]);
    let nodes: Vec<&str> = log
        .lines()
        .filter(|l| l.starts_with('@') || l.starts_with('◆') || l.starts_with('○'))
        .collect();
    assert_eq!(nodes.len(), 2, "{log}");
    assert!(
        nodes[0].starts_with('@') && nodes[0].contains("default@"),
        "{log}"
    );
    assert!(
        nodes[1].starts_with('◆') && nodes[1].contains("zzzzzzzz"),
        "{log}"
    );
    assert!(log.trim_end().ends_with("root()"), "{log}");
}

// Scenario from git t6003-rev-list-topo-order.sh: children always come before parents.
#[test]
fn log_is_in_topological_order() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("k", "k\n")],
        |r: &R| r.write("l", "l\n"),
        |r: &R| r.write("r", "r\n"),
    );
    r.ok(&["merge", "left"]);
    r.commit("after", &[("z", "z\n")]);
    r.ok(&["new", "base"]);
    r.commit("side", &[("s", "s\n")]);
    let log = r.out(&["log"]);
    assert_topological(&r, &log);
}

// Scenario from git t4202-log.sh (-n) / jj test_log_limit.
#[test]
fn log_limit_elides_the_rest() {
    let env = Env::new();
    let r = env.repo("p");
    for i in 0..5 {
        r.commit(&format!("c{i}"), &[("f", &format!("{i}\n"))]);
    }
    let log = r.out(&["log", "-n", "2"]);
    let nodes = log
        .lines()
        .filter(|l| l.starts_with('@') || l.starts_with('○'))
        .count();
    assert_eq!(nodes, 2, "{log}");
    assert!(log.contains("more snapshots elided"), "{log}");
    // Match description lines exactly: a hex id can contain "c3".
    let has = |d: &str| log.lines().any(|l| l.trim_start_matches(['│', ' ']).trim_end() == d);
    assert!(has("c4") && !has("c3"), "{log}");
}

// Scenario from git t4217-log-limit.sh: -n 0 shows nothing but the elision.
#[test]
fn log_limit_zero() {
    let env = Env::new();
    let r = env.repo("p");
    let log = r.out(&["log", "-n", "0"]);
    assert!(!log.lines().any(|l| l.starts_with('@')), "{log}");
}

// Scenario from jj test_log_bad_args: a malformed limit is refused.
#[test]
fn log_limit_must_be_a_number() {
    let env = Env::new();
    let r = env.repo("p");
    r.fails(&["log", "-n", "many"]);
    r.fails(&["log", "-n", "-3"]);
}

// Scenario from git t4214-log-graph-octopus.sh: an octopus merge is drawn and names its parents.
#[test]
fn log_names_the_parents_of_a_merge() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.tag("base", "@-");
    for n in ["a", "b", "c", "d"] {
        r.ok(&["new", "base"]);
        r.commit(n, &[(n, n)]);
        r.tag(n, "@-");
    }
    r.ok(&["new", "a"]);
    let ids: Vec<String> = ["a", "b", "c", "d"]
        .iter()
        .map(|t| r.cid(t)[..8].to_string())
        .collect();
    r.ok(&["merge", "b", "c", "d", "-m", "octopus"]);
    let log = r.out(&["log"]);
    let line = log.lines().find(|l| l.contains("octopus")).unwrap();
    assert!(
        line.contains(&format!("⇠ merges {}", ids.join(", "))),
        "{log}"
    );
    assert_topological(&r, &log);
}

// Scenario from git t4215-log-skewed-merges.sh / t4218-log-graph-indentation.sh: crossing merges.
#[test]
fn log_of_skewed_crossing_merges() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.tag("base", "@-");
    let mut tips = Vec::new();
    for n in 0..4 {
        r.ok(&["new", "base"]);
        r.commit(&format!("line{n}"), &[(&format!("f{n}"), "x\n")]);
        tips.push(r.sid("@-"));
    }
    // Cross-merge pairs: (0,2), (1,3), then the two merges.
    r.ok(&["new", &tips[0], &tips[2], "-m", "m02"]);
    let m02 = r.sid("@");
    r.ok(&["new", &tips[1], &tips[3], "-m", "m13"]);
    let m13 = r.sid("@");
    r.ok(&["new", &m13, &m02, "-m", "top"]);
    let out = r.run(&["log"]);
    assert!(
        out.status.success() && exited_cleanly(&out),
        "{}",
        text(&out)
    );
    let log = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_topological(&r, &log);
}

// Scenario from jj test_log (many heads): ten sibling lines are all shown.
#[test]
fn log_with_many_heads() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.tag("base", "@-");
    for n in 0..10 {
        r.ok(&["new", "base"]);
        r.commit(&format!("head{n}"), &[("h", &format!("{n}\n"))]);
    }
    let log = r.out(&["log"]);
    for n in 0..10 {
        assert!(log.contains(&format!("head{n}")), "head{n} missing:\n{log}");
    }
    assert_topological(&r, &log);
}

// Scenario from git t4202-log.sh (decorations) / jj test_log: tags, workspaces and empty changes are labelled.
#[test]
fn log_labels_tags_workspaces_and_empty_changes() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first", &[("f", "1\n")]);
    r.tag("main", "@-");
    r.ok(&["tag", "set", "other-tag", "-r", "@-"]);
    r.ok(&["ws", "new", "agent", "-r", "@-"]);
    let log = r.out(&["log"]);
    let first = log.lines().find(|l| l.contains(&r.cid("@-")[..8])).unwrap();
    assert!(first.contains(" main"), "{first}");
    assert!(first.contains("other-tag"), "{first}");
    let wc = log.lines().find(|l| l.contains("default@")).unwrap();
    assert!(wc.contains("default@") && wc.contains("(empty)"), "{wc}");
    assert!(log.contains("agent@"), "{log}");
}

// Scenario from jj test_log (abandoned commits are hidden).
#[test]
fn log_hides_abandoned_and_rewritten_snapshots() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("keep", &[("a", "a\n")]);
    r.commit("drop me", &[("b", "b\n")]);
    let dropped = r.cid("@-");
    let old_keep = r.sid("@--");
    r.ok(&["abandon", &dropped]);
    r.ok(&["describe", "-r", "@-", "-m", "kept, reworded"]);
    let log = r.out(&["log"]);
    assert!(
        !log.contains("drop me") && !log.contains(&dropped[..8]),
        "{log}"
    );
    assert!(
        !log.contains(&old_keep[..8]),
        "rewritten snapshot still listed:\n{log}"
    );
    assert!(log.contains("kept, reworded"), "{log}");
}

// Scenario from git t4202-log.sh: a description that is only whitespace counts as none.
#[test]
fn log_shows_placeholder_for_blank_descriptions() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("f", "x\n");
    r.ok(&["describe", "-m", "   "]);
    let log = r.out(&["log"]);
    assert!(
        log.lines().nth(1).unwrap().contains("(no description set)"),
        "{log}"
    );
}

// Scenario from git t4205-log-pretty-formats.sh (control characters): descriptions are escaped.
#[test]
fn log_escapes_control_characters_in_descriptions() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("evil \x1b[31mred\x1b[0m title", &[("f", "x\n")]);
    let log = r.out(&["log"]);
    assert!(!log.contains('\x1b'), "{log:?}");
    let show = r.out(&["show", "@-"]);
    assert!(!show.contains('\x1b'), "{show:?}");
}

// Scenario from jj test_log (conflict marker) / git t4202: conflicted snapshots are marked.
#[test]
fn log_marks_conflicted_snapshots() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n")],
        |r: &R| r.write("f", "l\n"),
        |r: &R| r.write("f", "r\n"),
    );
    r.ok(&["merge", "left", "-m", "the merge"]);
    let log = r.out(&["log"]);
    let row = log.lines().find(|l| l.contains(&r.cid("@-")[..8])).unwrap();
    assert!(row.contains("×") && row.contains("(conflict)"), "{log}");
}

// Scenario from guide (`vl --no-snapshot`): looking at the log without recording.
#[test]
fn log_with_no_snapshot_records_nothing() {
    let env = Env::new();
    let r = env.repo("p");
    r.ok(&["status"]);
    let op = r.op_head();
    r.write("new-file", "x\n");
    r.ok(&["--no-snapshot", "log"]);
    assert_eq!(r.op_head(), op);
    r.ok(&["log"]);
    assert_ne!(r.op_head(), op, "plain `vl log` should snapshot the edit");
}

// Scenario from jj test_log (divergence): two visible snapshots of one change are reported as divergent.
#[test]
fn divergent_change_is_reported_when_used() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    let change = r.cid("@-");
    let old = r.sid("@-");
    r.ok(&["describe", "-r", "@-", "-m", "one, v2"]);
    // Make the old version visible again: a workspace on its snapshot id.
    r.ok(&["ws", "new", "old", "-r", &old]);
    let err = r.fails(&["show", &change[..8]]);
    assert!(err.contains("divergent"), "{err}");
    let log = r.out(&["log"]);
    assert_eq!(log.matches(&change[..8]).count(), 2, "{log}");
}

// Scenario from the getting-started guide ("Conflicts"), checked against the behaviour
// (`merge::squashing_a_resolution_clears_the_conflict`) and `vl status`'s own hint.
#[test]
fn guide_describes_squashing_a_resolution_correctly() {
    let guide = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/guide/getting-started.md"
    ))
    .unwrap();
    let flat = guide.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !flat.contains(
            "running `vl squash` gives the right content but leaves the merge marked `(conflict)`"
        ),
        "getting-started.md still says squash leaves the conflict mark"
    );
}
