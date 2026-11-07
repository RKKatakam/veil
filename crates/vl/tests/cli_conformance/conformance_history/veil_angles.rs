//! Veil invariants under merging and rewriting: cloaked (secret) and
//! isolated files, embargoed history (withheld from every push until its
//! release), `.veilpolicy` edits, stable change ids and the op log.
//! Each scenario is a Git/jj history scenario (named per test) replayed
//! with protected content; plaintext must never reach what an outsider can
//! read (public snapshots, plaintext descriptions, a public remote).

use super::merge::fork;
use super::support::*;

/// A public remote `mirror`, pushed with `tags`; returns its directory.
fn push_public(r: &R, tags: &[&str]) -> std::path::PathBuf {
    let mirror = r.env.root.join("mirror");
    if !mirror.exists() {
        r.ok(&[
            "remote",
            "add",
            "mirror",
            mirror.to_str().unwrap(),
            "--public",
        ]);
    }
    for t in tags {
        r.ok(&["push", "mirror", "-t", t]);
    }
    mirror
}

fn assert_no_leak(r: &R, needle: &str) {
    let hits = r.store_contains(needle);
    assert!(
        hits.is_empty(),
        "plaintext {needle:?} stored unencrypted: {hits:?}"
    );
    let reads = r.outsider_reads(needle);
    assert!(reads.is_empty(), "an outsider reads {needle:?}: {reads:?}");
}

fn is_cloaked(v: &veil_core::Visibility) -> bool {
    matches!(v, veil_core::Visibility::Cloaked { .. })
}

/// base: `secret/.env.k` (a secret file) cloaked; then the usual left/right fork.
fn cloaked_fork<'a>(env: &'a Env, left: &str, right: &str) -> R<'a> {
    let r = env.repo("p");
    r.ok(&["cloak", "secret/.env.k"]);
    r.write("secret/.env.k", "line1\nline2\nline3\n");
    r.write("pub.txt", "p\n");
    r.ok(&["commit", "--no-advance", "-m", "base"]);
    r.tag("base", "@-");
    r.write("secret/.env.k", left);
    r.ok(&["commit", "--no-advance", "-m", "left"]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    r.write("secret/.env.k", right);
    r.ok(&["commit", "--no-advance", "-m", "right"]);
    r.tag("right", "@-");
    r
}

// Scenario from git t6427-diff3-conflict-markers.sh, with a cloaked file: the markers stay sealed.
#[test]
fn merge_conflict_in_a_cloaked_file_stays_sealed() {
    let env = Env::new();
    let r = cloaked_fork(
        &env,
        "line1\nLEFT-CLOAK-4417\nline3\n",
        "line1\nRIGHT-CLOAK-9921\nline3\n",
    );
    let out = r.ok(&["merge", "left"]);
    assert!(out.contains("conflicts in: secret/.env.k"), "{out}");
    let f = r.read("secret/.env.k");
    assert!(
        f.contains("<<<<<<<") && f.contains("LEFT-CLOAK-4417") && f.contains("RIGHT-CLOAK-9921"),
        "{f}"
    );
    assert!(
        is_cloaked(&r.visibility("@-", "secret/.env.k")),
        "conflicted cloaked file merged as public"
    );
    // Resolving it keeps it sealed too.
    r.write("secret/.env.k", "line1\nRESOLVED-CLOAK-5531\nline3\n");
    r.ok(&["squash"]);
    assert!(is_cloaked(&r.visibility("@-", "secret/.env.k")));
    for n in ["LEFT-CLOAK-4417", "RIGHT-CLOAK-9921", "RESOLVED-CLOAK-5531"] {
        assert_no_leak(&r, n);
    }
    let mirror = push_public(&r, &["right"]);
    for n in ["LEFT-CLOAK-4417", "RIGHT-CLOAK-9921", "RESOLVED-CLOAK-5531"] {
        assert!(
            store_contains(&mirror, n.as_bytes()).is_empty(),
            "{n} on the public mirror"
        );
    }
}

// Scenario from git t3400-rebase.sh (conflict), with a cloaked file.
#[test]
fn rebase_conflict_in_a_cloaked_file_stays_sealed() {
    let env = Env::new();
    let r = cloaked_fork(
        &env,
        "line1\nLEFT-RB-1180\nline3\n",
        "line1\nRIGHT-RB-2271\nline3\n",
    );
    let out = r.ok(&["rebase", "-s", "right", "-d", "left"]);
    assert!(out.contains("conflicts in: secret/.env.k"), "{out}");
    assert!(is_cloaked(&r.visibility("right", "secret/.env.k")));
    assert_no_leak(&r, "LEFT-RB-1180");
    assert_no_leak(&r, "RIGHT-RB-2271");
}

// Scenario from git t6403-merge-file.sh (clean merge), with a cloaked file.
#[test]
fn clean_merge_of_a_cloaked_file_stays_sealed() {
    let env = Env::new();
    let r = cloaked_fork(
        &env,
        "LEFT-CM-3301\nline2\nline3\n",
        "line1\nline2\nRIGHT-CM-3302\n",
    );
    let out = r.ok(&["merge", "left"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(
        r.read("secret/.env.k"),
        "LEFT-CM-3301\nline2\nRIGHT-CM-3302\n"
    );
    assert!(is_cloaked(&r.visibility("@-", "secret/.env.k")));
    assert_no_leak(&r, "LEFT-CM-3301");
    assert_no_leak(&r, "RIGHT-CM-3302");
}

// Scenario from git t6430 (policy on one side, new file on the other): a secret file added under a directory the other side cloaks.
#[test]
fn file_added_under_a_directory_cloaked_by_the_other_side_is_sealed_from_then_on() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.tag("base", "@-");
    r.write("private/existing.pem", "e\n");
    r.ok(&["cloak", "private/*.pem"]);
    r.ok(&["commit", "--no-advance", "-m", "cloak private"]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    r.write("private/new.pem", "added before the rule\n");
    r.ok(&["commit", "--no-advance", "-m", "add file"]);
    r.ok(&["merge", "left"]);
    // From the merge on, the merged policy cloaks private/: later edits are sealed.
    r.write("private/new.pem", "LATER-EDIT-7702\n");
    r.ok(&["commit", "--no-advance", "-m", "edit"]);
    assert!(is_cloaked(&r.visibility("@-", "private/new.pem")));
    assert_no_leak(&r, "LATER-EDIT-7702");
}

// Scenario from git t3400 (rebase), on a change that edits `.veilpolicy`: its cloak rule and cloaked file survive.
#[test]
fn rebasing_a_policy_change_keeps_its_cloaked_files_sealed() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.tag("base", "@-");
    r.ok(&["cloak", "vault/*.pem"]);
    r.write("vault/key.pem", "POLICY-RB-8812\n");
    r.ok(&["commit", "--no-advance", "-m", "cloak vault"]);
    r.tag("x", "@-");
    r.ok(&["new", "base"]);
    // Upstream edits the top of the policy; x appended at the bottom.
    let policy = r.read(".veilpolicy");
    r.write(".veilpolicy", format!("*.log ignore\n{policy}"));
    r.ok(&["commit", "--no-advance", "-m", "ignore logs"]);
    r.tag("upstream", "@-");
    r.ok(&["rebase", "-s", "x", "-d", "upstream"]);
    let policy = r.cat("x", ".veilpolicy");
    assert!(
        policy.contains("vault/") && policy.contains("*.log"),
        "{policy}"
    );
    assert!(r.snap("x").conflicts.is_empty());
    assert!(is_cloaked(&r.visibility("x", "vault/key.pem")));
    assert_no_leak(&r, "POLICY-RB-8812");
}

// Scenario from git t3400 (rebase with conflict), on `.veilpolicy`: a conflicted policy keeps cloaked files sealed.
#[test]
fn conflicted_policy_after_rebase_keeps_files_sealed() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.tag("base", "@-");
    r.ok(&["cloak", "vault/*.pem"]);
    r.write("vault/key.pem", "POLICY-CF-1212\n");
    r.ok(&["commit", "--no-advance", "-m", "cloak vault"]);
    r.tag("x", "@-");
    r.ok(&["new", "base"]);
    r.ok(&["ignore", "build/"]);
    r.ok(&["commit", "--no-advance", "-m", "ignore build"]);
    r.tag("upstream", "@-");
    r.ok(&["edit", "x"]);
    let out = r.ok(&["rebase", "-s", "x", "-d", "upstream"]);
    assert!(
        out.contains(".veilpolicy"),
        "the two appended rules should conflict:\n{out}"
    );
    // Every later command reads the conflicted policy; edits in vault/ stay sealed.
    r.write("vault/key.pem", "AFTER-CONFLICT-3434\n");
    let st = r.ok(&["status"]);
    assert!(!st.contains("panicked"), "{st}");
    assert!(is_cloaked(&r.visibility("@", "vault/key.pem")));
    assert_no_leak(&r, "POLICY-CF-1212");
    assert_no_leak(&r, "AFTER-CONFLICT-3434");
}

// Scenario from git t6430 (merge of policy edits): a policy merge that would declassify existing cloaked files is not taken.
#[test]
fn merged_policy_that_exposes_cloaked_files_is_not_taken() {
    let env = Env::new();
    let r = env.repo("p");
    r.ok(&["cloak", "vault/*.pem"]);
    r.write("vault/key.pem", "EXPOSE-MERGE-5151\n");
    r.ok(&["commit", "--no-advance", "-m", "base"]);
    r.tag("base", "@-");
    r.ok(&["expose", "vault/*.pem", "--force"]);
    r.ok(&["commit", "--no-advance", "-m", "expose vault"]);
    r.tag("exposer", "@-");
    r.ok(&["new", "base"]);
    r.commit("other", &[("o", "o\n")]);
    let out = r.ok(&["merge", "exposer"]);
    assert!(out.contains("kept the destination's .veilpolicy"), "{out}");
    assert!(is_cloaked(&r.visibility("@-", "vault/key.pem")));
}

// Scenario from jj test_abandon, on a change that cloaked a file: its child's edit of that file stays sealed.
#[test]
fn abandoning_the_change_that_cloaked_a_file_keeps_the_childs_edit_sealed() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.ok(&["cloak", "vault/*.pem"]);
    r.write("vault/key.pem", "first\n");
    r.ok(&["commit", "--no-advance", "-m", "cloak vault"]);
    let cloaker = r.cid("@-");
    r.write("vault/key.pem", "CHILD-EDIT-8080\n");
    r.ok(&["commit", "--no-advance", "-m", "edit the key"]);
    let child = r.cid("@-");
    r.ok(&["abandon", &cloaker]);
    assert!(r.paths(&child).contains(&"vault/key.pem".to_string()));
    assert!(
        is_cloaked(&r.visibility(&child, "vault/key.pem")),
        "abandon declassified the child's sealed edit"
    );
    assert_no_leak(&r, "CHILD-EDIT-8080");
}

// Scenario from git t6436-merge-overwrite.sh / jj rebase, with an isolated file: never recorded, never removed.
#[test]
fn isolated_file_survives_rebase_squash_and_abandon() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("k", "k\n")],
        |r: &R| r.write("l", "l\n"),
        |r: &R| r.write("r", "r\n"),
    );
    r.write(".env", "TOKEN=ISOLATED-VALUE-2323\n");
    r.write(
        "id_rsa",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nISOLATED-KEY-2324\n",
    );
    r.ok(&["rebase", "-s", "right", "-d", "left"]);
    r.write("x", "x\n");
    r.ok(&["squash"]);
    r.ok(&["abandon", "right"]);
    r.ok(&["undo"]);
    assert_eq!(r.read(".env"), "TOKEN=ISOLATED-VALUE-2323\n");
    assert!(r.read("id_rsa").contains("ISOLATED-KEY-2324"));
    assert!(r.store_contains("ISOLATED-VALUE-2323").is_empty());
    assert!(r.store_contains("ISOLATED-KEY-2324").is_empty());
}

// Scenario from git t3400 (rebase), with a quarantined secret in a public file: the rebase does not record it.
#[test]
fn quarantined_secret_is_not_recorded_by_a_rewrite() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("cfg.js", "a\n")],
        |r: &R| r.write("l", "l\n"),
        |r: &R| r.write("r", "r\n"),
    );
    r.write("cfg.js", "const k = \"AKIAIOSFODNN7EXAMPLE\";\n");
    r.ok(&["rebase", "-s", "right", "-d", "left"]);
    r.ok(&["merge", "base", "-m", "m"]);
    assert!(
        r.store_contains("AKIAIOSFODNN7EXAMPLE").is_empty(),
        "quarantined secret recorded"
    );
}

/// A repository with an unreleased embargoed merge on `main`, made the way
/// the guide does it (fix on its own workspace). The fix adds `FIX_MARK`
/// to `parser.py`.
const FIX_MARK: &str = "EMBARGOED-FIX-9090";

fn embargoed(env: &Env) -> R<'_> {
    let r = env.repo("p");
    r.commit(
        "parser",
        &[("parser.py", "def parse(buf):\n    return buf[0]\n")],
    );
    r.tag("main", "@-");
    r.ok(&["ws", "new", "fix", "-r", "main"]);
    r.ok(&["ws", "switch", "fix"]);
    r.write(
        "parser.py",
        format!("def parse(buf):\n    # {FIX_MARK}\n    return buf[0] if buf else None\n"),
    );
    r.ok(&["describe", "-m", "FIX-DESC-9091"]);
    r.ok(&["ws", "switch", "default"]);
    let out = r.ok(&[
        "merge",
        "fix@",
        "--into",
        "main",
        "--embargo",
        "-m",
        "EMBARGO-MERGE-DESC-9092",
    ]);
    assert!(out.contains("embargo"), "{out}");
    r
}

/// Push every tag to a public remote `mirror` and a team remote `origin`
/// (added on first use): neither receives any of `needles` (the embargoed
/// merge and the history it brings in are withheld until the release).
fn assert_withheld(r: &R, needles: &[&str]) {
    let mirror = push_public(r, &[]);
    let team = r.env.root.join("team");
    if !team.exists() {
        r.ok(&["remote", "add", "origin", team.to_str().unwrap()]);
    }
    let out = r.ok(&["push", "mirror"]);
    r.ok(&["push", "origin"]);
    for n in needles.iter().chain(&[FIX_MARK, "FIX-DESC-9091", "EMBARGO-MERGE-DESC-9092"]) {
        for remote in [&mirror, &team] {
            let hits = store_contains(remote, n.as_bytes());
            assert!(hits.is_empty(), "{n:?} reached {}: {hits:?}\n{out}", remote.display());
        }
    }
}

// Control: no remote receives anything of the embargoed fix.
#[test]
fn embargo_fixture_hides_the_fix_from_outsiders() {
    let env = Env::new();
    let r = embargoed(&env);
    assert!(r.read("parser.py").contains(FIX_MARK));
    assert_withheld(&r, &[]);
    // Asked for by name, the embargoed `main` is refused.
    let t = r.fails(&["push", "mirror", "-t", "main"]);
    assert!(t.contains("requested tag was not pushed: main"), "{t}");
}

// Scenario from jj test_rebase, on an embargoed line: a change rebased onto the embargoed merge is withheld with it.
#[test]
fn rebasing_onto_an_embargoed_merge_keeps_the_embargo() {
    let env = Env::new();
    let r = embargoed(&env);
    r.ok(&["new", "main-"]);
    r.write("other.txt", "ON-TOP-9093\n");
    r.ok(&["describe", "-m", "unrelated work"]);
    let w = r.cid("@");
    r.ok(&["rebase", "-s", &w, "-d", "main"]);
    assert!(r.read("parser.py").contains(FIX_MARK));
    r.tag("built-on", "@");
    assert_withheld(&r, &["ON-TOP-9093"]);
}

// Scenario from git t3423-rebase-reword.sh, on an embargoed merge: the reworded merge stays withheld.
#[test]
fn describing_an_embargoed_merge_keeps_its_description_sealed() {
    let env = Env::new();
    let r = embargoed(&env);
    r.ok(&["describe", "-r", "main", "-m", "REWORDED-EMBARGO-9094"]);
    assert_eq!(
        r.snap("main").description.as_deref(),
        Some("REWORDED-EMBARGO-9094")
    );
    assert_withheld(&r, &["REWORDED-EMBARGO-9094"]);
}

// Scenario from git t3423 (reword the merged-in fix): rewriting the fix change re-merges under the same embargo.
#[test]
fn rewording_the_fix_after_the_embargoed_merge_keeps_the_embargo() {
    let env = Env::new();
    let r = embargoed(&env);
    let embargo = r.snap("main").embargo.clone().expect("embargoed merge");
    r.ok(&["describe", "-r", "fix@", "-m", "FIX-REWORD-9095"]);
    assert_eq!(r.snap("main").embargo.as_deref(), Some(embargo.as_str()));
    assert_withheld(&r, &["FIX-REWORD-9095"]);
}

// Scenario from jj test_squash, into an embargoed merge: what is squashed in stays under the embargo.
#[test]
fn squashing_into_an_embargoed_merge_keeps_the_embargo() {
    let env = Env::new();
    let r = embargoed(&env);
    r.write("parser.py", format!("def parse(buf):\n    # {FIX_MARK}\n    # SQUASHED-IN-9096\n    return buf[0] if buf else None\n"));
    r.ok(&["describe", "-m", "SQUASHED-DESC-9097"]);
    r.ok(&["squash"]);
    assert!(r.cat("main", "parser.py").contains("SQUASHED-IN-9096"));
    assert_withheld(&r, &["SQUASHED-IN-9096", "SQUASHED-DESC-9097"]);
}

// Scenario from jj test_abandon, on an embargoed merge: abandoning it publishes nothing of the fix.
// Unlike jj, the abandon is refused while a change (here the working copy) is built on the
// merge: rebased onto its parents, that change would merge the fix with nothing withholding
// it (BUG-943). With the working copy moved off it, the abandon goes through.
#[test]
fn abandoning_an_embargoed_merge_leaks_nothing() {
    let env = Env::new();
    let r = embargoed(&env);
    let before = r.sid("main-");
    let m = r.cid("main");
    let err = r.fails(&["abandon", &m]);
    assert!(err.contains("embargoed merge") && err.contains("vl embargo release"), "{err}");
    r.ok(&["new", &before]);
    r.ok(&["abandon", &m]);
    // jj semantics: main moved to the abandoned merge's first parent.
    assert_eq!(r.tag_target("main"), Some(before));
    let mirror = push_public(&r, &["main"]);
    assert!(store_contains(&mirror, FIX_MARK.as_bytes()).is_empty());
    assert!(store_contains(&mirror, b"FIX-DESC-9091").is_empty());
}

// Scenario from jj test_undo, on an embargoed merge: undo restores the pre-merge state exactly.
#[test]
fn undoing_an_embargoed_merge_restores_the_previous_state() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("parser", &[("parser.py", "v1\n")]);
    r.tag("main", "@-");
    r.ok(&["ws", "new", "fix", "-r", "main"]);
    r.ok(&["ws", "switch", "fix"]);
    r.write("parser.py", "v1\nUNDO-FIX-9098\n");
    r.ok(&["ws", "switch", "default"]);
    let before = r.state();
    r.ok(&["merge", "fix@", "--into", "main", "--embargo"]);
    r.ok(&["undo"]);
    assert_eq!(r.state(), before);
    assert_eq!(r.read("parser.py"), "v1\n");
}

// Scenario from jj test_rewrite (change ids): a change id survives every rewrite, cloaked or not.
#[test]
fn change_ids_survive_every_rewrite_of_a_cloaked_change() {
    let env = Env::new();
    let r = cloaked_fork(&env, "L\n", "R\n");
    r.commit("on right", &[("secret/.env.k", "R2\n")]);
    let c = r.cid("@-");
    r.ok(&["describe", "-r", &c[..12], "-m", "renamed"]);
    r.ok(&["rebase", "-s", "right", "-d", "left"]);
    r.ok(&["edit", &c[..12]]);
    r.write("secret/.env.k", "R3\n");
    r.ok(&["new"]);
    r.ok(&["squash", "-r", &c[..12]]);
    // After squashing, c is folded into `right` (which keeps its own id).
    assert!(r.try_snap(&c[..12]).is_none());
    let right = r.snap("right");
    assert_eq!(r.cat("right", "secret/.env.k"), "R3\n");
    assert!(is_cloaked(&r.visibility("right", "secret/.env.k")));
    assert_eq!(right.description.as_deref(), Some("right\n\nrenamed"));
}

// Scenario from jj test_undo / test_op_restore, with cloaked content: undo after a cloaked merge restores tags and graph.
#[test]
fn undo_of_a_cloaked_conflict_merge_restores_everything() {
    let env = Env::new();
    let r = cloaked_fork(&env, "UNDO-L-1\n", "UNDO-R-2\n");
    r.ok(&["status"]);
    let before = r.state();
    r.ok(&["merge", "left"]);
    r.ok(&["undo"]);
    assert_eq!(r.state(), before);
    assert_eq!(r.read("secret/.env.k"), "UNDO-R-2\n");
    assert_no_leak(&r, "UNDO-L-1");
}

// Scenario from git t4013-diff-various.sh / jj test_diff (merge commits), seen by a non-member:
// `vl diff`, `vl show` and `vl log` of a cloaked conflict merge reveal no plaintext.
#[test]
fn non_member_diff_show_and_log_of_a_cloaked_merge_reveal_nothing() {
    let env = Env::new();
    let r = cloaked_fork(
        &env,
        "line1\nNM-LEFT-7171\nline3\n",
        "line1\nNM-RIGHT-7272\nline3\n",
    );
    r.ok(&["merge", "left", "-m", "merge of cloaked edits"]);
    r.write("secret/.env.k", "NM-RESOLVED-7373\n");
    r.ok(&["squash"]);
    r.tag("main", "@-");
    let team = env.root.join("team-remote");
    r.ok(&["remote", "add", "origin", team.to_str().unwrap()]);
    r.ok(&["push", "origin", "-t", "main", "-t", "left", "-t", "right"]);
    // Bob is not in `team`: he clones the team remote and holds no key.
    env.as_user(&env.root, "bob")
        .ok(&["clone", team.to_str().unwrap(), "bob"]);
    let bob = env.as_user(&env.root.join("bob"), "bob");
    let mut seen = String::new();
    for args in [
        vec!["diff", "-r", "main"],
        vec!["diff", "--from", "base", "--to", "main"],
        vec!["diff", "--from", "left", "--to", "right"],
        vec!["show", "main"],
        vec!["show", "left"],
        vec!["log"],
        vec!["diff", "--from", "base", "--to", "main", "--stat"],
    ] {
        let out = bob.run(&args);
        assert!(exited_cleanly(&out), "{args:?}: {}", text(&out));
        seen.push_str(&text(&out));
    }
    for n in ["NM-LEFT-7171", "NM-RIGHT-7272", "NM-RESOLVED-7373", "line2"] {
        assert!(!seen.contains(n), "bob saw {n:?}:\n{seen}");
    }
    assert!(
        seen.contains("content hidden") || seen.contains("redacted"),
        "{seen}"
    );
    if bob.exists("secret/.env.k") {
        let on_disk = bob.read("secret/.env.k");
        assert!(!on_disk.contains("NM-"), "{on_disk}");
    }
}
