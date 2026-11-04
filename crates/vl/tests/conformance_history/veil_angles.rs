//! Veil invariants under merging and rewriting: cloaked and isolated files,
//! embargoed history, `.veilpolicy` edits, stable change ids and the op log.
//! Each scenario is a Git/jj history scenario (named per test) replayed
//! with protected content; plaintext must never reach what an outsider can
//! read (public snapshots, plaintext descriptions, a public remote).

use crate::merge::fork;
use crate::support::*;

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

/// base: `secret/k.txt` cloaked; then the usual left/right fork.
fn cloaked_fork<'a>(env: &'a Env, left: &str, right: &str) -> R<'a> {
    let r = env.repo("p");
    r.ok(&["cloak", "secret/"]);
    r.write("secret/k.txt", "line1\nline2\nline3\n");
    r.write("pub.txt", "p\n");
    r.ok(&["commit", "--no-advance", "-m", "base"]);
    r.tag("base", "@-");
    r.write("secret/k.txt", left);
    r.ok(&["commit", "--no-advance", "-m", "left"]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    r.write("secret/k.txt", right);
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
    assert!(out.contains("conflicts in: secret/k.txt"), "{out}");
    let f = r.read("secret/k.txt");
    assert!(
        f.contains("<<<<<<<") && f.contains("LEFT-CLOAK-4417") && f.contains("RIGHT-CLOAK-9921"),
        "{f}"
    );
    assert!(
        is_cloaked(&r.visibility("@-", "secret/k.txt")),
        "conflicted cloaked file merged as public"
    );
    // Resolving it keeps it sealed too.
    r.write("secret/k.txt", "line1\nRESOLVED-CLOAK-5531\nline3\n");
    r.ok(&["squash"]);
    assert!(is_cloaked(&r.visibility("@-", "secret/k.txt")));
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
    assert!(out.contains("conflicts in: secret/k.txt"), "{out}");
    assert!(is_cloaked(&r.visibility("right", "secret/k.txt")));
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
        r.read("secret/k.txt"),
        "LEFT-CM-3301\nline2\nRIGHT-CM-3302\n"
    );
    assert!(is_cloaked(&r.visibility("@-", "secret/k.txt")));
    assert_no_leak(&r, "LEFT-CM-3301");
    assert_no_leak(&r, "RIGHT-CM-3302");
}

// Scenario from git t6430 (one side changes policy, other edits): left cloaks a public file and edits it, right edits it publicly.
#[test]
fn conflict_between_a_cloaking_edit_and_a_public_edit_stays_sealed() {
    for direction in ["left-into-right", "right-into-left"] {
        let env = Env::new();
        let r = env.repo("p");
        r.commit("base", &[("conf/app.cfg", "a\nb\nc\n")]);
        r.tag("base", "@-");
        r.ok(&["cloak", "conf/"]);
        r.write("conf/app.cfg", "a\nLEFT-NOWCLOAKED-6610\nc\n");
        r.ok(&["commit", "--no-advance", "-m", "cloak conf and edit"]);
        r.tag("left", "@-");
        assert!(is_cloaked(&r.visibility("left", "conf/app.cfg")));
        r.ok(&["new", "base"]);
        r.write("conf/app.cfg", "a\nright public edit\nc\n");
        r.ok(&["commit", "--no-advance", "-m", "public edit"]);
        r.tag("right", "@-");
        let (into, other) = if direction == "left-into-right" {
            ("right", "left")
        } else {
            ("left", "right")
        };
        r.ok(&["new", into]);
        r.ok(&["merge", other]);
        assert!(r.read("conf/app.cfg").contains("LEFT-NOWCLOAKED-6610"));
        assert!(
            is_cloaked(&r.visibility("@-", "conf/app.cfg")),
            "{direction}: the merged file holding cloaked text is public"
        );
        assert_no_leak(&r, "LEFT-NOWCLOAKED-6610");
    }
}

// Scenario from git t6430 (policy on one side, new file on the other): a file added under a directory the other side cloaks.
#[test]
fn file_added_under_a_directory_cloaked_by_the_other_side_is_sealed_from_then_on() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.tag("base", "@-");
    r.write("private/existing.txt", "e\n");
    r.ok(&["cloak", "private/"]);
    r.ok(&["commit", "--no-advance", "-m", "cloak private"]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    r.write("private/new.txt", "added publicly before the rule\n");
    r.ok(&["commit", "--no-advance", "-m", "add file"]);
    r.ok(&["merge", "left"]);
    // From the merge on, the merged policy cloaks private/: later edits are sealed.
    r.write("private/new.txt", "LATER-EDIT-7702\n");
    r.ok(&["commit", "--no-advance", "-m", "edit"]);
    assert!(is_cloaked(&r.visibility("@-", "private/new.txt")));
    assert_no_leak(&r, "LATER-EDIT-7702");
}

// Scenario from git t3400 (rebase), on a change that edits `.veilpolicy`: its cloak rule and cloaked file survive.
#[test]
fn rebasing_a_policy_change_keeps_its_cloaked_files_sealed() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.tag("base", "@-");
    r.ok(&["cloak", "vault/"]);
    r.write("vault/key.txt", "POLICY-RB-8812\n");
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
    assert!(is_cloaked(&r.visibility("x", "vault/key.txt")));
    assert_no_leak(&r, "POLICY-RB-8812");
}

// Scenario from git t3400 (rebase with conflict), on `.veilpolicy`: a conflicted policy keeps cloaked files sealed.
#[test]
fn conflicted_policy_after_rebase_keeps_files_sealed() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.tag("base", "@-");
    r.ok(&["cloak", "vault/"]);
    r.write("vault/key.txt", "POLICY-CF-1212\n");
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
    r.write("vault/key.txt", "AFTER-CONFLICT-3434\n");
    let st = r.ok(&["status"]);
    assert!(!st.contains("panicked"), "{st}");
    assert!(is_cloaked(&r.visibility("@", "vault/key.txt")));
    assert_no_leak(&r, "POLICY-CF-1212");
    assert_no_leak(&r, "AFTER-CONFLICT-3434");
}

// Scenario from git t6430 (merge of policy edits): a policy merge that would declassify existing cloaked files is not taken.
#[test]
fn merged_policy_that_exposes_cloaked_files_is_not_taken() {
    let env = Env::new();
    let r = env.repo("p");
    r.ok(&["cloak", "vault/"]);
    r.write("vault/key.txt", "EXPOSE-MERGE-5151\n");
    r.ok(&["commit", "--no-advance", "-m", "base"]);
    r.tag("base", "@-");
    r.ok(&["expose", "vault/", "--force"]);
    r.ok(&["commit", "--no-advance", "-m", "expose vault"]);
    r.tag("exposer", "@-");
    r.ok(&["new", "base"]);
    r.commit("other", &[("o", "o\n")]);
    let out = r.ok(&["merge", "exposer"]);
    assert!(out.contains("kept the destination's .veilpolicy"), "{out}");
    assert!(is_cloaked(&r.visibility("@-", "vault/key.txt")));
}

// Scenario from jj test_abandon, on a change that cloaked a file: its child's edit of that file stays sealed.
#[test]
fn abandoning_the_change_that_cloaked_a_file_keeps_the_childs_edit_sealed() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.ok(&["cloak", "vault/"]);
    r.write("vault/key.txt", "first\n");
    r.ok(&["commit", "--no-advance", "-m", "cloak vault"]);
    let cloaker = r.cid("@-");
    r.write("vault/key.txt", "CHILD-EDIT-8080\n");
    r.ok(&["commit", "--no-advance", "-m", "edit the key"]);
    let child = r.cid("@-");
    r.ok(&["abandon", &cloaker]);
    assert!(r.paths(&child).contains(&"vault/key.txt".to_string()));
    assert!(
        is_cloaked(&r.visibility(&child, "vault/key.txt")),
        "abandon declassified the child's sealed edit"
    );
    assert_no_leak(&r, "CHILD-EDIT-8080");
}

// Scenario from jj test_squash, cloaked line into public parent: description and content stay sealed.
#[test]
fn squashing_a_cloaked_change_into_a_public_parent_keeps_it_sealed() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("public base", &[("app.txt", "v1\n")]);
    r.tag("main", "@-");
    r.ok(&["ws", "new", "work", "-r", "main", "--cloak", "team"]);
    r.ok(&["ws", "switch", "work"]);
    r.write("app.txt", "v1\nSQUASH-CLOAKED-4545\n");
    r.ok(&["describe", "-m", "SQUASH-DESC-4546"]);
    r.ok(&["squash"]);
    let into = r.snap("main");
    assert!(
        is_cloaked(&r.visibility("main", "app.txt")),
        "squash published the cloaked edit"
    );
    assert!(into.description.unwrap().contains("SQUASH-DESC-4546"));
    assert_no_leak(&r, "SQUASH-CLOAKED-4545");
    assert_no_leak(&r, "SQUASH-DESC-4546");
}

// Scenario from git t3400 / jj test_rebase, cloaked line onto a new public base: still sealed after the rebase.
#[test]
fn rebasing_a_cloaked_line_onto_public_work_keeps_it_sealed() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("public base", &[("app.txt", "1\n2\n3\n")]);
    r.tag("main", "@-");
    r.ok(&["ws", "new", "work", "-r", "main", "--cloak", "team"]);
    r.ok(&["ws", "switch", "work"]);
    r.write("app.txt", "1\n2\nCLOAKED-LINE-6767\n");
    r.ok(&["describe", "-m", "CLOAKED-LINE-DESC-6768"]);
    let work = r.cid("work@");
    r.ok(&["ws", "switch", "default"]);
    r.ok(&["new", "main"]);
    r.commit("public follow-up", &[("app.txt", "ONE\n2\n3\n")]);
    r.tag("main2", "@-");
    r.ok(&["rebase", "-s", &work, "-d", "main2"]);
    assert_eq!(r.cid(&work[..12]), work);
    assert!(is_cloaked(&r.visibility(&work[..12], "app.txt")));
    assert_eq!(r.cat(&work[..12], "app.txt"), "ONE\n2\nCLOAKED-LINE-6767\n");
    assert_no_leak(&r, "CLOAKED-LINE-6767");
    assert_no_leak(&r, "CLOAKED-LINE-DESC-6768");
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
/// the guide does it (fix on a cloaked workspace). The fix adds
/// `FIX_MARK` to `parser.py`.
const FIX_MARK: &str = "EMBARGOED-FIX-9090";

fn embargoed(env: &Env) -> R<'_> {
    let r = env.repo("p");
    r.commit(
        "parser",
        &[("parser.py", "def parse(buf):\n    return buf[0]\n")],
    );
    r.tag("main", "@-");
    r.ok(&["ws", "new", "fix", "-r", "main", "--cloak", "team"]);
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

/// What an outsider can read (and the public mirror receives) holds none
/// of the fix. (The holder's own store is checked separately: BUG-249.)
fn assert_embargo_holds(r: &R) {
    for n in [FIX_MARK, "FIX-DESC-9091", "EMBARGO-MERGE-DESC-9092"] {
        assert_outsider_blind(r, n);
    }
}

fn assert_outsider_blind(r: &R, needle: &str) {
    let reads = r.outsider_reads(needle);
    assert!(reads.is_empty(), "an outsider reads {needle:?}: {reads:?}");
}

// Control: outsiders and the public mirror see nothing of the embargoed fix.
#[test]
fn embargo_fixture_hides_the_fix_from_outsiders() {
    let env = Env::new();
    let r = embargoed(&env);
    assert!(r.read("parser.py").contains(FIX_MARK));
    assert_embargo_holds(&r);
    let mirror = push_public(&r, &["main"]);
    assert!(store_contains(&mirror, FIX_MARK.as_bytes()).is_empty());
}

// Control: the cloaked fix line, before the merge, is encrypted at rest.
#[test]
fn cloaked_fix_line_is_encrypted_at_rest_before_the_merge() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("parser", &[("parser.py", "v1\n")]);
    r.tag("main", "@-");
    r.ok(&["ws", "new", "fix", "-r", "main", "--cloak", "team"]);
    r.ok(&["ws", "switch", "fix"]);
    r.write("parser.py", format!("v1\n{FIX_MARK}\n"));
    r.ok(&["describe", "-m", "FIX-DESC-9091"]);
    r.ok(&["ws", "switch", "default"]);
    assert_no_leak(&r, FIX_MARK);
    assert_no_leak(&r, "FIX-DESC-9091");
}

// Scenario from git t6430 (merge) with Veil's embargo: the embargoed merge writes no plaintext of the fix.
#[test]
fn embargoed_merge_stores_no_plaintext_of_the_fix() {
    let env = Env::new();
    let r = embargoed(&env);
    let hits = r.store_contains(FIX_MARK);
    assert!(
        hits.is_empty(),
        "the embargoed fix is stored in plaintext: {hits:?}"
    );
}

// Scenario from jj test_rebase, on an embargoed line: a key holder's change rebased onto the embargoed merge stays wrapped.
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
    assert_embargo_holds(&r);
    let mirror = push_public(&r, &["main"]);
    assert!(store_contains(&mirror, FIX_MARK.as_bytes()).is_empty());
}

// Scenario from git t3423-rebase-reword.sh, on an embargoed merge: rewording keeps the description sealed.
#[test]
fn describing_an_embargoed_merge_keeps_its_description_sealed() {
    let env = Env::new();
    let r = embargoed(&env);
    r.ok(&["describe", "-r", "main", "-m", "REWORDED-EMBARGO-9094"]);
    assert_eq!(
        r.snap("main").description.as_deref(),
        Some("REWORDED-EMBARGO-9094")
    );
    assert_outsider_blind(&r, "REWORDED-EMBARGO-9094");
    assert_embargo_holds(&r);
}

// Scenario from git t3423 (reword the merged-in fix): rewriting the fix change re-merges under the same embargo.
#[test]
fn rewording_the_fix_after_the_embargoed_merge_keeps_the_embargo() {
    let env = Env::new();
    let r = embargoed(&env);
    let embargo = r.snap("main").embargo.clone().expect("embargoed merge");
    r.ok(&["describe", "-r", "fix@", "-m", "FIX-REWORD-9095"]);
    assert_eq!(r.snap("main").embargo.as_deref(), Some(embargo.as_str()));
    assert_outsider_blind(&r, "FIX-REWORD-9095");
    assert_embargo_holds(&r);
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
    assert_outsider_blind(&r, "SQUASHED-IN-9096");
    assert_outsider_blind(&r, "SQUASHED-DESC-9097");
    assert_embargo_holds(&r);
}

// Scenario from jj test_abandon, on an embargoed merge: abandoning it leaves nothing readable behind.
#[test]
fn abandoning_an_embargoed_merge_leaks_nothing() {
    let env = Env::new();
    let r = embargoed(&env);
    let before = r.sid("main-");
    let m = r.cid("main");
    r.ok(&["abandon", &m]);
    // jj semantics: the child now merges both former parents; main moved to the first.
    assert_eq!(r.tag_target("main"), Some(before));
    assert_embargo_holds(&r);
    let mirror = push_public(&r, &["main"]);
    assert!(store_contains(&mirror, FIX_MARK.as_bytes()).is_empty());
    for n in [FIX_MARK, "FIX-DESC-9091"] {
        assert!(r.outsider_reads(n).is_empty());
    }
}

// Scenario from jj test_undo, on an embargoed merge: undo restores the pre-merge state exactly.
#[test]
fn undoing_an_embargoed_merge_restores_the_previous_state() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("parser", &[("parser.py", "v1\n")]);
    r.tag("main", "@-");
    r.ok(&["ws", "new", "fix", "-r", "main", "--cloak", "team"]);
    r.ok(&["ws", "switch", "fix"]);
    r.write("parser.py", "v1\nUNDO-FIX-9098\n");
    r.ok(&["ws", "switch", "default"]);
    let before = r.state();
    r.ok(&["merge", "fix@", "--into", "main", "--embargo"]);
    r.ok(&["undo"]);
    assert_eq!(r.state(), before);
    assert_eq!(r.read("parser.py"), "v1\n");
    assert_outsider_blind(&r, "UNDO-FIX-9098");
}

// Scenario from git t6427 (conflict) on an embargoed line: markers in the file, no conflict list in public metadata.
#[test]
fn conflict_on_an_embargoed_line_is_not_recorded_in_metadata() {
    let env = Env::new();
    let r = embargoed(&env);
    // A public change on main's first parent that touches the fixed line.
    r.ok(&["new", "main-"]);
    r.write("parser.py", "def parse(buf):\n    return buf[1]\n");
    r.ok(&["describe", "-m", "conflicting public edit"]);
    let side = r.cid("@");
    r.ok(&["new", "main"]);
    let out = r.ok(&["merge", &side[..12], "-m", "combine"]);
    assert!(out.contains("conflict"), "{out}");
    let m = r.snap("@-");
    assert!(
        m.conflicts.is_empty(),
        "conflicted paths published in metadata: {:?}",
        m.conflicts
    );
    assert!(r.read("parser.py").contains("<<<<<<<"));
    assert_embargo_holds(&r);
}

// Scenario from jj test_rewrite (change ids): a change id survives every rewrite, cloaked or not.
#[test]
fn change_ids_survive_every_rewrite_of_a_cloaked_change() {
    let env = Env::new();
    let r = cloaked_fork(&env, "L\n", "R\n");
    r.commit("on right", &[("secret/k.txt", "R2\n")]);
    let c = r.cid("@-");
    r.ok(&["describe", "-r", &c[..12], "-m", "renamed"]);
    r.ok(&["rebase", "-s", "right", "-d", "left"]);
    r.ok(&["edit", &c[..12]]);
    r.write("secret/k.txt", "R3\n");
    r.ok(&["new"]);
    r.ok(&["squash", "-r", &c[..12]]);
    // After squashing, c is folded into `right` (which keeps its own id).
    assert!(r.try_snap(&c[..12]).is_none());
    let right = r.snap("right");
    assert_eq!(r.cat("right", "secret/k.txt"), "R3\n");
    assert!(is_cloaked(&r.visibility("right", "secret/k.txt")));
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
    assert_eq!(r.read("secret/k.txt"), "UNDO-R-2\n");
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
    r.write("secret/k.txt", "NM-RESOLVED-7373\n");
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
    if bob.exists("secret/k.txt") {
        let on_disk = bob.read("secret/k.txt");
        assert!(!on_disk.contains("NM-"), "{on_disk}");
    }
}
