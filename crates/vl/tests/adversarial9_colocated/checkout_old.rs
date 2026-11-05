//! BUG-754: `git checkout` of an old commit that has a file Veil now hides
//! overwrites it: Git treats ignored files as expendable, and no Git hook
//! can stop a checkout from writing (`post-checkout` and
//! `reference-transaction` run after; the `core.fsmonitor` query runs
//! before but cannot refuse, see `docs/BUGS.md`). Design threat 8's mitigation (the
//! path in the index as skip-worktree) would show it as a staged new file
//! and make the `pre-commit` guard refuse every commit. So the edit made
//! since the last `vl` command stays lost (the original test, ignored);
//! what is fixed: a version Veil recorded is never dropped with the
//! previous change, and the next command names the overwrite and how to
//! restore it.

use crate::*;

#[test]
#[ignore = "BUG-754 (limitation, documented in the guide; no Git hook can stop a checkout from writing): `git checkout` of an old commit that had a now-cloaked file overwrites the member's file; the edit made since the last vl command is lost"]
fn bug754_an_old_checkout_never_overwrites_a_cloaked_file() {
    need_git!();
    let env = Env::new();
    let dir = env.dir("p");
    env.ok(&dir, &["init", "--colocate", "--experimental"]);
    env.write(&dir, "secrets/db.yml", "public before the cloak\n");
    env.ok(&dir, &["commit", "-m", "public db"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    let old = env.git_ok(&dir, &["rev-parse", "HEAD"]);
    let mut policy = std::fs::read_to_string(dir.join(".veilpolicy")).unwrap();
    policy.push_str("secrets/ cloak\n");
    std::fs::write(dir.join(".veilpolicy"), policy).unwrap();
    env.write(&dir, "secrets/db.yml", "CLOAKED-MARKER-9 recorded\n");
    env.ok(&dir, &["commit", "-m", "cloak db"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    env.write(&dir, "secrets/db.yml", "CLOAKED-MARKER-10 not yet recorded\n");
    let _ = env.git(&dir, &["checkout", "-q", &old]);
    let now = std::fs::read_to_string(dir.join("secrets/db.yml")).unwrap_or_default();
    assert!(now.contains("CLOAKED-MARKER-10"), "git checkout overwrote the cloaked file:\n{now}");
}

/// What is fixed: the previous change keeps the version Veil recorded (it
/// used to be abandoned, Git's checkout counting as "Git manages it now"),
/// and the follow says what Git overwrote and how to restore it.
#[test]
fn bug754_an_overwritten_cloaked_file_is_reported_and_restorable() {
    need_git!();
    for recorded in [true, false] {
        let env = Env::new();
        let dir = env.dir("p");
        env.ok(&dir, &["init", "--colocate", "--experimental"]);
        env.write(&dir, "secrets/db.yml", "public before the cloak\n");
        env.ok(&dir, &["commit", "-m", "public db"]);
        env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
        let old = env.git_ok(&dir, &["rev-parse", "HEAD"]);
        let mut policy = std::fs::read_to_string(dir.join(".veilpolicy")).unwrap();
        policy.push_str("secrets/ cloak\n");
        std::fs::write(dir.join(".veilpolicy"), policy).unwrap();
        env.write(&dir, "secrets/db.yml", "CLOAKED-MARKER-9 committed\n");
        env.ok(&dir, &["commit", "-m", "cloak db"]);
        env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
        let want = match recorded {
            true => {
                env.write(&dir, "secrets/db.yml", "CLOAKED-MARKER-10 recorded\n");
                env.ok(&dir, &["status"]);
                "CLOAKED-MARKER-10 recorded\n"
            }
            false => "CLOAKED-MARKER-9 committed\n",
        };
        let _ = env.git(&dir, &["checkout", "-q", old.trim()]);
        let out = env.ok(&dir, &["status"]);
        assert!(out.contains("Git's checkout overwrote secrets/db.yml"), "{out}");
        let cmd = out
            .split('`')
            .find(|s| s.starts_with("vl restore --from"))
            .unwrap_or_else(|| panic!("no restore command in:\n{out}"))
            .to_string();
        let args: Vec<&str> = cmd.split_whitespace().skip(1).collect();
        env.ok(&dir, &args);
        let now = std::fs::read_to_string(dir.join("secrets/db.yml")).unwrap();
        assert_eq!(now, want, "recorded={recorded}");
        assert_clean(&env, &dir.join(".git"), &["CLOAKED-MARKER"], "after the overwrite and the restore");
    }
}
