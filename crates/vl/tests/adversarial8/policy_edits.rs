//! BUG-560: a command in a `vl ws exec` sandbox, or a tool writing in a
//! `vl ws mount`, is not the member. An edit of `.veilpolicy` it makes that
//! weakens the recorded policy (truncating it, deleting a rule, `public!`,
//! `** public`, moving a scope's files to another scope) must never
//! declassify anything: it is held back (not recorded) until the member
//! runs `vl policy accept --workspace NAME`. Strengthening applies at once.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    adversarial_support::{read, text, write, Env},
    cat, U,
};

const PLAN: &str = "TOP-SECRET-PLAN-5521";

/// `secret/plan.md` cloaked for `team`, `src/lib.rs` public; scope `ops`
/// exists too. Returns the project and its committed `.veilpolicy`.
fn project(env: &Env) -> (PathBuf, String) {
    let proj = env.project(U, "proj", &[("src/lib.rs", "lib\n"), ("secret/plan.md", &format!("{PLAN}\n"))]);
    env.ok(U, &proj, &["scope", "create", "ops"]);
    let policy = format!("{}secret/ cloak team\n", read(&proj, ".veilpolicy"));
    write(&proj, ".veilpolicy", &policy);
    env.ok(U, &proj, &["commit", "-m", "cloak"]);
    env.ok(U, &proj, &["tag", "set", "base", "-r", "@-"]);
    (proj, policy)
}

/// Every way of weakening the policy: (name, shell script run in the
/// sandbox or the mount). Each also edits the cloaked file and adds one.
const SHAPES: &[(&str, &str)] = &[
    ("truncate", ": > .veilpolicy"),
    ("delete the rule", "grep -v '^secret/' .veilpolicy > p.tmp; cat p.tmp > .veilpolicy; rm p.tmp"),
    ("public!", "echo 'secret/** public!' >> .veilpolicy"),
    ("** public", "echo '** public' >> .veilpolicy"),
    ("retarget the scope", "sed 's/cloak team/cloak ops/' .veilpolicy > p.tmp; cat p.tmp > .veilpolicy; rm p.tmp"),
];

fn script(shape: &str) -> String {
    format!("{shape}; echo more >> secret/plan.md; echo NEW-SECRET-77 > secret/new.md")
}

/// The line of `vl files -r rev` for `path`.
fn listed(env: &Env, proj: &Path, rev: &str, path: &str) -> String {
    let all = env.stdout(U, proj, &["files", "-r", rev]);
    all.lines().find(|l| l.split_whitespace().last() == Some(path)).unwrap_or_default().to_string()
}

/// `rev` declassified nothing, and records the committed policy.
fn assert_protected(env: &Env, proj: &Path, rev: &str, policy: &str, what: &str, out: &str) {
    for p in ["secret/plan.md", "secret/new.md"] {
        let line = listed(env, proj, rev, p);
        assert!(line.starts_with("cloaked:team"), "{what}: {p} was declassified in {rev} ({line:?}):\n{out}");
    }
    assert_eq!(
        cat(env, U, proj, rev, ".veilpolicy").as_deref(),
        Some(policy),
        "{what}: the weakened .veilpolicy was recorded in {rev}:\n{out}"
    );
    assert!(out.contains("vl policy accept"), "{what}: no word of the held-back edit:\n{out}");
}

/// The change id a `Recorded <change> …` line names.
fn recorded_change(out: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix("Recorded "))
        .and_then(|r| r.split_whitespace().next())
        .unwrap_or_else(|| panic!("nothing recorded:\n{out}"))
        .to_string()
}

#[test]
fn a_sandbox_weakening_the_policy_never_declassifies() {
    let env = Env::new();
    let (proj, policy) = project(&env);
    for (i, (what, shape)) in SHAPES.iter().enumerate() {
        let ws = format!("agent-{i}");
        env.ok(U, &proj, &["ws", "new", &ws, "-r", "base"]);
        let out = env.ok(U, &proj, &["ws", "exec", &ws, "--", "sh", "-c", &script(shape)]);
        let rev = format!("{ws}@");
        assert_protected(&env, &proj, &rev, &policy, what, &out);
        // And the next run, which starts from what was recorded, too.
        let out = env.ok(U, &proj, &["ws", "exec", &ws, "--", "sh", "-c", "echo again >> secret/new.md"]);
        assert_protected(&env, &proj, &rev, &policy, &format!("{what}, second run"), &out);
    }
}

#[test]
fn a_sparse_sandbox_weakening_the_policy_never_declassifies() {
    let env = Env::new();
    let (proj, policy) = project(&env);
    for (i, (what, shape)) in SHAPES.iter().enumerate() {
        let ws = format!("sparse-{i}");
        env.ok(U, &proj, &["ws", "new", &ws, "-r", "base"]);
        // The set holds `secret/`, so the edits are recorded too.
        let out = env.ok(U, &proj, &["ws", "exec", &ws, "--only", "secret", "--", "sh", "-c", &script(shape)]);
        assert_protected(&env, &proj, &format!("{ws}@"), &policy, what, &out);
        // A set that leaves `secret/` out: its files are reclassified too.
        let ws = format!("narrow-{i}");
        env.ok(U, &proj, &["ws", "new", &ws, "-r", "base"]);
        let out = env.ok(U, &proj, &["ws", "exec", &ws, "--only", "src", "--", "sh", "-c", shape]);
        let line = listed(&env, &proj, &format!("{ws}@"), "secret/plan.md");
        assert!(line.starts_with("cloaked:team"), "{what}, outside the set: declassified ({line:?}):\n{out}");
        assert_eq!(cat(&env, U, &proj, &format!("{ws}@"), ".veilpolicy").as_deref(), Some(policy.as_str()), "{what}:\n{out}");
    }
}

#[test]
fn an_ephemeral_sandbox_weakening_the_policy_never_declassifies() {
    let env = Env::new();
    let (proj, policy) = project(&env);
    for (what, shape) in SHAPES {
        let out = env.ok(U, &proj, &["ws", "exec", "--ephemeral", "-r", "base", "--", "sh", "-c", &script(shape)]);
        let change = recorded_change(&out);
        assert_protected(&env, &proj, &change, &policy, what, &out);
        // A run on top of that result starts from the recorded policy.
        let out = env.ok(U, &proj, &["ws", "exec", "--ephemeral", "-r", &change, "--", "sh", "-c", "echo x > secret/third.md"]);
        let line = listed(&env, &proj, &recorded_change(&out), "secret/third.md");
        assert!(line.starts_with("cloaked:team"), "{what}, chained run: {line:?}\n{out}");
    }
}

#[test]
fn a_held_back_sandbox_edit_applies_once_the_member_accepts_it() {
    let env = Env::new();
    let (proj, policy) = project(&env);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "base"]);
    let out = env.ok(U, &proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo 'secret/ public' >> .veilpolicy"]);
    assert!(listed(&env, &proj, "agent@", "secret/plan.md").starts_with("cloaked:team"), "{out}");
    assert_eq!(cat(&env, U, &proj, "agent@", ".veilpolicy").as_deref(), Some(policy.as_str()), "{out}");
    assert!(out.contains("vl policy accept --workspace agent"), "{out}");
    let out = env.ok(U, &proj, &["policy", "accept", "--workspace", "agent"]);
    assert!(out.contains("secret/plan.md"), "accept should list what it weakens:\n{out}");
    let wanted = format!("{policy}secret/ public\n");
    assert_eq!(cat(&env, U, &proj, "agent@", ".veilpolicy").as_deref(), Some(wanted.as_str()), "{out}");
    let line = listed(&env, &proj, "agent@", "secret/plan.md");
    assert!(!line.starts_with("cloaked"), "accepted, yet still cloaked: {line:?}\n{out}");
    // The sandbox agrees: the next run records nothing new about it.
    let out = env.ok(U, &proj, &["ws", "exec", "agent", "--", "true"]);
    assert!(!out.contains("vl policy accept"), "{out}");
    // Nothing left to accept.
    let o = env.vl(U, &proj, &["policy", "accept", "--workspace", "agent"]);
    assert!(!o.status.success() || text(&o).contains("nothing"), "{}", text(&o));
}

#[test]
fn a_sandbox_strengthening_the_policy_applies_at_once() {
    let env = Env::new();
    let (proj, policy) = project(&env);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "base"]);
    let out = env.ok(U, &proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo 'src/ cloak team' >> .veilpolicy"]);
    let wanted = format!("{policy}src/ cloak team\n");
    assert_eq!(cat(&env, U, &proj, "agent@", ".veilpolicy").as_deref(), Some(wanted.as_str()), "{out}");
    assert!(listed(&env, &proj, "agent@", "src/lib.rs").starts_with("cloaked:team"), "{out}");
    assert!(!out.contains("vl policy accept"), "{out}");
    // Strengthening next to a weakening: the stronger rule applies now, the
    // weaker one waits.
    env.ok(U, &proj, &["ws", "new", "mixed", "-r", "base"]);
    let out = env.ok(
        U,
        &proj,
        &["ws", "exec", "mixed", "--", "sh", "-c", "echo 'src/ cloak team' >> .veilpolicy; echo 'secret/ public' >> .veilpolicy"],
    );
    assert!(listed(&env, &proj, "mixed@", "src/lib.rs").starts_with("cloaked:team"), "{out}");
    assert!(listed(&env, &proj, "mixed@", "secret/plan.md").starts_with("cloaked:team"), "{out}");
    assert_eq!(cat(&env, U, &proj, "mixed@", ".veilpolicy").as_deref(), Some(policy.as_str()), "{out}");
}

// ---- the mount -----------------------------------------------------------------

fn fuse_available() -> bool {
    let dev = std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse").is_ok();
    let tool = ["fusermount3", "fusermount"]
        .iter()
        .any(|b| Command::new(b).arg("-V").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok());
    if !(dev && tool && cfg!(target_os = "linux") && cfg!(feature = "fuse")) {
        eprintln!("skipping: FUSE is not available here");
        return false;
    }
    true
}

/// Unmounts (lazily) on drop, so a failing test leaves no mount behind.
struct Mounted(PathBuf);

impl Drop for Mounted {
    fn drop(&mut self) {
        for b in ["fusermount3", "fusermount"] {
            if Command::new(b).args(["-u", "-z", "-q"]).arg(&self.0).stderr(Stdio::null()).status().is_ok() {
                break;
            }
        }
    }
}

fn mount(env: &Env, proj: &Path, ws: &str) -> (PathBuf, Mounted) {
    let mnt = env.root.join(format!("mnt-{ws}"));
    let out = env.ok(U, proj, &["ws", "mount", ws, mnt.to_str().unwrap()]);
    assert!(out.contains("Mounted workspace"), "{out}");
    (mnt.clone(), Mounted(mnt))
}

fn sh_in(dir: &Path, script: &str) {
    let o = Command::new("sh").arg("-c").arg(script).current_dir(dir).output().unwrap();
    assert!(o.status.success(), "{script}: {}", text(&o));
}

#[test]
fn a_mount_weakening_the_policy_never_declassifies() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let (proj, policy) = project(&env);
    let mut shapes: Vec<(&str, String)> = SHAPES.iter().map(|(w, s)| (*w, script(s))).collect();
    shapes.push(("delete it", "rm .veilpolicy; echo more >> secret/plan.md; echo NEW-SECRET-77 > secret/new.md".into()));
    for (i, (what, script)) in shapes.iter().enumerate() {
        let ws = format!("m{i}");
        env.ok(U, &proj, &["ws", "new", &ws, "-r", "base"]);
        let (mnt, _g) = mount(&env, &proj, &ws);
        sh_in(&mnt, script);
        let out = env.ok(U, &proj, &["ws", "unmount", &ws]);
        let log = std::fs::read_to_string(proj.join(".veil/local/mounts").join(&ws).join("log")).unwrap_or_default();
        assert_protected(&env, &proj, &format!("{ws}@"), &policy, what, &format!("{out}{log}"));
    }
}

#[test]
fn a_mount_policy_edit_is_held_until_accepted_and_strengthening_applies() {
    if !fuse_available() {
        return;
    }
    let env = Env::new();
    let (proj, policy) = project(&env);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "base"]);
    let (mnt, _g) = mount(&env, &proj, "agent");
    sh_in(&mnt, "echo 'src/ cloak team' >> .veilpolicy");
    env.ok(U, &proj, &["status"]); // records the mount first
    let strong = format!("{policy}src/ cloak team\n");
    assert_eq!(cat(&env, U, &proj, "agent@", ".veilpolicy").as_deref(), Some(strong.as_str()));
    assert!(listed(&env, &proj, "agent@", "src/lib.rs").starts_with("cloaked:team"));

    sh_in(&mnt, "echo '** public' >> .veilpolicy");
    env.ok(U, &proj, &["status"]);
    assert!(listed(&env, &proj, "agent@", "secret/plan.md").starts_with("cloaked:team"));
    assert_eq!(cat(&env, U, &proj, "agent@", ".veilpolicy").as_deref(), Some(strong.as_str()));
    // The mount keeps showing the edit; accepting records it.
    assert!(read(&mnt, ".veilpolicy").ends_with("** public\n"));
    let out = env.ok(U, &proj, &["policy", "accept", "--workspace", "agent"]);
    let wanted = format!("{strong}** public\n");
    assert_eq!(cat(&env, U, &proj, "agent@", ".veilpolicy").as_deref(), Some(wanted.as_str()), "{out}");
    assert!(!listed(&env, &proj, "agent@", "secret/plan.md").starts_with("cloaked"), "{out}");
    let out = env.ok(U, &proj, &["ws", "unmount", "agent"]);
    assert!(!listed(&env, &proj, "agent@", "secret/plan.md").starts_with("cloaked"), "{out}");
    assert_eq!(cat(&env, U, &proj, "agent@", ".veilpolicy").as_deref(), Some(wanted.as_str()), "{out}");
}
