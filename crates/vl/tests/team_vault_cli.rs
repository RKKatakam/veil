//! `vl secret … --scope`, `vl run` precedence and scope choice, and the
//! revocation report of `vl scope revoke`, through the real binary.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

struct Env {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Env { _tmp: tmp, root }
    }

    fn cmd(&self, user: &str, cwd: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_vl"));
        c.args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.root.join(format!("home-{user}")))
            .env("VEIL_USER", user)
            .env("NO_COLOR", "1");
        c
    }

    fn vl(&self, user: &str, cwd: &Path, args: &[&str]) -> Output {
        self.cmd(user, cwd, args).output().unwrap()
    }

    /// (stdout, stderr) of a command that must succeed.
    fn ok2(&self, user: &str, cwd: &Path, args: &[&str]) -> (String, String) {
        let out = self.vl(user, cwd, args);
        let (o, e) = (String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned());
        assert!(out.status.success(), "vl {args:?} failed:\n{o}{e}");
        (o, e)
    }

    fn ok(&self, user: &str, cwd: &Path, args: &[&str]) -> String {
        let (o, e) = self.ok2(user, cwd, args);
        format!("{o}{e}")
    }

    fn fails(&self, user: &str, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(user, cwd, args);
        assert!(!out.status.success(), "vl {args:?} succeeded");
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    fn public_key(&self, user: &str) -> String {
        let out = self.ok(user, &self.root, &["identity", "show"]);
        out.lines()
            .find(|l| l.starts_with("public key"))
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap()
            .to_string()
    }
}

/// Alice's project with a team remote `team`; Bob granted and cloned.
fn setup(env: &Env) -> (PathBuf, PathBuf, String) {
    let proj = env.root.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("README"), "hi\n").unwrap();
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["commit", "-m", "v1"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    let bob = env.public_key("bob");
    env.ok("alice", &proj, &["scope", "grant", "team", &bob, "--name", "bob"]);
    env.ok("alice", &proj, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    (proj, env.root.join("bob"), bob)
}

#[test]
fn team_secrets_round_trip_and_reach_teammates() {
    let env = Env::new();
    let (proj, bob_dir, _) = setup(&env);
    // From stdin: the value never touches argv.
    let mut child = env
        .cmd("alice", &proj, &["secret", "set", "--scope", "team", "STRIPE_LIVE_KEY"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"sk_live_cli_canary\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    let (list, _) = env.ok2("alice", &proj, &["secret", "list", "--scope", "team"]);
    assert!(list.starts_with("STRIPE_LIVE_KEY"), "{list}");
    assert!(!list.contains("sk_live"), "list printed a value: {list}");
    // The local vault's list does not show team secrets.
    assert!(!env.ok("alice", &proj, &["secret", "list"]).contains("STRIPE"));
    assert_eq!(
        env.ok2("alice", &proj, &["secret", "get", "--scope", "team", "STRIPE_LIVE_KEY"]).0,
        "sk_live_cli_canary\n"
    );
    // Undo cannot take it back, and says what to do instead.
    let undo = env.fails("alice", &proj, &["undo"]);
    assert!(undo.contains("vl secret rm --scope team STRIPE_LIVE_KEY"), "{undo}");
    env.ok("alice", &proj, &["push"]);
    env.ok("bob", &bob_dir, &["pull"]);
    assert_eq!(
        env.ok2("bob", &bob_dir, &["secret", "get", "--scope", "team", "STRIPE_LIVE_KEY"]).0,
        "sk_live_cli_canary\n"
    );
    env.ok("bob", &bob_dir, &["secret", "rm", "--scope", "team", "STRIPE_LIVE_KEY"]);
    env.ok("bob", &bob_dir, &["push"]);
    env.ok("alice", &proj, &["pull"]);
    let err = env.fails("alice", &proj, &["secret", "get", "--scope", "team", "STRIPE_LIVE_KEY"]);
    assert!(err.contains("no secret named"), "{err}");
    // A non-member and a missing scope get a clear error.
    let err = env.fails("alice", &proj, &["secret", "set", "--scope", "nope", "A", "b"]);
    assert!(err.contains("no scope 'nope'"), "{err}");
}

#[test]
fn run_loads_team_secrets_then_the_local_vault_overrides() {
    let env = Env::new();
    let (proj, _, _) = setup(&env);
    env.ok("alice", &proj, &["scope", "create", "ops"]);
    env.ok("alice", &proj, &["secret", "set", "--scope", "team", "SHARED", "team-value"]);
    env.ok("alice", &proj, &["secret", "set", "--scope", "team", "TEAM_ONLY", "t"]);
    env.ok("alice", &proj, &["secret", "set", "--scope", "ops", "OPS_ONLY", "o"]);
    env.ok("alice", &proj, &["secret", "set", "--scope", "ops", "SHARED", "ops-value"]);
    let show = ["sh", "-c", "echo T=$TEAM_ONLY O=$OPS_ONLY S=$SHARED L=$LOCAL"];
    // Two scopes disagree on SHARED: refused rather than guessed.
    let mut args = vec!["run", "--"];
    args.extend(show);
    let err = env.fails("alice", &proj, &args);
    assert!(err.contains("SHARED") && err.contains("'ops'") && err.contains("'team'"), "{err}");
    // Choosing the scope settles it.
    let mut args = vec!["run", "--scope", "team", "--"];
    args.extend(show);
    assert_eq!(env.ok2("alice", &proj, &args).0, "T=t O= S=team-value L=\n");
    // The local vault overrides any team secret (and settles conflicts).
    env.ok("alice", &proj, &["secret", "set", "SHARED", "local-value"]);
    env.ok("alice", &proj, &["secret", "set", "LOCAL", "l"]);
    let mut args = vec!["run", "--"];
    args.extend(show);
    assert_eq!(env.ok2("alice", &proj, &args).0, "T=t O=o S=local-value L=l\n");
    let mut args = vec!["run", "--local-only", "--"];
    args.extend(show);
    assert_eq!(env.ok2("alice", &proj, &args).0, "T= O= S=local-value L=l\n");
    // The environment loses to both vaults.
    let out = env
        .cmd("alice", &proj, &["run", "--scope", "team", "--", "sh", "-c", "echo $TEAM_ONLY"])
        .env("TEAM_ONLY", "from-env")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "t\n");
}

#[test]
fn revoke_lists_the_secrets_to_rotate() {
    let env = Env::new();
    let (proj, bob_dir, bob) = setup(&env);
    env.ok("alice", &proj, &["secret", "set", "--scope", "team", "DB_PASSWORD", "p1"]);
    env.ok("alice", &proj, &["push"]);
    env.ok("bob", &bob_dir, &["pull"]);
    env.ok("bob", &bob_dir, &["secret", "set", "--scope", "team", "WEBHOOK_SECRET", "w1"]);
    env.ok("bob", &bob_dir, &["push"]);
    env.ok("alice", &proj, &["pull"]);
    let out = env.ok("alice", &proj, &["scope", "revoke", "team", &bob]);
    assert!(out.contains("could read 2 secret(s)"), "{out}");
    assert!(out.contains("  DB_PASSWORD\n") && out.contains("  WEBHOOK_SECRET\n"), "{out}");
    assert!(out.contains("re-signed the 1 secret(s) they last set"), "{out}");
    // Still available to the team, and still listed for rotation later.
    assert_eq!(env.ok2("alice", &proj, &["secret", "get", "--scope", "team", "WEBHOOK_SECRET"]).0, "w1\n");
    let (names, note) = env.ok2("alice", &proj, &["secret", "list", "--scope", "team", "--exposed-to", "bob"]);
    assert_eq!(names, "DB_PASSWORD\nWEBHOOK_SECRET\n");
    assert!(note.contains("were readable by bob"), "{note}");
    env.ok("alice", &proj, &["secret", "set", "--scope", "team", "DB_PASSWORD", "p2-rotated"]);
    let (names, _) = env.ok2("alice", &proj, &["secret", "list", "--scope", "team", "--exposed-to", &bob]);
    assert_eq!(names, "WEBHOOK_SECRET\n");
    // Bob, revoked, can no longer read or write it with vl.
    env.ok("alice", &proj, &["push"]);
    env.ok("bob", &bob_dir, &["pull"]);
    assert!(env.fails("bob", &bob_dir, &["secret", "get", "--scope", "team", "DB_PASSWORD"]).contains("not a member"));
    assert!(env
        .fails("bob", &bob_dir, &["secret", "set", "--scope", "team", "DB_PASSWORD", "x"])
        .contains("not a member"));
}
