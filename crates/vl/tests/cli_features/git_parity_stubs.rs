//! Stream 0 of the Git-parity round (`docs/design/git-parity/PLAN.md`): every
//! new command and flag parses the flags its design documents, and refuses
//! cleanly (exit 1, "not implemented yet", nothing changed) until its stream
//! lands. Each stream replaces its rows here with real tests.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Env {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    repo: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let env = Env { _tmp: tmp, root, repo };
        let out = env.vl(&env.repo, &["init"]);
        assert!(out.status.success(), "init: {}", String::from_utf8_lossy(&out.stderr));
        std::fs::write(env.repo.join("README.md"), "hello\n").unwrap();
        env.ok(&["commit", "-m", "first"]);
        env
    }

    fn vl(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vl"))
            .env("VEIL_TEST_PATH_REMOTES", "1")
            .args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.root.join("home"))
            .env("VEIL_USER", "alice")
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.vl(&self.repo, args);
        assert!(out.status.success(), "vl {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// The head of the operation log.
    fn head_op(&self) -> String {
        let log = self.ok(&["op", "log", "-n", "1", "--json"]);
        let v: serde_json::Value = serde_json::from_str(&log).unwrap();
        v["operations"][0]["op_id"].as_str().expect("an operation id").to_string()
    }

    /// `vl args` exits 1 with "not implemented yet" (naming `what`) and
    /// records no operation.
    fn refuses(&self, args: &[&str], what: &str) {
        let before = self.head_op();
        let out = self.vl(&self.repo, args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "vl {args:?}: {err}");
        assert!(err.contains("not implemented yet"), "vl {args:?}: {err}");
        assert!(err.contains(what), "vl {args:?} should name {what}: {err}");
        assert!(!err.contains("panicked"), "vl {args:?}: {err}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        if args.contains(&"--json") {
            // The failure as this invocation's one document.
            let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("vl {args:?}: {e}: {stdout}"));
            assert_eq!(v["schema"], "veil.error/1", "vl {args:?}");
            assert!(v["error"]["message"].as_str().unwrap().contains("not implemented yet"), "vl {args:?}: {stdout}");
        } else {
            assert!(stdout.is_empty(), "vl {args:?} printed {stdout}");
        }
        assert_eq!(self.head_op(), before, "vl {args:?} recorded an operation");
    }

    /// `vl args` is a usage error (exit 2, or help for a bare command
    /// group), not a stub refusal.
    fn usage_error(&self, args: &[&str]) {
        let out = self.vl(&self.repo, args);
        let err = String::from_utf8_lossy(&out.stderr);
        // Exit 2 is clap's; a stub refusal exits 1.
        assert_eq!(out.status.code(), Some(2), "vl {args:?}: {err}");
    }
}

#[test]
fn new_commands_parse_their_documented_flags_and_refuse() {
    let env = Env::new();
    let cases: &[(&[&str], &str)] = &[
    ];
    for (args, what) in cases {
        env.refuses(args, what);
    }
}

#[test]
fn new_flags_on_existing_commands_refuse_only_when_given() {
    let env = Env::new();
    // Without the new flags, the commands work as before.
    env.ok(&["log", "-n", "1"]);
    env.ok(&["log", "--json"]);
    env.ok(&["diff", "-r", "@-"]);
    env.ok(&["show", "@-", "--stat"]);
    env.ok(&["describe", "-m", "described"]);
    env.ok(&["tag", "set", "main", "-r", "@-"]);

    let cases: &[(&[&str], &str)] = &[
    ];
    for (args, what) in cases {
        env.refuses(args, what);
    }
}

#[test]
fn malformed_invocations_are_usage_errors() {
    let env = Env::new();
    for args in [
        &["blame"][..],
        &["grep"],
        &["bisect"],
        &["bisect", "start", "--bad", "@"],
        &["bisect", "run"],
        &["duplicate"],
        &["duplicate", "@", "--keep-description", "-m", "x"],
        &["cherry-pick"],
        &["hooks"],
        &["attr"],
        &["attr", "check"],
        &["log", "-S", "a", "-G", "b"],
        &["diff", "--no-renames", "-M"],
        &["diff", "-M=101"],
        &["tag", "verify"],
    ] {
        env.usage_error(args);
    }
}
