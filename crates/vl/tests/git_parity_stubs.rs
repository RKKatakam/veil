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
        // stream H: blame, grep, bisect
        (&["blame", "README.md"], "vl blame"),
        (
            &["blame", "README.md", "-r", "@-", "-L", "1,2", "--follow", "--max-changes", "10", "--public", "--json"],
            "vl blame",
        ),
        (&["annotate", "README.md"], "vl blame"),
        (&["grep", "hello"], "vl grep"),
        (
            &[
                "grep", "hello", "-r", "@-", "-i", "-F", "-w", "-n", "-l", "-c", "--max-count", "3", "-a", "--json", "--", "README.md",
                "src",
            ],
            "vl grep",
        ),
        (&["bisect", "start", "--bad", "@", "--good", "@-", "--good", "root()"], "vl bisect"),
        (&["bisect", "good"], "vl bisect"),
        (&["bisect", "bad", "@-", "--discard"], "vl bisect"),
        (&["bisect", "skip", "--discard"], "vl bisect"),
        (&["bisect", "run", "--with-isolated", "--trust-partial", "--", "make", "test", "-k"], "vl bisect"),
        (&["bisect", "reset"], "vl bisect"),
        (&["bisect", "log"], "vl bisect"),
        // stream R: duplicate, cherry-pick
        (&["duplicate", "@-"], "vl duplicate"),
        (&["duplicate", "@-", "@", "-d", "root()", "-d", "@-", "-m", "copy", "-x", "--json"], "vl duplicate"),
        (&["duplicate", "@-", "--keep-description"], "vl duplicate"),
        (&["cherry-pick", "@-", "-x", "--json"], "vl cherry-pick"),
        (&["cherry-pick", "@-", "-m", "copy"], "vl cherry-pick"),
        // stream P: format-patch, am
        (&["format-patch", "@-"], "vl format-patch"),
        (&["format-patch", "root()..@", "-o", "out", "--cover-letter", "--binary", "-M"], "vl format-patch"),
        (&["format-patch", "@-", "--stdout", "--audience", "me", "--include-embargoed", "e1", "--yes"], "vl format-patch"),
        (&["format-patch", "@-", "--audience", "public"], "vl format-patch"),
        (&["am", "-"], "vl am"),
        (&["am", "series.mbox", "-d", "@", "--3way", "--keep-author", "--signoff"], "vl am"),
        (&["am", "patches/", "--author-as-me"], "vl am"),
        // stream K: hooks
        (&["hooks", "show"], "vl hooks"),
        (&["hooks", "trust", "--yes", "--i-understand-indirect"], "vl hooks"),
        // stream G: submodules
        (&["submodule", "status"], "vl submodule"),
        (&["submodule", "status", "vendor/a"], "vl submodule"),
        (&["submodule", "update", "vendor/a", "--allow-local"], "vl submodule"),
        (&["submodule", "set", "vendor/a", "0123456789abcdef0123456789abcdef01234567"], "vl submodule"),
        (&["submodule", "add", "https://example.com/a.git", "vendor/a"], "vl submodule"),
        // stream W: attributes
        (&["attr", "check", "README.md", "src/x.c"], "vl attr"),
        (&["renormalize"], "vl renormalize"),
        (&["renormalize", "src"], "vl renormalize"),
        // stream C: colocated Git
        (&["git", "colocate"], "vl git colocate"),
        (&["git", "colocate", "--experimental"], "vl git colocate"),
        (&["git", "colocate", "--status"], "vl git colocate"),
        (&["git", "colocate", "--prune"], "vl git colocate"),
        (&["git", "uncolocate"], "vl git uncolocate"),
        (&["git", "check-push"], "vl git check-push"),
        (&["git", "check-push", "origin", "https://example.com/r.git"], "vl git check-push"),
        (&["policy", "import-gitignore"], "vl policy import-gitignore"),
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
        // stream H: log filters
        (&["log", "README.md"], "vl log PATH"),
        (&["log", "--", "README.md"], "vl log PATH"),
        (&["log", "-r", "root()..@"], "-r"),
        (&["log", "--author", "alice"], "--author"),
        (&["log", "--signed-by", "alice"], "--signed-by"),
        (&["log", "-S", "hello"], "-S"),
        (&["log", "-G", "hel+o", "-i"], "-G -i"),
        (&["log", "-S", "hello", "--pickaxe-all", "--show-skipped", "--max-changes", "5"], "--pickaxe-all"),
        (&["log", "--follow", "README.md", "--json"], "--follow"),
        // stream H: rename detection
        (&["diff", "--no-renames"], "--no-renames"),
        (&["diff", "-M"], "-M"),
        (&["diff", "-M=80"], "-M"),
        (&["diff", "--find-renames=30", "-C"], "-M -C"),
        (&["show", "@-", "-M"], "-M"),
        (&["show", "-C", "@-", "--json"], "-C"),
        // stream K: --no-verify
        (&["commit", "-m", "x", "--no-verify"], "--no-verify"),
        (&["describe", "-m", "x", "--no-verify"], "--no-verify"),
        (&["push", "--no-verify"], "--no-verify"),
        (&["push", "--dry-run", "--no-verify"], "--no-verify"),
        (&["git", "push", "--no-verify"], "--no-verify"),
        // stream G: annotated tags, Git tags
        (&["tag", "set", "v1", "-a"], "annotated tags"),
        (&["tag", "set", "v1", "-r", "@-", "-a", "-m", "release 1"], "annotated tags"),
        (&["tag", "set", "v1", "--force"], "annotated tags"),
        (&["tag", "verify", "v1"], "vl tag verify"),
        (&["git", "fetch", "--no-tags"], "--no-tags"),
        (&["git", "pull", "origin", "--prune-tags"], "--prune-tags"),
        (&["git", "push", "--force-tags"], "--force-tags"),
        (&["git", "push", "--delete-tag", "v1"], "--delete-tag"),
    ];
    for (args, what) in cases {
        env.refuses(args, what);
    }
}

#[test]
fn init_colocate_refuses_before_creating_anything() {
    let env = Env::new();
    let dir = env.root.join("colocated");
    let out = env.vl(&env.root, &["init", "--colocate", dir.to_str().unwrap()]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("`vl init --colocate` is not implemented yet"), "{err}");
    assert!(!dir.exists(), "init --colocate created {}", dir.display());
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
        &["format-patch"],
        &["format-patch", "@", "-o", "out", "--stdout"],
        &["format-patch", "@", "--audience", "everyone"],
        &["format-patch", "@", "--aud", "me"],
        &["am"],
        &["am", "-", "--keep-author", "--author-as-me"],
        &["hooks"],
        &["submodule"],
        &["submodule", "set", "vendor/a"],
        &["attr"],
        &["attr", "check"],
        &["git", "colocate", "--status", "--prune"],
        &["log", "-S", "a", "-G", "b"],
        &["diff", "--no-renames", "-M"],
        &["diff", "-M=101"],
        &["git", "fetch", "--no-tags", "--prune-tags"],
        &["tag", "verify"],
    ] {
        env.usage_error(args);
    }
}
