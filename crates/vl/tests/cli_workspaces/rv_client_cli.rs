//! Whole-codebase review, client area (`rv-client`, 2026-11-10): the
//! reproductions of BUG-1840 to BUG-1849 that concern `vl ws exec` and the
//! workspace socket. Each test states the guarantee, asserts that its
//! action succeeded, then checks the guarantee.

use crate::adversarial_support;

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use adversarial_support::*;

/// A project of alice's with a workspace `agent` on `main`, a private home
/// and a runtime directory short enough for the workspace socket.
struct T {
    env: Env,
    proj: PathBuf,
    home: PathBuf,
    runtime: tempfile::TempDir,
}

impl T {
    fn new(files: &[(&str, &str)]) -> T {
        let env = Env::new();
        let proj = env.project("alice", "proj", files);
        env.ok("alice", &proj, &["ws", "new", "agent", "-r", "main"]);
        let home = env.dir("fakehome");
        let short = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|d| d.is_dir()).unwrap_or_else(|| PathBuf::from("/tmp"));
        let runtime = tempfile::Builder::new().prefix("vt-").tempdir_in(short).unwrap();
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        T { env, proj, home, runtime }
    }

    fn cmd(&self, cwd: &Path, args: &[&str]) -> Command {
        let mut c = self.env.cmd("alice", cwd, args);
        c.env("HOME", &self.home).env("XDG_RUNTIME_DIR", self.runtime.path()).stdin(Stdio::null());
        c
    }

    fn vl(&self, args: &[&str]) -> Output {
        self.cmd(&self.proj, args).output().unwrap()
    }

    /// stdout + stderr of `vl ARGS` in the project; it must succeed.
    fn ok(&self, args: &[&str]) -> String {
        let o = self.vl(args);
        assert!(o.status.success(), "vl {args:?} failed:\n{}", text(&o));
        text(&o)
    }

    /// `vl ws exec agent FLAGS -- bash -c SCRIPT`.
    fn exec(&self, flags: &[&str], script: &str) -> Output {
        let mut a = vec!["ws", "exec", "agent"];
        a.extend_from_slice(flags);
        a.extend(["--", "bash", "-c", script]);
        self.vl(&a)
    }
}

/// `docs/VISIBILITY.md`, "Agents and secrets": "Agents on your computer
/// (`vl ws exec`) see what you see, including secrets you have access to.
/// If an agent writes a secret into some other file, Veil refuses to commit
/// it and removes it after the run." And CLAUDE.md: "Secrets are only ever
/// stored encrypted."
///
/// The sandbox holds the sealed `.env` in plain text (as designed). A
/// command that writes its value into another file (a bare value, or a
/// constant in code: nothing the pattern scanner knows) must not get that
/// file recorded: it would be stored unencrypted and pushed.
#[test]
#[ignore = "BUG-1840: a sandboxed command's copy of a sealed secret's value is recorded as a plain public file"]
fn bug_1840_the_value_of_a_sealed_secret_written_to_another_file_in_a_sandbox_is_never_recorded() {
    const SECRET: &str = "Xk29vLq8sPzQw7LmTr4Bn6Yc";
    let t = T::new(&[("a.txt", "a\n"), ("src/lib.rs", "pub fn f() {}\n"), (".env", &format!("API_KEY={SECRET}\n"))]);
    // The secret is sealed in history, and the sandbox gets its plain text.
    let ls = t.ok(&["ls", "-r", "main"]);
    assert!(ls.lines().any(|l| l.contains("cloaked") && l.ends_with(".env")), "the .env is a sealed secret:\n{ls}");

    let o = t.exec(
        &["-m", "agent: wire the key"],
        r#"set -e; v=$(cut -d= -f2 .env); test -n "$v"; printf '%s\n' "$v" > val.txt; printf 'const K = "%s";\n' "$v" > src/k.js"#,
    );
    assert!(o.status.success(), "the run itself works:\n{}", text(&o));

    // Nothing the run recorded holds the secret's value in the clear.
    let show = t.ok(&["diff", "--from", "main", "--to", "agent@"]);
    let listed = t.ok(&["ls", "-r", "agent@"]);
    assert!(
        !show.contains(SECRET),
        "the sealed secret's value was recorded in plain text (and would be pushed):\n{show}\nfiles:\n{listed}\nrun:\n{}",
        text(&o)
    );
    for f in ["val.txt", "src/k.js"] {
        assert!(!listed.lines().any(|l| l.ends_with(f)), "{f} holds the secret's value and must not be recorded:\n{listed}");
        // "… and removes it after the run."
        assert!(
            !t.proj.join(".veil/local/sandboxes/agent/files").join(f).exists(),
            "{f} holds the secret's value and must be taken out of the sandbox after the run"
        );
    }
}

/// The guide, "Isolated files in sandboxes: `--with-isolated`": "Anything
/// the command writes that contains one of their values is quarantined, so
/// a copy under another name can't be recorded … quarantine only keeps
/// them out of history." And `9-confinement.md` item 17: the socket's
/// commands go "through the same policy, scanner and injected-secret guard
/// as the run's end".
///
/// Since the workspace socket (S8) a command also writes change
/// descriptions (`vl commit -m`, `vl describe -m`, `vl new -m`). A
/// description that quotes an injected isolated secret must not enter
/// history: descriptions are plain text and are pushed.
#[test]
#[ignore = "BUG-1841: through the workspace socket, an injected isolated secret enters history in a change description"]
fn bug_1841_an_injected_secret_never_enters_history_through_a_description_set_inside_the_sandbox() {
    const SECRET: &str = "postgres://app:Xk29vLq8sPzQw7Lm@db/prod";
    let t = T::new(&[("a.txt", "a\n")]);
    // An isolated file: on this device only, never in a snapshot.
    write(&t.proj, "deploy.key", &format!("DB_URL={SECRET}\n"));
    let st = t.ok(&["status"]);
    assert!(st.contains("deploy.key [isolated]"), "deploy.key is isolated:\n{st}");

    let o = t.exec(
        &["--with-isolated", "-m", "agent run"],
        r#"test -s deploy.key || exit 9
           cp deploy.key copy.txt
           vl commit -m "use $(cat deploy.key)"; echo "commit: $?"
           vl describe -m "now $(cut -d= -f2- deploy.key)"; echo "describe: $?"
           vl new -m "next $(cut -d= -f2- deploy.key)"; echo "new: $?"
           exit 0"#,
    );
    assert!(o.status.success(), "the run itself works (the isolated file was injected):\n{}", text(&o));
    // The file guard works: the copy is quarantined, never recorded.
    let listed = t.ok(&["ls", "-r", "agent@"]);
    assert!(!listed.contains("copy.txt"), "the copy of the injected file is not recorded:\n{listed}");

    // Nothing of the workspace's history holds the injected value.
    let log = t.ok(&["log", "-r", "::agent@"]);
    assert!(
        !log.contains(SECRET),
        "an injected isolated secret is in the workspace's history, in a description (plain text, pushed):\n{log}\nrun:\n{}",
        text(&o)
    );
}
