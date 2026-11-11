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

#[test]
fn bug_1840_sealed_secret_guard_covers_mounts_socket_commits_and_allows_in_place_sealed_edits() {
    const SECRET: &str = "Xk29vLq8sPzQw7LmTr4Bn6Yc";
    // Both a checked-out sandbox and `--mount`, including mid-run `vl commit`
    // through the workspace socket, refuse and remove copies while recording
    // clean edits and in-place edits of the sealed `.env` itself.
    for flags in [&[][..], &["--mount"]] {
        let t = T::new(&[("a.txt", "a\n"), ("src/lib.rs", "pub fn f() {}\n"), (".env", &format!("API_KEY={SECRET}\n"))]);
        let o = t.exec(
            flags,
            r#"set -e
               v=$(cut -d= -f2 .env); test -n "$v"
               printf '%s\n' "$v" > val.txt
               printf '// %s\n' "$v" >> src/lib.rs
               echo 'clean' >> a.txt
               printf 'PORT=8080\n' >> .env
               vl commit -m 'mid-run commit'"#,
        );
        assert!(o.status.success(), "{flags:?}: run failed:\n{}", text(&o));

        let show = t.ok(&["diff", "--from", "main", "--to", "agent@-"]);
        let listed = t.ok(&["ls", "-r", "agent@-"]);
        assert!(listed.lines().any(|l| l.ends_with("a.txt")), "{flags:?}: {listed}");
        assert!(show.contains("+clean"), "{flags:?}: clean edit was committed:\n{show}");
        assert!(
            listed.lines().any(|l| l.contains("cloaked") && l.ends_with(".env")),
            "{flags:?}: in-place edit of sealed .env stays cloaked:\n{listed}"
        );
        assert!(!listed.lines().any(|l| l.ends_with("val.txt")), "{flags:?}: val.txt must not be recorded:\n{listed}");
        let lib = t.ok(&["ws", "cat", "agent", "src/lib.rs"]);
        assert_eq!(lib, "pub fn f() {}\n", "{flags:?}: tainted tracked edit was held back");
        let env_cat = t.ok(&["ws", "cat", "agent", ".env"]);
        assert!(env_cat.contains("PORT=8080"), "{flags:?}: in-place .env edit recorded: {env_cat}");
        assert!(
            !t.proj.join(".veil/local/sandboxes/agent/files/val.txt").exists(),
            "{flags:?}: val.txt removed from sandbox"
        );
        assert!(
            !t.proj.join(".veil/local/mounts/agent/upper/val.txt").exists(),
            "{flags:?}: val.txt removed from mount overlay"
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
fn bug_1841_an_injected_secret_never_enters_history_through_a_description_set_inside_the_sandbox() {
    const SECRET: &str = "postgres://app:Xk29vLq8sPzQw7Lm@db/prod";
    const SEALED: &str = "Rk91mNv4pQz8wLx2Tr7Bc5Yd";
    let t = T::new(&[("a.txt", "a\n"), (".env", &format!("API_KEY={SEALED}\n"))]);
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
           vl commit -m "sealed $(cut -d= -f2- .env)"; echo "sealed-commit: $?"
           exit 0"#,
    );
    let out = text(&o);
    assert!(o.status.success(), "the run itself works (the isolated file was injected):\n{out}");
    for tag in ["commit: 1", "describe: 1", "new: 1", "sealed-commit: 1"] {
        assert!(out.contains(tag), "expected refusal `{tag}`:\n{out}");
    }
    assert!(!out.contains(SECRET), "refusal message echoed the isolated secret:\n{out}");
    assert!(!out.contains(SEALED), "refusal message echoed the sealed secret:\n{out}");
    // The file guard works: the copy is quarantined, never recorded.
    let listed = t.ok(&["ls", "-r", "agent@"]);
    assert!(!listed.contains("copy.txt"), "the copy of the injected file is not recorded:\n{listed}");

    // Nothing of the workspace's history holds the injected or sealed value.
    let log = t.ok(&["log", "-r", "::agent@"]);
    assert!(
        !log.contains(SECRET) && !log.contains(SEALED),
        "a secret value is in the workspace's history, in a description (plain text, pushed):\n{log}\nrun:\n{out}"
    );
}

/// `9-confinement.md`, "Threat review": the command "can change only its
/// sandbox, and read only the sandbox, the computer's public tools, the
/// allow-list and what it is given (environment, injected secrets)". The
/// guide: "`--only` gives the sandbox just the paths you name … plus
/// `.veilpolicy`"; `docs/VISIBILITY.md`: an agent sees "exactly what the
/// person running it can see, or less if it's given less".
///
/// A sparse sandbox (`--only src`) holds neither `docs/` nor the sealed
/// `.env`. Through the workspace socket, the command must not read them
/// either (the `vl` outside opens them, decrypted, on its behalf).
#[test]
fn bug_1844_a_sparse_sandbox_reads_only_its_paths_through_the_workspace_socket() {
    const SECRET: &str = "Zk29vLq8sPzQw7LmTr4Bn6Yc";
    const DOC: &str = "DOCS-ONLY-MARKER-7f3a91c2";
    let t = T::new(&[
        ("src/lib.rs", "pub fn f() {}\n"),
        ("docs/d.md", &format!("{DOC}\n")),
        (".env", &format!("K={SECRET}\n")),
    ]);
    let o = t.exec(
        &["--only", "src", "-m", "sparse run"],
        r#"test -e src/lib.rs || exit 8
           test ! -e docs && test ! -e .env || exit 9
           vl status >/dev/null || exit 7
           vl blame src/lib.rs || exit 6
           vl blame .veilpolicy >/dev/null || exit 5
           vl log src || exit 4
           for cmd in "blame .env" "blame docs/d.md" "log .env" "log docs/d.md" "log ."; do
               out=$(vl $cmd 2>&1) && { echo "RAN: $cmd"; exit 3; }
               case "$out" in *'inside a sandbox with --only'*'outside --only'*) ;; *) echo "BAD REFUSAL: $cmd: $out"; exit 2;; esac
           done
           s_out=$(vl log -S 'K=Zk29' --pickaxe-all --json) || exit 10
           case "$s_out" in *'"entries":[]'*) ;; *) echo "LEAK -S: $s_out"; exit 10;; esac
           g_out=$(vl log -G 'DOCS-ONLY-MARKER' --pickaxe-all --json) || exit 11
           case "$g_out" in *'"entries":[]'*) ;; *) echo "LEAK -G: $g_out"; exit 11;; esac
           vl diff --from root --to @
           vl diff --from root --to @ --json
           vl show main
           vl show main --json
           exit 0"#,
    );
    // The sandbox is sparse, the socket answers, and the command's own
    // paths are readable through it.
    assert!(o.status.success(), "{}", text(&o));
    let seen = text(&o);
    assert!(seen.contains("pub fn f() {}"), "sandbox's own src/lib.rs should be shown:\n{seen}");
    assert!(
        !seen.contains(SECRET),
        "a sandbox given only src/ read the sealed .env, decrypted, through the workspace socket:\n{seen}"
    );
    assert!(!seen.contains(DOC), "a sandbox given only src/ read docs/d.md through the workspace socket:\n{seen}");
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        !stdout.contains("docs/d.md") && !stdout.contains("a/.env") && !stdout.contains(r#""path":".env""#),
        "paths outside --only leaked:\n{stdout}"
    );

    // Even when a file inside `src/` was renamed from outside `--only` (or
    // `@` already carries an edit outside `--only`), `--follow` and `status`
    // stay inside `--only`; a later full or `--mount` run sees the whole workspace again.
    let full = t.exec(
        &[],
        "mv docs/d.md src/from_doc.md && echo 'extra' > docs/other.md && vl commit -m 'move doc' && echo 'dirty-outside' >> docs/other.md",
    );
    assert!(full.status.success(), "{}", text(&full));
    let o2 = t.exec(
        &["--only", "src"],
        "vl status && vl status --json && vl blame --follow src/from_doc.md --json && vl log --follow src/from_doc.md --json",
    );
    assert!(o2.status.success(), "{}", text(&o2));
    let seen2 = text(&o2);
    assert!(
        !seen2.contains("docs/other.md") && !seen2.contains("docs/d.md") && !seen2.contains("dirty-outside"),
        "status or --follow crossed --only boundary:\n{seen2}"
    );
    let mounted = t.exec(&["--mount"], "vl blame docs/other.md");
    assert!(mounted.status.success() && text(&mounted).contains("dirty-outside"), "{}", text(&mounted));
}

/// Re-check of BUG-1840's fix (`rc-client`). The guard keeps a sealed
/// secret's values out of *other* files a sandboxed command writes. A
/// value a tracked file already held before the run was not written by
/// the command: a sealed `.env` carries plain settings beside its secrets
/// (`APP_URL=…`, a database URL also in `docker-compose.yml` or the
/// README), and an agent must still be able to edit those files. "Normal
/// use works"; `docs/VISIBILITY.md`: "If an agent writes a secret into
/// some other file, Veil refuses to commit it and removes it after the
/// run": this file's edit wrote none.
#[test]
#[ignore = "BUG-1931: a sandboxed edit of a file that already held a value of a sealed secret file is discarded"]
fn bug_1931_a_sandbox_edit_of_a_file_that_already_held_a_sealed_files_value_is_recorded() {
    const URL: &str = "http://localhost:3000/app";
    const SECRET: &str = "Xk29vLq8sPzQw7LmTr4Bn6Yc";
    let mut lost = Vec::new();
    for flags in [&[][..], &["--mount"]] {
        let t = T::new(&[
            ("README.md", &format!("# Demo\n\nRun the app at {URL} after `make up`.\n")),
            ("src/lib.rs", "pub fn f() {}\n"),
            (".env", &format!("APP_URL={URL}\nAPI_KEY={SECRET}\n")),
        ]);
        let ls = t.ok(&["ls", "-r", "main"]);
        assert!(ls.lines().any(|l| l.contains("cloaked") && l.ends_with(".env")), "the .env is a sealed secret:\n{ls}");
        // The command edits the README (its URL line untouched), edits the
        // code, and copies the real secret into a new file.
        let o = t.exec(
            flags,
            r#"set -e
               echo 'More docs.' >> README.md
               echo '// x' >> src/lib.rs
               v=$(grep API_KEY .env | cut -d= -f2); test -n "$v"; printf '%s\n' "$v" > val.txt"#,
        );
        assert!(o.status.success(), "{flags:?}: the run itself works:\n{}", text(&o));
        // Control: the guard holds (BUG-1840), and a clean edit is recorded.
        let listed = t.ok(&["ls", "-r", "agent@"]);
        assert!(!listed.lines().any(|l| l.ends_with("val.txt")), "{flags:?}: the copy of the secret is not recorded:\n{listed}");
        assert!(t.ok(&["cat", "-r", "agent@", "src/lib.rs"]).contains("// x"), "{flags:?}: the edit of the code is recorded");
        // The README's edit is recorded too.
        let readme = t.ok(&["cat", "-r", "agent@", "README.md"]);
        if !readme.contains("More docs.") {
            lost.push(format!("{flags:?}: the edit of README.md was not recorded:\n{}", text(&o)));
        }
    }
    assert!(lost.is_empty(), "{lost:#?}");
}

/// Re-check of BUG-1840's fix (`rc-client`): a sealed secret's value
/// written to another file in a sandbox is never recorded, also when the
/// secret is in conflict. The sandbox then holds every version of it in
/// plain text, between conflict markers, for the command to resolve.
#[test]
#[ignore = "BUG-1932: the values of a sealed secret that is in conflict are outside the sandbox's guard"]
fn bug_1932_the_values_of_a_conflicted_sealed_secret_copied_in_a_sandbox_are_never_recorded() {
    const KEYS: [&str; 3] = ["Xk29vLq8sPzQw7LmTr4Bn6Yc", "Qm83nRt5wZx1cVb7yHj2kLp9", "Ty64gFd2sAq9oPi3uLk8mNb5"];
    let t = T::new(&[("a.txt", "a\n"), (".env", &format!("API_KEY={}\n", KEYS[0]))]);
    // Two changes set the key differently; one rebased onto the other
    // conflicts, and the agent's workspace stands on the conflicted change.
    std::fs::write(t.proj.join(".env"), format!("API_KEY={}\n", KEYS[1])).unwrap();
    t.ok(&["commit", "-m", "key one"]);
    t.ok(&["tag", "set", "side-a", "-r", "@-"]);
    t.ok(&["new", "side-a-"]);
    std::fs::write(t.proj.join(".env"), format!("API_KEY={}\n", KEYS[2])).unwrap();
    t.ok(&["commit", "-m", "key two"]);
    t.ok(&["tag", "set", "side-b", "-r", "@-"]);
    let out = t.ok(&["rebase", "-s", "side-b", "-d", "side-a"]);
    assert!(out.contains("conflicts in: .env"), "control: the rebase conflicts:\n{out}");
    t.ok(&["rebase", "-s", "agent@", "-d", "side-b"]);
    let ls = t.ok(&["ls", "-r", "agent@"]);
    assert!(ls.lines().any(|l| l.contains("cloaked") && l.contains(".env") && l.contains("conflict")), "control: the sandbox's .env is a sealed secret in conflict:\n{ls}");

    let o = t.exec(&["-m", "agent: list the keys"], r#"set -e; grep -q '^<<<<<<<' .env; grep '^API_KEY' .env | cut -d= -f2 > vals.txt; test "$(wc -l < vals.txt)" = 3"#);
    assert!(o.status.success(), "the run itself works (the sandbox holds the conflict's versions in plain text):\n{}", text(&o));

    let listed = t.ok(&["ls", "-r", "agent@"]);
    let show = t.ok(&["diff", "--from", "side-b", "--to", "agent@"]);
    let recorded: Vec<&str> = KEYS.iter().copied().filter(|k| show.contains(k)).collect();
    assert!(
        recorded.is_empty() && !listed.lines().any(|l| l.ends_with("vals.txt")),
        "the sealed secret's values were recorded in plain text (and would be pushed): {recorded:?}\nfiles:\n{listed}\nrun:\n{}",
        text(&o)
    );
    assert!(!t.proj.join(".veil/local/sandboxes/agent/files/vals.txt").exists(), "vals.txt holds the secret's values and must be taken out of the sandbox after the run");
}
