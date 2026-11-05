//! Persistent and sparse `vl ws exec` sandboxes: injected secrets that
//! outlive the run, rebuilds and stray removal that destroy unrecorded work,
//! and a run whose recording fails or whose `vl` is terminated.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use veil_core::{lock::RepoLock, DiskBackend};

use super::{
    adversarial_support::{read, text, wait_for, write, Env},
    cat, tree_contains, U,
};

const SECRET: &str = "correct-horse-battery-staple-81";

fn sandbox_dir(proj: &Path) -> PathBuf {
    proj.join(".veil/local/sandboxes/agent")
}

fn files_dir(proj: &Path) -> PathBuf {
    sandbox_dir(proj).join("files")
}

/// `main` = `a.txt`, `src/lib.rs`, `README.md`, plus an isolated `.env`
/// (in the local vault); virtual workspace `agent` on it.
fn project(env: &Env) -> PathBuf {
    let proj = env.project(U, "proj", &[("a.txt", "a\n"), ("src/lib.rs", "pub fn f() {}\n"), ("README.md", "r\n")]);
    write(&proj, ".env", &format!("SESSION_SALT={SECRET}\n"));
    env.ok(U, &proj, &["commit", "-m", "env"]);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    proj
}

fn exec(env: &Env, proj: &Path, args: &[&str]) -> String {
    let mut all = vec!["ws", "exec", "agent"];
    all.extend_from_slice(args);
    env.ok(U, proj, &all)
}

/// The run's work survived: recorded into the workspace, or at least still
/// in the sandbox.
fn work_kept(env: &Env, proj: &Path, path: &str, content: &str) -> bool {
    cat(env, U, proj, "agent@", path).as_deref() == Some(content)
        || std::fs::read_to_string(files_dir(proj).join(path)).is_ok_and(|c| c == content)
}

// ---- BUG-546: copies of an injected secret survive the run ------------------

/// ARCHITECTURE §6 step 8 / `sandbox.rs` module docs: "nothing that copies
/// an injected secret survives into a run that no longer guards against
/// it". The guard only cleans what the builder quarantined, and the builder
/// never looks at ignored or isolated paths: a build that bakes `.env` into
/// `target/`, `node_modules/`, or a `.env.local` / `.env.bak` copy, keeps
/// the secret in the sandbox, readable by every later run that was not
/// given it.
#[test]
fn injected_secret_copies_in_ignored_or_isolated_paths_are_taken_out() {
    let env = Env::new();
    let proj = project(&env);
    let out = exec(
        &env,
        &proj,
        &[
            "--with-isolated",
            "--",
            "sh",
            "-c",
            "mkdir -p target node_modules/pkg; cp .env target/app.env; cp .env node_modules/pkg/config; cp .env .env.local; cp .env .env.bak",
        ],
    );
    assert!(!out.contains("error"), "{out}");
    let left = tree_contains(&sandbox_dir(&proj), SECRET.as_bytes());
    // A later run, not given the isolated files, must not find the secret.
    let later = exec(&env, &proj, &["--", "sh", "-c", "cat target/app.env node_modules/pkg/config .env.local .env.bak 2>/dev/null; true"]);
    assert!(
        left.is_empty() && !later.contains(SECRET),
        "the injected secret outlived its run in {left:?}; a run without --with-isolated read it:\n{later}"
    );
}

// ---- BUG-547: a later run records an injected secret into history ----------

/// The injected-secret guard (`InjectedSecrets`) is armed for the
/// `--with-isolated` run only. Anything holding the secret that is still in
/// the sandbox afterwards (a background process the command started, a dev
/// server writing its config into a log, or BUG-546's leftovers moved by a
/// later command) is recorded by the next plain `vl ws exec` like any other
/// file: the local-only secret enters the workspace's history (plaintext,
/// public), from where `vl push` publishes it. The scanner does not catch
/// an arbitrary value; only the injected guard knows it. `vl` has the vault
/// in every run and could always guard against its contents.
#[test]
fn a_secret_that_lands_after_an_injected_run_is_never_recorded() {
    let env = Env::new();
    let proj = project(&env);
    // A dev server started in the background keeps the environment and
    // writes it to its log a moment later.
    exec(
        &env,
        &proj,
        &[
            "--with-isolated",
            "--",
            "sh",
            "-c",
            "v=$(cat .env); (sleep 2; echo \"$v\" > server.log) </dev/null >/dev/null 2>&1 &",
        ],
    );
    let log = files_dir(&proj).join("server.log");
    assert!(wait_for(Duration::from_secs(20), || log.exists() && std::fs::metadata(&log).is_ok_and(|m| m.len() > 0)));
    // The next run, without --with-isolated, by another agent.
    exec(&env, &proj, &["-m", "next task", "--", "true"]);
    let recorded = cat(&env, U, &proj, "agent@", "server.log").unwrap_or_default();
    assert!(
        !recorded.contains(SECRET),
        "the isolated secret was recorded into the workspace's history: server.log = {recorded:?}"
    );
}

// ---- BUG-548: a rebuild destroys quarantined work and kept hand edits ------

/// Quarantined files are "local work that is in no snapshot" and `vl ws rm`
/// refuses to delete them without `--force`. But every rebuild
/// (`rebuild_reason`: another boot, which on Linux includes another pid
/// namespace, i.e. a `vl` run from a container or Flatpak terminal; an
/// interrupted run; a pruned tree) wipes the whole `files/` directory with
/// them, silently: the message only says the sandbox is rebuilt. The same
/// goes for hand edits a narrower `--only` set keeps "until a run whose set
/// holds them records them".
#[test]
fn a_rebuild_keeps_quarantined_work() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "sh", "-c", "echo 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' > creds.txt"]);
    assert!(files_dir(&proj).join("creds.txt").exists(), "quarantined work stays in the sandbox");
    exec(&env, &proj, &["--only", "src", "--", "true"]);
    write(&files_dir(&proj), "README.md", "edited by hand, kept outside --only src\n");
    // The machine reboots (or the next `vl` runs in another pid namespace):
    // the boot identity in the manifest no longer matches.
    let mpath = sandbox_dir(&proj).join("manifest.json");
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&mpath).unwrap()).unwrap();
    assert_eq!(m["quarantined"], serde_json::json!(["creds.txt"]), "{m}");
    m["boot"] = "an-earlier-boot/pid:[4026531836]".into();
    std::fs::write(&mpath, serde_json::to_vec(&m).unwrap()).unwrap();
    let out = exec(&env, &proj, &["--only", "src", "--", "true"]);
    assert!(out.contains("Rebuilding"), "{out}");
    let creds = files_dir(&proj).join("creds.txt");
    let readme = std::fs::read_to_string(files_dir(&proj).join("README.md")).unwrap_or_default();
    assert!(
        creds.exists() && readme.starts_with("edited by hand"),
        "the rebuild deleted unrecorded work (creds.txt kept: {}, README.md = {readme:?}):\n{out}",
        creds.exists()
    );
}

// ---- BUG-549: stray removal deletes files the command never wrote ----------

/// After a sparse run, `strays` (files outside the set a full snapshot would
/// record) are "what the command wrote outside the set" and are removed.
/// Files that were there before the command are excluded by the `kept`
/// listing, but that listing is taken under the policy before the command
/// and the strays under the policy after it. A command that edits
/// `.veilpolicy` (always in the set) so that an ignored or isolated path is
/// no longer so makes `vl` delete, as "written outside --only", files the
/// command never touched: build caches, local configs, an isolated
/// credentials file. They are in no snapshot.
#[test]
fn a_policy_edit_in_a_sparse_run_never_deletes_files_the_command_did_not_write() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--only", "src", "--", "sh", "-c", "mkdir -p target && echo 'hours of build cache' > target/cache.bin"]);
    assert_eq!(read(&files_dir(&proj), "target/cache.bin"), "hours of build cache\n");
    // A later run (another task) drops the `target/ ignore` rule.
    let out = exec(&env, &proj, &["--only", "src", "--", "sh", "-c", "grep -v '^target/' .veilpolicy > p && mv p .veilpolicy"]);
    assert!(
        files_dir(&proj).join("target/cache.bin").exists(),
        "vl deleted a file the command did not write, and it is in no snapshot:\n{out}"
    );
}

/// Control: without the policy edit the ignored output stays.
#[test]
fn ignored_output_outside_a_sparse_set_stays() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--only", "src", "--", "sh", "-c", "mkdir -p target && echo cache > target/cache.bin"]);
    exec(&env, &proj, &["--only", "src", "--", "sh", "-c", "echo x >> src/lib.rs"]);
    assert_eq!(read(&files_dir(&proj), "target/cache.bin"), "cache\n");
}

// ---- BUG-550: SIGTERM to vl wipes the running command's work ---------------

/// `vl` ignores SIGINT and SIGQUIT while the command runs, then records what
/// it left. SIGTERM and SIGHUP (an IDE stopping a task, `kill`, a closed
/// terminal) kill `vl` at once: the reaper sees the pipe close and wipes
/// the sandbox, the command's unrecorded output with it, while the command
/// itself (not signalled) keeps running in a deleted directory. Nothing was
/// injected here, so there is no secret to protect by wiping.
#[test]
fn sigterm_to_vl_keeps_the_commands_work() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "true"]);
    let started = env.root.join("started");
    let script = format!("echo 'an hour of agent work' > work.txt; touch {}; sleep 3; echo more >> work.txt", started.display());
    let child = env.spawn(U, &proj, &["ws", "exec", "agent", "--", "sh", "-c", &script]);
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    // SAFETY: signals our own child.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let out = child.wait_with_output().unwrap();
    // Let the command finish and the reaper act.
    std::thread::sleep(Duration::from_secs(5));
    let t = text(&out);
    assert!(
        work_kept(&env, &proj, "work.txt", "an hour of agent work\n")
            || work_kept(&env, &proj, "work.txt", "an hour of agent work\nmore\n"),
        "the command's work is gone (sandbox: {:?}):\n{t}",
        super::walk(&sandbox_dir(&proj))
    );
}

// ---- BUG-551: a busy repository lock at record time wipes the run ----------

/// After the command, `vl` records the sandbox under the repository lock,
/// which it waits for 15 s. If another `vl` holds it longer (a large
/// snapshot, `vl gc`, a slow remote), the snapshot fails, and every error
/// between steps 3 and 9 wipes the sandbox (`PersistentRun::drop`): the
/// command's whole output is destroyed because of lock contention. Nothing
/// was injected; the files could simply stay for the next run to record.
#[test]
fn a_busy_repository_lock_at_record_time_keeps_the_run() {
    let env = Env::new();
    let proj = project(&env);
    exec(&env, &proj, &["--", "true"]);
    let started = env.root.join("started");
    let script = format!("touch {}; sleep 1; echo 'agent output' > out.txt", started.display());
    let child = env.spawn(U, &proj, &["ws", "exec", "agent", "--", "sh", "-c", &script]);
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    // Another process takes the repository lock while the command runs and
    // holds it for 20 s.
    let backend: Arc<dyn veil_core::StorageBackend> = Arc::new(DiskBackend::new(&proj));
    let holder = std::thread::spawn(move || {
        let lock = RepoLock::acquire(backend).expect("lock");
        std::thread::sleep(Duration::from_secs(20));
        drop(lock);
    });
    let out = child.wait_with_output().unwrap();
    holder.join().unwrap();
    assert!(
        work_kept(&env, &proj, "out.txt", "agent output\n"),
        "the run's output was destroyed (exit {:?}):\n{}",
        out.status.code(),
        text(&out)
    );
}

// ---- BUG-552: deleting a spine directory deletes files outside the set -----

/// A sparse sandbox for `--only src/lib.rs` holds `src/` with that one
/// file. The command removes it and the directory it leaves empty (`rm
/// src/lib.rs && rmdir src`, or `rm -rf src`): `SparseView` then lists no
/// `src` at the root (the tree's spine entries are left to the sandbox's
/// listing, `spine_listing`), so the snapshot records every file under
/// `src/` as deleted, including `src/other.rs` and `src/deep/d.rs`, which
/// were never in the set or the sandbox.
#[test]
fn removing_the_last_file_of_a_spine_directory_keeps_the_rest_of_it() {
    let env = Env::new();
    let proj = env.project(
        U,
        "proj",
        &[("src/lib.rs", "lib\n"), ("src/other.rs", "other\n"), ("src/deep/d.rs", "d\n"), ("README.md", "r\n")],
    );
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    exec(&env, &proj, &["--only", "src/lib.rs", "--", "sh", "-c", "rm src/lib.rs && rmdir src"]);
    assert_eq!(cat(&env, U, &proj, "agent@", "src/lib.rs"), None, "the deletion inside the set is recorded");
    assert_eq!(
        (cat(&env, U, &proj, "agent@", "src/other.rs"), cat(&env, U, &proj, "agent@", "src/deep/d.rs")),
        (Some("other\n".to_string()), Some("d\n".to_string())),
        "files outside --only src/lib.rs were recorded as deleted"
    );
}

/// Control: deleting the file alone (the directory stays) is exact.
#[test]
fn deleting_a_file_of_the_set_keeps_its_siblings() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("src/lib.rs", "lib\n"), ("src/other.rs", "other\n")]);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    exec(&env, &proj, &["--only", "src/lib.rs", "--", "rm", "src/lib.rs"]);
    assert_eq!(cat(&env, U, &proj, "agent@", "src/lib.rs"), None);
    assert_eq!(cat(&env, U, &proj, "agent@", "src/other.rs").as_deref(), Some("other\n"));
}

// ---- BUG-553: deleting .veilpolicy in a sandbox declassifies everything ----

/// In the project directory a missing `.veilpolicy` is never the member's
/// edit ("deleting every rule at once is an accident far more often than a
/// decision"): the accepted policy keeps guarding. A sandbox has no
/// accepted policy (`Repo::snapshot_policy` for other backends:
/// `Policy::load`, which reads a missing file as the built-in rules), and a
/// deleted `.veilpolicy` is an edit of it, so rule 5 moves every cloaked
/// file to its new classification, public: a command that deletes the file
/// (a cleanup, `git clean`-like tools, regenerating the tree) gets every
/// cloaked file recorded as public plaintext, without a warning, ready for
/// the next public push. Sparse runs do the same to cloaked files outside
/// their set.
#[test]
fn deleting_the_policy_in_a_sandbox_never_declassifies_cloaked_files() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("src/lib.rs", "lib\n"), ("secret/plan.md", "TOP-SECRET-PLAN-5521\n")]);
    let policy = std::fs::read_to_string(proj.join(".veilpolicy")).unwrap();
    write(&proj, ".veilpolicy", &format!("{policy}secret/ cloak team\n"));
    env.ok(U, &proj, &["commit", "-m", "cloak"]);
    env.ok(U, &proj, &["ws", "new", "agent", "-r", "@-"]);
    env.ok(U, &proj, &["ws", "new", "sparse", "-r", "@-"]);
    let before = env.stdout(U, &proj, &["files", "-r", "agent@"]);
    assert!(before.contains("cloaked:team") && before.contains("secret/plan.md"), "{before}");
    exec(&env, &proj, &["--", "rm", ".veilpolicy"]);
    env.ok(U, &proj, &["ws", "exec", "sparse", "--only", "src", "--", "rm", ".veilpolicy"]);
    for ws in ["agent@", "sparse@"] {
        let after = env.stdout(U, &proj, &["files", "-r", ws]);
        let line = after.lines().find(|l| l.contains("secret/plan.md")).unwrap_or_default().to_string();
        assert!(line.starts_with("cloaked:team"), "{ws}: the cloaked file was declassified: {after}");
    }
}

// ---- BUG-554: an unreadable .veilpolicy fails the recording ----------------

/// `read_policy_file` promises that "nothing in the working copy may fail a
/// snapshot": the project directory falls back to the accepted policy. A
/// sandbox snapshot uses `Policy::load`, which turns an unreadable
/// `.veilpolicy` (mode 000, a directory, a symlink to a file not named like
/// a policy) into an error; the run fails and, because any error wipes the
/// sandbox (BUG-551), the command's work is destroyed.
#[test]
fn an_unreadable_policy_in_the_sandbox_neither_fails_the_run_nor_loses_its_work() {
    let env = Env::new();
    let proj = project(&env);
    let o = env.vl(U, &proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo important > work.txt; chmod 000 .veilpolicy"]);
    assert!(
        o.status.success() && work_kept(&env, &proj, "work.txt", "important\n"),
        "exit {:?}, work kept: {}:\n{}",
        o.status.code(),
        work_kept(&env, &proj, "work.txt", "important\n"),
        text(&o)
    );
}
