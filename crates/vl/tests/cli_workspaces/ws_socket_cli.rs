//! The guarantees of the workspace socket and of `vl ws exec --mount`
//! (milestone S8; `docs/design/server/phase-2-thin-clients.md` §4.6, §4.8):
//!
//! * a `vl` inside the sandbox runs only the workspace commands (status,
//!   diff, log, show, blame, commit, describe of `@`, new on `@`), on its own
//!   workspace; every other command, `-R`, and revisions of other changes
//!   are refused before anything is opened; nothing it sends changes who
//!   the command runs as (attribution comes from the `vl` outside); hooks
//!   never run for it; the project directory and the other workspaces are
//!   unchanged; hostile requests on the raw socket are refused; the socket
//!   is gone when the run ends;
//! * `--mount`: what the command writes, deletes, renames or `chmod`s is
//!   exactly what is recorded; the project directory is unchanged; the same
//!   holds checked out without FUSE (`VEIL_TEST_NO_FUSE`), where a note says
//!   so.

use crate::adversarial_support;

use std::{
    collections::BTreeMap,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use adversarial_support::*;

struct T {
    env: Env,
    proj: PathBuf,
    home: PathBuf,
    /// A runtime directory of this test's own, short enough for sockets.
    runtime: tempfile::TempDir,
}

impl T {
    fn new() -> T {
        let env = Env::new();
        let proj = env.project("alice", "proj", &[("a.txt", "a\n"), ("src/lib.rs", "pub fn f() {}\n"), ("docs/x.md", "x\n")]);
        env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
        env.ok("alice", &proj, &["ws", "new", "other", "-r", "@-"]);
        let home = env.dir("fakehome");
        let short = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|d| d.is_dir()).unwrap_or_else(|| PathBuf::from("/tmp"));
        let runtime = tempfile::Builder::new().prefix("vt-").tempdir_in(short).unwrap();
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        T { env, proj, home, runtime }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = self.env.cmd("alice", &self.proj, args);
        c.env("HOME", &self.home).env("XDG_RUNTIME_DIR", self.runtime()).stdin(Stdio::null());
        c
    }

    /// This test's own runtime directory (where runs keep their sockets).
    fn runtime(&self) -> PathBuf {
        self.runtime.path().to_path_buf()
    }

    fn exec(&self, flags: &[&str], script: &str) -> Output {
        let mut a = vec!["ws", "exec", "agent"];
        a.extend_from_slice(flags);
        a.extend(["--", "bash", "-c", script]);
        self.cmd(&a).output().unwrap()
    }

    /// The command's stdout; the run must succeed.
    fn ok(&self, flags: &[&str], script: &str) -> String {
        let o = self.exec(flags, script);
        assert!(o.status.success(), "{}", text(&o));
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    fn wc(&self, ws: &str) -> String {
        let o = self.env.ok("alice", &self.proj, &["log", "-n", "1", "-r", &format!("{ws}@"), "--json"]);
        let v: serde_json::Value = serde_json::from_str(o.lines().find(|l| l.starts_with('{')).unwrap()).unwrap();
        v["entries"][0]["snapshot_id"].as_str().unwrap().to_string()
    }

    fn cat(&self, ws: &str, path: &str) -> Option<String> {
        let o = self.env.vl("alice", &self.proj, &["ws", "cat", ws, path]);
        o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
    }

    /// The paths `vl show --stat` lists for `rev`.
    fn changed(&self, rev: &str) -> Vec<String> {
        let o = self.env.ok("alice", &self.proj, &["show", rev, "--stat", "--json"]);
        let v: serde_json::Value = serde_json::from_str(o.lines().find(|l| l.starts_with('{')).unwrap()).unwrap();
        let mut out: Vec<String> = v["diff"]["files"].as_array().unwrap().iter().map(|c| format!("{} {}", c["status"].as_str().unwrap(), c["path"].as_str().unwrap())).collect();
        out.sort();
        out
    }
}

/// Every file under `dir` but `.veil`, with content and mode.
fn files(dir: &Path) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            let rel = p.strip_prefix(dir).unwrap().to_path_buf();
            if rel.starts_with(".veil") {
                continue;
            }
            let m = std::fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                stack.push(p.clone());
                out.insert(rel, format!("dir {:o}", m.permissions().mode()));
            } else {
                out.insert(rel, format!("{:o} {}", m.permissions().mode(), blake3::hash(&std::fs::read(&p).unwrap()).to_hex()));
            }
        }
    }
    out
}

#[test]
fn the_sandboxs_vl_runs_workspace_commands_on_its_own_workspace() {
    let t = T::new();
    let project = files(&t.proj);
    let other = t.wc("other");
    let default = t.wc("default");
    for (i, flags) in [&[][..], &["--mount"], &["--unconfined"]].iter().enumerate() {
        let out = t.ok(
            flags,
            &format!(
                "echo new > made{i}.txt && echo changed{i} > a.txt && vl status && vl diff --stat && vl commit -m 'inside commit {i}' && \
                 vl describe -m 'next change {i}' && vl new && vl log -n 3 && vl show @-- --stat && vl blame a.txt"
            ),
        );
        assert!(out.contains(&format!("A made{i}.txt")) && out.contains("M a.txt"), "{flags:?}: status shows the command's edits: {out}");
        assert!(out.contains("Committed") && out.contains(&format!("inside commit {i}")) && out.contains(&format!("next change {i}")), "{flags:?}: {out}");
        assert!(out.contains(&format!("changed{i}")), "{flags:?}: blame: {out}");
        assert_eq!(t.cat("agent", &format!("made{i}.txt")).as_deref(), Some("new\n"));
        // The workspace's history holds the commit, its next change, then
        // the empty change `vl new` started.
        let log = t.env.ok("alice", &t.proj, &["log", "-n", "4", "-r", "::agent@"]);
        assert!(log.contains(&format!("inside commit {i}")) && log.contains(&format!("next change {i}")), "{flags:?}: {log}");
        // Nothing else moved: the project directory, its workspace, the
        // other workspace.
        assert_eq!(files(&t.proj), project, "{flags:?}: the project directory changed");
        assert_eq!(t.wc("other"), other, "{flags:?}");
        assert_eq!(t.wc("default"), default, "{flags:?}");
    }
}

#[test]
fn every_other_command_is_refused_before_anything_is_opened() {
    let t = T::new();
    let other_change = t.wc("other");
    let before_ops = t.env.ok("alice", &t.proj, &["op", "log", "-n", "1000"]).lines().count();
    let refused: Vec<String> = [
        "access a.txt public",
        "group create g",
        "group add g bob",
        "identity show",
        "invite bob --to g",
        "ws new x",
        "ws rm other",
        "ws switch other",
        "ws exec other -- true",
        "ws write other a.txt",
        "ws mount other /tmp/m",
        "push",
        "pull",
        "undo",
        "op restore @",
        "tag set main -r @",
        "merge other@",
        "rebase -s @ -d other@",
        "abandon other@",
        "edit other@",
        "restore a.txt",
        "secret list",
        "hooks trust",
        "gc",
        "upgrade",
        "serve --local",
        "init /tmp/x",
        "clone veil://localhost/p",
        "login veil://localhost",
        "remote add origin veil://localhost/p",
        "partial status",
        "-R / status",
        "-R .. status",
        &format!("describe -r {other_change} -m stolen"),
        "describe -r other@ -m stolen",
        "new other@",
        "new @ other@",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // Each must fail with the socket's own refusal, not for another reason.
    let script: String = refused
        .iter()
        .map(|c| {
            format!(
                "out=$(vl {c} 2>&1) && echo \"RAN: {c}\"; case \"$out\" in *'not available inside a sandbox'*|*'inside a sandbox, `vl'*) ;; \
                 *) echo \"NOT REFUSED: {c}: $out\";; esac; "
            )
        })
        .collect();
    let out = t.ok(&["--mount"], &format!("{script} echo done"));
    assert!(!out.contains("RAN:") && !out.contains("NOT REFUSED"), "commands ran through the socket: {out}");
    assert!(out.contains("done"));
    // Each refusal says why.
    let o = t.exec(&[], "vl access a.txt public");
    assert!(!o.status.success() && text(&o).contains("not available inside a sandbox"), "{}", text(&o));
    assert_eq!(t.wc("other"), other_change, "another workspace was changed");
    // The only operations are the runs' own recordings (none: no edits).
    let after_ops = t.env.ok("alice", &t.proj, &["op", "log", "-n", "1000"]).lines().count();
    assert_eq!(after_ops, before_ops, "a refused command recorded an operation");
}

#[test]
fn the_caller_cannot_change_who_runs_the_command_or_make_hooks_run() {
    let t = T::new();
    // A device-local hook that would run outside the sandbox.
    let veil_home = t.env.dir("home-alice");
    let marker = t.env.dir("hook-ran").join("marker");
    write(&veil_home, "hooks/pre-commit", &format!("#!/bin/sh\ntouch {}\n", marker.display()));
    std::fs::set_permissions(veil_home.join("hooks/pre-commit"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = t.ok(
        &["--mount"],
        "echo x > x.txt; VEIL_USER=mallory VEIL_HOME=/tmp/evil VEIL_AGENT=forged vl commit -m 'by whom' && vl log -n 2 --json",
    );
    assert!(out.contains("by whom"), "{out}");
    assert!(!out.contains("mallory"), "the caller's VEIL_USER was used: {out}");
    assert!(!marker.exists(), "a hook ran outside the sandbox for a command from inside");
    let log = t.env.ok("alice", &t.proj, &["log", "-n", "3", "-r", "::agent@", "--json"]);
    assert!(log.contains("alice") && !log.contains("mallory"), "{log}");
    // The same commit from the project directory runs the hook: it works.
    write(&t.proj, "y.txt", "y\n");
    t.env.ok("alice", &t.proj, &["commit", "-m", "outside"]);
    assert!(marker.exists(), "the hook itself works");
}

#[test]
fn hostile_requests_on_the_raw_socket_are_refused_and_the_socket_ends_with_the_run() {
    let t = T::new();
    let report = t.env.dir("report");
    // The command speaks to the socket itself: python3 inside the sandbox.
    let py = r#"
import json, os, socket, struct, sys
path = os.environ["VEIL_WORKSPACE_SOCKET"]
def ask(raw):
    s = socket.socket(socket.AF_UNIX); s.connect(path); s.sendall(raw)
    out, code = b"", None
    try:
        while True:
            head = s.recv(5, socket.MSG_WAITALL)
            if len(head) < 5: break
            n = struct.unpack(">I", head[1:])[0]
            body = b""
            while len(body) < n:
                c = s.recv(n - len(body))
                if not c: break
                body += c
            if head[:1] == b"x": code = struct.unpack(">i", body)[0]; break
            out += body
    except Exception as e:
        out += str(e).encode()
    return code, out
cases = {
  "huge": b'{"argv":["status"],"cwd":"/' + b"a" * (2 << 20) + b'"}\n',
  "nul": json.dumps({"argv": ["status", "a\u0000b"], "cwd": "/"}).encode() + b"\n",
  "garbage": b"\xff\xfe not json\n",
  "noline": b'{"argv":["status"],"cwd":"/"}',
  "repo": json.dumps({"argv": ["-R", "/", "status"], "cwd": "/"}).encode() + b"\n",
  "access": json.dumps({"argv": ["access", "a.txt", "public"], "cwd": "/"}).encode() + b"\n",
  "escape": json.dumps({"argv": ["status"], "cwd": "/../../etc"}).encode() + b"\n",
  "ok": json.dumps({"argv": ["status"], "cwd": "/"}).encode() + b"\n",
}
res = {}
for k, v in cases.items():
    try:
        code, out = ask(v) if k != "noline" else (None, b"")
    except Exception as e:
        code, out = None, str(e).encode()
    res[k] = [code, out.decode("utf-8", "replace")[:300]]
print(json.dumps(res))
print("SOCKET", path)
"#;
    write(&report, "probe.py", py);
    let o = t.cmd(&["ws", "exec", "agent", "--allow", report.to_str().unwrap(), "--", "python3", report.join("probe.py").to_str().unwrap()]).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let stdout = String::from_utf8_lossy(&o.stdout);
    let res: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    for k in ["huge", "nul", "garbage", "repo", "access"] {
        assert_ne!(res[k][0], serde_json::json!(0), "{k}: {res}");
        assert!(!res[k][1].as_str().unwrap().contains("Working copy"), "{k} ran: {res}");
    }
    // A cwd outside the project is the project's root, never elsewhere.
    assert_eq!(res["escape"][0], serde_json::json!(0), "{res}");
    assert_eq!(res["ok"][0], serde_json::json!(0), "{res}");
    assert!(res["ok"][1].as_str().unwrap().contains("Workspace    : agent"), "{res}");
    // After the run, no socket is left on the host (this test's runs keep
    // theirs in a runtime directory of their own).
    let inside = stdout.lines().find_map(|l| l.strip_prefix("SOCKET ")).unwrap().to_string();
    assert_eq!(inside, "/run/veil/workspace.sock");
    let left = |t: &T| std::fs::read_dir(t.runtime()).unwrap().flatten().map(|e| e.path()).collect::<Vec<_>>();
    assert_eq!(left(&t), Vec::<PathBuf>::new(), "a socket outlived its run");
    // From the host, an unconfined run's socket answers only while it runs.
    let o = t.ok(&["--unconfined"], "echo $VEIL_WORKSPACE_SOCKET");
    let host_path = PathBuf::from(o.trim());
    assert!(host_path.starts_with(t.runtime()), "{o}");
    // A `vl` killed in the middle of a run leaves its socket's directory;
    // the next run removes it.
    let mut c = t.cmd(&["ws", "exec", "agent", "--", "sh", "-c", "touch started; sleep 60"]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    assert!(wait_for(std::time::Duration::from_secs(20), || t.cat("agent", "started").is_some() || t.proj.join(".veil/local/sandboxes/agent/files/started").exists()));
    unsafe {
        libc::kill(c.id() as i32, libc::SIGKILL);
    }
    let _ = c.wait();
    assert!(!left(&t).is_empty(), "the killed run's socket directory");
    t.ok(&[], "rm -f started");
    assert_eq!(left(&t), Vec::<PathBuf>::new(), "the next run did not sweep the killed run's socket");
    assert!(UnixStream::connect(&host_path).is_err(), "the socket outlived its run");
}

/// One run of operations in a mount (or checked out): every kind of edit.
const EDITS: &str = "echo new > n1.txt && mkdir -p deep/er && echo d > deep/er/f.txt && echo changed > a.txt && rm docs/x.md \
    && mv src/lib.rs src/moved.rs && chmod +x src/moved.rs && true";

#[test]
fn what_a_mounted_command_changes_is_exactly_what_is_recorded_and_the_same_without_fuse() {
    let mut results = Vec::new();
    for no_fuse in [false, true] {
        let t = T::new();
        let project = files(&t.proj);
        let mut c = t.cmd(&["ws", "exec", "agent", "--mount", "--", "bash", "-c", EDITS]);
        if no_fuse {
            c.env("VEIL_TEST_NO_FUSE", "1");
        }
        let o = c.output().unwrap();
        assert!(o.status.success(), "{}", text(&o));
        assert_eq!(text(&o).contains("no mount here"), no_fuse, "{}", text(&o));
        let changed = t.changed("agent@");
        assert_eq!(
            changed,
            ["added deep/er/f.txt", "added n1.txt", "deleted docs/x.md", "modified a.txt", "renamed src/moved.rs"].map(String::from).to_vec(),
            "no_fuse={no_fuse}"
        );
        assert_eq!(files(&t.proj), project, "no_fuse={no_fuse}: the project directory changed");
        let x = t.env.ok("alice", &t.proj, &["files", "-r", "agent@"]);
        results.push((changed, x));
    }
    assert_eq!(results[0], results[1], "a mount and a checkout record the same");
}

#[test]
fn mount_flags_that_cannot_go_together_are_refused() {
    let t = T::new();
    for flags in [&["--mount", "--ephemeral"][..], &["--mount", "--with-isolated"], &["--mount", "--only", "src"], &["--mount", "--record-only"]] {
        let mut a = vec!["ws", "exec", "agent"];
        a.extend_from_slice(flags);
        if !flags.contains(&"--record-only") {
            a.extend(["--", "true"]);
        }
        let o = t.cmd(&a).output().unwrap();
        assert!(!o.status.success() && text(&o).contains("cannot be used with"), "{flags:?}: {}", text(&o));
    }
}

/// BUG-1361: the reading commands take any revision, so the sandbox's `vl`
/// reads another workspace's recorded files (`other@`) and the project
/// directory's (`default@`), which confinement hides from the command.
#[test]
fn bug_1361_the_sandboxs_vl_cannot_read_another_workspace_or_the_project_directory() {
    let t = T::new();
    let o = t.cmd(&["ws", "exec", "other", "--", "bash", "-c", "echo OTHER-WORKSPACE-MARKER-4242c > w.txt"]).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    write(&t.proj, "p.txt", "PROJECT-DIR-MARKER-777d\n");
    t.env.ok("alice", &t.proj, &["status"]);
    let other = t.wc("other");
    let reads = [
        "show other@".to_string(),
        "diff -r other@".into(),
        "blame -r other@ w.txt".into(),
        "diff --from @ --to other@".into(),
        "show default@".into(),
        "diff -r default@".into(),
        format!("show {other}"),
    ];
    for flags in [&[][..], &["--mount"]] {
        let script: String = reads
            .iter()
            .map(|c| format!("out=$(vl {c} 2>&1); case \"$out\" in *'inside a sandbox'*) echo \"REFUSED: {c}\";; *) echo \"NOT REFUSED: {c}: $out\";; esac; "))
            .collect();
        let out = t.ok(flags, &script);
        assert_eq!(out.matches("REFUSED: ").count(), reads.len(), "{flags:?}: every read ran and answered: {out}");
        assert!(!out.contains("NOT REFUSED"), "{flags:?}: the sandbox's vl read outside its workspace: {out}");
        for m in ["OTHER-WORKSPACE-MARKER-4242c", "PROJECT-DIR-MARKER-777d"] {
            assert!(!out.contains(m), "{flags:?}: the sandbox read {m}: {out}");
        }
    }
}

/// BUG-1362: `vl commit` through the socket advances the tags at `@-`, so
/// the sandbox moves `main` to its own change (`vl tag set` is refused).
#[test]
fn bug_1362_a_commit_from_inside_the_sandbox_moves_no_tag() {
    for flags in [&[][..], &["--mount"]] {
        let t = T::new();
        let main = |t: &T| {
            let o = t.env.ok("alice", &t.proj, &["log", "-n", "1", "-r", "main", "--json"]);
            let v: serde_json::Value = serde_json::from_str(o.lines().find(|l| l.starts_with('{')).unwrap()).unwrap();
            v["entries"][0]["snapshot_id"].as_str().unwrap().to_string()
        };
        let before = main(&t);
        // The workspace is on `main` (`-r @-`): a plain commit there would move it.
        let out = t.ok(flags, "echo agent-edit >> a.txt && vl commit -m 'agent commit'");
        assert!(out.contains("Committed"), "{flags:?}: {out}");
        let log = t.env.ok("alice", &t.proj, &["log", "-n", "3", "-r", "::agent@"]);
        assert!(log.contains("agent commit"), "{flags:?}: {log}");
        assert_eq!(main(&t), before, "{flags:?}: the sandbox moved main: {log}");
    }
}

/// BUG-1361, the whole class: `vl log` too reads only the workspace's own
/// history. A plain `vl log` shows `@` and its ancestors (not the other
/// workspaces' changes it lists outside); `-r` naming anything else, or a
/// set reaching past `@` (`A..`), is refused; one inside it runs.
#[test]
fn the_sandboxs_vl_log_shows_only_its_own_history() {
    let t = T::new();
    let o = t.cmd(&["ws", "exec", "other", "-m", "OTHER-DESCRIPTION-91fe", "--", "bash", "-c", "echo x > w.txt"]).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let outside = t.env.ok("alice", &t.proj, &["log"]);
    assert!(outside.contains("OTHER-DESCRIPTION-91fe") && outside.contains("other@"), "{outside}");
    for flags in [&[][..], &["--mount"]] {
        let out = t.ok(flags, "vl log; echo END-PLAIN; vl log -r ::@-; echo END-RANGE");
        assert!(out.contains("END-PLAIN") && out.contains("END-RANGE") && out.contains("agent@"), "{flags:?}: {out}");
        assert!(!out.contains("OTHER-DESCRIPTION-91fe") && !out.contains("other@") && !out.contains("default@"), "{flags:?}: {out}");
        for r in ["::other@", "other@", "main..", "root().."] {
            let o = t.exec(flags, &format!("vl log -r '{r}'"));
            let all = text(&o);
            assert!(!o.status.success() && all.contains("inside a sandbox"), "{flags:?} log -r {r}: {all}");
            assert!(!all.contains("OTHER-DESCRIPTION-91fe"), "{all}");
        }
    }
}

/// A `vl ws exec --mount` killed in the middle leaves its mount serving;
/// the next run takes it over, says what it recorded of the killed run's
/// output (never "No changes"), and unmounts it.
#[test]
fn the_next_run_records_and_names_what_a_killed_mounted_run_left() {
    let t = T::new();
    let mut c = t
        .cmd(&["ws", "exec", "agent", "--mount", "--", "sh", "-c", "echo left-by-the-killed-run > killed.txt; touch started; sleep 60"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = || {
        std::fs::read_dir(t.runtime()).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with("veil-ws-mnt-") && e.path().join("files/started").exists())
    };
    assert!(wait_for(std::time::Duration::from_secs(20), started), "the run did not start");
    unsafe {
        libc::kill(c.id() as i32, libc::SIGKILL);
    }
    let _ = c.wait();
    let o = t.exec(&["--mount"], "true");
    let all = text(&o);
    assert!(o.status.success(), "{all}");
    assert!(all.contains("Recorded") && all.contains("did not finish"), "the next run says what it recorded: {all}");
    assert_eq!(t.cat("agent", "killed.txt").as_deref(), Some("left-by-the-killed-run\n"));
    let mounted = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(!mounted.contains(t.runtime().to_str().unwrap()), "the killed run's mount is still mounted");
}
