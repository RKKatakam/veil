//! The guarantees of a confined `vl ws exec` (Linux, bubblewrap;
//! `docs/design/scale/9-confinement.md`). Each test runs a small command in
//! a confined run and checks what it could see or change from outside.
//!
//! Every test uses a fake `HOME` with planted secrets, so nothing depends
//! on the real home of whoever runs the tests.

use crate::adversarial_support;

use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use adversarial_support::*;

const SSH_KEY: &str = "PLANTED-SSH-PRIVATE-KEY-5e1f0c9a";
const GPG_KEY: &str = "PLANTED-GPG-SECRET-KEY-77c2b1de";
const OTHER: &str = "ANOTHER-PROJECTS-SECRET-a90b33f1";
const CARGO_TOKEN: &str = "PLANTED-CRATES-IO-TOKEN-4d2e8b6c";
const ISOLATED: &str = "API_TOKEN=super-secret-isolated-value-0b7d";

struct T {
    env: Env,
    proj: PathBuf,
    home: PathBuf,
}

impl T {
    fn new() -> T {
        let env = Env::new();
        let proj = env.project("alice", "proj", &[("a.txt", "a\n"), ("src/lib.rs", "pub fn f() {}\n")]);
        write(&proj, ".netrc", &format!("{ISOLATED}\n"));
        env.ok("alice", &proj, &["commit", "-m", "env"]);
        env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
        let home = env.dir("fakehome");
        write(&home, ".ssh/id_test", SSH_KEY);
        write(&home, ".gnupg/private-keys-v1.d/k.key", GPG_KEY);
        write(&home, "src/other-project/secret.txt", OTHER);
        write(&home, ".cargo/bin/tool", "#!/bin/sh\necho tool-ran\n");
        std::fs::set_permissions(home.join(".cargo/bin/tool"), std::fs::Permissions::from_mode(0o755)).unwrap();
        write(&home, ".cargo/credentials.toml", CARGO_TOKEN);
        T { env, proj, home }
    }

    fn files(&self, ws: &str) -> PathBuf {
        self.proj.join(".veil/local/sandboxes").join(ws).join("files")
    }

    fn cmd(&self, cwd: &Path, args: &[&str]) -> Command {
        let mut c = self.env.cmd("alice", cwd, args);
        c.env("HOME", &self.home);
        c
    }

    /// `vl ws exec <args>` from `cwd`.
    fn exec_in(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut all = vec!["ws", "exec"];
        all.extend_from_slice(args);
        self.cmd(cwd, &all).stdin(Stdio::null()).output().unwrap()
    }

    fn exec(&self, args: &[&str]) -> Output {
        self.exec_in(&self.proj, args)
    }

    /// `vl ws exec agent -- sh -c script`, which must succeed: its output.
    fn sh(&self, script: &str) -> String {
        let o = self.exec(&["agent", "--", "sh", "-c", script]);
        assert!(o.status.success(), "{}", text(&o));
        text(&o)
    }

    /// Like [`T::sh`], but only what the command printed (`vl` echoes the
    /// command line, markers included, on stderr).
    fn sh_out(&self, script: &str) -> String {
        let o = self.exec(&["agent", "--", "sh", "-c", script]);
        assert!(o.status.success(), "{}", text(&o));
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    fn cat(&self, path: &str) -> Option<String> {
        let o = self.env.vl("alice", &self.proj, &["ws", "cat", "agent", path]);
        o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
    }
}

/// Every file, directory and link under `dir`, with its content and mode.
fn snapshot(dir: &Path, skip: &[&str]) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            let rel = p.strip_prefix(dir).unwrap().to_path_buf();
            if skip.iter().any(|s| rel.starts_with(s)) {
                continue;
            }
            let m = std::fs::symlink_metadata(&p).unwrap();
            let v = if m.file_type().is_symlink() {
                format!("link {:?}", std::fs::read_link(&p).unwrap())
            } else if m.is_dir() {
                stack.push(p.clone());
                format!("dir {:o}", m.permissions().mode())
            } else {
                format!("file {:o} {}", m.permissions().mode(), blake3::hash(&std::fs::read(&p).unwrap()).to_hex())
            };
            out.insert(rel, v);
        }
    }
    out
}

/// Whether a process runs `sleep <secs>` (the vl and bwrap command lines
/// that name it do not count).
fn sleeping(secs: &str) -> bool {
    processes().lines().any(|l| l.trim_end() == format!("sleep {secs}"))
}

/// The command lines of every process this machine shows us.
fn processes() -> String {
    let mut all = String::new();
    for e in std::fs::read_dir("/proc").unwrap().flatten() {
        if let Ok(c) = std::fs::read(e.path().join("cmdline")) {
            all.push_str(&String::from_utf8_lossy(&c).replace('\0', " "));
            all.push('\n');
        }
    }
    all
}

fn systemd_scopes_work() -> bool {
    Command::new("systemd-run")
        .args(["--user", "--scope", "--quiet", "--collect", "--", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn the_sandbox_appears_at_the_projects_path_in_the_same_sub_folder() {
    let t = T::new();
    let o = t.exec_in(&t.proj.join("src"), &["agent", "--", "sh", "-c", "pwd; echo \"PWD=$PWD\"; cat lib.rs; echo edited > lib.rs"]);
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    let src = t.proj.join("src");
    assert!(out.contains(&format!("{}\nPWD={}\n", src.display(), src.display())), "{out}");
    assert!(out.contains("pub fn f() {}"), "{out}");
    // Every write went to the sandbox, and was recorded; the project is as it was.
    assert_eq!(t.cat("src/lib.rs").as_deref(), Some("edited\n"));
    assert_eq!(std::fs::read_to_string(src.join("lib.rs")).unwrap(), "pub fn f() {}\n");
    assert_eq!(std::fs::read_to_string(t.files("agent").join("src/lib.rs")).unwrap(), "edited\n");
    // Absolute paths into the project are the sandbox's files too.
    let out = t.sh(&format!("cat {}", t.proj.join("src/lib.rs").display()));
    assert!(out.contains("edited"), "{out}");
}

#[test]
fn planted_keys_in_home_and_other_projects_are_not_visible() {
    let t = T::new();
    let h = t.home.display();
    let script = format!(
        "echo \"HOME=$HOME\"; ls -A ~; cat {h}/.ssh/id_test; cat ~/.gnupg/private-keys-v1.d/k.key; cat {h}/src/other-project/secret.txt; \
         ls {h}/.ssh; find \"$HOME\" /tmp /var/tmp /run /home -name id_test 2>/dev/null; cat /tmp/*/fakehome/.ssh/id_test 2>&1; echo end"
    );
    let o = t.exec(&["agent", "--", "sh", "-c", &script]);
    assert!(o.status.success(), "{}", text(&o));
    let out = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr).lines().filter(|l| !l.starts_with("running ")).collect::<Vec<_>>().join("\n"));
    assert!(out.contains(&format!("HOME={h}\n")), "{out}");
    for planted in [SSH_KEY, GPG_KEY, OTHER] {
        assert!(!out.contains(planted), "{planted} was visible:\n{out}");
    }
    assert!(out.contains("No such file or directory"), "{out}");
    assert!(String::from_utf8_lossy(&o.stdout).trim_end().ends_with("end"), "{out}");
}

#[test]
fn the_veil_identity_keys_and_the_real_repository_are_not_visible() {
    let t = T::new();
    let veil_home = t.env.root.join("home-alice");
    let identity = std::fs::read_to_string(veil_home.join("identity.json")).unwrap();
    assert!(identity.len() > 40);
    let script = format!(
        "ls -A {vh}; cat {vh}/identity.json; ls -A {p}/.veil; cat {p}/.veil/local/sandboxes/agent/manifest.json; echo end",
        vh = veil_home.display(),
        p = t.proj.display()
    );
    // Also when an allowed folder holds the Veil home.
    for allow in [None, Some(t.env.root.display().to_string())] {
        let mut args = vec!["agent"];
        if let Some(a) = &allow {
            args.extend(["--allow", a.as_str()]);
        }
        args.extend(["--", "sh", "-c", &script]);
        let o = t.exec(&args);
        assert!(o.status.success(), "{}", text(&o));
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        assert!(!out.contains(identity.trim()) && !out.contains("\"secret\"") && !out.contains("identity.json\n"), "{allow:?}: {out}");
        assert!(!out.contains("\"pending\""), "{allow:?}: the real .veil is visible: {out}");
    }
}

#[test]
fn credentials_inside_allowed_toolchains_stay_hidden() {
    let t = T::new();
    let out = t.sh_out("~/.cargo/bin/tool; cat ~/.cargo/credentials.toml; echo end");
    assert!(out.contains("tool-ran"), "the default allow-list does not show ~/.cargo: {out}");
    assert!(!out.contains(CARGO_TOKEN), "{out}");
}

#[test]
fn writes_through_dot_dot_absolute_paths_and_links_leave_everything_outside_unchanged() {
    let t = T::new();
    let canary = t.env.dir("canary");
    write(&canary, "existing", "canary\n");
    write(&canary, "sub/deep", "deep\n");
    let c = canary.display().to_string();
    let p = t.proj.display().to_string();
    let h = t.home.display().to_string();
    // From the project root up to `/`.
    let up = "../".repeat(t.proj.components().count());
    let rel = format!("{up}{}", c.trim_start_matches('/'));
    let script = [
        format!("echo x > {rel}/new"),
        format!("echo x > {rel}/existing"),
        "echo x > ../canary/existing".to_string(),
        format!("echo x > {c}/new"),
        format!("echo x >> {c}/existing"),
        format!("rm -rf {c}/sub"),
        format!("mkdir {c}/made"),
        format!("chmod 777 {c}/existing"),
        format!("ln -s {c}/existing abs_link; echo x > abs_link"),
        format!("ln -s {rel}/existing rel_link; echo x > rel_link"),
        format!("ln -s {c} dir_link; echo x > dir_link/new; rm -f dir_link/existing"),
        format!("echo x > /proc/self/root{c}/existing"),
        format!("echo x > /proc/1/root{c}/existing"),
        format!("echo x > /proc/self/cwd/{rel}/existing"),
        format!("ls /proc/*/root{c} 2>&1 | head -2"),
        format!("echo x > {h}/.ssh/id_test; rm -f {h}/.ssh/id_test"),
        format!("echo x > {h}/.cargo/bin/tool; touch {h}/.cargo/new"),
        "echo x > /usr/veil-confine-test; echo x > /etc/veil-confine-test".to_string(),
        format!("echo inside > {p}/a.txt"),
    ]
    .iter()
    .map(|s| format!("( {s} ) 2>/dev/null;"))
    .collect::<Vec<_>>()
    .join(" ");
    let before = (snapshot(&canary, &[]), snapshot(&t.proj, &[".veil"]), snapshot(&t.home, &[]));
    let out = t.sh(&script);
    let after = (snapshot(&canary, &[]), snapshot(&t.proj, &[".veil"]), snapshot(&t.home, &[]));
    assert_eq!(before.0, after.0, "the canary changed: {out}");
    assert_eq!(before.1, after.1, "the real project changed: {out}");
    assert_eq!(before.2, after.2, "the home changed: {out}");
    assert!(!Path::new("/usr/veil-confine-test").exists() && !Path::new("/etc/veil-confine-test").exists());
    // The writes did run: the one into the project landed in the sandbox.
    assert_eq!(t.cat("a.txt").as_deref(), Some("inside\n"), "{out}");
}

#[test]
fn concurrent_workspaces_and_the_users_other_processes_are_invisible() {
    let t = T::new();
    t.env.ok("alice", &t.proj, &["ws", "new", "other", "-r", "@-"]);
    // The user's own process, outside any sandbox.
    let mut outside = Command::new("sleep").arg("31.4159").spawn().unwrap();
    let started = t.files("agent").join(".started");
    let a = t
        .cmd(&t.proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo WORKSPACE-A-PRIVATE-7c19 > mine.txt; touch .started; sleep 2.718"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    let _ = std::fs::remove_file(&started);
    let script = format!(
        "cat {a}/mine.txt; cat mine.txt; ls {p}/.veil; for f in /proc/[0-9]*/cmdline; do tr '\\0' ' ' < $f; echo; done; kill -0 {pid} && echo \"sig\"\"nalled\"; echo end",
        a = t.files("agent").display(),
        p = t.proj.display(),
        pid = outside.id()
    );
    let o = t.exec(&["other", "--", "sh", "-c", &script]);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let a = a.wait_with_output().unwrap();
    assert!(o.status.success() && a.status.success(), "{}\n{}", text(&o), text(&a));
    assert!(out.trim_end().ends_with("end"), "{out}");
    assert!(!out.contains("WORKSPACE-A-PRIVATE-7c19"), "{out}");
    assert!(!out.contains("31.4159") && !out.contains("2.718"), "processes outside the sandbox are visible: {out}");
    assert!(!out.lines().any(|l| l == "signalled"), "{out}");
    assert!(outside.try_wait().unwrap().is_none(), "the outside process was killed");
    let _ = outside.kill();
    let _ = outside.wait();
}

#[test]
fn no_network_blocks_connecting_to_a_local_listener() {
    if !Path::new("/bin/bash").exists() && !Path::new("/usr/bin/bash").exists() {
        return;
    }
    let t = T::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let probe = format!("if exec 3<>/dev/tcp/127.0.0.1/{port}; then echo CONNECTED; else echo REFUSED; fi");
    let stdout = |o: Output| String::from_utf8_lossy(&o.stdout).into_owned() + &text(&o);
    let on = stdout(t.exec(&["agent", "--", "bash", "-c", &probe]));
    assert!(on.starts_with("CONNECTED\n"), "the network is on by default: {on}");
    let off = stdout(t.exec(&["agent", "--no-network", "--", "bash", "-c", &probe]));
    assert!(off.starts_with("REFUSED\n"), "{off}");
}

#[test]
fn agent_sockets_namespaces_and_privileges_are_closed() {
    let t = T::new();
    let sock = t.home.join(".ssh/agent.sock");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let mut c = t.cmd(
        &t.proj,
        &["ws", "exec", "agent", "--", "sh", "-c", "test -S \"$SSH_AUTH_SOCK\" && echo SOCKET-VISIBLE; unshare -U true 2>/dev/null && echo NESTED-USERNS; grep -E '^(NoNewPrivs|CapEff)' /proc/self/status"],
    );
    c.env("SSH_AUTH_SOCK", &sock);
    let o = c.output().unwrap();
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(!stdout.contains("SOCKET-VISIBLE") && !stdout.contains("NESTED-USERNS"), "{out}");
    let flat: String = stdout.split_whitespace().collect();
    assert!(flat.contains("NoNewPrivs:1") && flat.contains("CapEff:0000000000000000"), "{out}");
}

#[test]
fn the_allow_list_is_never_written_and_only_device_local() {
    let t = T::new();
    let tools = t.env.dir("tools");
    write(&tools, "lib.txt", "TOOLS-VISIBLE-91ac\n");
    let conf = t.env.dir("conf-tools");
    write(&conf, "c.txt", "CONFIG-ALLOWED-3e2f\n");
    write(&t.env.root.join("home-alice"), "config.toml", &format!("[exec.confine]\nallow = [\"{}\"]\n", conf.display()));
    // A tracked file cannot widen the allow-list.
    let tracked = t.env.dir("tracked-only");
    write(&tracked, "t.txt", "TRACKED-ALLOW-6b0d\n");
    write(&t.proj, "config.toml", &format!("[exec.confine]\nallow = [\"{}\"]\n", tracked.display()));
    t.env.ok("alice", &t.proj, &["commit", "-m", "tracked config"]);
    t.env.ok("alice", &t.proj, &["ws", "new", "w2", "-r", "@-"]);
    let before = (snapshot(&tools, &[]), snapshot(&conf, &[]), snapshot(&t.home.join(".cargo"), &[]));
    let script = format!(
        "cat {tl}/lib.txt {cf}/c.txt {tr}/t.txt; echo x > {tl}/lib.txt; rm -f {tl}/lib.txt; touch {tl}/new; mkdir {cf}/d; \
         echo x > ~/.cargo/bin/tool; touch ~/.cargo/new; echo end",
        tl = tools.display(),
        cf = conf.display(),
        tr = tracked.display()
    );
    let o = t.exec(&["w2", "--allow", &tools.display().to_string(), "--", "sh", "-c", &script]);
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    assert!(out.contains("TOOLS-VISIBLE-91ac") && out.contains("CONFIG-ALLOWED-3e2f"), "{out}");
    assert!(!out.contains("TRACKED-ALLOW-6b0d"), "a tracked file widened the allow-list: {out}");
    // The writes went to the workspace's layers (BUG-1025), never to the folders.
    let after = (snapshot(&tools, &[]), snapshot(&conf, &[]), snapshot(&t.home.join(".cargo"), &[]));
    assert_eq!(before, after, "an allowed folder changed: {out}");
    let o = t.exec(&["w2", "--allow", &tools.display().to_string(), "--", "sh", "-c", &format!("ls {}; cat ~/.cargo/bin/tool", tools.display())]);
    assert_eq!(String::from_utf8_lossy(&o.stdout), "new\nx\n", "{}", text(&o));
}

#[test]
fn injected_secrets_are_still_removed_and_quarantine_still_works() {
    let t = T::new();
    let out = t.sh("true");
    assert!(!out.contains("isolated-value"), "{out}");
    let o = t.exec(&["agent", "--with-isolated", "--", "sh", "-c", "cat .netrc; cp .netrc copy.txt; echo 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' > creds.txt"]);
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    assert!(out.contains(ISOLATED), "the injected file is visible inside: {out}");
    assert!(!t.files("agent").join(".netrc").exists(), "the injected file was left in the sandbox");
    for p in ["copy.txt", ".netrc", "creds.txt"] {
        assert!(t.cat(p).is_none_or(|c| !c.contains("isolated-value") && !c.contains("EXAMPLEKEY")), "{p} recorded a secret");
    }
    assert!(t.files("agent").join("creds.txt").exists(), "quarantined work stays in the sandbox");
}

/// A CPU loop, a memory hog, a process storm and a hung command are each
/// stopped, under every limit mechanism here, and `vl` records afterwards.
#[test]
fn limits_stop_runaways_and_vl_still_records() {
    let t = T::new();
    let mut backends = vec!["poll"];
    if systemd_scopes_work() {
        backends.push("systemd");
    }
    for backend in backends {
        let run = |flags: &[&str], body: &str, file: &str| -> (String, Duration) {
            let script = format!("echo {backend} > {file}; {body}");
            let mut args = vec!["ws", "exec", "agent"];
            args.extend_from_slice(flags);
            args.extend(["--", "sh", "-c", &script]);
            let start = Instant::now();
            let o = t.cmd(&t.proj, &args).env("VEIL_EXEC_LIMITS_BACKEND", backend).output().unwrap();
            let out = text(&o);
            assert!(out.contains("Recorded") || out.contains("No changes"), "{backend}: not recorded: {out}");
            assert_eq!(t.cat(file).as_deref(), Some(format!("{backend}\n").as_str()), "{backend}: {out}");
            (out, start.elapsed())
        };
        let (out, took) = run(&["--cpu-time", "1s"], "while :; do :; done", "cpu.txt");
        assert!(out.contains("stopped: CPU-time limit (1s) reached"), "{backend}: {out}");
        assert!(took < Duration::from_secs(20), "{backend}: {took:?}");
        let (out, _) = run(&["--memory", "64M"], "head -c 4G /dev/zero | tail -n 1 > /dev/null", "mem.txt");
        assert!(out.contains("stopped: memory limit (64 MiB) reached"), "{backend}: {out}");
        let (out, _) = run(&["--timeout", "1s"], "sleep 60", "time.txt");
        assert!(out.contains("stopped: time limit (1s) reached"), "{backend}: {out}");
        let (out, _) = run(
            &["--pids", "32", "--timeout", "8s"],
            // Counted with built-ins as it goes: `sh` gives up at a refused fork.
            "rm -f count.txt; i=0; while [ $i -lt 400 ]; do sleep 4 & i=$((i+1)); echo $i > count.txt; done 2>/dev/null; wait",
            "pids.txt",
        );
        match backend {
            // Forks beyond the limit fail.
            "systemd" => {
                let n: u64 = t.cat("count.txt").unwrap_or_default().trim().parse().unwrap_or(999);
                assert!((1..=32).contains(&n), "{backend}: {n} processes ran under --pids 32: {out}");
                assert!(out.contains("process limit (32)"), "{backend}: {out}");
            }
            // The storm is stopped when seen.
            _ => assert!(out.contains("stopped: process limit (32) reached"), "{backend}: {out}"),
        }
    }
}

#[test]
fn a_memory_kill_still_takes_injected_secrets_out() {
    let t = T::new();
    t.sh("true");
    let o = t.exec(&["agent", "--with-isolated", "--memory", "64M", "--", "sh", "-c", "cp .netrc leaked.txt; head -c 4G /dev/zero | tail -n 1 > /dev/null"]);
    let out = text(&o);
    assert!(!o.status.success() && out.contains("memory limit"), "{out}");
    assert!(!t.files("agent").join(".netrc").exists(), "the injected file was left: {out}");
    assert!(t.cat("leaked.txt").is_none_or(|c| !c.contains("isolated-value")), "{out}");
    assert!(out.contains("Recorded") || out.contains("No changes"), "{out}");
}

#[test]
fn nothing_is_left_after_vl_is_killed() {
    let t = T::new();
    t.sh("true");
    let started = t.files("agent").join(".started");
    // A limit, so that a systemd scope exists where there is one.
    let mut child = t
        .cmd(&t.proj, &["ws", "exec", "agent", "--with-isolated", "--memory", "1G", "--", "sh", "-c", "touch .started; sleep 31.71 & sleep 31.72"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let vl_pid = child.id();
    assert!(wait_for(Duration::from_secs(20), || started.exists()));
    let _ = std::fs::remove_file(&started);
    assert!(wait_for(Duration::from_secs(10), || sleeping("31.71") && sleeping("31.72")), "the command never ran");
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(wait_for(Duration::from_secs(10), || !sleeping("31.71") && !sleeping("31.72")), "the command's processes outlived vl");
    assert!(wait_for(Duration::from_secs(10), || !t.files("agent").join(".netrc").exists()), "the injected file was left");
    if systemd_scopes_work() {
        let units = Command::new("systemctl").args(["--user", "list-units", "--all", "--no-legend", "veil-exec-*"]).output().unwrap();
        let units = String::from_utf8_lossy(&units.stdout).into_owned();
        assert!(wait_for(Duration::from_secs(10), || {
            let u = Command::new("systemctl").args(["--user", "list-units", "--all", "--no-legend", "veil-exec-*"]).output().unwrap();
            !String::from_utf8_lossy(&u.stdout).contains(&format!("veil-exec-{vl_pid}-"))
        }), "a scope was left: {units}");
    }
    // The next run records what the killed one left and works.
    let out = t.sh("cat a.txt");
    assert!(out.contains("Recording the output of an earlier run"), "{out}");
    // An ephemeral run's directory goes too.
    let tmp = t.env.root.join("tmp");
    let mut child = t
        .cmd(&t.proj, &["ws", "exec", "--ephemeral", "--with-isolated", "--", "sh", "-c", "sleep 31.73"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(wait_for(Duration::from_secs(20), || sleeping("31.73")));
    child.kill().unwrap();
    child.wait().unwrap();
    let left = || std::fs::read_dir(&tmp).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with("veil-ws-"));
    assert!(wait_for(Duration::from_secs(10), || !left() && !sleeping("31.73")), "the ephemeral sandbox was left");
}

#[test]
fn signals_reach_the_confined_command() {
    let t = T::new();
    t.sh("true");
    for (sig, code) in [(libc::SIGTERM, 3), (libc::SIGHUP, 5), (libc::SIGINT, 4)] {
        let started = t.files("agent").join(".started");
        let script = format!("trap 'echo got > sig.txt; exit {code}' {}; touch .started; sleep 30 & wait", match sig {
            libc::SIGTERM => "TERM",
            libc::SIGHUP => "HUP",
            _ => "INT",
        });
        let child = {
            use std::os::unix::process::CommandExt;
            t.cmd(&t.proj, &["ws", "exec", "agent", "--", "sh", "-c", &script])
                .process_group(0)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };
        assert!(wait_for(Duration::from_secs(20), || started.exists()));
        let _ = std::fs::remove_file(&started);
        // SAFETY: signals our own child (Ctrl-C: its whole process group).
        unsafe {
            if sig == libc::SIGINT {
                libc::kill(-(child.id() as i32), sig);
            } else {
                libc::kill(child.id() as i32, sig);
            }
        }
        let o = child.wait_with_output().unwrap();
        assert_eq!(o.status.code(), Some(code), "{sig}: {}", text(&o));
        assert_eq!(t.cat("sig.txt").as_deref(), Some("got\n"), "{sig}: {}", text(&o));
        t.sh("rm -f sig.txt");
    }
}

#[test]
fn a_missing_or_broken_bwrap_fails_before_anything_is_touched() {
    let t = T::new();
    t.sh("true");
    let manifest = t.proj.join(".veil/local/sandboxes/agent/manifest.json");
    let before = std::fs::read(&manifest).unwrap();
    let empty = t.env.dir("empty-path");
    let o = t.cmd(&t.proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo ran > ran.txt"]).env("PATH", &empty).output().unwrap();
    let out = text(&o);
    assert!(!o.status.success() && out.contains("install bubblewrap") && out.contains("--unconfined"), "{out}");
    let broken = t.env.dir("broken-path");
    write(&broken, "bwrap", "#!/bin/sh\necho 'bwrap: setting up uid map: Permission denied' >&2\nexit 1\n");
    std::fs::set_permissions(broken.join("bwrap"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", broken.display(), std::env::var("PATH").unwrap_or_default());
    let o = t.cmd(&t.proj, &["ws", "exec", "agent", "--", "sh", "-c", "echo ran > ran.txt"]).env("PATH", &path).output().unwrap();
    let out = text(&o);
    assert!(!o.status.success() && out.contains("confinement does not work") && out.contains("uid map") && out.contains("--unconfined"), "{out}");
    assert_eq!(std::fs::read(&manifest).unwrap(), before, "the sandbox was touched");
    assert!(!t.files("agent").join("ran.txt").exists() && t.cat("ran.txt").is_none());
    // A `bwrap` inside the project (a `PATH` entry such as `bin/`) is never
    // run: the confinement is the real one.
    let inner = t.proj.join("bin");
    write(&inner, "bwrap", "#!/bin/sh\nshift $#\nexec sh -c 'cat \"$HOME/.ssh/id_test\"'\n");
    std::fs::set_permissions(inner.join("bwrap"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path_in = format!("{}:{}", inner.display(), std::env::var("PATH").unwrap_or_default());
    let o = t.cmd(&t.proj, &["ws", "exec", "agent", "--", "sh", "-c", "cat $HOME/.ssh/id_test; echo end"]).env("PATH", &path_in).output().unwrap();
    assert!(o.status.success() && !String::from_utf8_lossy(&o.stdout).contains(SSH_KEY), "{}", text(&o));
    // The explicit opt-out runs, and says what it gives up.
    let o = t.cmd(&t.proj, &["ws", "exec", "agent", "--unconfined", "--", "sh", "-c", "cat $HOME/.ssh/id_test > /dev/null && echo ran > ran.txt"]).env("PATH", &path).output().unwrap();
    let out = text(&o);
    assert!(o.status.success() && out.contains("running unconfined"), "{out}");
    assert_eq!(t.cat("ran.txt").as_deref(), Some("ran\n"));
}

#[test]
fn hostile_flags_home_and_configuration_are_refused_or_contained() {
    let t = T::new();
    t.sh("true");
    let run = |args: &[&str], envs: &[(&str, &str)]| {
        let mut all = vec!["ws", "exec", "agent"];
        all.extend_from_slice(args);
        let mut c = t.cmd(&t.proj, &all);
        for (k, v) in envs {
            c.env(k, v);
        }
        c.output().unwrap()
    };
    for (args, want) in [
        (vec!["--allow", "/", "--", "true"], "the whole machine"),
        (vec!["--allow", "/etc/..", "--", "true"], "the whole machine"),
        (vec!["--allow", "/no/such/dir/9c1e", "--", "true"], "No such file"),
        (vec!["--allow", "/no/such/../dir", "--", "true"], "no such file"),
        (vec!["--memory", "99999999999999999999G", "--", "true"], "not a valid value"),
        (vec!["--memory", "lots", "--", "true"], "not a valid value"),
        (vec!["--timeout", "0s", "--", "true"], "not a valid value"),
        (vec!["--pids=-1", "--", "true"], "not a valid value"),
        (vec!["--unconfined", "--memory", "1G", "--", "true"], "cannot be used with"),
    ] {
        let o = run(&args, &[]);
        assert!(!o.status.success() && text(&o).contains(want), "{args:?}: {}", text(&o));
    }
    // A relative --allow is from the current directory; odd names are fine.
    let odd = t.env.root.join("--odd name\nx");
    std::fs::create_dir_all(&odd).unwrap();
    write(&odd, "f", "ODD-ALLOWED-c4e1\n");
    let o = run(&["--allow=../--odd name\nx", "--", "sh", "-c", "cat */f; cat \"$0\"/f", &odd.display().to_string()], &[]);
    assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).contains("ODD-ALLOWED-c4e1"), "{}", text(&o));
    // A HOME that is unset, relative or `/` still gets a private, empty one.
    for home in ["", "relative/home", "/"] {
        let o = run(&["--", "sh", "-c", "echo \"HOME=$HOME\"; ls -A \"$HOME\" | wc -l"], &[("HOME", home)]);
        let out = text(&o);
        assert!(o.status.success() && out.contains("HOME=/tmp/home\n0\n"), "HOME={home:?}: {out}");
    }
    // Configuration that cannot be read is an error, never a silently dropped limit.
    let cfg = t.proj.join(".veil/local/config.toml");
    for bad in ["[exec.limits]\nmemory = \"lots\"\n", "[exec.limits]\nmemroy = \"1G\"\n", "[exec.confine]\nallow = \"/usr\"\n", "[exec\n"] {
        std::fs::write(&cfg, bad).unwrap();
        let o = run(&["--", "true"], &[]);
        assert!(!o.status.success(), "{bad:?}: {}", text(&o));
    }
    std::fs::write(&cfg, vec![b'#'; (1 << 20) + 1]).unwrap();
    assert!(!run(&["--", "true"], &[]).status.success());
    // Limits from the configuration apply.
    std::fs::write(&cfg, "[exec.limits]\ntimeout = \"1s\"\n").unwrap();
    let o = run(&["--", "sleep", "30"], &[]);
    assert!(text(&o).contains("stopped: time limit (1s)"), "{}", text(&o));
    std::fs::remove_file(&cfg).unwrap();
}

#[test]
fn doctor_says_whether_confinement_works() {
    let t = T::new();
    let out = text(&t.cmd(&t.proj, &["doctor"]).output().unwrap());
    assert!(out.contains("confinement works (bubblewrap"), "{out}");
    assert!(out.contains("resource limits:"), "{out}");
    let empty = t.env.dir("empty-path");
    let out = text(&t.cmd(&t.proj, &["doctor"]).env("PATH", &empty).output().unwrap());
    assert!(out.contains("bubblewrap is not installed"), "{out}");
}

// ---- Confinement verification review --------------------------------------

/// `vl ws exec <args>` from the project, killed if it outlives `secs`:
/// `None` when it hung.
fn exec_deadline(t: &T, args: &[&str], envs: &[(&str, &std::ffi::OsStr)], secs: u64) -> Option<Output> {
    let mut all = vec!["ws", "exec"];
    all.extend_from_slice(args);
    let mut c = t.cmd(&t.proj, &all);
    for (k, v) in envs {
        c.env(k, v);
    }
    let mut child = c.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if child.try_wait().unwrap().is_some() {
            return Some(child.wait_with_output().unwrap());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[test]
fn an_allowed_link_to_a_folder_holding_keys_or_the_project_still_hides_them() {
    let t = T::new();
    let identity = std::fs::read_to_string(t.env.root.join("home-alice/identity.json")).unwrap();
    // A link to the folder that holds the Veil home and the project (as a
    // `~/src` link to a data disk would), and a link to `~/.cargo`.
    let alias = t.env.root.join("alias");
    std::os::unix::fs::symlink(&t.env.root, &alias).unwrap();
    std::os::unix::fs::symlink(t.home.join(".cargo"), t.home.join("cargo-link")).unwrap();
    // A `CARGO_HOME` outside the home, allowed.
    let cargo_home = t.env.dir("cargo-home");
    write(&cargo_home, "credentials", CARGO_TOKEN);
    let a = alias.display();
    let script = format!(
        "cat {a}/home-alice/identity.json; ls -A {a}/proj/.veil; cat {a}/proj/.veil/local/sandboxes/agent/manifest.json; \
         cat ~/cargo-link/credentials.toml {ch}/credentials; ls -A {a}/proj; echo end",
        ch = cargo_home.display()
    );
    let cargo_link = t.home.join("cargo-link").display().to_string();
    let o = t
        .cmd(&t.proj, &["ws", "exec", "agent", "--allow", &a.to_string(), "--allow", &cargo_link, "--allow", &cargo_home.display().to_string(), "--", "sh", "-c", &script])
        .env("CARGO_HOME", &cargo_home)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(out.trim_end().ends_with("end"), "{out}");
    assert!(!out.contains(identity.trim()), "the Veil identity is visible through an allowed link: {out}");
    assert!(!out.contains("\"pending\"") && !out.contains("sandboxes"), "the real .veil is visible through an allowed link: {out}");
    assert!(!out.contains(CARGO_TOKEN), "cargo's credentials are visible through an allowed link: {out}");
    assert!(!out.contains("a.txt"), "the real project is visible through an allowed link: {out}");
    // An allowed path inside the Veil home or the project is refused.
    for inside in [t.env.root.join("home-alice"), alias.join("proj/.veil"), t.proj.clone()] {
        let o = t.exec(&["agent", "--allow", &inside.display().to_string(), "--", "true"]);
        assert!(!o.status.success() && text(&o).contains("that is inside the"), "{inside:?}: {}", text(&o));
    }
}

#[test]
fn doctor_never_runs_a_bwrap_from_inside_the_project() {
    let t = T::new();
    let marker = t.env.root.join("doctor-ran-project-bwrap");
    let bin = t.proj.join("bin");
    for prog in ["bwrap", "systemd-run", "systemctl"] {
        write(&bin, prog, &format!("#!/bin/sh\ntouch {}\n", marker.display()));
        std::fs::set_permissions(bin.join(prog), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
    let out = text(&t.cmd(&t.proj.join("src"), &["doctor"]).env("PATH", &path).output().unwrap());
    assert!(!marker.exists(), "vl doctor ran the project's own program: {out}");
    assert!(out.contains("confinement works (bubblewrap"), "{out}");
}

#[test]
fn links_fifos_and_sockets_the_command_plants_never_make_vl_write_or_read_outside() {
    let t = T::new();
    write(&t.proj, "config/.env", "DB_PASSWORD=isolated-config-value-55e1\n");
    t.env.ok("alice", &t.proj, &["commit", "-m", "config"]);
    t.env.ok("alice", &t.proj, &["ws", "rm", "agent"]);
    t.env.ok("alice", &t.proj, &["ws", "new", "agent", "-r", "@-"]);
    let canary = t.env.dir("canary");
    write(&canary, "existing", "canary\n");
    write(&canary, ".env", "canary-env\n");
    write(&canary, ".netrc", "canary-netrc\n");
    let c = canary.display().to_string();
    let before = snapshot(&canary, &[]);
    // Run 1 swaps the injected files and their folder for links outside,
    // and leaves a FIFO and a socket.
    let script = format!(
        "rm -rf config src; ln -s {c} config; ln -s {c} src; rm -f .netrc; ln -s {c}/.netrc .netrc; mkfifo pipe; \
         ln -s {c}/existing a.txt.link; python3 -c 'import socket; socket.socket(socket.AF_UNIX).bind(\"sock\")' 2>/dev/null; echo end"
    );
    let o = exec_deadline(&t, &["agent", "--with-isolated", "--", "sh", "-c", &script], &[], 60).expect("vl hung after the run");
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(before, snapshot(&canary, &[]), "run 1 changed the canary: {}", text(&o));
    // Run 2 injects again, into the linked folder; a sparse run leaves
    // links outside its set, which `vl` removes.
    let o = exec_deadline(&t, &["agent", "--with-isolated", "--", "sh", "-c", "ls -la; cat config/.env; echo end"], &[], 60)
        .expect("vl hung on the next run");
    assert_eq!(before, snapshot(&canary, &[]), "the next run changed the canary: {}", text(&o));
    let script = format!("ln -s {c} stray; mkdir -p deep; ln -s {c}/existing deep/x; ln -s {c} deep/d; echo end");
    let o = exec_deadline(&t, &["agent", "--only", "a.txt", "--", "sh", "-c", &script], &[], 60).expect("vl hung on a sparse run");
    let o2 = exec_deadline(&t, &["agent", "--with-isolated", "--", "true"], &[], 60).expect("vl hung on a full run");
    assert_eq!(before, snapshot(&canary, &[]), "a sparse run changed the canary: {}\n{}", text(&o), text(&o2));
    let all = all_text(&canary);
    assert!(!all.contains("isolated"), "{all}");
}

fn all_text(dir: &Path) -> String {
    let mut s = String::new();
    for (p, _) in snapshot(dir, &[]) {
        if let Ok(c) = std::fs::read_to_string(dir.join(&p)) {
            s.push_str(&c);
        }
    }
    s
}

#[test]
fn the_command_inherits_no_descriptor_of_vl_but_its_stdio() {
    let t = T::new();
    // `ls` lists the shell's descriptors: what the same shell has outside.
    let script = "ls /proc/$$/fd > fds.txt; true";
    let base = t.env.dir("fd-baseline");
    let o = Command::new("sh").args(["-c", script]).current_dir(&base).stdin(Stdio::null()).output().unwrap();
    assert!(o.status.success());
    let want = std::fs::read_to_string(base.join("fds.txt")).unwrap();
    assert!(want.split_whitespace().count() <= 4, "{want}");
    for flags in [&[][..], &["--with-isolated", "--memory", "1G"][..]] {
        let mut args = vec!["agent"];
        args.extend_from_slice(flags);
        args.extend(["--", "sh", "-c", script]);
        let o = t.exec(&args);
        assert!(o.status.success(), "{}", text(&o));
        assert_eq!(t.cat("fds.txt").unwrap(), want, "{flags:?}: {}", text(&o));
    }
}

#[test]
fn a_slow_systemd_user_manager_does_not_hang_vl() {
    let t = T::new();
    t.sh("true");
    let slow = t.env.dir("slow-systemd");
    for prog in ["systemd-run", "systemctl"] {
        write(&slow, prog, "#!/bin/sh\nexec sleep 600\n");
        std::fs::set_permissions(slow.join(prog), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:{}", slow.display(), std::env::var("PATH").unwrap_or_default());
    let start = Instant::now();
    let o = exec_deadline(&t, &["agent", "--memory", "1G", "--", "sh", "-c", "echo ran > slow.txt"], &[("PATH", path.as_ref())], 60);
    let o = o.unwrap_or_else(|| panic!("vl hung on a slow systemd user manager ({:?})", start.elapsed()));
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(t.cat("slow.txt").as_deref(), Some("ran\n"), "{}", text(&o));
}

/// With a limit, the command goes through `systemd-run`, which must pass
/// it on as given (it expands `$VAR` and `$$` by default since systemd 254).
#[test]
fn a_command_with_dollar_signs_runs_as_given_under_a_systemd_scope() {
    if !systemd_scopes_work() {
        return;
    }
    let t = T::new();
    let script = "echo \"pid=$$ home=${HOME} x=$X\" > dollars.txt; echo '$$ ${HOME}' >> dollars.txt";
    let plain = t.cmd(&t.proj, &["ws", "exec", "agent", "--", "sh", "-c", script]).env("X", "outer").output().unwrap();
    assert!(plain.status.success(), "{}", text(&plain));
    let want = t.cat("dollars.txt").unwrap();
    let o = t.cmd(&t.proj, &["ws", "exec", "agent", "--memory", "1G", "--", "sh", "-c", script]).env("X", "outer").env("VEIL_EXEC_LIMITS_BACKEND", "systemd").output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(t.cat("dollars.txt").unwrap(), want, "systemd-run rewrote the command: {}", text(&o));
}

/// A `systemctl` that never answers after a scoped run that was killed
/// must not keep `vl` from recording.
#[test]
fn a_hung_systemctl_after_a_scoped_run_does_not_keep_vl_from_recording() {
    let t = T::new();
    t.sh("true");
    let fake = t.env.dir("fake-systemd");
    // `systemd-run` runs the command in place, as `--scope` does; `systemctl` hangs.
    write(&fake, "systemd-run", "#!/bin/sh\nwhile [ \"$1\" != -- ]; do shift; done; shift; exec \"$@\"\n");
    write(&fake, "systemctl", "#!/bin/sh\nexec sleep 600\n");
    for prog in ["systemd-run", "systemctl"] {
        std::fs::set_permissions(fake.join(prog), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:{}", fake.display(), std::env::var("PATH").unwrap_or_default());
    let o = exec_deadline(&t, &["agent", "--memory", "1G", "--", "sh", "-c", "echo ran > killed.txt; kill -9 $$"], &[("PATH", path.as_ref())], 60)
        .expect("vl hung on systemctl after the run");
    assert!(text(&o).contains("Recorded"), "{}", text(&o));
    assert_eq!(t.cat("killed.txt").as_deref(), Some("ran\n"), "{}", text(&o));
}

/// `kill -9` of `vl` while `bwrap` or `systemd-run` is still starting
/// (each made to take two seconds): the command never runs on, orphaned.
#[test]
fn killing_vl_while_bwrap_or_systemd_run_starts_leaves_nothing_running() {
    let t = T::new();
    t.sh("true");
    let which = |p: &str| {
        let o = Command::new("sh").args(["-c", &format!("command -v {p}")]).output().unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    let mut cases = vec![("bwrap", vec![])];
    if systemd_scopes_work() {
        cases.push(("systemd-run", vec!["--memory", "1G"]));
    }
    for (prog, flags) in cases {
        let slow = t.env.dir(&format!("slow-{prog}"));
        let started = slow.join("started");
        let marker = format!("30.{}{}", std::process::id(), prog.len());
        write(
            &slow,
            prog,
            &format!("#!/bin/sh\ncase \"$*\" in *{marker}*) touch {s}; sleep 2;; esac\nexec {real} \"$@\"\n", s = started.display(), real = which(prog)),
        );
        std::fs::set_permissions(slow.join(prog), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!("{}:{}", slow.display(), std::env::var("PATH").unwrap_or_default());
        let mut args = vec!["ws", "exec", "agent", "--with-isolated"];
        args.extend(flags.iter());
        let script = format!("sleep {marker}");
        args.extend(["--", "sh", "-c", &script]);
        let mut child = t.cmd(&t.proj, &args).env("PATH", &path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        assert!(wait_for(Duration::from_secs(20), || started.exists()), "{prog}: never started");
        child.kill().unwrap();
        child.wait().unwrap();
        std::thread::sleep(Duration::from_secs(4));
        assert!(!sleeping(&marker), "{prog}: the command ran on after vl was killed");
        assert!(wait_for(Duration::from_secs(10), || !t.files("agent").join(".netrc").exists()), "{prog}: the injected file was left");
    }
    let o = exec_deadline(&t, &["agent", "--", "sh", "-c", "echo next > next.txt"], &[], 60).expect("the next run hung");
    assert!(o.status.success() && t.cat("next.txt").as_deref() == Some("next\n"), "{}", text(&o));
}

/// `kill -9` of `vl` at every moment of a confined, limited run with
/// injected secrets: nothing is left running, no scope stays, the injected
/// file goes, and the next run records and works. `vl` killed after `bwrap`
/// cloned the sandbox's init but before that init armed its own
/// `--die-with-parent`, or `systemd-run` killed while systemd starts its
/// scope, leaves the command or the (empty) scope to the reaper (BUG-852).
#[test]
fn killing_vl_at_any_moment_leaves_nothing_and_the_next_run_recovers() {
    let t = T::new();
    t.sh("true");
    let scopes = || {
        let u = Command::new("systemctl").args(["--user", "list-units", "--all", "--no-legend", "veil-exec-*"]).output();
        u.map(|u| String::from_utf8_lossy(&u.stdout).into_owned()).unwrap_or_default()
    };
    for round in 0..4 {
        for (i, delay) in [0u64, 2, 5, 10, 20, 35, 50, 65, 80, 100, 120, 150, 200, 300, 500, 800].into_iter().enumerate() {
            // Unique to this test process: copies of it may run at once.
            let marker = format!("30.{}{round}{i:02}", std::process::id());
            let script = format!("echo {i} > run{i}.txt; sleep {marker}");
            let mut child = t
                .cmd(&t.proj, &["ws", "exec", "agent", "--with-isolated", "--memory", "1G", "--", "sh", "-c", &script])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id();
            std::thread::sleep(Duration::from_millis(delay));
            let _ = child.kill();
            child.wait().unwrap();
            assert!(wait_for(Duration::from_secs(15), || !sleeping(&marker)), "{delay} ms: the command outlived vl");
            assert!(wait_for(Duration::from_secs(15), || !t.files("agent").join(".netrc").exists()), "{delay} ms: the injected file was left");
            assert!(wait_for(Duration::from_secs(15), || !scopes().contains(&format!("veil-exec-{pid}-"))), "{delay} ms: a scope was left: {}", scopes());
        }
    }
    let o = exec_deadline(&t, &["agent", "--", "sh", "-c", "cat a.txt; echo next > next.txt"], &[], 60).expect("the next run hung");
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(t.cat("next.txt").as_deref(), Some("next\n"), "{}", text(&o));
    assert!(t.cat(".netrc").is_none_or(|c| !c.contains("isolated-value")), "{}", text(&o));
}

/// A run without injected secrets has no reaper: when its `vl` died in
/// the moment that leaves the sandbox's init running (BUG-852), the next
/// run in the workspace, and `vl ws rm`, stop it first. The moment is too
/// short to hit on purpose, so a `bwrap` started as `vl` starts it, with
/// the sandbox bound, stands in for the init that outlived `vl`.
#[test]
fn the_next_run_and_ws_rm_stop_what_a_dead_run_left_running() {
    let t = T::new();
    t.sh("true");
    let o = Command::new("sh").args(["-c", "command -v bwrap"]).output().unwrap();
    let bwrap = String::from_utf8_lossy(&o.stdout).trim().to_string();
    for (i, next) in [&["ws", "exec", "agent", "--", "true"][..], &["ws", "rm", "--force", "agent"]].into_iter().enumerate() {
        // A run killed while its command runs: its output is unrecorded.
        let marker = format!("30.{}{i}1", std::process::id());
        let script = format!("touch started{i}; sleep {marker}");
        let mut run = t.cmd(&t.proj, &["ws", "exec", "agent", "--", "sh", "-c", &script]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        assert!(wait_for(Duration::from_secs(20), || t.files("agent").join(format!("started{i}")).exists()), "never started");
        run.kill().unwrap();
        run.wait().unwrap();
        assert!(wait_for(Duration::from_secs(15), || !sleeping(&marker)), "the command outlived vl");
        let left = format!("30.{}{i}2", std::process::id());
        let files = t.files("agent");
        let mut init = Command::new(&bwrap)
            .args(["--die-with-parent", "--unshare-user", "--unshare-pid", "--ro-bind", "/", "/", "--bind"])
            .args([files.as_os_str(), t.proj.as_os_str()])
            .args(["--", "sleep", &left])
            .spawn()
            .unwrap();
        assert!(wait_for(Duration::from_secs(10), || sleeping(&left)), "the stand-in never started");
        let o = t.cmd(&t.proj, next).stdin(Stdio::null()).output().unwrap();
        assert!(o.status.success(), "{next:?}: {}", text(&o));
        assert!(!sleeping(&left), "{next:?}: what the dead run left still runs");
        assert!(init.try_wait().unwrap().is_some(), "{next:?}: the stand-in init still runs");
    }
    assert!(!t.files("agent").exists());
}

#[test]
fn a_project_path_with_spaces_newlines_dashes_and_dollars_is_bound_as_is() {
    let env = Env::new();
    let proj = env.project("alice", "-p $HOME x\ny", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
    for flags in [&[][..], &["--memory", "1G"][..], &["--ephemeral"][..]] {
        let mut args = vec!["ws", "exec"];
        if !flags.contains(&"--ephemeral") {
            args.push("agent");
        }
        args.extend_from_slice(flags);
        args.extend(["--", "sh", "-c", "pwd > where.txt; cat a.txt; echo x > new.txt"]);
        let o = env.cmd("alice", &proj, &args).stdin(Stdio::null()).output().unwrap();
        assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).contains("a\n"), "{flags:?}: {}", text(&o));
        assert!(!proj.join("new.txt").exists() && !proj.join("where.txt").exists(), "{flags:?}: wrote the real project");
        if flags.contains(&"--ephemeral") {
            continue;
        }
        let where_ = env.stdout("alice", &proj, &["ws", "cat", "agent", "where.txt"]);
        assert_eq!(where_, format!("{}\n", proj.display()), "{flags:?}");
    }
}

#[test]
fn renames_and_hard_links_across_the_sandbox_boundary_change_nothing_outside() {
    let t = T::new();
    let tools = t.env.dir("tools");
    write(&tools, "lib.txt", "TOOLS-LIB-1b7e\n");
    write(&tools, "sub/x", "x\n");
    let tl = tools.display();
    let h = t.home.display();
    let script = [
        format!("cp -a {tl}/lib.txt copy.txt"),
        format!("mv {tl}/lib.txt moved.txt"),
        format!("mv {tl}/sub ."),
        format!("mv a.txt {tl}/a.txt"),
        format!("mv src {tl}/src"),
        format!("ln {tl}/lib.txt hard.txt"),
        format!("ln a.txt {tl}/hard"),
        format!("ln {h}/.cargo/bin/tool hardtool"),
        format!("mv {h}/.cargo/bin/tool ."),
        "mv a.txt /tmp/a.txt; mv /tmp/a.txt a.txt".to_string(),
        format!("mknod {tl}/dev c 1 3"),
        format!("mkfifo {tl}/fifo"),
        "true".to_string(),
    ]
    .iter()
    .map(|s| format!("( {s} ) 2>/dev/null;"))
    .collect::<Vec<_>>()
    .join(" ");
    let before = (snapshot(&tools, &[]), snapshot(&t.home, &[]), snapshot(&t.proj, &[".veil"]));
    let o = t.exec(&["agent", "--allow", &tl.to_string(), "--", "sh", "-c", &script]);
    assert!(o.status.success(), "{}", text(&o));
    let after = (snapshot(&tools, &[]), snapshot(&t.home, &[]), snapshot(&t.proj, &[".veil"]));
    assert_eq!(before.0, after.0, "the allowed folder changed: {}", text(&o));
    assert_eq!(before.1, after.1, "the home changed: {}", text(&o));
    assert_eq!(before.2, after.2, "the real project changed: {}", text(&o));
    // Reading through the allow-list still works: the copy landed. Moves
    // out of an allowed folder took the file from its layer only (BUG-1025).
    assert_eq!(t.cat("copy.txt").as_deref(), Some("TOOLS-LIB-1b7e\n"), "{}", text(&o));
    assert_eq!(t.cat("moved.txt").as_deref(), Some("TOOLS-LIB-1b7e\n"), "{}", text(&o));
}

/// Several workspaces run at once, each planting a marker and trying to
/// read, change or signal the others'; none can.
#[test]
fn concurrent_runs_in_many_workspaces_stay_separate() {
    let t = T::new();
    let n = 6;
    for i in 0..n {
        t.env.ok("alice", &t.proj, &["ws", "new", &format!("w{i}"), "-r", "@-"]);
    }
    let p = t.proj.display().to_string();
    let others = (0..n).map(|i| t.files(&format!("w{i}")).display().to_string()).collect::<Vec<_>>().join(" ");
    let children: Vec<_> = (0..n)
        .map(|i| {
            let script = format!(
                "echo MARK-{i}-c0ffee > mine.txt; sleep 0.5; for d in {others}; do cat $d/mine.txt; echo x > $d/mine.txt; done; \
                 cat {p}/.veil/local/sandboxes/w*/files/mine.txt; \
                 for f in /proc/[0-9]*/cmdline; do tr '\\0' ' ' < $f; echo; done; sleep 0.5; cat mine.txt"
            );
            t.cmd(&t.proj, &["ws", "exec", &format!("w{i}"), "--", "sh", "-c", &script])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for (i, c) in children.into_iter().enumerate() {
        let o = c.wait_with_output().unwrap();
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        assert!(o.status.success(), "w{i}: {}", text(&o));
        for j in (0..n).filter(|j| *j != i) {
            assert!(!out.contains(&format!("MARK-{j}-c0ffee")), "w{i} saw w{j}: {out}");
        }
        assert!(out.trim_end().ends_with(&format!("MARK-{i}-c0ffee")), "w{i}'s own file changed: {out}");
        assert_eq!(t.env.stdout("alice", &t.proj, &["ws", "cat", &format!("w{i}"), "mine.txt"]), format!("MARK-{i}-c0ffee\n"));
    }
}

// ---- BUG-1025: the allow-list is writable, per workspace -------------------

const SESSION: &str = "CLAUDE-SESSION-LINE-2f6a";
const SETTINGS: &str = "{\"theme\":\"dark\",\"numStartups\":1}\n";

/// A fake home with a coding agent's configuration, and a run of `script`
/// in `ws` that must succeed: its stdout.
fn agent_home(t: &T) {
    write(&t.home, ".claude/settings.json", "{\"model\":\"opus\"}\n");
    write(&t.home, ".claude.json", SETTINGS);
    write(&t.home, ".codex/config.toml", "model = \"x\"\n");
}

fn run_out(t: &T, args: &[&str]) -> String {
    let o = t.exec(args);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// The real cargo of this machine's toolchain (`rustc --print sysroot`),
/// if there is one: `(sysroot, cargo)`.
fn real_cargo() -> Option<(PathBuf, PathBuf)> {
    let o = Command::new("rustc").args(["--print", "sysroot"]).output().ok()?;
    let sysroot = PathBuf::from(String::from_utf8(o.stdout).ok()?.trim());
    let cargo = sysroot.join("bin/cargo");
    (o.status.success() && cargo.is_file()).then_some((sysroot, cargo))
}

#[test]
fn bug_1025_a_confined_cargo_writes_its_home_and_the_next_run_has_it() {
    let t = T::new();
    // A stand-in for a download: what cargo writes under `~/.cargo/registry`.
    let o = t.exec(&["agent", "--", "sh", "-c", "mkdir -p ~/.cargo/registry/cache/i && echo crate > ~/.cargo/registry/cache/i/itoa-1.0.0.crate"]);
    assert!(o.status.success(), "a write under ~/.cargo/registry failed: {}", text(&o));
    let out = run_out(&t, &["agent", "--", "sh", "-c", "cat ~/.cargo/registry/cache/i/itoa-1.0.0.crate"]);
    assert_eq!(out, "crate\n", "the download did not survive to the next run");
    // The real cargo: `cargo install` writes `~/.cargo/bin` and `~/.cargo/.crates.toml`, offline.
    let Some((sysroot, cargo)) = real_cargo() else {
        eprintln!("no rustc toolchain here: the real cargo case is skipped");
        return;
    };
    // `CARGO_HOME` (rustup sets it for the tests) would name the real one.
    let script = format!(
        "unset CARGO_HOME RUSTUP_HOME; mkdir -p tool/src && printf '[package]\\nname = \"hello-1025\"\\nversion = \"0.1.0\"\\nedition = \"2021\"\\n' > tool/Cargo.toml && \
         echo 'fn main() {{ println!(\"hello-1025-ran\"); }}' > tool/src/main.rs && \
         CARGO_TARGET_DIR=/tmp/target RUSTC={s}/bin/rustc PATH={s}/bin:$PATH {cargo} install --offline --quiet --path tool && ls ~/.cargo/bin",
        s = sysroot.display(),
        cargo = cargo.display()
    );
    let s = sysroot.display().to_string();
    let o = t.exec(&["agent", "--allow", &s, "--", "sh", "-c", &script]);
    assert!(o.status.success(), "a confined `cargo install` failed: {}", text(&o));
    let out = run_out(&t, &["agent", "--", "sh", "-c", "~/.cargo/bin/hello-1025; grep -c hello-1025 ~/.cargo/.crates.toml"]);
    assert_eq!(out, "hello-1025-ran\n1\n", "what cargo installed did not survive to the next run");
}

#[test]
fn bug_1025_coding_agents_save_their_settings_and_sessions() {
    let t = T::new();
    agent_home(&t);
    let script = format!(
        "mkdir -p ~/.claude/projects/p && echo {SESSION} >> ~/.claude/projects/p/s.jsonl && echo {SESSION} >> ~/.claude/history.jsonl && \
         printf '{{\"theme\":\"light\"}}\\n' > ~/.claude.json && echo 'model = \"y\"' > ~/.codex/config.toml && echo saved"
    );
    let o = t.exec(&["agent", "--", "sh", "-c", &script]);
    assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).contains("saved"), "{}", text(&o));
    let out = run_out(&t, &["agent", "--", "sh", "-c", "cat ~/.claude/projects/p/s.jsonl ~/.claude/history.jsonl ~/.claude.json ~/.codex/config.toml"]);
    assert_eq!(out, format!("{SESSION}\n{SESSION}\n{{\"theme\":\"light\"}}\nmodel = \"y\"\n"), "the agent's settings and sessions were lost");
}

#[test]
fn bug_1025_what_a_run_writes_to_the_allow_list_stays_with_that_workspace_only() {
    let t = T::new();
    agent_home(&t);
    t.env.ok("alice", &t.proj, &["ws", "new", "other", "-r", "@-"]);
    let write_all = format!("echo {SESSION} > ~/.claude/mark; echo {SESSION} > ~/.cargo/mark; echo '{{\"w\":1}}' > ~/.claude.json; echo done");
    let o = t.exec(&["agent", "--", "sh", "-c", &write_all]);
    assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).contains("done"), "{}", text(&o));
    let read_all = "cat ~/.claude/mark ~/.cargo/mark ~/.claude.json 2>&1; echo end";
    let mine = run_out(&t, &["agent", "--", "sh", "-c", read_all]);
    assert_eq!(mine, format!("{SESSION}\n{SESSION}\n{{\"w\":1}}\nend\n"), "the next run of the workspace lost them");
    // Another workspace sees the real folders, not this one's writes.
    let other = run_out(&t, &["other", "--", "sh", "-c", read_all]);
    assert!(!other.contains(SESSION) && other.contains(SETTINGS.trim()), "{other}");
}

fn layers(t: &T, ws: &str) -> PathBuf {
    t.proj.join(".veil/local/sandboxes").join(ws).join("layers")
}

/// Every file under `dir` whose content holds `needle`.
fn holding(dir: &Path, needle: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let m = std::fs::symlink_metadata(e.path()).unwrap();
            if m.is_dir() {
                stack.push(e.path());
            } else if m.is_file() && std::fs::read(e.path()).is_ok_and(|c| String::from_utf8_lossy(&c).contains(needle)) {
                out.push(e.path());
            }
        }
    }
    out
}

/// The real folders and files of the allow-list are never written: every
/// kind of change a command makes to them, in a kept, a throwaway and an
/// injected run, leaves them byte for byte (and mtime) as they were.
#[test]
fn the_real_allowed_folders_and_files_are_unchanged_after_runs_that_write_them() {
    let t = T::new();
    agent_home(&t);
    write(&t.home, ".claude/projects/p/old.jsonl", "old\n");
    write(&t.home, ".cargo/registry/cache/i/a.crate", "crate\n");
    let mtime = |p: &Path| std::fs::symlink_metadata(p).unwrap().modified().unwrap();
    let (json, settings) = (t.home.join(".claude.json"), t.home.join(".claude/settings.json"));
    let before = (snapshot(&t.home, &[]), mtime(&json), mtime(&settings), mtime(&t.home.join(".claude")));
    let script = "echo x >> ~/.claude.json; : > ~/.claude/settings.json; chmod 777 ~/.claude/settings.json ~/.claude; \
                  mv ~/.claude/projects/p/old.jsonl ~/.claude/moved; rm -rf ~/.claude/projects ~/.cargo/registry; \
                  ln -s /etc/passwd ~/.claude/link; ln ~/.cargo/bin/tool ~/.cargo/hard; touch -d 2001-01-01 ~/.claude.json ~/.codex/config.toml; \
                  mkdir -p ~/.cargo/registry/index && echo new > ~/.cargo/registry/index/n; cat ~/.claude.json; echo end";
    for args in [&["agent"][..], &["--ephemeral"], &["agent", "--with-isolated"]] {
        let mut all = args.to_vec();
        all.extend(["--", "sh", "-c", script]);
        let out = run_out(&t, &all);
        assert!(out.ends_with(&format!("{SETTINGS}x\nend\n")), "{args:?}: {out}");
    }
    let after = (snapshot(&t.home, &[]), mtime(&json), mtime(&settings), mtime(&t.home.join(".claude")));
    assert_eq!(before, after, "a real allowed folder or file changed");
}

/// Cargo's credentials, the Veil home and the real project stay hidden on
/// top of the layers: nothing a command does in one run (delete, rename,
/// overwrite, link, rename a folder that holds them) shows them in the next.
#[test]
fn masks_hold_through_the_layers_in_this_run_and_the_next() {
    let t = T::new();
    let identity = std::fs::read_to_string(t.env.root.join("home-alice/identity.json")).unwrap();
    let id_line = identity.lines().find(|l| l.contains("secret")).unwrap_or(identity.trim()).trim().to_string();
    // A Veil home directly inside an allowed folder (a layer), and one two
    // levels down (that folder stays read-only).
    let top = t.env.dir("stash-top");
    let deep = t.env.dir("stash-deep");
    let copy = |to: &Path| {
        let o = Command::new("cp").arg("-a").arg(t.env.root.join("home-alice")).arg(to).output().unwrap();
        assert!(o.status.success(), "{}", text(&o));
    };
    copy(&top.join("vh"));
    std::fs::create_dir_all(deep.join("a")).unwrap();
    copy(&deep.join("a/vh"));
    let attack = |vh: &Path, allow: &Path| {
        let (v, a) = (vh.display(), allow.display());
        let script = format!(
            "cat ~/.cargo/credentials.toml; unlink ~/.cargo/credentials.toml; mv ~/.cargo/credentials.toml ~/.cargo/c2; mv ~/.cargo ~/.c2; \
             ln ~/.cargo/credentials.toml ~/.cargo/c3; cp ~/.cargo/credentials.toml ~/.cargo/c4; echo planted > ~/.cargo/credentials.toml; \
             rm -rf {v}; mv {v} {a}/moved; mv {a}/a {a}/b; ln -s {v} {a}/l; mkdir {a}/fresh; cat {v}/identity.json {a}/moved/identity.json {a}/b/vh/identity.json; echo end"
        );
        for _ in 0..2 {
            let o = t
                .cmd(&t.proj, &["ws", "exec", "agent", "--allow", &a.to_string(), "--", "sh", "-c", &script])
                .env("VEIL_HOME", vh)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let out = String::from_utf8_lossy(&o.stdout).into_owned();
            assert!(o.status.success() && out.ends_with("end\n"), "{}", text(&o));
            assert!(!out.contains(CARGO_TOKEN), "cargo's credentials showed through a layer: {out}");
            assert!(!out.contains(&id_line), "the Veil home showed through a layer: {out}");
        }
        text(&t.cmd(&t.proj, &["ws", "exec", "agent", "--allow", &a.to_string(), "--", "true"]).env("VEIL_HOME", vh).output().unwrap())
    };
    let top_run = attack(&top.join("vh"), &top);
    assert!(!top_run.contains("read-only:"), "{top_run}");
    let deep_run = attack(&deep.join("a/vh"), &deep);
    assert!(deep_run.contains(&format!("read-only: {}", deep.display())), "{deep_run}");
    // A folder that holds the project stays read-only too (its layers are in the project).
    let o = t.exec(&["agent", "--allow", &t.env.root.display().to_string(), "--", "sh", "-c", &format!("touch {}/x; echo end", t.env.root.display())]);
    assert!(text(&o).contains(&format!("read-only: {}", t.env.root.display())) && text(&o).contains("Read-only file system"), "{}", text(&o));
    // Nothing secret was ever copied into a layer.
    for secret in [CARGO_TOKEN, id_line.as_str()] {
        assert_eq!(holding(&layers(&t, "agent"), secret), Vec::<PathBuf>::new(), "{secret}");
    }
}

/// Links a command plants in its layers resolve inside the confinement
/// only, in later runs too; `vl` never follows one, nor a link put where a
/// file copy belongs.
#[test]
fn links_planted_in_the_layers_lead_nowhere_outside() {
    let t = T::new();
    agent_home(&t);
    let canary = t.env.dir("layer-canary");
    write(&canary, "secret", OTHER);
    let c = canary.display();
    let plant = format!(
        "ln -s {c}/secret ~/.cargo/l1; ln -s {c} ~/.claude/l2; ln -s ../../../../../../../../../.. ~/.claude/up; ln -s {h}/.ssh ~/.claude/ssh; echo end",
        h = t.home.display()
    );
    run_out(&t, &["agent", "--", "sh", "-c", &plant]);
    let out = run_out(&t, &["agent", "--", "sh", "-c", &format!("cat ~/.cargo/l1 ~/.claude/l2/secret ~/.claude/up{c}/secret ~/.claude/ssh/id_test 2>&1; echo x > ~/.claude/l2/new 2>&1; echo end")]);
    assert!(!out.contains(OTHER) && !out.contains(SSH_KEY), "{out}");
    // A link where the copy of `~/.claude.json` belongs is replaced, not written through.
    let copy = std::fs::read_dir(layers(&t, "agent")).unwrap().flatten().find(|e| e.file_name().to_string_lossy().starts_with("claude.json-")).unwrap().path();
    std::fs::remove_file(&copy).unwrap();
    std::os::unix::fs::symlink(canary.join("secret"), &copy).unwrap();
    let before = snapshot(&canary, &[]);
    let out = run_out(&t, &["agent", "--", "sh", "-c", "cat ~/.claude.json; echo over > ~/.claude.json"]);
    assert!(!out.contains(OTHER) && out.contains(SETTINGS.trim()), "{out}");
    assert!(std::fs::symlink_metadata(&copy).unwrap().is_file());
    // `vl ws rm` removes the layers without following a link.
    t.env.ok("alice", &t.proj, &["ws", "rm", "agent"]);
    assert!(!layers(&t, "agent").exists());
    assert_eq!(snapshot(&canary, &[]), before, "a planted link was followed");
}

/// The layers are the user's only (`0700`, copies `0600`), go with the
/// workspace, and deleting them resets the allow-list to the real folders.
#[test]
fn layers_are_private_and_go_with_the_workspace() {
    let t = T::new();
    agent_home(&t);
    run_out(&t, &["agent", "--", "sh", "-c", "echo a > ~/.cargo/mark; echo '{}' > ~/.claude.json"]);
    let dir = layers(&t, "agent");
    let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    let mut names = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        let p = e.path();
        names.push(e.file_name().to_string_lossy().into_owned());
        match p.is_dir() {
            true => assert!(mode(&p) == 0o700 && mode(&p.join("upper")) == 0o700 && mode(&p.join("work")) == 0o700, "{p:?}"),
            false => assert_eq!(mode(&p), 0o600, "{p:?}"),
        }
    }
    assert!(names.iter().any(|n| n.starts_with("cargo-")) && names.iter().any(|n| n.starts_with("claude.json-")), "{names:?}");
    // Deleting the folder resets the layers.
    veil_core::vfs::remove_tree(&dir).unwrap();
    let out = run_out(&t, &["agent", "--", "sh", "-c", "cat ~/.cargo/mark ~/.claude.json 2>&1; true"]);
    assert!(out.contains("No such file") && out.contains(SETTINGS.trim()), "{out}");
    // `vl ws rm` takes them; a new workspace of the same name starts from the real folders.
    run_out(&t, &["agent", "--", "sh", "-c", "echo b > ~/.cargo/mark"]);
    t.env.ok("alice", &t.proj, &["ws", "rm", "agent"]);
    assert!(!dir.exists() && !t.proj.join(".veil/local/sandboxes/agent").exists());
    t.env.ok("alice", &t.proj, &["ws", "new", "agent", "-r", "@-"]);
    let out = run_out(&t, &["agent", "--", "sh", "-c", "cat ~/.cargo/mark 2>&1; true"]);
    assert!(out.contains("No such file"), "{out}");
    // An allowed executable file stays executable in its copy.
    let tool = t.env.dir("bin").join("tool-1025");
    std::fs::write(&tool, "#!/bin/sh\necho tool-1025-ran\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let tl = tool.display().to_string();
    assert_eq!(run_out(&t, &["agent", "--allow", &tl, "--", &tl]), "tool-1025-ran\n");
    let copy = std::fs::read_dir(&dir).unwrap().flatten().find(|e| e.file_name().to_string_lossy().starts_with("tool-1025-")).unwrap().path();
    assert_eq!(mode(&copy), 0o700);
}

/// A throwaway sandbox, and a run given secrets, keep nothing of what they
/// wrote to the allow-list: an injected secret copied there is gone.
#[test]
fn throwaway_and_injected_runs_keep_no_writes() {
    let t = T::new();
    agent_home(&t);
    let tmp = t.env.root.join("tmp");
    for args in [&["--ephemeral"][..], &["agent", "--with-isolated"]] {
        let mut all = args.to_vec();
        all.extend(["--", "sh", "-c", "cat .netrc > ~/.claude/stash 2>/dev/null; cat .netrc >> ~/.claude.json 2>/dev/null; echo w > ~/.cargo/w; cat ~/.cargo/w"]);
        assert_eq!(run_out(&t, &all), "w\n", "{args:?}");
        let left: Vec<String> = std::fs::read_dir(&tmp).map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
        assert!(left.is_empty(), "{args:?}: left in TMPDIR: {left:?}");
    }
    for args in [&["--ephemeral"][..], &["agent"]] {
        let mut all = args.to_vec();
        all.extend(["--", "sh", "-c", "cat ~/.claude/stash ~/.cargo/w 2>&1; cat ~/.claude.json"]);
        let out = run_out(&t, &all);
        assert!(!out.contains("isolated-value") && !out.contains("w\n") && out.contains(SETTINGS.trim()), "{args:?}: {out}");
    }
    assert_eq!(holding(&t.proj.join(".veil/local/sandboxes"), "isolated-value"), Vec::<PathBuf>::new());
}

/// Where overlayfs does not work, the allow-list is read-only, the run
/// still happens, and `vl` (and `vl doctor`) say what that breaks.
#[test]
fn without_overlayfs_the_allow_list_is_read_only_and_vl_says_so() {
    let t = T::new();
    agent_home(&t);
    let real = std::env::split_paths(&std::env::var_os("PATH").unwrap()).map(|d| d.join("bwrap")).find(|p| p.is_file()).unwrap();
    let fake = t.env.dir("no-overlay");
    write(
        &fake,
        "bwrap",
        &format!(
            "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --overlay|--tmp-overlay) echo 'bwrap: Can'\"'\"'t make overlay mount: Operation not permitted' >&2; exit 1;; esac; done\nexec {} \"$@\"\n",
            real.display()
        ),
    );
    std::fs::set_permissions(fake.join("bwrap"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", fake.display(), std::env::var("PATH").unwrap_or_default());
    for args in [&["agent"][..], &["--ephemeral"]] {
        let mut all = vec!["ws", "exec"];
        all.extend_from_slice(args);
        all.extend(["--", "sh", "-c", "cat ~/.claude.json; echo x > ~/.claude/new; echo end"]);
        let o = t.cmd(&t.proj, &all).env("PATH", &path).stdin(Stdio::null()).output().unwrap();
        let out = text(&o);
        assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).ends_with("end\n"), "{args:?}: {out}");
        assert!(out.contains("the allow-list is read-only in this run") && out.contains("overlay mount") && out.contains("cargo cannot download crates"), "{args:?}: {out}");
        assert!(out.contains("Read-only file system"), "{args:?}: {out}");
    }
    let out = text(&t.cmd(&t.proj, &["doctor"]).env("PATH", &path).output().unwrap());
    assert!(out.contains("allow-list: read-only, overlayfs does not work here"), "{out}");
    let out = text(&t.cmd(&t.proj, &["doctor"]).output().unwrap());
    assert!(out.contains("allow-list: writable"), "{out}");
}
