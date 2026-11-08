//! The guarantees of `vl ws exec --private-ports` and `--seed SRC:DEST`
//! (`docs/design/server/phase-2-thin-clients.md` §4.9, milestone S8; Linux,
//! bubblewrap). Each test runs small commands in confined runs and checks,
//! from outside, what they could reach or change:
//!
//! * `--private-ports`: every run has its own loopback (two runs bind the
//!   same port at once); the host's loopback is neither reachable from a run
//!   nor changed by one; one run cannot reach another's ports; outbound
//!   connections reach what the host reaches; without `pasta` the flag fails
//!   before anything runs, never sharing the host's loopback; nothing is
//!   left running afterwards;
//! * `--seed`: a seed is never written, whatever the run does in it; every
//!   run starts from the seed as it is; one run never sees another's layer;
//!   nothing of a layer outlives its run; hostile sources and destinations
//!   are refused before anything runs.
//!
//! `pasta` (from passt) is looked for on `PATH`, then in `VEIL_TEST_PASTA`
//! (a path to the program). A machine without it fails these tests with a
//! message saying how to install it: a guarantee is never skipped.

use crate::adversarial_support;

use std::{
    collections::BTreeMap,
    ffi::OsString,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use adversarial_support::*;

struct T {
    env: Env,
    proj: PathBuf,
    home: PathBuf,
    /// `PATH` with `pasta` on it.
    path: OsString,
}

/// A directory holding `pasta`, for `PATH`.
fn pasta_dir() -> PathBuf {
    let on_path = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).map(|d| d.join("pasta")).find(|p| p.is_file()))
        .unwrap_or_default();
    let found = on_path.or_else(|| std::env::var_os("VEIL_TEST_PASTA").map(PathBuf::from).filter(|p| p.is_file()));
    let p = found.unwrap_or_else(|| {
        panic!(
            "these tests need pasta (from passt): install it (`apt install passt`, `dnf install passt`, `pacman -S passt`) \
             or set VEIL_TEST_PASTA to the program"
        )
    });
    p.parent().unwrap().to_path_buf()
}

impl T {
    fn new() -> T {
        let env = Env::new();
        let proj = env.project("alice", "proj", &[("a.txt", "a\n"), ("src/lib.rs", "pub fn f() {}\n")]);
        env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
        env.ok("alice", &proj, &["ws", "new", "other", "-r", "@-"]);
        let home = env.dir("fakehome");
        write(&home, ".ssh/id_test", "PLANTED-KEY");
        let mut dirs = vec![pasta_dir()];
        dirs.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
        let path = std::env::join_paths(dirs).unwrap();
        T { env, proj, home, path }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = self.env.cmd("alice", &self.proj, args);
        c.env("HOME", &self.home).env("PATH", &self.path).stdin(Stdio::null());
        c
    }

    /// `vl ws exec WS FLAGS -- bash -c SCRIPT`.
    fn exec(&self, ws: &str, flags: &[&str], script: &str) -> Output {
        let mut a = vec!["ws", "exec", ws];
        a.extend_from_slice(flags);
        a.extend(["--", "bash", "-c", script]);
        self.cmd(&a).output().unwrap()
    }

    fn spawn(&self, ws: &str, flags: &[&str], script: &str) -> Child {
        let mut a = vec!["ws", "exec", ws];
        a.extend_from_slice(flags);
        a.extend(["--", "bash", "-c", script]);
        self.cmd(&a).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
    }

    /// The run's own output (stdout), which must have succeeded.
    fn ok(&self, ws: &str, flags: &[&str], script: &str) -> String {
        let o = self.exec(ws, flags, script);
        assert!(o.status.success(), "{}", text(&o));
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    fn cat(&self, ws: &str, path: &str) -> Option<String> {
        let o = self.env.vl("alice", &self.proj, &["ws", "cat", ws, path]);
        o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
    }
}

/// Does `bash` here connect to `host:port` (within 3 s)?
fn probe(host: &str, port: u16) -> String {
    format!("if timeout 3 bash -c 'exec 3<>/dev/tcp/{host}/{port}' 2>/dev/null; then echo CONNECTED-{port}; else echo REFUSED-{port}; fi")
}

/// A python3 one-liner serving `port` on `addr` until `secs` pass, printing
/// `LISTENING` once bound and `SERVED` for each connection.
fn listen(addr: &str, port: u16, secs: u32) -> String {
    format!(
        "python3 -c \"import socket,sys,time\ns=socket.socket(socket.AF_INET6 if ':' in '{addr}' else socket.AF_INET)\n\
         s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\ns.bind(('{addr}',{port}))\ns.listen()\nprint('LISTENING',flush=True)\n\
         s.settimeout(0.2)\nend=time.time()+{secs}\nwhile time.time()<end:\n  try:\n    c,_=s.accept();print('SERVED',flush=True);c.close()\n  except OSError: pass\""
    )
}

/// A port nothing on this machine listens on (now).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// This test's `pasta` processes: their command line names a file under
/// the test's own directory (the pid file in its `TMPDIR`), so other tests'
/// runs never count.
fn pastas(t: &T) -> Vec<i32> {
    let mine = t.env.root.to_string_lossy().into_owned();
    let mut out = Vec::new();
    for e in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(comm) = std::fs::read_to_string(e.path().join("comm")) else { continue };
        let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else { continue };
        if comm.trim_end().starts_with("pasta") && String::from_utf8_lossy(&cmd).contains(&mine) {
            out.push(pid);
        }
    }
    out
}

/// Every file and directory under `dir`, with content and mode.
fn tree(dir: &Path) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            let rel = p.strip_prefix(dir).unwrap().to_path_buf();
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

// ---- --private-ports ---------------------------------------------------------------

#[test]
fn two_runs_bind_the_same_port_at_once_and_each_reaches_only_its_own() {
    let t = T::new();
    let port = free_port();
    // Run A binds the port on its loopback and serves for a while; run B,
    // at the same time, binds the same port and connects to it: it reaches
    // its own listener, never A's (A counts every connection it serves).
    let a = t.spawn("agent", &["--private-ports"], &format!("{} & sleep 6; wait", listen("127.0.0.1", port, 6)));
    let deadline = Instant::now() + Duration::from_secs(20);
    // B, until A is listening (B's own bind succeeding is the point, so it
    // is not a sign of A).
    let b_script = format!("{} & sleep 1; {}; {}; wait", listen("127.0.0.1", port, 2), probe("127.0.0.1", port), probe("::1", port));
    let b = loop {
        let b = t.exec("other", &["--private-ports"], &b_script);
        if b.status.success() || Instant::now() > deadline {
            break b;
        }
    };
    let b_out = String::from_utf8_lossy(&b.stdout).into_owned();
    assert!(b.status.success(), "{}", text(&b));
    assert!(b_out.contains("LISTENING") && b_out.contains(&format!("CONNECTED-{port}")), "B binds and reaches its own port: {}", text(&b));
    assert_eq!(b_out.matches("SERVED").count(), 1, "B's IPv4 connection reached B's own listener: {}", text(&b));
    let a = a.wait_with_output().unwrap();
    let a_out = String::from_utf8_lossy(&a.stdout).into_owned();
    assert!(a.status.success() && a_out.contains("LISTENING"), "{}", text(&a));
    assert!(!a_out.contains("SERVED"), "run B reached run A's port: {}", text(&a));
    // The host's loopback never held either: the port is free here.
    std::net::TcpListener::bind(("127.0.0.1", port)).expect("the host's port was taken by a run");
}

#[test]
fn a_run_cannot_reach_the_hosts_loopback_or_its_gateway_and_the_host_cannot_reach_the_run() {
    let t = T::new();
    let host = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let hport = host.local_addr().unwrap().port();
    host.set_nonblocking(true).unwrap();
    let host6 = std::net::TcpListener::bind("[::1]:0").ok();
    let h6port = host6.as_ref().map(|l| l.local_addr().unwrap().port());
    let run_port = free_port();
    let mut script = vec![
        probe("127.0.0.1", hport),
        probe("localhost", hport),
        // pasta maps the gateway to the host by default: not here.
        format!("GW=$(ip route 2>/dev/null | awk '/^default/{{print $3; exit}}'); [ -n \"$GW\" ] && {}", probe("$GW", hport)),
        format!("{} & sleep 3; wait", listen("0.0.0.0", run_port, 3)),
    ];
    if let Some(p) = h6port {
        script.insert(1, probe("::1", p));
    }
    let child = t.spawn("agent", &["--private-ports"], &script.join("; "));
    // Meanwhile the host tries the run's port on its loopback.
    std::thread::sleep(Duration::from_millis(1500));
    let mut reached = false;
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        reached |= std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], run_port).into(), Duration::from_millis(200)).is_ok();
        std::thread::sleep(Duration::from_millis(100));
    }
    let o = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "{}", text(&o));
    assert!(out.contains("LISTENING"), "{}", text(&o));
    assert!(!out.contains("CONNECTED"), "the run reached the host's loopback: {}", text(&o));
    assert!(out.matches(&format!("REFUSED-{hport}")).count() >= 2, "{}", text(&o));
    assert!(!reached && !out.contains("SERVED"), "the host reached the run's port: {}", text(&o));
    // Nothing reached the host's listeners.
    assert!(host.accept().is_err(), "a run connected to the host's loopback");
}

#[test]
fn outbound_connections_reach_what_the_host_reaches() {
    let t = T::new();
    // Outside addresses (no name lookup needed): whatever the host reaches,
    // the run reaches too, and nothing the host cannot.
    let targets = [("1.1.1.1", 443u16), ("8.8.8.8", 53), ("192.0.2.1", 9)];
    let host: Vec<bool> = targets
        .iter()
        .map(|(h, p)| std::net::TcpStream::connect_timeout(&format!("{h}:{p}").parse().unwrap(), Duration::from_secs(3)).is_ok())
        .collect();
    assert!(!host[2], "192.0.2.1 (TEST-NET-1) must be unreachable");
    let script: Vec<String> = targets.iter().map(|(h, p)| probe(h, *p)).collect();
    let out = t.ok("agent", &["--private-ports"], &script.join("; "));
    for ((h, p), reachable) in targets.iter().zip(&host) {
        let want = if *reachable { format!("CONNECTED-{p}") } else { format!("REFUSED-{p}") };
        assert!(out.contains(&want), "{h}:{p}: the host {}, the run printed {out}", if *reachable { "connects" } else { "does not" });
    }
    // Names resolve when the host resolves them.
    let host_dns = std::net::ToSocketAddrs::to_socket_addrs(&("example.com", 443)).is_ok();
    if host_dns {
        let out = t.ok("agent", &["--private-ports"], "getent hosts example.com >/dev/null && echo RESOLVED");
        assert!(out.contains("RESOLVED"), "the host resolves names; the run must too: {out}");
    }
    // And the network stays on by default, as it always was.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = port.local_addr().unwrap().port();
    let out = t.ok("agent", &[], &probe("127.0.0.1", p));
    assert!(out.contains(&format!("CONNECTED-{p}")), "without the flag the run shares the host's network, as before: {out}");
}

#[test]
fn without_pasta_private_ports_fails_before_anything_runs() {
    let t = T::new();
    // A PATH with bwrap but without pasta.
    let empty = t.env.dir("no-pasta");
    std::os::unix::fs::symlink(which("bwrap"), empty.join("bwrap")).unwrap();
    for tool in ["sh", "bash", "true", "python3"] {
        if let Some(p) = try_which(tool) {
            let _ = std::os::unix::fs::symlink(p, empty.join(tool));
        }
    }
    let manifest = t.proj.join(".veil/local/sandboxes/agent/manifest.json");
    t.ok("agent", &[], "true");
    let before = std::fs::read(&manifest).unwrap();
    let o = t.cmd(&["ws", "exec", "agent", "--private-ports", "--", "sh", "-c", "echo ran > ran.txt"]).env("PATH", &empty).output().unwrap();
    let out = text(&o);
    assert!(!o.status.success(), "{out}");
    assert!(out.contains("pasta") && out.contains("passt") && out.contains("nothing was run"), "{out}");
    assert_eq!(std::fs::read(&manifest).unwrap(), before, "the sandbox was touched");
    assert!(t.cat("agent", "ran.txt").is_none());
    // A `pasta` inside the project (a `PATH` entry such as `bin/`) is never
    // run.
    let inner = t.proj.join("bin");
    write(&inner, "pasta", "#!/bin/sh\ntouch /tmp/ran-fake-pasta\nexit 0\n");
    std::fs::set_permissions(inner.join("pasta"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut path = std::ffi::OsString::from(inner.as_os_str());
    path.push(":");
    path.push(&empty);
    let o = t.cmd(&["ws", "exec", "agent", "--private-ports", "--", "sh", "-c", "echo ran > ran.txt"]).env("PATH", &path).output().unwrap();
    assert!(!o.status.success() && text(&o).contains("passt"), "{}", text(&o));
    // Flags that cannot go together are refused.
    for flags in [&["--private-ports", "--no-network"][..], &["--private-ports", "--unconfined"]] {
        let mut a = vec!["ws", "exec", "agent"];
        a.extend_from_slice(flags);
        a.extend(["--", "true"]);
        let o = t.cmd(&a).output().unwrap();
        assert!(!o.status.success() && text(&o).contains("cannot be used with"), "{flags:?}: {}", text(&o));
    }
}

#[test]
fn nothing_is_left_running_after_a_run_even_when_vl_is_killed() {
    let t = T::new();
    t.ok("agent", &["--private-ports"], "true");
    assert!(wait_for(Duration::from_secs(5), || pastas(&t).is_empty()), "pasta outlived its run: {:?}", pastas(&t));
    // Killed in the middle of a run: the sandbox and its pasta stop.
    let marker = format!("sleep\0{}.5\0", 300 + std::process::id() % 1000);
    let secs = marker.trim_start_matches("sleep\0").trim_end_matches('\0').to_string();
    let mut child = t.spawn("agent", &["--private-ports"], &format!("echo started; sleep {secs}"));
    let running = || std::fs::read_dir("/proc").unwrap().flatten().any(|e| std::fs::read(e.path().join("cmdline")).is_ok_and(|c| c == marker.as_bytes()));
    assert!(wait_for(Duration::from_secs(20), running), "the run did not start");
    assert!(!pastas(&t).is_empty(), "the run has its pasta");
    unsafe {
        libc::kill(child.id() as i32, libc::SIGKILL);
    }
    let _ = child.wait();
    let gone = wait_for(Duration::from_secs(15), || !running() && pastas(&t).is_empty());
    assert!(gone, "a killed vl left the run or its pasta running: {:?}", pastas(&t));
}

fn try_which(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(name)).find(|p| p.is_file())
}

fn which(name: &str) -> PathBuf {
    try_which(name).unwrap_or_else(|| panic!("{name} is not on PATH"))
}

// ---- --seed --------------------------------------------------------------------------

/// A seed directory: a few files, a sub-folder, an executable.
fn seed(t: &T) -> PathBuf {
    let s = t.env.dir("seeds/pg");
    write(&s, "PG_VERSION", "16\n");
    write(&s, "base/1/1259", &"row\n".repeat(1000));
    write(&s, "global/pg_control", "control\n");
    write(&s, "bin/start", "#!/bin/sh\necho started\n");
    std::fs::set_permissions(s.join("bin/start"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(s.join("global"), std::fs::Permissions::from_mode(0o700)).unwrap();
    s
}

#[test]
fn a_seed_is_never_written_whatever_the_run_does_in_it() {
    let t = T::new();
    let s = seed(&t);
    let before = tree(&s);
    let spec = format!("{}:/var/lib/seeded", s.display());
    let out = t.ok(
        "agent",
        &["--seed", &spec],
        "cd /var/lib/seeded && cat PG_VERSION && echo 17 > PG_VERSION && rm -rf base && mkdir -p new/deep && echo x > new/deep/f \
         && chmod 777 global && chmod -x bin/start && mv global/pg_control moved && ln -s /etc/passwd link && truncate -s 0 moved \
         && echo WROTE && cat PG_VERSION",
    );
    assert!(out.contains("16\nWROTE\n17\n"), "the run sees the seed and its own writes: {out}");
    assert_eq!(tree(&s), before, "the seed was written");
    // Nothing of the layer is on the host, at DEST or in the project.
    assert!(!Path::new("/var/lib/seeded").exists(), "the seed's place exists on the host");
    assert!(t.cat("agent", "new/deep/f").is_none() && t.cat("agent", "moved").is_none());
}

#[test]
fn every_run_starts_from_the_seed_and_runs_never_see_each_others_layer() {
    let t = T::new();
    let s = seed(&t);
    let spec = format!("{}:/srv/db", s.display());
    t.ok("agent", &["--seed", &spec], "echo one > /srv/db/marker && rm /srv/db/PG_VERSION");
    let out = t.ok("agent", &["--seed", &spec], "ls /srv/db; cat /srv/db/PG_VERSION; test -e /srv/db/marker && echo LEAKED; true");
    assert!(out.contains("16\n") && !out.contains("LEAKED") && !out.contains("marker"), "the next run starts from the seed: {out}");
    // Two runs at once on the same seed.
    let a = t.spawn("agent", &["--seed", &spec], "echo from-a > /srv/db/a-only; echo A-WROTE; sleep 4; cat /srv/db/b-only 2>/dev/null && echo SAW-B; true");
    std::thread::sleep(Duration::from_millis(1500));
    let b = t.ok("other", &["--seed", &spec], "echo from-b > /srv/db/b-only; cat /srv/db/a-only 2>/dev/null && echo SAW-A; echo B-DONE");
    let a = a.wait_with_output().unwrap();
    let a_out = String::from_utf8_lossy(&a.stdout).into_owned();
    assert!(a.status.success() && a_out.contains("A-WROTE"), "{}", text(&a));
    assert!(b.contains("B-DONE") && !b.contains("SAW-A"), "run B saw run A's layer: {b}");
    assert!(!a_out.contains("SAW-B"), "run A saw run B's layer: {}", text(&a));
    assert!(!s.join("a-only").exists() && !s.join("b-only").exists());
}

#[test]
fn hostile_seeds_are_refused_before_anything_runs() {
    let t = T::new();
    let s = seed(&t);
    let file = t.env.dir("seed-file").join("f");
    write(file.parent().unwrap(), "f", "x");
    let veil_home = t.env.dir("home-alice");
    let manifest = t.proj.join(".veil/local/sandboxes/agent/manifest.json");
    t.ok("agent", &[], "true");
    let before = std::fs::read(&manifest).unwrap();
    let sd = s.display().to_string();
    let cases: Vec<(String, &str)> = vec![
        ("/:/seed".into(), "whole machine"),
        (format!("{}:/seed", t.home.display()), "home"),
        (format!("{}:/seed", t.proj.display()), "project"),
        (format!("{}:/seed", t.proj.join(".veil").display()), "project"),
        (format!("{}:/seed", t.proj.join("src").display()), "project"),
        // The test's root holds the home, the Veil home and the project.
        (format!("{}:/seed", t.env.dir("").display()), "home"),
        (format!("{}:/seed", veil_home.display()), "Veil home"),
        (format!("{}:/seed", t.env.dir("missing-seed").join("nope").display()), "no such directory"),
        (format!("{}:/seed", file.display()), "not a directory"),
        ("seeds/pg:/seed".into(), "absolute"),
        (format!("{sd}:relative/dest"), "absolute"),
        (format!("{sd}:/srv/../etc"), ".."),
        (format!("{sd}:/"), "whole machine"),
        (format!("{sd}:{}", t.proj.display()), "project"),
        (format!("{sd}:{}", t.proj.join("db").display()), "project"),
        (format!("{sd}"), "SRC:DEST"),
        (format!("{sd}:/a:/b"), "SRC:DEST"),
    ];
    for (spec, why) in &cases {
        let o = t.cmd(&["ws", "exec", "agent", "--seed", spec, "--", "sh", "-c", "echo ran > ran.txt"]).output().unwrap();
        let out = text(&o);
        assert!(!o.status.success(), "--seed {spec} ran: {out}");
        assert!(out.contains("--seed") && out.contains(why), "--seed {spec}: wanted '{why}' in: {out}");
    }
    // Two seeds at one place, or one inside another.
    for (a, b) in [("/srv/x", "/srv/x"), ("/srv/x", "/srv/x/y")] {
        let o = t
            .cmd(&["ws", "exec", "agent", "--seed", &format!("{sd}:{a}"), "--seed", &format!("{sd}:{b}"), "--", "true"])
            .output()
            .unwrap();
        assert!(!o.status.success() && text(&o).contains("overlap"), "{a} {b}: {}", text(&o));
    }
    let o = t.cmd(&["ws", "exec", "agent", "--unconfined", "--seed", &format!("{sd}:/srv/x"), "--", "true"]).output().unwrap();
    assert!(!o.status.success() && text(&o).contains("cannot be used with"), "{}", text(&o));
    assert_eq!(std::fs::read(&manifest).unwrap(), before, "the sandbox was touched");
    assert!(t.cat("agent", "ran.txt").is_none());
}
