//! `vl remote add`, `push`, `pull` and `clone` with SSH remotes, through
//! the real binary: once with a stand-in `ssh` (`VEIL_SSH` pointing at a
//! script that runs a local `sftp-server`), and once through the real
//! `ssh` against a throwaway `sshd` on localhost, with a host alias from an
//! `ssh_config` file. Each is skipped, with a message, when the tools are
//! missing.

use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const SFTP_SERVERS: &[&str] = &[
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/opt/homebrew/libexec/sftp-server",
];

fn sftp_server() -> Option<PathBuf> {
    let found = std::env::var("VEIL_TEST_SFTP_SERVER")
        .ok()
        .map(PathBuf::from)
        .or_else(|| SFTP_SERVERS.iter().map(PathBuf::from).find(|p| p.exists()));
    if found.is_none() {
        eprintln!("SKIPPED: no sftp-server binary found");
    }
    found
}

struct Env {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    ssh: String,
}

impl Env {
    fn new(ssh: String, tmp: tempfile::TempDir) -> Env {
        let root = tmp.path().to_path_buf();
        Env { _tmp: tmp, root, ssh }
    }

    fn dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn vl(&self, user: &str, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vl"))
            .args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.root.join(format!("home-{user}")))
            .env("VEIL_USER", user)
            .env("VEIL_SSH", &self.ssh)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn ok(&self, user: &str, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(user, cwd, args);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "vl {args:?} failed:\n{text}");
        text
    }
}

/// init → commit → push to `url` → clone → commit and push from the clone
/// → pull back.
fn round_trip(env: &Env, url: &str, remote_dir: &Path) {
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    std::fs::write(proj.join("hello.txt"), "hello over ssh\n").unwrap();
    env.ok("alice", &proj, &["commit", "-m", "first"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "origin", url]);
    let out = env.ok("alice", &proj, &["push"]);
    assert!(out.contains("pushed"), "{out}");
    assert!(remote_dir.join(".veil/repo.json").exists(), "push created the remote");
    assert!(env.ok("alice", &proj, &["push"]).contains("Pushed 0 object(s)"));

    let work = env.dir("work");
    let out = env.ok("bob", &work, &["clone", url, "copy"]);
    assert!(out.contains("Cloned"), "{out}");
    let copy = work.join("copy");
    assert_eq!(std::fs::read_to_string(copy.join("hello.txt")).unwrap(), "hello over ssh\n");
    assert!(env.ok("bob", &copy, &["remote", "list"]).contains(url));

    std::fs::write(copy.join("from-bob.txt"), "bob was here\n").unwrap();
    env.ok("bob", &copy, &["commit", "-m", "bob"]);
    env.ok("bob", &copy, &["tag", "set", "main", "-r", "@-"]);
    env.ok("bob", &copy, &["push"]);
    let out = env.ok("alice", &proj, &["pull"]);
    assert!(out.contains("updated"), "{out}");
    assert!(env.ok("alice", &proj, &["cat", "from-bob.txt", "-r", "main"]).contains("bob was here"));
    env.ok("alice", &proj, &["pull", "--full"]);
    env.ok("alice", &proj, &["push", "--full"]);
    let fsck = env.ok("alice", &proj, &["fsck", "--verbose", "-R", remote_dir.to_str().unwrap()]);
    assert!(fsck.contains("No corruption found"), "{fsck}");
}

#[test]
fn ssh_remotes_through_a_stand_in_ssh() {
    let Some(server) = sftp_server() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("fake-ssh");
    // Ignores the ssh arguments (host, -s sftp) and speaks SFTP on stdio.
    std::fs::write(&script, format!("#!/bin/sh\nexec {}\n", server.display())).unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let env = Env::new(script.display().to_string(), tmp);
    let remote = env.root.join("srv/team.veil");
    round_trip(&env, &format!("someone@example.invalid:{}", remote.display()), &remote);

    // `vl doctor --remotes` connects, and compares the remote's clock with
    // ours (the same machine here, so within a second or two).
    let proj = env.root.join("proj");
    let out = env.ok("alice", &proj, &["doctor", "--remotes"]);
    assert!(out.contains("origin (") && out.contains("reachable in"), "{out}");
    assert!(out.contains("origin's clock is within"), "{out}");

    // Malformed SSH URLs are refused up front.
    let out = env.vl("alice", &proj, &["remote", "add", "bad", "ssh://-oProxyCommand=x/r"]);
    assert!(!out.status.success());
}

struct Sshd(Child);

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

#[test]
fn ssh_remotes_through_real_ssh_and_a_throwaway_sshd() {
    let Some(server) = sftp_server() else { return };
    let sshd = ["/usr/sbin/sshd", "/usr/local/sbin/sshd"].into_iter().find(|p| Path::new(p).exists());
    let (Some(sshd), true) = (sshd, have("ssh") && have("ssh-keygen")) else {
        eprintln!("SKIPPED: sshd, ssh or ssh-keygen not available");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path().to_path_buf();
    for k in ["host_key", "user_key"] {
        let ok = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(t.join(k))
            .status()
            .unwrap()
            .success();
        assert!(ok);
    }
    std::fs::copy(t.join("user_key.pub"), t.join("authorized_keys")).unwrap();
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    std::fs::write(
        t.join("sshd_config"),
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {t}/host_key\nAuthorizedKeysFile {t}/authorized_keys\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\n\
             PidFile {t}/sshd.pid\nSubsystem sftp {server}\n",
            t = t.display(),
            server = server.display()
        ),
    )
    .unwrap();
    let child = Command::new(sshd)
        .arg("-D")
        .arg("-f")
        .arg(t.join("sshd_config"))
        .arg("-E")
        .arg(t.join("sshd.log"))
        .spawn()
        .unwrap();
    let _guard = Sshd(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        if Instant::now() > deadline {
            eprintln!("SKIPPED: the throwaway sshd did not start");
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // A host alias, as in ~/.ssh/config: everything comes from ssh itself.
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap();
    std::fs::write(
        t.join("ssh_config"),
        format!(
            "Host veil-test-host\n  HostName 127.0.0.1\n  Port {port}\n  User {}\n  IdentityFile {}/user_key\n  \
             IdentitiesOnly yes\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  BatchMode yes\n  \
             LogLevel ERROR\n",
            user.trim(),
            t.display()
        ),
    )
    .unwrap();
    let probe = Command::new("ssh")
        .arg("-F")
        .arg(t.join("ssh_config"))
        .args(["veil-test-host", "true"])
        .stdin(Stdio::null())
        .status()
        .unwrap();
    if !probe.success() {
        eprintln!("SKIPPED: cannot log in to the throwaway sshd");
        return;
    }
    let ssh = format!("ssh -F {}", t.join("ssh_config").display());
    let env = Env::new(ssh, tmp);
    let remote = env.root.join("srv/proj");
    round_trip(&env, &format!("ssh://veil-test-host{}", remote.display()), &remote);
}
