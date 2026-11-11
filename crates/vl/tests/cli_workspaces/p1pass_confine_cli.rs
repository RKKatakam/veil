//! Phase 1 final client security pass (`p1pass`): Guarantee 5 (`vl ws exec`
//! confinement invariants) and `BUG-1803` (workspace-socket `vl log -r`
//! confinement under `--no-network`).
//!
//! Every check is framed as an isolation property that holds for a confined
//! workspace run: private Veil directories, the daemon socket, other
//! workspaces, and disallowed network endpoints remain out of reach while the
//! workspace's own files and history work normally.

use crate::adversarial_support;

use std::{
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use adversarial_support::*;
use veil_core::repo::{PartialConfig, RepoConfig};

struct DaemonStop<'a> {
    env: &'a Env,
    user: &'a str,
}

impl Drop for DaemonStop<'_> {
    fn drop(&mut self) {
        if self.env.root.join(format!("home-{}/daemon", self.user)).exists() {
            let _ = self.env.vl(self.user, &self.env.root, &["daemon", "stop"]);
        }
    }
}

/// Minimal local HTTPS recorder so `--no-network` workspace runs can verify
/// that zero outbound server requests occur.
struct OfflineRecorder {
    port: u16,
    ca_pem: PathBuf,
    log_path: PathBuf,
    child: Child,
}

impl OfflineRecorder {
    fn start(env: &Env, name: &str) -> OfflineRecorder {
        let dir = env.dir(name);
        let ca_key = dir.join("ca.key");
        let ca_pem = dir.join("ca.pem");
        let srv_key = dir.join("srv.key");
        let srv_csr = dir.join("srv.csr");
        let srv_pem = dir.join("srv.pem");
        let ext_cnf = dir.join("ext.cnf");
        std::fs::write(
            &ext_cnf,
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n",
        )
        .unwrap();
        assert!(Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-keyout", ca_key.to_str().unwrap(), "-out", ca_pem.to_str().unwrap(),
                "-days", "1", "-subj", "/CN=VeilTestCA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("openssl")
            .args([
                "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-keyout", srv_key.to_str().unwrap(), "-out", srv_csr.to_str().unwrap(),
                "-subj", "/CN=127.0.0.1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("openssl")
            .args([
                "x509", "-req", "-in", srv_csr.to_str().unwrap(),
                "-CA", ca_pem.to_str().unwrap(), "-CAkey", ca_key.to_str().unwrap(),
                "-CAcreateserial", "-out", srv_pem.to_str().unwrap(),
                "-days", "1", "-extfile", ext_cnf.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());
        let port_path = dir.join("port.txt");
        let log_path = dir.join("requests.log");
        let script_path = dir.join("srv.py");
        let py = r#"
import http.server, json, ssl, sys
cert, key, port_file, log_file = sys.argv[1:5]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass
    def handle_any(self):
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{self.command} {self.path}\n")
        raw = json.dumps({"branches": {}, "default_branch": "main", "you": "alice", "admin": True, "revision": 4}).encode()
        if self.path.endswith("/history"):
            raw = b""
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_GET(self): self.handle_any()
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        if n: self.rfile.read(n)
        self.handle_any()
httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=cert, keyfile=key)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
with open(port_file, "w", encoding="utf-8") as pf:
    pf.write(str(httpd.server_address[1]))
httpd.serve_forever()
"#;
        std::fs::write(&script_path, py).unwrap();
        let child = Command::new("python3")
            .arg(&script_path)
            .arg(&srv_pem)
            .arg(&srv_key)
            .arg(&port_path)
            .arg(&log_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(wait_for(Duration::from_secs(10), || {
            std::fs::read_to_string(&port_path).ok().and_then(|s| s.trim().parse::<u16>().ok()).is_some()
        }));
        let port = std::fs::read_to_string(&port_path).unwrap().trim().parse::<u16>().unwrap();
        OfflineRecorder { port, ca_pem, log_path, child }
    }

    fn seed_login(&self, veil_home: &Path) {
        std::fs::create_dir_all(veil_home).unwrap();
        let ca = std::fs::read_to_string(&self.ca_pem).unwrap();
        let auth = format!("127.0.0.1:{}", self.port);
        let doc = serde_json::json!({
            "servers": {
                auth: {
                    "ca": ca,
                    "token": "OFFLINE_TEST_TOKEN",
                    "expires_at": veil_core::now_millis() + 3_600_000,
                    "person": "alice",
                }
            }
        });
        let p = veil_home.join("hub.json");
        std::fs::write(&p, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn hits(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log_path)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }
}

impl Drop for OfflineRecorder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn short_runtime() -> tempfile::TempDir {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_dir())
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let rt = tempfile::Builder::new().prefix("vp1-").tempdir_in(base).unwrap();
    std::fs::set_permissions(rt.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    rt
}

#[test]
fn p1pass_g5_ws_exec_confinement_isolates_private_folders_daemon_other_workspaces_and_network() {
    let env = Env::new();
    let _daemon = DaemonStop { env: &env, user: "alice" };
    let runtime = short_runtime();

    let proj = env.project("alice", "proj", &[("a.txt", "base\n"), ("src/lib.rs", "pub fn f() {}\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
    env.ok("alice", &proj, &["ws", "new", "other", "-r", "@-"]);

    // Populate `other` workspace's persistent sandbox and start the daemon.
    let other_run = env
        .cmd("alice", &proj, &["ws", "exec", "other", "--", "sh", "-c", "echo OTHER_WS_ISOLATED_DATA_5501 > other_only.txt"])
        .env("XDG_RUNTIME_DIR", runtime.path())
        .output()
        .unwrap();
    assert!(other_run.status.success(), "{}", text(&other_run));

    let st = env.ok("alice", &proj, &["status"]);
    assert!(!st.is_empty());
    let ds = env.ok("alice", &proj, &["daemon", "status"]);
    assert!(ds.contains("running"), "{ds}");

    let home = env.dir("fakehome");
    write(&home, ".config/veil/identity.json", "FAKE_CONFIG_VEIL_KEY_5502\n");
    write(&home, ".cache/veil/daemon/token", "FAKE_CACHE_DAEMON_5503\n");
    let veil_home = env.root.join("home-alice");
    let daemon_sock = veil_home.join("daemon/sock");
    assert!(daemon_sock.exists(), "daemon socket must exist on host");

    // Host loopback listener to verify network isolation (`--no-network` and default private-port isolation).
    let host_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let host_port = host_listener.local_addr().unwrap().port();

    // Run a confined verification inside `agent` with `--no-network`:
    // 1. workspace files are readable and writable;
    // 2. `.veil`, `$VEIL_HOME`, `~/.config/veil`, `~/.cache/veil`, the daemon socket, and `other`'s sandbox are not visible;
    // 3. `vl show other@` over the workspace socket is refused;
    // 4. host loopback TCP is unreachable under `--no-network`.
    let verify_py = format!(
        r#"
import os, pathlib, socket, subprocess, json

checks = {{}}
checks["own_file"] = pathlib.Path("a.txt").read_text() == "base\n"
pathlib.Path("agent_work.txt").write_text("done\n")

hidden_paths = [
    pathlib.Path(".veil/repo.json"),
    pathlib.Path({veil_home:?}) / "identity.json",
    pathlib.Path({daemon_sock:?}),
    pathlib.Path({other_sb:?}),
    pathlib.Path.home() / ".config/veil/identity.json",
    pathlib.Path.home() / ".cache/veil/daemon/token",
]
checks["private_hidden"] = all(not p.exists() for p in hidden_paths)

r = subprocess.run(["vl", "show", "other@"], capture_output=True, text=True)
checks["other_ws_refused"] = (r.returncode != 0 and "inside a sandbox" in (r.stdout + r.stderr))

net_blocked = False
try:
    s = socket.create_connection(("127.0.0.1", {host_port}), timeout=1.0)
    s.close()
except OSError:
    net_blocked = True
checks["no_network_holds"] = net_blocked

print(json.dumps(checks))
"#,
        veil_home = veil_home.to_str().unwrap(),
        daemon_sock = daemon_sock.to_str().unwrap(),
        other_sb = proj.join(".veil/local/sandboxes/other/files/other_only.txt").to_str().unwrap(),
    );

    let out = env
        .cmd("alice", &proj, &["ws", "exec", "agent", "--no-network", "--", "python3", "-c", &verify_py])
        .env("HOME", &home)
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "confined ws exec failed:\n{}", text(&out));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
    assert_eq!(report["own_file"], true, "{report}");
    assert_eq!(report["private_hidden"], true, "private Veil folders or daemon socket visible: {report}");
    assert_eq!(report["other_ws_refused"], true, "other workspace revision not refused: {report}");
    assert_eq!(report["no_network_holds"], true, "network reachable under --no-network: {report}");

    // Confirm the workspace recorded `agent_work.txt` while `other` remained untouched.
    assert_eq!(env.stdout("alice", &proj, &["ws", "cat", "agent", "agent_work.txt"]), "done\n");
    assert_eq!(
        env.stdout("alice", &proj, &["ws", "cat", "other", "other_only.txt"]),
        "OTHER_WS_ISOLATED_DATA_5501\n"
    );

    // Also verify `--private-ports` isolates host loopback ports (or refuses cleanly if `pasta` is absent).
    let port_check = format!(
        "import socket, sys\ntry:\n s = socket.create_connection(('127.0.0.1', {host_port}), timeout=1.0)\n s.close()\n sys.exit(1)\nexcept OSError:\n print('HOST_PORT_ISOLATED')\n"
    );
    let has_pasta = Command::new("pasta").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    let priv_ports = env
        .cmd("alice", &proj, &["ws", "exec", "agent", "--private-ports", "--", "python3", "-c", &port_check])
        .env("HOME", &home)
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    if has_pasta {
        assert!(priv_ports.status.success(), "host loopback port reachable under --private-ports:\n{}", text(&priv_ports));
        assert!(String::from_utf8_lossy(&priv_ports.stdout).contains("HOST_PORT_ISOLATED"));
    } else {
        assert!(!priv_ports.status.success() && text(&priv_ports).contains("pasta"), "{}", text(&priv_ports));
    }
    drop(host_listener);
}

#[test]
fn bug_1803_ws_socket_log_revsets_stay_within_workspace_and_offline_under_no_network() {
    let env = Env::new();
    let _daemon = DaemonStop { env: &env, user: "alice" };
    let runtime = short_runtime();

    let proj = env.project("alice", "proj", &[("a.txt", "v1\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
    env.ok("alice", &proj, &["ws", "new", "other", "-r", "@-"]);

    // Evict `other@`'s loose snapshot locally and turn `proj` into a thin clone (`partial`),
    // so traversing `other@` across `view.refs()` pages from `origin` over HTTPS.
    let other_snap = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&proj)), None, "default")
        .unwrap()
        .view()
        .workspaces["other"]
        .wc
        .hex();
    std::fs::remove_file(proj.join(".veil/objects").join(&other_snap[..2]).join(&other_snap[2..])).unwrap();

    let recorder = OfflineRecorder::start(&env, "rec-1803");
    let veil_home = env.root.join("home-alice");
    recorder.seed_login(&veil_home);
    let add_out = env
        .cmd("alice", &proj, &["remote", "add", "origin", &format!("veil://127.0.0.1:{}/proj", recorder.port)])
        .env("VEIL_KEY_SHARE", "0")
        .output()
        .unwrap();
    assert!(add_out.status.success(), "{}", text(&add_out));

    let cfg_path = proj.join(".veil/repo.json");
    let mut cfg: RepoConfig = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    cfg.partial = Some(PartialConfig { remote: "origin".into(), cache_limit: 32 << 20 });
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

    // Property that must hold inside `vl ws exec agent --no-network`:
    // 1. `vl log -r 'other@..@'` (referencing another workspace) is refused;
    // 2. `vl log -r 'agent(*..root()'` (an `agent(...)` revset across all refs) is refused;
    // 3. Zero remote HTTPS object-fetch requests occur while `--no-network` is set.
    let check_py = r#"
import json, subprocess

r_other = subprocess.run(["vl", "log", "-r", "other@..@"], capture_output=True, text=True)
r_agent = subprocess.run(["vl", "log", "-r", "agent(*..root()"], capture_output=True, text=True)
print(json.dumps({
    "other_refused": r_other.returncode != 0 and "inside a sandbox" in (r_other.stdout + r_other.stderr),
    "agent_refused": r_agent.returncode != 0 and "inside a sandbox" in (r_agent.stdout + r_agent.stderr),
}))
"#;

    let out = env
        .cmd("alice", &proj, &["ws", "exec", "agent", "--no-network", "--", "python3", "-c", check_py])
        .env("HOME", env.dir("fakehome-1803"))
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("VEIL_KEY_SHARE", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let res: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).lines().last().unwrap()).unwrap();
    let hits = recorder.hits();
    assert!(
        res["other_refused"] == true && res["agent_refused"] == true && hits.is_empty(),
        "workspace socket allowed cross-workspace / network-reaching `vl log -r` under --no-network: res={res}, remote_hits={hits:?}"
    );
}

/// Review `rv-client` (2026-11-10). BUG-1803's guarantee, `ws_socket.rs`:
/// "a thin clone never asks its server to place a revision a sandboxed
/// command named … and `--no-network` holds for the check too."
///
/// `NAME@tested` is a second way a revision reaches the server: `Ctx::rev`
/// asks `GET /v1/projects/{p}/tested/NAME` when the clone holds no such
/// remote tag, outside the store's `without_fetching`. The workspace's own
/// name passes the "names another workspace" check (`agent@tested`), and
/// `describe -r` and `new` are not checked for names at all.
#[test]
fn bug_1842_a_tested_revision_named_inside_a_sandbox_never_reaches_the_server_under_no_network() {
    let env = Env::new();
    let _daemon = DaemonStop { env: &env, user: "alice" };
    let runtime = short_runtime();

    let proj = env.project("alice", "proj", &[("a.txt", "v1\n")]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
    env.ok("alice", &proj, &["ws", "new", "other", "-r", "@-"]);

    let recorder = OfflineRecorder::start(&env, "rec-1842");
    let veil_home = env.root.join("home-alice");
    recorder.seed_login(&veil_home);
    let add_out = env
        .cmd("alice", &proj, &["remote", "add", "origin", &format!("veil://127.0.0.1:{}/proj", recorder.port)])
        .env("VEIL_KEY_SHARE", "0")
        .output()
        .unwrap();
    assert!(add_out.status.success(), "{}", text(&add_out));

    // Also test as a thin clone (`partial`) so 64-hex snapshot IDs and
    // snapshot/change prefixes would hit `deepen` / `server_names` if not
    // offline-gated.
    for partial in [false, true] {
        if partial {
            let cfg_path = proj.join(".veil/repo.json");
            let mut cfg: RepoConfig = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
            cfg.partial = Some(PartialConfig { remote: "origin".into(), cache_limit: 32 << 20 });
            std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        }
        let before = recorder.hits();

        let script = r#"
vl show 'agent@tested' >/dev/null 2>&1; echo "show=$?"
vl show 'origin/RVCLIENT@tested-' >/dev/null 2>&1; echo "show_origin=$?"
vl describe -r 'RVCLIENTBRANCH@tested' -m x >/dev/null 2>&1; echo "describe=$?"
vl new 'RVCLIENTNEW@tested' >/dev/null 2>&1; echo "new_tested=$?"
vl describe -r 'other@' -m x >/dev/null 2>&1; echo "describe_other=$?"
vl new 'other@' >/dev/null 2>&1; echo "new_other=$?"
vl show '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' >/dev/null 2>&1; echo "hex64=$?"
vl show '01234567' >/dev/null 2>&1; echo "prefix=$?"
vl status >/dev/null 2>&1; echo "status=$?"
"#;
        let out = env
            .cmd("alice", &proj, &["ws", "exec", "agent", "--no-network", "--", "bash", "-c", script])
            .env("HOME", env.dir(&format!("fakehome-1842-{partial}")))
            .env("XDG_RUNTIME_DIR", runtime.path())
            .env("VEIL_KEY_SHARE", "0")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "partial={partial}: {}", text(&out));
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        // The socket works in this run, and refuses every unheld / cross-workspace name.
        assert!(stdout.contains("status=0"), "partial={partial}: the workspace socket answers: {}", text(&out));
        for ok_zero in ["show=0", "show_origin=0", "describe=0", "new_tested=0", "describe_other=0", "new_other=0", "hex64=0", "prefix=0"] {
            assert!(!stdout.contains(ok_zero), "partial={partial}: {ok_zero} unexpectedly succeeded: {}", text(&out));
        }
        let hits: Vec<String> = recorder.hits().into_iter().skip(before.len()).collect();
        assert!(
            hits.is_empty(),
            "partial={partial}: under --no-network, revisions named inside the sandbox made the vl outside ask the server: {hits:?}"
        );
    }
}
