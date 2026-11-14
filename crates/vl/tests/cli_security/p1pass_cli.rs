//! Phase 1 final client security pass (`p1pass`): guarantees G1, G2, G3, G4,
//! G6 and reproductions for `BUG-1800`, `BUG-1801`, `BUG-1802`, and `BUG-1804`.

use crate::adversarial_support;

use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    time::Duration,
};

use adversarial_support::*;
use veil_core::{
    id::ChangeId,
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEntry, Visibility},
    oplog::Tag,
    policy::rule_scope_of,
    repo::{PartialConfig, RemoteConfig, RepoConfig, REPO_FORMAT},
    DiskBackend, ObjectId, Repo, StorageBackend,
};

/// A minimal local HTTPS mock Veil server (`python3` + self-signed EC cert)
/// that records every HTTP request it receives and serves configurable
/// `/tips`, `/objects`, `/push`, `/changes`, `/fetch`, and `/history` answers.
struct MockHub {
    dir: PathBuf,
    port: u16,
    ca_pem: PathBuf,
    log_path: PathBuf,
    child: Child,
}

impl MockHub {
    fn start(env: &Env, name: &str, state_json: &serde_json::Value) -> MockHub {
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
        let gen_ca = Command::new("openssl")
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
            .unwrap();
        assert!(gen_ca.success(), "openssl CA generation must succeed");
        let gen_csr = Command::new("openssl")
            .args([
                "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-keyout", srv_key.to_str().unwrap(), "-out", srv_csr.to_str().unwrap(),
                "-subj", "/CN=127.0.0.1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(gen_csr.success(), "openssl CSR generation must succeed");
        let gen_leaf = Command::new("openssl")
            .args([
                "x509", "-req", "-in", srv_csr.to_str().unwrap(),
                "-CA", ca_pem.to_str().unwrap(), "-CAkey", ca_key.to_str().unwrap(),
                "-CAcreateserial", "-out", srv_pem.to_str().unwrap(),
                "-days", "1", "-extfile", ext_cnf.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(gen_leaf.success(), "openssl leaf cert generation must succeed");

        let state_path = dir.join("state.json");
        std::fs::write(&state_path, serde_json::to_vec(state_json).unwrap()).unwrap();
        let port_path = dir.join("port.txt");
        let log_path = dir.join("requests.jsonl");
        let script_path = dir.join("server.py");

        let py = r#"
import base64, http.server, json, ssl, struct, sys

cert, key, state_file, port_file, log_file = sys.argv[1:6]
with open(state_file, "r", encoding="utf-8") as f:
    STATE = json.load(f)

def parse_frames(raw):
    out = []
    i = 0
    while i + 36 <= len(raw):
        oid = raw[i:i+32].hex()
        n = struct.unpack(">I", raw[i+32:i+36])[0]
        body = raw[i+36:i+36+n]
        out.append((oid, body))
        i += 36 + n
    return out

def pack_frames(items):
    buf = bytearray()
    for oid_hex, raw_b64 in items:
        raw = base64.b64decode(raw_b64)
        buf.extend(bytes.fromhex(oid_hex))
        buf.extend(struct.pack(">I", len(raw)))
        buf.extend(raw)
    return bytes(buf)

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def record(self, method, body):
        entry = {
            "method": method,
            "path": self.path,
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_utf8": body.decode("utf-8", "replace"),
        }
        with open(log_file, "a", encoding="utf-8") as lf:
            lf.write(json.dumps(entry) + "\n")

    def reply_json(self, code, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def reply_bytes(self, code, raw, ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.record("GET", b"")
        if self.path.endswith("/tips"):
            tips = STATE.get("tips")
            if tips is None:
                self.reply_json(404, {"code": "not_found", "message": "not found"})
            else:
                self.reply_json(200, tips)
        elif "/rings/" in self.path:
            self.reply_json(404, {"code": "not_found", "message": "no ring"})
        elif self.path.endswith("/keys/pending"):
            self.reply_json(200, [])
        elif self.path.endswith("/groups"):
            self.reply_json(200, [])
        else:
            self.reply_json(404, {"code": "not_found", "message": "unknown route"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n) if n > 0 else b""
        self.record("POST", body)
        if self.path.endswith("/objects"):
            frames = parse_frames(body)
            receipts = [f"rcpt-{i}-{oid[:12]}" for i, (oid, _) in enumerate(frames)]
            self.reply_json(200, {"stored": len(receipts), "receipts": receipts})
        elif self.path.endswith("/push"):
            if STATE.get("reject_push"):
                self.reply_json(403, {"code": "forbidden", "message": "personal key refused"})
                return
            req = json.loads(body.decode("utf-8"))
            results = []
            if STATE.get("tips") is None:
                STATE["tips"] = {
                    "branches": {},
                    "default_branch": "main",
                    "you": "alice",
                    "admin": True,
                    "revision": 1,
                }
            branches = STATE["tips"]["branches"]
            for u in req.get("updates", []):
                if u.get("new"):
                    branches[u["branch"]] = u["new"]
                results.append({"branch": u["branch"], "ok": True, "tip": u.get("new")})
            self.reply_json(200, {"results": results})
        elif self.path.endswith("/changes"):
            if STATE.get("reject_changes"):
                self.reply_json(403, {"code": "forbidden", "message": "rejected by server"})
                return
            snap = STATE.get("change_snapshot", "11" * 32)
            cid = STATE.get("change_id", "k" * 32)
            self.reply_json(200, {"change_id": cid, "snapshot": snap})
        elif self.path.endswith("/fetch"):
            req = json.loads(body.decode("utf-8"))
            fmap = STATE.get("fetch_map", {})
            items = []
            for w in req.get("objects", []):
                oid = w["id"]
                if oid not in fmap:
                    self.reply_json(404, {"code": "not_found", "message": "missing"})
                    return
                items.append(fmap[oid])
            self.reply_bytes(200, pack_frames(items))
        elif self.path.endswith("/history"):
            items = STATE.get("history_frames", [])
            self.reply_bytes(200, pack_frames(items))
        elif self.path.startswith("/v1/projects/"):
            if STATE.get("tips") is None:
                STATE["tips"] = {
                    "branches": {},
                    "default_branch": "main",
                    "you": "alice",
                    "admin": True,
                    "revision": 1,
                }
            self.reply_json(200, STATE["tips"])
        else:
            self.reply_json(404, {"code": "not_found", "message": "unknown post"})

httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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
            .arg(&state_path)
            .arg(&port_path)
            .arg(&log_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(
            wait_for(Duration::from_secs(10), || {
                std::fs::read_to_string(&port_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u16>().ok())
                    .is_some()
            }),
            "mock HTTPS server did not publish its port in {}",
            dir.display()
        );
        let port = std::fs::read_to_string(&port_path).unwrap().trim().parse::<u16>().unwrap();
        MockHub { dir, port, ca_pem, log_path, child }
    }

    fn url(&self, project: &str) -> String {
        format!("veil://127.0.0.1:{}/{project}", self.port)
    }

    fn authority(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Seed an owner-only (`0600`) `$VEIL_HOME/hub.json` entry with a live
    /// bearer token and the mock server's CA certificate.
    fn seed_login(&self, veil_home: &Path, person: &str, token: &str) {
        std::fs::create_dir_all(veil_home).unwrap();
        let ca = std::fs::read_to_string(&self.ca_pem).unwrap();
        let doc = serde_json::json!({
            "servers": {
                self.authority(): {
                    "ca": ca,
                    "token": token,
                    "expires_at": veil_core::now_millis() + 3_600_000,
                    "person": person,
                }
            }
        });
        let path = veil_home.join("hub.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn requests(&self) -> Vec<serde_json::Value> {
        let Ok(raw) = std::fs::read_to_string(&self.log_path) else {
            return Vec::new();
        };
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// Every raw request body decoded from base64, concatenated for substring
    /// scans, plus individual `(method, path, raw_bytes)` tuples.
    fn raw_requests(&self) -> Vec<(String, String, Vec<u8>)> {
        self.requests()
            .into_iter()
            .map(|v| {
                let b64 = v["body_b64"].as_str().unwrap_or("");
                let bytes = b64_decode(b64);
                (
                    v["method"].as_str().unwrap_or("").to_string(),
                    v["path"].as_str().unwrap_or("").to_string(),
                    bytes,
                )
            })
            .collect()
    }
}

impl Drop for MockHub {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = &self.dir;
    }
}

fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Vec<u8> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for c in bytes.chunks(4) {
        if c.len() < 4 {
            break;
        }
        let (Some(a), Some(b)) = (val(c[0]), val(c[1])) else { break };
        let n = (a << 18) | (b << 12) | (val(c[2]).unwrap_or(0) << 6) | val(c[3]).unwrap_or(0);
        out.push(((n >> 16) & 0xff) as u8);
        if c[2] != b'=' {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if c[3] != b'=' {
            out.push((n & 0xff) as u8);
        }
    }
    out
}

fn parse_frames(raw: &[u8]) -> Vec<(ObjectId, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 36 <= raw.len() {
        let id = ObjectId::from_hex(&hex::encode(&raw[i..i + 32])).unwrap();
        let n = u32::from_be_bytes(raw[i + 32..i + 36].try_into().unwrap()) as usize;
        out.push((id, raw[i + 36..i + 36 + n].to_vec()));
        i += 36 + n;
    }
    out
}

fn dir_contains_bytes(root: &Path, needle: &[u8]) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
            if m.is_dir() {
                stack.push(p);
            } else if m.is_file() {
                if let Ok(bytes) = std::fs::read(&p) {
                    if bytes.windows(needle.len()).any(|w| w == needle) {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

/// Guard stopping any daemon started under `home-<user>/daemon`.
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

fn copy_dir_all(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dst = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir_all(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), &dst).unwrap();
        }
    }
}

fn snapshot_bytes(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                stack.push(p);
            } else {
                out.insert(p.strip_prefix(dir).unwrap().to_path_buf(), std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

// ---- Guarantee 1 ------------------------------------------------------------------

#[test]
fn p1pass_g1_personal_keys_and_identity_secrets_stay_owner_only_and_out_of_outputs() {
    let env = Env::new();
    let _daemon = DaemonStop { env: &env, user: "alice" };

    // Create and rotate an identity, initialize a repo with a personal SSH key
    // (`id_ed25519`) in the working copy, start the daemon, and push to an HTTPS server.
    let created = env.ok("alice", &env.root, &["identity", "new", "--name", "alice"]);
    assert!(created.contains("Created identity"), "{created}");

    let proj = env.project("alice", "proj", &[("src/main.rs", "fn main() {}\n")]);
    let personal_ssh = "OPENSSH_PERSONAL_PRIVATE_KEY_9001_SECRET_MATERIAL";
    write(&proj, "id_ed25519", &format!("{personal_ssh}\n"));
    write(&proj, ".ssh/id_rsa", "RSA_PERSONAL_PRIVATE_KEY_9002_SECRET_MATERIAL\n");

    let rotated = env.ok("alice", &proj, &["identity", "new", "--force"]);
    assert!(rotated.contains("Created identity"), "{rotated}");

    let hub = MockHub::start(
        &env,
        "hub-g1",
        &serde_json::json!({
            "tips": null
        }),
    );
    let home = env.root.join("home-alice");
    hub.seed_login(&home, "alice", "SESSION_BEARER_SECRET_TOKEN_9003");
    env.ok("alice", &proj, &["remote", "add", "origin", &hub.url("proj")]);

    let show_txt = env.ok("alice", &proj, &["identity", "show"]);
    let st_json = env.stdout("alice", &proj, &["status", "--json"]);
    let c_out = env.ok("alice", &proj, &["commit", "-m", "work with local keys"]);
    assert!(c_out.contains("Committed"), "{c_out}");
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let push_out = env.ok("alice", &proj, &["push"]);
    assert!(push_out.contains("Pushed") || push_out.contains("main"), "{push_out}");
    let log_json = env.stdout("alice", &proj, &["log", "--json"]);
    let doc_out = env.ok("alice", &proj, &["doctor"]);
    let daemon_out = env.ok("alice", &proj, &["daemon", "status"]);

    // 1. Owner-only (0600) permissions on identity.json, retired/*, and hub.json.
    let id_path = home.join("identity.json");
    let id_mode = std::fs::symlink_metadata(&id_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(id_mode, 0o600, "identity.json must be 0600, got {id_mode:o}");

    let hub_mode = std::fs::symlink_metadata(home.join("hub.json")).unwrap().permissions().mode() & 0o777;
    assert_eq!(hub_mode, 0o600, "hub.json must be 0600, got {hub_mode:o}");

    let mut secret_needles: Vec<String> = vec![
        personal_ssh.to_string(),
        "RSA_PERSONAL_PRIVATE_KEY_9002_SECRET_MATERIAL".to_string(),
    ];
    let id_json: serde_json::Value = serde_json::from_slice(&std::fs::read(&id_path).unwrap()).unwrap();
    for field in ["signing_secret", "secret"] {
        if let Some(s) = id_json.get(field).and_then(|v| v.as_str()) {
            assert!(s.len() >= 32);
            secret_needles.push(s.to_string());
        }
    }
    let retired_entries: Vec<PathBuf> = std::fs::read_dir(home.join("retired"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(retired_entries.len(), 1);
    for rp in &retired_entries {
        let rmode = std::fs::symlink_metadata(rp).unwrap().permissions().mode() & 0o777;
        assert_eq!(rmode, 0o600, "retired key {} must be 0600, got {rmode:o}", rp.display());
        let rj: serde_json::Value = serde_json::from_slice(&std::fs::read(rp).unwrap()).unwrap();
        for field in ["signing_secret", "secret"] {
            if let Some(s) = rj.get(field).and_then(|v| v.as_str()) {
                secret_needles.push(s.to_string());
            }
        }
    }

    // 2. Under the default policy, working-copy personal keys are isolated and not tracked.
    let st_val: serde_json::Value = serde_json::from_str(&st_json).unwrap();
    let isolated: Vec<&str> = st_val["isolated"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["path"].as_str().or_else(|| v.as_str()))
        .collect();
    assert!(isolated.contains(&"id_ed25519"), "id_ed25519 must be isolated: {st_json}");
    let tracked = env.stdout("alice", &proj, &["files", "-r", "main"]);
    assert!(!tracked.contains("id_ed25519") && !tracked.contains("id_rsa"), "tracked files: {tracked}");

    // 3. No CLI output, JSON output, daemon state, or HTTP request contains any secret key.
    let combined = format!("{created}\n{rotated}\n{show_txt}\n{st_json}\n{c_out}\n{push_out}\n{log_json}\n{doc_out}\n{daemon_out}");
    for needle in &secret_needles {
        assert!(!combined.contains(needle), "secret material leaked in CLI output");
        for (_, path, body) in hub.raw_requests() {
            assert!(
                !body.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "secret material leaked in HTTP request to {path}"
            );
        }
        if home.join("daemon").exists() {
            assert!(
                dir_contains_bytes(&home.join("daemon"), needle.as_bytes()).is_none(),
                "secret material written under daemon folder"
            );
        }
    }
}

// ---- Guarantee 2 ------------------------------------------------------------------

#[test]
fn p1pass_g2_secret_files_are_sealed_on_push_thin_writeback_watcher_and_workspaces() {
    let env = Env::new();
    let _daemon = DaemonStop { env: &env, user: "alice" };

    let proj = env.project("alice", "proj", &[("src/lib.rs", "pub fn ok() {}\n")]);
    // Confirm `.veilpolicy` from `vl init` seals `.env` under `team`.
    let up = env.ok("alice", &proj, &["upgrade", "--sync-secrets"]);
    assert!(up.contains("already sync") || up.contains("Added the rules"), "{up}");

    let hub = MockHub::start(
        &env,
        "hub-g2",
        &serde_json::json!({
            "tips": null
        }),
    );
    let home = env.root.join("home-alice");
    hub.seed_login(&home, "alice", "TOKEN_G2_9910");
    env.ok("alice", &proj, &["remote", "add", "origin", &hub.url("proj")]);

    // Route 1 & 4: Watcher fast path + `vl push` over HTTPS.
    let _ = env.ok("alice", &proj, &["status"]); // registers watcher when supported
    let secret_push = "SECRET_ROUTE_PUSH_WATCH_VALUE_8801_NEVER_PLAIN";
    write(&proj, ".env", &format!("DB_URL={secret_push}\n"));
    let c1 = env.ok("alice", &proj, &["commit", "-m", "add sealed env"]);
    assert!(c1.contains("Committed"), "{c1}");
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let p1 = env.ok("alice", &proj, &["push"]);
    assert!(p1.contains("main"), "{p1}");

    // Route 2: API commit (`vl change new`) in the clone with accepted policy.
    let secret_api = "SECRET_ROUTE_API_COMMIT_VALUE_8802_NEVER_PLAIN";
    let base_hex = env
        .stdout("alice", &proj, &["log", "-n", "1", "-r", "main", "--json"])
        .lines()
        .find(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["entries"][0]["snapshot_id"].as_str().unwrap().to_string())
        .unwrap();
    let edits_path = env.root.join("edits-g2.json");
    std::fs::write(
        &edits_path,
        serde_json::to_vec(&serde_json::json!([
            { "path": ".env", "put": { "text": format!("DB_URL={secret_api}\n") } }
        ]))
        .unwrap(),
    )
    .unwrap();
    let api_out = env.ok("alice", &proj, &["change", "new", "--edits", edits_path.to_str().unwrap(), "--base", &base_hex, "-m", "api secret"]);
    assert!(api_out.contains("Change "), "{api_out}");

    // Verify `/changes` sent `put.object` (no `put.text`) and `/objects` carried `Object::Sealed`.
    let reqs = hub.raw_requests();
    let change_reqs: Vec<_> = reqs.iter().filter(|(_, p, _)| p.ends_with("/changes")).collect();
    assert_eq!(change_reqs.len(), 1);
    let change_body: serde_json::Value = serde_json::from_slice(&change_reqs[0].2).unwrap();
    assert!(change_body["edits"][0]["put"]["text"].is_null(), "put.text must be cleared: {change_body}");
    let api_obj_hex = change_body["edits"][0]["put"]["object"].as_str().expect("put.object set");
    let uploaded_frames: Vec<(ObjectId, Vec<u8>)> = reqs
        .iter()
        .filter(|(_, p, _)| p.ends_with("/objects"))
        .flat_map(|(_, _, b)| parse_frames(b))
        .collect();
    let (_, raw_api_obj) = uploaded_frames
        .iter()
        .find(|(id, _)| id.hex() == api_obj_hex)
        .expect("sealed object uploaded before /changes");
    assert!(
        matches!(Object::decode(raw_api_obj).unwrap(), Object::Sealed(_)),
        "API commit must upload Object::Sealed"
    );

    // Route 3: Thin-clone write-back (`partial` marker set on a clone pushing sealed `.env`).
    let thin = env.dir("thin-proj");
    copy_dir_all(&proj, &thin);
    let cfg_path = thin.join(".veil/repo.json");
    let mut cfg: RepoConfig = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    cfg.partial = Some(PartialConfig { remote: "origin".into(), cache_limit: 64 << 20 });
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    let secret_thin = "SECRET_ROUTE_THIN_WRITEBACK_VALUE_8803_NEVER_PLAIN";
    write(&thin, ".env", &format!("DB_URL={secret_thin}\n"));
    let ct = env.ok("alice", &thin, &["commit", "-m", "thin sealed edit"]);
    assert!(ct.contains("Committed"), "{ct}");
    env.ok("alice", &thin, &["tag", "set", "main", "-r", "@-"]);
    let pt = env.ok("alice", &thin, &["push"]);
    assert!(pt.contains("main"), "{pt}");

    // Route 5: Workspaces (`vl ws exec` recording `.env` sealed into `worker@` + pushing,
    // plus `--ephemeral` leaving zero decrypted copies in `$TMPDIR`).
    env.ok("alice", &proj, &["ws", "new", "worker", "-r", "main"]);
    let secret_ws = "SECRET_ROUTE_WORKSPACE_EXEC_VALUE_8804_NEVER_PLAIN";
    let ws_script = env.root.join("write-ws-env.sh");
    std::fs::write(&ws_script, format!("#!/bin/sh\nprintf 'DB_URL={secret_ws}\\n' > .env\n")).unwrap();
    let ws_out = env.ok(
        "alice",
        &proj,
        &["ws", "exec", "worker", "--unconfined", "--", "sh", ws_script.to_str().unwrap()],
    );
    assert!(ws_out.contains("Recorded"), "{ws_out}");
    assert_eq!(
        env.stdout("alice", &proj, &["ws", "cat", "worker", ".env"]),
        format!("DB_URL={secret_ws}\n")
    );
    env.ok("alice", &proj, &["tag", "set", "worker-branch", "-r", "worker@"]);
    let pw = env.ok("alice", &proj, &["push"]);
    assert!(pw.contains("worker-branch"), "{pw}");

    let secret_eph = "SECRET_ROUTE_EPHEMERAL_WS_VALUE_8805_NEVER_PLAIN";
    let eph_script = env.root.join("write-eph-env.sh");
    std::fs::write(&eph_script, format!("#!/bin/sh\nprintf 'DB_URL={secret_eph}\\n' > .env\n")).unwrap();
    let eph_out = env.ok(
        "alice",
        &proj,
        &["ws", "exec", "worker", "--ephemeral", "--unconfined", "--", "sh", eph_script.to_str().unwrap()],
    );
    assert!(!eph_out.contains("error"), "{eph_out}");

    // Confirm none of the 5 secret markers appear unencrypted in HTTP traffic, `.veil/objects`,
    // `.veil/ops`, `$TMPDIR`, or `$VEIL_HOME`.
    for marker in [secret_push, secret_api, secret_thin, secret_ws, secret_eph] {
        for (_, path, body) in hub.raw_requests() {
            assert!(
                !body.windows(marker.len()).any(|w| w == marker.as_bytes()),
                "plaintext secret {marker} sent on wire to {path}"
            );
        }
        for sub in [".veil/objects", ".veil/ops"] {
            assert!(
                dir_contains_bytes(&proj.join(sub), marker.as_bytes()).is_none(),
                "plaintext secret {marker} written under proj/{sub}"
            );
            assert!(
                dir_contains_bytes(&thin.join(sub), marker.as_bytes()).is_none(),
                "plaintext secret {marker} written under thin/{sub}"
            );
        }
        assert!(
            dir_contains_bytes(&env.root.join("tmp"), marker.as_bytes()).is_none(),
            "plaintext secret {marker} left in TMPDIR"
        );
        assert!(
            dir_contains_bytes(&home, marker.as_bytes()).is_none(),
            "plaintext secret {marker} written in VEIL_HOME"
        );
    }
}

// ---- Guarantee 3 ------------------------------------------------------------------

#[test]
fn p1pass_g3_hostile_server_answers_never_escape_execute_or_accept_mismatched_objects() {
    let env = Env::new();
    let _daemon = DaemonStop { env: &env, user: "alice" };

    let outside = env.dir("outside-target");
    let escape_marker = outside.join("escaped.txt");
    let hook_marker = outside.join("hook-executed");

    // 1. Canonical tree / VPath decoding refuses traversal, absolute, NUL, and `.veil` names.
    for bad_name in ["../escaped.txt", "/etc/passwd", "a/b.txt", ".veil", "bad\0name"] {
        let mut fake = b"veil:tree\n".to_vec();
        fake.extend_from_slice(
            serde_json::to_string(&serde_json::json!({
                "entries": [{
                    "name": bad_name,
                    "kind": "file",
                    "id": "22".repeat(32),
                    "size": 1,
                    "executable": false,
                    "visibility": "public"
                }]
            }))
            .unwrap()
            .as_bytes(),
        );
        assert!(Object::decode(&fake).is_err(), "Object::decode must reject tree entry {bad_name:?}");
    }

    // 2. Hostile remote snapshot with a symlink pointing to `outside` and an untrusted `.veilhooks`
    //    never writes through the symlink and never runs `.veilhooks` on clone or commit.
    let remote = env.dir("hostile-remote");
    evil_remote_on_disk(&remote, "hostile snapshot", &["main"], |r| {
        let link_id = blob(r, outside.to_str().unwrap().as_bytes());
        let hooks_id = blob(
            r,
            format!("[hooks]\npre-commit = \"touch {}\"\npost-checkout = \"touch {}\"\n", hook_marker.display(), hook_marker.display())
                .as_bytes(),
        );
        let readme_id = blob(r, b"safe\n");
        let mut entries = vec![
            TreeEntry {
                name: ".veilhooks".into(),
                kind: EntryKind::File,
                id: hooks_id,
                size: 0,
                executable: false,
                visibility: Visibility::Public,
            },
            file("README.md", readme_id),
            TreeEntry {
                name: "outlink".into(),
                kind: EntryKind::Symlink,
                id: link_id,
                size: 0,
                executable: false,
                visibility: Visibility::Public,
            },
        ];
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        raw_tree(r, entries)
    });

    let dest = env.root.join("victim-clone");
    let cl = env.vl("alice", &env.root, &["clone", remote.to_str().unwrap(), dest.to_str().unwrap()]);
    assert!(cl.status.success(), "{}", text(&cl));
    write(&dest, "local.txt", "edit\n");
    let cm = env.vl("alice", &dest, &["commit", "-m", "after untrusted clone"]);
    assert!(cm.status.success(), "{}", text(&cm));
    assert!(!hook_marker.exists(), "untrusted .veilhooks must never execute");
    assert!(!escape_marker.exists(), "nothing written outside working copy");

    // 3. Thin-clone `HubPromisor` verifies fetched objects against their ObjectIds:
    //    a valid object succeeds, while tampered bytes or mismatched ids are refused
    //    and never cached.
    let good_raw = Object::Blob(b"verified thin content\n".to_vec()).encode();
    let good_id = ObjectId::hash(&good_raw);
    let bad_expected_raw = Object::Blob(b"expected content\n".to_vec()).encode();
    let bad_id = ObjectId::hash(&bad_expected_raw);
    let tampered_raw = Object::Blob(b"TAMPERED_SERVER_PAYLOAD_7703\n".to_vec()).encode();

    let hub = MockHub::start(
        &env,
        "hub-g3",
        &serde_json::json!({
            "tips": {
                "branches": {},
                "default_branch": "main",
                "you": "alice",
                "admin": true,
                "revision": 4
            },
            "fetch_map": {
                good_id.hex(): [good_id.hex(), b64_encode(&good_raw)],
                bad_id.hex(): [bad_id.hex(), b64_encode(&tampered_raw)]
            }
        }),
    );
    let home = env.root.join("home-alice");
    hub.seed_login(&home, "alice", "TOKEN_G3_7703");

    // Build a format-10 thin clone whose snapshot references `good.txt` and `bad.txt`,
    // then remove both blobs from `.veil/objects` so `vl cat` fetches them via `HubPromisor`.
    let thin_dir = env.dir("thin-verify");
    env.ok("alice", &thin_dir, &["init"]);
    {
        let backend = Arc::new(DiskBackend::new(&thin_dir)) as Arc<dyn StorageBackend>;
        let id = veil_core::Identity::from_json(&std::fs::read_to_string(home.join("identity.json")).unwrap()).unwrap();
        let mut repo = Repo::open(backend.clone(), Some(id), "alice").unwrap();
        let mut entries = vec![
            TreeEntry {
                name: "bad.txt".into(),
                kind: EntryKind::File,
                id: bad_id,
                size: 17,
                executable: false,
                visibility: Visibility::Public,
            },
            TreeEntry {
                name: "good.txt".into(),
                kind: EntryKind::File,
                id: good_id,
                size: 22,
                executable: false,
                visibility: Visibility::Public,
            },
        ];
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let tree_id = repo.store().put(&Object::Tree(Tree { entries })).unwrap();
        let root_id = repo.root_id();
        let snap_id = repo
            .store()
            .put_snapshot(&Snapshot {
                parents: vec![root_id],
                change_id: ChangeId::random(),
                tree: tree_id,
                description: Text::Plain("thin snap".into()),
                author: "alice".into(),
                timestamp: 1,
                predecessors: vec![],
                conflicts: vec![],
                signature: None,
                embargo: None,
                agent: None,
                abandoned: None,
                attempts: vec![],
            })
            .unwrap();
        let mut tx = repo.transaction("seed thin").unwrap();
        tx.view.tags.insert("main".into(), Tag::new(snap_id));
        tx.view.remote_tags.insert("origin/main".into(), snap_id);
        tx.view.heads.insert(snap_id);
        tx.commit().unwrap();
    }
    let cfg_path = thin_dir.join(".veil/repo.json");
    let mut cfg: RepoConfig = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    cfg.remotes.insert(
        "origin".into(),
        RemoteConfig {
            url: hub.url("proj"),
            public: false,
            only: None,
            unknown: Default::default(),
        },
    );
    cfg.partial = Some(PartialConfig { remote: "origin".into(), cache_limit: 64 << 20 });
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

    // Valid object fetch succeeds and matches its id.
    let good_out = env.vl("alice", &thin_dir, &["cat", "good.txt", "-r", "main"]);
    assert!(good_out.status.success(), "{}", text(&good_out));
    assert_eq!(String::from_utf8_lossy(&good_out.stdout), "verified thin content\n");

    // Tampered object fetch is refused and never written to `.veil/cache` or stdout.
    let bad_out = env.vl("alice", &thin_dir, &["cat", "bad.txt", "-r", "main"]);
    assert!(!bad_out.status.success() && exited_cleanly(&bad_out), "{}", text(&bad_out));
    assert!(!text(&bad_out).contains("TAMPERED_SERVER_PAYLOAD_7703"), "{}", text(&bad_out));
    assert!(
        dir_contains_bytes(&thin_dir.join(".veil"), b"TAMPERED_SERVER_PAYLOAD_7703").is_none(),
        "tampered bytes must never be stored in .veil"
    );
    let fsck = env.vl("alice", &thin_dir, &["fsck"]);
    assert!(fsck.status.success(), "{}", text(&fsck));
}

// ---- Guarantee 4 ------------------------------------------------------------------

#[test]
fn p1pass_g4_daemon_store_sandboxes_and_watcher_state_enforce_owner_only_access() {
    let env = Env::new();
    let _daemon = DaemonStop { env: &env, user: "alice" };

    let proj = env.project("alice", "proj", &[("a.txt", "hello\n")]);
    env.ok("alice", &proj, &["ws", "new", "worker", "-r", "@-"]);

    // Trigger daemon + watcher registration, and create a persistent workspace sandbox.
    let st = env.ok("alice", &proj, &["status"]);
    assert!(st.contains("Working copy") || st.contains("No changes") || !st.is_empty(), "{st}");
    let ds = env.ok("alice", &proj, &["daemon", "status"]);
    assert!(ds.contains("running"), "daemon must start: {ds}");

    let ws_run = env.ok(
        "alice",
        &proj,
        &["ws", "exec", "worker", "--unconfined", "--", "sh", "-c", "echo sandbox-data > s.txt"],
    );
    assert!(ws_run.contains("Recorded") || !ws_run.contains("error"), "{ws_run}");

    // 1. Daemon folder (`0700`) and socket (`0600`).
    let home = env.root.join("home-alice");
    let daemon_dir = home.join("daemon");
    let dmode = std::fs::symlink_metadata(&daemon_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dmode, 0o700, "daemon dir must be 0700, got {dmode:o}");

    let sock_path = daemon_dir.join("sock");
    let smode = std::fs::symlink_metadata(&sock_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(smode, 0o600, "daemon socket must be 0600, got {smode:o}");

    if daemon_dir.join("store").exists() {
        let stmode = std::fs::symlink_metadata(daemon_dir.join("store")).unwrap().permissions().mode() & 0o777;
        assert_eq!(stmode, 0o700, "daemon store must be 0700, got {stmode:o}");
    }

    // 2. Persistent workspace sandboxes (`0700`).
    let sb_root = proj.join(".veil/local/sandboxes");
    let sb_mode = std::fs::symlink_metadata(&sb_root).unwrap().permissions().mode() & 0o777;
    assert_eq!(sb_mode, 0o700, "sandboxes root must be 0700, got {sb_mode:o}");
    let worker_sb = sb_root.join("worker");
    let w_mode = std::fs::symlink_metadata(&worker_sb).unwrap().permissions().mode() & 0o777;
    assert_eq!(w_mode, 0o700, "worker sandbox must be 0700, got {w_mode:o}");

    // 3. Shared `XDG_RUNTIME_DIR` (`0777`, without `VEIL_HOME`) is refused for the daemon socket,
    //    falling back to a private `0700` `~/.cache/veil/daemon/run` directory.
    let fake_home = env.dir("xdg-user-home");
    let shared_rt = env.dir("shared-runtime-0777");
    std::fs::set_permissions(&shared_rt, std::fs::Permissions::from_mode(0o777)).unwrap();
    let xdg_out = Command::new(env!("CARGO_BIN_EXE_vl"))
        .args(["daemon", "status"])
        .current_dir(&proj)
        .env_remove("VEIL_HOME")
        .env("HOME", &fake_home)
        .env_remove("XDG_CACHE_HOME")
        .env("XDG_RUNTIME_DIR", &shared_rt)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(xdg_out.status.success(), "{}", text(&xdg_out));
    assert!(
        !shared_rt.join("veil").exists(),
        "daemon must never place its socket inside a 0777 XDG_RUNTIME_DIR"
    );

    // 4. `vl doctor` detects overly permissive key files (`0644` on `identity.json`).
    std::fs::set_permissions(home.join("identity.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let doc_bad = env.vl("alice", &proj, &["doctor"]);
    assert!(!doc_bad.status.success(), "vl doctor must fail on 0644 identity.json: {}", text(&doc_bad));
    assert!(text(&doc_bad).contains("chmod 600"), "{}", text(&doc_bad));
    std::fs::set_permissions(home.join("identity.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
}

// ---- Guarantee 6 ------------------------------------------------------------------

#[test]
fn p1pass_g6_formats_8_to_10_upgrade_or_refuse_clearly_without_silent_loss() {
    let env = Env::new();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../veil-core/tests/fixtures");

    // 1. Dropped formats (< 6, e.g. format-5): refused clearly, nothing mutated.
    let f5 = env.dir("fx5");
    copy_dir_all(&fixtures.join("format-5"), &f5);
    let before_f5 = snapshot_bytes(&f5);
    let f5_open = Command::new(env!("CARGO_BIN_EXE_vl"))
        .args(["log"])
        .current_dir(f5.join("alice"))
        .env("VEIL_HOME", f5.join("home-alice"))
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(!f5_open.status.success(), "{}", text(&f5_open));
    assert!(text(&f5_open).contains("formats 1 to 5 were dropped") && text(&f5_open).contains("Nothing was changed"), "{}", text(&f5_open));
    let f5_up = Command::new(env!("CARGO_BIN_EXE_vl"))
        .args(["upgrade"])
        .current_dir(f5.join("alice"))
        .env("VEIL_HOME", f5.join("home-alice"))
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(!f5_up.status.success(), "{}", text(&f5_up));
    assert_eq!(before_f5, snapshot_bytes(&f5), "refused format-5 upgrade must mutate nothing");

    // 2. Format 8: opens cleanly, `--dry-run` mutates nothing, `vl upgrade` moves cleanly to format 10.
    let f8 = env.dir("fx8");
    copy_dir_all(&fixtures.join("format-8"), &f8);
    let f8_alice = f8.join("alice");
    let f8_home = f8.join("home-alice");
    // Background maintenance (`vl gc --auto`, started detached after a
    // command when it is due) is off for every command but the dry run:
    // once the fixture's last prune is a week old, the `vl log` below would
    // start one that runs on after `vl log` returned, into the snapshots
    // (BUG-2400). The dry run runs with it forced on, on a repository it is
    // due for, so a dry run that started maintenance would show in the
    // snapshot (the log line is written before the child starts).
    let run_f8_gc = |args: &[&str], gc: &str| -> Output {
        Command::new(env!("CARGO_BIN_EXE_vl"))
            .args(args)
            .current_dir(&f8_alice)
            .env("VEIL_HOME", &f8_home)
            .env("VEIL_USER", "alice")
            .env("NO_COLOR", "1")
            .env_remove("CI")
            .env("VEIL_GC_AUTO", gc)
            .output()
            .unwrap()
    };
    let run_f8 = |args: &[&str]| run_f8_gc(args, "0");
    let log_before = run_f8(&["log"]);
    assert!(log_before.status.success(), "format 8 must open cleanly: {}", text(&log_before));
    let last_prune: i64 = std::fs::read_to_string(f8_alice.join(".veil/local/gc/last-prune")).unwrap().trim().parse().unwrap();
    assert!(
        veil_core::now_millis() - last_prune > veil_core::maintenance::AUTO_PRUNE_AFTER.as_millis() as i64,
        "the fixture must be due for background maintenance"
    );

    let before_dry = snapshot_bytes(&f8_alice);
    let dry = run_f8_gc(&["upgrade", "--dry-run"], "1");
    assert!(dry.status.success(), "{}", text(&dry));
    assert!(
        text(&dry).contains(&format!("Would upgrade this repository from format 8 to format {REPO_FORMAT}")),
        "{}",
        text(&dry)
    );
    assert_eq!(before_dry, snapshot_bytes(&f8_alice), "--dry-run must not touch the repository");

    let up8 = run_f8(&["upgrade"]);
    assert!(up8.status.success(), "{}", text(&up8));
    assert!(
        text(&up8).contains(&format!("Upgraded this repository from format 8 to format {REPO_FORMAT}")),
        "{}",
        text(&up8)
    );
    let cfg8: serde_json::Value = serde_json::from_slice(&std::fs::read(f8_alice.join(".veil/repo.json")).unwrap()).unwrap();
    assert_eq!(cfg8["format"].as_u64(), Some(u64::from(REPO_FORMAT)));
    let fsck8 = run_f8(&["fsck"]);
    assert!(fsck8.status.success(), "{}", text(&fsck8));

    // 3. Format 9: requires `partial` marker (mismatched `partial` is refused as corrupt),
    //    and a valid format-9 thin clone upgrades cleanly to format 10 while keeping `partial`.
    let f9_bad = env.project("alice", "f9-no-partial", &[("a.txt", "a\n")]);
    let f9_bad_cfg_path = f9_bad.join(".veil/repo.json");
    let mut c_bad: serde_json::Value = serde_json::from_slice(&std::fs::read(&f9_bad_cfg_path).unwrap()).unwrap();
    c_bad["format"] = serde_json::json!(9);
    std::fs::write(&f9_bad_cfg_path, serde_json::to_vec_pretty(&c_bad).unwrap()).unwrap();
    let bad9 = env.vl("alice", &f9_bad, &["status"]);
    assert!(!bad9.status.success() && text(&bad9).contains("partial"), "format 9 without partial must fail: {}", text(&bad9));

    let f9 = env.project("alice", "f9-thin", &[("a.txt", "a\n")]);
    env.ok("alice", &f9, &["remote", "add", "origin", "veil://127.0.0.1:9/proj"]);
    let f9_cfg_path = f9.join(".veil/repo.json");
    let mut c9: RepoConfig = serde_json::from_slice(&std::fs::read(&f9_cfg_path).unwrap()).unwrap();
    c9.format = 9;
    c9.partial = Some(PartialConfig { remote: "origin".into(), cache_limit: 32 << 20 });
    std::fs::write(&f9_cfg_path, serde_json::to_vec_pretty(&c9).unwrap()).unwrap();
    let st9 = env.vl("alice", &f9, &["status"]);
    assert!(st9.status.success(), "valid format 9 thin clone must open: {}", text(&st9));
    let up9 = env.vl("alice", &f9, &["upgrade"]);
    assert!(up9.status.success(), "format 9 upgrade must succeed: {}", text(&up9));
    let c9_after: RepoConfig = serde_json::from_slice(&std::fs::read(&f9_cfg_path).unwrap()).unwrap();
    assert_eq!(c9_after.format, REPO_FORMAT);
    assert!(c9_after.partial.is_some(), "upgrading format 9 to 10 must preserve partial marker");

    // 4. Format 10 (already newest) + future format (99) & unknown repo.json field refused clearly.
    let up10 = env.vl("alice", &f9, &["upgrade"]);
    assert!(up10.status.success() && text(&up10).contains("already at format"), "{}", text(&up10));

    let f_future = env.project("alice", "f-future", &[("a.txt", "a\n")]);
    let fut_cfg_path = f_future.join(".veil/repo.json");
    let mut cfut: serde_json::Value = serde_json::from_slice(&std::fs::read(&fut_cfg_path).unwrap()).unwrap();
    cfut["future_unknown_flag"] = serde_json::json!(true);
    std::fs::write(&fut_cfg_path, serde_json::to_vec_pretty(&cfut).unwrap()).unwrap();
    let unk = env.vl("alice", &f_future, &["status"]);
    assert!(!unk.status.success() && text(&unk).contains("future_unknown_flag") && text(&unk).contains("Nothing was changed"), "{}", text(&unk));

    cfut.as_object_mut().unwrap().remove("future_unknown_flag");
    cfut["format"] = serde_json::json!(99);
    std::fs::write(&fut_cfg_path, serde_json::to_vec_pretty(&cfut).unwrap()).unwrap();
    let fut = env.vl("alice", &f_future, &["upgrade"]);
    assert!(!fut.status.success() && text(&fut).contains("format 99") && text(&fut).contains("newer vl"), "{}", text(&fut));
}

// ---- Ignored Bug Reproductions (BUG-1800, BUG-1801, BUG-1802, BUG-1804) -----------

#[test]
fn bug_1800_change_new_must_use_accepted_policy_and_refuse_personal_keys() {
    let env = Env::new();
    let upstream = env.dir("upstream-1800");
    veil_core::Repo::init_bare(std::sync::Arc::new(veil_core::DiskBackend::new(&upstream))).unwrap();

    let bob = env.project("bob", "bob-1800", &[("README.md", "hi\n")]);
    env.ok("bob", &bob, &["remote", "add", "origin", upstream.to_str().unwrap()]);
    env.ok("bob", &bob, &["push", "origin"]);

    let proj = env.root.join("alice-1800");
    env.ok("alice", &env.root, &["clone", upstream.to_str().unwrap(), proj.to_str().unwrap()]);

    // Bob pushes a `.veilpolicy` widening `.env` and `id_ed25519` to `public!`.
    write(&bob, ".veilpolicy", ".env public!\nid_ed25519 public!\n");
    env.ok("bob", &bob, &["commit", "-m", "widen policy"]);
    env.ok("bob", &bob, &["tag", "set", "main", "-r", "@-"]);
    env.ok("bob", &bob, &["push", "origin"]);

    // Alice pulls and switches to `main` WITHOUT running `vl policy accept`.
    // `vl status` confirms `.veilpolicy` is held back (`accepted: cloak team`, `wanted: public!`).
    env.ok("alice", &proj, &["pull", "origin"]);
    env.ok("alice", &proj, &["new", "main"]);
    write(&proj, ".env", "LOCAL_ONLY=1\n");
    let st: serde_json::Value = serde_json::from_str(&env.stdout("alice", &proj, &["status", "--json"])).unwrap();
    assert!(
        !st["policy_held_back"].as_array().unwrap().is_empty(),
        "under Alice's accepted policy, `.env` widening must be held back before `vl policy accept`: {st}"
    );

    let hub = MockHub::start(
        &env,
        "hub-1800",
        &serde_json::json!({
            "tips": {
                "branches": { "main": "11".repeat(32) },
                "default_branch": "main",
                "you": "alice",
                "admin": true,
                "revision": 1
            }
        }),
    );
    let home = env.root.join("home-alice");
    hub.seed_login(&home, "alice", "TOKEN_1800");
    env.ok("alice", &proj, &["remote", "rm", "origin"]);
    env.ok("alice", &proj, &["remote", "add", "origin", &hub.url("proj")]);

    let env_secret = "PLAIN_ENV_SECRET_LEAK_BUG_1800";
    let key_secret = "PLAIN_SSH_KEY_LEAK_BUG_1800";
    let edits_path = env.root.join("edits-1800.json");
    std::fs::write(
        &edits_path,
        serde_json::to_vec(&serde_json::json!([
            { "path": ".env", "put": { "text": format!("SECRET={env_secret}\n") } },
            { "path": "id_ed25519", "put": { "text": format!("{key_secret}\n") } }
        ]))
        .unwrap(),
    )
    .unwrap();

    let out = env.vl(
        "alice",
        &proj,
        &["change", "new", "--edits", edits_path.to_str().unwrap(), "--base", &"11".repeat(32), "-m", "api edit"],
    );
    let leaked_env = hub
        .raw_requests()
        .into_iter()
        .any(|(_, _, body)| body.windows(env_secret.len()).any(|w| w == env_secret.as_bytes()));
    let leaked_key = hub
        .raw_requests()
        .into_iter()
        .any(|(_, _, body)| body.windows(key_secret.len()).any(|w| w == key_secret.as_bytes()));
    assert!(
        !out.status.success() && !leaked_env && !leaked_key,
        "vl change new used unaccepted .veilpolicy and skipped personal_key check (exit={}, leaked_env={leaked_env}, leaked_key={leaked_key}): {}",
        out.status,
        text(&out)
    );
}

#[test]
fn class_1800_every_outbound_route_uses_accepted_policy_seals_secrets_and_refuses_personal_keys() {
    let env = Env::new();
    let upstream = env.dir("upstream-class-1800");
    veil_core::Repo::init_bare(std::sync::Arc::new(veil_core::DiskBackend::new(&upstream))).unwrap();

    // Alice initializes the project (holding the `team` key) and isolates `notes.secret`.
    let proj = env.project("alice", "alice-class-1800", &[("README.md", "hi\n")]);
    let base_policy = read(&proj, ".veilpolicy");
    write(&proj, ".veilpolicy", &format!("{base_policy}\nnotes.secret isolate\n"));
    env.ok("alice", &proj, &["commit", "-m", "isolate notes"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "origin", upstream.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "origin"]);

    // Bob clones and pushes an unaccepted `.veilpolicy` widening `.env`, `notes.secret`, and `id_rsa` to `public!`.
    let bob = env.root.join("bob-class-1800");
    env.ok("bob", &env.root, &["clone", upstream.to_str().unwrap(), bob.to_str().unwrap()]);
    write(&bob, ".veilpolicy", ".env public!\nnotes.secret public!\nid_rsa public!\n");
    env.ok("bob", &bob, &["commit", "-m", "hostile widen"]);
    env.ok("bob", &bob, &["tag", "set", "main", "-r", "@-"]);
    env.ok("bob", &bob, &["push", "origin"]);

    // Alice pulls WITHOUT running `vl policy accept`.
    env.ok("alice", &proj, &["pull", "origin"]);
    env.ok("alice", &proj, &["new", "main"]);

    let hub = MockHub::start(
        &env,
        "hub-class-1800",
        &serde_json::json!({
            "tips": {
                "branches": { "main": "22".repeat(32) },
                "default_branch": "main",
                "you": "alice",
                "admin": true,
                "revision": 1
            }
        }),
    );
    let home = env.root.join("home-alice");
    hub.seed_login(&home, "alice", "TOKEN_CLASS_1800");
    env.ok("alice", &proj, &["remote", "rm", "origin"]);
    env.ok("alice", &proj, &["remote", "add", "origin", &hub.url("proj")]);

    let has_marker = |marker: &str| {
        hub.raw_requests()
            .into_iter()
            .any(|(_, _, body)| body.windows(marker.len()).any(|w| w == marker.as_bytes()))
    };

    // 1. `vl change new` on `.env` classifies with Alice's accepted policy (`cloak team`),
    // sealing `.env` into `/objects` and sending `put.object` (never `put.text`) to `/changes`.
    let api_env_secret = "API_SEALED_ENV_SECRET_CLASS_1800";
    let env_edit = env.root.join("edit-env.json");
    std::fs::write(
        &env_edit,
        serde_json::to_vec(&serde_json::json!([
            { "path": ".env", "put": { "text": format!("SECRET={api_env_secret}\n") } }
        ]))
        .unwrap(),
    )
    .unwrap();
    env.ok(
        "alice",
        &proj,
        &["change", "new", "--edits", env_edit.to_str().unwrap(), "--base", &"22".repeat(32), "-m", "sealed env"],
    );
    assert!(!has_marker(api_env_secret), "vl change new sent .env plaintext instead of sealing under accepted policy");
    let change_reqs: Vec<serde_json::Value> = hub
        .raw_requests()
        .into_iter()
        .filter(|(m, p, _)| m == "POST" && p.ends_with("/changes"))
        .map(|(_, _, b)| serde_json::from_slice(&b).unwrap())
        .collect();
    assert_eq!(change_reqs.len(), 1);
    assert!(
        change_reqs[0]["edits"][0]["put"]["object"].is_string() && change_reqs[0]["edits"][0]["put"].get("text").is_none(),
        "expected sealed put.object on /changes, got: {}",
        change_reqs[0]
    );

    // 2. `vl change new` refuses personal keys, custom isolated files (even when unaccepted `.veilpolicy` says `public!`),
    // unsealed local `put.object` on `.env`, and `.env` outside any clone.
    let plain_readme_id = {
        let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&proj)), None, "alice").unwrap();
        let wc = repo.workspace_wc("default").unwrap();
        let tree = repo.snapshot(&wc).unwrap().tree;
        repo.store().tree(&tree).unwrap().get("README.md").unwrap().id.hex()
    };
    for (label, cwd, extra_args, edit_json, marker) in [
        (
            "personal key text",
            &proj,
            vec![],
            serde_json::json!([{ "path": "id_rsa", "put": { "text": "KEY_TEXT_CLASS_1800\n" } }]),
            Some("KEY_TEXT_CLASS_1800"),
        ),
        (
            "personal key object",
            &proj,
            vec![],
            serde_json::json!([{ "path": ".ssh/id_ed25519", "put": { "object": plain_readme_id } }]),
            None,
        ),
        (
            "accepted-isolated file text",
            &proj,
            vec![],
            serde_json::json!([{ "path": "notes.secret", "put": { "text": "ISOLATED_TEXT_CLASS_1800\n" } }]),
            Some("ISOLATED_TEXT_CLASS_1800"),
        ),
        (
            "accepted-isolated file object",
            &proj,
            vec![],
            serde_json::json!([{ "path": "notes.secret", "put": { "object": plain_readme_id } }]),
            None,
        ),
        (
            "unsealed object on cloaked .env",
            &proj,
            vec![],
            serde_json::json!([{ "path": ".env", "put": { "object": plain_readme_id } }]),
            None,
        ),
        (
            "cloneless .env object",
            &env.root,
            vec!["-p"],
            serde_json::json!([{ "path": ".env", "put": { "object": "33".repeat(32) } }]),
            None,
        ),
    ] {
        let p = env.root.join(format!("bad-{}.json", label.replace(' ', "-")));
        std::fs::write(&p, serde_json::to_vec(&edit_json).unwrap()).unwrap();
        let proj_url = hub.url("proj");
        let base_hex = "22".repeat(32);
        let mut args = vec!["change", "new"];
        if extra_args == vec!["-p"] {
            args.extend(["-p", proj_url.as_str()]);
        } else {
            args.extend(extra_args);
        }
        args.extend(["--edits", p.to_str().unwrap(), "--base", base_hex.as_str(), "-m", "bad"]);
        let out = env.vl("alice", cwd, &args);
        assert!(!out.status.success(), "{label} must be refused: {}", text(&out));
        if let Some(m) = marker {
            assert!(!has_marker(m), "{label} leaked {m}");
        }
    }

    // 3. `vl upgrade --rule-keys` refuses to read/rewrite while `.veilpolicy` has unaccepted changes.
    let upg = env.vl("alice", &proj, &["upgrade", "--rule-keys"]);
    assert!(!upg.status.success() && text(&upg).contains("unaccepted"), "{}", text(&upg));

    // 4. Working-copy snapshot + `vl push` seals `.env` under accepted policy and omits `notes.secret` and `id_ed25519`.
    let push_env = "PUSH_SEALED_ENV_CLASS_1800";
    let push_note = "PUSH_ISOLATED_NOTE_CLASS_1800";
    let push_key = "PUSH_PERSONAL_KEY_CLASS_1800";
    write(&proj, ".env", &format!("SECRET={push_env}\n"));
    write(&proj, "notes.secret", &format!("{push_note}\n"));
    write(&proj, "id_ed25519", &format!("{push_key}\n"));
    env.ok("alice", &proj, &["commit", "-m", "wc commit under accepted policy"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["push", "origin"]);
    for secret in [push_env, push_note, push_key] {
        assert!(!has_marker(secret), "vl push leaked {secret}");
    }
}

#[test]
fn bug_1801_access_line_grantee_edits_require_policy_accept_and_hold_back_in_ws_exec() {
    let env = Env::new();
    let upstream = env.dir("upstream-1801");
    veil_core::Repo::init_bare(std::sync::Arc::new(veil_core::DiskBackend::new(&upstream))).unwrap();

    let proj = env.project("alice", "proj", &[("src/app.rs", "pub fn run() {}\n")]);
    let fin_rule_scope = rule_scope_of("src/");
    env.ok("alice", &proj, &["scope", "create", &fin_rule_scope]);

    // Accept initial policy: `src/ public` (where `src/** cloak rule` seals `src/.env` to admins' `team`)
    // and `billing/ finance`.
    write(&proj, ".veilpolicy", "src/ public\nbilling/ finance\nsrc/** cloak rule\n");
    env.ok("alice", &proj, &["policy", "accept"]);
    write(&proj, "src/.env", "API_KEY=TEAM_ONLY_SECRET_1801_V1\n");
    env.ok("alice", &proj, &["commit", "-m", "initial policy and env"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "upstream", upstream.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "upstream"]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);

    // Part B first: Inside `vl ws exec`, a confined command rewriting `billing/ finance` -> `billing/ public`
    // widens folder visibility and must be held back, never recorded into `agent@`.
    let ws_out = env.ok(
        "alice",
        &proj,
        &[
            "ws",
            "exec",
            "agent",
            "--unconfined",
            "--",
            "sh",
            "-c",
            "printf 'src/ public\nbilling/ public\nsrc/** cloak rule\n' > .veilpolicy",
        ],
    );
    let recorded_policy = env.stdout("alice", &proj, &["ws", "cat", "agent", ".veilpolicy"]);

    // Part A: Bob pushes `src/ finance` (changing `src/ public` -> `src/ finance`, which redirects
    // `src/** cloak rule` from admins-only `team` to `fin_rule_scope` granted to `finance`), and Alice
    // pulls + switches to `main` WITHOUT running `vl policy accept`.
    let bob = env.root.join("bob-1801");
    env.ok("bob", &env.root, &["clone", upstream.to_str().unwrap(), bob.to_str().unwrap()]);
    write(&bob, ".veilpolicy", "src/ finance\nbilling/ finance\nsrc/** cloak rule\n");
    env.ok("bob", &bob, &["commit", "-m", "redirect src/ to finance"]);
    env.ok("bob", &bob, &["tag", "set", "main", "-r", "@-"]);
    env.ok("bob", &bob, &["push", "origin"]);

    env.ok("alice", &proj, &["pull", "upstream"]);
    env.ok("alice", &proj, &["new", "main"]);
    write(&proj, "src/.env", "API_KEY=TEAM_ONLY_SECRET_1801_V2\n");
    let st: serde_json::Value = serde_json::from_str(&env.stdout("alice", &proj, &["status", "--json"])).unwrap();
    let accepted_pin = read(&proj, ".veil/local/accepted-policy");
    let env_scope = st["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["path"] == "src/.env")
        .and_then(|c| c["visibility"]["scope"].as_str())
        .unwrap_or("");

    assert!(
        env_scope == "team" && accepted_pin.contains("src/ public") && recorded_policy.contains("billing/ finance"),
        "access-line grantee edits bypassed accepted-policy pin (accepted_pin={accepted_pin:?}, src/.env sealed to {env_scope:?} instead of \"team\" without `vl policy accept`) and ws exec command_policy (agent .veilpolicy={recorded_policy:?}; {ws_out})"
    );
}

#[test]
fn class_1801_any_grantee_change_needs_policy_accept_and_never_widens_in_ws_exec() {
    let env = Env::new();
    let upstream = env.dir("upstream-class-1801");
    veil_core::Repo::init_bare(Arc::new(DiskBackend::new(&upstream))).unwrap();

    let proj = env.project("alice", "proj-class-1801", &[("src/app.rs", "pub fn run() {}\n")]);
    for p in ["src", "src/secret", "billing"] {
        env.ok("alice", &proj, &["scope", "create", &rule_scope_of(p)]);
    }

    let initial = "src/ public\nsrc/secret/ ops\nbilling/ finance\n** cloak rule\n";
    write(&proj, ".veilpolicy", initial);
    env.ok("alice", &proj, &["policy", "accept"]);
    env.ok("alice", &proj, &["commit", "-m", "initial"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "upstream", upstream.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "upstream"]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);

    // Every confined command attempt that adds grantees, swaps grantees, adds writers to a public
    // folder, or drops an inner restricting rule must be held back in `agent@`.
    for attempt in [
        "src/ public devs\nsrc/secret/ ops\nbilling/ finance\n** cloak rule\n",
        "src/ public\nsrc/secret/ ops\nbilling/ finance eng\n** cloak rule\n",
        "src/ public\nsrc/secret/ ops\nbilling/ eng\n** cloak rule\n",
        "src/ public\nbilling/ finance\n** cloak rule\n",
    ] {
        let cmd = format!("printf %s {attempt:?} > .veilpolicy");
        let _ = env.ok("alice", &proj, &["ws", "exec", "agent", "--unconfined", "--", "sh", "-c", &cmd]);
        let recorded = env.stdout("alice", &proj, &["ws", "cat", "agent", ".veilpolicy"]);
        assert_eq!(recorded, initial, "confined command widened access with {attempt:?}: {recorded:?}");
    }

    // Pulling grantee changes (`billing/ finance` -> `billing/ finance carol` or `src/ public devs`)
    // never overwrites `.veil/local/accepted-policy` until `vl policy accept`.
    let bob = env.root.join("bob-class-1801");
    env.ok("bob", &env.root, &["clone", upstream.to_str().unwrap(), bob.to_str().unwrap()]);
    for (idx, remote_pol) in [
        "src/ public devs\nsrc/secret/ ops\nbilling/ finance\n** cloak rule\n",
        "src/ public\nsrc/secret/ ops\nbilling/ finance carol\n** cloak rule\n",
    ]
    .iter()
    .enumerate()
    {
        write(&bob, ".veilpolicy", remote_pol);
        env.ok("bob", &bob, &["commit", "-m", &format!("remote-{idx}")]);
        env.ok("bob", &bob, &["tag", "set", "main", "-r", "@-"]);
        env.ok("bob", &bob, &["push", "origin"]);

        env.ok("alice", &proj, &["pull", "upstream"]);
        env.ok("alice", &proj, &["new", "main"]);
        let _ = env.stdout("alice", &proj, &["status", "--json"]);
        let pin = read(&proj, ".veil/local/accepted-policy");
        assert_eq!(pin, initial, "pull #{idx} overwrote accepted-policy pin without accept: {pin:?}");
    }
    env.ok("alice", &proj, &["policy", "accept"]);
    assert!(read(&proj, ".veil/local/accepted-policy").contains("billing/ finance carol"));
}

#[test]
fn bug_1802_personal_private_keys_stay_isolated_and_never_upload_under_cloak_policy() {
    let env = Env::new();

    // A remote repository whose `.veilpolicy` contains `* cloak team`: cloning it
    // automatically pins `.veil/local/accepted-policy` with zero `vl policy accept`.
    let origin_bare = env.dir("origin-1802");
    evil_remote_on_disk(&origin_bare, "repo with broad cloak rule", &["main"], |r| {
        let pol = blob(r, b"* cloak team\n");
        raw_tree(r, vec![file(".veilpolicy", pol)])
    });

    let clone = env.root.join("clone-1802");
    let cl = env.vl("alice", &env.root, &["clone", origin_bare.to_str().unwrap(), clone.to_str().unwrap()]);
    assert!(cl.status.success(), "{}", text(&cl));
    env.ok("alice", &clone, &["scope", "create", "team"]);

    let hub = MockHub::start(
        &env,
        "hub-1802",
        &serde_json::json!({
            "tips": null,
            "reject_push": true
        }),
    );
    let home = env.root.join("home-alice");
    hub.seed_login(&home, "alice", "TOKEN_1802");
    env.ok("alice", &clone, &["remote", "add", "hub", &hub.url("proj")]);

    let key_marker = "PERSONAL_KEY_BYTES_NEVER_LEAVE_1802";
    write(&clone, "id_ed25519", &format!("{key_marker}\n"));
    write(&clone, "notes.txt", "work\n");
    let st: serde_json::Value = serde_json::from_str(&env.stdout("alice", &clone, &["status", "--json"])).unwrap();
    let isolated: Vec<&str> = st["isolated"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["path"].as_str().or_else(|| v.as_str()))
        .collect();
    assert!(isolated.contains(&"id_ed25519"), "vl status must report id_ed25519 as isolated: {st}");

    let cm = env.ok("alice", &clone, &["commit", "-m", "commit work"]);
    assert!(cm.contains("Committed"), "{cm}");
    env.ok("alice", &clone, &["tag", "set", "main", "-r", "@-"]);

    // Even before any push, `id_ed25519` must remain isolated and absent from the snapshot tree.
    let files = env.stdout("alice", &clone, &["files", "-r", "main"]);
    let _ = env.vl("alice", &clone, &["push", "hub"]);

    let leaked_in_objects = hub
        .raw_requests()
        .into_iter()
        .filter(|(_, p, _)| p.ends_with("/objects"))
        .any(|(_, _, body)| {
            body.windows(b"id_ed25519".len()).any(|w| w == b"id_ed25519")
                || body.windows(key_marker.len()).any(|w| w == key_marker.as_bytes())
        });
    assert!(
        !files.contains("id_ed25519") && !leaked_in_objects,
        "personal private key `id_ed25519` was recorded into snapshot (`{files}`) or uploaded (`leaked_in_objects={leaked_in_objects}`)"
    );
}

#[test]
fn class_1802_personal_private_keys_stay_isolated_under_every_policy_and_crafted_snapshots_never_upload() {
    let env = Env::new();
    let proj = env.project("alice", "proj-class-1802", &[("README.md", "hi\n")]);

    let policies = [
        "* cloak team\n",
        "** cloak rule\n",
        "* public!\n",
        "* public\n",
        "**/id_* ignore\n",
        "id_ed25519 public!\nid_rsa cloak team\nid_ecdsa ignore\nid_dsa public\n*.swp public!\n",
    ];
    let keys = [
        ("id_ed25519", "PK_ED25519_MARKER_1802"),
        (".ssh/id_rsa", "PK_RSA_MARKER_1802"),
        ("deploy/id_ecdsa", "PK_ECDSA_MARKER_1802"),
        ("keys/id_dsa", "PK_DSA_MARKER_1802"),
    ];
    for (p, marker) in keys {
        write(&proj, p, &format!("{marker}\n"));
    }
    write(&proj, "deploy/.id_ecdsa.swp", "PK_ECDSA_SWAP_1802\n");
    write(&proj, "deploy/id_ecdsa.bak", "PK_ECDSA_BAK_1802\n");

    for (idx, pol) in policies.iter().enumerate() {
        write(&proj, ".veilpolicy", pol);
        env.ok("alice", &proj, &["policy", "accept"]);
        let st: serde_json::Value = serde_json::from_str(&env.stdout("alice", &proj, &["status", "--json"])).unwrap();
        let isolated: Vec<&str> = st["isolated"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["path"].as_str().or_else(|| v.as_str()))
            .collect();
        for (k, _) in keys {
            assert!(isolated.contains(&k), "policy #{idx} ({pol:?}) failed to isolate {k}: {st}");
        }
        env.ok("alice", &proj, &["commit", "-m", &format!("policy-{idx}")]);
        let files = env.stdout("alice", &proj, &["files", "-r", "@-"]);
        for name in ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"] {
            assert!(!files.contains(name), "policy #{idx} ({pol:?}) recorded {name}: {files}");
        }
    }

    // Even under `* ignore` (which skips descending into ignored directories), root `id_ed25519`
    // is listed as isolated in `vl status` and `vl policy check` classifies every personal key as isolated.
    write(&proj, ".veilpolicy", "* ignore\n");
    env.ok("alice", &proj, &["policy", "accept"]);
    let st_ig: serde_json::Value = serde_json::from_str(&env.stdout("alice", &proj, &["status", "--json"])).unwrap();
    let iso_ig: Vec<&str> = st_ig["isolated"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
    assert!(iso_ig.contains(&"id_ed25519"), "{st_ig}");
    let chk = env.stdout("alice", &proj, &["policy", "check", "id_ed25519"]);
    assert!(chk.contains("isolate"), "{chk}");

    // Defense-in-depth: even if a crafted local snapshot tree directly contains `id_ed25519`,
    // both `vl push` to a Veil server and `vl push` to a path remote refuse BEFORE sending any object.
    let crafted_bare = env.dir("crafted-bare-1802");
    evil_remote_on_disk(&crafted_bare, "crafted personal key", &["main"], |r| {
        let k = blob(r, b"CRAFTED_PERSONAL_KEY_1802\n");
        raw_tree(r, vec![file("id_ed25519", k)])
    });
    let crafted = env.root.join("crafted-1802");
    env.ok("alice", &env.root, &["clone", crafted_bare.to_str().unwrap(), crafted.to_str().unwrap()]);
    let hub = MockHub::start(&env, "hub-crafted-1802", &serde_json::json!({ "tips": null }));
    let home = env.root.join("home-alice");
    hub.seed_login(&home, "alice", "TOKEN_CRAFTED_1802");
    env.ok("alice", &crafted, &["remote", "add", "hub", &hub.url("proj")]);
    let push_hub = env.vl("alice", &crafted, &["push", "hub"]);
    assert!(!push_hub.status.success() && text(&push_hub).contains("personal private key"), "{}", text(&push_hub));
    let uploaded = hub.raw_requests().into_iter().filter(|(_, p, _)| p.ends_with("/objects")).count();
    assert_eq!(uploaded, 0, "crafted personal key snapshot must fail before any /objects upload");

    let bare = env.dir("bare-1802");
    veil_core::Repo::init_bare(Arc::new(DiskBackend::new(&bare))).unwrap();
    env.ok("alice", &crafted, &["remote", "add", "disk", bare.to_str().unwrap()]);
    let push_disk = env.vl("alice", &crafted, &["push", "disk"]);
    assert!(!push_disk.status.success() && text(&push_disk).contains("personal private key"), "{}", text(&push_disk));
}

#[cfg(target_os = "linux")]
#[test]
fn bug_1804_watcher_tracks_nested_dot_veil_creation_and_removal_like_full_scan() {
    let env = Env::new();
    let _daemon = DaemonStop { env: &env, user: "alice" };

    let watched = env.dir("watched-1804");
    let scanned = env.dir("scanned-1804");
    for p in [&watched, &scanned] {
        write(p, "sub/hello.txt", "tracked in parent\n");
        env.ok("alice", p, &["init"]);
    }
    write(&scanned, ".veil/local/config.toml", "watch = false\n");
    for p in [&watched, &scanned] {
        env.ok("alice", p, &["commit", "-m", "initial"]);
    }

    // Register watcher on `watched` and confirm a watch token is recorded.
    let _ = env.stdout("alice", &watched, &["status", "--json"]);
    let _ = env.stdout("alice", &scanned, &["status", "--json"]);
    let ck: serde_json::Value =
        serde_json::from_slice(&std::fs::read(watched.join(".veil/local/checkout.json")).unwrap()).unwrap();
    assert!(ck.get("watch").is_some(), "watcher must record a watch token on Linux: {ck}");

    // Turning `sub/` into a nested Veil repository (`sub/.veil/repo.json`) makes a full scan
    // treat `sub/` as ignored (`sub/hello.txt` deleted); the watched repo must report the same.
    for p in [&watched, &scanned] {
        write(p, "sub/.veil/repo.json", "{}\n");
    }
    let st_w: serde_json::Value = serde_json::from_str(&env.stdout("alice", &watched, &["status", "--json"])).unwrap();
    let st_s: serde_json::Value = serde_json::from_str(&env.stdout("alice", &scanned, &["status", "--json"])).unwrap();
    assert!(!st_s["changes"].as_array().unwrap().is_empty(), "reference full scan detects nested .veil: {st_s}");
    assert_eq!(
        st_w["changes"], st_s["changes"],
        "watched status missed nested sub/.veil creation:\nwatched: {st_w}\nscanned: {st_s}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn class_1804_watcher_matches_full_scan_across_nested_dot_veil_transitions() {
    let env = Env::new();
    let _daemon = DaemonStop { env: &env, user: "alice" };

    let watched = env.dir("watched-class-1804");
    let scanned = env.dir("scanned-class-1804");
    for p in [&watched, &scanned] {
        write(p, "sub/hello.txt", "v1\n");
        write(p, "sub/deep/world.txt", "deep-v1\n");
        write(p, "a/b/leaf.txt", "leaf\n");
        write(p, "sym/file.txt", "sym\n");
        write(p, "reg/keep.txt", "keep\n");
        // `pre/` starts out as a nested repository BEFORE watcher registration.
        write(p, "pre/.veil/repo.json", "{}\n");
        write(p, "pre/deep/item.txt", "pre-item\n");
        env.ok("alice", p, &["init"]);
    }
    write(&scanned, ".veil/local/config.toml", "watch = false\n");
    for p in [&watched, &scanned] {
        env.ok("alice", p, &["commit", "-m", "initial"]);
    }

    let assert_parity = |step: &str| {
        let st_w: serde_json::Value = serde_json::from_str(&env.stdout("alice", &watched, &["status", "--json"])).unwrap();
        let st_s: serde_json::Value = serde_json::from_str(&env.stdout("alice", &scanned, &["status", "--json"])).unwrap();
        assert_eq!(
            st_w["changes"], st_s["changes"],
            "step '{step}': watched vs scanned diverged:\nwatched: {st_w}\nscanned: {st_s}"
        );
        st_w
    };

    // Prime watcher registration.
    assert_parity("initial registration");
    let ck: serde_json::Value =
        serde_json::from_slice(&std::fs::read(watched.join(".veil/local/checkout.json")).unwrap()).unwrap();
    assert!(ck.get("watch").is_some(), "watcher must record a watch token on Linux: {ck}");

    // 1. Removing `.veil` from pre-existing nested repo `pre/` exposes `pre/deep/item.txt`,
    // and subsequent edits inside `pre/deep/` are tracked by newly attached child watches.
    for p in [&watched, &scanned] {
        std::fs::remove_dir_all(p.join("pre/.veil")).unwrap();
    }
    let st = assert_parity("remove pre/.veil");
    assert!(!st["changes"].as_array().unwrap().is_empty(), "{st}");
    for p in [&watched, &scanned] {
        env.ok("alice", p, &["commit", "-m", "track pre"]);
        let _ = env.stdout("alice", p, &["status", "--json"]);
    }
    for p in [&watched, &scanned] {
        write(p, "pre/deep/item.txt", "pre-item-v2\n");
    }
    assert_parity("edit pre/deep/item.txt after un-nesting");

    // 2. Creating `sub/.veil`, committing deletion, then removing `sub/.veil` and editing `sub/deep/world.txt`.
    for p in [&watched, &scanned] {
        write(p, "sub/.veil/repo.json", "{}\n");
    }
    assert_parity("create sub/.veil");
    for p in [&watched, &scanned] {
        env.ok("alice", p, &["commit", "-m", "nested sub"]);
        let _ = env.stdout("alice", p, &["status", "--json"]);
    }
    for p in [&watched, &scanned] {
        std::fs::remove_dir_all(p.join("sub/.veil")).unwrap();
    }
    assert_parity("remove sub/.veil");
    for p in [&watched, &scanned] {
        write(p, "sub/deep/world.txt", "deep-v2\n");
    }
    assert_parity("edit sub/deep/world.txt after removing sub/.veil");

    // 3. Case-variant `a/b/.VEIL`, symlink `sym/.veil`, and regular file `reg/.veil` (not a repo).
    for p in [&watched, &scanned] {
        std::fs::create_dir_all(p.join("a/b/.VEIL")).unwrap();
        std::os::unix::fs::symlink("/nonexistent-veil-dir", p.join("sym/.veil")).unwrap();
        write(p, "reg/.veil", "plain file, not a repo\n");
    }
    assert_parity("case .VEIL, symlink .veil, and regular file .veil");
}
