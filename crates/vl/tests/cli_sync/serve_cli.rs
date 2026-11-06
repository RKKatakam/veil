//! `vl serve --local`, through the real `vl` binary and a raw socket client.
//!
//! * Every read method answers with the very document `vl … --json` prints,
//!   for a member and for a non-member (so it shows no more than the CLI).
//! * The write methods record the same operations (`vl undo` takes them
//!   back), and concurrent clients plus CLI commands stay correct.
//! * One server per repository; a stale socket is replaced; the socket is
//!   `0600` in a `0700` directory and is removed on SIGINT and SIGTERM.
//! * Malformed, oversized and abusive requests get JSON-RPC errors and
//!   never take the server down.

use crate::adversarial_support;

use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Output},
    time::Duration,
};

use adversarial_support::*;
use serde_json::{json, Value};

// ---- a server and a client ---------------------------------------------------------------

struct Server {
    child: Option<Child>,
    sock: PathBuf,
}

fn sock_of(dir: &Path) -> PathBuf {
    dir.join(".veil/local/sock")
}

impl Server {
    fn start(env: &Env, user: &str, dir: &Path) -> Server {
        Server::start_with(env, user, dir, &["serve", "--local"])
    }

    fn start_with(env: &Env, user: &str, dir: &Path, args: &[&str]) -> Server {
        let mut child = env.spawn(user, dir, args);
        let sock = sock_of(dir);
        let up = wait_for(Duration::from_secs(20), || {
            if let Ok(Some(_)) = child.try_wait() {
                return true;
            }
            UnixStream::connect(&sock).is_ok()
        });
        if let Ok(Some(_)) = child.try_wait() {
            let out = child.wait_with_output().unwrap();
            panic!("vl serve exited early:\n{}", text(&out));
        }
        assert!(up, "vl serve did not start listening on {}", sock.display());
        Server { child: Some(child), sock }
    }

    fn conn(&self) -> Conn {
        Conn::open(&self.sock)
    }

    fn pid(&self) -> i32 {
        self.child.as_ref().unwrap().id() as i32
    }

    /// Send `sig` and wait for the server to exit.
    fn stop(mut self, sig: i32) -> Output {
        let child = self.child.take().unwrap();
        unsafe { libc::kill(child.id() as i32, sig) };
        child.wait_with_output().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

struct Conn {
    r: BufReader<UnixStream>,
    w: UnixStream,
    next_id: u64,
}

impl Conn {
    fn open(sock: &Path) -> Conn {
        let s = UnixStream::connect(sock).unwrap_or_else(|e| panic!("connect {}: {e}", sock.display()));
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        Conn { w: s.try_clone().unwrap(), r: BufReader::new(s), next_id: 1 }
    }

    fn send(&mut self, line: &str) {
        self.w.write_all(line.as_bytes()).unwrap();
        self.w.write_all(b"\n").unwrap();
    }

    /// The next line, raw; `None` at end of stream.
    fn recv_line(&mut self) -> Option<String> {
        let mut l = String::new();
        match self.r.read_line(&mut l) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(l),
        }
    }

    fn recv(&mut self) -> Value {
        let l = self.recv_line().expect("a response");
        assert!(l.ends_with('\n'));
        serde_json::from_str(&l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}"))
    }

    /// The full response to `method(params)`.
    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string());
        let v = self.recv();
        assert_eq!(v["jsonrpc"], "2.0", "{v}");
        assert_eq!(v["id"], id, "{v}");
        v
    }

    /// The result of `method(params)`, which must succeed.
    fn ok(&mut self, method: &str, params: Value) -> Value {
        let v = self.call(method, params.clone());
        assert!(v.get("error").is_none(), "{method}({params}) failed: {v}");
        v["result"].clone()
    }

    /// The error code of `method(params)`, which must fail.
    fn err(&mut self, method: &str, params: Value) -> (i64, Value) {
        let v = self.call(method, params.clone());
        assert!(v.get("result").is_none(), "{method}({params}) succeeded: {v}");
        (v["error"]["code"].as_i64().unwrap(), v["error"].clone())
    }
}

fn cli_json(env: &Env, user: &str, dir: &Path, args: &[&str]) -> Value {
    let out = env.vl(user, dir, args);
    let s = String::from_utf8(out.stdout.clone()).unwrap();
    assert_eq!(s.lines().count(), 1, "vl {args:?}: {}", text(&out));
    serde_json::from_str(&s).unwrap()
}

fn write_stdin(env: &Env, user: &str, dir: &Path, args: &[&str], input: &[u8]) {
    let mut c = env.cmd(user, dir, args);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "vl {args:?}: {}", text(&out));
}

// ---- the scenario ----------------------------------------------------------------------

const CLOAKED_TEXT: &str = "CLOAKED-PLAN-4417";
const CLOAKED_DESC: &str = "CLOAKED-DESCRIPTION-9902";
const ISOLATED_TEXT: &str = "ISOLATED-VALUE-6623";
const VAULT_VALUE: &str = "VAULT-VALUE-1187";

/// Alice's project (public, cloaked and isolated files, a cloaked
/// workspace with a sealed description, a cloaked tag, a vault secret) and
/// Bob's clone of it, without a key for `team`.
fn world() -> (Env, PathBuf, PathBuf) {
    let env = Env::new();
    let alice = env.dir("alice");
    write(&alice, "README.md", "hello\n");
    write(&alice, "internal/plan.md", &format!("{CLOAKED_TEXT}\n"));
    write(&alice, ".netrc", &format!("API={ISOLATED_TEXT}\n"));
    write(&alice, "policy.txt", "");
    env.ok("alice", &alice, &["init"]);
    env.ok("alice", &alice, &["cloak", "internal/"]);
    env.ok("alice", &alice, &["commit", "-m", "initial"]);
    env.ok("alice", &alice, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &alice, &["secret", "set", "API_TOKEN", VAULT_VALUE]);
    env.ok("alice", &alice, &["secret", "set", "--scope", "team", "TEAM_TOKEN", VAULT_VALUE]);
    env.ok("alice", &alice, &["ws", "new", "plan", "-r", "main", "--cloak", "team"]);
    write_stdin(&env, "alice", &alice, &["ws", "write", "plan", "internal/plan.md"], format!("{CLOAKED_TEXT} v2\n").as_bytes());
    env.ok("alice", &alice, &["describe", "-r", "plan@", "-m", CLOAKED_DESC]);
    env.ok("alice", &alice, &["tag", "set", "plan-tag", "-r", "plan@", "--cloak", "team"]);
    write(&alice, "README.md", "hello\nworld\n");
    let team = env.root.join("team");
    env.ok("alice", &alice, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    (env, alice, bob)
}

/// Every read command, as CLI arguments and as a method call.
fn read_pairs(env: &Env, user: &str, dir: &Path) -> Vec<(Vec<String>, &'static str, Value)> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let mut pairs = vec![
        (s(&["status"]), "status", json!({})),
        (s(&["log"]), "log", json!({})),
        (s(&["log", "-n", "2"]), "log", json!({"limit": 2})),
        (s(&["diff"]), "diff", json!({})),
        (s(&["diff", "--from", "root()", "--to", "@"]), "diff", json!({"from": "root()", "to": "@"})),
        (s(&["diff", "--from", "root()", "--stat"]), "diff", json!({"from": "root()", "stat": true})),
        (s(&["show"]), "show", json!({})),
        (s(&["show", "main"]), "show", json!({"rev": "main"})),
        (s(&["show", "@-", "--stat"]), "show", json!({"rev": "@-", "stat": true})),
        (s(&["ws", "list"]), "ws.list", json!({})),
        (s(&["workspace", "list"]), "workspace.list", json!({})),
        (s(&["tag", "list"]), "tag.list", json!({})),
        (s(&["op", "log"]), "op.log", json!({})),
        (s(&["op", "log", "-n", "3"]), "op.log", json!({"limit": 3})),
        (s(&["scan"]), "scan", json!({})),
        (s(&["secret", "list"]), "secret.list", json!({})),
    ];
    // A team vault, for its member (BUG-494).
    if user == "alice" {
        pairs.push((s(&["secret", "list", "--scope", "team"]), "secret.list", json!({"scope": "team"})));
        pairs.push((
            s(&["secret", "list", "--scope", "team", "--exposed-to", "alice"]),
            "secret.list",
            json!({"scope": "team", "exposed_to": "alice"}),
        ));
    }
    // Every snapshot in the log, through show and diff.
    let log = cli_json(env, user, dir, &["--no-snapshot", "log", "--json"]);
    for e in log["entries"].as_array().unwrap() {
        let id = e["snapshot_id"].as_str().unwrap().to_string();
        pairs.push((vec!["show".into(), id.clone()], "show", json!({"rev": id})));
        pairs.push((vec!["diff".into(), "-r".into(), id.clone()], "diff", json!({"rev": id})));
    }
    pairs
}

/// The server's documents and the CLI's, for every read command, as `user`.
fn compare_all(env: &Env, user: &str, dir: &Path) -> String {
    // Settle the working copy first, so neither side records anything.
    env.ok(user, dir, &["status"]);
    let server = Server::start(env, user, dir);
    let mut c = server.conn();
    let mut all = String::new();
    for (args, method, params) in read_pairs(env, user, dir) {
        let mut cli: Vec<&str> = vec!["--no-snapshot"];
        cli.extend(args.iter().map(String::as_str));
        cli.push("--json");
        let want = cli_json(env, user, dir, &cli);
        let mut p = params.clone();
        p["snapshot"] = json!(false);
        let got = c.ok(method, p);
        assert_eq!(got, want, "{user}: {method}({params}) differs from vl {args:?} --json");
        // With the default (snapshot first, as the CLI does), too.
        let mut cli: Vec<&str> = args.iter().map(String::as_str).collect();
        cli.push("--json");
        let want = cli_json(env, user, dir, &cli);
        let got = c.ok(method, params.clone());
        assert_eq!(got, want, "{user}: {method}({params}) with a snapshot differs from vl {args:?} --json");
        all.push_str(&got.to_string());
    }
    all
}

// ---- tests -------------------------------------------------------------------------

#[test]
fn every_read_method_returns_the_clis_json_document() {
    let (env, alice, bob) = world();
    let a = compare_all(&env, "alice", &alice);
    assert!(a.contains(CLOAKED_TEXT) && a.contains(CLOAKED_DESC), "alice is a member and reads it");
    for secret in [ISOLATED_TEXT, VAULT_VALUE] {
        assert!(!a.contains(secret), "{secret} reached a document");
    }
    // Bob holds no key: the server shows him no more than his CLI does.
    let b = compare_all(&env, "bob", &bob);
    for secret in [CLOAKED_TEXT, CLOAKED_DESC, ISOLATED_TEXT, VAULT_VALUE] {
        assert!(!b.contains(secret), "{secret} reached bob");
    }
    assert!(b.contains("no_key"));
}

#[test]
fn the_byte_for_byte_result_is_the_clis_line() {
    let (env, alice, _) = world();
    env.ok("alice", &alice, &["status"]);
    let server = Server::start(&env, "alice", &alice);
    let mut c = server.conn();
    c.send(r#"{"jsonrpc":"2.0","id":"x","method":"log","params":{"snapshot":false}}"#);
    let line = c.recv_line().unwrap();
    let cli = env.stdout("alice", &alice, &["--no-snapshot", "log", "--json"]);
    assert_eq!(line, format!("{{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"result\":{}}}\n", cli.trim_end()));
    // And `--call` prints exactly the CLI's line.
    let call = env.stdout("alice", &alice, &["serve", "--call", "log", r#"{"snapshot": false}"#]);
    assert_eq!(call, cli);
}

#[test]
fn scan_gate_policy_must_lie_inside_the_repository() {
    let (env, alice, _) = world();
    let server = Server::start(&env, "alice", &alice);
    let mut c = server.conn();
    let want = cli_json(&env, "alice", &alice, &["scan", "--policy-from", "policy.txt", "--json"]);
    assert_eq!(c.ok("scan", json!({"policy_from": "policy.txt"})), want);
    write(&env.root, "outside.txt", "");
    std::os::unix::fs::symlink(env.root.join("outside.txt"), alice.join("link.txt")).unwrap();
    for bad in ["/etc/passwd", "../outside.txt", "link.txt", ".veil/repo.json", ".veil/local", "missing.txt"] {
        let (code, e) = c.err("scan", json!({"policy_from": bad}));
        assert!(code == -32602 || code == -32000, "{bad}: {e}");
    }
    let (code, _) = c.err("scan", json!({"policy_from": "policy.txt", "snapshot": true}));
    assert_eq!(code, -32602);
}

#[test]
fn write_methods_record_operations_that_undo_takes_back() {
    let (env, alice, _) = world();
    let server = Server::start(&env, "alice", &alice);
    let mut c = server.conn();

    write(&alice, "new.txt", "from the editor\n");
    let r = c.ok("snapshot", json!({}));
    assert_eq!(r["schema"], "veil.snapshot/1");
    let st = c.ok("status", json!({"snapshot": false}));
    assert!(st["changes"].as_array().unwrap().iter().any(|ch| ch["path"] == "new.txt"), "{st}");
    assert_eq!(st["working_copy"]["snapshot_id"], r["working_copy"]["snapshot_id"]);
    assert_eq!(c.ok("op.log", json!({"limit": 1, "snapshot": false}))["operations"][0]["op_id"], r["operation"]["op_id"]);

    let d = c.ok("describe", json!({"message": "described over the socket"}));
    assert_eq!(d["schema"], "veil.describe/1");
    assert_eq!(d["described"]["description"], "described over the socket");
    assert_eq!(cli_json(&env, "alice", &alice, &["show", "--json"])["description"], "described over the socket");

    let before = cli_json(&env, "alice", &alice, &["show", "--json"]);
    let cm = c.ok("commit", json!({"message": "committed over the socket"}));
    assert_eq!(cm["schema"], "veil.commit/1");
    assert_eq!(cm["committed"]["description"], "committed over the socket");
    assert_eq!(cm["committed"]["change_id"], before["change_id"]);
    assert_eq!(cm["working_copy"]["empty"], true);
    let at = cli_json(&env, "alice", &alice, &["show", "--json"]);
    assert_eq!(at["snapshot_id"], cm["working_copy"]["snapshot_id"]);
    // The same operation the CLI records: `vl undo` takes it back.
    env.ok("alice", &alice, &["undo"]);
    let at = cli_json(&env, "alice", &alice, &["show", "--json"]);
    assert_eq!(at["change_id"], before["change_id"]);
    assert_eq!(at["description"], "described over the socket");

    let n = c.ok("new", json!({"message": "next"}));
    assert_eq!(n["schema"], "veil.new/1");
    assert_eq!(n["working_copy"]["description"], "next");
    assert_eq!(cli_json(&env, "alice", &alice, &["show", "--json"])["snapshot_id"], n["working_copy"]["snapshot_id"]);
    env.ok("alice", &alice, &["undo"]);
    assert_eq!(cli_json(&env, "alice", &alice, &["show", "--json"])["change_id"], before["change_id"]);

    // A tag at the parent moves with the commit; `no_advance` keeps it.
    env.ok("alice", &alice, &["tag", "set", "here", "-r", "@-"]);
    let cm = c.ok("commit", json!({"message": "keep", "no_advance": true}));
    assert!(cm["kept"].as_array().unwrap().contains(&json!({"name": "here", "reason": "no_advance", "scope": null})), "{cm}");
    let cm = c.ok("commit", json!({"message": "x"}));
    assert_eq!(cm["advanced"], json!([]));

    // A failing write is a command error with its veil.error/1 document.
    let (code, e) = c.err("describe", json!({"rev": "no-such-rev", "message": "m"}));
    assert_eq!(code, -32000);
    assert_eq!(e["data"]["schema"], "veil.error/1");
    assert!(e["message"].as_str().unwrap().contains("no-such-rev"), "{e}");
    let _ = env.ok("alice", &alice, &["fsck"]);
}

#[test]
fn no_stale_data_after_a_cli_command() {
    let (env, alice, _) = world();
    let server = Server::start(&env, "alice", &alice);
    let mut c = server.conn();
    let before = c.ok("log", json!({"limit": 1}));
    env.ok("alice", &alice, &["describe", "-m", "changed by the CLI"]);
    let after = c.ok("log", json!({"limit": 1, "snapshot": false}));
    assert_ne!(before, after);
    assert_eq!(after["entries"][0]["description"], "changed by the CLI");
    env.ok("alice", &alice, &["tag", "set", "fresh", "-r", "@"]);
    let tags = c.ok("tag.list", json!({"snapshot": false}));
    assert!(tags["tags"].as_array().unwrap().iter().any(|t| t["name"] == "fresh"));
    // Edits on disk are seen by the next request that snapshots.
    write(&alice, "edited.txt", "x\n");
    let st = c.ok("status", json!({}));
    assert!(st["changes"].as_array().unwrap().iter().any(|ch| ch["path"] == "edited.txt"), "{st}");
}

#[test]
fn concurrent_clients_and_cli_writes_stay_correct() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    let server = Server::start(&env, "alice", &p);
    let sock = server.sock.clone();
    const CLIENTS: usize = 4;
    const ROUNDS: usize = 6;
    let threads: Vec<_> = (0..CLIENTS)
        .map(|i| {
            let sock = sock.clone();
            let p = p.clone();
            std::thread::spawn(move || {
                let mut c = Conn::open(&sock);
                for k in 0..ROUNDS {
                    write(&p, &format!("server-{i}-{k}.txt"), "x\n");
                    c.ok("status", json!({}));
                    c.ok("log", json!({"limit": 3, "snapshot": false}));
                    // As for the CLI below: "keeps moving, try again" did nothing.
                    let committed = (0..20).any(|_| {
                        let r = c.call("commit", json!({"message": format!("server {i} {k}")}));
                        let moving = r["error"]["message"].as_str().is_some_and(|m| m.contains("keeps moving"));
                        assert!(r.get("result").is_some() || moving, "{r}");
                        r.get("result").is_some()
                    });
                    assert!(committed);
                    c.ok("op.log", json!({"snapshot": false}));
                }
            })
        })
        .collect();
    for k in 0..ROUNDS {
        write(&p, &format!("cli-{k}.txt"), "y\n");
        // Under four clients committing in a loop, a command may be told
        // that the working copy keeps moving and to try again: it then did
        // nothing, and trying again is what the message asks.
        let msg = format!("cli {k}");
        let committed = (0..20).any(|_| {
            let out = env.vl("alice", &p, &["commit", "-m", &msg]);
            assert!(out.status.success() || text(&out).contains("keeps moving"), "{}", text(&out));
            out.status.success()
        });
        assert!(committed, "vl commit kept being told to try again");
        env.ok("alice", &p, &["--no-snapshot", "log", "-n", "2"]);
    }
    for t in threads {
        t.join().expect("a client failed");
    }
    // Every commit is in history, every file in the working copy's tree,
    // and the repository is sound.
    let log = cli_json(&env, "alice", &p, &["log", "--json"]);
    let descs: Vec<&str> = log["entries"].as_array().unwrap().iter().filter_map(|e| e["description"].as_str()).collect();
    for i in 0..CLIENTS {
        for k in 0..ROUNDS {
            assert!(descs.contains(&format!("server {i} {k}").as_str()), "server {i} {k} is missing: {descs:?}");
        }
    }
    for k in 0..ROUNDS {
        assert!(descs.contains(&format!("cli {k}").as_str()));
    }
    let diff = cli_json(&env, "alice", &p, &["diff", "--from", "root()", "--stat", "--json"]);
    let paths: Vec<&str> = diff["files"].as_array().unwrap().iter().map(|f| f["path"].as_str().unwrap()).collect();
    let mut lost: Vec<String> = (0..CLIENTS).flat_map(|i| (0..ROUNDS).map(move |k| format!("server-{i}-{k}.txt"))).collect();
    lost.extend((0..ROUNDS).map(|k| format!("cli-{k}.txt")));
    lost.retain(|f| !paths.contains(&f.as_str()));
    if !lost.is_empty() {
        let on_disk: Vec<&String> = lost.iter().filter(|f| p.join(f).exists()).collect();
        let log = env.ok("alice", &p, &["--no-snapshot", "log"]);
        let out = server.stop(libc::SIGTERM);
        panic!("not in @: {lost:?} (on disk: {on_disk:?})\nlog:\n{log}\nserver:\n{}", text(&out));
    }
    env.ok("alice", &p, &["fsck"]);
    // The lock is never held between requests: the CLI runs right now.
    assert!(env.vl("alice", &p, &["describe", "-m", "after"]).status.success());
    let st = Conn::open(&sock).ok("status", json!({"snapshot": false}));
    assert_eq!(st["working_copy"]["description"], "after");
    drop(server);
}

#[test]
fn watch_notifies_when_the_operation_log_moves() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    let server = Server::start(&env, "alice", &p);
    let mut c = server.conn();
    let w = c.ok("watch", json!({"interval_ms": 50}));
    assert_eq!(w["schema"], "veil.watch/1");
    assert_eq!(w["watching"], true);
    env.ok("alice", &p, &["describe", "-m", "watched"]);
    let n = c.recv();
    assert_eq!(n["method"], "changed", "{n}");
    assert!(n.get("id").is_none());
    assert_eq!(n["params"]["schema"], "veil.changed/1");
    let head = cli_json(&env, "alice", &p, &["--no-snapshot", "op", "log", "-n", "1", "--json"]);
    assert_eq!(n["params"]["operation"]["op_id"], head["operations"][0]["op_id"]);
    assert_eq!(n["params"]["operation"]["description"], head["operations"][0]["description"]);
    // Requests still work on a watching connection.
    let r = c.call("unwatch", json!({}));
    assert_eq!(r["result"]["watching"], false, "{r}");

    // With working_copy, edits on disk are recorded and announced.
    let mut c = server.conn();
    c.ok("watch", json!({"interval_ms": 50, "working_copy": true}));
    write(&p, "typed.txt", "typed in an editor\n");
    let n = c.recv();
    assert_eq!(n["method"], "changed", "{n}");
    let st = c.ok("status", json!({"snapshot": false}));
    assert!(st["changes"].as_array().unwrap().iter().any(|ch| ch["path"] == "typed.txt"), "{st}");
    let (code, _) = c.err("watch", json!({"interval_ms": 1}));
    assert_eq!(code, -32602);
}

#[test]
fn malformed_requests_get_json_rpc_errors() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    let server = Server::start(&env, "alice", &p);
    let mut c = server.conn();
    let code = |v: &Value| v["error"]["code"].as_i64().unwrap_or_else(|| panic!("not an error: {v}"));

    c.send("this is not json");
    assert_eq!(code(&c.recv()), -32700);
    c.send("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"status\"");
    assert_eq!(code(&c.recv()), -32700);
    c.w.write_all(b"\xff\xfe{}\n").unwrap();
    assert_eq!(code(&c.recv()), -32700);
    for (req, want) in [
        (r#"{"id":1,"method":"status"}"#, -32600),
        (r#"{"jsonrpc":"1.0","id":1,"method":"status"}"#, -32600),
        (r#"{"jsonrpc":"2.0","id":1,"method":7}"#, -32600),
        (r#"{"jsonrpc":"2.0","id":{"a":1},"method":"status"}"#, -32600),
        (r#"{"jsonrpc":"2.0","id":1,"method":"status","extra":1}"#, -32600),
        (r#"[]"#, -32600),
        (r#"42"#, -32600),
        (r#"{"jsonrpc":"2.0","id":1,"method":"nope"}"#, -32601),
        (r#"{"jsonrpc":"2.0","id":1,"method":"status","params":[1]}"#, -32602),
        (r#"{"jsonrpc":"2.0","id":1,"method":"status","params":{"bogus":1}}"#, -32602),
        (r#"{"jsonrpc":"2.0","id":1,"method":"log","params":{"limit":"ten"}}"#, -32602),
        (r#"{"jsonrpc":"2.0","id":1,"method":"log","params":{"limit":-1}}"#, -32602),
        (r#"{"jsonrpc":"2.0","id":1,"method":"commit","params":{}}"#, -32602),
        (r#"{"jsonrpc":"2.0","id":1,"method":"diff","params":{"rev":"@","from":"@"}}"#, -32602),
        (r#"{"jsonrpc":"2.0","id":1,"method":"show","params":{"rev":"nonexistent"}}"#, -32000),
    ] {
        c.send(req);
        let v = c.recv();
        assert_eq!(code(&v), want, "{req}: {v}");
    }
    // A notification (no id) gets no answer; the next request does.
    c.send(r#"{"jsonrpc":"2.0","method":"status","params":{"snapshot":false}}"#);
    c.send(r#"{"jsonrpc":"2.0","id":"after","method":"server.info"}"#);
    let v = c.recv();
    assert_eq!(v["id"], "after", "{v}");
    assert_eq!(v["result"]["schema"], "veil.server.info/1");
    // A batch: one answer per request, in one line.
    c.send(r#"[{"jsonrpc":"2.0","id":1,"method":"tag.list","params":{"snapshot":false}},{"jsonrpc":"2.0","method":"status"},{"jsonrpc":"2.0","id":2,"method":"nope"}]"#);
    let v = c.recv();
    let a = v.as_array().unwrap_or_else(|| panic!("{v}"));
    assert_eq!(a.len(), 2);
    assert_eq!(a[0]["result"]["schema"], "veil.tag.list/1");
    assert_eq!(a[1]["error"]["code"], -32601);
    let big: Vec<String> = (0..65).map(|i| format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"server.info"}}"#)).collect();
    c.send(&format!("[{}]", big.join(",")));
    assert_eq!(code(&c.recv()), -32600);
    // Deep nesting is a parse error, not a stack overflow.
    c.send(&format!("{}{}", "[".repeat(200_000), "]".repeat(200_000)));
    assert_eq!(code(&c.recv()), -32700);
    let deep = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"status","params":{{"snapshot":{}true{}}}}}"#, "[".repeat(100_000), "]".repeat(100_000));
    c.send(&deep);
    assert_eq!(code(&c.recv()), -32700);
    // Blank lines are skipped; the connection still works.
    c.send("");
    c.send("   ");
    assert_eq!(c.ok("server.info", json!({}))["schema"], "veil.server.info/1");
    // Nothing above hurt the repository.
    env.ok("alice", &p, &["fsck"]);
}

#[test]
fn oversized_requests_are_refused_and_the_connection_closed() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    let server = Server::start(&env, "alice", &p);
    let c = server.conn();
    let mut w = c.w.try_clone().unwrap();
    let writer = std::thread::spawn(move || {
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..40 {
            if w.write_all(&chunk).is_err() {
                return;
            }
        }
        let _ = w.shutdown(std::net::Shutdown::Write);
    });
    let mut c = c;
    let v = c.recv();
    assert_eq!(v["error"]["code"], -32600, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("too large"));
    assert!(c.recv_line().is_none(), "the connection is closed");
    writer.join().unwrap();
    // A request of exactly the limit is read (and is not JSON).
    let mut c = server.conn();
    let mut line = vec![b' '; 1 << 20];
    line[0] = b'{';
    c.w.write_all(&line).unwrap();
    c.w.write_all(b"\n").unwrap();
    assert_eq!(c.recv()["error"]["code"], -32700);
    // The server is fine.
    assert_eq!(server.conn().ok("server.info", json!({}))["max_request_bytes"], 1 << 20);
}

#[test]
fn connections_are_capped() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    let server = Server::start(&env, "alice", &p);
    let mut open: Vec<Conn> = (0..32).map(|_| server.conn()).collect();
    for c in &mut open {
        c.ok("server.info", json!({}));
    }
    let mut extra = server.conn();
    let v = extra.recv();
    assert_eq!(v["error"]["code"], -32001, "{v}");
    assert!(extra.recv_line().is_none());
    // A slot frees up when a client leaves.
    drop(open.pop());
    assert!(wait_for(Duration::from_secs(10), || {
        let mut c = server.conn();
        c.send(r#"{"jsonrpc":"2.0","id":1,"method":"server.info"}"#);
        c.recv().get("result").is_some()
    }));
}

#[test]
fn one_server_per_repository_and_stale_sockets_are_replaced() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    let sock = sock_of(&p);

    // A socket left by a server that died: nobody listens on it.
    drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
    assert!(sock.exists());
    let server = Server::start(&env, "alice", &p);
    server.conn().ok("server.info", json!({}));

    // A second server refuses, and leaves the live one alone.
    let out = env.vl("alice", &p, &["serve", "--local"]);
    assert!(!out.status.success());
    assert!(text(&out).contains("already serving"), "{}", text(&out));
    assert_eq!(server.conn().ok("server.info", json!({}))["pid"], server.pid());
    let out = server.stop(libc::SIGTERM);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("Replaced the stale socket"), "{}", text(&out));

    // Something that is not a socket is never removed.
    write(&p, ".veil/local/sock", "precious");
    let out = env.vl("alice", &p, &["serve", "--local"]);
    assert!(!out.status.success());
    assert!(text(&out).contains("not a socket"), "{}", text(&out));
    assert_eq!(read(&p, ".veil/local/sock"), "precious");
    std::fs::remove_file(&sock).unwrap();

    // A symlink there is not a socket either.
    std::os::unix::fs::symlink(env.root.join("elsewhere"), &sock).unwrap();
    let out = env.vl("alice", &p, &["serve", "--local"]);
    assert!(!out.status.success());
    assert!(std::fs::symlink_metadata(&sock).unwrap().file_type().is_symlink());
    assert!(!env.root.join("elsewhere").exists());
}

#[test]
fn socket_and_directory_are_private() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    let local = p.join(".veil/local");
    std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o755)).unwrap();
    let server = Server::start(&env, "alice", &p);
    let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&local), 0o700);
    assert_eq!(mode(&server.sock), 0o600);
    drop(server);

    // `.veil/local` must be a real directory, never a symlink to elsewhere.
    let moved = env.root.join("moved-local");
    std::fs::remove_file(sock_of(&p)).ok();
    std::fs::rename(&local, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &local).unwrap();
    let out = env.vl("alice", &p, &["serve", "--local"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!moved.join("sock").exists());
    // Nor does the client follow one.
    let out = env.vl("alice", &p, &["serve", "--call", "status"]);
    assert!(!out.status.success());
}

#[test]
fn shutdown_removes_the_socket() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        let server = Server::start(&env, "alice", &p);
        let mut idle = server.conn();
        idle.ok("server.info", json!({}));
        let sock = server.sock.clone();
        let out = server.stop(sig);
        assert!(out.status.success(), "signal {sig}: {}", text(&out));
        assert!(!sock.exists(), "signal {sig}: the socket is still there");
        assert!(idle.recv_line().is_none());
        // And the next server starts without complaint.
        assert!(!text(&out).contains("stale"));
    }
    // A server whose socket was taken away stops by itself.
    let mut server = Server::start(&env, "alice", &p);
    std::fs::remove_file(&server.sock).unwrap();
    let c = server.child.as_mut().unwrap();
    assert!(wait_for(Duration::from_secs(10), || matches!(c.try_wait(), Ok(Some(_)))), "the server kept running");
}

#[test]
fn the_client_mode_and_long_paths() {
    let env = Env::new();
    // Deeper than a socket address can hold (about 100 bytes).
    let deep = format!("p-{}", "d".repeat(120));
    let p = env.project("alice", &deep, &[("README.md", "hi\n")]);
    assert!(sock_of(&p).as_os_str().len() > 108);
    let mut child = env.spawn("alice", &p, &["serve", "--local"]);
    assert!(wait_for(Duration::from_secs(20), || env.vl("alice", &p, &["serve", "--call", "server.info"]).status.success()));
    let info: Value = serde_json::from_str(&env.stdout("alice", &p, &["serve", "--call", "server.info"])).unwrap();
    assert_eq!(info["schema"], "veil.server.info/1");
    // From a subdirectory, and with -R, as every command.
    std::fs::create_dir_all(p.join("sub")).unwrap();
    let st = env.stdout("alice", &p.join("sub"), &["serve", "--call", "status"]);
    assert!(st.starts_with("{\"schema\":\"veil.status/1\""));
    let st = env.stdout("alice", &env.root, &["-R", p.to_str().unwrap(), "serve", "--call", "op.log", r#"{"limit":1}"#]);
    assert!(st.starts_with("{\"schema\":\"veil.op.log/1\""));
    // Errors: the veil.error/1 document on stdout, exit 1.
    let out = env.vl("alice", &p, &["serve", "--call", "show", r#"{"rev":"nope"}"#]);
    assert_eq!(out.status.code(), Some(1));
    let e: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(e["schema"], "veil.error/1");
    let out = env.vl("alice", &p, &["serve", "--call", "status", "[1]"]);
    assert_eq!(out.status.code(), Some(1));
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert!(child.wait().unwrap().success());
    assert!(!sock_of(&p).exists());
    // No server: a clear error.
    let out = env.vl("alice", &p, &["serve", "--call", "status"]);
    assert!(!out.status.success());
    assert!(text(&out).contains("is `vl serve --local` running?"), "{}", text(&out));
}

#[test]
fn a_bare_repository_serves_history_only() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    let team = env.root.join("team");
    env.ok("alice", &p, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &p, &["push"]);
    let server = Server::start(&env, "alice", &team);
    let mut c = server.conn();
    assert_eq!(c.ok("log", json!({}))["schema"], "veil.log/1");
    assert_eq!(c.ok("tag.list", json!({}))["schema"], "veil.tag.list/1");
    for m in ["status", "commit", "snapshot"] {
        let params = if m == "commit" { json!({"message": "x"}) } else { json!({}) };
        let (code, e) = c.err(m, params);
        assert_eq!(code, -32000);
        assert!(e["message"].as_str().unwrap().contains("bare repository"), "{e}");
    }
}

#[test]
fn a_panicking_or_slow_reader_does_not_block_others() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    let server = Server::start(&env, "alice", &p);
    // A client that sends half a request and then nothing.
    let mut stuck = UnixStream::connect(&server.sock).unwrap();
    stuck.write_all(b"{\"jsonrpc\":\"2.0\",").unwrap();
    // Others are served meanwhile.
    let mut c = server.conn();
    assert_eq!(c.ok("status", json!({}))["schema"], "veil.status/1");
    let mut buf = [0u8; 1];
    stuck.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    assert!(stuck.read(&mut buf).is_err(), "no answer to half a request");
}

/// Every method, and every key of every result the server adds to the
/// `--json` schemas, is documented in `docs/reference/json-rpc.md`.
#[test]
fn the_protocol_is_documented() {
    let doc = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/reference/json-rpc.md")).unwrap();
    let json_md = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/reference/json.md")).unwrap();
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    env.ok("alice", &p, &["tag", "set", "kept", "-r", "@-"]);
    let server = Server::start(&env, "alice", &p);
    let mut c = server.conn();
    let info = c.ok("server.info", json!({}));
    let mut missing = Vec::new();
    for m in info["methods"].as_array().unwrap() {
        if !doc.contains(&format!("| `{}`", m.as_str().unwrap())) {
            missing.push(format!("method {m}"));
        }
    }
    write(&p, "x.txt", "x\n");
    let mut docs = vec![
        info,
        c.ok("snapshot", json!({})),
        c.ok("describe", json!({"message": "d"})),
        c.ok("commit", json!({"message": "c", "no_advance": true})),
        c.ok("new", json!({})),
        c.ok("watch", json!({"interval_ms": 50})),
    ];
    env.ok("alice", &p, &["describe", "-m", "e"]);
    docs.push(c.recv()["params"].clone());
    docs.push(c.ok("unwatch", json!({})));
    write(&p, "y.txt", "y\n");
    write(&p, "z.txt", "z\n");
    docs.push(c.ok("split", json!({"files": [{"path": "y.txt"}]})));
    docs.push(c.ok("squash", json!({"files": [{"path": "z.txt", "hunks": [1]}]})));
    fn keys(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(o) => {
                for (k, v) in o {
                    out.push(k.clone());
                    keys(v, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
            _ => {}
        }
    }
    for d in &docs {
        let schema = d["schema"].as_str().unwrap();
        assert!(doc.contains(&format!("`{schema}`")), "{schema} is not documented");
        let mut ks = Vec::new();
        keys(d, &mut ks);
        for k in ks {
            let k = format!("`{k}`");
            if !doc.contains(&k) && !json_md.contains(&k) {
                missing.push(format!("{schema}: {k}"));
            }
        }
    }
    assert!(missing.is_empty(), "undocumented in docs/reference/json-rpc.md:\n  {}", missing.join("\n  "));
}

/// BUG-360: concurrent first uses of `vl` on a fresh `VEIL_HOME` must end
/// with one identity, not one each.
#[test]
fn bug_360_concurrent_first_uses_share_one_identity() {
    let env = Env::new();
    for round in 0..3 {
        let user = format!("fresh{round}");
        let kids: Vec<_> = (0..12).map(|_| env.spawn(&user, &env.root, &["identity", "show"])).collect();
        let keys: std::collections::BTreeSet<String> = kids
            .into_iter()
            .map(|k| {
                let out = k.wait_with_output().unwrap();
                String::from_utf8_lossy(&out.stdout).lines().find(|l| l.starts_with("public key")).unwrap_or_default().to_string()
            })
            .collect();
        assert_eq!(keys.len(), 1, "round {round}: {} identities were created: {keys:?}", keys.len());
    }
}

/// BUG-361: a command that runs while another one has moved `@` to a
/// snapshot with the same tree (a `commit`, a `new`) but not yet recorded
/// its checkout must record edits on disk into `@`, not move them out of
/// the directory into a side change.
#[test]
fn bug_361_edits_survive_a_concurrent_commit() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    // The directory as the committing command left it before its checkout
    // was recorded: still at the committed change, whose tree `@` shares.
    let log = cli_json(&env, "alice", &p, &["--no-snapshot", "log", "--json"]);
    let committed = log["entries"][1]["snapshot_id"].as_str().unwrap().to_string();
    let rec = p.join(".veil/local/checkout.json");
    let mut st: Value = serde_json::from_str(&std::fs::read_to_string(&rec).unwrap()).unwrap();
    st["snapshot"] = json!(committed);
    std::fs::write(&rec, st.to_string()).unwrap();
    write(&p, "fresh.txt", "typed meanwhile\n");
    let out = env.ok("alice", &p, &["status"]);
    assert!(!out.contains("stale"), "{out}");
    assert_eq!(read(&p, "fresh.txt"), "typed meanwhile\n", "the edit was taken out of the working copy");
    let st = cli_json(&env, "alice", &p, &["status", "--json"]);
    assert!(st["changes"].as_array().unwrap().iter().any(|c| c["path"] == "fresh.txt"), "{st}");
    let log = cli_json(&env, "alice", &p, &["log", "--json"]);
    assert!(!log.to_string().contains("recovered working-copy edits"));
}

/// BUG-362: the same window after another command *recorded* the
/// directory (a snapshot, so the tree changed): what it recorded is on
/// disk, so the directory is not behind. A real move (here: `@` set to a
/// snapshot whose changes are not on disk) is still caught up with, the
/// edits saved aside as before.
#[test]
fn bug_362_edits_survive_a_concurrent_snapshot() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("README.md", "hi\n")]);
    let rec = p.join(".veil/local/checkout.json");
    let set_record = |id: &str| {
        let mut st: Value = serde_json::from_str(&std::fs::read_to_string(&rec).unwrap()).unwrap();
        st["snapshot"] = json!(id);
        std::fs::write(&rec, st.to_string()).unwrap();
    };
    let before = cli_json(&env, "alice", &p, &["--no-snapshot", "show", "--json"])["snapshot_id"].as_str().unwrap().to_string();
    write(&p, "first.txt", "recorded by another command\n");
    env.ok("alice", &p, &["status"]);
    // That command's checkout record is not written yet; more is typed.
    set_record(&before);
    write(&p, "second.txt", "typed meanwhile\n");
    let out = env.ok("alice", &p, &["status"]);
    assert!(!out.contains("stale"), "{out}");
    assert_eq!(read(&p, "second.txt"), "typed meanwhile\n");
    let st = cli_json(&env, "alice", &p, &["status", "--json"]);
    let changed: Vec<&str> = st["changes"].as_array().unwrap().iter().map(|c| c["path"].as_str().unwrap()).collect();
    assert!(changed.contains(&"first.txt") && changed.contains(&"second.txt"), "{st}");

    // Control: the record names a snapshot the directory never held
    // (`main`, without first.txt and second.txt, plus a change on disk
    // that `@` does not have): `@` is behind nothing, the directory is.
    write(&p, "README.md", "edited\n");
    env.ok("alice", &p, &["status"]);
    let main = cli_json(&env, "alice", &p, &["--no-snapshot", "show", "main", "--json"])["snapshot_id"].as_str().unwrap().to_string();
    env.ok("alice", &p, &["--no-snapshot", "describe", "-m", "moved"]);
    set_record(&main);
    write(&p, "README.md", "edited again\n");
    let out = env.ok("alice", &p, &["status"]);
    assert!(out.contains("stale"), "a real move is still recovered: {out}");
}

/// `split` and `squash` take what to move as a plan's `files` (no picker),
/// answer with the CLI's `--json` documents, and record one operation each.
#[test]
fn split_and_squash_from_a_plan() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("a.txt", "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n"), ("b.txt", "b\n")]);
    write(&p, "a.txt", "ONE\n2\n3\n4\n5\n6\n7\n8\n9\nTEN\n");
    write(&p, "b.txt", "B\n");
    write(&p, "c.txt", "c\n");
    let server = Server::start(&env, "alice", &p);
    let mut c = server.conn();
    let v = c.ok("split", json!({"message": "from the server", "files": [{"path": "a.txt", "hunks": [2]}]}));
    assert_eq!(v["schema"], "veil.split/1");
    assert_eq!(v["first"]["description"], "from the server");
    assert_eq!(env.stdout("alice", &p, &["cat", "-r", "@-", "a.txt"]), "1\n2\n3\n4\n5\n6\n7\n8\n9\nTEN\n");
    let v = c.ok("squash", json!({"files": [{"path": "c.txt"}]}));
    assert_eq!(v["schema"], "veil.squash/1");
    assert_eq!(v["source_abandoned"], false);
    assert_eq!(env.stdout("alice", &p, &["cat", "-r", "@-", "c.txt"]), "c\n");
    let (code, _) = c.err("squash", json!({"files": []}));
    assert_eq!(code, -32602);
    let (code, e) = c.err("split", json!({"files": [{"path": "a.txt", "hunks": [7]}]}));
    assert_eq!(code, -32000, "{e}");
    assert!(e["data"]["error"]["message"].as_str().unwrap().contains("has no hunk 7"), "{e}");
    let v = c.ok("squash", json!({}));
    assert_eq!(v["source_abandoned"], true);
    env.ok("alice", &p, &["undo"]);
    assert_eq!(read(&p, "a.txt"), "ONE\n2\n3\n4\n5\n6\n7\n8\n9\nTEN\n", "the working copy never changed");
}
