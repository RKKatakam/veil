//! `--json` on the read commands, through the real `vl` binary.
//!
//! * **Golden shapes.** Each schema's set of keys and the type at every
//!   level is pinned here (not the volatile values), and every key must be
//!   documented in `docs/reference/json.md` under its schema's heading.
//! * **Every read command accepts `--json`** and prints exactly one
//!   document, on one line, whose `schema` names it.
//! * **Confidentiality.** No plaintext of cloaked, embargoed or isolated
//!   content, no sealed description and no secret value appears in any
//!   JSON output, for a non-member, a public-mirror reader, or (for
//!   isolated files and vault values) the owner.

mod adversarial_support;

use std::{
    io::Write as _,
    path::{Path, PathBuf},
    process::Stdio,
};

use adversarial_support::*;
use serde_json::{json, Value};

// ---- running `vl … --json` ----------------------------------------------------------

/// Run `vl args` and parse its stdout as exactly one JSON document on one
/// line. Returns the document and the exit code.
fn json_doc(env: &Env, user: &str, dir: &Path, args: &[&str]) -> (Value, Option<i32>) {
    let out = env.vl(user, dir, args);
    let stdout = String::from_utf8(out.stdout.clone()).expect("JSON output is UTF-8");
    assert!(stdout.ends_with('\n'), "vl {args:?}: the document ends with a newline: {stdout:?}\n{}", text(&out));
    assert_eq!(stdout.lines().count(), 1, "vl {args:?}: exactly one line on stdout:\n{stdout}\n{}", text(&out));
    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("vl {args:?}: not JSON ({e}):\n{stdout}"));
    (v, out.status.code())
}

/// [`json_doc`] for a command that must succeed.
fn json_ok(env: &Env, user: &str, dir: &Path, args: &[&str]) -> Value {
    let (v, code) = json_doc(env, user, dir, args);
    assert_eq!(code, Some(0), "vl {args:?} failed: {v}");
    v
}

fn write_stdin(env: &Env, user: &str, dir: &Path, args: &[&str], input: &[u8]) {
    let mut c = env.cmd(user, dir, args);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "vl {args:?}: {}", text(&out));
}

// ---- shapes ----------------------------------------------------------------------------

/// Check `v` against `spec`:
/// * a string spec is a `|`-separated list of types (`string`, `number`,
///   `bool`, `null`);
/// * an object spec lists exactly the keys `v` must have (a `"?": true`
///   entry allows `null` instead);
/// * a one-element array spec gives the shape of every element (an empty
///   array matches anything).
fn check(at: &str, v: &Value, spec: &Value) {
    match spec {
        Value::String(types) => {
            let t = match v {
                Value::String(_) => "string",
                Value::Number(_) => "number",
                Value::Bool(_) => "bool",
                Value::Null => "null",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            };
            assert!(types.split('|').any(|x| x == t), "{at}: expected {types}, found {t}: {v}");
        }
        Value::Object(fields) => {
            if v.is_null() && fields.get("?") == Some(&Value::Bool(true)) {
                return;
            }
            let obj = v.as_object().unwrap_or_else(|| panic!("{at}: expected an object, found {v}"));
            let want: Vec<&String> = fields.keys().filter(|k| *k != "?").collect();
            let have: Vec<&String> = obj.keys().collect();
            let mut want_sorted = want.clone();
            want_sorted.sort();
            let mut have_sorted = have.clone();
            have_sorted.sort();
            assert_eq!(have_sorted, want_sorted, "{at}: keys differ in {v}");
            for k in want {
                check(&format!("{at}.{k}"), &obj[k], &fields[k]);
            }
        }
        Value::Array(elem) => {
            let arr = v.as_array().unwrap_or_else(|| panic!("{at}: expected an array, found {v}"));
            for (i, x) in arr.iter().enumerate() {
                check(&format!("{at}[{i}]"), x, &elem[0]);
            }
        }
        _ => unreachable!("bad spec"),
    }
}

fn nullable(mut spec: Value) -> Value {
    spec.as_object_mut().unwrap().insert("?".into(), Value::Bool(true));
    spec
}

fn vis() -> Value {
    json!({"kind": "string", "scope": "string|null", "embargo": "string|null"})
}

fn redaction() -> Value {
    json!({"reason": "string", "message": "string"})
}

fn hidden_text() -> Value {
    nullable(json!({"scope": "string", "reason": "string"}))
}

fn snapshot_ref() -> Value {
    json!({
        "snapshot_id": "string", "snapshot_short": "string",
        "change_id": "string|null", "change_short": "string|null",
        "available": "bool", "empty": "bool",
        "description": "string|null", "description_hidden": hidden_text(),
    })
}

fn sig() -> Value {
    nullable(json!({"status": "string", "signer": "string|null", "key": "string|null", "key_short": "string|null"}))
}

/// A conflict entry's description (`ConflictInfo`), or null.
fn conflict_info() -> Value {
    let version = json!({"role": "string", "number": "number", "visibility": nullable(vis()), "readable": "bool"});
    nullable(json!({"sides": "number", "bases": "number", "versions": [version], "redacted": "bool", "unreadable_side": "bool"}))
}

fn change() -> Value {
    json!({"path": "string", "status": "string", "visibility": vis(), "redacted": "bool", "tier": "string", "conflict": conflict_info()})
}

fn diff_files() -> Value {
    let entry = nullable(json!({"visibility": vis(), "executable": "bool", "mode": "string", "readable": "bool", "conflict": conflict_info()}));
    let line = json!({"kind": "string", "text": "string", "newline": "bool"});
    let hunk = json!({"old_start": "number", "old_lines": "number", "new_start": "number", "new_lines": "number", "lines": [line]});
    json!([{
        "path": "string", "status": "string", "old": entry, "new": entry,
        "content": nullable(json!({"binary": "bool", "hidden": nullable(redaction()), "hunks": [hunk]})),
    }])
}

/// Every schema, by name.
fn specs() -> Vec<(&'static str, Value)> {
    let tag_label = json!({"name": "string", "cloak": "string|null"});
    let parent = json!({"snapshot_id": "string", "snapshot_short": "string", "change_short": "string|null", "withheld": "bool"});
    let log_entry = json!({
        "snapshot_id": "string", "snapshot_short": "string", "change_id": "string", "change_short": "string",
        "root": "bool", "current": "bool", "author": "string|null", "timestamp": "string|null", "signature": sig(),
        "workspaces": ["string"], "tags": [tag_label], "remote_tags": ["string"], "empty": "bool",
        "conflicts": ["string"], "cloak": "string|null",
        "embargo": nullable(json!({"id": "string", "released": "bool"})),
        "description": "string|null", "description_hidden": hidden_text(), "parents": [parent],
    });
    let scan_file = json!({
        "path": "string", "tier": "string", "scope": "string|null", "protected": "bool",
        "findings": [{"line": "number", "rule": "string", "excerpt": "string"}], "error": "string|null",
    });
    vec![
        ("veil.status/1", json!({
            "schema": "string",
            "workspace": {"name": "string", "cloak": "string|null"},
            "working_copy": snapshot_ref(),
            "parents": [snapshot_ref()],
            "changes": [change()],
            "isolated": ["string"],
            "quarantined": [{"path": "string", "rule": "string", "line": "number", "state": "string", "tier": "string"}],
            "policy_held_back": [{
                "path": "string", "dir": "bool", "accepted": "string", "wanted": "string",
                "tier": "string", "scope": "string|null",
            }],
            "nested": ["string"],
            "redacted": [{"path": "string", "redaction": redaction(), "tier": "string"}],
            "conflicts": [{"path": "string", "recorded_on": "string|null", "conflict": conflict_info()}],
        })),
        ("veil.log/1", json!({"schema": "string", "entries": [log_entry], "truncated": "bool"})),
        ("veil.diff/1", json!({"schema": "string", "stat": "bool", "files": diff_files()})),
        ("veil.show/1", json!({
            "schema": "string", "snapshot_id": "string", "snapshot_short": "string",
            "change_id": "string", "change_short": "string", "root": "bool", "author": "string",
            "timestamp": "string|null", "signature": sig(), "parents": [snapshot_ref()], "tags": ["string"],
            "cloak": "string|null",
            "embargo": nullable(json!({"id": "string", "state": "string", "until": "string|null"})),
            "conflicts": ["string"], "description": "string|null", "description_hidden": hidden_text(),
            "diff": {"stat": "bool", "files": diff_files()},
        })),
        ("veil.workspace.list/1", json!({
            "schema": "string",
            "workspaces": [{"name": "string", "current": "bool", "cloak": "string|null", "working_copy": snapshot_ref()}],
        })),
        ("veil.tag.list/1", json!({
            "schema": "string",
            "tags": [{"name": "string", "cloak": "string|null", "target": snapshot_ref()}],
            "remote_tags": [{"name": "string", "target": snapshot_ref()}],
        })),
        ("veil.op.log/1", json!({
            "schema": "string",
            "operations": [{"op_id": "string", "op_short": "string", "timestamp": "string|null", "user": "string", "description": "string"}],
        })),
        ("veil.scan/1", json!({
            "schema": "string", "mode": "string", "policy_from": "string|null", "nested": ["string"],
            "files": [scan_file], "exposed": "number", "protected": "number", "clean": "bool",
        })),
        ("veil.secret.list/1", json!({"schema": "string", "secrets": [{"name": "string"}]})),
        ("veil.ls/1", json!({
            "schema": "string", "snapshot": snapshot_ref(), "working_copy": "bool", "all": "bool",
            "entries": [{
                "path": "string", "dir": "bool", "tier": "string", "scope": "string|null", "embargo": "string|null",
                "recorded": "bool", "visibility": nullable(vis()), "size": "number|null", "executable": "bool",
                "readable": "bool", "fallback": "bool", "redaction": nullable(redaction()),
                "quarantine": nullable(json!({"rule": "string", "line": "number", "state": "string"})),
                "conflict": conflict_info(),
            }],
        })),
        ("veil.resolve.list/1", json!({
            "schema": "string", "snapshot": snapshot_ref(),
            "conflicts": [{"path": "string", "conflict": conflict_info()}],
        })),
        ("veil.push.plan/1", {
            let snap = json!({"snapshot_id": "string", "snapshot_short": "string", "embargo": "string"});
            json!({
                "schema": "string",
                "remotes": [{
                    "name": "string", "url": "string", "public": "bool", "error": "string|null",
                    "creates_remote": "bool",
                    "tags": [{
                        "name": "string", "action": "string", "target": "string", "target_short": "string",
                        "remote_target": "string|null", "message": "string|null", "cloak": "string|null",
                    }],
                    "snapshots": "number", "objects": "number", "trees": "number", "blobs": "number",
                    "sealed": "number", "object_bytes": "number", "pack_bytes": "number",
                    "snapshot_ids": ["string"], "object_ids": ["string"], "withheld_objects": "number",
                    "withheld_snapshots": [snap], "releases": ["string"],
                    "files": nullable(json!({
                        "published": [{"path": "string", "exposure": "string", "size": "number|null", "released_embargo": "string|null"}],
                        "withheld": [{"path": "string", "reason": "string", "scope": "string|null", "embargo": "string|null", "message": "string"}],
                        "embargoed_trees": [snap],
                    })),
                    "warnings": ["string"],
                }],
            })
        }),
        ("veil.error/1", json!({"schema": "string", "error": {"message": "string", "hint": "string|null"}})),
        ("veil.split/1", {
            let taken = json!([{"path": "string", "whole": "bool", "hunks": ["string"]}]);
            json!({"schema": "string", "first": snapshot_ref(), "second": snapshot_ref(), "chosen": taken, "operation": {"op_id": "string", "op_short": "string"}})
        }),
        ("veil.squash/1", {
            let taken = json!([{"path": "string", "whole": "bool", "hunks": ["string"]}]);
            json!({
                "schema": "string", "destination": snapshot_ref(), "source": nullable(snapshot_ref()),
                "source_abandoned": "bool", "moved": taken, "operation": {"op_id": "string", "op_short": "string"},
            })
        }),
    ]
}

fn spec(schema: &str) -> Value {
    specs().into_iter().find(|(s, _)| *s == schema).unwrap_or_else(|| panic!("no spec for {schema}")).1
}

/// Check `v`'s shape against its schema's spec, and the conventions every
/// document follows.
fn check_doc(v: &Value, schema: &str) {
    assert_eq!(v["schema"], schema, "{v}");
    check(schema, v, &spec(schema));
    conventions(schema, v);
}

/// Ids are full hex with an 8-digit short form, change ids reverse hex,
/// times RFC 3339 UTC, paths relative with `/`.
fn conventions(at: &str, v: &Value) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                let here = format!("{at}.{k}");
                if let Some(s) = x.as_str() {
                    match k.as_str() {
                        "snapshot_id" | "op_id" => {
                            assert!(s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()), "{here}: {s}")
                        }
                        "change_id" => assert!(s.len() == 32 && s.bytes().all(|b| (b'k'..=b'z').contains(&b)), "{here}: {s}"),
                        "snapshot_short" | "op_short" | "change_short" => assert_eq!(s.len(), 8, "{here}: {s}"),
                        "timestamp" | "until" => {
                            assert!(s.ends_with('Z') && s.len() == 24 && &s[10..11] == "T", "{here}: not RFC 3339 UTC: {s}")
                        }
                        "path" => assert!(!s.starts_with('/') && !s.contains('\\'), "{here}: {s}"),
                        // (`mode` is also a Git file mode, `100644`.)
                        "mode" if s.bytes().all(|b| b.is_ascii_digit()) => {}
                        "kind" | "status" | "reason" | "state" | "tier" | "mode" => {
                            assert!(s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{here}: enum not lower-case: {s}")
                        }
                        _ => {}
                    }
                }
                assert!(k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{here}: key not snake_case");
                conventions(&here, x);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                conventions(&format!("{at}[{i}]"), x);
            }
        }
        _ => {}
    }
}

fn nonempty<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    let a = v[key].as_array().unwrap_or_else(|| panic!("{key} is not an array: {v}"));
    assert!(!a.is_empty(), "{key} should not be empty here: {v}");
    a
}

// ---- the scenario ----------------------------------------------------------------------

const CLOAKED_TEXT: &str = "CLOAKED-PLAN-4417";
const CLOAKED_DESC: &str = "CLOAKED-DESCRIPTION-9902";
const ISOLATED_TEXT: &str = "ISOLATED-VALUE-6623";
const VAULT_VALUE: &str = "VAULT-VALUE-1187";
const TOKEN: &str = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
const EMBARGO_TEXT: &str = "EMBARGOED-FIX-3359";

struct World {
    env: Env,
    alice: PathBuf,
    /// Bob cloned the team remote but holds no key for `team`.
    bob: PathBuf,
    /// Carol cloned the public mirror.
    carol: PathBuf,
}

/// Alice's project: public, cloaked, isolated, binary and executable files,
/// a cloaked workspace with a sealed description, a cloaked tag, an
/// unreleased embargo, a vault secret; a team remote Bob cloned without a
/// key and a public mirror Carol cloned.
fn world() -> World {
    let env = Env::new();
    let alice = env.dir("alice");
    write(&alice, "README.md", "hello\n");
    write(&alice, "internal/plan.md", &format!("{CLOAKED_TEXT}\n"));
    write(&alice, ".env", &format!("API={ISOLATED_TEXT}\n"));
    write(&alice, "run.sh", "echo hi\n");
    env.ok("alice", &alice, &["init"]);
    env.ok("alice", &alice, &["cloak", "internal/"]);
    std::fs::write(alice.join("logo.bin"), b"\x00\x01\x02binary").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(alice.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    env.ok("alice", &alice, &["commit", "-m", "initial"]);
    env.ok("alice", &alice, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &alice, &["secret", "set", "API_TOKEN", VAULT_VALUE]);

    // A cloaked line of work with a sealed description, and a cloaked tag.
    env.ok("alice", &alice, &["ws", "new", "plan", "-r", "main", "--cloak", "team"]);
    write_stdin(&env, "alice", &alice, &["ws", "write", "plan", "internal/plan.md"], format!("{CLOAKED_TEXT} v2\n").as_bytes());
    env.ok("alice", &alice, &["describe", "-r", "plan@", "-m", CLOAKED_DESC]);
    env.ok("alice", &alice, &["tag", "set", "plan-tag", "-r", "plan@", "--cloak", "team"]);

    // An unreleased embargo on main.
    env.ok("alice", &alice, &["ws", "new", "fix", "-r", "main"]);
    write_stdin(&env, "alice", &alice, &["ws", "write", "fix", "README.md"], format!("hello\n{EMBARGO_TEXT}\n").as_bytes());
    env.ok("alice", &alice, &["describe", "-r", "fix@", "-m", "fix"]);
    env.ok("alice", &alice, &["merge", "fix@", "--into", "main", "--embargo", "-m", "embargoed merge"]);

    let team = env.root.join("team");
    let mirror = env.root.join("mirror");
    env.ok("alice", &alice, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &alice, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok("alice", &alice, &["push"]);
    env.ok("alice", &alice, &["push", "mirror"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    env.ok("carol", &env.root, &["clone", "mirror", "carol"]);
    let bob = env.root.join("bob");
    let carol = env.root.join("carol");
    World { env, alice, bob, carol }
}

/// Every read command, with `--json`, and the schema it prints.
fn read_commands() -> Vec<(Vec<&'static str>, &'static str)> {
    vec![
        (vec!["status", "--json"], "veil.status/1"),
        (vec!["st", "--json"], "veil.status/1"),
        (vec!["log", "--json"], "veil.log/1"),
        (vec!["log", "-n", "1", "--json"], "veil.log/1"),
        (vec!["diff", "--json"], "veil.diff/1"),
        (vec!["diff", "--from", "root()", "--to", "@", "--json"], "veil.diff/1"),
        (vec!["diff", "--from", "root()", "--to", "@", "--stat", "--json"], "veil.diff/1"),
        (vec!["show", "--json"], "veil.show/1"),
        (vec!["show", "main", "--json"], "veil.show/1"),
        (vec!["show", "@-", "--stat", "--json"], "veil.show/1"),
        (vec!["workspace", "list", "--json"], "veil.workspace.list/1"),
        (vec!["ws", "list", "--json"], "veil.workspace.list/1"),
        (vec!["tag", "list", "--json"], "veil.tag.list/1"),
        (vec!["op", "log", "--json"], "veil.op.log/1"),
        (vec!["scan", "--json"], "veil.scan/1"),
        (vec!["secret", "list", "--json"], "veil.secret.list/1"),
        (vec!["ls", "--json"], "veil.ls/1"),
        (vec!["ls", "--all", "--json"], "veil.ls/1"),
        (vec!["push", "--dry-run", "--json"], "veil.push.plan/1"),
        (vec!["resolve", "--list", "--json"], "veil.resolve.list/1"),
        (vec!["resolve", "--json"], "veil.resolve.list/1"),
    ]
}

/// The JSON of every read command (and every revision of interest) as
/// `user` sees it in `dir`, concatenated.
fn all_json(env: &Env, user: &str, dir: &Path) -> String {
    let mut out = String::new();
    let mut cmds: Vec<Vec<String>> = read_commands().into_iter().map(|(a, _)| a.iter().map(|s| s.to_string()).collect()).collect();
    // Every snapshot the log shows, through show and diff.
    let log = json_ok(env, user, dir, &["log", "--json"]);
    for e in log["entries"].as_array().unwrap() {
        let id = e["snapshot_id"].as_str().unwrap().to_string();
        cmds.push(vec!["show".into(), id.clone(), "--json".into()]);
        cmds.push(vec!["diff".into(), "-r".into(), id.clone(), "--json".into()]);
        cmds.push(vec!["diff".into(), "--from".into(), "root()".into(), "--to".into(), id.clone(), "--json".into()]);
        cmds.push(vec!["ls".into(), "-r".into(), id, "--all".into(), "--json".into()]);
    }
    for c in &cmds {
        let args: Vec<&str> = c.iter().map(String::as_str).collect();
        let (v, _) = json_doc(env, user, dir, &args);
        out.push_str(&v.to_string());
        out.push('\n');
    }
    out
}

fn assert_absent(haystack: &str, needles: &[&str], who: &str) {
    for n in needles {
        assert!(!haystack.contains(n), "{who}: {n:?} appears in JSON output:\n{haystack}");
    }
}

// ---- tests -------------------------------------------------------------------------

#[test]
fn every_read_command_accepts_json_and_prints_one_document() {
    let w = world();
    for (args, schema) in read_commands() {
        let (v, code) = json_doc(&w.env, "alice", &w.alice, &args);
        assert_eq!(v["schema"], schema, "vl {args:?}: {v}");
        // `scan` exits 1 when a public file holds a secret; nothing does here.
        assert_eq!(code, Some(0), "vl {args:?}: {v}");
    }
    // The CI gate too, outside any repository.
    let policy = w.env.root.join("base.veilpolicy");
    std::fs::write(&policy, "").unwrap();
    let ci = w.env.dir("checkout");
    write(&ci, "ok.txt", "nothing here\n");
    let v = json_ok(&w.env, "alice", &ci, &["scan", "--policy-from", policy.to_str().unwrap(), "--json"]);
    check_doc(&v, "veil.scan/1");
    assert_eq!(v["mode"], "gate");
    // In a bare repository (a remote), the history commands.
    let team = w.env.root.join("team");
    for args in [&["log", "--json"][..], &["show", "main", "--json"], &["tag", "list", "--json"], &["op", "log", "--json"]] {
        let mut a = vec!["-R", team.to_str().unwrap()];
        a.extend_from_slice(args);
        let (v, code) = json_doc(&w.env, "alice", &w.env.root, &a);
        assert_eq!(code, Some(0), "vl {a:?}: {v}");
    }
}

#[test]
fn status_shape() {
    let w = world();
    let (env, alice) = (&w.env, &w.alice);
    // Quarantined (a token in a public file), a nested repository, changes.
    write(alice, "cfg.py", &format!("token = '{TOKEN}'\n"));
    write(alice, "README.md", "hello again\n");
    let nested = env.dir("alice/vendor/lib");
    env.ok("alice", &nested, &["init"]);
    let v = json_ok(env, "alice", alice, &["status", "--json"]);
    check_doc(&v, "veil.status/1");
    assert_eq!(v["workspace"]["name"], "default");
    assert_eq!(v["isolated"], json!([".env"]));
    let q = nonempty(&v, "quarantined");
    assert_eq!(q[0]["path"], "cfg.py");
    assert_eq!(q[0]["state"], "never_recorded");
    assert_eq!(v["nested"], json!(["vendor/lib"]));
    let c = nonempty(&v, "changes");
    assert!(c.iter().any(|c| c["path"] == "README.md" && c["status"] == "modified"), "{v}");
    nonempty(&v, "parents");
    assert_absent(&v.to_string(), &[TOKEN, ISOLATED_TEXT], "alice's status");

    // Bob holds no key: the cloaked file is redacted, with a reason.
    let v = json_ok(env, "bob", &w.bob, &["status", "--json"]);
    check_doc(&v, "veil.status/1");
    let r = nonempty(&v, "redacted");
    assert_eq!(r[0]["path"], "internal/plan.md");
    assert_eq!(r[0]["redaction"]["reason"], "no_key");
}

#[test]
fn status_shape_with_conflicts() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "base\n")]);
    env.ok("alice", &proj, &["ws", "new", "other", "-r", "main"]);
    write_stdin(&env, "alice", &proj, &["ws", "write", "other", "a.txt"], b"theirs\n");
    write(&proj, "a.txt", "ours\n");
    env.ok("alice", &proj, &["commit", "-m", "ours"]);
    env.ok("alice", &proj, &["merge", "other@", "-m", "merge"]);
    let v = json_ok(&env, "alice", &proj, &["status", "--json"]);
    check_doc(&v, "veil.status/1");
    let c = nonempty(&v, "conflicts");
    assert_eq!(c[0]["path"], "a.txt");
    assert!(c[0]["recorded_on"].is_string(), "{v}");
    let v = json_ok(&env, "alice", &proj, &["log", "--json"]);
    check_doc(&v, "veil.log/1");
    let merge = v["entries"].as_array().unwrap().iter().find(|e| e["parents"].as_array().unwrap().len() == 2).expect("a merge");
    assert_eq!(merge["conflicts"], json!(["a.txt"]));
    // Format 4: the conflict is data, described in every listing.
    assert_eq!(c[0]["conflict"]["sides"], 2, "{v}");
    let roles: Vec<&str> = c[0]["conflict"]["versions"].as_array().unwrap().iter().map(|x| x["role"].as_str().unwrap()).collect();
    assert_eq!(roles, ["side", "base", "side"]);
    let v = json_ok(&env, "alice", &proj, &["ls", "--json"]);
    check_doc(&v, "veil.ls/1");
    let a = v["entries"].as_array().unwrap().iter().find(|e| e["path"] == "a.txt").unwrap();
    assert_eq!(a["conflict"]["sides"], 2, "{a}");
    assert_eq!(a["tier"], "public");
    let v = json_ok(&env, "alice", &proj, &["resolve", "--list", "--json"]);
    check_doc(&v, "veil.resolve.list/1");
    assert_eq!(v["conflicts"][0]["path"], "a.txt");
    let v = json_ok(&env, "alice", &proj, &["diff", "-r", "@-", "--json"]);
    check_doc(&v, "veil.diff/1");
    let out = env.ok("alice", &proj, &["resolve", "a.txt", "--theirs"]);
    assert!(out.contains("Resolved a.txt"), "{out}");
    assert_eq!(std::fs::read_to_string(proj.join("a.txt")).unwrap(), "theirs\n");
    let v = json_ok(&env, "alice", &proj, &["status", "--json"]);
    assert!(v["conflicts"].as_array().unwrap().is_empty(), "{v}");
}

#[test]
fn log_shape() {
    let w = world();
    let v = json_ok(&w.env, "alice", &w.alice, &["log", "--json"]);
    check_doc(&v, "veil.log/1");
    assert_eq!(v["truncated"], false);
    let entries = nonempty(&v, "entries");
    let root = entries.last().unwrap();
    assert_eq!(root["root"], true);
    assert!(root["author"].is_null() && root["signature"].is_null() && root["timestamp"].is_null());
    assert!(entries.iter().any(|e| e["current"] == true && e["workspaces"] == json!(["default"])), "{v}");
    let plan = entries.iter().find(|e| e["workspaces"] == json!(["plan"])).expect("the plan workspace");
    assert_eq!(plan["cloak"], "team");
    assert_eq!(plan["description"], CLOAKED_DESC, "alice is a member");
    assert_eq!(plan["tags"], json!([{"name": "plan-tag", "cloak": "team"}]));
    assert_eq!(plan["signature"]["status"], "good");
    let merge = entries.iter().find(|e| e["embargo"].is_object()).expect("the embargoed merge");
    assert_eq!(merge["embargo"]["released"], false);
    assert_eq!(merge["parents"].as_array().unwrap().len(), 2);
    assert!(entries.iter().any(|e| !e["remote_tags"].as_array().unwrap().is_empty()), "{v}");

    let v = json_ok(&w.env, "alice", &w.alice, &["log", "-n", "2", "--json"]);
    check_doc(&v, "veil.log/1");
    assert_eq!(v["entries"].as_array().unwrap().len(), 2);
    assert_eq!(v["truncated"], true);

    // Bob: the sealed description is hidden, with its scope.
    let v = json_ok(&w.env, "bob", &w.bob, &["log", "--json"]);
    check_doc(&v, "veil.log/1");
    let plan = v["entries"].as_array().unwrap().iter().find(|e| e["cloak"] == "team").expect("the cloaked change");
    assert!(plan["description"].is_null(), "{plan}");
    assert_eq!(plan["description_hidden"], json!({"scope": "team", "reason": "no_key"}));
}

#[test]
fn diff_and_show_shape() {
    let w = world();
    let (env, alice) = (&w.env, &w.alice);
    let v = json_ok(env, "alice", alice, &["diff", "--from", "root()", "--to", "main", "--json"]);
    check_doc(&v, "veil.diff/1");
    assert_eq!(v["stat"], false);
    let files = nonempty(&v, "files");
    let by = |p: &str| files.iter().find(|f| f["path"] == p).unwrap_or_else(|| panic!("no {p} in {v}"));
    let readme = by("README.md");
    assert_eq!(readme["status"], "added");
    assert!(readme["old"].is_null());
    let hunk = &readme["content"]["hunks"][0];
    assert_eq!(hunk["lines"][0], json!({"kind": "added", "text": "hello", "newline": true}));
    assert_eq!(by("logo.bin")["content"]["binary"], true);
    assert_eq!(by("logo.bin")["content"]["hunks"], json!([]));
    #[cfg(unix)]
    assert_eq!(by("run.sh")["new"]["mode"], "100755");
    assert_eq!(by("internal/plan.md")["new"]["visibility"], json!({"kind": "cloaked", "scope": "team", "embargo": null}));
    assert!(!files.iter().any(|f| f["path"] == ".env"), "isolated files are never recorded");

    let v = json_ok(env, "alice", alice, &["diff", "--from", "root()", "--to", "main", "--stat", "--json"]);
    check_doc(&v, "veil.diff/1");
    assert!(v["files"].as_array().unwrap().iter().all(|f| f["content"].is_null()), "{v}");

    // A modification and a deletion.
    write(alice, "README.md", "hello\nworld");
    std::fs::remove_file(alice.join("run.sh")).unwrap();
    let v = json_ok(env, "alice", alice, &["diff", "--json"]);
    check_doc(&v, "veil.diff/1");
    let files = nonempty(&v, "files");
    let readme = files.iter().find(|f| f["path"] == "README.md").unwrap();
    assert_eq!(readme["status"], "modified");
    let lines = readme["content"]["hunks"][0]["lines"].as_array().unwrap();
    assert!(lines.iter().any(|l| l["text"] == "world" && l["newline"] == false && l["kind"] == "added"), "{readme}");
    assert!(files.iter().any(|f| f["path"] == "run.sh" && f["status"] == "deleted" && f["new"].is_null()), "{v}");

    let v = json_ok(env, "alice", alice, &["show", "main", "--json"]);
    check_doc(&v, "veil.show/1");
    assert_eq!(v["tags"], json!(["main"]));
    assert_eq!(v["embargo"]["state"], "pending");
    assert_eq!(v["parents"].as_array().unwrap().len(), 2);
    assert_eq!(v["signature"]["status"], "good");
    let v = json_ok(env, "alice", alice, &["show", "root()", "--json"]);
    check_doc(&v, "veil.show/1");
    assert!(v["root"] == true && v["signature"].is_null());

    // Bob: the cloaked file's content is hidden, with a reason.
    let v = json_ok(env, "bob", &w.bob, &["diff", "--from", "root()", "--to", "main", "--json"]);
    check_doc(&v, "veil.diff/1");
    let plan = v["files"].as_array().unwrap().iter().find(|f| f["path"] == "internal/plan.md").unwrap();
    assert_eq!(plan["new"]["readable"], false);
    assert_eq!(plan["content"]["hidden"]["reason"], "no_key");
    assert_eq!(plan["content"]["hunks"], json!([]));
    let v = json_ok(env, "bob", &w.bob, &["show", "plan-tag", "--json"]);
    check_doc(&v, "veil.show/1");
    assert!(v["description"].is_null());
    assert_eq!(v["description_hidden"]["scope"], "team");

    // Carol read the public mirror: the cloaked content was withheld.
    let v = json_ok(env, "carol", &w.carol, &["diff", "--from", "root()", "--to", "main", "--json"]);
    check_doc(&v, "veil.diff/1");
}

#[test]
fn list_shapes() {
    let w = world();
    let (env, alice) = (&w.env, &w.alice);
    let v = json_ok(env, "alice", alice, &["ws", "list", "--json"]);
    check_doc(&v, "veil.workspace.list/1");
    let ws = nonempty(&v, "workspaces");
    assert!(ws.iter().any(|w| w["name"] == "default" && w["current"] == true));
    assert!(ws.iter().any(|w| w["name"] == "plan" && w["cloak"] == "team" && w["current"] == false));

    let v = json_ok(env, "alice", alice, &["tag", "list", "--json"]);
    check_doc(&v, "veil.tag.list/1");
    nonempty(&v, "tags");
    let remote = nonempty(&v, "remote_tags");
    assert!(remote.iter().any(|t| t["name"].as_str().unwrap().contains('/')), "{v}");

    let v = json_ok(env, "alice", alice, &["op", "log", "-n", "3", "--json"]);
    check_doc(&v, "veil.op.log/1");
    assert_eq!(nonempty(&v, "operations").len(), 3);

    let v = json_ok(env, "alice", alice, &["secret", "list", "--json"]);
    check_doc(&v, "veil.secret.list/1");
    assert_eq!(v["secrets"], json!([{"name": "API_TOKEN"}]));
}

#[test]
fn ls_shape() {
    let w = world();
    let (env, alice) = (&w.env, &w.alice);
    write(alice, "cfg.py", &format!("token = '{TOKEN}'\n"));
    std::fs::create_dir_all(alice.join("target")).unwrap();
    write(alice, "target/out.o", "x\n");
    let v = json_ok(env, "alice", alice, &["ls", "--all", "--json"]);
    check_doc(&v, "veil.ls/1");
    assert_eq!((v["working_copy"].clone(), v["all"].clone()), (json!(true), json!(true)));
    let entries = nonempty(&v, "entries");
    let get = |p: &str| entries.iter().find(|e| e["path"] == p).unwrap_or_else(|| panic!("{p} not listed: {v}")).clone();
    assert_eq!(get("logo.bin")["tier"], "public");
    assert_eq!(get("README.md")["tier"], "embargoed", "@ is on the embargoed merge, whose key Alice holds");
    let plan = get("internal/plan.md");
    assert_eq!((plan["tier"].clone(), plan["scope"].clone(), plan["readable"].clone()), (json!("cloaked"), json!("team"), json!(true)));
    let env_file = get(".env");
    assert_eq!((env_file["tier"].clone(), env_file["recorded"].clone()), (json!("isolated"), json!(false)));
    let q = get("cfg.py");
    assert_eq!((q["tier"].clone(), q["quarantine"]["state"].clone()), (json!("quarantined"), json!("never_recorded")));
    let t = get("target");
    assert_eq!((t["tier"].clone(), t["dir"].clone(), t["size"].clone()), (json!("ignored"), json!(true), Value::Null));
    assert_eq!(get("run.sh")["executable"], true);

    // Bob holds no key: the cloaked file is redacted, with the reason.
    let v = json_ok(env, "bob", &w.bob, &["ls", "--json"]);
    check_doc(&v, "veil.ls/1");
    let entries = nonempty(&v, "entries");
    let plan = entries.iter().find(|e| e["path"] == "internal/plan.md").unwrap();
    assert_eq!((plan["tier"].clone(), plan["readable"].clone()), (json!("redacted"), json!(false)), "{v}");
    assert_eq!(plan["redaction"]["reason"], "no_key");
    // Alice holds the embargo key: main's README.md is embargoed for her.
    let v = json_ok(env, "alice", alice, &["ls", "-r", "main", "README.md", "--json"]);
    check_doc(&v, "veil.ls/1");
    assert_eq!(v["working_copy"], false);
    let e = &nonempty(&v, "entries")[0];
    assert_eq!(e["tier"], "embargoed", "{v}");
    assert!(e["embargo"].is_string());
}

#[test]
fn push_plan_shape() {
    let w = world();
    let (env, alice) = (&w.env, &w.alice);
    write(alice, "new.txt", "new\n");
    env.ok("alice", alice, &["commit", "-m", "next"]);
    env.ok("alice", alice, &["tag", "set", "next", "-r", "@-"]);
    let v = json_ok(env, "alice", alice, &["push", "--dry-run", "--json"]);
    check_doc(&v, "veil.push.plan/1");
    let remotes = nonempty(&v, "remotes");
    assert_eq!(remotes.len(), 2, "every configured remote: {v}");
    let mirror = remotes.iter().find(|r| r["name"] == "mirror").unwrap();
    assert_eq!(mirror["public"], true);
    let next = mirror["tags"].as_array().unwrap().iter().find(|t| t["name"] == "next").unwrap();
    assert_eq!(next["action"], "create");
    // `@` builds on the embargoed merge: new work there is sealed under the
    // embargo, so the mirror does not get it yet.
    let withheld = mirror["files"]["withheld"].as_array().unwrap();
    assert!(withheld.iter().any(|f| f["path"] == "new.txt" && f["reason"] == "embargoed"), "{mirror}");
    assert!(mirror["files"]["published"].as_array().unwrap().is_empty(), "{mirror}");
    assert!(!nonempty(mirror, "withheld_snapshots").is_empty());
    let skipped = mirror["tags"].as_array().unwrap().iter().find(|t| t["name"] == "plan-tag").unwrap();
    assert_eq!(skipped["action"], "skipped");
    let origin = remotes.iter().find(|r| r["name"] == "origin").unwrap();
    assert!(origin["files"].is_null(), "file lists are for public remotes");
    assert!(origin["objects"].as_u64().unwrap() >= 3);
    assert_eq!(origin["object_ids"].as_array().unwrap().len() as u64, origin["objects"].as_u64().unwrap());
    // One remote; --json needs --dry-run.
    let v = json_ok(env, "alice", alice, &["push", "origin", "--dry-run", "--json"]);
    assert_eq!(nonempty(&v, "remotes").len(), 1);
    assert!(!env.vl("alice", alice, &["push", "--json"]).status.success());
}

#[test]
fn scan_shape_and_exit_status() {
    let w = world();
    let (env, alice) = (&w.env, &w.alice);
    write(alice, ".env", &format!("API={ISOLATED_TEXT}\nGH={TOKEN}\n"));
    let v = json_ok(env, "alice", alice, &["scan", "--json"]);
    check_doc(&v, "veil.scan/1");
    assert_eq!(v["mode"], "working_copy");
    assert_eq!(v["clean"], true);
    let f = nonempty(&v, "files");
    assert!(f.iter().any(|f| f["path"] == ".env" && f["tier"] == "isolated" && f["protected"] == true), "{v}");

    write(alice, "cfg.py", &format!("token = '{TOKEN}'\n"));
    let (v, code) = json_doc(env, "alice", alice, &["scan", "--json"]);
    check_doc(&v, "veil.scan/1");
    assert_eq!(code, Some(1), "an exposed secret fails the scan, JSON or not");
    assert_eq!(v["clean"], false);
    assert_eq!(v["exposed"], 1);
    assert_absent(&v.to_string(), &[TOKEN, ISOLATED_TEXT], "scan");

    // The CI gate: every file counts as public; an unreadable one is reported.
    let policy = env.root.join("base.veilpolicy");
    std::fs::write(&policy, "").unwrap();
    let ci = env.dir("checkout");
    write(&ci, "cfg.py", &format!("token = '{TOKEN}'\n"));
    let (v, code) = json_doc(env, "alice", &ci, &["scan", "--policy-from", policy.to_str().unwrap(), "--json"]);
    check_doc(&v, "veil.scan/1");
    assert_eq!((code, v["mode"].as_str(), v["exposed"].as_u64()), (Some(1), Some("gate"), Some(1)), "{v}");
    assert_eq!(v["policy_from"], policy.to_str().unwrap());
    assert_absent(&v.to_string(), &[TOKEN], "scan gate");
}

#[test]
fn errors_are_a_json_document_too() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let (v, code) = json_doc(&env, "alice", &proj, &["show", "no-such-rev", "--json"]);
    assert_eq!(code, Some(1));
    check_doc(&v, "veil.error/1");
    assert!(v["error"]["message"].as_str().unwrap().contains("no-such-rev"), "{v}");
    // Without --json, stdout stays empty; stderr has the error either way.
    let out = env.vl("alice", &proj, &["show", "no-such-rev"]);
    assert!(out.stdout.is_empty());
    let out = env.vl("alice", &proj, &["show", "no-such-rev", "--json"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("error:"));
    // A bare repository refuses `status`: a JSON error, same exit code.
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &proj, &["push"]);
    let (v, code) = json_doc(&env, "alice", &env.root, &["-R", team.to_str().unwrap(), "status", "--json"]);
    assert_eq!(code, Some(1));
    check_doc(&v, "veil.error/1");
    // Outside a repository.
    let nowhere = env.dir("nowhere");
    let (v, code) = json_doc(&env, "alice", &nowhere, &["log", "--json"]);
    assert_eq!(code, Some(1));
    check_doc(&v, "veil.error/1");
}

#[test]
fn json_is_escaped_for_terminals_but_decodes_to_the_raw_data() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let evil = "evil\x1b]0;pwned\x07\u{202e}\u{9b}name";
    env.ok("alice", &proj, &["describe", "-r", "@-", "-m", evil]);
    let out = env.vl("alice", &proj, &["log", "--json"]);
    let raw = String::from_utf8(out.stdout).unwrap();
    assert!(!raw.chars().any(|c| c.is_control() && c != '\n' || c == '\u{202e}'), "raw controls on stdout: {raw:?}");
    let v: Value = serde_json::from_str(&raw).unwrap();
    assert!(v["entries"].as_array().unwrap().iter().any(|e| e["description"] == evil), "{v}");
}

/// No plaintext of cloaked, embargoed or isolated content, no sealed
/// description and no secret value, in any JSON output of any read command
/// on any revision, for anyone who may not read it.
#[test]
fn no_confidential_plaintext_in_any_json_output() {
    let w = world();
    // Bob: on the team remote, but not in `team`.
    let bob = all_json(&w.env, "bob", &w.bob);
    assert_absent(&bob, &[CLOAKED_TEXT, CLOAKED_DESC, ISOLATED_TEXT, VAULT_VALUE, EMBARGO_TEXT], "bob");
    assert!(bob.contains("no_key"), "bob's output should explain the redaction");
    // Carol: the public mirror.
    let carol = all_json(&w.env, "carol", &w.carol);
    assert_absent(&carol, &[CLOAKED_TEXT, CLOAKED_DESC, ISOLATED_TEXT, VAULT_VALUE, EMBARGO_TEXT, "plan-tag"], "carol");
    // Alice herself: isolated files and vault values never appear either.
    write(&w.alice, ".env", &format!("API={ISOLATED_TEXT}\nGH={TOKEN}\n"));
    let alice = all_json(&w.env, "alice", &w.alice);
    assert_absent(&alice, &[ISOLATED_TEXT, VAULT_VALUE, TOKEN], "alice");
    assert!(alice.contains(CLOAKED_TEXT) && alice.contains(CLOAKED_DESC), "alice is a member and reads it");
}

/// Every key of every schema is documented in `docs/reference/json.md`,
/// under that schema's heading or under "Common objects".
#[test]
fn every_schema_field_is_documented() {
    let doc = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/reference/json.md")).unwrap();
    fn keys(spec: &Value, out: &mut Vec<String>) {
        match spec {
            Value::Object(o) => {
                for (k, v) in o {
                    if k != "?" {
                        out.push(k.clone());
                    }
                    keys(v, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
            _ => {}
        }
    }
    let section = |heading: &str| -> &str {
        let start = doc.find(heading).unwrap_or_else(|| panic!("json.md has no section {heading}"));
        let rest = &doc[start + heading.len()..];
        &rest[..rest.find("\n## ").unwrap_or(rest.len())]
    };
    // Objects several schemas share are documented once.
    let common = section("## Common objects");
    let mut missing = Vec::new();
    for (schema, spec) in specs() {
        let own = section(&format!("## `{schema}`"));
        let mut ks = Vec::new();
        keys(&spec, &mut ks);
        for k in ks {
            let k = format!("`{k}`");
            if !own.contains(&k) && !common.contains(&k) {
                missing.push(format!("{schema}: {k}"));
            }
        }
    }
    assert!(missing.is_empty(), "undocumented fields in docs/reference/json.md:\n  {}", missing.join("\n  "));
}

/// `vl split --json` and `vl squash --json` (write commands with a result
/// document).
#[test]
fn split_and_squash_shapes() {
    let env = Env::new();
    let p = env.project("alice", "p", &[("a.txt", "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n"), ("b.txt", "b\n")]);
    write(&p, "a.txt", "ONE\n2\n3\n4\n5\n6\n7\n8\n9\nTEN\n");
    write(&p, "b.txt", "B\n");
    let v = json_ok(&env, "alice", &p, &["split", "--hunks", "a.txt:1", "-m", "first", "--json"]);
    check_doc(&v, "veil.split/1");
    assert_eq!(v["chosen"], json!([{"path": "a.txt", "whole": false, "hunks": ["1"]}]));
    assert_eq!(v["first"]["description"], "first");
    let v = json_ok(&env, "alice", &p, &["squash", "b.txt", "--json"]);
    check_doc(&v, "veil.squash/1");
    assert_eq!(v["source_abandoned"], false);
    assert_eq!(v["moved"], json!([{"path": "b.txt", "whole": true, "hunks": []}]));
    let v = json_ok(&env, "alice", &p, &["squash", "--json"]);
    check_doc(&v, "veil.squash/1");
    assert_eq!(v["source"], Value::Null);
    assert_eq!(v["source_abandoned"], true);
    // A refusal is a `veil.error/1` document.
    let (v, code) = json_doc(&env, "alice", &p, &["split", "nothing-here", "--json"]);
    assert_eq!(code, Some(1));
    check_doc(&v, "veil.error/1");
}
