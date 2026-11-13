//! The history read tools through the real `vl` binary (Git-parity stream
//! H): `vl blame`, `vl grep`, `vl bisect`, the `vl log` filters and rename
//! detection in `vl diff` / `vl show` / `vl status`, plus the `blame` and
//! `grep` methods of `vl serve`.
//!
//! The confidentiality tests byte-search every output (text, `--json`,
//! `vl serve`, stderr) of every new command, on every revision, as a
//! non-member and as a public-mirror reader, for cloaked, isolated,
//! quarantined, vault and embargoed content (the designs' threat reviews:
//! `docs/design/git-parity/1-…`, `2-…`, `3-…`).

use crate::adversarial_support;

use std::{
    io::Write as _,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Output, Stdio},
    time::Duration,
};

use adversarial_support::*;
use serde_json::Value;

// ---- helpers -------------------------------------------------------------------------

fn write_stdin(env: &Env, user: &str, dir: &Path, args: &[&str], input: &[u8]) {
    let mut c = env.cmd(user, dir, args);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "vl {args:?}: {}", text(&out));
}

/// `vl args --json`: exactly one document on one line.
fn json(env: &Env, user: &str, dir: &Path, args: &[&str]) -> (Value, Option<i32>) {
    let out = env.vl(user, dir, args);
    let stdout = String::from_utf8(out.stdout.clone()).expect("UTF-8");
    assert_eq!(stdout.lines().count(), 1, "vl {args:?}: one line:\n{}", text(&out));
    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("vl {args:?}: {e}: {stdout}"));
    (v, out.status.code())
}

fn json_ok(env: &Env, user: &str, dir: &Path, args: &[&str]) -> Value {
    let (v, code) = json(env, user, dir, args);
    assert_eq!(code, Some(0), "vl {args:?}: {v}");
    v
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn log_ids(env: &Env, user: &str, dir: &Path, args: &[&str]) -> Vec<String> {
    let mut a = vec!["log", "--json"];
    a.extend_from_slice(args);
    let v = json_ok(env, user, dir, &a);
    v["entries"].as_array().unwrap().iter().map(|e| e["change_short"].as_str().unwrap().to_string()).collect()
}

/// The snapshot id of a revision.
fn snapshot(env: &Env, user: &str, dir: &Path, rev: &str) -> String {
    let v = json_ok(env, user, dir, &["show", rev, "--stat", "--json"]);
    v["snapshot_id"].as_str().unwrap().to_string()
}

/// The change id of a revision.
fn change(env: &Env, user: &str, dir: &Path, rev: &str) -> String {
    let v = json_ok(env, user, dir, &["show", rev, "--stat", "--json"]);
    v["change_short"].as_str().unwrap().to_string()
}

fn commit(env: &Env, dir: &Path, files: &[(&str, &str)], msg: &str) -> String {
    for (p, c) in files {
        write(dir, p, c);
    }
    env.ok("alice", dir, &["commit", "-m", msg]);
    change(env, "alice", dir, "@-")
}

/// A `vl serve --local` for `dir`, stopped on drop.
struct Server {
    child: Child,
}

impl Server {
    fn start(env: &Env, user: &str, dir: &Path) -> Server {
        let mut child = env.spawn(user, dir, &["serve", "--local"]);
        let sock = dir.join(".veil/local/sock");
        let up = wait_for(Duration::from_secs(20), || {
            if let Ok(Some(_)) = child.try_wait() {
                return true;
            }
            UnixStream::connect(&sock).is_ok()
        });
        assert!(up && child.try_wait().unwrap().is_none(), "vl serve did not start ({})", sock.display());
        Server { child }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---- the confidentiality world ----------------------------------------------------------

const CLOAKED_TEXT: &str = "CLOAKED-PLAN-4417";
const CLOAKED_LINE: &str = "CLOAKED-LINE-2290";
/// The sealed secret file.
const PLAN: &str = "internal/.env.plan";
const ISOLATED_TEXT: &str = "ISOLATED-VALUE-6623";
const VAULT_VALUE: &str = "VAULT-VALUE-1187";
const TOKEN: &str = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
const EMBARGO_TEXT: &str = "EMBARGOED-FIX-3359";
/// The name of a file the embargoed fix creates by renaming another.
const EMBARGO_NAME: &str = "renamed_by_fix";

struct World {
    env: Env,
    alice: PathBuf,
    /// Cloned the team remote, holds no key for `team`.
    bob: PathBuf,
    /// Cloned the public mirror.
    carol: PathBuf,
}

/// Alice's project: a cloaked secret file edited twice (the second time on
/// another line of work, tagged `plan-tag`), an isolated `.netrc`, a
/// quarantined file, a vault secret, and an unreleased embargoed fix that
/// edits `src/vuln.c` and renames a file (tag `base`: main before it).
fn world() -> World {
    let env = Env::new();
    let alice = env.dir("alice");
    write(&alice, "README.md", "hello\nworld\n");
    write(&alice, PLAN, &format!("{CLOAKED_TEXT}\n"));
    write(&alice, "src/vuln.c", "int check(int x) {\n  return 1;\n}\n");
    write(&alice, "src/old.c", "int old(void) {\n  return 0;\n}\n/* padding so the rename is inexact */\n");
    write(&alice, ".netrc", &format!("KEY={ISOLATED_TEXT}\n"));
    env.ok("alice", &alice, &["init"]);
    env.ok("alice", &alice, &["cloak", PLAN]);
    env.ok("alice", &alice, &["commit", "-m", "initial"]);
    env.ok("alice", &alice, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &alice, &["secret", "set", "API_TOKEN", VAULT_VALUE]);
    // A quarantined file: stays local.
    write(&alice, "leak.txt", &format!("token = {TOKEN}\n"));

    // Another line of work: edits the cloaked file.
    env.ok("alice", &alice, &["ws", "new", "plan", "-r", "main"]);
    write_stdin(&env, "alice", &alice, &["ws", "write", "plan", PLAN], format!("{CLOAKED_TEXT} v2\n{CLOAKED_LINE}\nKEY step\n").as_bytes());
    env.ok("alice", &alice, &["describe", "-r", "plan@", "-m", "plan"]);
    env.ok("alice", &alice, &["tag", "set", "plan-tag", "-r", "plan@"]);

    // An unreleased embargo on main: the fix edits vuln.c and renames old.c.
    env.ok("alice", &alice, &["ws", "new", "fix", "-r", "main"]);
    write_stdin(&env, "alice", &alice, &["ws", "write", "fix", "src/vuln.c"], format!("int check(int x) {{\n  return x < 10; /* {EMBARGO_TEXT} */\n}}\n").as_bytes());
    let rename = format!("mv src/old.c src/{EMBARGO_NAME}.c && echo '/* more */' >> src/{EMBARGO_NAME}.c");
    env.ok("alice", &alice, &["ws", "exec", "fix", "-m", "fix", "--", "sh", "-c", &rename]);
    env.ok("alice", &alice, &["describe", "-r", "fix@", "-m", "fix"]);
    env.ok("alice", &alice, &["merge", "fix@", "--into", "main", "--embargo", "-m", "embargoed merge"]);
    // Main before the embargoed merge: what the remotes receive of it.
    env.ok("alice", &alice, &["tag", "set", "base", "-r", "plan@-"]);

    let team = env.root.join("team");
    let mirror = env.root.join("mirror");
    env.ok("alice", &alice, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &alice, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    // Pushed; `leak.txt` stays quarantined, so each push says so (BUG-2140).
    env.quarantined("alice", &alice, &["push"]);
    env.quarantined("alice", &alice, &["push", "mirror"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    env.ok("carol", &env.root, &["clone", "mirror", "carol"]);
    World { bob: env.root.join("bob"), carol: env.root.join("carol"), env, alice }
}

/// Everything every new command prints (stdout and stderr, text and
/// JSON, and `vl serve`) as `user` in `dir`, on every revision `vl log`
/// shows and for every file.
fn all_output(env: &Env, user: &str, dir: &Path) -> String {
    let mut out = String::new();
    let mut run = |args: Vec<String>| {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = env.vl(user, dir, &a);
        assert!(!text(&o).contains("panicked"), "vl {a:?}: {}", text(&o));
        out.push_str(&text(&o));
        out.push('\n');
    };
    let log = json_ok(env, user, dir, &["log", "--json"]);
    let ids: Vec<String> = log["entries"].as_array().unwrap().iter().map(|e| e["snapshot_id"].as_str().unwrap().to_string()).collect();
    let secrets = [CLOAKED_TEXT, CLOAKED_LINE, EMBARGO_TEXT, ISOLATED_TEXT, VAULT_VALUE, TOKEN, EMBARGO_NAME, "KEY", "."];
    // (Never the fix's new file name: an error would echo the argument.)
    let files = ["README.md", PLAN, "src/vuln.c", "src/old.c", ".netrc", "leak.txt"];
    for id in &ids {
        for f in files {
            for extra in [&[][..], &["--json"], &["--public"], &["--follow", "--json"]] {
                let mut a: Vec<String> = ["blame", f, "-r", id].iter().map(|s| s.to_string()).collect();
                a.extend(extra.iter().map(|s| s.to_string()));
                run(a);
            }
        }
        for s in secrets {
            for extra in [&["-n"][..], &["--json"], &["-c"], &["-l"], &["-i", "-a", "--json"]] {
                let mut a: Vec<String> = ["grep", s, "-r", id].iter().map(|s| s.to_string()).collect();
                a.extend(extra.iter().map(|s| s.to_string()));
                run(a);
            }
        }
        for extra in [&["--stat"][..], &["-C"], &["-C", "--json"], &["--stat", "-C", "--json"], &["-M=10", "--json"]] {
            let mut a: Vec<String> = ["show", id].iter().map(|s| s.to_string()).collect();
            a.extend(extra.iter().map(|s| s.to_string()));
            run(a);
            let mut a: Vec<String> = ["diff", "-r", id].iter().map(|s| s.to_string()).collect();
            a.extend(extra.iter().map(|s| s.to_string()));
            run(a);
        }
    }
    for s in secrets {
        for extra in [&["-S", s][..], &["-G", s], &["-S", s, "--show-skipped", "--json"], &["-G", s, "-i", "--pickaxe-all", "--json"], &["--author", s]] {
            let mut a = vec!["log".to_string()];
            a.extend(extra.iter().map(|s| s.to_string()));
            run(a);
        }
    }
    for f in files {
        run(vec!["log".into(), "--json".into(), "--".into(), f.into()]);
        run(vec!["log".into(), "--follow".into(), "--show-skipped".into(), f.into()]);
    }
    run(vec!["status".into(), "--json".into()]);
    run(vec!["status".into()]);
    // `vl serve`: the same documents.
    let server = Server::start(env, user, dir);
    for id in &ids {
        for f in files {
            run(vec!["serve".into(), "--call".into(), "blame".into(), format!("{{\"path\":\"{f}\",\"rev\":\"{id}\"}}")]);
        }
        for s in secrets {
            run(vec!["serve".into(), "--call".into(), "grep".into(), format!("{{\"pattern\":\"{s}\",\"rev\":\"{id}\",\"ignore_case\":true}}")]);
        }
    }
    drop(server);
    out
}

fn assert_absent(haystack: &str, needles: &[&str], who: &str) {
    for n in needles {
        assert!(!haystack.contains(n), "{who}: {n:?} appears in the output");
    }
}

/// No cloaked (secret-file), embargoed, isolated, quarantined or vault
/// content and not the embargoed fix's new file name, in any
/// output of the history tools for a non-member and a public-mirror
/// reader; isolated, quarantined and vault content not even for the
/// owner.
#[test]
fn history_tools_never_reveal_confidential_content() {
    let w = world();
    let bob = all_output(&w.env, "bob", &w.bob);
    assert_absent(&bob, &[CLOAKED_TEXT, CLOAKED_LINE, EMBARGO_TEXT, EMBARGO_NAME, ISOLATED_TEXT, VAULT_VALUE, TOKEN], "bob");
    assert!(bob.contains("hello"), "bob reads public content");
    let carol = all_output(&w.env, "carol", &w.carol);
    assert_absent(&carol, &[CLOAKED_TEXT, CLOAKED_LINE, EMBARGO_TEXT, EMBARGO_NAME, ISOLATED_TEXT, VAULT_VALUE, TOKEN], "carol");
    let alice = all_output(&w.env, "alice", &w.alice);
    assert_absent(&alice, &[ISOLATED_TEXT, VAULT_VALUE, TOKEN], "alice");
    assert!(alice.contains(CLOAKED_TEXT) && alice.contains(CLOAKED_LINE) && alice.contains(EMBARGO_TEXT), "alice reads her own work");
}

/// Design 3, threat 1: `vl grep` never searches (or counts) isolated or
/// quarantined files, for their owner either: no existence oracle.
#[test]
fn grep_never_searches_or_counts_local_only_files() {
    let w = world();
    let (v, _) = json(&w.env, "alice", &w.alice, &["grep", "KEY|token", "-r", "@", "--json"]);
    let s = v.to_string();
    assert!(!s.contains(".netrc") && !s.contains("leak.txt") && !s.contains(ISOLATED_TEXT) && !s.contains(TOKEN), "{s}");
    assert_eq!(v["skipped"]["sealed"], 0);
    // Exactly the snapshot's files were looked at.
    let ls = json_ok(&w.env, "alice", &w.alice, &["ls", "--json"]);
    let recorded = ls["entries"].as_array().unwrap().iter().filter(|e| !matches!(e["tier"].as_str(), Some("isolated" | "quarantined" | "ignored"))).count();
    assert_eq!(v["searched"].as_u64().unwrap() as usize, recorded, "{ls}");
    let out = w.env.vl("alice", &w.alice, &["grep", ISOLATED_TEXT]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(stdout_of(&out).is_empty());
}

/// Design 3, threat 12: for a non-member the cloaked file is
/// `skipped.sealed`; public hits are labelled `public`.
#[test]
fn sealed_files_are_skipped_for_readers_without_the_key() {
    let w = world();
    let plan = snapshot(&w.env, "alice", &w.alice, "plan@");
    let v = json_ok(&w.env, "bob", &w.bob, &["grep", "hello", "-r", &plan, "--json"]);
    assert_eq!(v["matches"][0]["path"], "README.md");
    assert_eq!(v["matches"][0]["tier"], "public", "{v}");
    assert_eq!(v["skipped"]["sealed"], 1, "{PLAN}: {v}");
    let (v, code) = json(&w.env, "bob", &w.bob, &["grep", CLOAKED_TEXT, "-r", &plan, "--json"]);
    assert_eq!(code, Some(1), "{v}");
    assert!(v["matches"].as_array().unwrap().is_empty(), "{v}");
    let v = json_ok(&w.env, "alice", &w.alice, &["grep", CLOAKED_TEXT, "-r", "plan@", "--json"]);
    assert_eq!(v["matches"][0]["tier"], "cloaked");
}

/// Design 1, threats 1-2: an outsider's blame of the cloaked file is
/// refused with the explanation, not its bytes; the member's attributes
/// her edit.
#[test]
fn outsider_blame_of_a_sealed_file_is_refused() {
    let w = world();
    let edit = change(&w.env, "alice", &w.alice, "plan@");
    let plan = snapshot(&w.env, "alice", &w.alice, "plan@");
    {
        let (who, dir) = ("bob", &w.bob);
        let out = w.env.vl(who, dir, &["blame", PLAN, "-r", &plan]);
        assert_eq!(out.status.code(), Some(1));
        assert!(text(&out).contains("cloaked under scope 'team'"), "{}", text(&out));
        assert!(!text(&out).contains(CLOAKED_TEXT) && !text(&out).contains(CLOAKED_LINE), "{}", text(&out));
    }
    let v = json_ok(&w.env, "alice", &w.alice, &["blame", PLAN, "-r", "plan@", "--json"]);
    assert_eq!(v["lines"][1]["change_short"], edit.as_str());
    assert_eq!(v["lines"][1]["text"], CLOAKED_LINE);
    // --public: as the mirror sees it.
    let out = w.env.vl("alice", &w.alice, &["blame", PLAN, "-r", "plan@", "--public", "--json"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains(CLOAKED_LINE), "{}", text(&out));
}

/// Design 1, threat 3 and design 3, threat 4: the embargoed fix of
/// `src/vuln.c` reaches no remote. Outsiders have no `main`; their blame
/// of the pre-fix main attributes the line to the pre-fix change;
/// `log -- src/vuln.c` and `log -S` list neither the merge nor the fix.
#[test]
fn the_embargoed_fix_stays_invisible_to_history_tools() {
    let w = world();
    let initial = change(&w.env, "alice", &w.alice, "main-");
    let merge = change(&w.env, "alice", &w.alice, "main");
    let fix = change(&w.env, "alice", &w.alice, "fix@");
    let v = json_ok(&w.env, "alice", &w.alice, &["blame", "src/vuln.c", "-r", "main", "--json"]);
    assert_eq!(v["lines"][1]["change_short"], fix.as_str(), "alice sees the fix: {v}");
    for (who, dir) in [("bob", &w.bob), ("carol", &w.carol)] {
        assert!(!w.env.vl(who, dir, &["show", "main"]).status.success(), "{who} received the embargoed merge");
        let v = json_ok(&w.env, who, dir, &["blame", "src/vuln.c", "-r", "base", "--json"]);
        for l in v["lines"].as_array().unwrap() {
            assert_eq!(l["change_short"], initial.as_str(), "{who}: {v}");
        }
        let all = log_ids(&w.env, who, dir, &[]);
        assert!(!all.contains(&merge) && !all.contains(&fix), "{who}: {all:?}");
        assert!(!log_ids(&w.env, who, dir, &["--", "src/vuln.c"]).contains(&merge), "{who}");
        assert!(!log_ids(&w.env, who, dir, &["--", "src/old.c"]).contains(&merge), "{who}");
        assert!(!log_ids(&w.env, who, dir, &["-S", "return x < 10", "--show-skipped"]).contains(&merge), "{who}");
        assert!(log_ids(&w.env, who, dir, &["-S", "return x < 10"]).is_empty(), "{who}");
    }
    assert!(log_ids(&w.env, "alice", &w.alice, &["--", "src/vuln.c"]).contains(&fix));
    let v = json_ok(&w.env, "alice", &w.alice, &["show", "fix@", "--json"]);
    let renamed: Vec<&Value> = v["diff"]["files"].as_array().unwrap().iter().filter(|f| f["status"] == "renamed").collect();
    assert_eq!(renamed.len(), 1, "alice sees the fix's rename: {v}");
    assert_eq!(renamed[0]["from"], "src/old.c");
}

/// Design 3, threat 3: `log -S` on a string in a sealed secret file. The member finds the
/// change; the non-member does not, and `--show-skipped` lists it as not
/// searched.
#[test]
fn pickaxe_on_cloaked_text_needs_the_key() {
    let w = world();
    let cloaked = change(&w.env, "alice", &w.alice, "plan@");
    assert!(log_ids(&w.env, "alice", &w.alice, &["-S", CLOAKED_LINE]).contains(&cloaked));
    assert!(log_ids(&w.env, "bob", &w.bob, &["-S", CLOAKED_LINE]).is_empty());
    let v = json_ok(&w.env, "bob", &w.bob, &["log", "-S", CLOAKED_LINE, "--show-skipped", "--json"]);
    let e = v["entries"].as_array().unwrap();
    assert!(e.iter().any(|e| e["change_short"] == cloaked.as_str() && e["not_searched"][0]["scope"] == "team"), "{v}");
    assert!(v["search"]["skipped"].as_u64().unwrap() >= 1);
    let out = w.env.vl("bob", &w.bob, &["log", "-S", CLOAKED_LINE]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not searched"), "{}", text(&out));
}

// ---- blame -------------------------------------------------------------------------------

#[test]
fn blame_text_json_and_flags() {
    let env = Env::new();
    let dir = env.project("alice", "p", &[("f.txt", "one\ntwo\n")]);
    let first = change(&env, "alice", &dir, "@-");
    let second = commit(&env, &dir, &[("f.txt", "one\nTWO\nthree\n")], "second");
    let out = env.stdout("alice", &dir, &["blame", "f.txt"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with(&first[..8]) && lines[0].ends_with(") one"), "{out}");
    assert!(lines[1].starts_with(&second[..8]) && lines[1].contains("alice") && lines[1].ends_with("2) TWO"), "{out}");
    assert_eq!(env.stdout("alice", &dir, &["annotate", "f.txt"]), out);
    let v = json_ok(&env, "alice", &dir, &["blame", "f.txt", "-L", "2,3", "--json"]);
    assert_eq!(v["schema"], "veil.blame/2");
    assert_eq!(v["lines"].as_array().unwrap().len(), 2);
    assert_eq!(v["lines"][0]["line"], 2);
    assert_eq!(v["lines"][0]["author"], "alice");
    assert_eq!(v["changes"].as_array().unwrap().len(), 1);
    assert_eq!(v["unattributed"], 0);
    assert_eq!(v["stopped"], Value::Null);
    // Renamed: plain blame stops at the rename, --follow goes on.
    std::fs::rename(dir.join("f.txt"), dir.join("g.txt")).unwrap();
    env.ok("alice", &dir, &["commit", "-m", "rename"]);
    let v = json_ok(&env, "alice", &dir, &["blame", "g.txt", "-r", "@-", "--follow", "--json"]);
    assert_eq!(v["lines"][0]["change_short"], first.as_str());
    assert_eq!(v["lines"][0]["path"], "f.txt");
    // --max-changes 1: unattributed, reported.
    let out = env.vl("alice", &dir, &["blame", "g.txt", "-r", "@-", "--follow", "--max-changes", "1"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unattributed"), "{}", text(&out));
}

/// Hostile input: bad ranges, missing files, directories, paths outside
/// the repository; terminal escapes and bidi overrides in lines, authors
/// and paths are escaped (design 1, threat 6).
#[test]
fn blame_refuses_bad_input_and_escapes_what_it_prints() {
    let env = Env::new();
    let dir = env.project("alice", "p", &[("f.txt", "safe\nclip \x1b]52;c;ZXZpbA==\x07 board\nbidi \u{202e}txt.exe\n"), ("d/x", "x\n")]);
    for (args, want) in [
        (&["blame", "f.txt", "-L", "0,2"][..], "1 <= START"),
        (&["blame", "f.txt", "-L", "3,2"], "1 <= START"),
        (&["blame", "f.txt", "-L", "x,2"], "line numbers"),
        (&["blame", "f.txt", "-L", "1"], "START,END"),
        (&["blame", "f.txt", "-L", "99,100"], "fewer than 99 lines"),
        (&["blame", "nope.txt"], "does not exist"),
        (&["blame", "d"], "directory"),
        (&["blame", "../outside"], "outside"),
        (&["blame", "f.txt", "--max-changes", "0"], "at least 1"),
        (&["blame", "f.txt", "-r", "no-such-rev"], "not found"),
    ] {
        let out = env.vl("alice", &dir, args);
        assert_eq!(out.status.code(), Some(1), "vl {args:?}: {}", text(&out));
        assert!(text(&out).contains(want), "vl {args:?}: {}", text(&out));
        assert!(!text(&out).contains("panicked"));
    }
    let out = env.stdout("alice", &dir, &["blame", "f.txt"]);
    assert!(!out.contains('\x1b') && !out.contains('\u{202e}') && !out.contains('\x07'), "{out:?}");
    assert!(out.contains("\\x1b]52;"), "{out}");
    let raw = env.stdout("alice", &dir, &["blame", "f.txt", "--json"]);
    assert!(!raw.contains('\x1b') && !raw.contains('\u{202e}'), "{raw:?}");
    let v: Value = serde_json::from_str(&raw).unwrap();
    assert!(v["lines"][1]["text"].as_str().unwrap().contains("\x1b]52;"), "JSON decodes to the raw line");
}

// ---- grep --------------------------------------------------------------------------------

#[test]
fn grep_flags_output_and_exit_codes() {
    let env = Env::new();
    let dir = env.project("alice", "p", &[("a.txt", "Key one\nkey two\nmonkey\n"), ("src/b.rs", "let key = 1;\n"), ("bin.dat", "key\0\x01\x02\n")]);
    // (`.veilpolicy` mentions `*.key`.)
    let out = env.stdout("alice", &dir, &["grep", "key", "a.txt", "bin.dat", "src"]);
    assert_eq!(out, "a.txt:key two\na.txt:monkey\nbinary file bin.dat matches\nsrc/b.rs:let key = 1;\n");
    assert_eq!(env.stdout("alice", &dir, &["grep", "-n", "-i", "-w", "key", "a.txt", "bin.dat", "src"]), "a.txt:1:Key one\na.txt:2:key two\nbinary file bin.dat matches\nsrc/b.rs:1:let key = 1;\n");
    assert_eq!(env.stdout("alice", &dir, &["grep", "-l", "key", "--", "src"]), "src/b.rs\n");
    assert_eq!(env.stdout("alice", &dir, &["grep", "-c", "key", "a.txt"]), "a.txt:2\n");
    assert_eq!(env.stdout("alice", &dir, &["grep", "--max-count", "1", "key", "a.txt"]), "a.txt:key two\n");
    assert_eq!(env.stdout("alice", &dir, &["grep", "-F", "y = 1;"]), "src/b.rs:let key = 1;\n");
    assert!(env.stdout("alice", &dir, &["grep", "-a", "key", "bin.dat"]).starts_with("bin.dat:key"));
    let out = env.vl("alice", &dir, &["grep", "absent-string"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let v = json_ok(&env, "alice", &dir, &["grep", "key", "--json", "a.txt", "bin.dat", "src"]);
    assert_eq!(v["schema"], "veil.grep/2");
    assert_eq!(v["matches"].as_array().unwrap().len(), 3);
    assert_eq!(v["files"].as_array().unwrap().len(), 3);
    assert_eq!(v["skipped"]["binary"], 1);
    // Only the snapshot: a file written since is snapshotted first.
    write(&dir, "new.txt", "key new\n");
    assert!(env.stdout("alice", &dir, &["grep", "key new"]).starts_with("new.txt:"));
    // An older revision.
    assert!(env.vl("alice", &dir, &["grep", "key new", "-r", "@-"]).status.code() == Some(1));
}

/// Hostile input: invalid and huge patterns; escapes and bidi overrides in
/// matched lines and paths (design 3, threats 6 and 10).
#[test]
fn grep_refuses_bad_patterns_and_escapes_what_it_prints() {
    let env = Env::new();
    let dir = env.project("alice", "p", &[("x\u{202e}gpj.exe", "evil \x1b[2J\u{202e} line\n")]);
    for (args, want) in [(&["grep", "("][..], "invalid regular expression"), (&["grep", "a", "-r", "nope"], "not found")] {
        let out = env.vl("alice", &dir, args);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        assert!(text(&out).contains(want), "{}", text(&out));
    }
    let huge = "a".repeat(100 << 10);
    let out = env.vl("alice", &dir, &["grep", &huge]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("at most"), "{}", &text(&out)[..200.min(text(&out).len())]);
    let out = env.stdout("alice", &dir, &["grep", "evil"]);
    assert!(!out.contains('\x1b') && !out.contains('\u{202e}'), "{out:?}");
    assert!(out.contains("\\u{202e}"), "{out}");
    let raw = env.stdout("alice", &dir, &["grep", "evil", "--json"]);
    assert!(!raw.contains('\u{202e}') && raw.contains("\\u202e"), "{raw}");
}

// ---- log filters --------------------------------------------------------------------------

#[test]
fn log_filters_select_snapshots() {
    let env = Env::new();
    let dir = env.project("alice", "p", &[("src/a.rs", "fn a() {}\n"), ("doc.md", "d\n")]);
    let c1 = change(&env, "alice", &dir, "@-");
    let c2 = commit(&env, &dir, &[("doc.md", "d2\n")], "docs");
    let c3 = commit(&env, &dir, &[("src/a.rs", "fn a() {}\nfn needle() {}\n")], "needle");
    let c4 = commit(&env, &dir, &[("src/a.rs", "fn a() {}\nfn needle() { 1 }\n")], "edit needle");
    env.ok("alice", &dir, &["tag", "set", "start", "-r", &c1]);
    assert_eq!(log_ids(&env, "alice", &dir, &["--", "src"]), [c4.clone(), c3.clone(), c1.clone()]);
    assert_eq!(log_ids(&env, "alice", &dir, &["src/a.rs", "-n", "1"]), [c4.as_str()]);
    assert_eq!(log_ids(&env, "alice", &dir, &["-S", "needle"]), [c3.as_str()]);
    assert_eq!(log_ids(&env, "alice", &dir, &["-G", "need+le"]), [c4.clone(), c3.clone()]);
    assert_eq!(log_ids(&env, "alice", &dir, &["-G", "NEEDLE", "-i"]), [c4.clone(), c3.clone()]);
    assert_eq!(log_ids(&env, "alice", &dir, &["-r", "start..@-"]), [c4.clone(), c3.clone(), c2.clone()]);
    assert_eq!(log_ids(&env, "alice", &dir, &["-r", &c2]), [c2.as_str()]);
    assert_eq!(log_ids(&env, "alice", &dir, &["-r", "::start"]).len(), 2, "start and the root");
    assert_eq!(log_ids(&env, "alice", &dir, &["--author", "^ali", "--", "doc.md"]), [c2.clone(), c1.clone()]);
    assert!(log_ids(&env, "alice", &dir, &["--author", "^bob$"]).is_empty());
    assert_eq!(log_ids(&env, "alice", &dir, &["--signed-by", "alice", "--", "doc.md"]), [c2.clone(), c1.clone()]);
    assert!(log_ids(&env, "alice", &dir, &["--signed-by", "mallory"]).is_empty());
    let v = json_ok(&env, "alice", &dir, &["log", "-S", "needle", "--pickaxe-all", "--json"]);
    assert_eq!(v["entries"][0]["files"], serde_json::json!(["src/a.rs"]));
    assert_eq!(v["search"]["stopped"], false);
    let v = json_ok(&env, "alice", &dir, &["log", "--max-changes", "2", "--json", "--", "src"]);
    assert_eq!(v["search"]["searched"], 2);
    assert_eq!(v["search"]["stopped"], true);
    // --follow across a rename.
    std::fs::rename(dir.join("doc.md"), dir.join("moved.md")).unwrap();
    env.ok("alice", &dir, &["commit", "-m", "move"]);
    let moved = change(&env, "alice", &dir, "@-");
    assert_eq!(log_ids(&env, "alice", &dir, &["--follow", "moved.md"]), [moved.clone(), c2.clone(), c1.clone()]);
    assert_eq!(log_ids(&env, "alice", &dir, &["moved.md"]), [moved]);
    // Text output: the matched files.
    let out = env.stdout("alice", &dir, &["log", "-S", "needle"]);
    assert!(out.contains("matched in: src/a.rs"), "{out}");
    // Without filters, `vl log` is unchanged (no `search` key).
    let v = json_ok(&env, "alice", &dir, &["log", "--json"]);
    assert!(v.get("search").is_none());
}

#[test]
fn log_filters_refuse_bad_input() {
    let env = Env::new();
    let dir = env.project("alice", "p", &[("a", "a\n"), ("b", "b\n")]);
    for (args, want) in [
        (&["log", "--follow", "a", "b"][..], "exactly one"),
        (&["log", "--follow"], "exactly one"),
        (&["log", "--pickaxe-all"], "goes with -S or -G"),
        (&["log", "-G", "("], "invalid regular expression"),
        (&["log", "--author", "["], "invalid regular expression"),
        (&["log", "-S", ""], "non-empty"),
        (&["log", "-r", "a..b..c"], "one `..`"),
        (&["log", "-r", "::"], "names no revision"),
        (&["log", "-r", "nope..@"], "not found"),
        (&["log", "--max-changes", "0", "--", "a"], "at least 1"),
        (&["log", "--", "../x"], "outside"),
    ] {
        let out = env.vl("alice", &dir, args);
        assert_eq!(out.status.code(), Some(1), "vl {args:?}: {}", text(&out));
        assert!(text(&out).contains(want), "vl {args:?}: {}", text(&out));
    }
    let huge = "x".repeat(100 << 10);
    let out = env.vl("alice", &dir, &["log", "-G", &huge]);
    assert_eq!(out.status.code(), Some(1));
}

// ---- renames -------------------------------------------------------------------------------

#[test]
fn renames_in_status_diff_and_show() {
    let env = Env::new();
    let body: String = (0..20).map(|i| format!("line {i}\n")).collect();
    let dir = env.project("alice", "p", &[("old.txt", &body), ("keep.txt", "k\n")]);
    std::fs::rename(dir.join("old.txt"), dir.join("new.txt")).unwrap();
    let st = env.stdout("alice", &dir, &["status"]);
    assert!(st.contains("R old.txt -> new.txt"), "{st}");
    let v = json_ok(&env, "alice", &dir, &["status", "--json"]);
    let c = &v["changes"][0];
    assert_eq!((c["status"].as_str(), c["from"].as_str(), c["path"].as_str(), c["score"].as_u64()), (Some("renamed"), Some("old.txt"), Some("new.txt"), Some(100)));
    assert_eq!(v["changes"].as_array().unwrap().len(), 1);
    assert_eq!(env.stdout("alice", &dir, &["diff", "--stat"]), "R100 old.txt -> new.txt\n");
    let d = env.stdout("alice", &dir, &["diff"]);
    assert!(d.starts_with("diff --veil a/old.txt b/new.txt\nsimilarity index 100%\nrename from old.txt\nrename to new.txt\n"), "{d}");
    assert_eq!(env.stdout("alice", &dir, &["diff", "--stat", "--no-renames"]), "A new.txt\nD old.txt\n");
    // Edited while moved: inexact, with the threshold.
    write(&dir, "new.txt", &format!("{body}one more\n"));
    let s = env.stdout("alice", &dir, &["diff", "--stat"]);
    assert!(s.starts_with("R09") , "{s}");
    assert_eq!(env.stdout("alice", &dir, &["diff", "--stat", "-M=99"]), "A new.txt\nD old.txt\n");
    let v = json_ok(&env, "alice", &dir, &["diff", "--json"]);
    let f = &v["files"][0];
    assert_eq!((f["status"].as_str(), f["from"].as_str()), (Some("renamed"), Some("old.txt")));
    assert!(f["content"]["hunks"][0]["lines"].as_array().unwrap().iter().any(|l| l["text"] == "one more"));
    // Copies with -C.
    env.ok("alice", &dir, &["commit", "-m", "moved"]);
    write(&dir, "copy.txt", &format!("{body}one more\n"));
    write(&dir, "new.txt", &format!("{body}one more\nand more\n"));
    assert!(env.stdout("alice", &dir, &["diff", "--stat", "-C"]).contains("C"), "copies are detected with -C");
    env.ok("alice", &dir, &["commit", "-m", "copied"]);
    let v = json_ok(&env, "alice", &dir, &["show", "@-", "-C", "--json"]);
    assert!(v["diff"]["files"].as_array().unwrap().iter().any(|f| f["status"] == "copied" && f["from"] == "new.txt"), "{v}");
    let s = env.stdout("alice", &dir, &["show", "@-", "-C"]);
    assert!(s.contains("copy from new.txt\ncopy to copy.txt"), "{s}");
}

/// Design 2, threat 11 (on any filesystem): a case-only rename is a
/// rename, not a deletion and an addition.
#[test]
fn a_case_only_rename_is_a_rename() {
    let env = Env::new();
    let dir = env.project("alice", "p", &[("README", "read me\n")]);
    std::fs::rename(dir.join("README"), dir.join("readme.tmp")).unwrap();
    std::fs::rename(dir.join("readme.tmp"), dir.join("readme")).unwrap();
    let st = env.stdout("alice", &dir, &["status"]);
    assert!(st.contains("R README -> readme"), "{st}");
}

/// Design 2, threat 1: renames are computed for the output only. Showing
/// them writes no object and no operation.
#[test]
fn renames_are_never_stored() {
    let env = Env::new();
    let dir = env.project("alice", "p", &[("a.txt", "some content here\n")]);
    std::fs::rename(dir.join("a.txt"), dir.join("b.txt")).unwrap();
    env.ok("alice", &dir, &["status"]);
    let count = || walk(&dir.join(".veil/objects"));
    let ops = || json_ok(&env, "alice", &dir, &["op", "log", "--json"])["operations"].as_array().unwrap().len();
    let (objects, n_ops) = (count(), ops());
    for args in [&["status", "--json"][..], &["diff", "-C", "--json"], &["show", "-C"], &["log", "--follow", "b.txt"], &["blame", "b.txt", "--follow"]] {
        env.ok("alice", &dir, args);
    }
    assert_eq!(count(), objects, "no object written");
    assert_eq!(ops(), n_ops, "no operation recorded");
    let oplog = env.stdout("alice", &dir, &["op", "log"]);
    assert!(!oplog.to_lowercase().contains("rename"), "{oplog}");
}

fn walk(d: &Path) -> usize {
    std::fs::read_dir(d).map(|r| r.flatten().map(|e| if e.path().is_dir() { walk(&e.path()) } else { 1 }).sum()).unwrap_or(0)
}

// ---- bisect --------------------------------------------------------------------------------

/// A project with 12 commits; `bug.txt` holds `bad` from commit 8 on.
fn bisect_project(env: &Env) -> (PathBuf, Vec<String>) {
    let dir = env.project("alice", "p", &[("bug.txt", "fine 0\n")]);
    let mut changes = vec![change(env, "alice", &dir, "@-")];
    for i in 1..12 {
        let state = if i >= 8 { "bad" } else { "fine" };
        changes.push(commit(env, &dir, &[("bug.txt", &format!("{state} {i}\n"))], &format!("c{i}")));
    }
    (dir, changes)
}

#[test]
fn bisect_by_hand_finds_the_first_bad_change() {
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    let started = change(&env, "alice", &dir, "@");
    env.ok("alice", &dir, &["bisect", "start", "--bad", &changes[11], "--good", &changes[0]]);
    for _ in 0..10 {
        let content = std::fs::read_to_string(dir.join("bug.txt")).unwrap();
        let verdict = if content.starts_with("bad") { "bad" } else { "good" };
        let out = env.ok("alice", &dir, &["bisect", verdict]);
        if out.contains("The first bad snapshot is") {
            assert!(out.contains(&changes[8]), "{out}");
            let log = env.stdout("alice", &dir, &["bisect", "log"]);
            assert!(log.contains("found") && log.contains(&changes[8]), "{log}");
            env.ok("alice", &dir, &["bisect", "reset"]);
            assert_eq!(change(&env, "alice", &dir, "@-"), changes[11], "back where it started");
            let _ = started;
            assert!(!dir.join(".veil/local/bisect.json").exists());
            return;
        }
    }
    panic!("bisect did not converge");
}

fn script(dir: &Path, name: &str, body: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p.to_str().unwrap().to_string()
}

#[test]
fn bisect_run_finds_it_without_touching_the_working_copy() {
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    write(&dir, "wip.txt", "my unfinished work\n");
    env.ok("alice", &dir, &["status"]);
    let ws_change = change(&env, "alice", &dir, "@");
    env.ok("alice", &dir, &["bisect", "start", "--bad", &changes[11], "--good", &changes[0]]);
    env.ok("alice", &dir, &["edit", &ws_change]);
    let test = script(&env.root, "test.sh", "grep -q fine bug.txt");
    let out = env.ok("alice", &dir, &["bisect", "run", "--", &test]);
    assert!(out.contains(&format!("The first bad snapshot is {}", changes[8])), "{out}");
    assert_eq!(std::fs::read_to_string(dir.join("wip.txt")).unwrap(), "my unfinished work\n");
    assert_eq!(change(&env, "alice", &dir, "@"), ws_change, "the working copy did not move");
    // Nothing was recorded per step.
    assert!(json_ok(&env, "alice", &dir, &["log", "--json"])["entries"].as_array().unwrap().len() < 16);
    env.ok("alice", &dir, &["bisect", "reset"]);
}

/// Design 1, threat 7: `bisect run` gets neither the isolated `.netrc` nor
/// vault values, unless `--with-isolated` (which copies the local-only
/// files, never vault values into the environment).
#[test]
fn bisect_run_injects_no_secrets() {
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    write(&dir, ".netrc", &format!("KEY={ISOLATED_TEXT}\n"));
    env.ok("alice", &dir, &["secret", "set", "API_TOKEN", VAULT_VALUE]);
    env.ok("alice", &dir, &["bisect", "start", "--bad", &changes[11], "--good", &changes[0]]);
    let test = script(&env.root, "env.sh", "env; ls -a; cat .netrc 2>/dev/null; grep -q fine bug.txt");
    let out = env.ok("alice", &dir, &["bisect", "run", "--", &test]);
    assert!(!out.contains(ISOLATED_TEXT) && !out.contains(VAULT_VALUE), "{out}");
    assert!(!out.contains(".netrc"), "{out}");
    env.ok("alice", &dir, &["bisect", "reset"]);
}

/// Design 1, threat 8: candidates this reader cannot fully read are
/// skipped by `bisect run` unless `--trust-partial`.
#[test]
fn bisect_run_skips_candidates_it_cannot_fully_read() {
    let env = Env::new();
    let alice = env.project("alice", "a", &[("bug.txt", "fine\n")]);
    env.ok("alice", &alice, &["cloak", "secret/.env.s"]);
    let good = commit(&env, &alice, &[("secret/.env.s", "sealed\n")], "cloak");
    let mid = commit(&env, &alice, &[("secret/.env.s", "sealed 2\n")], "sealed edit");
    let bad = commit(&env, &alice, &[("bug.txt", "bad\n")], "bad");
    env.ok("alice", &alice, &["tag", "set", "main", "-r", "@-"]);
    let team = env.root.join("team");
    env.ok("alice", &alice, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    env.ok("bob", &bob, &["bisect", "start", "--bad", &bad, "--good", &good]);
    let test = script(&env.root, "t.sh", "grep -q fine bug.txt");
    let out = env.ok("bob", &bob, &["bisect", "run", "--", &test]);
    assert!(out.contains("skipped") && out.contains(&mid), "{out}");
    assert!(out.contains("Only skipped snapshots are left"), "{out}");
    env.ok("bob", &bob, &["bisect", "reset"]);
    env.ok("bob", &bob, &["bisect", "start", "--bad", &bad, "--good", &good]);
    let out = env.ok("bob", &bob, &["bisect", "run", "--trust-partial", "--", &test]);
    assert!(out.contains(&format!("The first bad snapshot is {bad}")), "{out}");
}

/// Design 1, threat 9: a damaged, foreign or hostile state file stops
/// only `vl bisect`, which says to reset; reset removes it.
#[test]
fn a_damaged_bisect_state_stops_only_bisect() {
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    let state = dir.join(".veil/local/bisect.json");
    let bad_states: Vec<Vec<u8>> = vec![
        b"garbage".to_vec(),
        br#"{"version":2}"#.to_vec(),
        format!(r#"{{"version":1,"workspace":"default","started_from":"{0}","started_parents":[],"bad":"{0}","good":[],"extra":1}}"#, "0".repeat(64)).into_bytes(),
        format!(r#"{{"version":1,"workspace":"default","started_from":"x","started_parents":[],"bad":"{}","good":[]}}"#, "1".repeat(64)).into_bytes(),
        vec![b' '; 2 << 20],
    ];
    for s in bad_states {
        std::fs::write(&state, &s).unwrap();
        env.ok("alice", &dir, &["status"]);
        env.ok("alice", &dir, &["log", "-n", "1"]);
        for args in [&["bisect", "good"][..], &["bisect", "log"], &["bisect", "start", "--bad", "@-", "--good", &changes[0]]] {
            let out = env.vl("alice", &dir, args);
            assert_eq!(out.status.code(), Some(1), "{args:?}");
            assert!(text(&out).contains("vl bisect reset"), "{args:?}: {}", text(&out));
        }
        let out = env.ok("alice", &dir, &["bisect", "reset"]);
        assert!(out.contains("Removed"), "{out}");
        assert!(!state.exists());
    }
    // A symlink or a directory in its place is never followed.
    std::os::unix::fs::symlink("/etc/passwd", &state).unwrap();
    let out = env.vl("alice", &dir, &["bisect", "log"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("not a regular file"), "{}", text(&out));
    env.ok("alice", &dir, &["bisect", "reset"]);
    assert!(std::fs::symlink_metadata(&state).is_err());
    assert!(std::fs::read_to_string("/etc/passwd").is_ok());
}

/// Design 1, threat 10: an edit made while testing a candidate is never
/// lost; moving on is refused unless --discard, and the edit stays in
/// its change either way.
#[test]
fn bisect_refuses_to_move_off_a_candidate_holding_edits() {
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    env.ok("alice", &dir, &["bisect", "start", "--bad", &changes[11], "--good", &changes[0]]);
    write(&dir, "debug.txt", "printf debugging\n");
    let out = env.vl("alice", &dir, &["bisect", "good"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("holds edits") && text(&out).contains("--discard"), "{}", text(&out));
    assert_eq!(std::fs::read_to_string(dir.join("debug.txt")).unwrap(), "printf debugging\n");
    let edited = change(&env, "alice", &dir, "@");
    env.ok("alice", &dir, &["bisect", "good", "--discard"]);
    let v = json_ok(&env, "alice", &dir, &["show", &edited, "--json"]);
    assert!(v["diff"]["files"].as_array().unwrap().iter().any(|f| f["path"] == "debug.txt"), "the edit stays in its change");
    env.ok("alice", &dir, &["bisect", "reset"]);
}

/// Hostile and odd input: commands that cannot run, are killed or exit
/// above 127 abort cleanly and keep the state; another workspace is
/// refused; nothing is in progress.
#[test]
fn bisect_run_aborts_cleanly() {
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    let out = env.vl("alice", &dir, &["bisect", "good"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("no bisection in progress"), "{}", text(&out));
    env.ok("alice", &dir, &["bisect", "start", "--bad", &changes[11], "--good", &changes[0]]);
    let out = env.vl("alice", &dir, &["bisect", "run", "--", "/no/such/command"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("failed to run"), "{}", text(&out));
    let kill = script(&env.root, "kill.sh", "kill -9 $$");
    let out = env.vl("alice", &dir, &["bisect", "run", "--", &kill]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("exited with 137"), "{}", text(&out));
    let high = script(&env.root, "high.sh", "exit 200");
    let out = env.vl("alice", &dir, &["bisect", "run", "--", &high]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("exited with 200"), "{}", text(&out));
    // A hostile TMPDIR (a file, not a directory): refused cleanly.
    let not_a_dir = env.root.join("tmpfile");
    std::fs::write(&not_a_dir, "x").unwrap();
    let ok = script(&env.root, "ok.sh", "exit 0");
    let out = env.cmd("alice", &dir, &["bisect", "run", "--", &ok]).env("TMPDIR", &not_a_dir).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(!text(&out).contains("panicked"), "{}", text(&out));
    // The state survived all of it.
    env.ok("alice", &dir, &["bisect", "log"]);
    // Not from another workspace.
    env.ok("alice", &dir, &["ws", "new", "other", "-r", "@-"]);
    env.ok("alice", &dir, &["ws", "switch", "other"]);
    let out = env.vl("alice", &dir, &["bisect", "log"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("runs in workspace default"), "{}", text(&out));
    env.ok("alice", &dir, &["ws", "switch", "default"]);
    env.ok("alice", &dir, &["bisect", "reset"]);
    let out = env.ok("alice", &dir, &["bisect", "reset"]);
    assert!(out.contains("No bisection in progress"));
}

/// `.veil/local/bisect.json`.
fn bisect_state(dir: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir.join(".veil/local/bisect.json")).unwrap()).unwrap()
}

/// The verdicts in a bisection's log, in order: the action, the snapshot
/// marked and `bisect run`'s exit code.
fn bisect_verdicts(state: &Value) -> Vec<(String, String, Option<i64>)> {
    let line = |l: &Value| (l["action"].as_str().unwrap().to_string(), l["snapshot"].as_str().unwrap().to_string(), l["code"].as_i64());
    state["log"].as_array().unwrap().iter().map(line).filter(|l| ["good", "bad", "skip"].contains(&l.0.as_str())).collect()
}

/// What a verdict with no snapshot is told when no candidate is being
/// tested.
const NOTHING_TESTED: &str = "error: no candidate is being tested: give the snapshot to mark";

/// When only skipped snapshots are left the bisection is over, and a
/// verdict that names no snapshot is refused: nothing is being tested.
/// (It is what a verdict gets that was given at once with the last one,
/// BUG-1914.)
#[test]
fn a_bisect_verdict_with_nothing_being_tested_is_refused() {
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    env.ok("alice", &dir, &["bisect", "start", "--bad", &changes[11], "--good", &changes[9]]);
    let out = env.ok("alice", &dir, &["bisect", "skip"]);
    assert!(out.contains("Only skipped snapshots are left"), "{out}");
    let ended = bisect_state(&dir);
    assert!(ended["current"].is_null(), "{ended:#}");
    let out = env.vl("alice", &dir, &["bisect", "good"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), NOTHING_TESTED);
    assert_eq!(bisect_state(&dir), ended, "a refused verdict writes nothing");
    env.ok("alice", &dir, &["bisect", "reset"]);
}

/// Concurrency (BUG-1914): verdicts given at once are taken one at a
/// time, each reading the state the one before wrote (the directory's
/// lock; the state file is replaced atomically). So every verdict that
/// succeeded is in the log, on a candidate of its own, and the working
/// copy ends on the candidate the state names.
///
/// Two `good`s and a `skip` can end this bisection (only a skipped
/// snapshot is left), and the fourth verdict is then refused, rightly:
/// nothing is being tested. That is the only refusal there is.
#[test]
fn concurrent_bisect_commands_keep_the_state_valid() {
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    env.ok("alice", &dir, &["bisect", "start", "--bad", &changes[11], "--good", &changes[0]]);
    let asked = ["good", "skip", "good", "skip"];
    let kids: Vec<Child> = asked.iter().map(|v| env.spawn("alice", &dir, &["bisect", v, "--discard"])).collect();
    let outs: Vec<Output> = kids.into_iter().map(|k| k.wait_with_output().unwrap()).collect();
    let refused: Vec<&Output> = outs.iter().filter(|o| !o.status.success()).collect();
    for o in &refused {
        assert_eq!(String::from_utf8_lossy(&o.stderr).trim(), NOTHING_TESTED, "{}", text(o));
    }
    // A bisection of 11 snapshots takes three verdicts to end.
    assert!(refused.len() <= 1, "{:?}", outs.iter().map(text).collect::<Vec<_>>());
    let s = bisect_state(&dir);
    assert_eq!(s["version"], 1);
    // No verdict was written over another's: each that succeeded is there.
    let marked = bisect_verdicts(&s);
    for v in ["good", "skip"] {
        let succeeded = asked.iter().zip(&outs).filter(|(a, o)| **a == v && o.status.success()).count();
        assert_eq!(marked.iter().filter(|m| m.0 == v).count(), succeeded, "{v}: {s:#}");
    }
    // Each on the candidate the one before it checked out.
    let mut snapshots: Vec<&str> = marked.iter().map(|m| m.1.as_str()).collect();
    snapshots.sort_unstable();
    snapshots.dedup();
    assert_eq!(snapshots.len(), marked.len(), "{s:#}");
    match s["current"].as_str() {
        // Still bisecting: the candidate being tested is the one checked out.
        Some(current) => {
            assert!(refused.is_empty(), "refused while {current} was being tested: {s:#}");
            assert!(!snapshots.contains(&current), "{s:#}");
            let testing = change(&env, "alice", &dir, current);
            assert_eq!(change(&env, "alice", &dir, "@-"), testing);
            let i = changes.iter().position(|c| *c == testing).expect("a change of the project");
            assert_eq!(std::fs::read_to_string(dir.join("bug.txt")).unwrap(), format!("{} {i}\n", if i >= 8 { "bad" } else { "fine" }));
        }
        // Ended (only then is a verdict refused): by the third or the fourth.
        None => assert!(marked.len() >= 3, "{s:#}"),
    }
    env.ok("alice", &dir, &["bisect", "log"]);
    env.ok("alice", &dir, &["bisect", "reset"]);
}

/// A `vl bisect run` whose command has started on the first candidate and
/// waits there, between the run's read of the state and its write, until
/// the file returned exists.
fn paused_bisect_run(env: &Env, dir: &Path) -> (Child, PathBuf) {
    let (started, go) = (env.root.join("run-started"), env.root.join("run-go"));
    let body = format!("touch '{}'\nwhile [ ! -e '{}' ]; do sleep 0.05; done\ngrep -q fine bug.txt", started.display(), go.display());
    let test = script(&env.root, "paused.sh", &body);
    let run = env.spawn("alice", dir, &["bisect", "run", "--", &test]);
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    while !started.exists() {
        assert!(std::time::Instant::now() < deadline, "`vl bisect run` never ran its command");
        std::thread::sleep(Duration::from_millis(20));
    }
    (run, go)
}

const RUN_OVERTAKEN: &str = "the bisection changed while `vl bisect run` was running";

/// BUG-1914: `vl bisect reset` while `vl bisect run`'s command runs ends
/// the bisection; the run, which read the state before, does not write it
/// back.
#[test]
fn bug_1914_bisect_run_does_not_bring_back_a_bisection_reset_meanwhile() {
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    env.ok("alice", &dir, &["bisect", "start", "--bad", &changes[11], "--good", &changes[0]]);
    let (run, go) = paused_bisect_run(&env, &dir);
    let out = env.ok("alice", &dir, &["bisect", "reset"]);
    assert!(out.contains("Bisection ended"), "{out}");
    std::fs::write(&go, "").unwrap();
    let out = run.wait_with_output().unwrap();
    assert!(!out.status.success(), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains(RUN_OVERTAKEN), "{}", text(&out));
    assert!(!dir.join(".veil/local/bisect.json").exists(), "the run wrote the state back");
    let out = env.ok("alice", &dir, &["bisect", "reset"]);
    assert!(out.contains("No bisection in progress"), "{out}");
}

/// BUG-1914: a verdict marked by hand while `vl bisect run`'s command runs
/// stays: the run stops without writing over it, and the next run goes on
/// from it.
#[test]
fn bug_1914_bisect_run_keeps_a_verdict_marked_meanwhile() {
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    env.ok("alice", &dir, &["bisect", "start", "--bad", &changes[11], "--good", &changes[0]]);
    let (run, go) = paused_bisect_run(&env, &dir);
    env.ok("alice", &dir, &["bisect", "good", &changes[2], "--discard"]);
    std::fs::write(&go, "").unwrap();
    let out = run.wait_with_output().unwrap();
    assert!(!out.status.success(), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains(RUN_OVERTAKEN), "{}", text(&out));
    // The verdict by hand, and nothing of the run's.
    let marked = bisect_verdicts(&bisect_state(&dir));
    assert_eq!(marked.len(), 1, "{marked:?}");
    assert_eq!((marked[0].0.as_str(), marked[0].2), ("good", None));
    assert_eq!(change(&env, "alice", &dir, &marked[0].1), changes[2]);
    // The next run goes on from it, to the end.
    let out = env.ok("alice", &dir, &["bisect", "run", "--", &script(&env.root, "test.sh", "grep -q fine bug.txt")]);
    assert!(out.contains("The first bad snapshot is"), "{out}");
    let s = bisect_state(&dir);
    assert_eq!(change(&env, "alice", &dir, s["found"].as_str().expect("found")), changes[8]);
    let marked = bisect_verdicts(&s);
    assert_eq!((marked[0].0.as_str(), marked[0].2), ("good", None), "{marked:?}");
    assert_eq!(change(&env, "alice", &dir, &marked[0].1), changes[2]);
    env.ok("alice", &dir, &["bisect", "reset"]);
}

/// A pipe filled to the brim: a process that writes to it waits until it
/// is read. Returns how much filling it holds.
fn full_pipe() -> (std::io::PipeReader, std::io::PipeWriter, usize) {
    use std::os::fd::AsRawFd;
    let (reader, mut writer) = std::io::pipe().unwrap();
    let fd = writer.as_raw_fd();
    // SAFETY: the status flags of a descriptor this function owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0);
    let mut filled = 0;
    for chunk in [4096, 1] {
        loop {
            match writer.write(&vec![b'.'; chunk]) {
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("filling a pipe: {e}"),
            }
        }
    }
    // The flags are the pipe's, not the descriptor's: the writer blocks again.
    assert!(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } == 0);
    (reader, writer, filled)
}

/// Does a process hold the lock of the project directory `dir` (attached
/// to workspace `default`)?
fn directory_lock_held(dir: &Path) -> bool {
    use std::os::fd::AsRawFd;
    let lock = std::fs::File::open(dir.join(".veil/local/wc/ws-default.lock")).unwrap();
    // SAFETY: a descriptor this function owns; closing it gives the lock back.
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) != 0 }
}

/// BUG-1914: a verdict holds the directory's lock from before it reads
/// the state until it has written it, so a second one waits for that
/// write and marks the candidate the first one checked out. The first is
/// stopped in between: it prints the next candidate after it read the
/// state and before it writes it, and its stdout is a full pipe.
#[test]
fn bug_1914_a_bisect_verdict_holds_the_lock_from_its_read_of_the_state_to_its_write() {
    use std::io::Read as _;
    let env = Env::new();
    let (dir, changes) = bisect_project(&env);
    env.ok("alice", &dir, &["bisect", "start", "--bad", &changes[11], "--good", &changes[0]]);
    let before = bisect_state(&dir);
    let (mut reader, writer, filled) = full_pipe();
    let one = env.cmd("alice", &dir, &["bisect", "skip", "--discard"]).stdout(writer).stderr(Stdio::piped()).spawn().unwrap();
    // It stops there with the lock in hand (seen held for half a second:
    // a command that takes it only to record the directory gives it back).
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut held = 0;
    while held < 50 {
        assert!(std::time::Instant::now() < deadline, "a verdict that has read the state does not hold the directory's lock");
        held = if directory_lock_held(&dir) { held + 1 } else { 0 };
        std::thread::sleep(Duration::from_millis(10));
    }
    let two = env.spawn("alice", &dir, &["bisect", "skip", "--discard"]);
    assert_eq!(bisect_state(&dir), before, "nothing is written while the first verdict holds the lock");
    // Let the first one go on.
    let mut printed = Vec::new();
    reader.read_to_end(&mut printed).unwrap();
    let out = one.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(String::from_utf8_lossy(&printed[filled..]).contains("Testing "), "{}", String::from_utf8_lossy(&printed[filled..]));
    let out = two.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    // Both verdicts are in the log, the second on the first one's candidate.
    let s = bisect_state(&dir);
    let marked = bisect_verdicts(&s);
    assert_eq!(marked.len(), 2, "{s:#}");
    assert!(marked.iter().all(|m| m.0 == "skip"), "{s:#}");
    assert_eq!(Some(marked[0].1.as_str()), before["current"].as_str());
    assert_ne!(marked[1].1, marked[0].1);
    let current = s["current"].as_str().expect("still bisecting");
    assert!(marked.iter().all(|m| m.1 != current), "{s:#}");
    assert_eq!(change(&env, "alice", &dir, "@-"), change(&env, "alice", &dir, current));
    env.ok("alice", &dir, &["bisect", "reset"]);
}

/// Design 1, threat 17: `vl serve` offers `blame` and `grep`, never
/// `bisect` (it executes code).
#[test]
fn serve_offers_blame_and_grep_but_not_bisect() {
    let env = Env::new();
    let dir = env.project("alice", "p", &[("f.txt", "needle\n")]);
    let _server = Server::start(&env, "alice", &dir);
    let info = env.stdout("alice", &dir, &["serve", "--call", "server.info"]);
    assert!(info.contains("\"blame\"") && info.contains("\"grep\"") && !info.contains("bisect"), "{info}");
    let v: Value = serde_json::from_str(&env.stdout("alice", &dir, &["serve", "--call", "blame", r#"{"path":"f.txt","lines":[1,1]}"#])).unwrap();
    assert_eq!(v["schema"], "veil.blame/2");
    assert_eq!(v["lines"][0]["text"], "needle");
    let v: Value = serde_json::from_str(&env.stdout("alice", &dir, &["serve", "--call", "grep", r#"{"pattern":"NEEDLE","ignore_case":true}"#])).unwrap();
    assert_eq!(v["schema"], "veil.grep/2");
    assert_eq!(v["matches"][0]["path"], "f.txt");
    let out = env.vl("alice", &dir, &["serve", "--call", "bisect", "{}"]);
    assert!(!out.status.success());
    let out = env.vl("alice", &dir, &["serve", "--call", "grep", r#"{"pattern":"x","bogus":1}"#]);
    assert!(!out.status.success() && text(&out).contains("unknown field"), "{}", text(&out));
}

/// The new schemas: every key documented in `docs/reference/json.md`.
#[test]
fn new_schemas_are_documented() {
    let doc = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/reference/json.md")).unwrap();
    let env = Env::new();
    let dir = env.project("alice", "p", &[("f.txt", "one\n"), ("g.txt", "some content to move\n")]);
    std::fs::rename(dir.join("g.txt"), dir.join("h.txt")).unwrap();
    let docs = [
        ("veil.blame/2", json_ok(&env, "alice", &dir, &["blame", "f.txt", "--json"])),
        ("veil.grep/2", json_ok(&env, "alice", &dir, &["grep", "one", "--json"])),
        ("veil.log/2", json_ok(&env, "alice", &dir, &["log", "-S", "one", "--show-skipped", "--json"])),
        ("veil.diff/2", json_ok(&env, "alice", &dir, &["diff", "--json"])),
        ("veil.status/2", json_ok(&env, "alice", &dir, &["status", "--json"])),
    ];
    fn keys(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(o) => o.iter().for_each(|(k, v)| {
                out.push(k.clone());
                keys(v, out)
            }),
            Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
            _ => {}
        }
    }
    let common = &doc[doc.find("## Common objects").unwrap()..];
    let mut missing = Vec::new();
    for (schema, v) in docs {
        let start = doc.find(&format!("## `{schema}`")).unwrap_or_else(|| panic!("no section for {schema}"));
        let rest = &doc[start..];
        let own = &rest[..rest[3..].find("\n## ").map_or(rest.len(), |i| i + 3)];
        let mut ks = Vec::new();
        keys(&v, &mut ks);
        for k in ks {
            let k = format!("`{k}`");
            if !own.contains(&k) && !common.contains(&k) {
                missing.push(format!("{schema}: {k}"));
            }
        }
    }
    assert!(missing.is_empty(), "undocumented: {missing:?}");
}
