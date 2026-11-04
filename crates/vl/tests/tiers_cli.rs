//! Tiers on the command line: `vl ls`, the tier marks of `vl status`, and
//! `vl push --dry-run`, whose plan must be what `vl push` then sends.

mod adversarial_support;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use adversarial_support::*;
use serde_json::Value;
use veil_core::{DiskBackend, StorageBackend, VPath};

const CLOAKED: &str = "CLOAKED-DB-PASSWORD-PLAN-5521";
const ISOLATED: &str = "ISOLATED-ENV-VALUE-7731";
const FIX: &str = "EMBARGOED-FIX-TEXT-1907";

fn json(env: &Env, user: &str, dir: &Path, args: &[&str]) -> (Value, i32) {
    let out = env.vl(user, dir, args);
    let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("vl {args:?}: {e}\n{}", text(&out)));
    (v, out.status.code().unwrap())
}

/// `path → tier label` from the text of `vl ls`.
fn ls(env: &Env, user: &str, dir: &Path, args: &[&str]) -> BTreeMap<String, String> {
    let mut a = vec!["ls"];
    a.extend_from_slice(args);
    env.stdout(user, dir, &a)
        .lines()
        .map(|l| {
            let mut it = l.split_whitespace();
            let tier = it.next().unwrap().to_string();
            let _size = it.next().unwrap();
            let path = it.next().unwrap().to_string();
            (path, tier)
        })
        .collect()
}

/// Every file of a directory tree with its bytes.
fn dump(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let fs = DiskBackend::new(dir);
    if !dir.exists() {
        return BTreeMap::new();
    }
    veil_core::vfs::walk_files(&fs, &VPath::root(), &|_| false)
        .unwrap()
        .into_iter()
        .map(|p| (p.to_string(), fs.read(&p).unwrap()))
        .collect()
}

/// Objects in each pack of the repository at `dir`.
fn packs(dir: &Path) -> BTreeMap<String, Vec<String>> {
    let fs = DiskBackend::new(dir);
    let pdir = VPath::new(".veil/objects/pack").unwrap();
    let Ok(entries) = fs.list_dir(&pdir) else { return BTreeMap::new() };
    let mut out = BTreeMap::new();
    for e in entries {
        let Some(name) = veil_core::pack::name_from_index_file(&e.name) else { continue };
        let p = veil_core::pack::Pack::open(&fs, &pdir, name).unwrap();
        out.insert(e.name.clone(), p.index().ids().iter().map(|i| i.hex()).collect());
    }
    out
}

/// Plan a push of `remote` with `vl push --dry-run --json`, check it left
/// the remote alone, push, and check the push packed exactly the planned
/// objects and moved exactly the planned tags.
fn dry_run_then_push(env: &Env, dir: &Path, remote: &str, remote_dir: &Path) -> Value {
    let before = dump(remote_dir);
    let (doc, code) = json(env, "alice", dir, &["push", remote, "--dry-run", "--json"]);
    assert_eq!(code, 0, "{doc}");
    assert_eq!(dump(remote_dir), before, "the dry run wrote to {remote}");
    let plan = doc["remotes"][0].clone();
    let packs_before = packs(remote_dir);
    let pushed = env.ok("alice", dir, &["push", remote]);
    let sent: Vec<String> = packs(remote_dir)
        .into_iter()
        .filter(|(n, _)| !packs_before.contains_key(n))
        .flat_map(|(_, ids)| ids)
        .collect();
    let planned: Vec<String> = plan["object_ids"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert_eq!(sent.len(), planned.len(), "{plan}\n{pushed}");
    assert_eq!(sent.into_iter().collect::<BTreeSet<_>>(), planned.iter().cloned().collect::<BTreeSet<_>>());
    assert!(pushed.contains(&format!("Pushed {} object(s)", planned.len())), "{pushed}");
    for t in plan["tags"].as_array().unwrap() {
        let line = format!("pushed {} → {}", t["name"].as_str().unwrap(), t["target_short"].as_str().unwrap());
        let moves = t["action"] == "create" || t["action"] == "update";
        assert_eq!(pushed.contains(&line), moves, "{t}\n{pushed}");
    }
    plan
}

/// Alice's project: public, cloaked, isolated, executable files and a
/// cloaked tag; a team remote and a public mirror.
fn project(env: &Env) -> std::path::PathBuf {
    let dir = env.dir("alice");
    write(&dir, "src/main.rs", "fn main() {}\n");
    write(&dir, "secrets/db.yml", &format!("{CLOAKED}\n"));
    write(&dir, ".env", &format!("KEY={ISOLATED}\n"));
    env.ok("alice", &dir, &["init"]);
    env.ok("alice", &dir, &["cloak", "secrets/"]);
    env.ok("alice", &dir, &["commit", "-m", "one"]);
    env.ok("alice", &dir, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &dir, &["tag", "set", "ops", "-r", "@-", "--cloak", "team"]);
    let team = env.root.join("team");
    let mirror = env.root.join("mirror");
    env.ok("alice", &dir, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &dir, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    dir
}

#[test]
fn ls_shows_every_tier_and_status_marks_every_file() {
    let env = Env::new();
    let dir = project(&env);
    write(&dir, "cfg.js", "k = \"AKIAIOSFODNN7EXAMPLE\"\n");
    write(&dir, "target/debug/app", "binary\n");
    write(&dir, "secrets/db.yml", &format!("{CLOAKED} v2\n"));
    let files = ls(&env, "alice", &dir, &["--all"]);
    assert_eq!(files["src/main.rs"], "public");
    assert_eq!(files["secrets/db.yml"], "cloaked:team");
    assert_eq!(files[".env"], "isolated");
    assert_eq!(files["cfg.js"], "quarantined");
    assert_eq!(files["target/"], "ignored", "{files:?}");
    assert!(!ls(&env, "alice", &dir, &[]).contains_key("target/"), "ignored files need --all");
    // In tree order; filters by path, relative to the current directory.
    let only = ls(&env, "alice", &dir.join("src"), &["."]);
    assert_eq!(only.keys().collect::<Vec<_>>(), ["src/main.rs"]);
    let out = env.vl("alice", &dir, &["ls", "nope"]);
    assert!(!out.status.success() && text(&out).contains("matches no file"), "{}", text(&out));
    // An older snapshot has no local-only files.
    let old = ls(&env, "alice", &dir, &["-r", "main"]);
    assert!(!old.contains_key(".env") && !old.contains_key("cfg.js"), "{old:?}");
    // `vl files` keeps its format.
    let f = env.stdout("alice", &dir, &["files"]);
    assert!(f.lines().any(|l| l.starts_with("cloaked:team") && l.ends_with("secrets/db.yml")), "{f}");

    let st = env.stdout("alice", &dir, &["status"]);
    assert!(st.contains("M secrets/db.yml [cloaked:team]"), "{st}");
    assert!(st.contains("L .env [isolated]"), "{st}");
    assert!(st.contains("Q cfg.js [quarantined]  (aws-access-key-id; never recorded)"), "{st}");
    let (v, _) = json(&env, "alice", &dir, &["status", "--json"]);
    let change = v["changes"].as_array().unwrap().iter().find(|c| c["path"] == "secrets/db.yml").unwrap();
    assert_eq!(change["tier"], "cloaked");
    assert_eq!(v["quarantined"][0]["tier"], "quarantined");

    // Bob clones the team remote without a key for `team`.
    env.ok("alice", &dir, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    let files = ls(&env, "bob", &bob, &[]);
    assert_eq!(files["secrets/db.yml"], "redacted", "{files:?}");
    let line = env.stdout("bob", &bob, &["ls", "secrets"]);
    assert!(line.contains("(cloaked:team; no key)"), "{line}");
    assert!(!line.contains(CLOAKED));
    write(&bob, "src/main.rs", "fn main() { bob() }\n");
    let st = env.stdout("bob", &bob, &["status"]);
    assert!(st.contains("R secrets/db.yml [redacted]  (cloaked:team; no key)"), "{st}");
    assert!(st.contains("M src/main.rs\n"), "public files carry no mark: {st}");
}

#[test]
fn dry_run_lists_what_each_remote_would_get_and_the_push_agrees() {
    let env = Env::new();
    let dir = project(&env);
    // No remote named: every remote, nothing written anywhere.
    let out = env.ok("alice", &dir, &["push", "--dry-run"]);
    assert!(out.contains("Dry run: nothing was sent."), "{out}");
    assert!(out.contains("mirror public") && out.contains("origin team"), "{out}");
    assert!(out.contains("skipped   ops (cloaked tag is never pushed to a public remote)"), "{out}");
    assert!(out.contains("new") && out.contains("src/main.rs"), "{out}");
    assert!(out.contains("secrets/db.yml  (cloaked:team; public remotes never receive it)"), "{out}");
    assert!(!env.root.join("team").exists() && !env.root.join("mirror").exists(), "the dry run created a remote");
    assert!(!out.contains(CLOAKED) && !out.contains(ISOLATED), "{out}");

    let m = dry_run_then_push(&env, &dir, "mirror", &env.root.join("mirror"));
    assert_eq!(m["sealed"], 0);
    let t = dry_run_then_push(&env, &dir, "origin", &env.root.join("team"));
    assert!(t["sealed"].as_u64().unwrap() >= 1, "{t}");

    // Up to date.
    let out = env.ok("alice", &dir, &["push", "--dry-run"]);
    assert!(out.contains("unchanged main") && out.contains("no objects to send"), "{out}");

    // An edit, an exposure, a new cloaked file.
    write(&dir, "src/main.rs", "fn main() { run() }\n");
    write(&dir, "secrets/new.yml", "more\n");
    env.ok("alice", &dir, &["expose", "--force", "secrets/db.yml"]);
    env.ok("alice", &dir, &["commit", "-m", "two"]);
    env.ok("alice", &dir, &["tag", "set", "main", "-r", "@-"]);
    let (doc, _) = json(&env, "alice", &dir, &["push", "mirror", "--dry-run", "--json"]);
    let files = &doc["remotes"][0]["files"];
    let exposure = |p: &str| {
        files["published"].as_array().unwrap().iter().find(|f| f["path"] == p).map(|f| f["exposure"].as_str().unwrap().to_string())
    };
    assert_eq!(exposure("src/main.rs").as_deref(), Some("modified"), "{files}");
    assert_eq!(exposure("secrets/db.yml").as_deref(), Some("exposed"), "{files}");
    assert!(files["withheld"].as_array().unwrap().iter().any(|f| f["path"] == "secrets/new.yml" && f["reason"] == "cloaked"));
    dry_run_then_push(&env, &dir, "mirror", &env.root.join("mirror"));
    dry_run_then_push(&env, &dir, "origin", &env.root.join("team"));
}

#[test]
fn dry_run_reports_rejections_and_embargoes_and_exits_like_the_push() {
    let env = Env::new();
    let dir = project(&env);
    env.ok("alice", &dir, &["push"]);
    // Bob moves main on the team remote.
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    write(&bob, "bob.txt", "bob\n");
    env.ok("bob", &bob, &["commit", "-m", "bob"]);
    env.ok("bob", &bob, &["tag", "set", "main", "-r", "@-"]);
    env.ok("bob", &bob, &["push"]);
    // Alice diverges.
    write(&dir, "alice.txt", "alice\n");
    env.ok("alice", &dir, &["commit", "-m", "alice"]);
    env.ok("alice", &dir, &["tag", "set", "main", "-r", "@-"]);
    let out = env.vl("alice", &dir, &["push", "origin", "--dry-run"]);
    assert_eq!(out.status.code(), Some(1), "a rejected tag fails the dry run as it fails the push");
    let t = text(&out);
    assert!(t.contains("rejected  main (remote has diverged"), "{t}");
    let real = env.vl("alice", &dir, &["push", "origin"]);
    assert_eq!(real.status.code(), Some(1));
    // --force: the dry run says update.
    let t = env.ok("alice", &dir, &["push", "origin", "--dry-run", "--force"]);
    assert!(t.contains("update    main"), "{t}");

    // An embargoed fix: the mirror gets the pre-merge tree; the dry run
    // names the withheld history and the embargoed file, never its content.
    env.ok("alice", &dir, &["ws", "new", "fix", "-r", "main", "--cloak", "team"]);
    let mut c = env.cmd("alice", &dir, &["ws", "write", "fix", "src/main.rs"]);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), format!("// {FIX}\n").as_bytes()).unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    env.ok("alice", &dir, &["merge", "fix@", "--into", "main", "--embargo", "-m", "merge the fix"]);
    let (doc, code) = json(&env, "alice", &dir, &["push", "mirror", "--dry-run", "--json"]);
    assert_eq!(code, 0, "{doc}");
    let m = &doc["remotes"][0];
    assert!(!m["withheld_snapshots"].as_array().unwrap().is_empty(), "{m}");
    assert!(
        m["files"]["withheld"].as_array().unwrap().iter().any(|f| f["path"] == "src/main.rs" && f["reason"] == "embargoed"),
        "{m}"
    );
    let text_out = env.ok("alice", &dir, &["push", "mirror", "--dry-run"]);
    for out in [doc.to_string(), text_out] {
        assert!(!out.contains(FIX) && !out.contains(CLOAKED) && !out.contains(ISOLATED), "{out}");
    }
    dry_run_then_push(&env, &dir, "mirror", &env.root.join("mirror"));

    // Carol (no key) clones the mirror: her dry run and ls hold no fix.
    env.ok("carol", &env.root, &["clone", "mirror", "carol"]);
    let carol = env.root.join("carol");
    let all = format!(
        "{}{}{}",
        env.ok("carol", &carol, &["ls", "--all"]),
        env.ok("carol", &carol, &["ls", "-r", "main"]),
        env.ok("carol", &carol, &["push", "--dry-run"])
    );
    assert!(!all.contains(FIX) && !all.contains(CLOAKED), "{all}");
}
