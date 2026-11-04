//! Symlinks in the CLI (repository format 5): how `vl ls`, `status`, `diff`,
//! `show` and `cat` display them, that targets are escaped for terminals
//! and raw in JSON, that a cloaked link's target is never shown to someone
//! without the key, and that a `ws exec` sandbox never hands its command a
//! link that leads out of it (symlinks design, threats 7 and 15).

mod adversarial_support;

use adversarial_support::*;
use serde_json::Value;

fn json(env: &Env, user: &str, dir: &std::path::Path, args: &[&str]) -> Value {
    serde_json::from_str(&env.stdout(user, dir, args)).unwrap()
}

#[test]
fn links_are_listed_diffed_and_catted_as_links() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("lib/tool.sh", "echo\n"), ("config.yml", "port: 80\n")]);
    std::os::unix::fs::symlink("../lib/tool.sh", {
        std::fs::create_dir_all(proj.join("bin")).unwrap();
        proj.join("bin/tool")
    })
    .unwrap();
    std::fs::remove_file(proj.join("config.yml")).unwrap();
    std::os::unix::fs::symlink("config.d/default.yml", proj.join("config.yml")).unwrap();
    let st = env.stdout("alice", &proj, &["status"]);
    assert!(st.contains("A bin/tool"), "{st}");
    assert!(st.contains("T config.yml (file → symlink)"), "{st}");
    let diff = env.stdout("alice", &proj, &["diff"]);
    assert!(diff.contains("symlink bin/tool -> ../lib/tool.sh"), "{diff}");
    assert!(diff.contains("new file mode 120000"), "{diff}");
    assert!(diff.contains("old mode 100644") && diff.contains("new mode 120000"), "{diff}");
    let ls = env.stdout("alice", &proj, &["ls"]);
    assert!(ls.lines().any(|l| l.contains("bin/tool -> ../lib/tool.sh")), "{ls}");
    let v = json(&env, "alice", &proj, &["ls", "--json"]);
    let e = v["entries"].as_array().unwrap().iter().find(|e| e["path"] == "bin/tool").unwrap();
    assert_eq!((e["kind"].as_str(), e["target"].as_str(), e["size"].as_u64()), (Some("symlink"), Some("../lib/tool.sh"), Some(14)));
    let v = json(&env, "alice", &proj, &["status", "--json"]);
    let c = v["changes"].as_array().unwrap().iter().find(|c| c["path"] == "config.yml").unwrap();
    assert_eq!((c["kind"].as_str(), c["old_kind"].as_str()), (Some("symlink"), Some("file")));
    env.ok("alice", &proj, &["commit", "-m", "links"]);
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", "@-", "bin/tool"]), "../lib/tool.sh");
    let show = env.stdout("alice", &proj, &["show", "@-"]);
    assert!(show.contains("symlink config.yml -> config.d/default.yml"), "{show}");
    let v = json(&env, "alice", &proj, &["diff", "-r", "@-", "--json"]);
    let f = v["files"].as_array().unwrap().iter().find(|f| f["path"] == "config.yml").unwrap();
    assert_eq!((f["old"]["mode"].as_str(), f["new"]["mode"].as_str(), f["new"]["target"].as_str()), (Some("100644"), Some("120000"), Some("config.d/default.yml")));
}

/// Threat 15: a target is raw data. The text output escapes it; the JSON
/// output keeps it exactly (escaped as JSON).
#[test]
fn link_targets_are_escaped_for_terminals() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    const EVIL: &str = "\x1b]8;;https://evil.example/\x07click\x1b]8;;\x07";
    std::os::unix::fs::symlink(EVIL, proj.join("link")).unwrap();
    for args in [&["status"][..], &["diff"], &["ls"]] {
        let out = env.vl("alice", &proj, args);
        let all = text(&out);
        assert!(out.status.success(), "{args:?}: {all}");
        assert!(!all.contains('\x1b') && !all.contains('\x07'), "{args:?}: raw control characters: {all:?}");
    }
    assert!(env.stdout("alice", &proj, &["ls"]).contains("link -> \\x1b]8;;https://evil.example/"));
    let v = json(&env, "alice", &proj, &["ls", "--json"]);
    let e = v["entries"].as_array().unwrap().iter().find(|e| e["path"] == "link").unwrap();
    assert_eq!(e["target"].as_str(), Some(EVIL));
}

/// A link the policy cloaks: its target is sealed content. A clone without
/// the key lists the link as redacted, never its target, and a public
/// mirror never receives it.
#[test]
fn a_cloaked_links_target_is_never_shown_without_the_key() {
    let env = Env::new();
    const TARGET: &str = "/srv/acme-secret-merger/build";
    let dir = env.dir("alice");
    write(&dir, "README", "hi\n");
    std::fs::create_dir_all(dir.join("private")).unwrap();
    std::os::unix::fs::symlink(TARGET, dir.join("private/current")).unwrap();
    env.ok("alice", &dir, &["init"]);
    env.ok("alice", &dir, &["cloak", "private/"]);
    env.ok("alice", &dir, &["commit", "-m", "one"]);
    env.ok("alice", &dir, &["tag", "set", "main", "-r", "@-"]);
    let ls = env.stdout("alice", &dir, &["ls", "private"]);
    assert!(ls.contains(TARGET) && ls.contains("cloaked:team"), "{ls}");
    let team = env.root.join("team");
    let mirror = env.root.join("mirror");
    env.ok("alice", &dir, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &dir, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok("alice", &dir, &["push"]);
    env.ok("alice", &dir, &["push", "mirror"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    let out = env.vl("bob", &bob, &["ls", "private"]);
    let all = text(&out);
    assert!(out.status.success() && all.contains("redacted") && !all.contains(TARGET), "{all}");
    let v = json(&env, "bob", &bob, &["ls", "--json"]);
    let e = v["entries"].as_array().unwrap().iter().find(|e| e["path"] == "private/current").unwrap();
    assert_eq!((e["kind"].as_str(), e["target"].as_str(), e["tier"].as_str()), (Some("symlink"), None, Some("redacted")));
    assert!(std::fs::symlink_metadata(bob.join("private/current")).is_err(), "a link bob cannot read was written");
    let out = env.vl("bob", &bob, &["diff", "-r", "main"]);
    assert!(!text(&out).contains(TARGET), "{}", text(&out));
    let st = env.vl("bob", &bob, &["status"]);
    assert!(!text(&st).contains(TARGET));
    for f in tree_listing(&mirror) {
        let data = std::fs::read(mirror.join(&f)).unwrap_or_default();
        assert!(!String::from_utf8_lossy(&data).contains(TARGET), "{f} holds the sealed target");
    }
}

/// Threat 7: a tree link that climbs out of the sandbox (to the project's
/// isolated `.env`), or points into the project by absolute path, is never
/// materialised in a `ws exec` sandbox; the run says so.
#[test]
fn ws_exec_never_hands_its_command_a_link_out_of_the_sandbox() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    write(&proj, ".env", "API_TOKEN=super-secret-isolated-value\n");
    std::os::unix::fs::symlink("../../../../../.env", proj.join("x")).unwrap();
    std::os::unix::fs::symlink(proj.join(".env"), proj.join("abs")).unwrap();
    std::os::unix::fs::symlink("a.txt", proj.join("fine")).unwrap();
    env.ok("alice", &proj, &["commit", "-m", "links"]);
    env.ok("alice", &proj, &["ws", "new", "agent", "-r", "@-"]);
    for link in ["x", "abs"] {
        let out = env.vl("alice", &proj, &["ws", "exec", "agent", "--", "cat", link]);
        let all = text(&out);
        assert!(!all.contains("super-secret-isolated-value"), "{link}: the sandbox handed out the isolated file: {all}");
        assert!(all.contains(link), "{all}");
    }
    let out = env.ok("alice", &proj, &["ws", "exec", "agent", "--", "cat", "fine"]);
    assert!(out.contains("a\n"), "{out}");
    // The ephemeral and sparse sandboxes too.
    for extra in [&["--ephemeral"][..], &["--only", "x"]] {
        let mut args = vec!["ws", "exec", "agent"];
        args.extend_from_slice(extra);
        args.extend(["--", "cat", "x"]);
        let out = env.vl("alice", &proj, &args);
        assert!(!text(&out).contains("super-secret-isolated-value"), "{extra:?}: {}", text(&out));
    }
    // The recorded links are untouched by the run.
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", "agent@", "x"]), "../../../../../.env");
    // A link the command makes is recorded as a link (never followed).
    env.ok("alice", &proj, &["ws", "exec", "agent", "--", "ln", "-s", "a.txt", "made"]);
    assert_eq!(env.stdout("alice", &proj, &["cat", "-r", "agent@", "made"]), "a.txt");
    let ls = env.stdout("alice", &proj, &["ls", "-r", "agent@"]);
    assert!(ls.contains("made -> a.txt") && ls.contains("x -> ../../../../../.env"), "{ls}");
}
