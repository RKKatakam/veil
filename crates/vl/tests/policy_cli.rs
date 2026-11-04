//! `vl cloak / isolate / expose / ignore / policy`: literal paths versus
//! globs, odd file names, scope validation and fail-safe policy parsing.

mod adversarial_support;

use std::path::Path;

use adversarial_support::*;

/// `vl files -r @-` as (path, tier label) pairs.
fn recorded(env: &Env, proj: &Path) -> Vec<(String, String)> {
    env.stdout("alice", proj, &["files", "-r", "@-"])
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let tier = it.next()?.to_string();
            let path = l.rsplit("  ").next()?.trim().to_string();
            Some((path, tier))
        })
        .collect()
}

fn tier_of<'a>(files: &'a [(String, String)], path: &str) -> Option<&'a str> {
    files.iter().find(|(p, _)| p.ends_with(path)).map(|(_, t)| t.as_str())
}

#[test]
fn explicit_globs_still_match_as_globs() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, "config/a.yml", "a\n");
    write(&proj, "config/b.yml", "b\n");
    write(&proj, "config/c.txt", "c\n");
    write(&proj, "logs/x1.log", "x\n");
    let out = env.ok("alice", &proj, &["cloak", "config/*.yml"]);
    assert!(!out.contains("literal path"), "{out}");
    env.ok("alice", &proj, &["isolate", "logs/x[0-9].log"]);
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let files = recorded(&env, &proj);
    assert!(tier_of(&files, "config/a.yml").unwrap().starts_with("cloaked"), "{files:?}");
    assert!(tier_of(&files, "config/b.yml").unwrap().starts_with("cloaked"), "{files:?}");
    assert_eq!(tier_of(&files, "config/c.txt"), Some("public"), "{files:?}");
    assert_eq!(tier_of(&files, "logs/x1.log"), None, "{files:?}");
}

#[test]
fn literal_directories_and_names_with_spaces_or_hashes() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, "app/[id]/page.tsx", "p\n");
    write(&proj, "app/i/page.tsx", "should stay public\n");
    write(&proj, "my notes.txt", "private\n");
    write(&proj, "issue#12.md", "private\n");
    let out = env.ok("alice", &proj, &["cloak", "app/[id]/"]);
    assert!(out.contains("literal path"), "{out}");
    env.ok("alice", &proj, &["isolate", "my notes.txt", "issue#12.md"]);
    let policy = env.stdout("alice", &proj, &["policy", "show"]);
    let all = env.ok("alice", &proj, &["policy", "show"]);
    assert!(!all.contains("warning"), "the written rules must parse cleanly:\n{all}");
    assert!(policy.contains(r"app/\[id\]/"), "{policy}");
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let files = recorded(&env, &proj);
    assert!(tier_of(&files, "app/[id]/page.tsx").unwrap().starts_with("cloaked"), "{files:?}");
    assert_eq!(tier_of(&files, "app/i/page.tsx"), Some("public"), "{files:?}");
    assert_eq!(tier_of(&files, "my notes.txt"), None, "{files:?}");
    assert_eq!(tier_of(&files, "issue#12.md"), None, "{files:?}");
}

#[test]
fn a_missing_name_with_brackets_is_a_glob_and_says_so() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let out = env.ok("alice", &proj, &["isolate", "notes{1,2}.txt"]);
    assert!(out.contains("glob pattern") && out.contains(r"notes\{1,2\}.txt"), "{out}");
    write(&proj, "notes1.txt", "x\n");
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    assert_eq!(tier_of(&recorded(&env, &proj), "notes1.txt"), None);
}

#[test]
fn cloak_rejects_reserved_scope_names() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    for scope in ["local", "embargo", "embargo-x", "../x", "Team"] {
        let out = env.vl("alice", &proj, &["cloak", "a.txt", "--scope", scope]);
        assert!(!out.status.success(), "--scope {scope} accepted: {}", text(&out));
        assert!(text(&out).contains("invalid scope name"), "{}", text(&out));
    }
    assert!(!read(&proj, ".veilpolicy").contains("a.txt"));
}

#[test]
fn invalid_policy_rules_isolate_and_warn() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, ".veilpolicy", "secrets/ cloak local\nkeys/ clok team\nprivate/\n");
    write(&proj, "secrets/db.yml", "s\n");
    write(&proj, "keys/k.txt", "k\n");
    write(&proj, "private/p.txt", "p\n");
    write(&proj, "src/main.rs", "fn main() {}\n");
    let status = env.ok("alice", &proj, &["status"]);
    assert!(status.contains("invalid scope name 'local'"), "{status}");
    assert!(status.contains("unknown tier 'clok'"), "{status}");
    let check = env.stdout("alice", &proj, &["policy", "check", "secrets/db.yml", "keys/k.txt", "private/p.txt", "src/main.rs"]);
    let lines: Vec<&str> = check.lines().collect();
    assert!(lines[0].contains("isolated") && lines[1].contains("isolated") && lines[2].contains("isolated"), "{check}");
    assert!(lines[3].contains("public"), "{check}");
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let files = recorded(&env, &proj);
    for p in ["secrets/db.yml", "keys/k.txt", "private/p.txt"] {
        assert_eq!(tier_of(&files, p), None, "{p} recorded: {files:?}");
    }
}

#[test]
fn uppercase_secret_files_are_isolated_and_cloak_rules_ignore_case() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, ".ENV", "X=1\n");
    write(&proj, "Secrets/a.txt", "s\n");
    write(&proj, "Fixtures/key.pem", "not a key\n");
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    env.ok("alice", &proj, &["expose", "--force", "fixtures/"]);
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let files = recorded(&env, &proj);
    assert_eq!(tier_of(&files, ".ENV"), None, "{files:?}");
    assert!(tier_of(&files, "Secrets/a.txt").unwrap().starts_with("cloaked"), "{files:?}");
    // `public!` is case-sensitive: it does not expose `Fixtures/`.
    assert_eq!(tier_of(&files, "Fixtures/key.pem"), None, "{files:?}");
}
