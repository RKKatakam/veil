//! `vl cloak / isolate / expose / ignore / policy`: literal paths versus
//! globs, odd file names, scope validation and fail-safe policy parsing.

use crate::adversarial_support;

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
    write(&proj, ".veilpolicy", "secrets/ cloak local\nkeys/ Clok team\nprivate/\n");
    write(&proj, "secrets/db.yml", "s\n");
    write(&proj, "keys/k.txt", "k\n");
    write(&proj, "private/p.txt", "p\n");
    write(&proj, "src/main.rs", "fn main() {}\n");
    let status = env.ok("alice", &proj, &["status"]);
    assert!(status.contains("invalid scope name 'local'"), "{status}");
    assert!(status.contains("unknown tier 'Clok'"), "{status}");
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
    write(&proj, ".NETRC", "X=1\n");
    write(&proj, "Secrets/a.txt", "s\n");
    write(&proj, "Fixtures/key.pem", "not a key\n");
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    env.ok("alice", &proj, &["expose", "--force", "fixtures/"]);
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let files = recorded(&env, &proj);
    assert_eq!(tier_of(&files, ".NETRC"), None, "{files:?}");
    assert!(tier_of(&files, "Secrets/a.txt").unwrap().starts_with("cloaked"), "{files:?}");
    // `public!` is case-sensitive: it does not expose `Fixtures/`.
    assert_eq!(tier_of(&files, "Fixtures/key.pem"), None, "{files:?}");
}

/// BUG-045: a pulled `.veilpolicy` that publishes `.netrc` is held back on
/// the receiving member's device, says so, and applies only after
/// `vl policy accept`.
#[test]
fn a_pulled_policy_that_exposes_local_secrets_needs_policy_accept() {
    let env = Env::new();
    let proj = env.dir("proj");
    write(&proj, "README.md", "hello\n");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["commit", "-m", "v1"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &proj, &["push"]);
    let bob_key = env.ok("bob", &env.root, &["identity", "show"]);
    let bob_key = bob_key.lines().find(|l| l.starts_with("public key")).unwrap().split_whitespace().last().unwrap().to_string();
    env.ok("alice", &proj, &["scope", "grant", "team", &bob_key, "--name", "bob"]);
    env.ok("alice", &proj, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    write(&bob, ".netrc", "DB_PASSWORD=bob-local-Xk9mQ2vL7pR4\n");
    env.ok("bob", &bob, &["status"]);

    env.ok("alice", &proj, &["expose", "--force", ".netrc"]);
    env.ok("alice", &proj, &["commit", "-m", "publish fixtures"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["push"]);

    env.ok("bob", &bob, &["pull"]);
    let out = env.ok("bob", &bob, &["new", "main"]);
    assert!(out.contains("keep the protection you accepted") && out.contains(".netrc"), "{out}");
    let status = env.ok("bob", &bob, &["status"]);
    assert!(status.contains("Policy change not accepted") && status.contains(".netrc"), "{status}");
    let show = env.ok("bob", &bob, &["policy", "show"]);
    assert!(show.contains("Not yet accepted") && show.contains(".netrc: isolate → public!"), "{show}");
    let check = env.ok("bob", &bob, &["policy", "check", ".netrc"]);
    assert!(check.contains("isolated") && check.contains("not yet accepted"), "{check}");
    env.ok("bob", &bob, &["commit", "-m", "work"]);
    assert_eq!(tier_of(&recorded(&env, &bob), ".netrc"), None, "held back: not recorded");

    let out = env.ok("bob", &bob, &["policy", "accept"]);
    assert!(out.contains(".netrc: isolate → public!"), "{out}");
    env.ok("bob", &bob, &["commit", "-m", "accepted"]);
    assert_eq!(tier_of(&recorded(&env, &bob), ".netrc"), Some("public"), "applied once accepted");
}

// ---- the server-centric model (docs/VISIBILITY.md, milestone S1) --------------------

/// Every byte under `.veil/` of `proj`, packs included (stored, not decoded:
/// what someone copying the directory gets).
fn store_bytes(proj: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![proj.join(".veil")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                out.extend(std::fs::read(e.path()).unwrap_or_default());
            }
        }
    }
    out
}

fn holds(bytes: &[u8], needle: &str) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn new_repositories_seal_shared_secrets_and_keep_personal_keys_local() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, ".env", "TOKEN=SHARED-SECRET-VALUE-71c2e9\n");
    write(&proj, "deploy/.env.production", "TOKEN=SHARED-SECRET-VALUE-0d4b8a\n");
    write(&proj, "infra/main.tfstate", "{\"pw\": \"SHARED-SECRET-VALUE-5e6f10\"}\n");
    write(&proj, ".ssh/id_ed25519", "PERSONAL-KEY-VALUE-93ab02\n");
    write(&proj, "certs/server.pem", "PERSONAL-KEY-VALUE-1f2e3d\n");
    write(&proj, ".netrc", "machine x password PERSONAL-KEY-VALUE-c4d5e6\n");
    write(&proj, "app.py", "print('hi')\n");
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let files = recorded(&env, &proj);
    for p in [".env", "deploy/.env.production", "infra/main.tfstate"] {
        assert_eq!(tier_of(&files, p), Some("cloaked:team"), "{p}: {files:?}");
    }
    for p in ["id_ed25519", "server.pem", ".netrc"] {
        assert_eq!(tier_of(&files, p), None, "{p} left the device: {files:?}");
    }
    // Sealed means never plain text in the store, packs or op log.
    let bytes = store_bytes(&proj);
    for v in ["SHARED-SECRET-VALUE-71c2e9", "SHARED-SECRET-VALUE-0d4b8a", "SHARED-SECRET-VALUE-5e6f10"] {
        assert!(!holds(&bytes, v), "{v} stored in plain text");
    }
    // The member reads their own secret back.
    assert!(env.stdout("alice", &proj, &["cat", ".env", "-r", "@-"]).contains("SHARED-SECRET-VALUE-71c2e9"));
    // A team remote receives ciphertext only, and never the personal keys.
    let hub = env.dir("hub");
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["remote", "add", "origin", hub.to_str().unwrap()]);
    env.ok("alice", &proj, &["push"]);
    let remote = store_bytes(&hub);
    for v in ["SHARED-SECRET-VALUE-71c2e9", "PERSONAL-KEY-VALUE-93ab02", "PERSONAL-KEY-VALUE-1f2e3d", "PERSONAL-KEY-VALUE-c4d5e6"] {
        assert!(!holds(&remote, v), "{v} reached the remote");
    }
    // Someone without the key clones: no plaintext, and the file is not written.
    env.ok("bob", &env.root, &["clone", hub.to_str().unwrap(), "b"]);
    assert!(!env.root.join("b/.env").exists());
}

#[test]
fn existing_repositories_switch_to_synced_secrets_only_through_the_upgrade_step() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    // An existing repository: its policy has no rules for shared secrets.
    let policy = read(&proj, ".veilpolicy");
    let legacy: String = policy.lines().filter(|l| !l.contains("cloak team")).map(|l| format!("{l}\n")).collect();
    write(&proj, ".veilpolicy", &legacy);
    write(&proj, ".env", "TOKEN=LEGACY-SECRET-VALUE-aa11\n");
    write(&proj, "svc/.env.local", "TOKEN=LEGACY-SECRET-VALUE-bb22\n");
    write(&proj, "id_rsa", "PERSONAL\n");
    env.ok("alice", &proj, &["commit", "-m", "legacy"]);
    assert_eq!(tier_of(&recorded(&env, &proj), ".env"), None, "never silently");
    // The dry run lists exactly the files that would start syncing, and changes nothing.
    let dry = env.ok("alice", &proj, &["upgrade", "--sync-secrets", "--dry-run"]);
    assert!(dry.contains(".env") && dry.contains("svc/.env.local") && !dry.contains("id_rsa"), "{dry}");
    assert_eq!(read(&proj, ".veilpolicy"), legacy);
    env.ok("alice", &proj, &["commit", "-m", "still legacy"]);
    assert_eq!(tier_of(&recorded(&env, &proj), ".env"), None, "a dry run switched it");
    let out = env.ok("alice", &proj, &["upgrade", "--sync-secrets"]);
    assert!(out.contains("svc/.env.local"), "{out}");
    env.ok("alice", &proj, &["commit", "-m", "synced"]);
    let files = recorded(&env, &proj);
    assert_eq!(tier_of(&files, ".env"), Some("cloaked:team"), "{files:?}");
    assert_eq!(tier_of(&files, "svc/.env.local"), Some("cloaked:team"), "{files:?}");
    assert_eq!(tier_of(&files, "id_rsa"), None, "{files:?}");
    assert!(!holds(&store_bytes(&proj), "LEGACY-SECRET-VALUE-aa11"));
    // Running it again changes nothing.
    assert!(env.ok("alice", &proj, &["upgrade", "--sync-secrets"]).contains("already sync"));
}

#[test]
fn access_lines_record_plain_text_and_never_weaken_secrets() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["access", "ledger/", "finance"]);
    env.ok("alice", &proj, &["access", "src/", "public", "devs"]);
    // The same path again replaces its line instead of adding one.
    env.ok("alice", &proj, &["access", "ledger", "finance", "carol"]);
    let policy = read(&proj, ".veilpolicy");
    assert_eq!(policy.matches("ledger/").count(), 1, "{policy}");
    assert!(policy.contains("finance carol"), "{policy}");
    write(&proj, "ledger/invoice.txt", "invoice\n");
    write(&proj, "ledger/.env", "TOKEN=BILLING-SECRET-VALUE-77ee\n");
    write(&proj, "src/.env", "TOKEN=SRC-SECRET-VALUE-88ff\n");
    write(&proj, "src/id_ed25519", "PERSONAL\n");
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let files = recorded(&env, &proj);
    assert_eq!(tier_of(&files, "ledger/invoice.txt"), Some("public"), "folders under access lines are plain text: {files:?}");
    assert_eq!(tier_of(&files, "ledger/.env"), Some("cloaked:team"), "{files:?}");
    assert_eq!(tier_of(&files, "src/.env"), Some("cloaked:team"), "a public line never exposes a secret: {files:?}");
    assert_eq!(tier_of(&files, "src/id_ed25519"), None, "{files:?}");
    let bytes = store_bytes(&proj);
    assert!(!holds(&bytes, "BILLING-SECRET-VALUE-77ee") && !holds(&bytes, "SRC-SECRET-VALUE-88ff"));
    // Hostile names are refused, never written into the policy.
    for bad in [&["access", "x/", "Finance"][..], &["access", "x/", "a b"], &["access", "../x", "finance"], &["access", "*.rs", "finance"]] {
        assert!(!env.vl("alice", &proj, bad).status.success(), "{bad:?} accepted");
    }
    assert_eq!(read(&proj, ".veilpolicy"), policy);
}
