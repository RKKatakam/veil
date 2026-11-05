//! BUG-098 and round-5 leftovers, through the CLI: editor artefacts of
//! protected files in `vl status` and `vl policy check`, and why `vl status`
//! lists a file as redacted.

use crate::adversarial_support;

use adversarial_support::*;

const KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----
";

#[test]
fn status_lists_editor_artefacts_of_protected_files_as_local_only() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("README.md", "hello\n")]);
    write(&proj, "deploy/id_ed25519", KEY);
    write(&proj, "deploy/.id_ed25519.swp", KEY);
    write(&proj, ".env", "APP_KEY=base64:Zq8vXk9mQ2vL7pR4\n");
    write(&proj, ".env~", "APP_KEY=base64:Zq8vXk9mQ2vL7pR4\n");
    write(&proj, "deploy/server.pem.bak", KEY);
    write(&proj, "deploy/server.pem", KEY);
    write(&proj, "src/.main.rs.swp", "fn main() {}\n");
    let status = env.ok("alice", &proj, &["status"]);
    for path in ["deploy/.id_ed25519.swp", ".env~", "deploy/server.pem.bak"] {
        assert!(status.lines().any(|l| l.trim() == format!("L {path} [isolated]")), "{path} not local-only:\n{status}");
    }
    assert!(!status.contains("src/.main.rs.swp"), "a scratch file of a public file is ignored:\n{status}");
    let check = env.ok("alice", &proj, &["policy", "check", "deploy/.id_ed25519.swp", "src/.main.rs.swp"]);
    assert!(check.contains("artefact of deploy/id_ed25519"), "{check}");
    assert!(check.contains("built-in editor scratch rule '.*.sw[a-p]'"), "{check}");
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let files = env.stdout("alice", &proj, &["files", "-r", "@-"]);
    assert!(!files.contains("id_ed25519") && !files.contains(".env") && !files.contains(".swp"), "{files}");
    let show = env.ok("alice", &proj, &["policy", "show"]);
    assert!(show.contains(".*.sw[a-p]") && show.contains("take its protection"), "{show}");
}

#[test]
fn status_says_why_a_file_is_redacted() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("README.md", "hello\n")]);
    env.ok("alice", &proj, &["cloak", "plans/"]);
    write(&proj, "plans/q3.md", "launch\n");
    env.ok("alice", &proj, &["commit", "-m", "plans"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let mirror = env.root.join("mirror");
    env.ok("alice", &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok("alice", &proj, &["push", "mirror", "-t", "main"]);
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &proj, &["push", "origin", "-t", "main"]);

    env.ok("bob", &env.root, &["clone", mirror.to_str().unwrap(), "bob"]);
    let status = env.ok("bob", &env.root.join("bob"), &["status"]);
    assert!(status.contains("R plans/q3.md [redacted]  (cloaked:team; withheld by a public remote)"), "{status}");
    env.ok("carol", &env.root, &["clone", team.to_str().unwrap(), "carol"]);
    let status = env.ok("carol", &env.root.join("carol"), &["status"]);
    assert!(status.contains("R plans/q3.md [redacted]  (cloaked:team; no key)"), "{status}");
}
