//! Round-6 adversarial tests (Fable) through the real `vl` binary: ordinary
//! command sequences from the user guide that lose work, bypass the policy
//! pin, or launder secrets.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 6 findings (Fable)").

mod adversarial_support;

use std::path::Path;

use adversarial_support::{read, text, write, Env};

const U: &str = "alice";

/// The change id (first column) of the `vl log` line that describes `what`.
fn change_id_of(env: &Env, proj: &Path, what: &str) -> String {
    let log = env.stdout(U, proj, &["log"]);
    let lines: Vec<&str> = log.lines().collect();
    let i = lines.iter().position(|l| l.trim().ends_with(what)).unwrap_or_else(|| panic!("{what} not in log:\n{log}"));
    // The description is on the line after the one with the ids.
    let head = lines[i - 1];
    head.split_whitespace().nth(1).unwrap().to_string()
}

/// A binary secret: not valid UTF-8 anywhere, like a PKCS#12 bundle.
fn binary_secret() -> Vec<u8> {
    (0..300u32).map(|i| (i.wrapping_mul(97) ^ 0xa5) as u8 | 0x80).collect()
}

// ---- data loss ---------------------------------------------------------------

/// Control: `vl undo` after a command keeps the edits made before it.
#[test]
fn undo_after_a_commit_keeps_the_edits_made_since() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    env.ok(U, &proj, &["commit", "-m", "one"]);
    write(&proj, "work.txt", "important\n");
    env.ok(U, &proj, &["undo"]);
    assert_eq!(read(&proj, "work.txt"), "important\n");
    assert!(env.stdout(U, &proj, &["files"]).contains("work.txt"));
}

/// The guide: "Both [undo and op restore] keep the files on disk that you
/// had not recorded yet". `Repo::undo_keeping_edits` (`workspace.rs`,
/// `last_command_op`) skips automatic snapshots of the *attached*
/// workspace only. `vl ws switch` records no operation of its own, so
/// right after a switch the newest operation is the automatic snapshot of
/// the workspace just left, and `vl undo` undoes *that*: the edits made in
/// `default` before switching vanish from its working copy ("Undid:
/// snapshot working copy of 'default'"), and the directory, now attached
/// to `agent`, no longer holds them. They survive only in the op log.
#[test]
#[ignore = "BUG-100: `vl undo` right after `vl ws switch` discards the previous workspace's last edits instead of undoing a command"]
fn undo_after_a_workspace_switch_does_not_discard_the_previous_workspaces_edits() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    env.ok(U, &proj, &["ws", "new", "agent"]);
    write(&proj, "work.txt", "important\n");
    env.ok(U, &proj, &["ws", "switch", "agent"]);
    let out = env.ok(U, &proj, &["undo"]);
    let files = env.stdout(U, &proj, &["files", "-r", "default@"]);
    assert!(
        files.contains("work.txt"),
        "the edits of 'default' were undone ({}); its working copy now holds:\n{files}",
        out.trim()
    );
}

// ---- policy pin ----------------------------------------------------------------

/// Alice's project with an isolated `.env`, pushed to `hub`; Mallory's
/// clone pushes a `.veilpolicy` that says `.env public!`.
fn hostile_policy_on_main(env: &Env) -> std::path::PathBuf {
    let hub = env.dir("hub");
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".env", "DB_PASSWORD=hunter2hunter2\n");
    write(&proj, "a.txt", "a\n");
    env.ok(U, &proj, &["commit", "-m", "initial"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok(U, &proj, &["remote", "add", "origin", hub.to_str().unwrap()]);
    env.ok(U, &proj, &["push"]);
    let m = env.root.join("m");
    env.ok("mallory", &env.root, &["clone", hub.to_str().unwrap(), "m"]);
    let policy = read(&m, ".veilpolicy") + ".env public!\n";
    write(&m, ".veilpolicy", &policy);
    write(&m, "b.txt", "b\n");
    env.ok("mallory", &m, &["commit", "-m", "add b"]);
    env.ok("mallory", &m, &["push"]);
    proj
}

/// Control: the documented routes are guarded. After `vl pull` and
/// `vl rebase -d main`, `.env` keeps its protection until `vl policy accept`.
#[test]
fn a_pulled_policy_is_held_back_after_a_rebase() {
    let env = Env::new();
    let proj = hostile_policy_on_main(&env);
    env.ok(U, &proj, &["pull"]);
    let out = env.ok(U, &proj, &["rebase", "-d", "main"]);
    assert!(out.contains("policy accept"), "{out}");
    let files = env.stdout(U, &proj, &["files"]);
    assert!(!files.contains(".env"), "{files}");
}

/// `vl restore --from REV` writes REV's files into the working copy,
/// `.veilpolicy` included, and then snapshots as `restore …`
/// (`cmd_restore`, `main.rs`). The snapshot compares `.veilpolicy` with the
/// tree the directory was checked out from (`snapshot_policy(fs,
/// Some(&wc.tree))`), so a policy that arrived by `vl restore --from` counts
/// as **the member's own edit** and is folded into the accepted policy at
/// once (`policy::fold_edit`): the teammate's `.env public!` applies
/// without `vl policy accept`, `.env` is recorded in plaintext, and the
/// next commit and push publish it. The guide lists merge, pull, checkout,
/// rebase, Git import and undo as the guarded routes; `restore --from` is
/// a seventh route, and "put files back as they are in REV" does not read
/// as "and accept its policy".
#[test]
#[ignore = "BUG-101: `vl restore --from REV` accepts REV's .veilpolicy as the member's own edit, bypassing the policy pin"]
fn restore_from_a_revision_does_not_accept_its_policy() {
    let env = Env::new();
    let proj = hostile_policy_on_main(&env);
    env.ok(U, &proj, &["pull"]);
    env.ok(U, &proj, &["restore", "--from", "origin/main"]);
    let status = env.ok(U, &proj, &["status"]);
    let files = env.stdout(U, &proj, &["files"]);
    assert!(
        !files.contains(".env") && !status.contains("A .env"),
        "the restored policy published .env without `vl policy accept`:\n{status}\n{files}"
    );
    // And it never reaches the team remote.
    env.ok(U, &proj, &["commit", "-m", "after restore"]);
    env.ok(U, &proj, &["push"]);
    let hub = env.root.join("hub");
    let leaked = adversarial_support::tree_listing(&hub.join(".veil/objects"))
        .into_iter()
        .filter(|f| std::fs::read(hub.join(".veil/objects").join(f)).map_or(false, |d| d.windows(14).any(|w| w == b"hunter2hunter2")))
        .count();
    assert_eq!(leaked, 0, ".env reached the team remote in plaintext");
}

// ---- messages that lead users into mistakes --------------------------------------

/// `vl ws write NAME PATH` prints `Recorded PATH in …` whatever the builder
/// did with it (`cmd_ws`, `main.rs`): a path the policy isolates (`.env`,
/// `*.pem`, a user rule) is silently dropped, the overlay is discarded, and
/// the message says it was recorded. The user (or the agent driving `vl`)
/// believes the file is in the workspace; `vl ws cat` then says it does
/// not exist.
#[test]
#[ignore = "BUG-102: `vl ws write` of an isolated path says `Recorded` although the file was dropped"]
fn ws_write_of_an_isolated_path_does_not_claim_it_was_recorded() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("app.py", "x\n")]);
    env.ok(U, &proj, &["ws", "new", "agent"]);
    let mut c = env.cmd(U, &proj, &["ws", "write", "agent", ".env"]);
    c.stdin(std::process::Stdio::piped());
    c.stdout(std::process::Stdio::piped());
    c.stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write as _;
    child.stdin.take().unwrap().write_all(b"SECRET=abc\n").unwrap();
    let out = child.wait_with_output().unwrap();
    let t = text(&out);
    let cat = env.vl(U, &proj, &["ws", "cat", "agent", ".env"]);
    let recorded = cat.status.success();
    assert!(
        recorded || !t.contains("Recorded .env") || t.contains("isolat") || t.contains("local-only"),
        "the file was dropped but the command said:\n{t}"
    );
}

// ---- hostile team remote ----------------------------------------------------------

/// `vl git pull` refuses to create a local tag whose name is a change id
/// prefix (BUG-059). `vl pull` from a Veil remote does not (`remote.rs`,
/// `pull_with`: any name `validate_tag_name` accepts), and tags win over
/// change ids in revsets. Alice's change ids are visible on the team
/// remote, so Mallory, who can push there, tags her own snapshot with the
/// 8-letter prefix `vl log` shows for Alice's change. After `vl pull`,
/// Alice's `vl edit <prefix>` (or `vl new`, `vl squash -r`, `vl rebase -s`)
/// quietly lands on Mallory's snapshot; `vl log` shows the prefix as a tag
/// next to it.
#[test]
#[ignore = "BUG-105: a remote tag named after a change-id prefix hijacks that change in revsets after `vl pull`"]
fn a_pulled_tag_named_after_a_change_id_does_not_hijack_the_change() {
    let env = Env::new();
    let hub = env.dir("hub");
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, "a.txt", "a\n");
    env.ok(U, &proj, &["commit", "-m", "my work"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok(U, &proj, &["remote", "add", "origin", hub.to_str().unwrap()]);
    env.ok(U, &proj, &["push"]);
    let cid = change_id_of(&env, &proj, "my work");
    let full_cid = env.stdout(U, &proj, &["show", "@-"]).lines().next().unwrap().split_whitespace().last().unwrap().to_string();

    let m = env.root.join("m");
    env.ok("mallory", &env.root, &["clone", hub.to_str().unwrap(), "m"]);
    write(&m, "evil.txt", "evil\n");
    env.ok("mallory", &m, &["commit", "-m", "evil"]);
    env.ok("mallory", &m, &["tag", "set", &cid, "-r", "@-"]);
    env.ok("mallory", &m, &["push", "-t", &cid]);

    env.ok(U, &proj, &["pull"]);
    env.ok(U, &proj, &["edit", &cid]);
    let show = env.stdout(U, &proj, &["show", "@"]);
    let now = show.lines().next().unwrap().split_whitespace().last().unwrap().to_string();
    assert_eq!(now, full_cid, "`vl edit {cid}` landed on Mallory's snapshot:\n{show}");
}

// ---- injected secrets ---------------------------------------------------------------

/// Control: a text secret copied in the sandbox is quarantined.
#[test]
fn a_copied_text_secret_is_quarantined_in_the_sandbox() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("app.py", "x\n")]);
    write(&proj, ".env", "API_TOKEN=Xk9mQ2vL7pR4wZt8\n");
    env.ok(U, &proj, &["status"]);
    env.ok(U, &proj, &["ws", "new", "agent"]);
    let out = env.vl(U, &proj, &["ws", "exec", "agent", "--with-isolated", "--", "sh", "-c", "cp .env leaked.txt"]);
    assert!(text(&out).contains("quarantined"), "{}", text(&out));
    assert!(!env.stdout(U, &proj, &["files", "-r", "agent@"]).contains("leaked.txt"));
}

/// `server.p12` is isolated by a built-in rule and backed up in the vault.
/// `vl ws exec --with-isolated` injects it, the command copies it under a
/// public name, and the copy is recorded (see
/// `adversarial6_visibility::an_injected_binary_secret_is_recognised_in_a_copy`).
#[test]
#[ignore = "BUG-099: binary isolated files (keystores, PKCS#12, DER keys) injected into a sandbox are not recognised when copied"]
fn a_copied_keystore_is_quarantined_in_the_sandbox() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("app.py", "x\n")]);
    std::fs::write(proj.join("server.p12"), binary_secret()).unwrap();
    env.ok(U, &proj, &["status"]);
    env.ok(U, &proj, &["ws", "new", "agent"]);
    let out = env.vl(U, &proj, &["ws", "exec", "agent", "--with-isolated", "--", "sh", "-c", "cp server.p12 dist/bundle.bin 2>/dev/null || (mkdir dist && cp server.p12 dist/bundle.bin)"]);
    let files = env.stdout(U, &proj, &["files", "-r", "agent@"]);
    assert!(
        !files.contains("bundle.bin"),
        "the keystore copy was recorded in the workspace ({}):\n{files}",
        text(&out).trim()
    );
}
