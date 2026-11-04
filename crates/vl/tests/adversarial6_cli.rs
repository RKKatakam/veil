//! Round-6 adversarial tests (Fable) through the real `vl` binary: ordinary
//! command sequences from the user guide that lose work, bypass the policy
//! pin, or launder secrets.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 6 findings (Fable)").

mod adversarial_support;

use std::{path::Path, time::Duration};

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
    // And it never reaches the team remote (packs are zstd: read it back
    // through the engine, as any reader of the remote would).
    env.ok(U, &proj, &["commit", "-m", "after restore"]);
    env.ok(U, &proj, &["tag", "set", "after", "-r", "@-"]);
    env.ok(U, &proj, &["push"]);
    let hub = env.root.join("hub");
    assert!(remote_reads(&hub, "after", ".env").is_none(), ".env reached the team remote in plaintext");
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

// ---- the policy file itself ---------------------------------------------------------

/// [`remote_reads`] at tag `main`.
fn mirror_reads(mirror: &Path, path: &str) -> Option<Vec<u8>> {
    remote_reads(mirror, "main", path)
}

/// What an anonymous reader of the remote at `remote` gets for `path` at
/// `tag`: `Some(plaintext)` if it is there and readable.
fn remote_reads(remote: &Path, tag: &str, path: &str) -> Option<Vec<u8>> {
    use std::sync::Arc;
    use veil_core::{tree::lookup, DiskBackend, Identity, Repo, VPath};
    let anon = Repo::open(Arc::new(DiskBackend::new(remote)), Some(Identity::generate("anon")), "anon").unwrap();
    let main = anon.view().tags.get(tag)?.target;
    let tree = anon.snapshot(&main).unwrap().tree;
    let e = lookup(anon.store(), &tree, &VPath::new(path).unwrap()).unwrap()?;
    anon.store().read_entry(&e).ok()
}

/// A project with `secrets/ cloak team`, one cloaked file, tag `main` and
/// a public mirror remote `mirror`.
fn project_with_cloaked_secret(env: &Env) -> std::path::PathBuf {
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".veilpolicy", "secrets/ cloak team\n");
    write(&proj, "secrets/db.yml", "password: hunter2hunter2\n");
    write(&proj, "README", "hi\n");
    env.ok(U, &proj, &["commit", "-m", "initial"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    let mirror = env.dir("mirror");
    env.ok(U, &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok(U, &proj, &["push", "mirror"]);
    assert!(mirror_reads(&mirror, "secrets/db.yml").is_none(), "control: cloaked content is withheld");
    proj
}

/// `DiskBackend` reports nothing at a symlink, so when `.veilpolicy` is a
/// symlink (a dotfiles manager, `stow`, `chezmoi`, `cp -s`, a monorepo
/// pointing it at a shared file) `Policy::load` finds no policy at all
/// and every user rule stops applying. The working copy's "deleted" policy
/// counts as the member's own edit (`working_copy_policy`), so the accepted
/// policy follows it, and because the policy "changed" the builder's
/// "sealed content keeps its audience" rule is lifted (`file_entry`:
/// `reclassified`): the next snapshot re-stores every cloaked file in
/// plaintext, and the next push sends it to the public mirror. The only
/// message is `.veilpolicy is tracked but is now a symlink …; Veil … keeps
/// the recorded version`, which says the opposite of what happens: the
/// recorded *entry* is kept, the rules are not.
#[test]
#[ignore = "BUG-106: a symlinked .veilpolicy is ignored and previously cloaked files are re-recorded in plaintext"]
fn a_symlinked_policy_file_still_applies() {
    let env = Env::new();
    let proj = project_with_cloaked_secret(&env);
    let aside = env.root.join("dotfiles-veilpolicy");
    std::fs::rename(proj.join(".veilpolicy"), &aside).unwrap();
    std::os::unix::fs::symlink(&aside, proj.join(".veilpolicy")).unwrap();
    write(&proj, "secrets/api.yml", "token: Xk9mQ2vL7pR4wZt8\n");
    let status = env.ok(U, &proj, &["status"]);
    let files = env.stdout(U, &proj, &["files"]);
    assert!(
        files.contains("cloaked:team") && !files.lines().any(|l| l.starts_with("public") && l.contains("secrets/")),
        "the policy stopped applying:\n{status}\n{files}"
    );
    env.ok(U, &proj, &["commit", "-m", "more secrets"]);
    env.ok(U, &proj, &["push", "mirror"]);
    let mirror = env.root.join("mirror");
    assert!(mirror_reads(&mirror, "secrets/db.yml").is_none(), "the cloaked file reached the public mirror in plaintext");
    assert!(mirror_reads(&mirror, "secrets/api.yml").is_none(), "the new secret reached the public mirror in plaintext");
}

/// "Nothing in the working copy can fail a snapshot" (ARCHITECTURE §4):
/// an unreadable file is reported and skipped. `.veilpolicy` is the
/// exception: `Policy::load` runs before the build and propagates the I/O
/// error, so with `chmod 000 .veilpolicy` (or a directory named
/// `.veilpolicy`) every command fails, `vl ignore` and `vl status`
/// included; only `--no-snapshot` gets through.
#[test]
#[ignore = "BUG-107: an unreadable (or directory) .veilpolicy makes every command fail"]
fn an_unreadable_policy_file_does_not_brick_the_cli() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    std::fs::set_permissions(proj.join(".veilpolicy"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let out = env.vl(U, &proj, &["status"]);
    std::fs::set_permissions(proj.join(".veilpolicy"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(out.status.success(), "vl status failed on an unreadable .veilpolicy: {}", text(&out));
    std::fs::rename(proj.join(".veilpolicy"), proj.join("policy.bak")).unwrap();
    std::fs::create_dir(proj.join(".veilpolicy")).unwrap();
    let out = env.vl(U, &proj, &["status"]);
    assert!(out.status.success(), "vl status failed on a directory named .veilpolicy: {}", text(&out));
}

// ---- undo that does not undo ---------------------------------------------------------

/// `vl embargo release` is recorded as an operation (`Repo::release_embargo`
/// commits a `release embargo <id>` op with `record_always`), so `vl undo`
/// reports `Undid: release embargo <id>`. But the release lives in the
/// embargo *record* (`.veil/meta/embargoes/<id>.json`, the published key),
/// not in the view the operation log restores, so nothing is undone: the
/// embargo stays released, and the next `vl push mirror` publishes the
/// security fix. The guide promises "Undo anything" and lists every
/// repository-changing command as an operation; the one command whose
/// accidental use publishes a vulnerability is the one undo lies about.
#[test]
#[ignore = "BUG-109: `vl undo` after `vl embargo release` says it undid the release, but the embargo stays released and the next push publishes the fix"]
fn undo_of_an_embargo_release_keeps_the_fix_embargoed() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, "auth.rs", "fn check() { true }\n");
    env.ok(U, &proj, &["commit", "-m", "v1"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    let mirror = env.dir("mirror");
    env.ok(U, &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok(U, &proj, &["push", "mirror"]);
    env.ok(U, &proj, &["ws", "new", "fix", "-r", "main", "--cloak", "team"]);
    let mut c = env.cmd(U, &proj, &["ws", "write", "fix", "auth.rs"]);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write as _;
    child.stdin.take().unwrap().write_all(b"fn check() { verify_signature_secretfix() }\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    env.ok(U, &proj, &["merge", "fix@", "--into", "main", "--embargo", "-m", "Fix CVE"]);
    let id = env.stdout(U, &proj, &["embargo", "list"]).split_whitespace().next().unwrap().to_string();
    env.ok(U, &proj, &["embargo", "release", &id]);
    let undo = env.ok(U, &proj, &["undo"]);
    assert!(undo.contains("release embargo"), "{undo}");
    let list = env.stdout(U, &proj, &["embargo", "list"]);
    assert!(!list.contains("released"), "undo reported success but the embargo is still released:\n{list}");
    env.ok(U, &proj, &["push", "mirror"]);
    assert!(mirror_reads(&mirror, "auth.rs").is_none_or(|d| !d.windows(9).any(|w| w == b"secretfix")), "the fix was published after the release was undone");
}

// ---- checkout over local-only directories -------------------------------------------

/// Checkout never overwrites a *file* it did not write (`holds`), but
/// when the target tree has a file where the working copy has a directory
/// it runs `remove_dir_all` on that directory without looking inside
/// (`checkout.rs`, `apply_changes`). An isolated directory (`private/
/// isolate`) and an ignored one (`target/`, `node_modules/`) hold content
/// that is in no snapshot, and the file entry `private` does not match the
/// directory rule `private/`, so `is_local_only` does not protect it. One
/// `vl new <rev>` (a teammate's change, or a hostile remote's) deletes the
/// user's private notes and the build tree, and the next snapshot prunes
/// the vault's backup of the notes because they no longer exist.
#[test]
#[ignore = "BUG-110: checkout deletes an isolated or ignored directory (never recorded) when the target tree has a file at its path"]
fn checkout_does_not_delete_a_local_only_directory_to_place_a_file() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, ".veilpolicy", "private/ isolate\ntarget/ ignore\n");
    write(&proj, "a.txt", "a\n");
    env.ok(U, &proj, &["commit", "-m", "v1"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    write(&proj, "private/notes.md", "my private notes\n");
    write(&proj, "target/out.o", "build junk\n");
    let status = env.ok(U, &proj, &["status"]);
    assert!(status.contains("private/notes.md"), "control: the notes are isolated:\n{status}");
    env.ok(U, &proj, &["ws", "new", "t"]);
    for name in ["private", "target"] {
        let mut c = env.cmd(U, &proj, &["ws", "write", "t", name]);
        c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = c.spawn().unwrap();
        use std::io::Write as _;
        child.stdin.take().unwrap().write_all(b"x\n").unwrap();
        assert!(child.wait_with_output().unwrap().status.success());
    }
    let out = env.vl(U, &proj, &["new", "t@"]);
    assert!(
        proj.join("private/notes.md").is_file() && read(&proj, "private/notes.md") == "my private notes\n",
        "the isolated directory was deleted by the checkout ({})",
        text(&out).trim()
    );
    assert!(proj.join("target/out.o").is_file(), "the ignored directory was deleted by the checkout");
}

/// The opposite swap: a *file* in the working copy (here a quarantined
/// `cfg`, never recorded; any untracked file works) where the target tree
/// has a directory `cfg/`. Checkout writes `cfg/settings.json`;
/// `DiskBackend::write` fails with `File exists` on the parent, the
/// checkout aborts half way, and the error is returned **after the view
/// already moved**. From then on every command fails the same way: each
/// one finds the working copy stale and retries the same checkout
/// (`Ctx::record`). Only `vl --no-snapshot undo`, or deleting the file by
/// hand, gets out. The documented behaviour for a file in the way is to
/// keep it and report it (`CheckoutReport::blocked` / `kept_local`).
#[test]
#[ignore = "BUG-111: a file in the way of a directory makes a checkout fail half way and bricks every later command"]
fn a_file_in_the_way_of_a_directory_is_kept_and_reported() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    write(&proj, "cfg", "k = \"AKIAIOSFODNN7EXAMPLE\"\n");
    assert!(env.ok(U, &proj, &["status"]).contains("Q cfg"));
    env.ok(U, &proj, &["ws", "new", "t"]);
    let mut c = env.cmd(U, &proj, &["ws", "write", "t", "cfg/settings.json"]);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write as _;
    child.stdin.take().unwrap().write_all(b"{}\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    let out = env.vl(U, &proj, &["new", "t@"]);
    let status = env.vl(U, &proj, &["status"]);
    assert!(
        out.status.success() && status.status.success(),
        "checkout: {}\nnext command: {}",
        text(&out).trim(),
        text(&status).trim()
    );
    assert_eq!(read(&proj, "cfg"), "k = \"AKIAIOSFODNN7EXAMPLE\"\n", "the quarantined file was lost");
}

// ---- the identity file ------------------------------------------------------------------

/// `ctx::write_identity` creates `identity.json` with `std::fs::write`
/// (mode `0666 & ~umask`, so `0644` for most users) and only then
/// `chmod 0600`s it. Between the two calls the private keys are
/// world-readable in `$VEIL_HOME`, which on a shared machine is enough for
/// another local user polling the directory (round-1 hypothesis
/// "identity-file race", demonstrated here with `strace`). The retired
/// copy is created the right way (`create_new` with mode `0600`); the live
/// file is not. Skipped where `strace` is unavailable or cannot attach.
#[test]
#[ignore = "BUG-112: identity.json is created world-readable and chmod'ed 0600 afterwards"]
fn the_identity_file_is_never_world_readable_even_briefly() {
    let env = Env::new();
    let proj = env.dir("proj");
    let trace = env.root.join("trace.txt");
    let strace = match std::process::Command::new("strace").arg("-V").output() {
        Ok(o) if o.status.success() => "strace",
        _ => return, // not available: nothing to demonstrate with
    };
    let home = env.root.join("home-fresh");
    let out = std::process::Command::new(strace)
        .args(["-f", "-e", "trace=openat,open,creat,chmod,fchmod,fchmodat", "-o"])
        .arg(&trace)
        .arg(env!("CARGO_BIN_EXE_vl"))
        .args(["identity", "show"])
        .current_dir(&proj)
        .env("VEIL_HOME", &home)
        .env("VEIL_USER", U)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    if !out.status.success() || !trace.exists() {
        return; // ptrace not permitted here
    }
    let log = std::fs::read_to_string(&trace).unwrap();
    let creates: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("identity.json") && l.contains("O_CREAT") && !l.contains("ENOENT"))
        .collect();
    assert!(!creates.is_empty(), "no create of identity.json seen:\n{log}");
    for c in &creates {
        // `openat(AT_FDCWD, "…/identity.json", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 3`
        let mode = c.rsplit(", ").next().unwrap_or("").split(')').next().unwrap_or("").trim();
        assert!(
            mode.ends_with("600") || mode.ends_with("400"),
            "identity.json is created with mode {mode} (then chmod'ed): {c}"
        );
    }
}

// ---- `vl ws switch` is not failure-safe ----------------------------------------------

/// `vl ws switch` changes nothing in the repository: the attachment lives
/// only in `.veil/local/checkout.json`, written by `Ctx::finish` **after**
/// the checkout that replaces the directory's files. If that checkout
/// fails half way (here: a quarantined file `cfg` where `agent` has a
/// directory `cfg/`, BUG-111; a `kill -9` or a full disk at that point
/// leaves the same state), the directory holds a mix of both workspaces
/// but is still recorded as attached to `default`, and nothing is stale
/// (`Ctx::record`: same workspace, same snapshot). The next command
/// records that mix as `default`'s working copy: `agent`'s files appear as
/// additions and `default`'s own files, already removed by the checkout,
/// are recorded as deleted. `vl new`/`vl edit` survive the same crash
/// (the view moved, so the directory is detected as stale and its state is
/// saved as a change); `ws switch` does not.
#[test]
#[ignore = "BUG-113: a `vl ws switch` whose checkout fails or is interrupted records the half-switched directory as the old workspace's working copy"]
fn an_interrupted_workspace_switch_does_not_corrupt_the_old_workspace() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    env.ok(U, &proj, &["ws", "new", "agent"]);
    for (path, content) in [("agent.txt", "agent only\n"), ("cfg/settings.json", "{}\n")] {
        let mut c = env.cmd(U, &proj, &["ws", "write", "agent", path]);
        c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = c.spawn().unwrap();
        use std::io::Write as _;
        child.stdin.take().unwrap().write_all(content.as_bytes()).unwrap();
        assert!(child.wait_with_output().unwrap().status.success());
    }
    write(&proj, "default.txt", "default work\n");
    write(&proj, "cfg", "k = \"AKIAIOSFODNN7EXAMPLE\"\n");
    env.ok(U, &proj, &["status"]);
    let switch = env.vl(U, &proj, &["ws", "switch", "agent"]);
    let _ = env.vl(U, &proj, &["status"]);
    let default_files = env.stdout(U, &proj, &["files", "-r", "default@"]);
    assert!(
        default_files.contains("default.txt") && !default_files.contains("agent.txt"),
        "after the failed switch ({}), default's working copy is:\n{default_files}",
        text(&switch).trim()
    );
}

// ---- `vl scan` in CI ---------------------------------------------------------------

/// Control: the guide's CI recipe (`vl init` in a Git checkout, then
/// `vl --no-snapshot scan`) fails the job on a leaked key.
#[test]
fn the_ci_scan_recipe_fails_on_a_leaked_key() {
    let env = Env::new();
    let co = env.dir("checkout");
    write(&co, "README.md", "# project\n");
    write(&co, "leak.js", "const k = \"AKIAIOSFODNN7EXAMPLE\";\n");
    env.ok("ci", &co, &["init"]);
    let out = env.vl("ci", &co, &["--no-snapshot", "scan"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
}

/// The guide sells `vl scan` as the CI gate ("In a GitHub Actions step
/// this fails the job on a hit"), and `vl init` keeps the `.veilpolicy`
/// that is checked out. `vl scan` honours that policy's `public!` (and
/// `ignore`) rules, so the same pull request that adds the leaked key can
/// add `leak.js public!` (or `** public!`) next to it, and the gate
/// reports `ok: no secrets in public files`. A CI scan whose rules come
/// from the artefact it scans is not a gate; `vl scan` has no option to
/// ignore `public!` or to require the policy from a trusted ref.
#[test]
#[ignore = "BUG-115: the CI recipe `vl init && vl --no-snapshot scan` is switched off by a `public!` rule in the scanned checkout's .veilpolicy"]
fn the_ci_scan_recipe_cannot_be_switched_off_by_the_scanned_policy() {
    let env = Env::new();
    let co = env.dir("checkout");
    write(&co, "README.md", "# project\n");
    write(&co, "leak.js", "const k = \"AKIAIOSFODNN7EXAMPLE\";\n");
    write(&co, ".veilpolicy", "leak.js public!\n");
    env.ok("ci", &co, &["init"]);
    let out = env.vl("ci", &co, &["--no-snapshot", "scan"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the scan passed with a leaked key, because the checkout's own policy says so:\n{}",
        text(&out)
    );
}

// ---- undo reaching past commands that are not operations -------------------------

/// "Every command that changes the repository is an operation in the
/// operation log" (guide). `vl scope grant|revoke|rotate`, `vl remote
/// add|rm` and `vl secret set|rm|import` change the repository but record
/// no operation, so `vl undo` right after one of them undoes the *previous*
/// operation instead: here `set tag main` (it could as well be the last
/// commit or a merge). The grant stays, `main` is gone, and the one-line
/// `Undid: set tag main` is all that says so. A member who granted the
/// wrong key, "undid" it, and pushes, ships the ring with that key in it.
#[test]
#[ignore = "BUG-116: `vl undo` after `vl scope grant` (or `remote add`, `secret set`) undoes the previous unrelated operation and leaves the grant in place"]
fn undo_after_a_scope_grant_does_not_undo_an_unrelated_operation() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let bob = env.stdout("bob", &proj, &["identity", "show"]);
    let key = bob.lines().find(|l| l.starts_with("public key")).unwrap().split_whitespace().last().unwrap().to_string();
    env.ok(U, &proj, &["scope", "grant", "team", &key, "--name", "bob"]);
    let out = env.vl(U, &proj, &["undo"]);
    let tags = env.stdout(U, &proj, &["tag", "list"]);
    let scope = env.stdout(U, &proj, &["scope", "list"]);
    assert!(
        tags.contains("main") && (!out.status.success() || !scope.contains("bob")),
        "undo after the grant: {}\ntags:\n{tags}scope:\n{scope}",
        text(&out).trim()
    );
}

// ---- `vl watch` next to other commands ----------------------------------------------

/// `vl watch` is the guide's "records continuously, as files change". It
/// keeps one `Ctx` for its whole life, with the checkout pointer it read at
/// start; every tick reloads the *view* but not `checkout.json`. When
/// another `vl` command in the same directory moves the working copy (a
/// `vl commit`, `vl new`: it checks the directory out and rewrites
/// `checkout.json`), the watcher's next tick sees the view's working copy
/// differ from its cached pointer, judges the directory *stale*, saves
/// whatever the user wrote since as `recovered working-copy edits` on top
/// of the obsolete snapshot it remembers (a branch off a predecessor that
/// is no longer visible), and then checks the directory out again, which
/// **removes those files from disk**. The user's new file vanishes while
/// they are editing; it survives only in a stray change.
#[test]
#[ignore = "BUG-117: `vl watch` next to another `vl` command moves the user's new files off disk into a stray change on an obsolete snapshot"]
fn watch_does_not_move_new_files_off_disk_after_a_concurrent_command() {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    let mut watch = env.spawn(U, &proj, &["watch", "--interval-ms", "2500"]);
    std::thread::sleep(Duration::from_millis(300));
    write(&proj, "e1.txt", "edit before the other command\n");
    // Let one tick record e1.txt (the watcher is now at the recorded wc).
    std::thread::sleep(Duration::from_millis(3000));
    env.ok(U, &proj, &["commit", "-m", "from the other terminal"]);
    write(&proj, "f.txt", "new file right after the commit\n");
    // Two more ticks.
    std::thread::sleep(Duration::from_millis(6000));
    watch.kill().unwrap();
    let out = watch.wait_with_output().unwrap();
    let files = env.stdout(U, &proj, &["files"]);
    assert!(
        proj.join("f.txt").is_file() && files.contains("f.txt"),
        "f.txt was moved off disk by the watcher ({}):\nfiles:\n{files}",
        text(&out).trim()
    );
}

// ---- SSH remote paths -----------------------------------------------------------------

/// A fake `ssh` that ignores its arguments and serves SFTP from `home`
/// (the OpenSSH `sftp-server`, as `ssh -s host sftp` would run it on the
/// server). `None` if no `sftp-server` is installed.
fn fake_ssh(env: &Env, home: &Path) -> Option<std::path::PathBuf> {
    let server = ["/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server", "/usr/libexec/sftp-server"]
        .into_iter()
        .find(|p| Path::new(p).exists())?;
    let script = env.root.join("fake-ssh");
    std::fs::write(&script, format!("#!/bin/sh\ncd '{}' && exec {server}\n", home.display())).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    Some(script)
}

/// Git, `scp` and `sftp` all take `host:~/path` as the home directory
/// (`~` is expanded by the shell `scp` runs, or by `sftp`). Veil's
/// scp-style parsing hands the path to the SFTP server verbatim, and
/// OpenSSH's `sftp-server` does not expand `~`: `vl push` creates a
/// directory literally named `~` in the login directory and the
/// repository under it. Push and pull keep working against that path, so
/// nothing is lost, but the repository is not where the admin looks for it
/// (and backs it up), and `ssh host ls '~/repo'` says it does not exist.
/// The documented form `ssh://host/~/repo` is resolved. Skipped without an
/// `sftp-server` binary.
#[test]
#[ignore = "BUG-118: scp-style `host:~/path` creates a directory literally named `~` on the server"]
fn scp_style_tilde_paths_resolve_to_the_home_directory() {
    let env = Env::new();
    let home = env.dir("serverhome");
    let Some(ssh) = fake_ssh(&env, &home) else { return };
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    env.ok(U, &proj, &["remote", "add", "origin", "fakehost:~/repo"]);
    let mut c = env.cmd(U, &proj, &["push", "origin"]);
    c.env("VEIL_SSH", &ssh);
    let out = c.output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        home.join("repo/.veil/repo.json").is_file() && !home.join("~").exists(),
        "the repository landed in {:?}",
        adversarial_support::tree_listing(&home).into_iter().take(4).collect::<Vec<_>>()
    );
}

/// The hostile-server side of BUG-119 (see
/// `adversarial6_lock::a_symlinked_lock_file_does_not_spin_for_ever`): a
/// remote whose `.veil/lock` is a dangling symlink wedges `vl push` for
/// ever at full CPU. Skipped without an `sftp-server` binary.
#[test]
#[ignore = "BUG-119: a symlinked .veil/lock (local or on an SFTP remote) makes every command spin at full CPU for ever"]
fn a_push_to_a_remote_with_a_symlinked_lock_fails_instead_of_spinning() {
    let env = Env::new();
    let home = env.dir("serverhome");
    let Some(ssh) = fake_ssh(&env, &home) else { return };
    let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
    env.ok(U, &proj, &["remote", "add", "origin", "fakehost:repo"]);
    let mut c = env.cmd(U, &proj, &["push", "origin"]);
    c.env("VEIL_SSH", &ssh);
    assert!(c.output().unwrap().status.success());
    std::os::unix::fs::symlink("/nonexistent", home.join("repo/.veil/lock")).unwrap();
    write(&proj, "b.txt", "b\n");
    let mut c = env.cmd(U, &proj, &["push", "origin"]);
    c.env("VEIL_SSH", &ssh).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    let finished = adversarial_support::wait_for(Duration::from_secs(120), || child.try_wait().unwrap().is_some());
    if !finished {
        let _ = child.kill();
    }
    assert!(finished, "`vl push` was still running after 120 s against a remote whose lock is a symlink");
}
