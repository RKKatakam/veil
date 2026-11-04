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

// ---- the policy file itself ---------------------------------------------------------

/// What an anonymous reader of the public mirror at `mirror` gets for
/// `path` at tag `main`: `Some(plaintext)` if it is there and readable.
fn mirror_reads(mirror: &Path, path: &str) -> Option<Vec<u8>> {
    use std::sync::Arc;
    use veil_core::{tree::lookup, DiskBackend, Identity, Repo, VPath};
    let anon = Repo::open(Arc::new(DiskBackend::new(mirror)), Some(Identity::generate("anon")), "anon").unwrap();
    let main = anon.view().tags.get("main")?.target;
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
