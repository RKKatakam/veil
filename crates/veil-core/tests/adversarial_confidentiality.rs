//! Adversarial tests: can cloaked, isolated, embargoed or quarantined content
//! leak? Each test plays a concrete attack end to end and checks what a
//! non-member (public mirror reader, team-remote reader outside a scope, or a
//! malicious contributor) can actually read.

mod adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    crypto::Envelope,
    identity::WrappedKey,
    keychain::KeyRing,
    object::{Object, Text, Visibility},
    policy::{Policy, Tier},
    remote,
    revset::resolve,
    secrets, Identity, MemoryBackend, Repo, StorageBackend,
};

fn anon_view(backend: Arc<MemoryBackend>) -> Repo {
    Repo::open(backend, Some(Identity::generate("anon")), "anon").unwrap()
}

fn clone_as(id: &Identity, from: Arc<MemoryBackend>) -> Repo {
    let mut r = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(id.clone()), &id.name).unwrap();
    remote::pull(&mut r, "origin", from).unwrap();
    r
}

// ---- embargoes ---------------------------------------------------------------

/// The README flow: develop the fix as an ordinary change, merge it with
/// `--embargo`, push the main line to the public mirror.
#[test]
fn embargoed_merge_does_not_push_the_fix_branch_to_a_public_mirror() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let fix_ws = alice.ephemeral_workspace(main).unwrap();
    fix_ws.write("auth.rs", "fn check() -> bool { verify_signature() }\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&fix_ws, "fix").unwrap();
    alice
        .merge(WS, main, vec![fix], "merge", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();

    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let hits = backend_contains(&*mirror, b"verify_signature");
    assert!(hits.is_empty(), "the embargoed fix is readable on the public mirror: {hits:?}");
}

#[test]
fn embargo_messages_are_not_public_before_release() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "v1\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    // fix on a cloaked line, so only the merge metadata can leak
    alice.create_workspace("fix", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"v2\n").unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    alice
        .merge(
            WS,
            main,
            vec![fix],
            "Fix CVE-2026-31337: auth bypass via unsigned tokens",
            Some(EmbargoSpec { scope: "team".into(), until: None }),
        )
        .unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let hits = backend_contains(&*mirror, b"CVE-2026-31337");
    assert!(hits.is_empty(), "embargo description leaked to the public mirror: {hits:?}");
}

// ---- cloaked lines of work becoming public -----------------------------------

#[test]
fn merging_a_cloaked_workspace_scans_files_that_become_public() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    alice.create_workspace("exp", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("exp").unwrap();
    ov.write(&p("cfg.js"), b"const k = \"AKIAIOSFODNN7EXAMPLE\";\n").unwrap();
    let exp = alice.snapshot_workspace("exp", &ov).unwrap().snapshot;
    // sanity: a public snapshot of the same content is quarantined
    assert!(!secrets::scan(b"const k = \"AKIAIOSFODNN7EXAMPLE\";\n").is_empty());

    alice.merge(WS, main, vec![exp], "merge experiment", None).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let hits = backend_contains(&*mirror, b"AKIAIOSFODNN7EXAMPLE");
    assert!(hits.is_empty(), "an AWS key reached the public mirror unscanned: {hits:?}");
}

/// A cloaked change (scope `ops`) sits on a public parent. The parent is
/// amended; auto-rebase three-way-merges the cloaked file and stores the
/// result with the *parent's* visibility, i.e. in plaintext.
#[test]
fn auto_rebase_never_downgrades_cloaked_content_to_public() {
    let (mut alice, fs, _) = new_repo("alice");
    alice.keys().create_scope("ops").unwrap();
    let lines: String = (1..=12).map(|i| format!("line {i}\n")).collect();
    let base = commit_files(&mut alice, &*fs, &[("settings.conf", &lines)], "base");
    alice.create_workspace("sec", vec![base], Some("ops".into())).unwrap();
    let ov = alice.workspace_overlay("sec").unwrap();
    ov.write(&p("settings.conf"), lines.replace("line 12\n", "db_pass hunter2-OPS-ONLY\n").as_bytes()).unwrap();
    alice.snapshot_workspace("sec", &ov).unwrap();
    alice.commit_working_copy("sec", "ops tweak").unwrap();
    let c = resolve(&alice, "sec@-", WS).unwrap();
    assert!(!file_entry(&alice, &c, "settings.conf").unwrap().visibility.is_public());

    // amend the public parent (different hunk => clean merge)
    alice.edit(WS, base).unwrap();
    fs.write(&p("settings.conf"), lines.replace("line 1\n", "line one\n").as_bytes()).unwrap();
    snap(&mut alice, &*fs);

    let c2 = resolve(&alice, "sec@-", WS).unwrap();
    assert_ne!(c2, c, "the cloaked change was rebased");
    let e = file_entry(&alice, &c2, "settings.conf").unwrap();
    assert!(
        !e.visibility.is_public(),
        "rebased cloaked change now holds a public entry: {:?}",
        e.visibility
    );

    // End to end: Bob is on the team remote but not in `ops`.
    alice.set_tag("ops-work", c2, Some("ops".into()), false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();
    let bob = clone_as(&Identity::generate("bob"), team);
    let leaked = file_entry(&bob, &c2, "settings.conf").and_then(|e| bob.store().read_entry(&e).ok());
    assert!(
        !leaked.is_some_and(|d| String::from_utf8_lossy(&d).contains("hunter2")),
        "a non-member of `ops` reads ops-only content"
    );
}

/// `vl new <cloaked change>` from an ordinary workspace: the new change
/// inherits the sealed entries, and the very next auto-snapshot re-stores
/// them as public plaintext (the workspace is not cloaked). No warning.
#[test]
fn new_change_on_a_cloaked_change_does_not_declassify_it() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    alice.create_workspace("exp", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("exp").unwrap();
    ov.write(&p("plan.md"), b"CLOAKED-PLAN: acquire Initech\n").unwrap();
    let exp = alice.snapshot_workspace("exp", &ov).unwrap().snapshot;

    // `vl new exp@` in the default workspace, then any command.
    let old = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = alice.new_change(WS, vec![exp], "").unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&old), &to).unwrap();
    let wc = snap(&mut alice, &*fs);
    let e = file_entry(&alice, &wc, "plan.md").unwrap();
    assert!(!e.visibility.is_public(), "cloaked file silently re-stored as public");

    alice.commit_working_copy(WS, "continue").unwrap();
    alice.set_tag("main", resolve(&alice, "@-", WS).unwrap(), None, true).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    assert!(backend_contains(&*mirror, b"CLOAKED-PLAN").is_empty());
}

#[test]
fn squash_keeps_cloaked_descriptions_sealed() {
    let (mut alice, fs, _) = new_repo("alice");
    let base = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "public base");
    alice.set_tag("main", base, None, false).unwrap();
    alice.create_workspace("sec", vec![base], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("sec").unwrap();
    ov.write(&p("plan.md"), b"x\n").unwrap();
    let wc = alice.snapshot_workspace("sec", &ov).unwrap().snapshot;
    let wc = alice.describe(wc, "secret plan: acquire Initech in Q3").unwrap();
    assert!(matches!(alice.snapshot(&wc).unwrap().description, Text::Sealed(_)));
    alice.squash(wc).unwrap();

    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let hits = backend_contains(&*mirror, b"acquire Initech");
    assert!(hits.is_empty(), "cloaked description leaked to the public mirror: {hits:?}");
}

// ---- policy tricks -------------------------------------------------------------

/// A one-line `.veilpolicy` change (e.g. in a PR) cloaks `secrets/` under a
/// *released embargo* scope. The key of a released embargo is published, and
/// objects sealed under it are pushed to public remotes.
#[test]
fn policy_cannot_cloak_under_a_released_embargo_key() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("a.txt", "v1\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("a.txt", "v2\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let res = alice
        .merge(WS, main, vec![fix], "m", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    let e = res.embargo.unwrap();
    alice.release_embargo(&e).unwrap();

    let wc = alice.workspace_wc(WS).unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&alice.snapshot(&main).unwrap().tree), &to).unwrap();
    fs.write(&p(".veilpolicy"), format!("secrets/ cloak embargo/{e}\n").as_bytes()).unwrap();
    fs.write(&p("secrets/db.yml"), b"prod_db_password_is_correct-horse-battery\n").unwrap();
    snap(&mut alice, &*fs);
    alice.commit_working_copy(WS, "add db config").unwrap();

    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let anon = anon_view(mirror);
    let main = anon.view().tags["main"].target;
    let read = file_entry(&anon, &main, "secrets/db.yml").and_then(|e| anon.store().read_entry(&e).ok());
    assert!(read.is_none(), "anyone can read the 'cloaked' file: {:?}", read.map(String::from_utf8));
}

#[test]
fn policy_rejects_reserved_and_malformed_scope_names() {
    let p = Policy::parse("a cloak local\nb cloak embargo/abc\nc cloak ../../x\nd cloak UPPER\n");
    for path in ["a", "b", "c", "d"] {
        let t = p.classify(&veil_core::VPath::new(path).unwrap(), false).tier;
        assert!(
            !matches!(t, Tier::Cloaked(_)),
            "{path}: policy accepted an invalid scope name: {t:?} (warnings: {:?})",
            p.warnings
        );
    }
}

/// Mallory is on the team remote but not in scope `ops`. She creates scope
/// `opz` (members: herself and Alice), pushes the key ring, and opens a PR
/// that only changes `.veilpolicy`: `prod/ cloak ops` → `prod/ cloak opz`.
/// Alice merges the PR. Nothing warns her; `prod/` is re-encrypted to Mallory.
#[test]
fn policy_pr_cannot_rekey_cloaked_files_to_an_attacker_scope() {
    let alice_id = Identity::generate("alice");
    let (mut alice, fs) = repo_for("alice", &alice_id);
    alice.keys().create_scope("ops").unwrap();
    let main = commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", "prod/ cloak ops\n"), ("prod/db.yml", "ops-only-password\n")],
        "v1",
    );
    assert!(!file_entry(&alice, &main, "prod/db.yml").unwrap().visibility.is_public());
    alice.set_tag("main", main, None, false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();

    // Mallory clones, creates `opz` with Alice as a member, edits the policy.
    let mallory_id = Identity::generate("mallory");
    let mut mallory = clone_as(&mallory_id, team.clone());
    mallory.keys().create_scope("opz").unwrap();
    mallory.keys().grant("opz", &alice_id.public_hex(), "alice").unwrap();
    let mfs = MemoryBackend::new();
    let wc = mallory.new_change(WS, vec![main], "").unwrap();
    let to = mallory.snapshot(&wc).unwrap().tree;
    mallory.checkout_tree(&mfs, None, &to).unwrap();
    mfs.write(&p(".veilpolicy"), b"prod/ cloak opz\n").unwrap();
    let wc = snap(&mut mallory, &mfs);
    let pr = mallory.describe(wc, "tidy policy").unwrap(); // `main` stays put
    mallory.set_tag("pr", pr, None, false).unwrap();
    remote::push(&mut mallory, team.clone(), false, &[], false).unwrap();

    // Alice merges the PR and pushes.
    remote::pull(&mut alice, "origin", team.clone()).unwrap();
    let pr = alice.view().tags["pr"].target;
    alice.merge(WS, main, vec![pr], "merge PR", None).unwrap();
    remote::push(&mut alice, team.clone(), false, &["main".to_string()], false).unwrap();

    remote::pull(&mut mallory, "origin", team).unwrap();
    let main = mallory.view().tags["main"].target;
    let got = file_entry(&mallory, &main, "prod/db.yml").and_then(|e| mallory.store().read_entry(&e).ok());
    assert!(got.is_none(), "Mallory reads ops-only content: {:?}", got.map(String::from_utf8));
}

/// Same root cause, simplest form: a PR flips `secrets/ cloak team` to
/// `secrets/ public!`. Merging it decrypts every existing cloaked file into
/// public blobs; `vl merge` neither warns nor asks.
#[test]
fn merging_a_policy_change_does_not_silently_declassify_cloaked_files() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(
        &mut alice,
        &*fs,
        &[(".veilpolicy", "secrets/ cloak team\n"), ("secrets/db.yml", "db-password-xyz\n")],
        "v1",
    );
    alice.set_tag("main", main, None, false).unwrap();
    let pr_ws = alice.ephemeral_workspace(main).unwrap();
    pr_ws.write(".veilpolicy", "# tidy\nsecrets/ public!\n").unwrap();
    let (pr, _) = alice.commit_ephemeral(&pr_ws, "tidy policy").unwrap();
    alice.merge(WS, main, vec![pr], "merge PR", None).unwrap();
    let m = alice.view().tags["main"].target;
    let e = file_entry(&alice, &m, "secrets/db.yml").unwrap();
    assert!(!e.visibility.is_public(), "existing cloaked content became public by merging a policy edit");
}

/// The embargoed tree on a public mirror is supposed to look exactly like the
/// pre-merge tree. It reveals which files the fix touches, their new sizes,
/// and the names of files it adds.
#[test]
fn embargoed_tree_reveals_nothing_about_the_fix() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n"), ("lib.rs", "x\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    alice.create_workspace("fix", vec![main], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature_and_expiry_and_audience() }\n").unwrap();
    ov.write(&p("CVE-2026-31337-auth-bypass.md"), b"details\n").unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    alice
        .merge(WS, main, vec![fix], "merge", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let anon = anon_view(mirror);
    let m = anon.view().tags["main"].target;
    let listing = |r: &Repo, id| -> Vec<(String, u64)> {
        let tree = r.snapshot(&id).unwrap().tree;
        veil_core::tree::walk_files(r.store(), &tree).unwrap().into_iter().map(|(p, e)| (p.to_string(), e.size)).collect()
    };
    assert_eq!(listing(&anon, m), listing(&alice, main), "public mirror learns about the fix");
}

#[test]
fn builtin_secret_rules_are_case_insensitive() {
    let p = Policy::builtin();
    for path in [".ENV", ".Env", "certs/Server.PEM", "deploy/ID_RSA", "prod.TFSTATE", ".NETRC", ".Env.Production"] {
        assert_eq!(
            p.classify(&veil_core::VPath::new(path).unwrap(), false).tier,
            Tier::Isolated,
            "{path} is not isolated"
        );
    }
}

#[test]
fn uppercase_dotenv_never_reaches_a_public_mirror() {
    let (mut alice, fs, _) = new_repo("alice");
    let c = commit_files(&mut alice, &*fs, &[(".ENV", "DB_PASSWORD=hunter2hunter2\n")], "c");
    alice.set_tag("main", c, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(backend_contains(&*mirror, b"hunter2hunter2").is_empty());
}

// ---- key distribution ------------------------------------------------------------

/// `vl scope grant` accepts a low-order X25519 point. The ECDH shared secret
/// is then all zeros, so *anyone who can read the key ring* (rings are
/// published to every remote, public ones included) recovers the scope key.
#[test]
#[ignore = "BUG-010: grant accepts low-order X25519 public keys; the wrapped scope key is recoverable by anyone"]
fn granting_a_low_order_public_key_does_not_publish_the_scope_key() {
    let (mut alice, fs, _) = new_repo("alice");
    alice.keys().grant("team", &format!("veil1{}", "00".repeat(32)), "new-hire").unwrap_or(());
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    let c = commit_files(&mut alice, &*fs, &[("secrets/api.txt", "team-only-api-token\n")], "c");
    alice.set_tag("main", c, None, false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();

    // Outsider: no identity at all, just reads files from the team remote.
    let ring: KeyRing = serde_json::from_slice(&team.read(&p(".veil/meta/keyrings/team.json")).unwrap()).unwrap();
    let mut recovered = None;
    for m in ring.members.values() {
        let WrappedKey { ephemeral, sealed } = &m.wrapped;
        let eph = hex::decode(ephemeral).unwrap();
        let mut material = vec![0u8; 32]; // shared secret with a low-order point
        material.extend_from_slice(&eph);
        material.extend_from_slice(&[0u8; 32]); // recipient public key
        let kek = blake3::derive_key("veil 2026 key-wrap v1", &material);
        if let Ok(k) = sealed.open(&kek) {
            recovered = Some(<[u8; 32]>::try_from(k).unwrap());
        }
    }
    if let Some(key) = recovered {
        let e = file_entry(&alice, &c, "secrets/api.txt").unwrap();
        let raw = team.read(&p(&format!(".veil/objects/{}/{}", &e.id.hex()[..2], &e.id.hex()[2..]))).unwrap();
        let Object::Sealed(env) = Object::decode(&raw).unwrap() else { panic!() };
        let plain = env.open(&key).unwrap();
        panic!("outsider decrypted cloaked content: {:?}", String::from_utf8_lossy(&plain));
    }
}

/// Alice grants Bob `ops`, pushes, then revokes Bob *before he ever pulled*
/// and pushes again. Bob clones afterwards. Push unions key rings, so the
/// remote still wraps the key for Bob.
#[test]
#[ignore = "BUG-011: revocation never reaches remotes (key rings are merged as unions); a revoked member still gets the key"]
fn revoked_member_cannot_obtain_the_scope_key_from_the_remote() {
    let (mut alice, fs, _) = new_repo("alice");
    alice.keys().create_scope("ops").unwrap();
    let bob_id = Identity::generate("bob");
    alice.keys().grant("ops", &bob_id.public_hex(), "bob").unwrap();
    let c = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "c");
    alice.set_tag("main", c, None, false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();

    assert!(alice.keys().revoke("ops", &bob_id.public_hex()).unwrap());
    fs.write(&p(".veilpolicy"), b"ops/ cloak ops\n").unwrap();
    let c2 = commit_files(&mut alice, &*fs, &[("ops/plan.txt", "written after revocation\n")], "c2");
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();

    let bob = clone_as(&bob_id, team);
    let got = file_entry(&bob, &c2, "ops/plan.txt").and_then(|e| bob.store().read_entry(&e).ok());
    assert!(got.is_none(), "revoked member read post-revocation content");
}

#[test]
#[ignore = "BUG-011: revocation never reaches remotes (key rings are merged as unions); a replayed old ring re-adds the member"]
fn replayed_key_ring_does_not_undo_a_revocation() {
    let (mut alice, _fs, _) = new_repo("alice");
    alice.keys().create_scope("ops").unwrap();
    let bob_id = Identity::generate("bob");
    alice.keys().grant("ops", &bob_id.public_hex(), "bob").unwrap();
    let old_ring = alice.keys().load_ring("ops").unwrap().unwrap();
    alice.keys().revoke("ops", &bob_id.public_hex()).unwrap();
    // Bob replays the old ring on the remote he can write to.
    let team = Arc::new(MemoryBackend::new());
    Repo::init_bare(team.clone()).unwrap();
    team.write(&p(".veil/meta/keyrings/ops.json"), &serde_json::to_vec(&old_ring).unwrap()).unwrap();
    remote::pull(&mut alice, "origin", team).unwrap();
    let ring = alice.keys().load_ring("ops").unwrap().unwrap();
    assert!(!ring.members.contains_key(&bob_id.public_hex()), "revoked member silently re-added");
}

// ---- secret scanner --------------------------------------------------------------

#[test]
fn scanner_catches_common_secrets_in_public_files() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p("cfg.js"), b"const k = \"AKIAIOSFODNN7EXAMPLE\";\n").unwrap();
    fs.write(&p("k.txt"), b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n").unwrap();
    fs.write(&p("tok.txt"), b"ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\n").unwrap();
    let out = alice.snapshot_workspace(WS, &*fs).unwrap();
    assert_eq!(out.report.quarantined.len(), 3, "{:?}", out.report.quarantined);
    assert!(backend_contains(&*fs, b"AKIAIOSFODNN7EXAMPLE").iter().all(|f| !f.starts_with(".veil/objects")));
}

fn committed_publicly(data: &[u8]) -> bool {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p("conf/settings"), data).unwrap();
    let out = alice.snapshot_workspace(WS, &*fs).unwrap();
    out.report.quarantined.is_empty() && file_entry(&alice, &out.snapshot, "conf/settings").is_some()
}

#[test]
fn scanner_is_not_bypassed_by_utf16_encoding() {
    let text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\r\n";
    let mut utf16 = vec![0xff, 0xfe];
    for u in text.encode_utf16() {
        utf16.extend_from_slice(&u.to_le_bytes());
    }
    assert!(!committed_publicly(&utf16), "UTF-16 file with an AWS key was committed publicly");
}

#[test]
fn scanner_is_not_bypassed_by_a_single_nul_byte() {
    assert!(!committed_publicly(b"\0\nconst k = \"AKIAIOSFODNN7EXAMPLE\";\n"));
}

#[test]
fn scanner_is_not_bypassed_by_file_size() {
    let mut big = vec![b'x'; 8 * 1024 * 1024];
    big.extend_from_slice(b"\nconst k = \"AKIAIOSFODNN7EXAMPLE\";\n");
    assert!(!committed_publicly(&big));
}

#[test]
fn scanner_detects_unquoted_credentials() {
    for sample in [
        "database:\n  password: Xk9mQ2vL7pR4wZt8\n",
        "API_KEY=Xk9mQ2vL7pR4wZt8nB3c\n",
        "client_secret: Zt8nB3cXk9mQ2vL7pR4w\n",
    ] {
        assert!(!committed_publicly(sample.as_bytes()), "not detected: {sample:?}");
    }
}

#[test]
fn scanner_detects_aws_key_glued_to_an_identifier() {
    assert!(!committed_publicly(b"AWS_KEY_AKIAIOSFODNN7EXAMPLE\n"));
}

// ---- guards: things that must keep working -----------------------------------------

#[test]
fn isolated_content_never_enters_the_cas_or_op_log() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".env"), b"DB_URL=postgres://u:pw-ISOLATED-MARKER@db\n").unwrap();
    fs.write(&p("svc/.env.production"), b"X=ISOLATED-MARKER-2\n").unwrap();
    fs.write(&p("id_rsa"), b"ISOLATED-MARKER-3\n").unwrap();
    let out = alice.snapshot_workspace(WS, &*fs).unwrap();
    alice.capture_local_files(&*fs, &out.report).unwrap();
    alice.commit_working_copy(WS, "c").unwrap();
    for marker in [&b"ISOLATED-MARKER"[..], b"ISOLATED-MARKER-2", b"ISOLATED-MARKER-3"] {
        let hits: Vec<String> = backend_contains(&*fs, marker).into_iter().filter(|f| f.starts_with(".veil")).collect();
        assert!(hits.is_empty(), "isolated content stored in {hits:?}");
    }
    // ...but it is recoverable from the vault
    assert_eq!(alice.vault_load().unwrap().files.len(), 3);
}

#[test]
fn cloaked_content_and_cloaked_tags_never_reach_public_mirror() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    let c = commit_files(&mut alice, &*fs, &[("secrets/k.txt", "CLOAKED-MARKER\n"), ("pub.txt", "p\n")], "c");
    alice.set_tag("main", c, None, false).unwrap();
    alice.create_workspace("hidden", vec![c], Some("team".into())).unwrap();
    let ov = alice.workspace_overlay("hidden").unwrap();
    ov.write(&p("x.txt"), b"CLOAKED-WS-MARKER\n").unwrap();
    let h = alice.snapshot_workspace("hidden", &ov).unwrap().snapshot;
    let h = alice.describe(h, "CLOAKED-DESC-MARKER").unwrap();
    alice.set_tag("project-zeus", h, Some("team".into()), false).unwrap();

    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    for m in [&b"CLOAKED-MARKER"[..], b"CLOAKED-WS-MARKER", b"CLOAKED-DESC-MARKER", b"project-zeus"] {
        assert!(backend_contains(&*mirror, m).is_empty(), "{} leaked", String::from_utf8_lossy(m));
    }
    // the team remote gets ciphertext only
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();
    for m in [&b"CLOAKED-MARKER"[..], b"CLOAKED-WS-MARKER", b"CLOAKED-DESC-MARKER"] {
        assert!(backend_contains(&*team, m).is_empty());
    }
    // and a non-member cloning it cannot read
    let bob = clone_as(&Identity::generate("bob"), team);
    let e = file_entry(&bob, &c, "secrets/k.txt").unwrap();
    assert!(matches!(e.visibility, Visibility::Cloaked { .. }));
    assert!(bob.store().read_entry(&e).unwrap_err().is_unreadable());
}

#[test]
fn non_member_snapshot_never_deletes_hidden_content() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    let c = commit_files(&mut alice, &*fs, &[("secrets/k.txt", "s\n"), ("pub.txt", "p\n")], "c");
    alice.set_tag("main", c, None, false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();
    let mut bob = clone_as(&Identity::generate("bob"), team);
    let bfs = MemoryBackend::new();
    let wc = bob.new_change(WS, vec![c], "").unwrap();
    let to = bob.snapshot(&wc).unwrap().tree;
    let rep = bob.checkout_tree(&bfs, None, &to).unwrap();
    assert_eq!(rep.redacted.len(), 1);
    bfs.write(&p("pub.txt"), b"bob edit\n").unwrap();
    let s = snap(&mut bob, &bfs);
    assert!(file_entry(&bob, &s, "secrets/k.txt").is_some(), "redacted entry was deleted");
}

#[test]
fn envelope_scope_is_bound_to_ciphertext() {
    let (alice, _fs, _) = new_repo("alice");
    alice.keys().create_scope("ops").unwrap();
    let key = alice.keys().key("team").unwrap();
    let env = Envelope::seal(&key, "team", b"payload", true).unwrap();
    let mut moved = env.clone();
    moved.scope = "ops".into();
    assert!(moved.open(&alice.keys().key("ops").unwrap()).is_err());
    assert!(moved.open(&key).is_err(), "AAD binds the scope");
}
