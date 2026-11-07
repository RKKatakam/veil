//! Round-6 adversarial tests (Fable): confidentiality of the engine's
//! visibility rules under hostile input.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 6 findings (Fable)").

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    builder::InjectedSecrets,
    object::Visibility,
    remote, Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

fn anon_view(backend: Arc<MemoryBackend>) -> Repo {
    Repo::open(backend, Some(Identity::generate("anon")), "anon").unwrap()
}

/// 300 bytes that are not valid UTF-8 anywhere: what a PKCS#12 bundle, a
/// Java keystore or a DER key looks like.
fn binary_secret() -> Vec<u8> {
    (0..300u32).map(|i| (i.wrapping_mul(97) ^ 0xa5) as u8 | 0x80).collect()
}

// ---- injected secrets (ws exec --with-isolated) ------------------------------

/// Control: a text `.env` injected into a sandbox is recognised when a
/// command copies it under another name.
#[test]
fn an_injected_text_secret_is_recognised_in_a_copy() {
    let env = b"API_TOKEN=Xk9mQ2vL7pR4wZt8\n";
    let inj = InjectedSecrets::from_files([(".env", &env[..])]);
    assert!(inj.find(env).is_some());
    assert!(inj.find(b"token: Xk9mQ2vL7pR4wZt8\n").is_some());
}

/// `*.p12`, `*.pfx`, `*.jks` and `*.keystore` are built-in secrets, and
/// they are binary. `InjectedSecrets::from_files` (`builder.rs`) derives
/// its needles from `String::from_utf8_lossy` of each injected file and
/// drops every candidate that contains U+FFFD (`secret_like`), so a binary
/// isolated file yields **no needle at all**: `cp server.p12 bundle.bin`
/// in a `vl ws exec --with-isolated` sandbox records the keystore in
/// history, where the scanner (no PEM header, no assignment) finds nothing
/// either, and the next push ships it to every remote.
#[test]
fn an_injected_binary_secret_is_recognised_in_a_copy() {
    let p12 = binary_secret();
    let inj = InjectedSecrets::from_files([("server.p12", &p12[..])]);
    assert!(
        !inj.is_empty() && inj.find(&p12).is_some(),
        "no needle is derived from a binary isolated file"
    );
}

/// The same, end to end: the copy is quarantined, never recorded.
#[test]
fn a_copy_of_an_injected_keystore_is_quarantined() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("app.py", "x\n")], "init");
    let p12 = binary_secret();
    let inj = InjectedSecrets::from_files([("server.p12", &p12[..])]);
    let ws = repo.ephemeral_workspace(base).unwrap();
    ws.write("server.p12", &p12).unwrap(); // what --with-isolated injects
    ws.write("dist/bundle.bin", &p12).unwrap(); // what the command did with it
    let (snap, report) = repo.commit_fs_as_child_injected(base, &*ws.fs().clone(), "bundle", Some(&inj)).unwrap();
    assert!(
        report.quarantined.iter().any(|(p, _)| p.as_str() == "dist/bundle.bin"),
        "the copy was not quarantined: {report:?}"
    );
    assert!(file_entry(&repo, &snap, "dist/bundle.bin").is_none(), "the keystore copy was recorded");
}

// ---- tree entries from a hostile remote ---------------------------------------

/// Alice's project: `secrets/.env.db` cloaked under `team`, pushed to the
/// team remote `hub`. Returns (alice, her fs, hub, her `main`).
fn alice_with_hub() -> (Repo, Arc<MemoryBackend>, Arc<MemoryBackend>, ObjectId) {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    let main = commit_files(&mut alice, &*fs, &[("secrets/.env.db", "password: old-team-secret\n"), ("README", "hi\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    (alice, fs, hub, main)
}

/// Mallory can write to the team remote but is not in `team`. She clones
/// the hub and pushes `main` forward by one snapshot whose tree is Alice's,
/// except that the entry for `secrets/.env.db` claims to be sealed for
/// `audience` (the sealed object itself is untouched: Mallory cannot read
/// it, and does not need to). `prepare` runs in her repository first (to
/// create a scope or an embargo record that travels with the push).
fn mallory_relabels(hub: Arc<MemoryBackend>, alice_main: ObjectId, prepare: impl FnOnce(&Repo) -> String) -> ObjectId {
    let mallory = Identity::generate("mallory");
    let mut m = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(mallory.clone()), "mallory").unwrap();
    remote::pull(&mut m, "origin", hub.clone()).unwrap();
    let audience = prepare(&m);
    let store = m.store().clone();
    let root_tree = store.snapshot(&alice_main).unwrap().tree;
    let mut root = (*store.tree(&root_tree).unwrap()).clone();
    let secrets_id = root.get("secrets").unwrap().id;
    let mut secrets = (*store.tree(&secrets_id).unwrap()).clone();
    let mut e = secrets.get(".env.db").unwrap().clone();
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() });
    e.visibility = Visibility::Cloaked { scope: audience };
    secrets.insert(e);
    root.insert(veil_core::TreeEntry::dir("secrets", store.put_tree(&secrets).unwrap()));
    let tree = store.put_tree(&root).unwrap();
    let evil = raw_snapshot(&m, vec![alice_main], tree, "chore: tidy up");
    m.set_tag("main", evil, true).unwrap();
    remote::push(&mut m, hub, false, &["main".into()], false).unwrap();
    evil
}

/// Alice pulls, moves her working copy onto the new `main` (`vl new main`,
/// or `vl rebase -d main` as the guide says after a pull), edits the
/// secret, commits, tags and pushes `main` to the public mirror. Returns
/// the mirror.
fn alice_edits_and_publishes(alice: &mut Repo, fs: &Arc<MemoryBackend>, hub: Arc<MemoryBackend>) -> Arc<MemoryBackend> {
    remote::pull(alice, "origin", hub).unwrap();
    let main = alice.view().tags["main"].target;
    let old = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = alice.new_change(WS, vec![main], "").unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    alice.checkout_tree(&**fs, Some(&old), &to).unwrap();
    // Nothing looks wrong to Alice: her file still holds her secret.
    assert_eq!(fs.read(&p("secrets/.env.db")).unwrap(), b"password: old-team-secret\n");
    fs.write(&p("secrets/.env.db"), b"password: NEW-rotated-team-secret\n").unwrap();
    snap(alice, &**fs);
    let c = alice.commit_working_copy(WS, "rotate the db password").unwrap().0;
    alice.set_tag("main", c, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(alice, mirror.clone(), true, &["main".into()], false).unwrap();
    mirror
}

/// The builder's "sealed content keeps its audience" rule (`builder.rs`,
/// `file_entry`) trusted the *parent entry's* visibility label, and (in
/// formats 7 and earlier) a released embargo's key was handed to everyone.
/// Mallory creates an embargo under a scope
/// of her own, releases it, and relabels the entry of Alice's cloaked
/// `secrets/.env.db` as `cloaked:embargo/<id>`. The sealed object is still
/// Alice's (opened through its own `team` label), so her working copy shows
/// the right content and nothing warns. Her next edit of the file is sealed
/// under the embargo key, which is public, and the public mirror accepts
/// such objects as "released": anyone reads her new secret.
#[test]
fn a_relabelled_entry_cannot_seal_the_victims_edit_under_a_public_key() {
    let (mut alice, fs, hub, main) = alice_with_hub();
    mallory_relabels(hub.clone(), main, |m| {
        m.keys().create_scope("mal").unwrap();
        let id = m.keys().create_embargo("mal", None).unwrap();
        m.keys().release_embargo(&id).unwrap();
        format!("embargo/{id}")
    });
    let mirror = alice_edits_and_publishes(&mut alice, &fs, hub);
    let anon = anon_view(mirror.clone());
    let m = anon.view().tags["main"].target;
    let e = file_entry(&anon, &m, "secrets/.env.db").expect("entry");
    let leaked = anon.store().read_entry(&e).ok();
    assert!(
        leaked.as_deref() != Some(&b"password: NEW-rotated-team-secret\n"[..]),
        "an anonymous reader of the public mirror decrypts Alice's new secret ({:?})",
        leaked.map(|d| String::from_utf8_lossy(&d).into_owned())
    );
    assert!(backend_contains(&*mirror, b"NEW-rotated").is_empty());
}

/// The same with a scope Mallory controls: she grants Alice into `mal`
/// (anyone can create a scope and grant anyone), relabels the entry as
/// `cloaked:mal`, and reads Alice's next edit from the team remote. The
/// merge path refuses exactly this (`normalize_tree`, BUG-009); `vl new`
/// and `vl rebase` after a pull do not.
#[test]
fn a_relabelled_entry_cannot_rekey_the_victims_edit_to_an_attacker_scope() {
    let (mut alice, fs, hub, main) = alice_with_hub();
    let alice_pub = alice.identity().unwrap().public_id();
    let mallory_id = Identity::generate("mallory");
    let mallory_for_reading = mallory_id.clone();
    let _ = mallory_relabels(hub.clone(), main, move |m| {
        m.keys().create_scope("mal").unwrap();
        m.keys().grant("mal", &alice_pub, "alice").unwrap();
        "mal".to_string()
    });
    let _ = mallory_for_reading;
    // Alice pulls, works on the new main, edits and pushes to the team hub.
    remote::pull(&mut alice, "origin", hub.clone()).unwrap();
    let new_main = alice.view().tags["main"].target;
    let old = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = alice.new_change(WS, vec![new_main], "").unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&old), &to).unwrap();
    fs.write(&p("secrets/.env.db"), b"password: NEW-rotated-team-secret\n").unwrap();
    snap(&mut alice, &*fs);
    let c = alice.commit_working_copy(WS, "rotate").unwrap().0;
    let e = file_entry(&alice, &c, "secrets/.env.db").unwrap();
    assert_eq!(
        e.visibility,
        Visibility::Cloaked { scope: "team".into() },
        "Alice's edit of a team file was sealed for {}",
        e.visibility.label()
    );
}

// ---- names and ids from a hostile team remote -------------------------------------

/// The Git-side fix of BUG-059 ("a forged change-id header must not make
/// the user's change divergent") has no counterpart for Veil remotes:
/// `remote::pull` records every remote tag, and a snapshot that carries
/// Alice's change id (change ids are visible to every reader of the team
/// remote) becomes visible through `origin/<tag>`. From then on Alice's own
/// change id is "divergent" in every revset (`vl edit`, `vl new`,
/// `vl squash -r`, `vl describe -r`), until she abandons Mallory's snapshot.
#[test]
fn a_pulled_snapshot_with_a_forged_change_id_does_not_make_the_change_divergent() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("a.txt", "a\n")], "my work");
    alice.set_tag("main", main, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let cid = alice.snapshot(&main).unwrap().change_id;

    let mut m = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(Identity::generate("mallory")), "mallory").unwrap();
    remote::pull(&mut m, "origin", hub.clone()).unwrap();
    let tree = m.snapshot(&main).unwrap().tree;
    let evil = m
        .store()
        .put_snapshot(&veil_core::Snapshot {
            parents: vec![main],
            change_id: cid,
            tree,
            description: veil_core::object::Text::Plain("evil".into()),
            author: "mallory".into(),
            timestamp: 2,
            predecessors: vec![],
            conflicts: vec![],
            signature: None,
            embargo: None,
        })
        .unwrap();
    set_remote_tag(&mut m, "evil", evil);
    remote::push(&mut m, hub.clone(), false, &["evil".into()], false).unwrap();

    remote::pull(&mut alice, "origin", hub).unwrap();
    let short = cid.display()[..8].to_string();
    let resolved = veil_core::revset::resolve(&alice, &short, WS);
    assert_eq!(
        resolved.ok(),
        Some(main),
        "Alice's change id {short} no longer resolves to her change: {:?}",
        veil_core::revset::resolve(&alice, &short, WS).err()
    );
}
