//! Regression tests for the round-4 key-management fixes: identity bindings
//! (BUG-069), low-order ring members (BUG-070), the HPKE ring step in
//! clones already at format 3 (BUG-071), key rings on public remotes
//! (BUG-077) and handing admin rights over after `vl identity new --force`
//! (BUG-089). The reproductions themselves are in `adversarial4_crypto.rs`.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    fsck::{fsck, Severity},
    keychain::{
        current_key_has_legacy_wraps, AdminRecovery, KeyRing, Keychain, MemberGrant, RingChange, RingOp, Role,
        RING_FORMAT_HPKE,
    },
    remote,
    upgrade::{upgrade, UpgradeOptions},
    Identity, MemoryBackend, Repo, StorageBackend,
};

/// A repository at `format` for `id`, with a `team` scope `id` administers.
fn repo_at(format: u32, id: &Identity) -> (Repo, Arc<MemoryBackend>) {
    let fs = Arc::new(MemoryBackend::new());
    let repo = Repo::init_for_clone_at(fs.clone(), Some(id.clone()), &id.name, format).unwrap();
    repo.keys().create_scope("team").unwrap();
    (repo, fs)
}

fn ring(keys: &Keychain, scope: &str) -> KeyRing {
    keys.load_ring(scope).unwrap().unwrap()
}

/// `ring` plus a change signed by `signer` with `op`, exactly as the
/// keychain would sign it (not verified, not saved).
fn with_change(mut r: KeyRing, signer: &Identity, op: RingOp) -> KeyRing {
    let scope = r.scope.clone();
    let mut c = RingChange {
        seq: r.log.len() as u64,
        prev: r.log.last().map(|c| c.hash(&scope)).unwrap_or_default(),
        timestamp: 1,
        signer: signer.public_hex(),
        signing_key: signer.verifying_hex(),
        op,
        signature: String::new(),
    };
    c.signature = signer.sign("ring-change", &c.signing_body(&scope));
    r.log.push(c);
    r
}

/// A grant of `id` whose wrap is copied from the genesis (replay does not
/// open wraps).
fn grant_of(r: &KeyRing, id: &str, name: &str, signing_key: Option<String>, binding: Option<String>) -> RingOp {
    let st = r.verify().unwrap();
    let wrapped = match &r.log[0].op {
        RingOp::Genesis { members, .. } => members[0].wrapped.clone(),
        _ => unreachable!(),
    };
    RingOp::Grant {
        member: MemberGrant {
            id: id.to_string(),
            name: name.into(),
            signing_key,
            binding,
            role: Role::Member,
            generation: st.generation,
            wrapped,
        },
    }
}

fn legacy_identity(name: &str) -> Identity {
    let secret = hex::encode(veil_core::crypto::random_key());
    let pk = Identity::from_json(&format!(r#"{{"name":"{name}","public":"x","secret":"{secret}"}}"#)).unwrap();
    assert!(pk.signing_key_is_derived());
    pk
}

// ---- BUG-069: identity bindings --------------------------------------------

/// Format 3 records the binding in the grant, and replay checks it, for new
/// and legacy (derived signing key) identities alike. A legacy member can be
/// an admin and sign ring changes, and their snapshots are attributed.
#[test]
fn grants_record_a_verified_binding_for_new_and_legacy_identities() {
    let alice = Identity::generate("alice");
    let (repo, fs) = repo_at(3, &alice);
    let dave = legacy_identity("dave");
    let bob = Identity::generate("bob");
    repo.keys().grant_role("team", &dave.public_id(), "dave", Role::Admin).unwrap();
    repo.keys().grant("team", &bob.public_id(), "bob").unwrap();
    let r = ring(repo.keys(), "team");
    assert_eq!(r.format, RING_FORMAT_HPKE);
    let st = r.verify().unwrap();
    for id in [&alice, &dave, &bob] {
        let m = &st.members[&id.public_hex()];
        assert_eq!(m.binding.as_deref(), Some(id.binding_hex().as_str()), "{}", id.name);
        assert!(st.bound_signers.contains(&id.verifying_hex()));
    }
    // The legacy admin rotates the key and commits; both are attributed.
    let daves = Repo::open(fs.clone(), Some(dave.clone()), "dave").unwrap();
    daves.keys().rotate("team").unwrap();
    let mut daves = daves;
    let c = commit_files(&mut daves, &*fs, &[("d.txt", "dave\n")], "dave's change");
    let s = daves.snapshot(&c).unwrap();
    let reader = Repo::open(fs.clone(), None, "reader").unwrap();
    assert_eq!(reader.keys().snapshot_status(&s).label(), "signed by dave");

    // Replay refuses a binding that does not verify, and a binding without a key.
    let r = ring(repo.keys(), "team");
    let mallory = Identity::generate("mallory");
    let forged = with_change(
        r.clone(),
        &alice,
        grant_of(&r, &mallory.public_hex(), "m", Some(mallory.verifying_hex()), Some(alice.binding_hex())),
    );
    assert!(forged.verify().unwrap_err().contains("does not verify"), "{:?}", forged.verify());
    let keyless = with_change(r.clone(), &alice, grant_of(&r, &mallory.public_hex(), "m", None, Some(mallory.binding_hex())));
    assert!(keyless.verify().unwrap_err().contains("binding without a signing key"));
    // A ring labelled format 2 cannot carry bindings.
    let mut relabelled = ring(repo.keys(), "team");
    relabelled.format = 2;
    assert!(relabelled.verify().is_err());
}

/// Formats 1–2 check the binding at grant time but cannot record it (older
/// readers would drop it and fail the signature): the ring stays format 2.
#[test]
fn format_2_grants_check_the_binding_without_recording_it() {
    let alice = Identity::generate("alice");
    let (repo, _fs) = repo_at(2, &alice);
    let bob = Identity::generate("bob");
    let unbound = format!("{}{}", bob.public_hex(), bob.verifying_hex());
    let err = repo.keys().grant("team", &unbound, "bob").unwrap_err();
    assert!(err.to_string().contains("no proof"), "{err}");
    repo.keys().grant("team", &bob.public_id(), "bob").unwrap();
    let r = ring(repo.keys(), "team");
    assert_eq!(r.format, 2);
    let st = r.verify().unwrap();
    assert_eq!(st.members[&bob.public_hex()].signing_key.as_deref(), Some(bob.verifying_hex().as_str()));
    assert!(st.members.values().all(|m| m.binding.is_none()));
    // The short member id still grants read access without a signing key.
    let carol = Identity::generate("carol");
    repo.keys().grant("team", &carol.public_hex(), "carol").unwrap();
    // A signing key that already belongs to Bob cannot be given to Carol.
    let mallory = Identity::generate("mallory");
    let err = repo
        .keys()
        .grant("team", &format!("{}{}", mallory.public_hex(), bob.verifying_hex()), "m")
        .unwrap_err();
    assert!(err.to_string().contains("no proof"), "{err}");
}

/// Across rings, a key claimed for two members is attributed to the one
/// whose binding was proved; an unproved conflict attributes it to nobody.
/// And a snapshot whose `signer` is relabelled is never someone else's.
#[test]
fn a_key_claimed_by_another_ring_stays_its_owners() {
    let alice = Identity::generate("alice");
    let (mut repo, fs) = repo_at(3, &alice);
    let c = commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "alice's change");
    let s = repo.snapshot(&c).unwrap();
    // Mallory administers another scope here, and (hostile admin, or an
    // earlier vl) grants herself Alice's signing key there, unbound.
    let mallory = Identity::generate("mallory");
    let mk = Keychain::new(fs.clone(), Some(mallory.clone()), repo.repo_id().to_string());
    mk.create_scope("ops").unwrap();
    let ops = ring(&mk, "ops");
    let decoy = Identity::generate("decoy");
    let ops = with_change(ops.clone(), &mallory, grant_of(&ops, &decoy.public_hex(), "alice", Some(alice.verifying_hex()), None));
    ops.verify().expect("valid in its own ring: Alice is not a member of ops");
    mk.save_ring(&ops).unwrap();

    let reader = Repo::open(fs.clone(), None, "reader").unwrap();
    assert_eq!(reader.keys().known_signers()[&alice.verifying_hex()].0, alice.public_hex());
    assert!(reader.keys().snapshot_status(&s).is_good());
    // Relabelling the signature's claimed signer does not move it.
    let mut relabelled = (*s).clone();
    relabelled.signature.as_mut().unwrap().signer = decoy.public_hex();
    assert!(!reader.keys().snapshot_status(&relabelled).is_good());

    // Inside one ring a key cannot be claimed twice.
    let bob = Identity::generate("bob");
    let ops = ring(&mk, "ops");
    let twice = with_change(ops.clone(), &mallory, grant_of(&ops, &bob.public_hex(), "bob", Some(alice.verifying_hex()), None));
    assert!(twice.verify().unwrap_err().contains("already belongs"));

    // Two rings with unbound claims on Carol's key for two other members:
    // the key is attributed to nobody.
    let carol = Identity::generate("carol");
    let eve = Identity::generate("eve");
    let ek = Keychain::new(fs.clone(), Some(eve.clone()), repo.repo_id().to_string());
    ek.create_scope("dev").unwrap();
    for (k, admin, scope, who) in [(&mk, &mallory, "ops", &bob), (&ek, &eve, "dev", &decoy)] {
        let r = ring(k, scope);
        let r = with_change(r.clone(), admin, grant_of(&r, &who.public_hex(), "carol", Some(carol.verifying_hex()), None));
        k.save_ring(&r).unwrap();
    }
    let reader = Repo::open(fs.clone(), None, "reader").unwrap();
    assert!(!reader.keys().known_signers().contains_key(&carol.verifying_hex()), "conflict: left out");
    assert_eq!(reader.keys().known_signers()[&alice.verifying_hex()].0, alice.public_hex());
}

// ---- BUG-070: low-order members --------------------------------------------

/// A low-order member gets no key from a rotation, is reported, and can be
/// revoked; fsck then only notes it. A rotation that leaves out an ordinary
/// member is still refused.
#[test]
fn rotations_skip_a_low_order_member_and_it_can_be_revoked() {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let (repo, fs) = repo_at(3, &alice);
    repo.keys().grant("team", &bob.public_id(), "bob").unwrap();
    let low = format!("veil1{}", "00".repeat(32));
    let r = ring(repo.keys(), "team");
    let r = with_change(r.clone(), &alice, grant_of(&r, &low, "typo", None, None));
    repo.keys().save_ring(&r).unwrap();
    assert_eq!(repo.keys().unreachable_members("team"), vec![(low.clone(), "typo".to_string())]);

    let g = repo.keys().rotate("team").unwrap();
    let r = ring(repo.keys(), "team");
    let RingOp::Rotate { rotation } = &r.log.last().unwrap().op else { panic!() };
    assert_eq!(rotation.generation, g);
    assert!(!rotation.wrapped.contains_key(&low) && rotation.wrapped.contains_key(&bob.public_hex()));
    let warned = fsck(fs.clone(), Some(alice.clone())).unwrap();
    assert!(warned.findings.iter().any(|f| f.severity == Severity::Warning && f.message.contains(&low)));

    // Leaving out Bob (an ordinary member) is refused by replay.
    let mut cut = r.clone();
    let c = cut.log.last_mut().unwrap();
    if let RingOp::Rotate { rotation } = &mut c.op {
        rotation.wrapped.remove(&bob.public_hex());
    }
    c.signature = alice.sign("ring-change", &c.signing_body("team"));
    assert!(cut.verify().unwrap_err().contains("exactly the remaining members"));

    assert!(repo.keys().revoke("team", &low).unwrap());
    assert!(repo.keys().unreachable_members("team").is_empty());
    let after = fsck(fs.clone(), Some(alice.clone())).unwrap();
    assert!(
        !after.findings.iter().any(|f| matches!(f.severity, Severity::Corrupt | Severity::Warning)),
        "{:?}",
        after.findings
    );
    assert!(after.findings.iter().any(|f| f.message.contains("former member")));
}

// ---- BUG-071: the ring step in a clone already at format 3 ------------------

/// At format 3 with a legacy-wrapped ring: a dry run names the step and
/// writes nothing; a non-admin is told who can finish it; the admin's run
/// rotates, and a second run is up to date.
#[test]
fn the_ring_step_runs_whenever_it_is_pending() {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let (repo, fs) = repo_at(2, &alice);
    repo.keys().grant("team", &bob.public_id(), "bob").unwrap();
    drop(repo);
    // Bob (not an admin) upgrades the clone: the ring stays legacy-wrapped.
    let r = upgrade(fs.clone(), Some(bob.clone()), &UpgradeOptions::default()).unwrap();
    assert!(r.notes.iter().any(|n| n.contains("an admin should run `vl upgrade`")), "{:#?}", r.notes);
    let r = upgrade(fs.clone(), Some(bob.clone()), &UpgradeOptions::default()).unwrap();
    assert!(r.up_to_date);
    assert!(r.notes.iter().any(|n| n.contains("still wrapped with the legacy construction")), "{:#?}", r.notes);

    let before = ring(&Keychain::new(fs.clone(), None, String::new()), "team");
    let dry = upgrade(fs.clone(), Some(alice.clone()), &UpgradeOptions { dry_run: true, ..Default::default() }).unwrap();
    assert!(!dry.up_to_date && dry.steps == ["3:hpke-ring-keys"], "{dry:?}");
    assert_eq!(ring(&Keychain::new(fs.clone(), None, String::new()), "team"), before, "a dry run writes nothing");

    let done = upgrade(fs.clone(), Some(alice.clone()), &UpgradeOptions::default()).unwrap();
    assert_eq!((done.from, done.to, done.up_to_date), (veil_core::repo::REPO_FORMAT, veil_core::repo::REPO_FORMAT, false));
    let r = ring(&Keychain::new(fs.clone(), None, String::new()), "team");
    assert!(!current_key_has_legacy_wraps(&r, &r.verify().unwrap()));
    let again = upgrade(fs.clone(), Some(alice), &UpgradeOptions::default()).unwrap();
    assert!(again.up_to_date && again.notes.is_empty(), "{again:?}");
    let bobs = Repo::open(fs, Some(bob), "bob").unwrap();
    assert!(bobs.keys().is_member("team"), "Bob received the HPKE-wrapped key");
}

// ---- BUG-077: no key rings on public remotes --------------------------------

/// A public remote receives no key ring, so a public clone learns no member
/// names or ids; it still accepts embargo records and reads a released
/// embargo. A team remote still gets the rings.
#[test]
fn public_remotes_receive_no_key_rings_and_still_read_released_embargoes() {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let (mut repo, fs) = repo_at(3, &alice);
    repo.keys().grant("team", &bob.public_id(), "bob-the-member").unwrap();
    let main = commit_files(&mut repo, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    repo.set_tag("main", main, None, false).unwrap();
    let fix_ws = repo.ephemeral_workspace(main).unwrap();
    fix_ws.write("auth.rs", "fn check() -> bool { verify() }\n").unwrap();
    let (fix, _) = repo.commit_ephemeral(&fix_ws, "fix").unwrap();
    let spec = EmbargoSpec { scope: "team".into(), until: None };
    let res = repo.merge(WS, main, vec![fix], "embargoed fix", Some(spec)).unwrap();
    let embargo = res.embargo.clone().unwrap();

    let public = Arc::new(MemoryBackend::new());
    let team = Arc::new(MemoryBackend::new());
    let rep = remote::push(&mut repo, public.clone(), true, &[], false).unwrap();
    assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);
    remote::push(&mut repo, team.clone(), false, &[], false).unwrap();
    let leaks = |b: &MemoryBackend| {
        !backend_contains(b, b"bob-the-member").is_empty() || !backend_contains(b, &bob.public_hex().as_bytes()[5..]).is_empty()
    };
    assert!(leaks(&fs), "control: the member is named locally");
    assert!(!leaks(&public), "a public remote names a member");
    assert!(Repo::open(public.clone(), None, "r").unwrap().keys().rings().unwrap().is_empty());
    assert_eq!(Repo::open(team.clone(), None, "r").unwrap().keys().rings().unwrap().len(), 1);

    repo.release_embargo(&embargo).unwrap();
    remote::push(&mut repo, public.clone(), true, &[], false).unwrap();
    let cfs = Arc::new(MemoryBackend::new());
    let mut clone = Repo::init_for_clone_at(cfs.clone(), Some(Identity::generate("reader")), "reader", 3).unwrap();
    let rep = remote::pull(&mut clone, "origin", public.clone()).unwrap();
    assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);
    assert!(clone.keys().rings().unwrap().is_empty() && !leaks(&cfs));
    assert!(clone.keys().embargo_released(&embargo));
    assert_eq!(read_at(&clone, &res.snapshot, "auth.rs"), b"fn check() -> bool { verify() }\n");
}

/// A public clone accepts records it cannot judge; a record that a ring later
/// shows to be signed by a member replaces a forged local one, and the
/// released key it publishes is used.
#[test]
fn a_member_signed_record_replaces_an_unverified_local_one() {
    let alice = Identity::generate("alice");
    let (repo, fs) = repo_at(3, &alice);
    let id = repo.keys().create_embargo("team", None).unwrap();
    let real = repo.keys().load_embargo(&id).unwrap().unwrap();
    // A hostile public remote strips the signature and moves the deadline.
    let mut forged = real.clone();
    forged.until = Some(1);
    forged.signature = None;
    // A clone that holds no ring for the scope accepts the forgery unverified.
    let cfs = Arc::new(MemoryBackend::new());
    let ck = Keychain::new(cfs.clone(), None, "c".into());
    assert_eq!(ck.merge_embargo(&forged).unwrap(), None);
    assert!(!ck.embargo_trusted(&ck.load_embargo(&id).unwrap().unwrap()));
    // Then it learns the ring (a team remote) and the real, released record.
    ck.merge_ring(&ring(repo.keys(), "team")).unwrap();
    repo.keys().release_embargo(&id).unwrap();
    let released = repo.keys().load_embargo(&id).unwrap().unwrap();
    let w = ck.merge_embargo(&released).unwrap();
    assert!(w.is_some_and(|w| w.contains("replaced an unverified local record")));
    assert_eq!(ck.load_embargo(&id).unwrap().unwrap(), released);
    assert!(ck.embargo_released(&id));
    // With the ring here, a record signed by a non-member is rejected again.
    let (outsider, _ofs) = repo_at(3, &Identity::generate("outsider"));
    let oid = outsider.keys().create_embargo("team", None).unwrap();
    let theirs = outsider.keys().load_embargo(&oid).unwrap().unwrap();
    assert!(ck.merge_embargo(&theirs).unwrap().is_some_and(|w| w.contains("rejected")));
    drop(fs);
}

/// Rings an earlier vl pushed to a public remote are reported, not removed
/// (removing them would lock members out of a team remote added as public
/// by mistake).
#[test]
fn rings_already_on_a_public_remote_are_reported() {
    let alice = Identity::generate("alice");
    let (mut repo, fs) = repo_at(3, &alice);
    let c = commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "c");
    repo.set_tag("main", c, None, false).unwrap();
    let remote_fs = Arc::new(MemoryBackend::new());
    remote::push(&mut repo, remote_fs.clone(), false, &[], false).unwrap();
    let rep = remote::push(&mut repo, remote_fs.clone(), true, &[], false).unwrap();
    assert!(rep.warnings.iter().any(|w| w.contains("holds 1 key ring")), "{:?}", rep.warnings);
    assert!(remote_fs.exists(&p(".veil/meta/keyrings/team.json")).unwrap());
}

// ---- BUG-089: handing admin rights over -------------------------------------

/// After replacing the sole admin's identity, the retired identity signs a
/// grant that makes the new one an admin; with `revoke_retired` the old one
/// is then revoked. Scopes where the retired identity was only a member are
/// reported.
#[test]
fn a_retired_identity_hands_its_admin_rights_over() {
    let old = Identity::generate("alice");
    let new = Identity::generate("alice");
    let (repo, fs) = repo_at(3, &old);
    let bob = Identity::generate("bob");
    // Bob administers "ops", where Alice's old identity is a member.
    let bk = Keychain::new(fs.clone(), Some(bob.clone()), repo.repo_id().to_string());
    bk.create_scope("ops").unwrap();
    bk.grant("ops", &old.public_id(), "alice").unwrap();
    drop(repo);

    let repo = Repo::open(fs.clone(), Some(new.clone()), "alice").unwrap();
    assert!(repo.keys().grant("team", &bob.public_id(), "bob").is_err(), "frozen without the hand-over");
    let out = repo.keys().recover_admin(&old, false).unwrap();
    assert_eq!(
        out,
        // `team` first: `Keychain::rings` lists it first (BUG-845).
        vec![
            ("team".to_string(), AdminRecovery::HandedOver { revoked: false }),
            ("ops".to_string(), AdminRecovery::RetiredNotAdmin)
        ]
    );
    let st = ring(repo.keys(), "team").verify().unwrap();
    assert!(st.is_admin(&new.public_hex(), &new.verifying_hex()));
    assert!(st.is_admin(&old.public_hex(), &old.verifying_hex()));
    repo.keys().grant("team", &bob.public_id(), "bob").unwrap();
    assert!(repo.keys().is_member("team"));

    // Idempotent; and --revoke-old removes the retired identity.
    let out = repo.keys().recover_admin(&old, true).unwrap();
    assert!(out.contains(&("team".to_string(), AdminRecovery::HandedOver { revoked: true })), "{out:?}");
    let st = ring(repo.keys(), "team").verify().unwrap();
    assert!(!st.members.contains_key(&old.public_hex()));
    assert!(repo.keys().is_member("team"));
    let out = repo.keys().recover_admin(&old, true).unwrap();
    assert!(out.contains(&("team".to_string(), AdminRecovery::AlreadyAdmin)), "{out:?}");
    assert!(repo.keys().recover_admin(&new, false).is_err(), "not a replaced identity");
}
