//! Round 4 adversarial tests: the format-3 cryptography (AES-SIV objects,
//! HPKE key wrapping, independent signing keys) and `vl upgrade`'s
//! `3:hpke-ring-keys` step.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test demonstrates a bug listed in
//! `docs/BUGS.md` ("Round 4 findings"). The tests that are not ignored are
//! controls: they pin behaviour the attacks rely on, or attacks that failed.

mod adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    crypto::{random_key, Envelope},
    identity::{parse_public_identity, wrap_key, wrap_key_legacy, HpkeWrappedKey, WrappedKey, HPKE_SUITE},
    keychain::{current_key_has_legacy_wraps, KeyRing, MemberGrant, RingChange, RingOp, Role},
    object::Object,
    remote,
    upgrade::{upgrade, UpgradeOptions, JOURNAL_PATH},
    Identity, MemoryBackend, Repo, StorageBackend,
};

/// A repository at `format` for `id`, with a `team` scope `id` administers.
fn repo_at(format: u32, id: &Identity) -> (Repo, Arc<MemoryBackend>) {
    let fs = Arc::new(MemoryBackend::new());
    let repo = Repo::init_for_clone_at(fs.clone(), Some(id.clone()), &id.name, format).unwrap();
    repo.keys().create_scope("team").unwrap();
    (repo, fs)
}

fn ring(repo: &Repo, scope: &str) -> KeyRing {
    repo.keys().load_ring(scope).unwrap().unwrap()
}

/// Append a change to `scope`'s ring signed by `signer` (an admin), exactly
/// as `Keychain` would, but with an op of our choosing. Returns the ring.
fn append_signed(repo: &Repo, scope: &str, signer: &Identity, op: RingOp) -> KeyRing {
    let mut r = ring(repo, scope);
    let mut c = RingChange {
        seq: r.log.len() as u64,
        prev: r.log.last().map(|c| c.hash(scope)).unwrap_or_default(),
        timestamp: 1,
        signer: signer.public_hex(),
        signing_key: signer.verifying_hex(),
        op,
        signature: String::new(),
    };
    c.signature = signer.sign("ring-change", &c.signing_body(scope));
    r.log.push(c);
    r.verify().expect("the crafted ring verifies");
    repo.keys().save_ring(&r).unwrap();
    r
}

// ---- forged signing half of a public identity ----------------------------

/// The "full public identity" `veil1<x25519><ed25519>` is two keys pasted
/// together, and nothing proves the holder of the X25519 half also holds the
/// Ed25519 half. Mallory hands an admin her X25519 key followed by **Alice's**
/// (public) signing key. The grant is accepted, and the ring's signer table
/// (`RingState::ever_signers`, key → member) now maps Alice's key to Mallory.
/// Every signature Alice ever made is judged "unknown key" from then on, by
/// every reader, and Alice's timed embargoes never auto-release (only a
/// "good" creation signature may trigger a release).
#[test]
fn a_grant_cannot_rebind_another_members_signing_key() {
    let alice = Identity::generate("alice");
    let mallory = Identity::generate("mallory");
    let (mut repo, fs) = repo_at(3, &alice);
    commit_files(&mut repo, &*fs, &[("README.md", "hello\n")], "alice's work");
    let alices = repo.view().workspaces[WS].wc;
    let alices = repo.snapshot(&repo.snapshot(&alices).unwrap().parents[0]).unwrap();
    // Control: before the grant Alice's commit is good for a reader with no identity.
    let reader = Repo::open(fs.clone(), None, "reader").unwrap();
    assert!(reader.keys().snapshot_status(&alices).is_good());
    let until = veil_core::now_millis() + 50;
    let embargo = repo.keys().create_embargo("team", Some(until)).unwrap();
    let rec = repo.keys().load_embargo(&embargo).unwrap().unwrap();
    assert!(repo.keys().embargo_trusted(&rec), "control: Alice's record is trusted");

    // Mallory's "public identity": her X25519 key, Alice's signing key.
    let forged = format!("{}{}", mallory.public_hex(), alice.verifying_hex());
    let parsed = parse_public_identity(&forged).unwrap();
    assert_eq!(parsed.member_id(), mallory.public_hex());
    let granted = repo.keys().grant("team", &forged, "mallory");

    let reader = Repo::open(fs.clone(), None, "reader").unwrap();
    let status = reader.keys().snapshot_status(&alices);
    let trusted = repo.keys().embargo_trusted(&rec);
    assert!(
        granted.is_err() || (status.is_good() && trusted),
        "the grant of Alice's signing key to Mallory was accepted; Alice's commit is now {status:?} \
         and her embargo record trusted = {trusted}"
    );
}

/// Control for BUG-069: the forged binding cannot be used to sign ring
/// changes as Alice (Mallory lacks the secret), and Alice stays admin.
///
/// Adapted with the fix: the forged grant used to be accepted (and this
/// control checked what it could not do); it is now refused outright, in
/// every form, and an admin-signed grant that binds Alice's key to Mallory
/// anyway (a hostile admin, or a ring written by an earlier vl) fails
/// replay. The original checks still run on the ring.
#[test]
fn a_forged_signing_half_does_not_let_mallory_sign() {
    let alice = Identity::generate("alice");
    let mallory = Identity::generate("mallory");
    let (repo, _fs) = repo_at(3, &alice);
    let forged = format!("{}{}", mallory.public_hex(), alice.verifying_hex());
    assert!(repo.keys().grant_role("team", &forged, "mallory", Role::Admin).is_err());
    let with_alices_binding = format!("{forged}{}", alice.binding_hex());
    assert!(repo.keys().grant_role("team", &with_alices_binding, "mallory", Role::Admin).is_err());
    let st = ring(&repo, "team").verify().unwrap();
    assert!(st.is_admin(&alice.public_hex(), &alice.verifying_hex()));
    // Mallory signing with her own key is not her registered key.
    assert!(!st.is_admin(&mallory.public_hex(), &mallory.verifying_hex()));

    // Hand-crafted: Alice's key (unbound, as earlier grants were) for Mallory.
    let mut r = ring(&repo, "team");
    let st = r.verify().unwrap();
    let wrapped = match &r.log[0].op {
        RingOp::Genesis { members, .. } => members[0].wrapped.clone(),
        _ => unreachable!(),
    };
    let mut c = RingChange {
        seq: r.log.len() as u64,
        prev: r.log.last().unwrap().hash("team"),
        timestamp: 1,
        signer: alice.public_hex(),
        signing_key: alice.verifying_hex(),
        op: RingOp::Grant {
            member: MemberGrant {
                id: mallory.public_hex(),
                name: "mallory".into(),
                signing_key: Some(alice.verifying_hex()),
                binding: None,
                role: Role::Admin,
                generation: st.generation,
                wrapped,
            },
        },
        signature: String::new(),
    };
    c.signature = alice.sign("ring-change", &c.signing_body("team"));
    r.log.push(c);
    let err = r.verify().unwrap_err();
    assert!(err.contains("already belongs to member"), "{err}");
}

// ---- low-order member keys ----------------------------------------------

/// A low-order X25519 "member" in a ring (legacy rings granted before the
/// BUG-010 fix, or any admin's typo'd/hostile grant: replay never checks
/// member keys) makes every key rotation fail, because HPKE (and now the
/// legacy box) refuse to wrap to it. So:
/// * the admin can no longer revoke **anyone else** (a revocation rotates
///   the key to the remaining members, which include the low-order one);
/// * `vl upgrade` to format 3 fails *after* its commit point, at
///   `3:hpke-ring-keys`, and fails again on every resume.
#[test]
fn a_low_order_member_does_not_block_revocation_or_upgrade() {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let (repo, fs) = repo_at(2, &alice);
    repo.keys().grant("team", &bob.public_id(), "bob").unwrap();
    // A grant to the all-zero point, signed by the admin (as legacy vl
    // could make before BUG-010 was fixed). The wrap itself is irrelevant
    // to replay: copy Bob's.
    let st = ring(&repo, "team").verify().unwrap();
    let bobs_wrap = match &ring(&repo, "team").log.last().unwrap().op {
        RingOp::Grant { member } => member.wrapped.clone(),
        _ => unreachable!(),
    };
    let low = format!("veil1{}", "00".repeat(32));
    append_signed(
        &repo,
        "team",
        &alice,
        RingOp::Grant {
            member: MemberGrant {
                id: low.clone(),
                name: "typo".into(),
                signing_key: None,
                binding: None,
                role: Role::Member,
                generation: st.generation,
                wrapped: bobs_wrap,
            },
        },
    );
    // The ring is valid: replay does not look at member keys.
    assert!(ring(&repo, "team").verify().is_ok());

    // Revoking Bob (not the low-order member) must still work.
    let revoked = repo.keys().revoke("team", &bob.public_hex());
    // And the upgrade must get through its ring step (or report the member).
    drop(repo);
    let up = upgrade(fs.clone(), Some(alice.clone()), &UpgradeOptions::default());
    let journal_left = fs.exists(&p(JOURNAL_PATH)).unwrap();
    assert!(
        revoked.is_ok() && up.is_ok() && !journal_left,
        "revoke bob: {:?}; upgrade: {:?}; journal left behind: {journal_left}",
        revoked.map(|_| ()),
        up.map(|r| r.steps)
    );
}

// ---- the migration step never runs for admins of upgraded clones ---------

/// A non-admin's upgrade leaves the ring alone and tells the admin to "run
/// `vl upgrade` (or `vl scope rotate`) in an upgraded clone"; `vl upgrade
/// --remote` says rings "move to HPKE when an admin who has upgraded their
/// clone pushes". But an admin whose clone is *already* at format 3 (a fresh
/// clone of the upgraded remote, or the clone a non-admin upgraded) gets
/// "already at format 3" from `vl upgrade`: `3:hpke-ring-keys` only runs as
/// part of a 2 → 3 transition. The scope keeps sealing new content under a
/// key that was published under the legacy key wrap, and nothing says so.
#[test]
fn an_admin_upgrading_an_upgraded_clone_moves_their_rings_to_hpke() {
    let alice = Identity::generate("alice");
    let (mut a2, afs) = repo_at(2, &alice);
    commit_files(&mut a2, &*afs, &[("README.md", "hi\n")], "init");
    let main = a2.view().workspaces[WS].wc;
    let main = a2.snapshot(&main).unwrap().parents[0];
    a2.set_tag("main", main, None, true).unwrap();
    // The shared remote is at format 2 and gets upgraded structurally.
    let remote_fs = Arc::new(MemoryBackend::new());
    drop(Repo::init_bare_at(remote_fs.clone(), 2).unwrap());
    remote::push(&mut a2, remote_fs.clone(), false, &[], false).unwrap();
    let r = upgrade(remote_fs.clone(), None, &UpgradeOptions::default()).unwrap();
    assert!(r.notes.iter().any(|n| n.contains("when an admin who has upgraded their clone pushes")), "{:#?}", r.notes);

    // Alice starts a fresh clone of the (now format-3) remote, as `vl clone` does.
    let cfs = Arc::new(MemoryBackend::new());
    let mut clone = Repo::init_for_clone_at(cfs.clone(), Some(alice.clone()), "alice", 3).unwrap();
    remote::pull(&mut clone, "origin", remote_fs.clone()).unwrap();
    drop(clone);
    let r = upgrade(cfs.clone(), Some(alice.clone()), &UpgradeOptions::default()).unwrap();
    let clone = Repo::open(cfs.clone(), Some(alice.clone()), "alice").unwrap();
    let rg = ring(&clone, "team");
    let st = rg.verify().unwrap();
    assert!(
        !current_key_has_legacy_wraps(&rg, &st),
        "Alice (admin) ran `vl upgrade` as told; it said up_to_date = {} and scope 'team' still seals new \
         content under a legacy-wrapped key (generation {})",
        r.up_to_date,
        st.generation
    );
}

// ---- downgrade and mixing controls ---------------------------------------

/// Control: a format-3 store seals objects with AES-SIV and wraps with
/// HPKE; relabelling an AES-SIV object as legacy (or the reverse) fails to
/// open, and an HPKE wrap re-labelled to another scope fails.
#[test]
fn constructions_do_not_cross() {
    let k = random_key();
    let siv = Envelope::seal_deterministic(&k, "team#00", b"veil:blob\nx").unwrap();
    let raw = Object::Sealed(siv.clone()).encode();
    assert!(raw.starts_with(b"veil:sea2\n"));
    // Same body under the legacy tag: XChaCha20 with the SIV as "nonce" fails.
    let mut as_legacy = b"veil:seal\n".to_vec();
    as_legacy.extend_from_slice(&raw[b"veil:sea2\n".len()..]);
    if let Ok(Object::Sealed(e)) = Object::decode(&as_legacy) {
        assert!(e.open(&k).is_err());
    }
    let legacy = Envelope::seal_deterministic_legacy(&k, "team#00", b"veil:blob\nx").unwrap();
    let raw = Object::Sealed(legacy).encode();
    let mut as_siv = b"veil:sea2\n".to_vec();
    as_siv.extend_from_slice(&raw[b"veil:seal\n".len()..]);
    if let Ok(Object::Sealed(e)) = Object::decode(&as_siv) {
        assert!(e.open(&k).is_err());
    }
    let id = Identity::generate("x");
    let w = wrap_key(&id.public_key(), &k, "team").unwrap();
    assert!(id.unwrap_key(&w, "ops").is_err());
    let lw = wrap_key_legacy(&id.public_key(), &k, "team").unwrap();
    assert!(id.unwrap_key(&lw, "ops").is_err());
}

/// Control: an HPKE wrap whose `enc` is any of the eight low-order points
/// (and their non-canonical encodings with the top bit set) never opens,
/// and HPKE refuses to wrap to them.
#[test]
fn low_order_hpke_encapsulations_are_refused() {
    let id = Identity::generate("x");
    let k = random_key();
    let WrappedKey::Hpke(h) = wrap_key(&id.public_key(), &k, "team").unwrap() else { panic!() };
    // The order-8 subgroup of Curve25519, little-endian u-coordinates.
    let low: [&str; 7] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    for l in low {
        let mut b: [u8; 32] = hex::decode(l).unwrap().try_into().unwrap();
        for top in [false, true] {
            if top {
                b[31] |= 0x80;
            }
            let v = HpkeWrappedKey {
                hpke: HPKE_SUITE.into(),
                enc: hex::encode(b),
                ct: h.ct.clone(),
            };
            assert!(id.unwrap_key(&WrappedKey::Hpke(v), "team").is_err(), "{l} top={top}");
            assert!(wrap_key(&b, &k, "team").is_err() || !veil_core::identity::is_low_order_public_key(&b));
            assert!(wrap_key_legacy(&b, &k, "team").is_err() || !veil_core::identity::is_low_order_public_key(&b));
        }
    }
}
