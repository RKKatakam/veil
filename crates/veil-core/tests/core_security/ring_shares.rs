//! Ring format 4 (`docs/HUB.md` §13.12): invites, shares by members and a
//! member's removal of their own device. The ring's replay is the only
//! authority: whatever a compromised server lists, or a member's device is
//! made to sign, a device enters a ring only with a proof made outside the
//! server (an invite join, or a vouch by a current device of the same
//! person).

use std::sync::Arc;

use proptest::prelude::*;
use veil_core::{
    crypto::domains::{SIG_CONTEXT_HUB_DEVICE, SIG_CONTEXT_HUB_INVITE, SIG_CONTEXT_RING_CHANGE},
    hub::{
        access::AccessPolicy,
        wire::{join_message, vouch_message, InviteKey},
    },
    identity::{parse_public_identity, PublicIdentity},
    keychain::{KeyRing, Keychain, MemberGrant, RingChange, RingOp, Role, ShareProof, RING_FORMAT_SHARES, SHARES_REPO_FORMAT},
    policy::{rule_scope, rule_scope_of, Policy, Tier, DEFAULT_SCOPE},
    Identity, MemoryBackend, Repo, VPath,
};

const SCOPE: &str = "rule-abc";

fn pid(i: &Identity) -> PublicIdentity {
    parse_public_identity(&i.public_id()).unwrap()
}

/// A device's keychain at repository `format`, holding `ring` if given.
fn device(id: &Identity, format: u32, ring: Option<&KeyRing>) -> Repo {
    let fs = Arc::new(MemoryBackend::new());
    let repo = Repo::init_for_clone_at(fs, Some(id.clone()), &id.name, format).unwrap();
    if let Some(r) = ring {
        repo.keys().save_ring(r).unwrap();
    }
    repo
}

fn ring(keys: &Keychain) -> KeyRing {
    keys.load_ring(SCOPE).unwrap().unwrap()
}

fn vouch(by: &Identity, device: &Identity) -> ShareProof {
    ShareProof::Vouch {
        by: by.verifying_hex(),
        signature: by.sign(SIG_CONTEXT_HUB_DEVICE, &vouch_message(&pid(device)).unwrap()),
    }
}

fn joined(key: &InviteKey, person: &str, device: &Identity) -> ShareProof {
    ShareProof::Invite {
        key: key.public_hex(),
        signature: key.sign_join(person, &pid(device)).unwrap(),
    }
}

/// `r` plus `op` signed by `signer`, as a hostile writer would append it
/// (not checked first).
fn appended(r: &KeyRing, signer: &Identity, op: RingOp) -> KeyRing {
    let mut r = r.clone();
    let mut c = RingChange {
        seq: r.log.len() as u64,
        prev: r.log.last().map(|c| c.hash(&r.scope)).unwrap_or_default(),
        timestamp: veil_core::now_millis(),
        signer: signer.public_hex(),
        signing_key: signer.verifying_hex(),
        op,
        signature: String::new(),
    };
    c.signature = signer.sign(SIG_CONTEXT_RING_CHANGE, &c.signing_body(&r.scope));
    r.log.push(c);
    r.format = RING_FORMAT_SHARES;
    r
}

fn member(id: &Identity, name: &str, generation: u32, role: Role) -> MemberGrant {
    let p = pid(id);
    MemberGrant {
        id: p.member_id(),
        name: name.into(),
        signing_key: p.signing_hex(),
        binding: p.binding_hex(),
        role,
        generation,
        wrapped: veil_core::identity::wrap_key(&p.x25519, &[9; 32], SCOPE).unwrap(),
    }
}

/// admin's ring with alice's first device granted.
fn start() -> (Identity, Identity, Repo) {
    let admin = Identity::generate("admin");
    let alice = Identity::generate("alice");
    let a = device(&admin, SHARES_REPO_FORMAT, None);
    a.keys().create_scope(SCOPE).unwrap();
    a.keys().grant(SCOPE, &alice.public_id(), "alice").unwrap();
    (admin, alice, a)
}

#[test]
fn a_person_shares_with_their_new_device_which_then_opens_the_key() {
    let (_admin, alice, a) = start();
    let laptop = Identity::generate("alice");
    let al = device(&alice, SHARES_REPO_FORMAT, Some(&ring(a.keys())));
    al.keys().share(SCOPE, &laptop.public_id(), "alice", vouch(&alice, &laptop)).unwrap();
    let r = ring(al.keys());
    assert_eq!(r.format, RING_FORMAT_SHARES);
    let lp = device(&laptop, SHARES_REPO_FORMAT, Some(&r));
    assert_eq!(lp.keys().sealing_key(SCOPE).unwrap().1, al.keys().sealing_key(SCOPE).unwrap().1, "the shared device holds the key");
    // The admin's device takes it as a fast-forward.
    assert_eq!(a.keys().merge_ring(&r).unwrap(), veil_core::keychain::RingMerge::Updated);
}

#[test]
fn shares_without_a_proof_from_outside_the_server_are_refused() {
    let (admin, alice, a) = start();
    let r = ring(a.keys());
    let st = r.verify().unwrap();
    let g = st.generation;
    let mal = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let other = Identity::generate("alice");
    let cases: Vec<(&str, &Identity, MemberGrant, ShareProof)> = vec![
        ("its own vouch", &alice, member(&mal, "alice", g, Role::Member), vouch(&mal, &mal)),
        ("alice's vouch moved from another device", &alice, member(&mal, "alice", g, Role::Member), {
            let ShareProof::Vouch { by, signature } = vouch(&alice, &other) else { unreachable!() };
            ShareProof::Vouch { by, signature }
        }),
        ("a vouch by someone not in the ring", &alice, member(&mal, "alice", g, Role::Member), vouch(&bob, &mal)),
        ("a vouch by another person (the admin)", &alice, member(&mal, "alice", g, Role::Member), vouch(&admin, &mal)),
        ("a vouch for alice used for a device named bob", &alice, member(&mal, "bob", g, Role::Member), vouch(&alice, &mal)),
        ("signed by an outsider", &mal, member(&mal, "alice", g, Role::Member), vouch(&alice, &mal)),
        ("as an admin", &alice, member(&mal, "alice", g, Role::Admin), vouch(&alice, &mal)),
        ("at an old generation", &alice, member(&mal, "alice", g + 1, Role::Member), vouch(&alice, &mal)),
        ("a join under no invite", &alice, member(&mal, "alice", g, Role::Member), joined(&InviteKey::generate(), "alice", &mal)),
        ("the device signs its join itself", &alice, member(&mal, "alice", g, Role::Member), ShareProof::Invite {
            key: mal.verifying_hex(),
            signature: mal.sign(SIG_CONTEXT_HUB_INVITE, &join_message("alice", &pid(&mal)).unwrap()),
        }),
    ];
    for (what, signer, m, proof) in cases {
        let bad = appended(&r, signer, RingOp::Share { member: m, proof });
        assert!(bad.verify().is_err(), "accepted a share: {what}");
        assert!(matches!(a.keys().merge_ring(&bad).unwrap(), veil_core::keychain::RingMerge::Rejected(_)), "{what}");
    }
    // A device without its binding, or with a binding forged for its keys.
    let mut unbound = member(&mal, "alice", g, Role::Member);
    unbound.binding = None;
    assert!(appended(&r, &alice, RingOp::Share { member: unbound, proof: vouch(&alice, &mal) }).verify().is_err());
}

#[test]
fn an_invite_is_used_once_before_it_expires_and_can_be_cancelled() {
    let (admin, _alice, a) = start();
    let key = InviteKey::generate();
    let far = veil_core::now_millis() + 3_600_000;
    a.keys().invite(SCOPE, "carol", &key.public_hex(), far).unwrap();
    let carol = Identity::generate("carol");
    let second = Identity::generate("carol");
    // The admin (any member) shares under the join; the ring marks it used.
    a.keys().share(SCOPE, &carol.public_id(), "carol", joined(&key, "carol", &carol)).unwrap();
    let r = ring(a.keys());
    assert!(r.verify().unwrap().invites[&key.public_hex()].used);
    let g = r.verify().unwrap().generation;
    let again = appended(&r, &admin, RingOp::Share { member: member(&second, "carol", g, Role::Member), proof: joined(&key, "carol", &second) });
    assert!(again.verify().unwrap_err().contains("already used"));
    // For another person, or after its expiry.
    let k2 = InviteKey::generate();
    a.keys().invite(SCOPE, "dave", &k2.public_hex(), veil_core::now_millis() - 1).unwrap();
    let dave = Identity::generate("dave");
    let r = ring(a.keys());
    let late = appended(&r, &admin, RingOp::Share { member: member(&dave, "dave", g, Role::Member), proof: joined(&k2, "dave", &dave) });
    assert!(late.verify().unwrap_err().contains("expired"));
    let k3 = InviteKey::generate();
    a.keys().invite(SCOPE, "erin", &k3.public_hex(), far).unwrap();
    let r = ring(a.keys());
    let wrong = appended(&r, &admin, RingOp::Share { member: member(&dave, "dave", g, Role::Member), proof: joined(&k3, "dave", &dave) });
    assert!(wrong.verify().unwrap_err().contains("someone else"));
    // Cancelled.
    assert!(a.keys().uninvite(SCOPE, &k3.public_hex()).unwrap());
    let erin = Identity::generate("erin");
    let r = ring(a.keys());
    let gone = appended(&r, &admin, RingOp::Share { member: member(&erin, "erin", g, Role::Member), proof: joined(&k3, "erin", &erin) });
    assert!(gone.verify().is_err());
    // Only an admin invites.
    let r = ring(a.keys());
    let by_member = appended(&r, &carol, RingOp::Invite { person: "x".into(), key: InviteKey::generate().public_hex(), expires_at: far });
    assert!(by_member.verify().unwrap_err().contains("not an admin"));
}

#[test]
fn a_member_removes_only_their_own_devices_and_the_key_rotates() {
    let (_admin, alice, a) = start();
    let laptop = Identity::generate("alice");
    let bob = Identity::generate("bob");
    a.keys().grant(SCOPE, &bob.public_id(), "bob").unwrap();
    let al = device(&alice, SHARES_REPO_FORMAT, Some(&ring(a.keys())));
    al.keys().share(SCOPE, &laptop.public_id(), "alice", vouch(&alice, &laptop)).unwrap();
    let before = al.keys().sealing_key(SCOPE).unwrap();
    // Not bob's device.
    assert!(al.keys().revoke_device(SCOPE, &bob.public_hex()).is_err());
    assert!(al.keys().revoke_device(SCOPE, &laptop.public_hex()).unwrap());
    let r = ring(al.keys());
    let st = r.verify().unwrap();
    assert!(!st.members.contains_key(&laptop.public_hex()));
    assert!(matches!(r.log.last().unwrap().op, RingOp::RevokeOwn { .. }));
    let after = al.keys().sealing_key(SCOPE).unwrap();
    assert_ne!(before.1, after.1, "the key did not rotate");
    let lp = device(&laptop, SHARES_REPO_FORMAT, Some(&r));
    assert!(lp.keys().sealing_key(SCOPE).is_err(), "the removed device holds the new key");
    // Never shared to again, even with a genuine vouch.
    assert!(al.keys().share(SCOPE, &laptop.public_id(), "alice", vouch(&alice, &laptop)).is_err());
    // bob's revocation of alice's device, signed by hand: refused by name.
    let RingOp::RevokeOwn { rotation, .. } = r.log.last().unwrap().op.clone() else { unreachable!() };
    let bad = appended(&r, &bob, RingOp::RevokeOwn { member: alice.public_hex(), rotation });
    assert!(bad.verify().unwrap_err().contains("only their own devices"));
}

#[test]
fn ring_format_4_needs_repository_format_7() {
    let (_admin, alice, a) = start();
    let laptop = Identity::generate("alice");
    let al = device(&alice, SHARES_REPO_FORMAT, Some(&ring(a.keys())));
    al.keys().share(SCOPE, &laptop.public_id(), "alice", vouch(&alice, &laptop)).unwrap();
    let r = ring(al.keys());
    // A format-6 repository cannot store it (`vl upgrade`), and a ring that
    // says format 3 while holding a share does not verify.
    let old = device(&alice, 6, None);
    let e = old.keys().save_ring(&r).unwrap_err().to_string();
    assert!(e.contains("vl upgrade"), "{e}");
    let mut labelled = r.clone();
    labelled.format = 3;
    assert!(labelled.verify().unwrap_err().contains("ring format 4"));
    let mut newer = r.clone();
    newer.format = RING_FORMAT_SHARES + 1;
    assert!(newer.verify().unwrap_err().contains("newer vl"));
}

#[test]
fn a_cloak_rule_secret_takes_the_key_of_its_deciding_line() {
    let text = "\
.env            cloak rule
billing/        finance
billing/eu/     finance-eu carol
docs/           public
infra/*         ops
";
    let p = Policy::parse(text);
    let scope = |path: &str| match p.classify(&VPath::new(path).unwrap(), false).tier {
        Tier::Cloaked(s) => s,
        t => panic!("{path}: {t:?}"),
    };
    assert_eq!(scope("billing/.env"), rule_scope_of("billing"));
    assert_eq!(scope("billing/x/.env"), rule_scope_of("billing"));
    assert_eq!(scope("billing/eu/.env"), rule_scope_of("billing/eu"));
    // No line, a line naming nobody, and a glob line (grants nothing): the
    // admins' key.
    assert_eq!(scope(".env"), DEFAULT_SCOPE);
    assert_eq!(scope("docs/.env"), DEFAULT_SCOPE);
    assert_eq!(scope("infra/x/.env"), DEFAULT_SCOPE);
    assert_ne!(rule_scope_of("billing"), rule_scope_of("billing/eu"));
    assert_eq!(rule_scope(&AccessPolicy::parse(text), "billing/eu/.env"), rule_scope_of("billing/eu"));
    // `rule` is never a scope of its own.
    assert!(veil_core::keychain::validate_scope_name("rule").is_err());
    let lit = Policy::parse(".env cloak rule\n");
    assert_eq!(lit.classify(&VPath::new(".env").unwrap(), false).tier, Tier::Cloaked(DEFAULT_SCOPE.into()));
}

// ---- property: a compromised server never gets a device into a ring -----------------------

#[derive(Clone, Debug)]
enum Try {
    /// The server lists its device under alice with a vouch it makes up
    /// (by its own key, moved from another device, by another person).
    Vouch(u8),
    /// The server makes a join for its device: its own key, a key of its
    /// choosing, alice's join moved onto it, an invite used or cancelled.
    Join(u8),
    /// Honest steps around it.
    AliceConfirmsLaptop,
    AdminInvitesCarol,
    CarolJoins,
    AdminRemovesAlice,
    AliceRemovesLaptop,
}

fn tries() -> impl Strategy<Value = Try> {
    prop_oneof![
        (0u8..3).prop_map(Try::Vouch),
        (0u8..4).prop_map(Try::Join),
        Just(Try::AliceConfirmsLaptop),
        Just(Try::AdminInvitesCarol),
        Just(Try::CarolJoins),
        Just(Try::AdminRemovesAlice),
        Just(Try::AliceRemovesLaptop),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]
    /// Honest members' devices sign whatever share a compromised server
    /// asks for (the worst case: `vl` itself checks first); the ring's
    /// replay still never lets one of the server's devices in.
    #[test]
    fn the_servers_devices_never_enter_a_ring(steps in proptest::collection::vec(tries(), 1..10)) {
        let (admin, alice, a) = start();
        let laptop = Identity::generate("alice");
        let carol = Identity::generate("carol");
        let carol_key = InviteKey::generate();
        let servers: Vec<Identity> = (0..3).map(|_| Identity::generate("alice")).collect();
        for step in steps {
            let r = ring(a.keys());
            let st = r.verify().unwrap();
            let g = st.generation;
            // Some current member's device signs the server's share.
            let signer = [&admin, &alice, &laptop, &carol].into_iter().find(|i| st.members.contains_key(&i.public_hex())).unwrap().clone();
            let mal = &servers[step_index(&step) % servers.len()];
            let forged = match &step {
                Try::Vouch(0) => Some(("alice", vouch(mal, mal))),
                Try::Vouch(1) => Some(("alice", {
                    let ShareProof::Vouch { by, signature } = vouch(&alice, &laptop) else { unreachable!() };
                    ShareProof::Vouch { by, signature }
                })),
                Try::Vouch(_) => Some(("alice", vouch(&admin, mal))),
                Try::Join(0) => Some(("carol", ShareProof::Invite {
                    key: carol_key.public_hex(),
                    signature: mal.sign(SIG_CONTEXT_HUB_INVITE, &join_message("carol", &pid(mal)).unwrap()),
                })),
                Try::Join(1) => Some(("carol", joined(&InviteKey::generate(), "carol", mal))),
                Try::Join(2) => Some(("carol", {
                    let ShareProof::Invite { key, signature } = joined(&carol_key, "carol", &carol) else { unreachable!() };
                    ShareProof::Invite { key, signature }
                })),
                Try::Join(_) => Some(("alice", joined(&carol_key, "alice", mal))),
                _ => None,
            };
            if let Some((name, proof)) = forged {
                let bad = appended(&r, &signer, RingOp::Share { member: member(mal, name, g, Role::Member), proof });
                prop_assert!(bad.verify().is_err(), "a server's device entered the ring: {step:?}");
                continue;
            }
            // Honest steps (each may not apply; then nothing happens).
            let _ = match step {
                Try::AliceConfirmsLaptop if st.members.contains_key(&alice.public_hex()) => {
                    let al = device(&alice, SHARES_REPO_FORMAT, Some(&r));
                    al.keys().share(SCOPE, &laptop.public_id(), "alice", vouch(&alice, &laptop)).map(|()| ring(al.keys()))
                }
                Try::AdminInvitesCarol if !st.invites.contains_key(&carol_key.public_hex()) => {
                    a.keys().invite(SCOPE, "carol", &carol_key.public_hex(), veil_core::now_millis() + 60_000).map(|()| ring(a.keys()))
                }
                Try::CarolJoins => a.keys().share(SCOPE, &carol.public_id(), "carol", joined(&carol_key, "carol", &carol)).map(|()| ring(a.keys())),
                Try::AdminRemovesAlice => {
                    for d in [&alice, &laptop] {
                        let _ = a.keys().revoke(SCOPE, &d.public_hex());
                    }
                    Ok(ring(a.keys()))
                }
                Try::AliceRemovesLaptop if st.members.contains_key(&alice.public_hex()) => {
                    let al = device(&alice, SHARES_REPO_FORMAT, Some(&r));
                    al.keys().revoke_device(SCOPE, &laptop.public_hex()).map(|_| ring(al.keys()))
                }
                _ => Ok(r.clone()),
            }
            .map(|new| a.keys().merge_ring(&new));
            let st = ring(a.keys()).verify().unwrap();
            for m in &servers {
                prop_assert!(!st.members.contains_key(&m.public_hex()));
            }
        }
    }
}

fn step_index(t: &Try) -> usize {
    match t {
        Try::Vouch(i) | Try::Join(i) => *i as usize,
        _ => 0,
    }
}
