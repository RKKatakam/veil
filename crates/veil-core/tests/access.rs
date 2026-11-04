//! Access control and authenticity: signed key rings, key rotation on
//! revoke, signed embargo records and snapshot signatures. Adversarial cases
//! play the attacker by editing the shared metadata files directly.

use std::sync::Arc;

use serde_json::Value;
use veil_core::{
    commands::EmbargoSpec,
    keychain::{KeyRing, Keychain, RingChange, RingMerge, RingOp, Role, SignatureStatus},
    remote,
    revset::resolve,
    tree::lookup,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

const WS: &str = "default";
const RING: &str = ".veil/meta/keyrings/team.json";

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

struct Peer {
    repo: Repo,
    fs: Arc<MemoryBackend>,
    id: Identity,
}

fn peer(name: &str) -> Peer {
    let fs = Arc::new(MemoryBackend::new());
    let id = Identity::generate(name);
    let repo = Repo::init(fs.clone(), Some(id.clone()), name).unwrap();
    Peer { repo, fs, id }
}

/// A peer that starts from a clone of `remote` (no scope of its own).
fn clone_of(name: &str, remote: &Arc<MemoryBackend>) -> Peer {
    let fs = Arc::new(MemoryBackend::new());
    let id = Identity::generate(name);
    let mut repo = Repo::init_for_clone(fs.clone(), Some(id.clone()), name).unwrap();
    remote::pull(&mut repo, "origin", remote.clone()).unwrap();
    Peer { repo, fs, id }
}

fn clone_as(id: &Identity, remote: &Arc<MemoryBackend>) -> Repo {
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init_for_clone(fs, Some(id.clone()), &id.name).unwrap();
    remote::pull(&mut repo, "origin", remote.clone()).unwrap();
    repo
}

fn read_json(fs: &dyn StorageBackend, path: &str) -> Value {
    serde_json::from_slice(&fs.read(&p(path)).unwrap()).unwrap()
}

fn write_json(fs: &dyn StorageBackend, path: &str, v: &Value) {
    fs.write(&p(path), &serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

fn ring(fs: &dyn StorageBackend) -> KeyRing {
    serde_json::from_slice(&fs.read(&p(RING)).unwrap()).unwrap()
}

fn members(repo: &Repo) -> Vec<String> {
    let st = repo.keys().ring_state("team").unwrap().unwrap().unwrap();
    let mut names: Vec<String> = st.members.values().map(|m| m.name.clone()).collect();
    names.sort();
    names
}

/// Commit `path = content` (cloaked under `team`) and tag it `main`.
fn commit_cloaked(peer: &mut Peer, path: &str, content: &str, msg: &str) -> ObjectId {
    peer.fs.write(&p(".veilpolicy"), b"secret/ cloak team\n").unwrap();
    peer.fs.write(&p(path), content.as_bytes()).unwrap();
    peer.repo.snapshot_workspace(WS, &*peer.fs).unwrap();
    let (c, _) = peer.repo.commit_working_copy(WS, msg).unwrap();
    peer.repo.set_tag("main", c, None, true).unwrap();
    c
}

fn read(repo: &Repo, rev: &ObjectId, path: &str) -> Option<Vec<u8>> {
    let tree = repo.snapshot(rev).unwrap().tree;
    let e = lookup(repo.store(), &tree, &p(path)).unwrap()?;
    repo.store().read_entry(&e).ok()
}

/// Alice (admin) and Bob (member) share `team` through `remote`.
fn team_with_bob() -> (Peer, Identity, Arc<MemoryBackend>) {
    let mut alice = peer("alice");
    let bob = Identity::generate("bob");
    alice.repo.keys().grant("team", &bob.public_id(), "bob").unwrap();
    commit_cloaked(&mut alice, "secret/plan.md", "v1 plan\n", "v1");
    let remote = Arc::new(MemoryBackend::new());
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();
    (alice, bob, remote)
}

// ---- revocation survives synchronisation ---------------------------------

#[test]
fn revoke_then_pull_from_a_remote_that_still_lists_the_member() {
    let (mut alice, bob, remote) = team_with_bob();
    assert!(alice.repo.keys().revoke("team", &bob.public_id()).unwrap());
    // The remote still lists Bob. Pulling must not resurrect him.
    let rep = remote::pull(&mut alice.repo, "origin", remote.clone()).unwrap();
    assert_eq!(members(&alice.repo), vec!["alice"], "{:?}", rep.warnings);
    // Push, then pull again: the remote now carries the revocation too.
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();
    remote::pull(&mut alice.repo, "origin", remote.clone()).unwrap();
    assert_eq!(members(&alice.repo), vec!["alice"]);
    let on_remote = Repo::open(remote.clone(), None, "remote").unwrap();
    assert_eq!(members(&on_remote), vec!["alice"]);
}

#[test]
fn revoke_push_and_a_stale_replica_cannot_undo_it() {
    let (mut alice, bob, remote) = team_with_bob();
    // Carol's replica (and its key ring listing Bob) predates the revocation.
    let mut carol = clone_of("carol", &remote);
    assert_eq!(members(&carol.repo), vec!["alice", "bob"]);

    alice.repo.keys().revoke("team", &bob.public_id()).unwrap();
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();

    // Direction 1: the stale replica pushes its old ring back to the remote.
    let rep = remote::push(&mut carol.repo, remote.clone(), false, &[], false).unwrap();
    let on_remote = Repo::open(remote.clone(), None, "remote").unwrap();
    assert_eq!(members(&on_remote), vec!["alice"], "stale push ignored: {:?}", rep.warnings);

    // Direction 2: the stale replica pulls and learns about the revocation.
    remote::pull(&mut carol.repo, "origin", remote.clone()).unwrap();
    assert_eq!(members(&carol.repo), vec!["alice"]);

    // And Alice pulling from the replica (as a remote) stays revoked too.
    remote::pull(&mut alice.repo, "carol", carol.fs.clone()).unwrap();
    assert_eq!(members(&alice.repo), vec!["alice"]);
}

#[test]
fn revoked_member_reads_history_but_not_new_content() {
    let (mut alice, bob, remote) = team_with_bob();
    let v1 = resolve(&alice.repo, "main", WS).unwrap();
    alice.repo.keys().revoke("team", &bob.public_id()).unwrap();
    let v2 = commit_cloaked(&mut alice, "secret/plan.md", "v2 plan: after revocation\n", "v2");
    commit_cloaked(&mut alice, "secret/new.md", "brand new\n", "v3");
    let v3 = resolve(&alice.repo, "main", WS).unwrap();
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();

    let bob_repo = clone_as(&bob, &remote);
    assert_eq!(read(&bob_repo, &v1, "secret/plan.md").unwrap(), b"v1 plan\n", "history stays readable");
    assert_eq!(read(&bob_repo, &v2, "secret/plan.md"), None, "changed file uses the new generation");
    assert_eq!(read(&bob_repo, &v3, "secret/new.md"), None, "new file uses the new generation");
    assert!(!bob_repo.keys().is_member("team"));

    // Bob tampers with his own copy of the ring to re-add himself: the ring
    // stops verifying, and he still has no key for the new generation.
    let mut v = read_json(&**bob_repo.backend(), RING);
    let log = v["log"].as_array_mut().unwrap();
    log.truncate(2); // drop the revocation
    write_json(&**bob_repo.backend(), RING, &v);
    let bob_repo = Repo::open(bob_repo.backend().clone(), Some(bob.clone()), "bob").unwrap();
    assert_eq!(read(&bob_repo, &v2, "secret/plan.md"), None);

    // Members (and Alice) still read everything.
    let alice_clone = clone_as(&alice.id, &remote);
    assert_eq!(read(&alice_clone, &v1, "secret/plan.md").unwrap(), b"v1 plan\n");
    assert_eq!(read(&alice_clone, &v2, "secret/plan.md").unwrap(), b"v2 plan: after revocation\n");
}

#[test]
fn members_granted_after_a_rotation_read_all_generations() {
    let (mut alice, bob, remote) = team_with_bob();
    let v1 = resolve(&alice.repo, "main", WS).unwrap();
    alice.repo.keys().revoke("team", &bob.public_id()).unwrap();
    let v2 = commit_cloaked(&mut alice, "secret/plan.md", "v2\n", "v2");
    let dave = Identity::generate("dave");
    alice.repo.keys().grant("team", &dave.public_id(), "dave").unwrap();
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();
    let dave_repo = clone_as(&dave, &remote);
    assert_eq!(read(&dave_repo, &v1, "secret/plan.md").unwrap(), b"v1 plan\n");
    assert_eq!(read(&dave_repo, &v2, "secret/plan.md").unwrap(), b"v2\n");
}

#[test]
fn rotation_does_not_dirty_unchanged_cloaked_files() {
    let (mut alice, bob, _remote) = team_with_bob();
    let wc = alice.repo.workspace_wc(WS).unwrap();
    alice.repo.keys().revoke("team", &bob.public_id()).unwrap();
    let out = alice.repo.snapshot_workspace(WS, &*alice.fs).unwrap();
    assert!(!out.changed, "re-snapshotting after a rotation is a no-op");
    assert_eq!(out.snapshot, wc);
}

// ---- tampered, forged and replayed rings ---------------------------------

#[test]
fn tampered_ring_is_rejected_on_pull() {
    let (mut alice, _bob, remote) = team_with_bob();
    let mallory = Identity::generate("mallory");
    let mut carol = clone_of("carol", &remote);

    // The attacker controls the remote and rewrites Bob's grant to Mallory,
    // keeping the original signature.
    let mut v = read_json(&*remote, RING);
    v["log"][1]["op"]["member"]["id"] = Value::String(mallory.public_hex());
    v["log"][1]["op"]["member"]["name"] = Value::String("bob".into());
    write_json(&*remote, RING, &v);

    // Only Alice's revocation-free ring is offered; it fails verification.
    let rep = remote::pull(&mut carol.repo, "origin", remote.clone()).unwrap();
    assert!(rep.warnings.iter().any(|w| w.contains("does not verify")), "{:?}", rep.warnings);
    assert_eq!(members(&carol.repo), vec!["alice", "bob"]);

    // A fresh clone rejects it too, so it simply has no ring.
    let fresh = clone_as(&mallory, &remote);
    assert!(fresh.keys().load_ring("team").unwrap().is_none());

    // Tampering with the role (bob → admin) or a wrapped key is caught too.
    let mut v = read_json(&*alice.fs, RING);
    v["log"][1]["op"]["member"]["role"] = Value::String("admin".into());
    let tampered: KeyRing = serde_json::from_value(v).unwrap();
    assert!(tampered.verify().is_err());
    assert!(matches!(alice.repo.keys().merge_ring(&tampered).unwrap(), RingMerge::Rejected(_)));
    let _ = remote::pull(&mut alice.repo, "origin", remote.clone()).unwrap();
    assert_eq!(members(&alice.repo), vec!["alice", "bob"]);
}

#[test]
fn forged_member_addition_is_rejected() {
    let (alice, bob, remote) = team_with_bob();
    let mallory = Identity::generate("mallory");

    // Bob (a member, not an admin) cannot grant through the API...
    let bob_repo = clone_as(&bob, &remote);
    assert!(bob_repo.keys().grant("team", &mallory.public_id(), "mallory").is_err());

    // ...and a grant he signs himself and appends by hand does not verify:
    // the signature is valid, but Bob is not an admin at that point.
    let mut forged = ring(&*remote);
    let mut c = forged.log[1].clone();
    c.seq = 2;
    c.prev = forged.log[1].hash("team");
    c.signer = bob.public_hex();
    c.signing_key = bob.verifying_hex();
    if let RingOp::Grant { member } = &mut c.op {
        member.id = mallory.public_hex();
        member.name = "mallory".into();
    }
    resign(&mut c, &bob);
    forged.log.push(c.clone());
    let err = forged.verify().unwrap_err();
    assert!(err.contains("change #2") && err.contains("not an admin"), "{err}");
    assert!(matches!(alice.repo.keys().merge_ring(&forged).unwrap(), RingMerge::Rejected(_)));

    // Claiming to be Alice while signing with Bob's key fails the same way.
    let mut as_alice = c;
    as_alice.signer = alice.id.public_hex();
    resign(&mut as_alice, &bob);
    forged.log[2] = as_alice;
    assert!(forged.verify().unwrap_err().contains("not an admin"));

    // An outsider forging a whole new ring for the scope: different key → not merged.
    let outsider_fs = Arc::new(MemoryBackend::new());
    let mut outsider = Repo::init(outsider_fs.clone(), Some(mallory.clone()), "mallory").unwrap();
    let rep = remote::push(&mut outsider, remote.clone(), false, &[], false).unwrap();
    assert!(rep.warnings.iter().any(|w| w.contains("different keys")), "{:?}", rep.warnings);
    assert_eq!(members(&Repo::open(remote.clone(), None, "r").unwrap()), vec!["alice", "bob"]);

    // The outsider forges a genesis that claims the real key id and copies
    // the real wrapped keys, naming himself admin. Members who hold the key
    // catch the bad genesis proof.
    let real = ring(&*remote);
    let mut hijack = real.clone();
    hijack.log.truncate(1);
    if let RingOp::Genesis { members, .. } = &mut hijack.log[0].op {
        members[0].role = Role::Member;
        let mut m = members[0].clone();
        m.id = mallory.public_hex();
        m.name = "mallory".into();
        m.role = Role::Admin;
        m.signing_key = Some(mallory.verifying_hex());
        // A forger signs their own binding (the copied one is Alice's).
        m.binding = Some(mallory.binding_hex());
        members.push(m);
    }
    hijack.log[0].signer = mallory.public_hex();
    hijack.log[0].signing_key = mallory.verifying_hex();
    resign(&mut hijack.log[0], &mallory);
    assert!(hijack.verify().is_ok(), "structurally valid: {:?}", hijack.verify());
    match fresh_keychain(&alice.id).merge_ring(&hijack).unwrap() {
        RingMerge::Rejected(w) => assert!(w.contains("genesis proof"), "{w}"),
        other => panic!("forged genesis accepted: {other:?}"),
    }
}

/// A keychain over an empty backend, for "fresh clone" checks.
fn fresh_keychain(id: &Identity) -> Keychain {
    Keychain::new(Arc::new(MemoryBackend::new()), Some(id.clone()), "x".into())
}

/// Re-sign a ring change with `who` (what a forger would do).
fn resign(c: &mut RingChange, who: &Identity) {
    c.signature = who.sign("ring-change", &c.signing_body("team"));
}

#[test]
fn replayed_old_ring_is_ignored() {
    let (mut alice, bob, remote) = team_with_bob();
    let old_ring = remote.read(&p(RING)).unwrap();
    alice.repo.keys().revoke("team", &bob.public_id()).unwrap();
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();

    // The attacker rolls the remote's ring back to the version listing Bob.
    remote.write(&p(RING), &old_ring).unwrap();
    remote::pull(&mut alice.repo, "origin", remote.clone()).unwrap();
    assert_eq!(members(&alice.repo), vec!["alice"], "rollback ignored");
    // Pushing heals the remote.
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();
    assert_eq!(members(&Repo::open(remote.clone(), None, "r").unwrap()), vec!["alice"]);
}

#[test]
fn diverged_rings_keep_the_local_log_and_warn() {
    let (mut alice, bob, remote) = team_with_bob();
    // Alice makes Bob an admin; both then change the ring independently.
    alice
        .repo
        .keys()
        .grant_role("team", &bob.public_id(), "bob", Role::Admin)
        .unwrap();
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();
    let mut bob_repo = clone_as(&bob, &remote);
    bob_repo.keys().grant("team", &Identity::generate("erin").public_id(), "erin").unwrap();
    alice.repo.keys().grant("team", &Identity::generate("fred").public_id(), "fred").unwrap();
    remote::push(&mut bob_repo, remote.clone(), false, &[], false).unwrap();
    let rep = remote::pull(&mut alice.repo, "origin", remote.clone()).unwrap();
    assert!(rep.warnings.iter().any(|w| w.contains("diverged") && w.contains("erin")), "{:?}", rep.warnings);
    assert_eq!(members(&alice.repo), vec!["alice", "bob", "fred"]);
}

// ---- embargo records ------------------------------------------------------

fn embargoed(alice: &mut Peer) -> String {
    alice.fs.write(&p("auth.rs"), b"v1\n").unwrap();
    alice.repo.snapshot_workspace(WS, &*alice.fs).unwrap();
    let (main, _) = alice.repo.commit_working_copy(WS, "v1").unwrap();
    alice.repo.set_tag("main", main, None, true).unwrap();
    let ws = alice.repo.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "v2 fix\n").unwrap();
    let (fix, _) = alice.repo.commit_ephemeral(&ws, "fix").unwrap();
    let far = veil_core::now_millis() + 7 * 24 * 3600 * 1000;
    let spec = EmbargoSpec {
        scope: "team".into(),
        until: Some(far),
    };
    alice.repo.merge(WS, main, vec![fix], "embargoed fix", Some(spec)).unwrap().embargo.unwrap()
}

#[test]
fn tampered_embargo_deadline_is_rejected_and_never_auto_releases() {
    let (mut alice, bob, remote) = team_with_bob();
    let e = embargoed(&mut alice);
    let rec = alice.repo.keys().load_embargo(&e).unwrap().unwrap();
    assert!(matches!(alice.repo.keys().embargo_status(&rec), SignatureStatus::Good { .. }));
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();
    let mut carol = clone_of("carol", &remote);
    let path = format!(".veil/meta/embargoes/{e}.json");

    // The attacker moves the deadline into the past on the remote.
    let mut v = read_json(&*remote, &path);
    v["until"] = Value::from(1);
    write_json(&*remote, &path, &v);
    let rep = remote::pull(&mut carol.repo, "origin", remote.clone()).unwrap();
    assert!(rep.warnings.iter().any(|w| w.contains(&e)), "{:?}", rep.warnings);
    assert_ne!(carol.repo.keys().load_embargo(&e).unwrap().unwrap().until, Some(1));

    // A member cloning fresh rejects the record (bad signature), so the
    // embargo key is never auto-published by their engine.
    let mut bob_repo = clone_as(&bob, &remote);
    assert!(bob_repo.keys().load_embargo(&e).unwrap().is_none());
    assert!(bob_repo.auto_release_embargoes().unwrap().is_empty());

    // Stripping the signature instead: accepted only as an unsigned record,
    // which is never released automatically.
    v.as_object_mut().unwrap().remove("signature");
    write_json(&*remote, &path, &v);
    let mut bob_repo = clone_as(&bob, &remote);
    let stripped = bob_repo.keys().load_embargo(&e).unwrap().unwrap();
    assert_eq!(bob_repo.keys().embargo_status(&stripped), SignatureStatus::Unsigned);
    assert!(bob_repo.auto_release_embargoes().unwrap().is_empty());
    assert!(!bob_repo.keys().embargo_released(&e));
}

#[test]
fn forged_embargo_release_is_rejected() {
    let (mut alice, _bob, remote) = team_with_bob();
    let e = embargoed(&mut alice);
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();
    let path = format!(".veil/meta/embargoes/{e}.json");
    let mut v = read_json(&*remote, &path);
    v["released_key"] = Value::String(hex::encode([7u8; 32]));
    v["released_at"] = Value::from(5);
    write_json(&*remote, &path, &v);
    let rep = remote::pull(&mut alice.repo, "origin", remote.clone()).unwrap();
    assert!(rep.warnings.iter().any(|w| w.contains("does not match")), "{:?}", rep.warnings);
    assert!(!alice.repo.keys().embargo_released(&e));
    // A genuine release propagates.
    alice.repo.release_embargo(&e).unwrap();
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();
    let carol = clone_of("carol", &remote);
    assert!(carol.repo.keys().embargo_released(&e));
}

// ---- snapshot signatures --------------------------------------------------

#[test]
fn snapshots_are_signed_and_rebases_are_signed_by_the_rewriter() {
    let (mut alice, bob, remote) = team_with_bob();
    let v1 = resolve(&alice.repo, "main", WS).unwrap();
    let v2 = commit_cloaked(&mut alice, "secret/more.md", "more\n", "v2");
    remote::push(&mut alice.repo, remote.clone(), false, &[], false).unwrap();
    let s = alice.repo.snapshot(&v1).unwrap();
    assert_eq!(s.signature_valid(), Some(true));
    assert_eq!(
        alice.repo.keys().snapshot_status(&s),
        SignatureStatus::Good {
            member: alice.id.public_hex(),
            name: "alice".into()
        }
    );

    // Bob describes Alice's change: same author, Bob's signature, and the
    // evolution log still points at Alice's original.
    let mut bob_repo = clone_as(&bob, &remote);
    let rewritten = bob_repo.describe(v1, "v1, reworded by bob").unwrap();
    let r = bob_repo.snapshot(&rewritten).unwrap();
    assert_eq!(r.author, "alice");
    assert_eq!(r.predecessors, vec![v1]);
    assert!(matches!(bob_repo.keys().snapshot_status(&r), SignatureStatus::Good { name, .. } if name == "bob"));
    assert!(bob_repo.keys().snapshot_status(&bob_repo.snapshot(&v1).unwrap()).is_good());

    // The auto-rebase moved Alice's child v2 onto the rewritten v1: the new
    // snapshot keeps Alice as author, is signed by Bob (who produced it), and
    // its predecessor is Alice's signed original.
    let v2_new = resolve(&bob_repo, "main", WS).unwrap();
    assert_ne!(v2_new, v2);
    let r2 = bob_repo.snapshot(&v2_new).unwrap();
    assert_eq!((r2.author.as_str(), r2.parents.clone(), r2.predecessors.clone()), ("alice", vec![rewritten], vec![v2]));
    assert!(matches!(bob_repo.keys().snapshot_status(&r2), SignatureStatus::Good { name, .. } if name == "bob"));
    assert!(matches!(
        bob_repo.keys().snapshot_status(&bob_repo.snapshot(&v2).unwrap()),
        SignatureStatus::Good { name, .. } if name == "alice"
    ));
}

#[test]
fn signature_stripping_and_transplants_are_detected() {
    let (alice, _bob, _remote) = team_with_bob();
    let v1 = resolve(&alice.repo, "main", WS).unwrap();
    let s = (*alice.repo.snapshot(&v1).unwrap()).clone();

    // Stripping the signature yields a different object: the id commits to
    // the signature, so children of the signed snapshot do not point at it.
    let mut stripped = s.clone();
    stripped.signature = None;
    let stripped_id = alice.repo.store().put_snapshot(&stripped).unwrap();
    assert_ne!(stripped_id, v1);
    assert_eq!(stripped_id, s.unsigned_id());
    assert_eq!(alice.repo.keys().snapshot_status(&stripped), SignatureStatus::Unsigned);

    // Moving Alice's signature onto different content fails verification.
    let mut transplant = s.clone();
    transplant.description = veil_core::object::Text::Plain("evil".into());
    assert_eq!(transplant.signature_valid(), Some(false));
    assert_eq!(alice.repo.keys().snapshot_status(&transplant), SignatureStatus::Bad);

    // A valid signature by a key no ring knows is "unknown", not "good".
    let mut by_stranger = s.clone();
    by_stranger.sign(&Identity::generate("stranger"));
    assert!(matches!(alice.repo.keys().snapshot_status(&by_stranger), SignatureStatus::Unknown { .. }));
    // Claiming to be Alice while signing with a stranger's key is not "good".
    by_stranger.signature.as_mut().unwrap().signer = alice.id.public_hex();
    assert!(by_stranger.signature_valid() == Some(true));
    assert!(!alice.repo.keys().snapshot_status(&by_stranger).is_good());

    // A pull reports snapshots whose signature does not verify.
    let bad_remote_fs = Arc::new(MemoryBackend::new());
    let mut bad = Repo::init_bare(bad_remote_fs.clone()).unwrap();
    let bad_id = bad.store().put_snapshot(&transplant).unwrap();
    {
        let mut tx = bad.transaction("plant").unwrap();
        tx.view.tags.insert(
            "evil".into(),
            veil_core::oplog::Tag::new(bad_id, None),
        );
        tx.commit().unwrap();
    }
    let mut victim = peer("victim");
    let rep = remote::pull(&mut victim.repo, "evil", bad_remote_fs).unwrap();
    assert!(rep.warnings.iter().any(|w| w.contains("invalid signature")), "{:?}", rep.warnings);
}

#[test]
fn ring_change_with_stripped_signature_is_rejected() {
    let (alice, _bob, remote) = team_with_bob();
    let mut r = ring(&*remote);
    r.log[1].signature = String::new();
    assert!(r.verify().unwrap_err().contains("bad signature"));
    assert!(matches!(alice.repo.keys().merge_ring(&r).unwrap(), RingMerge::Rejected(_)));
    // Downgrading to an unsigned legacy ring that lists extra members is
    // also refused.
    let mut legacy = serde_json::json!({"scope": "team", "key_id": "", "members": {}});
    legacy["members"][Identity::generate("m").public_hex()] =
        serde_json::to_value(veil_core::keychain::RingMember {
            name: "mallory".into(),
            wrapped: veil_core::identity::wrap_key_legacy(&[9u8; 32], &[1u8; 32], "team").unwrap(),
        })
        .unwrap();
    let legacy: KeyRing = serde_json::from_value(legacy).unwrap();
    assert!(matches!(alice.repo.keys().merge_ring(&legacy).unwrap(), RingMerge::Rejected(_)));
    assert_eq!(members(&alice.repo), vec!["alice", "bob"]);
}

// ---- backward compatibility ----------------------------------------------

#[test]
fn legacy_rings_and_envelopes_keep_working_and_upgrade_on_first_change() {
    use veil_core::{
        crypto::{random_key, Envelope},
        identity::wrap_key_legacy as wrap_key,
        keychain::{key_fingerprint, RingMember},
        object::Object,
    };
    // Build a repository the way the previous format did: an unsigned ring
    // and a blob sealed under the bare scope label.
    let fs = Arc::new(MemoryBackend::new());
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let repo = Repo::init_for_clone(fs.clone(), Some(alice.clone()), "alice").unwrap();
    let key = random_key();
    let mut legacy = KeyRing {
        scope: "team".into(),
        key_id: key_fingerprint(&key),
        ..Default::default()
    };
    for who in [&alice, &bob] {
        legacy.members.insert(
            who.public_hex(),
            RingMember {
                name: who.name.clone(),
                wrapped: wrap_key(&who.public_key(), &key, "team").unwrap(),
            },
        );
    }
    repo.keys().save_ring(&legacy).unwrap();
    let blob = Object::Blob(b"old secret".to_vec());
    let sealed = Object::Sealed(Envelope::seal_deterministic_legacy(&key, "team", &blob.encode()).unwrap());
    let old_id = repo.store().put(&sealed).unwrap();
    assert_eq!(repo.store().read_blob(&old_id).unwrap(), b"old secret");
    assert!(repo.keys().is_member("team"));

    // Revoking Bob upgrades the ring to a signed log; the legacy content is
    // still readable (bare label = generation 0) and Bob is out.
    assert!(repo.keys().revoke("team", &bob.public_hex()).unwrap());
    let r = repo.keys().load_ring("team").unwrap().unwrap();
    assert!(!r.is_legacy());
    assert_eq!(r.log.len(), 2);
    assert_eq!(members(&repo), vec!["alice"]);
    assert_eq!(repo.store().read_blob(&old_id).unwrap(), b"old secret");
    let (label, _) = repo.keys().sealing_key("team").unwrap();
    assert!(label.starts_with("team#"));

    let bob_keys = Keychain::new(fs.clone(), Some(bob), "x".into());
    assert!(bob_keys.has("team"), "Bob keeps generation 0 (history)");
    assert!(!bob_keys.is_member("team"), "but not the new generation");
}

#[test]
fn embargo_on_a_legacy_ring_upgrades_it_so_the_record_is_attributable() {
    use veil_core::{crypto::random_key, identity::wrap_key_legacy as wrap_key, keychain::{key_fingerprint, RingMember}};
    let fs = Arc::new(MemoryBackend::new());
    let alice = Identity::generate("alice");
    let repo = Repo::init_for_clone(fs, Some(alice.clone()), "alice").unwrap();
    let key = random_key();
    let mut legacy = KeyRing {
        scope: "team".into(),
        key_id: key_fingerprint(&key),
        ..Default::default()
    };
    legacy.members.insert(
        alice.public_hex(),
        RingMember {
            name: "alice".into(),
            wrapped: wrap_key(&alice.public_key(), &key, "team").unwrap(),
        },
    );
    repo.keys().save_ring(&legacy).unwrap();
    let id = repo.keys().create_embargo("team", Some(1)).unwrap();
    assert!(!repo.keys().load_ring("team").unwrap().unwrap().is_legacy());
    let rec = repo.keys().load_embargo(&id).unwrap().unwrap();
    assert!(repo.keys().embargo_trusted(&rec));
}
