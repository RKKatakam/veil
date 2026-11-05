//! The team vault (`vl secret --scope`): sealed, signed records shared with
//! a scope's members through team remotes, last-signed-write-wins merging,
//! revocation, rotation, and what never leaves (public remotes, Git).

use crate::adversarial_support;
use crate::sftp_support;

use std::sync::Arc;

use adversarial_support::backend_contains;
use veil_core::{
    fsck, remote,
    team_vault::{IgnoredReason, VaultRecord, MAX_CLOCK_SKEW_MS, TEAM_VAULT_DIR},
    Identity, MemoryBackend, Repo, StorageBackend, VPath,
};

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

fn clone_of(name: &str, remote: &Arc<MemoryBackend>) -> Peer {
    let fs = Arc::new(MemoryBackend::new());
    let id = Identity::generate(name);
    clone_as(id, fs, remote)
}

fn clone_as(id: Identity, fs: Arc<MemoryBackend>, remote: &Arc<MemoryBackend>) -> Peer {
    let mut repo = Repo::init_for_clone(fs.clone(), Some(id.clone()), &id.name).unwrap();
    remote::pull(&mut repo, "origin", remote.clone()).unwrap();
    Peer { repo, fs, id }
}

fn push(p: &mut Peer, remote: &Arc<MemoryBackend>) -> remote::SyncReport {
    remote::push(&mut p.repo, remote.clone(), false, &[], false).unwrap()
}

fn push_public(p: &mut Peer, remote: &Arc<MemoryBackend>) -> remote::SyncReport {
    remote::push(&mut p.repo, remote.clone(), true, &[], false).unwrap()
}

fn pull(p: &mut Peer, remote: &Arc<MemoryBackend>) -> remote::SyncReport {
    remote::pull(&mut p.repo, "origin", remote.clone()).unwrap()
}

fn set(p: &Peer, name: &str, value: &str) {
    p.repo.keys().team_secret_write("team", name, Some(value)).unwrap();
}

fn get(p: &Peer, name: &str) -> Option<String> {
    p.repo.keys().team_vault("team").unwrap().get(name).and_then(|e| e.value.clone())
}

fn record_files(fs: &dyn StorageBackend, scope: &str) -> Vec<String> {
    let dir = VPath::new(&format!("{TEAM_VAULT_DIR}/{scope}")).unwrap();
    if !fs.exists(&dir).unwrap() {
        return vec![];
    }
    fs.list_dir(&dir).unwrap().into_iter().map(|e| e.name).collect()
}

/// Alice (admin) and Bob (member) share `team` through `remote`.
fn team() -> (Peer, Peer, Arc<MemoryBackend>) {
    let mut alice = peer("alice");
    let remote = Arc::new(MemoryBackend::new());
    let bob_id = Identity::generate("bob");
    alice.repo.keys().grant("team", &bob_id.public_id(), "bob").unwrap();
    push(&mut alice, &remote);
    let bob = clone_as(bob_id, Arc::new(MemoryBackend::new()), &remote);
    (alice, bob, remote)
}

fn plant(fs: &dyn StorageBackend, rec: &VaultRecord) {
    fs.write(&rec.path().unwrap(), &rec.to_bytes()).unwrap();
}

#[test]
fn set_get_list_rm_round_trip_and_names_are_sealed() {
    let alice = peer("alice");
    set(&alice, "STRIPE_LIVE_KEY", "sk_live_round_trip_value");
    set(&alice, "DATABASE_URL", "postgres://u:p@h/db");
    assert_eq!(get(&alice, "STRIPE_LIVE_KEY").as_deref(), Some("sk_live_round_trip_value"));
    let v = alice.repo.keys().team_vault("team").unwrap();
    let names: Vec<&str> = v.live().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["DATABASE_URL", "STRIPE_LIVE_KEY"]);
    assert_eq!(v.get("STRIPE_LIVE_KEY").unwrap().signer_name, "alice");
    // Neither name nor value is anywhere in plaintext.
    for needle in ["STRIPE_LIVE_KEY", "sk_live_round_trip_value", "DATABASE_URL", "postgres://"] {
        assert!(backend_contains(&*alice.fs, needle.as_bytes()).is_empty(), "{needle} in plaintext");
    }
    // Delete: a signed tombstone; deleting again is NotFound.
    alice.repo.keys().team_secret_write("team", "DATABASE_URL", None).unwrap();
    assert_eq!(get(&alice, "DATABASE_URL"), None);
    assert!(alice
        .repo
        .keys()
        .team_secret_write("team", "DATABASE_URL", None)
        .unwrap_err()
        .is_not_found());
    // Overwrites by the same writer are compacted: one record per name.
    for i in 0..5 {
        set(&alice, "STRIPE_LIVE_KEY", &format!("v{i}"));
    }
    assert_eq!(get(&alice, "STRIPE_LIVE_KEY").as_deref(), Some("v4"));
    assert_eq!(record_files(&*alice.fs, "team").len(), 2);
    // fsck is happy with the vault directory.
    let report = fsck::fsck_repo(&alice.repo).unwrap();
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    // A damaged record is reported (and still never counts).
    alice
        .fs
        .write(&VPath::new(&format!("{TEAM_VAULT_DIR}/team/{}.json", "b".repeat(64))).unwrap(), b"{}")
        .unwrap();
    let report = fsck::fsck_repo(&alice.repo).unwrap();
    assert!(report.is_ok());
    assert_eq!(report.count(fsck::Severity::Warning), 1, "{:?}", report.findings);
}

#[test]
fn names_and_values_are_validated() {
    let alice = peer("alice");
    let k = alice.repo.keys();
    for bad in ["", "1ABC", "A=B", "A B", "\u{1b}[31m", "Ä", &"A".repeat(200)] {
        assert!(k.team_secret_write("team", bad, Some("v")).is_err(), "{bad:?} accepted");
    }
    assert!(k.team_secret_write("team", "A", Some("nul\0byte")).is_err());
    assert!(k.team_secret_write("team", "A", Some(&"x".repeat(70_000))).is_err());
    assert!(k.team_secret_write("nosuchscope", "A", Some("v")).is_err());
    assert!(k.team_secret_write("../x", "A", Some("v")).is_err());
}

#[test]
fn padding_hides_value_length() {
    let alice = peer("alice");
    set(&alice, "A", "x");
    set(&alice, "B", &"y".repeat(60));
    let sizes: Vec<u64> = record_files(&*alice.fs, "team")
        .iter()
        .map(|f| alice.fs.read(&VPath::new(&format!("{TEAM_VAULT_DIR}/team/{f}")).unwrap()).unwrap().len() as u64)
        .collect();
    assert_eq!(sizes[0], sizes[1], "a 1-byte and a 60-byte secret give different record sizes");
}

#[test]
fn entries_sync_through_a_team_remote_both_ways() {
    let (mut alice, mut bob, remote) = team();
    set(&alice, "API_TOKEN", "tok-from-alice");
    push(&mut alice, &remote);
    pull(&mut bob, &remote);
    assert_eq!(get(&bob, "API_TOKEN").as_deref(), Some("tok-from-alice"));
    // Bob overwrites and deletes; Alice sees both.
    set(&bob, "API_TOKEN", "tok-from-bob");
    set(&bob, "OTHER", "o");
    bob.repo.keys().team_secret_write("team", "OTHER", None).unwrap();
    push(&mut bob, &remote);
    pull(&mut alice, &remote);
    assert_eq!(get(&alice, "API_TOKEN").as_deref(), Some("tok-from-bob"));
    assert_eq!(get(&alice, "OTHER"), None);
    // The team remote holds ciphertext only.
    for needle in ["API_TOKEN", "tok-from-alice", "tok-from-bob", "OTHER"] {
        assert!(backend_contains(&*remote, needle.as_bytes()).is_empty(), "{needle} on the team remote");
    }
}

#[test]
fn concurrent_writes_converge_on_one_winner() {
    let (mut alice, mut bob, remote) = team();
    set(&alice, "K", "alice-value");
    set(&bob, "K", "bob-value");
    push(&mut alice, &remote);
    push(&mut bob, &remote);
    pull(&mut alice, &remote);
    pull(&mut bob, &remote);
    let a = alice.repo.keys().team_vault("team").unwrap().get("K").unwrap().clone();
    let b = bob.repo.keys().team_vault("team").unwrap().get("K").unwrap().clone();
    assert_eq!(a.record, b.record);
    assert_eq!(a.value, b.value);
    // A write always beats what its writer had seen, whatever the clocks.
    set(&alice, "K", "after-seeing-both");
    let w = alice.repo.keys().team_vault("team").unwrap().get("K").unwrap().clone();
    assert!(w.timestamp > a.timestamp);
    push(&mut alice, &remote);
    pull(&mut bob, &remote);
    assert_eq!(get(&bob, "K").as_deref(), Some("after-seeing-both"));
}

#[test]
fn a_future_dated_member_write_does_not_pin_the_value() {
    let (mut alice, mut bob, remote) = team();
    // Bob stamps a record an hour ahead (a skewed clock).
    let ahead = veil_core::now_millis() + 3_600_000;
    let rec = VaultRecord::seal(bob.repo.keys(), &bob.id, "team", "K", Some("bob-ahead"), 0, ahead).unwrap();
    plant(&*bob.fs, &rec);
    push(&mut bob, &remote);
    pull(&mut alice, &remote);
    assert_eq!(get(&alice, "K").as_deref(), Some("bob-ahead"));
    set(&alice, "K", "alice-later");
    assert_eq!(get(&alice, "K").as_deref(), Some("alice-later"));
    // Beyond the skew limit, a record is refused on sync.
    let far = veil_core::now_millis() + MAX_CLOCK_SKEW_MS + 3_600_000;
    let rec = VaultRecord::seal(bob.repo.keys(), &bob.id, "team", "PINNED", Some("x"), 0, far).unwrap();
    plant(&*remote, &rec);
    let r = pull(&mut alice, &remote);
    assert!(r.warnings.iter().any(|w| w.contains("timestamp out of range")), "{:?}", r.warnings);
    assert_eq!(get(&alice, "PINNED"), None);
}

#[test]
fn non_members_forgeries_and_tampering_are_ignored_on_pull_with_a_warning() {
    let (mut alice, bob, remote) = team();
    set(&alice, "K", "genuine");
    push(&mut alice, &remote);

    // Mallory, who was never a member, holds a copy of the scope key (say,
    // leaked) and writes a record signed with her own key.
    let mallory = Identity::generate("mallory");
    let rec = VaultRecord::seal(bob.repo.keys(), &mallory, "team", "K", Some("mallory-1"), 0, veil_core::now_millis() + 1000).unwrap();
    plant(&*remote, &rec);
    // She claims Bob's member id while signing with her key.
    let mut forged = VaultRecord::seal(bob.repo.keys(), &mallory, "team", "K", Some("mallory-2"), 0, veil_core::now_millis() + 2000).unwrap();
    forged.signature.signer = bob.id.public_hex();
    forged.signature.sig = mallory.sign("vault-entry", &forged.signing_body());
    plant(&*remote, &forged);
    // Bob's genuine record with the value swapped for another record's
    // ciphertext (bad signature).
    let mut tampered = VaultRecord::seal(bob.repo.keys(), &bob.id, "team", "K", Some("bob"), 0, veil_core::now_millis() + 3000).unwrap();
    let other = VaultRecord::seal(bob.repo.keys(), &bob.id, "team", "K", Some("swapped"), 0, 1).unwrap();
    tampered.sealed = other.sealed;
    plant(&*remote, &tampered);
    // A record sealed with a key the ring never had.
    let stranger = peer("stranger");
    let alien = VaultRecord::seal(stranger.repo.keys(), &bob.id, "team", "K", Some("alien"), 0, veil_core::now_millis() + 4000).unwrap();
    plant(&*remote, &alien);
    // A member's record that does not decrypt (ciphertext flipped, re-signed).
    let mut garbled = VaultRecord::seal(bob.repo.keys(), &bob.id, "team", "K", Some("garbled"), 0, veil_core::now_millis() + 5000).unwrap();
    garbled.sealed.ciphertext[3] ^= 1;
    garbled.resign(&bob.id);
    plant(&*remote, &garbled);
    // Junk files.
    remote
        .write(&VPath::new(&format!("{TEAM_VAULT_DIR}/team/{}.json", "0".repeat(64))).unwrap(), b"{not json")
        .unwrap();

    let r = pull(&mut alice, &remote);
    assert_eq!(get(&alice, "K").as_deref(), Some("genuine"), "{:?}", r.warnings);
    let w = r.warnings.join("\n");
    assert!(w.contains("never a member"), "{w}");
    assert!(w.contains("bad signature"), "{w}");
    assert!(w.contains("key generation"), "{w}");
    assert!(w.contains("does not decrypt"), "{w}");
    assert!(w.contains("not a readable record"), "{w}");
    // None of them was imported.
    assert_eq!(record_files(&*alice.fs, "team").len(), 1);
}

#[test]
fn a_record_planted_locally_does_not_count_either() {
    let alice = peer("alice");
    set(&alice, "K", "genuine");
    let mallory = Identity::generate("mallory");
    let rec = VaultRecord::seal(alice.repo.keys(), &mallory, "team", "K", Some("evil"), 0, veil_core::now_millis() + 1000).unwrap();
    plant(&*alice.fs, &rec);
    let v = alice.repo.keys().team_vault("team").unwrap();
    assert_eq!(v.get("K").unwrap().value.as_deref(), Some("genuine"));
    assert!(v.ignored.iter().any(|i| i.reason == IgnoredReason::NotAMember));
    // Moved to another scope's directory: refused (label and scope bound).
    alice.repo.keys().create_scope("ops").unwrap();
    let rec = VaultRecord::seal(alice.repo.keys(), &alice.id, "team", "MOVED", Some("x"), 0, 1).unwrap();
    alice
        .fs
        .write(&VPath::new(&format!("{TEAM_VAULT_DIR}/ops/{}.json", rec.id())).unwrap(), &rec.to_bytes())
        .unwrap();
    let ops = alice.repo.keys().team_vault("ops").unwrap();
    assert!(ops.entries.is_empty());
    assert!(matches!(ops.ignored[0].reason, IgnoredReason::Malformed(_)));
    // Renamed (id mismatch) or re-encoded (not canonical): refused.
    let rec = VaultRecord::seal(alice.repo.keys(), &alice.id, "team", "RENAMED", Some("x"), 0, 1).unwrap();
    let mut pretty = serde_json::to_vec_pretty(&rec).unwrap();
    alice
        .fs
        .write(&VPath::new(&format!("{TEAM_VAULT_DIR}/team/{}.json", "a".repeat(64))).unwrap(), &rec.to_bytes())
        .unwrap();
    pretty.push(b'\n');
    alice.fs.write(&rec.path().unwrap(), &pretty).unwrap();
    assert_eq!(get(&alice, "RENAMED"), None);
}

#[test]
fn newer_record_formats_are_skipped_not_misread() {
    let alice = peer("alice");
    let mut rec = VaultRecord::seal(alice.repo.keys(), &alice.id, "team", "NEW", Some("x"), 0, 1).unwrap();
    rec.format = 2;
    rec.resign(&alice.id);
    plant(&*alice.fs, &rec);
    let v = alice.repo.keys().team_vault("team").unwrap();
    assert!(v.entries.is_empty());
    assert!(matches!(&v.ignored[0].reason, IgnoredReason::Malformed(w) if w.contains("newer vl")));
}

#[test]
fn revocation_reports_exposed_keys_and_stops_counting_their_writes() {
    let (mut alice, mut bob, remote) = team();
    set(&alice, "BY_ALICE", "a1");
    set(&bob, "BY_BOB", "b1");
    set(&bob, "DELETED_BY_BOB", "d1");
    push(&mut bob, &remote);
    pull(&mut alice, &remote);
    alice.repo.keys().team_secret_write("team", "DELETED_BY_BOB", None).unwrap();
    // Bob deletes Alice's entry.
    set(&alice, "TO_BE_DELETED", "t1");
    push(&mut alice, &remote);
    pull(&mut bob, &remote);
    bob.repo.keys().team_secret_write("team", "TO_BE_DELETED", None).unwrap();
    push(&mut bob, &remote);
    pull(&mut alice, &remote);
    assert_eq!(get(&alice, "TO_BE_DELETED"), None);

    let report = alice
        .repo
        .keys()
        .revoke_with_vault("team", &bob.id.public_id())
        .unwrap()
        .unwrap();
    assert_eq!(report.exposed, ["BY_ALICE", "BY_BOB"]);
    assert_eq!(report.adopted, ["BY_BOB"]);
    assert!(report.warning.is_none());
    // Bob's value and Bob's deletion both still stand, now signed by Alice
    // under the new generation.
    assert_eq!(get(&alice, "BY_BOB").as_deref(), Some("b1"));
    assert_eq!(get(&alice, "TO_BE_DELETED"), None);
    let e = alice.repo.keys().team_vault("team").unwrap().get("BY_BOB").unwrap().clone();
    assert_eq!((e.signer_name.as_str(), e.generation, e.since), ("alice", 1, 0));
    // Re-signing does not hide the exposure; a new value does.
    let exposed = |a: &Peer| -> Vec<String> {
        let (_, _, es) = a.repo.keys().team_vault_exposed_to("team", "bob").unwrap();
        es.into_iter().map(|e| e.name).collect()
    };
    assert_eq!(exposed(&alice), ["BY_ALICE", "BY_BOB"]);
    set(&alice, "BY_ALICE", "rotated");
    set(&alice, "NEW_AFTER", "n");
    assert_eq!(exposed(&alice), ["BY_BOB"]);
    // Re-setting the same (still exposed) value keeps it exposed.
    set(&alice, "BY_BOB", "b1");
    assert_eq!(exposed(&alice), ["BY_BOB"]);
    push(&mut alice, &remote);

    // Bob, revoked, keeps writing with his old signing key: ignored by
    // everyone. He no longer holds the current generation...
    pull(&mut bob, &remote);
    assert!(bob.repo.keys().team_secret_write("team", "BY_ALICE", Some("x")).is_err());
    // ...but even with it (leaked to him), his write would not count...
    let rec = VaultRecord::seal(alice.repo.keys(), &bob.id, "team", "BY_ALICE", Some("bob-injected"), 0, veil_core::now_millis() + 60_000);
    plant(&*remote, &rec.unwrap());
    // ...and neither does one under generation 0, which he still holds.
    let old = generation_zero_record(&bob, "BY_ALICE", "bob-old-gen");
    plant(&*remote, &old);
    let r = pull(&mut alice, &remote);
    assert_eq!(get(&alice, "BY_ALICE").as_deref(), Some("rotated"));
    assert!(r.warnings.iter().any(|w| w.contains("no longer a member")), "{:?}", r.warnings);
    // A teammate who clones later agrees.
    let carol_id = Identity::generate("carol");
    alice.repo.keys().grant("team", &carol_id.public_id(), "carol").unwrap();
    push(&mut alice, &remote);
    let carol = clone_as(carol_id, Arc::new(MemoryBackend::new()), &remote);
    assert_eq!(get(&carol, "BY_ALICE").as_deref(), Some("rotated"));
    assert_eq!(get(&carol, "BY_BOB").as_deref(), Some("b1"));
    assert_eq!(get(&carol, "TO_BE_DELETED"), None);
    // Bob can no longer read the vault through vl.
    assert!(bob.repo.keys().team_vault("team").is_err());
}

/// A record by `p` sealed under generation 0 of `team` (which a revoked
/// member still holds), stamped well in the future, built by hand.
fn generation_zero_record(p: &Peer, name: &str, value: &str) -> VaultRecord {
    let keys = p.repo.keys();
    let st = keys.ring_state("team").unwrap().unwrap().unwrap();
    let kid = &st.generations[0];
    let key = keys.key(&format!("team#{kid}")).unwrap();
    let pt = serde_json::to_vec(&serde_json::json!({ "name": name, "value": value, "since": 0 })).unwrap();
    let sealed = veil_core::crypto::Envelope::seal_random(&key, &format!("vault:team#{kid}"), &pt).unwrap();
    let mut rec: VaultRecord = serde_json::from_value(serde_json::json!({
        "format": 1, "scope": "team", "sealed": sealed, "timestamp": veil_core::now_millis() + 120_000,
        "signature": { "signer": p.id.public_hex(), "key": p.id.verifying_hex(), "sig": "" }
    }))
    .unwrap();
    rec.resign(&p.id);
    rec
}

#[test]
fn exposure_of_a_member_who_joined_late_and_a_stranger() {
    let (alice, _bob, _remote) = team();
    set(&alice, "OLD", "o");
    alice.repo.keys().rotate("team").unwrap();
    set(&alice, "NEW", "n");
    let carol = Identity::generate("carol");
    alice.repo.keys().grant("team", &carol.public_id(), "carol").unwrap();
    // A member reads every generation back to 0.
    let (_, _, es) = alice.repo.keys().team_vault_exposed_to("team", &carol.public_id()).unwrap();
    assert_eq!(es.len(), 2);
    alice.repo.keys().revoke("team", &carol.public_id()).unwrap();
    set(&alice, "AFTER_CAROL", "x");
    let (_, name, es) = alice.repo.keys().team_vault_exposed_to("team", "carol").unwrap();
    assert_eq!(name, "carol");
    assert_eq!(es.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["NEW", "OLD"]);
    assert!(alice
        .repo
        .keys()
        .team_vault_exposed_to("team", &Identity::generate("x").public_id())
        .is_err());
    assert!(alice.repo.keys().team_vault_exposed_to("team", "nobody").is_err());
}

#[test]
fn rotation_new_writes_use_the_new_generation_old_entries_stay_readable() {
    let (mut alice, mut bob, remote) = team();
    set(&alice, "OLD", "old-value");
    alice.repo.keys().rotate("team").unwrap();
    set(&alice, "NEW", "new-value");
    let v = alice.repo.keys().team_vault("team").unwrap();
    assert_eq!(v.get("OLD").unwrap().generation, 0);
    assert_eq!(v.get("NEW").unwrap().generation, 1);
    // Re-sealed on the next write.
    set(&alice, "OLD", "old-value");
    let e = alice.repo.keys().team_vault("team").unwrap().get("OLD").unwrap().clone();
    assert_eq!((e.generation, e.since), (1, 0));
    push(&mut alice, &remote);
    pull(&mut bob, &remote);
    assert_eq!(get(&bob, "NEW").as_deref(), Some("new-value"));
    assert_eq!(get(&bob, "OLD").as_deref(), Some("old-value"));
    // Bob writes under generation 1 too.
    set(&bob, "BOBS", "b");
    assert_eq!(bob.repo.keys().team_vault("team").unwrap().get("BOBS").unwrap().generation, 1);
}

#[test]
fn non_members_and_members_without_a_signing_key_cannot_write() {
    let (mut alice, _bob, remote) = team();
    let outsider = clone_of("outsider", &remote);
    assert!(outsider.repo.keys().team_secret_write("team", "K", Some("v")).is_err());
    assert!(outsider.repo.keys().team_vault("team").is_err());
    // Granted by the short member id: can read, cannot write.
    let short = Identity::generate("short");
    alice.repo.keys().grant("team", &short.public_hex(), "short").unwrap();
    set(&alice, "K", "v");
    push(&mut alice, &remote);
    let s = clone_as(short, Arc::new(MemoryBackend::new()), &remote);
    assert_eq!(get(&s, "K").as_deref(), Some("v"));
    let err = s.repo.keys().team_secret_write("team", "K", Some("w")).unwrap_err().to_string();
    assert!(err.contains("signing key"), "{err}");
}

#[test]
fn a_non_member_relays_records_it_cannot_read() {
    let (mut alice, mut bob, remote) = team();
    set(&alice, "K", "relayed");
    push(&mut alice, &remote);
    // An outsider clones the team remote and pushes everything to another
    // team remote, from which Bob pulls.
    let mut relay = clone_of("relay", &remote);
    assert_eq!(record_files(&*relay.fs, "team").len(), 1);
    let second = Arc::new(MemoryBackend::new());
    push(&mut relay, &second);
    pull(&mut bob, &second);
    assert_eq!(get(&bob, "K").as_deref(), Some("relayed"));
}

#[test]
fn compaction_on_push_never_changes_the_vault() {
    let (mut alice, mut bob, remote) = team();
    set(&bob, "K", "bob-1");
    push(&mut bob, &remote);
    pull(&mut alice, &remote);
    for i in 0..4 {
        set(&alice, "K", &format!("alice-{i}"));
    }
    push(&mut alice, &remote);
    // One record per (name, writer) on the remote: Bob's and Alice's last.
    assert_eq!(record_files(&*remote, "team").len(), 2);
    // Whoever is revoked later, every replica (compacted or not) agrees.
    let fresh = clone_of("fresh", &remote);
    alice.repo.keys().revoke("team", &bob.id.public_id()).unwrap();
    assert_eq!(get(&alice, "K").as_deref(), Some("alice-3"));
    push(&mut alice, &remote);
    let mut alice2 = clone_as(alice.id.clone(), Arc::new(MemoryBackend::new()), &remote);
    assert_eq!(get(&alice2, "K").as_deref(), Some("alice-3"));
    pull(&mut alice2, &remote);
    drop(fresh);
}

// ---- what never leaves ------------------------------------------------------

const SECRET_NAME: &str = "STRIPE_LIVE_KEY_TEAMVAULT_CANARY";
const SECRET_VALUE: &str = "sk_live_9f8e7d6c5b4a3210_TEAMVAULT_CANARY";

#[test]
fn the_vault_never_reaches_a_public_remote() {
    let mut alice = peer("alice");
    let commit = adversarial_support::commit_files(&mut alice.repo, &*alice.fs, &[("README", "hello\n")], "c");
    alice.repo.set_tag("main", commit, None, false).unwrap();
    set(&alice, SECRET_NAME, SECRET_VALUE);
    alice.repo.keys().create_scope("ops").unwrap();
    alice.repo.keys().team_secret_write("ops", "OPS_ONLY_NAME_CANARY", Some("ops-value-canary")).unwrap();
    let public = Arc::new(MemoryBackend::new());
    let r = push_public(&mut alice, &public);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    for needle in [SECRET_NAME, SECRET_VALUE, "OPS_ONLY_NAME_CANARY", "ops-value-canary"] {
        assert!(backend_contains(&*public, needle.as_bytes()).is_empty(), "{needle} on the public remote");
    }
    assert!(record_files(&*public, "team").is_empty());
    assert!(!public.exists(&VPath::new(TEAM_VAULT_DIR).unwrap()).unwrap());
    // Also after a gc packs everything, and a second push.
    veil_core::gc::gc(&mut alice.repo, &veil_core::gc::GcOptions::default()).ok();
    push_public(&mut alice, &public);
    assert!(!public.exists(&VPath::new(TEAM_VAULT_DIR).unwrap()).unwrap());
    // A public remote that holds records (planted, or a team remote added
    // as public by mistake) is flagged, and never fed more.
    let rec = VaultRecord::seal(alice.repo.keys(), &alice.id, "team", "X", Some("y"), 0, 1).unwrap();
    plant(&*public, &rec);
    let r = push_public(&mut alice, &public);
    assert!(r.warnings.iter().any(|w| w.contains("team-vault record")), "{:?}", r.warnings);
    assert_eq!(record_files(&*public, "team").len(), 1);
}

#[test]
fn entries_sync_over_sftp_and_the_remote_holds_ciphertext_only() {
    let Some(server) = sftp_support::server() else { return };
    let dir = tempfile::tempdir().unwrap();
    let sftp = |root: &std::path::Path| -> Arc<dyn StorageBackend> { Arc::new(sftp_support::connect(&server, root)) };
    let mut alice = peer("alice");
    let bob_id = Identity::generate("bob");
    alice.repo.keys().grant("team", &bob_id.public_id(), "bob").unwrap();
    set(&alice, SECRET_NAME, SECRET_VALUE);
    remote::push(&mut alice.repo, sftp(dir.path()), false, &[], false).unwrap();
    let mut bob = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(bob_id.clone()), "bob").unwrap();
    remote::pull(&mut bob, "origin", sftp(dir.path())).unwrap();
    assert_eq!(
        bob.keys().team_vault("team").unwrap().get(SECRET_NAME).unwrap().value.as_deref(),
        Some(SECRET_VALUE)
    );
    bob.keys().team_secret_write("team", SECRET_NAME, None).unwrap();
    remote::push(&mut bob, sftp(dir.path()), false, &[], false).unwrap();
    remote::pull(&mut alice.repo, "origin", sftp(dir.path())).unwrap();
    assert_eq!(get(&alice, SECRET_NAME), None);
    let disk = veil_core::DiskBackend::new(dir.path());
    assert_eq!(record_files(&disk, "team").len(), 2);
    for needle in [SECRET_NAME, SECRET_VALUE] {
        assert!(backend_contains(&disk, needle.as_bytes()).is_empty(), "{needle} on the SFTP remote");
    }
    let r = fsck::fsck(Arc::new(disk), None).unwrap();
    assert!(r.is_ok(), "{:?}", r.findings);
}

// ---- round-8 vault wave ---------------------------------------------------

fn records_on(fs: &dyn StorageBackend, scope: &str) -> Vec<VaultRecord> {
    let dir = VPath::new(&format!("{TEAM_VAULT_DIR}/{scope}")).unwrap();
    if !fs.exists(&dir).unwrap() {
        return vec![];
    }
    fs.list_dir(&dir)
        .unwrap()
        .into_iter()
        .filter_map(|e| serde_json::from_slice(&fs.read(&dir.join(&e.name)).ok()?).ok())
        .collect()
}

/// Alice and Bob as in [`team`], plus Carol (member) who cloned while Bob
/// was still a member; then Alice revokes Bob and pushes. Carol has not
/// pulled since.
fn revoked_bob_and_stale_carol() -> (Peer, Peer, Peer, Arc<MemoryBackend>) {
    let (mut alice, mut bob, remote) = team();
    let carol_id = Identity::generate("carol");
    alice.repo.keys().grant("team", &carol_id.public_id(), "carol").unwrap();
    set(&alice, "OLD", "old-value");
    push(&mut alice, &remote);
    let carol = clone_as(carol_id, Arc::new(MemoryBackend::new()), &remote);
    pull(&mut bob, &remote);
    alice.repo.keys().revoke_with_vault("team", &bob.id.public_id()).unwrap().unwrap();
    push(&mut alice, &remote);
    (alice, bob, carol, remote)
}

/// BUG-524: a write made with a stale ring is re-sealed under the current
/// generation by the push, so the revoked member never gets it, and the
/// pusher's ring catches up.
#[test]
fn a_stale_writers_push_reseals_under_the_current_generation() {
    let (mut alice, mut bob, mut carol, remote) = revoked_bob_and_stale_carol();
    set(&carol, "NEW", "fresh-after-revocation");
    assert_eq!(carol.repo.keys().team_vault("team").unwrap().get("NEW").unwrap().generation, 0);
    let r = push(&mut carol, &remote);
    assert!(r.warnings.iter().any(|w| w.contains("re-sealed") && w.contains("NEW")), "{:?}", r.warnings);
    // Carol's ring caught up, and her own copy moved to generation 1.
    assert_eq!(carol.repo.keys().ring_state("team").unwrap().unwrap().unwrap().generation, 1);
    assert_eq!(carol.repo.keys().team_vault("team").unwrap().get("NEW").unwrap().generation, 1);
    // Bob's generation-0 key opens none of Carol's records on the remote.
    pull(&mut bob, &remote);
    let kid0 = alice.repo.keys().ring_state("team").unwrap().unwrap().unwrap().generations[0].clone();
    let key0 = bob.repo.keys().key(&format!("team#{kid0}")).unwrap();
    for rec in records_on(&*remote, "team").iter().filter(|r| r.signature.signer == carol.id.public_hex()) {
        assert!(rec.sealed.open(&key0).is_err(), "Bob can read a record Carol wrote after his revocation");
    }
    let r = pull(&mut alice, &remote);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    let e = alice.repo.keys().team_vault("team").unwrap().get("NEW").cloned().unwrap();
    assert_eq!((e.value.as_deref(), e.generation, e.stale_generation), (Some("fresh-after-revocation"), 1, false));
}

/// BUG-524: a record that reaches the remote sealed under the old
/// generation anyway (an older vl pushed it, or it came by another path) is
/// flagged by name on pull, marked in the vault, and counted as exposed,
/// until someone sets it again.
#[test]
fn a_record_sealed_late_under_an_old_generation_is_flagged_on_pull() {
    let (mut alice, bob, carol, remote) = revoked_bob_and_stale_carol();
    let late = VaultRecord::seal(carol.repo.keys(), &carol.id, "team", "LATE", Some("v"), 0, veil_core::now_millis()).unwrap();
    plant(&*remote, &late);
    let r = pull(&mut alice, &remote);
    assert!(
        r.warnings.iter().any(|w| w.contains("LATE") && w.contains("generation 0") && w.contains("vl secret set --scope team")),
        "{:?}",
        r.warnings
    );
    let e = alice.repo.keys().team_vault("team").unwrap().get("LATE").cloned().unwrap();
    assert!(e.stale_generation);
    // An old value that was simply never re-sealed is not "late".
    assert!(!alice.repo.keys().team_vault("team").unwrap().get("OLD").unwrap().stale_generation);
    let (_, _, exposed) = alice.repo.keys().team_vault_exposed_to("team", &bob.id.public_id()).unwrap();
    assert!(exposed.iter().any(|e| e.name == "LATE"));
    set(&alice, "LATE", "v");
    let e = alice.repo.keys().team_vault("team").unwrap().get("LATE").cloned().unwrap();
    assert_eq!((e.generation, e.stale_generation), (1, false));
}

/// BUG-522: push says which records it does not send, instead of reporting
/// success silently.
#[test]
fn push_reports_the_records_it_does_not_send() {
    let (mut alice, _bob, remote) = team();
    let far = veil_core::now_millis() + 2 * MAX_CLOCK_SKEW_MS;
    let rec = VaultRecord::seal(alice.repo.keys(), &alice.id, "team", "AHEAD", Some("x"), 0, far).unwrap();
    plant(&*alice.fs, &rec);
    let r = push(&mut alice, &remote);
    assert!(r.warnings.iter().any(|w| w.contains("1 record(s) not copied") && w.contains("ahead")), "{:?}", r.warnings);
}

/// BUG-522: a write of a name whose own earlier record was stamped far
/// ahead replaces it (here and, on the next push, on the remote), instead
/// of being stamped after it.
#[test]
fn a_record_stamped_far_ahead_is_replaced_by_the_next_write_everywhere() {
    let (mut alice, mut bob, remote) = team();
    let far = veil_core::now_millis() + 2 * MAX_CLOCK_SKEW_MS;
    let glitch = VaultRecord::seal(alice.repo.keys(), &alice.id, "team", "API_KEY", Some("glitch"), 0, far).unwrap();
    // Pushed while the clock was wrong: it is on the remote too.
    plant(&*alice.fs, &glitch);
    plant(&*remote, &glitch);
    let out = alice.repo.keys().team_secret_write("team", "API_KEY", Some("rotated")).unwrap();
    assert!(out.notes.iter().any(|n| n.contains("replaces")), "{:?}", out.notes);
    let mine = alice.repo.keys().team_vault("team").unwrap().get("API_KEY").cloned().unwrap();
    assert_eq!(mine.value.as_deref(), Some("rotated"));
    assert!(mine.timestamp <= veil_core::now_millis());
    let r = push(&mut alice, &remote);
    assert!(r.warnings.iter().any(|w| w.contains("removed 1")), "{:?}", r.warnings);
    assert!(!records_on(&*remote, "team").contains(&glitch));
    pull(&mut bob, &remote);
    assert_eq!(get(&bob, "API_KEY").as_deref(), Some("rotated"));
    // Someone else's winning write that far ahead: an error, not a write
    // that silently loses or is pinned out of the window.
    let bobs = VaultRecord::seal(bob.repo.keys(), &bob.id, "team", "PINNED", Some("b"), 0, far).unwrap();
    plant(&*alice.fs, &bobs);
    let err = alice.repo.keys().team_secret_write("team", "PINNED", Some("a")).unwrap_err().to_string();
    assert!(err.contains("ahead of this device's clock"), "{err}");
}

/// BUG-523: a scope's live entries are capped in total, so `vl run` can
/// always pass them to a command; a write that shrinks the vault is fine.
#[test]
fn a_scope_vault_is_capped_in_total() {
    let alice = peer("alice");
    let big = "x".repeat(64_000);
    for i in 0..4 {
        set(&alice, &format!("BLOB_{i}"), &big);
    }
    let err = alice.repo.keys().team_secret_write("team", "BLOB_4", Some(&big)).unwrap_err().to_string();
    assert!(err.contains("scope 'team'") && err.contains("KiB"), "{err}");
    set(&alice, "BLOB_0", "small");
    set(&alice, "BLOB_4", &big);
}

/// BUG-521: the exposure the writer's device remembers travels in the
/// record, so a teammate's `--exposed-to` agrees.
#[test]
fn going_back_to_a_leaked_value_is_exposed_on_every_replica() {
    let (mut alice, bob, mut carol, remote) = revoked_bob_and_stale_carol();
    pull(&mut carol, &remote);
    set(&alice, "OLD", "rotated");
    set(&alice, "OLD", "old-value");
    let out_rec = alice.repo.keys().team_vault("team").unwrap().get("OLD").cloned().unwrap();
    assert_eq!(out_rec.since, 0);
    push(&mut alice, &remote);
    pull(&mut carol, &remote);
    let (_, _, exposed) = carol.repo.keys().team_vault_exposed_to("team", &bob.id.public_id()).unwrap();
    assert_eq!(exposed.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["OLD"]);
}

/// BUG-524: records written *before* a rotation are pushed as they are to a
/// new team remote (nothing to re-seal, no warning).
#[test]
fn old_records_reach_a_new_remote_unchanged() {
    let (mut alice, _bob, remote) = team();
    set(&alice, "OLD", "v");
    let before = records_on(&*alice.fs, "team");
    alice.repo.keys().rotate("team").unwrap();
    push(&mut alice, &remote);
    let fresh = Arc::new(MemoryBackend::new());
    let r = push(&mut alice, &fresh);
    assert!(!r.warnings.iter().any(|w| w.contains("re-sealed")), "{:?}", r.warnings);
    let on_fresh = records_on(&*fresh, "team");
    assert!(before.iter().all(|b| on_fresh.contains(b)), "the old record reached the new remote as it was");
}
