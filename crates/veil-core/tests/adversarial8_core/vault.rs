//! Round 8: the synced team vault (`team_vault.rs`, `sync_meta`), at the
//! engine level, with forged and hand-placed records.

use std::sync::Arc;

use veil_core::{remote, team_vault::VaultRecord, Identity, MemoryBackend, Repo, StorageBackend};

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

fn clone_as(id: Identity, remote: &Arc<MemoryBackend>) -> Peer {
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init_for_clone(fs.clone(), Some(id.clone()), &id.name).unwrap();
    remote::pull(&mut repo, "origin", remote.clone()).unwrap();
    Peer { repo, fs, id }
}

fn push(p: &mut Peer, remote: &Arc<MemoryBackend>) -> remote::SyncReport {
    remote::push(&mut p.repo, remote.clone(), false, &[], false).unwrap()
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

fn plant(fs: &dyn StorageBackend, rec: &VaultRecord) {
    fs.write(&rec.path().unwrap(), &rec.to_bytes()).unwrap();
}

/// Alice (admin) and Bob (member, full key) share `team` through `remote`.
fn team() -> (Peer, Peer, Arc<MemoryBackend>) {
    let mut alice = peer("alice");
    let remote = Arc::new(MemoryBackend::new());
    let bob_id = Identity::generate("bob");
    alice.repo.keys().grant("team", &bob_id.public_id(), "bob").unwrap();
    push(&mut alice, &remote);
    let bob = clone_as(bob_id, &remote);
    (alice, bob, remote)
}

fn exposed_to(p: &Peer, who: &str) -> Vec<String> {
    let (_, _, es) = p.repo.keys().team_vault_exposed_to("team", who).unwrap();
    es.into_iter().map(|e| e.name).collect()
}

// ---- BUG-521: the rotation report forgets a leaked value set again ---------

/// Control: re-setting the *current* leaked value keeps it listed.
#[test]
fn exposure_survives_setting_the_current_value_again() {
    let (alice, bob, _remote) = team();
    set(&alice, "DB_PASSWORD", "p1-leaked");
    alice.repo.keys().revoke_with_vault("team", &bob.id.public_id()).unwrap().unwrap();
    set(&alice, "DB_PASSWORD", "p1-leaked");
    assert_eq!(exposed_to(&alice, "bob"), ["DB_PASSWORD"]);
}

/// Bob could read `p1`. After his revocation Alice rotates to `p2`, then
/// goes back to `p1` (the rotation broke something; or she follows `vl
/// undo`'s "set it again" instructions). The value in use is one Bob holds,
/// yet `--exposed-to bob` no longer lists it: `since` is carried over only
/// from the immediately previous winner, not from the value's history.
#[test]
fn exposure_survives_going_back_to_a_leaked_value() {
    let (alice, bob, _remote) = team();
    set(&alice, "DB_PASSWORD", "p1-leaked");
    set(&alice, "API_TOKEN", "t1-leaked");
    let report = alice.repo.keys().revoke_with_vault("team", &bob.id.public_id()).unwrap().unwrap();
    assert_eq!(report.exposed, ["API_TOKEN", "DB_PASSWORD"]);
    // Rotation, then back to the old value.
    set(&alice, "DB_PASSWORD", "p2-rotated");
    set(&alice, "DB_PASSWORD", "p1-leaked");
    // Deleted, then set back to the old value.
    alice.repo.keys().team_secret_write("team", "API_TOKEN", None).unwrap();
    set(&alice, "API_TOKEN", "t1-leaked");
    assert_eq!(get(&alice, "DB_PASSWORD").as_deref(), Some("p1-leaked"));
    assert_eq!(
        exposed_to(&alice, "bob"),
        ["API_TOKEN", "DB_PASSWORD"],
        "both values in use are ones Bob read before his revocation"
    );
}

// ---- BUG-522: push silently keeps records stamped over a day ahead ---------

/// Alice wrote `API_KEY` while her clock ran two days ahead (a bad RTC, a
/// wrong manual date); the clock is fixed since. Every later write of that
/// name is stamped after the bad one (`max(now, winner + 1)`), so it is "more
/// than a day ahead" too: `push` skips it without a word (`sync` only warns
/// when pulling), reports success, and teammates never receive the
/// rotation. Alice's own vault shows the new value.
#[test]
fn a_rotation_after_a_clock_glitch_reaches_teammates_or_push_says_why() {
    let (mut alice, mut bob, remote) = team();
    set(&alice, "API_KEY", "v1");
    push(&mut alice, &remote);
    pull(&mut bob, &remote);
    assert_eq!(get(&bob, "API_KEY").as_deref(), Some("v1"));
    // Written two days "ahead", by Alice herself, with her own key.
    let ahead = veil_core::now_millis() + 2 * 24 * 3600 * 1000;
    let glitch = VaultRecord::seal(alice.repo.keys(), &alice.id, "team", "API_KEY", Some("v2-glitch"), 0, ahead).unwrap();
    plant(&*alice.fs, &glitch);
    // Clock fixed; v1 leaked, so Alice rotates it, and pushes.
    set(&alice, "API_KEY", "v3-rotated");
    assert_eq!(get(&alice, "API_KEY").as_deref(), Some("v3-rotated"));
    let report = push(&mut alice, &remote);
    pull(&mut bob, &remote);
    let shared = get(&bob, "API_KEY").as_deref() == Some("v3-rotated");
    assert!(
        shared || report.warnings.iter().any(|w| w.contains("timestamp") || w.contains("ahead")),
        "push reported success ({:?}) but Bob still has {:?}",
        report.warnings,
        get(&bob, "API_KEY")
    );
}

// ---- BUG-524: a teammate with a stale ring seals new values for the revoked -

/// Every record of `scope` on `fs`.
fn records(fs: &dyn StorageBackend, scope: &str) -> Vec<VaultRecord> {
    let dir = veil_core::VPath::new(&format!("{}/{scope}", veil_core::team_vault::TEAM_VAULT_DIR)).unwrap();
    if !fs.exists(&dir).unwrap() {
        return vec![];
    }
    fs.list_dir(&dir)
        .unwrap()
        .into_iter()
        .filter_map(|e| serde_json::from_slice(&fs.read(&dir.join(&e.name)).ok()?).ok())
        .collect()
}

/// Alice revokes Bob and pushes. Carol, a member who has not pulled since,
/// stores a *new* secret: her ring still says generation 0 is current, so
/// it is sealed under generation 0, which Bob holds. Her push copies it to
/// the remote (it passes every check against the remote's merged ring),
/// Alice's pull accepts it, and nobody is told that a value first written
/// after the revocation is readable by the revoked member. Push (which
/// merges the remote's ring anyway) should refuse or re-seal it, or warn.
#[test]
fn a_value_written_after_a_revocation_is_not_readable_by_the_revoked_member() {
    let (mut alice, mut bob, remote) = team();
    let carol_id = Identity::generate("carol");
    alice.repo.keys().grant("team", &carol_id.public_id(), "carol").unwrap();
    set(&alice, "OLD", "old");
    push(&mut alice, &remote);
    let mut carol = clone_as(carol_id, &remote);
    pull(&mut bob, &remote);
    let kid0 = alice.repo.keys().ring_state("team").unwrap().unwrap().unwrap().generations[0].clone();

    alice.repo.keys().revoke_with_vault("team", &bob.id.public_id()).unwrap().unwrap();
    push(&mut alice, &remote);
    // Carol has not pulled: she writes a brand-new value and pushes.
    set(&carol, "NEW_AFTER_REVOCATION", "fresh-value-bob-must-not-read");
    let carol_push = push(&mut carol, &remote);
    let alice_pull = pull(&mut alice, &remote);
    assert_eq!(get(&alice, "NEW_AFTER_REVOCATION").as_deref(), Some("fresh-value-bob-must-not-read"));

    // Bob (revoked) still derives the generation-0 key from the ring.
    pull(&mut bob, &remote);
    let key0 = bob.repo.keys().key(&format!("team#{kid0}")).expect("Bob keeps generation 0");
    let bob_reads = records(&*remote, "team")
        .iter()
        .filter(|r| r.signature.signer == carol.id.public_hex())
        .any(|r| r.sealed.open(&key0).is_ok_and(|pt| String::from_utf8_lossy(&pt).contains("fresh-value-bob-must-not-read")));
    let warned = carol_push.warnings.iter().chain(&alice_pull.warnings).any(|w| w.contains("generation") || w.contains("revoked"));
    assert!(
        !bob_reads || warned,
        "the revoked member can decrypt a value first written after his revocation, and nobody was warned \
         (push: {:?}, pull: {:?})",
        carol_push.warnings,
        alice_pull.warnings
    );
}
