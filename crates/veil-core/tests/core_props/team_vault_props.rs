//! Property: the team vault converges. Members write and delete names, and
//! push and pull through a team remote in a random order (every write
//! compacts the writer's replica, every push the remote); a revocation may
//! happen in between. Once everyone has pulled, every replica reads the
//! same entries, and they equal what the full, never-compacted set of
//! records gives.

use std::{collections::BTreeMap, sync::Arc};

use proptest::prelude::*;
use veil_core::{remote, Identity, MemoryBackend, Repo, StorageBackend, VPath};

#[derive(Clone, Debug)]
enum Step {
    Write { who: usize, name: usize, value: Option<u8> },
    Push(usize),
    Pull(usize),
    RevokeLast,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => (0..3usize, 0..3usize, proptest::option::weighted(0.8, 0..4u8))
            .prop_map(|(who, name, value)| Step::Write { who, name, value }),
        2 => (0..3usize).prop_map(Step::Push),
        2 => (0..3usize).prop_map(Step::Pull),
        1 => Just(Step::RevokeLast),
    ]
}

fn state(repo: &Repo) -> BTreeMap<String, Option<String>> {
    repo.keys()
        .team_vault("team")
        .unwrap()
        .entries
        .into_values()
        .map(|e| (e.name, e.value))
        .collect()
}

fn copy_records(from: &dyn StorageBackend, to: &dyn StorageBackend) {
    let dir = VPath::new(".veil/meta/vault/team").unwrap();
    if !from.exists(&dir).unwrap() {
        return;
    }
    for e in from.list_dir(&dir).unwrap() {
        let p = dir.join(&e.name);
        to.write(&p, &from.read(&p).unwrap()).unwrap();
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, .. ProptestConfig::default() })]

    #[test]
    fn replicas_converge(steps in proptest::collection::vec(step(), 1..24)) {
        let remote = Arc::new(MemoryBackend::new());
        let ids: Vec<Identity> = ["alice", "bob", "carol"].iter().map(|n| Identity::generate(n)).collect();
        let mut alice = Repo::init(Arc::new(MemoryBackend::new()), Some(ids[0].clone()), "alice").unwrap();
        for id in &ids[1..] {
            alice.keys().grant("team", &id.public_id(), &id.name).unwrap();
        }
        remote::push(&mut alice, remote.clone(), false, &[], false).unwrap();
        let mut repos = vec![alice];
        for id in &ids[1..] {
            let mut r = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(id.clone()), &id.name).unwrap();
            remote::pull(&mut r, "origin", remote.clone()).unwrap();
            repos.push(r);
        }
        // Every record ever written, never compacted.
        let archive = MemoryBackend::new();
        let mut revoked = false;
        let mut carol_knows_revoked = false;
        for s in steps {
            match s {
                Step::Write { who, name, value } => {
                    let key = format!("N{name}");
                    let v = value.map(|v| format!("v{v}-{who}"));
                    if who == 2 && carol_knows_revoked {
                        let res = repos[who].keys().team_secret_write("team", &key, v.as_deref());
                        assert!(res.is_err(), "revoked member wrote team secret: {res:?}");
                    } else {
                        let had = state(&repos[who]).get(&key).and_then(|v| v.as_ref()).is_some();
                        let res = repos[who].keys().team_secret_write("team", &key, v.as_deref());
                        if v.is_none() && !had {
                            assert!(matches!(res, Err(veil_core::VeilError::NotFound(_))), "{res:?}");
                        } else {
                            res.unwrap();
                        }
                    }
                    copy_records(&**repos[who].backend(), &archive);
                }
                Step::Push(who) => {
                    remote::push(&mut repos[who], remote.clone(), false, &[], false).unwrap();
                }
                Step::Pull(who) => {
                    remote::pull(&mut repos[who], "origin", remote.clone()).unwrap();
                    if who == 2 && revoked {
                        carol_knows_revoked = true;
                    }
                }
                Step::RevokeLast if !revoked => {
                    // Alice revokes Carol (re-signing what Carol last set).
                    remote::pull(&mut repos[0], "origin", remote.clone()).unwrap();
                    repos[0].keys().revoke_with_vault("team", &ids[2].public_id()).unwrap();
                    copy_records(&**repos[0].backend(), &archive);
                    remote::push(&mut repos[0], remote.clone(), false, &[], false).unwrap();
                    revoked = true;
                }
                Step::RevokeLast => {}
            }
        }
        // Everyone (still a member) pushes, then everyone pulls.
        let members = if revoked { 2 } else { 3 };
        for r in repos.iter_mut().take(members) {
            remote::push(r, remote.clone(), false, &[], false).unwrap();
        }
        for r in repos.iter_mut().take(members) {
            remote::pull(r, "origin", remote.clone()).unwrap();
        }
        let first = state(&repos[0]);
        for r in repos.iter().take(members).skip(1) {
            prop_assert_eq!(&state(r), &first);
        }
        // The uncompacted archive, read with Alice's rings, agrees.
        let check = Arc::new(MemoryBackend::new());
        let mut full = Repo::init_for_clone(check.clone(), Some(ids[0].clone()), "check").unwrap();
        remote::pull(&mut full, "origin", remote.clone()).unwrap();
        copy_records(&archive, &*check);
        prop_assert_eq!(state(&full), first);
    }
}
