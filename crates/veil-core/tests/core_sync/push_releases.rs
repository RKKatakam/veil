//! Pushes and embargo releases through the engine's in-process transfer
//! (`remote::push`): a fix withheld by an unreleased embargo never reaches
//! another repository, whatever is released or taken back before a push;
//! a published fix always arrives with its released record (BUG-807); and
//! concurrent pushers to one repository all land.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    commands::EmbargoSpec,
    fsck::{fsck, Severity},
    remote, Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

const FIX_MARKER: &str = "verify_signature_of_the_embargoed_fix_4c1d";

/// Alice's repository: `main` on a public mirror, then a plaintext fix
/// merged into `main` under an embargo of scope `team`. Returns the repo,
/// its backend, the identity, the mirror, the embargo and the fix.
fn embargoed_fix() -> (Repo, Arc<MemoryBackend>, Identity, Arc<MemoryBackend>, String, ObjectId) {
    let (mut alice, fs, id) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    alice.create_workspace("fix", vec![main]).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), format!("fn check() -> bool {{ {FIX_MARKER}() }}\n").as_bytes()).unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let r = alice
        .merge(WS, main, vec![fix], "merge the fix", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    alice.set_tag("main", r.snapshot, false).unwrap();
    let e = r.embargo.unwrap();
    let withheld = remote::withheld_by_embargo(&alice, &e).unwrap();
    assert!(withheld.contains(&fix) && withheld.contains(&r.snapshot), "control: the merge and the fix are withheld: {withheld:?}");
    (alice, fs, id, mirror, e, fix)
}

/// Is any of the fix's history on `mirror` (published or staged)?
fn fix_reached(mirror: &MemoryBackend, fix: &ObjectId) -> Vec<String> {
    let mut hits = backend_contains(mirror, FIX_MARKER.as_bytes());
    if mirror.exists(&p(&format!(".veil/objects/{}/{}", &fix.hex()[..2], &fix.hex()[2..]))).unwrap() {
        hits.push(format!("loose snapshot {}", fix.short()));
    }
    hits.extend(packed_objects(mirror).into_iter().filter(|(_, raw)| ObjectId::hash(raw) == *fix).map(|(l, _)| l));
    hits
}

/// The invariant behind BUG-807, without the race: whatever a push
/// publishes about an embargo's fix, the remote's record of that embargo
/// says released by the time the operation that references it lands.
#[test]
fn a_published_fix_always_comes_with_its_released_record() {
    let (mut alice, _fs, _id, mirror, e, fix) = embargoed_fix();
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(fix_reached(&mirror, &fix).is_empty(), "control: unreleased, the fix stays here");
    alice.release_embargo(&e).unwrap();
    let rep = remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert_eq!(rep.releases_published, vec![e.clone()]);
    assert!(!fix_reached(&mirror, &fix).is_empty(), "control: released, the fix is pushed");
    let anon = Repo::open(mirror.clone(), Some(Identity::generate("anon")), "anon").unwrap();
    assert!(anon.keys().embargo_released(&e), "the fix is on the mirror, its record unreleased");
}

#[derive(Clone, Debug)]
enum Op {
    Commit(u8),
    Embargo(u8),
    Release(u8),
    TakeBack(u8),
    Push { public: bool },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => any::<u8>().prop_map(Op::Commit),
        2 => any::<u8>().prop_map(Op::Embargo),
        2 => (0..2u8).prop_map(Op::Release),
        2 => (0..2u8).prop_map(Op::TakeBack),
        3 => any::<bool>().prop_map(|public| Op::Push { public }),
    ]
}

fn marker(n: usize) -> String {
    format!("embargoed-fix-marker-{n:04}-5e9d2a71")
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Whatever is released or taken back before each push, no remote ever
    /// holds the fix of an embargo this repository does not treat as
    /// released once the push is done.
    #[test]
    fn nothing_withheld_is_ever_pushed(ops in prop::collection::vec(op(), 1..14)) {
        let (mut alice, fs, _) = new_repo("alice");
        let base = commit_files(&mut alice, &*fs, &[("a.txt", "base\n")], "base");
        alice.set_tag("main", base, false).unwrap();
        let (mirror, team) = (Arc::new(MemoryBackend::new()), Arc::new(MemoryBackend::new()));
        let mut fixes: Vec<(String, usize)> = Vec::new();
        let mut attempts = 0;
        for op in ops {
            match op {
                Op::Commit(n) => {
                    let main = alice.view().tags["main"].target;
                    let ws = alice.ephemeral_workspace(main).unwrap();
                    ws.write(&format!("f{}.txt", n % 5), format!("edit {n}\n")).unwrap();
                    if let Ok((c, _)) = alice.commit_ephemeral(&ws, "edit") {
                        alice.set_tag("main", c, true).unwrap();
                    }
                }
                Op::Embargo(n) => {
                    let main = alice.view().tags["main"].target;
                    attempts += 1;
                    let ws = format!("fix{attempts}");
                    alice.create_workspace(&ws, vec![main]).unwrap();
                    let ov = alice.workspace_overlay(&ws).unwrap();
                    ov.write(&p(&format!("fix{n}-{attempts}.txt")), format!("{}\n", marker(fixes.len())).as_bytes()).unwrap();
                    // Refused when `main` combines embargoes whose releases
                    // were taken back meanwhile, as the merge may be.
                    let Ok(fix) = alice.snapshot_workspace(&ws, &ov).map(|s| s.snapshot) else { continue };
                    let spec = EmbargoSpec { scope: "team".into(), until: None };
                    if let Ok(r) = alice.merge(WS, main, vec![fix], "merge", Some(spec)) {
                        alice.set_tag("main", r.snapshot, true).unwrap();
                        fixes.push((r.embargo.unwrap(), fixes.len()));
                    }
                }
                Op::Release(i) => {
                    if let Some((e, _)) = fixes.get(i as usize) {
                        alice.keys().stage_release(e).unwrap();
                    }
                }
                Op::TakeBack(i) => {
                    if let Some((e, _)) = fixes.get(i as usize) {
                        alice.keys().take_back_release(e).unwrap();
                    }
                }
                Op::Push { public } => {
                    let target = if public { mirror.clone() } else { team.clone() };
                    alice.keys().invalidate();
                    let _ = remote::push(&mut alice, target, public, &[], false);
                    alice.keys().invalidate();
                    for (e, n) in &fixes {
                        if alice.keys().embargo_released(e) {
                            continue;
                        }
                        for (name, remote) in [("mirror", &mirror), ("team", &team)] {
                            let hits = backend_contains(&**remote, marker(*n).as_bytes());
                            prop_assert!(hits.is_empty(), "{name} holds the fix of unreleased embargo {e}: {hits:?}");
                        }
                    }
                }
            }
        }
    }
}

/// Many clients push their own tags to one repository on disk at once:
/// every push lands (one at a time, under its lock) and it is complete.
#[test]
fn many_concurrent_pushers_to_one_repository() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("hub");
    let (mut alice, fs, id) = new_repo("alice");
    let base = commit_files(&mut alice, &*fs, &[("a.txt", "base\n")], "base");
    alice.set_tag("main", base, false).unwrap();
    remote::push(&mut alice, Arc::new(veil_core::DiskBackend::new(&root)), false, &[], false).unwrap();
    const N: usize = 12;
    let threads: Vec<_> = (0..N)
        .map(|i| {
            let (root, id) = (root.clone(), id.clone());
            std::thread::spawn(move || {
                let hub: Arc<dyn StorageBackend> = Arc::new(veil_core::DiskBackend::new(&root));
                let mut me = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(id), "agent").unwrap();
                remote::pull(&mut me, "origin", hub.clone()).unwrap();
                let mut tips = Vec::new();
                for round in 0..3 {
                    let at = me.view().tags.get(&format!("agent-{i}")).map_or(me.view().tags["main"].target, |t| t.target);
                    let ws = me.ephemeral_workspace(at).unwrap();
                    let body: String = (0..300).map(|j| format!("{i}-{round}-{j} ")).collect();
                    ws.write(&format!("agents/{i}.txt"), &body).unwrap();
                    let (c, _) = me.commit_ephemeral(&ws, "work").unwrap();
                    me.set_tag(&format!("agent-{i}"), c, true).unwrap();
                    let rep = remote::push(&mut me, hub.clone(), false, &[format!("agent-{i}")], false).unwrap();
                    assert!(rep.tags_updated.iter().any(|(t, s)| *t == format!("agent-{i}") && *s == c), "{rep:#?}");
                    tips.push((c, body));
                }
                tips.pop().unwrap()
            })
        })
        .collect();
    let tips: Vec<(ObjectId, String)> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let hub: Arc<dyn StorageBackend> = Arc::new(veil_core::DiskBackend::new(&root));
    let bad: Vec<String> = fsck(hub.clone(), None).unwrap().findings.iter().filter(|f| matches!(f.severity, Severity::Corrupt | Severity::Warning)).map(|f| f.to_string()).collect();
    assert!(bad.is_empty(), "{bad:#?}");
    let mut c = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(Identity::generate("carol")), "carol").unwrap();
    remote::pull(&mut c, "origin", hub.clone()).unwrap();
    for (i, (tip, body)) in tips.iter().enumerate() {
        assert_eq!(c.view().tags[&format!("agent-{i}")].target, *tip);
        assert_eq!(read_at(&c, tip, &format!("agents/{i}.txt")), body.as_bytes());
    }
}

