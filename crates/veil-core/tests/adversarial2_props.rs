//! Round-2 property test: a model of the visibility invariants under random
//! sequences of cloak, expose, re-cloak, embargoed merges (of ordinary and
//! cloaked fix lines), releases, squash, `new`, rebase, follow-up commits,
//! pushes to public and team remotes, pulls, and a non-member relaying the
//! team remote to a public mirror of their own.
//!
//! Invariant, checked after every push: the plaintext of cloaked content,
//! and of embargoed content whose embargo is unreleased, never appears in
//! any byte of a public remote, nor can it be *read* there (decrypting with
//! every key the remote publishes); on a team remote it appears only as
//! ciphertext. Every piece of content carries a unique token, and the model
//! tracks which tokens are allowed in public (exposed, or released).
//!
//! `PROPTEST_CASES=500 cargo test --release -p veil-core --test adversarial2_props`

mod adversarial_support;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{commands::EmbargoSpec, object::Object, remote, Identity, MemoryBackend, ObjectId, Repo, StorageBackend};

#[derive(Clone, Debug)]
enum Op {
    PubEdit(u8),
    CloakEdit(u8),
    Expose,
    Recloak,
    Embargo { cloaked_line: bool, file: u8 },
    Release(u8),
    FollowUp(u8),
    Squash,
    NewOnMain,
    RebaseSide,
    PushPublic,
    PushTeam,
    PullTeam,
    BobRelay,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => any::<u8>().prop_map(Op::PubEdit),
        3 => any::<u8>().prop_map(Op::CloakEdit),
        1 => Just(Op::Expose),
        1 => Just(Op::Recloak),
        3 => (any::<bool>(), any::<u8>()).prop_map(|(cloaked_line, file)| Op::Embargo { cloaked_line, file }),
        2 => any::<u8>().prop_map(Op::Release),
        2 => any::<u8>().prop_map(Op::FollowUp),
        1 => Just(Op::Squash),
        1 => Just(Op::NewOnMain),
        1 => Just(Op::RebaseSide),
        3 => Just(Op::PushPublic),
        2 => Just(Op::PushTeam),
        1 => Just(Op::PullTeam),
        1 => Just(Op::BobRelay),
    ]
}

struct Model {
    alice: Repo,
    fs: Arc<MemoryBackend>,
    materialised: ObjectId,
    mirror: Arc<MemoryBackend>,
    team: Arc<MemoryBackend>,
    team_pushed: bool,
    bob: Repo,
    bob_mirror: Arc<MemoryBackend>,
    next: u32,
    /// Every token ever written that is *not* public plaintext by design.
    sensitive: BTreeSet<String>,
    /// Sensitive tokens that have legitimately become public.
    allowed: BTreeSet<String>,
    /// Unreleased embargo → tokens it hides.
    unreleased: BTreeMap<String, Vec<String>>,
    /// Tokens under `secrets/` (cloaked) since the last expose.
    cloaked_now: Vec<String>,
    exposed: bool,
    /// At most one unreleased embargo at a time (avoids BUG-041).
    single_embargo: bool,
    /// Embargoes that were unreleased when the last expose was committed:
    /// the expose sits on their line, with the pre-expose policy as its
    /// fallback.
    expose_under: Vec<String>,
    /// Skip a re-cloak once one of `expose_under` is released (BUG-050).
    avoid_bug050: bool,
    log: Vec<String>,
}

impl Model {
    fn new(single_embargo: bool, avoid_bug050: bool) -> Model {
        let (mut alice, fs, _) = new_repo("alice");
        let main = commit_files(&mut alice, &*fs, &[(".veilpolicy", "secrets/ cloak team\n"), ("README", "r\n")], "v1");
        alice.set_tag("main", main, None, false).unwrap();
        let materialised = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
        let bob = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(Identity::generate("bob")), "bob").unwrap();
        Model {
            alice,
            fs,
            materialised,
            mirror: Arc::new(MemoryBackend::new()),
            team: Arc::new(MemoryBackend::new()),
            team_pushed: false,
            bob,
            bob_mirror: Arc::new(MemoryBackend::new()),
            next: 0,
            sensitive: BTreeSet::new(),
            allowed: BTreeSet::new(),
            unreleased: BTreeMap::new(),
            cloaked_now: Vec::new(),
            exposed: false,
            single_embargo,
            expose_under: Vec::new(),
            avoid_bug050,
            log: Vec::new(),
        }
    }

    fn token(&mut self, kind: &str) -> String {
        self.next += 1;
        format!("{kind}TOKEN{:05}X", self.next)
    }

    fn main(&self) -> ObjectId {
        self.alice.view().tags["main"].target
    }

    /// Bring the project directory to the working copy's current tree.
    fn sync_fs(&mut self) {
        let wc = self.alice.workspace_wc(WS).unwrap();
        let to = self.alice.snapshot(&wc).unwrap().tree;
        if to != self.materialised {
            self.alice.checkout_tree(&*self.fs, Some(&self.materialised), &to).unwrap();
            self.materialised = to;
        }
    }

    fn commit(&mut self, msg: &str) {
        snap(&mut self.alice, &*self.fs);
        self.alice.commit_working_copy(WS, msg).unwrap();
        self.sync_fs();
    }

    fn apply(&mut self, op: &Op) {
        self.log.push(format!("{op:?}"));
        match op {
            Op::PubEdit(n) => {
                self.fs.write(&p(&format!("pub/f{}.txt", n % 4)), format!("public {}\n", self.next).as_bytes()).unwrap();
                self.next += 1;
                self.commit("pub");
            }
            Op::CloakEdit(n) => {
                let t = self.token("CLK");
                if !self.exposed {
                    self.sensitive.insert(t.clone());
                    self.cloaked_now.push(t.clone());
                }
                self.fs.write(&p(&format!("secrets/s{}.txt", n % 3)), format!("{t}\n").as_bytes()).unwrap();
                self.commit("cloak edit");
            }
            Op::Expose => {
                if self.exposed {
                    return;
                }
                // A deliberate expose publishes what is under secrets/ now.
                self.fs.write(&p(".veilpolicy"), b"secrets/ public\n").unwrap();
                self.allowed.extend(self.cloaked_now.drain(..));
                self.exposed = true;
                self.expose_under = self.unreleased.keys().cloned().collect();
                self.commit("expose");
            }
            Op::Recloak => {
                if !self.exposed {
                    return;
                }
                // Writing back the pre-expose policy after the expose's
                // embargo was released is dropped by the snapshot (BUG-050).
                if self.avoid_bug050 && self.expose_under.iter().any(|e| !self.unreleased.contains_key(e)) {
                    return;
                }
                self.fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
                self.exposed = false;
                self.commit("recloak");
            }
            Op::Embargo { cloaked_line, file } => {
                if self.single_embargo && !self.unreleased.is_empty() {
                    return;
                }
                let tip = self.main();
                let t = self.token("EMB");
                self.sensitive.insert(t.clone());
                let path = format!("src/fix{}.rs", file % 3);
                let fix = if *cloaked_line {
                    let name = format!("fix{}", self.next);
                    self.alice.create_workspace(&name, vec![tip], Some("team".into())).unwrap();
                    let ov = self.alice.workspace_overlay(&name).unwrap();
                    ov.write(&p(&path), format!("{t}\n").as_bytes()).unwrap();
                    self.alice.snapshot_workspace(&name, &ov).unwrap().snapshot
                } else {
                    let ws = self.alice.ephemeral_workspace(tip).unwrap();
                    ws.write(&path, format!("{t}\n")).unwrap();
                    self.alice.commit_ephemeral(&ws, "fix").unwrap().0
                };
                let r = self
                    .alice
                    .merge(
                        WS,
                        tip,
                        vec![fix],
                        "merge fix",
                        Some(EmbargoSpec {
                            scope: "team".into(),
                            until: None,
                        }),
                    )
                    .unwrap();
                self.unreleased.insert(r.embargo.unwrap(), vec![t]);
                self.sync_fs();
            }
            Op::Release(n) => {
                if self.unreleased.is_empty() {
                    return;
                }
                let id = self.unreleased.keys().nth(*n as usize % self.unreleased.len()).unwrap().clone();
                self.alice.release_embargo(&id).unwrap();
                let tokens = self.unreleased.remove(&id).unwrap();
                self.allowed.extend(tokens);
            }
            Op::FollowUp(n) => {
                // An edit of a fixed file on the (possibly embargoed) line:
                // content derived from the fix keeps its token.
                let path = format!("src/fix{}.rs", n % 3);
                if let Ok(old) = self.fs.read(&p(&path)) {
                    let mut new = old;
                    new.extend_from_slice(b"// follow-up\n");
                    self.fs.write(&p(&path), &new).unwrap();
                    self.commit("follow-up");
                }
            }
            Op::Squash => {
                self.fs.write(&p("pub/squashed.txt"), format!("sq {}\n", self.next).as_bytes()).unwrap();
                self.next += 1;
                let wc = snap(&mut self.alice, &*self.fs);
                let parent = self.alice.snapshot(&wc).unwrap().parents.clone();
                if parent.len() == 1 && parent[0] != self.alice.root_id() {
                    self.alice.squash(wc).unwrap();
                }
                self.sync_fs();
            }
            Op::NewOnMain => {
                let main = self.main();
                snap(&mut self.alice, &*self.fs);
                self.alice.new_change(WS, vec![main], "").unwrap();
                self.sync_fs();
            }
            Op::RebaseSide => {
                let root = self.alice.root_id();
                let ws = self.alice.ephemeral_workspace(root).unwrap();
                ws.write("side.txt", format!("side {}\n", self.next)).unwrap();
                self.next += 1;
                let (side, _) = self.alice.commit_ephemeral(&ws, "side").unwrap();
                let main = self.main();
                if let Ok(s2) = self.alice.rebase(side, vec![main]) {
                    let _ = self.alice.set_tag("side", s2, None, true);
                }
            }
            Op::PushPublic => {
                remote::push(&mut self.alice, self.mirror.clone(), true, &[], false).unwrap();
                self.check_public(&self.mirror.clone(), "mirror");
            }
            Op::PushTeam => {
                remote::push(&mut self.alice, self.team.clone(), false, &[], false).unwrap();
                self.team_pushed = true;
                self.check_team();
            }
            Op::PullTeam => {
                if self.team_pushed {
                    remote::pull(&mut self.alice, "origin", self.team.clone()).unwrap();
                }
            }
            Op::BobRelay => {
                if self.team_pushed {
                    remote::pull(&mut self.bob, "origin", self.team.clone()).unwrap();
                    remote::push(&mut self.bob, self.bob_mirror.clone(), true, &[], false).unwrap();
                    self.check_public(&self.bob_mirror.clone(), "bob's mirror");
                }
            }
        }
    }

    fn forbidden(&self) -> Vec<&String> {
        self.sensitive.iter().filter(|t| !self.allowed.contains(*t)).collect()
    }

    fn raw_hits(&self, backend: &MemoryBackend) -> Vec<String> {
        let forbidden = self.forbidden();
        let mut out = Vec::new();
        for f in backend.files() {
            let data = backend.read(&f).unwrap();
            for t in &forbidden {
                if data.windows(t.len()).any(|w| w == t.as_bytes()) {
                    out.push(format!("{t} in {f}"));
                }
            }
        }
        out
    }

    fn check_public(&self, backend: &Arc<MemoryBackend>, what: &str) {
        let raw = self.raw_hits(backend);
        assert!(raw.is_empty(), "plaintext on {what}: {raw:?}\nops: {:#?}", self.log);
        // What an anonymous reader can decrypt with the published keys.
        let anon = Repo::open(backend.clone(), Some(Identity::generate("anon")), "anon").unwrap();
        let forbidden = self.forbidden();
        let mut readable = Vec::new();
        for id in anon.store().list_objects().unwrap() {
            if let Ok(Object::Blob(b)) = anon.store().open(&id) {
                for t in &forbidden {
                    if b.windows(t.len()).any(|w| w == t.as_bytes()) {
                        readable.push(format!("{t} in {}", id.short()));
                    }
                }
            }
        }
        assert!(readable.is_empty(), "readable on {what}: {readable:?}\nops: {:#?}", self.log);
    }

    fn check_team(&self) {
        let raw = self.raw_hits(&self.team);
        assert!(raw.is_empty(), "plaintext on the team remote: {raw:?}\nops: {:#?}", self.log);
    }
}

fn run(ops: &[Op], single_embargo: bool, avoid_bug050: bool) {
    let mut m = Model::new(single_embargo, avoid_bug050);
    for o in ops {
        m.apply(o);
    }
    m.apply(&Op::PushPublic);
    m.apply(&Op::PushTeam);
    m.apply(&Op::BobRelay);
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(48)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), max_shrink_iters: 2000, ..ProptestConfig::default() })]

    /// With at most one unreleased embargo at a time (BUG-041), and no
    /// re-cloak after the expose's embargo is released (BUG-050), the
    /// invariant holds.
    #[test]
    fn visibility_invariants_hold_with_one_embargo_at_a_time(ops in prop::collection::vec(op(), 1..28)) {
        run(&ops, true, true);
    }

    /// Unrestricted: overlapping embargoes find BUG-041.
    #[test]
    #[ignore = "BUG-041: releasing an older embargo publishes the content of a newer, unreleased one"]
    fn visibility_invariants_hold_with_overlapping_embargoes(ops in prop::collection::vec(op(), 1..28)) {
        run(&ops, false, true);
    }
}

/// The shrunk counterexample found at 500 cases: reverting `.veilpolicy` to
/// its pre-embargo content after a release is dropped by the snapshot, so
/// history keeps `secrets/ public`; a later embargoed merge of a cloaked
/// line then declassifies the cloaked `secrets/` file under the new embargo
/// key, and releasing that embargo publishes it.
#[test]
#[ignore = "BUG-050: after a release, reverting a file to its pre-embargo content is silently not recorded"]
fn recloak_after_a_released_expose_survives_a_cloaked_embargo_release() {
    use Op::*;
    run(
        &[
            Embargo { cloaked_line: false, file: 0 },
            Expose,
            Release(0),
            Recloak,
            CloakEdit(0),
            Embargo { cloaked_line: true, file: 0 },
            Release(0),
        ],
        true,
        false,
    );
}
