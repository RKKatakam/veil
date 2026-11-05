//! Two-phase pushes (`docs/design/scale/1-lock-free-push.md`): objects are
//! staged on the remote without its lock, then published under it.
//!
//! Also the release race (BUG-807): a push decides what an embargo withholds
//! before it publishes the releases staged here, so an undo of a release
//! between the two must make the push withhold the fix again.

use crate::adversarial_support;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    keychain::ReleaseState,
    remote,
    vfs::{DirEntry, Metadata, StorageBackend},
    Identity, MemoryBackend, ObjectId, Repo, Result, VPath,
};

/// A backend that runs `hook` once, the first time a pack file is written
/// (staged or published): "meanwhile, in another terminal".
struct Tripwire {
    inner: Arc<MemoryBackend>,
    fired: AtomicBool,
    hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl std::fmt::Debug for Tripwire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tripwire")
    }
}

impl Tripwire {
    fn new(inner: Arc<MemoryBackend>, hook: impl FnOnce() + Send + 'static) -> Tripwire {
        Tripwire {
            inner,
            fired: AtomicBool::new(false),
            hook: Mutex::new(Some(Box::new(hook))),
        }
    }

    fn check(&self, path: &VPath) {
        if path.as_str().ends_with(".pack") && !self.fired.swap(true, Ordering::SeqCst) {
            if let Some(h) = self.hook.lock().unwrap().take() {
                h();
            }
        }
    }
}

impl StorageBackend for Tripwire {
    fn kind(&self) -> &'static str {
        "tripwire"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.check(path);
        self.inner.write(path, data)
    }
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.check(path);
        self.inner.write_unsynced(path, data)
    }
    fn rename_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        self.inner.rename_unsynced(from, to)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.inner.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.inner.set_executable(path, executable)
    }
}

const FIX_MARKER: &str = "verify_signature_of_the_embargoed_fix_4c1d";

/// Alice's repository: `main` on a public mirror, then a plaintext fix
/// merged into `main` under an embargo of scope `team`. Returns the repo,
/// its backend, the identity, the mirror, the embargo and the fix.
fn embargoed_fix() -> (Repo, Arc<MemoryBackend>, Identity, Arc<MemoryBackend>, String, ObjectId) {
    let (mut alice, fs, id) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    alice.create_workspace("fix", vec![main], None).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), format!("fn check() -> bool {{ {FIX_MARKER}() }}\n").as_bytes()).unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let r = alice
        .merge(WS, main, vec![fix], "merge the fix", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    alice.set_tag("main", r.snapshot, None, false).unwrap();
    let e = r.embargo.unwrap();
    assert_eq!(remote::withheld_by_embargo(&alice, &e).unwrap(), vec![fix], "control: the fix is withheld");
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

/// BUG-807: `vl embargo release`, `vl push` to a public mirror, and, while
/// the push uploads, `vl undo` of the release in another terminal. The undo
/// succeeds (the release was only staged), so the embargo stays unreleased;
/// the push must then not publish the fix's history.
#[test]
fn push_racing_an_undo_of_a_staged_release_never_publishes_the_fix() {
    let (mut alice, fs, id, mirror, e, fix) = embargoed_fix();
    alice.release_embargo(&e).unwrap();
    assert_eq!(alice.keys().release_state(&e), ReleaseState::Staged);

    let (other_fs, other_id) = (fs.clone(), id.clone());
    let undone = Arc::new(AtomicBool::new(false));
    let undone2 = undone.clone();
    let wire = Arc::new(Tripwire::new(mirror.clone(), move || {
        // Another `vl` process on the same repository.
        let mut other = Repo::open(other_fs, Some(other_id), "alice").unwrap();
        other.undo().unwrap();
        undone2.store(true, Ordering::SeqCst);
    }));
    let res = remote::push(&mut alice, wire, true, &[], false);
    assert!(undone.load(Ordering::SeqCst), "control: the undo ran during the push");
    assert_eq!(alice.keys().release_state(&e), ReleaseState::Unreleased, "the undo took the release back");
    let hits = fix_reached(&mirror, &fix);
    assert!(hits.is_empty(), "the push published the fix of an embargo whose release was taken back: {hits:?} ({res:?})");
    let anon = Repo::open(mirror.clone(), Some(Identity::generate("anon")), "anon").unwrap();
    assert!(!anon.keys().embargo_released(&e), "the mirror's record says released");
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

// ---- the two phases ---------------------------------------------------------------

use std::collections::BTreeSet;
use std::sync::Barrier;

use veil_core::{
    fsck::{fsck, Severity},
    gc::{gc, GcOptions},
    pack,
    remote::{PushHook, SyncOptions},
    VeilError,
};

type OnMutation = Box<dyn Fn(&str, &VPath, &VPath) -> Result<()> + Send + Sync>;

/// A remote that runs `on(op, path)` before each mutation; an error from it
/// fails the mutation (a dropped connection, a stalled holder).
struct Hooked {
    inner: Arc<MemoryBackend>,
    on: OnMutation,
}

impl std::fmt::Debug for Hooked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hooked")
    }
}

impl StorageBackend for Hooked {
    fn kind(&self) -> &'static str {
        "hooked"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        (self.on)("write", path, path)?;
        self.inner.write(path, data)
    }
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        (self.on)("write", path, path)?;
        self.inner.write_unsynced(path, data)
    }
    fn rename_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        (self.on)("rename", from, to)?;
        self.inner.rename_unsynced(from, to)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.inner.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.inner.set_executable(path, executable)
    }
}

fn dropped() -> VeilError {
    VeilError::Io {
        path: "<remote>".into(),
        source: std::io::Error::other("connection dropped"),
    }
}

fn hook(f: impl Fn() + Send + Sync + 'static) -> Option<PushHook> {
    Some(PushHook(Arc::new(f)))
}

/// `fsck` of a remote: nothing worse than notes.
fn assert_clean(fs: Arc<dyn StorageBackend>, ctx: &str) {
    let bad: Vec<String> = fsck(fs, None)
        .unwrap()
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Corrupt | Severity::Warning))
        .map(|f| f.to_string())
        .collect();
    assert!(bad.is_empty(), "{ctx}: {bad:#?}");
}

/// Every `.veil/objects/incoming/push-*` directory on `fs`.
fn staging(fs: &MemoryBackend) -> Vec<String> {
    match fs.list_dir(&p(".veil/objects/incoming")) {
        Ok(l) => l.into_iter().filter(|e| e.name.starts_with("push-")).map(|e| e.name).collect(),
        Err(_) => Vec::new(),
    }
}

/// The packs in `objects/pack/` on `fs`, by name, with their objects.
fn published_packs(fs: &MemoryBackend) -> std::collections::BTreeMap<String, Vec<ObjectId>> {
    let dir = p(".veil/objects/pack");
    let mut out = std::collections::BTreeMap::new();
    for e in fs.list_dir(&dir).unwrap_or_default() {
        if let Some(name) = pack::name_from_index_file(&e.name) {
            let pk = pack::Pack::open(fs, &dir, name).unwrap();
            out.insert(name.to_string(), pk.index().ids().to_vec());
        }
    }
    out
}

/// A clone of `remote` checks out `tag` with `want` in `path`.
fn clone_reads(remote: &Arc<MemoryBackend>, tag: &str, path: &str, want: &str) {
    let id = Identity::generate("carol");
    let mut c = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(id), "carol").unwrap();
    remote::pull(&mut c, "origin", remote.clone()).unwrap();
    let target = c.view().tags[tag].target;
    assert_eq!(read_at(&c, &target, path), want.as_bytes(), "a fresh clone reads {tag}:{path}");
}

/// Alice with `n` files of incompressible-ish content, committed as `main`.
fn alice_with_files(n: usize) -> (Repo, Arc<MemoryBackend>, Identity) {
    let (mut alice, fs, id) = new_repo("alice");
    let files: Vec<(String, String)> = (0..n)
        .map(|i| {
            let body: String = (0..400).map(|j| format!("{:08x}", (i * 7919 + j * 104729) as u32 ^ 0x5bd1e995)).collect();
            (format!("src/f{i}.txt"), body)
        })
        .collect();
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let main = commit_files(&mut alice, &*fs, &refs, "many files");
    alice.set_tag("main", main, None, false).unwrap();
    (alice, fs, id)
}

/// Threat 1: two pushers both pass the advisory check; exactly one moves
/// the tag, the other is rejected under the lock, and on a public remote
/// its staging is gone.
#[test]
fn two_pushers_racing_on_one_tag_exactly_one_wins() {
    for public in [false, true] {
        let (mut alice, fs, _) = new_repo("alice");
        let base = commit_files(&mut alice, &*fs, &[("a.txt", "base\n")], "base");
        alice.set_tag("main", base, None, false).unwrap();
        let hub = Arc::new(MemoryBackend::new());
        remote::push(&mut alice, hub.clone(), public, &[], false).unwrap();
        let mut bob = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(Identity::generate("bob")), "bob").unwrap();
        remote::pull(&mut bob, "origin", hub.clone()).unwrap();
        let bob_fs = bob.backend().clone();
        let a2 = commit_files(&mut alice, &*fs, &[("a.txt", "alice's line, long enough to be its own object\n")], "alice");
        alice.set_tag("main", a2, None, true).unwrap();
        let ws = bob.ephemeral_workspace(base).unwrap();
        ws.write("b.txt", "bob's line, also long enough to be its own object\n").unwrap();
        let (b2, _) = bob.commit_ephemeral(&ws, "bob").unwrap();
        bob.set_tag("main", b2, None, true).unwrap();
        drop(bob_fs);

        let gate = Arc::new(Barrier::new(2));
        let run = |mut repo: Repo, gate: Arc<Barrier>, hub: Arc<MemoryBackend>| {
            std::thread::spawn(move || {
                let once = AtomicBool::new(false);
                let opts = SyncOptions {
                    pause_before_lock: hook(move || {
                        if !once.swap(true, Ordering::SeqCst) {
                            gate.wait();
                        }
                    }),
                    ..Default::default()
                };
                remote::push_with(&mut repo, hub, public, &[], false, &opts).unwrap()
            })
        };
        let ra = run(alice, gate.clone(), hub.clone());
        let rb = run(bob, gate, hub.clone());
        let (ra, rb) = (ra.join().unwrap(), rb.join().unwrap());
        let won = [&ra, &rb].iter().filter(|r| r.tags_updated.iter().any(|(t, _)| t == "main")).count();
        let lost = [&ra, &rb].iter().filter(|r| r.tags_rejected.contains(&"main".to_string())).count();
        assert_eq!((won, lost), (1, 1), "public: {public}\n{ra:#?}\n{rb:#?}");
        let there = Repo::open_remote(hub.clone()).unwrap().view().tags["main"].target;
        assert!(there == a2 || there == b2);
        assert_clean(hub.clone(), "after the race");
        if public {
            assert!(staging(&hub).is_empty(), "a rejected push left its staging on a public remote: {:?}", staging(&hub));
        }
    }
}

/// Threat 2: the snapshot the upload built on is rewound and pruned between
/// the phases; phase B notices, the push sends it again, and the remote is
/// complete.
#[test]
fn the_boundary_vanishing_between_the_phases_is_sent_again() {
    let (mut alice, fs, id) = new_repo("alice");
    let v1 = commit_files(&mut alice, &*fs, &[("a.txt", "one\n")], "v1");
    alice.set_tag("main", v1, None, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let v2 = commit_files(&mut alice, &*fs, &[("b.txt", "two: only v2 has this file at first\n")], "v2");
    alice.set_tag("main", v2, None, true).unwrap();
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let v3 = commit_files(&mut alice, &*fs, &[("c.txt", "three\n")], "v3");
    alice.set_tag("main", v3, None, true).unwrap();

    let (hub2, id2) = (hub.clone(), id.clone());
    let once = AtomicBool::new(false);
    let opts = SyncOptions {
        pause_before_lock: hook(move || {
            if once.swap(true, Ordering::SeqCst) {
                return;
            }
            // Another client deletes `main` there (its history stops being
            // visible), records one more operation, and prunes at once.
            let mut bob = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(id2.clone()), "bob").unwrap();
            remote::pull(&mut bob, "origin", hub2.clone()).unwrap();
            bob.delete_tag("main").unwrap();
            let d = remote::delete_remote_tags(&mut bob, "origin", hub2.clone(), &["main".to_string()], true).unwrap();
            assert_eq!(d.tags_deleted, vec!["main".to_string()]);
            bob.set_tag("other", v1, None, false).unwrap();
            remote::push(&mut bob, hub2.clone(), false, &["other".to_string()], false).unwrap();
            let mut r = Repo::open_remote(hub2.clone()).unwrap();
            gc(&mut r, &GcOptions { keep_ops: Some(std::time::Duration::ZERO), grace: std::time::Duration::ZERO, ..Default::default() }).unwrap();
            assert!(!r.store().has(&v2), "control: v2 was pruned");
        }),
        ..Default::default()
    };
    let rep = remote::push_with(&mut alice, hub.clone(), false, &["main".to_string()], false, &opts).unwrap();
    assert!(rep.tags_updated.iter().any(|(t, s)| t == "main" && *s == v3), "{rep:#?}");
    assert_clean(hub.clone(), "after the boundary vanished");
    clone_reads(&hub, "main", "b.txt", "two: only v2 has this file at first\n");
}

/// A push interrupted after staging some packs (a dropped connection),
/// retried with its journal: the packs staged are published as they are,
/// never sent again, and the result is complete.
#[test]
fn a_retried_push_never_sends_a_staged_pack_again() {
    let (mut alice, _fs, _) = alice_with_files(40);
    let hub = Arc::new(MemoryBackend::new());
    let packs_written = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (count, cut) = (packs_written.clone(), Arc::new(AtomicBool::new(true)));
    let cut2 = cut.clone();
    let flaky: Arc<dyn StorageBackend> = Arc::new(Hooked {
        inner: hub.clone(),
        on: Box::new(move |_, path, _| {
            if path.as_str().contains("/incoming/push-") && path.as_str().ends_with(".idx") {
                // The third staged pack never arrives.
                if count.fetch_add(1, Ordering::SeqCst) == 2 && cut2.load(Ordering::SeqCst) {
                    return Err(dropped());
                }
            }
            Ok(())
        }),
    });
    let opts = SyncOptions { journal: Some("ssh://hub/repo".into()), chunk: 16 << 10, ..Default::default() };
    let err = remote::push_with(&mut alice, flaky.clone(), false, &[], false, &opts).unwrap_err();
    assert!(err.to_string().contains("connection dropped"), "{err}");
    assert!(published_packs(&hub).len() <= 1, "nothing of the push was published yet");
    let staged: BTreeSet<String> = {
        let dir = p(&format!(".veil/objects/incoming/{}", staging(&hub)[0]));
        hub.list_dir(&dir).unwrap().into_iter().filter_map(|e| pack::name_from_index_file(&e.name).map(str::to_string)).collect()
    };
    assert_eq!(staged.len(), 2, "two packs were staged before the drop");
    let full = veil_core::push_plan::plan_push(&alice, Arc::new(MemoryBackend::new()), false, &[], false).unwrap().objects.len();

    cut.store(false, Ordering::SeqCst);
    let rep = remote::push_with(&mut alice, flaky, false, &[], false, &opts).unwrap();
    assert!(rep.tags_updated.iter().any(|(t, _)| t == "main"));
    let after = published_packs(&hub);
    for name in &staged {
        assert!(after.contains_key(name), "staged pack {name} was not published as it was");
    }
    assert!(rep.objects_copied < full, "the retry sent everything again ({} of {full})", rep.objects_copied);
    let resent: usize = staged.iter().map(|n| after[n].len()).sum();
    assert_eq!(rep.objects_copied + resent, full, "every object is sent exactly once over both attempts");
    assert!(staging(&hub).is_empty(), "the staging is removed once published");
    assert!(!alice.backend().exists(&p(".veil/local/push")).unwrap() || alice.backend().list_dir(&p(".veil/local/push")).unwrap().is_empty(), "the journal is removed once published");
    assert_clean(hub.clone(), "after the resumed push");
    clone_reads(&hub, "main", "src/f7.txt", &String::from_utf8(read_at(&alice, &alice.view().tags["main"].target, "src/f7.txt")).unwrap());
}

/// Threat 4 and the confidentiality rule: what a push stages on a public
/// remote passed the public filter. Nothing cloaked or isolated is ever
/// staged there, even for the moment between the phases.
#[test]
fn a_public_push_never_stages_cloaked_content() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    let c = commit_files(&mut alice, &*fs, &[("src/a.rs", "fn a() {}\n"), ("secrets/key.txt", "cloaked-secret-needle-93ab17\n")], "v1");
    alice.set_tag("main", c, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    let (m2, seen) = (mirror.clone(), Arc::new(AtomicBool::new(false)));
    let seen2 = seen.clone();
    let opts = SyncOptions {
        pause_before_lock: hook(move || {
            let staged: Vec<_> = packed_objects(&*m2).into_iter().filter(|(l, _)| l.contains("/incoming/")).collect();
            assert!(!staged.is_empty(), "control: the push staged its objects");
            for (label, raw) in &staged {
                assert!(veil_core::object::Object::sealed_scope(raw).is_none(), "{label}: a sealed object was staged on a public remote");
            }
            assert!(backend_contains(&*m2, b"cloaked-secret-needle-93ab17").is_empty());
            seen2.store(true, Ordering::SeqCst);
        }),
        ..Default::default()
    };
    let rep = remote::push_with(&mut alice, mirror.clone(), true, &[], false, &opts).unwrap();
    assert!(seen.load(Ordering::SeqCst));
    assert!(rep.redacted > 0, "control: the cloaked file was withheld");
    assert!(backend_contains(&*mirror, b"cloaked-secret-needle-93ab17").is_empty());
    assert!(staging(&mirror).is_empty());
}

/// Threat 5: a foreign push's staging (here holding a corrupt object) is
/// invisible to every reader, and never makes another push skip anything.
#[test]
fn foreign_staging_is_invisible_to_readers_and_to_other_pushes() {
    let (mut alice, fs, _) = new_repo("alice");
    let v1 = commit_files(&mut alice, &*fs, &[("a.txt", "first version of a\n")], "v1");
    alice.set_tag("main", v1, None, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let v2 = commit_files(&mut alice, &*fs, &[("a.txt", "second version of a, staged by someone else\n")], "v2");
    alice.set_tag("main", v2, None, true).unwrap();
    // Someone else staged exactly v2's objects, then went away; one of
    // them is corrupt in its pack.
    let other = Arc::new(MemoryBackend::new());
    let mut c = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(Identity::generate("x")), "x").unwrap();
    remote::pull(&mut c, "origin", hub.clone()).unwrap();
    remote::push(&mut alice, other.clone(), false, &[], false).unwrap();
    let foreign = p(".veil/objects/incoming/push-00112233445566778899aabbccddeeff");
    for e in other.list_dir(&p(".veil/objects/pack")).unwrap() {
        let mut data = other.read(&p(".veil/objects/pack").join(&e.name)).unwrap();
        if e.name.ends_with(".pack") {
            let n = data.len();
            data[n / 2] ^= 0xff;
        }
        hub.write(&foreign.join(&e.name), &data).unwrap();
    }
    hub.write(&foreign.join("touched"), crate_now().to_string().as_bytes()).unwrap();

    assert_clean(hub.clone(), "fsck with foreign staging");
    let notes: Vec<String> = fsck(hub.clone(), None).unwrap().findings.iter().map(|f| f.to_string()).collect();
    assert!(notes.iter().any(|n| n.contains("push-00112233") && n.contains("not part of the repository")), "{notes:#?}");
    remote::pull(&mut c, "origin", hub.clone()).unwrap();
    clone_reads(&hub, "main", "a.txt", "first version of a\n");
    let mut r = Repo::open_remote(hub.clone()).unwrap();
    let g = gc(&mut r, &GcOptions::default()).unwrap();
    assert_eq!(g.push_staging_removed, 0, "fresh staging is never removed");
    assert!(hub.exists(&foreign.join("touched")).unwrap(), "gc left the foreign staging alone");

    let rep = remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    assert!(rep.objects_copied >= 2, "the push sent v2's objects itself: {rep:#?}");
    assert_clean(hub.clone(), "after the push");
    clone_reads(&hub, "main", "a.txt", "second version of a, staged by someone else\n");
}

fn crate_now() -> i64 {
    veil_core::now_millis()
}

/// Threat 6: `incoming` is a symlink on a path remote. The push fails with
/// a message and writes nothing through it.
#[cfg(unix)]
#[test]
fn a_symlinked_staging_directory_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, outside) = (tmp.path().join("hub"), tmp.path().join("outside"));
    std::fs::create_dir_all(&outside).unwrap();
    let (mut alice, fs, _) = new_repo("alice");
    let v1 = commit_files(&mut alice, &*fs, &[("a.txt", "one\n")], "v1");
    alice.set_tag("main", v1, None, false).unwrap();
    let hub: Arc<dyn StorageBackend> = Arc::new(veil_core::DiskBackend::new(&root));
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let incoming = root.join(".veil/objects/incoming");
    let _ = std::fs::remove_dir_all(&incoming);
    std::os::unix::fs::symlink(&outside, &incoming).unwrap();
    let v2 = commit_files(&mut alice, &*fs, &[("a.txt", "two\n")], "v2");
    alice.set_tag("main", v2, None, true).unwrap();
    let err = remote::push(&mut alice, hub.clone(), false, &[], false).unwrap_err().to_string();
    assert!(err.contains("symlink") && err.contains("incoming"), "{err}");
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "the push wrote through the symlink");
}

/// Threat 7: a staged pack disappears between the phases (a hand `rm`, the
/// week-old cleanup). Phase B notices, and the push stages exactly that
/// pack's objects again.
#[test]
fn a_staged_pack_that_vanished_is_sent_again() {
    let (mut alice, _fs, _) = alice_with_files(30);
    let hub = Arc::new(MemoryBackend::new());
    let (h2, removed) = (hub.clone(), Arc::new(Mutex::new(Vec::<ObjectId>::new())));
    let removed2 = removed.clone();
    let once = AtomicBool::new(false);
    let opts = SyncOptions {
        chunk: 16 << 10,
        pause_before_lock: hook(move || {
            if once.swap(true, Ordering::SeqCst) {
                return;
            }
            let dir = p(&format!(".veil/objects/incoming/{}", staging(&h2)[0]));
            let names: Vec<String> = h2.list_dir(&dir).unwrap().into_iter().filter_map(|e| pack::name_from_index_file(&e.name).map(str::to_string)).collect();
            assert!(names.len() >= 3, "control: several packs staged ({names:?})");
            let pk = pack::Pack::open(&*h2, &dir, &names[1]).unwrap();
            removed2.lock().unwrap().extend(pk.index().ids().iter().copied());
            h2.remove_file(&pack::pack_file(&dir, &names[1])).unwrap();
        }),
        ..Default::default()
    };
    let rep = remote::push_with(&mut alice, hub.clone(), false, &[], false, &opts).unwrap();
    let removed = removed.lock().unwrap().clone();
    assert_eq!(rep.objects_copied, removed.len(), "the retry sends exactly the vanished pack's objects");
    assert_clean(hub.clone(), "after the vanished pack");
    clone_reads(&hub, "main", "src/f3.txt", &String::from_utf8(read_at(&alice, &alice.view().tags["main"].target, "src/f3.txt")).unwrap());
}

/// Threat 8: the lock is taken over after the packs are published and
/// before the operation. The push fails, records nothing, leaves its packs
/// unreferenced, and a retry succeeds.
#[test]
fn a_push_whose_lock_is_taken_over_before_the_operation_records_nothing() {
    let (mut alice, fs, _) = new_repo("alice");
    let v1 = commit_files(&mut alice, &*fs, &[("a.txt", "one\n")], "v1");
    alice.set_tag("main", v1, None, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let v2 = commit_files(&mut alice, &*fs, &[("a.txt", "two, published but never recorded\n")], "v2");
    alice.set_tag("main", v2, None, true).unwrap();
    let before = Repo::open_remote(hub.clone()).unwrap().op_id();
    let packs_before = published_packs(&hub).len();
    let (h2, stolen) = (hub.clone(), Arc::new(AtomicBool::new(false)));
    let stolen2 = stolen.clone();
    let thief: Arc<dyn StorageBackend> = Arc::new(Hooked {
        inner: hub.clone(),
        on: Box::new(move |op, _, to| {
            if op == "rename" && to.as_str().ends_with(".idx") && !stolen2.swap(true, Ordering::SeqCst) {
                // Another holder took the lock over (our lease lapsed).
                let lock = p(".veil/lock");
                let mut info: serde_json::Value = serde_json::from_slice(&h2.read(&lock).unwrap()).unwrap();
                info["token"] = serde_json::Value::String("someone-else".into());
                h2.write(&lock, &serde_json::to_vec(&info).unwrap()).unwrap();
            }
            Ok(())
        }),
    });
    let opts = SyncOptions { journal: Some("ssh://hub/repo".into()), ..Default::default() };
    let err = remote::push_with(&mut alice, thief.clone(), false, &[], false, &opts).unwrap_err();
    assert!(matches!(err, VeilError::Locked(_)), "{err}");
    assert_eq!(Repo::open_remote(hub.clone()).unwrap().op_id(), before, "no operation was recorded");
    assert_eq!(Repo::open_remote(hub.clone()).unwrap().view().tags["main"].target, v1);
    assert!(published_packs(&hub).len() > packs_before, "control: the packs were renamed into place first");
    assert_clean(hub.clone(), "with unreferenced packs");
    // The other holder is done.
    hub.remove_file(&p(".veil/lock")).unwrap();
    let rep = remote::push_with(&mut alice, thief, false, &[], false, &opts).unwrap();
    assert_eq!(rep.objects_copied, 0, "the retry reuses the published packs: {rep:#?}");
    assert!(rep.tags_updated.iter().any(|(t, s)| t == "main" && *s == v2));
    assert_clean(hub.clone(), "after the retry");
    clone_reads(&hub, "main", "a.txt", "two, published but never recorded\n");
}

/// Threat 9: staging untouched for over a week is removed (by a push and by
/// the remote's gc); staging touched within the day never is.
#[test]
fn only_week_old_staging_is_removed() {
    let hub = Arc::new(MemoryBackend::new());
    let (mut alice, fs, _) = new_repo("alice");
    let v1 = commit_files(&mut alice, &*fs, &[("a.txt", "one\n")], "v1");
    alice.set_tag("main", v1, None, false).unwrap();
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let now = crate_now();
    const DAY: i64 = 24 * 3600 * 1000;
    let plant = |name: &str, age: Option<i64>| {
        let dir = p(&format!(".veil/objects/incoming/push-{name}"));
        hub.write(&dir.join("pack-x.pack"), b"partial").unwrap();
        if let Some(age) = age {
            hub.write(&dir.join("touched"), (now - age).to_string().as_bytes()).unwrap();
        }
    };
    plant("8d0000000000000000000000000000ab", Some(8 * DAY));
    plant("1h0000000000000000000000000000ab", Some(3600 * 1000));
    plant("000000000000000000000000000000ab", Some(0));
    plant("unknown0000000000000000000000ab", None);
    // Hostile values from the remote are just old or unreadable.
    let hostile = p(".veil/objects/incoming/push-ffff0000000000000000000000000000");
    hub.write(&hostile.join("touched"), i64::MIN.to_string().as_bytes()).unwrap();
    let mut r = Repo::open_remote(hub.clone()).unwrap();
    let g = gc(&mut r, &GcOptions::default()).unwrap();
    assert_eq!(g.push_staging_removed, 2, "the week-old one and the hostile one");
    let mut left = staging(&hub);
    left.sort();
    assert_eq!(left, ["push-000000000000000000000000000000ab", "push-1h0000000000000000000000000000ab", "push-unknown0000000000000000000000ab"]);
    // A week later (by the clock of whoever looks), the rest goes too; the
    // one that did not say when was marked then.
    assert_eq!(remote::expire_push_staging(&*hub, now + 8 * DAY).unwrap(), 3);
    // And a push removes week-old staging too.
    plant("8d0000000000000000000000000000ab", Some(8 * DAY));
    let v2 = commit_files(&mut alice, &*fs, &[("a.txt", "two\n")], "v2");
    alice.set_tag("main", v2, None, true).unwrap();
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    assert!(staging(&hub).is_empty(), "{:?}", staging(&hub));
}

/// Threat 11: metadata written by another command during phase A (a
/// revocation pushed meanwhile) is merged under the lock in phase B, not
/// overwritten by what the push read before.
#[test]
fn a_revocation_pushed_during_phase_a_is_kept() {
    let (mut alice, fs, id) = new_repo("alice");
    let (bob, carol) = (Identity::generate("bob"), Identity::generate("carol"));
    alice.keys().grant("team", &bob.public_id(), "bob").unwrap();
    let v1 = commit_files(&mut alice, &*fs, &[("a.txt", "one\n")], "v1");
    alice.set_tag("main", v1, None, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    alice.keys().grant("team", &carol.public_id(), "carol").unwrap();
    let v2 = commit_files(&mut alice, &*fs, &[("a.txt", "two\n")], "v2");
    alice.set_tag("main", v2, None, true).unwrap();
    let (fs2, id2, hub2, bob2) = (fs.clone(), id.clone(), hub.clone(), bob.clone());
    let once = AtomicBool::new(false);
    let opts = SyncOptions {
        pause_before_lock: hook(move || {
            if once.swap(true, Ordering::SeqCst) {
                return;
            }
            // Another terminal: revoke Bob, and push.
            let mut other = Repo::open(fs2.clone(), Some(id2.clone()), "alice").unwrap();
            assert!(other.keys().revoke("team", &bob2.public_id()).unwrap());
            remote::push(&mut other, hub2.clone(), false, &[], false).unwrap();
        }),
        ..Default::default()
    };
    remote::push_with(&mut alice, hub.clone(), false, &[], false, &opts).unwrap();
    let there = Repo::open(hub.clone(), Some(Identity::generate("anon")), "anon").unwrap();
    let state = there.keys().ring_state("team").unwrap().unwrap().expect("ring verifies");
    assert!(state.members.contains_key(&carol.public_hex()), "the grant was lost");
    assert!(!state.members.contains_key(&bob.public_hex()), "the revocation was lost");
}

/// Threat 13: a format-5 remote takes two-phase pushes, and its staging is
/// a note for fsck, never counted or touched by gc.
#[test]
fn a_format_5_remote_takes_two_phase_pushes() {
    let hub = Arc::new(MemoryBackend::new());
    Repo::init_bare_at(hub.clone(), 5).unwrap();
    let (mut alice, fs, _) = new_repo_v5("alice");
    let v1 = commit_files(&mut alice, &*fs, &[("a.txt", "one\n")], "v1");
    alice.set_tag("main", v1, None, false).unwrap();
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let stale = p(".veil/objects/incoming/push-55555555555555555555555555555555");
    hub.write(&stale.join("pack-x.pack"), b"a torn upload").unwrap();
    hub.write(&stale.join("touched"), crate_now().to_string().as_bytes()).unwrap();
    let v2 = commit_files(&mut alice, &*fs, &[("a.txt", "two\n")], "v2");
    alice.set_tag("main", v2, None, true).unwrap();
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let r = Repo::open_remote(hub.clone()).unwrap();
    assert_eq!(r.format(), 5);
    assert_eq!(r.view().tags["main"].target, v2);
    assert_clean(hub.clone(), "format 5 with staging");
    let mut r = r;
    let before = gc(&mut r, &GcOptions::default()).unwrap();
    assert!(hub.exists(&stale.join("pack-x.pack")).unwrap(), "gc touched the staging");
    assert_eq!(before.push_staging_removed, 0);
    clone_reads(&hub, "main", "a.txt", "two\n");
}

// ---- releases between the phases (threat 10) ----------------------------------------

use proptest::prelude::*;

#[derive(Clone, Debug)]
enum Between {
    Nothing,
    Release(u8),
    TakeBack(u8),
}

#[derive(Clone, Debug)]
enum Op {
    Commit(u8),
    Embargo(u8),
    Release(u8),
    Push { public: bool, between: Between },
}

fn op() -> impl Strategy<Value = Op> {
    let between = prop_oneof![
        1 => Just(Between::Nothing),
        1 => (0..2u8).prop_map(Between::Release),
        2 => (0..2u8).prop_map(Between::TakeBack),
    ];
    prop_oneof![
        2 => any::<u8>().prop_map(Op::Commit),
        2 => any::<u8>().prop_map(Op::Embargo),
        2 => (0..2u8).prop_map(Op::Release),
        3 => (any::<bool>(), between).prop_map(|(public, between)| Op::Push { public, between }),
    ]
}

fn marker(n: usize) -> String {
    format!("embargoed-fix-marker-{n:04}-5e9d2a71")
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Whatever is released or taken back between a push's two phases, no
    /// remote ever holds (published or staged) the fix of an embargo this
    /// repository does not treat as released once the push is done.
    #[test]
    fn nothing_withheld_is_ever_staged(ops in prop::collection::vec(op(), 1..14)) {
        let (mut alice, fs, id) = new_repo("alice");
        let base = commit_files(&mut alice, &*fs, &[("a.txt", "base\n")], "base");
        alice.set_tag("main", base, None, false).unwrap();
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
                        alice.set_tag("main", c, None, true).unwrap();
                    }
                }
                Op::Embargo(n) => {
                    let main = alice.view().tags["main"].target;
                    attempts += 1;
                    let ws = format!("fix{attempts}");
                    alice.create_workspace(&ws, vec![main], None).unwrap();
                    let ov = alice.workspace_overlay(&ws).unwrap();
                    ov.write(&p(&format!("fix{n}-{attempts}.txt")), format!("{}\n", marker(fixes.len())).as_bytes()).unwrap();
                    let fix = alice.snapshot_workspace(&ws, &ov).unwrap().snapshot;
                    let spec = EmbargoSpec { scope: "team".into(), until: None };
                    if let Ok(r) = alice.merge(WS, main, vec![fix], "merge", Some(spec)) {
                        alice.set_tag("main", r.snapshot, None, true).unwrap();
                        fixes.push((r.embargo.unwrap(), fixes.len()));
                    }
                }
                Op::Release(i) => {
                    if let Some((e, _)) = fixes.get(i as usize) {
                        alice.keys().stage_release(e).unwrap();
                    }
                }
                Op::Push { public, between } => {
                    let target = if public { mirror.clone() } else { team.clone() };
                    let (fs2, id2) = (fs.clone(), id.clone());
                    let once = AtomicBool::new(false);
                    let embargoes: Vec<String> = fixes.iter().map(|(e, _)| e.clone()).collect();
                    let opts = SyncOptions {
                        pause_before_lock: hook(move || {
                            if once.swap(true, Ordering::SeqCst) {
                                return;
                            }
                            let other = Repo::open(fs2.clone(), Some(id2.clone()), "alice").unwrap();
                            match &between {
                                Between::Nothing => {}
                                Between::Release(i) => {
                                    if let Some(e) = embargoes.get(*i as usize) {
                                        other.keys().stage_release(e).unwrap();
                                    }
                                }
                                Between::TakeBack(i) => {
                                    if let Some(e) = embargoes.get(*i as usize) {
                                        other.keys().take_back_release(e).unwrap();
                                    }
                                }
                            }
                        }),
                        ..Default::default()
                    };
                    alice.keys().invalidate();
                    let _ = remote::push_with(&mut alice, target, public, &[], false, &opts);
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

// ---- many pushers ------------------------------------------------------------------

/// Many clients push their own tags to one path remote at once: every push
/// lands, none waits for another's upload, and the remote is complete.
#[test]
fn many_concurrent_pushers_to_one_path_remote() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("hub");
    let (mut alice, fs, id) = new_repo("alice");
    let base = commit_files(&mut alice, &*fs, &[("a.txt", "base\n")], "base");
    alice.set_tag("main", base, None, false).unwrap();
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
                    me.set_tag(&format!("agent-{i}"), c, None, true).unwrap();
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
    assert!(!root.join(".veil/objects/incoming").exists() || std::fs::read_dir(root.join(".veil/objects/incoming")).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().starts_with("push-")));
}
