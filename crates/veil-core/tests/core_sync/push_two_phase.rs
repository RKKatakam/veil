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
#[ignore = "BUG-807: a push racing an undo of a staged release publishes the fix"]
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
