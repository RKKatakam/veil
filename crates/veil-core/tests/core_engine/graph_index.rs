//! The history index on disk (`graph_index`): what commits leave behind,
//! how layers are merged, and the states another process can leave it in.
//! The query results themselves are checked against full walks in
//! `core_props/graph_index_props.rs`.

use std::sync::Arc;

use veil_core::{revset, MemoryBackend, Repo, StorageBackend, VPath};

const WS: &str = "default";

fn dir() -> VPath {
    VPath::new(".veil/index/graph").unwrap()
}

fn files(backend: &dyn StorageBackend) -> Vec<String> {
    let mut v: Vec<String> = backend.list_dir(&dir()).unwrap_or_default().into_iter().map(|e| e.name).collect();
    v.sort();
    v
}

fn layers(backend: &dyn StorageBackend) -> Vec<String> {
    files(backend).into_iter().filter(|n| n.starts_with("L-")).collect()
}

fn setup() -> (Arc<dyn StorageBackend>, Repo) {
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let repo = Repo::init(backend.clone(), None, "t").unwrap();
    (backend, repo)
}

/// Commits append small layers, which merge geometrically: after 200
/// commits the chain is a handful of files, and a fresh handle answers from
/// them.
#[test]
fn commits_append_layers_that_stay_few() {
    let (backend, mut repo) = setup();
    for i in 0..200 {
        repo.describe(repo.workspace_wc(WS).unwrap(), &format!("change {i}")).unwrap();
        repo.new_change(WS, vec![repo.workspace_wc(WS).unwrap()], "").unwrap();
    }
    let names = layers(&*backend);
    assert!(!names.is_empty() && names.len() <= 16, "layers: {names:?}");
    let reopened = Repo::open(backend.clone(), None, "t").unwrap();
    let wc = reopened.workspace_wc(WS).unwrap();
    let parent = reopened.snapshot(&wc).unwrap().parents[0];
    let (g, pg) = (reopened.held().index().generation(&reopened, &wc).unwrap(), reopened.held().index().generation(&reopened, &parent).unwrap());
    assert!(g.is_some() && pg.is_some() && g > pg, "{g:?} above {pg:?}");
    let visible: Vec<_> = reopened.held().visible_iter().map(Result::unwrap).collect();
    assert_eq!(visible, reopened.exact().visible().unwrap());
}

/// Counts the layer files created (`create_new` under the index).
#[derive(Debug, Default)]
struct Counting {
    inner: MemoryBackend,
    created: std::sync::atomic::AtomicUsize,
}

impl StorageBackend for Counting {
    fn kind(&self) -> &'static str {
        "memory"
    }
    fn read(&self, path: &VPath) -> veil_core::Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> veil_core::Result<()> {
        self.inner.write(path, data)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> veil_core::Result<bool> {
        if path.as_str().starts_with(".veil/index/graph/L-") {
            self.created.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> veil_core::Result<()> {
        self.inner.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> veil_core::Result<()> {
        self.inner.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> veil_core::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> veil_core::Result<Vec<veil_core::vfs::DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> veil_core::Result<Option<veil_core::vfs::Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> veil_core::Result<()> {
        self.inner.set_executable(path, executable)
    }
}

/// A merge that the geometric rule takes several steps for is written as
/// one layer: an append creates at most its own layer and one merged one
/// (each layer file costs two fsyncs on a disk), never one per step, and
/// the chain is what the steps would have left.
#[test]
fn a_compaction_writes_one_merged_layer() {
    let backend = Arc::new(Counting::default());
    let mut repo = Repo::init(backend.clone(), None, "t").unwrap();
    let mut most = 0;
    for i in 0..64 {
        let before = backend.created.load(std::sync::atomic::Ordering::SeqCst);
        repo.describe(repo.workspace_wc(WS).unwrap(), &format!("change {i}")).unwrap();
        let created = backend.created.load(std::sync::atomic::Ordering::SeqCst) - before;
        most = most.max(created);
        assert!(created <= 2, "append {i} created {created} layers: {:?}", layers(&*backend));
    }
    assert_eq!(most, 2, "some append merged");
    let names = layers(&*backend);
    assert!(!names.is_empty() && names.len() <= 8, "layers: {names:?}");
    let reopened = Repo::open(backend.clone(), None, "t").unwrap();
    let wc = reopened.workspace_wc(WS).unwrap();
    assert!(reopened.held().index().generation(&reopened, &wc).unwrap().is_some());
}

/// Another process took the next slot first: the appender reads its layer
/// and takes the slot after it; nothing is overwritten.
#[test]
fn a_lost_slot_is_retried_after_the_winners_layer() {
    let (backend, mut repo) = setup();
    repo.describe(repo.workspace_wc(WS).unwrap(), "one").unwrap();
    let before = layers(&*backend);
    // A second handle commits too (its own layer, in the next slot).
    let mut other = Repo::open(backend.clone(), None, "t").unwrap();
    other.describe(other.workspace_wc(WS).unwrap(), "two").unwrap();
    repo.reload().unwrap();
    repo.describe(repo.workspace_wc(WS).unwrap(), "three").unwrap();
    let after = layers(&*backend);
    assert!(after.len() >= before.len(), "{before:?} -> {after:?}");
    let fresh = Repo::open(backend.clone(), None, "t").unwrap();
    let wc = fresh.workspace_wc(WS).unwrap();
    assert!(fresh.held().index().generation(&fresh, &wc).unwrap().is_some());
    assert_eq!(fresh.held().visible_iter().map(Result::unwrap).collect::<Vec<_>>(), fresh.exact().visible().unwrap());
}

/// A layer of a voided epoch (left by a process that appended while the
/// index was being dropped) is never read, and is removed later.
#[test]
fn layers_of_an_older_epoch_are_ignored() {
    let (backend, mut repo) = setup();
    repo.describe(repo.workspace_wc(WS).unwrap(), "one").unwrap();
    // Plant garbage under epoch 0 and a marker for epoch 1.
    backend.write(&dir().join("L-0-7-7.vcg"), b"not a layer").unwrap();
    backend.create_new(&dir().join("E-1"), b"").unwrap();
    let mut fresh = Repo::open(backend.clone(), None, "t").unwrap();
    assert_eq!(fresh.held().visible_iter().map(Result::unwrap).collect::<Vec<_>>(), fresh.exact().visible().unwrap());
    fresh.describe(fresh.workspace_wc(WS).unwrap(), "two").unwrap();
    let names = files(&*backend);
    assert!(names.iter().any(|n| n.starts_with("L-1-")), "{names:?}");
    assert!(!names.iter().any(|n| n.starts_with("L-0-")), "epoch-0 layers removed: {names:?}");
}

/// Files that are not layers, and a damaged layer, never make a command
/// fail: the index is dropped and computed again.
#[test]
fn a_damaged_index_is_rebuilt_not_an_error() {
    let (backend, mut repo) = setup();
    for i in 0..5 {
        repo.describe(repo.workspace_wc(WS).unwrap(), &format!("c{i}")).unwrap();
    }
    for name in layers(&*backend) {
        backend.write(&dir().join(&name), b"VEILCG01 but truncated").unwrap();
    }
    backend.write(&dir().join("README"), b"stray").unwrap();
    backend.write(&dir().join("L-01-1.vcg"), b"non-canonical name").unwrap();
    let mut fresh = Repo::open(backend.clone(), None, "t").unwrap();
    let wc = fresh.workspace_wc(WS).unwrap();
    assert!(fresh.held().index().generation(&fresh, &wc).unwrap().is_some());
    fresh.describe(wc, "after").unwrap();
    assert!(!layers(&*backend).is_empty());
}

/// A deep linear history is indexed without recursion (threat 9), and a
/// query near the top reads only the top.
#[test]
fn a_deep_history_is_indexed_iteratively() {
    let (_, mut repo) = setup();
    let mut tx = repo.transaction("chain").unwrap();
    let mut parent = tx.repo().root_id();
    let tree = tx.repo().store().empty_tree().unwrap();
    for i in 0..20_000i64 {
        let s = veil_core::Snapshot {
            parents: vec![parent],
            change_id: veil_core::ChangeId::random(),
            tree,
            description: veil_core::object::Text::default(),
            author: "t".into(),
            timestamp: i,
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
        };
        parent = tx.repo().store().put_snapshot(&s).unwrap();
    }
    tx.add_head(parent).unwrap();
    tx.commit().unwrap();
    assert_eq!(repo.held().index().generation(&repo, &parent).unwrap(), Some(20_001));
    let first: Vec<_> = repo.held().topo_iter([parent]).take(3).map(Result::unwrap).collect();
    assert_eq!(first[0], parent);
    assert_eq!(first.len(), 3);
}

/// An index entry for a snapshot that is gone from the store (collected by
/// gc) never resolves (threat 7).
#[test]
fn collected_snapshots_do_not_resolve_through_the_index() {
    let (backend, mut repo) = setup();
    let wc = repo.workspace_wc(WS).unwrap();
    repo.describe(wc, "doomed").unwrap();
    let doomed = repo.workspace_wc(WS).unwrap();
    let change = repo.snapshot(&doomed).unwrap().change_id;
    repo.new_change(WS, vec![repo.root_id()], "").unwrap();
    repo.abandon(doomed).unwrap();
    // Indexed (the commits persisted it), then collected: remove the
    // loose object as gc would.
    assert!(repo.held().index().generation(&repo, &doomed).unwrap().is_some());
    let hex = doomed.hex();
    backend.remove_file(&VPath::new(&format!(".veil/objects/{}/{}", &hex[..2], &hex[2..])).unwrap()).unwrap();
    let fresh = Repo::open(backend.clone(), None, "t").unwrap();
    assert!(fresh.exact().snapshot(&doomed).unwrap().is_none(), "collected");
    let prefix = &change.to_string()[..8];
    let err = revset::resolve(&fresh, prefix, WS).unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
}
