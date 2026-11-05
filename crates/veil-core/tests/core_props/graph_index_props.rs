//! The history index (`graph_index`, `docs/design/scale/3-history-index.md`)
//! against the full walks it replaces, on random histories: merges,
//! criss-crosses, equal timestamps and parents the store does not hold (a
//! public clone's view of an unreleased embargo). Every query must give
//! exactly the full walk's answer, whatever state the index is in: empty,
//! partly persisted, reopened from disk, damaged, or stale after a missing
//! parent arrived (threats 4, 5 and 12).
//!
//! Set `PROPTEST_CASES` to run more cases.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use proptest::prelude::*;
use veil_core::{object::Text, ChangeId, MemoryBackend, ObjectId, Repo, Snapshot, StorageBackend, VPath};

fn cfg(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(cases),
        failure_persistence: None,
        max_shrink_iters: 2000,
        ..ProptestConfig::default()
    }
}

/// One random history: node `i`'s parents are earlier nodes, or "absent"
/// ids the store never holds (`None`).
#[derive(Clone, Debug)]
struct Dag {
    parents: Vec<Vec<Option<usize>>>,
    /// Timestamps from a small range, so ties are common.
    times: Vec<i64>,
    /// Nodes whose snapshot is written only in the second phase.
    late: Vec<bool>,
}

fn dag() -> impl Strategy<Value = Dag> {
    (2usize..28).prop_flat_map(|n| {
        let parents = (0..n)
            .map(|i| {
                let earlier = proptest::option::weighted(0.9, 0..i.max(1));
                proptest::collection::vec(earlier, if i == 0 { 0..1 } else { 1..4 })
            })
            .collect::<Vec<_>>();
        (parents, proptest::collection::vec(0i64..4, n), proptest::collection::vec(proptest::bool::weighted(0.15), n))
    })
    .prop_map(|(parents, times, late)| {
        // Node 0 has no parents; `None` stands for an absent parent.
        let parents = parents.into_iter().enumerate().map(|(i, ps)| if i == 0 { vec![] } else { ps }).collect();
        Dag { parents, times, late }
    })
}

fn snap(parents: Vec<ObjectId>, i: usize, ts: i64, tree: ObjectId) -> Snapshot {
    let mut change = [0u8; 16];
    change[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
    Snapshot {
        parents,
        change_id: ChangeId(change),
        tree,
        description: Text::default(),
        author: "t".into(),
        timestamp: ts,
        predecessors: vec![],
        conflicts: vec![],
        cloak: None,
        embargo: None,
        signature: None,
    }
}

/// The snapshot ids of `dag` and the snapshots, parents first. The ids
/// come from storing them in a scratch repository.
fn build(dag: &Dag, tree: ObjectId) -> (Vec<ObjectId>, Vec<Snapshot>) {
    let (_, scratch) = repo();
    let mut ids: Vec<ObjectId> = Vec::new();
    let mut snaps = Vec::new();
    for (i, ps) in dag.parents.iter().enumerate() {
        let mut parents: Vec<ObjectId> = Vec::new();
        for (k, p) in ps.iter().enumerate() {
            let id = match p {
                Some(j) => ids[*j],
                None => ObjectId::hash(format!("absent {i} {k}").as_bytes()),
            };
            if !parents.contains(&id) {
                parents.push(id);
            }
        }
        let s = snap(parents, i, dag.times[i], tree);
        ids.push(scratch.store().put_snapshot(&s).unwrap());
        snaps.push(s);
    }
    (ids, snaps)
}

fn repo() -> (Arc<dyn StorageBackend>, Repo) {
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let repo = Repo::init(backend.clone(), None, "t").unwrap();
    (backend, repo)
}

/// Full-walk answers.
fn naive_generation(repo: &Repo, id: &ObjectId, memo: &mut HashMap<ObjectId, Option<u32>>) -> Option<u32> {
    if let Some(g) = memo.get(id) {
        return *g;
    }
    let g = repo.snapshot_opt(id).unwrap().map(|s| {
        let mut g = 0;
        for p in &s.parents {
            if let Some(pg) = naive_generation(repo, p, memo) {
                g = g.max(pg);
            }
        }
        g + 1
    });
    memo.insert(*id, g);
    g
}

fn reachable(repo: &Repo, roots: &[ObjectId]) -> HashSet<ObjectId> {
    repo.topo_children_first(roots.iter().copied()).unwrap().into_iter().collect()
}

/// Check every query against the full walks, for some roots and pairs.
fn check_all(repo: &Repo, nodes: &[ObjectId], pick: &[usize]) {
    let pick: Vec<ObjectId> = pick.iter().map(|i| nodes[i % nodes.len()]).collect();
    let roots: Vec<ObjectId> = pick.iter().take(3).copied().collect();
    let g = repo.graph();
    // Order: exactly `topo_children_first`'s (threat 12).
    let lazy: Vec<ObjectId> = repo.topo_iter(roots.iter().copied()).map(Result::unwrap).collect();
    assert_eq!(lazy, repo.topo_children_first(roots.iter().copied()).unwrap(), "topo order");
    let mut memo = HashMap::new();
    for id in nodes {
        // Generations strictly decrease along every edge.
        if let (Some(gen), Some(s)) = (g.generation(repo, id).unwrap(), repo.snapshot_opt(id).unwrap()) {
            for p in &s.parents {
                if let Some(pg) = g.generation(repo, p).unwrap() {
                    assert!(pg < gen, "generation of a parent below its child's");
                }
            }
            assert_eq!(Some(gen), naive_generation(repo, id, &mut memo), "generation");
        }
    }
    for a in &pick {
        for b in &pick {
            let naive = a == b || repo.ancestors(b).unwrap().contains(a);
            assert_eq!(repo.is_ancestor(a, b).unwrap(), naive, "is_ancestor");
            assert_eq!(repo.merge_bases(&[*a], &[*b]).unwrap(), repo.merge_bases_naive(&[*a], &[*b]).unwrap(), "merge bases");
        }
    }
    let (inc, exc) = pick.split_at(pick.len() / 2);
    let naive_range: HashSet<ObjectId> = &reachable(repo, inc) - &reachable(repo, exc);
    assert_eq!(g.range(repo, inc, exc).unwrap(), naive_range, "range");
    let candidates: HashSet<ObjectId> = nodes.iter().copied().step_by(2).collect();
    let from_roots = reachable(repo, &roots);
    let naive_among: HashSet<ObjectId> = candidates.iter().copied().filter(|c| from_roots.contains(c)).collect();
    assert_eq!(g.reachable_among(repo, roots.iter().copied(), &candidates).unwrap(), naive_among, "reachable_among");
    for floor in [1, 3, 6] {
        let naive: HashSet<ObjectId> =
            from_roots.iter().copied().filter(|id| naive_generation(repo, id, &mut memo).is_some_and(|x| x >= floor)).collect();
        let got: HashSet<ObjectId> = g.down_to(repo, roots.iter().copied(), floor).unwrap().into_keys().collect();
        assert_eq!(got, naive, "down_to {floor}");
    }
}

fn index_files(backend: &dyn StorageBackend) -> Vec<(String, Vec<u8>)> {
    let dir = VPath::new(".veil/index/graph").unwrap();
    let mut out: Vec<(String, Vec<u8>)> = backend
        .list_dir(&dir)
        .unwrap_or_default()
        .into_iter()
        .map(|e| {
            let data = backend.read(&dir.join(&e.name)).unwrap();
            (e.name, data)
        })
        .collect();
    out.sort();
    out
}

proptest! {
    #![proptest_config(cfg(64))]

    /// Every index state gives the full walks' answers.
    #[test]
    fn index_queries_equal_full_walks(dag in dag(), pick in proptest::collection::vec(0usize..64, 2..7), damage in 0usize..4096) {
        let (backend, repo) = repo();
        let tree = repo.store().empty_tree().unwrap();
        let (ids, snaps) = build(&dag, tree);
        for (i, s) in snaps.iter().enumerate() {
            if !dag.late[i] {
                repo.store().put_snapshot(s).unwrap();
            }
        }
        // Empty index, computed on the fly.
        check_all(&repo, &ids, &pick);
        // Persisted, then read back by another handle.
        repo.graph().persist(&repo);
        let reopened = Repo::open(backend.clone(), None, "t").unwrap();
        check_all(&reopened, &ids, &pick);
        // The late snapshots arrive: some were missing parents of indexed
        // ones (threat 4), and a fresh handle must notice.
        for (i, s) in snaps.iter().enumerate() {
            if dag.late[i] {
                repo.store().put_snapshot(s).unwrap();
            }
        }
        let later = Repo::open(backend.clone(), None, "t").unwrap();
        check_all(&later, &ids, &pick);
        later.graph().persist(&later);
        // So must a handle that indexed before they arrived.
        reopened.graph().revalidate(&reopened);
        check_all(&reopened, &ids, &pick);
        // A damaged layer (threat 5): one byte flipped, or cut short.
        let files = index_files(&*backend);
        if let Some((name, data)) = files.iter().find(|(n, _)| n.starts_with("L-")) {
            let mut data = data.clone();
            match damage % 2 {
                0 => { let at = damage % data.len(); data[at] ^= 1; }
                _ => data.truncate(damage % data.len()),
            }
            backend.write(&VPath::new(".veil/index/graph").unwrap().join(name), &data).unwrap();
            let damaged = Repo::open(backend.clone(), None, "t").unwrap();
            check_all(&damaged, &ids, &pick);
        }
    }

    /// The index bytes are a function of plaintext snapshot fields: the
    /// same with and without keys (threat 1), and the same however the
    /// entries were computed.
    #[test]
    fn index_bytes_do_not_depend_on_who_built_them(dag in dag()) {
        let (backend, repo) = repo();
        let tree = repo.store().empty_tree().unwrap();
        let (ids, snaps) = build(&dag, tree);
        for s in &snaps {
            repo.store().put_snapshot(s).unwrap();
        }
        let dir = VPath::new(".veil/index/graph").unwrap();
        let build_with = |identity: Option<veil_core::Identity>| {
            let _ = backend.remove_dir_all(&dir);
            let r = Repo::open(backend.clone(), identity, "t").unwrap();
            for id in &ids {
                r.graph().generation(&r, id).unwrap();
            }
            r.graph().persist(&r);
            index_files(&*backend).into_iter().map(|(_, d)| d).collect::<Vec<_>>()
        };
        let without = build_with(None);
        let with = build_with(Some(veil_core::Identity::generate("t")));
        prop_assert_eq!(without, with);
    }
}
