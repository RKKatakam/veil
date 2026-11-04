//! Tree decoding benchmark (ignored by default): the trees of the
//! `vl status` benchmark layout (`src/mNNN/sK/fJJ.rs`, 200 × 5 × 20 =
//! 20,000 files, 1,206 trees), decoded in both encodings.
//!
//! ```sh
//! cargo test --release -p veil-core --test tree_bench -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use veil_core::{
    object::{EntryKind, Object, Tree, TreeEncoding, TreeEntry, Visibility},
    ObjectId,
};

fn layout() -> Vec<Tree> {
    let mut trees = Vec::new();
    let mut src = Tree::default();
    for m in 0..200u32 {
        let mut module = Tree::default();
        for s in 0..5u32 {
            let mut sub = Tree::default();
            for f in 0..20u32 {
                let seed = (m * 100 + s * 20 + f).to_le_bytes();
                let mut id = [0u8; 32];
                id[..4].copy_from_slice(&seed);
                let cloaked = m < 10;
                sub.insert(TreeEntry {
                    name: format!("f{f:02}.rs"),
                    kind: EntryKind::File,
                    id: ObjectId(*blake3::hash(&id).as_bytes()),
                    size: 400 + u64::from((m * 7 + s * 3 + f) % 40) * 50,
                    executable: false,
                    visibility: if cloaked {
                        Visibility::Cloaked { scope: "team".into() }
                    } else {
                        Visibility::Public
                    },
                    fallback: None,
                });
            }
            let id = ObjectId::hash(&Object::Tree(sub.clone()).encode());
            trees.push(sub);
            module.insert(TreeEntry::dir(&format!("s{s}"), id));
        }
        let id = ObjectId::hash(&Object::Tree(module.clone()).encode());
        trees.push(module);
        src.insert(TreeEntry::dir(&format!("m{m:03}"), id));
    }
    trees.push(src);
    trees
}

fn time(raws: &[Vec<u8>]) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..20 {
        let t = Instant::now();
        for r in raws {
            std::hint::black_box(Object::decode(r).unwrap());
        }
        best = best.min(t.elapsed());
    }
    best
}

#[test]
#[ignore = "benchmark: run with --release --ignored --nocapture"]
fn decode_status_layout_trees() {
    let trees = layout();
    for enc in [TreeEncoding::Json, TreeEncoding::Binary] {
        let raws: Vec<Vec<u8>> = trees.iter().map(|t| Object::Tree(t.clone()).encode_with(enc)).collect();
        let bytes: usize = raws.iter().map(Vec::len).sum();
        let d = time(&raws);
        println!(
            "{enc:?}: {} trees, {} entries, {:.0} KiB, decode {:.2} ms (best of 20)",
            raws.len(),
            trees.iter().map(|t| t.entries.len()).sum::<usize>(),
            bytes as f64 / 1024.0,
            d.as_secs_f64() * 1000.0
        );
    }
}
