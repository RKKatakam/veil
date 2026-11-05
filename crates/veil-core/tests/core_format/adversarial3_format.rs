//! Round 3: is every accepted encoding canonical? Random trees are encoded
//! (JSON and binary), then mutated byte by byte; whatever the decoder still
//! accepts must re-encode to exactly the bytes it was given, so no object
//! has a second encoding (and with it a second id) in the same format.
//! The golden fixtures are checked the same way.

use proptest::prelude::*;
use veil_core::{
    object::{EntryKind, Object, Tree, TreeEncoding, TreeEntry, Visibility},
    ObjectId,
};

fn entry() -> impl Strategy<Value = TreeEntry> {
    (
        "[a-z]{1,3}",
        any::<bool>(),
        any::<[u8; 32]>(),
        prop_oneof![Just(0u64), 1u64..300, any::<u64>()],
        any::<bool>(),
        0u8..3,
        prop::option::of(any::<[u8; 32]>()),
    )
        .prop_map(|(name, dir, id, size, exec, tier, fb)| TreeEntry {
            name,
            kind: if dir { EntryKind::Dir } else { EntryKind::File },
            id: ObjectId(id),
            size,
            executable: exec,
            visibility: match tier {
                0 => Visibility::Public,
                1 => Visibility::Cloaked { scope: "team".into() },
                _ => Visibility::Embargoed { embargo: "0123456789".into() },
            },
            fallback: fb.map(ObjectId),
        })
}

fn tree() -> impl Strategy<Value = Tree> {
    prop::collection::btree_map("[a-z]{1,3}", entry(), 1..5).prop_map(|m| Tree {
        entries: m
            .into_iter()
            .map(|(name, mut e)| {
                e.name = name;
                e
            })
            .collect(),
    })
}

fn check_canonical(raw: &[u8]) -> Result<(), String> {
    let Ok(obj) = Object::decode(raw) else { return Ok(()) };
    let enc = match Object::tree_encoding(raw) {
        Some(e) => e,
        None => TreeEncoding::Json,
    };
    let again = obj.encode_with(enc);
    if again != raw {
        return Err(format!(
            "accepted a second encoding:\n  given   {}\n  encodes {}",
            hex::encode(raw),
            hex::encode(&again)
        ));
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn mutated_trees_are_either_refused_or_canonical(
        t in tree(),
        binary in any::<bool>(),
        muts in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>(), 0u8..3), 1..4),
    ) {
        let enc = if binary { TreeEncoding::Binary } else { TreeEncoding::Json };
        let mut raw = Object::Tree(t).encode_with(enc);
        for (at, b, how) in muts {
            let i = at.index(raw.len());
            match how {
                0 => raw[i] = b,
                1 => raw.insert(i, b),
                _ => { if raw.len() > 12 { raw.remove(i); } }
            }
        }
        if let Err(e) = check_canonical(&raw) {
            prop_assert!(false, "{}", e);
        }
    }
}

#[test]
fn golden_fixtures_are_canonical() {
    let text = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/encodings.txt"));
    let mut n = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
        let Some((name, hexed)) = line.split_once(' ') else { continue };
        let Ok(raw) = hex::decode(hexed.trim()) else { continue };
        if Object::decode(&raw).is_ok() {
            check_canonical(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
            n += 1;
        }
    }
    assert!(n >= 4, "only {n} fixtures decoded");
}
