//! The binary tree encoding (repository format 2) is canonical: every valid
//! tree has exactly one encoding, decoding accepts only that encoding, and
//! the two encodings describe the same trees (see `docs/FORMAT.md`). Since
//! format 5 that includes symlink and gitlink entries (flag bit 7 and a
//! kind byte) and conflict terms of those kinds.

use proptest::prelude::*;
use veil_core::{
    object::{EntryKind, Object, Tree, TreeEncoding, TreeEntry, Visibility},
    ObjectId, VeilError,
};

fn entry_strategy() -> impl Strategy<Value = TreeEntry> {
    (
        "[a-zA-Z0-9._ é-]{1,12}",
        prop_oneof![Just(EntryKind::File), Just(EntryKind::Dir), Just(EntryKind::Symlink), Just(EntryKind::Gitlink)],
        any::<[u8; 32]>(),
        prop_oneof![Just(0u64), 1u64..200, any::<u64>()],
        any::<bool>(),
        prop_oneof![
            Just(Visibility::Public),
            "[a-z]{0,8}".prop_map(|s| Visibility::Cloaked { scope: s }),
            "[0-9a-f]{10}".prop_map(|s| Visibility::Embargoed { embargo: s }),
        ],
        proptest::option::of(any::<[u8; 32]>()),
    )
        .prop_map(|(name, kind, id, size, executable, visibility, fallback)| TreeEntry {
            name,
            kind,
            id: ObjectId(id),
            size,
            // A symlink or gitlink is never executable (refused below).
            executable: executable && !kind.is_special(),
            visibility,
            fallback: fallback.map(ObjectId),
        })
}

fn tree_strategy() -> impl Strategy<Value = Tree> {
    proptest::collection::vec(entry_strategy(), 1..20).prop_filter_map("valid names", |entries| {
        let mut t = Tree::default();
        for e in entries {
            t.insert(e);
        }
        t.validate().ok().map(|_| t)
    })
}

proptest! {
    #[test]
    fn binary_roundtrip_is_exact(t in tree_strategy()) {
        let raw = Object::Tree(t.clone()).encode_with(TreeEncoding::Binary);
        prop_assert_eq!(Object::tree_encoding(&raw), Some(TreeEncoding::Binary));
        let back = match Object::decode(&raw).unwrap() { Object::Tree(t) => t, _ => unreachable!() };
        prop_assert_eq!(&back, &t);
        prop_assert_eq!(Object::Tree(back.clone()).encode_with(TreeEncoding::Binary), raw);
        // Both encodings carry the same tree.
        let json = Object::Tree(t.clone()).encode_with(TreeEncoding::Json);
        let via_json = match Object::decode(&json).unwrap() { Object::Tree(t) => t, _ => unreachable!() };
        prop_assert_eq!(via_json, t);
    }

    /// Any single-byte change of a valid encoding either fails to decode or
    /// decodes to a tree whose canonical encoding is exactly the changed
    /// bytes (a different tree, never a second encoding of the same one).
    #[test]
    fn mutations_never_yield_a_second_encoding(t in tree_strategy(), at in any::<prop::sample::Index>(), x in 1u8..=255) {
        let raw = Object::Tree(t).encode_with(TreeEncoding::Binary);
        let i = 10 + at.index(raw.len() - 10);
        let mut m = raw.clone();
        m[i] ^= x;
        if let Ok(Object::Tree(d)) = Object::decode(&m) {
            prop_assert_eq!(Object::Tree(d).encode_with(TreeEncoding::Binary), m);
        }
    }

    /// Truncations and arbitrary bytes never panic.
    #[test]
    fn garbage_never_panics(body in proptest::collection::vec(any::<u8>(), 0..200)) {
        let mut raw = b"veil:tree\n\x02".to_vec();
        raw.extend_from_slice(&body);
        let _ = Object::decode(&raw);
    }
}

fn one_entry() -> Vec<u8> {
    let mut t = Tree::default();
    t.insert(TreeEntry {
        name: "a".into(),
        kind: EntryKind::File,
        id: ObjectId([1; 32]),
        size: 5,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
    });
    Object::Tree(t).encode_with(TreeEncoding::Binary)
}

fn corrupt(raw: &[u8]) -> bool {
    matches!(Object::decode(raw), Err(VeilError::Corrupt(..)))
}

#[test]
fn non_canonical_binary_trees_are_refused() {
    let good = one_entry();
    // tag(10) | 02 | count | name_len | 'a' | flags | id(32) | size
    assert_eq!(&good[10..15], &[0x02, 0x01, 0x01, b'a', 0x04]);
    assert!(Object::decode(&good).is_ok());

    let mut overlong_count = good[..11].to_vec();
    overlong_count.extend_from_slice(&[0x81, 0x00]);
    overlong_count.extend_from_slice(&good[12..]);
    assert!(corrupt(&overlong_count), "non-minimal varint accepted");

    let mut zero_size = good.clone();
    let last = zero_size.len() - 1;
    zero_size[last] = 0;
    assert!(corrupt(&zero_size), "explicit zero size accepted");

    let mut trailing = good.clone();
    trailing.push(0);
    assert!(corrupt(&trailing), "trailing bytes accepted");

    assert!(corrupt(&good[..good.len() - 1]), "truncated tree accepted");
    assert!(corrupt(b"veil:tree\n\x02\x00"), "empty binary tree accepted");

    let mut bad_utf8 = good.clone();
    bad_utf8[13] = 0xff;
    assert!(corrupt(&bad_utf8), "invalid UTF-8 name accepted");

    // Names are still validated, and entries must be sorted and unique.
    let mut dot_veil = Tree::default();
    dot_veil.entries.push(TreeEntry::dir(".veil", ObjectId([2; 32])));
    assert!(corrupt(&Object::Tree(dot_veil).encode_with(TreeEncoding::Binary)));
    let mut unsorted = Tree::default();
    unsorted.entries.push(TreeEntry::dir("b", ObjectId([2; 32])));
    unsorted.entries.push(TreeEntry::dir("a", ObjectId([2; 32])));
    assert!(corrupt(&Object::Tree(unsorted).encode_with(TreeEncoding::Binary)));
}

#[test]
fn the_empty_tree_is_always_format_1() {
    let json = Object::Tree(Tree::default()).encode_with(TreeEncoding::Json);
    assert_eq!(Object::Tree(Tree::default()).encode_with(TreeEncoding::Binary), json);
    assert_eq!(json, b"veil:tree\n{\"entries\":[]}");
}

#[test]
fn binary_trees_are_smaller() {
    let mut t = Tree::default();
    for i in 0..100 {
        t.insert(TreeEntry {
            name: format!("file_{i:03}.rs"),
            kind: EntryKind::File,
            id: ObjectId([i as u8; 32]),
            size: 1000 + i,
            executable: false,
            visibility: Visibility::Public,
            fallback: None,
        });
    }
    let json = Object::Tree(t.clone()).encode_with(TreeEncoding::Json).len();
    let bin = Object::Tree(t).encode_with(TreeEncoding::Binary).len();
    assert!(bin * 2 < json, "binary {bin} vs JSON {json}");
}

// ---- format 5: symlinks, gitlinks, link terms --------------------------------

fn special(kind: EntryKind) -> Vec<u8> {
    let mut t = Tree::default();
    t.insert(TreeEntry {
        name: "a".into(),
        kind,
        id: ObjectId([1; 32]),
        size: 5,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
    });
    Object::Tree(t).encode_with(TreeEncoding::Binary)
}

#[test]
fn symlink_and_gitlink_entries_round_trip_and_need_format_5() {
    for (kind, byte) in [(EntryKind::Symlink, 1u8), (EntryKind::Gitlink, 2)] {
        let raw = special(kind);
        // tag(10) | 02 | count | name_len | 'a' | flags (KIND|SIZE) | kind
        assert_eq!(&raw[10..16], &[0x02, 0x01, 0x01, b'a', 0x84, byte]);
        let Object::Tree(t) = Object::decode(&raw).unwrap() else { panic!() };
        assert_eq!(t.entries[0].kind, kind);
        assert_eq!(Object::min_repo_format(&raw), 5);
        // JSON trees spell the kind.
        let json = Object::Tree(t.clone()).encode_with(TreeEncoding::Json);
        assert!(String::from_utf8_lossy(&json).contains(&format!("\"kind\":\"{}\"", kind.name())));
        assert_eq!(Object::min_repo_format(&json), 5);
        assert_eq!(Object::decode(&json).unwrap(), Object::Tree(t));
    }
    // A plain file tree stays format 2 (and a conflict tree format 4).
    assert_eq!(Object::min_repo_format(&one_entry()), 2);
}

#[test]
fn hostile_special_entries_are_refused() {
    let good = special(EntryKind::Symlink);
    let flags_at = 14;
    // KIND with DIR, EXECUTABLE or CONFLICT: corrupt (canonical by
    // construction: one kind per entry).
    for extra in [0x01u8, 0x02, 0x40] {
        let mut raw = good.clone();
        raw[flags_at] |= extra;
        assert!(corrupt(&raw), "flags {:#04x} accepted", raw[flags_at]);
    }
    // Unknown kind bytes: "needs a newer vl".
    for k in [0u8, 3, 4, 0x80, 0xff] {
        let mut raw = good.clone();
        raw[flags_at + 1] = k;
        assert!(matches!(Object::decode(&raw), Err(VeilError::Unsupported(_))), "kind {k}");
    }
    // Truncated right after the KIND flag.
    assert!(corrupt(&good[..flags_at + 1]));
    // JSON: an executable symlink is refused too.
    let json = br#"veil:tree
{"entries":[{"name":"a","kind":"symlink","id":"0101010101010101010101010101010101010101010101010101010101010101","executable":true}]}"#;
    assert!(corrupt(json), "executable symlink in a JSON tree accepted");
}

fn link_term_strategy() -> impl Strategy<Value = Option<veil_core::ConflictTerm>> {
    use veil_core::object::TermKind;
    proptest::option::of(
        (
            prop_oneof![Just(TermKind::File), Just(TermKind::Symlink), Just(TermKind::Gitlink)],
            any::<[u8; 32]>(),
            prop_oneof![Just(0u64), 1u64..5000],
            any::<bool>(),
            prop_oneof![Just(Visibility::Public), "[a-z]{1,8}".prop_map(|s| Visibility::Cloaked { scope: s })],
            proptest::option::of(any::<[u8; 32]>()),
        )
            .prop_map(|(kind, id, size, executable, visibility, fallback)| veil_core::ConflictTerm {
                kind,
                id: ObjectId(id),
                size,
                executable: executable && kind == TermKind::File,
                visibility,
                fallback: fallback.map(ObjectId),
            }),
    )
}

proptest! {
    /// Conflicts with link and gitlink terms round-trip exactly; a term
    /// kind other than file makes them format 5.
    #[test]
    fn conflicts_with_link_terms_round_trip(n in 1usize..4, terms in proptest::collection::vec(link_term_strategy(), 7)) {
        let c = veil_core::Conflict { adds: terms[..=n].to_vec(), removes: terms[n + 1..].iter().chain(terms.iter()).take(n).cloned().collect() };
        let raw = Object::Conflict(c.clone()).encode();
        let back = Object::decode(&raw).unwrap();
        prop_assert_eq!(&back, &Object::Conflict(c.clone()));
        let want = if c.has_special_terms() { 5 } else { 4 };
        prop_assert_eq!(Object::min_repo_format(&raw), want);
    }

    /// Single-byte changes of a conflict with link terms never yield a
    /// second encoding of one conflict.
    #[test]
    fn link_conflict_mutations_never_yield_a_second_encoding(terms in proptest::collection::vec(link_term_strategy(), 3), at in any::<prop::sample::Index>(), x in 1u8..=255) {
        let c = veil_core::Conflict { adds: terms[..2].to_vec(), removes: terms[2..].to_vec() };
        let raw = Object::Conflict(c).encode();
        let i = 10 + at.index(raw.len() - 10);
        let mut m = raw.clone();
        m[i] ^= x;
        if let Ok(o @ Object::Conflict(_)) = Object::decode(&m) {
            prop_assert_eq!(o.encode(), m);
        }
    }
}

#[test]
fn executable_link_terms_are_refused() {
    use veil_core::{object::TermKind, ConflictTerm};
    let t = |kind| ConflictTerm {
        kind,
        id: ObjectId([1; 32]),
        size: 0,
        executable: false,
        visibility: Visibility::Public,
        fallback: None,
    };
    let c = veil_core::Conflict {
        adds: vec![Some(t(TermKind::Symlink)), Some(t(TermKind::File))],
        removes: vec![None],
    };
    let mut raw = Object::Conflict(c).encode();
    // tag(10) | 04 | removes | first term flags
    assert_eq!(raw[12], 0x41);
    raw[12] |= 0x02;
    assert!(corrupt(&raw) || matches!(Object::decode(&raw), Err(VeilError::Corrupt(..))));
}
