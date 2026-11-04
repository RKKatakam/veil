//! Proptest-based fuzzing of every parser that sees untrusted bytes
//! (`cargo fuzz` is not available in this environment), plus crypto misuse:
//! tampered, truncated, re-scoped and replayed envelopes.

mod adversarial_support;

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    checkout::checkout,
    crypto::{random_key, Envelope},
    id::ChangeId,
    identity::wrap_key,
    object::{EntryKind, Object, Tree, TreeEntry, Visibility},
    policy::Policy,
    revset::resolve,
    secrets,
    tree::{diff_trees, lookup, walk_files},
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

fn cfg(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(cases),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

const TAGS: [&[u8]; 5] = [b"veil:blob\n", b"veil:tree\n", b"veil:snap\n", b"veil:seal\n", b""];

proptest! {
    #![proptest_config(cfg(2000))]

    #[test]
    fn object_decode_never_panics(tag in 0usize..5, body in proptest::collection::vec(any::<u8>(), 0..300)) {
        let mut raw = TAGS[tag].to_vec();
        raw.extend_from_slice(&body);
        let _ = Object::decode(&raw);
        let _ = Object::sealed_scope(&raw);
    }

    #[test]
    fn object_decode_of_json_like_bodies_never_panics(tag in 1usize..3, body in "\\{[\"a-z:,\\[\\]{}0-9 ]{0,200}\\}") {
        let mut raw = TAGS[tag].to_vec();
        raw.extend_from_slice(body.as_bytes());
        let _ = Object::decode(&raw);
    }

    #[test]
    fn envelope_from_bytes_never_panics(b in proptest::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(env) = Envelope::from_bytes(&b) {
            prop_assert!(env.open(&random_key()).is_err());
        }
        let _ = Envelope::peek_scope(&b);
    }

    #[test]
    fn policy_parse_and_classify_never_panic(text in "[ -~\\n\\t]{0,300}", path in "[a-z./*\\[\\]{}!-]{1,40}") {
        let p = Policy::parse(&text);
        if let Ok(vp) = VPath::new(&path) {
            let _ = p.classify(&vp, false);
            let _ = p.classify(&vp, true);
        }
    }

    #[test]
    fn secret_scan_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let _ = secrets::scan(&data);
    }

    #[test]
    fn id_parsers_never_panic(s in "\\PC{0,80}") {
        let _ = ObjectId::from_hex(&s);
        let _ = ChangeId::parse(&s);
        let _ = ChangeId::reverse_hex_to_hex(&s);
    }

    #[test]
    fn vpath_new_upholds_its_invariants(s in "[a-z./\\\\\\x00 ]{0,40}") {
        if let Ok(v) = VPath::new(&s) {
            prop_assert!(!v.as_str().starts_with('/') && !v.as_str().ends_with('/'));
            for c in v.as_str().split('/') {
                prop_assert!(v.is_root() || (!c.is_empty() && c != "." && c != ".."), "{v:?}");
            }
        }
    }

    #[test]
    fn envelope_any_bit_flip_is_detected(msg in proptest::collection::vec(any::<u8>(), 0..64), pos in any::<usize>(), bit in 0u8..8) {
        let k = random_key();
        let env = Envelope::seal(&k, "team", &msg, true).unwrap();
        let mut bytes = env.to_bytes();
        let i = pos % bytes.len();
        bytes[i] ^= 1 << bit;
        if let Ok(e) = Envelope::from_bytes(&bytes) {
            prop_assert!(e.open(&k).is_err(), "flipped byte {i} still opened");
        }
    }

    #[test]
    fn envelope_truncation_is_detected(msg in proptest::collection::vec(any::<u8>(), 0..64), cut in any::<usize>()) {
        let k = random_key();
        let bytes = Envelope::seal(&k, "team", &msg, false).unwrap().to_bytes();
        let n = cut % bytes.len();
        if let Ok(e) = Envelope::from_bytes(&bytes[..n]) {
            prop_assert!(e.open(&k).is_err());
        }
    }
}

// ---- revset fuzzing against a real repository ----------------------------------

fn small_repo() -> Repo {
    let (mut repo, fs, _) = new_repo("alice");
    let a = commit_files(&mut repo, &*fs, &[("a.txt", "1\n")], "one");
    repo.set_tag("main", a, None, false).unwrap();
    commit_files(&mut repo, &*fs, &[("b.txt", "2\n")], "two");
    repo.create_workspace("agent", vec![a], None).unwrap();
    repo
}

proptest! {
    #![proptest_config(cfg(1000))]

    #[test]
    fn revset_resolve_never_panics(spec in "[@a-z0-9kz/\\-_. ()]{0,24}|\\PC{0,24}") {
        thread_local!(static REPO: Repo = small_repo());
        REPO.with(|repo| {
            let r = catch_unwind(AssertUnwindSafe(|| { let _ = resolve(repo, &spec, WS); }));
            assert!(r.is_ok(), "revset {spec:?} panicked");
        });
    }
}

// ---- hostile tree decoding ----------------------------------------------------------

fn arb_entry(name: BoxedStrategy<String>) -> impl Strategy<Value = (String, bool, u8)> {
    (name, any::<bool>(), any::<u8>())
}

fn exercise_tree(entries: Vec<(String, bool, u8)>) {
    let (repo, _fs, _) = new_repo("v");
    let store = repo.store().clone();
    let b = blob(&repo, b"payload\n");
    let sub = raw_tree(&repo, vec![file("leaf", b)]);
    let entries: Vec<TreeEntry> = entries
        .into_iter()
        .map(|(name, is_dir, k)| TreeEntry {
            name,
            kind: if is_dir { EntryKind::Dir } else { EntryKind::File },
            id: match k % 3 {
                0 => b,
                1 => sub,
                _ => ObjectId([k; 32]),
            },
            size: k as u64,
            executable: k % 2 == 0,
            visibility: Visibility::Public,
            fallback: None,
        })
        .collect();
    let root = repo.store().put(&Object::Tree(Tree { entries })).unwrap();
    let wc = MemoryBackend::new();
    let _ = walk_files(&store, &root);
    let _ = diff_trees(&store, None, Some(&root));
    let _ = lookup(&store, &root, &p("leaf"));
    let _ = checkout(&store, &wc, None, &root);
    let _ = repo.store().tree(&root);
}

proptest! {
    #![proptest_config(cfg(500))]

    /// Well-formed names: nothing may panic.
    #[test]
    fn tree_operations_never_panic_on_valid_names(
        entries in proptest::collection::vec(arb_entry("[a-zA-Z0-9_.-]{1,8}".prop_filter("dots", |s| s != "." && s != "..").boxed()), 0..8)
    ) {
        let r = catch_unwind(AssertUnwindSafe(|| exercise_tree(entries.clone())));
        prop_assert!(r.is_ok(), "panic on {entries:?}");
    }
}

proptest! {
    #![proptest_config(cfg(500))]

    /// Arbitrary names, as a malicious remote may send them.
    #[test]
    fn tree_operations_never_panic_on_hostile_names(
        entries in proptest::collection::vec(arb_entry("[a/.\\x00]{0,4}".boxed()), 0..6)
    ) {
        let r = catch_unwind(AssertUnwindSafe(|| exercise_tree(entries.clone())));
        prop_assert!(r.is_ok(), "panic on {entries:?}");
    }
}

// ---- crypto misuse --------------------------------------------------------------------

#[test]
fn sealed_blob_replayed_into_another_repository_is_unreadable() {
    // Same scope *name*, different scope key.
    let (mut a, afs, _) = new_repo("alice");
    afs.write(&p(".veilpolicy"), b"s/ cloak team\n").unwrap();
    let c = commit_files(&mut a, &*afs, &[("s/k", "alice secret\n")], "c");
    let e = file_entry(&a, &c, "s/k").unwrap();
    let raw = a.store().get_raw(&e.id).unwrap();

    let (b, _bfs, _) = new_repo("bob");
    b.store().put_raw(&e.id, &raw).unwrap();
    let err = b.store().read_entry(&e).unwrap_err();
    assert!(err.is_unreadable(), "{err}");
}

#[test]
fn sealed_blob_with_rewritten_scope_header_is_unreadable() {
    let (mut a, afs, _) = new_repo("alice");
    a.keys().create_scope("ops").unwrap();
    afs.write(&p(".veilpolicy"), b"s/ cloak ops\n").unwrap();
    let c = commit_files(&mut a, &*afs, &[("s/k", "ops secret\n")], "c");
    let e = file_entry(&a, &c, "s/k").unwrap();
    let Object::Sealed(mut env) = a.store().get(&e.id).unwrap() else { panic!() };
    env.scope = "team".into();
    let forged = a.store().put(&Object::Sealed(env)).unwrap();
    assert!(a.store().read_blob(&forged).is_err(), "AEAD must bind the scope");
}

#[test]
fn wrapped_key_moved_between_scopes_or_recipients_fails() {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let k = random_key();
    let w = wrap_key(&alice.public_key(), &k, "team").unwrap();
    assert!(alice.unwrap_key(&w, "ops").is_err());
    assert!(bob.unwrap_key(&w, "team").is_err());
    let mut relabelled = w.clone();
    relabelled.sealed.scope = "wrap:ops".into();
    assert!(alice.unwrap_key(&relabelled, "ops").is_err());
    assert_eq!(alice.unwrap_key(&w, "team").unwrap(), k);
}

#[test]
fn descriptions_use_random_nonces_but_blobs_are_convergent() {
    let (repo, _fs, _) = new_repo("alice");
    let t1 = repo.store().make_text("same", Some("team")).unwrap();
    let t2 = repo.store().make_text("same", Some("team")).unwrap();
    assert_ne!(t1, t2, "description ciphertexts must not reveal equality");
    let v = Visibility::Cloaked { scope: "team".into() };
    assert_eq!(repo.store().store_file(b"x", &v).unwrap(), repo.store().store_file(b"x", &v).unwrap());
}

#[test]
fn envelope_encoding_roundtrips_or_refuses_long_scopes() {
    let k = random_key();
    let scope = "s".repeat(70_000);
    match Envelope::seal(&k, &scope, b"hi", true) {
        Err(_) => {}
        Ok(env) => {
            let back = Envelope::from_bytes(&env.to_bytes());
            assert_eq!(back.ok(), Some(env), "encoding is not a bijection");
        }
    }
}

#[test]
fn memory_backends_are_independent_after_fork() {
    let m = MemoryBackend::from_files([("a", &b"1"[..])]).unwrap();
    let f = m.fork();
    f.write(&p("a"), b"2").unwrap();
    assert_eq!(m.read(&p("a")).unwrap(), b"1");
    let _ = Arc::new(f);
}
