//! The leak checks in the adversarial suites search remotes for plaintext.
//! Pushed objects arrive zstd-packed, so a raw byte search alone is blind:
//! this pins that `backend_contains` really looks inside packs.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{remote, MemoryBackend, StorageBackend, VPath};

#[test]
fn backend_contains_sees_plaintext_inside_pushed_packs() {
    let (mut alice, fs, _) = new_repo("alice");
    // Compressible, so zstd really changes the bytes.
    let body = "public-needle-7f3a ".repeat(200);
    let main = commit_files(&mut alice, &*fs, &[("notes.txt", body.as_str())], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();

    let needle = b"public-needle-7f3a public-needle-7f3a";
    let raw_hits: Vec<_> = veil_core::vfs::walk_files(&*mirror, &VPath::root(), &|_| false)
        .unwrap()
        .into_iter()
        .filter(|f| mirror.read(f).unwrap().windows(needle.len()).any(|w| w == needle))
        .collect();
    assert!(
        raw_hits.is_empty(),
        "the file arrived uncompressed; this test no longer exercises packed content: {raw_hits:?}"
    );
    let hits = backend_contains(&*mirror, needle);
    assert!(!hits.is_empty(), "backend_contains must find plaintext inside packs");
}
