//! Conformance tests for remotes and storage: Veil's
//! equivalents of Git's t5xxx (clone, fetch, push, pull, remote), t1050
//! (large files), t1450 (fsck) and t5304/t6500 (prune, gc), and of
//! Jujutsu's `test_bookmark_command`, `test_concurrent_operations` and
//! `test_gc`.
//! Coverage: `docs/conformance/sync.md`. Bugs: `docs/BUGS.md`,
//! "Conformance findings: remotes and storage".

mod support;

mod clone;
mod concurrency;
mod formats;
mod gc;
mod integrity;
mod large;
mod push_pull;
mod remotes;
mod sftp;
mod visibility;
