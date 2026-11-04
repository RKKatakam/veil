//! Conformance tests for remotes, storage and Git interop: Veil's
//! equivalents of Git's t5xxx (clone, fetch, push, pull, remote), t1050
//! (large files), t1450 (fsck), t5304/t6500 (prune, gc) and the fast-import
//! / fast-export round trips of t9300/t9350, and of Jujutsu's `test_git_*`,
//! `test_bookmark_command`, `test_concurrent_operations` and `test_gc`.
//! Coverage: `docs/conformance/sync.md`. Bugs: `docs/BUGS.md`,
//! "Conformance findings: remotes, storage and Git interop".

mod support;

mod remotes;
mod clone;
mod push_pull;
mod visibility;
mod integrity;
mod gc;
mod large;
mod git_bridge;
