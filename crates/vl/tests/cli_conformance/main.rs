//! Conformance tests translated from Git's and Jujutsu's test suites. The
//! coverage maps are in `docs/conformance/`.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

mod conformance_history;
mod conformance_sync;
mod conformance_worktree;
