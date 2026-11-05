//! History and Git-parity features through the real `vl` binary: history
//! tools, duplicate, split, patches, conflicts, hooks, attributes, symlinks.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod attributes_cli;
mod conflicts_cli;
mod duplicate_cli;
mod git_parity_stubs;
mod history_cli;
mod hooks_cli;
mod split_cli;
mod symlinks_cli;
