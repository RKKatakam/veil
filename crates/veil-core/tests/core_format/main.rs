//! Repository formats: compatibility, canonical encodings and `fsck`.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod adversarial3_format;
mod deep_trees;
mod format_compat;
mod fsck;
mod git_parity_format;
mod tree_encoding;
