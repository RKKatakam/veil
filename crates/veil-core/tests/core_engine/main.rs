//! The engine: commits, history tools, merges, conflicts, rewriting,
//! embargo releases, attributes and `ws exec` sandboxes.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod attributes;
mod conflicts;
mod duplicate;
mod embargo_release;
mod engine;
mod checkout_speed;
mod graph_index;
mod history_rename;
mod history_tools;
mod mount_recording;
mod refused_folder;
mod rename_merge;
mod review_core;
mod sandbox;
mod split_squash;
