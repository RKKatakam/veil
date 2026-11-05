//! Workspaces through the real `vl` binary: `ws exec` sandboxes, sparse
//! sandboxes, `ws mount` and workspace undo, and the guide's library examples.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod guide_library;
mod mount_cli;
mod mount_props;
mod working_copy_edges_cli;
mod workspace_undo_props;
mod ws_sandbox_cli;
mod ws_sandbox_failures_cli;
mod ws_sparse_cli;
