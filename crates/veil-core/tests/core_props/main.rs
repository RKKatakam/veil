//! Property tests and fuzzing.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod adversarial2_props;
mod adversarial6_props;
mod adversarial_fuzz;
mod adversarial_props;
mod graph_index_props;
mod hostile_labels_props;
mod policy_fold_props;
mod team_vault_props;
mod undo_redo_props;
