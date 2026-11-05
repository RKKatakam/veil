//! Two-way Git interop and `.gitattributes` against the system `git`.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

// `pub`, as its unused `pub` helpers were when it was a crate root.
pub mod adversarial3_git;
mod adversarial3_git_props;
mod attributes_git;
mod git;
mod git_bridge_g;
