//! The working copy: checkout, the stat cache, symlinks, filesystem semantics,
//! editor artefacts, fallbacks and the accepted policy.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;
#[path = "../macos_support/mod.rs"]
mod macos_support;

mod checkout_obstacles;
mod cloaked_fallback;
mod editor_artefacts;
mod macos_fs;
mod policy_accept;
mod stale_fallback;
mod symlinks;
mod working_copy;
mod working_copy_edges;
