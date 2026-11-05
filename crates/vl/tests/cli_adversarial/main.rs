//! The adversarial rounds through the real `vl` binary.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod adversarial2_cli;
mod adversarial3_git_cli;
mod adversarial3_release;
mod adversarial4_cli;
mod adversarial5_cli;
mod adversarial6_cli;
mod adversarial6_docs;
mod adversarial7;
mod adversarial8;
mod adversarial9;
mod adversarial_cli_abuse;
mod adversarial_cli_crash;
mod adversarial_cli_remote;
